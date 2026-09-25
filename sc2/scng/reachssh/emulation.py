"""
reachssh emulation — optional shim for mock-device testing.

Inert unless enable_emulation() is called. Redirects SSH connections to a
local mock-device server based on ip_lookup.json.

Provides transparent SSH connection redirection to NetEmulate mock devices.
Extracted as a standalone module so any component can query emulation state without importing
SSH internals.

Usage:
    from sc2.scng.reachssh.emulation import enable_emulation, disable_emulation

    count = enable_emulation("/path/to/ip_lookup.json")
    print(f"Loaded {count} mock device IPs")

    # ... all SSH connections now route to mock devices ...
    # Other modules can check state:
    #   from sc2.scng.reachssh.emulation import is_enabled, lookup

    disable_emulation()

"""

import json
import logging
from pathlib import Path
from typing import Optional, Dict, Tuple

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# Module state — private, accessed only through public functions below
# ═══════════════════════════════════════════════════════════════════════════

_enabled: bool = False
_lookup: Dict[str, dict] = {}
_host: str = "127.0.0.1"
_creds: Tuple[str, str] = ("admin", "admin")
_dns_intercept_installed: bool = False
_original_getaddrinfo = None

# Default search paths for ip_lookup.json (checked in order)
_DEFAULT_SEARCH_PATHS = [
    Path("ip_lookup.json"),
    Path.home() / "netemulate" / "ip_lookup.json",
]


# ═══════════════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════════════

def enable_emulation(
    lookup_path: Optional[str] = None,
    bind_host: str = "127.0.0.1",
    creds: Tuple[str, str] = ("admin", "admin"),
) -> int:
    """
    Enable emulation mode — redirect SSH connections to NetEmulate mock devices.

    Args:
        lookup_path: Path to ip_lookup.json. If None, searches default locations.
        bind_host: Address mock servers are bound to (default: 127.0.0.1).
        creds: Username/password for mock devices (default: admin/admin).

    Returns:
        Number of IPs loaded into the lookup table.

    Raises:
        FileNotFoundError: If no lookup file can be found.
    """
    global _enabled, _lookup, _host, _creds

    if lookup_path is None:
        for p in _DEFAULT_SEARCH_PATHS:
            if p.exists():
                lookup_path = str(p)
                break
        else:
            raise FileNotFoundError(
                "Emulation lookup not found. Searched:\n"
                + "\n".join(f"  - {p}" for p in _DEFAULT_SEARCH_PATHS)
            )

    path = Path(lookup_path)
    if not path.exists():
        raise FileNotFoundError(f"Emulation lookup not found: {lookup_path}")

    _lookup = json.loads(path.read_text())
    _host = bind_host
    _creds = creds
    _enabled = True
    _install_dns_intercept()

    logger.info(f"[EMULATION] Enabled — {len(_lookup)} IPs loaded from {lookup_path}")
    return len(_lookup)


def disable_emulation() -> None:
    """Disable emulation mode — restore normal SSH connections."""
    global _enabled, _lookup
    _enabled = False
    _lookup = {}
    _uninstall_dns_intercept()
    logger.info("[EMULATION] Disabled — connections restored to normal")


def is_enabled() -> bool:
    """Check whether emulation mode is currently active."""
    return _enabled


def get_bind_host() -> str:
    """Return the address mock servers are bound to."""
    return _host


def get_credentials() -> Tuple[str, str]:
    """Return the (username, password) for mock device connections."""
    return _creds


def lookup(host: str) -> Optional[dict]:
    """
    Resolve a host/IP to a mock device entry.

    Tries multiple strategies before giving up:
      1. Exact match on host as-is (covers plain IPs — most common)
      2. DNS resolution → IP lookup (covers hostnames)
      3. FQDN strip → hostname match (e.g. tor101.site1.company.com → tor101.site1)
      4. Reverse scan: find any entry whose 'hostname' field matches

    Args:
        host: IP address or hostname to look up.

    Returns:
        {"hostname": "...", "port": N, "source": "..."} or None.
    """
    if not _enabled:
        return None

    # Never redirect localhost — that's where mock devices already live
    if host == "127.0.0.1" or host.startswith("127."):
        return None

    if not _lookup:
        _auto_load()

    if not _lookup:
        return None

    # ── Strategy 1: exact match (plain IP, most common) ──────────────
    result = _lookup.get(host)
    if result:
        logger.info(
            f"[EMULATION] HIT  {host!r} → {result['hostname']}:{result['port']}  (exact)"
        )
        return result

    # ── Strategy 2: DNS resolve → IP lookup ──────────────────────────
    import socket
    try:
        resolved_ip = socket.gethostbyname(host)
        if resolved_ip != host:
            logger.debug(f"[EMULATION] DNS  {host!r} → {resolved_ip}")
            result = _lookup.get(resolved_ip)
            if result:
                logger.info(
                    f"[EMULATION] HIT  {host!r} → {result['hostname']}:{result['port']}  "
                    f"(dns→{resolved_ip})"
                )
                return result
    except Exception:
        pass

    # ── Strategy 3: strip FQDN suffixes → hostname match ─────────────
    host_lower = host.lower()
    parts = host_lower.split(".")
    for i in range(1, len(parts)):
        candidate = ".".join(parts[: i + 1])
        for _ip, entry in _lookup.items():
            if entry.get("hostname", "").lower() == candidate:
                logger.info(
                    f"[EMULATION] HIT  {host!r} → {entry['hostname']}:{entry['port']}  "
                    f"(fqdn-strip→{candidate})"
                )
                return entry

    # ── Strategy 4: reverse scan on hostname field ────────────────────
    for _ip, entry in _lookup.items():
        if entry.get("hostname", "").lower() == host_lower:
            logger.info(
                f"[EMULATION] HIT  {host!r} → {entry['hostname']}:{entry['port']}  "
                f"(hostname-match on {_ip})"
            )
            return entry

    logger.info(
        f"[EMULATION] MISS {host!r}  (tried exact, dns, fqdn-strip, reverse-scan)"
    )
    return None


def find_ip_for_hostname(hostname: str) -> Optional[str]:
    """
    Reverse-lookup: find the IP key in the lookup table for a given hostname.

    Useful when a neighbor advertises a hostname but no routable IP — the
    caller can recover the emulation-routable address.

    Args:
        hostname: Mock device hostname to find.

    Returns:
        The IP address key from ip_lookup.json, or None.
    """
    hostname_lower = hostname.lower()
    for ip, entry in _lookup.items():
        if entry.get("hostname", "").lower() == hostname_lower:
            return ip
    return None


def get_lookup_table() -> Dict[str, dict]:
    """
    Return a read-only reference to the current lookup table.

    Callers should not modify the returned dict.
    """
    return _lookup


# ═══════════════════════════════════════════════════════════════════════════
# DNS intercept — patches socket.getaddrinfo so hostname resolution
# returns 127.0.0.1 for mock devices instead of failing with NXDOMAIN.
# ═══════════════════════════════════════════════════════════════════════════

def _install_dns_intercept() -> None:
    """
    Monkey-patch socket.getaddrinfo for mock device hostname resolution.

    Only intercepts hostnames that resolve via lookup() — all other DNS
    queries pass through to the real resolver unchanged.
    """
    import socket as _socket

    global _dns_intercept_installed, _original_getaddrinfo

    if _dns_intercept_installed:
        return

    _original_getaddrinfo = _socket.getaddrinfo

    def _patched_getaddrinfo(host, port, *args, **kwargs):
        if _enabled and isinstance(host, str):
            emu = lookup(host)
            if emu:
                real_ip = find_ip_for_hostname(emu["hostname"])
                if real_ip:
                    logger.info(
                        f"[EMULATION] DNS intercept: {host!r} → {real_ip}  "
                        f"(mock: {emu['hostname']}:{emu['port']})"
                    )
                    return [
                        (_socket.AF_INET, _socket.SOCK_STREAM, 6, "",
                         (real_ip, port or 22))
                    ]
        return _original_getaddrinfo(host, port, *args, **kwargs)

    _socket.getaddrinfo = _patched_getaddrinfo
    _dns_intercept_installed = True
    logger.info("[EMULATION] DNS intercept installed — hostname resolution patched")


def _uninstall_dns_intercept() -> None:
    """Restore original socket.getaddrinfo."""
    import socket as _socket

    global _dns_intercept_installed, _original_getaddrinfo
    if _original_getaddrinfo:
        _socket.getaddrinfo = _original_getaddrinfo
        _original_getaddrinfo = None
    _dns_intercept_installed = False
    logger.info("[EMULATION] DNS intercept removed")


def _auto_load() -> None:
    """Auto-load emulation lookup if enabled but table is empty."""
    global _lookup
    if _enabled and not _lookup:
        for p in _DEFAULT_SEARCH_PATHS:
            if p.exists():
                _lookup = json.loads(p.read_text())
                logger.info(
                    f"[EMULATION] Auto-loaded {len(_lookup)} IPs from {p}"
                )
                return
        logger.warning("[EMULATION] Enabled but no lookup file found")
