"""
sc2/scng/discovery/engine.py

SecureCartography NG - Concurrent Discovery Engine.

High-level discovery orchestration with vault integration.
Combines SNMP collectors with credential management from scng.creds.

Features:
- Single device discovery
- Recursive crawl with depth limits
- SNMP-first with SSH fallback
- CONCURRENT discovery within each depth level (configurable parallelism)
- Credential preference caching by subnet
- Atomic deduplication to prevent duplicate discovery
- Structured event emission for GUI integration
- Cancellation support
- Async file I/O for non-blocking output
"""

import asyncio
import ipaddress
import re
import socket
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Callable, Any, Set, Union, Tuple
import json

# Async file I/O - optional, falls back to executor if not available
try:
    import aiofiles
    HAS_AIOFILES = True
except ImportError:
    HAS_AIOFILES = False

# Try new pysnmp first, fall back to older v3arch path
try:
    from pysnmp.hlapi.asyncio import (
        SnmpEngine, CommunityData, UsmUserData,
        usmHMACMD5AuthProtocol, usmHMACSHAAuthProtocol,
        usmHMAC128SHA224AuthProtocol, usmHMAC192SHA256AuthProtocol,
        usmHMAC256SHA384AuthProtocol, usmHMAC384SHA512AuthProtocol,
        usmDESPrivProtocol, usmAesCfb128Protocol,
        usmAesCfb192Protocol, usmAesCfb256Protocol,
        usmNoAuthProtocol, usmNoPrivProtocol,
    )
except ImportError:
    from pysnmp.hlapi.v3arch.asyncio import (
        SnmpEngine, CommunityData, UsmUserData,
        usmHMACMD5AuthProtocol, usmHMACSHAAuthProtocol,
        usmHMAC128SHA224AuthProtocol, usmHMAC192SHA256AuthProtocol,
        usmHMAC256SHA384AuthProtocol, usmHMAC384SHA512AuthProtocol,
        usmDESPrivProtocol, usmAesCfb128Protocol,
        usmAesCfb192Protocol, usmAesCfb256Protocol,
        usmNoAuthProtocol, usmNoPrivProtocol,
    )

from .models import (
    Device, Interface, Neighbor, DiscoveryResult,
    DeviceVendor, DiscoveryProtocol, NeighborProtocol,
)
from .snmp import (
    SNMPWalker,
    get_system_info,
    get_interface_table,
    get_cdp_neighbors,
    get_lldp_neighbors,
    get_arp_table,
    get_entity_info,
    lookup_ip_by_mac,
    get_sys_name,
    should_exclude,
    detect_vendor,
    extract_hostname,
    build_fqdn,
    is_ip_address,
)

# Import SSH collector
from .ssh import SSHCollector

# Import event system
from .events import (
    EventEmitter, EventCallback, EventType, LogLevel,
    ConsoleEventPrinter, DiscoveryEvent,
)

# Emulation mode flag — set by ssh.client when enable_emulation() is called.
# When active, skip real OS-level DNS so the SSH client can handle hostname
# resolution via ip_lookup.json instead.
from .ssh import client as _ssh_client_module

# Import from scng.creds for vault integration
# Try multiple import paths to handle different package structures
HAS_VAULT = False
try:
    from scng.creds import (
        CredentialVault,
        CredentialType,
        SSHCredential,
        SNMPv2cCredential,
        SNMPv3Credential,
        SNMPv3AuthProtocol,
        SNMPv3PrivProtocol,
    )
    HAS_VAULT = True
except ImportError:
    pass

if not HAS_VAULT:
    try:
        from sc2.scng.creds import (
            CredentialVault,
            CredentialType,
            SSHCredential,
            SNMPv2cCredential,
            SNMPv3Credential,
            SNMPv3AuthProtocol,
            SNMPv3PrivProtocol,
        )
        HAS_VAULT = True
    except ImportError:
        pass

if not HAS_VAULT:
    # Try relative import as last resort
    try:
        from ..creds import (
            CredentialVault,
            CredentialType,
            SSHCredential,
            SNMPv2cCredential,
            SNMPv3Credential,
            SNMPv3AuthProtocol,
            SNMPv3PrivProtocol,
        )
        HAS_VAULT = True
    except ImportError:
        pass


# Legacy type alias for backward compatibility
ProgressCallback = Callable[[str, int, int], None]  # (message, current, total)

# MAC address patterns to filter out
MAC_PATTERN = re.compile(r'^([0-9a-fA-F]{2}[:\-.]?){5}[0-9a-fA-F]{2}$|^([0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4}$')


def is_mac_address(value: str) -> bool:
    """Check if string looks like a MAC address."""
    if not value:
        return False
    # Cisco format: 00cc.344b.b47e
    # Standard formats: 00:cc:34:4b:b4:7e or 00-cc-34-4b-b4-7e
    return bool(MAC_PATTERN.match(value))


def extract_platform(sys_descr: str, vendor: str = None) -> str:
    """
    Extract a concise platform string from sysDescr or show version output.

    Handles both SNMP sysDescr (single-line) and SSH show version (multi-line).

    Examples:
        SNMP: "Arista Networks EOS version 4.33.1F running on an Arista vEOS-lab"
        -> "Arista vEOS-lab EOS 4.33.1F"

        SNMP: "Cisco IOS Software, IOSv Software (VIOS-ADVENTERPRISEK9-M), Version 15.6(2)T..."
        -> "Cisco IOSv IOS 15.6(2)T"

        SSH: "Cisco Nexus Operating System (NX-OS) Software\\n...\\nNXOS: version 9.3(11)\\n..."
        -> "Cisco NX-OS 9.3(11)"
    """
    if not sys_descr:
        return vendor or "Unknown"

    # === Arista ===
    if 'Arista' in sys_descr:
        model = "Arista"
        version = ""
        if 'vEOS-lab' in sys_descr:
            model = "Arista vEOS-lab"
        elif 'vEOS' in sys_descr:
            model = "Arista vEOS"
        else:
            # Try to extract hardware model from show version
            hw_match = re.search(r'Arista\s+(DCS-\S+|[A-Z]+-\S+)', sys_descr)
            if hw_match:
                model = f"Arista {hw_match.group(1)}"
        eos_match = re.search(r'(?:EOS version|Software image version:?)\s*[:\s]*(\S+)', sys_descr)
        if eos_match:
            version = f"EOS {eos_match.group(1)}"
        return f"{model} {version}".strip()

    # === Cisco NX-OS (check before generic Cisco) ===
    if 'NX-OS' in sys_descr or 'Nexus' in sys_descr:
        model = "Cisco NX-OS"
        # Extract hardware model: "cisco Nexus9000 C9396PX" or "Nexus 9396PX"
        hw_match = re.search(r'[Cc]isco\s+(Nexus\S+\s+\S+)', sys_descr)
        if hw_match:
            model = f"Cisco {hw_match.group(1)}"
        else:
            hw_match = re.search(r'(Nexus\s*\S+)', sys_descr)
            if hw_match:
                model = f"Cisco {hw_match.group(1)}"
        # Extract version: "NXOS: version 9.3(11)" or "system:  version 9.3(11)"
        ver_match = re.search(r'(?:NXOS|system|NXOS image file).*?version\s+(\S+)', sys_descr, re.IGNORECASE)
        if not ver_match:
            ver_match = re.search(r'NX-OS.*?Version\s+(\S+)', sys_descr)
        if ver_match:
            return f"{model} {ver_match.group(1)}"
        return model

    # === Cisco IOS / IOS-XE ===
    if 'Cisco IOS' in sys_descr or ('Cisco' in sys_descr and 'IOS' in sys_descr):
        model = "Cisco"
        if 'IOS-XE' in sys_descr or 'IOS XE' in sys_descr or 'IOSXE' in sys_descr:
            model = "Cisco IOS-XE"
        elif 'IOSv' in sys_descr or 'VIOS' in sys_descr:
            model = "Cisco IOSv"
        elif 'vios_l2' in sys_descr:
            model = "Cisco IOS"

        # Try multiple version formats
        # SNMP: "Version 15.6(2)T,"
        ver_match = re.search(r'Version\s+(\S+?)[,\s]', sys_descr)
        if ver_match:
            return f"{model} {ver_match.group(1)}"
        return model

    # === Cisco generic (WLC, other) ===
    if 'Cisco' in sys_descr:
        model = "Cisco"
        # Check for specific platforms
        if '7200' in sys_descr:
            model = "Cisco 7200"
        elif '7206VXR' in sys_descr:
            model = "Cisco 7206VXR"
        elif 'WLC' in sys_descr or 'Wireless' in sys_descr:
            model = "Cisco WLC"
        elif 'ASA' in sys_descr:
            model = "Cisco ASA"
        ver_match = re.search(r'Version\s+(\S+?)[,\s]', sys_descr)
        if ver_match:
            return f"{model} {ver_match.group(1)}"
        return model

    # === Juniper ===
    if 'Juniper' in sys_descr or 'JUNOS' in sys_descr or 'junos' in sys_descr.lower():
        model = "Juniper"
        # SNMP: "Juniper Networks, Inc. qfx5100-48s..."
        hw_match = re.search(r'Juniper\s+Networks.*?((?:qfx|ex|mx|srx|ptx)\S+)', sys_descr, re.IGNORECASE)
        if hw_match:
            model = f"Juniper {hw_match.group(1).upper()}"
        ver_match = re.search(r'JUNOS\s+(\S+)', sys_descr, re.IGNORECASE)
        if ver_match:
            return f"{model} JUNOS {ver_match.group(1)}"
        return model

    # === Aruba / HP ProCurve (SSH show version) ===
    if 'Aruba' in sys_descr or 'ProCurve' in sys_descr or 'ArubaOS' in sys_descr:
        model = "Aruba"
        hw_match = re.search(r'Aruba\s+(JL\S+\s+\S+|[A-Z0-9]+-\S+)', sys_descr)
        if hw_match:
            model = f"Aruba {hw_match.group(1)}"
        ver_match = re.search(r'(?:Software revision|revision)\s*[:\s]*(\S+)', sys_descr, re.IGNORECASE)
        if ver_match:
            return f"{model} {ver_match.group(1)}"
        return model

    # === Palo Alto ===
    if 'Palo Alto' in sys_descr or 'PAN-OS' in sys_descr:
        model = "Palo Alto"
        ver_match = re.search(r'PAN-OS\s+(\S+)', sys_descr)
        if ver_match:
            return f"{model} PAN-OS {ver_match.group(1)}"
        ver_match = re.search(r'sw-version:\s*(\S+)', sys_descr)
        if ver_match:
            return f"{model} {ver_match.group(1)}"
        return model

    # === CloudGenix / Prisma SD-WAN ===
    if 'CloudGenix' in sys_descr or 'ION' in sys_descr:
        model = "CloudGenix ION"
        ver_match = re.search(r'(?:version|Version)\s+(\S+)', sys_descr)
        if ver_match:
            return f"{model} {ver_match.group(1)}"
        return model

    # === Vendor fallback: use vendor string if patterns didn't match ===
    if vendor and vendor.lower() != 'unknown':
        return vendor.capitalize()

    # Default: first line, max 50 chars
    first_line = sys_descr.split('\n')[0].strip()
    return first_line[:50] if first_line else "Unknown"


def extract_os_version(sys_descr: str, vendor: str = None) -> Optional[str]:
    """
    Extract just the OS version string from sysDescr or show version output.

    ENTITY-MIB entPhysicalSoftwareRev is the preferred source, but plenty of
    agents leave that column empty on the chassis row even when they populate
    model and serial. sysDescr almost always carries the version somewhere, so
    this is the fallback that keeps Device.os_version consistently populated.

    Distinct from extract_platform(), which returns a combined
    model-plus-version display string. This returns the bare version only.

    Examples:
        "... IOSv Software (VIOS-...), Version 15.6(2)T, RELEASE..." -> "15.6(2)T"
        "Arista Networks EOS version 4.33.1F running on ..."         -> "4.33.1F"
        "... kernel JUNOS 18.4R2-S3, Build date: ..."                -> "18.4R2-S3"
    """
    if not sys_descr:
        return None

    # Ordered most specific first - a generic "Version x" pattern would
    # otherwise win on platforms whose version lives in a distinct field.
    patterns = [
        r'EOS\s+version\s+(\S+)',                     # Arista
        r'Software\s+image\s+version:\s*(\S+)',       # Arista show version
        r'JUNOS\s+(\S+)',                             # Juniper
        r'PAN-OS\s+(\S+)',                            # Palo Alto
        r'sw-version:\s*(\S+)',                       # Palo Alto show system
        r'FortiOS\s+v?(\S+)',                         # Fortinet
        r'(?:NXOS|system):\s*version\s+(\S+)',        # Cisco NX-OS
        r'NX-OS.*?[Vv]ersion\s+(\S+)',                # Cisco NX-OS (sysDescr)
        r'[Vv]ersion\s+(\S+)',                        # Cisco IOS / IOS-XE / generic
        # The SSH path composes sys_descr as "<Vendor> <Platform> <Version>"
        # with no 'version' keyword at all, so the patterns above all miss.
        # Match an OS family name followed directly by its version, and as a
        # last resort a trailing version-looking token.
        r'\b(?:EOS|IOS-XE|IOS|NX-OS|JUNOS|PAN-OS|FortiOS|VRP)\s+v?(\d\S*)',
        r'(?:^|\s)v?(\d+(?:\.\d+)+[\w().\-]*)\s*$',
    ]

    for pattern in patterns:
        match = re.search(pattern, sys_descr)
        if match:
            version = match.group(1)
            # sysDescr is prose, so the captured token often carries the
            # sentence punctuation that followed it.
            version = version.strip().rstrip(',;.')
            # The generic trailing pattern will otherwise happily match prose
            # like "no version string". A real version starts with a digit,
            # optionally prefixed by 'v'.
            if version and re.match(r'^v?\d', version):
                return version

    return None


class DiscoveryEngine:
    """
    Concurrent network discovery engine with vault integration.

    Combines SNMP-based discovery with credential management
    from scng.creds vault. Falls back to SSH when SNMP fails.

    Features:
    - Parallel discovery within each depth level (breadth-first)
    - Credential preference caching by /24 subnet
    - Atomic deduplication prevents double-discovery
    - Configurable concurrency limits
    - Structured event emission for GUI integration

    Usage:
        from scng.creds import CredentialVault
        from scng.discovery import DiscoveryEngine

        vault = CredentialVault()
        vault.unlock("password")

        engine = DiscoveryEngine(vault, max_concurrent=20)

        # Subscribe to events (for GUI)
        engine.events.subscribe(my_gui_handler)

        # Or use console printer for CLI
        printer = ConsoleEventPrinter(verbose=True)
        engine.events.subscribe(printer.handle_event)

        # Single device
        device = await engine.discover_device("192.168.1.1")

        # Recursive crawl (concurrent within each depth)
        result = await engine.crawl(
            seeds=["192.168.1.1"],
            max_depth=3,
            domains=["example.com"],
        )
    """

    def __init__(
        self,
        vault: Optional['CredentialVault'] = None,
        snmp_engine: Optional[SnmpEngine] = None,
        default_timeout: float = 5.0,
        verbose: bool = False,
        no_dns: bool = False,
        max_concurrent: int = 20,
        event_emitter: Optional[EventEmitter] = None,
        hosts_file: Optional[Path] = None,
        jump_config: Optional[Path] = None,
        device_deadline: float = 300.0,
    ):
        """
        Initialize discovery engine.

        Args:
            vault: Unlocked CredentialVault for credential retrieval
            snmp_engine: Shared pysnmp engine (created if not provided)
            default_timeout: Default SNMP timeout in seconds
            verbose: Enable debug output
            no_dns: Disable DNS lookups (targets must be IPs)
            max_concurrent: Maximum concurrent device discoveries (default 20)
            event_emitter: Event emitter for GUI integration (created if not provided)
            jump_config: Path to a jump-host YAML config. When set (or when the
                        default ~/.seccart2/jump_hosts.yaml exists), SSH collection
                        routes through the matching bastion. Note this reaches
                        SSH only - SNMP is UDP and does not tunnel - so
                        bastion-reached devices return thin records.
            hosts_file: Path to hosts-format file for name→IP resolution.
                        Checked before DNS when resolving neighbor hostnames.
                        Format: IP  shortname  FQDN  # optional comment
        """
        self.vault = vault
        self.snmp_engine = snmp_engine or SnmpEngine()
        self.default_timeout = default_timeout
        self.verbose = verbose
        self.no_dns = no_dns
        self.max_concurrent = max_concurrent
        # Absolute cap on one device's whole discovery (all credentials, SNMP
        # walks, SSH collection, DNS-fallback retries). A catch-all so no
        # single device can stall a depth; <= 0 disables it.
        self.device_deadline = float(device_deadline or 0)

        # Jump-host routing. Built once here rather than per device so the
        # config is validated (and a bad jump name fails) at startup, and so
        # bastion credentials are resolved once and cached by the resolver.
        self.proxy_resolver = None
        try:
            from .jump import build_jump_resolver, DEFAULT_JUMP_CONFIG
            if jump_config or DEFAULT_JUMP_CONFIG.exists():
                self.proxy_resolver = build_jump_resolver(vault, jump_config)
                if self.proxy_resolver is not None:
                    self._vprint(
                        f"Jump-host routing loaded from "
                        f"{jump_config or DEFAULT_JUMP_CONFIG} "
                        f"(SSH only - SNMP does not tunnel)", 0
                    )
        except Exception as e:
            # Surface loudly - silently ignoring jump config would mean every
            # bastion-only device fails with an unexplained timeout.
            raise ValueError(f"Jump-host configuration error: {e}") from e

        # Local hosts file: hostname → IP (checked before DNS)
        self._hosts_map: Dict[str, str] = {}
        if hosts_file:
            self._hosts_map = self._load_hosts_file(hosts_file)

        # Event system
        self.events = event_emitter or EventEmitter()

        # Concurrency primitives
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._executor = ThreadPoolExecutor(max_workers=max_concurrent * 2)

        # Deduplication: normalized identifiers we've claimed or processed
        # In asyncio single-thread model, no lock needed between awaits
        self._claimed: Set[str] = set()

        # Track discovered sysNames separately — _claimed includes queued
        # targets that haven't been discovered yet, so we can't use it
        # to detect duplicate discoveries from concurrent batches.
        self._discovered_sysnames: Set[str] = set()

        # Credential preference cache: /24 subnet -> (cred_name, protocol)
        # When a credential works for an IP, remember it for the subnet
        self._subnet_preferences: Dict[str, Tuple[str, str]] = {}
        self._ssh_blocked: Dict[str, str] = {}  # target -> why SSH cannot work (2FA, unreachable)

        # Legacy cache for backward compatibility (IP -> full credential result)
        self._credential_cache: Dict[str, tuple] = {}

    def _vprint(self, msg: str, level: int = 1):
        """Print verbose message if enabled."""
        if self.verbose:
            indent = "  " * level
            print(f"{indent}[discovery] {msg}")

    def _log(self, message: str, level: LogLevel = LogLevel.INFO, device: str = ""):
        """Emit log message event."""
        self.events.log(message, level, device)
        if self.verbose or level in (LogLevel.WARNING, LogLevel.ERROR):
            self._vprint(message, 1)

    # =========================================================================
    # Exclusion
    # =========================================================================

    @staticmethod
    def _expand_patterns(exclude_patterns: List[str]) -> List[str]:
        """Split comma-separated entries into individual lowercase substrings."""
        out: List[str] = []
        for p in exclude_patterns or []:
            out.extend(part.strip().lower() for part in p.split(',') if part.strip())
        return out

    def _neighbor_exclusion(self, neighbor, name: Optional[str], patterns: List[str]) -> str:
        """
        Pre-dial exclusion: match a CDP/LLDP neighbor entry before dialing it.

        Checks the advertised name, platform and system description. Returns
        the matching pattern, or "" to dial. Neighbors that advertise nothing
        useful fall through to the post-dial sysDescr check.
        """
        if not patterns:
            return ""
        fields = [
            (name or neighbor.remote_device or "").lower(),
            (neighbor.remote_platform or "").lower(),
            (neighbor.remote_description or "").lower(),
        ]
        for pattern in patterns:
            if any(pattern in f for f in fields if f):
                return pattern
        return ""

    def _should_exclude_device(self, device: Device, exclude_patterns: List[str]) -> Tuple[bool, str]:
        """
        Check if device should be excluded from crawl propagation.

        Matches against multiple device identifiers:
        - sys_descr (SNMP)
        - hostname
        - sys_name

        Supports comma-separated patterns: "linux,rtr,use-"

        Args:
            device: Discovered device to check
            exclude_patterns: List of patterns (may contain comma-separated values)

        Returns:
            (should_exclude, matching_pattern)
        """
        if not exclude_patterns:
            return False, ""

        # Expand comma-separated patterns
        expanded_patterns = []
        for p in exclude_patterns:
            expanded_patterns.extend(part.strip() for part in p.split(',') if part.strip())

        # Fields to check (lowercased)
        check_fields = [
            (device.sys_descr or "").lower(),
            (device.hostname or "").lower(),
            (device.sys_name or "").lower(),
            # SSH-only devices may have no sys_descr at all; the vendor the
            # SSH collector detected (e.g. "linux" from uname) still counts.
            (device.vendor.value if device.vendor else "").lower(),
        ]

        for pattern in expanded_patterns:
            pattern_lower = pattern.lower()
            for field in check_fields:
                if field and pattern_lower in field:
                    return True, pattern

        return False, ""

    # =========================================================================
    # Deduplication
    # =========================================================================

    def _normalize_identifier(self, identifier: str) -> str:
        """
        Normalize an identifier for deduplication.

        - Lowercase
        - Strip trailing dots (FQDN normalization)
        - For hostnames, also store the short name
        """
        if not identifier:
            return ""
        return identifier.lower().rstrip('.')

    def _try_claim(self, target: str) -> bool:
        """
        Atomically claim a target for discovery.

        Returns True if we got it, False if already claimed.
        Thread-safe in asyncio single-thread model (no lock needed).
        """
        normalized = self._normalize_identifier(target)
        if not normalized:
            return False
        if normalized in self._claimed:
            return False
        self._claimed.add(normalized)
        return True

    def _register_device(self, device: Device) -> None:
        """
        Register all known identifiers for a discovered device.

        Called after discovery completes to prevent rediscovery
        via alternate identifiers (IP vs hostname vs sysName).
        """
        identifiers = [
            device.ip_address,
            device.hostname,
            device.sys_name,
            device.fqdn,
        ]
        for ident in identifiers:
            if ident:
                self._claimed.add(self._normalize_identifier(ident))

    def _is_claimed(self, target: str) -> bool:
        """Check if a target has been claimed."""
        return self._normalize_identifier(target) in self._claimed

    def reset_state(self) -> None:
        """Reset discovery state for a new crawl."""
        self._claimed.clear()
        self._discovered_sysnames.clear()
        self._subnet_preferences.clear()
        self._credential_cache.clear()
        # Per-crawl bookkeeping for live preview and the not-dialed roll-up
        self._target_names: Dict[str, str] = {}      # crawl target -> display name
        self._node_status: Dict[str, str] = {}       # name -> failed | not_dialed
        self._not_dialed: Dict[str, Tuple[str, str]] = {}  # key -> (reason, from)
        self._excluded_by_pattern: Dict[str, int] = {}
        self._dns_fallback_hits = 0
        self._ssh_blocked.clear()
        self.events.reset_stats()

    # =========================================================================
    # Hosts File Resolution
    # =========================================================================

    def _load_hosts_file(self, hosts_path: Path) -> Dict[str, str]:
        """
        Load a hosts-format file into a hostname → IP lookup dict.

        Parses lines of the form:
            IP_ADDRESS   shortname   FQDN   # optional comment

        Indexes on every non-IP column (lowercased), so both short names
        and FQDNs resolve.  Skips blank lines and comment-only lines.
        """
        hosts: Dict[str, str] = {}

        if not hosts_path.exists():
            self._vprint(f"Hosts file not found: {hosts_path}", 1)
            return hosts

        try:
            with open(hosts_path) as f:
                for line in f:
                    line = line.split('#')[0].strip()
                    if not line:
                        continue

                    parts = line.split()
                    if len(parts) < 2:
                        continue

                    ip = parts[0]
                    if not is_ip_address(ip):
                        continue

                    for name in parts[1:]:
                        name_lower = name.lower().rstrip('.')
                        if name_lower and not is_ip_address(name_lower):
                            hosts[name_lower] = ip

            self._vprint(
                f"Loaded hosts file: {hosts_path} "
                f"({len(hosts)} name→IP entries)", 1
            )
        except Exception as e:
            self._vprint(f"Failed to load hosts file: {e}", 1)

        return hosts

    def _resolve_from_hosts(self, name: str) -> Optional[str]:
        """
        Look up a hostname in the local hosts file.

        Returns the IP address or None if not found.
        """
        if not self._hosts_map or not name:
            return None

        lookup = name.lower().rstrip('.')

        if lookup in self._hosts_map:
            return self._hosts_map[lookup]

        return None

    # =========================================================================
    # sysName Resolution (for MAC-named LLDP neighbors)
    # =========================================================================

    async def _resolve_sysname(self, ip: str) -> Optional[str]:
        """
        Quick SNMP sysName probe on a neighbor IP.

        Used when LLDP reports a MAC as the device name but gives us
        a management IP. Single SNMP GET with short timeout — if it
        fails, caller falls back to IP-based queuing.
        """
        try:
            from .snmp.collectors.system import get_sys_name

            # Use first available credential
            auth = None
            if self.vault and HAS_VAULT:
                creds = self.vault.get_credentials(CredentialType.SNMPV2C)
                if creds:
                    auth = self._build_auth(creds[0])

            # Check subnet preference cache for a known-good credential
            subnet = self._get_subnet(ip)
            if subnet in self._subnet_preferences:
                cached_name, cached_auth = self._subnet_preferences[subnet]
                if cached_auth:
                    auth = cached_auth

            if not auth:
                return None

            walker = SNMPWalker(
                engine=self.snmp_engine,
                auth=auth,
                default_timeout=3.0,
                verbose=self.verbose,
            )

            name = await get_sys_name(ip, auth, walker, timeout=3.0)
            if name:
                return name.strip().rstrip('.')
        except Exception:
            pass
        return None

    # =========================================================================
    # Credential Management
    # =========================================================================

    def _get_subnet(self, ip: str) -> str:
        """Extract /24 subnet from IP address."""
        if not ip or not is_ip_address(ip):
            return ""
        parts = ip.split('.')
        if len(parts) == 4:
            return '.'.join(parts[:3])
        return ip

    def _build_auth(self, credential) -> Optional[Any]:
        """
        Build pysnmp auth data from vault credential.

        Returns CommunityData for SNMPv2c or UsmUserData for SNMPv3.
        """
        if not HAS_VAULT:
            return None

        if isinstance(credential, SNMPv2cCredential):
            return CommunityData(credential.community, mpModel=1)

        elif isinstance(credential, SNMPv3Credential):
            # Map auth protocols
            auth_map = {
                SNMPv3AuthProtocol.NONE: usmNoAuthProtocol,
                SNMPv3AuthProtocol.MD5: usmHMACMD5AuthProtocol,
                SNMPv3AuthProtocol.SHA: usmHMACSHAAuthProtocol,
                SNMPv3AuthProtocol.SHA224: usmHMAC128SHA224AuthProtocol,
                SNMPv3AuthProtocol.SHA256: usmHMAC192SHA256AuthProtocol,
                SNMPv3AuthProtocol.SHA384: usmHMAC256SHA384AuthProtocol,
                SNMPv3AuthProtocol.SHA512: usmHMAC384SHA512AuthProtocol,
            }

            # Map priv protocols
            priv_map = {
                SNMPv3PrivProtocol.NONE: usmNoPrivProtocol,
                SNMPv3PrivProtocol.DES: usmDESPrivProtocol,
                SNMPv3PrivProtocol.AES: usmAesCfb128Protocol,
                SNMPv3PrivProtocol.AES192: usmAesCfb192Protocol,
                SNMPv3PrivProtocol.AES256: usmAesCfb256Protocol,
            }

            usm_kwargs = {}

            if credential.auth_protocol != SNMPv3AuthProtocol.NONE:
                usm_kwargs['authKey'] = credential.auth_password
                usm_kwargs['authProtocol'] = auth_map.get(
                    credential.auth_protocol, usmNoAuthProtocol
                )

            if credential.priv_protocol != SNMPv3PrivProtocol.NONE:
                usm_kwargs['privKey'] = credential.priv_password
                usm_kwargs['privProtocol'] = priv_map.get(
                    credential.priv_protocol, usmNoPrivProtocol
                )

            return UsmUserData(credential.username, **usm_kwargs)

        return None

    def _test_ssh_credential_sync(self, target: str, cred, jump=None) -> bool:
        """
        Synchronous SSH credential test for use in executor.

        Args:
            target: IP address or hostname
            cred: SSHCredential from vault

        Returns:
            True if connection successful
        """
        from .ssh.client import SSHClient, SSHClientConfig

        config = SSHClientConfig(
            host=target,
            username=cred.username,
            password=cred.password,
            key_content=cred.key_content,
            key_passphrase=cred.key_passphrase,
            timeout=min(cred.timeout_seconds, 10),  # Cap at 10s for testing
            jump=jump,  # same route the real collection will take
        )

        try:
            with SSHClient(config) as client:
                client.find_prompt()
                return True
        except Exception as e:
            from ..reachssh import SecondFactorRequired, TargetUnreachable
            if isinstance(e, (SecondFactorRequired, TargetUnreachable)):
                # Not a credential problem: other credentials would hit the
                # same prompt or the same unreachable path.
                self._ssh_blocked[target] = str(e)
                self._vprint(f"{target}: {e}", 1)
            return False

    async def _test_ssh_credential(self, target: str, cred, jump=None) -> bool:
        """
        Test if SSH credential works for target (async wrapper).

        Runs the blocking SSH test in a thread pool executor.
        """
        loop = asyncio.get_event_loop()
        try:
            return await loop.run_in_executor(
                self._executor,
                self._test_ssh_credential_sync,
                target,
                cred,
                jump,
            )
        except Exception as e:
            self._vprint(f"SSH test failed: {e}", 3)
            return False

    async def _test_snmp_credential(
        self,
        target: str,
        cred_name: str,
        auth: Any,
    ) -> bool:
        """Test if SNMP credential works for target."""
        try:
            sys_name = await asyncio.wait_for(
                get_sys_name(target, auth, self.snmp_engine, timeout=3.0),
                timeout=5.0
            )
            return bool(sys_name)
        except asyncio.TimeoutError:
            self._vprint(f"SNMP credential '{cred_name}' timed out for {target}", 3)
            return False
        except Exception as e:
            self._vprint(f"SNMP credential '{cred_name}' failed for {target}: {e}", 3)
            return False

    def _jump_for(self, name: Optional[str], ip: Optional[str]):
        """
        JumpSpec for a device per the jump-host rules, or None for direct.
        Rules match on the device name; ip is passed along for context.
        """
        if self.proxy_resolver is None:
            return None
        from .jump import device_context
        return self.proxy_resolver.resolve(device_context(hostname=name, ip=ip))

    async def _get_working_credential(
        self,
        target: str,
        credential_names: Optional[List[str]] = None,
        jump=None,
    ) -> Optional[tuple]:
        """
        Find a working credential for target.

        Tries credentials in order:
        1. Check if we have a preference for this subnet (from previous success)
        2. Try SNMP credentials
        3. Fall back to SSH credentials

        Returns:
            Tuple of (credential, credential_name, protocol) or None.
            - For SNMP: credential is CommunityData or UsmUserData
            - For SSH: credential is SSHCredential
            - protocol is 'snmp' or 'ssh'
        """
        # Check legacy cache first (exact IP match)
        if target in self._credential_cache:
            return self._credential_cache[target]

        if not self.vault:
            return None

        # Check subnet preference
        subnet = self._get_subnet(target)
        if subnet in self._subnet_preferences and not (
            jump and self._subnet_preferences[subnet][1] == 'snmp'
        ):
            pref_name, pref_proto = self._subnet_preferences[subnet]
            self._vprint(f"Using subnet preference: {pref_name} ({pref_proto})", 3)

            # Get the preferred credential
            info = self.vault.get_credential_info(name=pref_name)
            if info:
                if pref_proto == 'snmp':
                    if info.credential_type == CredentialType.SNMP_V2C:
                        cred = self.vault.get_snmpv2c_credential(name=pref_name)
                        if cred:
                            auth = self._build_auth(cred)
                            if auth:
                                result = (auth, pref_name, 'snmp')
                                self._credential_cache[target] = result
                                return result
                    elif info.credential_type == CredentialType.SNMP_V3:
                        cred = self.vault.get_snmpv3_credential(name=pref_name)
                        if cred:
                            auth = self._build_auth(cred)
                            if auth:
                                result = (auth, pref_name, 'snmp')
                                self._credential_cache[target] = result
                                return result
                elif pref_proto == 'ssh':
                    cred = self.vault.get_ssh_credential(name=pref_name)
                    if cred:
                        result = (cred, pref_name, 'ssh')
                        self._credential_cache[target] = result
                        return result

        # Get credential list
        if credential_names:
            cred_list = credential_names
        else:
            cred_list = [c.name for c in self.vault.list_credentials()]

        # Try SNMP credentials first - unless the device is behind a bastion:
        # SNMP is UDP and cannot ride the SSH channel, so every attempt would
        # just burn a timeout.
        if jump:
            self._vprint(f"{target}: routed via {jump.describe()}, skipping SNMP", 2)
        for cred_name in ([] if jump else cred_list):
            info = self.vault.get_credential_info(name=cred_name)
            if not info:
                continue

            if info.credential_type == CredentialType.SNMP_V2C:
                cred = self.vault.get_snmpv2c_credential(name=cred_name)
                if cred:
                    auth = self._build_auth(cred)
                    if auth and await self._test_snmp_credential(target, cred_name, auth):
                        self._vprint(f"SNMP credential '{cred_name}' works for {target}", 2)
                        # Save preference
                        if subnet:
                            self._subnet_preferences[subnet] = (cred_name, 'snmp')
                        result = (auth, cred_name, 'snmp')
                        self._credential_cache[target] = result
                        return result

            elif info.credential_type == CredentialType.SNMP_V3:
                cred = self.vault.get_snmpv3_credential(name=cred_name)
                if cred:
                    auth = self._build_auth(cred)
                    if auth and await self._test_snmp_credential(target, cred_name, auth):
                        self._vprint(f"SNMPv3 credential '{cred_name}' works for {target}", 2)
                        if subnet:
                            self._subnet_preferences[subnet] = (cred_name, 'snmp')
                        result = (auth, cred_name, 'snmp')
                        self._credential_cache[target] = result
                        return result

        # Fall back to SSH
        for cred_name in cred_list:
            info = self.vault.get_credential_info(name=cred_name)
            if not info or info.credential_type != CredentialType.SSH:
                continue

            if target in self._ssh_blocked:
                # Each further try would hit the second-factor prompt again
                break
            cred = self.vault.get_ssh_credential(name=cred_name)
            if cred and await self._test_ssh_credential(target, cred, jump):
                self._vprint(f"SSH credential '{cred_name}' works for {target}", 2)
                if subnet:
                    self._subnet_preferences[subnet] = (cred_name, 'ssh')
                result = (cred, cred_name, 'ssh')
                self._credential_cache[target] = result
                return result

        return None

    # =========================================================================
    # SSH Fallback Discovery
    # =========================================================================

    async def _discover_via_ssh(
        self,
        device_ip: str,
        ssh_cred,
        credential_name: str,
        hostname: str,
        depth: int,
        domains: List[str],
    ) -> Device:
        """
        Discover device via SSH when SNMP fails.

        Uses SSHCollector to execute commands and parse output.
        Limited to neighbor discovery (CDP/LLDP) without full SNMP data.
        """
        start_time = datetime.now()

        self._vprint(f"SSH fallback for {hostname} ({device_ip})", 1)

        device = Device(
            hostname=hostname,
            ip_address=device_ip,
            credential_used=credential_name,
            depth=depth,
            discovered_via=DiscoveryProtocol.SSH,
        )

        loop = asyncio.get_event_loop()

        try:
            # Create SSH collector (host is passed to collect(), not constructor)
            collector = SSHCollector(
                username=ssh_cred.username,
                password=ssh_cred.password,
                key_content=getattr(ssh_cred, 'key_content', None),
                key_passphrase=getattr(ssh_cred, 'key_passphrase', None),
                timeout=getattr(ssh_cred, 'timeout_seconds', 30),
                proxy_resolver=self.proxy_resolver,
            )

            # Collect in thread pool - pass host and debug flag
            ssh_result = await loop.run_in_executor(
                self._executor,
                lambda: collector.collect(
                    device_ip, debug=self.verbose,
                    # Jump rules match on the device NAME. When the crawl dials a
                    # neighbor by its advertised IP, use the name the neighbor
                    # entry gave us, or name globs would never match.
                    hostname_hint=(
                        hostname if not is_ip_address(hostname)
                        else getattr(self, "_target_names", {}).get(device_ip)
                    ),
                )
            )

            # ssh_result is SSHCollectorResult dataclass
            if ssh_result is not None:
                if ssh_result.jump_via:
                    self._vprint(f"Reached via jump host {ssh_result.jump_via}", 2)
                else:
                    self._vprint("Direct SSH connection (no jump host matched)", 3)

            if ssh_result and ssh_result.success:
                # Update device with SSH results
                if ssh_result.vendor:
                    device.vendor = ssh_result.vendor
                if ssh_result.hostname:
                    # Normalize hostname by stripping domain suffix
                    normalized = extract_hostname(ssh_result.hostname, domains)
                    device.hostname = normalized or ssh_result.hostname
                    device.sys_name = ssh_result.hostname  # Keep original as sys_name
                    if normalized != ssh_result.hostname:
                        device.fqdn = ssh_result.hostname

                # Build sys_descr from parsed version fields (clean platform string)
                if ssh_result.platform or ssh_result.version:
                    vendor_str = ssh_result.vendor.value.capitalize() if ssh_result.vendor else ""
                    parts = [vendor_str, ssh_result.platform or "", ssh_result.version or ""]
                    device.sys_descr = ' '.join(p for p in parts if p)
                elif ssh_result.raw_output.get('show_version'):
                    # tfsm_fire didn't extract structured fields — fall back
                    # to extract_platform() regex parsing on the raw output
                    raw_version = ssh_result.raw_output['show_version']
                    device.sys_descr = extract_platform(
                        raw_version,
                        ssh_result.vendor.value if ssh_result.vendor else None,
                    )

                # Keep os_version populated on the SSH path too - prefer the
                # structured field tfsm_fire already parsed, else recover it
                # from whatever sys_descr we just built.
                if ssh_result.version:
                    device.os_version = ssh_result.version
                elif device.sys_descr:
                    device.os_version = extract_os_version(
                        device.sys_descr,
                        ssh_result.vendor.value if ssh_result.vendor else None,
                    )

                # Process neighbors - normalize their hostnames too
                for neighbor in ssh_result.neighbors:
                    # Normalize neighbor hostname (stored in remote_device)
                    if neighbor.remote_device and domains:
                        normalized_neighbor = extract_hostname(neighbor.remote_device, domains)
                        if normalized_neighbor:
                            neighbor.remote_device = normalized_neighbor
                    device.add_neighbor(neighbor)

                device.discovery_success = True
                device.discovery_duration_ms = ssh_result.duration_ms

                self._vprint(f"SSH collected {len(ssh_result.neighbors)} neighbors", 2)
            else:
                # Collection failed or returned no data.
                # Device.discovery_success defaults to True, so it must be
                # cleared explicitly here - otherwise an auth failure is
                # counted as a successful discovery and an empty device record
                # is written into the topology map.
                device.discovery_success = False
                if ssh_result and ssh_result.errors:
                    for err in ssh_result.errors:
                        device.discovery_errors.append(err)
                else:
                    device.discovery_errors.append("SSH collection returned no data")

        except Exception as e:
            device.discovery_success = False
            device.discovery_errors.append(f"SSH discovery failed: {e}")
            self._vprint(f"SSH exception: {e}", 1)

        if device.discovery_duration_ms == 0:
            device.discovery_duration_ms = (datetime.now() - start_time).total_seconds() * 1000

        return device

    # =========================================================================
    # Hostname Resolution
    # =========================================================================

    @staticmethod
    def _name_candidates(name: str, domains: List[str]) -> List[str]:
        """
        DNS names to try for a device name, most specific first.

        The discovered name may or may not carry a domain, and the domain it
        carries may not be one of ours:
            agg1.dc2.corp.example  -> as-is, then +each suffix, then the short
            agg1.dc2               -> as-is, agg1.dc2.<suffix>, agg1.<suffix>, agg1
            agg1                   -> agg1.<suffix>..., agg1
        The bare short name goes last so the resolver's own search list gets
        a chance too.
        """
        name = (name or "").strip().rstrip(".")
        if not name or is_ip_address(name):
            return []
        domains = [d.strip().strip(".") for d in (domains or []) if d and d.strip()]
        short = name.split(".", 1)[0]
        out: List[str] = []

        def add(c: str):
            c = c.lower()
            if c and c not in out:
                out.append(c)

        if "." in name:
            add(name)
        # Append suffixes to the full name only when it looks partial
        # (host or host.site). A 3+ label name is already an FQDN, just
        # possibly in someone else's domain - its short form is tried below.
        if name.count(".") <= 1:
            for d in domains:
                if not name.lower().endswith("." + d.lower()):
                    add(f"{name}.{d}")
        for d in domains:
            add(f"{short}.{d}")
        add(short)
        return out

    def _resolve_hostname(self, hostname: str, domains: List[str]) -> Optional[str]:
        """
        Resolve hostname to an IPv4 address, trying the name variants from
        _name_candidates(). Returns the first address found, or None.
        """
        if self.no_dns:
            return None
        if is_ip_address(hostname):
            return hostname
        for candidate in self._name_candidates(hostname, domains):
            try:
                ip = socket.gethostbyname(candidate)
                self._vprint(f"Resolved {hostname} -> {candidate} -> {ip}", 3)
                return ip
            except (socket.gaierror, UnicodeError):
                continue
        return None

    async def _resolve_all(self, name: str, domains: List[str], timeout: float = 3.0) -> List[str]:
        """
        Async DNS for the fallback path: IPv4 addresses for the first name
        variant that resolves. Runs off the event loop, bounded per lookup so
        a slow resolver cannot stall a whole depth.
        """
        if self.no_dns:
            return []
        loop = asyncio.get_running_loop()
        for candidate in self._name_candidates(name, domains):
            try:
                infos = await asyncio.wait_for(
                    loop.run_in_executor(
                        None, socket.getaddrinfo, candidate, None,
                        socket.AF_INET, socket.SOCK_STREAM,
                    ),
                    timeout,
                )
            except (asyncio.TimeoutError, socket.gaierror, UnicodeError, OSError):
                continue
            ips: List[str] = []
            for info in infos:
                ip = info[4][0]
                if ip not in ips:
                    ips.append(ip)
            if ips:
                self._vprint(f"DNS fallback: {name} -> {candidate} -> {', '.join(ips)}", 2)
                return ips
        return []

    @staticmethod
    def _is_unroutable(ip: str) -> bool:
        """Addresses that can never be reached from here: dial by name instead."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return (addr.is_link_local or addr.is_loopback or
                addr.is_unspecified or addr.is_multicast)

    # =========================================================================
    # Device Discovery
    # =========================================================================

    async def discover_device(
        self,
        target: str,
        auth: Optional[Any] = None,
        credential_name: Optional[str] = None,
        domains: Optional[List[str]] = None,
        depth: int = 0,
        collect_arp: bool = True,
    ) -> Device:
        """
        Discover a single device.

        Tries SNMP first for full discovery, falls back to SSH
        for neighbor-only discovery if SNMP fails.

        Args:
            target: IP address or hostname
            auth: Pre-built auth data (CommunityData or UsmUserData)
            credential_name: Specific credential to use from vault
            domains: Domain suffixes for hostname resolution
            depth: Discovery depth (for tracking)
            collect_arp: Whether to collect ARP table (SNMP only)

        Returns:
            Device dataclass with collected information
        """
        start_time = datetime.now()
        domains = domains or []

        # Resolve hostname to IP
        if is_ip_address(target):
            device_ip = target
            hostname = target
        else:
            hostname = target
            device_ip = None

            # Try local hosts file first (avoids DNS dependency)
            hosts_ip = self._resolve_from_hosts(target)
            if hosts_ip:
                device_ip = hosts_ip
                self._vprint(f"Resolved {target} → {hosts_ip} via hosts file", 2)

            # Emulation mode: skip real DNS, let SSH client handle resolution
            if not device_ip and getattr(_ssh_client_module, 'EMULATION_ENABLED', False):
                device_ip = target

            # Fall back to DNS (name variants: as-is, +suffixes, short name)
            if not device_ip and not self.no_dns:
                device_ip = self._resolve_hostname(target, domains)

            # Bastion-routed device whose name we cannot resolve from here:
            # hand the name to the bastion, which resolves it on its side.
            if not device_ip and self._jump_for(target, None):
                device_ip = target
                self._vprint(f"{target}: not resolvable locally; bastion will resolve it", 2)

            if not device_ip:
                return Device(
                    hostname=target,
                    ip_address="",
                    discovery_success=False,
                    discovery_errors=[
                        f"Resolution failed for {target} "
                        f"(hosts file: {'miss' if not hosts_ip else 'hit'}, "
                        f"DNS: {'disabled' if self.no_dns else 'failed'})"
                    ],
                    depth=depth,
                )

        self._vprint(f"Discovering {hostname} ({device_ip})", 1)

        # Get auth if not provided
        protocol = 'snmp'  # Default assumption
        ssh_cred = None

        if not auth:
            if credential_name and self.vault:
                # Try specific credential by name
                info = self.vault.get_credential_info(name=credential_name)
                if info:
                    if info.credential_type == CredentialType.SNMP_V2C:
                        cred = self.vault.get_snmpv2c_credential(name=credential_name)
                        if cred:
                            auth = self._build_auth(cred)
                    elif info.credential_type == CredentialType.SNMP_V3:
                        cred = self.vault.get_snmpv3_credential(name=credential_name)
                        if cred:
                            auth = self._build_auth(cred)
                    elif info.credential_type == CredentialType.SSH:
                        ssh_cred = self.vault.get_ssh_credential(name=credential_name)
                        protocol = 'ssh'
            else:
                # Auto-discover working credential - through the bastion if a
                # jump rule routes this device (SNMP cannot, so it is skipped)
                name_hint = hostname if not is_ip_address(hostname) else \
                    getattr(self, "_target_names", {}).get(device_ip)
                try:
                    jump = self._jump_for(name_hint, device_ip)
                except Exception as e:
                    return Device(
                        hostname=hostname, ip_address=device_ip, depth=depth,
                        discovery_success=False,
                        discovery_errors=[f"Jump-host resolution failed: {e}"],
                    )
                result = await self._get_working_credential(device_ip, jump=jump)
                if result:
                    cred, credential_name, protocol = result
                    if protocol == 'ssh':
                        ssh_cred = cred
                    else:
                        auth = cred  # It's already the auth object for SNMP

        # Use SSH fallback if that's what worked
        if protocol == 'ssh' and ssh_cred:
            return await self._discover_via_ssh(
                device_ip, ssh_cred, credential_name, hostname, depth, domains
            )

        # No working credential found
        if not auth:
            return Device(
                hostname=hostname,
                ip_address=device_ip,
                discovery_success=False,
                discovery_errors=[
                    f"SSH: {self._ssh_blocked[device_ip]}"
                    if device_ip in self._ssh_blocked
                    else "No working SNMP or SSH credential found"
                ],
                depth=depth,
            )

        # Continue with SNMP discovery
        # Collect system info
        self._vprint("Collecting system info...", 2)
        sys_info = await get_system_info(
            device_ip, auth, self.snmp_engine,
            timeout=self.default_timeout, verbose=self.verbose
        )

        # Create device
        device = Device(
            hostname=hostname,
            ip_address=device_ip,
            sys_name=sys_info.get('sys_name'),
            sys_descr=sys_info.get('sys_descr'),
            sys_location=sys_info.get('sys_location'),
            sys_contact=sys_info.get('sys_contact'),
            sys_object_id=sys_info.get('sys_object_id'),
            uptime_ticks=sys_info.get('uptime_ticks'),
            vendor=sys_info.get('vendor', DeviceVendor.UNKNOWN),
            model=sys_info.get('model'),
            credential_used=credential_name,
            depth=depth,
            discovered_via=DiscoveryProtocol.SNMP,
        )

        # Update hostname if we got sysName and it differs
        if device.sys_name and is_ip_address(hostname):
            resolved_hostname = extract_hostname(device.sys_name, domains)
            if resolved_hostname:
                device.hostname = resolved_hostname
                device.fqdn = device.sys_name

        # The system group is the minimum viable result. If none of it came
        # back, the credential test passed but the device is not actually
        # answering - record a failure rather than emitting an empty device,
        # since discovery_success defaults to True.
        if not any((device.sys_name, device.sys_descr, device.sys_object_id)):
            device.discovery_success = False
            device.discovery_errors.append(
                "SNMP returned no system information (sysName, sysDescr, sysObjectID all empty)"
            )
            device.discovery_duration_ms = (datetime.now() - start_time).total_seconds() * 1000
            self._vprint("No system info returned - marking discovery failed", 1)
            return device

        # Collect interfaces
        self._vprint("Collecting interface table...", 2)
        try:
            interface_dict = await get_interface_table(
                device_ip, auth, self.snmp_engine,
                timeout=self.default_timeout, verbose=self.verbose
            )
            device.interfaces = list(interface_dict.values())
        except Exception as e:
            device.discovery_errors.append(f"Interface collection failed: {e}")
            interface_dict = {}

        # Collect physical inventory (ENTITY-MIB) for model and serial.
        # entPhysicalModelName is the specific chassis, so it supersedes the
        # sysObjectID-derived product-line model when both are available.
        # Non-fatal: many virtual platforms return nothing here.
        self._vprint("Collecting physical inventory...", 2)
        try:
            entity_info = await get_entity_info(
                device_ip, auth, self.snmp_engine,
                timeout=self.default_timeout, verbose=self.verbose
            )
            if entity_info.get('supported'):
                if entity_info.get('model'):
                    device.model = entity_info['model']
                if entity_info.get('serial'):
                    device.serial = entity_info['serial']
                if entity_info.get('software_rev') and not device.os_version:
                    device.os_version = entity_info['software_rev']
            else:
                self._vprint("ENTITY-MIB not supported on this device", 3)
        except Exception as e:
            device.discovery_errors.append(f"Entity collection failed: {e}")

        # entPhysicalSoftwareRev is commonly blank even on agents that populate
        # model and serial, so fall back to the version embedded in sysDescr.
        if not device.os_version and device.sys_descr:
            device.os_version = extract_os_version(
                device.sys_descr,
                device.vendor.value if device.vendor else None,
            )

        # Collect ARP table (for LLDP fallback)
        arp_table = {}
        if collect_arp:
            self._vprint("Collecting ARP table...", 2)
            try:
                arp_table = await get_arp_table(
                    device_ip, auth, self.snmp_engine,
                    timeout=self.default_timeout, verbose=self.verbose
                )
                device.arp_table = arp_table
            except Exception as e:
                device.discovery_errors.append(f"ARP collection failed: {e}")

        # Collect CDP neighbors (Cisco only)
        if device.vendor == DeviceVendor.CISCO:
            self._vprint("Collecting CDP neighbors...", 2)
            try:
                cdp_neighbors = await get_cdp_neighbors(
                    device_ip, auth, interface_dict, self.snmp_engine,
                    timeout=self.default_timeout, verbose=self.verbose
                )
                for n in cdp_neighbors:
                    # Normalize neighbor hostname (stored in remote_device)
                    if n.remote_device and domains:
                        normalized = extract_hostname(n.remote_device, domains)
                        if normalized:
                            n.remote_device = normalized
                    device.add_neighbor(n)
            except Exception as e:
                device.discovery_errors.append(f"CDP collection failed: {e}")

        # Collect LLDP neighbors (all vendors)
        self._vprint("Collecting LLDP neighbors...", 2)
        try:
            lldp_neighbors = await get_lldp_neighbors(
                device_ip, auth, interface_dict, self.snmp_engine,
                timeout=self.default_timeout * 2,  # LLDP can be slow
                verbose=self.verbose
            )

            # Try to resolve missing management addresses via ARP
            for n in lldp_neighbors:
                if not n.remote_ip and n.chassis_id and arp_table:
                    resolved_ip = lookup_ip_by_mac(n.chassis_id, arp_table)
                    if resolved_ip:
                        n.remote_ip = resolved_ip
                        self._vprint(f"Resolved {n.chassis_id} to {resolved_ip} via ARP", 3)

                # Normalize neighbor hostname (stored in remote_device)
                if n.remote_device and domains:
                    normalized = extract_hostname(n.remote_device, domains)
                    if normalized:
                        n.remote_device = normalized

                device.add_neighbor(n)

        except Exception as e:
            device.discovery_errors.append(f"LLDP collection failed: {e}")

        # Calculate duration
        device.discovery_duration_ms = (datetime.now() - start_time).total_seconds() * 1000

        self._vprint(
            f"Discovery complete: {len(device.interfaces)} interfaces, "
            f"{len(device.neighbors)} neighbors in {device.discovery_duration_ms:.0f}ms",
            1
        )

        return device

    # =========================================================================
    # Async File I/O
    # =========================================================================

    async def _write_json_file(self, filepath: Path, data: dict) -> None:
        """Write JSON data to file asynchronously."""
        content = json.dumps(data, indent=2)

        if HAS_AIOFILES:
            async with aiofiles.open(filepath, 'w') as f:
                await f.write(content)
        else:
            # Fallback to executor
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                self._executor,
                self._write_json_file_sync,
                filepath,
                content,
            )

    def _write_json_file_sync(self, filepath: Path, content: str) -> None:
        """Synchronous file write for executor fallback."""
        with open(filepath, 'w') as f:
            f.write(content)

    async def _save_device_files(
        self,
        device: Device,
        output_dir: Path,
    ) -> None:
        """Save device data to individual files asynchronously."""
        device_dir = output_dir / device.hostname
        device_dir.mkdir(parents=True, exist_ok=True)

        # Save device JSON
        device_file = device_dir / 'device.json'
        await self._write_json_file(device_file, device.to_dict())

        # Save neighbors
        if device.cdp_neighbors:
            cdp_file = device_dir / 'cdp.json'
            await self._write_json_file(
                cdp_file,
                [n.to_dict() for n in device.cdp_neighbors]
            )

        if device.lldp_neighbors:
            lldp_file = device_dir / 'lldp.json'
            await self._write_json_file(
                lldp_file,
                [n.to_dict() for n in device.lldp_neighbors]
            )

    # =========================================================================
    # Crawl
    # =========================================================================

    async def _discover_with_semaphore(
        self,
        target: str,
        depth: int,
        domains: List[str],
    ) -> Device:
        """
        Rate-limited device discovery.

        Acquires semaphore before discovery to limit concurrency.
        """
        # Emit device started event
        self.events.device_started(target, depth)

        async with self._semaphore:
            if self.device_deadline <= 0:
                return await self._discover_target(target, depth, domains)
            try:
                return await asyncio.wait_for(
                    self._discover_target(target, depth, domains),
                    timeout=self.device_deadline,
                )
            except asyncio.TimeoutError:
                name = getattr(self, "_target_names", {}).get(target, target)
                msg = (f"no result within {self.device_deadline:.0f}s "
                       f"(per-device deadline) - abandoned")
                self._log(f"{name}: {msg}", LogLevel.WARNING, name)
                device = Device(
                    hostname=name or target,
                    ip_address=target if is_ip_address(target) else "",
                    depth=depth,
                )
                device.discovery_success = False
                device.discovery_errors = [msg]
                return device

    async def _discover_target(
        self,
        target: str,
        depth: int,
        domains: List[str],
    ) -> Device:
        """One device, start to finish: dial, then DNS fallback if needed."""
        name = getattr(self, "_target_names", {}).get(target, target)
        by_ip = is_ip_address(target)
        skip_dial = by_ip and self._is_unroutable(target) and name != target

        device: Optional[Device] = None
        if not skip_dial:
            device = await self.discover_device(target=target, domains=domains, depth=depth)
            if device.discovery_success:
                return device

        # DNS fallback: the advertised management IP failed (or can never
        # work), but the neighbor also gave us a name. Try what DNS says
        # that name is before giving up on the device.
        if by_ip and name and name != target and not self.no_dns:
            alternates = [
                ip for ip in await self._resolve_all(name, domains)
                if ip != target and not self._is_claimed(ip)
            ]
            for alt_ip in alternates[:2]:
                self._target_names.setdefault(alt_ip, name)
                self._log(
                    f"{name}: {target} "
                    f"{'unroutable' if skip_dial else 'failed'}; "
                    f"retrying via DNS -> {alt_ip}",
                    LogLevel.INFO, name,
                )
                alt = await self.discover_device(target=alt_ip, domains=domains, depth=depth)
                if alt.discovery_success:
                    self._dns_fallback_hits = getattr(self, "_dns_fallback_hits", 0) + 1
                    return alt

        if device is None:
            # Unroutable and DNS had nothing usable - fail without dialing
            device = Device(hostname=name or target, ip_address=target)
            device.discovery_success = False
            device.discovery_errors = [
                f"advertised address {target} is unroutable and "
                f"no DNS name variant of '{name}' resolved"
            ]
        return device

    async def crawl(
        self,
        seeds: List[str],
        max_depth: int = 3,
        domains: Optional[List[str]] = None,
        exclude_patterns: Optional[List[str]] = None,
        credential_names: Optional[List[str]] = None,
        output_dir: Optional[Path] = None,
        progress_callback: Optional[ProgressCallback] = None,
        cancel_event: Optional[asyncio.Event] = None,
    ) -> DiscoveryResult:
        """
        Recursively discover network from seed devices.

        Discovery is CONCURRENT within each depth level (up to max_concurrent
        devices at once), but proceeds breadth-first across depths.

        Args:
            seeds: Starting IP addresses or hostnames
            max_depth: Maximum recursion depth
            domains: Domain suffixes for hostname resolution
            exclude_patterns: sysDescr patterns to skip
            credential_names: Specific credentials to try
            output_dir: Directory to save per-device JSON
            progress_callback: Legacy callback (message, current, total)
            cancel_event: Set to cancel discovery

        Returns:
            DiscoveryResult with all discovered devices
        """
        domains = domains or []
        exclude_patterns = exclude_patterns or []
        expanded_excludes = self._expand_patterns(exclude_patterns)

        # Reset state for new crawl
        self.reset_state()

        result = DiscoveryResult(
            seed_devices=seeds,
            max_depth=max_depth,
            domains=domains,
            exclude_patterns=exclude_patterns,
            started_at=datetime.now(),
        )

        # Emit crawl started event
        self.events.crawl_started(
            seeds, max_depth, domains, exclude_patterns,
            no_dns=self.no_dns,
            concurrency=self.max_concurrent,
            timeout=self.default_timeout,
        )

        # Claim and queue seeds
        current_batch: List[Tuple[str, int]] = []
        for seed in seeds:
            if self._try_claim(seed):
                current_batch.append((seed, 0))
                self._target_names[seed] = seed
                self.events.device_queued(seed, 0)

        if output_dir:
            output_dir.mkdir(parents=True, exist_ok=True)

        while current_batch:
            # Check cancellation
            if cancel_event and cancel_event.is_set():
                self.events.crawl_cancelled()
                result.completed_at = datetime.now()
                return result

            depth = current_batch[0][1]
            batch_size = len(current_batch)

            # Emit depth started event
            self.events.depth_started(depth, batch_size)

            # Legacy progress callback
            if progress_callback:
                progress_callback(
                    f"Depth {depth}: discovering {batch_size} devices",
                    result.total_attempted,
                    result.total_attempted + batch_size
                )

            # Discover all devices at this depth concurrently
            tasks = [
                self._discover_with_semaphore(target, d, domains)
                for target, d in current_batch
            ]

            # Gather with exception handling - don't let one failure stop others
            devices = await asyncio.gather(*tasks, return_exceptions=True)

            # Process results and collect next batch
            next_batch: List[Tuple[str, int]] = []
            depth_discovered = 0
            depth_failed = 0
            depth_excluded = 0
            not_dialed_before = len(self._not_dialed)

            for i, device_or_error in enumerate(devices):
                target, _ = current_batch[i]
                result.total_attempted += 1

                # Handle exceptions
                if isinstance(device_or_error, Exception):
                    result.failed += 1
                    depth_failed += 1
                    self._node_status[self._target_names.get(target, target)] = "failed"
                    self.events.device_failed(
                        target=target,
                        error=str(device_or_error),
                        depth=depth,
                    )
                    continue

                device: Device = device_or_error

                # Post-discovery dedup: two IPs in the same concurrent
                # batch can resolve to the same device (same sysName).
                # Check against actually-discovered sysNames, not the
                # _claimed set (which includes queued-but-not-yet-discovered).
                if device.discovery_success and device.sys_name:
                    norm_sysname = self._normalize_identifier(device.sys_name)
                    if norm_sysname in self._discovered_sysnames:
                        self._vprint(
                            f"Dedup: {target} is {device.sys_name} "
                            f"(already discovered via another IP)", 1
                        )
                        self._register_device(device)
                        continue
                    self._discovered_sysnames.add(norm_sysname)

                # Register all identifiers to prevent rediscovery
                self._register_device(device)

                if device.discovery_success:
                    result.successful += 1
                    depth_discovered += 1
                    result.devices.append(device)

                    # Emit device complete event
                    method = device.discovered_via.value if device.discovered_via else "unknown"
                    self.events.device_complete(
                        target=target,
                        hostname=device.hostname,
                        ip=device.ip_address,
                        vendor=device.vendor.value if device.vendor else "unknown",
                        neighbor_count=len(device.neighbors),
                        duration_ms=device.discovery_duration_ms,
                        method=method,
                        depth=depth,
                    )

                    # Check exclusion (sys_descr, hostname, sys_name)
                    excluded, matching_pattern = self._should_exclude_device(device, exclude_patterns)
                    if excluded:
                        result.excluded += 1
                        depth_excluded += 1
                        self._excluded_by_pattern[matching_pattern] = (
                            self._excluded_by_pattern.get(matching_pattern, 0) + 1
                        )
                        self.events.device_excluded(device.hostname, matching_pattern)
                        # Its neighbors are never queued; say so rather than
                        # leaving them as unexplained placeholders.
                        for neighbor in device.neighbors:
                            key = neighbor.remote_device or neighbor.remote_ip
                            if key and not is_mac_address(key) and not self._is_claimed(key):
                                self._record_not_dialed(
                                    key, f"behind excluded device ({matching_pattern})",
                                    device.hostname,
                                )
                        continue

                    # Save to file asynchronously
                    if output_dir:
                        try:
                            await self._save_device_files(device, output_dir)
                        except Exception as e:
                            self._log(
                                f"Failed to save {device.hostname}: {e}",
                                LogLevel.WARNING,
                                device.hostname
                            )

                    # Queue neighbors for next depth
                    if depth < max_depth:
                        for neighbor in device.neighbors:
                            device_name = neighbor.remote_device
                            neighbor_ip = neighbor.remote_ip

                            # MAC as device name: LLDP sometimes reports
                            # chassis_id (MAC) instead of sysName. Try to
                            # resolve the real hostname via SNMP sysName probe.
                            if device_name and is_mac_address(device_name):
                                if neighbor_ip and not is_mac_address(neighbor_ip):
                                    resolved_name = await self._resolve_sysname(
                                        neighbor_ip
                                    )
                                    if resolved_name:
                                        self._vprint(
                                            f"Resolved MAC {device_name} → "
                                            f"{resolved_name} via sysName "
                                            f"({neighbor_ip})", 2
                                        )
                                        device_name = resolved_name
                                    else:
                                        # sysName probe failed — still crawl
                                        # by IP, use IP as dedup key
                                        self._vprint(
                                            f"sysName probe failed for "
                                            f"{device_name} ({neighbor_ip}), "
                                            f"queuing by IP", 2
                                        )
                                        device_name = None
                                else:
                                    # MAC name and no usable IP — skip
                                    self._record_not_dialed(
                                        device_name, "MAC address, no IP",
                                        device.hostname,
                                    )
                                    continue

                            if neighbor_ip and is_mac_address(neighbor_ip):
                                neighbor_ip = None

                            # Dedup by device name (sysName) — that's the
                            # device identity. IP is just a transport handle;
                            # multi-homed devices have many IPs but one name.
                            dedup_key = device_name
                            if not dedup_key:
                                dedup_key = neighbor_ip

                            if not dedup_key:
                                continue

                            # Crawl target: prefer IP (avoids DNS failures),
                            # fall back to hosts file, then hostname.
                            if neighbor_ip:
                                crawl_target = neighbor_ip
                            elif device_name:
                                hosts_ip = self._resolve_from_hosts(device_name)
                                if hosts_ip:
                                    crawl_target = hosts_ip
                                    self._vprint(
                                        f"Resolved {device_name} → {hosts_ip} "
                                        f"via hosts file", 2
                                    )
                                else:
                                    crawl_target = device_name
                            else:
                                crawl_target = None

                            if not crawl_target:
                                continue

                            # Exclude before dialing when the neighbor entry
                            # already tells us what it is.
                            matched = self._neighbor_exclusion(neighbor, device_name, expanded_excludes)
                            if matched:
                                if not self._is_claimed(dedup_key):
                                    self._excluded_by_pattern[matched] = (
                                        self._excluded_by_pattern.get(matched, 0) + 1
                                    )
                                    self._record_not_dialed(
                                        dedup_key, f"matches exclude '{matched}'", device.hostname
                                    )
                                continue

                            # Atomically claim the target
                            if self._try_claim(dedup_key):
                                next_batch.append((crawl_target, depth + 1))
                                self._target_names[crawl_target] = device_name or crawl_target

                                # Also claim the other identifier
                                if neighbor_ip and neighbor_ip != dedup_key:
                                    self._try_claim(neighbor_ip)
                                if device_name and device_name != dedup_key:
                                    self._try_claim(device_name)

                                # Emit neighbor queued event
                                self.events.neighbor_queued(
                                    target=crawl_target,
                                    ip=neighbor_ip if neighbor_ip != crawl_target else None,
                                    from_device=device.hostname,
                                    depth=depth + 1,
                                )
                            else:
                                self.events.neighbor_skipped(
                                    dedup_key, "already claimed", device.hostname
                                )
                    else:
                        # Last depth: record neighbors we will never dial so
                        # the UI can report them instead of dropping them.
                        for neighbor in device.neighbors:
                            name = neighbor.remote_device
                            ip = neighbor.remote_ip
                            if ip and is_mac_address(ip):
                                ip = None
                            if name and is_mac_address(name):
                                name = None
                            key = name or ip
                            if key and not self._is_claimed(key):
                                self._record_not_dialed(
                                    key, "beyond max depth", device.hostname
                                )

                else:
                    result.failed += 1
                    depth_failed += 1
                    self._node_status[self._target_names.get(target, target)] = "failed"
                    error_msg = "; ".join(device.discovery_errors) if device.discovery_errors else "Unknown error"
                    self.events.device_failed(
                        target=target,
                        error=error_msg,
                        depth=depth,
                    )

            # Emit depth complete event
            self.events.depth_complete(
                depth, depth_discovered, depth_failed,
                attempted=batch_size,
                excluded=depth_excluded,
                not_dialed=len(self._not_dialed) - not_dialed_before,
            )

            # Live preview: cumulative map after every depth. Cheap (dict
            # build over discovered devices); the GUI merges it in place.
            if result.devices:
                try:
                    self.events.topology_updated(
                        self._generate_topology_map(result.devices),
                        node_status=dict(self._node_status),
                        depth=depth,
                        final=False,
                    )
                except Exception as e:
                    self._log(f"Live topology update failed: {e}", LogLevel.DEBUG)

            # Move to next depth
            current_batch = next_batch

        result.completed_at = datetime.now()

        # Generate topology map
        topology_map = None
        if output_dir:
            topology_map = self._generate_topology_map(result.devices)
            map_file = output_dir / 'map.json'
            await self._write_json_file(map_file, topology_map)
            self._log(f"Topology map saved to: {map_file}", LogLevel.INFO)

        # Emit topology update
        if topology_map:
            self.events.topology_updated(
                topology_map,
                node_status=dict(self._node_status),
                final=True,
            )

        if self._dns_fallback_hits:
            self._log(
                f"DNS fallback reached {self._dns_fallback_hits} device(s) whose "
                f"advertised address failed", LogLevel.INFO,
            )

        # Not-dialed roll-up by reason
        not_dialed_counts: Dict[str, int] = {}
        for reason, _src in self._not_dialed.values():
            not_dialed_counts[reason] = not_dialed_counts.get(reason, 0) + 1

        # Emit crawl complete event
        self.events.crawl_complete(
            duration_seconds=result.duration_seconds or 0,
            topology=topology_map,
            not_dialed=not_dialed_counts,
            excluded_by_pattern=dict(self._excluded_by_pattern),
        )

        return result

    # =========================================================================
    # Topology Generation
    # =========================================================================

    def _record_not_dialed(self, key: str, reason: str, from_device: str) -> None:
        """Record a neighbor that will never be dialed (unique per key)."""
        norm = self._normalize_identifier(key)
        if norm in self._not_dialed:
            return
        self._not_dialed[norm] = (reason, from_device)
        self._node_status[key] = "not_dialed"
        self.events.neighbor_skipped(key, reason, from_device)

    def _generate_topology_map(self, devices: List[Device]) -> Dict[str, Any]:
        """
        Generate topology map from discovered devices with bidirectional validation.

        Connections are only included if:
        1. Both sides confirm the link (bidirectional), OR
        2. The peer wasn't discovered (leaf/edge case - trust unidirectional)

        Returns a dict suitable for visualization:
        {
            "device_name": {
                "node_details": {"ip": "...", "platform": "..."},
                "peers": {
                    "peer_name": {
                        "ip": "...",
                        "platform": "...",
                        "connections": [["local_if", "remote_if"], ...]
                    }
                }
            }
        }
        """
        # Build lookup for device info by various identifiers
        device_info: Dict[str, Device] = {}
        for device in devices:
            if device.hostname:
                device_info[device.hostname] = device
            if device.sys_name and device.sys_name != device.hostname:
                device_info[device.sys_name] = device
            if device.ip_address:
                device_info[device.ip_address] = device

        # Get canonical name for a device
        def get_canonical_name(device: Device) -> str:
            return device.sys_name or device.hostname or device.ip_address

        # Build set of discovered device canonical names
        discovered_devices: Set[str] = set()
        for device in devices:
            canonical = get_canonical_name(device)
            if canonical:
                discovered_devices.add(canonical)
                # Also add variations for matching
                if device.sys_name:
                    discovered_devices.add(device.sys_name)
                if device.hostname:
                    discovered_devices.add(device.hostname)

        # First pass: collect all neighbor claims
        # Key: (canonical_device, normalized_local_if) -> list of (canonical_peer, normalized_remote_if, neighbor_obj)
        all_claims: Dict[tuple, List[tuple]] = {}

        for device in devices:
            device_canonical = get_canonical_name(device)
            if not device_canonical:
                continue

            for neighbor in device.neighbors:
                if not neighbor.remote_device:
                    continue

                # Filter parsing artifacts
                peer_check = neighbor.remote_device.strip().lower().strip("'\"")
                if peer_check in ('detail', '^', '%', 'sho', '') or len(peer_check) < 2:
                    continue

                local_if = self._normalize_interface(neighbor.local_interface)
                remote_if = self._normalize_interface(neighbor.remote_interface)

                if not local_if or not remote_if:
                    continue

                # Get canonical peer name
                peer_name = neighbor.remote_device
                canonical_peer = peer_name
                if peer_name in device_info:
                    peer_dev = device_info[peer_name]
                    canonical_peer = get_canonical_name(peer_dev)

                key = (device_canonical, local_if)
                if key not in all_claims:
                    all_claims[key] = []
                all_claims[key].append((canonical_peer, remote_if, neighbor))

        # Helper to check if reverse claim exists
        def has_reverse_claim(device_canonical: str, local_if: str,
                            peer_canonical: str, remote_if: str) -> bool:
            return True

            """Check if peer claims the reverse connection."""
            reverse_key = (peer_canonical, remote_if)
            if reverse_key not in all_claims:
                return False

            for (claimed_peer, claimed_remote, _) in all_claims[reverse_key]:
                # Peer should claim connection back to us on our local interface
                if claimed_peer == device_canonical and claimed_remote == local_if:
                    return True
                # Also check if claimed_peer matches any of our identifiers
                if device_canonical in device_info:
                    dev = device_info[device_canonical]
                    if claimed_peer in [dev.hostname, dev.sys_name, dev.ip_address]:
                        if claimed_remote == local_if:
                            return True
            return False

        # Helper to check if peer was discovered
        def peer_was_discovered(peer_canonical: str, peer_name_original: str) -> bool:
            """Check if we discovered this peer."""
            if peer_canonical in discovered_devices:
                return True
            if peer_name_original in discovered_devices:
                return True
            if peer_name_original in device_info:
                return True
            return False

        # Helper to check if peer is a leaf node (discovered but has no neighbors)
        def peer_is_leaf(peer_canonical: str, peer_name_original: str) -> bool:
            """Check if peer is a leaf node (no LLDP/CDP capability)."""
            # Check by canonical name
            if peer_canonical in device_info:
                peer_dev = device_info[peer_canonical]
                if len(peer_dev.neighbors) == 0:
                    return True
            # Check by original name
            if peer_name_original in device_info:
                peer_dev = device_info[peer_name_original]
                if len(peer_dev.neighbors) == 0:
                    return True
            return False

        # Second pass: build topology with validated connections
        topology: Dict[str, Any] = {}
        seen_devices: Set[str] = set()

        for device in devices:
            canonical_name = get_canonical_name(device)
            if not canonical_name or canonical_name in seen_devices:
                continue
            seen_devices.add(canonical_name)

            # Platform: SSH devices have clean sys_descr from tfsm_fire,
            # SNMP devices need extract_platform() to parse raw sysDescr
            if device.discovered_via == DiscoveryProtocol.SSH and device.sys_descr:
                device_platform = device.sys_descr
            else:
                device_platform = extract_platform(
                    device.sys_descr,
                    device.vendor.value if device.vendor else None,
                )

            node = {
                "node_details": {
                    "ip": device.ip_address,
                    "platform": device_platform,
                    # Asset identity from ENTITY-MIB / sysObjectID resolution.
                    # Emitted even when empty so the viewer can render a
                    # consistent field set rather than branching on presence.
                    "model": device.model or "",
                    "serial": device.serial or "",
                    "os_version": device.os_version or "",
                    "vendor": device.vendor.value if device.vendor else "",
                    # Full per-device record for the viewer's detail modal.
                    # Nested rather than flattened so existing consumers reading
                    # node_details.platform and friends keep working unchanged.
                    "metadata": self._build_node_metadata(device),
                },
                "peers": {}
            }

            # Group validated connections by peer
            peer_connections: Dict[str, Dict] = {}
            used_local_interfaces: Set[str] = set()  # Track used interfaces globally for this device

            # Sort: prefer neighbors with real hostnames over bare MACs.
            # Multiple LLDP remTable entries can exist for the same local
            # port (firmware vs OS LLDP agent, different remIndex values).
            # The used_local_interfaces gate below is first-one-wins, so
            # we must ensure the named entry comes first regardless of
            # SNMP walk order (which shifts with lldpRemTimeMark).
            sorted_neighbors = sorted(
                device.neighbors,
                key=lambda n: (1 if is_mac_address(n.remote_device) else 0),
            )

            for neighbor in sorted_neighbors:
                if not neighbor.remote_device:
                    continue

                # Filter parsing artifacts — NX-OS command echo/error
                # markers that leak through TextFSM as phantom neighbors
                peer_check = neighbor.remote_device.strip().lower().strip("'\"")
                if peer_check in ('detail', '^', '%', 'sho', '') or len(peer_check) < 2:
                    continue

                local_if = self._normalize_interface(neighbor.local_interface)
                remote_if = self._normalize_interface(neighbor.remote_interface)

                if not local_if or not remote_if:
                    continue

                # Skip if we've already used this local interface
                if local_if in used_local_interfaces:
                    continue

                # Get canonical peer name
                peer_name = neighbor.remote_device
                canonical_peer = peer_name
                if peer_name in device_info:
                    peer_dev = device_info[peer_name]
                    canonical_peer = get_canonical_name(peer_dev)

                # Validate connection
                peer_discovered = peer_was_discovered(canonical_peer, peer_name)

                if peer_discovered:
                    # Peer was discovered - check if it's a leaf node
                    is_leaf = peer_is_leaf(canonical_peer, peer_name)

                    if is_leaf:
                        # Leaf node (no neighbors) - trust unidirectional claim
                        pass
                    elif not has_reverse_claim(canonical_name, local_if, canonical_peer, remote_if):
                        # Not a leaf and no reverse claim - drop
                        self._vprint(f"Dropping unconfirmed link: {canonical_name}:{local_if} -> {canonical_peer}:{remote_if}", 2)
                        continue
                # else: peer not discovered (leaf/edge) - trust unidirectional claim

                # Get peer platform — priority:
                # 1. CDP remote_platform (e.g., "N9K-C9372PX") — most specific
                # 2. Discovered device sys_descr (already parsed by tfsm_fire for SSH)
                # 3. LLDP remote_description through extract_platform()
                # 4. "Unknown"
                peer_platform = None
                if neighbor.remote_platform:
                    peer_platform = neighbor.remote_platform
                if peer_name in device_info:
                    peer_dev = device_info[peer_name]
                    if peer_dev.sys_descr:
                        # sys_descr from SSH is already clean ("Cisco C9372PX 9.3(11)")
                        # sys_descr from SNMP is raw and needs extract_platform()
                        if peer_dev.discovered_via == DiscoveryProtocol.SSH:
                            peer_platform = peer_dev.sys_descr
                        else:
                            peer_platform = extract_platform(
                                peer_dev.sys_descr,
                                peer_dev.vendor.value if peer_dev.vendor else None,
                            )
                elif not peer_platform and neighbor.remote_description:
                    peer_platform = extract_platform(neighbor.remote_description)

                if canonical_peer not in peer_connections:
                    peer_connections[canonical_peer] = {
                        "ip": neighbor.remote_ip,
                        "platform": peer_platform or "Unknown",
                        "connections": []
                    }

                # Add validated connection
                conn = [local_if, remote_if]
                peer_connections[canonical_peer]["connections"].append(conn)
                used_local_interfaces.add(local_if)

            node["peers"] = peer_connections
            topology[canonical_name] = node

        return topology

    def _build_node_metadata(self, device: Device) -> Dict[str, Any]:
        """
        Build the metadata block embedded in each topology map node.

        Carries the full per-device record - system group, inventory, discovery
        provenance, and the interface and ARP tables - so the map viewer can
        render device detail without a second lookup.

        Note this makes map.json substantially larger than the topology alone;
        ARP tables on aggregation devices dominate the size. Downstream
        consumers that only want topology should read node_details' top-level
        keys and ignore this block.
        """
        return {
            # System group
            "sys_name": device.sys_name or "",
            "sys_descr": device.sys_descr or "",
            "sys_location": device.sys_location or "",
            "sys_contact": device.sys_contact or "",
            "sys_object_id": device.sys_object_id or "",
            "uptime_ticks": device.uptime_ticks,
            "fqdn": device.fqdn or "",

            # Discovery provenance
            "discovered_via": device.discovered_via.value if device.discovered_via else "",
            "credential_used": device.credential_used or "",
            "discovered_at": device.discovered_at.isoformat() if device.discovered_at else "",
            "discovery_duration_ms": device.discovery_duration_ms,
            "depth": device.depth,
            "discovery_errors": list(device.discovery_errors or []),

            "counts": {
                "interfaces": len(device.interfaces or []),
                "neighbors": len(device.neighbors or []),
                "arp_entries": len(device.arp_table or {}),
            },

            # Full tables
            "interfaces": [i.to_dict() for i in (device.interfaces or [])],
            "arp_table": dict(device.arp_table or {}),
            "neighbors": [n.to_dict() for n in (device.neighbors or [])],
        }

    def _normalize_interface(self, interface: str) -> str:
        """Normalize interface name for consistent display and deduplication."""
        if not interface:
            return ""

        result = interface.strip()

        # === Cisco long-form to short-form ===
        cisco_replacements = [
            ("GigabitEthernet", "Gi"),
            ("TenGigabitEthernet", "Te"),
            ("TenGigE", "Te"),              # IOS-XR style
            ("FortyGigabitEthernet", "Fo"),
            ("FortyGigE", "Fo"),
            ("HundredGigE", "Hu"),
            ("HundredGigabitEthernet", "Hu"),
            ("TwentyFiveGigE", "Twe"),
            ("FastEthernet", "Fa"),
            ("Ethernet", "Eth"),            # Must come after longer variants
        ]

        for long, short in cisco_replacements:
            if result.startswith(long):
                result = short + result[len(long):]
                break

        # === Port-channel normalization (case-insensitive) ===
        # Port-channel1, Port-Channel1, port-channel1 -> Po1
        port_channel_match = re.match(r'^[Pp]ort-[Cc]hannel(\d+.*)$', result)
        if port_channel_match:
            result = f"Po{port_channel_match.group(1)}"

        # === Vlan normalization ===
        # Vlan666, VLAN-666, vlan666 -> Vl666
        vlan_match = re.match(r'^[Vv][Ll][Aa][Nn]-?(\d+.*)$', result)
        if vlan_match:
            result = f"Vl{vlan_match.group(1)}"

        # === Null interface normalization ===
        # Null0 -> Nu0
        if result.startswith("Null"):
            result = "Nu" + result[4:]

        # === Loopback normalization ===
        # Loopback0 -> Lo0
        if result.startswith("Loopback"):
            result = "Lo" + result[8:]

        # === Short form normalization ===
        # Et1/1 -> Eth1/1 (Arista short form in LLDP)
        result = re.sub(r'^Et(\d)', r'Eth\1', result)

        # === Juniper subinterface normalization ===
        # xe-0/0/0.0 -> xe-0/0/0 (strip default .0 unit for matching)
        # But keep .123 or other non-zero units
        result = re.sub(r'^((?:xe|ge|et|ae|irb|em|me|fxp)-?\d+(?:/\d+)*)\.0$', r'\1', result, flags=re.IGNORECASE)

        return result

    def _connections_equal(self, conn1: List[str], conn2: List[str]) -> bool:
        """Check if two connections are equivalent (same interfaces, normalized)."""
        if len(conn1) != 2 or len(conn2) != 2:
            return False

        local1, remote1 = self._normalize_interface(conn1[0]), self._normalize_interface(conn1[1])
        local2, remote2 = self._normalize_interface(conn2[0]), self._normalize_interface(conn2[1])

        return local1 == local2 and remote1 == remote2


# Convenience function for single device discovery
async def discover_device(
    target: str,
    vault: Optional['CredentialVault'] = None,
    auth: Optional[Any] = None,
    **kwargs
) -> Device:
    """
    Quick single-device discovery.

    Args:
        target: IP address or hostname
        vault: Unlocked CredentialVault
        auth: Pre-built auth data
        **kwargs: Passed to DiscoveryEngine.discover_device()

    Returns:
        Device dataclass
    """
    engine = DiscoveryEngine(vault=vault)
    return await engine.discover_device(target, auth=auth, **kwargs)