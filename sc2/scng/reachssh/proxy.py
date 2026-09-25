"""
reachssh proxy — jump-host (ProxyJump / bastion) resolution.

Two concerns, both driven from config.yaml:

  1. A named *registry* of jump hosts — each a {host, port, credential}
     where ``credential`` is a credential *name*. Bastion credentials are
     resolved through a caller-supplied resolver (see ``credential_resolver``
     below) so this library never stores or imports secrets itself.

  2. An *ordered* rule list that associates devices with a jump host.
     Rules are evaluated top-to-bottom, FIRST MATCH WINS. Within one rule,
     every present match key must match (logical AND). A rule with no match
     keys is an explicit catch-all. The first matching rule's ``jump`` wins;
     a ``jump: direct`` rule short-circuits to a direct connection. No
     matching rule also means a direct connection.

This route-map / ACL ordering is the only association model that resolves
the "device sits in a site but is special" conflict deterministically — a
DMZ firewall is also in site ``site1`` but must not use the ``site1`` bastion,
so an explicit ``devices:`` rule is placed *above* the broad ``site:`` rule
and wins by position, not by an implicit specificity ranking.

config.yaml shape (top-level, alongside ``credentials``)::

    jump_hosts:
      site-bastion:
        host: 10.0.1.10
        port: 22
        credential: bastion-site1       # credential name (resolved by caller)
      dmz-jump:
        host: 198.51.100.5
        credential: bastion-dmz

    proxy_rules:                        # top -> bottom, first match wins
      - match: {devices: [bastion-site1]}   # the bastion itself: direct
        jump: direct
      - match: {devices: [fw01-dmz, "fw*-dmz", lb01-dmz]}
        jump: dmz-jump
      - match: {site: site1}
        jump: site-bastion
      - match: {site: [site1, site2]}        # values may be scalar or list
        jump: site-bastion

Match vocabulary (each key optional, AND-combined within a rule):

  - ``site``       — device site_slug, scalar or list
  - ``role``       — device role_slug, scalar or list
  - ``platform``   — device platform_slug, scalar or list
  - ``devices``    — device name, exact or fnmatch glob, scalar or list
  - ``name_regex`` — device name, ``re.search`` (anchor it yourself)

The ``jump:`` value is a jump-host name, the sentinel ``direct``, or a list
of names for multi-hop chaining. The data model accepts a chain today; the
SSH client implements single-hop now and raises an explicit error for >1 hop
so chaining can land later without a config/model change.

Credential resolution is lazy and cached: a jump host costs one credential lookup
the first time a device routes through it, not once per device.
"""

import fnmatch
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union

logger = logging.getLogger(__name__)

# A credential resolver maps a credential *name* (or None for "default") to a
# credential tuple: (username, password) or (username, password, key_content).
# The caller supplies this so reachssh never imports a vault or touches secrets
# at rest. netlapse passes its vault bridge; a script can pass a lambda reading
# from env vars or a dict.
CredentialResolver = Callable[[Optional[str]], Optional[Sequence[str]]]

DIRECT = "direct"


# ═══════════════════════════════════════════════════════════════════════════
# Resolved connection types — what flows down to the SSH client
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class JumpHop:
    """A single resolved jump hop with credentials already resolved."""
    name: str
    host: str
    port: int = 22
    username: str = ""
    password: Optional[str] = None
    key_content: Optional[str] = None


@dataclass
class JumpSpec:
    """
    An ordered chain of jump hops between the caller and the target device.

    ``hops[0]`` is reached directly; each subsequent hop is reached through
    the previous one. A single-element chain is the common bastion case.
    """
    hops: List[JumpHop] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.hops)

    @property
    def is_single_hop(self) -> bool:
        return len(self.hops) == 1

    def describe(self) -> str:
        return " -> ".join(f"{h.name}({h.host}:{h.port})" for h in self.hops)


# ═══════════════════════════════════════════════════════════════════════════
# Parsed config types
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class _JumpHostDef:
    """Registry entry — credential is a name, resolved lazily by the caller."""
    name: str
    host: str
    port: int
    credential: Optional[str]   # credential name (resolved by caller); None -> vault default


@dataclass
class _ProxyRule:
    """One parsed rule: a matcher plus an ordered list of jump-host names."""
    # Match keys (None = key absent = not constrained)
    sites: Optional[set] = None
    roles: Optional[set] = None
    platforms: Optional[set] = None
    device_globs: Optional[List[str]] = None
    name_regex: Optional[re.Pattern] = None
    # Target: list of jump-host names, or None for the `direct` sentinel
    jump_names: Optional[List[str]] = None   # None => direct
    raw_index: int = 0                        # position, for diagnostics

    @property
    def is_direct(self) -> bool:
        return self.jump_names is None

    def matches(self, device: Dict[str, Any]) -> bool:
        """True if every present key matches this device (AND)."""
        if self.sites is not None and device.get("site_slug") not in self.sites:
            return False
        if self.roles is not None and device.get("role_slug") not in self.roles:
            return False
        if self.platforms is not None and device.get("platform_slug") not in self.platforms:
            return False
        name = device.get("name", "")
        if self.device_globs is not None:
            if not any(fnmatch.fnmatch(name, g) for g in self.device_globs):
                return False
        if self.name_regex is not None and not self.name_regex.search(name):
            return False
        return True


# ═══════════════════════════════════════════════════════════════════════════
# Parsing helpers
# ═══════════════════════════════════════════════════════════════════════════

def _as_list(value: Any) -> List[str]:
    """Normalize a scalar-or-list YAML value into a list of strings."""
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(v) for v in value]
    return [str(value)]


def _normalize_jump(value: Any, rule_index: int) -> Optional[List[str]]:
    """
    Normalize a rule's ``jump`` value into either None (direct) or a list of
    jump-host names. ``direct`` may not be mixed with named hops.
    """
    names = _as_list(value)
    if not names:
        raise ValueError(
            f"proxy_rules[{rule_index}]: 'jump' is required "
            f"(a jump-host name, a list of names, or 'direct')"
        )
    lowered = [n.lower() for n in names]
    if DIRECT in lowered:
        if len(names) > 1:
            raise ValueError(
                f"proxy_rules[{rule_index}]: 'direct' cannot be combined "
                f"with named jump hosts"
            )
        return None  # direct sentinel
    return names


def _parse_rule(raw: Dict[str, Any], index: int) -> _ProxyRule:
    if not isinstance(raw, dict):
        raise ValueError(f"proxy_rules[{index}] must be a mapping, got {type(raw).__name__}")

    match = raw.get("match") or {}
    if not isinstance(match, dict):
        raise ValueError(f"proxy_rules[{index}].match must be a mapping")

    unknown = set(match) - {"site", "role", "platform", "devices", "name_regex"}
    if unknown:
        raise ValueError(
            f"proxy_rules[{index}].match has unknown key(s): {', '.join(sorted(unknown))}. "
            f"Allowed: site, role, platform, devices, name_regex"
        )

    sites = set(_as_list(match["site"])) if "site" in match else None
    roles = set(_as_list(match["role"])) if "role" in match else None
    platforms = set(_as_list(match["platform"])) if "platform" in match else None
    device_globs = _as_list(match["devices"]) if "devices" in match else None

    name_regex = None
    if "name_regex" in match:
        try:
            name_regex = re.compile(str(match["name_regex"]))
        except re.error as e:
            raise ValueError(
                f"proxy_rules[{index}].match.name_regex is not a valid regex: {e}"
            )

    if not match:
        logger.debug("proxy_rules[%d] has an empty match — it is a catch-all", index)

    return _ProxyRule(
        sites=sites,
        roles=roles,
        platforms=platforms,
        device_globs=device_globs,
        name_regex=name_regex,
        jump_names=_normalize_jump(raw.get("jump"), index),
        raw_index=index,
    )


# ═══════════════════════════════════════════════════════════════════════════
# Resolver
# ═══════════════════════════════════════════════════════════════════════════

class ProxyResolver:
    """
    Resolves a device to its JumpSpec via the ordered, first-match rule list.

    Construction validates that every jump-host name referenced by a rule
    exists in the registry, so a typo fails loudly at startup rather than
    silently turning a bastion-only device into a (failing) direct connect.
    Bastion *credentials* are resolved lazily via credential_resolver on first use
    and cached.
    """

    def __init__(
        self,
        registry: Dict[str, _JumpHostDef],
        rules: List[_ProxyRule],
        credential_resolver: "CredentialResolver",
    ):
        """
        Args:
            registry: name -> _JumpHostDef, the parsed jump_hosts block.
            rules: ordered _ProxyRule list, first-match-wins.
            credential_resolver: callable ``(credential_name) -> creds`` where
                creds is a tuple ``(username, password)`` or
                ``(username, password, key_content)``. Called lazily, once per
                jump host, and cached. This is the ONLY place bastion secrets
                enter the library — reachssh never imports a vault or reads
                secrets from disk itself. ``credential_name`` may be None,
                meaning "resolver's default credential".
        """
        self._registry = registry
        self._rules = rules
        self._resolve_credential = credential_resolver
        self._hop_cache: Dict[str, JumpHop] = {}

        # Fail-fast: every referenced jump name must exist in the registry.
        for rule in rules:
            for name in (rule.jump_names or []):
                if name not in registry:
                    raise ValueError(
                        f"proxy_rules[{rule.raw_index}] references unknown jump host "
                        f"{name!r}. Defined jump_hosts: "
                        f"{', '.join(sorted(registry)) or '(none)'}"
                    )

        logger.info(
            "Proxy resolver loaded: %d jump host(s), %d rule(s)",
            len(registry), len(rules),
        )

    # -- public API ----------------------------------------------------------

    def resolve(self, device: Dict[str, Any]) -> Optional[JumpSpec]:
        """
        Return the JumpSpec for a device, or None for a direct connection.

        Walks the rule list top-to-bottom and returns on the first match.
        A matched ``direct`` rule returns None; so does falling off the end.
        """
        for rule in self._rules:
            if rule.matches(device):
                if rule.is_direct:
                    logger.debug(
                        "%s matched proxy_rules[%d] -> direct",
                        device.get("name"), rule.raw_index,
                    )
                    return None
                spec = JumpSpec(hops=[self._hop(n) for n in rule.jump_names])
                logger.debug(
                    "%s matched proxy_rules[%d] -> %s",
                    device.get("name"), rule.raw_index, spec.describe(),
                )
                return spec
        return None

    # -- internals -----------------------------------------------------------

    def _hop(self, name: str) -> JumpHop:
        """Resolve (and cache) a jump host's credentials via the injected resolver."""
        if name in self._hop_cache:
            return self._hop_cache[name]

        defn = self._registry[name]
        cred = self._resolve_credential(defn.credential)
        if not cred:
            raise ValueError(
                f"credential_resolver returned nothing for jump host {name!r} "
                f"(credential={defn.credential!r})"
            )
        username = cred[0]
        password = cred[1] if len(cred) > 1 else None
        key_content = cred[2] if len(cred) > 2 else None

        hop = JumpHop(
            name=name,
            host=defn.host,
            port=defn.port,
            username=username,
            password=password,
            key_content=key_content,
        )
        self._hop_cache[name] = hop
        logger.debug(
            "Resolved jump host %r -> %s:%d as %s (cred=%s)",
            name, defn.host, defn.port, username, defn.credential or "default",
        )
        return hop


def build_proxy_resolver(
    proxy_config: Optional[Dict[str, Any]],
    credential_resolver: "CredentialResolver",
) -> Optional[ProxyResolver]:
    """
    Build a ProxyResolver from the config.yaml ``jump_hosts`` + ``proxy_rules``
    slice, or return None when no jump-host config is present.

    Args:
        proxy_config: ``{"jump_hosts": {...}, "proxy_rules": [...]}`` — typically
            the top-level keys lifted out of config.yaml.
        credential_resolver: callable ``(credential_name) -> (user, password[,
            key_content])`` used to resolve bastion credentials lazily. See
            ProxyResolver for the contract.

    Returns:
        A ProxyResolver, or None if neither jump_hosts nor proxy_rules is set.

    Raises:
        ValueError: on malformed config (bad rule, unknown match key, a rule
            that references an undefined jump host, invalid regex).
    """
    proxy_config = proxy_config or {}
    raw_hosts = proxy_config.get("jump_hosts") or {}
    raw_rules = proxy_config.get("proxy_rules") or []

    if not raw_hosts and not raw_rules:
        return None

    if not isinstance(raw_hosts, dict):
        raise ValueError("jump_hosts must be a mapping of name -> {host, port, credential}")
    if not isinstance(raw_rules, list):
        raise ValueError("proxy_rules must be a list")

    registry: Dict[str, _JumpHostDef] = {}
    for name, body in raw_hosts.items():
        if not isinstance(body, dict):
            raise ValueError(f"jump_hosts[{name}] must be a mapping")
        host = body.get("host")
        if not host:
            raise ValueError(f"jump_hosts[{name}] is missing required 'host'")
        registry[str(name)] = _JumpHostDef(
            name=str(name),
            host=str(host),
            port=int(body.get("port") or 22),
            credential=(str(body["credential"]) if body.get("credential") else None),
        )

    rules = [_parse_rule(r, i) for i, r in enumerate(raw_rules)]
    return ProxyResolver(registry, rules, credential_resolver)