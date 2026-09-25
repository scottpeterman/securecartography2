"""
sc2/scng/discovery/jump.py

Jump-host (bastion / ProxyJump) support for SSH discovery.

Bridges three things that deliberately know nothing about each other:

  - sc2.scng.reachssh.ProxyResolver, which owns the rule-matching model but never
    touches secrets - it asks for credentials through a callable
  - the SC2 credential vault, which owns secrets
  - the discovery engine, which knows the device being reached

Config file
-----------
YAML, by default ~/.seccart2/jump_hosts.yaml. Rules are evaluated top to bottom,
FIRST MATCH WINS, and every key present in one rule must match (AND). This is
route-map ordering, not implicit specificity, so an exception is expressed by
position - put the narrow rule above the broad one:

    jump_hosts:
      lab-bastion:
        host: 192.0.2.10
        port: 22
        credential: bastion-lab      # name of a vault SSH credential
      dmz-jump:
        host: 198.51.100.5
        credential: bastion-dmz

    proxy_rules:
      - match: {devices: [lab-bastion]}   # the bastion itself, never via itself
        jump: direct
      - match: {devices: ["fw*-dmz"]}     # exception, must sit above the site rule
        jump: dmz-jump
      - match: {platform: [juniper]}
        jump: lab-bastion
      - match: {}                          # catch-all
        jump: lab-bastion

Match keys: devices (exact or glob), name_regex, site, role, platform.

IMPORTANT - what this does and does not reach
---------------------------------------------
A jump host is an SSH 'direct-tcpip' channel, which carries TCP only. SNMP is
UDP and cannot traverse it. Discovery through a bastion therefore collects via
the SSH path only: no ENTITY-MIB inventory, no interface table, no ARP, no
sysObjectID. Devices come back with neighbors and a platform string and little
else. For full inventory, run discovery from a host with direct SNMP
reachability - the bastion path is for topology and for reaching devices that
are otherwise unreachable.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

import yaml

from .ssh.client import ProxyResolver, build_proxy_resolver
from ...paths import JUMP_HOSTS_FILE

logger = logging.getLogger(__name__)

DEFAULT_JUMP_CONFIG = JUMP_HOSTS_FILE


def load_jump_config(path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """
    Load the jump-host config slice from YAML.

    Returns None when the file does not exist, so a missing config is simply
    "no jump hosts configured" rather than an error. A malformed file DOES
    raise - silently falling back to direct connections would look like a
    working discovery that quietly skipped every bastion-only device.
    """
    path = Path(path) if path else DEFAULT_JUMP_CONFIG

    if not path.exists():
        logger.debug("No jump-host config at %s", path)
        return None

    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a YAML mapping at the top level")

    if not data.get("jump_hosts") and not data.get("proxy_rules"):
        logger.warning("%s exists but defines no jump_hosts or proxy_rules", path)
        return None

    return {
        "jump_hosts": data.get("jump_hosts") or {},
        "proxy_rules": data.get("proxy_rules") or [],
    }


def build_vault_credential_resolver(vault) -> "callable":
    """
    Adapt the SC2 credential vault to the reachssh CredentialResolver contract.

    The resolver calls this with a credential *name* and expects
    (username, password) or (username, password, key_content), or None if the
    name cannot be resolved. Lookups are lazy and cached by the resolver - one per
    jump host, not one per device.
    """
    def resolve(credential_name: Optional[str]) -> Optional[Sequence[str]]:
        if vault is None:
            logger.error("Jump host needs credential %r but no vault is open", credential_name)
            return None
        if not credential_name:
            logger.error("Jump host has no 'credential' set; name it explicitly")
            return None

        try:
            cred = vault.get_ssh_credential(name=credential_name)
        except Exception as e:
            logger.error("Vault lookup failed for jump credential %r: %s", credential_name, e)
            return None

        if not cred:
            logger.error(
                "Jump credential %r not found in vault. Add it, or fix the "
                "'credential:' name in the jump-host config.", credential_name
            )
            return None

        key_content = getattr(cred, "key_content", None)
        if key_content:
            return (cred.username, cred.password, key_content)
        return (cred.username, cred.password)

    return resolve


def build_jump_resolver(
    vault,
    config_path: Optional[Path] = None,
) -> Optional[ProxyResolver]:
    """
    Build a ProxyResolver from config plus the vault, or None if unconfigured.

    Raises on malformed config or on a rule referencing an undefined jump host,
    since both mean devices would silently connect directly instead.
    """
    config = load_jump_config(config_path)
    if not config:
        return None

    resolver = build_proxy_resolver(config, build_vault_credential_resolver(vault))
    if resolver:
        logger.info(
            "Jump-host routing active from %s",
            config_path or DEFAULT_JUMP_CONFIG,
        )
    return resolver


def device_context(
    hostname: Optional[str] = None,
    ip: Optional[str] = None,
    vendor: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Build the device dict that ProxyResolver matches rules against.

    SC2 has no CMDB, so site_slug and role_slug are left unset - rules using
    those keys simply will not match. What SC2 does know maps as:

        name           <- hostname, falling back to IP
        platform_slug  <- discovered vendor (cisco, juniper, arista, ...)

    In practice that means 'devices' globs, 'name_regex', and 'platform' are
    the useful match keys here. Naming conventions carry site information in
    most fleets, so name_regex covers the site case.
    """
    return {
        "name": hostname or ip or "",
        "ip": ip or "",
        "platform_slug": (vendor or "").lower() or None,
        "site_slug": None,
        "role_slug": None,
    }