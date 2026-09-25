"""
sc2.scng.reachssh - vendored SSH client for Secure Cartography.

Sourced from the reachssh project and carried in-tree so seccart2 has no
external SSH dependency beyond Paramiko. Modules:

    client     - Paramiko invoke-shell client (legacy algos, pagination,
                 prompt detection, ANSI filtering, single-hop ProxyJump)
    proxy      - jump-host registry + first-match-wins proxy rules
    emulation  - optional mock-device redirection (inert unless enabled)

The public names below match the reachssh package surface, so callers that
used `from reachssh import X` only need the import path changed.
"""

from .client import (
    SSHClient,
    SSHClientConfig,
    LegacySSHSupport,
    filter_ansi_sequences,
    PAGINATION_DISABLE_SHOTGUN,
    SecondFactorRequired,
    TargetUnreachable,
)
from .proxy import (
    DIRECT,
    JumpHop,
    JumpSpec,
    ProxyResolver,
    CredentialResolver,
    build_proxy_resolver,
)
from . import emulation
from .emulation import (
    enable_emulation,
    disable_emulation,
    find_ip_for_hostname,
    get_lookup_table,
)

# reachssh-compatible aliases for the emulation state/query functions
emulation_is_enabled = emulation.is_enabled
emulation_lookup = emulation.lookup

__all__ = [
    "SSHClient",
    "SSHClientConfig",
    "LegacySSHSupport",
    "filter_ansi_sequences",
    "PAGINATION_DISABLE_SHOTGUN",
    "SecondFactorRequired",
    "TargetUnreachable",
    "DIRECT",
    "JumpHop",
    "JumpSpec",
    "ProxyResolver",
    "CredentialResolver",
    "build_proxy_resolver",
    "emulation",
    "enable_emulation",
    "disable_emulation",
    "emulation_is_enabled",
    "emulation_lookup",
    "find_ip_for_hostname",
    "get_lookup_table",
]
