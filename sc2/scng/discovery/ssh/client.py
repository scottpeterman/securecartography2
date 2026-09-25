"""
sc2/scng/discovery/ssh/client.py

SSH client - thin re-export layer over the vendored `sc2.scng.reachssh`
package (sourced in-tree from reachssh; see that package's docstring).

Keeping this file as a re-export means every existing `from .client import ...`
and `from sc2.scng.discovery.ssh import ...` keeps working unchanged.

Jump-host usage
---------------
Populate SSHClientConfig.jump with a JumpSpec to reach a device through a
bastion. Build specs with build_proxy_resolver(), which takes a jump-host
registry plus an ordered, first-match-wins rule list and a credential
resolver callable - so bastion secrets are fetched from the vault at call time
rather than stored here.

Note this only tunnels TCP. SNMP is UDP and does not traverse a
'direct-tcpip' channel, so a jump host reaches SSH collection only; full
SNMP discovery still has to run from a host with direct reachability.
"""

from ...reachssh import (
    # Core client - identical API to the previous local implementation
    SSHClient,
    SSHClientConfig,
    LegacySSHSupport,
    filter_ansi_sequences,
    PAGINATION_DISABLE_SHOTGUN,
    # Jump host / bastion
    JumpSpec,
    JumpHop,
    ProxyResolver,
    build_proxy_resolver,
    CredentialResolver,
    DIRECT,
    # Emulation
    enable_emulation,
    disable_emulation,
    emulation_is_enabled,
    emulation_lookup,
    find_ip_for_hostname,
)

# The collector imports this under its pre-extraction name.
lookup_emulation = emulation_lookup

__all__ = [
    "SSHClient",
    "SSHClientConfig",
    "LegacySSHSupport",
    "filter_ansi_sequences",
    "PAGINATION_DISABLE_SHOTGUN",
    "JumpSpec",
    "JumpHop",
    "ProxyResolver",
    "build_proxy_resolver",
    "CredentialResolver",
    "DIRECT",
    "enable_emulation",
    "disable_emulation",
    "emulation_is_enabled",
    "emulation_lookup",
    "lookup_emulation",
    "find_ip_for_hostname",
    "EMULATION_ENABLED",
]


def __getattr__(name: str):
    """
    Back-compat for the module-level EMULATION_ENABLED flag.

    The old implementation exposed a module global that callers read directly
    (engine.py checks it to decide whether to skip real DNS). The emulation module tracks
    the same state behind emulation_is_enabled(), so resolve the attribute on
    access via PEP 562 - a plain assignment here would snapshot the value at
    import time and never reflect a later enable_emulation() call.
    """
    if name == "EMULATION_ENABLED":
        return emulation_is_enabled()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")