"""
sc2/scng/discovery/snmp/collectors/system.py

SecureCartography NG - System Info Collector.

Collects system MIB information (sysDescr, sysName, etc.).
"""

import asyncio
import ipaddress
import socket
from typing import Optional, Dict, Any

from pysnmp.hlapi.v3arch.asyncio import SnmpEngine

from ...oids import SYSTEM
from ...models import DeviceVendor
from ...sysobjectid import resolve as resolve_sys_object_id
from ..walker import SNMPWalker, AuthData
from ..parsers import decode_string, decode_int, detect_vendor


def decode_oid(value) -> Optional[str]:
    """
    Render an SNMP OID value as bare numeric dotted form.

    decode_string() routes through prettyPrint(), which resolves the OID against
    any loaded MIB and yields symbolic output such as
    'SNMPv2-SMI::enterprises.9.1.222'. That is fine for display but useless as a
    lookup key, so prefer the pysnmp tuple form when it is available and fall
    back to the string decoder otherwise.
    """
    if value is None:
        return None
    as_tuple = getattr(value, "asTuple", None)
    if callable(as_tuple):
        try:
            return ".".join(str(part) for part in as_tuple())
        except Exception:
            pass
    return decode_string(value)


# 100.64.0.0/10 - RFC 6598 shared address space (CGNAT). Addresses here are
# ambiguous across contexts, so when a target lands in this range we attempt a
# name lookup to recover a stable identifier rather than keying on the raw IP.
_CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")


def is_cgnat(ip: str) -> bool:
    """True if ip is in the RFC 6598 CGNAT shared range (100.64.0.0/10)."""
    try:
        return ipaddress.ip_address(ip) in _CGNAT_NET
    except ValueError:
        return False


async def resolve_cgnat_name(ip: str, timeout: float = 2.0) -> Optional[str]:
    """
    For a CGNAT target, attempt a name lookup via the socket library.

    We start from an address, so this is a reverse lookup (gethostbyaddr); the
    blocking call is pushed to a thread so the async discovery loop is not
    stalled, and failures are swallowed (returns None) to stay non-fatal.
    """
    def _lookup() -> Optional[str]:
        old = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            return None
        finally:
            socket.setdefaulttimeout(old)

    return await asyncio.get_event_loop().run_in_executor(None, _lookup)


async def get_system_info(
    target: str,
    auth: AuthData,
    engine: Optional[SnmpEngine] = None,
    timeout: float = 5.0,
    verbose: bool = False,
) -> Dict[str, Any]:
    """
    Get system MIB information from device.

    Queries SNMPv2-MIB system group for basic device information.

    Args:
        target: Device IP address
        auth: SNMP authentication data
        engine: Optional shared SnmpEngine
        timeout: Request timeout
        verbose: Enable debug output

    Returns:
        Dictionary with keys:
            - sys_descr: System description
            - sys_name: System name
            - sys_location: Physical location
            - sys_contact: Contact person
            - sys_object_id: Vendor OID
            - uptime_ticks: Uptime in hundredths of seconds
            - vendor: Detected DeviceVendor enum

    Example:
        info = await get_system_info("192.168.1.1", CommunityData("public"))
        print(f"Device: {info['sys_name']} ({info['vendor']})")
    """
    walker = SNMPWalker(
        engine=engine,
        auth=auth,
        default_timeout=timeout,
        verbose=verbose
    )

    # Get all system scalars in one request
    oids = [
        SYSTEM.SYS_DESCR,
        SYSTEM.SYS_NAME,
        SYSTEM.SYS_LOCATION,
        SYSTEM.SYS_CONTACT,
        SYSTEM.SYS_OBJECT_ID,
        SYSTEM.SYS_UPTIME,
    ]

    values = await walker.get_multiple(target, oids, auth)

    result = {
        'sys_descr': None,
        'sys_name': None,
        'sys_location': None,
        'sys_contact': None,
        'sys_object_id': None,
        'uptime_ticks': None,
        'vendor': DeviceVendor.UNKNOWN,
        'vendor_name': None,      # free-text vendor (covers non-enum vendors)
        'model': None,            # populated on a model-level sysObjectID hit
        'os_family': None,        # deterministic OS where sysObjectID allows
        'vendor_source': None,    # 'sysobjectid' | 'sysdescr' | None
        'resolved_name': None,    # reverse-DNS name when target is CGNAT
    }

    if values[0]:
        result['sys_descr'] = decode_string(values[0])
        result['vendor'] = detect_vendor(result['sys_descr'])

    if values[1]:
        result['sys_name'] = decode_string(values[1])

    if values[2]:
        result['sys_location'] = decode_string(values[2])

    if values[3]:
        result['sys_contact'] = decode_string(values[3])

    if values[4]:
        result['sys_object_id'] = decode_oid(values[4])

    if values[5]:
        result['uptime_ticks'] = decode_int(values[5])

    # Baseline vendor came from the free-text sysDescr regex above. sysObjectID
    # is a structured, vendor-assigned identity, so it takes precedence when it
    # resolves - and it also yields model / os_family that sysDescr often omits.
    if result['sys_descr'] and result['vendor'] != DeviceVendor.UNKNOWN:
        result['vendor_source'] = 'sysdescr'

    oid_match = resolve_sys_object_id(result['sys_object_id'])
    if oid_match.is_match:
        if oid_match.vendor != DeviceVendor.UNKNOWN:
            result['vendor'] = oid_match.vendor
        result['vendor_name'] = oid_match.vendor_name
        if oid_match.model:
            result['model'] = oid_match.model
        if oid_match.os_family:
            result['os_family'] = oid_match.os_family
        result['vendor_source'] = 'sysobjectid'

    # RFC 6598 CGNAT targets are ambiguous; recover a stable name if we can.
    if is_cgnat(target):
        result['resolved_name'] = await resolve_cgnat_name(target)

    return result


async def get_sys_name(
    target: str,
    auth: AuthData,
    engine: Optional[SnmpEngine] = None,
    timeout: float = 3.0,
) -> Optional[str]:
    """
    Quick sysName lookup.

    Used for resolving IP addresses to hostnames during discovery.
    """
    walker = SNMPWalker(engine=engine, auth=auth, default_timeout=timeout)
    value = await walker.get(target, SYSTEM.SYS_NAME, auth)

    if value:
        return decode_string(value)
    return None


async def get_sys_descr(
    target: str,
    auth: AuthData,
    engine: Optional[SnmpEngine] = None,
    timeout: float = 3.0,
) -> Optional[str]:
    """
    Quick sysDescr lookup.

    Used for vendor detection during discovery.
    """
    walker = SNMPWalker(engine=engine, auth=auth, default_timeout=timeout)
    value = await walker.get(target, SYSTEM.SYS_DESCR, auth)

    if value:
        return decode_string(value)
    return None


async def detect_device_vendor(
    target: str,
    auth: AuthData,
    engine: Optional[SnmpEngine] = None,
    timeout: float = 3.0,
) -> tuple[DeviceVendor, Optional[str]]:
    """
    Detect device vendor from sysDescr.

    Returns:
        Tuple of (DeviceVendor, sysDescr string or None)
    """
    sys_descr = await get_sys_descr(target, auth, engine, timeout)
    vendor = detect_vendor(sys_descr)
    return vendor, sys_descr