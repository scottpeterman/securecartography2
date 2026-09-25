"""
sc2/scng/discovery/sysobjectid.py

SecureCartography NG - sysObjectID Resolver.

Deterministic device identity from SNMPv2-MIB sysObjectID.0 (1.3.6.1.2.1.1.2.0).

Why this exists
---------------
sysDescr is a free-text string. It can be truncated, localized, rebranded by
an OEM, or stripped by policy, which makes regex matching against it fragile.
sysObjectID is a structured OID rooted in the vendor's IANA Private Enterprise
Number (1.3.6.1.4.1.<PEN>...). It is assigned by the vendor and does not change
with cosmetic config, so it is a far more reliable identity key.

Resolution strategy
-------------------
Longest-prefix match against a registry of enterprise / product OID prefixes:

  1.3.6.1.4.1.2636.1.1.1.2.29   -> most specific model entry wins
  1.3.6.1.4.1.2636              -> falls back to vendor-level entry

The registry returns an enum vendor where one exists (so existing callers keep
working), plus a free-text vendor_name, model, and os_family so vendors outside
the enum still yield useful identity instead of UNKNOWN.

The model table below is intentionally a small, verifiable seed. Extend it from
an authoritative source (e.g. CISCO-PRODUCTS-MIB entries under .9.1, or a Recog
sysobjid pattern set) rather than guessing OID->model mappings, since a wrong
mapping silently mislabels a device.

This module performs no network I/O and is safe to unit test in isolation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional

from .models import DeviceVendor


@dataclass(frozen=True)
class SysObjectIDResult:
    """Outcome of resolving a sysObjectID."""
    vendor: DeviceVendor = DeviceVendor.UNKNOWN  # enum, for existing callers
    vendor_name: Optional[str] = None            # human string, always set on a hit
    model: Optional[str] = None                  # populated for model-level hits
    os_family: Optional[str] = None              # deterministic OS where unambiguous
    matched_prefix: Optional[str] = None         # the registry prefix that matched
    specificity: int = 0                         # OID node count of the match (0 = miss)

    @property
    def is_match(self) -> bool:
        return self.specificity > 0


@dataclass(frozen=True)
class _Entry:
    vendor: DeviceVendor
    vendor_name: str
    os_family: Optional[str] = None
    model: Optional[str] = None


# =============================================================================
# Vendor-level registry, keyed by enterprise OID prefix (1.3.6.1.4.1.<PEN>).
#
# os_family is only set where a single PEN maps to a single OS. Cisco (PEN 9)
# spans IOS / IOS-XE / NX-OS / IOS-XR, so its os_family stays None and must be
# disambiguated by a model-level entry or by sysDescr downstream.
# =============================================================================
_VENDOR_REGISTRY: Dict[str, _Entry] = {
    "1.3.6.1.4.1.9":     _Entry(DeviceVendor.CISCO,    "Cisco"),
    "1.3.6.1.4.1.2636":  _Entry(DeviceVendor.JUNIPER,  "Juniper Networks", "JUNOS"),
    "1.3.6.1.4.1.30065": _Entry(DeviceVendor.ARISTA,   "Arista Networks",  "EOS"),
    "1.3.6.1.4.1.25461": _Entry(DeviceVendor.PALOALTO, "Palo Alto Networks", "PAN-OS"),
    "1.3.6.1.4.1.12356": _Entry(DeviceVendor.FORTINET, "Fortinet",         "FortiOS"),
    "1.3.6.1.4.1.2011":  _Entry(DeviceVendor.HUAWEI,   "Huawei",           "VRP"),
    "1.3.6.1.4.1.11":    _Entry(DeviceVendor.HP,       "HP/HPE"),
    "1.3.6.1.4.1.8072":  _Entry(DeviceVendor.LINUX,    "net-snmp (host)"),
    # Vendors outside the enum still resolve to useful identity via vendor_name.
    "1.3.6.1.4.1.674":   _Entry(DeviceVendor.UNKNOWN,  "Dell"),
    "1.3.6.1.4.1.14988": _Entry(DeviceVendor.UNKNOWN,  "MikroTik",   "RouterOS"),
    "1.3.6.1.4.1.6527":  _Entry(DeviceVendor.UNKNOWN,  "Nokia",      "SR OS"),
    "1.3.6.1.4.1.40310": _Entry(DeviceVendor.UNKNOWN,  "Cumulus",    "Cumulus Linux"),
    "1.3.6.1.4.1.14823": _Entry(DeviceVendor.UNKNOWN,  "Aruba"),
    "1.3.6.1.4.1.1916":  _Entry(DeviceVendor.UNKNOWN,  "Extreme Networks"),
    "1.3.6.1.4.1.41112": _Entry(DeviceVendor.UNKNOWN,  "Ubiquiti"),
}

# =============================================================================
# Model-level seed entries (longest-prefix wins over vendor-level above).
#
# Keep these authoritative. Each entry should come from the vendor's product
# MIB, not from inference. This is a starting set to extend, not a full DB.
# =============================================================================
_MODEL_REGISTRY: Dict[str, _Entry] = {
    # Cisco Nexus family lives under CISCO-PRODUCTS with NX-OS, which lets us
    # pin the OS family that the bare PEN 9 entry cannot.
    "1.3.6.1.4.1.9.12.3": _Entry(DeviceVendor.CISCO, "Cisco", "NX-OS"),
}

# Merged view used at resolve time.
_REGISTRY: Dict[str, _Entry] = {**_VENDOR_REGISTRY, **_MODEL_REGISTRY}


def _normalize(sys_object_id: str) -> str:
    """
    Reduce a sysObjectID to bare numeric dotted form.

    pysnmp renders an OID through the MIB when one is loaded, so the same value
    can arrive in several shapes depending on how it was decoded:

        1.3.6.1.4.1.9.1.222              already numeric
        .1.3.6.1.4.1.9.1.222             leading dot
        SNMPv2-SMI::enterprises.9.1.222  MIB-symbolic (pysnmp prettyPrint)
        enterprises.9.1.222              bare symbolic
        iso.3.6.1.4.1.9.1.222            net-snmp style

    All of the above normalize to 1.3.6.1.4.1.9.1.222 so prefix matching works
    regardless of which decoder produced the string.
    """
    oid = sys_object_id.strip()

    # Drop any MIB module qualifier, e.g. "SNMPv2-SMI::enterprises.9.1.222".
    if "::" in oid:
        oid = oid.split("::", 1)[1]

    if oid.startswith("."):
        oid = oid[1:]

    # Expand well-known symbolic roots to their numeric equivalents. The more
    # qualified form is checked first so it is not missed by a shorter variant.
    for symbol, numeric in (
        ("private.enterprises.", "1.3.6.1.4.1."),
        ("enterprises.", "1.3.6.1.4.1."),
        ("mib-2.", "1.3.6.1.2.1."),
        ("iso.", "1."),
    ):
        if oid.startswith(symbol):
            oid = numeric + oid[len(symbol):]
            break

    return oid


def resolve(sys_object_id: Optional[str]) -> SysObjectIDResult:
    """
    Resolve a sysObjectID to vendor / model / OS via longest-prefix match.

    Returns an empty (is_match == False) result on None, empty input, or no hit,
    so callers can cleanly fall back to sysDescr-based detection.

    Examples:
        >>> resolve("1.3.6.1.4.1.30065.1.3011.7048").vendor
        <DeviceVendor.ARISTA: 'arista'>
        >>> resolve("1.3.6.1.4.1.9.12.3.1.3.1234").os_family
        'NX-OS'
        >>> resolve("1.3.6.1.4.1.14988.2").vendor_name
        'MikroTik'
        >>> resolve(None).is_match
        False
    """
    if not sys_object_id:
        return SysObjectIDResult()

    oid = _normalize(sys_object_id)
    if not oid:
        return SysObjectIDResult()

    best_prefix: Optional[str] = None
    best_len = -1
    for prefix in _REGISTRY:
        if oid == prefix or oid.startswith(prefix + "."):
            plen = prefix.count(".") + 1
            if plen > best_len:
                best_prefix, best_len = prefix, plen

    if best_prefix is None:
        return SysObjectIDResult()

    entry = _REGISTRY[best_prefix]
    return SysObjectIDResult(
        vendor=entry.vendor,
        vendor_name=entry.vendor_name,
        model=entry.model,
        os_family=entry.os_family,
        matched_prefix=best_prefix,
        specificity=best_len,
    )


if __name__ == "__main__":
    # Lab-safe smoke test. Run: python -m sc2.scng.discovery.sysobjectid
    _cases = [
        ("1.3.6.1.4.1.30065.1.3011.7048", DeviceVendor.ARISTA, "EOS"),
        ("1.3.6.1.4.1.2636.1.1.1.2.29",   DeviceVendor.JUNIPER, "JUNOS"),
        ("1.3.6.1.4.1.9.1.516",           DeviceVendor.CISCO,   None),
        ("1.3.6.1.4.1.9.12.3.1.3.1234",   DeviceVendor.CISCO,   "NX-OS"),
        ("1.3.6.1.4.1.14988.2",           DeviceVendor.UNKNOWN, "RouterOS"),
        (".1.3.6.1.4.1.25461.2.3.18",     DeviceVendor.PALOALTO, "PAN-OS"),
        # Symbolic renderings - pysnmp resolves the OID through the MIB when one
        # is loaded, so these are what actually come off the wire in practice.
        ("SNMPv2-SMI::enterprises.9.1.222", DeviceVendor.CISCO, None),
        ("enterprises.30065.1.3011.7048",   DeviceVendor.ARISTA, "EOS"),
        ("iso.3.6.1.4.1.2636.1.1.1.2.29",   DeviceVendor.JUNIPER, "JUNOS"),
        ("1.3.6.1.2.1.1.2.0",             DeviceVendor.UNKNOWN, None),  # miss
        (None,                            DeviceVendor.UNKNOWN, None),
    ]
    failures = 0
    for oid, want_vendor, want_os in _cases:
        r = resolve(oid)
        ok = r.vendor == want_vendor and r.os_family == want_os
        failures += 0 if ok else 1
        flag = "ok " if ok else "FAIL"
        print(f"[{flag}] {str(oid):32} -> vendor={r.vendor.value:8} "
              f"name={r.vendor_name} model={r.model} os={r.os_family} "
              f"(prefix={r.matched_prefix}, spec={r.specificity})")
    print(f"\n{len(_cases) - failures}/{len(_cases)} passed")
    raise SystemExit(1 if failures else 0)