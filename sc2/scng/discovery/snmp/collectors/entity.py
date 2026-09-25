"""
sc2/scng/discovery/snmp/collectors/entity.py

SecureCartography NG - ENTITY-MIB Physical Inventory Collector.

Collects asset-grade identity - model name, serial number, hardware/firmware/
software revisions - from the entPhysicalTable (RFC 4133).

Why this exists
---------------
sysObjectID identifies the product line and sysDescr carries the OS string, but
neither reports the serial number, and many platforms omit the specific model
from sysDescr entirely. entPhysicalTable is the standards-track, multi-vendor
source for both, so it fills the gap that OID resolution structurally cannot.

Support is uneven, which is expected rather than an error condition:
  - Most physical Cisco, Arista, Juniper, and Aruba platforms populate it well.
  - Stacked switches expose one chassis entry per stack member.
  - Virtual and emulated platforms (vEOS, IOSv, dynamips) frequently return an
    empty table or omit the serial, since there is no real hardware behind it.
A device that returns nothing sets supported=False and leaves every field None;
callers should treat that as "not available here", not as a failure.

Collection strategy
-------------------
The full table is 16 columns wide and can run to thousands of rows on a large
chassis, so a blind subtree walk is wasteful. Instead:

  1. Walk entPhysicalClass alone (one column) to locate chassis rows.
  2. Issue targeted GETs for just those row indices.

That keeps cost roughly constant regardless of how many line cards, ports, and
sensors the device enumerates.
"""

from typing import Optional, Dict, Any, List

from pysnmp.hlapi.v3arch.asyncio import SnmpEngine

from ...oids import ENTITY
from ..walker import SNMPWalker, AuthData
from ..parsers import decode_string, decode_int


# entPhysicalClass values (ENTITY-MIB PhysicalClass TEXTUAL-CONVENTION).
CLASS_OTHER = 1
CLASS_UNKNOWN = 2
CLASS_CHASSIS = 3
CLASS_BACKPLANE = 4
CLASS_CONTAINER = 5
CLASS_POWER_SUPPLY = 6
CLASS_FAN = 7
CLASS_SENSOR = 8
CLASS_MODULE = 9
CLASS_PORT = 10
CLASS_STACK = 11
CLASS_CPU = 12

CLASS_NAMES = {
    CLASS_OTHER: "other",
    CLASS_UNKNOWN: "unknown",
    CLASS_CHASSIS: "chassis",
    CLASS_BACKPLANE: "backplane",
    CLASS_CONTAINER: "container",
    CLASS_POWER_SUPPLY: "powerSupply",
    CLASS_FAN: "fan",
    CLASS_SENSOR: "sensor",
    CLASS_MODULE: "module",
    CLASS_PORT: "port",
    CLASS_STACK: "stack",
    CLASS_CPU: "cpu",
}

# Columns fetched for each candidate row, in GET order.
_ROW_COLUMNS = (
    ("descr", ENTITY.PHYS_DESCR),
    ("name", ENTITY.PHYS_NAME),
    ("model", ENTITY.PHYS_MODEL_NAME),
    ("serial", ENTITY.PHYS_SERIAL_NUM),
    ("mfg_name", ENTITY.PHYS_MFG_NAME),
    ("hardware_rev", ENTITY.PHYS_HARDWARE_REV),
    ("firmware_rev", ENTITY.PHYS_FIRMWARE_REV),
    ("software_rev", ENTITY.PHYS_SOFTWARE_REV),
    ("contained_in", ENTITY.PHYS_CONTAINED_IN),
)

# Placeholder strings some agents return instead of omitting an empty column.
_NULL_VALUES = {"", "n/a", "na", "none", "unknown", "unspecified", "not applicable", "0"}

# --- Vendor fallback: Juniper -----------------------------------------------
# Junos does not implement ENTITY-MIB on many platforms - the agent returns
# "No Such Object" for the entPhysicalTable base OID rather than an empty table.
# Chassis identity lives in the enterprise jnxBoxAnatomy tree instead.
#
# Verified against JUNIPER-MIB / JUNIPER-SMI:
#   enterprises 2636 -> juniperMIB, juniperMIB 3 -> jnxMibs, jnxMibs 1 -> jnxBoxAnatomy
# These are scalars, so they take a .0 instance suffix.
JNX_BOX_DESCR = "1.3.6.1.4.1.2636.3.1.2.0"     # name/model of the box, e.g. "M40"
JNX_BOX_SERIAL = "1.3.6.1.4.1.2636.3.1.3.0"    # chassis serial, blank if unknown
JNX_BOX_REVISION = "1.3.6.1.4.1.2636.3.1.4.0"  # chassis revision


def _clean(value: Any) -> Optional[str]:
    """
    Decode a string column, mapping agent placeholder values to None.

    Several agents return a literal 'N/A' or a single space rather than an
    empty varbind, which would otherwise be stored as if it were a real serial.
    """
    if value is None:
        return None
    text = decode_string(value)
    if text is None:
        return None
    text = text.strip()
    if not text or text.lower() in _NULL_VALUES:
        return None
    return text


def _index_from_oid(oid: str) -> Optional[int]:
    """Extract the entPhysicalIndex (final sub-identifier) from a walked OID."""
    try:
        return int(oid.rsplit(".", 1)[-1])
    except (ValueError, IndexError):
        return None


async def _try_juniper_fallback(
    walker,
    target: str,
    auth: AuthData,
    result: Dict[str, Any],
    vprint,
) -> Dict[str, Any]:
    """
    Recover chassis identity from jnxBoxAnatomy when ENTITY-MIB is absent.

    Junos commonly returns "No Such Object" for the entPhysicalTable base OID,
    so there is no table to select a chassis row from. The enterprise tree
    carries the same information as three scalars.

    Mutates and returns the caller's result dict. On a non-Juniper device the
    GET simply returns nothing and the result is left untouched.
    """
    vprint("ENTITY-MIB absent; trying jnxBoxAnatomy")
    try:
        values = await walker.get_multiple(
            target, [JNX_BOX_DESCR, JNX_BOX_SERIAL, JNX_BOX_REVISION], auth
        )
    except Exception as e:
        vprint(f"jnxBoxAnatomy GET failed: {e}")
        return result

    descr, serial, revision = (_clean(v) for v in values)
    if not descr and not serial:
        vprint("jnxBoxAnatomy returned nothing")
        return result

    result['supported'] = True
    result['source'] = 'jnx-box-anatomy'
    result['model'] = descr
    result['serial'] = serial
    result['hardware_rev'] = revision
    result['chassis'] = [{
        'index': 0,
        'class': 'chassis',
        'model': descr,
        'serial': serial,
        'hardware_rev': revision,
        'contained_in': 0,
    }]
    result['chassis_count'] = 1
    vprint(f"jnxBoxAnatomy: Model={descr} Serial={serial}")
    return result


async def get_entity_info(
    target: str,
    auth: AuthData,
    engine: Optional[SnmpEngine] = None,
    timeout: float = 5.0,
    verbose: bool = False,
    max_chassis: int = 16,
) -> Dict[str, Any]:
    """
    Collect physical inventory identity from ENTITY-MIB.

    Args:
        target: Device IP address
        auth: SNMP authentication data
        engine: Optional shared SnmpEngine
        timeout: Request timeout
        verbose: Enable debug output
        max_chassis: Cap on rows fetched, so a device that reports an
                     unreasonable number of chassis entries cannot turn this
                     into an unbounded sequence of GETs

    Returns:
        Dict with primary-chassis identity plus the full chassis list:
            supported      bool - device returned usable entPhysical data
            model          str|None - primary chassis entPhysicalModelName
            serial         str|None - primary chassis entPhysicalSerialNum
            hardware_rev   str|None
            firmware_rev   str|None
            software_rev   str|None
            mfg_name       str|None
            chassis_count  int  - >1 indicates a switch stack
            chassis        list - per-chassis dicts, ordered by entPhysicalIndex

    Example:
        info = await get_entity_info("192.0.2.1", auth)
        if info['supported']:
            print(info['model'], info['serial'])
    """
    walker = SNMPWalker(
        engine=engine,
        auth=auth,
        default_timeout=timeout,
        verbose=verbose,
    )

    def _vprint(msg: str):
        if verbose:
            print(f"  [entity] {msg}")

    result: Dict[str, Any] = {
        'supported': False,
        'source': None,   # 'entity-mib' | 'jnx-box-anatomy'
        'model': None,
        'serial': None,
        'hardware_rev': None,
        'firmware_rev': None,
        'software_rev': None,
        'mfg_name': None,
        'chassis_count': 0,
        'chassis': [],
    }

    # --- Phase 1: locate candidate rows via entPhysicalClass ----------------
    _vprint(f"Walking entPhysicalClass: {ENTITY.PHYS_CLASS}")
    try:
        class_rows = await walker.walk(target, ENTITY.PHYS_CLASS, auth)
    except Exception as e:
        _vprint(f"entPhysicalClass walk failed: {e}")
        return await _try_juniper_fallback(walker, target, auth, result, _vprint)

    if not class_rows:
        _vprint("No entPhysical data - device does not support ENTITY-MIB")
        return await _try_juniper_fallback(walker, target, auth, result, _vprint)

    classes: Dict[int, int] = {}
    for oid, value in class_rows:
        idx = _index_from_oid(oid)
        cls = decode_int(value)
        if idx is not None and cls is not None:
            classes[idx] = cls

    _vprint(f"entPhysical rows: {len(classes)}")

    # Prefer real chassis rows. Some agents populate only module entries, so
    # fall back to those rather than reporting nothing.
    candidates = sorted(i for i, c in classes.items() if c == CLASS_CHASSIS)
    fallback_used = False
    if not candidates:
        candidates = sorted(i for i, c in classes.items() if c == CLASS_MODULE)
        fallback_used = bool(candidates)
        if fallback_used:
            _vprint("No chassis rows; falling back to module rows")

    if not candidates:
        _vprint("No chassis or module rows found")
        return await _try_juniper_fallback(walker, target, auth, result, _vprint)

    if len(candidates) > max_chassis:
        _vprint(f"Capping {len(candidates)} candidate rows at {max_chassis}")
        candidates = candidates[:max_chassis]

    # --- Phase 2: targeted GETs for the candidate rows ----------------------
    entries: List[Dict[str, Any]] = []
    for idx in candidates:
        oids = [f"{col_oid}.{idx}" for _, col_oid in _ROW_COLUMNS]
        try:
            values = await walker.get_multiple(target, oids, auth)
        except Exception as e:
            _vprint(f"GET failed for index {idx}: {e}")
            continue

        entry: Dict[str, Any] = {
            'index': idx,
            'class': CLASS_NAMES.get(classes.get(idx, CLASS_UNKNOWN), "unknown"),
        }
        for (field, _), value in zip(_ROW_COLUMNS, values):
            if field == 'contained_in':
                entry[field] = decode_int(value)
            else:
                entry[field] = _clean(value)

        # Older platforms (notably Catalyst) populate the serial but leave
        # entPhysicalModelName blank, carrying the model in descr or name
        # instead. Both are already fetched, so recover it rather than
        # reporting a device with a serial and no model.
        if not entry.get('model'):
            entry['model'] = entry.get('descr') or entry.get('name')

        # A row carrying neither a model nor a serial adds nothing.
        if entry.get('model') or entry.get('serial'):
            entries.append(entry)

    if not entries:
        _vprint("Candidate rows carried no model or serial")
        return await _try_juniper_fallback(walker, target, auth, result, _vprint)

    # Primary chassis: the row contained in nothing (entPhysicalContainedIn 0)
    # is the physical root. Stack members and modules report a parent, so this
    # picks the real chassis rather than whichever row walked first.
    primary = next((e for e in entries if e.get('contained_in') == 0), entries[0])

    result['supported'] = True
    result['source'] = 'entity-mib'
    result['model'] = primary.get('model')
    result['serial'] = primary.get('serial')
    result['hardware_rev'] = primary.get('hardware_rev')
    result['firmware_rev'] = primary.get('firmware_rev')
    result['software_rev'] = primary.get('software_rev')
    result['mfg_name'] = primary.get('mfg_name')
    result['chassis'] = entries
    result['chassis_count'] = len(entries)

    _vprint(
        f"Model={result['model']} Serial={result['serial']} "
        f"entries={len(entries)}{' (module fallback)' if fallback_used else ''}"
    )

    return result