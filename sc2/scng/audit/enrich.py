"""
SCNG Enrich - second-pass full collection over a discovery output folder.

Path: scng/audit/enrich.py

The crawl's job is topology: it collects what it needs to find neighbors and
moves on, and a device reached over SSH comes back with neighbors and little
else. This pass revisits every successfully discovered device and runs the
collection the tool already has, against each device it can reach:

  SNMP  get_system_info / get_interface_table / get_entity_info / get_arp_table
        - only for the pieces a device.json is missing (in practice the
        SSH-discovered devices, and maps written before the ENTITY record
        was kept). Skipped for jump-routed devices: SNMP is UDP and does not
        ride the bastion's TCP channel.

  SSH   the audit collector's per-vendor config + inventory commands, using
        the credential discovery used first, then the vault's other SSH
        credentials, through the same jump-host rules as the crawl. Writes
        config.txt and inventory.txt beside device.json, as `audit collect`
        always has, so `audit report` keeps working on the same folder.

Results are written back into each device.json (so the map viewer's Rebuild
keeps them) and patched into map.json's node metadata in place (so
placeholder nodes and anything else in the crawl's map survive).

Usage:
    from sc2.scng.audit.enrich import DiscoveryEnricher

    enricher = DiscoveryEnricher(vault, concurrency=10)
    summary = asyncio.run(enricher.run("./network_maps/"))
"""

import asyncio
import json
import os
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from ..discovery.models import Device, DiscoveryProtocol
from ..discovery.snmp import (
    get_system_info,
    get_interface_table,
    get_entity_info,
    get_arp_table,
    is_ip_address,
)
from .collector import AuditCollector

# Vault credential types - same multi-path import the engine and collector use
try:
    from scng.creds import CredentialType
except ImportError:
    try:
        from sc2.scng.creds import CredentialType
    except ImportError:
        from ..creds import CredentialType


# Progress callback: receives one dict per event.
#   {"type": "started",  "total": int, "path": str}
#   {"type": "device",   "index": int, "total": int, "name": str,
#                        "ssh": {...}, "snmp": {...}}
#   {"type": "log",      "level": "info|warning|error", "message": str}
#   {"type": "complete", ...EnrichSummary.to_dict()}
EnrichCallback = Callable[[Dict[str, Any]], None]


@dataclass
class EnrichSummary:
    """Totals for one enrichment run."""
    path: str
    devices_total: int = 0
    ssh_ok: int = 0
    ssh_failed: int = 0
    snmp_ok: int = 0
    snmp_failed: int = 0
    snmp_skipped: int = 0
    map_nodes_updated: int = 0
    cancelled: bool = False
    duration_seconds: float = 0.0
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "devices_total": self.devices_total,
            "ssh_ok": self.ssh_ok,
            "ssh_failed": self.ssh_failed,
            "snmp_ok": self.snmp_ok,
            "snmp_failed": self.snmp_failed,
            "snmp_skipped": self.snmp_skipped,
            "map_nodes_updated": self.map_nodes_updated,
            "cancelled": self.cancelled,
            "duration_seconds": self.duration_seconds,
            "errors": list(self.errors),
        }


def _write_json_atomic(path: Path, data: Any) -> None:
    """Write JSON via temp file + replace so a crash never leaves half a file."""
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


class DiscoveryEnricher:
    """
    Second-pass collector over a discovery output folder.

    Args:
        vault: Unlocked CredentialVault.
        concurrency: Devices processed at once.
        ssh_timeout: SSH connect timeout, and the idle-gap timeout for the
                     config/inventory commands (seconds).
        snmp_timeout: SNMP request timeout (seconds).
        legacy_mode: Enable legacy SSH algorithms.
        jump_config: Jump-host YAML; None picks up ~/.seccart2/jump_hosts.yaml
                     when it exists, exactly as the crawl does.
        do_ssh / do_snmp: Enable each half of the pass.
        verbose: Engine/collector debug output.
        callback: Progress callback (see EnrichCallback).
    """

    def __init__(
        self,
        vault,
        concurrency: int = 10,
        ssh_timeout: int = 30,
        snmp_timeout: float = 5.0,
        legacy_mode: bool = True,
        jump_config: Optional[Path] = None,
        do_ssh: bool = True,
        do_snmp: bool = True,
        verbose: bool = False,
        callback: Optional[EnrichCallback] = None,
    ):
        self.vault = vault
        self.concurrency = max(1, int(concurrency))
        self.ssh_timeout = int(ssh_timeout)
        self.snmp_timeout = float(snmp_timeout)
        self.legacy_mode = legacy_mode
        self.jump_config = jump_config
        self.do_ssh = do_ssh
        self.do_snmp = do_snmp
        self.verbose = verbose
        self.callback = callback

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------

    def _emit(self, event: Dict[str, Any]) -> None:
        if self.callback:
            try:
                self.callback(event)
            except Exception:
                pass

    def _log(self, message: str, level: str = "info") -> None:
        self._emit({"type": "log", "level": level, "message": message})

    # ------------------------------------------------------------------
    # Run
    # ------------------------------------------------------------------

    async def run(
        self,
        discovery_path,
        devices: Optional[List[str]] = None,
        cancel_event: Optional[asyncio.Event] = None,
    ) -> EnrichSummary:
        """
        Enrich every successfully discovered device under discovery_path.

        Args:
            discovery_path: Discovery output folder (holds <device>/device.json
                            and map.json).
            devices: Optional folder names to limit the pass to.
            cancel_event: Set to stop; in-flight devices are abandoned (their
                          device.json is left as it was) and map.json is
                          still patched from what completed.
        """
        # Engine import is deferred: it pulls in pysnmp and the jump resolver,
        # and the engine instance is only a provider of its existing
        # credential, jump-routing and SNMP plumbing here.
        from ..discovery.engine import DiscoveryEngine

        start = time.time()
        root = Path(discovery_path)
        summary = EnrichSummary(path=str(root))

        if not root.is_dir():
            raise ValueError(f"Discovery path not found: {root}")

        engine = DiscoveryEngine(
            vault=self.vault,
            default_timeout=self.snmp_timeout,
            verbose=self.verbose,
            max_concurrent=self.concurrency,
            jump_config=self.jump_config,
        )
        audit = AuditCollector(
            self.vault, timeout=self.ssh_timeout, legacy_mode=self.legacy_mode
        )

        folders = sorted(p.parent for p in root.glob("*/device.json"))
        if devices:
            wanted = set(devices)
            folders = [f for f in folders if f.name in wanted]

        loaded: List[tuple] = []
        for folder in folders:
            try:
                with open(folder / "device.json", encoding="utf-8") as f:
                    data = json.load(f)
                device = Device.from_dict(data)
            except Exception as e:
                summary.errors.append(f"{folder.name}: device.json unreadable: {e}")
                continue
            if not device.discovery_success or not device.ip_address:
                continue
            loaded.append((folder, device))

        summary.devices_total = len(loaded)
        self._emit({"type": "started", "total": len(loaded), "path": str(root)})
        if engine.proxy_resolver is not None:
            self._log("Jump-host routing active - routed devices get SSH collection only")

        sem = asyncio.Semaphore(self.concurrency)
        done = 0
        enriched: Dict[str, Device] = {}

        async def one(folder: Path, device: Device):
            nonlocal done
            async with sem:
                if cancel_event is not None and cancel_event.is_set():
                    return
                record = await self._enrich_device(engine, audit, folder, device)
                device.enrichment = record
                try:
                    _write_json_atomic(folder / "device.json", device.to_dict())
                except Exception as e:
                    summary.errors.append(f"{folder.name}: write failed: {e}")
                enriched[folder.name] = device

                ssh, snmp = record.get("ssh", {}), record.get("snmp", {})
                if ssh.get("status") == "ok":
                    summary.ssh_ok += 1
                elif ssh.get("status") not in (None, "disabled"):
                    summary.ssh_failed += 1
                if snmp.get("status") == "ok":
                    summary.snmp_ok += 1
                elif snmp.get("status") in ("not-needed", "skipped-jump", "disabled"):
                    summary.snmp_skipped += 1
                elif snmp.get("status"):
                    summary.snmp_failed += 1

                done += 1
                self._emit({
                    "type": "device", "index": done, "total": len(loaded),
                    "name": folder.name, "ssh": ssh, "snmp": snmp,
                })

        tasks = [asyncio.ensure_future(one(f, d)) for f, d in loaded]
        try:
            gathered = asyncio.gather(*tasks, return_exceptions=True)
            if cancel_event is not None:
                cancel_wait = asyncio.ensure_future(cancel_event.wait())
                await asyncio.wait({gathered, cancel_wait},
                                   return_when=asyncio.FIRST_COMPLETED)
                if not gathered.done():
                    # Abandon in-flight devices; their device.json is only
                    # written on completion, so nothing is left half-updated.
                    for t in tasks:
                        t.cancel()
                cancel_wait.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        finally:
            engine._executor.shutdown(wait=False, cancel_futures=True)
            # Stop pysnmp's dispatcher timer so closing the loop is clean
            close = getattr(engine.snmp_engine, "close_dispatcher", None)
            if callable(close):
                try:
                    close()
                except Exception:
                    pass

        summary.cancelled = bool(cancel_event is not None and cancel_event.is_set())

        # Patch map.json from every device on disk, not just this run's -
        # a --devices subset still leaves the map consistent.
        try:
            summary.map_nodes_updated = self._patch_map(root, engine)
        except Exception as e:
            summary.errors.append(f"map.json update failed: {e}")

        summary.duration_seconds = time.time() - start
        self._emit({"type": "complete", **summary.to_dict()})
        return summary

    # ------------------------------------------------------------------
    # Per device
    # ------------------------------------------------------------------

    async def _enrich_device(self, engine, audit: AuditCollector,
                             folder: Path, device: Device) -> Dict[str, Any]:
        """Run SNMP then SSH collection for one device; return its record."""
        record: Dict[str, Any] = {"collected_at": datetime.now().isoformat()}

        name_hint = device.hostname if not is_ip_address(device.hostname) else (
            device.sys_name or None)
        try:
            jump = engine._jump_for(name_hint, device.ip_address)
        except Exception as e:
            record["ssh"] = {"status": "error", "errors": [f"Jump-host resolution failed: {e}"]}
            record["snmp"] = {"status": "error", "errors": [f"Jump-host resolution failed: {e}"]}
            return record

        # SNMP first: cheap, and SSH can then be judged on its own.
        if not self.do_snmp:
            record["snmp"] = {"status": "disabled"}
        else:
            record["snmp"] = await self._snmp_pass(engine, device, jump)

        if not self.do_ssh:
            record["ssh"] = {"status": "disabled"}
        else:
            record["ssh"] = await self._ssh_pass(engine, audit, folder, device, jump)

        return record

    async def _snmp_pass(self, engine, device: Device, jump) -> Dict[str, Any]:
        missing = []
        if not device.interfaces:
            missing.append("interfaces")
        if not device.entity:
            missing.append("entity")
        if not device.arp_table:
            missing.append("arp")
        if not missing:
            return {"status": "not-needed"}
        if jump:
            return {"status": "skipped-jump", "missing": missing,
                    "note": "SNMP does not traverse the jump host"}

        auth, cred_name = await self._snmp_auth(engine, device)
        if auth is None:
            return {"status": "no-credential", "missing": missing,
                    "errors": ["No SNMP credential answered"]}

        ip = device.ip_address
        t = engine.default_timeout
        collected: List[str] = []
        errors: List[str] = []

        # System group - fill gaps only. sys_descr is left alone on SSH
        # devices: it holds the clean tfsm-parsed platform string the map
        # uses as the node's platform.
        if device.discovered_via != DiscoveryProtocol.SNMP:
            try:
                info = await get_system_info(ip, auth, engine.snmp_engine, timeout=t,
                                             verbose=self.verbose)
                for attr in ("sys_location", "sys_contact", "sys_object_id", "uptime_ticks"):
                    if getattr(device, attr) in (None, "") and info.get(attr) not in (None, ""):
                        setattr(device, attr, info.get(attr))
                if not device.sys_descr and info.get("sys_descr"):
                    device.sys_descr = info.get("sys_descr")
                collected.append("system")
            except Exception as e:
                errors.append(f"System info failed: {e}")

        if "interfaces" in missing:
            try:
                table = await get_interface_table(ip, auth, engine.snmp_engine, timeout=t,
                                                  verbose=self.verbose)
                if table:
                    device.interfaces = list(table.values())
                    collected.append("interfaces")
            except Exception as e:
                errors.append(f"Interface collection failed: {e}")

        if "entity" in missing:
            try:
                info = await get_entity_info(ip, auth, engine.snmp_engine, timeout=t,
                                             verbose=self.verbose)
                if info.get("supported"):
                    device.entity = info
                    if info.get("model") and not device.model:
                        device.model = info["model"]
                    if info.get("serial") and not device.serial:
                        device.serial = info["serial"]
                    if info.get("software_rev") and not device.os_version:
                        device.os_version = info["software_rev"]
                    collected.append("entity")
            except Exception as e:
                errors.append(f"Entity collection failed: {e}")

        if "arp" in missing:
            try:
                arp = await get_arp_table(ip, auth, engine.snmp_engine, timeout=t,
                                          verbose=self.verbose)
                if arp:
                    device.arp_table = arp
                    collected.append("arp")
            except Exception as e:
                errors.append(f"ARP collection failed: {e}")

        return {
            "status": "ok" if collected else "error",
            "credential": cred_name,
            "collected": collected,
            "missing": [m for m in missing if m not in collected],
            "errors": errors,
        }

    async def _snmp_auth(self, engine, device: Device):
        """
        SNMP auth for a device: the credential discovery used when that was
        SNMP, else the first vault SNMP credential that answers sysName.
        """
        vault = self.vault
        if device.discovered_via == DiscoveryProtocol.SNMP and device.credential_used:
            info = vault.get_credential_info(name=device.credential_used)
            if info:
                cred = None
                if info.credential_type == CredentialType.SNMP_V2C:
                    cred = vault.get_snmpv2c_credential(name=device.credential_used)
                elif info.credential_type == CredentialType.SNMP_V3:
                    cred = vault.get_snmpv3_credential(name=device.credential_used)
                auth = engine._build_auth(cred) if cred else None
                if auth is not None:
                    return auth, device.credential_used

        for c in vault.list_credentials():
            cred = None
            if c.credential_type == CredentialType.SNMP_V2C:
                cred = vault.get_snmpv2c_credential(name=c.name)
            elif c.credential_type == CredentialType.SNMP_V3:
                cred = vault.get_snmpv3_credential(name=c.name)
            if not cred:
                continue
            auth = engine._build_auth(cred)
            if auth is not None and await engine._test_snmp_credential(
                    device.ip_address, c.name, auth):
                return auth, c.name
        return None, None

    async def _ssh_pass(self, engine, audit: AuditCollector, folder: Path,
                        device: Device, jump) -> Dict[str, Any]:
        names = audit._ssh_credential_names(preferred=device.credential_used)
        if not names:
            return {"status": "no-credential", "errors": ["No SSH credentials in vault"]}

        loop = asyncio.get_running_loop()
        vendor = device.vendor.value if device.vendor else "unknown"
        try:
            result = await loop.run_in_executor(
                engine._executor,
                lambda: audit._audit_device(
                    hostname=folder.name,
                    ip_address=device.ip_address,
                    vendor=vendor,
                    output_folder=folder,
                    debug=self.verbose,
                    credential_names=names,
                    jump=jump,
                ),
            )
        except Exception as e:
            return {"status": "error", "errors": [f"SSH collection failed: {e}"]}

        return {
            "status": "ok" if result.success else "error",
            "credential": result.credential_used,
            "jump_via": result.jump_via,
            "config_file": result.config_file,
            "config_bytes": result.config_size,
            "inventory_file": result.inventory_file,
            "inventory_bytes": result.inventory_size,
            "duration_ms": round(result.duration_ms),
            "errors": list(result.errors),
        }

    # ------------------------------------------------------------------
    # map.json
    # ------------------------------------------------------------------

    def _patch_map(self, root: Path, engine) -> int:
        """
        Refresh node_details.metadata (and empty identity fields) in map.json
        from the device.json files. Everything else in the map is left as the
        crawl wrote it. Returns the number of nodes updated.
        """
        map_file = root / "map.json"
        if not map_file.exists():
            return 0
        with open(map_file, encoding="utf-8") as f:
            topology = json.load(f)
        if not isinstance(topology, dict):
            return 0

        index: Dict[str, Device] = {}
        for path in root.glob("*/device.json"):
            try:
                with open(path, encoding="utf-8") as f:
                    dev = Device.from_dict(json.load(f))
            except Exception:
                continue
            if not dev.discovery_success:
                continue
            # Same identity precedence the map generator uses for node keys
            for key in (dev.sys_name, dev.hostname, dev.ip_address):
                if key and key not in index:
                    index[key] = dev

        updated = 0
        for node_name, node in topology.items():
            if not isinstance(node, dict):
                continue
            details = node.get("node_details")
            if not isinstance(details, dict):
                continue
            meta = details.get("metadata") or {}
            dev = (index.get(node_name)
                   or index.get(meta.get("sys_name") or "")
                   or index.get(details.get("ip") or ""))
            if dev is None:
                continue
            details["metadata"] = engine._build_node_metadata(dev)
            for key, value in (("model", dev.model), ("serial", dev.serial),
                               ("os_version", dev.os_version)):
                if value and not details.get(key):
                    details[key] = value
            updated += 1

        _write_json_atomic(map_file, topology)
        return updated


def enrich_discovery(
    discovery_path,
    vault,
    concurrency: int = 10,
    **kwargs,
) -> EnrichSummary:
    """Synchronous convenience wrapper around DiscoveryEnricher.run()."""
    devices = kwargs.pop("devices", None)
    enricher = DiscoveryEnricher(vault, concurrency=concurrency, **kwargs)
    return asyncio.run(enricher.run(discovery_path, devices=devices))
