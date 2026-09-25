"""
SCNG SSH Collector - SSH-based neighbor discovery.

Path: scng/discovery/ssh/collector.py

Collects CDP/LLDP neighbor information via SSH when SNMP fails or
lacks neighbor data. Uses TextFSM templates for multi-vendor parsing.

Integrated with scng.creds for credential management.
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Tuple

from ..models import (
    Neighbor, NeighborProtocol, DeviceVendor,
)
from .client import SSHClient, SSHClientConfig, lookup_emulation, find_ip_for_hostname
from . import client as _ssh_client
from .parsers import TextFSMParser, ParseResult

logger = logging.getLogger(__name__)


# =============================================================================
# Vendor-specific command definitions
# =============================================================================

@dataclass
class VendorCommands:
    """Commands and templates for a specific vendor."""
    cdp_command: Optional[str] = None
    cdp_template: Optional[str] = None
    lldp_command: Optional[str] = None
    lldp_template: Optional[str] = None
    # Tried when lldp_command is rejected (older OS releases lack "detail")
    lldp_fallback_command: Optional[str] = None
    lldp_fallback_template: Optional[str] = None
    system_command: Optional[str] = None
    version_template: Optional[str] = None
    interfaces_command: Optional[str] = None

from ..snmp.collectors.lldp import _looks_like_interface


VENDOR_COMMANDS: Dict[DeviceVendor, VendorCommands] = {
    DeviceVendor.CISCO: VendorCommands(
        cdp_command="show cdp neighbors detail",
        cdp_template="cisco_ios_show_cdp_neighbors_detail",
        lldp_command="show lldp neighbors detail",
        lldp_template="lldp",
        system_command="show version",
        version_template="show_version",
        interfaces_command="show interfaces description",
    ),
    DeviceVendor.ARISTA: VendorCommands(
        lldp_command="show lldp neighbors detail",
        lldp_template="lldp",
        system_command="show version",
        version_template="arista_eos_show_version",
        interfaces_command="show interfaces description",
    ),
    DeviceVendor.JUNIPER: VendorCommands(
        # "| no-more" on every Junos command: a session can come up paging
        # (e.g. after an RE hop), and keystrokes typed into the pager are pager
        # commands - "s" saves the output to a FILE ON THE ROUTER.
        lldp_command="show lldp neighbors detail | no-more",
        lldp_template="juniper_junos_show_lldp_neighbors_detail",
        # Junos 14.x/15.x (e.g. QFX5100 14.1X53) reject "detail" with a
        # syntax error. The summary still gives names and ports, though no
        # management address or system description.
        lldp_fallback_command="show lldp neighbors | no-more",
        lldp_fallback_template="juniper_junos_show_lldp_neighbors",
        system_command="show version | no-more",
        version_template="juniper_junos_show_version",
        interfaces_command="show interfaces descriptions",
    ),
    DeviceVendor.LINUX: VendorCommands(
        lldp_command="lldpcli show neighbors detail",
        lldp_template="linux_lldpcli_show_neighbors_detail",
        system_command="uname -a",
        interfaces_command="ip link show",
    ),
    # Add more vendors as needed
}

# Fallback for unknown vendors
DEFAULT_COMMANDS = VendorCommands(
    lldp_command="show lldp neighbors detail",
    system_command="show version",
)


def detect_vendor_from_output(output: str) -> DeviceVendor:
    """Detect vendor from CLI output (show version or uname -a)."""
    output_lower = output.lower()

    patterns = {
        DeviceVendor.CISCO: ['cisco', 'ios', 'nx-os', 'asa'],
        DeviceVendor.ARISTA: ['arista', 'eos'],
        DeviceVendor.JUNIPER: ['juniper', 'junos', 'srx', 'qfx'],
        DeviceVendor.PALOALTO: ['palo alto', 'pan-os'],
        DeviceVendor.FORTINET: ['fortinet', 'fortigate', 'fortios'],
        DeviceVendor.HUAWEI: ['huawei', 'vrp'],
        DeviceVendor.HP: ['hewlett', 'procurve', 'aruba', 'comware'],
        DeviceVendor.LINUX: ['linux', 'ubuntu', 'debian', 'centos', 'red hat', 'rhel', 'fedora', 'rocky', 'gnu/linux'],
    }

    for vendor, keywords in patterns.items():
        if any(kw in output_lower for kw in keywords):
            return vendor

    return DeviceVendor.UNKNOWN


# Minimum tfsm_fire confidence for a `show version` parse to be trusted.
# Below this the template matched structurally but poorly, and the extracted
# platform/version/serial are more likely wrong than useful.
MIN_VERSION_PARSE_SCORE = 30.0


@dataclass
class SSHCollectorResult:
    """Result of SSH collection."""
    success: bool
    neighbors: List[Neighbor]
    vendor: DeviceVendor
    hostname: Optional[str] = None  # Extracted from prompt
    platform: Optional[str] = None  # Parsed from show version (e.g., "N9K-C9396PX")
    version: Optional[str] = None   # Parsed from show version (e.g., "9.3(11)")
    serial: Optional[str] = None    # Parsed from show version
    raw_output: Dict[str, str] = field(default_factory=dict)  # command -> output
    errors: List[str] = field(default_factory=list)
    duration_ms: float = 0.0
    # How the device was reached: a jump-host description, or None for a
    # direct connection. Surfaced by the caller so an operator can confirm
    # bastion routing actually engaged rather than silently falling through.
    jump_via: Optional[str] = None


class SSHCollector:
    """
    SSH-based neighbor collector.

    Connects to device via SSH, runs vendor-appropriate commands,
    and parses output using TextFSM templates.

    Example:
        from scng.creds import CredentialVault

        vault = CredentialVault()
        vault.unlock("password")
        ssh_cred = vault.get_ssh_credential("lab")

        collector = SSHCollector(
            username=ssh_cred.username,
            password=ssh_cred.password,
        )

        result = collector.collect("192.168.1.1")
        for neighbor in result.neighbors:
            print(f"{neighbor.local_interface} -> {neighbor.remote_device}")
    """

    def __init__(
        self,
        username: str,
        password: Optional[str] = None,
        key_content: Optional[str] = None,
        key_file: Optional[str] = None,
        key_passphrase: Optional[str] = None,
        timeout: int = 30,
        legacy_mode: bool = False,
        template_db_path: Optional[str] = None,
        proxy_resolver=None,
    ):
        """
        Initialize SSH collector.

        Args:
            username: SSH username.
            password: SSH password.
            key_content: SSH private key (PEM string, for GUI).
            key_file: Path to SSH private key file.
            key_passphrase: Passphrase for encrypted key.
            timeout: Connection timeout in seconds.
            legacy_mode: Enable legacy algorithm support.
            template_db_path: Optional path to TextFSM templates database.
            proxy_resolver: Optional sc2.scng.reachssh ProxyResolver. When set, each
                device is matched against the jump-host rules and reached
                through the resulting bastion instead of directly.
        """
        self.username = username
        self.password = password
        self.key_content = key_content
        self.key_file = key_file
        self.key_passphrase = key_passphrase
        self.timeout = timeout
        self.legacy_mode = legacy_mode
        self.proxy_resolver = proxy_resolver

        self.parser = TextFSMParser(db_path=template_db_path)

    def collect(
        self,
        host: str,
        vendor_hint: Optional[DeviceVendor] = None,
        collect_cdp: bool = True,
        collect_lldp: bool = True,
        debug: bool = False,
        hostname_hint: Optional[str] = None,
    ) -> SSHCollectorResult:
        """
        Collect neighbor information from device.

        Args:
            host: Device IP or hostname.
            vendor_hint: Known vendor (skips detection if provided).
            hostname_hint: Device name, used for jump-host rule matching when
                the caller knows it (host may be a bare IP).
            collect_cdp: Collect CDP neighbors (Cisco only).
            collect_lldp: Collect LLDP neighbors.
            debug: Enable debug output.

        Returns:
            SSHCollectorResult with neighbors and metadata.
        """
        import time
        start_time = time.time()

        if debug:
            print(f"[DEBUG] ========================================")
            print(f"[DEBUG] SSH Collection starting for {host}")
            print(f"[DEBUG] Using TextFSM database: {self.parser.db_path}")
            print(f"[DEBUG] ========================================")

        neighbors: List[Neighbor] = []
        raw_output: Dict[str, str] = {}
        errors: List[str] = []
        vendor = vendor_hint or DeviceVendor.UNKNOWN
        hostname: Optional[str] = None
        version_info: Dict[str, str] = {}

        # Resolve a jump host for this device, if routing is configured.
        # A resolver failure must not silently fall back to a direct connect -
        # a bastion-only device would then fail with a confusing timeout - so
        # the error is recorded and surfaced.
        jump = None
        jump_via: Optional[str] = None
        if self.proxy_resolver is not None:
            from ..jump import device_context
            try:
                jump = self.proxy_resolver.resolve(
                    device_context(hostname=hostname_hint, ip=host, vendor=(
                        vendor_hint.value if vendor_hint else None))
                )
                if jump:
                    jump_via = jump.describe()
                    logger.info("%s routed via jump host %s", host, jump_via)
            except Exception as e:
                logger.error("Jump-host resolution failed for %s: %s", host, e)
                errors.append(f"Jump-host resolution failed: {e}")
                return SSHCollectorResult(
                    success=False,
                    neighbors=[],
                    vendor=vendor,
                    hostname=None,
                    raw_output={},
                    errors=errors,
                    duration_ms=(time.time() - start_time) * 1000,
                )

        config = SSHClientConfig(
            host=host,
            username=self.username,
            password=self.password,
            key_content=self.key_content,
            key_file=self.key_file,
            key_passphrase=self.key_passphrase,
            timeout=self.timeout,
            legacy_mode=self.legacy_mode,
            jump=jump,
        )

        try:
            with SSHClient(config) as client:
                # Detect prompt and set for command completion detection
                if debug:
                    print(f"[DEBUG] === PHASE: Prompt detection ===")
                logger.debug("=== PHASE: Prompt detection ===")
                prompt = client.find_prompt()
                client.set_expect_prompt(prompt)
                if debug:
                    print(f"[DEBUG] Detected prompt: {prompt!r}")

                # Extract hostname from prompt
                hostname = client.extract_hostname_from_prompt()
                if debug:
                    print(f"[DEBUG] Extracted hostname: {hostname}")

                # Disable pagination first (vendor-agnostic shotgun)
                if debug:
                    print(f"[DEBUG] === PHASE: Disable pagination ===")
                logger.debug("=== PHASE: Disable pagination ===")
                client.disable_pagination()

                # Now safe to detect vendor (show version won't hang)
                if debug:
                    print(f"[DEBUG] === PHASE: Vendor detection ===")
                logger.debug("=== PHASE: Vendor detection ===")
                if vendor == DeviceVendor.UNKNOWN:
                    vendor = self._detect_vendor(client, raw_output, errors, debug=debug)
                if debug:
                    print(f"[DEBUG] Detected vendor: {vendor.value}")

                # Get vendor-specific commands
                commands = VENDOR_COMMANDS.get(vendor, DEFAULT_COMMANDS)
                if debug:
                    print(f"[DEBUG] Using commands: CDP={commands.cdp_command}, LLDP={commands.lldp_command}")
                    print(f"[DEBUG] Using templates: CDP={commands.cdp_template}, LLDP={commands.lldp_template}")
                logger.debug(f"Using commands: CDP={commands.cdp_command}, LLDP={commands.lldp_command}")

                # Parse show version through TextFSM for structured fields
                version_info = {}
                if raw_output.get('show_version') and commands.version_template:
                    if debug:
                        print(f"[DEBUG] === PHASE: Parse show version ===")
                    version_info = self._parse_version(
                        raw_output['show_version'], commands, vendor, debug=debug
                    )

                # Junos: landed on the backup RE / a backup VC member?
                # LLDP runs on the master, so collecting here returns nothing.
                if vendor == DeviceVendor.JUNIPER:
                    self._junos_ensure_master(client, raw_output, errors, debug=debug)

                # Collect CDP (Cisco only)
                if collect_cdp and commands.cdp_command:
                    if debug:
                        print(f"[DEBUG] === PHASE: CDP collection ===")
                    logger.debug("=== PHASE: CDP collection ===")
                    cdp_neighbors = self._collect_cdp(
                        client, commands, raw_output, errors, debug=debug
                    )
                    neighbors.extend(cdp_neighbors)
                    logger.debug(f"CDP complete: {len(cdp_neighbors)} neighbors")

                # Collect LLDP
                if collect_lldp and commands.lldp_command:
                    if debug:
                        print(f"[DEBUG] === PHASE: LLDP collection ===")
                    logger.debug("=== PHASE: LLDP collection ===")
                    lldp_neighbors = self._collect_lldp(
                        client, commands, raw_output, errors, debug=debug
                    )
                    neighbors.extend(lldp_neighbors)
                    logger.debug(f"LLDP complete: {len(lldp_neighbors)} neighbors")

                logger.debug("=== PHASE: Disconnecting ===")

        except Exception as e:
            if debug:
                print(f"[DEBUG] SSH Exception: {e}")
            errors.append(f"SSH connection failed: {e}")
            logger.error(f"SSH collection failed for {host}: {e}")

        duration_ms = (time.time() - start_time) * 1000

        return SSHCollectorResult(
            success=len(neighbors) > 0 or len(errors) == 0,
            neighbors=neighbors,
            vendor=vendor,
            hostname=hostname,
            platform=version_info.get('platform'),
            version=version_info.get('version'),
            serial=version_info.get('serial'),
            raw_output=raw_output,
            errors=errors,
            duration_ms=duration_ms,
            jump_via=jump_via,
        )

    def _detect_vendor(
        self,
        client: SSHClient,
        raw_output: Dict[str, str],
        errors: List[str],
        debug: bool = False,
    ) -> DeviceVendor:
        """Detect vendor by running 'show version', fallback to 'uname -a'."""

        # Try network-style first
        try:
            if debug:
                print(f"[DEBUG VENDOR] Sending: show version")
            output = self._exec(client, "show version", errors)
            raw_output['show_version'] = output
            if debug:
                print(f"[DEBUG VENDOR] show version returned {len(output)} bytes")
                print(f"[DEBUG VENDOR] First 300 chars:\n{output[:300]}")
            vendor = detect_vendor_from_output(output)
            if vendor != DeviceVendor.UNKNOWN:
                if debug:
                    print(f"[DEBUG VENDOR] Detected: {vendor.value}")
                logger.debug(f"Detected vendor: {vendor.value}")
                return vendor
        except Exception as e:
            if debug:
                print(f"[DEBUG VENDOR] show version exception: {e}")
            logger.debug(f"show version failed: {e}")

        # Fallback to uname for Linux/Unix
        try:
            if debug:
                print(f"[DEBUG VENDOR] Sending: uname -a")
            output = self._exec(client, "uname -a", errors)
            raw_output['uname'] = output
            if debug:
                print(f"[DEBUG VENDOR] uname returned {len(output)} bytes: {output[:200]}")
            vendor = detect_vendor_from_output(output)
            if vendor != DeviceVendor.UNKNOWN:
                if debug:
                    print(f"[DEBUG VENDOR] Detected via uname: {vendor.value}")
                logger.debug(f"Detected vendor via uname: {vendor.value}")
                return vendor
        except Exception as e:
            if debug:
                print(f"[DEBUG VENDOR] uname exception: {e}")
            errors.append(f"Vendor detection failed: {e}")
            logger.debug(f"uname -a failed: {e}")

        if debug:
            print(f"[DEBUG VENDOR] Could not detect vendor, returning UNKNOWN")
        return DeviceVendor.UNKNOWN

    def _parse_version(
        self,
        version_output: str,
        commands: VendorCommands,
        vendor: DeviceVendor,
        debug: bool = False,
    ) -> Dict[str, str]:
        """
        Parse show version output through TextFSM for structured fields.

        Returns dict with keys: platform, version, serial, hostname
        (any may be absent if parsing fails or field not found).
        """
        result: Dict[str, str] = {}

        if not commands.version_template:
            return result

        # Refine filter based on output content — Cisco IOS and NX-OS
        # share DeviceVendor.CISCO but need different templates
        filter_string = commands.version_template
        output_lower = version_output.lower()
        if filter_string == "show_version":
            if 'nx-os' in output_lower or 'nexus' in output_lower:
                filter_string = "cisco_nxos_show_version"
            elif 'ios' in output_lower:
                filter_string = "cisco_ios_show_version"

        try:
            # parse() has no min_score parameter - passing one raised TypeError
            # on every device, and the broad except below swallowed it, so this
            # whole block silently produced nothing. Apply the confidence
            # threshold to the returned score instead.
            parsed = self.parser.parse(version_output, filter_string)

            if not parsed.success or not parsed.records:
                if debug:
                    print(f"[DEBUG VERSION] TextFSM parse failed: {parsed.error}")
                return result

            if parsed.score is not None and parsed.score < MIN_VERSION_PARSE_SCORE:
                if debug:
                    print(
                        f"[DEBUG VERSION] Discarding low-confidence parse "
                        f"(score {parsed.score:.1f} < {MIN_VERSION_PARSE_SCORE})"
                    )
                return result

            rec = parsed.records[0]
            if debug:
                print(f"[DEBUG VERSION] Parsed fields: {list(rec.keys())}")

            # NX-OS: PLATFORM, OS, HOSTNAME, SERIAL
            if rec.get('PLATFORM'):
                result['platform'] = rec['PLATFORM']
            # IOS: HARDWARE (list), VERSION, HOSTNAME, SERIAL (list)
            elif rec.get('HARDWARE'):
                hw = rec['HARDWARE']
                if isinstance(hw, list) and hw:
                    result['platform'] = hw[0]
                elif isinstance(hw, str):
                    result['platform'] = hw
            # Arista: MODEL
            elif rec.get('MODEL'):
                result['platform'] = rec['MODEL']

            # Version
            if rec.get('VERSION'):
                ver = rec['VERSION']
                if isinstance(ver, str):
                    result['version'] = ver.strip()
            elif rec.get('OS'):
                result['version'] = rec['OS']
            elif rec.get('JUNOS_VERSION'):
                result['version'] = rec['JUNOS_VERSION']

            # Serial
            if rec.get('SERIAL'):
                ser = rec['SERIAL']
                if isinstance(ser, list) and ser:
                    result['serial'] = ser[0]
                elif isinstance(ser, str):
                    result['serial'] = ser
            elif rec.get('SERIAL_NUMBER'):
                result['serial'] = rec['SERIAL_NUMBER']

            # Hostname from template (may be more reliable than prompt)
            if rec.get('HOSTNAME'):
                result['hostname'] = rec['HOSTNAME']

            if debug:
                print(f"[DEBUG VERSION] Extracted: {result}")

        except Exception as e:
            if debug:
                print(f"[DEBUG VERSION] Parse exception: {e}")
            logger.debug(f"Version parsing failed: {e}")

        return result

    # Junos prints the RE / VC role on its own line with every command:
    # {master} {backup} on dual-RE routers, {master:0} {backup:1} on VC.
    _JUNOS_ROLE = re.compile(r"^\{(master|backup|linecard)(?::(\d+))?\}\s*$", re.M)
    # show virtual-chassis: "1 (FPC 1)  Prsnt  <serial>  <model>  <prio>  Master* ..."
    _VC_MASTER_ROW = re.compile(r"^\s*(\d+)\s+\(FPC\s+\d+\)\s.*\bMaster\b", re.M)

    def _junos_role(self, output: str):
        """(role, member) from the last Junos context line in output, or (None, None)."""
        found = self._JUNOS_ROLE.findall(output or "")
        if not found:
            return None, None
        role, member = found[-1]
        return role, (int(member) if member else None)

    def _junos_ensure_master(self, client, raw_output: Dict[str, str],
                             errors: List[str], debug: bool = False) -> None:
        """
        If the session landed on a backup routing engine or backup VC member,
        move to the master before collecting. Uses Junos's own internal hop, so
        no second login or credential is needed:
            dual RE: request routing-engine login other-routing-engine
            VC:      request session member <master id>
        On failure, records why and carries on (collection will be empty).
        """
        role, member = self._junos_role(raw_output.get('show_version', ''))
        if role != 'backup':
            return

        if member is None:
            hop_cmd = "request routing-engine login other-routing-engine"
        else:
            vc = self._exec(client, "show virtual-chassis | no-more", errors)
            raw_output['show_virtual_chassis'] = vc
            m = self._VC_MASTER_ROW.search(vc or "")
            if not m:
                errors.append("On a backup VC member and could not find the master "
                              "in 'show virtual-chassis'; LLDP will be empty")
                return
            hop_cmd = f"request session member {m.group(1)}"

        if debug:
            print(f"[DEBUG JUNOS] Landed on backup ({'RE' if member is None else f'VC member {member}'}); "
                  f"hopping to master: {hop_cmd}")
        logger.info("Junos backup %s; hopping to master with '%s'",
                    "RE" if member is None else f"VC member {member}", hop_cmd)
        try:
            raw_output['re_hop'] = client.execute_command(hop_cmd)
            client.find_prompt()   # the other RE may present a different prompt
            # The hop opens a NEW CLI session on the other RE with default
            # paging; turn it off there too before anything else is sent.
            client.disable_pagination("set cli screen-length 0")
            check = self._exec(client, "show version | no-more", errors)
        except Exception as e:
            errors.append(f"On backup RE; hop to master failed: {e}")
            return

        new_role, _ = self._junos_role(check)
        if new_role == 'master':
            raw_output['show_version'] = check
            if debug:
                print("[DEBUG JUNOS] Now on master")
        else:
            errors.append(f"On backup RE; '{hop_cmd}' did not reach the master "
                          f"(context now {new_role or 'unknown'}); LLDP will be empty")

    # Pager prompts: Junos, IOS/NX-OS/EOS, some appliances
    _PAGER = re.compile(r"---\(more[^)]*\)---|--\s?More\s?--|<--- More --->", re.IGNORECASE)

    def _exec(self, client, command: str, errors: Optional[List[str]] = None) -> str:
        """
        execute_command plus a pager guard. If the device is sitting in a pager,
        quit it immediately ('q') so the NEXT command is not typed into the
        pager as keystrokes, and treat this output as unusable.
        """
        output = client.execute_command(command)
        if output and self._PAGER.search(output[-400:]):
            logger.warning("Pager active after '%s'; quitting pager", command)
            try:
                client._shell.send("q")
                client.find_prompt(attempt_count=2, timeout=3.0)
            except Exception:
                pass
            if errors is not None:
                errors.append(f"Output of '{command}' was paginated; pager quit, output discarded")
            return "% paginated output discarded"
        return output

    def _is_command_error(self, output: str) -> bool:
        """Check if command output indicates an error (not real data)."""
        if not output:
            return True
        # Strip prompt lines and whitespace
        lines = [l.strip() for l in output.strip().split('\n') if l.strip()]
        if not lines:
            return True
        # Check for CLI error markers
        error_markers = [
            '% invalid command',
            '% paginated output discarded',
            '% incomplete command',
            '% ambiguous command',
            '% unknown command',
            '% unrecognized command',
            'syntax error',
            'command not found',
        ]
        output_lower = output.lower()
        for marker in error_markers:
            if marker in output_lower:
                return True
        return False

    def _collect_cdp(
        self,
        client: SSHClient,
        commands: VendorCommands,
        raw_output: Dict[str, str],
        errors: List[str],
        debug: bool = False,
    ) -> List[Neighbor]:
        """Collect CDP neighbors."""
        logger.info(f"[COLLECTOR] _collect_cdp called — emulation={'ON' if _ssh_client.EMULATION_ENABLED else 'OFF'}")
        neighbors = []

        try:
            if debug:
                print(f"[DEBUG CDP] Sending command: {commands.cdp_command}")
            logger.debug(f"Sending CDP command: {commands.cdp_command}")
            output = self._exec(client, commands.cdp_command, errors)
            if debug:
                print(f"[DEBUG CDP] Command returned {len(output)} bytes")
                print(f"[DEBUG CDP] First 500 chars:\n{output[:500]}")
            logger.debug(f"CDP command returned {len(output)} bytes")
            raw_output['cdp'] = output

            # Check for command errors before parsing
            if self._is_command_error(output):
                if debug:
                    print(f"[DEBUG CDP] Command returned error, skipping parse")
                logger.debug("CDP command returned error output, skipping parse")
                return neighbors

            if debug:
                print(f"[DEBUG CDP] Parsing with template: {commands.cdp_template}")
            logger.debug(f"Parsing with template filter: {commands.cdp_template}")
            result = self.parser.parse(output, commands.cdp_template)
            if debug:
                print(f"[DEBUG CDP] Parse result: success={result.success}, records={result.record_count}, score={result.score}, error={result.error}")
            logger.debug(f"Parse complete: success={result.success}, records={result.record_count}, score={result.score}")

            if result.success and result.records:
                logger.debug(f"Converting {len(result.records)} records to Neighbor objects")
                for i, record in enumerate(result.records):
                    if debug:
                        print(f"[DEBUG CDP] Record {i+1}: {record}")
                    logger.debug(f"  Record {i+1}: {record}")
                    neighbor = self._cdp_record_to_neighbor(record)
                    if neighbor:
                        self._enrich_neighbor_ip(neighbor)
                        neighbors.append(neighbor)
                        logger.info(f"  [COLLECTOR] CDP neighbor: {neighbor.local_interface} -> {neighbor.remote_device}  ip={neighbor.remote_ip or 'NONE'}")
                    else:
                        logger.debug(f"  -> Skipped (missing required fields)")
                logger.info(f"[COLLECTOR] Parsed {len(neighbors)} CDP neighbors")
            else:
                if debug:
                    print(f"[DEBUG CDP] Parsing failed: {result.error}")
                logger.info(f"[COLLECTOR] CDP parsing failed or no records: score={result.score} error={result.error}")

        except Exception as e:
            if debug:
                print(f"[DEBUG CDP] Exception: {e}")
            errors.append(f"CDP collection failed: {e}")
            logger.warning(f"CDP collection failed: {e}")

        return neighbors

    def _collect_lldp(
        self,
        client: SSHClient,
        commands: VendorCommands,
        raw_output: Dict[str, str],
        errors: List[str],
        debug: bool = False,
    ) -> List[Neighbor]:
        """Collect LLDP neighbors."""
        logger.info(f"[COLLECTOR] _collect_lldp called — emulation={'ON' if _ssh_client.EMULATION_ENABLED else 'OFF'}")
        neighbors = []

        try:
            if debug:
                print(f"[DEBUG LLDP] Sending command: {commands.lldp_command}")
            logger.debug(f"Sending LLDP command: {commands.lldp_command}")
            output = self._exec(client, commands.lldp_command, errors)
            if debug:
                print(f"[DEBUG LLDP] Command returned {len(output)} bytes")
                print(f"[DEBUG LLDP] First 500 chars:\n{output[:500]}")
            logger.debug(f"LLDP command returned {len(output)} bytes")
            raw_output['lldp'] = output

            template = commands.lldp_template

            # Check for command errors before parsing
            if self._is_command_error(output):
                if not commands.lldp_fallback_command:
                    if debug:
                        print(f"[DEBUG LLDP] Command returned error, skipping parse")
                    logger.debug("LLDP command returned error output, skipping parse")
                    return neighbors
                if debug:
                    print(f"[DEBUG LLDP] Rejected; falling back to: {commands.lldp_fallback_command}")
                logger.info("LLDP '%s' rejected; trying '%s'",
                            commands.lldp_command, commands.lldp_fallback_command)
                output = self._exec(client, commands.lldp_fallback_command, errors)
                raw_output['lldp'] = output
                template = commands.lldp_fallback_template
                if self._is_command_error(output):
                    if debug:
                        print(f"[DEBUG LLDP] Fallback also rejected, skipping parse")
                    return neighbors

            if debug:
                print(f"[DEBUG LLDP] Parsing with template: {template}")
            logger.debug(f"Parsing with template filter: {template}")
            result = self.parser.parse(output, template)
            if debug:
                print(f"[DEBUG LLDP] Parse result: success={result.success}, records={result.record_count}, score={result.score}, error={result.error}")
            logger.debug(f"Parse complete: success={result.success}, records={result.record_count}, score={result.score}")

            if result.success and result.records:
                logger.debug(f"Converting {len(result.records)} records to Neighbor objects")
                for i, record in enumerate(result.records):
                    if debug:
                        print(f"[DEBUG LLDP] Record {i+1}: {record}")
                    logger.debug(f"  Record {i+1}: {record}")
                    neighbor = self._lldp_record_to_neighbor(record)
                    if neighbor:
                        self._enrich_neighbor_ip(neighbor)
                        neighbors.append(neighbor)
                        logger.debug(f"  -> Neighbor: {neighbor.local_interface} -> {neighbor.remote_device} ip={neighbor.remote_ip or 'none'}")
                    else:
                        logger.debug(f"  -> Skipped (missing required fields)")
                logger.debug(f"Parsed {len(neighbors)} LLDP neighbors")
            else:
                if debug:
                    print(f"[DEBUG LLDP] Parsing failed: {result.error}")
                logger.debug(f"LLDP parsing failed or no records: {result.error}")

        except Exception as e:
            if debug:
                print(f"[DEBUG LLDP] Exception: {e}")
            errors.append(f"LLDP collection failed: {e}")
            logger.warning(f"LLDP collection failed: {e}")

        return neighbors

    def _enrich_neighbor_ip(self, neighbor) -> None:
        """
        Ensure neighbor.remote_ip is reachable in the emulation table.

        When emulation is active the crawler can only connect to IPs that
        exist in ip_lookup.json.  A device may advertise a loopback or
        OOB address as its LLDP management IP — that address will be a
        MISS in the emulation table even though the hostname is known.

        Strategy:
          1. No-op when emulation is off.
          2. If remote_ip is already set, verify it resolves in the
             emulation table.  If it does, we're done.
          3. Otherwise (IP absent OR IP is an emulation MISS) try a
             hostname-based lookup and replace/set remote_ip with the
             emulation-routable address.
        """
        if not _ssh_client.EMULATION_ENABLED:
            return

        # If we already have an IP, check whether it's in the emulation table.
        if neighbor.remote_ip:
            emu = lookup_emulation(neighbor.remote_ip)
            if emu:
                return  # IP is valid in emulation — nothing to do.
            # IP is set but not resolvable (e.g. a loopback or OOB address).
            # Fall through to hostname-based recovery below.
            logger.debug(
                f"[EMULATION] IP {neighbor.remote_ip} not in emulation table "
                f"for {neighbor.remote_device} — attempting hostname fallback"
            )

        emu = lookup_emulation(neighbor.remote_device)
        if not emu:
            return

        real_ip = find_ip_for_hostname(emu['hostname'])
        if real_ip:
            old_ip = neighbor.remote_ip
            neighbor.remote_ip = real_ip
            if old_ip:
                logger.info(
                    f"[EMULATION] IP replaced: {neighbor.remote_device} "
                    f"{old_ip} -> {real_ip}"
                )
            else:
                logger.info(
                    f"[EMULATION] IP enriched: {neighbor.remote_device} -> {real_ip}"
                )

    def _cdp_record_to_neighbor(self, record: Dict[str, Any]) -> Optional[Neighbor]:
        """Convert CDP TextFSM record to Neighbor object."""
        # NEIGHBOR_NAME for NTC templates, DESTINATION_HOST/DEVICE_ID for legacy
        remote_device = (
            record.get('NEIGHBOR_NAME') or
            record.get('DESTINATION_HOST') or
            record.get('DEVICE_ID') or
            record.get('NEIGHBOR')
        )
        local_interface = (
            record.get('LOCAL_INTERFACE') or
            record.get('LOCAL_PORT')
        )
        remote_interface = (
            record.get('NEIGHBOR_INTERFACE') or
            record.get('REMOTE_PORT') or
            record.get('PORT_ID')
        )
        # MGMT_ADDRESS for NTC templates, MANAGEMENT_IP for legacy
        remote_ip = (
            record.get('MGMT_ADDRESS') or
            record.get('MANAGEMENT_IP') or
            record.get('REMOTE_IP')
        )

        if not remote_device or not local_interface:
            return None

        return Neighbor(
            local_interface=local_interface,
            remote_device=remote_device,
            remote_interface=remote_interface or "",
            protocol=NeighborProtocol.CDP,
            remote_ip=remote_ip if remote_ip else None,
            remote_platform=record.get('PLATFORM') or None,
            remote_description=record.get('NEIGHBOR_DESCRIPTION') or None,
        )

    def _lldp_record_to_neighbor(self, record: Dict[str, Any]) -> Optional[Neighbor]:
        """Convert LLDP TextFSM record to Neighbor object."""
        # NEIGHBOR_NAME for Arista/Cisco/Juniper templates
        # NEIGHBOR/SYSTEM_NAME for legacy compatibility
        # CHASSIS_ID as last resort
        remote_device = (
            record.get('NEIGHBOR_NAME') or
            record.get('NEIGHBOR') or
            record.get('SYSTEM_NAME') or
            record.get('CHASSIS_ID')
        )
        local_interface = (
            record.get('LOCAL_INTERFACE') or
            record.get('LOCAL_PORT')
        )
        # Remote interface. Most templates put the LLDP Port ID in
        # NEIGHBOR_INTERFACE. The Cisco IOS template instead puts the remote's
        # Port *Description* there (human-entered, unreliable) and the Port ID
        # in NEIGHBOR_PORT_ID. Same rule as the SNMP path: Port ID first; the
        # description only if the Port ID is a MAC/number and the description
        # looks like an interface name.
        port_id = (
            record.get('NEIGHBOR_PORT_ID') or
            record.get('PORT_ID') or
            record.get('REMOTE_PORT')
        )
        if port_id:
            desc = record.get('NEIGHBOR_INTERFACE') or ""
            if _looks_like_interface(port_id) or not _looks_like_interface(desc):
                remote_interface = port_id
            else:
                remote_interface = desc
        else:
            remote_interface = record.get('NEIGHBOR_INTERFACE')
        # MGMT_ADDRESS for Arista/Cisco/NX-OS, REMOTE_IP for the JUNOS
        # template, MANAGEMENT_IP for legacy
        remote_ip = (
            record.get('MGMT_ADDRESS') or
            record.get('REMOTE_IP') or
            record.get('MANAGEMENT_IP')
        )

        if not remote_device or not local_interface:
            return None

        # Keep what the neighbor says it is - the pre-dial exclude filter
        # matches on these, same as it does for SNMP-collected LLDP.
        description = (
            record.get('NEIGHBOR_DESCRIPTION') or
            record.get('SYSTEM_DESCRIPTION')
        )

        return Neighbor(
            local_interface=local_interface,
            remote_device=remote_device,
            remote_interface=remote_interface or "",
            protocol=NeighborProtocol.LLDP,
            remote_ip=remote_ip if remote_ip else None,
            remote_platform=record.get('PLATFORM') or None,
            remote_description=description or None,
            remote_capabilities=record.get('CAPABILITIES') or None,
            chassis_id=record.get('CHASSIS_ID'),
        )


def collect_neighbors_ssh(
    host: str,
    username: str,
    password: Optional[str] = None,
    key_content: Optional[str] = None,
    key_file: Optional[str] = None,
    vendor: Optional[DeviceVendor] = None,
    legacy_mode: bool = False,
) -> Tuple[List[Neighbor], List[str]]:
    """
    Convenience function for SSH neighbor collection.

    Args:
        host: Device IP or hostname.
        username: SSH username.
        password: SSH password.
        key_content: SSH private key (PEM string).
        key_file: Path to SSH private key file.
        vendor: Known vendor (optional).
        legacy_mode: Enable legacy SSH algorithms.

    Returns:
        Tuple of (neighbors list, errors list).
    """
    collector = SSHCollector(
        username=username,
        password=password,
        key_content=key_content,
        key_file=key_file,
        legacy_mode=legacy_mode,
    )
    result = collector.collect(host, vendor_hint=vendor)
    return result.neighbors, result.errors