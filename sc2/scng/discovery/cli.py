#!/usr/bin/env python3
"""
SecureCartography NG - Discovery CLI.

Command-line interface for network discovery with structured event output.

Usage:
    # Discover single device
    python -m scng.discovery discover 192.168.1.1

    # Recursive crawl
    python -m scng.discovery crawl 192.168.1.1 --depth 3 --domain example.com

    # With specific credential
    python -m scng.discovery discover 192.168.1.1 --credential lab-snmp

    # Quick test (no vault)
    python -m scng.discovery test 192.168.1.1 --community public

    # Home lab mode (no DNS, IPs only)
    python -m scng.discovery crawl 192.168.1.1 --depth 3 --no-dns

    # Verbose with timestamps
    python -m scng.discovery crawl 192.168.1.1 -v --timestamps
"""

import argparse
import asyncio
import sys
import json
from pathlib import Path
from datetime import datetime

# Check for pysnmp
try:
    try:
        from pysnmp.hlapi.asyncio import CommunityData, SnmpEngine
    except ImportError:
        from pysnmp.hlapi.v3arch.asyncio import CommunityData, SnmpEngine

    HAS_PYSNMP = True
except ImportError:
    HAS_PYSNMP = False

from .models import Device
from .engine import DiscoveryEngine, discover_device
from .events import (
    EventEmitter, ConsoleEventPrinter, EventType, LogLevel,
)


def _activate_emulation(args) -> bool:
    """Activate NetEmulate mode if --emulate was passed. Returns True if enabled."""
    emulate_path = getattr(args, 'emulate', None)
    if not emulate_path:
        return False

    from .ssh.client import enable_emulation
    count = enable_emulation(str(emulate_path))
    print(f"[EMULATION] Enabled — {count} IPs loaded from {emulate_path}")
    return True


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser."""
    parser = argparse.ArgumentParser(
        prog='scng.discovery',
        description='SCNG Network Discovery',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Quick test with community string
  python -m scng.discovery test 192.168.1.1 --community public

  # Discover using vault credentials
  python -m scng.discovery discover 192.168.1.1

  # Recursive crawl with output
  python -m scng.discovery crawl 192.168.1.1 -d 3 --domain example.com -o ./output

  # Home lab (no DNS, use IPs from LLDP/CDP)
  python -m scng.discovery crawl 192.168.1.1 -d 3 --no-dns

  # High concurrency for large networks
  python -m scng.discovery crawl 192.168.1.1 -d 5 --concurrency 30

  # NetEmulate mode (mock devices on localhost)
  python -m scng.discovery crawl 192.0.2.10 -d 5 --emulate ./ip_lookup.json --no-dns

  # Rebuild topology from collected device data
  python -m scng.discovery rebuild ./output -v

  # Verbose with timestamps
  python -m scng.discovery crawl 192.168.1.1 -v --timestamps
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Test command (no vault required)
    test_parser = subparsers.add_parser(
        'test',
        help='Quick discovery test with community string'
    )
    test_parser.add_argument('target', help='IP address or hostname')
    test_parser.add_argument(
        '-c', '--community',
        default='public',
        help='SNMP community string (default: public)'
    )
    test_parser.add_argument(
        '-t', '--timeout',
        type=float,
        default=5.0,
        help='SNMP timeout in seconds (default: 5)'
    )
    test_parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    test_parser.add_argument(
        '-o', '--output',
        type=Path,
        help='Output JSON file'
    )
    test_parser.add_argument(
        '--no-dns',
        action='store_true',
        dest='no_dns',
        help='Disable DNS lookups (target must be IP)'
    )

    # Device command (uses vault) - also aliased as 'discover' for backward compatibility
    device_parser = subparsers.add_parser(
        'device',
        aliases=['discover'],
        help='Discover single device using vault credentials'
    )
    device_parser.add_argument('target', help='IP address or hostname')
    device_parser.add_argument(
        '--credential',
        help='Specific credential name to use'
    )
    device_parser.add_argument(
        '--domain',
        action='append',
        dest='domains',
        help='Domain suffix(es) for hostname resolution'
    )
    device_parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    device_parser.add_argument(
        '-o', '--output',
        type=Path,
        help='Output JSON file'
    )
    device_parser.add_argument(
        '--no-dns',
        action='store_true',
        dest='no_dns',
        help='Disable DNS lookups (target must be IP)'
    )
    device_parser.add_argument(
        '--no-color',
        action='store_true',
        dest='no_color',
        help='Disable colored output'
    )

    # Crawl command (recursive discovery)
    crawl_parser = subparsers.add_parser(
        'crawl',
        help='Recursive network discovery'
    )
    crawl_parser.add_argument(
        'seeds',
        nargs='+',
        help='Seed IP addresses or hostnames'
    )
    crawl_parser.add_argument(
        '-d', '--depth',
        type=int,
        default=3,
        help='Maximum discovery depth (default: 3)'
    )
    crawl_parser.add_argument(
        '--domain',
        action='append',
        dest='domains',
        help='Domain suffix(es) for hostname resolution'
    )
    crawl_parser.add_argument(
        '--exclude',
        action='append',
        dest='exclude_patterns',
        help='patterns to exclude'
    )
    crawl_parser.add_argument(
        '-o', '--output',
        type=Path,
        help='Output directory for results'
    )
    crawl_parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    crawl_parser.add_argument(
        '--no-dns',
        action='store_true',
        dest='no_dns',
        help='Disable DNS lookups, use IPs from LLDP/CDP only'
    )
    crawl_parser.add_argument(
        '--device-deadline',
        type=float,
        default=300.0,
        help='Absolute seconds allowed per device, all attempts included; '
             'the crawl moves on after this (default: 300, 0 = no limit)',
    )
    crawl_parser.add_argument(
        '-c', '--concurrency',
        type=int,
        default=20,
        help='Maximum concurrent device discoveries (default: 20)'
    )
    crawl_parser.add_argument(
        '-t', '--timeout',
        type=float,
        default=5.0,
        help='SNMP timeout in seconds (default: 5)'
    )
    crawl_parser.add_argument(
        '--no-color',
        action='store_true',
        dest='no_color',
        help='Disable colored output'
    )
    crawl_parser.add_argument(
        '--timestamps',
        action='store_true',
        help='Show timestamps in output'
    )
    crawl_parser.add_argument(
        '--json-events',
        action='store_true',
        dest='json_events',
        help='Output events as JSON lines (for GUI integration)'
    )
    crawl_parser.add_argument(
        '--emulate',
        type=Path,
        metavar='LOOKUP_JSON',
        help='Enable NetEmulate mode with ip_lookup.json path'
    )
    crawl_parser.add_argument(
        '--jump-config',
        type=Path,
        dest='jump_config',
        metavar='PATH',
        help='Jump-host YAML config (default: ~/.seccart2/jump_hosts.yaml if present). '
             'Routes SSH through a bastion; SNMP is UDP and does not tunnel.',
    )
    crawl_parser.add_argument(
        '--hosts-file',
        type=Path,
        dest='hosts_file',
        metavar='FILE',
        help='Hosts-format file for name→IP resolution (checked before DNS)'
    )

    # Add --emulate and --hosts-file to device/test parsers too
    for p in (device_parser, test_parser):
        p.add_argument(
            '--emulate',
            type=Path,
            metavar='LOOKUP_JSON',
            help='Enable NetEmulate mode with ip_lookup.json path'
        )
        p.add_argument(
            '--jump-config',
            type=Path,
            dest='jump_config',
            metavar='PATH',
            help='Jump-host YAML config (default: ~/.seccart2/jump_hosts.yaml if present)',
        )
        p.add_argument(
            '--hosts-file',
            type=Path,
            dest='hosts_file',
            metavar='FILE',
            help='Hosts-format file for name→IP resolution (checked before DNS)'
        )

    # --- rebuild command ---
    rebuild_parser = subparsers.add_parser(
        'rebuild',
        help='Rebuild topology map from collected device.json files',
        description='Read all device.json files from a discovery output folder '
                    'and regenerate map.json. Recovers devices that were collected '
                    'but missed during the live crawl topology generation.'
    )
    rebuild_parser.add_argument(
        'input_dir',
        type=Path,
        help='Discovery output directory containing device folders'
    )
    rebuild_parser.add_argument(
        '-o', '--output',
        type=Path,
        dest='output',
        help='Output map.json path (default: <input_dir>/map.json)'
    )
    rebuild_parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show details during rebuild'
    )

    return parser


class JsonEventPrinter:
    """
    Prints events as JSON lines for GUI consumption.

    Each event is printed as a single JSON line that can be
    parsed by a GUI process reading stdout.
    """

    def handle_event(self, event):
        """Print event as JSON line."""
        output = {
            "type": event.event_type.value,
            "timestamp": event.timestamp.isoformat(),
            "data": event.data,
        }
        print(json.dumps(output), flush=True)


async def cmd_test(args) -> int:
    """Run quick test discovery with community string."""
    _activate_emulation(args)

    if not HAS_PYSNMP:
        print("ERROR: pysnmp not installed")
        print("Install with: pip install pysnmp-lextudio")
        return 1

    print(f"Testing discovery: {args.target}")
    print(f"Community: {args.community}")
    print(f"Timeout: {args.timeout}s")
    print(f"No DNS: {args.no_dns}")
    print()

    # Build auth
    auth = CommunityData(args.community, mpModel=1)

    # Create engine
    engine = DiscoveryEngine(
        default_timeout=args.timeout,
        verbose=args.verbose,
        no_dns=args.no_dns,
        hosts_file=getattr(args, 'hosts_file', None),
        jump_config=getattr(args, 'jump_config', None),
    )

    # Discover
    try:
        device = await engine.discover_device(
            target=args.target,
            auth=auth,
        )
    except Exception as e:
        print(f"ERROR: Discovery failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1

    # Print results
    print(f"{'=' * 60}")
    print(f"DISCOVERY RESULTS: {device.hostname}")
    print(f"{'=' * 60}")
    print(f"IP Address:   {device.ip_address}")
    print(f"sysName:      {device.sys_name or 'N/A'}")
    print(f"Vendor:       {device.vendor.value}")
    print(f"sysDescr:     {(device.sys_descr or 'N/A')[:60]}...")
    print(f"Interfaces:   {len(device.interfaces)}")
    print(f"CDP Neighbors: {len(device.cdp_neighbors)}")
    print(f"LLDP Neighbors: {len(device.lldp_neighbors)}")
    print(f"Duration:     {device.discovery_duration_ms:.0f}ms")

    if device.discovery_errors:
        print(f"\nErrors:")
        for err in device.discovery_errors:
            print(f"  - {err}")

    # Print neighbors
    if device.neighbors:
        print(f"\nNeighbors:")
        for n in device.neighbors:
            proto = n.protocol.value.upper()
            print(f"  [{proto}] {n.local_interface} -> {n.remote_device} ({n.remote_interface})")
            if n.remote_ip:
                print(f"         IP: {n.remote_ip}")

    # Save output
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(device.to_dict(), f, indent=2)
        print(f"\nSaved to: {args.output}")

    return 0 if device.discovery_success else 1


async def cmd_device(args) -> int:
    """Discover device using vault credentials."""
    _activate_emulation(args)

    # Import vault - try multiple paths for different package structures
    CredentialVault = None
    try:
        from scng.creds import CredentialVault
    except ImportError:
        try:
            from sc2.scng.creds import CredentialVault
        except ImportError:
            try:
                from ..creds import CredentialVault
            except ImportError:
                pass

    if CredentialVault is None:
        print("ERROR: scng.creds module not available")
        print("Make sure the creds module is installed")
        return 1

    # Open vault
    vault = CredentialVault()

    if not vault.is_initialized:
        print("ERROR: Vault not initialized")
        print("Run: python -m scng.creds init")
        return 1

    # Prompt for password
    import getpass
    try:
        password = getpass.getpass("Vault password: ")
        vault.unlock(password)
    except Exception as e:
        print(f"ERROR: Failed to unlock vault: {e}")
        return 1

    print(f"\nDiscovering: {args.target}")
    if args.no_dns:
        print("DNS: disabled")

    # Create event printer
    printer = ConsoleEventPrinter(
        verbose=args.verbose,
        color=not getattr(args, 'no_color', False),
    )

    # Create engine with event system
    emitter = EventEmitter()
    emitter.subscribe(printer.handle_event)

    engine = DiscoveryEngine(
        vault=vault,
        verbose=args.verbose,
        no_dns=args.no_dns,
        event_emitter=emitter,
        hosts_file=getattr(args, 'hosts_file', None),
        jump_config=getattr(args, 'jump_config', None),
    )

    # Discover
    try:
        device = await engine.discover_device(
            target=args.target,
            credential_name=args.credential,
            domains=args.domains or [],
        )
    except Exception as e:
        print(f"ERROR: Discovery failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1
    finally:
        vault.lock()

    # Print results
    print(f"\n{'=' * 60}")
    print(f"DISCOVERY RESULTS: {device.hostname}")
    print(f"{'=' * 60}")
    print(f"IP Address:   {device.ip_address}")
    print(f"sysName:      {device.sys_name or 'N/A'}")
    print(f"Vendor:       {device.vendor.value}")
    print(f"Credential:   {device.credential_used or 'N/A'}")
    print(f"Interfaces:   {len(device.interfaces)}")
    print(f"CDP Neighbors: {len(device.cdp_neighbors)}")
    print(f"LLDP Neighbors: {len(device.lldp_neighbors)}")
    print(f"Duration:     {device.discovery_duration_ms:.0f}ms")

    if device.neighbors:
        print(f"\nNeighbors:")
        for n in device.neighbors:
            proto = n.protocol.value.upper()
            print(f"  [{proto}] {n.local_interface} -> {n.remote_device}")
            if n.remote_ip:
                print(f"         IP: {n.remote_ip}")

    if args.output:
        with open(args.output, 'w') as f:
            json.dump(device.to_dict(), f, indent=2)
        print(f"\nSaved to: {args.output}")

    return 0 if device.discovery_success else 1


async def cmd_crawl(args) -> int:
    """Run recursive network discovery with event-driven output."""
    _activate_emulation(args)

    # Import vault - try multiple paths for different package structures
    CredentialVault = None
    try:
        from scng.creds import CredentialVault
    except ImportError:
        try:
            from sc2.scng.creds import CredentialVault
        except ImportError:
            try:
                from ..creds import CredentialVault
            except ImportError:
                pass

    if CredentialVault is None:
        print("ERROR: scng.creds module not available")
        return 1

    # Open vault
    vault = CredentialVault()

    if not vault.is_initialized:
        print("ERROR: Vault not initialized")
        print("Run: python -m scng.creds init")
        return 1

    import getpass
    try:
        password = getpass.getpass("Vault password: ")
        vault.unlock(password)
    except Exception as e:
        print(f"ERROR: Failed to unlock vault: {e}")
        return 1

    # Setup output directory
    output_dir = args.output
    if output_dir:
        output_dir = Path(output_dir)
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = Path(f"./discovery_{timestamp}")

    output_dir.mkdir(parents=True, exist_ok=True)

    # Create event emitter and printer
    emitter = EventEmitter()

    if args.json_events:
        # JSON output for GUI integration
        json_printer = JsonEventPrinter()
        emitter.subscribe(json_printer.handle_event)
    else:
        # Human-readable console output
        console_printer = ConsoleEventPrinter(
            verbose=args.verbose,
            color=not args.no_color,
            show_timestamps=args.timestamps,
        )
        emitter.subscribe(console_printer.handle_event)

    # Create engine with event system
    engine = DiscoveryEngine(
        vault=vault,
        verbose=args.verbose,
        no_dns=args.no_dns,
        max_concurrent=args.concurrency,
        default_timeout=args.timeout,
        event_emitter=emitter,
        hosts_file=getattr(args, 'hosts_file', None),
        jump_config=getattr(args, 'jump_config', None),
        device_deadline=getattr(args, 'device_deadline', 300.0),
    )

    # Print configuration (unless JSON mode)
    if not args.json_events:
        print(f"Output: {output_dir.absolute()}")
        print(f"Concurrency: {args.concurrency} workers")

    # Run crawl
    try:
        result = await engine.crawl(
            seeds=args.seeds,
            max_depth=args.depth,
            domains=args.domains or [],
            exclude_patterns=args.exclude_patterns or [],
            output_dir=output_dir,
        )
    except Exception as e:
        print(f"ERROR: Crawl failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1
    finally:
        vault.lock()

    # Save summary
    summary_file = output_dir / 'discovery_summary.json'
    with open(summary_file, 'w') as f:
        json.dump(result.to_dict(), f, indent=2)

    if not args.json_events:
        print(f"\nSummary saved to: {summary_file}")

    return 0 if result.successful > 0 else 1


def cmd_rebuild(args) -> int:
    """Rebuild topology map from collected device.json files."""
    input_dir = args.input_dir
    verbose = args.verbose

    if not input_dir.is_dir():
        print(f"ERROR: {input_dir} is not a directory")
        return 1

    # Scan for device.json files
    device_files = list(input_dir.glob('*/device.json'))
    if not device_files:
        print(f"ERROR: No device.json files found in {input_dir}")
        return 1

    print(f"Scanning {input_dir}...")
    print(f"Found {len(device_files)} device folders")

    # Load all devices
    devices = []
    load_errors = 0
    for device_file in sorted(device_files):
        try:
            with open(device_file) as f:
                data = json.load(f)

            device = Device.from_dict(data)

            # Only include successfully discovered devices
            if not device.discovery_success:
                if verbose:
                    print(f"  SKIP: {device_file.parent.name} (discovery_success=false)")
                continue

            devices.append(device)
            if verbose:
                neighbor_count = len(device.neighbors)
                via = device.discovered_via.value if device.discovered_via else "?"
                print(f"  OK: {device.hostname} ({device.ip_address}) "
                      f"via {via}, {neighbor_count} neighbors")

        except Exception as e:
            load_errors += 1
            print(f"  ERROR: {device_file}: {e}")

    if not devices:
        print("ERROR: No valid devices loaded")
        return 1

    print(f"\nLoaded {len(devices)} devices ({load_errors} errors)")

    # Create a minimal engine for topology generation
    engine = DiscoveryEngine(verbose=verbose)

    # Generate topology map
    print("Generating topology map...")
    topology = engine._generate_topology_map(devices)

    # Count stats
    node_count = len(topology)
    edge_count = 0
    connection_count = 0
    for device_data in topology.values():
        for peer_data in device_data.get('peers', {}).values():
            edge_count += 1
            connection_count += len(peer_data.get('connections', []))

    # Write output
    output_path = args.output or (input_dir / 'map.json')
    with open(output_path, 'w') as f:
        json.dump(topology, f, indent=2)

    print(f"\n{'=' * 60}")
    print(f"REBUILD COMPLETE")
    print(f"{'=' * 60}")
    print(f"Devices loaded:    {len(devices)}")
    print(f"Topology nodes:    {node_count}")
    print(f"Topology edges:    {edge_count}")
    print(f"Total connections: {connection_count}")
    print(f"Output: {output_path}")

    return 0


def _configure_logging(verbose: bool) -> None:
    """
    Route library logging to the console.

    Without this, every logger.info() in the discovery modules is dropped and
    behaviour like jump-host routing looks like it never happened. Third-party
    loggers stay at WARNING - paramiko at INFO is unreadable.
    """
    import logging
    logging.basicConfig(
        level=logging.INFO if verbose else logging.WARNING,
        format="  [%(name)s] %(message)s",
    )
    for noisy in ("paramiko", "paramiko.transport", "pysnmp", "asyncio"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def main():
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()

    _configure_logging(getattr(args, 'verbose', False))

    if not args.command:
        parser.print_help()
        return 1

    # Run appropriate command
    if args.command == 'test':
        return asyncio.run(cmd_test(args))
    elif args.command in ('device', 'discover'):
        return asyncio.run(cmd_device(args))
    elif args.command == 'crawl':
        return asyncio.run(cmd_crawl(args))
    elif args.command == 'rebuild':
        return cmd_rebuild(args)
    else:
        parser.print_help()
        return 1


if __name__ == '__main__':
    sys.exit(main())