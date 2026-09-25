"""
SecureCartography v2 - Draw.io Exporter

Exports network topology to Draw.io format with Cisco stencils and vendor coloring.
Supports tree, balloon, and grid layouts.

Usage:
    from sc2.export.drawio_exporter import DrawioExporter

    exporter = DrawioExporter(use_icons=True, layout_type='tree')
    exporter.export(topology_data, Path("output.drawio"))
"""

import json
import math
import re
import xml.etree.ElementTree as ET
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from xml.dom import minidom

from sc2.scng.utils.resource_helper import (
    get_resource_dir,
    read_resource_text
)


@dataclass
class Connection:
    """Represents a single port-to-port connection."""
    local_port: str
    remote_port: str


# =============================================================================
# Layout Manager
# =============================================================================

class DrawioLayoutManager:
    """Calculates node positions for different layout algorithms."""

    def __init__(self, layout_type: str = 'tree'):
        self.layout_type = layout_type
        self.vertical_spacing = 150
        self.horizontal_spacing = 200
        self.start_x = 1000
        self.start_y = 350
        self.balloon_radius = 300
        self.balloon_ring_spacing = 200

    def get_node_positions(
        self,
        network_data: Dict,
        edges: List[Tuple[str, str]]
    ) -> Dict[str, Tuple[int, int]]:
        """Calculate node positions based on layout type."""
        if not network_data:
            return {}

        if self.layout_type == 'tree':
            return self._calculate_tree_layout(network_data, edges)
        elif self.layout_type == 'balloon':
            return self._calculate_balloon_layout(network_data, edges)
        else:
            return self._calculate_grid_layout(network_data)

    def _calculate_grid_layout(self, network_data: Dict) -> Dict[str, Tuple[int, int]]:
        """Simple grid layout."""
        positions = {}
        nodes = sorted(network_data.keys())
        total = len(nodes)
        cols = max(1, int(total ** 0.5))

        for idx, node_id in enumerate(nodes):
            row = idx // cols
            col = idx % cols
            x = self.start_x + (col * self.horizontal_spacing)
            y = self.start_y + (row * self.vertical_spacing)
            positions[node_id] = (x, y)

        return positions

    def _calculate_tree_layout(
        self,
        network_data: Dict,
        edges: List[Tuple[str, str]]
    ) -> Dict[str, Tuple[int, int]]:
        """Hierarchical tree layout."""
        positions = {}

        # Build adjacency list
        adjacency = defaultdict(list)
        for source, target in edges:
            adjacency[source].append(target)
            adjacency[target].append(source)

        # Find root node
        root = self._find_root_node(network_data, adjacency)

        # Build tree levels using BFS
        levels = defaultdict(list)
        visited = {root}
        queue = [(root, 0)]
        levels[0].append(root)

        while queue:
            node, level = queue.pop(0)
            neighbors = sorted(adjacency[node], key=lambda x: (
                'core' in x.lower(),
                'rtr' in x.lower(),
                x.lower()
            ), reverse=True)

            for neighbor in neighbors:
                if neighbor not in visited:
                    visited.add(neighbor)
                    levels[level + 1].append(neighbor)
                    queue.append((neighbor, level + 1))

        # Assign positions
        level_adjustments = {0: 1, 1: 1.2, 2: 1.5, 3: 2}

        for level, nodes in levels.items():
            y = self.start_y + (level * self.vertical_spacing)
            adjustment = level_adjustments.get(level, 2)
            level_width = (len(nodes) - 1) * (self.horizontal_spacing * adjustment)
            start_x = self.start_x - (level_width / 2)

            for idx, node in enumerate(sorted(nodes)):
                x = start_x + (idx * (self.horizontal_spacing * adjustment))
                positions[node] = (int(x), int(y))

        return positions

    def _calculate_balloon_layout(
        self,
        network_data: Dict,
        edges: List[Tuple[str, str]]
    ) -> Dict[str, Tuple[int, int]]:
        """Radial/balloon layout."""
        positions = {}

        adjacency = defaultdict(list)
        for source, target in edges:
            adjacency[source].append(target)
            adjacency[target].append(source)

        center_node = self._find_root_node(network_data, adjacency)
        positions[center_node] = (self.start_x, self.start_y)

        # Build rings using BFS
        rings = []
        visited = {center_node}
        current_ring = set()
        queue = [(center_node, 0)]
        current_level = 0

        while queue:
            node, level = queue.pop(0)

            if level > current_level:
                if current_ring:
                    rings.append(current_ring)
                current_ring = set()
                current_level = level

            for neighbor in sorted(adjacency[node]):
                if neighbor not in visited:
                    current_ring.add(neighbor)
                    visited.add(neighbor)
                    queue.append((neighbor, level + 1))

        if current_ring:
            rings.append(current_ring)

        # Position nodes in rings
        for ring_idx, ring_nodes in enumerate(rings):
            if not ring_nodes:
                continue

            radius = self.balloon_radius + (ring_idx * self.balloon_ring_spacing)

            for idx, node in enumerate(sorted(ring_nodes)):
                angle = (2 * math.pi * idx) / len(ring_nodes)
                x = self.start_x + int(radius * math.cos(angle))
                y = self.start_y + int(radius * math.sin(angle))
                positions[node] = (x, y)

        return positions

    def _find_root_node(self, network_data: Dict, adjacency: Dict) -> str:
        """Find the best root/center node for layout."""
        # Prefer core switches
        for node_id in network_data:
            if '-core-' in node_id.lower():
                return node_id

        # Fall back to most connected node
        if adjacency:
            return max(adjacency.items(), key=lambda x: len(x[1]))[0]

        # Last resort: first node
        return next(iter(network_data.keys()))

    def get_edge_style(self) -> str:
        """Get draw.io edge style string."""
        return (
            "edgeStyle=orthogonalEdgeStyle;rounded=0;orthogonalLoop=1;"
            "jettySize=auto;html=1;noEdgeStyle=1;endArrow=none;startArrow=none"
        )


# =============================================================================
# Icon Manager
# =============================================================================

class DrawioIconManager:
    """Manages platform-to-icon mapping and vendor coloring for draw.io."""

    # Default vendor colors
    DEFAULT_VENDOR_COLORS = {
        'juniper': '#F58536',
        'arista': '#2D8659',
        'cisco': '#036897',
    }

    DEFAULT_STYLE = {
        'fillColor': '#036897',
        'strokeColor': '#ffffff',
        'strokeWidth': '2',
        'html': '1',
        'verticalLabelPosition': 'bottom',
        'verticalAlign': 'top',
        'align': 'center',
        'labelBackgroundColor': 'none',
        'fontColor': '#000000',
    }

    def __init__(self, icons_package: Optional[str] = None):
        self._icons_package = icons_package or 'sc2.ui.assets.icons_lib'
        self.platform_patterns: Dict[str, str] = {}
        self.fallback_patterns: Dict[str, dict] = {}
        self.vendor_defaults: Dict[str, str] = {}
        self.vendor_colors: Dict[str, str] = self.DEFAULT_VENDOR_COLORS.copy()
        self.style_defaults: Dict[str, str] = self.DEFAULT_STYLE.copy()
        self._load_config()

    def _load_config(self) -> None:
        """Load icon configuration from JSON."""
        config_data = None

        # Try package resources first
        try:
            config_data = read_resource_text(
                self._icons_package,
                'platform_icon_drawio.json'
            )
        except Exception:
            pass

        # Parse if found
        if config_data:
            try:
                config = json.loads(config_data)
                self.platform_patterns = config.get('platform_patterns', {})
                self.fallback_patterns = config.get('fallback_patterns', {})
                self.vendor_defaults = config.get('vendor_defaults', {})
                self.vendor_colors.update(config.get('vendor_colors', {}))
                self.style_defaults.update(config.get('style_defaults', {}))
            except json.JSONDecodeError:
                pass

    def _detect_vendor(self, node_id: str, platform: str) -> Optional[str]:
        """Detect vendor from platform string or node_id."""
        platform_lower = platform.lower()
        node_id_lower = node_id.lower()

        # Juniper patterns
        juniper_patterns = ['junos', 'jnp', 'juniper', 'mx', 'qfx', 'ex2', 'ex3', 'ex4', 'srx', 'ptx']
        for pattern in juniper_patterns:
            if pattern in platform_lower or pattern in node_id_lower:
                return 'juniper'

        # Arista patterns
        arista_patterns = ['arista', 'eos', 'veos', 'dcs-', 'ccs-']
        for pattern in arista_patterns:
            if pattern in platform_lower or pattern in node_id_lower:
                return 'arista'

        # Cisco patterns
        cisco_patterns = ['cisco', 'ios', 'nx-os', 'nexus', 'catalyst', 'c9', 'ws-c', 'isr', 'asr']
        for pattern in cisco_patterns:
            if pattern in platform_lower or pattern in node_id_lower:
                return 'cisco'

        return None

    def get_node_style(self, node_id: str, platform: str) -> Dict[str, str]:
        """Get complete style dictionary for a node."""
        style = self.style_defaults.copy()
        platform_lower = platform.lower() if platform else ''
        node_id_lower = node_id.lower()

        shape = None

        # First pass: exact matches
        for pattern, shape_value in self.platform_patterns.items():
            if pattern.startswith('_'):  # Skip comments
                continue
            pattern_lower = pattern.lower()
            if pattern_lower == platform_lower or pattern_lower == node_id_lower:
                shape = shape_value
                break

        # Second pass: substring matches (longest first)
        if not shape:
            sorted_patterns = sorted(
                [(k, v) for k, v in self.platform_patterns.items() if not k.startswith('_')],
                key=lambda x: len(x[0]),
                reverse=True
            )
            for pattern, shape_value in sorted_patterns:
                pattern_lower = pattern.lower()
                if pattern_lower in platform_lower or pattern_lower in node_id_lower:
                    shape = shape_value
                    break

        # Third pass: fallback patterns
        if not shape and self.fallback_patterns:
            for fallback_type, fallback_config in self.fallback_patterns.items():
                # Check platform patterns
                for fallback_pattern in fallback_config.get('platform_patterns', []):
                    if fallback_pattern.lower() in platform_lower:
                        shape = fallback_config.get('shape')
                        break

                # Check name patterns
                if not shape:
                    for name_pattern in fallback_config.get('name_patterns', []):
                        if name_pattern.lower() in node_id_lower:
                            shape = fallback_config.get('shape')
                            break

                if shape:
                    break

        # Fourth pass: vendor defaults
        if not shape and self.vendor_defaults:
            for vendor_name, vendor_shape in self.vendor_defaults.items():
                if vendor_name.lower() in platform_lower:
                    shape = vendor_shape
                    break

        # Apply shape if found
        if shape:
            if shape.startswith('shape='):
                shape_value = shape.split('=', 1)[1]
                style['shape'] = shape_value
            else:
                style['shape'] = shape
            style['sketch'] = '0'

        # Apply vendor-specific colors
        vendor = self._detect_vendor(node_id, platform)
        if vendor and vendor in self.vendor_colors:
            style['fillColor'] = self.vendor_colors[vendor]
            style['gradientColor'] = 'none'

        return style


# =============================================================================
# Main Exporter
# =============================================================================

class DrawioExporter:
    """
    Export network topology to Draw.io format.

    Features:
    - Cisco mxgraph stencils for device visualization
    - Vendor-specific coloring (Cisco blue, Juniper orange, Arista green)
    - Tree, balloon, and grid layout algorithms
    - Port labels on edges
    """

    def __init__(
        self,
        use_icons: bool = True,
        include_endpoints: bool = True,
        connected_only: bool = False,
        layout_type: str = 'tree'
    ):
        self.use_icons = use_icons
        self.include_endpoints = include_endpoints
        self.connected_only = connected_only
        self.layout_type = layout_type

        self.icon_manager = DrawioIconManager()
        self.layout_manager = DrawioLayoutManager(layout_type)

        self.node_id_map: Dict[str, str] = {}
        self.edge_id_map: Dict[tuple, str] = {}
        self.next_id = 1

        self.mac_pattern = re.compile(r'^([0-9a-f]{4}\.){2}[0-9a-f]{4}$', re.IGNORECASE)

    # -----------------------------------------------------------------
    # Viewer position → DrawIO coordinate conversion
    #
    # Cytoscape positions are node-center in an arbitrary coordinate
    # system with potentially negative values.  DrawIO positions are
    # top-left with positive coordinates.  This mirrors the approach
    # from netaudit's drawio-export.js._buildPositions().
    # -----------------------------------------------------------------

    @staticmethod
    def _positions_from_viewer(
        data: Dict,
        viewer_pos: Dict[str, Dict[str, float]],
        node_w: int = 60,
        node_h: int = 60,
        scale: float = 1.8,
        margin: int = 80,
    ) -> Dict[str, Tuple[int, int]]:
        """
        Convert Cytoscape center-based positions to DrawIO top-left positions.

        Args:
            data: Preprocessed topology (determines which nodes need positions)
            viewer_pos: {node_id: {"x": float, "y": float}} from Cytoscape
            node_w: DrawIO node width
            node_h: DrawIO node height
            scale: Scale factor (Cytoscape spacing is tighter than DrawIO)
            margin: Pixel margin around the diagram
        """
        positions = {}
        node_ids = list(data.keys())
        half_w = node_w / 2
        half_h = node_h / 2

        # Find bounding box of viewer positions
        min_x = float('inf')
        min_y = float('inf')
        matched = 0
        for nid in node_ids:
            pos = viewer_pos.get(nid)
            if pos:
                min_x = min(min_x, pos['x'])
                min_y = min(min_y, pos['y'])
                matched += 1

        if matched > 0:
            for nid in node_ids:
                pos = viewer_pos.get(nid)
                if pos:
                    # Center → top-left, normalize to positive, scale up
                    positions[nid] = (
                        int((pos['x'] - min_x) * scale + margin - half_w),
                        int((pos['y'] - min_y) * scale + margin - half_h),
                    )
                else:
                    # Node exists in topology but wasn't visible in viewer
                    positions[nid] = (margin, margin)
        else:
            # No positions matched — fall back to simple grid
            cols = max(1, int(len(node_ids) ** 0.5))
            for idx, nid in enumerate(sorted(node_ids)):
                col = idx % cols
                row = idx // cols
                positions[nid] = (
                    margin + col * 160,
                    margin + row * 140,
                )

        return positions

    def _reset_state(self) -> None:
        """Reset internal state between exports."""
        self.node_id_map.clear()
        self.edge_id_map.clear()
        self.next_id = 1

    def _get_next_id(self) -> str:
        """Generate next unique cell ID."""
        cell_id = f"node_{self.next_id}"
        self.next_id += 1
        return cell_id

    def _is_endpoint(self, node_id: str, platform: str) -> bool:
        """Determine if a node is an endpoint device."""
        if self.mac_pattern.match(node_id):
            return True

        platform_lower = platform.lower() if platform else ''
        endpoint_keywords = {'endpoint', 'camera', 'phone', 'printer', 'pc', 'workstation'}
        return any(kw in platform_lower for kw in endpoint_keywords)

    def _preprocess_topology(self, data: Dict) -> Dict:
        """Normalize topology and apply filters."""
        # Find all referenced nodes
        defined = set(data.keys())
        referenced = set()

        for node_data in data.values():
            if isinstance(node_data, dict) and 'peers' in node_data:
                referenced.update(node_data['peers'].keys())

        # Add undefined nodes as endpoints
        result = data.copy()
        for node_id in referenced - defined:
            result[node_id] = {
                'node_details': {'ip': '', 'platform': 'endpoint'},
                'peers': {}
            }

        # Filter endpoints if requested
        if not self.include_endpoints:
            endpoints = {
                nid for nid, ndata in result.items()
                if self._is_endpoint(nid, ndata.get('node_details', {}).get('platform', ''))
            }

            filtered = {}
            for node_id, node_data in result.items():
                if node_id not in endpoints:
                    node_copy = node_data.copy()
                    if 'peers' in node_copy:
                        node_copy['peers'] = {
                            pid: pdata for pid, pdata in node_copy['peers'].items()
                            if pid not in endpoints
                        }
                    filtered[node_id] = node_copy
            result = filtered

        # Filter unconnected nodes if requested
        if self.connected_only:
            connected_nodes = set()
            for node_id, node_data in result.items():
                if isinstance(node_data, dict):
                    peers = node_data.get('peers', {})
                    if peers:
                        connected_nodes.add(node_id)
                        connected_nodes.update(peers.keys())

            result = {nid: ndata for nid, ndata in result.items() if nid in connected_nodes}

        return result

    def _create_mxfile(self) -> Tuple[ET.Element, ET.Element]:
        """Create the base mxfile XML structure."""
        mxfile = ET.Element("mxfile")
        mxfile.set("host", "app.diagrams.net")
        mxfile.set("type", "device")

        diagram = ET.SubElement(mxfile, "diagram")
        diagram.set("name", "Network Topology")
        diagram.set("id", "network_diagram_1")

        mxgraph = ET.SubElement(diagram, "mxGraphModel")
        mxgraph.set("dx", "1426")
        mxgraph.set("dy", "798")
        mxgraph.set("grid", "1")
        mxgraph.set("gridSize", "10")
        mxgraph.set("guides", "1")
        mxgraph.set("tooltips", "1")
        mxgraph.set("connect", "1")
        mxgraph.set("arrows", "1")
        mxgraph.set("fold", "1")
        mxgraph.set("page", "1")
        mxgraph.set("pageScale", "1")
        mxgraph.set("pageWidth", "1654")
        mxgraph.set("pageHeight", "1169")
        mxgraph.set("math", "0")
        mxgraph.set("shadow", "0")

        root = ET.SubElement(mxgraph, "root")

        # Add required base cells
        cell0 = ET.SubElement(root, "mxCell")
        cell0.set("id", "root_0")

        cell1 = ET.SubElement(root, "mxCell")
        cell1.set("id", "root_1")
        cell1.set("parent", "root_0")

        return mxfile, root

    def _format_label(self, node_id: str, ip: str, platform: str) -> str:
        """Format multi-line label for node."""
        parts = [node_id]
        if ip:
            parts.append(ip)
        if platform:
            if len(platform) > 40:
                platform = platform[:37] + "..."
            parts.append(platform)
        return "<br>".join(parts)

    def _add_node(
        self,
        root: ET.Element,
        node_id: str,
        node_data: Dict,
        x: int,
        y: int
    ) -> str:
        """Add a node element to the diagram."""
        cell_id = self._get_next_id()
        self.node_id_map[node_id] = cell_id

        cell = ET.SubElement(root, "mxCell")
        cell.set("id", cell_id)

        node_details = node_data.get('node_details', {})
        ip = node_details.get('ip', '')
        platform = node_details.get('platform', 'Unknown')

        label = self._format_label(node_id, ip, platform)
        cell.set("value", label)

        # Get style from icon manager
        style_dict = self.icon_manager.get_node_style(node_id, platform)
        style_dict["html"] = "1"

        style_str = ";".join(f"{k}={v}" for k, v in style_dict.items())
        cell.set("style", style_str)

        cell.set("vertex", "1")
        cell.set("parent", "root_1")

        geometry = ET.SubElement(cell, "mxGeometry")
        geometry.set("x", str(x))
        geometry.set("y", str(y))
        geometry.set("width", "60")
        geometry.set("height", "60")
        geometry.set("as", "geometry")

        return cell_id

    def _add_edge(
        self,
        root: ET.Element,
        source_id: str,
        target_id: str,
        connection: Connection
    ) -> None:
        """Add an edge element to the diagram, or append to existing edge label."""
        edge_key = tuple(sorted([source_id, target_id]))
        conn_label = f"{connection.local_port} → {connection.remote_port}"

        if edge_key in self.edge_id_map:
            # Edge already exists — append this connection to its label
            cell_id = self.edge_id_map[edge_key]
            for cell in root.iter("mxCell"):
                if cell.get("id") == cell_id:
                    existing = cell.get("value", "")
                    cell.set("value", f"{existing}&#xa;{conn_label}")
                    break
            return

        cell_id = self._get_next_id()
        self.edge_id_map[edge_key] = cell_id

        cell = ET.SubElement(root, "mxCell")
        cell.set("id", cell_id)
        cell.set("parent", "root_1")
        cell.set("source", source_id)
        cell.set("target", target_id)
        cell.set("style", self.layout_manager.get_edge_style())
        cell.set("edge", "1")

        cell.set("value", conn_label)

        geometry = ET.SubElement(cell, "mxGeometry")
        geometry.set("relative", "1")
        geometry.set("as", "geometry")

    def export(
        self,
        topology: Dict,
        output_path: Path,
        viewer_positions: Optional[Dict[str, Dict[str, float]]] = None,
    ) -> None:
        """
        Export topology to Draw.io file.

        Args:
            topology: SC2 map format topology dict
            output_path: Output file path
            viewer_positions: Optional Cytoscape node positions {id: {x, y}}.
                              When provided, the DrawIO layout mirrors the
                              interactive viewer instead of computing its own.
        """
        self._reset_state()

        # Preprocess topology
        data = self._preprocess_topology(topology)

        # Build edges list
        edges = []
        for source_id, source_data in data.items():
            if 'peers' in source_data:
                for target_id in source_data['peers']:
                    if target_id in data:
                        edges.append((source_id, target_id))

        # Calculate positions
        if viewer_positions:
            positions = self._positions_from_viewer(
                data, viewer_positions, node_w=60, node_h=60
            )
        else:
            positions = self.layout_manager.get_node_positions(data, edges)

        # Create XML structure
        mxfile_root, cell_root = self._create_mxfile()

        # Add nodes
        for node_id, (x, y) in positions.items():
            if node_id in data:
                node_data = data[node_id]
                self._add_node(cell_root, node_id, node_data, x, y)

        # Add edges
        for source_id, source_data in data.items():
            if 'peers' not in source_data:
                continue
            for target_id, peer_data in source_data['peers'].items():
                if source_id in self.node_id_map and target_id in self.node_id_map:
                    for local_port, remote_port in peer_data.get('connections', []):
                        connection = Connection(local_port, remote_port)
                        self._add_edge(
                            cell_root,
                            self.node_id_map[source_id],
                            self.node_id_map[target_id],
                            connection
                        )

        # Write file
        xml_str = ET.tostring(mxfile_root, encoding='unicode')
        pretty_xml = minidom.parseString(xml_str).toprettyxml(indent="  ")

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(pretty_xml)


# =============================================================================
# CLI
# =============================================================================

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description='Export SC2 topology to Draw.io format'
    )
    parser.add_argument('input', help='Input topology JSON file')
    parser.add_argument('output', help='Output Draw.io file')
    parser.add_argument('--no-icons', action='store_true',
                        help='Use basic shapes instead of Cisco stencils')
    parser.add_argument('--no-endpoints', action='store_true',
                        help='Exclude endpoint devices')
    parser.add_argument('--connected-only', action='store_true',
                        help='Only show connected nodes')
    parser.add_argument('--layout', choices=['tree', 'balloon', 'grid'],
                        default='tree', help='Layout algorithm (default: tree)')

    args = parser.parse_args()

    with open(args.input, 'r') as f:
        topology = json.load(f)

    exporter = DrawioExporter(
        use_icons=not args.no_icons,
        include_endpoints=not args.no_endpoints,
        connected_only=args.connected_only,
        layout_type=args.layout
    )

    exporter.export(topology, Path(args.output))

    print(f"Exported to {args.output}")
    print(f"  Nodes: {len(topology)}")
    print(f"  Layout: {args.layout}")
    print(f"  Vendor coloring: enabled")


if __name__ == '__main__':
    main()