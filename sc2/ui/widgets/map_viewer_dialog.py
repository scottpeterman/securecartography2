"""
SecureCartography v2 - Map Viewer Dialog

Full-featured standalone topology viewer for opening and viewing map JSON files.
Provides layout controls, export options, and theme-aware rendering.

Usage:
    dialog = MapViewerDialog(theme_manager=tm, parent=main_window)
    dialog.show()  # or dialog.exec() for modal

    # Open with file:
    dialog.open_file("/path/to/map.json")
"""

import copy
import json
from pathlib import Path
from typing import Optional, Dict, Any, Set

from PyQt6.QtCore import Qt, pyqtSignal, QTimer
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QLabel, QPushButton,
    QFileDialog, QFrame, QComboBox, QMessageBox, QSizePolicy,
    QToolBar, QStatusBar, QWidget, QCheckBox
)
from PyQt6.QtGui import QAction, QKeySequence

from sc2.ui.themes import ThemeColors, ThemeManager, qss_glyph
from sc2.ui.widgets.topology_viewer import TopologyViewer, SC2_THEMES
from sc2.ui.widgets.platform_icons import PlatformIconManager, get_platform_icon_manager


def theme_colors_to_viewer_theme(theme: ThemeColors) -> Dict[str, str]:
    """Convert SC2 ThemeColors to topology viewer CSS variables."""
    return {
        '--bg-primary': theme.bg_primary,
        '--bg-surface': theme.bg_secondary,
        '--text-primary': theme.text_primary,
        '--text-secondary': theme.text_secondary,
        '--accent-primary': theme.accent,
        '--accent-secondary': theme.accent_dim,
        '--border-color': theme.border_dim,
        '--node-border': theme.accent,
        '--edge-color': theme.text_muted,
    }


def filter_topology(topology_data: Dict, connected_only: bool = True, include_leaves: bool = False,
                    include_undiscovered: Optional[bool] = None) -> Dict:
    """
    Filter topology based on connection criteria.

    Args:
        topology_data: The topology to filter
        connected_only: If True, exclude orphan nodes (no connections either direction)
        include_leaves: If True, include leaf nodes (referenced but no outgoing peers)
                       If False, only show nodes that have outgoing peer connections
        include_undiscovered: If True, include names that exist only as a
                       neighbor reference (failed, excluded, never dialed).
                       None = follow include_leaves (the pre-split behavior).

    Connection types:
    - Orphan: No connections in either direction (always excluded if connected_only=True)
    - Leaf: Referenced by others but has no outgoing peers (servers, endpoints, phones)
    - Infrastructure: Has outgoing peer connections (switches, routers, firewalls)
    """
    if not topology_data:
        return topology_data

    # Handle different topology formats
    if 'nodes' in topology_data:
        # Cytoscape format: {"nodes": [...], "edges": [...]}
        return _filter_cytoscape_format(topology_data, connected_only, include_leaves, include_undiscovered)
    elif 'cytoscape' in topology_data:
        # VelocityMaps format: {"cytoscape": {"nodes": [...], "edges": [...]}}
        filtered_cyto = _filter_cytoscape_format(topology_data['cytoscape'], connected_only, include_leaves,
                                                 include_undiscovered)
        result = topology_data.copy()
        result['cytoscape'] = filtered_cyto
        return result
    else:
        # SC2 map format: {device_name: {peers: {...}, node_details: {...}}}
        return _filter_sc2_format(topology_data, connected_only, include_leaves, include_undiscovered)


def _filter_sc2_format(topology: Dict, connected_only: bool, include_leaves: bool,
                       include_undiscovered: Optional[bool] = None) -> Dict:
    """
    Filter SC2 native format.

    Three kinds of node:
      infrastructure - discovered, reported neighbors (always shown)
      leaf           - discovered, but reported no neighbors of its own
                       (include_leaves)
      undiscovered   - never a top-level entry: exists only as someone's
                       neighbor - failed, excluded or never dialed
                       (include_undiscovered)
    Orphans (discovered, no links either way) are dropped when connected_only.
    """
    if include_undiscovered is None:
        include_undiscovered = include_leaves
    if not connected_only and include_leaves and include_undiscovered:
        return topology

    discovered = {n.lower() for n, d in topology.items() if isinstance(d, dict)}
    referenced: Set[str] = set()
    for node_data in topology.values():
        if isinstance(node_data, dict):
            referenced.update(p.lower() for p in node_data.get('peers', {}))

    # IMPORTANT: deep copy to avoid mutating the original topology data
    filtered: Dict[str, Any] = {}
    for node_name, node_data in topology.items():
        if not isinstance(node_data, dict):
            continue
        has_peers = bool(node_data.get('peers'))
        is_referenced = node_name.lower() in referenced
        if has_peers:
            keep = True
        elif is_referenced:
            keep = include_leaves
        else:
            keep = not connected_only
        if keep:
            filtered[node_name] = copy.deepcopy(node_data)

    # Trim peer references: keep links to shown discovered nodes, and to
    # undiscovered names only when those are wanted.
    kept = {n.lower() for n in filtered}
    for node_data in filtered.values():
        peers = node_data.get('peers') or {}
        node_data['peers'] = {
            p: v for p, v in peers.items()
            if p.lower() in kept or (include_undiscovered and p.lower() not in discovered)
        }

    # Post-trim orphan sweep: trimming may leave a node with no links at all
    if connected_only:
        still_referenced: Set[str] = set()
        for node_data in filtered.values():
            still_referenced.update(p.lower() for p in node_data.get('peers', {}))
        for name in [n for n, d in filtered.items()
                     if not d.get('peers') and n.lower() not in still_referenced]:
            del filtered[name]

    return filtered


def _filter_cytoscape_format(cyto_data: Dict, connected_only: bool, include_leaves: bool,
                             include_undiscovered: Optional[bool] = None) -> Dict:
    """Filter Cytoscape format based on connection criteria."""
    nodes = cyto_data.get('nodes', [])
    edges = cyto_data.get('edges', [])

    if include_undiscovered is None:
        include_undiscovered = include_leaves
    if not include_undiscovered:
        hidden = {
            n.get('data', n).get('id', '') for n in nodes
            if n.get('data', n).get('discovered') is False
        }
        if hidden:
            nodes = [n for n in nodes if n.get('data', n).get('id', '') not in hidden]
            edges = [e for e in edges
                     if e.get('data', e).get('source', '') not in hidden
                     and e.get('data', e).get('target', '') not in hidden]

    if not connected_only and include_leaves:
        # No further filtering needed
        return {'nodes': nodes, 'edges': edges}

    # Build set of node IDs that are sources (have outgoing connections)
    source_ids: Set[str] = set()
    # Build set of node IDs that are targets (referenced by others)
    target_ids: Set[str] = set()

    for edge in edges:
        edge_data = edge.get('data', edge)
        source = edge_data.get('source', '')
        target = edge_data.get('target', '')
        if source:
            source_ids.add(source)
        if target:
            target_ids.add(target)

    # Filter nodes based on criteria
    filtered_nodes = []
    included_ids: Set[str] = set()

    for node in nodes:
        node_data = node.get('data', node)
        node_id = node_data.get('id', '')

        is_source = node_id in source_ids  # Has outgoing connections
        is_target = node_id in target_ids  # Referenced by others
        is_connected = is_source or is_target

        # Determine if node should be included
        if is_source:
            # Infrastructure node - always include
            filtered_nodes.append(node)
            included_ids.add(node_id)
        elif is_target:
            # Leaf node - include only if include_leaves is True
            if include_leaves:
                filtered_nodes.append(node)
                included_ids.add(node_id)
        else:
            # Orphan node - include only if connected_only is False
            if not connected_only:
                filtered_nodes.append(node)
                included_ids.add(node_id)

    # Filter edges to only include those between included nodes
    filtered_edges = []
    for edge in edges:
        edge_data = edge.get('data', edge)
        source = edge_data.get('source', '')
        target = edge_data.get('target', '')
        if source in included_ids and target in included_ids:
            filtered_edges.append(edge)

    # Post-filter orphan sweep: edge filtering may have left nodes with no
    # remaining connections.  When connected_only, drop those stranded nodes.
    if connected_only:
        still_connected: Set[str] = set()
        for edge in filtered_edges:
            ed = edge.get('data', edge)
            still_connected.add(ed.get('source', ''))
            still_connected.add(ed.get('target', ''))

        filtered_nodes = [
            n for n in filtered_nodes
            if n.get('data', n).get('id', '') in still_connected
        ]
        included_ids = still_connected & included_ids

    return {
        'nodes': filtered_nodes,
        'edges': filtered_edges
    }


class MapViewerDialog(QDialog):
    """
    Full-featured Map Viewer dialog.

    Features:
    - Open map JSON files (SC2, VelocityMaps, or raw Cytoscape formats)
    - Interactive topology view with pan/zoom
    - Multiple layout algorithms
    - Export to PNG
    - Theme-aware

    Signals:
        file_loaded(str): Emitted when a file is successfully loaded (path)
    """

    file_loaded = pyqtSignal(str)

    def __init__(
            self,
            theme_manager: Optional[ThemeManager] = None,
            icon_manager: Optional[PlatformIconManager] = None,
            parent: Optional[QWidget] = None
    ):
        super().__init__(parent)

        self.theme_manager = theme_manager
        self._current_theme: Optional[ThemeColors] = None
        self._icon_manager = icon_manager or get_platform_icon_manager()
        self._current_file: Optional[Path] = None
        # Folder exports/open default to when no file is loaded (in-memory
        # map from a crawl): the crawl's output directory.
        self._export_dir: Optional[Path] = None
        self._topology_data: Optional[Dict] = None  # Original unfiltered data
        self._viewer_ready = False
        self._connected_only = True  # Default: ON (matches CLI behavior)
        self._include_leaves = False  # Default: OFF (hide leaf/endpoint nodes)
        self._include_undiscovered = False  # Default: OFF (hide failed/excluded/not-dialed placeholders)

        self.setWindowTitle("Map Viewer")
        self.setMinimumSize(1000, 700)
        self.resize(1200, 800)

        self._setup_ui()
        self._connect_signals()

        if theme_manager:
            self.apply_theme(theme_manager.theme)

    def _setup_ui(self):
        """Build the dialog UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Toolbar
        self._toolbar = self._create_toolbar()
        layout.addWidget(self._toolbar)

        # Topology viewer (main content - no splitter needed now)
        self._viewer = TopologyViewer(
            show_controls=False,
            icon_manager=self._icon_manager
        )
        self._viewer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        layout.addWidget(self._viewer, 1)

        # Status bar
        self._status_bar = QStatusBar()
        self._status_bar.setObjectName("mapViewerStatus")
        self._status_label = QLabel("No map loaded")
        self._status_bar.addWidget(self._status_label)

        self._stats_label = QLabel("")
        self._status_bar.addPermanentWidget(self._stats_label)

        layout.addWidget(self._status_bar)

    def _create_toolbar(self) -> QToolBar:
        """Create the toolbar with actions."""
        toolbar = QToolBar("Map Viewer Tools")
        toolbar.setObjectName("mapViewerToolbar")
        toolbar.setMovable(False)
        toolbar.setIconSize(toolbar.iconSize())

        # Open file
        open_action = QAction("📂 Open", self)
        open_action.setShortcut(QKeySequence.StandardKey.Open)
        open_action.setToolTip("Open map JSON file (Ctrl+O)")
        open_action.triggered.connect(self._on_open_file)
        toolbar.addAction(open_action)

        toolbar.addSeparator()

        # Layout selector
        layout_label = QLabel(" Layout: ")
        toolbar.addWidget(layout_label)

        self._layout_combo = QComboBox()
        self._layout_combo.setObjectName("layoutCombo")
        self._layout_combo.setFixedWidth(160)
        self._layout_combo.addItem("Dagre ↓ Top→Bottom", "dagre")
        self._layout_combo.addItem("Dagre → Left→Right", "dagre-lr")
        self._layout_combo.addItem("Breadthfirst", "breadthfirst")
        self._layout_combo.addItem("fCoSE (Fast Compound)", "fcose")
        self._layout_combo.addItem("CoSE (Built-in)", "cose")
        self._layout_combo.addItem("Cola (Constraint)", "cola")
        self._layout_combo.addItem("Concentric", "concentric")
        self._layout_combo.addItem("Circle", "circle")
        self._layout_combo.addItem("Grid", "grid")
        self._layout_combo.setCurrentIndex(0)
        self._layout_combo.currentIndexChanged.connect(self._on_layout_changed)
        toolbar.addWidget(self._layout_combo)

        toolbar.addSeparator()

        # Connected-only checkbox
        self._connected_only_checkbox = QCheckBox("Connected Only")
        self._connected_only_checkbox.setObjectName("connectedOnlyCheckbox")
        self._connected_only_checkbox.setToolTip(
            "Show only devices with connections\n"
            "(hides standalone/orphan nodes)"
        )
        self._connected_only_checkbox.setChecked(True)
        self._connected_only_checkbox.stateChanged.connect(self._on_connected_only_changed)
        toolbar.addWidget(self._connected_only_checkbox)

        # Show Leaves checkbox
        self._show_leaves_checkbox = QCheckBox("Show Leaves")
        self._show_leaves_checkbox.setObjectName("showLeavesCheckbox")
        self._show_leaves_checkbox.setToolTip(
            "Show discovered devices that reported no\n"
            "neighbors of their own (edge of the map).\n"
            "Uncheck for infrastructure-only view."
        )
        self._show_leaves_checkbox.setChecked(False)
        self._show_leaves_checkbox.stateChanged.connect(self._on_show_leaves_changed)
        toolbar.addWidget(self._show_leaves_checkbox)

        # Show Undiscovered checkbox
        self._show_undiscovered_checkbox = QCheckBox("Show Undiscovered")
        self._show_undiscovered_checkbox.setObjectName("showUndiscoveredCheckbox")
        self._show_undiscovered_checkbox.setToolTip(
            "Show names seen only as a neighbor:\n"
            "failed, excluded, or never dialed (drawn as placeholders)."
        )
        self._show_undiscovered_checkbox.setChecked(False)
        self._show_undiscovered_checkbox.stateChanged.connect(self._on_show_undiscovered_changed)
        toolbar.addWidget(self._show_undiscovered_checkbox)

        toolbar.addSeparator()

        # View controls
        fit_action = QAction("⊡ Fit View", self)
        fit_action.setShortcut(QKeySequence("F"))
        fit_action.setToolTip("Fit view to all devices (F)")
        fit_action.triggered.connect(self._on_fit_view)
        toolbar.addAction(fit_action)

        refresh_action = QAction("↻ Reload", self)
        refresh_action.setShortcut(QKeySequence.StandardKey.Refresh)
        refresh_action.setToolTip("Reload current file (F5)")
        refresh_action.triggered.connect(self._on_reload)
        toolbar.addAction(refresh_action)

        focus_action = QAction("🎯 Focus Map", self)
        focus_action.setShortcut(QKeySequence("Ctrl+Shift+F"))
        focus_action.setToolTip(
            "Open selected nodes in new viewer (Ctrl+Shift+F)\n"
            "Shift+click or drag to multi-select"
        )
        focus_action.triggered.connect(self._on_create_focus_map)
        toolbar.addAction(focus_action)
        poll_action = QAction("🔍 Poll Device", self)
        poll_action.setToolTip("SNMP poll selected device for fingerprinting")
        poll_action.triggered.connect(self._on_poll_device)
        toolbar.addAction(poll_action)
        toolbar.addSeparator()

        # Export dropdown
        export_label = QLabel(" Export: ")
        toolbar.addWidget(export_label)

        self._export_combo = QComboBox()
        self._export_combo.setObjectName("exportCombo")
        self._export_combo.setFixedWidth(100)
        self._export_combo.addItem("PNG", "png")
        self._export_combo.addItem("yEd", "graphml")
        self._export_combo.addItem("Draw.io", "drawio")
        self._export_combo.addItem("CSV", "csv")
        self._export_combo.addItem("JSON", "json")
        self._export_combo.setCurrentIndex(-1)
        self._export_combo.setPlaceholderText("Select...")
        self._export_combo.currentIndexChanged.connect(self._on_export_selected)
        toolbar.addWidget(self._export_combo)

        # Rebuild button
        rebuild_action = QAction("🔄 Rebuild", self)
        rebuild_action.setToolTip("Rebuild topology from all device.json files in the map's directory")
        rebuild_action.triggered.connect(self._on_rebuild_map)
        toolbar.addAction(rebuild_action)

        toolbar.addSeparator()

        # Layout persistence
        save_layout_action = QAction("💾 Save Layout", self)
        save_layout_action.setShortcut(QKeySequence("Ctrl+S"))
        save_layout_action.setToolTip("Save current node positions (Ctrl+S)")
        save_layout_action.triggered.connect(self._on_save_layout)
        toolbar.addAction(save_layout_action)

        clear_layout_action = QAction("🗑 Clear Layout", self)
        clear_layout_action.setToolTip("Delete saved layout for this map")
        clear_layout_action.triggered.connect(self._on_clear_layout)
        toolbar.addAction(clear_layout_action)

        # Spacer
        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        toolbar.addWidget(spacer)

        # Help button
        help_action = QAction("? Help", self)
        help_action.setShortcut(QKeySequence.StandardKey.HelpContents)
        help_action.setToolTip("Keyboard shortcuts and tips")
        help_action.triggered.connect(self._on_show_help)
        toolbar.addAction(help_action)

        # Close button
        close_action = QAction("✕ Close", self)
        close_action.setShortcut(QKeySequence.StandardKey.Close)
        close_action.triggered.connect(self.close)
        toolbar.addAction(close_action)

        return toolbar

    def _on_poll_device(self):
        """Poll selected device via SNMP"""
        if not self._viewer_ready:
            return

        def on_selection(selected_ids):
            if len(selected_ids) != 1:
                QMessageBox.information(
                    self, "Poll Device",
                    "Select a single node to poll"
                )
                return

            node_id = selected_ids[0]
            node_data = self._get_node_data(node_id)

            ip = node_data.get('ip', '')
            if not ip:
                QMessageBox.warning(
                    self, "Poll Device",
                    f"No IP address for {node_id}"
                )
                return

            from sc2.ui.widgets.device_poll_dialog import DevicePollDialog

            dialog = DevicePollDialog(
                ip=ip,
                hostname=node_id,
                theme_manager=self.theme_manager,
                parent=self
            )
            dialog.node_update_available.connect(
                lambda data: self._on_node_updated(data)
            )
            dialog.exec()

        self._viewer.get_selected_nodes(on_selection)

    def _get_node_data(self, node_id: str) -> Dict:
        """Get node data from topology by ID"""
        if self._topology_data is None:
            return {}

        # Handle different formats
        if 'nodes' in self._topology_data:
            for node in self._topology_data['nodes']:
                if node.get('data', node).get('id') == node_id:
                    return node.get('data', node)
        elif 'cytoscape' in self._topology_data:
            for node in self._topology_data['cytoscape'].get('nodes', []):
                if node.get('data', node).get('id') == node_id:
                    return node.get('data', node)
        else:
            # SC2 format
            if node_id in self._topology_data:
                details = self._topology_data[node_id].get('node_details', {})
                return {'id': node_id, **details}

        return {'id': node_id}

    def _on_show_help(self):
        """Show keyboard shortcuts and tips."""
        QMessageBox.information(
            self, "Map Viewer Help",
            "Keyboard Shortcuts:\n\n"
            "Ctrl+O\t\tOpen file\n"
            "F\t\tFit view\n"
            "F5\t\tReload\n"
            "Ctrl+S\t\tSave layout\n"
            "Ctrl+Shift+F\tFocus map from selection\n"
            "Ctrl+W\t\tClose\n\n"
            "Mouse:\n\n"
            "Click\t\tSelect node\n"
            "Shift+Click\tAdd to selection\n"
            "Drag\t\tPan view\n"
            "Drag on node\tMove node\n"
            "Scroll\t\tZoom\n"
            "Double-click\tEdit node\n\n"
            "Layout:\n\n"
            "Save Layout persists positions to a .layout.json\n"
            "file next to the map. Positions are auto-restored\n"
            "when the map is reopened."
        )

    def _on_export_selected(self, index: int):
        """Handle export dropdown selection."""
        if index < 0:
            return

        export_type = self._export_combo.itemData(index)

        # Reset combo to placeholder state
        self._export_combo.blockSignals(True)
        self._export_combo.setCurrentIndex(-1)
        self._export_combo.blockSignals(False)

        if export_type == "png":
            self._on_export_png()
        elif export_type == "graphml":
            self._on_export_graphml()
        elif export_type == "drawio":
            self._on_export_drawio()
        elif export_type == "csv":
            self._on_export_csv()
        elif export_type == "json":
            self._on_save_map()

    def _connect_signals(self):
        """Connect viewer signals."""
        self._viewer.ready.connect(self._on_viewer_ready)

        # Node editing (requires updated topology_viewer.py with node_edit_requested signal)
        if hasattr(self._viewer, 'node_edit_requested'):
            self._viewer.node_edit_requested.connect(self._on_node_edit_requested)

    def _on_create_focus_map(self):
        """Create a new viewer with only selected nodes and their interconnections."""
        if not self._viewer_ready or self._topology_data is None:
            QMessageBox.warning(self, "Focus Map", "No topology loaded.")
            return

        def on_selection(selected_ids):
            if not selected_ids:
                QMessageBox.information(
                    self, "Focus Map",
                    "Select one or more nodes first.\n\n"
                    "Shift+click to add to selection\n"
                    "Or drag a box to select multiple"
                )
                return

            # Extract subgraph with only selected nodes
            subgraph = self._extract_subgraph(set(selected_ids))
            if not subgraph:
                QMessageBox.warning(self, "Focus Map", "Could not extract subgraph.")
                return

            # Create new viewer — disable filtering since the subgraph is
            # already scoped; re-filtering would drop orphaned single nodes.
            focus_viewer = MapViewerDialog(
                theme_manager=self.theme_manager,
                icon_manager=self._icon_manager,
                parent=self.parent()
            )
            focus_viewer.set_export_dir(self._current_file.parent if self._current_file else self._export_dir)
            focus_viewer._connected_only = False
            focus_viewer._include_leaves = True
            focus_viewer._include_undiscovered = True
            focus_viewer._show_undiscovered_checkbox.setChecked(True)
            focus_viewer._connected_only_checkbox.setChecked(False)
            focus_viewer._show_leaves_checkbox.setChecked(True)
            focus_viewer.load_topology(subgraph, f"Focus ({len(selected_ids)} nodes)")
            focus_viewer.show()

        self._viewer.get_selected_nodes(on_selection)

    def set_export_dir(self, path) -> None:
        """Default folder for export/open dialogs when no map file is loaded."""
        self._export_dir = Path(path) if path else None

    def _default_path(self, suffix: str, fallback_stem: str = "topology") -> str:
        """
        Default file path for save dialogs: next to the loaded map file, else
        in the crawl output folder, else the home directory.
        """
        if self._current_file:
            folder, stem = self._current_file.parent, self._current_file.stem
        else:
            folder = self._export_dir if (self._export_dir and self._export_dir.is_dir()) else Path.home()
            stem = fallback_stem
        return str(folder / f"{stem}{suffix}")

    def _extract_subgraph(self, node_ids: set) -> Optional[Dict]:
        """Extract subgraph containing only specified nodes and their interconnections."""
        if not self._topology_data or not node_ids:
            return None

        # Work from filtered data so focus map respects current view settings
        display_data = self._get_display_topology()
        if not display_data:
            return None

        # Handle different formats
        if 'nodes' in display_data:
            return self._extract_subgraph_cytoscape(display_data, node_ids)
        elif 'cytoscape' in display_data:
            cyto_sub = self._extract_subgraph_cytoscape(display_data['cytoscape'], node_ids)
            return {'cytoscape': cyto_sub} if cyto_sub else None
        else:
            return self._extract_subgraph_sc2(display_data, node_ids)

    def _extract_subgraph_cytoscape(self, cyto_data: Dict, node_ids: set) -> Dict:
        """Extract subgraph from Cytoscape format with 1-hop neighbor expansion."""
        edges = cyto_data.get('edges', [])

        # Expand to 1-hop neighbors
        include_ids = set(node_ids)
        for e in edges:
            ed = e.get('data', e)
            src, tgt = ed.get('source', ''), ed.get('target', '')
            if src in node_ids:
                include_ids.add(tgt)
            if tgt in node_ids:
                include_ids.add(src)

        # Filter nodes
        nodes = [
            n for n in cyto_data.get('nodes', [])
            if n.get('data', n).get('id') in include_ids
        ]

        # Filter edges - keep only those connecting included nodes
        filtered_edges = [
            e for e in edges
            if e.get('data', e).get('source') in include_ids
               and e.get('data', e).get('target') in include_ids
        ]

        return {'nodes': nodes, 'edges': filtered_edges}

    def _extract_subgraph_sc2(self, sc2_data: Dict, node_ids: set) -> Dict:
        """
        Extract subgraph from SC2 map format.

        Expands selection to include 1-hop neighbors so that a single-node
        selection produces a useful neighborhood view.  Undiscovered peers
        (nodes that exist only inside ``peers`` dicts, not as top-level keys)
        are represented as stub entries so they render in the focus viewer.
        """
        subgraph = {}

        # Case-insensitive lookup helpers
        node_ids_lower = {n.lower() for n in node_ids}

        def _matches(name: str) -> bool:
            return name in include_ids or name.lower() in include_ids_lower

        # --- Expand selection to 1-hop neighbors ---
        # Walk full topology (not just display-filtered) so we catch peers
        # that are undiscovered or filtered out of the current view.
        include_ids = set(node_ids)
        for node_name, node_data in sc2_data.items():
            if not isinstance(node_data, dict):
                continue
            if node_name in node_ids or node_name.lower() in node_ids_lower:
                # Selected node — pull in all its peers
                for peer_name in node_data.get('peers', {}):
                    include_ids.add(peer_name)
            else:
                # Not selected — but if it peers with a selected node, include it
                for peer_name in node_data.get('peers', {}):
                    if peer_name in node_ids or peer_name.lower() in node_ids_lower:
                        include_ids.add(node_name)
                        break

        include_ids_lower = {n.lower() for n in include_ids}

        # --- Build subgraph from discovered devices ---
        for node_name, node_data in sc2_data.items():
            if not isinstance(node_data, dict):
                continue
            if not _matches(node_name):
                continue

            node_copy = copy.deepcopy(node_data)

            # Keep only peers that are in the expanded set
            if 'peers' in node_copy:
                filtered_peers = {}
                for peer_name, peer_data in node_copy['peers'].items():
                    if _matches(peer_name):
                        filtered_peers[peer_name] = peer_data
                node_copy['peers'] = filtered_peers

            subgraph[node_name] = node_copy

        # --- Create stub entries for undiscovered peers ---
        # These are nodes referenced in peers dicts but missing as top-level
        # keys (e.g. servers, endpoints that were never fully discovered).
        all_referenced = set()
        for node_data in subgraph.values():
            for peer_name in node_data.get('peers', {}):
                all_referenced.add(peer_name)

        for peer_name in all_referenced:
            if peer_name not in subgraph:
                subgraph[peer_name] = {
                    'node_details': {'ip': '', 'platform': 'Undiscovered'},
                    'peers': {}
                }

        return subgraph

    def _on_connected_only_changed(self, state: int):
        """Handle connected-only checkbox toggle - refilter and reload view."""
        self._connected_only = (state == Qt.CheckState.Checked.value)

        # Reload the view with updated filter
        if self._topology_data and self._viewer_ready:
            self._load_topology_to_viewer()
            self._update_stats()

    def _on_show_leaves_changed(self, state: int):
        """Handle show-leaves checkbox toggle - refilter and reload view."""
        self._include_leaves = (state == Qt.CheckState.Checked.value)

        # Reload the view with updated filter
        if self._topology_data and self._viewer_ready:
            self._load_topology_to_viewer()
            self._update_stats()

    def _on_show_undiscovered_changed(self, state: int):
        """Handle show-undiscovered checkbox toggle - refilter and reload view."""
        self._include_undiscovered = (state == Qt.CheckState.Checked.value)
        if self._topology_data and self._viewer_ready:
            self._load_topology_to_viewer()
            self._update_stats()

    def _on_export_csv(self):
        """Export device inventory to CSV."""
        if self._topology_data is None:
            QMessageBox.warning(self, "Export", "No topology loaded to export.")
            return

        # Get save path
        start_dir = self._default_path(".csv", "devices")

        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Device Inventory to CSV",
            start_dir,
            "CSV Files (*.csv)"
        )

        if not path:
            return

        try:
            import csv

            # Get filtered topology (respects current view filters)
            display_data = self._get_export_topology()
            devices = self._extract_device_inventory(display_data)

            if not devices:
                QMessageBox.warning(self, "Export", "No devices to export.")
                return

            # Collect all fields across all devices
            all_fields = set()
            for device in devices:
                all_fields.update(device.keys())

            # Order fields sensibly
            priority = ['hostname', 'ip', 'platform', 'model', 'serial', 'version', 'site', 'role']
            fieldnames = [f for f in priority if f in all_fields]
            fieldnames += sorted(f for f in all_fields if f not in fieldnames)

            with open(path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(devices)

            self._status_label.setText(f"Exported: {Path(path).name} ({len(devices)} devices)")

        except Exception as e:
            QMessageBox.warning(self, "Export Failed", f"Error exporting CSV: {e}")

    def _extract_device_inventory(self, data: Optional[Dict]) -> list:
        """Extract flat device inventory from topology data."""
        if not data:
            return []

        devices = []

        if 'nodes' in data:
            # Cytoscape format
            for node in data.get('nodes', []):
                node_data = node.get('data', node)
                devices.append(dict(node_data))

        elif 'cytoscape' in data:
            # VelocityMaps format
            return self._extract_device_inventory(data['cytoscape'])

        else:
            # SC2 map format
            for device_name, device_data in data.items():
                if not isinstance(device_data, dict):
                    continue

                node_details = device_data.get('node_details', {})
                record = {'hostname': device_name}

                # Pull from node_details first, then top-level
                for key in ['ip', 'platform', 'model', 'serial', 'version', 'site', 'role', 'vendor']:
                    val = node_details.get(key) or device_data.get(key)
                    if val:
                        record[key] = val

                # Add any other scalar fields from node_details
                for k, v in node_details.items():
                    if k not in record and isinstance(v, (str, int, float, bool)):
                        record[k] = v

                devices.append(record)

        return devices

    def _extract_nodes_edges(self, data: Optional[Dict]) -> tuple:
        """
        Extract nodes and edges from topology data in any supported format.

        Returns:
            Tuple of (nodes_list, edges_list) where each is a list of dicts
        """
        if not data:
            return [], []

        nodes = []
        edges = []

        if 'nodes' in data:
            # Cytoscape format: {"nodes": [...], "edges": [...]}
            for node in data.get('nodes', []):
                node_data = node.get('data', node)
                nodes.append(dict(node_data))

            for edge in data.get('edges', []):
                edge_data = edge.get('data', edge)
                edges.append({
                    'source': edge_data.get('source', ''),
                    'source_port': edge_data.get('source_port', edge_data.get('sourcePort', '')),
                    'target': edge_data.get('target', ''),
                    'target_port': edge_data.get('target_port', edge_data.get('targetPort', '')),
                    'edge_id': edge_data.get('id', f"{edge_data.get('source', '')}-{edge_data.get('target', '')}")
                })

        elif 'cytoscape' in data:
            # VelocityMaps format: {"cytoscape": {"nodes": [...], "edges": [...]}}
            return self._extract_nodes_edges(data['cytoscape'])

        else:
            # SC2 map format: {device_name: {peers: {...}, node_details: {...}}}
            seen_edges = set()

            for device_name, device_data in data.items():
                if not isinstance(device_data, dict):
                    continue

                # Build node record
                node_details = device_data.get('node_details', {})
                node_record = {
                    'id': device_name,
                    'label': device_name,
                    'hostname': device_name,
                    'ip': node_details.get('ip', device_data.get('ip', '')),
                    'platform': node_details.get('platform', device_data.get('platform', '')),
                    'model': node_details.get('model', device_data.get('model', '')),
                    'site': node_details.get('site', device_data.get('site', '')),
                }
                # Add any extra fields from node_details
                for k, v in node_details.items():
                    if k not in node_record and isinstance(v, (str, int, float, bool)):
                        node_record[k] = v
                nodes.append(node_record)

                # Build edge records from peers
                for peer_name, peer_data in device_data.get('peers', {}).items():
                    # Canonical edge key to avoid duplicate edges (A→B and B→A)
                    edge_key = tuple(sorted([device_name, peer_name]))
                    if edge_key in seen_edges:
                        continue
                    seen_edges.add(edge_key)

                    # Read connections array from SC2 format:
                    # "connections": [["Eth3/1", "Eth3/1"], ["Eth3/2", "Eth3/2"]]
                    connections = []
                    if isinstance(peer_data, dict):
                        connections = peer_data.get('connections', [])
                    elif isinstance(peer_data, list):
                        connections = peer_data

                    if connections:
                        # Build label listing all interface pairs
                        conn_labels = []
                        for conn in connections:
                            if isinstance(conn, (list, tuple)) and len(conn) >= 2:
                                conn_labels.append(f"{conn[0]} ↔ {conn[1]}")
                        label = '\n'.join(conn_labels)

                        # First connection for source/target ports
                        first = connections[0] if connections else ['', '']
                        source_port = first[0] if isinstance(first, (list, tuple)) and len(first) >= 1 else ''
                        target_port = first[1] if isinstance(first, (list, tuple)) and len(first) >= 2 else ''
                    else:
                        label = ''
                        source_port = ''
                        target_port = ''

                    edges.append({
                        'source': device_name,
                        'source_port': source_port,
                        'target': peer_name,
                        'target_port': target_port,
                        'edge_id': f"{device_name}--{peer_name}",
                        'label': label,
                        'connection_count': len(connections),
                        'connections': connections,
                    })

        return nodes, edges

    def _get_display_topology(self) -> Optional[Dict]:
        """Get topology data for display, applying filters based on checkbox states."""
        if self._topology_data is None:
            return None

        # Apply filtering based on current checkbox states
        return filter_topology(
            self._topology_data,
            connected_only=self._connected_only,
            include_leaves=self._include_leaves,
            include_undiscovered=self._include_undiscovered,
        )

    @staticmethod
    def _normalize_to_sc2_format(data: Optional[Dict]) -> Optional[Dict]:
        """
        Convert any supported topology format to SC2 native format.

        SC2 native format: {hostname: {"node_details": {...}, "peers": {...}}, ...}

        This ensures exporters (DrawIO, GraphML) receive a consistent format
        regardless of whether the data was loaded from file or from live
        discovery.

        Supports:
        - SC2 native format (pass-through)
        - Cytoscape format: {"nodes": [...], "edges": [...]}
        - VelocityMaps format: {"cytoscape": {"nodes": [...], "edges": [...]}}
        """
        if not data:
            return data

        # Already SC2 native format — no 'nodes' or 'cytoscape' top-level keys
        if 'nodes' not in data and 'cytoscape' not in data:
            return data

        # Unwrap VelocityMaps format
        if 'cytoscape' in data:
            cyto_data = data['cytoscape']
        else:
            cyto_data = data

        nodes_list = cyto_data.get('nodes', [])
        edges_list = cyto_data.get('edges', [])

        # Build SC2 format
        sc2_map: Dict[str, Any] = {}

        # Create node entries
        for node in nodes_list:
            nd = node.get('data', node)
            node_id = nd.get('id', '')
            if not node_id:
                continue

            # Gather node_details from flat Cytoscape data fields
            details: Dict[str, Any] = {}
            for key in ('ip', 'platform', 'model', 'serial', 'version',
                        'site', 'role', 'vendor', 'notes'):
                val = nd.get(key)
                if val:
                    details[key] = val

            sc2_map[node_id] = {
                'node_details': details,
                'peers': {},
            }

        # Group edges by source -> target, collecting connection info
        for edge in edges_list:
            ed = edge.get('data', edge)
            source = ed.get('source', '')
            target = ed.get('target', '')
            if not source or not target:
                continue

            # Ensure both nodes exist (edges may reference nodes not in
            # the filtered node list)
            for nid in (source, target):
                if nid not in sc2_map:
                    sc2_map[nid] = {
                        'node_details': {},
                        'peers': {},
                    }

            # Build connection pair
            source_port = ed.get('source_port', ed.get('sourcePort', ''))
            target_port = ed.get('target_port', ed.get('targetPort', ''))

            if source not in sc2_map:
                continue

            peers = sc2_map[source]['peers']
            if target not in peers:
                peers[target] = {'connections': []}

            if source_port or target_port:
                peers[target]['connections'].append(
                    [source_port or '', target_port or '']
                )

        return sc2_map

    def _get_export_topology(self) -> Optional[Dict]:
        """
        Get filtered topology data normalized to SC2 native format for export.

        All export code paths should use this instead of _get_display_topology()
        so that exporters receive a consistent format regardless of how the
        data was originally loaded.
        """
        display_data = self._get_display_topology()
        return self._normalize_to_sc2_format(display_data)

    def _load_topology_to_viewer(self):
        """Load the (potentially filtered) topology into the viewer."""
        display_data = self._get_display_topology()
        if display_data and self._viewer_ready:
            self._viewer.load_topology(display_data)
            QTimer.singleShot(500, self._viewer.fit_view)

    def _on_node_edit_requested(self, node_data: dict):
        """Handle double-click request to edit a node."""
        from sc2.ui.widgets.node_edit_dialog import NodeEditDialog

        dialog = NodeEditDialog(
            node_data=node_data,
            theme_manager=self.theme_manager,
            parent=self
        )

        dialog.node_updated.connect(self._on_node_updated)
        dialog.exec()

    def _on_node_updated(self, updated_data: dict):
        """Handle node data update from edit dialog."""
        node_id = updated_data.get('id')
        if not node_id:
            return

        # Update local topology data (the original, unfiltered data)
        if self._topology_data:
            # Detect format and update accordingly
            if 'nodes' in self._topology_data:
                # Cytoscape format: {"nodes": [...], "edges": [...]}
                self._update_cytoscape_node(self._topology_data, node_id, updated_data)
            elif 'cytoscape' in self._topology_data:
                # VelocityMaps format: {"cytoscape": {"nodes": [...], "edges": [...]}}
                self._update_cytoscape_node(self._topology_data['cytoscape'], node_id, updated_data)
            else:
                # SC2 map format (dict of device_name -> data)
                self._update_sc2_node(node_id, updated_data)

        # Push update to JS viewer (requires updated topology_viewer.py)
        if hasattr(self._viewer, 'update_node'):
            self._viewer.update_node(node_id, updated_data)

        self._status_label.setText(f"Updated: {updated_data.get('label', node_id)}")

    def _update_sc2_node(self, node_id: str, updated_data: dict):
        """Update or create a node in SC2 map format."""
        if node_id in self._topology_data:
            # Existing discovered device - update node_details
            device_data = self._topology_data[node_id]
            if 'node_details' not in device_data:
                device_data['node_details'] = {}
            device_data['node_details']['ip'] = updated_data.get('ip', '')
            device_data['node_details']['platform'] = updated_data.get('platform', '')
            device_data['node_details']['notes'] = updated_data.get('notes', '')
        else:
            # Previously undiscovered node - create new entry
            # This promotes an undiscovered peer to a proper device entry
            self._topology_data[node_id] = {
                'node_details': {
                    'ip': updated_data.get('ip', ''),
                    'platform': updated_data.get('platform', ''),
                    'notes': updated_data.get('notes', ''),
                },
                'peers': {}  # Empty peers - will be populated if relationships exist
            }

    def _update_cytoscape_node(self, cyto_data: dict, node_id: str, updated_data: dict):
        """Update a node in Cytoscape format."""
        nodes = cyto_data.get('nodes', [])
        for node in nodes:
            node_data = node.get('data', node)
            if node_data.get('id') == node_id:
                node_data['label'] = updated_data.get('label', node_id)
                node_data['ip'] = updated_data.get('ip', '')
                node_data['platform'] = updated_data.get('platform', '')
                node_data['discovered'] = updated_data.get('discovered', True)
                node_data['notes'] = updated_data.get('notes', '')
                return

        # Node not found - add it (was undiscovered placeholder)
        nodes.append({
            'data': {
                'id': node_id,
                'label': updated_data.get('label', node_id),
                'ip': updated_data.get('ip', ''),
                'platform': updated_data.get('platform', ''),
                'discovered': updated_data.get('discovered', True),
                'notes': updated_data.get('notes', ''),
            }
        })

    def _on_viewer_ready(self):
        """Handle viewer initialization."""
        self._viewer_ready = True
        print(f"[_on_viewer_ready] viewer is now ready")
        print(f"[_on_viewer_ready]   topology_data={'yes' if self._topology_data else 'no'}")
        print(f"[_on_viewer_ready]   current_file={self._current_file}")

        # Apply theme if we have one stored
        if self._current_theme:
            viewer_theme = theme_colors_to_viewer_theme(self._current_theme)
            self._viewer.set_theme(viewer_theme)

        # Load pending data
        if self._topology_data:
            print(f"[_on_viewer_ready]   loading pending topology data")
            self._load_topology_to_viewer()

    def _on_open_file(self):
        """Open file dialog to select a map JSON."""
        start_dir = str(Path(self._default_path("")).parent)

        path, _ = QFileDialog.getOpenFileName(
            self,
            "Open Map File",
            start_dir,
            "JSON Files (*.json);;All Files (*)"
        )

        if path:
            self.open_file(path)

    def _on_layout_changed(self, index: int):
        """Apply selected layout algorithm."""
        if not self._viewer_ready:
            return

        algorithm = self._layout_combo.itemData(index)
        if algorithm:
            self._viewer.apply_layout(algorithm)

    def _on_fit_view(self):
        """Fit view to all elements."""
        if self._viewer_ready:
            self._viewer.fit_view()

    def _on_reload(self):
        """Reload current file with layout restore and diagnostic logging."""
        if not self._current_file or not self._current_file.exists():
            return

        print(f"[_on_reload] START file={self._current_file.name}")
        print(f"[_on_reload]   viewer_ready={self._viewer_ready}")
        print(f"[_on_reload]   topology_data keys={list(self._topology_data.keys())[:5] if self._topology_data else None}")

        # Load the file (open_file will try _restore_layout internally)
        result = self.open_file(str(self._current_file))
        print(f"[_on_reload]   open_file returned {result}")

        # Also schedule an explicit layout restore after dagre settles,
        # as a fallback / debug hook
        layout_file = self._layout_path()
        if layout_file and layout_file.exists():
            print(f"[_on_reload]   layout file exists: {layout_file.name}")
            print(f"[_on_reload]   scheduling deferred restore at +1500ms")
            QTimer.singleShot(1500, self._debug_restore_layout)
        else:
            print(f"[_on_reload]   no layout file found")

    def _debug_restore_layout(self):
        """Debug: deferred layout restore with full logging."""
        print(f"[_debug_restore_layout] FIRED")
        print(f"[_debug_restore_layout]   viewer_ready={self._viewer_ready}")

        layout_file = self._layout_path()
        if not layout_file or not layout_file.exists():
            print(f"[_debug_restore_layout]   no layout file, aborting")
            return

        try:
            with open(layout_file, 'r', encoding='utf-8') as f:
                layout_data = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            print(f"[_debug_restore_layout]   failed to read layout: {e}")
            return

        positions = layout_data.get('positions', {})
        print(f"[_debug_restore_layout]   positions: {len(positions)} nodes")
        print(f"[_debug_restore_layout]   saved filters: connected_only={layout_data.get('connected_only')}, include_leaves={layout_data.get('include_leaves')}")
        print(f"[_debug_restore_layout]   current filters: connected_only={self._connected_only}, include_leaves={self._include_leaves}")

        if not positions:
            print(f"[_debug_restore_layout]   no positions to restore, aborting")
            return

        # Restore filter state with signals blocked
        self._connected_only_checkbox.blockSignals(True)
        self._show_leaves_checkbox.blockSignals(True)
        self._show_undiscovered_checkbox.blockSignals(True)
        self._layout_combo.blockSignals(True)

        filters_changed = False
        try:
            saved_connected = layout_data.get('connected_only')
            saved_leaves = layout_data.get('include_leaves')
            if saved_connected is not None and saved_connected != self._connected_only:
                self._connected_only = saved_connected
                self._connected_only_checkbox.setChecked(saved_connected)
                filters_changed = True
            if saved_leaves is not None and saved_leaves != self._include_leaves:
                self._include_leaves = saved_leaves
                self._show_leaves_checkbox.setChecked(saved_leaves)
                filters_changed = True

            saved_layout = layout_data.get('layout')
            if saved_layout:
                for i in range(self._layout_combo.count()):
                    if self._layout_combo.itemData(i) == saved_layout:
                        self._layout_combo.setCurrentIndex(i)
                        break
        finally:
            self._connected_only_checkbox.blockSignals(False)
            self._show_leaves_checkbox.blockSignals(False)
            self._show_undiscovered_checkbox.blockSignals(False)
            self._layout_combo.blockSignals(False)

        print(f"[_debug_restore_layout]   filters_changed={filters_changed}")

        if filters_changed:
            print(f"[_debug_restore_layout]   reloading topology with new filters")
            self._load_topology_to_viewer()
            self._update_stats()
            print(f"[_debug_restore_layout]   scheduling position apply at +800ms")
            QTimer.singleShot(800, lambda: self._debug_apply_positions(positions))
        else:
            print(f"[_debug_restore_layout]   filters match, applying positions now")
            self._debug_apply_positions(positions)

    def _debug_apply_positions(self, positions):
        """Debug: apply positions with logging."""
        print(f"[_debug_apply_positions] FIRED  viewer_ready={self._viewer_ready}  positions={len(positions)}")
        if self._viewer_ready and positions:
            self._viewer.restore_positions(positions)
            self._status_label.setText(
                f"Layout restored: {len(positions)} positions"
            )
            print(f"[_debug_apply_positions]   restore_positions() called successfully")
        else:
            print(f"[_debug_apply_positions]   SKIPPED  viewer_ready={self._viewer_ready}")

    # -----------------------------------------------------------------
    # Layout Persistence — sidecar .layout.json files
    #
    # Stores node positions, layout algorithm, filter state, zoom, and
    # pan next to the map file.  Travels with the map and survives
    # QWebEngine profile resets.
    # -----------------------------------------------------------------

    def _layout_path(self) -> Optional[Path]:
        """Get the sidecar layout file path for the current map."""
        if self._current_file:
            return self._current_file.with_suffix('.layout.json')
        return None

    def _on_save_layout(self):
        """Save current viewer positions to sidecar file."""
        if not self._viewer_ready:
            return

        layout_file = self._layout_path()
        if not layout_file:
            self._status_label.setText("Save Layout: no file loaded (save map first)")
            return

        def on_positions(positions_json):
            try:
                positions = json.loads(positions_json) if positions_json else {}
            except (json.JSONDecodeError, TypeError):
                positions = {}

            if not positions:
                self._status_label.setText("Save Layout: no positions to save")
                return

            layout_data = {
                'positions': positions,
                'layout': self._layout_combo.currentData() or 'dagre',
                'connected_only': self._connected_only,
                'include_leaves': self._include_leaves,
                'include_undiscovered': self._include_undiscovered,
                'saved_at': __import__('datetime').datetime.now().isoformat(),
            }

            try:
                with open(layout_file, 'w', encoding='utf-8') as f:
                    json.dump(layout_data, f, indent=2)
                self._status_label.setText(
                    f"Layout saved: {layout_file.name} ({len(positions)} nodes)"
                )
            except IOError as e:
                self._status_label.setText(f"Save Layout failed: {e}")

        self._viewer._run_js("TopologyViewer.exportPositions()", on_positions)

    def _on_clear_layout(self):
        """Delete saved layout for this map."""
        layout_file = self._layout_path()
        if layout_file and layout_file.exists():
            layout_file.unlink()
            self._status_label.setText(f"Layout cleared: {layout_file.name}")
        else:
            self._status_label.setText("No saved layout to clear")

    def _restore_layout(self):
        """Restore saved layout from sidecar file if present."""
        print(f"[_restore_layout] START")
        layout_file = self._layout_path()
        if not layout_file or not layout_file.exists():
            print(f"[_restore_layout]   no layout file, returning False")
            return False

        try:
            with open(layout_file, 'r', encoding='utf-8') as f:
                layout_data = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            print(f"[_restore_layout]   failed to read: {e}")
            return False

        positions = layout_data.get('positions')
        if not positions:
            print(f"[_restore_layout]   no positions in layout file, returning False")
            return False

        print(f"[_restore_layout]   {len(positions)} positions found")
        print(f"[_restore_layout]   saved: connected_only={layout_data.get('connected_only')}, include_leaves={layout_data.get('include_leaves')}, layout={layout_data.get('layout')}")
        print(f"[_restore_layout]   current: connected_only={self._connected_only}, include_leaves={self._include_leaves}")

        # ----------------------------------------------------------
        # Restore ALL UI state atomically with signals blocked so we
        # don't trigger cascading _load_topology_to_viewer() calls
        # with partially-updated filter state.
        # ----------------------------------------------------------
        self._connected_only_checkbox.blockSignals(True)
        self._show_leaves_checkbox.blockSignals(True)
        self._show_undiscovered_checkbox.blockSignals(True)
        self._layout_combo.blockSignals(True)

        try:
            saved_connected = layout_data.get('connected_only')
            saved_leaves = layout_data.get('include_leaves')
            if saved_connected is not None:
                self._connected_only = saved_connected
                self._connected_only_checkbox.setChecked(saved_connected)
            if saved_leaves is not None:
                self._include_leaves = saved_leaves
                self._show_leaves_checkbox.setChecked(saved_leaves)
            saved_undisc = layout_data.get('include_undiscovered')
            if saved_undisc is not None:
                self._include_undiscovered = saved_undisc
                self._show_undiscovered_checkbox.setChecked(saved_undisc)

            saved_layout = layout_data.get('layout')
            if saved_layout:
                for i in range(self._layout_combo.count()):
                    if self._layout_combo.itemData(i) == saved_layout:
                        self._layout_combo.setCurrentIndex(i)
                        break
        finally:
            self._connected_only_checkbox.blockSignals(False)
            self._show_leaves_checkbox.blockSignals(False)
            self._show_undiscovered_checkbox.blockSignals(False)
            self._layout_combo.blockSignals(False)

        # Single reload with all filters correctly set
        print(f"[_restore_layout]   calling _load_topology_to_viewer()")
        self._load_topology_to_viewer()
        self._update_stats()

        # Apply positions after a short delay to let the viewer render
        def apply_positions():
            print(f"[_restore_layout.apply_positions] FIRED  viewer_ready={self._viewer_ready}")
            self._viewer.restore_positions(positions)
            self._status_label.setText(
                f"Layout restored: {len(positions)} positions"
            )
            print(f"[_restore_layout.apply_positions]   restore_positions() called with {len(positions)} nodes")

        QTimer.singleShot(600, apply_positions)
        print(f"[_restore_layout]   timer scheduled at +600ms, returning True")
        return True

    def _get_viewer_positions(self, callback):
        """
        Async helper: get current node positions from the JS viewer.

        Args:
            callback: Function receiving {node_id: {x, y}} dict
        """
        if not self._viewer_ready:
            callback({})
            return

        def on_result(positions_json):
            try:
                positions = json.loads(positions_json) if positions_json else {}
            except (json.JSONDecodeError, TypeError):
                positions = {}
            callback(positions)

        self._viewer._run_js("TopologyViewer.exportPositions()", on_result)

    def _on_rebuild_map(self):
        """Rebuild topology map from all device.json files in the output directory."""
        # Determine the directory to scan
        scan_dir = None

        if self._current_file:
            # map.json is typically at the root of the output directory
            scan_dir = self._current_file.parent
        else:
            # No file loaded — ask user to pick a directory
            dir_path = QFileDialog.getExistingDirectory(
                self,
                "Select Discovery Output Directory",
                str(Path(self._default_path("")).parent),
                QFileDialog.Option.ShowDirsOnly,
            )
            if dir_path:
                scan_dir = Path(dir_path)

        if not scan_dir or not scan_dir.is_dir():
            return

        # Scan for device.json files
        device_files = list(scan_dir.glob('*/device.json'))
        if not device_files:
            QMessageBox.warning(
                self, "Rebuild",
                f"No device.json files found in:\n{scan_dir}\n\n"
                "This directory should contain per-device subfolders "
                "from a discovery crawl."
            )
            return

        # Confirm with user
        reply = QMessageBox.question(
            self, "Rebuild Topology",
            f"Found {len(device_files)} device folders in:\n{scan_dir}\n\n"
            "Rebuild the topology map from all collected device data?\n"
            "This will replace the current map.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        # Load all devices
        try:
            try:
                from sc2.scng.discovery.models import Device
                from sc2.scng.discovery.engine import DiscoveryEngine
            except ImportError:
                from scng.discovery.models import Device
                from scng.discovery.engine import DiscoveryEngine

            devices = []
            errors = []
            for device_file in sorted(device_files):
                try:
                    with open(device_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    device = Device.from_dict(data)
                    if device.discovery_success:
                        devices.append(device)
                except Exception as e:
                    errors.append(f"{device_file.parent.name}: {e}")

            if not devices:
                QMessageBox.warning(
                    self, "Rebuild",
                    "No valid devices loaded from device.json files."
                )
                return

            # Generate topology
            engine = DiscoveryEngine()
            topology = engine._generate_topology_map(devices)

            # Count stats
            edge_count = 0
            conn_count = 0
            for device_data in topology.values():
                for peer_data in device_data.get('peers', {}).values():
                    edge_count += 1
                    conn_count += len(peer_data.get('connections', []))

            # Save the rebuilt map
            output_path = scan_dir / 'map.json'
            with open(output_path, 'w') as f:
                json.dump(topology, f, indent=2)

            # Load into viewer
            self._current_file = output_path
            self._topology_data = topology
            self.setWindowTitle(f"Map Viewer - {output_path.name}")
            self._update_stats()

            if self._viewer_ready:
                self._load_topology_to_viewer()

            # Show summary
            error_msg = f"\n\n{len(errors)} load errors." if errors else ""
            self._status_label.setText(
                f"Rebuilt: {len(devices)} devices, {edge_count} edges, "
                f"{conn_count} connections"
            )

            QMessageBox.information(
                self, "Rebuild Complete",
                f"Topology rebuilt from {len(devices)} devices.\n\n"
                f"Nodes: {len(topology)}\n"
                f"Edges: {edge_count}\n"
                f"Connections: {conn_count}\n"
                f"Saved to: {output_path}"
                f"{error_msg}"
            )

        except ImportError as e:
            QMessageBox.warning(
                self, "Rebuild Failed",
                f"Required module not available:\n{e}"
            )
        except Exception as e:
            QMessageBox.warning(
                self, "Rebuild Failed",
                f"Error during rebuild:\n{e}"
            )

    def _on_export_png(self):
        """Export topology as PNG."""
        if not self._viewer_ready or self._topology_data is None:
            QMessageBox.warning(self, "Export", "No topology loaded to export.")
            return

        # Get save path
        start_dir = self._default_path(".png")

        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Topology as PNG",
            start_dir,
            "PNG Images (*.png)"
        )

        if not path:
            return

        # Export (async callback approach)
        def on_png_ready(base64_data):
            if not base64_data:
                QMessageBox.warning(self, "Export Failed", "Failed to generate PNG.")
                return

            try:
                import base64
                png_bytes = base64.b64decode(base64_data)
                with open(path, 'wb') as f:
                    f.write(png_bytes)
                self._status_label.setText(f"Exported: {Path(path).name}")
            except Exception as e:
                QMessageBox.warning(self, "Export Failed", f"Error saving file: {e}")

        self._viewer._run_js("TopologyViewer.exportPNG()", on_png_ready)

    def _on_export_drawio(self):
        """Export topology to Draw.io format using viewer positions for layout."""
        if self._topology_data is None:
            QMessageBox.warning(self, "Export", "No topology loaded to export.")
            return

        # Determine default filename
        start_dir = self._default_path(".drawio")

        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export to Draw.io",
            start_dir,
            "Draw.io Files (*.drawio);;XML Files (*.xml)"
        )

        if not path:
            return

        # Get viewer positions, then export with them so the DrawIO
        # layout matches what the user arranged in the interactive viewer.
        def do_export(viewer_positions):
            try:
                from sc2.export.drawio_exporter import DrawioExporter

                display_data = self._get_export_topology()
                if not display_data:
                    QMessageBox.warning(self, "Export", "No topology data after filtering.")
                    return

                exporter = DrawioExporter(
                    use_icons=True,
                    include_endpoints=True,
                    connected_only=False,
                    layout_type='tree'
                )

                # Pass viewer positions — exporter will use them instead
                # of computing its own tree/grid layout.
                exporter.export(
                    display_data,
                    Path(path),
                    viewer_positions=viewer_positions or None,
                )

                status_msg = f"Exported: {Path(path).name}"
                if viewer_positions:
                    status_msg += " (viewer layout)"
                filter_notes = []
                if self._connected_only:
                    filter_notes.append("connected only")
                if not self._include_leaves:
                    filter_notes.append("infra only")
                if filter_notes:
                    status_msg += f" ({', '.join(filter_notes)})"
                self._status_label.setText(status_msg)

            except ImportError:
                QMessageBox.warning(
                    self,
                    "Export Failed",
                    "Draw.io exporter not available.\n"
                    "Ensure sc2.export.drawio_exporter is installed."
                )
            except Exception as e:
                QMessageBox.warning(self, "Export Failed", f"Error exporting: {e}")

        self._get_viewer_positions(do_export)

    def _on_export_graphml(self):
        """Export topology to yEd GraphML format."""
        if self._topology_data is None:
            QMessageBox.warning(self, "Export", "No topology loaded to export.")
            return

        # Determine default filename
        start_dir = self._default_path(".graphml")

        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export to yEd GraphML",
            start_dir,
            "GraphML Files (*.graphml)"
        )

        if not path:
            return

        try:
            from sc2.export.graphml_exporter import GraphMLExporter

            # Get filtered topology (same as what's displayed in viewer)
            display_data = self._get_export_topology()

            if not display_data:
                QMessageBox.warning(self, "Export", "No topology data after filtering.")
                return

            # Create exporter - filtering already applied, so disable exporter's filters
            exporter = GraphMLExporter(
                use_icons=True,
                include_endpoints=True,  # Don't filter again - already filtered
                connected_only=False,  # Don't filter again - already filtered
                layout_type='grid'
            )

            exporter.export(display_data, Path(path))

            # Update status message to reflect filtering
            status_msg = f"Exported: {Path(path).name}"
            filter_notes = []
            if self._connected_only:
                filter_notes.append("connected only")
            if not self._include_leaves:
                filter_notes.append("infra only")
            if filter_notes:
                status_msg += f" ({', '.join(filter_notes)})"
            self._status_label.setText(status_msg)

        except ImportError:
            QMessageBox.warning(
                self,
                "Export Failed",
                "GraphML exporter not available.\n"
                "Ensure sc2.export.graphml_exporter is installed."
            )
        except Exception as e:
            QMessageBox.warning(self, "Export Failed", f"Error exporting: {e}")

    def _on_save_map(self):
        """Export filtered topology to JSON file."""
        if self._topology_data is None:
            QMessageBox.warning(self, "Export", "No topology loaded to export.")
            return

        # Get filtered topology (same as what's displayed in viewer)
        display_data = self._get_export_topology()
        if not display_data:
            QMessageBox.warning(self, "Export", "No topology data after filtering.")
            return

        # Get save path
        default_path = self._default_path("_export.json")

        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Topology to JSON",
            default_path,
            "JSON Files (*.json)"
        )

        if not path:
            return

        try:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(display_data, f, indent=2)

            # Build status message reflecting filters
            node_count, edge_count = self._count_topology(display_data)
            status_msg = f"Exported: {Path(path).name} ({node_count} devices)"
            filter_notes = []
            if self._connected_only:
                filter_notes.append("connected only")
            if not self._include_leaves:
                filter_notes.append("infra only")
            if filter_notes:
                status_msg += f" [{', '.join(filter_notes)}]"
            self._status_label.setText(status_msg)
        except IOError as e:
            QMessageBox.warning(self, "Save Failed", f"Error saving file: {e}")

    def load_topology(self, data: Dict[str, Any], name: Optional[str] = None):
        """
        Load topology data directly (not from file).

        Args:
            data: Topology dictionary (SC2 format, Cytoscape format, etc.)
            name: Optional name for display in title bar
        """
        if not isinstance(data, dict):
            return

        self._current_file = None  # No file associated
        self._topology_data = data

        display_name = name or "Untitled"
        self.setWindowTitle(f"Map Viewer - {display_name}")

        self._update_stats()
        self._status_label.setText(f"Loaded: {display_name} (from memory)")

        if self._viewer_ready:
            self._load_topology_to_viewer()

    def open_file(self, path: str) -> bool:
        """
        Open and display a map JSON file.

        Args:
            path: Path to JSON file

        Returns:
            True if loaded successfully
        """
        file_path = Path(path)

        if not file_path.exists():
            QMessageBox.warning(self, "File Not Found", f"File not found:\n{path}")
            return False

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            QMessageBox.warning(self, "Invalid JSON", f"Failed to parse JSON:\n{e}")
            return False
        except IOError as e:
            QMessageBox.warning(self, "Read Error", f"Failed to read file:\n{e}")
            return False

        # Validate we got something useful
        if not isinstance(data, dict):
            QMessageBox.warning(self, "Invalid Format", "Map file must be a JSON object.")
            return False

        # Store data (unfiltered - filtering happens at display time)
        self._current_file = file_path
        self._topology_data = data

        # Update window title
        self.setWindowTitle(f"Map Viewer - {file_path.name}")

        # Update status
        self._update_stats()
        self._status_label.setText(f"Loaded: {file_path.name}")

        # Load into viewer (with filtering if enabled)
        print(f"[open_file] viewer_ready={self._viewer_ready}")
        if self._viewer_ready:
            # Try restoring a saved layout (positions + filters).
            # If no saved layout, fall through to default load + fit.
            restore_ok = self._restore_layout()
            print(f"[open_file] _restore_layout returned {restore_ok}")
            if not restore_ok:
                print(f"[open_file] falling back to _load_topology_to_viewer")
                self._load_topology_to_viewer()
        else:
            print(f"[open_file] viewer not ready, data stored for later")

        # Emit signal
        self.file_loaded.emit(str(file_path))

        return True

    def _update_stats(self):
        """Update stats display showing both total and displayed counts."""
        if self._topology_data is None:
            self._stats_label.setText("")
            return

        # Count from original data
        total_nodes, total_edges = self._count_topology(self._topology_data)

        # Count from filtered data
        display_data = self._get_display_topology()
        display_nodes, display_edges = self._count_topology(display_data)

        # Build status text
        if display_nodes < total_nodes:
            # Filtering is active and reducing node count
            filter_desc = []
            if self._connected_only:
                filter_desc.append("connected")
            if not self._include_leaves:
                filter_desc.append("infra only")

            filter_text = ", ".join(filter_desc) if filter_desc else "filtered"
            self._stats_label.setText(
                f"Devices: {display_nodes}/{total_nodes} ({filter_text}) | Connections: {display_edges}"
            )
        else:
            # No filtering effect
            self._stats_label.setText(f"Devices: {total_nodes} | Connections: {total_edges}")

    def _count_topology(self, data: Optional[Dict]) -> tuple:
        """Count nodes and edges in topology data."""
        if not data:
            return 0, 0

        # Count nodes and edges based on format
        if 'nodes' in data:
            nodes = len(data['nodes'])
            edges = len(data.get('edges', []))
        elif 'cytoscape' in data:
            cyto = data['cytoscape']
            nodes = len(cyto.get('nodes', []))
            edges = len(cyto.get('edges', []))
        else:
            # SC2 map format
            nodes = len(data)
            edges = set()
            for device, device_data in data.items():
                if isinstance(device_data, dict):
                    for peer in device_data.get('peers', {}).keys():
                        edge_id = tuple(sorted([device, peer]))
                        edges.add(edge_id)
            edges = len(edges)

        return nodes, edges

    def _apply_content_theme(self, theme: ThemeColors):
        """Apply theme to dialog content."""
        self._current_theme = theme

        # Apply to viewer if ready
        if self._viewer_ready:
            viewer_theme = theme_colors_to_viewer_theme(theme)
            self._viewer.set_theme(viewer_theme)

        # Dialog styling
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {theme.bg_primary};
            }}

            QToolBar#mapViewerToolbar {{
                background-color: {theme.bg_secondary};
                border: none;
                border-bottom: 1px solid {theme.border_dim};
                spacing: 8px;
                padding: 4px 8px;
            }}

            QToolBar#mapViewerToolbar QToolButton {{
                background-color: transparent;
                border: 1px solid transparent;
                border-radius: 4px;
                padding: 6px 12px;
                color: {theme.text_primary};
                font-size: 12px;
            }}

            QToolBar#mapViewerToolbar QToolButton:hover {{
                background-color: {theme.bg_hover};
                border-color: {theme.border_dim};
            }}

            QToolBar#mapViewerToolbar QToolButton:pressed {{
                background-color: {theme.bg_tertiary};
            }}

            QToolBar#mapViewerToolbar QLabel {{
                color: {theme.text_secondary};
                background: transparent;
            }}

            QComboBox#layoutCombo {{
                background-color: {theme.bg_tertiary};
                border: 1px solid {theme.border_dim};
                border-radius: 4px;
                padding: 4px 8px;
                color: {theme.text_primary};
                min-height: 24px;
            }}

            QComboBox#layoutCombo:hover {{
                border-color: {theme.accent};
            }}

            QComboBox#layoutCombo::drop-down {{
                border: none;
                width: 20px;
            }}

            QComboBox#layoutCombo::down-arrow {{
                image: {qss_glyph('down', theme.text_secondary)};
                width: 10px;
                height: 6px;
            }}

            QComboBox#layoutCombo QAbstractItemView {{
                background-color: {theme.bg_secondary};
                border: 1px solid {theme.border_dim};
                selection-background-color: {theme.accent};
                color: {theme.text_primary};
            }}

            QCheckBox#connectedOnlyCheckbox, QCheckBox#showLeavesCheckbox {{
                color: {theme.text_primary};
                spacing: 6px;
                padding: 4px 8px;
            }}

            QCheckBox#connectedOnlyCheckbox::indicator, QCheckBox#showLeavesCheckbox::indicator {{
                width: 16px;
                height: 16px;
                border: 1px solid {theme.border_dim};
                border-radius: 3px;
                background-color: {theme.bg_tertiary};
            }}

            QCheckBox#connectedOnlyCheckbox::indicator:checked, QCheckBox#showLeavesCheckbox::indicator:checked {{
                background-color: {theme.accent};
                border-color: {theme.accent};
            }}

            QCheckBox#connectedOnlyCheckbox::indicator:hover, QCheckBox#showLeavesCheckbox::indicator:hover {{
                border-color: {theme.accent};
            }}

            QStatusBar#mapViewerStatus {{
                background-color: {theme.bg_secondary};
                border-top: 1px solid {theme.border_dim};
                color: {theme.text_secondary};
                font-size: 11px;
            }}

            QStatusBar#mapViewerStatus QLabel {{
                color: {theme.text_secondary};
                padding: 2px 8px;
            }}
        """)

    def apply_theme(self, theme: ThemeColors):
        """Apply theme to entire dialog."""
        self._apply_content_theme(theme)

    def set_theme(self, theme_manager: ThemeManager):
        """Update theme manager and apply."""
        self.theme_manager = theme_manager
        self._apply_content_theme(theme_manager.theme)


# =============================================================================
# Standalone test
# =============================================================================

if __name__ == '__main__':
    import sys
    from PyQt6.QtWidgets import QApplication

    app = QApplication(sys.argv)

    dialog = MapViewerDialog()
    dialog.show()

    sys.exit(app.exec())