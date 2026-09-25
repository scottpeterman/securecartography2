"""
SecureCartography v2 - Discovery Options Panel Widget

Contains:
- Max Depth (spinbox)
- Concurrency (spinbox)
- Timeout (spinbox)
- No DNS Mode (toggle)
- Verbose Output (toggle)
- Layout Algorithm (dropdown)
- Map Name (text input)
"""

from typing import Optional
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QSpinBox, QFrame, QSizePolicy
)
from PyQt6.QtGui import QFont

from ..themes import ThemeColors, ThemeManager, StyledComboBox, qss_glyph
from .panel import Panel
from .toggle_switch import ToggleOption


class FormLabel(QLabel):
    """Styled form field label."""

    def __init__(self, text: str, parent=None):
        super().__init__(text, parent)
        self.setObjectName("formLabel")
        font = self.font()
        font.setPointSize(10)
        font.setWeight(QFont.Weight.Medium)
        self.setFont(font)


class DiscoveryOptionsPanel(Panel):
    """
    Discovery options configuration panel.

    Layout:
    ┌─ DISCOVERY OPTIONS ──────────────────────────┐
    │ MAX DEPTH    CONCURRENCY    TIMEOUT (SEC)    │
    │ ┌────────┐   ┌────────┐     ┌────────┐      │
    │ │   3    │   │   20   │     │   5    │      │
    │ └────────┘   └────────┘     └────────┘      │
    │                                              │
    │ ┌──────────────────────────────────────────┐ │
    │ │ No DNS Mode                        [═══] │ │
    │ │ Use IPs from LLDP/CDP only (home lab)    │ │
    │ └──────────────────────────────────────────┘ │
    │                                              │
    │ ┌──────────────────────────────────────────┐ │
    │ │ Verbose Output                     [═══] │ │
    │ │ Enable detailed logging                   │ │
    │ └──────────────────────────────────────────┘ │
    │                                              │
    │ LAYOUT ALGORITHM                             │
    │ ┌──────────────────────────────────────  ▼┐ │
    │ │ Hierarchical                            │ │
    │ └──────────────────────────────────────────┘ │
    │                                              │
    │ MAP NAME                                     │
    │ ┌──────────────────────────────────────────┐ │
    │ │ 📄 network_map_001                       │ │
    │ └──────────────────────────────────────────┘ │
    └──────────────────────────────────────────────┘

    Usage:
        panel = DiscoveryOptionsPanel(theme_manager=tm)

        # Get values
        depth = panel.max_depth
        concurrency = panel.concurrency
        timeout = panel.timeout
        no_dns = panel.no_dns
        verbose = panel.verbose
        layout = panel.layout_algorithm
        map_name = panel.map_name

        # Connect to changes
        panel.options_changed.connect(on_options_changed)
    """

    options_changed = pyqtSignal()  # Emitted when any option changes

    LAYOUT_ALGORITHMS = [
        "Hierarchical",
        "Organic",
        "Circular",
        "Tree",
        "Orthogonal",
    ]

    def __init__(
        self,
        theme_manager: Optional[ThemeManager] = None,
        parent: Optional[QWidget] = None
    ):
        super().__init__(
            title="DISCOVERY OPTIONS",
            icon="⚙️",
            theme_manager=theme_manager,
            parent=parent,
            _defer_theme=True  # Apply theme after _setup_content
        )
        self._setup_content()
        if theme_manager:
            self.apply_theme(theme_manager.theme)

    def _setup_content(self):
        """Build the options panel content."""
        # Numeric options row (Depth, Concurrency, Timeout)
        numbers_row = QHBoxLayout()
        numbers_row.setSpacing(12)

        # Max Depth
        depth_group = QVBoxLayout()
        depth_group.setSpacing(4)
        depth_label = FormLabel("MAX DEPTH")
        depth_group.addWidget(depth_label)
        self.depth_spin = QSpinBox()
        self.depth_spin.setObjectName("depthSpin")
        self.depth_spin.setRange(1, 10)
        self.depth_spin.setValue(5)
        self.depth_spin.valueChanged.connect(self._emit_changed)
        self.depth_spin.setFixedHeight(38)
        depth_group.addWidget(self.depth_spin)
        numbers_row.addLayout(depth_group)

        # Concurrency
        conc_group = QVBoxLayout()
        conc_group.setSpacing(4)
        conc_label = FormLabel("CONCURRENCY")
        conc_group.addWidget(conc_label)
        self.concurrency_spin = QSpinBox()
        self.concurrency_spin.setObjectName("concurrencySpin")
        self.concurrency_spin.setRange(1, 100)
        self.concurrency_spin.setValue(20)
        self.concurrency_spin.valueChanged.connect(self._emit_changed)
        self.concurrency_spin.setFixedHeight(38)
        conc_group.addWidget(self.concurrency_spin)
        numbers_row.addLayout(conc_group)

        # Timeout
        timeout_group = QVBoxLayout()
        timeout_group.setSpacing(4)
        timeout_label = FormLabel("TIMEOUT (SEC)")
        timeout_group.addWidget(timeout_label)
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setObjectName("timeoutSpin")
        self.timeout_spin.setRange(1, 60)
        self.timeout_spin.setValue(5)
        self.timeout_spin.valueChanged.connect(self._emit_changed)
        self.timeout_spin.setFixedHeight(38)
        timeout_group.addWidget(self.timeout_spin)
        numbers_row.addLayout(timeout_group)

        self.content_layout.addLayout(numbers_row)

        # Toggle options
        self.content_layout.addSpacing(8)

        self.no_dns_toggle = ToggleOption(
            label="No DNS Mode",
            description="Use IPs from LLDP/CDP only (home lab)",
            checked=False,
            theme_manager=self.theme_manager
        )
        self.no_dns_toggle.toggled.connect(self._emit_changed)
        self.content_layout.addWidget(self.no_dns_toggle)

        self.verbose_toggle = ToggleOption(
            label="Verbose Output",
            description="Enable detailed logging",
            checked=False,
            theme_manager=self.theme_manager
        )
        self.verbose_toggle.toggled.connect(self._emit_changed)
        self.content_layout.addWidget(self.verbose_toggle)

        # Separator
        self.content_layout.addSpacing(8)
        separator = QFrame()
        separator.setFrameShape(QFrame.Shape.HLine)
        separator.setObjectName("optionsSeparator")
        self.content_layout.addWidget(separator)
        self.content_layout.addSpacing(8)

        # Layout algorithm dropdown
        layout_label = FormLabel("LAYOUT ALGORITHM")
        self.content_layout.addWidget(layout_label)

        self.layout_combo = StyledComboBox()
        self.layout_combo.setObjectName("layoutCombo")
        for algo in self.LAYOUT_ALGORITHMS:
            self.layout_combo.addItem(algo)
        if self.theme_manager:
            self.layout_combo.set_theme_colors(self.theme_manager.theme)
        self.layout_combo.currentIndexChanged.connect(self._emit_changed)
        self.content_layout.addWidget(self.layout_combo)

        # Map name input
        self.content_layout.addSpacing(8)
        mapname_label = FormLabel("MAP NAME")
        # self.content_layout.addWidget(mapname_label)

        self.mapname_input = QLineEdit()
        self.mapname_input.setObjectName("mapnameInput")
        self.mapname_input.setPlaceholderText("network_map_001")
        self.mapname_input.textChanged.connect(self._emit_changed)
        # self.content_layout.addWidget(self.mapname_input)

    def _emit_changed(self):
        """Emit options_changed signal."""
        self.options_changed.emit()

    # === Properties ===

    @property
    def max_depth(self) -> int:
        return self.depth_spin.value()

    @property
    def concurrency(self) -> int:
        return self.concurrency_spin.value()

    @property
    def timeout(self) -> int:
        return self.timeout_spin.value()

    @property
    def no_dns(self) -> bool:
        return self.no_dns_toggle.isChecked()

    @property
    def verbose(self) -> bool:
        return self.verbose_toggle.isChecked()

    @property
    def layout_algorithm(self) -> str:
        return self.layout_combo.currentText()

    @property
    def map_name(self) -> str:
        return self.mapname_input.text().strip() or "network_map"

    # === Setters ===

    def set_max_depth(self, value: int):
        self.depth_spin.setValue(value)

    def set_concurrency(self, value: int):
        self.concurrency_spin.setValue(value)

    def set_timeout(self, value: int):
        self.timeout_spin.setValue(value)

    def set_no_dns(self, enabled: bool):
        self.no_dns_toggle.setChecked(enabled)

    def set_verbose(self, enabled: bool):
        self.verbose_toggle.setChecked(enabled)

    def set_layout_algorithm(self, algorithm: str):
        index = self.layout_combo.findText(algorithm)
        if index >= 0:
            self.layout_combo.setCurrentIndex(index)

    def set_map_name(self, name: str):
        self.mapname_input.setText(name)

    def _apply_content_theme(self, theme: ThemeColors):
        """Apply theme to panel content."""
        # Labels
        label_style = f"""
            QLabel#formLabel {{
                color: {theme.text_secondary};
                text-transform: uppercase;
                letter-spacing: 0.5px;
                background: transparent;
                border: none;
                padding-bottom: 4px;
            }}
        """
        for label in self.findChildren(FormLabel):
            label.setStyleSheet(label_style)

        # Spinboxes
        spinbox_style = f"""
            QSpinBox {{
                background-color: {theme.bg_input};
                border: 1px solid {theme.border_dim};
                border-radius: 6px;
                padding: 8px 26px 8px 12px;
                color: {theme.text_primary};
                font-size: 14px;
                min-width: 60px;
            }}
            QSpinBox:focus {{
                border-color: {theme.accent};
            }}
            QSpinBox::up-button, QSpinBox::down-button {{
                subcontrol-origin: border;
                width: 20px;
                height: 18px;
                border: none;
                border-left: 1px solid {theme.border_dim};
                background-color: {theme.bg_tertiary};
            }}
            QSpinBox::up-button {{
                subcontrol-position: top right;
                border-top-right-radius: 5px;
            }}
            QSpinBox::down-button {{
                subcontrol-position: bottom right;
                border-top: 1px solid {theme.border_dim};
                border-bottom-right-radius: 5px;
            }}
            QSpinBox::up-button:hover, QSpinBox::down-button:hover {{
                background-color: {theme.bg_hover};
            }}
            QSpinBox::up-arrow {{
                image: {qss_glyph('up', theme.text_secondary)};
                width: 10px;
                height: 6px;
            }}
            QSpinBox::down-arrow {{
                image: {qss_glyph('down', theme.text_secondary)};
                width: 10px;
                height: 6px;
            }}
        """
        self.depth_spin.setStyleSheet(spinbox_style)
        self.concurrency_spin.setStyleSheet(spinbox_style)
        self.timeout_spin.setStyleSheet(spinbox_style)

        # Toggles
        self.no_dns_toggle.apply_theme(theme)
        self.verbose_toggle.apply_theme(theme)

        # Separator
        separator_style = f"""
            QFrame#optionsSeparator {{
                background-color: {theme.border_dim};
                border: none;
                max-height: 1px;
            }}
        """
        for sep in self.findChildren(QFrame):
            if sep.objectName() == "optionsSeparator":
                sep.setStyleSheet(separator_style)

        # ComboBox
        self.layout_combo.set_theme_colors(theme)
        self.layout_combo.setStyleSheet(f"""
            QComboBox#layoutCombo {{
                background-color: {theme.bg_input};
                border: 1px solid {theme.border_dim};
                border-radius: 6px;
                padding: 10px 12px;
                color: {theme.text_primary};
                font-size: 13px;
            }}
            QComboBox#layoutCombo:hover {{
                border-color: {theme.border_hover};
            }}
            QComboBox#layoutCombo:focus {{
                border-color: {theme.accent};
            }}
            QComboBox#layoutCombo::drop-down {{
                border: none;
                width: 24px;
            }}
            QComboBox#layoutCombo::down-arrow {{
                image: {qss_glyph('down', theme.text_secondary)};
                width: 10px;
                height: 6px;
            }}
        """)

        # Map name input
        self.mapname_input.setStyleSheet(f"""
            QLineEdit#mapnameInput {{
                background-color: {theme.bg_input};
                border: 1px solid {theme.border_dim};
                border-radius: 6px;
                padding: 10px 12px;
                color: {theme.text_primary};
                font-size: 13px;
            }}
            QLineEdit#mapnameInput:focus {{
                border-color: {theme.accent};
            }}
            QLineEdit#mapnameInput::placeholder {{
                color: {theme.text_muted};
            }}
        """)

    def apply_theme(self, theme: ThemeColors):
        """Apply theme to entire panel."""
        super().apply_theme(theme)
        self._apply_content_theme(theme)

    def set_theme(self, theme_manager: ThemeManager):
        """Update theme manager and apply."""
        super().set_theme(theme_manager)
        self._apply_content_theme(theme_manager.theme)