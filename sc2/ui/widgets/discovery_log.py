"""
SecureCartography v2 - Discovery Log Panel Widget

Styled monospace log output with colored entries:
- Timestamps (muted)
- Success entries (green/accent)
- Warning entries (orange/warning)
- Error entries (red/danger)
- Info entries (white/primary)
"""

from typing import List, Optional, Tuple
from datetime import datetime
from enum import Enum
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QTextEdit, QVBoxLayout, QWidget, QSizePolicy, QPushButton, QDialog,
    QTableWidget, QTableWidgetItem, QHeaderView, QDialogButtonBox, QLabel,
    QAbstractItemView,
)
from PyQt6.QtGui import QFont, QTextCursor, QColor, QTextCharFormat

from ..themes import ThemeColors, ThemeManager
from .panel import Panel


class LogLevel(Enum):
    """Log entry severity levels."""
    INFO = "info"
    SUCCESS = "success"
    WARNING = "warning"
    ERROR = "error"
    DEBUG = "debug"


class DiscoveryLogPanel(Panel):
    """
    Discovery log panel with styled monospace output.

    Features:
    - Timestamp prefix on each line
    - Color-coded by log level
    - Auto-scroll to bottom
    - Monospace font
    - Copy support

    Usage:
        log = DiscoveryLogPanel(theme_manager=tm)

        log.info("Starting crawl from 2 seeds")
        log.success("core-switch-01 (Cisco) - 847ms")
        log.warning("192.168.1.50 - Timeout")
        log.error("Connection refused")

        # With custom prefix
        log.log("  └─ CDP: 4 neighbors", LogLevel.INFO)

        # Clear log
        log.clear()
    """

    def __init__(
        self,
        theme_manager: Optional[ThemeManager] = None,
        max_lines: int = 1000,
        parent: Optional[QWidget] = None
    ):
        super().__init__(
            title="DISCOVERY LOG",
            icon="📋",
            theme_manager=theme_manager,
            parent=parent,
            _defer_theme=True  # Apply theme after _setup_content
        )
        self.max_lines = max_lines
        self._line_count = 0
        self._setup_content()
        if theme_manager:
            self.apply_theme(theme_manager.theme)

    def _setup_content(self):
        """Build the log panel content."""
        # Log text area
        self.log_text = QTextEdit()
        self.log_text.setObjectName("discoveryLog")
        self.log_text.setReadOnly(True)
        self.log_text.setFont(QFont("JetBrains Mono", 11))
        self.log_text.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        self.log_text.setMinimumHeight(150)

        self.content_layout.addWidget(self.log_text)

        # Header button: list of neighbors that were never dialed, and why
        self._not_dialed: List[Tuple[str, str, str]] = []
        self.not_dialed_btn = QPushButton("Not dialed (0)")
        self.not_dialed_btn.setObjectName("notDialedButton")
        self.not_dialed_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.not_dialed_btn.clicked.connect(self._show_not_dialed)
        self.not_dialed_btn.hide()
        self.title_right_layout.addWidget(self.not_dialed_btn)

    # ------------------------------------------------------------ not dialed

    def add_not_dialed(self, target: str, reason: str, from_device: str = ""):
        """Record a neighbor that will not be dialed."""
        self._not_dialed.append((target, reason, from_device))
        self.not_dialed_btn.setText(f"Not dialed ({len(self._not_dialed)})")
        self.not_dialed_btn.show()

    def not_dialed_entries(self) -> List[Tuple[str, str, str]]:
        return list(self._not_dialed)

    def _show_not_dialed(self):
        dlg = QDialog(self)
        dlg.setWindowTitle(f"Not dialed ({len(self._not_dialed)})")
        dlg.resize(640, 420)
        lay = QVBoxLayout(dlg)
        lay.addWidget(QLabel(
            "Neighbors seen in CDP/LLDP that the crawl did not connect to."))
        table = QTableWidget(len(self._not_dialed), 3)
        table.setHorizontalHeaderLabels(["Neighbor", "Reason", "Seen from"])
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        for r, (target, reason, src) in enumerate(sorted(self._not_dialed, key=lambda e: (e[1], e[0]))):
            for c, v in enumerate((target, reason, src)):
                table.setItem(r, c, QTableWidgetItem(v))
        hdr = table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        table.setSortingEnabled(True)
        lay.addWidget(table)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(dlg.reject)
        lay.addWidget(buttons)
        dlg.exec()

    def _get_timestamp(self) -> str:
        """Get formatted timestamp."""
        return datetime.now().strftime("[%H:%M:%S]")

    def _get_level_color(self, level: LogLevel, theme: ThemeColors) -> str:
        """Get color for log level."""
        colors = {
            LogLevel.INFO: theme.text_primary,
            LogLevel.SUCCESS: theme.accent_success,
            LogLevel.WARNING: theme.accent_warning,
            LogLevel.ERROR: theme.accent_danger,
            LogLevel.DEBUG: theme.text_muted,
        }
        return colors.get(level, theme.text_primary)

    def _get_level_prefix(self, level: LogLevel) -> str:
        """Get prefix symbol for log level."""
        prefixes = {
            LogLevel.INFO: "",
            LogLevel.SUCCESS: "✓ ",
            LogLevel.WARNING: "⚠ ",
            LogLevel.ERROR: "✗ ",
            LogLevel.DEBUG: "· ",
        }
        return prefixes.get(level, "")

    def log(
        self,
        message: str,
        level: LogLevel = LogLevel.INFO,
        timestamp: bool = True,
        prefix: bool = True
    ):
        """
        Add a log entry.

        Args:
            message: Log message text
            level: Log level for coloring
            timestamp: Whether to include timestamp
            prefix: Whether to include level prefix (✓, ⚠, etc.)
        """
        theme = self.theme_manager.theme if self.theme_manager else None

        cursor = self.log_text.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)

        # Build the formatted line
        parts = []

        if timestamp:
            ts = self._get_timestamp()
            # Timestamp in muted color
            ts_format = QTextCharFormat()
            if theme:
                ts_format.setForeground(QColor(theme.text_muted))
            cursor.insertText(ts + " ", ts_format)

        # Level prefix
        if prefix:
            level_prefix = self._get_level_prefix(level)
            if level_prefix:
                prefix_format = QTextCharFormat()
                if theme:
                    prefix_format.setForeground(QColor(self._get_level_color(level, theme)))
                cursor.insertText(level_prefix, prefix_format)

        # Message
        msg_format = QTextCharFormat()
        if theme:
            msg_format.setForeground(QColor(self._get_level_color(level, theme)))
        cursor.insertText(message + "\n", msg_format)

        # Auto-scroll to bottom
        self.log_text.setTextCursor(cursor)
        self.log_text.ensureCursorVisible()

        # Trim old lines if over limit
        self._line_count += 1
        if self._line_count > self.max_lines:
            self._trim_old_lines()

    def _trim_old_lines(self):
        """Remove oldest lines when over max_lines."""
        # Get all text, split into lines, keep recent ones
        text = self.log_text.toPlainText()
        lines = text.split('\n')

        if len(lines) > self.max_lines:
            # Keep last max_lines lines
            # This is a simplistic approach; loses formatting
            # For better performance, use QTextDocument block removal
            pass  # TODO: implement proper trimming

    # === Convenience methods ===

    def info(self, message: str, timestamp: bool = True):
        """Log an info message."""
        self.log(message, LogLevel.INFO, timestamp=timestamp, prefix=False)

    def success(self, message: str, timestamp: bool = True):
        """Log a success message."""
        self.log(message, LogLevel.SUCCESS, timestamp=timestamp)

    def warning(self, message: str, timestamp: bool = True):
        """Log a warning message."""
        self.log(message, LogLevel.WARNING, timestamp=timestamp)

    def error(self, message: str, timestamp: bool = True):
        """Log an error message."""
        self.log(message, LogLevel.ERROR, timestamp=timestamp)

    def debug(self, message: str, timestamp: bool = True):
        """Log a debug message."""
        self.log(message, LogLevel.DEBUG, timestamp=timestamp)

    def detail(self, message: str):
        """Log a detail line (no timestamp, for sub-items)."""
        self.log(message, LogLevel.INFO, timestamp=False, prefix=False)

    def clear(self):
        """Clear all log entries."""
        self.log_text.clear()
        self._line_count = 0
        self._not_dialed = []
        self.not_dialed_btn.setText("Not dialed (0)")
        self.not_dialed_btn.hide()

    def get_text(self) -> str:
        """Get all log text."""
        return self.log_text.toPlainText()

    def _apply_content_theme(self, theme: ThemeColors):
        """Apply theme to log panel content."""
        self.log_text.setStyleSheet(f"""
            QTextEdit#discoveryLog {{
                background-color: {theme.bg_tertiary};
                border: 1px solid {theme.border_dim};
                border-radius: 6px;
                padding: 8px;
                color: {theme.text_primary};
            }}
            
            QTextEdit#discoveryLog QScrollBar:vertical {{
                background-color: {theme.bg_tertiary};
                width: 8px;
                margin: 0;
                border-radius: 4px;
            }}
            
            QTextEdit#discoveryLog QScrollBar::handle:vertical {{
                background-color: {theme.scrollbar_handle};
                border-radius: 4px;
                min-height: 20px;
            }}
            
            QTextEdit#discoveryLog QScrollBar::handle:vertical:hover {{
                background-color: {theme.scrollbar_hover};
            }}
            
            QTextEdit#discoveryLog QScrollBar::add-line:vertical,
            QTextEdit#discoveryLog QScrollBar::sub-line:vertical {{
                height: 0px;
            }}
            
            QTextEdit#discoveryLog QScrollBar::add-page:vertical,
            QTextEdit#discoveryLog QScrollBar::sub-page:vertical {{
                background: none;
            }}
        """)
        self.not_dialed_btn.setStyleSheet(f"""
            QPushButton#notDialedButton {{
                background-color: transparent;
                border: 1px solid {theme.border_secondary};
                border-radius: 4px;
                padding: 3px 10px;
                color: {theme.text_secondary};
                font-size: 11px;
            }}
            QPushButton#notDialedButton:hover {{
                border-color: {theme.accent};
                color: {theme.accent};
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