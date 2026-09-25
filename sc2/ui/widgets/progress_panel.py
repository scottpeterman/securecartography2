"""
Secure Cartography - Progress Panel

Live crawl progress:
- Counters: Reached, Failed, Not dialed, In flight
- Status line (state + elapsed / seed)
- One row per depth: reached (success) / failed (danger) / pending segments,
  with "done/attempted" and not-dialed count for that depth
"""

from typing import Dict, Optional

from PyQt6.QtCore import Qt, QRectF, QSize
from PyQt6.QtGui import QColor, QFont, QPainter, QPainterPath
from PyQt6.QtWidgets import (
    QFrame, QGridLayout, QHBoxLayout, QLabel, QSizePolicy, QVBoxLayout, QWidget,
)

from ..themes import ThemeColors, ThemeManager
from .panel import Panel
from .stat_box import StatBoxRow


class DepthBar(QWidget):
    """Thin segmented bar: reached | failed | pending (of attempted)."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.attempted = 0
        self.reached = 0
        self.failed = 0
        self._colors = ("#22c55e", "#ef4444", "#3a404c")
        self.setFixedHeight(8)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

    def sizeHint(self) -> QSize:
        return QSize(200, 8)

    def set_counts(self, attempted: int, reached: int, failed: int):
        self.attempted, self.reached, self.failed = attempted, reached, failed
        self.update()

    def set_colors(self, success: str, danger: str, track: str):
        self._colors = (success, danger, track)
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = float(self.width()), float(self.height())
        radius = h / 2

        clip = QPainterPath()
        clip.addRoundedRect(QRectF(0, 0, w, h), radius, radius)
        p.setClipPath(clip)
        p.fillRect(QRectF(0, 0, w, h), QColor(self._colors[2]))

        total = max(self.attempted, self.reached + self.failed, 1)
        x = 0.0
        for count, color in ((self.reached, self._colors[0]), (self.failed, self._colors[1])):
            if count <= 0:
                continue
            seg = w * count / total
            p.fillRect(QRectF(x, 0, seg, h), QColor(color))
            x += seg
        p.end()


class ProgressPanel(Panel):
    """
    Progress tracking panel.

    Driven by DiscoveryController:
        start(max_depth)                  - crawl started
        depth_started(depth, count)       - a depth began with `count` targets
        device_result(depth, ok)          - one target at `depth` finished
        depth_complete(data)              - depth tallies from the engine
        add_not_dialed(depth)             - a neighbor will never be dialed
        set_complete(seconds, ...)        - crawl finished
    """

    def __init__(
        self,
        theme_manager: Optional[ThemeManager] = None,
        parent: Optional[QWidget] = None,
    ):
        super().__init__(
            title="PROGRESS",
            icon="",
            theme_manager=theme_manager,
            parent=parent,
            _defer_theme=True,
        )
        self._state = "idle"
        self._max_depth = 0
        self._rows: Dict[int, dict] = {}
        self._reached = 0
        self._failed = 0
        self._not_dialed = 0
        self._current_depth = -1
        self._theme: Optional[ThemeColors] = None
        self._setup_content()
        if theme_manager:
            self.apply_theme(theme_manager.theme)

    # ------------------------------------------------------------------ UI

    def _setup_content(self):
        self.stats = StatBoxRow(theme_manager=self.theme_manager, auto_total=False)
        self.stats.discovered.set_label("REACHED")
        self.stats.discovered.set_color_role("success")
        self.stats.failed.set_label("FAILED")
        self.stats.queued.set_label("NOT DIALED")
        self.stats.queued.set_color_role("muted")
        self.stats.total.set_label("IN FLIGHT")
        self.stats.total.set_color_role("accent")
        self.content_layout.addWidget(self.stats)

        # Status line
        status_row = QHBoxLayout()
        status_row.setSpacing(8)
        self.status_label = QLabel("Ready")
        self.status_label.setObjectName("progressStatus")
        status_row.addWidget(self.status_label, 1)
        self.elapsed_label = QLabel("")
        self.elapsed_label.setObjectName("progressElapsed")
        status_row.addWidget(self.elapsed_label)
        self.content_layout.addLayout(status_row)

        # "BY DEPTH" rows
        self.depth_header = QLabel("BY DEPTH")
        self.depth_header.setObjectName("depthHeader")
        self.content_layout.addWidget(self.depth_header)

        self.depth_frame = QWidget()
        self.depth_grid = QGridLayout(self.depth_frame)
        self.depth_grid.setContentsMargins(0, 0, 0, 0)
        self.depth_grid.setHorizontalSpacing(10)
        self.depth_grid.setVerticalSpacing(6)
        self.depth_grid.setColumnStretch(1, 1)
        self.content_layout.addWidget(self.depth_frame)

        self.depth_empty = QLabel("Depth rows appear as the crawl runs")
        self.depth_empty.setObjectName("depthEmpty")
        self.depth_grid.addWidget(self.depth_empty, 0, 0, 1, 3)

    def _row(self, depth: int) -> dict:
        """Get or create the widgets for one depth row."""
        if depth in self._rows:
            return self._rows[depth]
        self.depth_empty.hide()

        name = QLabel(f"D{depth}")
        name.setObjectName("depthName")
        bar = DepthBar()
        text = QLabel("")
        text.setObjectName("depthText")
        text.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        text.setMinimumWidth(130)

        r = depth + 1
        self.depth_grid.addWidget(name, r, 0)
        self.depth_grid.addWidget(bar, r, 1)
        self.depth_grid.addWidget(text, r, 2)

        row = {"name": name, "bar": bar, "text": text,
               "attempted": 0, "reached": 0, "failed": 0, "not_dialed": 0}
        self._rows[depth] = row
        if self._theme:
            self._style_row(row, self._theme)
        return row

    def _refresh_row(self, depth: int):
        row = self._rows.get(depth)
        if not row:
            return
        done = row["reached"] + row["failed"]
        row["bar"].set_counts(row["attempted"], row["reached"], row["failed"])
        text = f"{done}/{row['attempted']}"
        if row["not_dialed"]:
            text += f"  ·  {row['not_dialed']} not dialed"
        row["text"].setText(text)

    def _refresh_counters(self):
        self.stats.set_discovered(self._reached)
        self.stats.set_failed(self._failed)
        self.stats.set_queued(self._not_dialed)
        in_flight = 0
        cur = self._rows.get(self._current_depth)
        if cur and self._state == "running":
            in_flight = max(0, cur["attempted"] - cur["reached"] - cur["failed"])
        self.stats.set_total(in_flight)

    # ------------------------------------------------------------ Public API

    def reset(self):
        """Clear all counters and depth rows."""
        for row in self._rows.values():
            for key in ("name", "bar", "text"):
                self.depth_grid.removeWidget(row[key])
                row[key].deleteLater()
        self._rows.clear()
        self.depth_empty.show()
        self._reached = self._failed = self._not_dialed = 0
        self._current_depth = -1
        self.stats.reset()
        self.elapsed_label.setText("")
        self._state = "idle"
        self.status_label.setText("Ready")

    def start(self, max_depth: int, seeds: str = ""):
        self.reset()
        self._max_depth = max_depth
        self._state = "running"
        self.status_label.setText(f"Crawling {seeds}".strip() if seeds else "Crawling")
        self._restyle_status()

    def depth_started(self, depth: int, count: int, max_depth: int = 0):
        if max_depth:
            self._max_depth = max_depth
        self._current_depth = depth
        row = self._row(depth)
        row["attempted"] = count
        self._refresh_row(depth)
        self._refresh_counters()
        self.status_label.setText(f"Depth {depth} of {self._max_depth}  ·  {count} targets")

    def device_result(self, depth: int, ok: bool):
        row = self._row(depth)
        if ok:
            row["reached"] += 1
            self._reached += 1
        else:
            row["failed"] += 1
            self._failed += 1
        self._refresh_row(depth)
        self._refresh_counters()

    def depth_complete(self, data: dict):
        """Reconcile with the engine's final tallies for the depth."""
        depth = int(data.get("depth", 0))
        row = self._row(depth)
        attempted = int(data.get("attempted") or row["attempted"])
        reached = int(data.get("discovered", row["reached"]))
        failed = int(data.get("failed", row["failed"]))
        self._reached += reached - row["reached"]
        self._failed += failed - row["failed"]
        row.update(attempted=attempted, reached=reached, failed=failed)
        self._refresh_row(depth)
        self._refresh_counters()

    def add_not_dialed(self, depth: Optional[int] = None):
        self._not_dialed += 1
        d = self._current_depth if depth is None else depth
        if d in self._rows:
            self._rows[d]["not_dialed"] += 1
            self._refresh_row(d)
        self._refresh_counters()

    def set_counts(self, discovered: int = 0, failed: int = 0, **_ignored):
        """Engine stats are authoritative for the totals."""
        self._reached, self._failed = int(discovered), int(failed)
        self._refresh_counters()

    def set_complete(self, elapsed_seconds: float = 0, discovered: int = 0, failed: int = 0):
        self._state = "complete"
        m, s = divmod(int(elapsed_seconds), 60)
        self.elapsed_label.setText(f"{m}:{s:02d}" if elapsed_seconds else "")
        self.status_label.setText(
            f"Complete  ·  {discovered} reached, {failed} failed, {self._not_dialed} not dialed"
        )
        self._refresh_counters()
        self._restyle_status()

    def set_cancelled(self):
        self._state = "cancelled"
        self.status_label.setText("Cancelled")
        self._refresh_counters()
        self._restyle_status()

    def set_error(self, message: str = ""):
        self._state = "error"
        self.status_label.setText(message or "Error")
        self._restyle_status()

    # Compatibility with existing callers
    def set_idle(self):
        if self._state in ("complete", "cancelled", "error"):
            return  # keep the result visible after the worker exits
        self._state = "idle"
        self.status_label.setText("Ready")
        self._refresh_counters()
        self._restyle_status()

    def set_running(self):
        self._state = "running"

    def set_depth(self, current: int, maximum: int):
        self._max_depth = maximum

    def set_progress(self, percent: int):
        pass

    def set_current_target(self, target: str):
        if target:
            self.status_label.setText(target)

    # ---------------------------------------------------------------- Theme

    def _style_row(self, row: dict, t: ThemeColors):
        row["bar"].set_colors(t.accent_success, t.accent_danger, t.border_secondary)
        row["name"].setStyleSheet(
            f"color: {t.text_secondary}; font-size: 12px; background: transparent;")
        row["text"].setStyleSheet(
            f"color: {t.text_secondary}; font-size: 12px; background: transparent;")

    def _restyle_status(self):
        t = self._theme
        if not t:
            return
        color = {
            "complete": t.accent_success,
            "cancelled": t.accent_warning,
            "error": t.accent_danger,
        }.get(self._state, t.text_primary)
        self.status_label.setStyleSheet(
            f"color: {color}; font-size: 13px; background: transparent;")

    def _apply_content_theme(self, theme: ThemeColors):
        self._theme = theme
        self.stats.apply_theme(theme)
        self._restyle_status()
        self.elapsed_label.setStyleSheet(
            f"color: {theme.text_secondary}; font-size: 13px; background: transparent;")
        self.depth_header.setStyleSheet(
            f"color: {theme.text_muted}; font-size: 10px; font-weight: 600; "
            f"letter-spacing: 1px; background: transparent; padding-top: 4px;")
        self.depth_empty.setStyleSheet(
            f"color: {theme.text_muted}; font-size: 12px; background: transparent;")
        for row in self._rows.values():
            self._style_row(row, theme)

    def apply_theme(self, theme: ThemeColors):
        super().apply_theme(theme)
        self._apply_content_theme(theme)

    def set_theme(self, theme_manager: ThemeManager):
        super().set_theme(theme_manager)
        self._apply_content_theme(theme_manager.theme)
