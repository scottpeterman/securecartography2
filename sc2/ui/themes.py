"""
SecureCartography v2 - Theme System

Defines the enterprise Dark (default) and Light palettes and generates
comprehensive QSS stylesheets from them.
Provides holistic styling for all common PyQt6 widget types.

Widget Coverage:
    - Core: QWidget, QMainWindow, QDialog, QFrame
    - Text: QLabel, QLineEdit, QTextEdit, QPlainTextEdit
    - Buttons: QPushButton, QToolButton, QRadioButton, QCheckBox
    - Selection: QComboBox, QSpinBox, QDoubleSpinBox, QSlider
    - Containers: QGroupBox, QTabWidget, QScrollArea, QSplitter
    - Data: QTableWidget, QTableView, QListWidget, QListView, QTreeWidget, QTreeView
    - Navigation: QMenu, QMenuBar, QToolBar, QStatusBar
    - Feedback: QProgressBar, QToolTip, QMessageBox
    - Scrolling: QScrollBar

"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional
from enum import Enum
from ..paths import CACHE_DIR



class ThemeName(str, Enum):
    """Available themes."""
    DARK = "dark"
    LIGHT = "light"

    @classmethod
    def from_str(cls, value: Optional[str], default: "ThemeName" = None) -> "ThemeName":
        """
        Resolve a persisted/CLI theme string to a ThemeName.

        Unknown and retired names (anything left in a settings.json from an
        earlier release) fall back to the default rather than raising, so an
        upgrade never blocks startup.
        """
        if default is None:
            default = cls.DARK
        if isinstance(value, cls):
            return value
        try:
            return cls(str(value).strip().lower())
        except ValueError:
            return default


@dataclass
class ThemeColors:
    """
    Complete color palette for a theme.

    Naming convention matches the React mockup for easy reference.
    All colors are defined as solid hex or named colors for QSS compatibility.
    """
    # Background hierarchy
    bg_primary: str      # Main window background
    bg_secondary: str    # Panel backgrounds
    bg_tertiary: str     # Nested elements, table headers
    bg_input: str        # Input field backgrounds (solid approximation)
    bg_hover: str        # Hover state backgrounds (solid approximation)
    bg_selected: str     # Selected item backgrounds
    bg_disabled: str     # Disabled widget backgrounds
    bg_overlay: str      # Modal overlays (solid approximation)

    # Accent colors
    accent: str          # Primary accent (buttons, highlights)
    accent_dim: str      # Dimmed accent (gradient end, disabled)
    accent_hover: str    # Accent on hover
    accent_pressed: str  # Accent when pressed
    accent_danger: str   # Error/destructive actions
    accent_success: str  # Success states
    accent_warning: str  # Warnings, queue count
    accent_info: str     # Informational highlights

    # Text hierarchy
    text_primary: str    # Main text
    text_secondary: str  # Labels, descriptions
    text_muted: str      # Hints, timestamps, placeholders
    text_disabled: str   # Disabled text
    text_accent: str     # Accent-colored text
    text_on_accent: str  # Text on accent background (buttons)

    # Borders
    border_primary: str   # Focused/active borders
    border_secondary: str # Panel borders
    border_dim: str       # Subtle borders
    border_hover: str     # Hover state borders

    # Scrollbar specific
    scrollbar_bg: str     # Scrollbar track background
    scrollbar_handle: str # Scrollbar handle
    scrollbar_hover: str  # Scrollbar handle on hover

    # Theme metadata
    name: str = ""
    icon: str = ""
    is_dark: bool = True


# =============================================================================
# Theme Definitions
# =============================================================================

DARK_THEME = ThemeColors(
    name="Dark",
    icon="",
    is_dark=True,

    # Backgrounds - neutral graphite, panels one step lighter than the window
    bg_primary="#16181d",
    bg_secondary="#1c1f26",
    bg_tertiary="#242833",
    bg_input="#14161b",
    bg_hover="#2a2f3a",
    bg_selected="#1e3a5f",
    bg_disabled="#1a1c21",
    bg_overlay="#0f1115",

    # Accent - restrained blue; status colors kept conventional
    accent="#3b82f6",
    accent_dim="#2563eb",
    accent_hover="#60a5fa",
    accent_pressed="#1d4ed8",
    accent_danger="#ef4444",
    accent_success="#22c55e",
    accent_warning="#f59e0b",
    accent_info="#38bdf8",

    # Text
    text_primary="#e6e8eb",
    text_secondary="#aab1bc",
    text_muted="#7c8491",
    text_disabled="#4b515c",
    text_accent="#60a5fa",
    text_on_accent="#ffffff",

    # Borders - neutral; accent only on focus
    border_primary="#3b82f6",
    border_secondary="#3a404c",
    border_dim="#2c313b",
    border_hover="#4a5160",

    # Scrollbar - neutral, no accent
    scrollbar_bg="#1c1f26",
    scrollbar_handle="#3a404c",
    scrollbar_hover="#555d6b",
)

LIGHT_THEME = ThemeColors(
    name="Light",
    icon="",
    is_dark=False,

    # Backgrounds - off-white window, white panels
    bg_primary="#f5f6f8",
    bg_secondary="#ffffff",
    bg_tertiary="#eef0f3",
    bg_input="#ffffff",
    bg_hover="#e8ebf0",
    bg_selected="#dbe7fb",
    bg_disabled="#f0f1f3",
    bg_overlay="#e9ebef",

    # Accent
    accent="#2563eb",
    accent_dim="#1d4ed8",
    accent_hover="#3b82f6",
    accent_pressed="#1e40af",
    accent_danger="#dc2626",
    accent_success="#16a34a",
    accent_warning="#d97706",
    accent_info="#0284c7",

    # Text
    text_primary="#1f2328",
    text_secondary="#4b5563",
    text_muted="#6b7280",
    text_disabled="#9ca3af",
    text_accent="#1d4ed8",
    text_on_accent="#ffffff",

    # Borders
    border_primary="#2563eb",
    border_secondary="#c9ced6",
    border_dim="#dfe3e8",
    border_hover="#9aa3af",

    # Scrollbar
    scrollbar_bg="#eef0f3",
    scrollbar_handle="#c9ced6",
    scrollbar_hover="#9aa3af",
)

DEFAULT_THEME = ThemeName.DARK

THEMES: Dict[ThemeName, ThemeColors] = {
    ThemeName.DARK: DARK_THEME,
    ThemeName.LIGHT: LIGHT_THEME,
}


def get_theme(name: ThemeName) -> ThemeColors:
    """Get theme by name."""
    return THEMES[name]


# =============================================================================
# QSS Stylesheet Generation
# =============================================================================

# QSS has no CSS border-triangle support (the old trick renders as a bar) and
# no data: URIs, so arrow/check glyphs are small SVG files written once per
# colour into a cache dir and referenced by path.
_GLYPH_DIR = CACHE_DIR / "qss"

_GLYPHS = {
    "down":  '<svg xmlns="http://www.w3.org/2000/svg" width="10" height="6" viewBox="0 0 10 6">'
             '<path d="M1 1l4 4 4-4" fill="none" stroke="{c}" stroke-width="1.6" '
             'stroke-linecap="round" stroke-linejoin="round"/></svg>',
    "up":    '<svg xmlns="http://www.w3.org/2000/svg" width="10" height="6" viewBox="0 0 10 6">'
             '<path d="M1 5l4-4 4 4" fill="none" stroke="{c}" stroke-width="1.6" '
             'stroke-linecap="round" stroke-linejoin="round"/></svg>',
    "check": '<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 12 12">'
             '<path d="M2.5 6.2l2.4 2.4 4.6-5" fill="none" stroke="{c}" stroke-width="1.8" '
             'stroke-linecap="round" stroke-linejoin="round"/></svg>',
}


def _glyph(name: str, color: str) -> str:
    """
    Return a QSS `image:` value for a glyph in the given colour.

    Falls back to `none` if the cache dir is not writable, which degrades to
    the platform default rather than breaking the stylesheet.
    """
    path = _GLYPH_DIR / f"{name}-{color.lstrip('#').lower()}.svg"
    try:
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(_GLYPHS[name].format(c=color), encoding="utf-8")
    except OSError:
        return "none"
    # QSS wants forward slashes on every platform
    return f'url("{path.as_posix()}")'


qss_glyph = _glyph  # public: widgets with local stylesheets use this too


def generate_stylesheet(theme: ThemeColors) -> str:
    """
    Generate complete QSS stylesheet for the given theme.

    This creates consistent styling across all widgets while
    allowing the theme colors to drive the visual identity.

    Args:
        theme: ThemeColors instance defining the color palette

    Returns:
        Complete QSS stylesheet as a string
    """
    t = theme  # Shorthand for cleaner f-strings
    g_down = _glyph("down", t.text_secondary)
    g_down_hover = _glyph("down", t.text_primary)
    g_down_disabled = _glyph("down", t.text_disabled)
    g_up = _glyph("up", t.text_secondary)
    g_check = _glyph("check", t.text_on_accent)

    return f"""
/* ==========================================================================
   SecureCartography v2 - {t.name} Theme
   Generated QSS Stylesheet
   ========================================================================== */

/* ==========================================================================
   GLOBAL DEFAULTS
   ========================================================================== */

* {{
    outline: none;
}}

QWidget {{
    background-color: {t.bg_primary};
    color: {t.text_primary};
    font-family: "Segoe UI", "SF Pro Display", -apple-system, "Helvetica Neue", sans-serif;
    font-size: 13px;
    selection-background-color: {t.accent};
    selection-color: {t.text_on_accent};
}}

QWidget:disabled {{
    color: {t.text_disabled};
}}

/* ==========================================================================
   MAIN WINDOW & DIALOGS
   ========================================================================== */

QMainWindow {{
    background-color: {t.bg_primary};
}}

QMainWindow::separator {{
    background-color: {t.border_dim};
    width: 1px;
    height: 1px;
}}

QDialog {{
    background-color: {t.bg_secondary};
    border: 1px solid {t.border_dim};
    border-radius: 12px;
}}

/* ==========================================================================
   FRAMES & CONTAINERS
   ========================================================================== */

QFrame {{
    background-color: transparent;
    border: none;
}}

QFrame[frameShape="4"], /* StyledPanel */
QFrame[frameShape="5"], /* Panel */
QFrame[frameShape="6"] /* Box */ {{
    background-color: {t.bg_secondary};
    border: 1px solid {t.border_dim};
    border-radius: 8px;
}}

/* Named panel styles for custom widgets */
QFrame#panel {{
    background-color: {t.bg_secondary};
    border: 1px solid {t.border_dim};
    border-radius: 12px;
}}

QFrame#panelHeader {{
    background-color: {t.bg_tertiary};
    border: none;
    border-bottom: 1px solid {t.border_dim};
    border-top-left-radius: 12px;
    border-top-right-radius: 12px;
    padding: 8px 12px;
}}

QFrame#panelContent {{
    background-color: transparent;
    border: none;
    padding: 12px;
}}

/* ==========================================================================
   LABELS
   ========================================================================== */

QLabel {{
    background-color: transparent;
    border: none;
    color: {t.text_primary};
    padding: 0;
}}

QLabel:disabled {{
    color: {t.text_disabled};
}}

/* Named label styles */
QLabel#heading {{
    font-size: 18px;
    font-weight: bold;
    letter-spacing: 1px;
    color: {t.text_primary};
}}

QLabel#title {{
    font-size: 16px;
    font-weight: 600;
    color: {t.text_primary};
}}

QLabel#subheading {{
    font-size: 12px;
    color: {t.text_secondary};
}}

QLabel#sectionTitle {{
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: {t.text_secondary};
}}

QLabel#muted {{
    color: {t.text_muted};
    font-size: 11px;
}}

QLabel#accent {{
    color: {t.accent};
}}

QLabel#success {{
    color: {t.accent_success};
}}

QLabel#warning {{
    color: {t.accent_warning};
}}

QLabel#danger, QLabel#error {{
    color: {t.accent_danger};
}}

/* ==========================================================================
   LINE EDIT (Text Input)
   ========================================================================== */

QLineEdit {{
    background-color: {t.bg_input};
    border: 1px solid {t.border_dim};
    border-radius: 6px;
    padding: 8px 12px;
    color: {t.text_primary};
    selection-background-color: {t.accent};
    selection-color: {t.text_on_accent};
}}

QLineEdit:hover {{
    border-color: {t.border_hover};
}}

/* Inline cell editors (double-click a table cell). The form padding above
   would leave no room for text inside a table row. */
QAbstractItemView QLineEdit {{
    padding: 0px 6px;
    margin: 0px;
    border: 1px solid {t.accent};
    border-radius: 3px;
}}

QLineEdit:focus {{
    border-color: {t.accent};
}}

QLineEdit:disabled {{
    background-color: {t.bg_disabled};
    border-color: {t.border_dim};
    color: {t.text_disabled};
}}

QLineEdit[readOnly="true"] {{
    background-color: {t.bg_tertiary};
    border-color: {t.border_dim};
}}

/* Placeholder text - requires setPlaceholderText() */
QLineEdit::placeholder {{
    color: {t.text_muted};
}}

/* ==========================================================================
   TEXT EDIT / PLAIN TEXT EDIT (Multiline Text)
   ========================================================================== */

QTextEdit, QPlainTextEdit {{
    background-color: {t.bg_input};
    border: 1px solid {t.border_dim};
    border-radius: 6px;
    padding: 8px;
    color: {t.text_primary};
    selection-background-color: {t.accent};
    selection-color: {t.text_on_accent};
}}

/* Viewport inside text edits */
QTextEdit::viewport, QPlainTextEdit::viewport {{
    background-color: {t.bg_input};
}}

QTextEdit:hover, QPlainTextEdit:hover {{
    border-color: {t.border_hover};
}}

QTextEdit:focus, QPlainTextEdit:focus {{
    border-color: {t.accent};
}}

QTextEdit:disabled, QPlainTextEdit:disabled {{
    background-color: {t.bg_disabled};
    border-color: {t.border_dim};
    color: {t.text_disabled};
}}

/* Code/log style text areas */
QTextEdit#code, QPlainTextEdit#code,
QTextEdit#log, QPlainTextEdit#log {{
    font-family: "JetBrains Mono", "Cascadia Code", "Fira Code", "Consolas", monospace;
    font-size: 12px;
    background-color: {t.bg_tertiary};
}}

/* ==========================================================================
   PUSH BUTTON
   ========================================================================== */

QPushButton {{
    background-color: {t.bg_tertiary};
    border: 1px solid {t.border_dim};
    border-radius: 6px;
    padding: 8px 16px;
    color: {t.text_primary};
    font-weight: 500;
    min-width: 60px;
}}

QPushButton:hover {{
    background-color: {t.bg_hover};
    border-color: {t.border_hover};
}}

QPushButton:pressed {{
    background-color: {t.bg_selected};
    border-color: {t.accent};
}}

QPushButton:focus {{
    border-color: {t.accent};
}}

QPushButton:disabled {{
    background-color: {t.bg_disabled};
    border-color: {t.border_dim};
    color: {t.text_disabled};
}}

/* Primary/accent button */
QPushButton#primary, QPushButton[primary="true"] {{
    background-color: {t.accent};
    border: 1px solid {t.accent};
    color: {t.text_on_accent};
    font-weight: 600;
}}

QPushButton#primary:hover, QPushButton[primary="true"]:hover {{
    background-color: {t.accent_hover};
    border-color: {t.accent_hover};
}}

QPushButton#primary:pressed, QPushButton[primary="true"]:pressed {{
    background-color: {t.accent_pressed};
}}

QPushButton#primary:disabled, QPushButton[primary="true"]:disabled {{
    background-color: {t.bg_disabled};
    border-color: {t.border_dim};
    color: {t.text_disabled};
}}

/* Danger/destructive button */
QPushButton#danger, QPushButton[danger="true"] {{
    background-color: transparent;
    border: 1px solid {t.accent_danger};
    color: {t.accent_danger};
}}

QPushButton#danger:hover, QPushButton[danger="true"]:hover {{
    background-color: {t.accent_danger};
    color: white;
}}

QPushButton#danger:pressed, QPushButton[danger="true"]:pressed {{
    background-color: #b91c1c;
}}

/* Success button */
QPushButton#success, QPushButton[success="true"] {{
    background-color: transparent;
    border: 1px solid {t.accent_success};
    color: {t.accent_success};
}}

QPushButton#success:hover, QPushButton[success="true"]:hover {{
    background-color: {t.accent_success};
    color: white;
}}

/* Ghost/text button */
QPushButton#ghost, QPushButton[flat="true"] {{
    background-color: transparent;
    border: none;
    color: {t.text_secondary};
    padding: 4px 8px;
    min-width: 0;
}}

QPushButton#ghost:hover, QPushButton[flat="true"]:hover {{
    background-color: {t.bg_hover};
    color: {t.text_primary};
}}

/* Icon-only button */
QPushButton#icon {{
    background-color: transparent;
    border: none;
    padding: 6px;
    min-width: 0;
    min-height: 0;
}}

QPushButton#icon:hover {{
    background-color: {t.bg_hover};
    border-radius: 4px;
}}

/* ==========================================================================
   TOOL BUTTON
   ========================================================================== */

QToolButton {{
    background-color: transparent;
    border: none;
    border-radius: 4px;
    padding: 6px;
    color: {t.text_primary};
}}

QToolButton:hover {{
    background-color: {t.bg_hover};
}}

QToolButton:pressed {{
    background-color: {t.bg_selected};
}}

QToolButton:checked {{
    background-color: {t.bg_selected};
    border: 1px solid {t.accent};
}}

QToolButton:disabled {{
    color: {t.text_disabled};
}}

QToolButton::menu-indicator {{
    image: none;
    width: 0;
}}

QToolButton[popupMode="1"] {{
    padding-right: 16px;
}}

QToolButton[popupMode="1"]::menu-button {{
    border: none;
    width: 16px;
}}

/* ==========================================================================
   CHECKBOX
   ========================================================================== */

QCheckBox {{
    spacing: 8px;
    color: {t.text_primary};
    background-color: transparent;
}}

QCheckBox:disabled {{
    color: {t.text_disabled};
}}

QCheckBox::indicator {{
    width: 18px;
    height: 18px;
    border: 2px solid {t.border_secondary};
    border-radius: 4px;
    background-color: {t.bg_input};
}}

QCheckBox::indicator:hover {{
    border-color: {t.border_hover};
}}

QCheckBox::indicator:checked {{
    background-color: {t.accent};
    border-color: {t.accent};
    image: {g_check};
}}

QCheckBox::indicator:checked:hover {{
    background-color: {t.accent_hover};
    border-color: {t.accent_hover};
}}

QCheckBox::indicator:disabled {{
    background-color: {t.bg_disabled};
    border-color: {t.border_dim};
}}

QCheckBox::indicator:checked:disabled {{
    background-color: {t.text_disabled};
    border-color: {t.text_disabled};
}}


/* ==========================================================================
   RADIO BUTTON
   ========================================================================== */

QRadioButton {{
    spacing: 8px;
    color: {t.text_primary};
    background-color: transparent;
}}

QRadioButton:disabled {{
    color: {t.text_disabled};
}}

QRadioButton::indicator {{
    width: 18px;
    height: 18px;
    border: 2px solid {t.border_secondary};
    border-radius: 9px;
    background-color: {t.bg_input};
}}

QRadioButton::indicator:hover {{
    border-color: {t.border_hover};
}}

QRadioButton::indicator:checked {{
    background-color: {t.bg_input};
    border-color: {t.accent};
}}

QRadioButton::indicator:checked:hover {{
    border-color: {t.accent_hover};
}}

QRadioButton::indicator:disabled {{
    background-color: {t.bg_disabled};
    border-color: {t.border_dim};
}}

/* Inner dot - using border trick */
QRadioButton::indicator:checked {{
    border: 5px solid {t.accent};
}}

/* ==========================================================================
   COMBOBOX (Dropdown)
   ========================================================================== */

QComboBox {{
    background-color: {t.bg_input};
    border: 1px solid {t.border_dim};
    border-radius: 6px;
    padding: 8px 12px;
    padding-right: 30px;
    color: {t.text_primary};
    min-width: 80px;
}}

QComboBox:hover {{
    border-color: {t.border_hover};
}}

QComboBox:focus {{
    border-color: {t.accent};
}}

QComboBox:disabled {{
    background-color: {t.bg_disabled};
    border-color: {t.border_dim};
    color: {t.text_disabled};
}}

QComboBox::drop-down {{
    border: none;
    width: 24px;
    padding-right: 4px;
}}

QComboBox::down-arrow {{
    image: {g_down};
    width: 10px;
    height: 6px;
}}

QComboBox::down-arrow:hover {{
    image: {g_down_hover};
}}

QComboBox::down-arrow:disabled {{
    image: {g_down_disabled};
}}

/* Dropdown list - must style multiple levels to prevent white bleed-through */
QComboBox QAbstractItemView {{
    background-color: {t.bg_secondary};
    border: 1px solid {t.border_dim};
    border-radius: 6px;
    padding: 4px;
    selection-background-color: {t.bg_selected};
    selection-color: {t.text_primary};
    outline: none;
}}

/* Critical: Style the viewport inside the dropdown */
QComboBox QAbstractItemView::viewport {{
    background-color: {t.bg_secondary};
}}

/* Style the QListView specifically used by QComboBox */
QComboBox QListView {{
    background-color: {t.bg_secondary};
    border: 1px solid {t.border_dim};
    border-radius: 6px;
    padding: 4px;
    outline: none;
}}

QComboBox QListView::viewport {{
    background-color: {t.bg_secondary};
}}

QComboBox QAbstractItemView::item {{
    padding: 8px 12px;
    border-radius: 4px;
    min-height: 24px;
    background-color: {t.bg_secondary};
    color: {t.text_primary};
}}

QComboBox QAbstractItemView::item:hover {{
    background-color: {t.bg_hover};
}}

QComboBox QAbstractItemView::item:selected {{
    background-color: {t.bg_selected};
    color: {t.accent};
}}

/* Ensure the popup frame itself is styled */
QComboBox QFrame {{
    background-color: {t.bg_secondary};
    border: 1px solid {t.border_dim};
    border-radius: 6px;
}}

/* ==========================================================================
   SPINBOX (Number Input)
   ========================================================================== */

QSpinBox, QDoubleSpinBox {{
    background-color: {t.bg_input};
    border: 1px solid {t.border_dim};
    border-radius: 6px;
    padding: 8px 12px;
    padding-right: 24px;
    color: {t.text_primary};
    min-width: 60px;
}}

QSpinBox:hover, QDoubleSpinBox:hover {{
    border-color: {t.border_hover};
}}

QSpinBox:focus, QDoubleSpinBox:focus {{
    border-color: {t.accent};
}}

QSpinBox:disabled, QDoubleSpinBox:disabled {{
    background-color: {t.bg_disabled};
    border-color: {t.border_dim};
    color: {t.text_disabled};
}}

QSpinBox::up-button, QDoubleSpinBox::up-button {{
    subcontrol-origin: border;
    subcontrol-position: right top;
    width: 20px;
    height: 14px;
    border: none;
    border-left: 1px solid {t.border_dim};
    border-top-right-radius: 5px;
    background-color: {t.bg_tertiary};
}}

QSpinBox::up-button:hover, QDoubleSpinBox::up-button:hover {{
    background-color: {t.bg_hover};
}}

QSpinBox::up-button:pressed, QDoubleSpinBox::up-button:pressed {{
    background-color: {t.bg_selected};
}}

QSpinBox::down-button, QDoubleSpinBox::down-button {{
    subcontrol-origin: border;
    subcontrol-position: right bottom;
    width: 20px;
    height: 14px;
    border: none;
    border-left: 1px solid {t.border_dim};
    border-top: 1px solid {t.border_dim};
    border-bottom-right-radius: 5px;
    background-color: {t.bg_tertiary};
}}

QSpinBox::down-button:hover, QDoubleSpinBox::down-button:hover {{
    background-color: {t.bg_hover};
}}

QSpinBox::down-button:pressed, QDoubleSpinBox::down-button:pressed {{
    background-color: {t.bg_selected};
}}

QSpinBox::up-arrow, QDoubleSpinBox::up-arrow {{
    image: {g_up};
    width: 10px;
    height: 6px;
}}

QSpinBox::down-arrow, QDoubleSpinBox::down-arrow {{
    image: {g_down};
    width: 10px;
    height: 6px;
}}

/* ==========================================================================
   SLIDER
   ========================================================================== */

QSlider::groove:horizontal {{
    height: 6px;
    background-color: {t.bg_tertiary};
    border-radius: 3px;
}}

QSlider::handle:horizontal {{
    width: 16px;
    height: 16px;
    margin: -5px 0;
    background-color: {t.accent};
    border: 2px solid {t.accent};
    border-radius: 8px;
}}

QSlider::handle:horizontal:hover {{
    background-color: {t.accent_hover};
    border-color: {t.accent_hover};
}}

QSlider::handle:horizontal:pressed {{
    background-color: {t.accent_pressed};
}}

QSlider::handle:horizontal:disabled {{
    background-color: {t.text_disabled};
    border-color: {t.text_disabled};
}}

QSlider::sub-page:horizontal {{
    background-color: {t.accent};
    border-radius: 3px;
}}

QSlider::add-page:horizontal {{
    background-color: {t.bg_tertiary};
    border-radius: 3px;
}}

/* Vertical slider */
QSlider::groove:vertical {{
    width: 6px;
    background-color: {t.bg_tertiary};
    border-radius: 3px;
}}

QSlider::handle:vertical {{
    width: 16px;
    height: 16px;
    margin: 0 -5px;
    background-color: {t.accent};
    border: 2px solid {t.accent};
    border-radius: 8px;
}}

QSlider::handle:vertical:hover {{
    background-color: {t.accent_hover};
}}

QSlider::sub-page:vertical {{
    background-color: {t.accent};
    border-radius: 3px;
}}

QSlider::add-page:vertical {{
    background-color: {t.bg_tertiary};
    border-radius: 3px;
}}

/* ==========================================================================
   GROUP BOX
   ========================================================================== */

QGroupBox {{
    background-color: {t.bg_secondary};
    border: 1px solid {t.border_dim};
    border-radius: 8px;
    margin-top: 20px;
    padding: 16px;
    padding-top: 24px;
    font-weight: 600;
}}

QGroupBox::title {{
    color: {t.text_secondary};
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 12px;
    top: 8px;
    padding: 0 8px;
    background-color: {t.bg_secondary};
}}

QGroupBox:disabled {{
    color: {t.text_disabled};
}}

QGroupBox::title:disabled {{
    color: {t.text_disabled};
}}

/* ==========================================================================
   TAB WIDGET
   ========================================================================== */

QTabWidget {{
    background-color: transparent;
}}

QTabWidget::pane {{
    background-color: {t.bg_secondary};
    border: 1px solid {t.border_dim};
    border-radius: 8px;
    border-top-left-radius: 0;
    padding: 8px;
}}

QTabWidget::tab-bar {{
    left: 0px;
}}

QTabBar {{
    background-color: transparent;
}}

QTabBar::tab {{
    background-color: {t.bg_tertiary};
    color: {t.text_secondary};
    padding: 10px 20px;
    border: 1px solid {t.border_dim};
    border-bottom: none;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    margin-right: 2px;
}}

QTabBar::tab:hover {{
    background-color: {t.bg_hover};
    color: {t.text_primary};
}}

QTabBar::tab:selected {{
    background-color: {t.bg_secondary};
    color: {t.accent};
    border-bottom: 2px solid {t.accent};
}}

QTabBar::tab:disabled {{
    color: {t.text_disabled};
}}

/* Vertical tabs (left side) */
QTabBar[orientation="1"]::tab {{
    border: 1px solid {t.border_dim};
    border-right: none;
    border-top-left-radius: 6px;
    border-bottom-left-radius: 6px;
    border-top-right-radius: 0;
    border-bottom-right-radius: 0;
    margin-bottom: 2px;
    margin-right: 0;
}}

QTabBar[orientation="1"]::tab:selected {{
    border-right: 2px solid {t.accent};
    border-bottom: 1px solid {t.border_dim};
}}

/* ==========================================================================
   TABLES
   ========================================================================== */

QTableWidget, QTableView {{
    background-color: {t.bg_secondary};
    alternate-background-color: {t.bg_tertiary};
    border: 1px solid {t.border_dim};
    border-radius: 8px;
    gridline-color: {t.border_dim};
    selection-background-color: {t.bg_selected};
    selection-color: {t.text_primary};
}}

/* Viewport inside tables */
QTableWidget::viewport, QTableView::viewport {{
    background-color: {t.bg_secondary};
}}

QTableWidget::item, QTableView::item {{
    padding: 8px;
    border: none;
}}

QTableWidget::item:hover, QTableView::item:hover {{
    background-color: {t.bg_hover};
}}

QTableWidget::item:selected, QTableView::item:selected {{
    background-color: {t.bg_selected};
    color: {t.text_primary};
}}

QTableWidget::item:focus, QTableView::item:focus {{
    background-color: {t.bg_selected};
    border: 1px solid {t.accent};
}}

/* Table headers */
QHeaderView {{
    background-color: transparent;
}}

QHeaderView::section {{
    background-color: {t.bg_tertiary};
    color: {t.text_secondary};
    font-weight: 600;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 1px;
    padding: 10px 8px;
    border: none;
    border-bottom: 1px solid {t.border_dim};
    border-right: 1px solid {t.border_dim};
}}

QHeaderView::section:first {{
    border-top-left-radius: 7px;
}}

QHeaderView::section:last {{
    border-right: none;
    border-top-right-radius: 7px;
}}

QHeaderView::section:hover {{
    background-color: {t.bg_hover};
    color: {t.text_primary};
}}

QHeaderView::section:pressed {{
    background-color: {t.bg_selected};
}}

/* Corner button (between headers) */
QTableCornerButton::section {{
    background-color: {t.bg_tertiary};
    border: none;
    border-bottom: 1px solid {t.border_dim};
    border-right: 1px solid {t.border_dim};
}}

/* ==========================================================================
   LIST WIDGET / LIST VIEW
   ========================================================================== */

QListWidget, QListView {{
    background-color: {t.bg_secondary};
    alternate-background-color: {t.bg_tertiary};
    border: 1px solid {t.border_dim};
    border-radius: 8px;
    padding: 4px;
    outline: none;
}}

/* Viewport inside lists */
QListWidget::viewport, QListView::viewport {{
    background-color: {t.bg_secondary};
}}

QListWidget::item, QListView::item {{
    padding: 8px 12px;
    border-radius: 4px;
    margin: 1px 0;
}}

QListWidget::item:hover, QListView::item:hover {{
    background-color: {t.bg_hover};
}}

QListWidget::item:selected, QListView::item:selected {{
    background-color: {t.bg_selected};
    color: {t.text_primary};
}}

QListWidget::item:selected:active, QListView::item:selected:active {{
    background-color: {t.bg_selected};
}}

/* ==========================================================================
   TREE WIDGET / TREE VIEW
   ========================================================================== */

QTreeWidget, QTreeView {{
    background-color: {t.bg_secondary};
    alternate-background-color: {t.bg_tertiary};
    border: 1px solid {t.border_dim};
    border-radius: 8px;
    padding: 4px;
    outline: none;
}}

/* Viewport inside trees */
QTreeWidget::viewport, QTreeView::viewport {{
    background-color: {t.bg_secondary};
}}

QTreeWidget::item, QTreeView::item {{
    padding: 6px 8px;
    border-radius: 4px;
}}

QTreeWidget::item:hover, QTreeView::item:hover {{
    background-color: {t.bg_hover};
}}

QTreeWidget::item:selected, QTreeView::item:selected {{
    background-color: {t.bg_selected};
    color: {t.text_primary};
}}

QTreeWidget::branch {{
    background-color: transparent;
}}

QTreeWidget::branch:has-children:closed,
QTreeView::branch:has-children:closed {{
    border-image: none;
    image: none;
}}

QTreeWidget::branch:has-children:open,
QTreeView::branch:has-children:open {{
    border-image: none;
    image: none;
}}

/* ==========================================================================
   SCROLL AREA
   ========================================================================== */

QScrollArea {{
    background-color: transparent;
    border: none;
}}

QScrollArea > QWidget > QWidget {{
    background-color: transparent;
}}

QScrollArea > QWidget {{
    background-color: transparent;
}}

/* Viewport inside scroll areas */
QScrollArea QWidget#qt_scrollarea_viewport {{
    background-color: transparent;
}}

/* ==========================================================================
   SCROLLBARS
   ========================================================================== */

QScrollBar:vertical {{
    background-color: {t.scrollbar_bg};
    width: 12px;
    border-radius: 6px;
    margin: 0;
}}

QScrollBar::handle:vertical {{
    background-color: {t.scrollbar_handle};
    border-radius: 5px;
    min-height: 30px;
    margin: 2px;
}}

QScrollBar::handle:vertical:hover {{
    background-color: {t.scrollbar_hover};
}}

QScrollBar::add-line:vertical, 
QScrollBar::sub-line:vertical {{
    height: 0;
    background: none;
}}

QScrollBar::add-page:vertical, 
QScrollBar::sub-page:vertical {{
    background: none;
}}

QScrollBar:horizontal {{
    background-color: {t.scrollbar_bg};
    height: 12px;
    border-radius: 6px;
    margin: 0;
}}

QScrollBar::handle:horizontal {{
    background-color: {t.scrollbar_handle};
    border-radius: 5px;
    min-width: 30px;
    margin: 2px;
}}

QScrollBar::handle:horizontal:hover {{
    background-color: {t.scrollbar_hover};
}}

QScrollBar::add-line:horizontal, 
QScrollBar::sub-line:horizontal {{
    width: 0;
    background: none;
}}

QScrollBar::add-page:horizontal, 
QScrollBar::sub-page:horizontal {{
    background: none;
}}

/* ==========================================================================
   PROGRESS BAR
   ========================================================================== */

QProgressBar {{
    background-color: {t.bg_tertiary};
    border: none;
    border-radius: 4px;
    height: 8px;
    text-align: center;
}}

QProgressBar::chunk {{
    background-color: {t.accent};
    border-radius: 4px;
}}

/* Named variants for status */
QProgressBar#success::chunk {{
    background-color: {t.accent_success};
}}

QProgressBar#warning::chunk {{
    background-color: {t.accent_warning};
}}

QProgressBar#danger::chunk {{
    background-color: {t.accent_danger};
}}

/* ==========================================================================
   MENU BAR
   ========================================================================== */

QMenuBar {{
    background-color: {t.bg_secondary};
    border-bottom: 1px solid {t.border_dim};
    padding: 2px;
}}

QMenuBar::item {{
    background-color: transparent;
    padding: 6px 12px;
    border-radius: 4px;
}}

QMenuBar::item:selected {{
    background-color: {t.bg_hover};
}}

QMenuBar::item:pressed {{
    background-color: {t.bg_selected};
}}

/* ==========================================================================
   MENU (Context/Dropdown)
   ========================================================================== */

QMenu {{
    background-color: {t.bg_secondary};
    border: 1px solid {t.border_dim};
    border-radius: 8px;
    padding: 4px;
}}

/* Viewport inside menus */
QMenu::viewport {{
    background-color: {t.bg_secondary};
}}

QMenu::item {{
    padding: 8px 24px 8px 12px;
    border-radius: 4px;
    margin: 1px 0;
    background-color: transparent;
}}

QMenu::item:selected {{
    background-color: {t.bg_hover};
}}

QMenu::item:disabled {{
    color: {t.text_disabled};
}}

QMenu::separator {{
    height: 1px;
    background-color: {t.border_dim};
    margin: 4px 8px;
}}

QMenu::icon {{
    padding-left: 8px;
}}

QMenu::indicator {{
    width: 16px;
    height: 16px;
    padding-left: 4px;
}}

/* ==========================================================================
   TOOLBAR
   ========================================================================== */

QToolBar {{
    background-color: {t.bg_secondary};
    border: none;
    border-bottom: 1px solid {t.border_dim};
    padding: 4px;
    spacing: 4px;
}}

QToolBar::handle {{
    background-color: {t.border_dim};
    width: 2px;
    margin: 4px 2px;
}}

QToolBar::separator {{
    background-color: {t.border_dim};
    width: 1px;
    margin: 4px 4px;
}}

/* ==========================================================================
   STATUS BAR
   ========================================================================== */

QStatusBar {{
    background-color: {t.bg_secondary};
    border-top: 1px solid {t.border_dim};
    color: {t.text_secondary};
    font-size: 12px;
}}

QStatusBar::item {{
    border: none;
}}

QStatusBar QLabel {{
    padding: 2px 8px;
}}

/* ==========================================================================
   TOOLTIP
   ========================================================================== */

QToolTip {{
    background-color: {t.bg_secondary};
    color: {t.text_primary};
    border: 1px solid {t.border_dim};
    border-radius: 4px;
    padding: 6px 10px;
    font-size: 12px;
}}

/* ==========================================================================
   MESSAGE BOX
   ========================================================================== */

QMessageBox {{
    background-color: {t.bg_secondary};
}}

QMessageBox QLabel {{
    color: {t.text_primary};
}}

QMessageBox QPushButton {{
    min-width: 80px;
    padding: 8px 16px;
}}

/* ==========================================================================
   SPLITTER
   ========================================================================== */

QSplitter::handle {{
    background-color: {t.border_dim};
}}

QSplitter::handle:hover {{
    background-color: {t.accent};
}}

QSplitter::handle:horizontal {{
    width: 2px;
}}

QSplitter::handle:vertical {{
    height: 2px;
}}

/* ==========================================================================
   DOCK WIDGET
   ========================================================================== */

QDockWidget {{
    titlebar-close-icon: none;
    titlebar-normal-icon: none;
}}

QDockWidget::title {{
    background-color: {t.bg_tertiary};
    padding: 8px;
    border-bottom: 1px solid {t.border_dim};
}}

QDockWidget::close-button, QDockWidget::float-button {{
    background-color: transparent;
    border: none;
    padding: 2px;
}}

QDockWidget::close-button:hover, QDockWidget::float-button:hover {{
    background-color: {t.bg_hover};
    border-radius: 4px;
}}

/* ==========================================================================
   CALENDAR WIDGET
   ========================================================================== */

QCalendarWidget {{
    background-color: {t.bg_secondary};
}}

QCalendarWidget QToolButton {{
    color: {t.text_primary};
    background-color: {t.bg_tertiary};
    border: none;
    border-radius: 4px;
    padding: 4px 8px;
}}

QCalendarWidget QToolButton:hover {{
    background-color: {t.bg_hover};
}}

QCalendarWidget QSpinBox {{
    background-color: {t.bg_input};
}}

QCalendarWidget QWidget#qt_calendar_navigationbar {{
    background-color: {t.bg_tertiary};
}}

/* ==========================================================================
   DATE/TIME EDIT
   ========================================================================== */

QDateEdit, QTimeEdit, QDateTimeEdit {{
    background-color: {t.bg_input};
    border: 1px solid {t.border_dim};
    border-radius: 6px;
    padding: 8px 12px;
    color: {t.text_primary};
}}

QDateEdit:hover, QTimeEdit:hover, QDateTimeEdit:hover {{
    border-color: {t.border_hover};
}}

QDateEdit:focus, QTimeEdit:focus, QDateTimeEdit:focus {{
    border-color: {t.accent};
}}

QDateEdit::drop-down, QTimeEdit::drop-down, QDateTimeEdit::drop-down {{
    subcontrol-origin: padding;
    subcontrol-position: right center;
    width: 20px;
    border: none;
}}

/* ==========================================================================
   CUSTOM WIDGET CLASSES - SecureCartography Specific
   ========================================================================== */

/* Stats counter boxes */
QFrame#statBox {{
    background-color: {t.bg_tertiary};
    border: 1px solid {t.border_dim};
    border-radius: 8px;
    padding: 8px;
}}

QFrame#statBox:hover {{
    border-color: {t.border_hover};
}}

QLabel#statValue {{
    font-size: 24px;
    font-weight: bold;
    color: {t.text_primary};
}}

QLabel#statValueAccent {{
    font-size: 24px;
    font-weight: bold;
    color: {t.accent};
}}

QLabel#statValueSuccess {{
    font-size: 24px;
    font-weight: bold;
    color: {t.accent_success};
}}

QLabel#statValueWarning {{
    font-size: 24px;
    font-weight: bold;
    color: {t.accent_warning};
}}

QLabel#statValueDanger {{
    font-size: 24px;
    font-weight: bold;
    color: {t.accent_danger};
}}

QLabel#statLabel {{
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: {t.text_muted};
}}

/* Tag/badge components */
QFrame#tag {{
    background-color: {t.bg_hover};
    border: 1px solid {t.border_dim};
    border-radius: 4px;
    padding: 4px 8px;
}}

QFrame#tagAccent {{
    background-color: {t.bg_selected};
    border: 1px solid {t.accent};
    border-radius: 4px;
    padding: 4px 8px;
}}

QLabel#tagText {{
    font-size: 11px;
    color: {t.text_primary};
}}

QLabel#tagTextAccent {{
    font-size: 11px;
    color: {t.accent};
}}

/* Log entry styles */
QLabel#logSuccess {{
    color: {t.accent_success};
}}

QLabel#logWarning {{
    color: {t.accent_warning};
}}

QLabel#logError {{
    color: {t.accent_danger};
}}

QLabel#logInfo {{
    color: {t.accent_info};
}}

QLabel#logTimestamp {{
    color: {t.text_muted};
    font-family: "JetBrains Mono", "Cascadia Code", monospace;
    font-size: 11px;
}}

/* Card component */
QFrame#card {{
    background-color: {t.bg_secondary};
    border: 1px solid {t.border_dim};
    border-radius: 12px;
    padding: 16px;
}}

QFrame#card:hover {{
    border-color: {t.border_hover};
}}

/* Sidebar component */
QFrame#sidebar {{
    background-color: {t.bg_secondary};
    border-right: 1px solid {t.border_dim};
}}

/* Toolbar area */
QFrame#toolbarArea {{
    background-color: {t.bg_tertiary};
    border-bottom: 1px solid {t.border_dim};
    padding: 8px 12px;
}}

/* Input container (for password fields, search, etc) */
QFrame#inputContainer {{
    background-color: {t.bg_input};
    border: 1px solid {t.border_dim};
    border-radius: 6px;
}}

QFrame#inputContainer:focus-within {{
    border-color: {t.accent};
}}

/* Clickable item in lists */
QFrame#listItem {{
    background-color: transparent;
    border: none;
    border-radius: 6px;
    padding: 8px 12px;
}}

QFrame#listItem:hover {{
    background-color: {t.bg_hover};
}}

/* Empty state placeholder */
QLabel#emptyState {{
    color: {t.text_muted};
    font-size: 14px;
    padding: 32px;
}}

/* Divider */
QFrame#divider {{
    background-color: {t.border_dim};
    max-height: 1px;
    min-height: 1px;
}}

QFrame#dividerVertical {{
    background-color: {t.border_dim};
    max-width: 1px;
    min-width: 1px;
}}
"""


class ThemeManager:
    """
    Manages application theming.

    Usage:
        manager = ThemeManager()
        manager.set_theme(ThemeName.LIGHT)
        app.setStyleSheet(manager.stylesheet)

        # Get current colors for custom painting
        color = manager.theme.accent

        # Get specific color values
        bg = manager.get_color("bg_primary")
    """

    def __init__(self, initial_theme: ThemeName = DEFAULT_THEME):
        """
        Initialize theme manager.

        Args:
            initial_theme: Starting theme (default: DARK)
        """
        initial_theme = ThemeName.from_str(initial_theme)
        self._current_theme = initial_theme
        self._stylesheet = generate_stylesheet(THEMES[initial_theme])

    @property
    def theme(self) -> ThemeColors:
        """Get current theme colors."""
        return THEMES[self._current_theme]

    @property
    def theme_name(self) -> ThemeName:
        """Get current theme name."""
        return self._current_theme

    @property
    def stylesheet(self) -> str:
        """Get current stylesheet."""
        return self._stylesheet

    def set_theme(self, name: ThemeName) -> str:
        """
        Set active theme.

        Args:
            name: Theme to activate

        Returns:
            Generated stylesheet for the theme.
        """
        name = ThemeName.from_str(name)
        self._current_theme = name
        self._stylesheet = generate_stylesheet(THEMES[name])
        return self._stylesheet

    def get_color(self, color_name: str) -> Optional[str]:
        """
        Get a specific color from the current theme.

        Args:
            color_name: Name of the color attribute (e.g., "accent", "bg_primary")

        Returns:
            Color value string or None if not found
        """
        return getattr(self.theme, color_name, None)

    def available_themes(self) -> list:
        """
        List available themes with metadata.

        Returns:
            List of dicts with name, icon, and value for each theme
        """
        return [
            {
                "name": THEMES[t].name,
                "icon": THEMES[t].icon,
                "value": t,
                "is_dark": THEMES[t].is_dark
            }
            for t in ThemeName
        ]

    def is_dark_theme(self) -> bool:
        """Check if current theme is a dark theme."""
        return self.theme.is_dark


# =============================================================================
# Convenience Functions
# =============================================================================

def get_themed_stylesheet(theme_name: ThemeName) -> str:
    """
    Quick function to get a stylesheet for a theme.

    Args:
        theme_name: Which theme to generate stylesheet for

    Returns:
        Complete QSS stylesheet string
    """
    return generate_stylesheet(THEMES[theme_name])


def apply_widget_style(widget, style_name: str):
    """
    Apply a named style to a widget using setObjectName.

    This is a convenience for setting the object name which
    then triggers the appropriate QSS selector.

    Args:
        widget: The QWidget to style
        style_name: Object name to set (e.g., "primary", "danger", "panel")

    Example:
        apply_widget_style(my_button, "primary")
        apply_widget_style(my_label, "heading")
    """
    widget.setObjectName(style_name)


# =============================================================================
# Module-level exports
# =============================================================================

__all__ = [
    # Enums
    'ThemeName',
    # Dataclasses
    'ThemeColors',
    # Theme instances
    'DARK_THEME',
    'LIGHT_THEME',
    'THEMES',
    'DEFAULT_THEME',
    'qss_glyph',
    # Classes
    'ThemeManager',
    'StyledComboBox',
    # Functions
    'get_theme',
    'generate_stylesheet',
    'get_themed_stylesheet',
    'apply_widget_style',
]


# =============================================================================
# StyledComboBox - Properly styled dropdown
# =============================================================================

class StyledComboBox:
    """
    QComboBox subclass that properly styles the dropdown popup.

    The white frame around QComboBox dropdowns is caused by:
    1. The popup being a separate top-level window
    2. QSS can't fully style native window decorations
    3. The container widget isn't accessible via QSS

    This class fixes it by applying styling in showPopup() when
    the popup is actually created.

    Usage:
        from themes import StyledComboBox

        combo = StyledComboBox()
        combo.addItems(["Option 1", "Option 2"])
        combo.set_theme_colors(theme_manager.theme)  # Apply theme

    Or manually:
        combo.set_popup_colors(
            bg_color="#1c1f26",
            text_color="#e6e8eb",
            border_color="#2c313b",
            hover_color="#2a2f3a",
            selected_color="#1e3a5f",
            accent="#3b82f6"
        )
    """

    def __new__(cls, parent=None):
        # Lazy import to avoid circular dependency
        from PyQt6.QtWidgets import QComboBox, QListView
        from PyQt6.QtCore import Qt
        from PyQt6.QtGui import QPalette, QColor

        class _StyledComboBox(QComboBox):
            def __init__(self, parent=None):
                super().__init__(parent)
                self._popup_bg = DARK_THEME.bg_secondary
                self._popup_text = DARK_THEME.text_primary
                self._popup_border = DARK_THEME.border_dim
                self._popup_hover = DARK_THEME.bg_hover
                self._popup_selected = DARK_THEME.bg_selected
                self._popup_accent = DARK_THEME.accent

                # Use QListView for better styling control
                list_view = QListView()
                self.setView(list_view)

            def set_popup_colors(self, bg_color: str, text_color: str, border_color: str,
                                 hover_color: str, selected_color: str, accent: str):
                """Set the colors for the dropdown popup."""
                self._popup_bg = bg_color
                self._popup_text = text_color
                self._popup_border = border_color
                self._popup_hover = hover_color
                self._popup_selected = selected_color
                self._popup_accent = accent

            def set_theme_colors(self, theme: ThemeColors):
                """Set popup colors from a ThemeColors instance."""
                self.set_popup_colors(
                    bg_color=theme.bg_secondary,
                    text_color=theme.text_primary,
                    border_color=theme.border_dim,
                    hover_color=theme.bg_hover,
                    selected_color=theme.bg_selected,
                    accent=theme.accent
                )

            def showPopup(self):
                """Override to style the popup container when it's shown."""
                self._configure_popup()
                super().showPopup()
                self._style_popup_window()

            def _configure_popup(self):
                """Configure the view and its styling."""
                view = self.view()
                if not view:
                    return

                # Style with palette (most reliable)
                palette = view.palette()
                palette.setColor(QPalette.ColorRole.Base, QColor(self._popup_bg))
                palette.setColor(QPalette.ColorRole.Window, QColor(self._popup_bg))
                palette.setColor(QPalette.ColorRole.Text, QColor(self._popup_text))
                palette.setColor(QPalette.ColorRole.Highlight, QColor(self._popup_selected))
                palette.setColor(QPalette.ColorRole.HighlightedText, QColor(self._popup_accent))
                palette.setColor(QPalette.ColorRole.AlternateBase, QColor(self._popup_bg))
                view.setPalette(palette)

                # Style viewport too
                viewport = view.viewport()
                if viewport:
                    viewport.setPalette(palette)
                    viewport.setAutoFillBackground(True)

                # Apply stylesheet to view
                view.setStyleSheet(f"""
                    QListView {{
                        background-color: {self._popup_bg};
                        border: 1px solid {self._popup_border};
                        border-radius: 6px;
                        padding: 4px;
                        outline: none;
                    }}
                    QListView::item {{
                        background-color: {self._popup_bg};
                        color: {self._popup_text};
                        padding: 8px 12px;
                        border-radius: 4px;
                        min-height: 24px;
                    }}
                    QListView::item:hover {{
                        background-color: {self._popup_hover};
                    }}
                    QListView::item:selected {{
                        background-color: {self._popup_selected};
                        color: {self._popup_accent};
                    }}
                """)

            def _style_popup_window(self):
                """Style the popup container window after it's shown."""
                view = self.view()
                if not view:
                    return

                try:
                    container = view.parentWidget()
                    if container:
                        container.setWindowFlags(
                            Qt.WindowType.Popup |
                            Qt.WindowType.FramelessWindowHint |
                            Qt.WindowType.NoDropShadowWindowHint
                        )
                        container.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)

                        container.setStyleSheet(f"""
                            background-color: {self._popup_bg};
                            border: 1px solid {self._popup_border};
                            border-radius: 6px;
                        """)

                        palette = container.palette()
                        palette.setColor(QPalette.ColorRole.Window, QColor(self._popup_bg))
                        palette.setColor(QPalette.ColorRole.Base, QColor(self._popup_bg))
                        container.setPalette(palette)
                        container.setAutoFillBackground(True)
                except Exception:
                    pass  # Visual enhancement only

        return _StyledComboBox(parent)


def fix_combobox_popup(combobox, theme: ThemeColors):
    """
    Apply Python-side fixes for QComboBox popup styling.

    QSS alone often can't fully style the combo popup due to how Qt
    creates the popup window. This function applies additional fixes.

    Call this after creating the QComboBox and after setting the stylesheet.

    Args:
        combobox: The QComboBox widget to fix
        theme: ThemeColors instance for the current theme

    Example:
        combo = QComboBox()
        fix_combobox_popup(combo, theme_manager.theme)
    """
    from PyQt6.QtCore import Qt
    from PyQt6.QtGui import QPalette, QColor

    try:
        view = combobox.view()

        # Set window flags for frameless popup
        popup = view.window()
        popup.setWindowFlags(
            Qt.WindowType.Popup | Qt.WindowType.FramelessWindowHint
        )
        popup.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)

        # Also set palette colors as fallback
        palette = view.palette()
        palette.setColor(QPalette.ColorRole.Base, QColor(theme.bg_secondary))
        palette.setColor(QPalette.ColorRole.Window, QColor(theme.bg_secondary))
        palette.setColor(QPalette.ColorRole.Text, QColor(theme.text_primary))
        palette.setColor(QPalette.ColorRole.Highlight, QColor(theme.bg_selected))
        palette.setColor(QPalette.ColorRole.HighlightedText, QColor(theme.accent))
        view.setPalette(palette)

        # Set viewport palette too
        if hasattr(view, 'viewport') and view.viewport():
            view.viewport().setPalette(palette)
            view.viewport().setAutoFillBackground(True)

    except Exception as e:
        # Silently fail - this is a visual enhancement, not critical
        pass


def fix_all_comboboxes(parent_widget, theme: ThemeColors):
    """
    Find and fix all QComboBox widgets under a parent.

    Useful for applying the popup fix to an entire dialog or window.

    Args:
        parent_widget: Parent widget to search under
        theme: ThemeColors instance for the current theme

    Example:
        fix_all_comboboxes(main_window, theme_manager.theme)
    """
    from PyQt6.QtWidgets import QComboBox

    for combo in parent_widget.findChildren(QComboBox):
        fix_combobox_popup(combo, theme)