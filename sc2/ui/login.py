"""
SecureCartography v2 - Login Dialog

Vault unlock screen with password authentication.
Matches the mockup design with icon, title, and styled inputs.
"""
import traceback
from pathlib import Path
from typing import Optional, Callable

from PyQt6.QtCore import Qt, QSize, QPointF, pyqtSignal
from PyQt6.QtGui import QFont, QIcon, QColor, QPainter, QPen, QBrush
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QFrame, QWidget, QMessageBox, QApplication,
    QGraphicsDropShadowEffect
)

from .themes import (
    ThemeColors, ThemeManager, ThemeName, DEFAULT_THEME, get_theme,
    fix_all_comboboxes, StyledComboBox, qss_glyph,
)
from .. import __version__
from .settings import SettingsManager, get_settings
from ..paths import APP_DIR


class IconLabel(QLabel):
    """
    Label that renders a simple icon using unicode or custom painting.
    For PyQt6, we'll use a simple approach with unicode symbols
    or custom SVG rendering.
    """

    def __init__(self, icon_char: str = "", size: int = 32, parent=None):
        super().__init__(parent)
        self.setText(icon_char)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        font = self.font()
        font.setPointSize(size)
        self.setFont(font)


class ThemeBanner(QWidget):
    """
    Code-drawn product mark: a small node/link glyph in the theme palette.

    Replaces the old per-theme raster banners. Painting it keeps the package
    small, stays crisp at any DPI, and follows theme changes without assets.
    API (set_theme / set_max_size) is unchanged from the image version.
    """

    # Normalised node positions and links - a minimal topology motif
    _NODES = [(0.14, 0.72), (0.50, 0.22), (0.86, 0.72), (0.50, 0.78)]
    _LINKS = [(0, 1), (1, 2), (0, 3), (3, 2), (1, 3)]
    _HUB = 1

    def __init__(self, theme_name: ThemeName = DEFAULT_THEME,
                 max_width: int = 320, max_height: int = 120, parent=None):
        super().__init__(parent)
        self._theme: ThemeColors = get_theme(ThemeName.from_str(theme_name))
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.set_max_size(max_width, max_height)

    def set_theme(self, theme_name: ThemeName):
        """Repaint with a different theme's palette."""
        self._theme = get_theme(ThemeName.from_str(theme_name))
        self.update()

    def set_max_size(self, width: int, height: int):
        """Constrain the mark; it never grows past a compact 120x80."""
        self.setFixedSize(min(width, 120), min(height, 80))
        self.update()

    def paintEvent(self, event):
        t = self._theme
        w, h = self.width(), self.height()
        r = min(w, h) * 0.09

        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        pts = [QPointF(x * w, y * h) for x, y in self._NODES]

        painter.setPen(QPen(QColor(t.border_hover), 2))
        for a_idx, b_idx in self._LINKS:
            painter.drawLine(pts[a_idx], pts[b_idx])

        for i, pt in enumerate(pts):
            hub = i == self._HUB
            painter.setPen(QPen(QColor(t.accent), 2))
            painter.setBrush(QBrush(QColor(t.accent if hub else t.bg_secondary)))
            radius = r * 1.25 if hub else r
            painter.drawEllipse(pt, radius, radius)

        painter.end()


class PasswordInput(QWidget):
    """
    Styled password input with visibility toggle,
    matching the mockup's ThemedInput component.
    """

    textChanged = pyqtSignal(str)
    returnPressed = pyqtSignal()

    def __init__(self, placeholder: str = "Enter password...", parent=None):
        super().__init__(parent)
        self._setup_ui(placeholder)

    def _setup_ui(self, placeholder: str):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Container frame for styling
        self.container = QFrame()
        self.container.setObjectName("passwordContainer")
        container_layout = QHBoxLayout(self.container)
        container_layout.setContentsMargins(12, 0, 8, 0)
        container_layout.setSpacing(8)

        # Shield icon (as text for simplicity)
        self.icon_label = QLabel("")
        self.icon_label.setStyleSheet("background: transparent; border: none;")
        self.icon_label.hide()
        container_layout.addWidget(self.icon_label)

        # Password input
        self.input = QLineEdit()
        self.input.setPlaceholderText(placeholder)
        self.input.setEchoMode(QLineEdit.EchoMode.Password)
        self.input.setStyleSheet("""
            QLineEdit {
                background: transparent;
                border: none;
                padding: 10px 0;
                font-size: 14px;
            }
        """)
        self.input.textChanged.connect(self.textChanged.emit)
        self.input.returnPressed.connect(self.returnPressed.emit)
        container_layout.addWidget(self.input, 1)

        # Visibility toggle
        self.toggle_btn = QPushButton("Show")
        self.toggle_btn.setFixedSize(48, 32)
        self.toggle_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.toggle_btn.setStyleSheet("""
            QPushButton {
                background: transparent;
                border: none;
                font-size: 14px;
            }
            QPushButton:hover {
                opacity: 0.7;
            }
        """)
        self.toggle_btn.clicked.connect(self._toggle_visibility)
        container_layout.addWidget(self.toggle_btn)

        layout.addWidget(self.container)

        self._visible = False

    def _toggle_visibility(self):
        self._visible = not self._visible
        if self._visible:
            self.input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.toggle_btn.setText("Hide")
        else:
            self.input.setEchoMode(QLineEdit.EchoMode.Password)
            self.toggle_btn.setText("Show")

    def text(self) -> str:
        return self.input.text()

    def setText(self, text: str):
        self.input.setText(text)

    def clear(self):
        self.input.clear()

    def setFocus(self):
        self.input.setFocus()

    def apply_theme(self, theme: ThemeColors):
        """Apply theme colors to the input."""
        bg_input = theme.bg_input
        border_dim = theme.border_secondary

        self.container.setStyleSheet(f"""
            QFrame#passwordContainer {{
                background-color: {bg_input};
                border: 1px solid {border_dim};
                border-radius: 8px;
            }}
        """)
        self.icon_label.setStyleSheet(f"""
            background: transparent; 
            border: none;
            color: {theme.text_muted};
        """)
        self.input.setStyleSheet(f"""
            QLineEdit {{
                background: transparent;
                border: none;
                padding: 10px 0;
                font-size: 14px;
                color: {theme.text_primary};
            }}
        """)
        self.toggle_btn.setStyleSheet(f"""
            QPushButton {{
                background: transparent;
                border: none;
                font-size: 12px;
                color: {theme.text_muted};
            }}
            QPushButton:hover {{
                color: {theme.accent};
            }}
        """)


class LoginDialog(QDialog):
    """
    Vault login dialog.

    Handles:
    - First-time vault initialization
    - Vault unlock with password
    - Vault reset (delete and reinitialize)

    Signals:
        vault_unlocked: Emitted when vault is successfully unlocked
    """

    vault_unlocked = pyqtSignal(object)  # Emits the unlocked vault

    def __init__(
        self,
        vault,  # CredentialVault instance
        theme_manager: ThemeManager,
        settings: Optional[SettingsManager] = None,
        parent=None
    ):
        super().__init__(parent)
        self.vault = vault
        self.theme_manager = theme_manager
        self.settings = settings or get_settings()

        self.setWindowTitle("Secure Cartography")
        self.setFixedSize(420, 620)  # Fixed size for clean layout
        self.setWindowFlags(
            Qt.WindowType.Dialog |
            Qt.WindowType.FramelessWindowHint
        )
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)

        self._setup_ui()
        self._apply_theme()

    def _setup_ui(self):
        """Build the login dialog UI."""
        # Main layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)

        # Content card
        self.card = QFrame()
        self.card.setObjectName("loginCard")
        card_layout = QVBoxLayout(self.card)
        card_layout.setContentsMargins(32, 24, 32, 24)
        card_layout.setSpacing(0)  # Control spacing manually

        # Top accent line
        self.accent_line = QFrame()
        self.accent_line.setFixedHeight(3)
        self.accent_line.setObjectName("accentLine")
        card_layout.addWidget(self.accent_line)

        # Theme selector row (right-aligned)
        theme_row = QHBoxLayout()
        theme_row.setContentsMargins(0, 12, 0, 0)
        theme_row.addStretch()

        self.theme_combo = StyledComboBox()
        self.theme_combo.setFixedWidth(120)
        self.theme_combo.setFixedHeight(32)
        self.theme_combo.setCursor(Qt.CursorShape.PointingHandCursor)
        self.theme_combo.addItem("Dark", ThemeName.DARK)
        self.theme_combo.addItem("Light", ThemeName.LIGHT)

        # Set popup colors from current theme
        self.theme_combo.set_theme_colors(self.theme_manager.theme)

        # Set current theme from settings
        current_theme = self.theme_manager.theme_name
        for i in range(self.theme_combo.count()):
            if self.theme_combo.itemData(i) == current_theme:
                self.theme_combo.setCurrentIndex(i)
                break

        self.theme_combo.currentIndexChanged.connect(self._on_theme_changed)
        theme_row.addWidget(self.theme_combo)

        card_layout.addLayout(theme_row)

        # Spacer
        card_layout.addSpacing(16)

        # Banner image (theme-aware)
        banner_container = QWidget()
        banner_container.setObjectName("bannerContainer")
        banner_container.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        banner_layout = QHBoxLayout(banner_container)
        banner_layout.setContentsMargins(0, 0, 0, 0)
        banner_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.banner = ThemeBanner(
            theme_name=self.theme_manager.theme_name,
            max_width=320,
            max_height=100
        )
        banner_layout.addWidget(self.banner)

        card_layout.addWidget(banner_container)

        # Spacer
        card_layout.addSpacing(16)

        # Title
        self.title_label = QLabel("Secure Cartography")
        self.title_label.setObjectName("heading")
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.title_label.setFixedHeight(28)
        font = self.title_label.font()
        font.setPointSize(17)
        font.setWeight(QFont.Weight.DemiBold)
        self.title_label.setFont(font)
        card_layout.addWidget(self.title_label)

        # Spacer
        card_layout.addSpacing(8)

        # Subtitle
        self.subtitle_label = QLabel("Network Discovery & Topology Mapping")
        self.subtitle_label.setObjectName("subheading")
        self.subtitle_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.subtitle_label.setFixedHeight(20)
        card_layout.addWidget(self.subtitle_label)

        # Spacer before form
        card_layout.addSpacing(28)

        # Password section
        form_container = QWidget()
        form_container.setObjectName("formContainer")
        form_container.setAutoFillBackground(False)
        form_layout = QVBoxLayout(form_container)
        form_layout.setContentsMargins(0, 0, 0, 0)
        form_layout.setSpacing(10)

        self.password_label = QLabel("Master password")
        self.password_label.setObjectName("sectionTitle")
        self.password_label.setFixedHeight(16)
        form_layout.addWidget(self.password_label)

        self.password_input = PasswordInput("Enter vault password")
        self.password_input.setFixedHeight(48)
        form_layout.addWidget(self.password_input)

        # Status message (for errors)
        self.status_label = QLabel("")
        self.status_label.setObjectName("statusError")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setWordWrap(True)
        self.status_label.setFixedHeight(40)
        self.status_label.hide()
        form_layout.addWidget(self.status_label)

        self.form_container = form_container  # Save reference for styling
        card_layout.addWidget(form_container)

        # Spacer before buttons
        card_layout.addSpacing(24)

        # Buttons
        button_container = QWidget()
        button_container.setObjectName("buttonContainer")
        button_layout = QVBoxLayout(button_container)
        button_layout.setContentsMargins(0, 0, 0, 0)
        button_layout.setSpacing(12)

        self.unlock_btn = QPushButton("Unlock Vault")
        self.unlock_btn.setFixedHeight(48)
        self.unlock_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.unlock_btn.clicked.connect(self._on_unlock)
        button_layout.addWidget(self.unlock_btn)

        self.reset_btn = QPushButton("Reset Vault")
        self.reset_btn.setFixedHeight(48)
        self.reset_btn.setObjectName("danger")
        self.reset_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.reset_btn.clicked.connect(self._on_reset)
        button_layout.addWidget(self.reset_btn)

        self.button_container = button_container  # Save reference for styling
        card_layout.addWidget(button_container)

        # Spacer before version
        card_layout.addSpacing(24)

        # Version info
        self.version_label = QLabel(f"v{__version__}")
        self.version_label.setObjectName("muted")
        self.version_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.version_label.setFixedHeight(16)
        card_layout.addWidget(self.version_label)

        # Bottom padding
        card_layout.addSpacing(8)

        main_layout.addWidget(self.card)

        # Connect enter key
        self.password_input.returnPressed.connect(self._on_unlock)

        # Update UI based on vault state
        self._update_for_vault_state()

    def _update_for_vault_state(self):
        """Update UI based on whether vault exists."""
        if self.vault.is_initialized:
            self.unlock_btn.setText("Unlock Vault")
            self.reset_btn.show()
        else:
            self.unlock_btn.setText("Create Vault")
            self.reset_btn.hide()

    def _apply_theme(self):
        """Apply current theme to dialog."""
        theme = self.theme_manager.theme

        bg_hover = theme.bg_hover
        border_dim = theme.border_dim
        border_secondary = theme.border_secondary
        shadow_color = QColor(0, 0, 0, 110 if theme.is_dark else 40)

        # Dialog background is transparent (for the rounded card effect)
        self.setStyleSheet("background-color: transparent;")

        # Card styling - this is the main visible background
        self.card.setStyleSheet(f"""
            QFrame#loginCard {{
                background-color: {theme.bg_secondary};
                border: 1px solid {border_secondary};
                border-radius: 10px;
            }}
        """)

        # Explicitly set all intermediate container backgrounds to transparent
        # These are layout containers that shouldn't have visible backgrounds
        transparent_style = "background-color: transparent; border: none;"
        self.form_container.setStyleSheet(transparent_style)
        self.button_container.setStyleSheet(transparent_style)

        # Add shadow effect
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(40)
        shadow.setXOffset(0)
        shadow.setYOffset(10)
        shadow.setColor(shadow_color)
        self.card.setGraphicsEffect(shadow)

        # Accent line - flat
        self.accent_line.setStyleSheet(f"""
            QFrame#accentLine {{
                background-color: {theme.accent};
                border: none;
                border-radius: 1px;
            }}
        """)
        try:
            fix_all_comboboxes(self,self.theme_manager.theme)
        except Exception as e:
            traceback.print_exc()

        # Update banner for current theme
        self.banner.set_theme(self.theme_manager.theme_name)

        # Labels
        self.title_label.setStyleSheet(f"""
            QLabel#heading {{
                color: {theme.text_primary};
                background: transparent;
                border: none;
            }}
        """)

        self.subtitle_label.setStyleSheet(f"""
            QLabel#subheading {{
                color: {theme.text_secondary};
                background: transparent;
                border: none;
            }}
        """)

        self.password_label.setStyleSheet(f"""
            QLabel#sectionTitle {{
                color: {theme.text_secondary};
                font-size: 12px;
                font-weight: 600;
                background: transparent;
                border: none;
            }}
        """)

        self.status_label.setStyleSheet(f"""
            QLabel#statusError {{
                color: {theme.accent_danger};
                background: transparent;
                border: none;
                padding: 8px;
            }}
        """)

        self.version_label.setStyleSheet(f"""
            QLabel#muted {{
                color: {theme.text_muted};
                background: transparent;
                border: none;
            }}
        """)

        # Password input
        self.password_input.apply_theme(theme)

        # Theme combo box
        self.theme_combo.setStyleSheet(f"""
            QComboBox {{
                background-color: {theme.bg_tertiary};
                border: 1px solid {border_dim};
                border-radius: 6px;
                padding: 6px 12px;
                color: {theme.text_primary};
                font-size: 12px;
            }}
            QComboBox:hover {{
                border-color: {theme.accent};
            }}
            QComboBox::drop-down {{
                border: none;
                width: 20px;
            }}
            QComboBox::down-arrow {{
                image: {qss_glyph('down', theme.text_secondary)};
                width: 10px;
                height: 6px;
                margin-right: 6px;
            }}
            QComboBox QAbstractItemView {{
                background-color: {theme.bg_secondary};
                border: 1px solid {border_dim};
                selection-background-color: {theme.accent};
                selection-color: {theme.bg_primary};
                outline: none;
                padding: 4px;
            }}
            QComboBox QAbstractItemView::item {{
                padding: 6px 12px;
                min-height: 24px;
            }}
            QComboBox QAbstractItemView::item:hover {{
                background-color: {bg_hover};
            }}
        """)

        # Update combobox popup colors for the new theme
        self.theme_combo.set_theme_colors(theme)

        # Buttons
        self.unlock_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {theme.accent};
                color: {theme.text_on_accent};
                border: 1px solid {theme.accent};
                border-radius: 6px;
                padding: 14px 20px;
                font-weight: 600;
                font-size: 13px;
            }}
            QPushButton:hover {{
                background-color: {theme.accent_hover};
                border-color: {theme.accent_hover};
            }}
            QPushButton:pressed {{
                background-color: {theme.accent_pressed};
            }}
        """)

        self.reset_btn.setStyleSheet(f"""
            QPushButton#danger {{
                background-color: transparent;
                color: {theme.accent_danger};
                border: 1px solid {theme.accent_danger};
                border-radius: 6px;
                padding: 14px 20px;
                font-weight: 600;
                font-size: 13px;
            }}
            QPushButton#danger:hover {{
                background-color: {theme.accent_danger};
                color: white;
            }}
        """)

    def _show_error(self, message: str):
        """Show error message."""
        self.status_label.setText(message)
        self.status_label.show()

    def _hide_error(self):
        """Hide error message."""
        self.status_label.hide()

    def _on_unlock(self):
        """Handle unlock/create button click."""
        password = self.password_input.text()

        if not password:
            self._show_error("Please enter a password")
            return

        self._hide_error()

        try:
            if self.vault.is_initialized:
                # Unlock existing vault
                self.vault.unlock(password)
            else:
                # Initialize new vault
                if len(password) < 8:
                    self._show_error("Password must be at least 8 characters")
                    return
                self.vault.initialize(password)

            # Success - emit signal and close
            self.vault_unlocked.emit(self.vault)
            self.accept()

        except Exception as e:
            error_msg = str(e)
            if "Invalid" in error_msg or "password" in error_msg.lower():
                self._show_error("Invalid password")
            else:
                self._show_error(f"Error: {error_msg}")
            self.password_input.clear()
            self.password_input.setFocus()

    def _on_reset(self):
        """Handle reset credentials button click."""
        reply = QMessageBox.warning(
            self,
            "Reset Credentials",
            "This will DELETE all stored credentials.\n\n"
            "This action cannot be undone.\n\n"
            "Are you sure you want to continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            try:
                # Delete vault database
                db_path = self.vault.db_path
                if db_path.exists():
                    db_path.unlink()

                # Also delete salt file if separate
                salt_path = db_path.parent / ".salt"
                if salt_path.exists():
                    salt_path.unlink()

                # Reinitialize vault object
                self.vault = type(self.vault)(db_path)
                self._update_for_vault_state()

                self._show_error("Vault reset. Please create a new password.")
                self.password_input.clear()
                self.password_input.setFocus()

            except Exception as e:
                self._show_error(f"Reset failed: {e}")

    def showEvent(self, event):
        """Focus password input on show."""
        super().showEvent(event)
        self.password_input.setFocus()

    def set_theme(self, theme_name: ThemeName):
        """Change theme and reapply styling."""
        self.theme_manager.set_theme(theme_name)
        self._apply_theme()

    def _on_theme_changed(self, index: int):
        """Handle theme dropdown selection."""
        theme = self.theme_combo.itemData(index)
        if theme:
            # Update theme manager
            self.theme_manager.set_theme(theme)

            # Save to settings
            self.settings.set_theme(theme)

            # Update application-wide stylesheet
            app = QApplication.instance()
            if app:
                app.setStyleSheet(self.theme_manager.stylesheet)

            # Reapply dialog-specific styling
            self._apply_theme()


# =============================================================================
# Mock Vault for Testing
# =============================================================================

class MockVault:
    """
    Mock vault for testing UI without real credentials.
    Password 'testpass' unlocks, anything else fails.
    """

    def __init__(self, db_path: Optional[Path] = None):
        self._initialized = True
        self._unlocked = False
        self.db_path = db_path or APP_DIR / "test_vault.db"

    @property
    def is_initialized(self):
        return self._initialized

    @property
    def is_unlocked(self):
        return self._unlocked

    def initialize(self, password):
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters")
        self._initialized = True
        self._unlocked = True

    def unlock(self, password):
        if password != "testpass":
            raise Exception("Invalid vault password")
        self._unlocked = True
        return True

    def lock(self):
        self._unlocked = False


# =============================================================================
# Standalone testing
# =============================================================================

if __name__ == "__main__":
    import sys

    app = QApplication(sys.argv)

    theme_manager = ThemeManager(ThemeName.DARK)
    vault = MockVault()

    dialog = LoginDialog(vault, theme_manager)

    # Test theme switching
    # dialog.set_theme(ThemeName.DARK)
    # dialog.set_theme(ThemeName.LIGHT)

    if dialog.exec() == QDialog.DialogCode.Accepted:
        print("Vault unlocked successfully!")
    else:
        print("Login cancelled")

    sys.exit()