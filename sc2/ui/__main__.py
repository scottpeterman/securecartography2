"""
sc2/ui/__main__.py

SecureCartography v2 - UI Entry Point

Application startup with:
- Login dialog for vault unlock
- Main window launch on successful authentication
- Theme persistence
"""
import os
import sys


def _apply_software_gl_guard() -> None:
    """
    Force software rendering for QtWebEngine on ChromeOS/Crostini.

    The container host ships virgl disabled, so Mesa falls back to swrast and
    there is no usable DRM render node. When QtWebEngine attempts GPU
    compositing against that, the EGL init failure takes down the Wayland
    compositor connection instead of degrading - the process dies with no
    Python traceback, because nothing in Python raised.

    Three pieces are needed, and all must land before QApplication is
    constructed (that is when QtWebEngine initialises):
        QT_QPA_PLATFORM=xcb                     -> Xwayland instead of native Wayland
        QTWEBENGINE_CHROMIUM_FLAGS=--disable-gpu -> no GPU compositing in the
                                                    WebEngine subprocess
        AA_ShareOpenGLContexts                  -> set by the caller below

    Scoped to Linux, and only when a container marker is present, so a normal
    desktop with working GPU compositing is untouched. setdefault() is used
    throughout so an explicit override (e.g. QT_QPA_PLATFORM=wayland sc2) still
    wins.

    The xcb platform plugin also needs a package absent from the base container
    image - Qt 6.5+ made it a hard dependency:

        sudo apt install -y libxcb-cursor0
    """
    if not sys.platform.startswith("linux"):
        return

    # Container marker: present on Crostini-style images, absent on a normal desktop.
    if not os.path.exists("/dev/.cros_milestone") and not os.path.exists("/opt/google/cros-containers"):
        return

    os.environ.setdefault("QT_QPA_PLATFORM", "xcb")
    os.environ.setdefault("QTWEBENGINE_CHROMIUM_FLAGS", "--disable-gpu")


_apply_software_gl_guard()

# Remote debugging is opt-in - exporting SC2_WEBENGINE_DEBUG=<port> enables it.
# It was previously pinned on for every run, which leaves a debug listener open.
_webengine_debug_port = os.environ.get("SC2_WEBENGINE_DEBUG")
if _webengine_debug_port:
    os.environ.setdefault("QTWEBENGINE_REMOTE_DEBUGGING", _webengine_debug_port)

from pathlib import Path
from typing import Optional

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QApplication, QDialog

from sc2.ui.themes import ThemeManager, ThemeName
from sc2.ui.settings import SettingsManager, get_settings
from sc2.ui.login import LoginDialog
from sc2.ui.main_window import MainWindow


def run_app():
    """
    Run the Secure Cartography application.

    Flow:
    1. Initialize Qt application
    2. Load settings (including saved theme)
    3. Initialize vault
    4. Show login dialog
    5. On successful unlock, show main window with vault
    """
    # High DPI support
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )

    # Required when QtWebEngine views share the app's GL context. Must be set
    # before QApplication is constructed or WebEngine can abort at init.
    QApplication.setAttribute(Qt.ApplicationAttribute.AA_ShareOpenGLContexts, True)

    app = QApplication(sys.argv)
    # Fusion gives QSS full control of sub-controls (spin/combo arrows,
    # indicators). The native macOS style ignores parts of the stylesheet.
    app.setStyle("Fusion")
    app.setApplicationName("Secure Cartography")
    from sc2 import __version__
    app.setApplicationVersion(__version__)

    # Load settings
    settings = get_settings()
    theme_name = settings.get_theme()

    # Initialize theme manager
    theme_manager = ThemeManager(theme_name)

    # Set application-wide stylesheet
    app.setStyleSheet(theme_manager.stylesheet)

    # Initialize vault
    try:
        from ..scng.creds.vault import CredentialVault
        vault = CredentialVault()
    except ImportError as e:
        print(f"Warning: Could not import CredentialVault: {e}")
        print("Using mock vault for development")
        from .login import MockVault
        vault = MockVault()

    # Show login dialog
    login_dialog = LoginDialog(
        vault=vault,
        theme_manager=theme_manager,
        settings=settings
    )

    # Connect vault unlock to main window launch
    main_window: Optional[MainWindow] = None

    def on_vault_unlocked(unlocked_vault):
        """Handle successful vault unlock."""
        nonlocal main_window

        # Create and show main window - pass settings for theme persistence
        main_window = MainWindow(
            vault=unlocked_vault,
            theme_name=theme_manager.theme_name,
            settings=settings  # FIX: Pass settings so MainWindow can persist theme changes
        )
        main_window.show()

    login_dialog.vault_unlocked.connect(on_vault_unlocked)

    # Run login dialog
    result = login_dialog.exec()

    if result != QDialog.DialogCode.Accepted:
        # User cancelled or closed login
        sys.exit(0)

    # Run main event loop
    sys.exit(app.exec())


def main():
    """Entry point for console_scripts."""
    run_app()


if __name__ == "__main__":
    main()