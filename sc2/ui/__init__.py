"""
SecureCartography v2 - GUI Package

PyQt6-based graphical interface for network discovery and topology mapping.

Usage:
    from sc2.ui import main
    main()
    
    # Or run as module
    python -m sc2.ui
"""
import os
import sys


from .themes import ThemeManager, ThemeName, ThemeColors, get_theme, THEMES
from .login import LoginDialog, MockVault

__all__ = [
    'ThemeManager',
    'ThemeName', 
    'ThemeColors',
    'get_theme',
    'THEMES',
    'LoginDialog',
    'MockVault',
    'main',
]


def main():
    """Launch the GUI (same entry point as the `seccart2` console script)."""
    from .__main__ import main as _main
    _main()
