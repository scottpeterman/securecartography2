"""Secure Cartography 2 - network discovery and topology mapping."""

__version__ = "1.0.0"

import os
import sys

# Must be set before ANY PyQt6 WebEngine imports
os.environ.setdefault("QTWEBENGINE_CHROMIUM_FLAGS", "--disable-gpu")