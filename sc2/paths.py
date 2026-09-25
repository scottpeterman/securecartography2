"""
sc2/paths.py - where Secure Cartography 2 keeps its per-user data.

Everything user-scoped (credential vault, settings, jump-host config, caches)
lives under APP_DIR, default ~/.seccart2. Override with SECCART2_HOME, e.g.
to keep a separate vault per engagement or to run from a shared jump host.

One-time migration
------------------
Earlier releases (and the original secure-cartography package) used ~/.seccart2.
The first time APP_DIR is needed and does not exist yet, the legacy directory
is COPIED into it - not moved - so an old install still finds its own vault.
After that the two are independent. Nothing is copied when SECCART2_HOME is
set explicitly, or when APP_DIR already exists.
"""

from __future__ import annotations

import logging
import os
import shutil
from pathlib import Path

logger = logging.getLogger(__name__)

LEGACY_DIR = Path.home() / ".scng"
_ENV_OVERRIDE = os.environ.get("SECCART2_HOME")
APP_DIR = Path(_ENV_OVERRIDE).expanduser() if _ENV_OVERRIDE else Path.home() / ".seccart2"

# Well-known files
VAULT_DB = APP_DIR / "credentials.db"
SETTINGS_FILE = APP_DIR / "settings.json"
JUMP_HOSTS_FILE = APP_DIR / "jump_hosts.yaml"
CACHE_DIR = APP_DIR / "cache"

_ensured = False


def ensure_app_dir() -> Path:
    """
    Create APP_DIR, copying the legacy ~/.seccart2 on first use. Idempotent and
    cheap after the first call; safe to call from every entry point.
    """
    global _ensured
    if _ensured:
        return APP_DIR
    _ensured = True

    if not APP_DIR.exists() and not _ENV_OVERRIDE and LEGACY_DIR.is_dir():
        try:
            # Skip regenerable caches; they are rebuilt on demand.
            shutil.copytree(
                LEGACY_DIR, APP_DIR,
                ignore=shutil.ignore_patterns("cache", "__pycache__"),
                copy_function=shutil.copy2,
            )
            logger.info("Copied %s -> %s (legacy settings, vault, jump hosts)", LEGACY_DIR, APP_DIR)
        except Exception as e:  # never block startup on migration
            logger.warning("Could not copy %s to %s: %s", LEGACY_DIR, APP_DIR, e)

    APP_DIR.mkdir(parents=True, exist_ok=True)
    return APP_DIR


# Run once at import so every entry point (GUI, CLIs, library use) sees the
# same directory without having to remember to call it.
ensure_app_dir()
