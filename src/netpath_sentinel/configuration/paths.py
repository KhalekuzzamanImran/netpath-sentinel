import os
import sys
import tempfile
from pathlib import Path


def app_data_dir() -> Path:
    override = os.environ.get("NETPATH_SENTINEL_DATA_DIR")
    if override:
        path = Path(override)
        path.mkdir(parents=True, exist_ok=True)
        return path
    if sys.platform == "win32":
        root = Path(os.environ.get("APPDATA", Path.home() / "AppData/Roaming"))
    elif sys.platform == "darwin":
        root = Path.home() / "Library/Application Support"
    else:
        root = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share"))
    path = root / "NetPath Sentinel"
    try:
        path.mkdir(parents=True, exist_ok=True)
        return path
    except OSError:
        fallback = Path(tempfile.gettempdir()) / "NetPath Sentinel"
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback


def capture_dir() -> Path:
    path = app_data_dir() / "captures"
    path.mkdir(parents=True, exist_ok=True)
    return path
