import os
import sys
from pathlib import Path


def app_data_dir() -> Path:
    override = os.environ.get("NETPATH_SENTINEL_DATA_DIR")
    if override:
        return _private_dir(Path(override))
    if sys.platform == "win32":
        root = Path(os.environ.get("APPDATA", Path.home() / "AppData/Roaming"))
    elif sys.platform == "darwin":
        root = Path.home() / "Library/Application Support"
    else:
        root = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share"))
    return _private_dir(root / "NetPath Sentinel")


def _private_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != "nt":
        path.chmod(0o700)
    return path


def capture_dir() -> Path:
    path = app_data_dir() / "captures"
    path.mkdir(parents=True, exist_ok=True)
    return path
