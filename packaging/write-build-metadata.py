"""Write checksums and provenance for explicitly supplied release artifacts."""

from __future__ import annotations

import hashlib
import json
import platform
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path


def main() -> int:
    artifacts = [Path(item) for item in sys.argv[1:]]
    if not artifacts:
        raise SystemExit("usage: write-build-metadata.py ARTIFACT [ARTIFACT ...]")
    root = Path.cwd()
    checksums: list[str] = []
    entries = []
    for artifact in artifacts:
        if not artifact.is_file():
            raise SystemExit(f"artifact not found: {artifact}")
        hasher = hashlib.sha256()
        with artifact.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                hasher.update(chunk)
        digest = hasher.hexdigest()
        checksums.append(f"{digest}  {artifact.as_posix()}")
        entries.append({"path": artifact.as_posix(), "sha256": digest, "size": artifact.stat().st_size})
    (root / "dist/SHA256SUMS").write_text("\n".join(checksums) + "\n", encoding="utf-8")
    try:
        revision = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], text=True, stderr=subprocess.DEVNULL
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        revision = "unavailable"
    try:
        dirty = bool(
            subprocess.check_output(
                ["git", "status", "--porcelain"], text=True, stderr=subprocess.DEVNULL
            ).strip()
        )
    except (OSError, subprocess.CalledProcessError):
        dirty = None
    metadata = {
        "created_utc": datetime.now(UTC).isoformat(),
        "git_revision": revision,
        "working_tree_dirty": dirty,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "artifacts": entries,
    }
    (root / "dist/build-metadata.json").write_text(
        json.dumps(metadata, indent=2) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
