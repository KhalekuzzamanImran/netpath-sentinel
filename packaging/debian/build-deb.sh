#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERSION="$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$ROOT/pyproject.toml" | tr -d '\r' | head -n 1)"
DIST="$ROOT/dist/linux"
WORK="$ROOT/build/deb"
PACKAGE="$WORK/netpath-sentinel"
PYTHON="${PYTHON:-$(command -v python3.12 || command -v python3)}"

command -v dpkg-deb >/dev/null || { echo "dpkg-deb is required" >&2; exit 2; }
"$PYTHON" -m PyInstaller --noconfirm --clean --onefile --name netpath-sentinel \
  --distpath "$DIST" --workpath "$ROOT/build/pyinstaller-linux" \
  --collect-submodules netpath_sentinel "$ROOT/packaging/gui_main.py"
rm -rf "$PACKAGE"
install -D -m 0755 "$DIST/netpath-sentinel" "$PACKAGE/usr/bin/netpath-sentinel"
install -D -m 0755 "$ROOT/packaging/linux/netpath-sentinel-cli" \
  "$PACKAGE/usr/bin/netpath-sentinel-cli"
install -D -m 0644 "$ROOT/packaging/debian/netpath-sentinel.desktop" \
  "$PACKAGE/usr/share/applications/netpath-sentinel.desktop"
install -D -m 0644 "$ROOT/packaging/debian/netpath-sentinel.svg" \
  "$PACKAGE/usr/share/icons/hicolor/scalable/apps/netpath-sentinel.svg"
install -D -m 0644 "$ROOT/packaging/debian/control" "$PACKAGE/DEBIAN/control"
sed -i "s/^Version: .*/Version: $VERSION/" "$PACKAGE/DEBIAN/control"
mkdir -p "$ROOT/dist/packages"
dpkg-deb --build --root-owner-group "$PACKAGE" \
  "$ROOT/dist/packages/netpath-sentinel_$VERSION""_amd64.deb"
if command -v lintian >/dev/null; then
  lintian "$ROOT/dist/packages/netpath-sentinel_$VERSION""_amd64.deb"
fi
echo "Built dist/packages/netpath-sentinel_$VERSION""_amd64.deb"
