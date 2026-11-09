#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERSION="$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$ROOT/pyproject.toml" | tr -d '\r' | head -n 1)"
TOP="$ROOT/build/rpmbuild"
DIST="$ROOT/dist/linux"
PYTHON="${PYTHON:-$(command -v python3.12 || command -v python3)}"

command -v rpmbuild >/dev/null || { echo "rpmbuild is required" >&2; exit 2; }
"$PYTHON" -m PyInstaller --noconfirm --clean --onefile --name netpath-sentinel \
  --distpath "$DIST" --workpath "$ROOT/build/pyinstaller-linux" \
  --collect-submodules netpath_sentinel "$ROOT/packaging/gui_main.py"
mkdir -p "$TOP"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS} "$ROOT/dist/packages"
install -m 0755 "$DIST/netpath-sentinel" "$TOP/SOURCES/netpath-sentinel"
install -m 0755 "$ROOT/packaging/linux/netpath-sentinel-cli" \
  "$TOP/SOURCES/netpath-sentinel-cli"
install -m 0644 "$ROOT/packaging/debian/netpath-sentinel.desktop" \
  "$TOP/SOURCES/netpath-sentinel.desktop"
install -m 0644 "$ROOT/packaging/debian/netpath-sentinel.svg" \
  "$TOP/SOURCES/netpath-sentinel.svg"
tr -d '\r' < "$ROOT/packaging/rpm/netpath-sentinel.spec" \
  > "$TOP/SPECS/netpath-sentinel.spec"
sed -i "s/^Version: .*/Version: $VERSION/" "$TOP/SPECS/netpath-sentinel.spec"
rpmbuild -bb --define "_topdir $TOP" "$TOP/SPECS/netpath-sentinel.spec"
find "$TOP/RPMS" -name '*.rpm' -exec cp {} "$ROOT/dist/packages/" \;
echo "Built RPM package(s) in dist/packages"
