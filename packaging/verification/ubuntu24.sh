#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y python3 python3-pip python3-dev build-essential dpkg-dev \
  libpcap0.8 libpcap-dev libxkbcommon0 libxkbcommon-x11-0 libegl1 libgl1 \
  libfontconfig1 libfreetype6 libxcb-cursor0 libxcb-icccm4 libxcb-keysyms1 \
  libxcb-shape0 libxcb-xkb1 libxcb-randr0 libxcb-render-util0 libxcb-image0 \
  libxcb-xinerama0 libxcb-shm0 libxcb-sync1 libxcb-util1 libx11-xcb1 \
  libglib2.0-0t64 libdbus-1-3 libgssapi-krb5-2 ca-certificates util-linux coreutils

python3 -m pip install --break-system-packages uv
export UV_PROJECT_ENVIRONMENT=/tmp/netpath-sentinel-venv
uv sync --locked --extra dev
export PYTHON="$UV_PROJECT_ENVIRONMENT/bin/python"
export PATH="$UV_PROJECT_ENVIRONMENT/bin:$PATH"
"$PYTHON" -m ruff check .
"$PYTHON" -m mypy src
"$PYTHON" -m pytest -q -rs
"$PYTHON" -m netpath_sentinel.cli --help
bash packaging/debian/build-deb.sh
dpkg-deb --info dist/packages/netpath-sentinel_0.1.0_amd64.deb
dpkg -i dist/packages/netpath-sentinel_0.1.0_amd64.deb
/usr/bin/netpath-sentinel-cli --help

mkdir -p /tmp/netpath-sentinel-test-data
chown nobody:nogroup /tmp/netpath-sentinel-test-data
mkdir -p /tmp/netpath-runtime-nobody
chown nobody:nogroup /tmp/netpath-runtime-nobody
chmod 0700 /tmp/netpath-runtime-nobody
set +e
runuser -u nobody -- env QT_QPA_PLATFORM=offscreen \
  LANG=C.UTF-8 LC_ALL=C.UTF-8 \
  XDG_RUNTIME_DIR=/tmp/netpath-runtime-nobody \
  NETPATH_SENTINEL_DATA_DIR=/tmp/netpath-sentinel-test-data \
  timeout 8s /usr/bin/netpath-sentinel >/tmp/netpath-sentinel-gui.out \
  2>/tmp/netpath-sentinel-gui.err
gui_status=$?
set -e
test "$gui_status" -eq 124
test -s /tmp/netpath-sentinel-test-data/netpath-sentinel.sqlite3
if grep -Eqi 'Could not load the Qt platform plugin|This application failed to start' \
  /tmp/netpath-sentinel-gui.err; then
  cat /tmp/netpath-sentinel-gui.err >&2
  exit 1
fi

dpkg -P netpath-sentinel
test ! -e /usr/bin/netpath-sentinel
test ! -e /usr/bin/netpath-sentinel-cli
test ! -e /usr/share/applications/netpath-sentinel.desktop
test ! -e /usr/share/icons/hicolor/scalable/apps/netpath-sentinel.svg
echo 'Ubuntu 24.04 package verification passed'
