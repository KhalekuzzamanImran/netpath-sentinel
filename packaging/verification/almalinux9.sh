#!/usr/bin/env bash
set -euo pipefail

dnf -y install dnf-plugins-core
dnf config-manager --set-enabled crb
dnf -y install python3.12 python3.12-pip python3.12-devel gcc gcc-c++ make \
  rpm-build libpcap libpcap-devel libxkbcommon libxkbcommon-x11 mesa-libEGL \
  mesa-libGL \
  libX11 libxcb xcb-util-cursor xcb-util-wm xcb-util-keysyms \
  xcb-util-renderutil xcb-util-image fontconfig freetype ca-certificates \
  shadow-utils

python3.12 -m pip install --root-user-action=ignore uv
export UV_PROJECT_ENVIRONMENT=/tmp/netpath-sentinel-venv
uv sync --locked --extra dev
export PYTHON="$UV_PROJECT_ENVIRONMENT/bin/python"
export PATH="$UV_PROJECT_ENVIRONMENT/bin:$PATH"
"$PYTHON" -m ruff check .
"$PYTHON" -m mypy src
"$PYTHON" -m pytest -q -rs
"$PYTHON" -m netpath_sentinel.cli --help
bash packaging/rpm/build-rpm.sh 2>&1 | tee /tmp/netpath-rpm-build.log
if grep -q 'Duplicate build-ids' /tmp/netpath-rpm-build.log; then
  echo 'RPM build contains duplicate ELF build IDs' >&2
  exit 1
fi
rpm_file=$(find dist/packages -maxdepth 1 -name '*.rpm' -print -quit)
test -n "$rpm_file"
rpm -qpi "$rpm_file"
dnf -y install "$rpm_file"
/usr/bin/netpath-sentinel-cli --help
test -x /usr/bin/netpath-sentinel
test -f /usr/share/applications/netpath-sentinel.desktop

mkdir -p /tmp/netpath-sentinel-test-data
id netpath-test >/dev/null 2>&1 || useradd -m netpath-test
chown netpath-test:netpath-test /tmp/netpath-sentinel-test-data
mkdir -p /tmp/netpath-runtime-test
chown netpath-test:netpath-test /tmp/netpath-runtime-test
chmod 0700 /tmp/netpath-runtime-test
set +e
runuser -u netpath-test -- env QT_QPA_PLATFORM=offscreen \
  LANG=C.UTF-8 LC_ALL=C.UTF-8 \
  XDG_RUNTIME_DIR=/tmp/netpath-runtime-test \
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

dnf -y remove netpath-sentinel
test ! -e /usr/bin/netpath-sentinel
test ! -e /usr/bin/netpath-sentinel-cli
test ! -e /usr/share/applications/netpath-sentinel.desktop
test ! -e /usr/share/icons/hicolor/scalable/apps/netpath-sentinel.svg
echo 'AlmaLinux 9 package verification passed'
