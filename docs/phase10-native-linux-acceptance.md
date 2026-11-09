# Phase 10 native Linux acceptance runbook

Use a disposable **native Ubuntu 24.04 or AlmaLinux 9 VM/host** with a normal
desktop login. WSL and containers can validate builds, but do not count as the
native desktop, capture, SELinux, or package-removal acceptance in this runbook.
Keep SELinux enforcing on AlmaLinux and leave firewalld/routing unchanged.
Capture only traffic you are authorized to inspect.

## Record the baseline

Before installation, save these results with the test run:

```bash
uname -a
python3 --version
ip -brief address
ip route
id
```

For Ubuntu, record `lsb_release -a` and `dpkg --print-architecture`. For
AlmaLinux, record `cat /etc/os-release`, `rpm --eval '%{_arch}'`,
`getenforce`, and `systemctl is-active firewalld` (a non-running firewalld
service is an observation, not a reason to enable/disable it).

## Build from the checked-out source

Use CPython 3.13 and the checked-in `uv.lock`. Install only the build tools
required by the platform according to `docs/development-setup.md`. Then run:

```bash
uv sync --locked --python 3.13 --extra dev
uv run --locked ruff check .
uv run --locked mypy src
uv run --locked pytest -q
```

On Ubuntu 24.04, install `dpkg-dev`, `libpcap0.8`, and `libpcap-dev`, then:

```bash
bash packaging/debian/build-deb.sh
dpkg-deb --info dist/packages/netpath-sentinel_0.1.0_amd64.deb
dpkg-deb --contents dist/packages/netpath-sentinel_0.1.0_amd64.deb
sudo apt install ./dist/packages/netpath-sentinel_0.1.0_amd64.deb
netpath-sentinel-cli --help
```

On AlmaLinux 9, install `rpm-build`, `libpcap`, and `libpcap-devel`, then:

```bash
bash packaging/rpm/build-rpm.sh
rpm -qpi dist/packages/netpath-sentinel-0.1.0-1.el9.x86_64.rpm
rpm -qpl dist/packages/netpath-sentinel-0.1.0-1.el9.x86_64.rpm
sudo dnf install ./dist/packages/netpath-sentinel-0.1.0-1.el9.x86_64.rpm
netpath-sentinel-cli --help
getenforce
```

The expected AlmaLinux policy state is `Enforcing` before and after package
installation. Do not set file capabilities or alter SELinux/firewalld as an
implicit test setup step. If capture permission is unavailable, record the
structured permission error and mark native capture blocked pending an
administrator-approved least-privilege configuration.

## Desktop, data, and replay smoke checks

Log into the desktop as an unprivileged test user. Do not run the whole GUI as
root. Start the application from the desktop launcher and from a terminal:

```bash
QT_QPA_PLATFORM=offscreen netpath-sentinel
```

For the terminal smoke, run it under a timeout and record that it initializes
and remains running; the timeout status is expected. Verify the launcher
exists, inspect the process owner, and verify the database is created in the
test user's XDG data directory with mode `0700` directory and `0600` database.
Use a synthetic PCAP to verify replay, evidence persistence, and HTML/JSON
export without requiring capture privileges.

For live capture, select the exact interface returned by `ip -brief address`,
use an authorized local test port and synthetic test payload, then verify
capture readiness, captured TCP records, direction, session state, persistence,
RCA evidence, and reports. Record `getcap` for packaged binaries and the
effective capture permission. Do not use broad host privileges to make a test
pass; permission failure is a valid result and remains a release limitation.

## Remove and verify package cleanup

On Ubuntu:

```bash
sudo apt remove netpath-sentinel
dpkg -l netpath-sentinel
test ! -e /usr/bin/netpath-sentinel
test ! -e /usr/bin/netpath-sentinel-cli
test ! -e /usr/share/applications/netpath-sentinel.desktop
```

On AlmaLinux:

```bash
sudo dnf remove netpath-sentinel
rpm -q netpath-sentinel
test ! -e /usr/bin/netpath-sentinel
test ! -e /usr/bin/netpath-sentinel-cli
test ! -e /usr/share/applications/netpath-sentinel.desktop
getenforce
```

Keep per-user diagnostic history unless the test owner explicitly removes the
disposable test account/data. Record package-manager output and residual file
checks. Do not delete unrelated system files.

## Evidence and current status

Retain OS/version, package hash and metadata, commands/output, launcher result,
CLI result, GUI process owner, `stat` output for data files, libpcap version,
capture-permission result, selected interface/port, packet/evidence references,
report paths, and package removal result. Redact usernames, hostnames, and
addresses before sharing.

Phase 10 host preflight found no native Ubuntu or AlmaLinux distribution. WSL
enumeration exposed only the internal `docker-desktop` distribution, so neither
native procedure has been executed. Existing container results are not native
acceptance evidence.
