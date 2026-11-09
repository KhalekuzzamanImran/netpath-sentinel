# Phase 7 release candidate procedures

## Current known blockers

- No genuine previous-version installer/package artifact is present, so upgrade
  preservation has not been tested. Do not label a same-version reinstall as an
  upgrade. Obtain and record a real prior artifact before running the upgrade
  procedure.
- Npcap is absent on the available Windows host. Obtain it from the [official
  Npcap download page](https://npcap.com/#download); review its separate license
  before installation or redistribution. Restart the app and rerun
  `tests/integration/test_windows_live_acceptance.py` after installing it.
- Ubuntu and AlmaLinux have been checked in distro containers, not native VMs.
  Native GUI integration, host capture permissions, and AlmaLinux SELinux
  behavior remain pending.
- Scapy/Qt redistribution terms require a legal/compliance decision. See
  `licensing-and-distribution.md`.

## Windows Npcap acceptance

On an authorized Windows 11 test host, record OS build, architecture, Npcap
version, service state, driver/DLL locations, interface diagnostics, and the
selected adapter. Use Npcap's loopback adapter for loopback; an Ethernet or Wi-Fi
adapter does not imply loopback visibility. Run the marked live test with the
project environment, then use the desktop UI to capture on an explicitly chosen
adapter and test port. Generate a loopback TCP connect, send a unique harmless
payload, close the connection, and stop the session. Confirm SYN/SYN-ACK/ACK,
payload length, timestamps, evidence IDs, UI updates before stop, persisted
session, exported JSON/HTML, and cancellation cleanup. Record socket-level
listener/client results separately from packet observations. Never infer
packet evidence from socket success.

For LAN acceptance, repeat from a second authorized host and record both
addresses. Test a listening port, a known closed port, payload and heartbeat,
FIN, and cancellation. Do not alter host firewalls or routes.

## Native Ubuntu 24.04 and AlmaLinux 9 acceptance

On disposable native VMs, install the matching artifact from `dist/packages/`.
Record OS/kernel and package manager output. As the ordinary desktop account,
launch the desktop file, check CLI `--help` and `inspect-host`, verify the user
data directory and SQLite file owner/mode, and export a replay diagnostic
report. Confirm libpcap is installed and interfaces enumerate. For capture,
use an authorized test port and grant only the platform's documented capture
access; do not launch the whole UI as root. On AlmaLinux, leave SELinux
enforcing and firewalld unchanged; collect `getenforce`, AVC denials, and
firewalld state. Perform any capture policy adjustment only through the host
administrator's approved process. Remove the package and record residual user
data separately from system package files.

Container procedures remain useful package smoke tests but cannot satisfy
native display-server, host security policy, or live-capture acceptance.

## Upgrade acceptance

Use an authentic prior-version artifact and a disposable OS profile. Install
the prior artifact; launch once; create a diagnostic session and retain its
database/profile. Install the candidate over it using the platform's normal
upgrade path. Verify app and CLI startup, schema/table availability, original
session/profile rows, new diagnostic persistence and report export, desktop
shortcut uniqueness, and uninstallation. Preserve test logs and database
before/after hashes. A synthetic schema fixture can validate migration code,
but cannot stand in for upgrade testing against a genuine prior release.

## Release evidence generation

After `uv sync --locked --extra dev`, run:

```sh
python packaging/generate-sbom.py uv.lock dist/sbom.cdx.json
python packaging/write-build-metadata.py dist/installer/NetPathSentinel-Setup-0.1.0-windows-x64.exe dist/packages/netpath-sentinel_0.1.0_amd64.deb dist/packages/netpath-sentinel-0.1.0-1.el9.x86_64.rpm
```

Only include artifacts that exist. Metadata records local build time, platform,
Python version, git revision, sizes, and SHA-256. It is not a signed provenance
statement. Do not publish or sign artifacts without release approval and
authorized credentials.
