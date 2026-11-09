# Phase 6 release verification

## Execution record

Verification host: Windows 11 x64, CPython 3.13.17. Linux package checks run
inside official Ubuntu 24.04 and AlmaLinux 9 containers using `uv sync
--locked`. The containers build and install packages as root but launch the GUI
as an unprivileged account. They do not use host packet capture privileges.

Evidence artifacts are written by the scripts under `dist/packages/`; the
repeatable commands are `packaging/verification/ubuntu24.sh` and
`packaging/verification/almalinux9.sh`. The scripts inspect package metadata,
run tests and CLI checks, start the packaged GUI offscreen, and remove the
package while checking installed files. Docker Desktop uses WSL2 internally;
the host's direct WSL distribution enumeration was denied, but Linux containers
were available through the local Docker engine.

## Verification matrix

| Platform | Scenario | Expected result | Actual result | Status | Evidence |
| --- | --- | --- | --- | --- | --- |
| Windows 11 x64 | Ruff, mypy, pytest | Clean lint/types and passing deterministic suite; native capture may skip without Npcap | 28 passed, 1 skipped; Ruff and mypy passed | Pass (source suite) | Terminal output; `tests/integration/test_windows_live_acceptance.py` |
| Windows 11 x64 | Npcap dependency and interface probe | Detect runtime, interfaces, and missing dependencies accurately | No Npcap service, driver, `wpcap.dll`, or `Packet.dll`; interfaces enumerated. Capture unavailable. | Blocked | `windows_capture_diagnostics()`; unit tests |
| Windows 11 x64 | Loopback capture and LAN capture | Observe TCP handshake/payload, persistence, reports, cleanup | Not run because Npcap is unavailable; no second host was available | Blocked | `docs/windows-capture.md` manual procedure |
| Windows 11 x64 | GUI/CLI build and installer install/remove | Build, launch, install, CLI smoke, and remove cleanly | Prior Phase 5 build/startup/install/uninstall checks passed; unchanged Windows payload/configuration in this phase | Pass (prior artifact) | `dist/installer/NetPathSentinel-Setup-0.1.0-windows-x64.exe` |
| Windows 11 x64 | Installer upgrade | Preserve profile and history, migrations, shortcuts, uninstaller | No older installer artifact or disposable prior profile available in this workspace | Not tested | Upgrade test pending |
| Ubuntu 24.04 x86_64 (Docker Desktop / WSL2 kernel) | Locked tests, DEB build/install, GUI/CLI, removal | Pass tests; satisfy libpcap; launch as ordinary user; remove package files | 28 passed, 1 Windows-only skip; DEB built and metadata checked; dependencies resolved; CLI help passed; GUI remained alive for 8 seconds and created the SQLite DB; purge removed package files | Pass (container userland) | [DEB artifact](../dist/packages/netpath-sentinel_0.1.0_amd64.deb); `packaging/verification/ubuntu24.sh` |
| AlmaLinux 9 x86_64 (Docker Desktop / WSL2 kernel) | Locked tests, RPM build/install, GUI/CLI, removal | Pass tests; satisfy libpcap and Qt libraries; launch as ordinary user; remove files | 28 passed, 1 Windows-only skip; RPM metadata inspected; install succeeded; CLI help passed; GUI remained alive for 8 seconds and created SQLite DB as unprivileged user; removal succeeded | Pass (container userland) | [RPM artifact](../dist/packages/netpath-sentinel-0.1.0-1.el9.x86_64.rpm); `packaging/verification/almalinux9.sh` |

The AlmaLinux run also exposed a CRLF-bearing RPM spec file; the build now
normalizes it before `rpmbuild`. Phase 7 changed Linux packaging to build one
PyInstaller GUI executable and a shell CLI dispatcher, eliminating the
duplicate PyInstaller bootloader ELF that caused duplicate build IDs. The new
RPM needs a clean rebuild/install/removal pass before this resolution is
verified.
The first Ubuntu package attempt exposed CRLF version parsing in the filename;
the build scripts now remove carriage returns and the rerun passed. The first
GUI smoke assertion also rejected a benign Qt offscreen stderr message; the
test now checks for fatal platform-plugin errors while still requiring the GUI
to remain alive and create its database. A pytest cache warning occurs because
the Windows workspace mount is not writable at `.pytest_cache`; it does not
change the test result. Earlier interrupted container attempts are not counted.

## Release decision

- **Windows:** blocked for live capture acceptance until Npcap capture is run
  on a host with Npcap and loopback support. Source and installer smoke checks
  pass, but LAN acceptance and upgrade behavior remain unverified.
- **Ubuntu 24.04:** conditionally ready for package testing and a controlled
  desktop pilot. The DEB passed in a Noble container, but native VM display,
  SELinux-equivalent policy, and privileged live capture have not been tested.
- **AlmaLinux 9:** conditionally ready for package testing and a controlled
  desktop pilot. The RPM passed in an AlmaLinux 9 container, but native VM
  SELinux policy, desktop integration, and privileged live capture remain
  unverified.
- **Commercial distribution:** blocked on review of Scapy's GPL-2.0-only
  inclusion and Qt LGPL/GPL obligations, plus an SBOM/third-party notices. The
  Windows Inno Setup compiler also needs its requested commercial license for
  commercial build use. See [licensing review](licensing-and-distribution.md).

No platform is declared production-ready by this record.
