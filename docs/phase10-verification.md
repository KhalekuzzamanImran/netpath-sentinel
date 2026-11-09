# Phase 10 environment and acceptance results

Run date: 2026-11-09. Results below come from the current Windows workspace.
Linux container build checks from earlier phases are not counted as native
Linux acceptance.

## Host capability inventory

| Capability | Observed result |
| --- | --- |
| Windows | `cmd /c ver`: 10.0.26300.9711 x64; application host diagnostic identifies Windows 11. `Get-NetAdapter` identifies a Windows 10 Pro product string due legacy Windows reporting. |
| Physical network | Wi-Fi (Intel Dual Band Wireless-AC 8265) is up at `192.168.70.150`, link rate reported 866.7 Mbps. No second authorized host was identified; no scan or connection attempt was made. |
| Other interfaces | Hyper-V `vEthernet (WSL (Hyper-V firewall))` is up at `172.26.64.1`. Fortinet Ethernet and PANGP virtual interfaces are disconnected/disabled. Bluetooth and Wi-Fi Direct interfaces are disconnected/disabled. |
| Virtualization | `HypervisorPresent=True`; host reports HP EliteBook x360 1040 G5. No VirtualBox, VMware, or libvirt VM management commands were found. Hyper-V `Get-VM` was not available. |
| WSL | WSL lists only internal `docker-desktop` distro, state Running, version 2. No Ubuntu 24.04 or AlmaLinux distro. |
| Docker Desktop | Docker Desktop 29.9.2, Linux engine. Existing `dcim-platform-postgres-1` and `dcim-platform-redis-1` containers were running and left untouched. Docker access requires elevation in this workspace. |
| Npcap | Service `npcap` is running. `npcap.sys` 1.90, `wpcap.dll` 1.10.7, `Packet.dll` 1.90. Loopback and Wi-Fi capture adapter mappings are enumerated by the adapter. Npcap was not installed by this phase. |
| Inno Setup | `C:\Program Files\Inno Setup 7\ISCC.exe`, compiler 7.1.1, found. Installer compiler reports “Non-commercial use only”; commercial compiler licensing must be checked before a commercial build. |
| Existing release artifacts | Phase 7/8/9 EXEs, prior installer 0.1.0, DEB, and RPM exist under `dist/`. The DEB/RPM are old container artifacts, not Phase 10/native packages. |

Windows Management Instrumentation and network adapter queries returned
Access Denied in the restricted workspace. The read-only host inventory was
rerun with elevated command access. Docker and WSL API commands also failed in
the restricted workspace and returned the above inventory only with elevated
read access.

## Executed verification

| Platform | Test | Actual result | Evidence | Status |
| --- | --- | --- | --- | --- |
| Windows 11 x64 | Ruff | `All checks passed!` | Command output in Phase 10 run | Passed |
| Windows 11 x64 | mypy | Success, no issues in 18 source files | Command output in Phase 10 run | Passed |
| Windows 11 x64 | pytest | 38 passed, 0 failed, 0 skipped | `tests/` | Passed |
| Windows 11 x64 | Npcap loopback integration | 3 passed: real loopback capture, idle cancellation, Qt live update. Full pytest also passed with no skips. | `tests/integration/test_windows_live_acceptance.py`; detailed Phase 8 packet evidence in `phase8-verification.md` | Passed |
| Windows 11 x64 | CLI | Installed project CLI `--help` and `inspect-host` executed; current installer installed CLI `--help` executed with exit 0. | Command output in Phase 10 run; install log under `dist/phase10-install-test/` | Passed |
| Windows 11 x64 | GUI startup | Installed GUI launched and remained alive during startup check; created 94,208-byte SQLite database in the configured temporary test data path. | `dist/phase10-install-test/`; installation log and SQLite file were observed before uninstallation | Passed, database ACL not audited |
| Windows 11 x64 | Inno Setup build | Compiler 7.1.1 completed successfully and produced `NetPathSentinel-Setup-0.1.0-windows-x64.exe`. Compiled from `dist/phase9-candidate` GUI/CLI files. | `dist/phase10-installer/`; SHA-256 below | Passed |
| Windows 11 x64 | Clean installer install/uninstall | Install used per-user HKCU mode (`User privileges: None` in setup log); installed both executables and Start Menu shortcuts. Uninstall log says `Removed all? Yes`; install files/shortcuts and uninstall registry entry were removed. | `dist/phase10-install-test/install-final.log`; `uninstall-final.log` | Passed |
| Windows 11 x64 | User data after uninstall / ACL | The GUI created its test SQLite database, but the sandbox later denied read access to the test data folder. Preservation and child-directory ACL could not be verified. The actual default `%APPDATA%\NetPath Sentinel` did not exist before this run; `%APPDATA%` parent ACL grants the user, SYSTEM, and Administrators full access and sandbox group read/execute. | `icacls %APPDATA%`; test directory ACL probe returned Access Denied | Blocked |
| Windows 11 x64 | LAN acceptance | No authorized peer was confirmed, so no traffic was generated. | `phase9-lan-acceptance.md` | Blocked |
| Windows 11 x64 | Upgrade | Old on-disk installer is also version 0.1.0; no genuine prior-version upgrade was claimed or tested. | `dist/installer/NetPathSentinel-Setup-0.1.0-windows-x64.exe` | Blocked |
| Ubuntu 24.04 | Native package/desktop/capture | No Ubuntu WSL distro or native VM. Not run. | WSL inventory | Blocked |
| AlmaLinux 9 | Native package/desktop/capture/SELinux | No native environment. Not run; SELinux/firewalld unchanged. | Host/VM tool inventory | Blocked |

## Windows installer artifact

Built installer:

```text
dist/phase10-installer/NetPathSentinel-Setup-0.1.0-windows-x64.exe
SHA-256 1fb9beb8f4efecbceacf8956580cf081206abf83f2810fc6f7a9d601644dfd53
```

The build uses `BinaryDir` in `packaging/windows/NetPathSentinel.iss`; default
remains `dist`, and the Phase 10 build passed `--define=BinaryDir=..\..\dist\phase9-candidate`
to avoid replacing executables held open by previous GUI processes. Checksums
and build metadata are in `dist/SHA256SUMS` and `dist/build-metadata.json`.

The test installer was explicitly non-elevated and created its test
installation directory under `dist/phase10-install-test/app`. Npcap is not
bundled. The host capture diagnostics and current three native capture tests
confirmed the installed runtime is available, but a separate installed-GUI
interface-selection capture was not run. The previous 0.1.0 installer is not a
valid version upgrade baseline for the current 0.1.0 candidate.

## Security review

- GUI does not request elevation. Installer declares `PrivilegesRequired=lowest`;
  the successful test log confirms a per-user HKCU install.
- Windows capture access is provided by separately installed Npcap. Host
  runtime detection and loopback live capture pass; physical Wi-Fi capture
  permission was not exercised because no peer was available.
- Default application data path is `%APPDATA%\NetPath Sentinel`. It inherits
  Windows ACLs from the profile's Roaming directory; the target directory did
  not exist at preflight. The smoke test used an explicit workspace override,
  whose ACL was not inspectable due sandbox access restrictions.
- Existing tests cover payload redaction, bounded payload preview, and POSIX
  directory/file modes. Installer payload includes only the application GUI
  and CLI; it does not bundle Npcap.
- The uninstaller preserved only items outside its install tree by design; the
  test data file was inaccessible after the test and its post-uninstall state
  is not claimed.
- No firewall, route, adapter, Npcap, or virtualization settings changed.

## Native Linux procedure and release decision

Repeatable build/install/test/remove instructions for genuine Ubuntu 24.04 and
AlmaLinux 9 hosts are in [phase10-native-linux-acceptance.md](phase10-native-linux-acceptance.md).
Neither environment was provisioned or tested in Phase 10. Container results
remain historical build/package checks only.

| Platform | Development | Packaging | Native capture | Controlled pilot | Production |
| --- | --- | --- | --- | --- | --- |
| Windows 11 | Verified | Current installer build/install/uninstall passed | Loopback verified; LAN and physical adapter pending | Blocked | Not ready |
| Ubuntu 24.04 | Prior container only | Historical container package only | Not tested | Blocked | Not ready |
| AlmaLinux 9 | Prior container only | Historical container package only | Not tested; SELinux not tested | Blocked | Not ready |

Release recommendation: keep the release blocked pending authorized LAN
acceptance, native Ubuntu and AlmaLinux acceptance, a genuine upgrade baseline,
post-install user data ACL/persistence verification, and the required
commercial licensing review.
