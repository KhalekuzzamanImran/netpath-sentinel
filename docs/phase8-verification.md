# Phase 8 native platform acceptance

## Preflight

| Capability | Observed result |
| --- | --- |
| Host OS | Windows build 10.0.26300.9711; CPython project environment 3.13.17. A global Python 3.15.1 is present but was not used. |
| Npcap | Version 1.90; service `npcap` running; `npcap.sys`, `wpcap.dll` 1.10.7, and `Packet.dll` present under Windows System32. Runtime was detected during Phase 8; no Npcap installation was performed by this run. |
| Interfaces | Wi-Fi, Ethernet/virtual adapters, and `Loopback Pseudo-Interface 1` enumerated. Loopback maps to `\\Device\\NPF_Loopback`. |
| Capture permission | No elevation: process token is Medium Mandatory Integrity. Npcap successfully opened loopback and captured controlled traffic. |
| Native Linux | No native Linux host/VM found. WSL distro enumeration returned `E_ACCESSDENIED`; no VBoxManage, vmrun, Hyper-V `Get-VM`, or libvirt client was available. Docker engine named pipe access was denied in the sandbox. Phase 7 container results are not counted as native. |
| Installer | Inno Setup compiler (`ISCC`) is unavailable. A prior 0.1.0 setup EXE exists but was not rebuilt from Phase 8 source. |
| Upgrade baseline | No genuine earlier release artifact is available. |

## Acceptance matrix

| Platform | Test | Preconditions | Expected | Actual | Evidence | Status | Blocker |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Windows 11 x64 | Npcap runtime/interface probe | Installed Npcap | Service, DLLs, driver, and adapters reported | Service running; all components and loopback adapter detected | `windows_capture_diagnostics()`; OS files | Passed | None for loopback |
| Windows 11 x64 | Controlled loopback TCP capture | Npcap; local selected free port; medium-integrity process | SYN/SYN-ACK/ACK, payload, live events, persisted session, finding, reports | 9 loopback TCP records from 12:20:08.924197Z to 12:20:08.978088Z; flags included S/SA/A/PA/FA; 19 payload bytes; complete handshake; packet events arrived before completion; `TCP_HANDSHAKE_COMPLETE` finding references evidence `c139ef08-a399-4e22-832b-ff9915194a45`; HTML/JSON reports persisted | `dist/phase8-live-acceptance/test_npcap_loopback_diagnostic0/` | Passed | LAN/second host not tested |
| Windows 11 x64 | Idle live-capture cancellation | Npcap; loopback capture ready | Prompt idempotent stop, partial evidence, final cancellation event | 0.359 s; persisted `incomplete` packet summary; terminal status `cancelled` | `dist/phase8-cancellation-evidence/` (`cancellation-evidence.json`) | Passed | None observed |
| Windows 11 x64 | Qt live UI delivery | Npcap; GUI worker and loopback traffic | Timeline updates before capture finishes; GUI remains responsive; persistence/reporting work | Passed after fixing worker-to-UI cross-thread signal handling; timeline updated during capture, report/finding displayed, worker exited cleanly | `dist/phase8-qt-thread-fix/test_npcap_loopback_events_update_qt_ui_0/` | Passed | Installer rebuild pending |
| Windows 11 x64 | Replay resource limit and malformed input | Synthetic PCAP | Enforce packet cap; incomplete evidence; malformed input produces workflow error | Tests enforce packet cap and mark evidence incomplete; malformed global header fails session cleanly with terminal error | `tests/integration/test_runner_replay.py` | Passed | None |
| Windows 11 x64 | GUI privilege/data/report privacy | Medium-integrity process; private user data | GUI not elevated; payload redaction; private output | Medium integrity confirmed; known test payload was absent from HTML/JSON; SQLite `integrity_check` returned `ok`; POSIX redaction/file-mode tests pass | `tests/unit/test_report_security.py`; loopback evidence DB and reports | Passed | Windows ACL inheritance not independently audited |
| Windows 11 x64 | Current GUI/CLI build smoke | PyInstaller | Build, CLI, and GUI start | Phase 8 PyInstaller build succeeded; CLI help/inspect-host passed; GUI stayed alive six seconds and initialized SQLite. Archive inspection found no Npcap DLL/driver bundled. | `dist/phase8-final/NetPathSentinel.exe`, `NetPathSentinelCLI.exe` | Passed | Inno Setup absent |
| Windows 11 x64 | Installer install/uninstall/upgrade | Inno Setup; genuine older installer for upgrade | Install, launch, CLI, preserve history, uninstall | Not run against Phase 8 candidate | Prior Phase 7 installer evidence only | Blocked | ISCC unavailable; no previous release baseline |
| All platforms | Licensing and SBOM | Locked dependency inventory and complete packaged-binary review | License obligations documented and approved; binary notices complete | Preliminary review records Scapy GPL-2.0-only, Qt LGPL/GPL/commercial alternatives, Inno commercial-license request, and Npcap OEM redistribution requirements. Lock SBOM has 37 packages and license metadata for 33; packaged Qt/bootloader components and notices still need review. No legal clearance issued. | `docs/licensing-and-distribution.md`; `dist/sbom.cdx.json` | Blocked | Authorized legal review and complete binary notices required |
| Ubuntu 24.04 | Native DEB desktop/capture | Native Ubuntu VM/host | Install, GUI, CLI, capture, report, purge | Not run; Phase 7 container package tests do not qualify | WSL denial; `packaging/verification/ubuntu24.sh` is container procedure | Blocked | No native environment available |
| AlmaLinux 9 | Native RPM/SELinux/capture | Native AlmaLinux VM/host | Install, GUI, enforcing SELinux, capture, report, removal | Not run; Phase 7 container package tests do not qualify | `packaging/verification/almalinux9.sh` is container procedure | Blocked | No native environment available |
| LAN | Second-host acceptance | Authorized second host | Incoming connection/refusal, payload, heartbeat, FIN, cancellation | Not run | `docs/windows-capture.md` manual steps | Not tested | No second host confirmed |

The source suite reports **38 passed, 0 skipped** on this Windows host with
Npcap present. Ruff, mypy, compileall, and `git diff --check` pass. The Qt live
acceptance first exposed UI mutation from the worker thread; completion and
failure are now delivered through QObject slots, and the live test verifies the
worker exits after display updates.

## Platform classification

| Platform | Development verified | Packaging verified | Native integration verified | Ready for controlled pilot | Production-ready | Classification |
| --- | --- | --- | --- | --- | --- | --- |
| Windows 11 x64 | Yes | Phase 8 GUI/CLI EXEs rebuilt and smoke-tested; installer not rebuilt | Yes for local loopback with Npcap; LAN pending | No, installer/release approval pending | No | **Blocked** for distributed pilot until current installer and licensing are approved |
| Ubuntu 24.04 | Historical locked/container checks | Phase 7 DEB only; not rebuilt for Phase 8 source | No | No | No | **Blocked** pending native host and current package build |
| AlmaLinux 9 | Historical locked/container checks | Phase 7 RPM only; not rebuilt for Phase 8 source | No | No | No | **Blocked** pending native host, SELinux, and current package build |

Commercial distribution remains blocked on legal review and complete binary
notices. The dependency SBOM is a lock-based inventory; its license metadata is
not proof of binary contents or legal compliance. See
`licensing-and-distribution.md` and `phase7-release-candidate.md`.

## Manual actions required

1. Install Inno Setup 6 on an authorized Windows build host and compile the
   Phase 8 EXEs into a versioned setup package; run clean install and removal.
2. Supply a genuine prior release installer/package and a disposable profile
   before claiming upgrade and migration preservation.
3. Provision native Ubuntu 24.04 and AlmaLinux 9 VMs/hosts. Rebuild Phase 8 DEB
   and RPM from this source, then test desktop integration and capture there;
   keep AlmaLinux SELinux enforcing.
4. Obtain an authorized legal review of Scapy, Qt modules/plugins, notices,
   PyInstaller contents, Npcap distribution rights, and Inno Setup commercial
   terms before commercial release.
5. If LAN coverage is required, run the manual procedure from a second
   authorized host without changing firewall or routing policy.
