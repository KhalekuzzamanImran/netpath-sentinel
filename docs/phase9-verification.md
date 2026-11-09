# Phase 9 platform verification

Date: 2026-11-09. This record distinguishes test executions from prior-phase
evidence. `Passed` means the named execution completed in this environment;
`Blocked` means its required host, tool, or authorization was unavailable.

## Capability preflight

| Capability | Current observation |
| --- | --- |
| Host | Windows 11 x64, build `10.0.26300.9711`; project CPython 3.13.17 in `.venv`. |
| Npcap | Runtime diagnostic reports service registered and running, driver and `wpcap.dll` / `Packet.dll` paths present. The three live Windows tests also opened the Npcap loopback adapter. Npcap was not installed by this phase. |
| Interfaces | Npcap lists Wi-Fi at `192.168.70.150`, Hyper-V and virtual adapters, and loopback at `\\Device\\NPF_Loopback`. The live tests used loopback. No LAN peer was identified or probed. |
| Elevation | The Phase 8 acceptance record documents medium-integrity execution; this phase ran the application without requesting elevation. Npcap diagnostic itself reports permission as “not tested”; the live loopback tests confirm permission for that adapter only. |
| Inno Setup | `ISCC.exe` was not found in PATH or the standard Program Files locations. |
| Native Linux | WSL distro listing returns `E_ACCESSDENIED`; native Linux is not available. Docker/RPM/DEB commands are not on this Windows PATH. Earlier container outcomes are not native acceptance. |
| Upgrade baseline | No genuine older installer/package artifact identified. The existing 0.1.0 setup artifact is from an earlier build and does not qualify as an upgrade baseline for this candidate. |

## Acceptance matrix

| Platform | Test | Preconditions | Expected | Actual observations | Evidence | Status | Blocker |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Windows 11 x64 | Ruff, mypy, full pytest | Project `.venv` | All checks pass | Ruff passed; mypy passed on 18 source files; pytest 38 passed, 0 failed, 0 skipped. | Command output in Phase 9 run; tests in `tests/` | Passed | None for this host |
| Windows 11 x64 | Npcap loopback packet capture | Npcap runtime and local listener | SYN/SYN-ACK/ACK, payload, persistence, report | Targeted suite rerun: 3 passed. It covers Npcap packet capture, idle cancellation, and Qt event delivery. Historical Phase 8 evidence records 9 packets, 19 payload bytes, timestamps, SQLite integrity, and HTML/JSON reports. | `tests/integration/test_windows_live_acceptance.py`; `dist/phase8-live-acceptance/`; `dist/phase8-qt-thread-fix/`; `dist/phase8-cancellation-evidence/` | Passed | This is loopback, not LAN |
| Windows 11 x64 | CLI smoke | Candidate executable | Help and host inspection work | `--help` and `inspect-host` both exited successfully. Host inspection lists Wi-Fi `192.168.70.150`; this was not used to contact any peer. | `dist/phase9-candidate/NetPathSentinelCLI.exe` | Passed | None |
| Windows 11 x64 | GUI smoke | Candidate executable, user-level execution | GUI initializes and remains running | Candidate GUI remained running after 5 seconds and created its SQLite data file under `dist/phase9-candidate/smoke-data`; launched process was then stopped. | `dist/phase9-candidate/NetPathSentinel.exe`; `dist/phase9-candidate/smoke-data/netpath-sentinel.sqlite3` | Passed | Not a clean installer test |
| Windows 11 x64 | PyInstaller candidate build | Locked project environment | GUI and CLI executables built | Both built successfully. SHA-256: GUI `0939a7cd254203b3b51165d57e9b680a67bcb729b38f46429ff0ffe4bab3428a`; CLI `84edbf6b93a46d6812bfb13e25755d5759552e951efddad6f521217cec28200d`. | `dist/phase9-candidate/`; `dist/SHA256SUMS`; `dist/build-metadata.json` | Passed | Installer not built |
| Windows 11 x64 | Inno Setup build/install/remove | ISCC and disposable install target | Compile current installer; install, launch, remove | Not run. `ISCC.exe` unavailable. The prior Phase 7 installer result is not evidence for current binaries. | Inno Setup availability probe | Blocked | Install Inno Setup 6 on authorized build host |
| Windows 11 x64 | Installer upgrade | Genuine previous version and disposable data | Preserve profile/history through upgrade and remove | Not run; no valid prior-version baseline is available. | Artifact inventory under `dist/` | Blocked | Supply genuine older release artifact and disposable seeded profile/history |
| Windows 11 x64 | Two-host LAN success/refusal/no-listener/payload/heartbeat/FIN/RST | Authorized peer and selected interface/port | Verify source/destination tuples, flags, state, UI, evidence, RCA, reports | No second authorized host was confirmed. No LAN probes or generated traffic were performed. Executable helper and procedure are prepared. | `tools/lan_acceptance.py`; `docs/phase9-lan-acceptance.md` | Blocked | Authorized peer and operator-provided interface/address/port |
| Ubuntu 24.04 | Native DEB + GUI/CLI/capture | Native Ubuntu 24.04 host/VM | Install, launch, capture, report, uninstall | Not run. Phase 7 container tests are not native evidence. | WSL returns `E_ACCESSDENIED`; prior procedure `packaging/verification/ubuntu24.sh` | Blocked | Provision accessible native Ubuntu 24.04 host/VM |
| AlmaLinux 9 | Native RPM + SELinux enforcing/capture | Native AlmaLinux 9 host/VM | Install, SELinux enforcing, capture, report, remove | Not run. No SELinux/firewalld changes made. Prior container tests do not establish native behavior. | WSL returns `E_ACCESSDENIED`; prior procedure `packaging/verification/almalinux9.sh` | Blocked | Provision accessible native AlmaLinux 9 host/VM |
| All platforms | Licensing / distribution approval | Exact binary inventory and authorized legal review | Approved notices and distribution model | Preliminary obligations remain documented; metadata and SBOM are not legal clearance. | `docs/licensing-and-distribution.md`; `dist/sbom.cdx.json` | Blocked | Legal review of Scapy GPL obligations, Qt terms/notices, Inno Setup commercial use, Npcap rights, bundled components/assets |

## Security observations

- The current executable starts without elevation. Npcap loopback access worked
  for the current user; least-privilege LAN capture permissions still need
  validation on the selected physical adapter and target customer policy.
- The LAN helper outputs packet metadata and byte counts, not payload text; its
  diagnostic config disables payload capture. On POSIX it sets the evidence
  directory to mode `0700`. Windows ACL inheritance is not independently
  audited in this phase.
- The prior report-security tests and Phase 8 acceptance verified redaction.
  The Phase 9 helper's local listener intentionally counts test payload bytes
  and heartbeat lines; use synthetic payloads only.
- Resource limits and malformed PCAP behavior remain covered by the existing
  automated suite. This run did not fuzz untrusted PCAP input or audit installer
  behavior because the installer compiler is unavailable.
- No firewall, routing, SELinux, or privilege settings were changed.

## Release classification

| Platform | Development verified | Packaging verified | Native integration verified | Controlled pilot | Production-ready | Current classification |
| --- | --- | --- | --- | --- | --- | --- |
| Windows 11 | Yes | PyInstaller GUI/CLI candidate verified; current installer not verified | Local Npcap loopback verified; LAN pending | No | No | **Blocked** pending current installer verification, LAN acceptance if required, and release/legal approval |
| Ubuntu 24.04 | Prior container checks only; no native Phase 9 execution | Historical container package only | No | No | No | **Blocked** pending native acceptance |
| AlmaLinux 9 | Prior container checks only; no native Phase 9 execution | Historical container package only | No | No | No | **Blocked** pending native acceptance with SELinux enforcing |

Commercial release remains blocked on licensing review. No platform is
production-ready based on this evidence.

## Manual actions required

1. On the Windows build host, install an appropriately licensed Inno Setup 6,
   build the installer from `dist/phase9-candidate/`, then perform clean install,
   startup, dependency diagnostics, uninstallation, and upgrade only when a
   genuine previous release is supplied.
2. Supply an authorized second host and run the two-host procedure in
   `phase9-lan-acceptance.md`; attach the redacted JSON event log, SQLite
   integrity result, findings, and report paths.
3. Provision native Ubuntu 24.04 and AlmaLinux 9 systems. Build/install/test
   packages there, leave SELinux enforcing and firewalld unchanged, and retain
   command output and package-removal evidence.
4. Obtain legal approval and produce complete platform-specific third-party
   notices from the actual packaged binaries before distribution.
