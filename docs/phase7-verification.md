# Phase 7 release-candidate verification

## Executed checks

| Check | Expected | Actual | Status | Evidence |
| --- | --- | --- | --- | --- |
| Windows source quality | Ruff, mypy, deterministic tests pass | Ruff passed; mypy passed (18 source files); pytest 32 passed, 1 skipped | Pass | Terminal run; skip is Npcap integration test |
| Windows CLI | Help and host inspection execute | Both commands executed from editable environment | Pass | Terminal run |
| Windows Qt startup | Desktop event loop remains active | Offscreen process remained alive 3 seconds and was stopped normally | Pass | Terminal run |
| Windows Npcap | Interfaces and real TCP packets observed | Runtime components absent; no live capture attempted | Blocked | `windows_capture_diagnostics()`; `docs/windows-capture.md` |
| Windows EXE packaging | Current GUI and CLI PyInstaller builds and smoke tests pass | Build succeeded into `dist/phase7`; CLI help and inspect-host passed; GUI stayed alive for 6 seconds and initialized SQLite | Pass (EXE build/smoke) | `dist/phase7/NetPathSentinel.exe`, `dist/phase7/NetPathSentinelCLI.exe` |
| Windows installer build/upgrade | Candidate installer built and upgrades genuine earlier release | Inno Setup compiler unavailable; no genuine prior artifact | Not tested | Phase 6 installer result only covers prior candidate clean install/removal |
| Ubuntu DEB | Current package install/GUI/CLI/remove | 31 passed, 1 Windows-only skip; DEB built, dependencies and metadata inspected, installed; CLI help passed; unprivileged GUI remained alive and created SQLite DB; purge removed system package files | Pass (container userland) | `packaging/verification/ubuntu24.sh`; `dist/packages/netpath-sentinel_0.1.0_amd64.deb` |
| AlmaLinux RPM build ID | No duplicate build ID warning | Single PyInstaller GUI/CLI executable plus text CLI dispatcher; RPM built without `Duplicate build-ids` output | Pass (build) | Container output; `packaging/verification/almalinux9.sh` |
| AlmaLinux RPM install/GUI/CLI/remove | Candidate installs, launches, and removes | 31 passed, 1 Windows-only skip; no duplicate build-ID warning; RPM installed, CLI help passed, unprivileged GUI stayed alive and created SQLite DB, removal succeeded | Pass (container userland) | `packaging/verification/almalinux9.sh`; `dist/packages/netpath-sentinel-0.1.0-1.el9.x86_64.rpm` |
| SBOM | Lock-version inventory with relationships and license metadata | CycloneDX 1.5 generated for 37 locked packages; license metadata present for 33 | Pass (inventory generated) | `dist/sbom.cdx.json` |
| Report privacy | Default exports omit payload/stream content and use private files | Nested redaction and POSIX mode 0600 verified by tests | Pass | `tests/unit/test_report_security.py` |
| Native Ubuntu/AlmaLinux | Desktop, capture, policy checks on native VMs | No native VMs available; container evidence does not cover native desktop/security policy | Not tested | `docs/phase7-release-candidate.md` |
| Previous-version upgrade | Preserve real profile/history and validate migrations | No genuine prior release artifacts available; same-version reinstall not substituted | Not tested | `docs/phase7-release-candidate.md` |

The source suite skips the live Windows integration because Npcap is unavailable.
Container package checks are separate from native OS integration checks. No
live capture, native SELinux verification, previous-release upgrade, signing,
or publication is claimed.

The final Windows source suite is 32 passed, 1 skipped; the Ubuntu and
AlmaLinux image runs each report 31 passed, 1 Windows-only skip (the additional
Linux CLI dispatch test was added after those container test phases). The final
current DEB, RPM, Windows GUI EXE, and Windows CLI EXE are listed in
`dist/SHA256SUMS`; build facts and dirty-tree status are in
`dist/build-metadata.json`. These metadata files are unsigned and the Windows
installer artifact was not rebuilt.

## Platform classification

| Platform | Development verified | Packaging verified | Native integration verified | Controlled pilot | Production-ready | Decision |
| --- | --- | --- | --- | --- | --- | --- |
| Windows 11 x64 | Yes, current source checks | Phase 7 GUI/CLI EXEs rebuilt and smoke-tested; installer not compiled | No; Npcap missing | No | No | **Blocked** pending Npcap, installer, upgrade, and capture acceptance |
| Ubuntu 24.04 x86_64 | Yes in compatible container | Current DEB build/install/CLI/GUI/removal passed | No native VM | No | No | **Conditionally ready for package testing only** |
| AlmaLinux 9 x86_64 | Yes in distro container | Current RPM build/install/CLI/GUI/removal passed with no duplicate build-ID warning | No native VM/SELinux check | No | No | **Conditionally ready for package testing only** |

Commercial distribution is blocked pending licensing review and artifact
notices. See `licensing-and-distribution.md` and
`phase7-release-candidate.md`.
