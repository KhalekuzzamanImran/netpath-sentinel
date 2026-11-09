# Release readiness

## Verified on this workspace

- Source tree and packaging configuration created.
- Linux host inspection implementation is present.
- Unit/integration tests are included.
- Native Qt shell is implemented.
- Replay-mode diagnostics execute through the workflow, stream packet events into the Qt details view, persist results, and export reports.
- Windows development environment provisioned with CPython 3.13, uv.lock, and an editable .venv install.
- Ruff, mypy, pytest, CLI smoke checks, PySide6/Scapy imports, and offscreen Qt window startup pass.
- Simulated live capture verifies packet delivery before capture stops, partial persistence on cancellation, and idle cancellation without a leaked worker.
- Live capture uses a bounded event queue and reports internal queue drops in packet-summary evidence.
- Windows Npcap diagnostics and a marked native loopback acceptance test are available. The test reports a clear skip when Npcap is absent.
- Linux RPM now uses one PyInstaller executable for the GUI and CLI, routed by a shell dispatcher, to eliminate duplicate bootloader ELF build IDs.
- Report exports recursively redact raw payload and stream fields by default; POSIX report files use mode 0600 and user data directories mode 0700. The shared temporary-directory fallback was removed.
- CycloneDX inventory and artifact checksum/build metadata generators are available; package license metadata remains subject to manual review.
- Phase 7 Windows GUI and CLI executables rebuilt into `dist/phase7`; CLI help/inspect-host and offscreen GUI startup/database creation passed. Inno Setup is unavailable, so this is not a refreshed installer.
- Phase 8 native Windows Npcap loopback acceptance passed unelevated: handshake, 19-byte test payload, incremental UI events, persistence, RCA, reports, and 0.359-second idle cancellation are recorded in [Phase 8 verification](phase8-verification.md).
- Phase 8 UI acceptance found and fixed worker-thread widget mutation by routing results through QObject slots. The full current Windows suite passes with Npcap active.
- Replay now enforces `max_packets`, marks capped evidence incomplete, and tests malformed PCAP failure handling.
- Phase 9 Windows GUI/CLI candidate executables rebuilt and smoke-tested in `dist/phase9-candidate`; its installer compiler probe did not search Inno Setup 7's installed path, and no Phase 9 installer was built.
- Phase 9 full Windows suite passed: 38 passed, 0 skipped; the targeted native Windows Npcap suite passed 3 tests, including loopback streaming, idle cancellation, and live Qt delivery.
- Phase 9 includes an explicit two-host test helper and procedure. No authorized peer was confirmed; no LAN traffic was generated. See [Phase 9 LAN acceptance](phase9-lan-acceptance.md) and [Phase 9 verification](phase9-verification.md).
- Phase 10 found Inno Setup 7.1.1, built `dist/phase10-installer/NetPathSentinel-Setup-0.1.0-windows-x64.exe` from the current GUI/CLI candidates, then verified per-user clean install, CLI help, GUI startup/database creation, and uninstall cleanup. See [Phase 10 verification](phase10-verification.md).
- Phase 10 reran Ruff and mypy successfully, full pytest 38 passed/0 skipped, and Npcap-specific tests 3 passed. Native physical-adapter LAN capture remains pending.
- Ubuntu 24.04 DEB and AlmaLinux 9 RPM built and passed package metadata, install, CLI, unprivileged offscreen GUI/database, and removal checks in distro containers. Native VM desktop integration, SELinux policy, and live capture remain unverified; see [Phase 6 verification](phase6-verification.md).
- The final Windows Inno Setup installer compiled, passed a clean per-user install, installed CLI `--help`, and uninstall checks. The verification installation was removed.
- The final packaged Windows GUI remained running through an 8-second offscreen startup check and created its SQLite database in the configured user data directory.
- The packaged CLI `--help` and `inspect-host` commands executed successfully on Windows 11 x64.
- Session history can reopen persisted packet timelines and findings.
- Windows installer and DEB/RPM build definitions are present.

## Pending verification

- Genuine prior-version installer upgrade; the available earlier installer is also version 0.1.0 and is not a valid upgrade baseline.
- Post-install application data ACL and data preservation after uninstall; sandbox access restrictions prevented reading the test data folder after the GUI smoke.
- Native Ubuntu 24.04 and AlmaLinux 9 VM installation/desktop checks.
- Rebuild current Linux packages after Phase 8 source changes; Phase 7 DEB/RPM artifacts do not contain the new replay limit and UI thread fix.
- No authorized second host was confirmed for LAN acceptance.
- WSL distribution enumeration is denied, VM management tooling is unavailable, and Docker named-pipe access is denied in this sandbox. Native Linux verification is blocked.
- PCAP fixtures for all acceptance scenarios beyond the synthetic handshake/payload fixture.

Commercial redistribution remains blocked pending Scapy GPL and Qt obligations review, complete binary notices/SBOM review, and confirmation of the applicable Inno Setup commercial license. The installed compiler identifies itself as non-commercial use only. No platform is declared production-ready. See [Phase 10 evidence](phase10-verification.md) for current capture, installer, and platform status.
