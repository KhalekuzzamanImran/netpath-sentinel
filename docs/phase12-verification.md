# Phase 12 verification

## Scope

Phase 12 updates the PySide6 diagnostic experience, structured workflow findings, TCP state accounting, and executive/technical exports. It also refreshes host inspection pages when opened and adds packaging-version consistency checks. This is a Windows development-host verification record, not a production release approval.

## Implementation summary

- The desktop shell now has consistent navigation, persisted light/dark styling, status cards, a guided diagnostic wizard, searchable/sortable session and packet views, expandable diagnostic steps, a bidirectional TCP flow view, and report links. Host inspection pages refresh on navigation so their contents do not remain frozen at window construction.
- Workflow steps and findings carry status, timestamps, evidence references, confidence, limitations, verification guidance, and next actions. RCA avoids attributing missing responses to an unobserved firewall or other intermediary.
- TCP analysis preserves the handshake result separately from observed closure state, records FIN observations by direction, and counts duplicate ACKs only when unacknowledged outbound data exists. Retransmissions are counted once and retained sequence tracking is bounded.
- Reports include executive and technical self-contained HTML plus structured JSON. Export checks the output files before saving report references, and sensitive payload fields remain redacted.
- The GUI obtains session persistence/history through worker threads; live packet events are consumed through Qt signals/timer processing. Cancellation and shutdown paths are covered by tests.

## Environment and commands

- Host: Windows 11 x64, build `10.0.26300`; Python `3.13.17` in `.venv`.
- Npcap: version `1.90` was available for the live loopback integration run. No LAN peer was available.
- Inno Setup: `7.1.1`.
- Candidate version: `0.1.0` across package metadata, CLI, GUI and installer.

Commands executed:

```powershell
.venv\Scripts\ruff.exe check .
.venv\Scripts\mypy.exe src
.venv\Scripts\python.exe -m compileall -q src tests
.venv\Scripts\python.exe -m pytest -q
.venv\Scripts\python.exe -m PyInstaller packaging/windows/NetPathSentinel.spec --clean --distpath dist/phase12-candidate
& 'C:\Program Files\Inno Setup 7\ISCC.exe' '--define=BinaryDir=..\..\dist\phase12-candidate' '--output-dir=dist\phase12-installer' 'packaging\windows\NetPathSentinel.iss'
```

Results: Ruff passed; mypy passed with no issues in 20 source files; compilation passed; pytest passed **61 tests, 0 failed, 0 skipped**. PyInstaller built the GUI and CLI executables. Inno Setup compiled the installer successfully.

## Acceptance matrix

| Platform/scenario | Expected | Actual | Status | Evidence |
|---|---|---|---|---|
| Windows quality gates | Lint, typing, compile, tests pass | Ruff and mypy clean; compile clean; 61 pytest passed | Passed | Commands above; test files under `tests/` |
| Windows simulated/replay desktop workflows | UI remains responsive and regression suite passes | Dashboard, route refresh, session details, report and workflow tests passed | Passed | `tests/desktop/test_ui.py`, `tests/integration/test_runner_replay.py` |
| Windows Npcap loopback in Qt test process | Live packet events, session/evidence persistence, redacted reports, cleanup | Controlled local TCP payload was observed; packet events arrived during capture; handshake finding, DB records, report paths and redaction assertions passed | Passed | `tests/integration/test_windows_live_acceptance.py::test_npcap_loopback_events_update_qt_ui_while_capture_is_running`; test runner output |
| Windows GUI visual review | Layout and key labels readable | Dashboard screenshot rendered and reviewed | Passed | [`phase12-dashboard.png`](../dist/phase12-dashboard.png) |
| Fresh packaged CLI | Executable starts and identifies build | `NetPathSentinelCLI.exe --version` returned `netpath-sentinel 0.1.0` | Passed | `dist/phase12-candidate/NetPathSentinelCLI.exe` |
| Installed packaged CLI routing | Installed command reports IPv4 and IPv6 routes | Installed CLI returned 44 routes: 24 IPv4, 20 IPv6; `route print` showed both route families | Passed | `dist/phase12-installed/NetPathSentinelCLI.exe`; command output recorded during this run |
| Windows route cross-check | Compare with native route tools | `route print` available and listed both families. `Get-NetRoute` was denied by the execution context (`HRESULT 0x80041003`), so exact row-by-row PowerShell comparison could not be completed | Blocked | Execution output; no route-table data altered |
| Installer compile | Current GUI/CLI included in installer | Successful Inno Setup 7.1.1 compile | Passed | [`NetPathSentinel-Setup-0.1.0-windows-x64.exe`](../dist/phase12-installer/NetPathSentinel-Setup-0.1.0-windows-x64.exe) |
| Disposable per-user install | Files install and app can start | Installation created GUI, CLI and uninstaller in `dist/phase12-installed`; installed GUI process remained responsive on launch and was closed | Passed, startup only | `dist/phase12-installed/`; `dist/phase12-install-elevated.log` |
| Installed GUI live capture and report export | Installed GUI captures loopback, displays events and exports reports | Not exercised end-to-end from the installed GUI. The passing Npcap test launches the application in-process and does not prove frozen executable capture/UI behavior | Not tested | Requires interactive installed-GUI acceptance |
| Two-host LAN | Real peer cases | No authorized second host available | Blocked | Manual LAN acceptance remains required |
| Native Ubuntu / AlmaLinux | Native package and capture acceptance | No native Linux host/VM available in this work session | Blocked | Container results from earlier phases are not native acceptance |
| Upgrade preservation | Upgrade older genuine release and retain data | No genuine older release baseline exercised in this pass | Not tested | Previous Phase 11/earlier upgrade remains pending |
| Commercial distribution review | Legal terms cleared | Not performed by legal counsel; Inno compiler reports “Non-commercial use only” | Blocked | Obtain authorized licensing review; see existing licensing/SBOM materials |

## Host route observation and GUI refresh behavior

The installed CLI was run directly from the disposable install directory. It returned 44 route records (24 IPv4 and 20 IPv6); the native `route print` command showed both families. The `Get-NetRoute` cmdlet was inaccessible in this execution context, so route normalization was not compared row-by-row against that cmdlet here.

The GUI routing page is populated into a text widget during construction. Previously the inspection text could remain stale after host state changed. Navigation now refreshes interface, route, and listener pages from a fresh `HostInspector.snapshot()`. A regression test verifies the routing page refreshes when selected. This resolves the UI refresh defect; it does not claim a full native API row comparison.

## Artifacts and checksums

Fresh outputs are kept under a Phase 12-specific directory so prior release artifacts remain intact:

- GUI: `dist/phase12-candidate/NetPathSentinel.exe`
- CLI: `dist/phase12-candidate/NetPathSentinelCLI.exe`
- Installer: `dist/phase12-installer/NetPathSentinel-Setup-0.1.0-windows-x64.exe`
- Disposable installation: `dist/phase12-installed/`

SHA-256:

| Artifact | SHA-256 |
|---|---|
| GUI | `A1B773A056CED4A4286628665E044F28CBE5CF019195CA8724DBD2CAF9CD3283` |
| CLI | `33D597B798E982FE083DEE8FC4849879CBF0E7A7B66B5E5178063B5C67EBF060` |
| Installer | `5FCFC1417A9CCC5FE09F0CB8424D82C69368F492D044621DCDDBA255E5D2334F` |

## Remaining actions and release decision

Windows development verification and packaging are successful. Native Npcap loopback was verified through the Qt integration test, but the installed executable's capture path remains unverified. The GUI startup process launched and responded, which is not equivalent to the requested installed-GUI capture/report acceptance.

Before a controlled pilot, run an interactive installed-GUI loopback capture and report export, row-compare routes against an unrestricted `Get-NetRoute`, verify an actual upgrade from a genuine prior release, and perform LAN acceptance with an authorized peer. Native Ubuntu 24.04 and AlmaLinux 9 acceptance, commercial licensing clearance, and the prior-release upgrade test remain outstanding. **NetPath Sentinel is not production-ready.**
