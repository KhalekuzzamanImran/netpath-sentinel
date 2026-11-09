# Phase 11 verification — Windows route discovery and interface selection

Date: 2026-11-09  
Environment: Windows 11 x64, Python 3.13.17, project `.venv`, Npcap 1.90.

## Root cause and implementation

`HostInspector.routes()` had a Windows implementation branch, but the route collector had not been implemented in the checked-in host inspection code. It returned an empty list on Windows, so the CLI could not distinguish “no routes” from “not collected.” The Linux collector also caught command and parse failures and returned an indistinguishable empty list.

Windows collection now uses `GetIpForwardTable2(AF_UNSPEC)` from IP Helper and always releases the native table with `FreeMibTable`. The domain route preserves destination prefix, gateway, adapter index and name, address family, raw route metric, interface metric, and effective metric. Adapter names and interface metrics are associated by the stable Windows interface index. Collection failures propagate into the snapshot's `route_error`; unsupported operating systems and Linux `ip -j route` failures likewise produce explicit errors. Normal Linux route parsing remains unchanged.

Capture selection continues to resolve Scapy's Npcap network name from adapter GUID/metadata rather than relying on interface list position. Explicit interface resolution does not fall back to a different adapter. Automatic selection uses loopback for loopback targets, otherwise the best matching route/interface metric, and requires explicit selection when ambiguous.

The Windows IP Helper route APIs provide the IPv4 and IPv6 forwarding table and interface-index route fields; see [GetIpForwardTable2](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getipforwardtable2) and [MIB_IPFORWARD_ROW2](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_ipforward_row2).

## Native comparison

The current host's Wi-Fi adapter is interface index 13, address `192.168.70.150`, gateway `192.168.70.1`.

| Source | Result |
| --- | --- |
| NetPath Sentinel IP Helper API | 44 routes: 24 IPv4 and 20 IPv6; `route_error` is null. |
| Installed CLI | Same 44 routes; IPv4 default `0.0.0.0/0` via `192.168.70.1`, Wi-Fi/index 13, route metric 0, interface metric 35, effective metric 35. |
| `route print -4` | Default route via `192.168.70.1`, Wi-Fi address `192.168.70.150`, metric 35; connected `192.168.70.0/24` metric 291. |
| `route print -6` | 20 active IPv6 routes; no IPv6 default route on this host. |
| `Get-NetRoute -PolicyStore ActiveStore` | 24 IPv4 + 20 IPv6. Wi-Fi default route and `192.168.70.0/24` route map to index 13. It reports route metric 0 for default and 256 for the connected route separately from interface metric. |

`Get-NetRoute` returned access denied from the ordinary tool shell; the comparison was repeated successfully in the authorized elevated diagnostic shell. This does not imply the application requires elevation: its IP Helper API collection and installed CLI check both succeeded as the ordinary user. `route print` and the API's effective metrics agree after adding the adapter metric to the route metric.

## Commands and results

Commands run from the repository root:

```powershell
.venv\Scripts\ruff.exe check .
.venv\Scripts\mypy.exe src/netpath_sentinel
.venv\Scripts\python.exe -m pytest -q
.venv\Scripts\python.exe -m compileall -q src tests
.venv\Scripts\python.exe -m PyInstaller packaging/windows/NetPathSentinel.spec --clean --distpath dist/phase11-candidate2
& 'C:\Program Files\Inno Setup 7\ISCC.exe' '--define=BinaryDir=..\..\dist\phase11-candidate2' '--output-dir=dist\phase11-installer2' 'packaging\windows\NetPathSentinel.iss'
```

Results: Ruff passed; mypy passed (20 source files); pytest passed (51 passed, 0 failed, 0 skipped); compileall passed; PyInstaller GUI and CLI builds passed; Inno Setup 7.1.1 compiled the installer successfully.

Installed candidate CLI:

```powershell
dist\phase11-install-test\app2\NetPathSentinelCLI.exe inspect-host
dist\phase11-install-test\app2\NetPathSentinelCLI.exe --help
```

Both commands executed. `inspect-host` returned 44 routes, `route_error: null`, and the expected Wi-Fi default route and metrics. The per-user test installation log is `dist/phase11-install-test/install2.log`.

## Artifact locations and SHA-256

- GUI: `dist/phase11-candidate2/NetPathSentinel.exe`
- CLI: `dist/phase11-candidate2/NetPathSentinelCLI.exe`
- Installer: `dist/phase11-installer2/NetPathSentinel-Setup-0.1.0-windows-x64.exe`
- Build log: `build/NetPathSentinel/`
- Install log: `dist/phase11-install-test/install2.log`

Checksums are recorded in `dist/phase11-installer2/SHA256SUMS.txt`.

## Acceptance matrix

| Check | Status | Evidence / notes |
| --- | --- | --- |
| Windows IPv4 and IPv6 route API | PASS | Host API returned 44 routes (24 IPv4, 20 IPv6); cross-checked with `route print` and `Get-NetRoute`. |
| Route collection failure reporting | PASS | Regression test verifies a failed Windows API call appears as `route_error`; Linux command failure raises instead of returning empty success. |
| Stable adapter mapping and VPN/Hyper-V retention | PASS | Windows route rows map by interface index and retain unmapped indices; runtime enumeration includes active/inactive virtual adapters. Deterministic route mapping tests pass. |
| Installed CLI route discovery | PASS | Installed `app2` CLI returns default Wi-Fi route, gateway, interface index/name, family, and metrics. |
| Automated quality gates | PASS | Ruff, mypy, pytest 51/51, compileall. |
| Windows GUI/CLI fresh build and installer compile | PASS | Artifacts listed above; installer compilation succeeded. |
| Installed GUI startup | PASS | Candidate GUI process opened and responded; Npcap runtime exists on host. |
| Installed GUI live TCP capture, persistence, redacted reports, cancellation/repeat/shutdown | BLOCKED | The installed app window was visible to UI Automation, but Windows foreground activation was denied from the automation session, so the form could not be reliably operated. No installed-GUI traffic was generated and no such success is claimed. In-process live Npcap tests are not a substitute. |
| Installed-app clean uninstall | NOT TESTED | Candidate per-user installation retained at `dist/phase11-install-test/app2` for follow-up acceptance. |
| Authorized two-host LAN test | BLOCKED | No authorized peer is available. |
| Native Linux acceptance | BLOCKED | No native Ubuntu or AlmaLinux host/VM is available. |
| Commercial licensing, genuine upgrade baseline | BLOCKED | Require legal review and a genuine earlier release artifact. |

The GUI acceptance remains an explicit completion blocker. Repeat it from an interactive Windows desktop session: launch the installed GUI unelevated, choose the Npcap loopback adapter explicitly, configure a free local TCP port, start capture, generate a local TCP connection carrying a known payload, then verify timeline events, session/evidence persistence, redacted HTML/JSON export, cancellation, repeated capture, and clean shutdown. Preserve the resulting database, reports, application log, and installer log as acceptance evidence.

Phase 11 is not complete and the product is not classified production-ready. Linux acceptance, LAN acceptance, licensing approval, and real upgrade verification remain blocked as previously scoped.
