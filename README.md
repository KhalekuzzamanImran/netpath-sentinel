# NetPath Sentinel

NetPath Sentinel is a cross-platform, evidence-driven TCP connectivity diagnostic and monitoring desktop application. It inspects the local host, captures authorized traffic, tracks TCP sessions, evaluates payload freshness, and produces explainable findings with evidence references.

## Current implementation

The repository contains an end-to-end diagnostic vertical slice: domain models, OS-backed Linux inspection, TCP packet/session analysis, classic-PCAP replay without host-interface initialization, bounded live capture integration, heartbeat evaluation, SQLite persistence for workflow/packet/session/evidence/RCA/report data, asynchronous worker-driven Qt execution, deterministic RCA, HTML/JSON reporting, and a native PySide6 session-details UI. Platform adapters and packaging definitions are included for Windows and RPM/DEB Linux builds; those artifacts must be built on their native CI runners.

## Development

Use CPython 3.12 through 3.14 and uv to install the locked development environment:

```bash
uv python install 3.13
uv sync --python 3.13 --extra dev
uv run pytest -q
uv run ruff check .
uv run mypy src
uv run netpath-sentinel inspect-host
```

Platform-specific Windows, Ubuntu, and AlmaLinux instructions and troubleshooting
are in [docs/development-setup.md](docs/development-setup.md).
Native Windows capture setup and the Npcap loopback/LAN acceptance procedure are
in [docs/windows-capture.md](docs/windows-capture.md). Phase 6 status is tracked in [docs/phase6-verification.md](docs/phase6-verification.md).
Dependency redistribution obligations are summarized in [docs/licensing-and-distribution.md](docs/licensing-and-distribution.md).
Privilege and payload-retention boundaries are described in
[docs/privileges-and-privacy.md](docs/privileges-and-privacy.md).

Live packets are normalized in the capture worker and passed through a bounded
queue to the analyzer while capture is active. Queue overflow is counted in the
packet-summary evidence. Packet events and connection state updates are sent to
the bounded Qt display queue as they are analyzed. Packet capture requires a supported
capture backend and appropriate permissions. The application never changes
firewall rules, routes, or existing listeners automatically. Npcap is required
on Windows and is not bundled by this project.

## Limitations

The current verification host is Windows 11 x64 with Npcap available. Windows
loopback capture and a Phase 10 installer clean install/uninstall are verified;
authorized second-host LAN acceptance and native Ubuntu/AlmaLinux acceptance
remain pending. See [docs/phase10-verification.md](docs/phase10-verification.md).

## License

MIT. See `LICENSE`.
