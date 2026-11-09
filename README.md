# NetPath Sentinel

NetPath Sentinel is a cross-platform, evidence-driven TCP connectivity diagnostic and monitoring desktop application. It inspects the local host, captures authorized traffic, tracks TCP sessions, evaluates payload freshness, and produces explainable findings with evidence references.

## Current implementation

The repository contains an end-to-end diagnostic vertical slice: domain models, OS-backed Linux inspection, TCP packet/session analysis, classic-PCAP replay without host-interface initialization, bounded live capture integration, heartbeat evaluation, SQLite persistence for workflow/packet/session/evidence/RCA/report data, asynchronous worker-driven Qt execution, deterministic RCA, HTML/JSON reporting, and a native PySide6 session-details UI. Platform adapters and packaging definitions are included for Windows and RPM/DEB Linux builds; those artifacts must be built on their native CI runners.

## Development

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
pytest
ruff check .
mypy src
python -m netpath_sentinel.cli inspect-host
python -m netpath_sentinel.main
```

Packet capture requires an installed libpcap-compatible backend and appropriate permissions. The application never changes firewall rules, routes, or existing listeners automatically. Npcap is required on Windows and is not bundled by this project.

## Limitations

The current host is Ubuntu 26.04, so Windows/Npcap and AlmaLinux/RPM execution verification remain pending. See `docs/release-readiness.md` and `docs/architecture.md`.

## License

MIT. See `LICENSE`.
