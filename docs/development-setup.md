# Development setup and troubleshooting

## Supported interpreter

Use CPython 3.12, 3.13, or 3.14. The project rejects 3.15 and newer in
pyproject.toml. uv.lock pins the resolved dependency set for repeatable
development installs. The application is installed in editable mode.

## Windows 11

Install uv (or use the existing uv executable), then run these commands from
the repository root in PowerShell:

    winget install --id astral-sh.uv -e
    uv python install 3.13
    uv sync --python 3.13 --extra dev
    .\.venv\Scripts\python.exe -m pytest -q
    .\.venv\Scripts\ruff.exe check .
    .\.venv\Scripts\mypy.exe src
    .\.venv\Scripts\netpath-sentinel.exe --help

For an offscreen Qt startup check:

    $env:QT_QPA_PLATFORM = "offscreen"
    .\.venv\Scripts\python.exe -c "from PySide6.QtWidgets import QApplication; from netpath_sentinel.presentation.desktop.app import MainWindow; app=QApplication([]); window=MainWindow(); print(window.windowTitle()); window.close()"

Npcap is required for live capture on Windows. Synthetic tests and PCAP replay
do not need Npcap or administrator privileges.

## Ubuntu

Install uv using the official installer, then create the locked development
environment:

    curl -LsSf https://astral.sh/uv/install.sh | sh
    uv python install 3.13
    uv sync --python 3.13 --extra dev
    .venv/bin/python -m pytest -q
    .venv/bin/ruff check .
    .venv/bin/mypy src
    .venv/bin/netpath-sentinel --help
    QT_QPA_PLATFORM=offscreen .venv/bin/python -c 'from PySide6.QtWidgets import QApplication; from netpath_sentinel.presentation.desktop.app import MainWindow; app=QApplication([]); window=MainWindow(); print(window.windowTitle()); window.close()'

## AlmaLinux

Install curl and platform build tools, install uv, and run the same locked
environment commands:

    sudo dnf install -y curl gcc gcc-c++ make
    curl -LsSf https://astral.sh/uv/install.sh | sh
    uv python install 3.13
    uv sync --python 3.13 --extra dev
    .venv/bin/python -m pytest -q
    .venv/bin/ruff check .
    .venv/bin/mypy src
    .venv/bin/netpath-sentinel --help
    QT_QPA_PLATFORM=offscreen .venv/bin/python -c 'from PySide6.QtWidgets import QApplication; from netpath_sentinel.presentation.desktop.app import MainWindow; app=QApplication([]); window=MainWindow(); print(window.windowTitle()); window.close()'

The PySide6 wheel supplies Qt Essentials. If the wheel is unavailable for the
platform architecture, use a supported CPython version and consult the PySide6
installation guide before installing system Qt packages.

## Troubleshooting

- If tests or commands are missing, check python --version and invoke tools
  from .venv rather than relying on global PATH entries.
- If uv cannot run due to endpoint execution policy, invoke
  .venv/Scripts/python.exe -m pytest -q and the corresponding .exe tools on
  Windows after provisioning the environment.
- If uv sync reports an interpreter mismatch, install CPython 3.13 with uv
  python install 3.13, then repeat uv sync --python 3.13 --extra dev.
- Live capture additionally needs a supported packet capture driver and
  permissions. Use simulated capture tests for ordinary development.

## Packaging smoke check

    uv run pyinstaller --version
    uv run pyinstaller packaging/windows/NetPathSentinel.spec --clean

On Debian/Ubuntu, build a DEB with:

    bash packaging/debian/build-deb.sh

On AlmaLinux/Rocky Linux, build an RPM with:

    bash packaging/rpm/build-rpm.sh

Build installers on their native operating systems. The Windows spec smoke
check does not verify Npcap availability or the Inno Setup installer.
