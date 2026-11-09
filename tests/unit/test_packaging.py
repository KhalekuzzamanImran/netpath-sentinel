import os
import subprocess
import sys
from pathlib import Path

from netpath_sentinel.configuration.paths import app_data_dir

ROOT = Path(__file__).parents[2]


def test_windows_installer_uses_onefile_executable_and_versioned_name() -> None:
    installer = (ROOT / "packaging/windows/NetPathSentinel.iss").read_text()
    spec = (ROOT / "packaging/windows/NetPathSentinel.spec").read_text()
    assert "NetPathSentinel-Setup-{#AppVersion}-windows-x64" in installer
    assert '#define BinaryDir "..\\..\\dist"' in installer
    assert 'Source: "{#BinaryDir}\\NetPathSentinel.exe"' in installer
    assert 'Source: "{#BinaryDir}\\NetPathSentinelCLI.exe"' in installer
    assert "runasoriginaluser" in installer
    assert "SetupIconFile=netpath-sentinel.ico" in installer
    assert "version_info.txt" in spec
    assert (ROOT / "packaging/windows/netpath-sentinel.ico").is_file()
    assert "from netpath_sentinel.presentation.desktop.app import run" in (
        ROOT / "packaging/gui_main.py"
    ).read_text()


def test_linux_package_definitions_use_self_contained_binary() -> None:
    deb = (ROOT / "packaging/debian/control").read_text()
    rpm = (ROOT / "packaging/rpm/netpath-sentinel.spec").read_text()
    assert "Depends: libpcap0.8" in deb
    assert "python3 (>= 3.12)" not in deb
    assert "Requires: libpcap" in rpm
    assert "%{_datadir}/icons/hicolor/scalable/apps/netpath-sentinel.svg" in rpm
    assert (ROOT / "packaging/debian/build-deb.sh").is_file()
    assert (ROOT / "packaging/rpm/build-rpm.sh").is_file()
    assert (ROOT / "packaging/linux/netpath-sentinel-cli").read_text().startswith("#!/bin/sh")
    assert "--cli" in (ROOT / "packaging/gui_main.py").read_text()


def test_linux_build_uses_one_pyinstaller_binary_to_avoid_build_id_collision() -> None:
    for script in ("packaging/debian/build-deb.sh", "packaging/rpm/build-rpm.sh"):
        source = (ROOT / script).read_text()
        assert source.count("-m PyInstaller") == 1
        assert "netpath-sentinel-cli.py" not in source


def test_shared_linux_executable_routes_cli_mode() -> None:
    result = subprocess.run(
        [sys.executable, str(ROOT / "packaging/gui_main.py"), "--cli", "--help"],
        capture_output=True,
        check=False,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0
    assert "usage: netpath-sentinel" in result.stdout


def test_application_data_directory_override_is_created(tmp_path, monkeypatch) -> None:
    target = tmp_path / "user-data"
    monkeypatch.setenv("NETPATH_SENTINEL_DATA_DIR", str(target))
    assert app_data_dir() == target
    assert target.is_dir()
    if os.name != "nt":
        assert target.stat().st_mode & 0o777 == 0o700
