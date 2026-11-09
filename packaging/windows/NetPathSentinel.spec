from PyInstaller.utils.hooks import collect_submodules
from pathlib import Path

hiddenimports = collect_submodules("netpath_sentinel")
project_root = Path(SPECPATH).parents[1]

a = Analysis(
    [str(project_root / "packaging" / "gui_main.py")],
    pathex=[str(project_root / "src")],
    hiddenimports=hiddenimports,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="NetPathSentinel",
    console=False,
    icon=str(project_root / "packaging" / "windows" / "netpath-sentinel.ico"),
    version=str(project_root / "packaging" / "windows" / "version_info.txt"),
)
cli_analysis = Analysis(
    [str(project_root / "packaging" / "windows" / "cli_main.py")],
    pathex=[str(project_root / "src")],
)
cli_pyz = PYZ(cli_analysis.pure)
cli_exe = EXE(
    cli_pyz,
    cli_analysis.scripts,
    cli_analysis.binaries,
    cli_analysis.datas,
    [],
    name="NetPathSentinelCLI",
    console=True,
    icon=str(project_root / "packaging" / "windows" / "netpath-sentinel.ico"),
    version=str(project_root / "packaging" / "windows" / "version_info.txt"),
)
