from PyInstaller.utils.hooks import collect_submodules

hiddenimports = collect_submodules("netpath_sentinel")

a = Analysis(["src/netpath_sentinel/main.py"], pathex=["."], hiddenimports=hiddenimports)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, a.binaries, a.datas, [], name="NetPathSentinel", console=False)
