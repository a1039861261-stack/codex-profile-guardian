# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path


project_root = Path(globals().get("SPECPATH", Path.cwd())).resolve()

a = Analysis(
    [str(project_root / "main.py")],
    pathex=[str(project_root)],
    binaries=[],
    datas=[
        (str(project_root / "dist" / "index.html"), "dist"),
        (str(project_root / "dist" / "assets"), "dist/assets"),
    ],
    hiddenimports=["webview", "webview.platforms.edgechromium"],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="CodexProfileGuardian",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
)
