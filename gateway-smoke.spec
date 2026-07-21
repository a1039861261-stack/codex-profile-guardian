# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path


project_root = Path(globals().get("SPECPATH", Path.cwd())).resolve()

a = Analysis(
    [str(project_root / "tools" / "gateway_g3_smoke.py")],
    pathex=[str(project_root)],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["webview"],
    noarchive=False,
    optimize=1,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="GuardianGatewayG3Smoke",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=True,
)
