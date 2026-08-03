import os
from pathlib import Path

source_dir = Path(SPECPATH)
dist_name = os.environ.get("SMART7Z_DIST_NAME", "Smart7z")
version_file = os.environ.get(
    "SMART7Z_VERSION_FILE",
    str(source_dir / "build" / "smart7z_version_info.txt"),
)

a = Analysis(
    [str(source_dir / "smart7z.py")],
    pathex=[str(source_dir)],
    # tkinterdnd2's hook selects the current Windows architecture.
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["PIL", "pytest", "unittest"],
    noarchive=False,
    optimize=1,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="Smart7z",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(source_dir / "build_assets" / "smart7z.ico"),
    version=version_file,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name=dist_name,
)
