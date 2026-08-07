import os
from pathlib import Path, PurePosixPath

source_dir = Path(SPECPATH)
dist_name = os.environ.get("SMART7Z_DIST_NAME", "Smart7z")
version_file = os.environ.get(
    "SMART7Z_VERSION_FILE",
    str(source_dir / "build" / "smart7z_version_info.txt"),
)
excluded_legacy_modules = [
    "".join(chr(value) for value in values)
    for values in (
        (116, 107, 105, 110, 116, 101, 114),
        (95, 116, 107, 105, 110, 116, 101, 114),
        (116, 107, 105, 110, 116, 101, 114, 100, 110, 100, 50),
    )
]
excluded_qt_modules = [
    "PySide6.QtNetwork",
    "PySide6.QtOpenGL",
    "PySide6.QtOpenGLWidgets",
    "PySide6.QtPdf",
    "PySide6.QtPdfWidgets",
    "PySide6.QtQml",
    "PySide6.QtQuick",
    "PySide6.QtQuickControls2",
    "PySide6.QtQuickWidgets",
    "PySide6.QtSvg",
    "PySide6.QtSvgWidgets",
    "PySide6.QtWebEngineCore",
    "PySide6.QtWebEngineQuick",
    "PySide6.QtWebEngineWidgets",
]

allowed_qt_binding_files = {
    "qtcore.pyd",
    "qtgui.pyd",
    "qtwidgets.pyd",
}
allowed_qt_module_dlls = {
    "qt6core.dll",
    "qt6gui.dll",
    "qt6widgets.dll",
}
allowed_qt_plugin_paths = {
    "plugins/imageformats/qico.dll",
    "plugins/platforms/qwindows.dll",
    "plugins/styles/qmodernwindowsstyle.dll",
}


def _pyside6_relative_toc_name(entry):
    normalized = str(entry[0]).replace("\\", "/").lstrip("./")
    lower = normalized.casefold()
    marker = "pyside6/"
    marker_index = lower.find(marker)
    if marker_index < 0:
        return normalized, None
    return normalized, normalized[marker_index + len(marker):]


def _keep_minimal_qt_entry(entry):
    normalized, pyside_relative = _pyside6_relative_toc_name(entry)
    leaf = PurePosixPath(normalized).name.casefold()

    if (
        pyside_relative is not None
        and PurePosixPath(pyside_relative).name.casefold() == "opengl32sw.dll"
    ):
        return False

    if leaf.startswith("qt6") and leaf.endswith(".dll"):
        return pyside_relative is not None and leaf in allowed_qt_module_dlls

    if pyside_relative is None:
        return True

    relative_lower = pyside_relative.casefold()
    relative_leaf = PurePosixPath(relative_lower).name
    if relative_lower.startswith("qml/"):
        return False
    if relative_lower.startswith("plugins/"):
        return relative_lower in allowed_qt_plugin_paths
    if relative_leaf.startswith("qt") and relative_leaf.endswith(".pyd"):
        return relative_leaf in allowed_qt_binding_files
    return True

a = Analysis(
    [str(source_dir / "smart7z.py")],
    pathex=[str(source_dir)],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "PIL",
        "pytest",
        "unittest",
        *excluded_legacy_modules,
        *excluded_qt_modules,
    ],
    noarchive=False,
    optimize=1,
)
a.binaries = [entry for entry in a.binaries if _keep_minimal_qt_entry(entry)]
a.datas = [entry for entry in a.datas if _keep_minimal_qt_entry(entry)]
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
