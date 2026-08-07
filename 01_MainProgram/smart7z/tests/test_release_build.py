from __future__ import annotations

import base64
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SPEC_PATH = PROJECT_ROOT / "smart7z.spec"
BUILD_SCRIPT_PATH = PROJECT_ROOT / "build_release.ps1"
REQUIREMENTS_PATH = PROJECT_ROOT / "requirements-build.txt"


class _FakeAnalysis:
    last_kwargs = None

    def __init__(self, *args, **kwargs):
        type(self).last_kwargs = kwargs
        self.binaries = [
            (r"PySide6\QtCore.pyd", "source", "BINARY"),
            (r"PySide6\QtGui.pyd", "source", "BINARY"),
            (r"PySide6\QtWidgets.pyd", "source", "BINARY"),
            (r"PySide6\QtNetwork.pyd", "source", "BINARY"),
            (r"PySide6\Qt6Core.dll", "source", "BINARY"),
            (r"PySide6\Qt6Gui.dll", "source", "BINARY"),
            (r"PySide6\Qt6Widgets.dll", "source", "BINARY"),
            (r"PySide6\opengl32sw.dll", "source", "BINARY"),
            (r"PySide6\Qt6Pdf.dll", "source", "BINARY"),
            (r"PySide6\plugins\platforms\qwindows.dll", "source", "BINARY"),
            (r"PySide6\plugins\platforms\qoffscreen.dll", "source", "BINARY"),
            (
                r"PySide6\plugins\styles\qmodernwindowsstyle.dll",
                "source",
                "BINARY",
            ),
            (r"PySide6\plugins\imageformats\qico.dll", "source", "BINARY"),
            (r"PySide6\plugins\imageformats\qsvg.dll", "source", "BINARY"),
            (r"PySide6\pyside6.abi3.dll", "source", "BINARY"),
        ]
        self.datas = [
            (r"PySide6\qml\QtQuick\qmldir", "source", "DATA"),
            (r"PySide6\translations\qtbase_zh_CN.qm", "source", "DATA"),
        ]
        self.pure = []
        self.scripts = []


class TestSmart7zSpecQtBoundary(unittest.TestCase):
    def test_build_requirements_lock_pyinstaller_windows_dependencies(self):
        expected = {
            "PyInstaller==6.21.0",
            "pyinstaller-hooks-contrib==2026.6",
            "Pillow==12.3.0",
            "PySide6==6.11.1",
            "altgraph==0.17.5",
            "packaging==26.3",
            "pefile==2024.8.26",
            "pywin32-ctypes==0.2.3",
            "setuptools==83.0.0",
        }
        requirements = {
            line.strip()
            for line in REQUIREMENTS_PATH.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }
        self.assertEqual(requirements, expected)

        build_script = BUILD_SCRIPT_PATH.read_text(encoding="utf-8")
        for requirement in expected:
            name, version = requirement.split("==", 1)
            self.assertIn(f"('{name}','{version}')", build_script)

    def test_spec_filters_to_the_minimal_qt_runtime(self):
        namespace = {
            "SPECPATH": str(PROJECT_ROOT),
            "Analysis": _FakeAnalysis,
            "PYZ": lambda *args, **kwargs: object(),
            "EXE": lambda *args, **kwargs: object(),
            "COLLECT": lambda *args, **kwargs: object(),
        }
        source = SPEC_PATH.read_text(encoding="utf-8")
        exec(compile(source, str(SPEC_PATH), "exec"), namespace)

        binary_names = {entry[0].replace("\\", "/") for entry in namespace["a"].binaries}
        self.assertEqual(
            binary_names,
            {
                "PySide6/QtCore.pyd",
                "PySide6/QtGui.pyd",
                "PySide6/QtWidgets.pyd",
                "PySide6/Qt6Core.dll",
                "PySide6/Qt6Gui.dll",
                "PySide6/Qt6Widgets.dll",
                "PySide6/plugins/imageformats/qico.dll",
                "PySide6/plugins/platforms/qwindows.dll",
                "PySide6/plugins/styles/qmodernwindowsstyle.dll",
                "PySide6/pyside6.abi3.dll",
            },
        )
        self.assertEqual(
            [entry[0].replace("\\", "/") for entry in namespace["a"].datas],
            ["PySide6/translations/qtbase_zh_CN.qm"],
        )

        excludes = set(_FakeAnalysis.last_kwargs["excludes"])
        for module in (
            "PySide6.QtNetwork",
            "PySide6.QtPdf",
            "PySide6.QtQml",
            "PySide6.QtQuick",
            "PySide6.QtSvg",
            "PySide6.QtWebEngineQuick",
        ):
            self.assertIn(module, excludes)


@unittest.skipUnless(os.name == "nt" and shutil.which("powershell.exe"), "Windows PowerShell is required")
class TestReleaseQtRuntimeAudit(unittest.TestCase):
    REQUIRED_FILES = (
        "QtCore.pyd",
        "QtGui.pyd",
        "QtWidgets.pyd",
        "Qt6Core.dll",
        "Qt6Gui.dll",
        "Qt6Widgets.dll",
        "plugins/imageformats/qico.dll",
        "plugins/platforms/qwindows.dll",
        "plugins/styles/qmodernwindowsstyle.dll",
    )

    def _create_minimal_runtime(self, root: Path) -> Path:
        pyside_root = root / "_internal" / "PySide6"
        for relative in self.REQUIRED_FILES:
            path = pyside_root / Path(relative)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()
        return pyside_root

    def _run_runtime_audit(self, root: Path) -> subprocess.CompletedProcess[str]:
        command = r"""
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    $env:SMART7Z_TEST_BUILD_SCRIPT,
    [ref]$tokens,
    [ref]$errors
)
if ($errors.Count -gt 0) {
    throw ($errors | ForEach-Object Message | Out-String)
}
$functionAst = $ast.Find({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Assert-MinimalQtRuntime'
}, $true)
if ($null -eq $functionAst) {
    throw 'Assert-MinimalQtRuntime was not found.'
}
Invoke-Expression $functionAst.Extent.Text
Assert-MinimalQtRuntime -Root $env:SMART7Z_TEST_RUNTIME_ROOT
"""
        encoded = base64.b64encode(command.encode("utf-16le")).decode("ascii")
        env = os.environ.copy()
        env["SMART7Z_TEST_BUILD_SCRIPT"] = str(BUILD_SCRIPT_PATH)
        env["SMART7Z_TEST_RUNTIME_ROOT"] = str(root)
        return subprocess.run(
            ["powershell.exe", "-NoProfile", "-EncodedCommand", encoded],
            cwd=PROJECT_ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

    def test_minimal_runtime_passes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self._create_minimal_runtime(root)
            result = self._run_runtime_audit(root)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_forbidden_qt_module_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            pyside_root = self._create_minimal_runtime(root)
            (pyside_root / "Qt6Pdf.dll").touch()
            result = self._run_runtime_audit(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Qt6Pdf.dll", result.stdout + result.stderr)

    def test_forbidden_qt_plugin_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            pyside_root = self._create_minimal_runtime(root)
            plugin = pyside_root / "plugins" / "imageformats" / "qsvg.dll"
            plugin.parent.mkdir(parents=True, exist_ok=True)
            plugin.touch()
            result = self._run_runtime_audit(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("plugins/imageformats/qsvg.dll", result.stdout + result.stderr)

    def test_forbidden_qt_auxiliary_runtime_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            pyside_root = self._create_minimal_runtime(root)
            (pyside_root / "opengl32sw.dll").touch()
            result = self._run_runtime_audit(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("opengl32sw.dll", result.stdout + result.stderr)

    def test_required_qtbase_plugins_are_enforced(self):
        for relative in (
            "plugins/imageformats/qico.dll",
            "plugins/styles/qmodernwindowsstyle.dll",
        ):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                pyside_root = self._create_minimal_runtime(root)
                (pyside_root / Path(relative)).unlink()
                result = self._run_runtime_audit(root)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f"missing: {relative}", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
