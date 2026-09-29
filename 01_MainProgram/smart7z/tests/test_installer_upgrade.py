"""Compile and execute the installer logic with isolated OS-effect adapters."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "smart7z_installer.iss"
COMPILER = next(
    (
        str(path)
        for path in (
            os.environ.get("INNO_SETUP_COMPILER"),
            ROOT / ".build-tools" / "inno" / "ISCC.exe",
            ROOT / ".build-tools" / "inno" / "app" / "ISCC.exe",
            *(
                Path(base) / f"Inno Setup {version}" / "ISCC.exe"
                for version in (7, 6)
                for base in (os.environ.get("ProgramFiles(x86)"), os.environ.get("ProgramFiles"))
                if base
            ),
            shutil.which("ISCC.exe"),
        )
        if path and Path(path).is_file()
    ),
    "",
)


class TestInstallerUpgradeContract(unittest.TestCase):
    def test_uninstall_runs_before_copy_and_failure_blocks_install(self):
        code = INSTALLER.read_text("utf-8")
        prepare = code.split("function PrepareToInstall", 1)[1].split("procedure RemoveOwned", 1)[0]
        self.assertIn("HKCU64, PreviousUninstallKey", prepare)
        self.assertIn("CheckForMutexes('Smart7z_Instance_Mutex')", prepare)
        self.assertIn("if not BackupUpgradeMenus then", prepare)
        self.assertIn("ewWaitUntilTerminated", prepare)
        self.assertIn("/NORESTART /RESTARTEXITCODE=3010", prepare)
        self.assertIn("not Executed or (ResultCode <> 0) or RegKeyExists", prepare)
        self.assertLess(prepare.index("BackupUpgradeMenus"), prepare.index("Exec(Uninstaller"))
        uninstall_at = prepare.index("Exec(Uninstaller")
        self.assertLess(uninstall_at, prepare.index("RestoreUpgradeMenus;", uninstall_at))
        self.assertNotIn("[UninstallDelete]", code)
        self.assertIn("onlyifdoesntexist uninsneveruninstall", code)

    def test_menu_backups_survive_failed_setup_and_do_not_replace_existing_keys(self):
        code = INSTALLER.read_text("utf-8")
        self.assertIn(r"{localappdata}\Smart7z\upgrade-menus-", code)
        self.assertIn("and not RegKeyExists(HKCU64, UpgradeMenuKey(Index))", code)
        self.assertIn("PreviousVersionRemoved and IsCommandFromDirectory", code)
        self.assertNotIn("DelTree(", code)


@unittest.skipUnless(os.name == "nt" and Path(COMPILER).is_file(), "Inno Setup compiler is required")
class TestInstallerUpgradeExecution(unittest.TestCase):
    def test_actual_installer_compiles(self):
        with tempfile.TemporaryDirectory(prefix="smart7z-compiler-") as temp:
            area = Path(temp)
            payload = area / "payload"
            payload.mkdir()
            (payload / "Smart7z.exe").write_bytes(b"compile-only")
            (payload / "code.txt").touch()
            result = subprocess.run(
                [COMPILER, "/Q", f"/DSourceDir={payload}", f"/DOutputDir={area}",
                 "/DInstallerBaseName=compile-check", str(INSTALLER)],
                capture_output=True, timeout=90,
            )
            self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode("utf-8", "replace"))

    def test_upgrade_state_transitions_without_touching_real_registry(self):
        code = INSTALLER.read_text("utf-8").split("[Code]\n", 1)[1]
        adapters = (
            "RegKeyExists", "RegQueryStringValue", "RegDeleteKeyIncludingSubkeys",
            "RegWriteStringValue", "FileExists", "ForceDirectories", "Exec", "CheckForMutexes",
        )
        for name in adapters:
            code = code.replace(name + "(", "Probe" + name + "(")
        code = code.replace("procedure CurStepChanged", "procedure OriginalCurStepChanged")
        code = code.replace("procedure CurUninstallStepChanged", "procedure OriginalCurUninstallStepChanged")
        code = code.replace("{#MyAppExeName}", "Smart7z.exe")
        # Pascal globals must precede function definitions in the combined harness.
        split = code.index("function CommandExecutable")
        declarations, functions = code[:split], code[split:]
        with tempfile.TemporaryDirectory(prefix="smart7z-upgrade-") as temp:
            area = Path(temp)
            script = area / "probe.iss"
            script.write_text(
                PREAMBLE.replace("@OUTPUT@", str(area))
                + declarations + ADAPTERS + functions + SCENARIOS,
                encoding="utf-8",
            )
            compiled = subprocess.run(
                [COMPILER, "/Q", str(script)], capture_output=True, timeout=90,
            )
            self.assertEqual(compiled.returncode, 0, (compiled.stdout + compiled.stderr).decode("utf-8", "replace"))
            log = area / "probe.log"
            startup = subprocess.STARTUPINFO()
            startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startup.wShowWindow = 0
            result = subprocess.run(
                [str(area / "probe.exe"), "/VERYSILENT", "/SUPPRESSMSGBOXES",
                 "/NORESTART", f"/LOG={log}", f"/RESULT={area / 'result.txt'}"],
                startupinfo=startup, timeout=60,
            )
            progress = area / "result.txt"
            evidence = progress.read_text("utf-8-sig", errors="replace") if progress.exists() else "No scenario reached"
            self.assertEqual(result.returncode, 0, evidence + "\n" + log.read_text("utf-8-sig", errors="replace"))
            self.assertEqual((area / "result.txt").read_text("utf-8-sig").strip(), "12 cases passed")


PREAMBLE = r"""
[Setup]
AppId=Smart7z-Upgrade-Logic-Probe
AppName=Smart7z Upgrade Logic Probe
AppVersion=1
DefaultDirName={tmp}\Smart7z-Upgrade-Probe
CreateAppDir=no
Uninstallable=no
PrivilegesRequired=lowest
OutputDir=@OUTPUT@
OutputBaseFilename=probe
Compression=none
[CustomMessages]
UpgradeCloseApp=running
UpgradeInvalidUninstaller=invalid
UpgradeMenuBackupFailed=backup
UpgradeUninstallFailed=uninstall %1
UpgradeMenuRestoreFailed=restore %1
UpgradeUninstalling=uninstalling
[Code]
"""

ADAPTERS = r"""
var
  OldExists, Running, Missing, InvalidPath, ExecuteOK, BackupOK, RestoreOK, Lingering: Boolean;
  UninstallCode, UninstallCalls, ExportCalls, ImportCalls: Integer;
  MenuExists: array[0..5] of Boolean;
  MenuCommands: array[0..5] of String;

function KeyIndex(const Key: String): Integer;
begin
  Result := -1;
  if Pos('Smart7zExtractHereDelete', Key) > 0 then Result := 1
  else if Pos('Smart7zExtractHere', Key) > 0 then Result := 0
  else if Pos('\shell\Smart7z', Key) > 0 then Result := 2;
  if (Result >= 0) and (Pos('\Directory\', Key) > 0) then Result := Result + 3;
end;

function ProbeRegKeyExists(const Root: Integer; const Key: String): Boolean;
var I: Integer;
begin
  if Key = PreviousUninstallKey then Result := OldExists
  else begin I := KeyIndex(Key); Result := False; if I >= 0 then Result := MenuExists[I]; end;
end;

function ProbeRegQueryStringValue(const Root: Integer; const Key, Name: String; var Value: String): Boolean;
var I: Integer;
begin
  Result := True;
  if Key = PreviousUninstallKey then
  begin
    if Name = 'InstallLocation' then Value := 'C:\Old'
    else if Name = 'UninstallString' then
    begin
      Value := '"C:\Old\unins000.exe"';
      if InvalidPath then Value := '"C:\Other\unins000.exe"';
    end
    else Result := False;
  end
  else begin
    I := KeyIndex(Key); Result := I >= 0;
    if Result then begin Result := MenuExists[I]; Value := MenuCommands[I]; end;
  end;
end;

function ProbeRegWriteStringValue(const Root: Integer; const Key, Name, Value: String): Boolean;
var I: Integer;
begin
  I := KeyIndex(Key); Result := I >= 0;
  if Result then begin MenuExists[I] := True; MenuCommands[I] := Value; end;
end;

function ProbeRegDeleteKeyIncludingSubkeys(const Root: Integer; const Key: String): Boolean;
var I: Integer;
begin I := KeyIndex(Key); Result := I >= 0; if Result then MenuExists[I] := False; end;

function ProbeFileExists(const Name: String): Boolean;
begin Result := (Pos('.reg', Name) > 0) or not Missing; end;

function ProbeForceDirectories(const Name: String): Boolean;
begin Result := True; end;

function ProbeCheckForMutexes(const Names: String): Boolean;
begin Result := Running; end;

function ProbeExec(const Filename, Params, Dir: String; const ShowCmd: Integer;
  const Wait: TExecWait; var ResultCode: Integer): Boolean;
var I: Integer;
begin
  ResultCode := 0;
  if Pos('export ', Params) = 1 then
  begin ExportCalls := ExportCalls + 1; Result := BackupOK; if not Result then ResultCode := 5; end
  else if Pos('import ', Params) = 1 then
  begin
    ImportCalls := ImportCalls + 1; Result := RestoreOK;
    if Result then
      for I := 0 to 5 do if Pos(MenuBackups[I], Params) > 0 then MenuExists[I] := True;
  end
  else begin
    UninstallCalls := UninstallCalls + 1; Result := ExecuteOK; ResultCode := UninstallCode;
    if Result then begin
      if ResultCode = 0 then OldExists := Lingering;
      for I := 0 to 5 do MenuExists[I] := False;
    end;
  end;
end;

procedure ResetProbe;
var I: Integer;
begin
  OldExists := True; Running := False; Missing := False; InvalidPath := False;
  ExecuteOK := True; BackupOK := True; RestoreOK := True; Lingering := False;
  UninstallCode := 0; UninstallCalls := 0; ExportCalls := 0; ImportCalls := 0;
  PreviousInstallDir := ''; PreviousVersionRemoved := False;
  for I := 0 to 5 do begin
    MenuExists[I] := True; MenuBackups[I] := '';
    MenuCommands[I] := '"C:\Old\Smart7z.exe" --start "%1"';
  end;
  MenuCommands[4] := '"C:\Other\Smart7z.exe" --start "%1"';
end;

procedure Verify(const Good: Boolean; const Message: String);
begin
  SaveStringToFile(ExpandConstant('{param:RESULT}'), Message + ': ' + IntToStr(Ord(Good)) + #13#10, True);
  if not Good then RaiseException(Message);
end;
"""

SCENARIOS = r"""
procedure CurStepChanged(CurStep: TSetupStep);
var Message: String; Restart: Boolean;
begin
  if CurStep <> ssInstall then exit;
  ResetProbe; OldExists := False;
  Message := PrepareToInstall(Restart);
  Verify((Message = '') and (UninstallCalls = 0), 'fresh install');

  ResetProbe;
  Message := PrepareToInstall(Restart);
  Verify((Message = '') and PreviousVersionRemoved and (UninstallCalls = 1), 'upgrade');
  Verify((ExportCalls = 6) and (ImportCalls = 6), 'legacy menu preservation');
  OriginalCurStepChanged(ssPostInstall);
  Verify(Pos(ExpandConstant('{app}'), MenuCommands[0]) > 0, 'owned menu retarget');
  Verify(Pos(ExpandConstant('{app}'), MenuCommands[2]) > 0, 'legacy file menu retarget');
  Verify(Pos(ExpandConstant('{app}'), MenuCommands[5]) > 0, 'legacy folder menu retarget');
  Verify(Pos('C:\Other', MenuCommands[4]) > 0, 'foreign menu retained');
  Message := PrepareToInstall(Restart);
  Verify((Message = '') and (UninstallCalls = 1), 'no repeated uninstall');

  ResetProbe; Running := True;
  Verify((PrepareToInstall(Restart) <> '') and (UninstallCalls = 0), 'running app');
  ResetProbe; Missing := True;
  Verify((PrepareToInstall(Restart) <> '') and (UninstallCalls = 0), 'missing uninstaller');
  ResetProbe; InvalidPath := True;
  Verify((PrepareToInstall(Restart) <> '') and (UninstallCalls = 0), 'uninstaller outside installation');
  ResetProbe; BackupOK := False;
  Verify((PrepareToInstall(Restart) <> '') and (UninstallCalls = 0), 'backup failure');
  ResetProbe; ExecuteOK := False;
  Verify((PrepareToInstall(Restart) <> '') and not PreviousVersionRemoved, 'launch failure');
  ResetProbe; UninstallCode := 2;
  Verify((PrepareToInstall(Restart) <> '') and not PreviousVersionRemoved, 'uninstall cancelled');
  ResetProbe; UninstallCode := 3010;
  Message := PrepareToInstall(Restart);
  Verify((Message <> '') and Restart and not PreviousVersionRemoved, 'restart required');
  ResetProbe; Lingering := True;
  Verify((PrepareToInstall(Restart) <> '') and not PreviousVersionRemoved, 'registration remains');
  ResetProbe; RestoreOK := False;
  Verify(PrepareToInstall(Restart) <> '', 'menu restore failure');
  ResetProbe; OldExists := False;
  OriginalCurUninstallStepChanged(usUninstall);
  Verify(MenuExists[4], 'standalone uninstall preserves foreign menus');
  if not SaveStringToFile(ExpandConstant('{param:RESULT}'), '12 cases passed', False) then
    RaiseException('result write');
end;
"""
