#ifndef MyAppVersion
  #define MyAppVersion "1.0.5"
#endif
#ifndef SourceDir
  #error SourceDir must be supplied with /DSourceDir=...
#endif
#ifndef OutputDir
  #define OutputDir "."
#endif
#ifndef InstallerBaseName
  #define InstallerBaseName "Smart7z-Setup"
#endif

#define MyAppName "Smart 7z Ultra"
#define MyAppExeName "Smart7z.exe"
#define MyAppPublisher "Kurpphy"

[Setup]
AppId={{EDCB8E16-9106-4D4B-8520-4D63F5D22370}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
VersionInfoVersion={#MyAppVersion}
VersionInfoProductName={#MyAppName}
VersionInfoDescription={#MyAppName} Installer
DefaultDirName={localappdata}\Programs\Smart7z
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
OutputDir={#OutputDir}
OutputBaseFilename={#InstallerBaseName}
SetupIconFile={#SourcePath}\build_assets\smart7z.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
MinVersion=10.0.17763
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
CloseApplications=yes
RestartApplications=no
AppMutex=Smart7z_Instance_Mutex
SetupLogging=yes
ChangesAssociations=no

[Languages]
Name: "chinesesimp"; MessagesFile: "{#SourcePath}\build_assets\ChineseSimplified.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "{#SourceDir}\*"; Excludes: "code.txt"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#SourceDir}\code.txt"; DestDir: "{app}"; Flags: onlyifdoesntexist uninsneveruninstall

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[CustomMessages]
english.UpgradeCloseApp=Close all Smart7z windows before upgrading.
english.UpgradeInvalidUninstaller=The existing Smart7z uninstall record is incomplete or invalid. Repair or manually uninstall that installation, then run Setup again.
english.UpgradeMenuBackupFailed=Could not preserve the existing Smart7z context menus. The old version has not been uninstalled.
english.UpgradeUninstallFailed=The old version could not be fully uninstalled (code %1). Setup will not install the new version. Resolve the uninstall problem and run Setup again.
english.UpgradeMenuRestoreFailed=Could not restore the saved Smart7z context menus. Setup has stopped. The registry backups are in: %1
english.UpgradeUninstalling=Uninstalling the existing Smart7z version...

[Code]
const
  PreviousUninstallKey = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{EDCB8E16-9106-4D4B-8520-4D63F5D22370}_is1';

var
  PreviousInstallDir: String;
  PreviousVersionRemoved: Boolean;
  UpgradeBackupDir: String;
  MenuBackups: array[0..5] of String;

function CommandExecutable(const Command: String): String;
var
  Executable: String;
  Boundary: Integer;
begin
  Result := '';
  Executable := Trim(Command);
  if Executable = '' then
    exit;
  if Executable[1] = '"' then
  begin
    Delete(Executable, 1, 1);
    Boundary := Pos('"', Executable);
    if Boundary = 0 then
      exit;
    Executable := Copy(Executable, 1, Boundary - 1);
  end
  else
  begin
    Boundary := Pos(' ', Executable);
    if Boundary > 0 then
      Executable := Copy(Executable, 1, Boundary - 1);
  end;
  Result := Executable;
end;

function IsCommandFromDirectory(const Command, Directory: String): Boolean;
var
  Executable: String;
begin
  Executable := CommandExecutable(Command);
  Result := (Directory <> '') and
    ((CompareText(Executable, AddBackslash(Directory) + '{#MyAppExeName}') = 0) or
     (CompareText(Executable, AddBackslash(Directory) + 'Smart7zShell.exe') = 0));
end;

function IsOwnedContextMenuCommand(const Command: String): Boolean;
begin
  Result := IsCommandFromDirectory(Command, ExpandConstant('{app}'));
end;

function UpgradeMenuKey(const Index: Integer): String;
begin
  if Index < 3 then
    Result := 'Software\Classes\*\shell\'
  else
    Result := 'Software\Classes\Directory\shell\';
  case Index mod 3 of
    0: Result := Result + 'Smart7zExtractHere';
    1: Result := Result + 'Smart7zExtractHereDelete';
    2: Result := Result + 'Smart7z';
  end;
end;

function BackupUpgradeMenus: Boolean;
var
  Index, ResultCode: Integer;
  BackupPath, KeyPath: String;
begin
  Result := False;
  UpgradeBackupDir := ExpandConstant('{localappdata}\Smart7z\upgrade-menus-') +
    GetDateTimeString('yyyymmddhhnnss', '-', ':');
  if not ForceDirectories(UpgradeBackupDir) then
    exit;
  for Index := 0 to 5 do
  begin
    MenuBackups[Index] := '';
    KeyPath := UpgradeMenuKey(Index);
    if RegKeyExists(HKCU64, KeyPath) then
    begin
      BackupPath := AddBackslash(UpgradeBackupDir) + 'menu-' + IntToStr(Index) + '.reg';
      if not Exec(ExpandConstant('{sys}\reg.exe'),
        'export "HKCU\' + KeyPath + '" "' + BackupPath + '" /y /reg:64',
        '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
        exit;
      if (ResultCode <> 0) or not FileExists(BackupPath) then
        exit;
      MenuBackups[Index] := BackupPath;
    end;
  end;
  Result := True;
end;

function RestoreUpgradeMenus: Boolean;
var
  Index, ResultCode: Integer;
begin
  Result := True;
  for Index := 0 to 5 do
    if (MenuBackups[Index] <> '') and not RegKeyExists(HKCU64, UpgradeMenuKey(Index)) then
    begin
      { Older uninstallers removed even menus owned by another copy. }
      if not Exec(ExpandConstant('{sys}\reg.exe'),
        'import "' + MenuBackups[Index] + '" /reg:64',
        '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
        Result := False
      else if ResultCode <> 0 then
        Result := False;
    end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  UninstallCommand, Uninstaller, UninstallerName: String;
  ResultCode: Integer;
  Executed, MenusRestored: Boolean;
begin
  Result := '';
  if PreviousVersionRemoved then
  begin
    if not RestoreUpgradeMenus then
      Result := FmtMessage(CustomMessage('UpgradeMenuRestoreFailed'), [UpgradeBackupDir]);
    exit;
  end;
  if not RegKeyExists(HKCU64, PreviousUninstallKey) then
    exit;
  if CheckForMutexes('Smart7z_Instance_Mutex') then
  begin
    Result := CustomMessage('UpgradeCloseApp');
    exit;
  end;
  if not RegQueryStringValue(HKCU64, PreviousUninstallKey, 'InstallLocation', PreviousInstallDir) or
     not RegQueryStringValue(HKCU64, PreviousUninstallKey, 'UninstallString', UninstallCommand) then
  begin
    Result := CustomMessage('UpgradeInvalidUninstaller');
    exit;
  end;
  Uninstaller := RemoveQuotes(Trim(UninstallCommand));
  UninstallerName := Lowercase(ExtractFileName(Uninstaller));
  if (PreviousInstallDir = '') or not FileExists(Uninstaller) or
     (CompareText(AddBackslash(ExtractFileDir(Uninstaller)), AddBackslash(PreviousInstallDir)) <> 0) or
     (Length(UninstallerName) <> 12) or (Copy(UninstallerName, 1, 5) <> 'unins') or
     (Copy(UninstallerName, 9, 4) <> '.exe') or
     (StrToIntDef(Copy(UninstallerName, 6, 3), -1) < 0) then
  begin
    Result := CustomMessage('UpgradeInvalidUninstaller');
    exit;
  end;
  if not BackupUpgradeMenus then
  begin
    Result := CustomMessage('UpgradeMenuBackupFailed');
    exit;
  end;
  WizardForm.StatusLabel.Caption := CustomMessage('UpgradeUninstalling');
  Executed := Exec(Uninstaller, '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /RESTARTEXITCODE=3010',
    PreviousInstallDir, SW_HIDE, ewWaitUntilTerminated, ResultCode);
  MenusRestored := RestoreUpgradeMenus;
  if not Executed or (ResultCode <> 0) or RegKeyExists(HKCU64, PreviousUninstallKey) then
  begin
    NeedsRestart := ResultCode = 3010;
    Result := FmtMessage(CustomMessage('UpgradeUninstallFailed'), [IntToStr(ResultCode)]);
    exit;
  end;
  PreviousVersionRemoved := True;
  if not MenusRestored then
    Result := FmtMessage(CustomMessage('UpgradeMenuRestoreFailed'), [UpgradeBackupDir]);
end;

procedure RemoveOwnedContextMenuKey(const KeyPath: String);
var
  ExistingCommand: String;
begin
  if RegQueryStringValue(HKCU, KeyPath + '\command', '', ExistingCommand) then
    if IsOwnedContextMenuCommand(ExistingCommand) then
      RegDeleteKeyIncludingSubkeys(HKCU, KeyPath);
end;

procedure RemoveContextMenuKeys;
begin
  RemoveOwnedContextMenuKey('Software\Classes\*\shell\Smart7zExtractHere');
  RemoveOwnedContextMenuKey('Software\Classes\*\shell\Smart7zExtractHereDelete');
  RemoveOwnedContextMenuKey('Software\Classes\*\shell\Smart7z');
  RemoveOwnedContextMenuKey('Software\Classes\Directory\shell\Smart7zExtractHere');
  RemoveOwnedContextMenuKey('Software\Classes\Directory\shell\Smart7zExtractHereDelete');
  RemoveOwnedContextMenuKey('Software\Classes\Directory\shell\Smart7z');
end;

procedure RefreshOwnedContextMenuCommand(const Scope, Verb, CleanupFlag: String);
var
  KeyPath: String;
  CommandKey: String;
  ExistingCommand: String;
  MainExecutable: String;
  UpdatedCommand: String;
begin
  KeyPath := Scope + '\' + Verb;
  CommandKey := KeyPath + '\command';
  if not RegQueryStringValue(HKCU, CommandKey, '', ExistingCommand) then
    exit;

  MainExecutable := ExpandConstant('{app}\{#MyAppExeName}');
  if not IsOwnedContextMenuCommand(ExistingCommand) then
    if not (PreviousVersionRemoved and IsCommandFromDirectory(ExistingCommand, PreviousInstallDir)) then
      exit;

  UpdatedCommand := '"' + MainExecutable +
    '" --context-menu --start --extract-here ' + CleanupFlag + ' "%1"';
  RegWriteStringValue(HKCU, CommandKey, '', UpdatedCommand);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    RefreshOwnedContextMenuCommand(
      'Software\Classes\*\shell', 'Smart7zExtractHere', '--keep-source');
    RefreshOwnedContextMenuCommand(
      'Software\Classes\*\shell', 'Smart7zExtractHereDelete', '--delete-source');
    RefreshOwnedContextMenuCommand(
      'Software\Classes\*\shell', 'Smart7z', '--keep-source');
    RefreshOwnedContextMenuCommand(
      'Software\Classes\Directory\shell', 'Smart7zExtractHere', '--keep-source');
    RefreshOwnedContextMenuCommand(
      'Software\Classes\Directory\shell', 'Smart7zExtractHereDelete', '--delete-source');
    RefreshOwnedContextMenuCommand(
      'Software\Classes\Directory\shell', 'Smart7z', '--keep-source');
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
    RemoveContextMenuKeys;
end;
