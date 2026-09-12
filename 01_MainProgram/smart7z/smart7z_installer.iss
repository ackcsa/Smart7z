#ifndef MyAppVersion
  #define MyAppVersion "1.0.4"
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
#define MyAppPublisher "Smart7z"

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

[Code]
function IsOwnedContextMenuCommand(const Command: String): Boolean;
var
  Executable: String;
  Boundary: Integer;
begin
  Result := False;
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
  Result :=
    (CompareText(Executable, ExpandConstant('{app}\{#MyAppExeName}')) = 0) or
    (CompareText(Executable, ExpandConstant('{app}\Smart7zShell.exe')) = 0);
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
      'Software\Classes\Directory\shell', 'Smart7zExtractHere', '--keep-source');
    RefreshOwnedContextMenuCommand(
      'Software\Classes\Directory\shell', 'Smart7zExtractHereDelete', '--delete-source');
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
    RemoveContextMenuKeys;
end;
