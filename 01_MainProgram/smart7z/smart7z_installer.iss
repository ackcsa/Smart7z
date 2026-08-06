#ifndef MyAppVersion
  #define MyAppVersion "1.0.0"
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
LicenseFile={#SourceDir}\THIRD_PARTY_NOTICES.txt
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
procedure RemoveContextMenuKeys;
begin
  RegDeleteKeyIncludingSubkeys(HKCU, 'Software\Classes\*\shell\Smart7zExtractHere');
  RegDeleteKeyIncludingSubkeys(HKCU, 'Software\Classes\*\shell\Smart7zExtractHereDelete');
  RegDeleteKeyIncludingSubkeys(HKCU, 'Software\Classes\*\shell\Smart7z');
  RegDeleteKeyIncludingSubkeys(HKCU, 'Software\Classes\Directory\shell\Smart7zExtractHere');
  RegDeleteKeyIncludingSubkeys(HKCU, 'Software\Classes\Directory\shell\Smart7zExtractHereDelete');
  RegDeleteKeyIncludingSubkeys(HKCU, 'Software\Classes\Directory\shell\Smart7z');
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
    RemoveContextMenuKeys;
end;
