; Softcurse Sentinel — Inno Setup Script

#define MyAppName "Softcurse Sentinel"
#define MyAppVersion "2.0"
#define MyAppPublisher "Softcurse Inc."
#define MyAppExeName "Softcurse.UI.exe"

[Setup]
AppId={{7010568A-8183-410E-9E54-C9388DBE65F5}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
UninstallDisplayIcon={app}\{#MyAppExeName}
; Setup wizard icon — full logo with text
SetupIconFile=D:\Projects\Softcurse Anticheat\SoftcurseSentinel\publish\setup.ico
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
DisableProgramGroupPage=yes
PrivilegesRequired=admin
OutputDir=D:\Projects\Softcurse Anticheat\SoftcurseSentinel\output
OutputBaseFilename=SoftcurseSentinelSetup
SolidCompression=yes
WizardStyle=modern

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "german"; MessagesFile: "compiler:Languages\German.isl"
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "D:\Projects\Softcurse Anticheat\SoftcurseSentinel\publish\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent runascurrentuser
