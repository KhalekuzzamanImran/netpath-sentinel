#define AppName "NetPath Sentinel"
#define AppVersion "0.1.0"
#define Publisher "NetPath Sentinel Contributors"
#define AppExeName "NetPathSentinel.exe"

[Setup]
AppId={{5C321B2B-2C57-44D5-9E6A-4BBF4C2D4A01}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#Publisher}
DefaultDirName={autopf}\NetPath Sentinel
DefaultGroupName={#AppName}
OutputBaseFilename=NetPathSentinel-Setup-{#AppVersion}-windows-x64
ArchitecturesInstallIn64BitMode=x64
PrivilegesRequired=admin
UninstallDisplayIcon={app}\{#AppExeName}
Compression=lzma
SolidCompression=yes

[Files]
Source: "..\..\dist\windows\NetPathSentinel\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExeName}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; Flags: unchecked

[Run]
Filename: "{app}\{#AppExeName}"; Description: "Launch {#AppName}"; Flags: nowait postinstall skipifsilent
