#define AppName "NetPath Sentinel"
#define AppVersion "0.1.0"
#define Publisher "NetPath Sentinel Contributors"
#define AppExeName "NetPathSentinel.exe"
#define CliExeName "NetPathSentinelCLI.exe"
#ifndef BinaryDir
#define BinaryDir "..\..\dist"
#endif

[Setup]
AppId={{5C321B2B-2C57-44D5-9E6A-4BBF4C2D4A01}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#Publisher}
SetupIconFile=netpath-sentinel.ico
DefaultDirName={localappdata}\Programs\NetPath Sentinel
DefaultGroupName={#AppName}
OutputBaseFilename=NetPathSentinel-Setup-{#AppVersion}-windows-x64
OutputDir=..\..\dist\installer
ArchitecturesInstallIn64BitMode=x64compatible
ArchitecturesAllowed=x64compatible
PrivilegesRequired=lowest
UninstallDisplayIcon={app}\{#AppExeName}
CloseApplications=yes
RestartApplications=no
UsePreviousAppDir=yes
Compression=lzma
SolidCompression=yes

[Files]
Source: "{#BinaryDir}\NetPathSentinel.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BinaryDir}\NetPathSentinelCLI.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExeName}"
Name: "{group}\{#AppName} CLI"; Filename: "{app}\{#CliExeName}"; Parameters: "inspect-host"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; Flags: unchecked

[Run]
Filename: "{app}\{#AppExeName}"; Description: "Launch {#AppName}"; Flags: nowait postinstall skipifsilent runasoriginaluser
