
[Setup]
AppName=Secnet
AppVersion=v0.9
WizardStyle=modern
DefaultDirName={autopf}\secnet
DefaultGroupName=\secnet
UninstallDisplayIcon={app}\secnet.exe
Compression=lzma2
SolidCompression=yes
InfoBeforeFile=license.txt
OutputDir=.
OutputBaseFilename=secnet-v0.9-installer
ChangesEnvironment=yes

[Files]
Source: "secnet.exe"; DestDir: "{app}"
Source: "oui.txt"; DestDir: "{app}"
Source: "usage.txt"; DestDir: "{app}"; Flags: isreadme

[Icons]
Name: "{group}\secnet"; Filename: "secnet.exe"

[Registry]
Root: HKLM; SubKey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment\"; ValueType: string; ValueName: "Path"; ValueData: "{reg:HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment\,Path};{app}"

[Code]
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Path, AppDir: string;
  Index: Integer;
begin
  if CurUninstallStep = usUninstall then
  begin
    if RegQueryStringValue(HKEY_LOCAL_MACHINE,
      'SYSTEM\CurrentControlSet\Control\Session Manager\Environment\',
      'Path', Path) then
    begin
      AppDir := ExpandConstant('{app}');
      Index := Pos(AppDir, Path);
      Delete(Path, Index-1, Length(AppDir)+1);
      RegWriteStringValue(HKEY_LOCAL_MACHINE,
        'SYSTEM\CurrentControlSet\Control\Session Manager\Environment\',
        'Path', Path);
    end;
  end;
end;
