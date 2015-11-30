calldll kernel32.dll GetComputerNameExW int:3 out-wstr inout-plen:100
calldll kernel32.dll GetDiskFreeSpaceW wstr:C:\ out-pint out-pint out-pint out-pint

calldll user32.dll SendNotifyMessageW int:0xffff int:0x1A int:0 wstr:Environment

calldll user32.dll FindWindowW int:0 int:0
calldll user32.dll GetWindowTextW int:266406 out-wstr len:100

calldll user32.dll AllowSetForegroundWindow int:0xffffffff

calldll user32.dll EnumWindows callback:int,int:0 int:0x100
calldll psapi.dll EnumProcesses out-buffer:532 len:532 out-pint
calldll kernel32.dll EnumUILanguagesW callback:wstr,int:1 int:0x28 int:0

calldll kernel32.dll Sleep int:2000 >nul

calldll shell32.dll ShellExecuteA int:0 str:runas str:cmd.exe int:0 int:0 int:5



