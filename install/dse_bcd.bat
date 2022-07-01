@echo off
bcdedit /copy {current} /d "STrace (Press F8 to disable DSE)"
For /F "tokens=2 delims={}" %%i in ('bcdedit.exe') do (set _NEWGUID=%%i)
echo {%_NEWGUID%}
bcdedit /displayorder {%_NEWGUID%} /addlast
bcdedit /set {%_NEWGUID%} nointegritychecks on
bcdedit /set {%_NEWGUID%} debug off
bcdedit /set "{current}" bootmenupolicy legacy
bcdedit /set {bootmgr} displaybootmenu yes