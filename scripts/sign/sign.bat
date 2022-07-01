@echo off
set path=C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Tools\MSVC\14.28.29333\bin\Hostx64\x64;C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x64;%path%
set bin_path=D:\repos\STrace\bin

title Compiling STrace, 64-Bit Windows
echo Project: STrace
echo Platform: 64-Bit Windows
echo Preset: Release Build
echo Author: stevemk14ebr
pause

echo ============ Code Signing Driver ============
signtool sign /v /f %cert_path_pfx% /p %cert_password% %bin_path%\STrace.sys

echo ============ Copying to VM share ============
copy /y %bin_path%\STrace.sys F:\vmshare\STrace.sys
copy /y %bin_path%\STrace.pdb F:\vmshare\STrace.pdb

pause