$ScriptDir = Split-Path $script:MyInvocation.MyCommand.Path
Write-Host "STrace Install: Root - $ScriptDir"

$apisetReg = join-path -path $ScriptDir -childpath "STraceApiSet.reg"
$driverReg = join-path -path $ScriptDir -childpath "STraceDriver.reg"

Write-Host "$apisetReg $driverReg"

reg import $apisetReg
reg import $driverReg

$windir = $env:windir

# apiset dlls are signed, and this one says filename must be dtrace.sys
Copy-Item -Path $(join-path -path $ScriptDir -childpath "STraceSchemaSetFrwd.dll") -Destination "$windir\system32\" -force
Copy-Item -Path $(join-path -path $ScriptDir -childpath "STrace.sys") -Destination "$windir\system32\drivers\dtrace.sys" -force

BCDEDIT /set TESTSIGNING on
BCDEDIT /set dtrace on
Start-Process -FilePath .\dse_bcd.bat -Wait -passthru
