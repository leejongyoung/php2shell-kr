# Real-Windows check of Test-TrustedPath in quickcheck/php2shell-quickcheck.ps1 (the .bat embeds the same function).
# The PowerShell harness only injects fake ACLs; this uses real icacls state, like tests/windows_acl_check.py does for the Python tool.
# Run on a disposable elevated Windows machine: powershell -NoProfile -ExecutionPolicy Bypass -File tests\windows_ps1_acl_check.ps1
# Messages are ASCII so Windows PowerShell 5.1 can parse this file without a BOM.
$ErrorActionPreference = 'Stop'
$Repo = Split-Path -Parent $PSScriptRoot
. (Join-Path $Repo 'quickcheck\php2shell-quickcheck.ps1')   # the script returns early when dot-sourced, leaving only the functions

$script:Failures = 0
function Check([bool]$Actual, [bool]$Expected, [string]$Name) {
    if ($Actual -eq $Expected) { Write-Host "PASS $Name (actual=$Actual)" }
    else { Write-Host "FAIL $Name (actual=$Actual expected=$Expected)"; $script:Failures++ }
}
function Icacls { param([string[]]$IcaclsArgs) & "$env:SystemRoot\System32\icacls.exe" @IcaclsArgs | Out-Null; if ($LASTEXITCODE -ne 0) { throw "icacls failed: $IcaclsArgs" } }

$cmd = Join-Path $env:SystemRoot 'System32\cmd.exe'
$base = 'C:\p2s-ps1-acl'
if (Test-Path $base) { Remove-Item $base -Recurse -Force }
New-Item -ItemType Directory $base | Out-Null

function New-Exe([string]$Dir) {
    New-Item -ItemType Directory -Force $Dir | Out-Null
    $target = Join-Path $Dir 'php.exe'
    Copy-Item $cmd $target
    return $target
}

Check (Test-TrustedPath $cmd) $true 'System32\cmd.exe is trusted (default C:\ has Authenticated Users:(AD))'

# Everyone can write the folder
$openDir = Join-Path $base 'open'
$openExe = New-Exe $openDir
Icacls @($openDir, '/grant', '*S-1-1-0:(OI)(CI)F')
Check (Test-TrustedPath $openExe) $false 'file in an Everyone-writable folder is not trusted'

# Administrators/SYSTEM only: owner, no inheritance
$lockedDir = Join-Path $base 'locked'
$lockedExe = New-Exe $lockedDir
foreach ($target in @($lockedDir, $lockedExe, $base)) {
    Icacls @($target, '/setowner', '*S-1-5-32-544')
    Icacls @($target, '/inheritance:r')
    Icacls @($target, '/grant:r', '*S-1-5-32-544:(OI)(CI)F', '*S-1-5-18:(OI)(CI)F')
}
Check (Test-TrustedPath $lockedExe) $true 'file in an Administrators/SYSTEM-only folder is trusted'

# app folder: Users may create files there (DLL planting)
Icacls @($lockedDir, '/grant', '*S-1-5-32-545:(WD)')
Check (Test-TrustedPath $lockedExe) $false 'Users can create files in the app folder: not trusted'
Icacls @($lockedDir, '/remove:g', '*S-1-5-32-545')
Check (Test-TrustedPath $lockedExe) $true 'app folder rights restored: trusted again'

# parent folder: create-only right is ignored, delete-child is not
Icacls @($base, '/grant', '*S-1-5-11:(AD)')
Check (Test-TrustedPath $lockedExe) $true 'Authenticated Users:(AD) on a parent folder is ignored'
Icacls @($base, '/grant', '*S-1-5-11:(DC)')
Check (Test-TrustedPath $lockedExe) $false 'Authenticated Users:(DC) on a parent folder: not trusted'
Icacls @($base, '/remove:g', '*S-1-5-11')

# links: this implementation refuses any reparse point on the path (the Python tool resolves it first)
$junction = Join-Path $base 'junction'
cmd.exe /c mklink /J $junction $lockedDir | Out-Null
Check (Test-TrustedPath (Join-Path $junction 'php.exe')) $false 'path through a junction is not trusted'

Remove-Item $base -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "failures: $script:Failures"
if ($script:Failures -gt 0) { exit 1 }
exit 0
