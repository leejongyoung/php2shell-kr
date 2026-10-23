# Real-Windows checks that containers cannot do (run on a disposable Windows Server / windows-latest runner, elevated).
#   1) IIS: virtual-patch web.config (multipart block + request size limit) really returns 403 / 404.13, and rolls back
#   2) IIS FastCGI: a real php-cgi.exe behind IIS is found as running by the Python tool; documented iisreset /stop,/start work
#   3) Patch plan: the generated patch-plan.ps1 evidence step (icacls, Get-Process, Get-NetTCPConnection, SHA256) really runs
#   4) Console code page 949: output stays byte-identical valid UTF-8 (Python tool and the single-file .bat)
# Usage: pwsh -File tests/windows_iis_check.ps1 [-PhpDir C:\php-fixed]
# Messages are ASCII on purpose so Windows PowerShell 5.1 can parse this file without a BOM.
param([string]$PhpDir = 'C:\php-fixed')

$ErrorActionPreference = 'Stop'
$Repo = Split-Path -Parent $PSScriptRoot
$script:Failures = 0
function Pass([string]$m) { Write-Host "PASS $m" }
function Fail([string]$m) { Write-Host "FAIL $m"; $script:Failures++ }
function Check([bool]$ok, [string]$m) { if ($ok) { Pass $m } else { Fail $m } }

function Send-Post([string]$Url, $Content) {
    $client = New-Object System.Net.Http.HttpClient
    $client.Timeout = [TimeSpan]::FromSeconds(60)
    try { return [int]($client.PostAsync($Url, $Content).GetAwaiter().GetResult().StatusCode) }
    finally { $client.Dispose() }
}
function Multipart-Content {
    $c = New-Object System.Net.Http.MultipartFormDataContent
    $c.Add((New-Object System.Net.Http.StringContent('a')), 'f')
    return $c
}
function Form-Content([int]$Bytes) {
    return New-Object System.Net.Http.StringContent(('a=' + ('b' * $Bytes)), [Text.Encoding]::ASCII, 'application/x-www-form-urlencoded')
}

# ---------------------------------------------------------------- IIS install
Write-Host '== install IIS + URL Rewrite'
Install-WindowsFeature -Name Web-Server, Web-CGI, Web-Mgmt-Tools | Out-Null
choco install urlrewrite -y --no-progress | Out-Null
$global:LASTEXITCODE = 0
Start-Service W3SVC
$appcmd = Join-Path $env:SystemRoot 'System32\inetsrv\appcmd.exe'
$wwwroot = 'C:\inetpub\wwwroot'
if (-not (Test-Path (Join-Path $wwwroot 'iisstart.htm'))) { Set-Content (Join-Path $wwwroot 'iisstart.htm') 'iis' }
Check (Test-Path 'C:\Windows\System32\inetsrv\config\applicationHost.config') 'applicationHost.config exists (tool uses this path to detect IIS)'

# ---------------------------------------------------------------- 1) web.config virtual patch
Write-Host '== IIS web.config virtual patch'
$out = Join-Path $env:TEMP ('p2s-vp-' + [guid]::NewGuid().ToString('N'))
python "$Repo\php2shell_triage.py" --emit-virtual-patch $out --uploads no 2>&1 | Out-Null
$rule = [xml](Get-Content (Join-Path $out 'iis\web.config.block-multipart.xml') -Raw -Encoding UTF8)
$snip = [xml](Get-Content (Join-Path $out 'iis\web.config.snippet.xml') -Raw -Encoding UTF8)
$merged = [xml]'<?xml version="1.0" encoding="utf-8"?><configuration><system.webServer/></configuration>'
$target = $merged.SelectSingleNode('/configuration/system.webServer')
foreach ($doc in @($rule, $snip)) {
    foreach ($node in @($doc.SelectSingleNode('/configuration/system.webServer').ChildNodes)) {
        [void]$target.AppendChild($merged.ImportNode($node, $true))
    }
}
$webConfig = Join-Path $wwwroot 'web.config'
Remove-Item $webConfig -ErrorAction SilentlyContinue
$url = 'http://localhost/iisstart.htm'
$baseline = Send-Post $url (Multipart-Content)
Check ($baseline -ne 403) "baseline: multipart POST without the rule is not 403 (got $baseline)"

$merged.Save($webConfig)
$mp = Send-Post $url (Multipart-Content)
Check ($mp -eq 403) "multipart POST is blocked with 403 after merging web.config (got $mp)"
$small = Send-Post $url (Form-Content 100)
Check ($small -ne 403 -and $small -ne 404) "small urlencoded POST is not blocked (got $small)"
$limit = [int](([regex]::Match((Get-Content $webConfig -Raw), 'maxAllowedContentLength="(\d+)"')).Groups[1].Value)
Check ($limit -eq 8388608) "maxAllowedContentLength substituted to 8388608 (got $limit)"
$big = Send-Post $url (Form-Content ($limit + 1024))
Check ($big -eq 404) "request above maxAllowedContentLength is rejected (IIS 404.13) (got $big)"

Remove-Item $webConfig
$after = Send-Post $url (Multipart-Content)
Check ($after -ne 403) "rollback: after deleting web.config multipart is no longer 403 (got $after)"

# ---------------------------------------------------------------- 2) IIS FastCGI + real php-cgi
Write-Host '== IIS FastCGI with real php-cgi'
$phpCgi = Join-Path $PhpDir 'php-cgi.exe'
if (Test-Path $phpCgi) {
    & $appcmd set config /section:system.webServer/fastCgi "/+[fullPath='$phpCgi']" | Out-Null
    & $appcmd set config /section:system.webServer/handlers "/+[name='PHP_via_FastCGI',path='*.php',verb='*',modules='FastCgiModule',scriptProcessor='$phpCgi',resourceType='Either']" | Out-Null
    Set-Content (Join-Path $wwwroot 'v.php') '<?php echo "php-", PHP_VERSION;'
    $body = (Invoke-WebRequest 'http://localhost/v.php' -UseBasicParsing).Content
    Check ($body -like 'php-8.4.*') "IIS serves PHP through FastCGI ($body)"
    $before = Get-Process php-cgi -ErrorAction SilentlyContinue | Select-Object -First 1
    Check ($null -ne $before) 'php-cgi.exe is running under IIS'

    $json = python "$Repo\php2shell_triage.py" --json --no-response | Out-String
    $data = $json | ConvertFrom-Json
    $row = @($data.installations | Where-Object { $_.path -like "$PhpDir*php-cgi.exe" -and $_.running })
    Check ($row.Count -ge 1) 'tool reports the IIS-hosted php-cgi.exe as running'
    if ($row.Count -ge 1) { Write-Host ("  pids: " + ($row[0].pids -join ',')) }

    $startBefore = $before.StartTime
    & "$env:SystemRoot\System32\iisreset.exe" /stop | Out-Null
    Check ($LASTEXITCODE -eq 0) 'iisreset /stop (command from the patch plan) succeeded'
    Start-Sleep -Seconds 3
    Check (-not (Get-Process php-cgi, w3wp -ErrorAction SilentlyContinue)) 'no php-cgi/w3wp left after iisreset /stop'
    & "$env:SystemRoot\System32\iisreset.exe" /start | Out-Null
    Check ($LASTEXITCODE -eq 0) 'iisreset /start succeeded'
    $body2 = (Invoke-WebRequest 'http://localhost/v.php' -UseBasicParsing).Content
    $after = Get-Process php-cgi -ErrorAction SilentlyContinue | Select-Object -First 1
    Check ($null -ne $after -and $after.StartTime -gt $startBefore) "php-cgi restarted with a newer StartTime ($body2)"
} else {
    Fail "php-cgi.exe not found at $phpCgi"
}

# ---------------------------------------------------------------- 3) patch plan evidence step
Write-Host '== patch-plan.ps1 evidence step'
$planDir = Join-Path $env:TEMP ('p2s-plan-' + [guid]::NewGuid().ToString('N'))
python "$Repo\php2shell_triage.py" --emit-patch-plan $planDir --no-response 2>&1 | Out-Null
$plan = Join-Path $planDir 'patch-plan.ps1'
Check (Test-Path $plan) 'patch-plan.ps1 generated'
if (Test-Path $plan) {
    $work = Join-Path $env:TEMP ('p2s-run-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory $work | Out-Null
    Push-Location $work
    try {
        $env:PHP2SHELL_I_REVIEWED = 'yes'
        # answer y to step 0 (evidence), n to the rest
        $answers = @('y') + (1..20 | ForEach-Object { 'n' })
        $answers | & powershell -NoProfile -ExecutionPolicy Bypass -File $plan 2>&1 | Out-Host
        Check ($LASTEXITCODE -eq 0) "patch-plan.ps1 exit code ($LASTEXITCODE)"
        $ev = Get-ChildItem -Directory -Filter 'php2shell-evidence-*' | Select-Object -First 1
        Check ($null -ne $ev) 'evidence folder created'
        if ($ev) {
            foreach ($f in 'processes.csv', 'tcp.csv', 'SHA256.csv') { Check (Test-Path (Join-Path $ev.FullName $f)) "evidence file $f exists" }
            $acl = (& "$env:SystemRoot\System32\icacls.exe" $ev.FullName) -join "`n"
            Write-Host $acl
            Check ($acl -match 'BUILTIN\\Administrators' -and $acl -match 'NT AUTHORITY\\SYSTEM') 'evidence folder ACL has Administrators and SYSTEM'
            Check ($acl -notmatch 'Everyone|BUILTIN\\Users|Authenticated Users') 'evidence folder ACL has no Everyone/Users/Authenticated Users'
        }
    } finally { Pop-Location; Remove-Item Env:\PHP2SHELL_I_REVIEWED -ErrorAction SilentlyContinue }
}

# ---------------------------------------------------------------- 4) code page 949
Write-Host '== console code page 949'
function Check-Utf8File([string]$Path, [string]$Label) {
    $bytes = [IO.File]::ReadAllBytes($Path)
    Check ($bytes.Length -gt 0) "$Label produced output ($($bytes.Length) bytes)"
    $strict = New-Object System.Text.UTF8Encoding($false, $true)
    try { $text = $strict.GetString($bytes) } catch { Fail "$Label output is not valid UTF-8 under chcp 949"; return }
    Check ($text -match '[\uAC00-\uD7A3]') "$Label output contains Hangul as UTF-8 (no mojibake)"
    Check (-not ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)) "$Label output has no BOM"
}
$tmp949 = Join-Path $env:TEMP 'p2s-cp949'
New-Item -ItemType Directory -Force $tmp949 | Out-Null
$py949 = Join-Path $tmp949 'py.txt'
& cmd.exe /c "chcp 949 >nul & python `"$Repo\php2shell_triage.py`" --no-response > `"$py949`" 2>&1"
Check-Utf8File $py949 'python tool'
python "$Repo\tools\build_dist.py" --out (Join-Path $tmp949 'dist') 2>&1 | Out-Null
$bat = (Get-ChildItem (Join-Path $tmp949 'dist') -Recurse -Filter 'php2shell-quickcheck.bat' | Select-Object -First 1).FullName
$bat949 = Join-Path $tmp949 'bat.txt'
$env:P2S_NOPAUSE = '1'
& cmd.exe /c "chcp 949 >nul & `"$bat`" > `"$bat949`" 2>&1"
Check-Utf8File $bat949 'single-file .bat'

Write-Host "failures: $script:Failures"
if ($script:Failures -gt 0) { exit 1 }
exit 0
