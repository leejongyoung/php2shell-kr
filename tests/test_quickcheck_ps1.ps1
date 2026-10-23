<#
.SYNOPSIS
  quickcheck/php2shell-quickcheck.ps1 테스트 하네스 (Windows PowerShell 5.1 / PowerShell 7+, Linux/macOS pwsh 모두 가능).

.DESCRIPTION
  실행:  pwsh -NoProfile -File tests/test_quickcheck_ps1.ps1
  실패가 하나라도 있으면 종료 코드 1 로 끝납니다.

  fixture 규칙(테스트 전용): -Root <디렉터리> 를 쓰면 점검 대상이 실제 PHP 바이너리가 아니라 빈 파일일 수 있으므로
  각 PHP 디렉터리의 `php.version` 텍스트 파일(첫 비어 있지 않은 줄)을 버전 문자열로 우선 읽습니다. 이 훅은 -Root 가
  있을 때만 동작합니다. -Root 에서는 기본적으로 트리 안 실행 파일을 실행하지 않으며(파일 버전정보/바이너리 문자열 기반),
  신뢰할 수 있는 트리에서만 -Exec 를 함께 주면 실행합니다(이 하네스의 -Exec 테스트는 Linux/macOS 셸 스크립트로만 수행).
  이 하네스는 취약점을 재현하는 어떤 입력도 만들지 않습니다(버전 문자열과 설정 파일만 사용).

  이 파일은 한글을 포함하므로 UTF-8 (BOM 포함)으로 저장하세요.
#>
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
$script:QcPath = Join-Path $script:RepoRoot 'quickcheck/php2shell-quickcheck.ps1'
$script:VecPath = Join-Path $script:RepoRoot 'tests/vectors/versions.json'
$script:AdvPath = Join-Path $script:RepoRoot 'data/advisory.json'
$script:Passed = 0
$script:Failed = 0
$script:TmpDirs = New-Object 'System.Collections.Generic.List[string]'

function Assert-True {
    param($Condition, [string]$Message)
    if ($Condition) { $script:Passed++ } else { $script:Failed++; [Console]::Error.WriteLine('FAIL: ' + $Message) }
}

function Assert-Eq {
    param($Actual, $Expected, [string]$Message)
    if ($Actual -eq $Expected) { $script:Passed++ }
    else { $script:Failed++; [Console]::Error.WriteLine(('FAIL: {0} (실제=[{1}] 기대=[{2}])' -f $Message, $Actual, $Expected)) }
}

function New-TmpDir {
    $d = Join-Path ([System.IO.Path]::GetTempPath()) ('p2s-ps1-' + [guid]::NewGuid().ToString('N'))
    [void](New-Item -ItemType Directory -Path $d)
    $script:TmpDirs.Add($d)
    return $d
}

function Add-TestFile {
    param([string]$Base, [string]$Rel, [string]$Content)
    $p = Join-Path $Base $Rel
    $dir = Split-Path -Parent $p
    if (-not (Test-Path -LiteralPath $dir)) { [void](New-Item -ItemType Directory -Path $dir -Force) }
    [System.IO.File]::WriteAllText($p, $Content)
}

function Add-PhpDir {
    # 빈 php-cgi.exe/php.exe 와 php.version 을 만든다.
    param([string]$Base, [string]$Rel, [string]$Version, [string[]]$Extra = @())
    Add-TestFile $Base ($Rel + '/php-cgi.exe') ''
    Add-TestFile $Base ($Rel + '/php.exe') ''
    Add-TestFile $Base ($Rel + '/php.version') ($Version + "`n")
    foreach ($e in $Extra) { Add-TestFile $Base ($Rel + '/' + $e) '' }
}

# 테스트 대상을 자식 프로세스로 실행 (실제 CLI 경로 검증)
$script:HostExe = (Get-Process -Id $PID).Path

function Invoke-Qc {
    param([string[]]$QcArgs)
    $a = New-Object 'System.Collections.Generic.List[string]'
    $a.Add('-NoProfile')
    if ($script:OnWindows) { $a.Add('-ExecutionPolicy'); $a.Add('Bypass') }
    $a.Add('-File'); $a.Add($script:QcPath)
    foreach ($x in $QcArgs) { $a.Add($x) }
    $out = & $script:HostExe @($a.ToArray()) 2>$null
    $code = $LASTEXITCODE
    return [pscustomobject]@{ Code = [int]$code; Text = (@($out) -join "`n") }
}

function Invoke-QcJson {
    param([string]$FixtureRoot, [string[]]$Extra = @())
    $r = Invoke-Qc (@('-Json', '-Root', $FixtureRoot) + $Extra)
    $obj = $null
    try { $obj = ConvertFrom-Json -InputObject $r.Text } catch { $obj = $null }
    return [pscustomobject]@{ Code = $r.Code; Text = $r.Text; Obj = $obj }
}

function Get-InstList {
    param($Obj)
    return ,@($Obj.installations | Where-Object { $null -ne $_ })
}

function Invoke-ChildStdinClosed {
    # 생성된 계획 스크립트를 stdin 을 닫은 자식 프로세스로 실행(Read-Host 가 대기하지 않도록). 확인 질문은 모두 '아니오'가 된다.
    param([string]$ScriptPath, [hashtable]$EnvVars)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $script:HostExe
    $argText = '-NoProfile'
    if ($script:OnWindows) { $argText = $argText + ' -ExecutionPolicy Bypass' }
    $psi.Arguments = $argText + ' -File "' + $ScriptPath + '"'
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.StandardOutputEncoding = New-Object System.Text.UTF8Encoding($false)
    [void]$psi.EnvironmentVariables.Remove('PHP2SHELL_I_REVIEWED')
    foreach ($k in $EnvVars.Keys) { $psi.EnvironmentVariables[[string]$k] = [string]$EnvVars[$k] }
    $p = [System.Diagnostics.Process]::Start($psi)
    $p.StandardInput.Close()
    $so = $p.StandardOutput.ReadToEndAsync()
    $se = $p.StandardError.ReadToEndAsync()
    if (-not $p.WaitForExit(60000)) {
        try { $p.Kill() } catch { }
        return [pscustomobject]@{ Code = -1; Text = '' }
    }
    $p.WaitForExit()
    return [pscustomobject]@{ Code = [int]$p.ExitCode; Text = [string]$so.Result }
}

function Test-PlanFile {
    param([string]$Path, [string]$Label)
    Assert-True (Test-Path -LiteralPath $Path -PathType Leaf) ($Label + ': 계획 파일 생성')
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    Assert-True ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) ($Label + ': 계획 파일 UTF-8 BOM')
    $tokens = $null; $perrs = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$perrs)
    Assert-Eq @($perrs).Count 0 ($Label + ': 계획 파일 구문 오류 없음')
    foreach ($pe in @($perrs)) { [Console]::Error.WriteLine('  파싱 오류: ' + $pe.Message + ' (줄 ' + $pe.Extent.StartLineNumber + ')') }
    $g = Invoke-ChildStdinClosed $Path @{}
    Assert-Eq $g.Code 64 ($Label + ': 가드(PHP2SHELL_I_REVIEWED 없음) 종료 코드 64')
    Assert-True ($g.Text.Contains('PHP2SHELL_I_REVIEWED')) ($Label + ': 가드 메시지')
    $y = Invoke-ChildStdinClosed $Path @{ PHP2SHELL_I_REVIEWED = 'yes' }
    Assert-Eq $y.Code 65 ($Label + ': 증거 확인 단계에서 답이 없으면 종료 코드 65(아무것도 실행 안 함)')
    Assert-True ($y.Text.Contains('KISA 118')) ($Label + ': 0단계 증거 보존 안내 출력')
}

function Test-NoteMatch {
    param($Inst, [string]$Pattern)
    foreach ($n in @($Inst.notes)) { if ([string]$n -match $Pattern) { return $true } }
    return $false
}

try {
    # -----------------------------------------------------------------------
    # 0. 정적 점검: BOM / 파싱 / PowerShell 7 전용 문법 없음
    # -----------------------------------------------------------------------
    foreach ($f in @($script:QcPath, $PSCommandPath)) {
        $bytes = [System.IO.File]::ReadAllBytes($f)
        Assert-True ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) ('UTF-8 BOM 필요(Windows PowerShell 5.1 한글 호환): ' + $f)
        $tokens = $null; $perrs = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($f, [ref]$tokens, [ref]$perrs)
        Assert-Eq @($perrs).Count 0 ('구문 오류 없음: ' + $f)
        $badKinds = @('QuestionQuestion', 'QuestionQuestionEquals', 'QuestionDot', 'QuestionLBracket', 'Question', 'AndAnd', 'OrOr')
        foreach ($t in @($tokens)) {
            Assert-True ($badKinds -notcontains $t.Kind.ToString()) ('PS7 전용 연산자 사용 금지: {0} 줄 {1} {2}' -f $f, $t.Extent.StartLineNumber, $t.Kind)
        }
        foreach ($n in @($ast.FindAll({ param($x) $true }, $true))) {
            $tn = $n.GetType().Name
            Assert-True ($tn -notmatch '^(TernaryExpressionAst|PipelineChainAst|NullConditional\w*)$') ('PS7 전용 구문 금지: {0} 줄 {1} {2}' -f $f, $n.Extent.StartLineNumber, $tn)
            if ($n -is [System.Management.Automation.Language.CommandParameterAst]) {
                Assert-True (@('Parallel', 'AsHashtable', 'AsByteStream', 'SkipHttpErrorCheck', 'SkipCertificateCheck', 'ThrottleLimit') -notcontains $n.ParameterName) ('PS7 전용 파라미터 금지: {0} 줄 {1} -{2}' -f $f, $n.Extent.StartLineNumber, $n.ParameterName)
            }
            if ($n -is [System.Management.Automation.Language.CommandAst]) {
                $cn = $n.GetCommandName()
                if ($cn) { Assert-True (@('Join-String', 'Get-Error', 'Test-Json', 'ConvertFrom-Markdown', 'Remove-Alias') -notcontains $cn) ('PS7 전용 cmdlet 금지: {0} 줄 {1} {2}' -f $f, $n.Extent.StartLineNumber, $cn) }
            }
            if ($n -is [System.Management.Automation.Language.VariableExpressionAst]) {
                $vn = $n.VariablePath.UserPath
                if ($vn -in @('IsWindows', 'IsLinux', 'IsMacOS', 'PSStyle')) {
                    $lineText = (Get-Content -LiteralPath $f)[$n.Extent.StartLineNumber - 1]
                    Assert-True ($lineText -match 'PSVersion') ('${0} 는 PSVersion 가드와 같은 줄에서만 사용: {1} 줄 {2}' -f $vn, $f, $n.Extent.StartLineNumber)
                }
            }
        }
    }

    # -----------------------------------------------------------------------
    # 1. 함수 단위 테스트 (도트 소싱)
    # -----------------------------------------------------------------------
    . $script:QcPath
    if ($script:OnWindows) { try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch { } }

    $vec = Get-Content -LiteralPath $script:VecPath -Raw | ConvertFrom-Json
    $adv = Get-Content -LiteralPath $script:AdvPath -Raw | ConvertFrom-Json
    $caseCount = 0
    foreach ($c in @($vec.cases)) {
        $caseCount++
        $got = Get-PhpClass ([string]$c.version)
        Assert-Eq $got ([string]$c.class) ('Get-PhpClass [{0}]' -f $c.version)
    }
    Assert-True ($caseCount -ge 40) 'versions.json 케이스가 충분히 읽혀야 함'

    # CLI 경로(-Classify) 로도 비어 있지 않은 모든 케이스 검증. (빈 인자는 5.1 에서 전달 중 사라지므로 공백 한 칸으로 대체)
    foreach ($c in @($vec.cases)) {
        $v = [string]$c.version
        if ($v.Length -eq 0) { $v = ' ' }
        $r = Invoke-Qc @('-Classify', $v)
        Assert-Eq $r.Text.Trim() ([string]$c.class) ('-Classify [{0}]' -f $c.version)
        Assert-Eq $r.Code 0 ('-Classify 종료 코드 [{0}]' -f $c.version)
    }

    Assert-Eq (ConvertFrom-PhpVersion 'PHP 8.2.35.0 (cli)').Text '8.2.35' '4번째 성분 제거'
    Assert-Eq (ConvertFrom-PhpVersion '8.6.0RC3').Text '8.6.0RC3' '프리릴리스 표기 보존'
    Assert-Eq (ConvertFrom-PhpVersion '8.4.27-1+deb12u1').Text '8.4.27' 'deb 접미사는 프리릴리스 아님'
    Assert-Eq (Get-Verdict 'fixed' 'unknown') 'fixed' 'verdict fixed'
    Assert-Eq (Get-Verdict 'eol_backport' 'yes') 'vendor_patched' 'verdict vendor_patched'
    Assert-Eq (Get-Verdict 'eol_no_fix' 'unknown') 'vulnerable' 'verdict eol_no_fix -> vulnerable'
    Assert-Eq (Get-Verdict 'old_unsupported' 'yes') 'eol' 'verdict eol'
    Assert-Eq (Get-Verdict 'unknown' 'unknown') 'unknown' 'verdict unknown'

    # advisory.json 일치 검사
    Assert-Eq $script:AsOf ([string]$adv.as_of) 'as_of 일치'
    Assert-Eq (@($script:Cves) -join ',') (@($adv.cves) -join ',') 'CVE 목록 일치'
    foreach ($p in $adv.fixed_releases.PSObject.Properties) {
        Assert-True ($script:FixedReleases.Contains($p.Name) -and $script:FixedReleases[$p.Name] -eq [string]$p.Value) ('fixed_releases 일치: ' + $p.Name)
    }
    Assert-Eq @($script:FixedReleases.Keys).Count @($adv.fixed_releases.PSObject.Properties).Count 'fixed_releases 개수 일치'
    Assert-Eq @($script:Sources).Count @($adv.sources).Count 'sources 개수 일치'
    $srcIdx = 0
    foreach ($s in @($adv.sources)) {
        $mine = $script:Sources[$srcIdx]
        Assert-Eq $mine.id ([string]$s.id) ('source id 일치 #' + $srcIdx)
        Assert-Eq $mine.url ([string]$s.url) ('source url 일치 ' + $s.id)
        Assert-Eq $mine.title ([string]$s.title) ('source title 일치 ' + $s.id)
        $srcIdx++
    }
    Assert-True ($script:MemoryLimitWarning -match 'RLIMIT') 'memory_limit 경고에 RLIMIT 언급'
    Assert-Eq $script:AutoStartWarning ([string](@($adv.interim_mitigation.settings | Where-Object { $_.key -eq 'session.auto_start' })[0].warning_ko)) 'session.auto_start 경고 문구 일치'

    # 재시작 판정
    $now = Get-Date
    Assert-Eq (Get-RestartState @([pscustomobject]@{ StartTime = $now.AddHours(-3) }) $now.AddHours(-1)) $true '이전 시작 프로세스 -> true'
    Assert-Eq (Get-RestartState @([pscustomobject]@{ StartTime = $now.AddHours(-1) }) $now.AddHours(-3)) $false '이후 시작 프로세스 -> false'
    Assert-Eq (Get-RestartState @([pscustomobject]@{ StartTime = $now.AddHours(-1) }, [pscustomobject]@{ StartTime = $now.AddHours(-5) }) $now.AddHours(-3)) $true '하나라도 이전이면 true'
    Assert-True ($null -eq (Get-RestartState @([pscustomobject]@{ StartTime = $null }) $now)) '시작 시각 불명 -> null'
    Assert-True ($null -eq (Get-RestartState @([pscustomobject]@{ StartTime = $now }) $null)) '파일 시각 불명 -> null'
    Assert-Eq (Get-RestartState @() $now) $false '프로세스 없음 -> false'
    Assert-Eq (Get-RestartState $null $now) $false '프로세스 null -> false'

    # php.ini 정적 파싱
    $iniDir = New-TmpDir
    Add-TestFile $iniDir 'php.ini' "; comment`n[PHP]`nmemory_limit = 128M`nsession.upload_progress.enabled = `"0`" ; 끔`npost_max_size=8M`nmemory_limit = -1`nsession.auto_start = Off`n"
    $set = @{}
    Assert-True (Read-IniSettings (Join-Path $iniDir 'php.ini') $set) 'Read-IniSettings 성공'
    Assert-Eq $set['memory_limit'] '-1' 'ini 마지막 값 우선'
    Assert-Eq $set['session.upload_progress.enabled'] '0' 'ini 따옴표/주석 제거'
    Assert-Eq $set['post_max_size'] '8M' 'ini 공백 없는 ='
    Assert-True (Test-IniOff 'Off') 'Test-IniOff Off'
    Assert-True (-not (Test-IniOff '1')) 'Test-IniOff 1'

    # -----------------------------------------------------------------------
    # 2. fixture 통합 테스트 (-Root, 자식 프로세스, -Json)
    # -----------------------------------------------------------------------
    # 2-1 빈 루트
    $fx = New-TmpDir
    $r = Invoke-QcJson $fx
    Assert-Eq $r.Code 0 '빈 루트 종료 코드 0'
    Assert-True ($null -ne $r.Obj) '빈 루트 JSON 파싱'
    if ($null -ne $r.Obj) {
        Assert-Eq (Get-InstList $r.Obj).Count 0 '빈 루트 설치 0'
        Assert-Eq $r.Obj.tool 'php2shell-quickcheck-ps1' 'tool 이름'
        Assert-Eq $r.Obj.as_of '2026-10-23' 'as_of'
        Assert-Eq $r.Obj.exit_code 0 'JSON exit_code'
        Assert-Eq $r.Obj.summary.vulnerable 0 '요약 vulnerable 0'
        Assert-True ([bool]$r.Obj.host) 'host 존재'
        Assert-True ([bool]$r.Obj.platform) 'platform 존재'
    }

    # 2-2 취약 CGI (C:\php)
    $fx = New-TmpDir
    Add-PhpDir $fx 'php' '8.4.26'
    $r = Invoke-QcJson $fx @('-NoExec')
    Assert-Eq $r.Code 1 '8.4.26 종료 코드 1'
    if ($null -ne $r.Obj) {
        $i = Get-InstList $r.Obj
        Assert-Eq $i.Count 1 '8.4.26 설치 1'
        Assert-Eq $i[0].version '8.4.26' '8.4.26 version'
        Assert-Eq $i[0].class 'vulnerable' '8.4.26 class'
        Assert-Eq $i[0].verdict 'vulnerable' '8.4.26 verdict'
        Assert-Eq $i[0].sapi 'cgi' '8.4.26 sapi cgi'
        Assert-Eq $i[0].running $false '8.4.26 running false'
        Assert-Eq @($i[0].pids).Count 0 '8.4.26 pids 빈 배열'
        Assert-True ($i[0].path -like '*php-cgi.exe') '8.4.26 대표 경로는 php-cgi.exe'
        Assert-Eq $i[0].vendor_patch 'unknown' '8.4.26 vendor_patch unknown'
        Assert-Eq $r.Obj.summary.vulnerable 1 '8.4.26 요약'
        Assert-Eq $r.Obj.exit_code 1 '8.4.26 JSON exit_code'
        Assert-True (Test-NoteMatch $i[0] 'php\.ini') '8.4.26 php.ini 없음 안내'
    }

    # 2-3 수정 버전
    $fx = New-TmpDir
    Add-PhpDir $fx 'php' '8.4.27'
    $r = Invoke-QcJson $fx
    Assert-Eq $r.Code 0 '8.4.27 종료 코드 0'
    if ($null -ne $r.Obj) {
        $i = Get-InstList $r.Obj
        Assert-Eq $i.Count 1 '8.4.27 설치 1'
        Assert-Eq $i[0].verdict 'fixed' '8.4.27 verdict'
        Assert-Eq $r.Obj.summary.fixed 1 '8.4.27 요약 fixed'
    }

    # 2-4 IIS FastCGI 등록 + PHPRC 의 php.ini
    $fx = New-TmpDir
    Add-PhpDir $fx 'php-iis' '8.3.35'
    Add-TestFile $fx 'php-iis/conf/php.ini' "session.upload_progress.enabled = 0`nmemory_limit = 256M`npost_max_size = 100M`n"
    $apphost = @'
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.applicationHost>
    <applicationPools><add name="PhpPool" /></applicationPools>
    <sites><site name="Shop" id="1" /></sites>
  </system.applicationHost>
  <system.webServer>
    <fastCgi>
      <application fullPath="C:\php-iis\php-cgi.exe" arguments="">
        <environmentVariables>
          <environmentVariable name="PHPRC" value="C:\php-iis\conf" />
        </environmentVariables>
      </application>
      <application fullPath="C:\Python\python.exe" />
      <application fullPath="C:\missing-php\php-cgi.exe" />
    </fastCgi>
    <handlers>
      <add name="PHP_via_FastCGI" path="*.php" verb="*" modules="FastCgiModule" scriptProcessor="C:\php-iis\php-cgi.exe|C:\php-iis\php-cgi.exe" resourceType="Either" />
    </handlers>
  </system.webServer>
</configuration>
'@
    Add-TestFile $fx 'Windows/System32/inetsrv/config/applicationHost.config' $apphost
    $r = Invoke-QcJson $fx
    Assert-Eq $r.Code 1 'IIS 8.3.35 종료 코드 1'
    if ($null -ne $r.Obj) {
        $i = Get-InstList $r.Obj
        Assert-Eq $i.Count 1 'IIS 설치 1(중복/비PHP/누락 제외)'
        Assert-Eq $i[0].sapi 'iis' 'IIS sapi'
        Assert-Eq $i[0].verdict 'vulnerable' 'IIS verdict'
        Assert-True (Test-NoteMatch $i[0] 'session\.upload_progress\.enabled = 0\s+\(적용됨\)') 'PHPRC php.ini 의 upload_progress 적용 인식'
        Assert-True (Test-NoteMatch $i[0] 'memory_limit = 256M') 'memory_limit 현재 값 보고'
        Assert-True (Test-NoteMatch $i[0] 'post_max_size = 100M\s+\(8M') 'post_max_size 높음 경고'
        Assert-True (Test-NoteMatch $i[0] 'IIS FastCGI') 'IIS 등록 노트'
        $warnText = (@($r.Obj.warnings) -join "`n")
        Assert-True ($warnText -match 'missing-php') '누락된 FastCGI 경로 경고'
    }
    $fxIis = $fx

    # 2-5 Apache (XAMPP 스타일): Define/ServerRoot/Include/LoadModule/PHPIniDir
    $fx = New-TmpDir
    Add-PhpDir $fx 'xampp/php' '8.2.34' @('php8apache2_4.dll', 'php8ts.dll')
    Add-TestFile $fx 'xampp/php/php.ini' "post_max_size = 2G`nsession.auto_start = 1`n"
    Add-TestFile $fx 'xampp/apache/conf/httpd.conf' "Define SRVROOT `"C:/xampp/apache`"`nServerRoot `"`${SRVROOT}`"`n# LoadModule php_module `"C:/nowhere/php8apache2_4.dll`"`nInclude conf/extra/httpd-xampp.conf`n"
    Add-TestFile $fx 'xampp/apache/conf/extra/httpd-xampp.conf' "LoadModule php_module `"C:/xampp/php/php8apache2_4.dll`"`nPHPIniDir `"C:/xampp/php`"`n"
    $r = Invoke-QcJson $fx
    Assert-Eq $r.Code 1 'Apache 8.2.34 종료 코드 1'
    if ($null -ne $r.Obj) {
        $i = Get-InstList $r.Obj
        Assert-Eq $i.Count 1 'Apache 설치 1'
        Assert-Eq $i[0].sapi 'apache' 'Apache sapi'
        Assert-True ($i[0].path -like '*php8apache2_4.dll') 'Apache 대표 경로는 모듈 DLL'
        Assert-Eq $i[0].verdict 'vulnerable' 'Apache verdict'
        Assert-True (Test-NoteMatch $i[0] 'LoadModule') 'LoadModule 발견 경로 노트'
        Assert-True (Test-NoteMatch $i[0] 'post_max_size = 2G') 'post_max_size 2G 경고'
        Assert-True (Test-NoteMatch $i[0] 'session\.auto_start = 1') 'session.auto_start=1 경고'
        Assert-True (Test-NoteMatch $i[0] '2026-12-31') '8.2 보안 지원 종료 안내'
        Assert-eq (@($r.Obj.warnings) -join '') '' 'Apache fixture 경고 없음'
    }
    $fxApache = $fx

    # 2-6 EOL 분류들
    foreach ($case in @(
            @{ v = '7.4.33'; cls = 'eol_backport'; verdict = 'vulnerable'; code = 1 },
            @{ v = '8.1.35'; cls = 'eol_backport'; verdict = 'vulnerable'; code = 1 },
            @{ v = '5.6.40'; cls = 'eol_no_fix'; verdict = 'vulnerable'; code = 1 },
            @{ v = '5.3.29'; cls = 'old_unsupported'; verdict = 'eol'; code = 1 },
            @{ v = '8.6.0RC3'; cls = 'vulnerable'; verdict = 'vulnerable'; code = 1 },
            @{ v = '8.6.0RC4'; cls = 'fixed'; verdict = 'fixed'; code = 0 },
            @{ v = 'garbage'; cls = 'unknown'; verdict = 'unknown'; code = 3 })) {
        $fx = New-TmpDir
        Add-PhpDir $fx 'php' $case.v
        $r = Invoke-QcJson $fx @('-NoExec')
        Assert-Eq $r.Code $case.code ('종료 코드 ' + $case.v)
        if ($null -ne $r.Obj) {
            $i = Get-InstList $r.Obj
            Assert-Eq $i.Count 1 ('설치 1 ' + $case.v)
            Assert-Eq $i[0].class $case.cls ('class ' + $case.v)
            Assert-Eq $i[0].verdict $case.verdict ('verdict ' + $case.v)
        }
    }

    # 2-7 벤더 패치 증거(NEWS 에 두 CVE 모두): 7.4 + 증거 -> vendor_patched, 종료 코드 0
    $fx = New-TmpDir
    Add-PhpDir $fx 'php' '7.4.33'
    Add-TestFile $fx 'php/news.txt' "Backported fixes: CVE-2026-109618, CVE-2026-109619`n"
    $r = Invoke-QcJson $fx
    Assert-Eq $r.Code 0 '벤더 패치 증거 종료 코드 0'
    if ($null -ne $r.Obj) {
        $i = Get-InstList $r.Obj
        Assert-Eq $i[0].verdict 'vendor_patched' '벤더 패치 verdict'
        Assert-Eq $i[0].vendor_patch 'yes' '벤더 패치 yes'
        Assert-Eq $r.Obj.summary.vendor_patched 1 '요약 vendor_patched'
    }
    # 하나만 언급하면 증거가 아니다
    $fx = New-TmpDir
    Add-PhpDir $fx 'php' '7.4.33'
    Add-TestFile $fx 'php/news.txt' "only CVE-2026-109618 mentioned`n"
    $r = Invoke-QcJson $fx
    Assert-Eq $r.Code 1 'CVE 하나만 언급 -> 증거 아님'

    # 2-8 여러 설치 (WAMP 스타일) 요약 개수
    $fx = New-TmpDir
    Add-PhpDir $fx 'wamp64/bin/php/php8.4.27' '8.4.27'
    Add-PhpDir $fx 'wamp64/bin/php/php8.2.34' '8.2.34'
    Add-PhpDir $fx 'laragon/bin/php/php-8.5.11-nts-Win32-vs17-x64' '8.5.11'
    Add-PhpDir $fx 'Program Files/PHP/v8.3' '8.3.36'
    Add-PhpDir $fx 'Users/alice/scoop/apps/php/current' '8.5.12'
    Add-PhpDir $fx 'Program Files (x86)/Plesk/Additional/PleskPHP83' '8.3.35'
    $r = Invoke-QcJson $fx
    Assert-Eq $r.Code 1 '다중 설치 종료 코드 1'
    if ($null -ne $r.Obj) {
        Assert-Eq (Get-InstList $r.Obj).Count 6 '다중 설치 개수'
        Assert-Eq $r.Obj.summary.vulnerable 3 '다중 요약 vulnerable'
        Assert-Eq $r.Obj.summary.fixed 3 '다중 요약 fixed'
    }

    # 2-9 사람이 읽는 출력 (한글 조치 계획, 증거 보존, 출처)
    $r = Invoke-Qc @('-Root', $fx)
    Assert-Eq $r.Code 1 '텍스트 출력 종료 코드'
    foreach ($needle in @('조치 계획', '증거 보존', 'KISA 118', 'https://boho.or.kr', 'windows.php.net/download', 'Get-FileHash', 'iisreset /stop', 'Stop-Service', 'session.upload_progress.enabled = 0', 'memory_limit = -1', 'RLIMIT_AS', 'fatal_error_backtraces = 0', 'session.auto_start', 'php_admin_value', '.user.ini', '가상 패치', 'virtual-patch/', 'maxAllowedContentLength', 'New-NetFirewallRule', '업데이트만이 근본 조치', '8.2.35 이상', '8.3.36 이상', '8.5.12 이상')) {
        Assert-True ($r.Text.Contains($needle)) ('텍스트 출력에 포함: ' + $needle)
    }
    foreach ($s in $script:Sources) { Assert-True ($r.Text.Contains($s.url)) ('출처 URL 출력: ' + $s.id) }
    Assert-True (-not $r.Text.Contains('[2-오프라인]')) '-Offline 없으면 오프라인 절 없음'
    $r = Invoke-Qc @('-Root', $fx, '-Offline')
    foreach ($needle in @('[2-오프라인]', '이동매체', 'Visual C++', 'Get-FileHash', '.old-')) {
        Assert-True ($r.Text.Contains($needle)) ('-Offline 출력에 포함: ' + $needle)
    }

    # 2-10 -Help / 잘못된 -Root
    $r = Invoke-Qc @('-Help')
    Assert-Eq $r.Code 0 '-Help 종료 코드'
    Assert-True ($r.Text.Contains('-Json') -and $r.Text.Contains('-NoExec') -and $r.Text.Contains('-Root') -and $r.Text.Contains('-Offline')) '-Help 에 옵션 설명'
    Assert-True (-not $r.Text.Contains('-Classify')) '-Classify 는 숨김'
    $r = Invoke-Qc @('-Json', '-Root', (Join-Path $fx 'does-not-exist'))
    Assert-Eq $r.Code 2 '없는 -Root 는 종료 코드 2'

    # 2-11 -PlanFile: 맞춤 조치 계획 파일 (생성만 하고 실행하지 않음)
    $planDir = New-TmpDir
    $pfIis = Join-Path $planDir 'plan-iis.ps1'
    $r = Invoke-QcJson $fxIis @('-PlanFile', $pfIis)
    Assert-Eq $r.Code 1 'PlanFile IIS: 종료 코드는 분석 결과(1) 그대로'
    if ($null -ne $r.Obj) { Assert-Eq $r.Obj.plan_file $pfIis 'JSON plan_file 경로' }
    Test-PlanFile $pfIis 'IIS 계획'
    if (Test-Path -LiteralPath $pfIis) {
        $pt = Get-Content -LiteralPath $pfIis -Raw
        foreach ($needle in @('PHP2SHELL_I_REVIEWED', 'exit 64', 'Confirm-Step', 'Read-Host', 'Invoke-Step', 'iisreset /stop', 'iisreset /start', 'PhpPool', 'Shop', 'php-iis', 'php-cgi')) {
            Assert-True ($pt.Contains($needle)) ('IIS 계획 포함: ' + $needle)
        }
        Assert-True ($pt.IndexOf('exit 64') -lt $pt.IndexOf('function Confirm-Step')) '가드가 파일 맨 앞(함수 정의보다 먼저)'
        Assert-True ($pt.IndexOf('[0단계]') -ge 0 -and $pt.IndexOf('[0단계]') -lt $pt.IndexOf('iisreset /stop')) '증거 보존 단계가 서비스 중지보다 앞'
        Assert-True ($pt.IndexOf('Confirm-Step ''침해 징후') -lt $pt.IndexOf('iisreset /stop')) '증거 확인 질문이 서비스 중지보다 앞'
    }
    $pfAp = Join-Path $planDir 'plan-apache.ps1'
    $r = Invoke-QcJson $fxApache @('-PlanFile', $pfAp)
    Test-PlanFile $pfAp 'Apache 계획'
    if (Test-Path -LiteralPath $pfAp) {
        $pt = Get-Content -LiteralPath $pfAp -Raw
        Assert-True ($pt.Contains('Stop-Service -Name ''Apache2.4''') -and $pt.Contains('Start-Service -Name ''Apache2.4''')) 'Apache 계획: 서비스 중지/시작'
        Assert-True (-not $pt.Contains('iisreset')) 'Apache 계획에는 IIS 단계 없음'
    }
    $pfMulti = Join-Path $planDir 'plan-multi.ps1'
    $r = Invoke-Qc @('-Root', $fx, '-PlanFile', $pfMulti, '-Offline')
    Assert-Eq $r.Code 1 'PlanFile 다중: 종료 코드'
    Assert-True ($r.Text.Contains($pfMulti)) '텍스트 출력에 저장 경로 안내'
    Test-PlanFile $pfMulti '다중 계획'
    if (Test-Path -LiteralPath $pfMulti) {
        $pt = Get-Content -LiteralPath $pfMulti -Raw
        foreach ($needle in @('Rename-Item', 'Expand-Archive', 'Get-FileHash', 'PleskPHP83', '벤더 번들 감지', '오프라인 서버')) {
            Assert-True ($pt.Contains($needle)) ('다중 계획 포함: ' + $needle)
        }
    }
    # 작은따옴표가 든 경로가 계획 스크립트를 깨뜨리지 않는다(리터럴 이스케이프)
    $fxQ = New-TmpDir
    Add-PhpDir $fxQ "php-it's" '8.4.26'
    $pfQ = Join-Path $planDir 'plan-quote.ps1'
    $r = Invoke-Qc @('-Root', $fxQ, '-PlanFile', $pfQ)
    Test-PlanFile $pfQ '따옴표 경로 계획'
    if (Test-Path -LiteralPath $pfQ) { Assert-True ((Get-Content -LiteralPath $pfQ -Raw).Contains("php-it''s")) '작은따옴표 이스케이프' }
    # 조치할 것이 없는 서버: 계획 파일도 유효하고 가드가 동작
    $fxOk = New-TmpDir
    Add-PhpDir $fxOk 'php' '8.4.27'
    $pfOk = Join-Path $planDir 'plan-ok.ps1'
    $r = Invoke-Qc @('-Root', $fxOk, '-PlanFile', $pfOk)
    Assert-Eq $r.Code 0 'PlanFile 수정됨: 종료 코드 0'
    Test-PlanFile $pfOk '조치 불필요 계획'
    # 도구는 계획 파일의 명령을 실행하지 않았다: fixture 와 시스템 드라이브에 변경 없음
    $oldDirs = @(Get-ChildItem -LiteralPath $fxQ -Recurse -Filter '*.old-*' -ErrorAction SilentlyContinue)
    Assert-Eq $oldDirs.Count 0 '계획 실행/폴더 교체가 일어나지 않음'
    # 저장 실패(없는 디렉터리)는 경고만 하고 분석 종료 코드를 바꾸지 않는다
    $r = Invoke-QcJson $fxOk @('-PlanFile', (Join-Path $planDir 'nodir/x.ps1'))
    Assert-Eq $r.Code 0 'PlanFile 저장 실패해도 종료 코드는 분석 결과'
    if ($null -ne $r.Obj) { Assert-True ((@($r.Obj.warnings) -join ' ') -match '저장하지 못했습니다') '저장 실패 경고' }

    # 2-12 -Root 기본 비실행 / 바이너리 문자열 / -Exec
    $fxN = New-TmpDir
    Add-TestFile $fxN 'php/php.exe' ''
    $r = Invoke-QcJson $fxN
    Assert-Eq $r.Code 3 '버전을 알 수 없으면 종료 코드 3'
    if ($null -ne $r.Obj) {
        $i = Get-InstList $r.Obj
        Assert-Eq $i[0].verdict 'unknown' '버전 불명 verdict'
        Assert-True (Test-NoteMatch $i[0] '-Root 에서는 실행 파일을 실행하지 않습니다.*-Exec') '-Root 비실행 안내 노트(-Exec 언급)'
    }
    # PHP/X.Y.Z 문자열이 4MB 읽기 경계에 걸쳐 있어도 찾는다(ts DLL 우선)
    $fxT = New-TmpDir
    Add-TestFile $fxT 'php/php-cgi.exe' ''
    $big = New-Object 'byte[]' 5000000
    $needleBytes = [System.Text.Encoding]::ASCII.GetBytes('X-Powered-By: PHP/8.4.26')
    [Array]::Copy($needleBytes, 0, $big, (4194368 - 8), $needleBytes.Length)
    $tsDir = Join-Path $fxT 'php'
    [System.IO.File]::WriteAllBytes((Join-Path $tsDir 'php8ts.dll'), $big)
    $r = Invoke-QcJson $fxT
    Assert-Eq $r.Code 1 '바이너리 문자열 8.4.26 -> 취약(종료 코드 1)'
    if ($null -ne $r.Obj) {
        $i = Get-InstList $r.Obj
        Assert-Eq $i[0].version '8.4.26' '경계에 걸친 문자열에서 버전 추출'
        Assert-True (Test-NoteMatch $i[0] '바이너리 문자열') '바이너리 문자열 출처 노트'
    }
    if (-not $script:OnWindows) {
        $fxE = New-TmpDir
        $marker = Join-Path $fxE 'EXECUTED.marker'
        $phpPath = Join-Path $fxE 'php/php.exe'
        Add-TestFile $fxE 'php/php.exe' ("#!/bin/sh`n# X-Powered-By: PHP/8.4.26`n: > '" + $marker + "'`necho 'PHP 8.4.27 (cli) (built: test)'`n")
        & chmod 755 $phpPath
        $r = Invoke-QcJson $fxE
        Assert-True (-not (Test-Path -LiteralPath $marker)) '-Root 기본: 트리 안 실행 파일을 실행하지 않음'
        Assert-Eq $r.Code 1 '-Root 기본: 바이너리 문자열 8.4.26 -> 취약'
        if ($null -ne $r.Obj) { Assert-Eq (Get-InstList $r.Obj)[0].version '8.4.26' '-Root 기본 버전(문자열 기반)' }
        $r = Invoke-QcJson $fxE @('-Exec', '-NoExec')
        Assert-True (-not (Test-Path -LiteralPath $marker)) '-NoExec 는 -Exec 보다 우선'
        $r = Invoke-QcJson $fxE @('-Exec')
        Assert-True (Test-Path -LiteralPath $marker) '-Exec: 실행 허용'
        Assert-Eq $r.Code 0 '-Exec: 실행 출력 8.4.27 -> 수정됨'
        if ($null -ne $r.Obj) {
            $i = Get-InstList $r.Obj
            Assert-Eq $i[0].version '8.4.27' '-Exec 버전'
            Assert-True (Test-NoteMatch $i[0] 'php\.exe -n -v') '-Exec 출처 노트'
        }
    } else {
        Write-Output 'SKIP: -Exec 실행 테스트는 Linux/macOS 에서만 실행됩니다.'
    }

    # -----------------------------------------------------------------------
    # 3. 라이브 프로세스 발견 / 재시작 필요 (Linux 에서만: 복사한 sleep 을 php-cgi 로 위장하지 않고 이름만 사용)
    # -----------------------------------------------------------------------
    $isLinuxHost = $false
    if ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Unix -and (Test-Path -LiteralPath '/proc/self/exe')) { $isLinuxHost = $true }
    $sleepSrc = ''
    foreach ($c in @('/bin/sleep', '/usr/bin/sleep')) { if (Test-Path -LiteralPath $c) { $sleepSrc = $c; break } }
    if ($isLinuxHost -and $sleepSrc) {
        $liveDir = New-TmpDir
        $fake = Join-Path $liveDir 'php-cgi'
        Copy-Item -LiteralPath $sleepSrc -Destination $fake
        & chmod 755 $fake
        Start-Sleep -Milliseconds 1500
        $proc = Start-Process -FilePath $fake -ArgumentList '300' -PassThru
        try {
            $ok = $false
            for ($n = 0; $n -lt 20; $n++) {
                $gp = Get-Process -Id $proc.Id -ErrorAction SilentlyContinue
                if ($null -ne $gp -and $gp.Path -eq $fake) { $ok = $true; break }
                Start-Sleep -Milliseconds 250
            }
            Assert-True $ok '가짜 php-cgi 프로세스 경로 확인(환경 준비)'
            if ($ok) {
                # A) 파일 mtime 이 프로세스 시작보다 미래 -> 재시작 필요, 종료 코드 1
                [System.IO.File]::SetLastWriteTime($fake, (Get-Date).AddHours(1))
                $r = Invoke-Qc @('-Json', '-NoExec')
                $obj = $null
                try { $obj = ConvertFrom-Json -InputObject $r.Text } catch { }
                Assert-True ($null -ne $obj) '라이브 JSON 파싱'
                if ($null -ne $obj) {
                    $mine = @($obj.installations | Where-Object { $_.path -eq $fake })
                    Assert-Eq $mine.Count 1 '라이브: 실행 중 php-cgi 발견'
                    if ($mine.Count -eq 1) {
                        Assert-Eq $mine[0].running $true '라이브 running'
                        Assert-True (@($mine[0].pids) -contains $proc.Id) '라이브 pid 포함'
                        Assert-Eq $mine[0].sapi 'cgi' '라이브 sapi cgi'
                        Assert-Eq $mine[0].needs_restart $true '라이브 needs_restart(파일이 더 새로움)'
                    }
                    Assert-Eq $r.Code 1 '라이브: 재시작 필요 -> 종료 코드 1'
                }
                # B) 파일이 프로세스보다 오래됨 -> 재시작 불필요 (버전은 알 수 없어 unknown -> 3)
                [System.IO.File]::SetLastWriteTime($fake, (Get-Date).AddDays(-1))
                $r = Invoke-Qc @('-Json', '-NoExec')
                $obj = $null
                try { $obj = ConvertFrom-Json -InputObject $r.Text } catch { }
                if ($null -ne $obj) {
                    $mine = @($obj.installations | Where-Object { $_.path -eq $fake })
                    Assert-Eq $mine.Count 1 '라이브 B: 발견'
                    if ($mine.Count -eq 1) {
                        Assert-Eq $mine[0].needs_restart $false '라이브 B needs_restart false'
                        Assert-Eq $mine[0].verdict 'unknown' '라이브 B: 버전 정보 없으면 unknown'
                    }
                }
            }
        } finally {
            try { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue } catch { }
        }
    } else {
        Write-Output 'SKIP: 라이브 프로세스 테스트는 Linux + sleep 이 있을 때만 실행됩니다(실제 Windows 프로세스/서비스/레지스트리/IIS 동작은 이 하네스로 검증되지 않음).'
    }
} finally {
    foreach ($d in $script:TmpDirs) { try { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue } catch { } }
}

Write-Output ('통과 {0}, 실패 {1}' -f $script:Passed, $script:Failed)
if ($script:Failed -gt 0) { exit 1 }
exit 0
