<#
.SYNOPSIS
  PHP2Shell (CVE-2026-109618 / CVE-2026-109619) Windows 점검 스크립트 (방어 전용).

.DESCRIPTION
  Python 없이 Windows PowerShell 5.1 / PowerShell 7+ 에서 실행됩니다. 외부 모듈과 관리자 권한이 필요 없습니다.
  PHP 설치(php.exe, php-cgi.exe, php-win.exe, php*apache*.dll, php*ts.dll)를 실행 중 프로세스, IIS FastCGI 설정,
  Apache 서비스/httpd.conf, 일반적인 설치 경로에서 찾아 버전을 분류하고 조치 계획을 출력합니다.
  서버 설정·패키지를 바꾸지 않습니다. 신뢰할 수 있는 PHP 바이너리만 -n -v 로 실행합니다(-NoExec 로 끌 수 있음).
  의심되는 호스트에서는 -NoExec 를 쓰세요. -Exec 는 신뢰하는 호스트에서만 사용하세요(신뢰 검사를 우회하여 실행).
  네트워크 호출과 취약점 재현은 하지 않습니다. -PlanFile 을 지정한 경우에만 새 계획 파일을 만듭니다(기존 파일 거부).

  종료 코드: 0 = 조치 필요 없음, 1 = 취약/EOL 또는 수정되었으나 이전 코드가 실행 중, 3 = 판단 불가.

  이 파일은 한글을 포함하므로 UTF-8 (BOM 포함)으로 저장되어 있습니다. Windows PowerShell 5.1 이 한글을 올바르게
  읽으려면 BOM 이 필요하므로 편집 후에도 BOM 을 유지하세요.
#>
param(
    [switch]$Json,
    [switch]$NoExec,
    [switch]$Offline,
    [switch]$Exec,
    [string]$PlanFile = '',
    [string]$Root = '',
    [switch]$Help,
    [string]$Classify = ''
)

Set-StrictMode -Version 2.0

# ---------------------------------------------------------------------------
# 상수 / 공통 데이터 (data/advisory.json 과 동일해야 하며 tests 가 일치 여부를 검사합니다)
# ---------------------------------------------------------------------------
$script:ToolName = 'php2shell-quickcheck-ps1'
$script:AsOf = '2026-10-23'
$script:Cves = @('CVE-2026-109618', 'CVE-2026-109619')
$script:FixedReleases = [ordered]@{
    '8.2' = '8.2.35'
    '8.3' = '8.3.36'
    '8.4' = '8.4.27'
    '8.5' = '8.5.12'
    '8.6' = '8.6.0RC4'
}
$script:Sources = @(
    @{ id = 'php-official'; title = 'PHP.net Security advisory: Critical remote code execution vulnerabilities, update now'; url = 'https://www.php.net/archive/2026.php#2026-10-21-5' },
    @{ id = 'ghsa-109618'; title = 'GHSA-w8hw-w9fx-j79w (CVE-2026-109618)'; url = 'https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w' },
    @{ id = 'ghsa-109619'; title = 'GHSA-6wmf-4rv5-p3rp (CVE-2026-109619)'; url = 'https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp' },
    @{ id = 'kisa'; title = 'KISA 보호나라: PHP 보안취약점(PHP2Shell) 관련 기업 보안 대응 수칙 (2026-10-22)'; url = 'https://www.boho.or.kr/kr/bbs/view.do?bbsId=B0000133&menuNo=205020&nttId=72230' },
    @{ id = 'ncsc-nl'; title = 'NCSC-NL/CERT-EU php2shell operational information'; url = 'https://github.com/NCSC-NL/php2shell' },
    @{ id = 'sysdig'; title = 'Sysdig: PHP2Shell detection and recommendations'; url = 'https://www.sysdig.com/blog/php2shell-cve-2026-109618-and-cve-2026-109619-detecting-unauthenticated-remote-code-execution-in-php-core' },
    @{ id = 'xint'; title = 'Xint: PHP2Shell 긴급 대응 방안'; url = 'https://xint.io/ko/blog/php2shell-vulnerability-emergency-response' }
)
$script:AutoStartWarning = 'session_start()를 호출하지 않는 페이지의 세션 기능이 멈출 수 있습니다.'
$script:MemoryLimitWarning = '메모리 상한이 없어지므로 컨테이너·작업 개체(Job Object) 등 OS 수준 상한을 함께 설정해야 합니다. Windows에는 RLIMIT_AS/RLIMIT_DATA가 없으며 해당 방식은 쓰지 마세요.'
$script:LogReviewSince = '2026-10-17'

# ---------------------------------------------------------------------------
# 실행 상태 (Invoke-Main 이 초기화)
# ---------------------------------------------------------------------------
$script:RootDir = ''
$script:NoExecMode = $false
$script:ExecInRoot = $false
$script:OfflineMode = $false
$script:IisPools = New-Object 'System.Collections.Generic.List[string]'
$script:IisSites = New-Object 'System.Collections.Generic.List[string]'
$script:OnWindows = $true
if ($PSVersionTable.PSVersion.Major -ge 6) { $script:OnWindows = [bool]$IsWindows }
$script:Insts = New-Object 'System.Collections.Generic.Dictionary[string,object]'
$script:Warnings = New-Object 'System.Collections.Generic.List[string]'
$script:ApacheServices = New-Object 'System.Collections.Generic.List[string]'
$script:ProcEnumOk = $true
$script:LimitedProcs = 0
$script:W3wpCount = 0
$script:IisConfigRead = $false
$script:IisConfigDenied = $false
$script:Elevated = $null

# ---------------------------------------------------------------------------
# 버전 분류 (tests/vectors/versions.json 규칙)
# ---------------------------------------------------------------------------
function ConvertFrom-PhpVersion {
    # 문자열에서 처음 나오는 X.Y.Z 를 취하고(4번째 숫자 성분은 무시), 바로 뒤의 alpha|beta|RC|dev 태그를 읽습니다.
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    if ($Text.Length -gt 4096) { $Text = $Text.Substring(0, 4096) }
    $m = [regex]::Match($Text, '(?<!\d)(\d{1,9})\.(\d{1,9})\.(\d{1,9})(?:\.\d+)?(?:([-.]?)(alpha|beta|RC|dev)(?![A-Za-z])(\d*))?', 'IgnoreCase')
    if (-not $m.Success) { return $null }
    $rank = 4
    $num = [long]0
    $tagText = ''
    if ($m.Groups[5].Success -and $m.Groups[5].Value.Length -gt 0) {
        $tag = $m.Groups[5].Value.ToLowerInvariant()
        if ($tag -eq 'dev') { $rank = 0 }
        elseif ($tag -eq 'alpha') { $rank = 1 }
        elseif ($tag -eq 'beta') { $rank = 2 }
        else { $rank = 3 }
        if ($m.Groups[6].Value.Length -gt 0 -and -not [long]::TryParse($m.Groups[6].Value, [ref]$num)) { return $null }
        $tagText = $m.Groups[4].Value + $m.Groups[5].Value + $m.Groups[6].Value
    }
    $patch = [long]$m.Groups[3].Value
    return [pscustomobject]@{
        Major = [long]$m.Groups[1].Value
        Minor = [long]$m.Groups[2].Value
        Patch = $patch
        Rank  = $rank
        Num   = $num
        Key   = ($patch * 100000000) + ($rank * 100000) + [Math]::Min($num, [long]99999)
        Text  = ('{0}.{1}.{2}{3}' -f $m.Groups[1].Value, $m.Groups[2].Value, $m.Groups[3].Value, $tagText)
    }
}

function Get-FixKey {
    # FixedReleases 에서 브랜치별 최소 수정 버전의 비교 키를 계산합니다.
    param([string]$Branch)
    if (-not $script:FixedReleases.Contains($Branch)) { return $null }
    $f = ConvertFrom-PhpVersion $script:FixedReleases[$Branch]
    if ($null -eq $f) { return $null }
    return $f.Key
}

function Get-PhpClass {
    param([string]$Text)
    $v = ConvertFrom-PhpVersion $Text
    if ($null -eq $v) { return 'unknown' }
    $maj = $v.Major
    $min = $v.Minor
    if ($maj -lt 5) { return 'old_unsupported' }
    if ($maj -eq 5) {
        if ($min -lt 4) { return 'old_unsupported' }
        if ($min -le 6) { return 'eol_no_fix' }
        return 'unknown'
    }
    if ($maj -eq 6) { return 'unknown' }
    if ($maj -eq 7) {
        if ($min -le 3) { return 'eol_no_fix' }
        if ($min -eq 4) { return 'eol_backport' }
        return 'unknown'
    }
    if ($maj -eq 8) {
        if ($min -le 1) { return 'eol_backport' }
        $fk = Get-FixKey ('8.' + $min)
        if ($null -ne $fk) {
            if ($v.Key -ge $fk) { return 'fixed' }
            return 'vulnerable'
        }
        if ($min -ge 7) { return 'fixed' }
        return 'unknown'
    }
    return 'fixed'
}

function Get-Verdict {
    param([string]$Class, [string]$VendorPatch)
    if ($Class -eq 'fixed') { return 'fixed' }
    if ($Class -eq 'old_unsupported') { return 'eol' }
    if ($Class -eq 'unknown') { return 'unknown' }
    if ($VendorPatch -eq 'yes') { return 'vendor_patched' }
    return 'vulnerable'
}

function Get-Branch {
    param([string]$Text)
    $v = ConvertFrom-PhpVersion $Text
    if ($null -eq $v) { return '' }
    return ('{0}.{1}' -f $v.Major, $v.Minor)
}

# ---------------------------------------------------------------------------
# 일반 도우미
# ---------------------------------------------------------------------------
function Add-Warn {
    param([string]$Message)
    foreach ($w in $script:Warnings) { if ($w -eq $Message) { return } }
    $script:Warnings.Add($Message)
}

function Add-Unique {
    param($List, [string]$Value)
    foreach ($e in $List) { if ([string]::Equals($e, $Value, [StringComparison]::OrdinalIgnoreCase)) { return } }
    $List.Add($Value)
}

function ConvertTo-SafeText {
    param([string]$Text)
    return [regex]::Replace($Text, '[\x00-\x1f\x7f-\x9f\u2028\u2029]', '?')
}

function Test-RootPath {
    # -Root 안의 각 구성요소를 검사한다. 바깥 심볼릭 링크/정션 및 해석할 수 없는 링크는 열지 않는다.
    param([string]$Path, [int]$Depth = 0)
    if (-not $Path -or $Depth -gt 16) { return $false }
    if (-not $script:RootDir) { return $true }
    try {
        $rootPath = [IO.Path]::GetFullPath($script:RootDir)
        if ($rootPath -ne [IO.Path]::GetPathRoot($rootPath)) { $rootPath = $rootPath.TrimEnd([IO.Path]::DirectorySeparatorChar) }
        $full = [IO.Path]::GetFullPath($Path)
        $comparison = [StringComparison]::Ordinal
        if ($script:OnWindows) { $comparison = [StringComparison]::OrdinalIgnoreCase }
        $prefix = $rootPath.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
        if (-not $full.Equals($rootPath, $comparison) -and -not $full.StartsWith($prefix, $comparison)) {
            Add-Warn ('-Root 밖 경로 무시: ' + (ConvertTo-SafeText $Path))
            return $false
        }
        $relative = $full.Substring($rootPath.Length).TrimStart([IO.Path]::DirectorySeparatorChar)
        $current = $rootPath
        foreach ($part in ($relative -split '[\\/]')) {
            if (-not $part) { continue }
            $current = [IO.Path]::Combine($current, $part)
            $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                $target = ''
                if ($item.PSObject.Methods['ResolveLinkTarget']) {
                    $resolved = $item.ResolveLinkTarget($true)
                    if ($null -ne $resolved) { $target = $resolved.FullName }
                } elseif ($item.PSObject.Properties['Target']) {
                    $targets = @($item.Target)
                    if ($targets.Count -eq 1) {
                        $target = [string]$targets[0]
                        if (-not [IO.Path]::IsPathRooted($target)) { $target = Join-Path (Split-Path -Parent $current) $target }
                        $target = [IO.Path]::GetFullPath($target)
                    }
                }
                # PS 5.1의 Target은 중첩 링크를 완전히 해석하지 못하므로 그 구성요소도 재귀 검사한다.
                if (-not $target -or (-not $target.Equals($rootPath, $comparison) -and -not $target.StartsWith($prefix, $comparison))) {
                    Add-Warn ('-Root 밖 또는 해석 불가능한 링크/정션 무시: ' + (ConvertTo-SafeText $current))
                    return $false
                }
                if (-not $item.PSObject.Methods['ResolveLinkTarget']) {
                    # 오래된 .NET에서는 링크를 보수적으로 건너뛰어 중첩 링크 우회를 막는다.
                    Add-Warn ('-Root 링크/정션 무시(완전한 대상 해석 불가): ' + (ConvertTo-SafeText $current))
                    return $false
                }
                if (-not (Test-RootPath $target ($Depth + 1))) { return $false }
                $current = $target
            }
        }
        return $true
    } catch { return $false }
}

function Test-RegularFile {
    param([string]$Path, [long]$MaxBytes = 125829120)
    if (-not (Test-RootPath $Path)) { return $false }
    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if (-not ($item -is [IO.FileInfo]) -or ($item.Attributes -band [IO.FileAttributes]::Device)) { return $false }
        if (-not $script:OnWindows -and $item.PSObject.Properties['UnixStat']) {
            if (([long]$item.UnixStat.Mode -band 61440) -ne 32768) { return $false }
        }
        if ($item.Length -gt $MaxBytes) {
            Add-Warn ('파일 읽기 상한 초과로 무시: ' + (ConvertTo-SafeText $Path))
            return $false
        }
        return $true
    } catch { return $false }
}

function Read-SafeText {
    # 텍스트 <= 2 MiB, 정규 파일만. UTF-8 BOM/UTF-16 BOM도 StreamReader가 처리한다.
    param([string]$Path)
    if (-not (Test-RegularFile $Path 2097152)) { return $null }
    $reader = $null
    try {
        $reader = New-Object IO.StreamReader($Path, [Text.Encoding]::UTF8, $true)
        $buffer = New-Object 'char[]' 2097153
        $count = $reader.ReadBlock($buffer, 0, $buffer.Length)
        if ($count -gt 2097152) { return $null }
        return (New-Object string($buffer, 0, $count))
    } catch { return $null } finally { if ($null -ne $reader) { $reader.Dispose() } }
}

function Read-SafeLines {
    param([string]$Path)
    $text = Read-SafeText $Path
    if ($null -eq $text) { return @() }
    foreach ($line in ($text -split "`r?`n")) {
        if ($line.Length -gt 4096) { $line = $line.Substring(0, 4096) }
        $line
    }
}

function Resolve-FsPath {
    # Windows 경로(문자열)를 실제 파일시스템 경로로 바꿉니다. -Root 가 있으면 드라이브 문자를 떼고 Root 아래로 매핑합니다.
    param([string]$Path)
    if ([string]::IsNullOrEmpty($Path)) { return $Path }
    $p = $Path.Trim().Trim('"')
    if ($script:RootDir) {
        $p = $p -replace '^%[^%]+%', ''
        $p = $p -replace '^[A-Za-z]:', ''
        $p = $p -replace '\\', '/'
        if (@($p.Split('/') | Where-Object { $_ -eq '..' }).Count -gt 0) {
            Add-Warn ('-Root 설정 경로의 .. 거부: ' + (ConvertTo-SafeText $Path))
            return ''
        }
        $p = $p.TrimStart('/')
        return (Join-Path $script:RootDir $p)
    }
    return [System.Environment]::ExpandEnvironmentVariables($p)
}

function Get-DirKey {
    param([string]$Dir)
    $f = $Dir
    try { $f = [System.IO.Path]::GetFullPath($Dir) } catch { }
    return $f.TrimEnd('\', '/').ToLowerInvariant()
}

function Get-FullPathSafe {
    param([string]$Path)
    try { return [System.IO.Path]::GetFullPath($Path) } catch { return $Path }
}

function Get-Inst {
    param([string]$Dir)
    $key = Get-DirKey $Dir
    if (-not $script:Insts.ContainsKey($key)) {
        $script:Insts[$key] = [pscustomobject]@{
            Dir         = $Dir
            Binaries    = (New-Object 'System.Collections.Generic.List[string]')
            Sapis       = (New-Object 'System.Collections.Generic.List[string]')
            Sources     = (New-Object 'System.Collections.Generic.List[string]')
            Notes       = (New-Object 'System.Collections.Generic.List[string]')
            Procs       = (New-Object 'System.Collections.Generic.List[object]')
            ApacheRoots = (New-Object 'System.Collections.Generic.List[string]')
            Services    = (New-Object 'System.Collections.Generic.List[string]')
            Iis         = $false
            ApacheMod   = $false
            IniDir      = ''
            IniFile     = ''
            Phprc       = ''
            ScanDir     = ''
        }
    }
    return $script:Insts[$key]
}

function Get-BinKind {
    param([string]$Path)
    $n = [System.IO.Path]::GetFileName($Path)
    if ($n -match '^php-cgi\.exe$') { return 'cgi' }
    if ($n -match '^php(-win)?\.exe$') { return 'cli' }
    if ($n -match '^php\d*apache[\w.]*\.dll$') { return 'apache' }
    if ($n -match '^php\d*ts\.dll$') { return 'ts' }
    return 'other'
}

function Add-Binary {
    param([string]$Path, [string]$Source, [string]$Sapi)
    if ([string]::IsNullOrEmpty($Path)) { return $null }
    $full = Get-FullPathSafe $Path
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
        Add-Warn ('{0} 에서 참조된 파일을 찾을 수 없습니다: {1}' -f $Source, $Path)
        return $null
    }
    if (-not (Test-RegularFile $full)) { return $null }
    $dir = Split-Path -Parent $full
    $inst = Get-Inst $dir
    Add-Unique $inst.Binaries $full
    Add-Unique $inst.Sources $Source
    if ($Sapi) { Add-Unique $inst.Sapis $Sapi }
    return $inst
}

function Add-DirScan {
    param([string]$Dir, [string]$Source)
    if (-not (Test-RootPath $Dir)) { return }
    $files = @()
    try { $files = @([System.IO.Directory]::GetFiles($Dir)) } catch { return }
    foreach ($f in $files) {
        $kind = Get-BinKind $f
        if ($kind -eq 'other') { continue }
        $sapi = ''
        if ($kind -ne 'ts') { $sapi = $kind }
        [void](Add-Binary $f $Source $sapi)
    }
}

function Expand-Glob {
    param([string]$Base, [string]$Rel, [bool]$FilesOnly)
    try {
        $b = [System.Management.Automation.WildcardPattern]::Escape($Base)
        $p = Join-Path $b $Rel
        $found = @()
        if ($FilesOnly) { $found = @(Get-ChildItem -Path $p -File -ErrorAction SilentlyContinue) }
        else { $found = @(Get-ChildItem -Path $p -Directory -ErrorAction SilentlyContinue) }
        return @($found | Where-Object { Test-RootPath $_.FullName })
    } catch { return @() }
}

function Get-DriveRoots {
    if ($script:RootDir) { return @($script:RootDir) }
    if (-not $script:OnWindows) { return @() }
    $r = New-Object 'System.Collections.Generic.List[string]'
    try {
        foreach ($d in [System.IO.DriveInfo]::GetDrives()) {
            if ($d.DriveType -eq [System.IO.DriveType]::Fixed -and $d.IsReady) { $r.Add($d.RootDirectory.FullName) }
        }
    } catch { }
    return @($r.ToArray())
}

# ---------------------------------------------------------------------------
# 환경: 권한 / 프로세스
# ---------------------------------------------------------------------------
function Test-Elevated {
    if (-not $script:OnWindows) { return $null }
    try {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $pr = New-Object System.Security.Principal.WindowsPrincipal($id)
        return $pr.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $null }
}

function Get-LiveProcesses {
    # php / php-cgi / php-win / httpd / apache / w3wp 프로세스를 읽습니다. 경로나 시작 시각을 못 읽은 것은 Limited 로 센다.
    $res = @{ Ok = $true; Limited = 0; W3wp = 0; List = (New-Object 'System.Collections.Generic.List[object]') }
    $all = @()
    try { $all = @(Get-Process -ErrorAction Stop) } catch { $res.Ok = $false; return $res }
    foreach ($p in $all) {
        $name = ''
        try { $name = [string]$p.Name } catch { continue }
        $kind = ''
        if ($name -match '^(?i)php(-cgi|-win)?$') { $kind = 'php' }
        elseif ($name -match '^(?i)(httpd|apache)$') { $kind = 'httpd' }
        elseif ($name -match '^(?i)w3wp$') { $res.W3wp = $res.W3wp + 1; continue }
        else { continue }
        $path = $null
        try { $path = $p.Path } catch { $path = $null }
        $start = $null
        try { $start = $p.StartTime } catch { $start = $null }
        if ([string]::IsNullOrEmpty($path)) { $res.Limited = $res.Limited + 1 }
        $res.List.Add([pscustomobject]@{ Pid = [int]$p.Id; Name = $name; Kind = $kind; Path = $path; StartTime = $start })
    }
    return $res
}

# ---------------------------------------------------------------------------
# 발견 단계 1: IIS (applicationHost.config 정적 파싱, appcmd 실행 없음)
# ---------------------------------------------------------------------------
function Get-IisConfigPath {
    if ($script:RootDir) { return (Join-Path $script:RootDir 'Windows/System32/inetsrv/config/applicationHost.config') }
    if (-not $script:OnWindows) { return $null }
    $win = $env:windir
    if ([string]::IsNullOrEmpty($win)) { return $null }
    $sys = 'System32'
    # 32비트 PowerShell 이 64비트 OS 에서 실행되면 System32 가 SysWOW64 로 리다이렉트되므로 Sysnative 를 쓴다.
    try { if ([System.Environment]::Is64BitOperatingSystem -and -not [System.Environment]::Is64BitProcess) { $sys = 'Sysnative' } } catch { }
    return (Join-Path (Join-Path $win $sys) 'inetsrv\config\applicationHost.config')
}

function Find-IisPhpRegistrations {
    $cfg = Get-IisConfigPath
    if ([string]::IsNullOrEmpty($cfg)) { return }
    $inetsrv = Split-Path -Parent (Split-Path -Parent $cfg)
    if (-not (Test-Path -LiteralPath $cfg -PathType Leaf)) {
        if ((Test-Path -LiteralPath $inetsrv -PathType Container) -and -not $script:RootDir -and ($script:Elevated -eq $false)) {
            $script:IisConfigDenied = $true
            Add-Warn 'IIS 가 설치된 것으로 보이나 applicationHost.config 를 읽을 수 없습니다. 관리자 권한 PowerShell 에서 다시 실행하세요.'
        }
        return
    }
    if (-not (Test-RegularFile $cfg 2097152)) { return }
    $xml = New-Object System.Xml.XmlDocument
    try {
        $rs = New-Object System.Xml.XmlReaderSettings
        $rs.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
        $rs.XmlResolver = $null
        $rs.MaxCharactersInDocument = 2097152
        $content = Read-SafeText $cfg
        if ($null -eq $content) { return }
        $sr = New-Object IO.StringReader($content)
        $reader = [System.Xml.XmlReader]::Create($sr, $rs)
        try { $xml.Load($reader) } finally { $reader.Close(); $sr.Dispose() }
    } catch {
        $script:IisConfigDenied = $true
        Add-Warn ('applicationHost.config 를 읽거나 파싱하지 못했습니다 ({0}). 관리자 권한으로 다시 실행하세요.' -f $_.Exception.Message)
        return
    }
    $script:IisConfigRead = $true
    foreach ($ap in @($xml.SelectNodes('//applicationPools/add'))) {
        $apn = $ap.GetAttribute('name')
        if ($apn) { Add-Unique $script:IisPools $apn }
    }
    foreach ($st in @($xml.SelectNodes('//sites/site'))) {
        $stn = $st.GetAttribute('name')
        if ($stn) { Add-Unique $script:IisSites $stn }
    }

    foreach ($app in @($xml.SelectNodes('//fastCgi/application'))) {
        $full = $app.GetAttribute('fullPath')
        if ([string]::IsNullOrEmpty($full) -or $full.Length -gt 4096) { continue }
        if ([System.IO.Path]::GetFileName($full.Replace('\', '/')) -notmatch '^(?i)php[\w.-]*\.exe$') { continue }
        $inst = Add-Binary (Resolve-FsPath $full) 'IIS FastCGI 등록' 'cgi'
        if ($null -eq $inst) { continue }
        $inst.Iis = $true
        $argText = $app.GetAttribute('arguments')
        if ($argText.Length -gt 4096) { $argText = $argText.Substring(0, 4096) }
        if ($argText) {
            $am = [regex]::Match($argText, '(?:^|\s)-c\s+("[^"]+"|\S+)')
            if ($am.Success) { $inst.IniFile = (Resolve-FsPath $am.Groups[1].Value.Trim('"')) }
        }
        foreach ($ev in @($app.SelectNodes('environmentVariables/environmentVariable'))) {
            $n = $ev.GetAttribute('name')
            $v = $ev.GetAttribute('value')
            if ($n.Length -gt 4096 -or $v.Length -gt 4096) { continue }
            if ($n -ieq 'PHPRC') { $inst.Phprc = (Resolve-FsPath $v) }
            elseif ($n -ieq 'PHP_INI_SCAN_DIR') { $inst.ScanDir = $v }
        }
    }
    foreach ($h in @($xml.SelectNodes('//handlers/add'))) {
        $sp = $h.GetAttribute('scriptProcessor')
        if ([string]::IsNullOrEmpty($sp) -or $sp.Length -gt 4096) { continue }
        $exe = $sp.Split('|')[0]
        if ([System.IO.Path]::GetFileName($exe.Replace('\', '/')) -notmatch '^(?i)php[\w.-]*\.exe$') { continue }
        $inst = Add-Binary (Resolve-FsPath $exe) 'IIS 핸들러 매핑' 'cgi'
        if ($null -ne $inst) { $inst.Iis = $true }
    }
}

# ---------------------------------------------------------------------------
# 발견 단계 2: Apache (서비스 ImagePath, httpd.conf LoadModule php*_module)
# ---------------------------------------------------------------------------
function Get-ApacheServiceInfo {
    # 레지스트리의 서비스 ImagePath 를 읽는다(관리자 권한 불필요, 서비스 제어/실행 없음).
    $out = New-Object 'System.Collections.Generic.List[object]'
    if ($script:RootDir -or -not $script:OnWindows) { return @() }
    try {
        foreach ($k in (Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -ErrorAction Stop)) {
            $ip = $null
            try { $ip = [string]$k.GetValue('ImagePath') } catch { continue }
            if ([string]::IsNullOrEmpty($ip)) { continue }
            $m = [regex]::Match($ip, '^\s*"?([^"]+?\.exe)"?(.*)$')
            if (-not $m.Success) { continue }
            $exe = $m.Groups[1].Value
            if ([System.IO.Path]::GetFileName($exe.Replace('\', '/')) -notmatch '^(?i)(httpd|apache)[\w.-]*\.exe$') { continue }
            $rest = $m.Groups[2].Value
            $exeDir = Split-Path -Parent $exe
            $root = $exeDir
            if ((Split-Path -Leaf $exeDir) -ieq 'bin') { $root = Split-Path -Parent $exeDir }
            $dm = [regex]::Match($rest, '(?:^|\s)-d\s+("[^"]+"|\S+)')
            if ($dm.Success) { $root = $dm.Groups[1].Value.Trim('"') }
            $conf = Join-Path $root 'conf\httpd.conf'
            $fm = [regex]::Match($rest, '(?:^|\s)-f\s+("[^"]+"|\S+)')
            if ($fm.Success) {
                $c = $fm.Groups[1].Value.Trim('"')
                if ($c -match '^([A-Za-z]:|[\\/])') { $conf = $c } else { $conf = Join-Path $root $c }
            }
            $out.Add([pscustomobject]@{ Name = $k.PSChildName; Exe = $exe; Root = $root; Conf = $conf })
        }
    } catch {
        Add-Warn ('서비스 레지스트리를 읽지 못했습니다: {0}' -f $_.Exception.Message)
    }
    return @($out.ToArray())
}

function Expand-ApacheVars {
    param([string]$Text, [hashtable]$Defs)
    $s = $Text
    foreach ($k in @($Defs.Keys)) {
        if ($k.StartsWith('__')) { continue }
        $s = $s.Replace('${' + $k + '}', [string]$Defs[$k])
    }
    return $s
}

function Resolve-ApachePath {
    param([string]$Path, [string]$RealRoot)
    $p = $Path.Trim().Trim('"')
    if (-not $p -or -not $RealRoot) { return '' }
    if ($script:RootDir -and @($p.Replace('\', '/').Split('/') | Where-Object { $_ -eq '..' }).Count -gt 0) {
        Add-Warn ('-Root 설정 경로의 .. 거부: ' + (ConvertTo-SafeText $Path))
        return ''
    }
    if ($p -match '^([A-Za-z]:|[\\/])') { return (Resolve-FsPath $p) }
    return (Join-Path $RealRoot $p)
}

function Read-ApacheConfFile {
    # Include/IncludeOptional 을 3단계까지 따라가며 LoadModule php*_module, PHPIniDir, FcgidWrapper 를 수집한다.
    param([string]$File, [hashtable]$Defs, $Found, [int]$Depth)
    if ($Depth -gt 3) { return }
    $vk = Get-DirKey $File
    if ($Defs['__visited'].ContainsKey($vk)) { return }
    $Defs['__visited'][$vk] = $true
    $lines = @()
    if (-not (Test-RegularFile $File 2097152)) { return }
    $lines = @(Read-SafeLines $File)
    foreach ($raw in $lines) {
        $line = ([string]$raw).Trim()
        if ($line.Length -eq 0 -or $line.StartsWith('#')) { continue }
        $m = [regex]::Match($line, '^Define\s+(\w+)\s+(.+)$', 'IgnoreCase')
        if ($m.Success) { $Defs[$m.Groups[1].Value] = $m.Groups[2].Value.Trim().Trim('"'); continue }
        $line = Expand-ApacheVars $line $Defs
        $m = [regex]::Match($line, '^ServerRoot\s+(.+)$', 'IgnoreCase')
        if ($m.Success) {
            $newRoot = Resolve-FsPath $m.Groups[1].Value.Trim().Trim('"')
            if ($newRoot) { $Defs['__root'] = $newRoot }
            continue
        }
        $m = [regex]::Match($line, '^LoadModule\s+(\w*php\w*)\s+("[^"]+"|\S+)', 'IgnoreCase')
        if ($m.Success) {
            $Found.Add([pscustomobject]@{ Type = 'module'; Path = (Resolve-ApachePath $m.Groups[2].Value $Defs['__root']); Conf = $File })
            continue
        }
        $m = [regex]::Match($line, '^PHPIniDir\s+("[^"]+"|\S+)', 'IgnoreCase')
        if ($m.Success) { $Found.Add([pscustomobject]@{ Type = 'ini'; Path = (Resolve-ApachePath $m.Groups[1].Value $Defs['__root']); Conf = $File }); continue }
        $m = [regex]::Match($line, '^FcgidWrapper\s+("[^"]+"|\S+)', 'IgnoreCase')
        if ($m.Success) {
            $w = $m.Groups[1].Value.Trim('"')
            if ([System.IO.Path]::GetFileName($w.Replace('\', '/')) -match '^(?i)php[\w.-]*\.exe$') {
                $Found.Add([pscustomobject]@{ Type = 'fcgid'; Path = (Resolve-ApachePath $w $Defs['__root']); Conf = $File })
            }
            continue
        }
        $m = [regex]::Match($line, '^Include(Optional)?\s+("[^"]+"|\S+)', 'IgnoreCase')
        if ($m.Success) {
            $target = Resolve-ApachePath $m.Groups[2].Value $Defs['__root']
            if (-not $target) { continue }
            if ($target -notmatch '[*?]' -and -not (Test-RootPath $target)) { continue }
            if (Test-Path -LiteralPath $target -PathType Container) {
                foreach ($f in @(Get-ChildItem -LiteralPath $target -Filter '*.conf' -File -ErrorAction SilentlyContinue | Sort-Object Name)) {
                    Read-ApacheConfFile $f.FullName $Defs $Found ($Depth + 1)
                }
            } elseif (Test-Path -LiteralPath $target -PathType Leaf) {
                Read-ApacheConfFile $target $Defs $Found ($Depth + 1)
            } elseif ($target -match '[*?]') {
                $d = Split-Path -Parent $target
                $leaf = Split-Path -Leaf $target
                if (-not (Test-RootPath $d)) { continue }
                if (Test-Path -LiteralPath $d -PathType Container) {
                    foreach ($f in @(Get-ChildItem -LiteralPath $d -Filter $leaf -File -ErrorAction SilentlyContinue | Sort-Object Name)) {
                        Read-ApacheConfFile $f.FullName $Defs $Found ($Depth + 1)
                    }
                }
            }
        }
    }
}

function Read-ApacheConf {
    param([string]$Conf, [string]$ServerRoot)
    $defs = @{}
    $defs['__visited'] = @{}
    $defs['__root'] = $ServerRoot
    $defs['SRVROOT'] = $ServerRoot
    $found = New-Object 'System.Collections.Generic.List[object]'
    Read-ApacheConfFile $Conf $defs $found 0
    $guessKey = Get-DirKey $ServerRoot
    $rootKey = Get-DirKey ([string]$defs['__root'])
    $iniDir = ''
    foreach ($f in $found) { if ($f.Type -eq 'ini') { $iniDir = $f.Path } }
    foreach ($f in $found) {
        if ($f.Type -eq 'module') {
            $inst = Add-Binary $f.Path ('httpd.conf LoadModule ({0})' -f $f.Conf) 'apache'
            if ($null -eq $inst) { continue }
            $inst.ApacheMod = $true
            Add-Unique $inst.ApacheRoots $guessKey
            Add-Unique $inst.ApacheRoots $rootKey
            if ($iniDir) { $inst.IniDir = $iniDir }
        } elseif ($f.Type -eq 'fcgid') {
            $inst = Add-Binary $f.Path ('httpd.conf FcgidWrapper ({0})' -f $f.Conf) 'cgi'
            if ($null -ne $inst) { Add-Unique $inst.Notes 'Apache mod_fcgid(FcgidWrapper)로 php-cgi 를 사용합니다.' }
        }
    }
}

function Find-ApachePhpModules {
    param($LiveProcs)
    $confs = New-Object 'System.Collections.Generic.List[object]'
    $seen = @{}
    $addConf = {
        param([string]$Conf, [string]$Root)
        $k = Get-DirKey $Conf
        if (-not $seen.ContainsKey($k) -and (Test-Path -LiteralPath $Conf -PathType Leaf)) {
            $seen[$k] = $true
            $confs.Add([pscustomobject]@{ Conf = $Conf; Root = $Root })
        }
    }
    foreach ($s in @(Get-ApacheServiceInfo)) {
        Add-Unique $script:ApacheServices $s.Name
        & $addConf $s.Conf $s.Root
    }
    foreach ($p in $LiveProcs) {
        if ($p.Kind -ne 'httpd' -or [string]::IsNullOrEmpty($p.Path)) { continue }
        $d = Split-Path -Parent $p.Path
        $root = $d
        if ((Split-Path -Leaf $d) -ieq 'bin') { $root = Split-Path -Parent $d }
        & $addConf (Join-Path $root 'conf/httpd.conf') $root
    }
    $patterns = @(
        'Apache*/conf/httpd.conf', 'Apache24/conf/httpd.conf', 'xampp/apache/conf/httpd.conf',
        'wamp*/bin/apache/apache*/conf/httpd.conf', 'laragon/bin/apache/*/conf/httpd.conf',
        'Program Files/Apache*/conf/httpd.conf', 'Program Files (x86)/Apache*/conf/httpd.conf',
        'Program Files/Apache Software Foundation/Apache*/conf/httpd.conf',
        'Program Files (x86)/Apache Software Foundation/Apache*/conf/httpd.conf',
        'MAMP/conf/apache/httpd.conf', 'Plesk/Apache*/conf/httpd.conf'
    )
    foreach ($base in @(Get-DriveRoots)) {
        foreach ($pat in $patterns) {
            foreach ($f in @(Expand-Glob $base $pat $true)) {
                $root = Split-Path -Parent (Split-Path -Parent $f.FullName)
                & $addConf $f.FullName $root
            }
        }
    }
    foreach ($c in $confs) { Read-ApacheConf $c.Conf $c.Root }
}

# ---------------------------------------------------------------------------
# 발견 단계 3: 흔한 설치 경로
# ---------------------------------------------------------------------------
function Find-CommonPhpDirs {
    $patterns = @(
        'php*', 'xampp/php', 'wamp*/bin/php/php*', 'laragon/bin/php/php*',
        'Program Files/PHP*', 'Program Files (x86)/PHP*', 'Program Files/PHP/*', 'Program Files (x86)/PHP/*',
        'MAMP/bin/php/php*', 'Program Files (x86)/Plesk/Additional/PleskPHP*', 'Program Files/Plesk/Additional/PleskPHP*',
        'tools/php*', 'ProgramData/chocolatey/lib/php*/tools',
        'ProgramData/scoop/apps/php*/current', 'Users/*/scoop/apps/php*/current'
    )
    foreach ($base in @(Get-DriveRoots)) {
        foreach ($pat in $patterns) {
            foreach ($d in @(Expand-Glob $base $pat $false)) { Add-DirScan $d.FullName '일반 설치 경로' }
        }
    }
    if (-not $script:RootDir -and $script:OnWindows) {
        $homes = @($env:USERPROFILE, $env:SCOOP)
        foreach ($h in $homes) {
            if ([string]::IsNullOrEmpty($h)) { continue }
            foreach ($rel in @('scoop/apps/php*/current', 'apps/php*/current')) {
                foreach ($d in @(Expand-Glob $h $rel $false)) { Add-DirScan $d.FullName 'Scoop' }
            }
        }
    }
}

# ---------------------------------------------------------------------------
# 버전 / 벤더 증거 / php.ini
# ---------------------------------------------------------------------------
function Get-TrustAcl {
    param([string]$Path)
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $rules = New-Object 'System.Collections.Generic.List[object]'
    foreach ($ace in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        $rules.Add([pscustomobject]@{
            Sid = $ace.IdentityReference.Value
            Allow = ($ace.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow)
            InheritOnly = (($ace.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0)
            Rights = [long]$ace.FileSystemRights
        })
    }
    return [pscustomobject]@{ Owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value; Rules = @($rules.ToArray()) }
}

function Test-TrustedPath {
    # 파일 자신과 그 파일이 들어 있는 폴더(앱 폴더)는 전체 쓰기 권한을 본다: 폴더에 새 파일을 만들 수 있으면 DLL 을 심어 실행을 가로챌 수 있다.
    # 그보다 위의 상위 폴더는 "새 파일/하위 폴더 만들기"(CreateFiles 0x2, CreateDirectories 0x4)만 허용하는 권한을 무시한다:
    # 기본 Windows 의 C:\ 에는 Authenticated Users:(AD) 가 있고, 이것으로는 이미 있는 하위 폴더를 바꾸거나 지울 수 없다.
    # ACL reader를 주입하여 Windows 밖에서도 정책을 검증한다.
    param([string]$Path, [scriptblock]$AclReader = { param($p) Get-TrustAcl $p })
    $owners = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    $untrusted = @('S-1-1-0', 'S-1-5-32-545', 'S-1-5-11')
    # WriteData/CreateFiles, AppendData/CreateDirectories, WriteEA/Attributes, Delete, DeleteChild, WRITE_DAC, WRITE_OWNER.
    $fullMask = [long]0x000D0156
    $ancestorMask = [long]0x000D0150
    try {
        $current = [IO.Path]::GetFullPath($Path)
        if (-not (Test-RegularFile $current)) { return $false }
        $depth = 0
        while ($current) {
            $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return $false }
            $acl = & $AclReader $current
            if ($null -eq $acl -or $owners -notcontains $acl.Owner) { return $false }
            $mask = if ($depth -le 1) { $fullMask } else { $ancestorMask }
            foreach ($rule in @($acl.Rules)) {
                if ($rule.Allow -and -not $rule.InheritOnly -and $untrusted -contains $rule.Sid -and (([long]$rule.Rights -band $mask) -ne 0)) { return $false }
            }
            $parent = [IO.Path]::GetDirectoryName($current)
            if (-not $parent -or $parent -eq $current) { break }
            $current = $parent
            $depth++
        }
        return $true
    } catch { return $false }
}

function Get-ExecMode {
    if ($script:NoExecMode) { return 'never' }
    if ($script:ExecInRoot) { return 'all' }
    if ($script:RootDir) { return 'never' }
    return 'auto'
}

function Test-ExecAllowed {
    param([string]$Path = '', [string]$ExecMode = '', $Privileged = $script:Elevated,
          [scriptblock]$TrustCheck = { param($p) Test-TrustedPath $p })
    if (-not $ExecMode) { $ExecMode = Get-ExecMode }
    if ($ExecMode -eq 'never') { return $false }
    if (-not (Test-RegularFile $Path)) { return $false }
    if ($ExecMode -eq 'all') { return $true }
    if ($Privileged -eq $false) { return $true }
    return [bool](& $TrustCheck $Path)
}

function Invoke-PhpVersion {
    # 절대 경로, 최소 환경, stdin 닫음, 10초 제한. stdout/stderr 각 2048바이트(합계 최대 4096).
    param([string]$Exe)
    $proc = $null
    try {
        if (-not (Test-RegularFile $Exe)) { return $null }
        $psi = New-Object Diagnostics.ProcessStartInfo
        $psi.FileName = [IO.Path]::GetFullPath($Exe)
        $psi.Arguments = '-n -v'
        $psi.UseShellExecute = $false
        $psi.RedirectStandardInput = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.CreateNoWindow = $true
        $psi.EnvironmentVariables.Clear()
        if ($script:OnWindows) {
            $win = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
            $psi.EnvironmentVariables['SystemRoot'] = $win
            $psi.EnvironmentVariables['PATH'] = [IO.Path]::Combine($win, 'System32')
            $psi.WorkingDirectory = [IO.Path]::Combine($win, 'System32')
        } else {
            $psi.EnvironmentVariables['LC_ALL'] = 'C'
            $psi.EnvironmentVariables['PATH'] = '/usr/sbin:/usr/bin:/sbin:/bin'
            $psi.WorkingDirectory = '/'
        }
        $proc = [Diagnostics.Process]::Start($psi)
        $proc.StandardInput.Close()
        $streams = @($proc.StandardOutput.BaseStream, $proc.StandardError.BaseStream)
        $buffers = @((New-Object 'byte[]' 2048), (New-Object 'byte[]' 2048))
        $counts = @(0, 0)
        $done = @($false, $false)
        $tasks = @($streams[0].ReadAsync($buffers[0], 0, 2048), $streams[1].ReadAsync($buffers[1], 0, 2048))
        $deadline = [DateTime]::UtcNow.AddSeconds(10)
        while ([DateTime]::UtcNow -lt $deadline) {
            for ($n = 0; $n -lt 2; $n++) {
                if (-not $done[$n] -and $tasks[$n].IsCompleted) {
                    $got = $tasks[$n].Result
                    $counts[$n] += $got
                    if ($got -eq 0 -or $counts[$n] -ge 2048) { $done[$n] = $true }
                    else { $tasks[$n] = $streams[$n].ReadAsync($buffers[$n], $counts[$n], 2048 - $counts[$n]) }
                }
            }
            if (($done[0] -and $done[1]) -or $counts[0] -ge 2048 -or $counts[1] -ge 2048) { break }
            [Threading.Thread]::Sleep(10)
        }
        if (-not $proc.HasExited) { $proc.Kill() }
        $text = [Text.Encoding]::UTF8.GetString($buffers[0], 0, $counts[0])
        foreach ($line in ($text -split "`r?`n")) { if ($line -match '^PHP\s+\d') { return $line.Trim() } }
        return $null
    } catch { return $null } finally {
        if ($null -ne $proc) {
            try { if (-not $proc.HasExited) { $proc.Kill() } } catch { }
            $proc.Dispose()
        }
    }
}

function Get-BinaryVersion {
    # 실행하지 않고 파일의 'PHP/X.Y.Z' 문자열(X-Powered-By 헤더 상수)에서 버전을 읽는다. 추정이므로 보조 수단이다.
    param([string]$Path)
    if (-not (Test-RegularFile $Path 125829120)) { return '' }
    $fs = $null
    try {
        $fs = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $enc = [System.Text.Encoding]::GetEncoding(28591)
        $buf = New-Object 'byte[]' 4194368
        $carry = 0
        $total = [long]0
        while ($total -lt 125829120) {
            $n = $fs.Read($buf, $carry, [int][Math]::Min($buf.Length - $carry, 125829120 - $total))
            if ($n -le 0) { break }
            $total = $total + $n
            $len = $carry + $n
            $text = $enc.GetString($buf, 0, $len)
            $m = [regex]::Match($text, 'PHP/(\d{1,9}\.\d{1,9}\.\d{1,9}(?:[-.]?(?:alpha|beta|RC|dev)(?![A-Za-z])\d*)?)', 'IgnoreCase')
            if ($m.Success) { return $m.Groups[1].Value }
            if ($len -gt 64) { [Array]::Copy($buf, $len - 64, $buf, 0, 64); $carry = 64 } else { $carry = $len }
        }
    } catch { } finally { if ($null -ne $fs) { $fs.Dispose() } }
    return ''
}

function Get-InstVersion {
    param($Inst)
    $res = @{ Text = ''; Source = ''; Notes = (New-Object 'System.Collections.Generic.List[string]') }
    # 명시적 테스트 환경에서만 fixture 지름길 허용. 일반 -Root 검사에서는 php.version을 신뢰하지 않는다.
    if ($script:RootDir -and $env:PHP2SHELL_TEST_VERSION_FILE -eq '1') {
        $vf = Join-Path $Inst.Dir 'php.version'
        if (Test-RegularFile $vf 2097152) {
            $first = ''
            foreach ($l in @(Read-SafeLines $vf)) { if (([string]$l).Trim()) { $first = ([string]$l).Trim(); break } }
            $res.Text = $first
            $res.Source = '테스트 fixture(php.version)'
            return $res
        }
    }
    $bins = @($Inst.Binaries)
    if ((Get-ExecMode) -ne 'never') {
        foreach ($want in @('cli', 'cgi')) {
            foreach ($b in $bins) {
                if ((Get-BinKind $b) -ne $want) { continue }
                if ([System.IO.Path]::GetFileName($b) -imatch '^php-win\.exe$') { continue }
                if (-not (Test-ExecAllowed $b)) {
                    $res.Notes.Add('실행 안 함: 신뢰할 수 없는 위치(쓰기 가능하거나 소유자가 root/관리자가 아님)')
                    continue
                }
                $out = Invoke-PhpVersion $b
                if ($out -and $null -ne (ConvertFrom-PhpVersion $out)) {
                    $res.Text = $out
                    $res.Source = ('{0} -n -v 출력' -f [System.IO.Path]::GetFileName($b))
                    break
                }
            }
            if ($res.Text) { break }
        }
        if (-not $res.Text) { $res.Notes.Add('실행으로 버전을 얻지 못해 파일 버전정보로 대체했습니다.') }
    }
    $vis = New-Object 'System.Collections.Generic.List[string]'
    $firstVi = ''
    $firstViName = ''
    foreach ($want in @('cgi', 'cli', 'apache', 'ts')) {
        foreach ($b in $bins) {
            if ((Get-BinKind $b) -ne $want) { continue }
            if (-not (Test-RegularFile $b)) { continue }
            $v = ''
            try {
                $vi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($b)
                $v = [string]$vi.ProductVersion
                if ($null -eq (ConvertFrom-PhpVersion $v)) { $v = [string]$vi.FileVersion }
            } catch { $v = '' }
            $pv = ConvertFrom-PhpVersion $v
            if ($null -eq $pv) { continue }
            $vis.Add(('{0}={1}' -f [System.IO.Path]::GetFileName($b), $pv.Text))
            if (-not $firstVi) { $firstVi = $v; $firstViName = [System.IO.Path]::GetFileName($b) }
        }
    }
    if (-not $res.Text -and $firstVi) {
        $res.Text = $firstVi
        $res.Source = ('{0} 파일 버전정보' -f $firstViName)
    }
    if (-not $res.Text) {
        foreach ($want in @('ts', 'cgi', 'cli', 'apache')) {
            foreach ($b in $bins) {
                if ((Get-BinKind $b) -ne $want) { continue }
                $sv = Get-BinaryVersion $b
                if ($sv) {
                    $res.Text = $sv
                    $res.Source = ('{0} 바이너리 문자열(PHP/x.y.z, 실행 안 함; 추정)' -f [System.IO.Path]::GetFileName($b))
                    break
                }
            }
            if ($res.Text) { break }
        }
    }
    if (-not $res.Text -and $script:RootDir -and -not $script:NoExecMode -and -not $script:ExecInRoot) {
        $res.Notes.Add('-Root 에서는 실행 파일을 실행하지 않습니다. 신뢰할 수 있는 트리라면 -Exec 를 함께 지정하세요.')
    }
    if ($res.Text) {
        $chosen = ConvertFrom-PhpVersion $res.Text
        $distinct = @{}
        foreach ($e in $vis) {
            $ver = $e.Split('=')[1]
            $pp = ConvertFrom-PhpVersion $ver
            if ($null -ne $pp -and $null -ne $chosen -and $pp.Key -ne $chosen.Key) { $distinct[$e] = $true }
        }
        if ($distinct.Count -gt 0) {
            $res.Notes.Add(('같은 디렉터리의 파일 버전이 서로 다릅니다({0}). 일부 파일만 교체되었을 수 있으니 전체를 교체하세요.' -f ((@($distinct.Keys) | Sort-Object) -join ', ')))
        }
    }
    return $res
}


function Read-IniSettings {
    # php.ini 를 정적 파싱한다(php -i 는 CLI 용 ini 를 읽어 웹 SAPI 와 다를 수 있으므로 쓰지 않는다). 마지막 값이 우선.
    param([string]$File, [hashtable]$Into)
    $lines = @()
    if (-not (Test-RegularFile $File 2097152)) { return $false }
    $lines = @(Read-SafeLines $File)
    foreach ($raw in $lines) {
        $line = ([string]$raw).Trim()
        if ($line.Length -eq 0 -or $line.StartsWith(';') -or $line.StartsWith('[')) { continue }
        $m = [regex]::Match($line, '^([A-Za-z0-9_.]+)\s*=\s*(.*)$')
        if (-not $m.Success) { continue }
        $val = $m.Groups[2].Value.Trim()
        if ($val.StartsWith('"')) {
            $end = $val.IndexOf('"', 1)
            if ($end -gt 0) { $val = $val.Substring(1, $end - 1) } else { $val = $val.Trim('"') }
        } elseif ($val.StartsWith("'")) {
            $end = $val.IndexOf("'", 1)
            if ($end -gt 0) { $val = $val.Substring(1, $end - 1) } else { $val = $val.Trim("'") }
        } else {
            $sc = $val.IndexOf(';')
            if ($sc -ge 0) { $val = $val.Substring(0, $sc).Trim() }
        }
        $Into[$m.Groups[1].Value.ToLowerInvariant()] = $val
    }
    return $true
}

function ConvertTo-IniBytes {
    param([string]$Value)
    $m = [regex]::Match($Value.Trim(), '^(-?\d+)\s*([KMGkmg]?)$')
    if (-not $m.Success) { return $null }
    $n = [decimal]$m.Groups[1].Value
    $u = $m.Groups[2].Value.ToUpperInvariant()
    if ($u -eq 'K') { $n = $n * 1KB } elseif ($u -eq 'M') { $n = $n * 1MB } elseif ($u -eq 'G') { $n = $n * 1GB }
    return $n
}

function Test-IniOff {
    param([string]$Value)
    return ($Value.Trim() -match '^(?i)(0|off|false|no|none|)$')
}

function Get-IniFileForInst {
    param($Inst)
    $cands = New-Object 'System.Collections.Generic.List[string]'
    if ($Inst.IniFile) { $cands.Add([string]$Inst.IniFile) }
    if ($Inst.Phprc) {
        if ($Inst.Phprc -match '\.ini$') { $cands.Add([string]$Inst.Phprc) } else { $cands.Add((Join-Path $Inst.Phprc 'php.ini')) }
    }
    if ($Inst.IniDir) { $cands.Add((Join-Path $Inst.IniDir 'php.ini')) }
    $cands.Add((Join-Path $Inst.Dir 'php.ini'))
    foreach ($c in $cands) { if (Test-Path -LiteralPath $c -PathType Leaf) { return $c } }
    return ''
}

function Get-MitigationNotes {
    param($Inst, [string]$Branch)
    $notes = New-Object 'System.Collections.Generic.List[string]'
    $ini = Get-IniFileForInst $Inst
    if (-not $ini) {
        $notes.Add('php.ini 를 찾지 못했습니다(기본값 사용 추정). 임시 조치 설정 상태를 확인할 수 없습니다.')
        return @($notes.ToArray())
    }
    $set = @{}
    [void](Read-IniSettings $ini $set)
    $scanned = ''
    if ($Inst.ScanDir) {
        foreach ($sd in ([string]$Inst.ScanDir).Split(';')) {
            if ([string]::IsNullOrWhiteSpace($sd)) { continue }
            $real = Resolve-FsPath $sd
            if (-not $real -or -not (Test-RootPath $real)) { continue }
            if (-not (Test-Path -LiteralPath $real -PathType Container)) { continue }
            foreach ($f in @(Get-ChildItem -LiteralPath $real -Filter '*.ini' -File -ErrorAction SilentlyContinue | Sort-Object Name)) {
                if (Read-IniSettings $f.FullName $set) { $scanned = $scanned + ' ' + $f.Name }
            }
        }
    }
    $hdr = ('임시 조치 설정 상태(php.ini 정적 분석, php -i 아님): {0}' -f $ini)
    if ($scanned) { $hdr = $hdr + ' + PHP_INI_SCAN_DIR:' + $scanned }
    $notes.Add($hdr)
    $notes.Add('임시 조치는 일부 공격 경로만 줄이며 완전한 해결이 아닙니다. 업데이트만이 근본 조치입니다.')

    $k = 'session.upload_progress.enabled'
    if ($set.ContainsKey($k)) {
        if (Test-IniOff $set[$k]) { $notes.Add(('{0} = {1}  (적용됨)' -f $k, $set[$k])) } else { $notes.Add(('{0} = {1}  (켜져 있음; 0 권장)' -f $k, $set[$k])) }
    } else { $notes.Add(('{0} 미설정  (기본값 1=켜짐; 0 권장)' -f $k)) }

    $k = 'memory_limit'
    if ($set.ContainsKey($k)) {
        if ($set[$k].Trim() -eq '-1') { $notes.Add('memory_limit = -1  (적용됨; 주의: OS 수준 메모리 상한 필요)') } else { $notes.Add(('memory_limit = {0}  (-1 권장이나 OS 수준 상한과 함께만 사용)' -f $set[$k])) }
    } else { $notes.Add('memory_limit 미설정  (기본값 128M)') }

    $k = 'post_max_size'
    if ($set.ContainsKey($k)) {
        $b = ConvertTo-IniBytes $set[$k]
        if ($null -ne $b -and $b -gt 0 -and $b -le 32MB) { $notes.Add(('post_max_size = {0}  (낮게 설정됨)' -f $set[$k])) } else { $notes.Add(('post_max_size = {0}  (8M~32M 이하 권장)' -f $set[$k])) }
    } else { $notes.Add('post_max_size 미설정  (기본값 8M)') }

    $k = 'session.auto_start'
    if ($set.ContainsKey($k)) {
        if (Test-IniOff $set[$k]) { $notes.Add(('{0} = {1}  (적용됨)' -f $k, $set[$k])) } else { $notes.Add(('{0} = {1}  (0 권장; {2})' -f $k, $set[$k], $script:AutoStartWarning)) }
    } else { $notes.Add(('{0} 미설정  (기본값 0)' -f $k)) }

    if ($Branch -eq '8.5') {
        $k = 'fatal_error_backtraces'
        if ($set.ContainsKey($k)) {
            if (Test-IniOff $set[$k]) { $notes.Add(('{0} = {1}  (적용됨)' -f $k, $set[$k])) } else { $notes.Add(('{0} = {1}  (0 권장)' -f $k, $set[$k])) }
        } else { $notes.Add(('{0} 미설정  (8.5 기본값 켜짐; 0 권장)' -f $k)) }
    }
    return @($notes.ToArray())
}

# ---------------------------------------------------------------------------
# 재시작 필요 여부
# ---------------------------------------------------------------------------
function Get-FileStamp {
    # 교체 시각 = LastWriteTime 과 CreationTime 중 늦은 쪽 (ZIP 해제본은 빌드 시각이 mtime 으로 남기 때문)
    param([string]$Path)
    if (-not (Test-RegularFile $Path)) { return $null }
    try {
        $fi = New-Object System.IO.FileInfo $Path
        if (-not $fi.Exists) { return $null }
        $t = $fi.LastWriteTime
        if ($fi.CreationTime -gt $t) { $t = $fi.CreationTime }
        return $t
    } catch { return $null }
}

function Get-RestartState {
    # $true: 파일 교체 이전에 시작된 프로세스가 있음 / $false: 없음(또는 프로세스 없음) / $null: 시작 시각이나 파일 시각을 알 수 없음
    param($Procs, $Stamp)
    if ($null -eq $Procs) { return $false }
    $list = @($Procs)
    if ($list.Count -eq 0) { return $false }
    if ($null -eq $Stamp) { return $null }
    $known = 0
    foreach ($p in $list) {
        if ($null -ne $p.StartTime) {
            $known++
            if ($p.StartTime -lt $Stamp) { return $true }
        }
    }
    if ($known -eq 0) { return $null }
    return $false
}

function Get-InstRestart {
    param($Inst)
    if ($script:RootDir) { return $null }
    $dllStamp = $null
    foreach ($b in $Inst.Binaries) {
        $k = Get-BinKind $b
        if ($k -eq 'ts' -or $k -eq 'apache') {
            $s = Get-FileStamp $b
            if ($null -ne $s -and ($null -eq $dllStamp -or $s -gt $dllStamp)) { $dllStamp = $s }
        }
    }
    $phpProcs = New-Object 'System.Collections.Generic.List[object]'
    $httpdProcs = New-Object 'System.Collections.Generic.List[object]'
    foreach ($p in $Inst.Procs) { if ($p.Kind -eq 'httpd') { $httpdProcs.Add($p) } else { $phpProcs.Add($p) } }
    $states = New-Object 'System.Collections.Generic.List[object]'
    if ($phpProcs.Count -gt 0) {
        $stamp = $dllStamp
        foreach ($p in $phpProcs) {
            if ($p.Path) {
                $s = Get-FileStamp $p.Path
                if ($null -ne $s -and ($null -eq $stamp -or $s -gt $stamp)) { $stamp = $s }
            }
        }
        $states.Add((Get-RestartState $phpProcs.ToArray() $stamp))
    }
    if ($httpdProcs.Count -gt 0) { $states.Add((Get-RestartState $httpdProcs.ToArray() $dllStamp)) }
    if ($states.Count -eq 0) { return $false }
    $anyNull = $false
    foreach ($s in $states) {
        if ($s -eq $true) { return $true }
        if ($null -eq $s) { $anyNull = $true }
    }
    if ($anyNull) { return $null }
    return $false
}

# ---------------------------------------------------------------------------
# 설치별 보고 객체
# ---------------------------------------------------------------------------
function Get-InstSapi {
    param($Inst)
    if ($Inst.Iis) { return 'iis' }
    if ($Inst.ApacheMod) { return 'apache' }
    $hasCgi = $false; $hasApache = $false; $hasCli = $false
    foreach ($b in $Inst.Binaries) {
        $k = Get-BinKind $b
        if ($k -eq 'cgi') { $hasCgi = $true } elseif ($k -eq 'apache') { $hasApache = $true } elseif ($k -eq 'cli') { $hasCli = $true }
    }
    foreach ($p in $Inst.Procs) { if ($p.Name -imatch '^php-cgi$') { $hasCgi = $true } }
    if ($hasCgi) { return 'cgi' }
    if ($hasApache) { return 'apache' }
    if ($hasCli) { return 'cli' }
    return 'unknown'
}

function Get-InstPrimaryPath {
    param($Inst, [string]$Sapi)
    $want = 'cli'
    if ($Sapi -eq 'iis' -or $Sapi -eq 'cgi') { $want = 'cgi' } elseif ($Sapi -eq 'apache') { $want = 'apache' }
    foreach ($w in @($want, 'cgi', 'cli', 'apache', 'ts')) {
        foreach ($b in $Inst.Binaries) { if ((Get-BinKind $b) -eq $w) { return $b } }
    }
    if ($Inst.Binaries.Count -gt 0) { return $Inst.Binaries[0] }
    return $Inst.Dir
}

function New-Report {
    param($Inst)
    $notes = New-Object 'System.Collections.Generic.List[string]'
    $ver = Get-InstVersion $Inst
    foreach ($n in $ver.Notes) { $notes.Add($n) }
    $cls = Get-PhpClass $ver.Text
    $pv = ConvertFrom-PhpVersion $ver.Text
    $vtext = ''
    if ($null -ne $pv) { $vtext = $pv.Text } elseif ($ver.Text) { $vtext = [string]$ver.Text }
    $branch = Get-Branch $ver.Text

    $vendor = 'unknown'
    if ($cls -ne 'fixed') {
        $notes.Add('Windows에서는 패키지 변경 내역 DB가 없어 벤더 패치를 확인하지 않습니다(vendor_patch=unknown). README/NEWS의 CVE 언급은 증거로 인정하지 않습니다.')
    }
    $verdict = Get-Verdict $cls $vendor

    $sapi = Get-InstSapi $Inst
    $path = Get-InstPrimaryPath $Inst $sapi
    $pids = New-Object 'System.Collections.Generic.List[int]'
    foreach ($p in $Inst.Procs) { if (-not $pids.Contains([int]$p.Pid)) { $pids.Add([int]$p.Pid) } }
    $running = ($pids.Count -gt 0)
    $needs = Get-InstRestart $Inst

    if ($ver.Source) { $notes.Add(('버전 확인 방법: {0}' -f $ver.Source)) }
    $notes.Add(('발견 경로: {0}' -f ($Inst.Sources -join ', ')))
    $names = New-Object 'System.Collections.Generic.List[string]'
    foreach ($b in $Inst.Binaries) { $names.Add([System.IO.Path]::GetFileName($b)) }
    $notes.Add(('이 디렉터리의 PHP 파일: {0}' -f ($names -join ', ')))
    if ($Inst.Iis) { $notes.Add('IIS FastCGI/핸들러 매핑에 등록되어 있습니다. 웹 요청을 처리하는 SAPI 입니다.') }
    elseif ($sapi -eq 'cgi') { $notes.Add('php-cgi.exe 가 있으나 IIS/Apache 등록은 확인되지 않았습니다(다른 설정 위치이거나 미사용일 수 있음).') }
    elseif ($sapi -eq 'cli') { $notes.Add('php.exe(CLI)만 발견되었습니다. 웹으로 노출되는 SAPI 는 확인되지 않았지만 예약 작업·배치로 외부 입력을 처리하면 영향을 받을 수 있습니다.') }
    if ($Inst.Services.Count -gt 0) { $notes.Add(('관련 서비스: {0}' -f ($Inst.Services -join ', '))) }
    if ($script:RootDir) {
        if ($script:ExecInRoot -and -not $script:NoExecMode) { $notes.Add('-Root 모드: 라이브 프로세스/서비스 점검을 건너뛰었습니다. -Exec 지정으로 트리 안 실행 파일 실행이 허용되었습니다.') }
        else { $notes.Add('-Root 모드: 라이브 프로세스/서비스 점검을 건너뛰었고 트리 안 실행 파일을 실행하지 않았습니다(-Exec 로 허용 가능).') }
    } elseif ($Inst.Procs.Count -gt 0 -and $null -eq $needs) {
        $notes.Add('프로세스 시작 시각을 읽지 못해 재시작 필요 여부를 판단할 수 없습니다(관리자 권한 필요).')
    }
    if ($needs -eq $true) { $notes.Add('실행 중인 프로세스가 PHP 파일 교체 시각보다 먼저 시작되었습니다. 디스크의 파일이 바뀌었어도 메모리의 이전 코드가 계속 동작하므로 서비스/워커를 재시작해야 합니다.') }
    if ($verdict -eq 'vulnerable' -and ($cls -eq 'eol_backport' -or $cls -eq 'eol_no_fix')) {
        if ($cls -eq 'eol_backport') { $notes.Add('7.4/8.0/8.1 은 공식 수정 릴리스가 없습니다. 벤더 패치 또는 소스 백포트만 가능하며, 8.3 이상으로의 이전을 권장합니다.') }
        else { $notes.Add('5.4~7.3 은 EOL 이며 어디에도 수정이 없습니다. 지원되는 브랜치로 이전하세요.') }
    }
    if ($verdict -eq 'eol') { $notes.Add('5.4 미만은 공표된 영향 범위 밖이지만 오래전에 EOL 된 버전입니다. 안전하지 않으므로 이전하세요.') }
    if ($branch -eq '8.2') { $notes.Add('8.2 의 보안 지원은 2026-12-31 에 종료됩니다. 8.4/8.5 로의 이전을 계획하세요.') }
    if ($verdict -ne 'fixed' -or $needs -eq $true) {
        foreach ($mn in @(Get-MitigationNotes $Inst $branch)) { $notes.Add($mn) }
    }

    return [ordered]@{
        path          = $path
        version       = $vtext
        class         = $cls
        verdict       = $verdict
        sapi          = $sapi
        running       = $running
        pids          = @($pids.ToArray())
        package       = $null
        vendor_patch  = $vendor
        needs_restart = $needs
        notes         = @($notes.ToArray())
    }
}

# ---------------------------------------------------------------------------
# 조치 계획 / 출력
# ---------------------------------------------------------------------------
function Get-VerdictLabel {
    param([string]$Verdict)
    switch ($Verdict) {
        'fixed' { return '수정됨(업스트림 수정 버전 이상)' }
        'vendor_patched' { return '벤더 패치 확인됨' }
        'vulnerable' { return '취약' }
        'eol' { return '지원 종료(EOL) - 이전 필요' }
        default { return '판단 불가' }
    }
}

function Get-TargetLine {
    param([string]$Branch, [string]$Class)
    if ($script:FixedReleases.Contains($Branch)) {
        return ('PHP {0}: {1} 이상으로 업데이트' -f $Branch, $script:FixedReleases[$Branch])
    }
    if ($Class -eq 'eol_backport') { return ('PHP {0}: 공식 수정 릴리스 없음 -> 벤더 패치 확인 또는 {1} 이상(권장 8.4/8.5)으로 이전 후 호환성 테스트' -f $Branch, $script:FixedReleases['8.3']) }
    return ('PHP {0}: 수정 없음(EOL) -> {1} 이상(권장 8.4/8.5)으로 이전. 이전 전까지는 외부에서 이 PHP로 오는 요청을 차단/격리' -f $Branch, $script:FixedReleases['8.3'])
}

function Get-PlanLines {
    param($Reports, $Insts)
    $L = New-Object 'System.Collections.Generic.List[string]'
    $L.Add('=== 조치 계획 (Windows) ===')
    $L.Add('업데이트만이 근본 조치입니다. 아래 임시 조치는 일부 공격 경로만 줄이며 안전을 보장하지 않습니다.')
    $L.Add('서버 설정·패키지를 바꾸지 않았습니다. 신뢰할 수 있는 PHP 바이너리만 -n -v 로 실행합니다(-NoExec 로 끌 수 있음). 아래 조치 명령은 출력만 했습니다.')
    $L.Add('')

    $branches = New-Object 'System.Collections.Generic.List[string]'
    $dirs = New-Object 'System.Collections.Generic.List[string]'
    $hasIis = $false; $hasApache = $false; $vendorDirs = New-Object 'System.Collections.Generic.List[string]'
    $anyRestartOnly = $false
    foreach ($r in $Reports) {
        $act = ($r.verdict -in @('vulnerable', 'eol', 'unknown')) -or ($r.needs_restart -eq $true)
        if (-not $act) { continue }
        if ($r.verdict -in @('vulnerable', 'eol')) {
            $line = Get-TargetLine (Get-Branch $r.version) $r.class
            Add-Unique $branches $line
        }
        $d = Split-Path -Parent $r.path
        if ($r.path -and -not (Test-Path -LiteralPath $r.path -PathType Container)) { Add-Unique $dirs $d }
        if ($r.sapi -eq 'iis' -or $r.sapi -eq 'cgi') { $hasIis = $hasIis -or ($r.sapi -eq 'iis') }
        if ($r.sapi -eq 'apache') { $hasApache = $true }
        if ($r.verdict -eq 'fixed' -or $r.verdict -eq 'vendor_patched') { $anyRestartOnly = $true }
        if ($d -match '(?i)[\\/](xampp|wamp[^\\/]*|laragon|mamp)[\\/]') { Add-Unique $vendorDirs $d }
    }

    $L.Add('[1] 업데이트 대상')
    if ($branches.Count -eq 0) { $L.Add('  - (업데이트가 필요한 브랜치 없음 - 아래 재시작/확인 항목만 해당)') }
    foreach ($b in $branches) { $L.Add('  - ' + $b) }
    $L.Add('')
    $L.Add('[2] 수정된 Windows ZIP 받기 (수동 다운로드; 이 도구는 네트워크를 사용하지 않음)')
    $L.Add('  - https://windows.php.net/download 에서 해당 브랜치의 최신 ZIP 을 받습니다.')
    $L.Add('  - Apache(mod_php): Thread Safe(TS) ZIP / IIS FastCGI(php-cgi): Non Thread Safe(NTS) ZIP.')
    $L.Add('    Apache 는 VS 런타임(vs16/vs17)이 Apache 빌드와 일치해야 합니다.')
    $L.Add('  - 페이지에 표시된 SHA-256 체크섬과 직접 대조하세요:')
    $L.Add('      Get-FileHash -Algorithm SHA256 -LiteralPath .\<다운로드한파일>.zip')
    $L.Add('')
    if ($script:OfflineMode) {
        $L.Add('[2-오프라인] 오프라인/폐쇄망 서버 절차 (서버가 인터넷에 연결되지 않은 경우)')
        $L.Add('  1) 인터넷이 되는 별도 PC 에서 https://windows.php.net/download 의 해당 브랜치 ZIP 과 페이지에 표시된 SHA-256 값을 받아 둡니다.')
        $L.Add('       Get-FileHash -Algorithm SHA256 -LiteralPath .\<다운로드한파일>.zip   # 페이지의 값과 대조하고 값을 텍스트 파일로 함께 보관')
        $L.Add('     같은 PC 에서 PHP ZIP 이 요구하는 Microsoft Visual C++ 재배포 가능 패키지(x64, VS 2015-2022 계열; 8.2/8.3 은 vs16, 8.4/8.5 는 vs17 빌드)도')
        $L.Add('     Microsoft 공식 배포처에서 받아 둡니다(ZIP 다운로드 페이지의 요구 사항 표기를 확인하세요).')
        $L.Add('  2) 이동매체(USB 등)로 서버에 옮기고, 서버에서 다시 Get-FileHash 를 실행해 1) 의 값과 일치하는지 확인합니다(전송 중 손상/변조 확인).')
        $L.Add('  3) 서버에 VC++ 재배포 패키지가 있는지 확인하고 없으면 옮겨 온 설치 파일로 설치합니다.')
        $L.Add('       Get-ItemProperty ''HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64'' -ErrorAction SilentlyContinue | Select-Object Installed, Version')
        $L.Add('  4) 아래 [3] 의 순서대로 서비스 중지 -> php 폴더 교체(php.ini 보존, 이전 폴더는 .old-날짜 이름으로 백업 보관) -> 서비스 시작을 진행합니다.')
        $L.Add('  - 백업한 이전 폴더는 롤백용이며 취약 버전입니다. 검증이 끝나면 웹에서 접근할 수 없는 위치로 옮기거나 삭제하세요.')
        $L.Add('')
    }

    $L.Add('[3] 서비스를 멈추고 PHP 디렉터리 교체 (php.ini 는 보존)')
    if ($hasIis -or -not $hasApache) {
        $L.Add('  IIS(FastCGI):')
        $L.Add('      iisreset /stop')
        $L.Add('      # 특정 앱 풀만 멈추려면: Import-Module WebAdministration; Stop-WebAppPool -Name ''<앱풀이름>''')
    }
    if ($hasApache -or -not $hasIis) {
        $svc = 'Apache2.4'
        if ($script:ApacheServices.Count -gt 0) { $svc = $script:ApacheServices[0] }
        $L.Add('  Apache:')
        $L.Add(('      Stop-Service -Name {0}' -f (ConvertTo-PsLiteral $svc)))
        if ($script:ApacheServices.Count -gt 1) { $L.Add(('      # 발견된 Apache 서비스: {0}' -f ($script:ApacheServices -join ', '))) }
    }
    $stampDir = '20261023'
    $zipVar = '.\<다운로드한파일>.zip'
    if ($dirs.Count -eq 0) { $L.Add('  (교체 대상 디렉터리가 확정되지 않았습니다. 아래 형식에서 경로를 바꿔 사용하세요.)'); [void]$dirs.Add('C:\php') }
    foreach ($d in $dirs) {
        if ($vendorDirs.Contains($d)) { continue }
        $L.Add(('  교체: {0}' -f $d))
        $L.Add(('      Rename-Item -LiteralPath {0} -NewName {1}' -f (ConvertTo-PsLiteral $d), (ConvertTo-PsLiteral ((Split-Path -Leaf $d) + '.old-' + $stampDir))))
        $L.Add(('      Expand-Archive -LiteralPath {0} -DestinationPath {1}' -f $zipVar, (ConvertTo-PsLiteral $d)))
        $L.Add(('      Copy-Item -LiteralPath {0} -Destination {1}' -f (ConvertTo-PsLiteral ($d + '.old-' + $stampDir + '\php.ini')), (ConvertTo-PsLiteral ($d + '\php.ini'))))
    }
    $L.Add('      # 확장(ext) 디렉터리 경로와 새 php.ini-production 의 변경점도 비교하세요.')
    foreach ($d in $vendorDirs) {
        $L.Add(('  벤더 번들 감지: {0}' -f $d))
    }
    if ($vendorDirs.Count -gt 0) {
        $L.Add('    XAMPP/WAMP/Laragon/MAMP 는 벤더 패키지로 업데이트하세요(수동 교체는 번들과 어긋날 수 있음):')
        $L.Add('      - XAMPP: https://www.apachefriends.org 에서 PHP 가 수정된 새 인스톨러로 업데이트 후 제어판에서 Apache 재시작')
        $L.Add('      - WAMP: Wampserver 의 PHP 애드온(수정된 버전)을 설치한 뒤 트레이 메뉴에서 PHP 버전 전환')
        $L.Add('      - Laragon: 메뉴 > PHP > 버전 추가 로 수정된 버전을 추가하고 전환')
        $L.Add('    번들 갱신이 아직 없다면 위 ZIP 을 별도 디렉터리에 풀어 해당 제품의 PHP 경로를 바꾸는 방법이 있습니다.')
    }
    $L.Add('')

    $L.Add('[4] 다시 시작하고 모든 PHP 워커 재시작')
    if ($hasIis -or -not $hasApache) {
        $L.Add('      iisreset /start')
        $L.Add('      Get-Process php-cgi -ErrorAction SilentlyContinue | Stop-Process -Force   # 남은 php-cgi 워커 종료(이전 코드 제거)')
    }
    if ($hasApache -or -not $hasIis) {
        $svc = 'Apache2.4'
        if ($script:ApacheServices.Count -gt 0) { $svc = $script:ApacheServices[0] }
        $L.Add(('      Start-Service -Name {0}   # mod_php 는 전체 Stop/Start로 DLL을 다시 로드' -f (ConvertTo-PsLiteral $svc)))
    }
    $L.Add('  재시작은 모든 워커가 대상입니다. 파일만 교체하면 실행 중 프로세스는 계속 이전 코드를 사용합니다.')
    $L.Add('')

    $L.Add('[5] 웹 요청으로 확인 (CLI 의 php -v 는 웹 SAPI 와 다른 PHP/ini 를 볼 수 있음)')
    $L.Add('  - 웹 루트에 로컬호스트 전용으로 PHP_VERSION 만 출력하는 임시 페이지를 만들어 웹 요청으로 확인한 뒤 즉시 삭제하세요.')
    $L.Add('      (phpinfo() 등 상세 정보 페이지는 외부에 노출하지 마세요.)')
    $L.Add('      Invoke-WebRequest -UseBasicParsing http://localhost/<임시페이지>.php')
    $L.Add('')

    $L.Add('[6] 업데이트 전 임시 조치 (완전한 해결 아님) - php.ini 에 관리자만 수정 가능하게 적용')
    $L.Add('      session.upload_progress.enabled = 0')
    $L.Add('      memory_limit = -1')
    $L.Add('        ; 주의: ' + $script:MemoryLimitWarning)
    $L.Add('      post_max_size = 8M        ; 업로드가 필요 없으면 8M, 필요하면 32M 수준. upload_max_filesize 는 post_max_size 보다 작게 유지')
    $L.Add('      session.auto_start = 0')
    $L.Add('        ; 주의: ' + $script:AutoStartWarning)
    $L.Add('      fatal_error_backtraces = 0   ; PHP 8.5 에만 해당')
    $L.Add('      user_ini.filename =          ; .user.ini 비활성화(.user.ini/ini_set 으로 사용자가 바꿀 수 없게)')
    $L.Add('  - 위 값은 php.ini 파일에 두고 파일 ACL 을 관리자/SYSTEM 쓰기 전용으로 제한하세요. IIS FastCGI 에는 php_admin_value 가 없습니다.')
    $L.Add('  - Apache(mod_php)는 httpd.conf 의 php_admin_value 를 쓰면 사용자 ini_set/.htaccess 로 덮어쓸 수 없습니다.')
    $L.Add('        php_admin_value session.upload_progress.enabled 0')
    $L.Add('        php_admin_value memory_limit -1')
    $L.Add('        php_admin_value session.auto_start 0')
    $L.Add('  - ini 위치가 SAPI 마다 다릅니다: IIS FastCGI 의 php-cgi 는 PHPRC 환경변수(FastCGI 설정) 또는 php-cgi.exe 가 있는 디렉터리의')
    $L.Add('    php.ini 를, Apache 모듈은 PHPIniDir 를 봅니다. 실제 웹 프로세스가 읽는 파일에 적용되었는지 웹 요청으로 확인하세요.')
    $L.Add('  - .user.ini 에 의존하지 마세요. 설정 변경 후 모든 워커를 재시작해야 반영됩니다.')
    $L.Add('')
    $L.Add('[7] 가상 패치(임시 대응) - 완전한 해결이 아닙니다. 업데이트 전까지 공격 경로를 줄이는 용도입니다. virtual-patch/ 디렉터리(저장소)를 참고하세요.')
    $L.Add('  - IIS Request Filtering: 본문 크기 상한(maxAllowedContentLength, 바이트)을 낮춥니다:')
    $L.Add('      Set-WebConfigurationProperty -PSPath ''MACHINE/WEBROOT/APPHOST'' -Location ''<사이트이름>'' -Filter ''system.webServer/security/requestFiltering/requestLimits'' -Name maxAllowedContentLength -Value 8388608')
    $L.Add('  - IIS URL Rewrite(업로드가 필요 없는 사이트만): web.config 의 <system.webServer><rewrite><rules> 에 multipart/form-data 요청을 403 으로 거부하는 규칙을 추가합니다:')
    $L.Add('      <rule name="deny-multipart" stopProcessing="true"><match url=".*" /><conditions><add input="{HTTP_CONTENT_TYPE}" pattern="^multipart/form-data" /></conditions><action type="CustomResponse" statusCode="403" statusReason="Forbidden" statusDescription="Forbidden" /></rule>')
    $L.Add('  - php.ini 임시 값: 위 [6] 의 값을 적용(session.upload_progress.enabled=0, post_max_size 하향 등)하고 모든 워커를 재시작합니다.')
    $L.Add('  - 노출 축소: IIS IP 주소 제한(IP Address and Domain Restrictions)이나 Apache Require ip 로 접근을 신뢰 대역에 한정하거나, 점검 페이지로 전환하거나, 사이트를 중지합니다:')
    $L.Add('      Stop-Website -Name ''<사이트이름>''     # 또는 Stop-WebAppPool -Name ''<앱풀이름>''')
    $L.Add('  - Windows 방화벽 아웃바운드 제한: PHP 프로세스가 외부로 나가는 연결을 막아 침해 후 외부 통신을 줄입니다(외부 API/메일 연동이 없는지 확인 후):')
    $L.Add('      New-NetFirewallRule -DisplayName ''php-cgi outbound block'' -Direction Outbound -Action Block -Program ''<php-cgi.exe 전체 경로>''')
    $L.Add('  - WAF: 사용 중인 WAF 에서 multipart/form-data 요청의 본문 크기 상한과 업로드 가능 경로 제한, 공급사가 배포한 PHP2Shell 서명 규칙을 적용합니다.')
    $L.Add('  - 위 항목은 모두 일부 공격 경로만 줄입니다. 반드시 업데이트(또는 지원되는 브랜치로 이전)를 완료하세요.')
    $L.Add('')
    return @($L.ToArray())
}

function Get-EvidenceLines {
    $L = New-Object 'System.Collections.Generic.List[string]'
    $L.Add('=== 증거 보존 / 신고 ===')
    $L.Add('  - 침해가 의심되면 증거를 수집하기 전에 서버를 재시작하거나 PHP 를 교체하지 마세요(메모리/프로세스 증거가 사라집니다).')
    $L.Add('    먼저 격리(네트워크 차단) 후 메모리 덤프, 웹/PHP/이벤트 로그, php-cgi·w3wp·httpd 프로세스 목록을 보존하세요.')
    $L.Add(('  - 로그 검토 시작 기준일: {0} (최초 악용 관측일 2026-10-17)' -f $script:LogReviewSince))
    $L.Add('  - 침해사고 신고/상담: KISA 118 (국번 없이 118), https://boho.or.kr')
    return @($L.ToArray())
}

function Get-SourceLines {
    $L = New-Object 'System.Collections.Generic.List[string]'
    $L.Add('=== 참고 자료 ===')
    foreach ($s in $script:Sources) { $L.Add(('  - {0}: {1}' -f $s.title, $s.url)) }
    return @($L.ToArray())
}

function Get-HelpLines {
    return @(
        'php2shell-quickcheck.ps1 - PHP2Shell(CVE-2026-109618 / CVE-2026-109619) Windows 점검 (방어 전용)',
        '',
        '사용법:  powershell -NoProfile -ExecutionPolicy Bypass -File .\php2shell-quickcheck.ps1 [옵션]',
        '',
        '옵션:',
        '  -Json          기계 판독용 JSON 을 출력합니다.',
        '  -NoExec        발견한 어떤 바이너리도 실행하지 않고 파일 버전정보/바이너리 문자열을 사용합니다.',
        '  -Exec          신뢰하는 호스트에서만 사용하세요. 신뢰 검사를 우회하여 발견한 PHP 바이너리를 -n -v 로 실행합니다(-NoExec 가 우선).',
        '                 -Root 에서는 -Exec 없이는 실행하지 않습니다.',
        '  -Offline       오프라인/폐쇄망 서버용 패치 절차(다른 PC 에서 ZIP/SHA-256 확보 -> 이동매체 -> 교체)를 조치 계획에 추가합니다.',
        '  -PlanFile <경로> 이 서버(탐지한 PHP 경로·서비스·SAPI) 맞춤 조치 계획을 관리자가 검토하는 .ps1 파일로 저장합니다.',
        '                 생성 파일은 환경 변수 PHP2SHELL_I_REVIEWED=yes 가 없으면 종료 코드 64 로 끝나며, 위험 단계마다 y/N 확인을 묻습니다.',
        '                 이 도구는 그 명령을 절대 실행하지 않습니다(자동 패치 없음). 기존 파일은 덮어쓰지 않으며 종료 코드 2로 거부합니다.',
        '  -Root <경로>   <경로>를 파일시스템 루트로 간주하고 라이브 프로세스/서비스 점검을 건너뜁니다(오프라인 트리 검사).',
        '  -Help          이 도움말을 출력합니다.',
        '',
        '종료 코드:  0 = 조치 필요 없음 / 1 = 취약·EOL 또는 수정됐으나 이전 코드 실행 중 / 3 = 판단 불가',
        '',
        '서버 설정·패키지를 바꾸지 않습니다. 기본적으로 신뢰할 수 있는 PHP 바이너리만 -n -v 로 실행합니다(-NoExec 로 끌 수 있음). 의심되는 호스트에서는 -NoExec 를 쓰세요.',
        '관리자 권한 없이도 실행되지만 다른 계정(IIS 앱 풀 ID 등)의 프로세스 정보와 applicationHost.config 는 읽지 못할 수 있습니다.',
        '',
        '출력 인코딩: 한글과 JSON 은 항상 BOM 없는 UTF-8 로 출력합니다. cp949 콘솔에서 한글이 깨지면 먼저 `chcp 65001` 을 실행하거나 Windows Terminal 에서 실행하세요.',
        '  배치 래퍼 예: powershell -NoProfile -ExecutionPolicy Bypass -File php2shell-quickcheck.ps1 %*  (종료 코드는 %ERRORLEVEL 로 전달됩니다)'
    )
}

function ConvertTo-ReportText {
    param($Reports, $Summary, [int]$ExitCode, [string]$HostName, [string]$Platform, [string]$PlanSaved = '')
    $L = New-Object 'System.Collections.Generic.List[string]'
    $L.Add('PHP2Shell (CVE-2026-109618 / CVE-2026-109619) 점검 - Windows (PowerShell)')
    $L.Add(('기준일: {0}   호스트: {1}   플랫폼: {2}' -f $script:AsOf, $HostName, $Platform))
    $L.Add('방식: 파일/프로세스/설정 정적 분석(php -i 미사용). 서버 설정·패키지를 바꾸지 않습니다. 신뢰할 수 있는 PHP만 -n -v 로 실행(-NoExec 로 끔).')
    $L.Add('')
    foreach ($w in $script:Warnings) { $L.Add('[주의] ' + $w) }
    if ($script:Warnings.Count -gt 0) { $L.Add('') }
    if ($Reports.Count -eq 0) {
        $L.Add('발견된 PHP 설치가 없습니다.')
        if ($ExitCode -eq 3) { $L.Add('다만 권한/프로세스 열거 제한으로 확정할 수 없습니다(판단 불가).') }
        $L.Add('')
    }
    $i = 0
    foreach ($r in $Reports) {
        $i++
        $L.Add(('--- [{0}] {1} (class: {2}) ---' -f $i, (Get-VerdictLabel $r.verdict), $r.class))
        $vt = $r.version
        if (-not $vt) { $vt = '(알 수 없음)' }
        $L.Add(('  버전    : {0}' -f $vt))
        $L.Add(('  경로    : {0}' -f $r.path))
        $L.Add(('  SAPI    : {0}' -f $r.sapi))
        if ($r.running) { $L.Add(('  실행 중 : 예 (PID {0})' -f ($r.pids -join ', '))) } else { $L.Add('  실행 중 : 아니오(확인된 프로세스 없음)') }
        $nr = '알 수 없음'
        if ($r.needs_restart -eq $true) { $nr = '예 - 파일 교체 이전에 시작된 프로세스가 있음' } elseif ($r.needs_restart -eq $false) { $nr = '아니오' }
        $L.Add(('  재시작 필요: {0}' -f $nr))
        $L.Add(('  벤더 패치: {0}' -f $r.vendor_patch))
        foreach ($n in $r.notes) { $L.Add('  - ' + $n) }
        $L.Add('')
    }
    $L.Add(('요약: 취약 {0}, 수정됨 {1}, 벤더패치 {2}, EOL {3}, 판단불가 {4}, 재시작필요 {5}   (종료 코드 {6})' -f $Summary.vulnerable, $Summary.fixed, $Summary.vendor_patched, $Summary.eol, $Summary.unknown, $Summary.needs_restart, $ExitCode))
    $L.Add('')
    $actionable = ($Summary.vulnerable + $Summary.eol + $Summary.unknown + $Summary.needs_restart) -gt 0
    if ($actionable) {
        foreach ($p in (Get-PlanLines $Reports $null)) { $L.Add($p) }
    } elseif ($Reports.Count -gt 0) {
        $L.Add('조치 계획: 모든 설치가 수정 버전이며 재시작 필요 항목이 없습니다. 추가 조치는 필요 없습니다.')
        $L.Add('')
    }
    if ($PlanSaved) {
        $L.Add(('맞춤 조치 계획 스크립트를 저장했습니다: {0}' -f $PlanSaved))
        $L.Add('  이 도구는 그 명령을 실행하지 않았습니다. 검토 후 $env:PHP2SHELL_I_REVIEWED = ''yes'' 를 설정하고 직접 실행하세요(서비스 중지·폴더 교체·시작 전 y/N 확인).')
        $L.Add('')
    }
    foreach ($p in (Get-EvidenceLines)) { $L.Add($p) }
    $L.Add('')
    foreach ($p in (Get-SourceLines)) { $L.Add($p) }
    return ((@($L | ForEach-Object { ConvertTo-SafeText $_ })) -join "`n")
}

function Get-PlatformString {
    try {
        if ($script:OnWindows) {
            $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
            return ('{0} {1}' -f $os.Caption, $os.Version)
        }
    } catch { }
    return [System.Environment]::OSVersion.VersionString
}

function ConvertTo-PsLiteral {
    param([string]$Text)
    $safe = ConvertTo-SafeText $Text
    return ("'" + [regex]::Replace($safe, "['\u2018\u2019\u201a\u201b]", '$0$0') + "'")
}

function ConvertTo-CommentText {
    param([string]$Text)
    return (ConvertTo-SafeText $Text)
}

function New-PlanScript {
    # 이 서버 맞춤 조치 계획을 "관리자가 검토 후 직접 실행하는" .ps1 텍스트로 만든다. 이 도구는 생성한 명령을 절대 실행하지 않는다.
    param($Pairs)
    $S = New-Object 'System.Collections.Generic.List[string]'
    $replace = New-Object 'System.Collections.Generic.List[object]'
    $restartOnly = New-Object 'System.Collections.Generic.List[string]'
    $review = New-Object 'System.Collections.Generic.List[string]'
    $svcs = New-Object 'System.Collections.Generic.List[string]'
    $cgiPaths = New-Object 'System.Collections.Generic.List[string]'
    $hasIis = $false
    $hasApache = $false
    foreach ($p in $Pairs) {
        $r = $p.Report
        $i = $p.Inst
        if ($i.Dir -match '[\x00-\x1f\x7f-\x9f\u2028\u2029]') {
            $review.Add((ConvertTo-SafeText $i.Dir))
            continue
        }
        $isReplace = ($r.verdict -eq 'vulnerable' -or $r.verdict -eq 'eol')
        $isRestart = ($r.needs_restart -eq $true -and -not $isReplace)
        if ($r.verdict -eq 'unknown') { Add-Unique $review $i.Dir }
        if (-not ($isReplace -or $isRestart)) { continue }
        if ($i.Iis) { $hasIis = $true }
        if ($i.ApacheMod) {
            $hasApache = $true
            foreach ($sv in $i.Services) { Add-Unique $svcs $sv }
        }
        foreach ($b in $i.Binaries) { if ((Get-BinKind $b) -eq 'cgi') { Add-Unique $cgiPaths $b } }
        if ($isReplace) {
            $vendor = ($i.Dir -match '(?i)[\\/](xampp|wamp[^\\/]*|laragon|mamp)[\\/]')
            $replace.Add([pscustomobject]@{ Dir = $i.Dir; Vendor = $vendor; Report = $r })
        } else { Add-Unique $restartOnly $i.Dir }
    }
    if ($hasApache -and $svcs.Count -eq 0) {
        foreach ($sv in $script:ApacheServices) { Add-Unique $svcs $sv }
        if ($svcs.Count -eq 0) { $svcs.Add('Apache2.4') }
    }
    $anyAction = ($replace.Count -gt 0 -or $restartOnly.Count -gt 0)

    $S.Add('<#')
    $S.Add('  !!! 경고 !!! PHP2Shell (CVE-2026-109618 / CVE-2026-109619) 맞춤 조치 계획 - 자동 실행용이 아닙니다.')
    $S.Add('')
    $S.Add('  이 파일은 php2shell-quickcheck.ps1 이 이 서버에서 읽은 정보(PHP 경로, 서비스, SAPI)로 생성한 초안입니다.')
    $S.Add('  생성 도구는 이 파일의 어떤 명령도 실행하지 않았습니다. 관리자가 각 단계를 직접 검토한 뒤 실행해야 합니다.')
    $S.Add('  - 서비스 중지, 폴더 교체, 서비스 시작 전에는 y/N 확인을 묻습니다.')
    $S.Add('  - 침해가 의심되면 재시작/교체 전에 증거를 먼저 확보하세요(0단계).')
    $S.Add('  - 서비스 중단이 발생합니다. 점검 시간대에, 백업과 롤백 계획을 갖춘 뒤 진행하세요.')
    $S.Add('  - 실행하려면 검토 후 같은 세션에서 다음을 설정하세요:  $env:PHP2SHELL_I_REVIEWED = ''yes''')
    $S.Add('#>')
    $S.Add('if ($env:PHP2SHELL_I_REVIEWED -ne ''yes'') {')
    $S.Add('    Write-Output ''이 파일은 자동 실행용이 아닙니다. 각 단계를 검토한 뒤 직접 실행하세요. (검토 후: $env:PHP2SHELL_I_REVIEWED = ''''yes'''')''')
    $S.Add('    exit 64')
    $S.Add('}')
    $S.Add('')
    $S.Add('$ErrorActionPreference = ''Stop''')
    $S.Add('Set-StrictMode -Version 2.0')
    $S.Add('$script:ZipPath = ''''')
    $S.Add('')
    $S.Add('function Confirm-Step {')
    $S.Add('    param([string]$Message)')
    $S.Add('    try { $a = Read-Host ($Message + '' - 진행하시겠습니까? (y/N)'') } catch { return $false }')
    $S.Add('    if ($null -eq $a) { return $false }')
    $S.Add('    return ($a.Trim() -match ''^(?i)y(es)?$'')')
    $S.Add('}')
    $S.Add('')
    $S.Add('function Invoke-Step {')
    $S.Add('    param([string]$Title, [scriptblock]$Action)')
    $S.Add('    Write-Output ''''')
    $S.Add('    Write-Output (''=== '' + $Title + '' ==='')')
    $S.Add('    if (Confirm-Step $Title) { & $Action } else { Write-Output (''건너뜀: '' + $Title) }')
    $S.Add('}')
    $S.Add('')
    $S.Add('# ---------------------------------------------------------------------------')
    $S.Add('# 0단계: 증거 보존 (가장 먼저)')
    $S.Add('# ---------------------------------------------------------------------------')
    $S.Add('Write-Output ''[0단계] 증거 보존''')
    $S.Add('Write-Output ''  침해가 의심되면 서비스를 중지/재시작하거나 PHP 를 교체하기 전에 증거를 확보하세요(재시작하면 메모리/프로세스 증거가 사라집니다).''')
    $S.Add('Write-Output ''  네트워크 격리 후 메모리 덤프, 웹/PHP/이벤트 로그(2026-10-17 이후), php-cgi·w3wp·httpd 프로세스 목록을 보존하세요.''')
    $S.Add('Write-Output ''  침해사고 신고/상담: KISA 118 (국번 없이 118), https://boho.or.kr''')
    $S.Add('if (-not (Confirm-Step ''침해 징후가 없거나 증거 수집을 이미 마쳤습니까'')) {')
    $S.Add('    Write-Output ''증거 수집 후 다시 실행하세요. 아무것도 변경하지 않았습니다.''')
    $S.Add('    exit 65')
    $S.Add('}')
    $S.Add('Invoke-Step ''증거 스냅샷 저장(프로세스/연결 목록을 CSV 로 저장; 로그/덤프는 직접 수집)'' {')
    $S.Add('    $ev = $env:SystemDrive + ''\p2s-evidence-'' + [guid]::NewGuid().ToString(''N'')')
    $S.Add('    [void](New-Item -ItemType Directory -Path $ev)')
    $S.Add('    $icacls = [IO.Path]::Combine([Environment]::GetFolderPath([Environment+SpecialFolder]::Windows), ''System32\icacls.exe'')')
    $S.Add('    & $icacls $ev /inheritance:r /grant:r ''*S-1-5-32-544:(OI)(CI)F'' ''*S-1-5-18:(OI)(CI)F'' | Out-Null')
    $S.Add('    if ($LASTEXITCODE -ne 0) { throw ''증거 폴더 ACL 제한 실패: 데이터 수집을 중지합니다.'' }')
    $S.Add('    Get-Process -ErrorAction SilentlyContinue | Select-Object Id, ProcessName, Path, StartTime | Export-Csv -NoTypeInformation -LiteralPath (Join-Path $ev ''processes.csv'')')
    $S.Add('    if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) { Get-NetTCPConnection | Export-Csv -NoTypeInformation -LiteralPath (Join-Path $ev ''connections.csv'') }')
    $S.Add('    Write-Output (''저장됨: '' + $ev)')
    $S.Add('}')
    $S.Add('')

    if (-not $anyAction) {
        $S.Add('Write-Output ''이 서버에서는 업데이트/재시작이 필요한 항목이 확인되지 않았습니다.''')
        if ($review.Count -gt 0) {
            foreach ($d in $review) { $S.Add('# 버전을 확인하지 못한 설치: ' + (ConvertTo-CommentText $d)) }
            $S.Add('Write-Output ''버전을 확인하지 못한 PHP 설치가 있습니다. 직접 확인하세요.''')
        }
        $S.Add('exit 0')
        return ($S -join "`r`n")
    }

    $S.Add('# ---------------------------------------------------------------------------')
    $S.Add('# 1단계: 수정된 Windows ZIP 확인 (수동 다운로드, 이 파일은 네트워크를 쓰지 않음)')
    $S.Add('# ---------------------------------------------------------------------------')
    $S.Add('# https://windows.php.net/download 에서 받은 ZIP 의 SHA-256 을 페이지 값과 대조합니다.')
    $S.Add('# Apache(mod_php): Thread Safe(TS) / IIS FastCGI: Non Thread Safe(NTS).')
    if ($script:OfflineMode) {
        $S.Add('# 오프라인 서버: 인터넷 PC 에서 ZIP·SHA-256(·VC++ 재배포 패키지)을 받아 이동매체로 옮긴 뒤 서버에서 다시 해시를 대조합니다.')
        $S.Add('# VC++ 확인: Get-ItemProperty ''HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64'' -ErrorAction SilentlyContinue')
    }
    if ($replace.Count -gt 0) {
        foreach ($t in $replace) {
            $S.Add('# 대상 ' + (ConvertTo-CommentText $t.Dir) + ' (현재 ' + (ConvertTo-CommentText $t.Report.version) + ', sapi ' + $t.Report.sapi + '): ' + (Get-TargetLine (Get-Branch $t.Report.version) $t.Report.class))
        }
        $S.Add('Invoke-Step ''ZIP 체크섬 검증'' {')
        $S.Add('    $script:ZipPath = Read-Host ''받은 ZIP 파일 전체 경로''')
        $S.Add('    $expected = (Read-Host ''다운로드 페이지에 표시된 SHA-256 값'').Trim()')
        $S.Add('    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $script:ZipPath).Hash')
        $S.Add('    if ($actual -ne $expected) { $script:ZipPath = ''''; throw (''SHA-256 불일치: 실제 '' + $actual) }')
        $S.Add('    Write-Output ''SHA-256 일치''')
        $S.Add('}')
    } else {
        $S.Add('# (교체 대상 없음: 수정 버전이 이미 디스크에 있고 실행 중 프로세스만 이전 코드를 사용 중)')
    }
    $S.Add('')

    $S.Add('# ---------------------------------------------------------------------------')
    $S.Add('# 2단계: 서비스 중지 / PHP 워커 종료')
    $S.Add('# ---------------------------------------------------------------------------')
    if ($hasIis) {
        $S.Add('# IIS 만 멈추려면 앱 풀 단위(Import-Module WebAdministration; Stop-WebAppPool -Name <풀이름>)도 가능합니다.')
        if ($script:IisPools.Count -gt 0) { $S.Add('# 이 서버의 앱 풀: ' + (ConvertTo-CommentText ($script:IisPools -join ', '))) }
        if ($script:IisSites.Count -gt 0) { $S.Add('# 이 서버의 사이트: ' + (ConvertTo-CommentText ($script:IisSites -join ', '))) }
        $S.Add('Invoke-Step ''IIS 중지 (W3SVC/WAS 포함: iisreset /stop)'' { & ([IO.Path]::Combine([Environment]::GetFolderPath([Environment+SpecialFolder]::Windows), ''System32\iisreset.exe'')) /stop; if ($LASTEXITCODE -ne 0) { throw ''IIS 중지 실패'' } }')
    }
    foreach ($sv in $svcs) {
        $S.Add('Invoke-Step ''Apache 서비스 중지(경로/이름은 확인 후 평가)'' { Stop-Service -Name ' + (ConvertTo-PsLiteral $sv) + ' }')
    }
    if (-not $hasIis -and $svcs.Count -eq 0) { $S.Add('# 연결된 IIS/Apache 서비스를 확인하지 못했습니다. 이 PHP 를 사용하는 서비스를 직접 중지하세요.') }
    foreach ($c in $cgiPaths) { $S.Add('# php-cgi: ' + (ConvertTo-CommentText $c)) }
    $S.Add('Invoke-Step ''남은 php-cgi 워커 종료(이전 코드 제거)'' { Get-Process php-cgi -ErrorAction SilentlyContinue | Stop-Process -Force }')
    $S.Add('')

    if ($replace.Count -gt 0) {
        $S.Add('# ---------------------------------------------------------------------------')
        $S.Add('# 3단계: PHP 폴더 교체 (php.ini 보존, 이전 폴더는 백업 이름으로 보관)')
        $S.Add('# ---------------------------------------------------------------------------')
        foreach ($t in $replace) {
            if ($t.Vendor) {
                $S.Add('# 벤더 번들 감지: ' + (ConvertTo-CommentText $t.Dir) + ' - XAMPP/WAMP/Laragon/MAMP 는 벤더 패키지로 업데이트하세요(수동 교체 자동화 안 함).')
                continue
            }
            if ($t.Report.class -eq 'eol_backport' -or $t.Report.class -eq 'eol_no_fix' -or $t.Report.class -eq 'old_unsupported') {
                $S.Add('# 주의 ' + (ConvertTo-CommentText $t.Dir) + ': 같은 브랜치의 수정 릴리스가 없습니다. 지원되는 브랜치(8.3 이상)의 ZIP 으로 교체하려면 앱 호환성을 먼저 테스트하세요.')
            }
            $lit = ConvertTo-PsLiteral $t.Dir
            $S.Add('Invoke-Step ''PHP 폴더 교체(대상 경로는 확인 후 평가)'' {')
            $S.Add('    if (-not $script:ZipPath) { throw ''1단계(ZIP 체크섬 검증)를 먼저 완료하세요.'' }')
            $S.Add('    $dir = ' + $lit)
            $S.Add('    $old = $dir + ''.old-'' + (Get-Date -Format ''yyyyMMdd-HHmmss'')')
            $S.Add('    Rename-Item -LiteralPath $dir -NewName (Split-Path -Leaf $old)')
            $S.Add('    Expand-Archive -LiteralPath $script:ZipPath -DestinationPath $dir')
            $S.Add('    $ini = Join-Path $old ''php.ini''')
            $S.Add('    if (Test-Path -LiteralPath $ini) { Copy-Item -LiteralPath $ini -Destination (Join-Path $dir ''php.ini'') }')
            $S.Add('    Write-Output (''이전 폴더는 롤백용으로 보관됨(취약 버전이므로 검증 후 이동/삭제): '' + $old)')
            $S.Add('}')
        }
        $S.Add('# 새 php.ini-production 의 변경점과 extension_dir 경로를 기존 php.ini 와 비교하세요.')
        $S.Add('')
    }
    foreach ($d in $restartOnly) { $S.Add('# 재시작만 필요(수정 버전 파일은 이미 있음): ' + (ConvertTo-CommentText $d)) }

    $S.Add('# ---------------------------------------------------------------------------')
    $S.Add('# 4단계: 서비스 시작')
    $S.Add('# ---------------------------------------------------------------------------')
    if ($hasIis) { $S.Add('Invoke-Step ''IIS 시작 (iisreset /start)'' { & ([IO.Path]::Combine([Environment]::GetFolderPath([Environment+SpecialFolder]::Windows), ''System32\iisreset.exe'')) /start; if ($LASTEXITCODE -ne 0) { throw ''IIS 시작 실패'' } }') }
    foreach ($sv in $svcs) {
        $S.Add('Invoke-Step ''Apache 서비스 시작(경로/이름은 확인 후 평가)'' { Start-Service -Name ' + (ConvertTo-PsLiteral $sv) + ' }')
    }
    $S.Add('')
    $S.Add('# ---------------------------------------------------------------------------')
    $S.Add('# 5단계: 확인 (CLI 의 php -v 가 아니라 웹 요청으로)')
    $S.Add('# ---------------------------------------------------------------------------')
    $S.Add('Write-Output ''[5단계] 웹 요청으로 확인하세요: 로컬호스트 전용 임시 페이지에서 PHP_VERSION 만 출력해 확인한 뒤 즉시 삭제합니다(phpinfo 노출 금지).''')
    $S.Add('Write-Output ''  모든 워커가 재시작되었는지, 그리고 php2shell-quickcheck.ps1 을 다시 실행해 종료 코드 0 인지 확인하세요.''')
    $S.Add('')
    $S.Add('# 업데이트 전 임시 대응(완전한 해결 아님; virtual-patch/ 디렉터리 참고): session.upload_progress.enabled = 0, post_max_size 하향,')
    $S.Add('#   IIS Request Filtering maxAllowedContentLength, 노출 축소(IP 제한/점검 페이지/사이트 중지), 방화벽 아웃바운드 제한, WAF 규칙.')
    $S.Add('#   memory_limit = -1 은 OS 수준 메모리 상한과 함께만 사용하세요(RLIMIT_AS/RLIMIT_DATA 사용 금지).')
    $S.Add('# 근거 자료: ' + $script:Sources[0].url)
    return ($S -join "`r`n")
}

function Save-PlanFile {
    param([string]$Path, [string]$Content)
    $stream = $null
    try {
        $full = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
        # 원자적으로 새 파일만 생성: 기존 파일, 디렉터리, dangling symlink 모두 거부한다.
        $stream = New-Object IO.FileStream($full, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $encoding = New-Object Text.UTF8Encoding($true)
        $bom = $encoding.GetPreamble()
        $bytes = $encoding.GetBytes($Content)
        $stream.Write($bom, 0, $bom.Length)
        $stream.Write($bytes, 0, $bytes.Length)
        return $full
    } catch {
        Add-Warn ('조치 계획 파일 생성 거부(기존 파일은 덮어쓰지 않음): {0}' -f (ConvertTo-SafeText $_.Exception.Message))
        return ''
    } finally { if ($null -ne $stream) { $stream.Dispose() } }
}

# ---------------------------------------------------------------------------
# 진입점. 종료 코드는 $script:MainExit 로 전달한다(출력 스트림과 섞이지 않도록 반환값을 쓰지 않음).
# ---------------------------------------------------------------------------
function Invoke-Main {
    param([bool]$AsJson, [bool]$NoExecFlag, [string]$RootPath, [bool]$ShowHelp, [bool]$HasClassify, [string]$ClassifyText, [bool]$OfflineFlag, [string]$PlanFilePath, [bool]$ExecFlag)
    $script:MainExit = 0
    $oldEnc = $null
    $changed = $false
    if ($script:OnWindows -and -not $HasClassify) {
        # 한글(및 JSON)을 항상 BOM 없는 UTF-8 로 내보낸다. cp949 콘솔에서 깨지면 chcp 65001 / Windows Terminal 사용(-Help 참고).
        try {
            $oldEnc = [Console]::OutputEncoding
            [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
            $changed = $true
        } catch { }
    }
    try {
        Invoke-MainCore $AsJson $NoExecFlag $RootPath $ShowHelp $HasClassify $ClassifyText $OfflineFlag $PlanFilePath $ExecFlag
    } finally {
        if ($changed) { try { [Console]::OutputEncoding = $oldEnc } catch { } }
    }
}

function Invoke-MainCore {
    param([bool]$AsJson, [bool]$NoExecFlag, [string]$RootPath, [bool]$ShowHelp, [bool]$HasClassify, [string]$ClassifyText, [bool]$OfflineFlag, [string]$PlanFilePath, [bool]$ExecFlag)

    if ($ShowHelp) { Write-Output ((Get-HelpLines) -join "`n"); return }
    if ($HasClassify) { Write-Output (Get-PhpClass $ClassifyText); return }

    $script:NoExecMode = $NoExecFlag
    $script:ExecInRoot = $ExecFlag
    $script:OfflineMode = $OfflineFlag
    $script:RootDir = ''
    if ($RootPath) {
        if (-not (Test-Path -LiteralPath $RootPath -PathType Container)) {
            [Console]::Error.WriteLine('-Root 경로가 디렉터리가 아닙니다: ' + $RootPath)
            $script:MainExit = 2
            return
        }
        $script:RootDir = Get-FullPathSafe $RootPath
        if (-not $script:RootDir) { $script:RootDir = $RootPath }
    }
    $script:Insts.Clear()
    $script:Warnings.Clear()
    $script:ApacheServices.Clear()
    $script:IisPools.Clear()
    $script:IisSites.Clear()
    $script:ProcEnumOk = $true
    $script:LimitedProcs = 0
    $script:W3wpCount = 0
    $script:IisConfigRead = $false
    $script:IisConfigDenied = $false

    $live = $null
    if (-not $script:RootDir) {
        $script:Elevated = Test-Elevated
        if ($script:Elevated -eq $false) {
            Add-Warn '관리자 권한이 아니므로 다른 계정(IIS 앱 풀 ID 등)으로 실행 중인 php-cgi/w3wp/httpd 프로세스의 경로·시작 시각과 IIS 설정 파일을 읽지 못할 수 있습니다(가시성 축소). 관리자 PowerShell 에서 다시 실행하세요.'
        }
        if (-not $script:OnWindows) { Add-Warn 'Windows 가 아닌 환경입니다. 이 스크립트는 Windows 용이므로 프로세스 기반 발견만 수행합니다(Linux/macOS 는 quickcheck.sh 사용).' }
        $live = Get-LiveProcesses
        $script:ProcEnumOk = [bool]$live.Ok
        $script:LimitedProcs = [int]$live.Limited
        $script:W3wpCount = [int]$live.W3wp
        if (-not $script:ProcEnumOk) { Add-Warn '프로세스 목록을 열거하지 못했습니다. 실행 중 여부와 재시작 필요 여부를 판단할 수 없습니다.' }
        if ($script:LimitedProcs -gt 0) { Add-Warn ('PHP/Apache 계열 프로세스 {0}개의 실행 경로를 읽지 못했습니다(권한 부족). 해당 프로세스는 위 목록에서 빠져 있을 수 있습니다.' -f $script:LimitedProcs) }
    }

    # 1) IIS
    Find-IisPhpRegistrations
    # 2) Apache (서비스 / httpd.conf)
    $liveList = @()
    if ($null -ne $live) { $liveList = @($live.List.ToArray()) }
    Find-ApachePhpModules $liveList
    # 3) 흔한 경로
    Find-CommonPhpDirs
    # 4) 실행 중 프로세스
    foreach ($p in $liveList) {
        if ([string]::IsNullOrEmpty($p.Path)) { continue }
        if ($p.Kind -eq 'php') {
            $sapi = 'cli'
            if ($p.Name -imatch '^php-cgi$') { $sapi = 'cgi' }
            $inst = Add-Binary $p.Path '실행 중인 프로세스' $sapi
            if ($null -ne $inst) { $inst.Procs.Add($p) }
        } elseif ($p.Kind -eq 'httpd') {
            $d = Split-Path -Parent $p.Path
            $root = $d
            if ((Split-Path -Leaf $d) -ieq 'bin') { $root = Split-Path -Parent $d }
            $rk = Get-DirKey $root
            foreach ($inst in $script:Insts.Values) {
                foreach ($ar in $inst.ApacheRoots) { if ($ar -eq $rk) { $inst.Procs.Add($p); break } }
            }
        }
    }
    foreach ($inst in $script:Insts.Values) {
        foreach ($svc in $script:ApacheServices) { if ($inst.ApacheMod -and $inst.ApacheRoots.Count -gt 0) { Add-Unique $inst.Services $svc } }
    }

    $reports = New-Object 'System.Collections.Generic.List[object]'
    $pairs = New-Object 'System.Collections.Generic.List[object]'
    $dirKeys = @($script:Insts.Keys | Sort-Object)
    foreach ($k in $dirKeys) {
        $rep = New-Report $script:Insts[$k]
        $reports.Add($rep)
        $pairs.Add([pscustomobject]@{ Inst = $script:Insts[$k]; Report = $rep })
    }

    $sum = [ordered]@{ vulnerable = 0; fixed = 0; vendor_patched = 0; eol = 0; unknown = 0; needs_restart = 0 }
    foreach ($r in $reports) {
        $sum[$r.verdict] = [int]$sum[$r.verdict] + 1
        if ($r.needs_restart -eq $true) { $sum['needs_restart'] = [int]$sum['needs_restart'] + 1 }
    }

    $exit = 0
    if ($sum.vulnerable -gt 0 -or $sum.eol -gt 0 -or $sum.needs_restart -gt 0) { $exit = 1 }
    elseif ($sum.unknown -gt 0) { $exit = 3 }
    elseif ($reports.Count -eq 0 -and -not $script:RootDir) {
        if (-not $script:ProcEnumOk -or $script:LimitedProcs -gt 0 -or $script:IisConfigDenied) { $exit = 3 }
    }

    $planSaved = ''
    if ($PlanFilePath) {
        # 파일에 쓰기만 한다. 생성한 명령은 이 도구가 실행하지 않는다.
        $planSaved = Save-PlanFile $PlanFilePath (New-PlanScript $pairs)
        if (-not $planSaved) { $exit = 2 }
    }

    $hostName = [System.Environment]::MachineName
    $platform = Get-PlatformString
    if ($AsJson) {
        $obj = [ordered]@{
            tool          = $script:ToolName
            as_of         = $script:AsOf
            host          = $hostName
            platform      = $platform
            installations = @($reports.ToArray())
            summary       = $sum
            exit_code     = $exit
            warnings      = @($script:Warnings.ToArray())
        }
        if ($planSaved) { $obj['plan_file'] = $planSaved }
        Write-Output (ConvertTo-Json -InputObject $obj -Depth 6)
    } else {
        Write-Output (ConvertTo-ReportText $reports $sum $exit $hostName $platform $planSaved)
    }
    $script:MainExit = $exit
}

# 테스트에서 `. .\php2shell-quickcheck.ps1` 로 함수만 불러올 수 있도록, 도트 소싱이면 실행하지 않는다.
if ($MyInvocation.InvocationName -eq '.') { return }

Invoke-Main -AsJson ([bool]$Json) -NoExecFlag ([bool]$NoExec) -RootPath $Root -ShowHelp ([bool]$Help) -HasClassify ($PSBoundParameters.ContainsKey('Classify')) -ClassifyText $Classify -OfflineFlag ([bool]$Offline) -PlanFilePath $PlanFile -ExecFlag ([bool]$Exec)
# 종료 코드는 return 이 아니라 exit 로 정확히 전달한다(.bat 래퍼의 %ERRORLEVEL).
exit ([int]$script:MainExit)
