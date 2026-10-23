# Diagnosis: why does the IIS URL Rewrite multipart rule not match? (run on a disposable Windows runner, elevated)
$ErrorActionPreference = 'Stop'
Install-WindowsFeature -Name Web-Server, Web-Mgmt-Tools | Out-Null
choco install urlrewrite -y --no-progress | Out-Null
$global:LASTEXITCODE = 0
Start-Service W3SVC
$wwwroot = 'C:\inetpub\wwwroot'
$webConfig = Join-Path $wwwroot 'web.config'
if (-not (Test-Path (Join-Path $wwwroot 'iisstart.htm'))) { Set-Content (Join-Path $wwwroot 'iisstart.htm') 'iis' }

function Post-Multipart {
    $handler = New-Object System.Net.Http.HttpClientHandler
    $handler.AllowAutoRedirect = $false
    $client = New-Object System.Net.Http.HttpClient($handler)
    $content = New-Object System.Net.Http.MultipartFormDataContent
    $content.Add((New-Object System.Net.Http.StringContent('a')), 'f')
    $request = New-Object System.Net.Http.HttpRequestMessage('POST', 'http://localhost/iisstart.htm')
    $request.Content = $content
    $request.Headers.Add('X-Test', 'one')
    $response = $client.SendAsync($request).GetAwaiter().GetResult()
    $location = if ($response.Headers.Location) { $response.Headers.Location.OriginalString } else { '' }
    $client.Dispose()
    return @{ Status = [int]$response.StatusCode; Location = $location }
}
function Try-Rule([string]$Name, [string]$Source, [string]$Pattern, [string]$Action, [string]$Extra = '') {
    $xml = '<?xml version="1.0" encoding="utf-8"?><configuration><system.webServer><rewrite><rules><rule name="d" stopProcessing="true"><match url=".*" /><conditions><add input="' + $Source + '" pattern="' + $Pattern + '"' + $Extra + ' /></conditions>' + $Action + '</rule></rules></rewrite></system.webServer></configuration>'
    Set-Content $webConfig $xml -Encoding UTF8
    $r = Post-Multipart
    Write-Host ("RESULT {0,-34} status={1} location={2}" -f $Name, $r.Status, $r.Location)
}
$block = '<action type="CustomResponse" statusCode="403" statusReason="Forbidden" statusDescription="x" />'
Try-Rule 'method POST'                  '{REQUEST_METHOD}'     'POST'      $block
Try-Rule 'custom header HTTP_X_TEST'    '{HTTP_X_TEST}'        'one'       $block
Try-Rule 'HTTP_CONTENT_TYPE any'        '{HTTP_CONTENT_TYPE}'  '.+'        $block
Try-Rule 'CONTENT_TYPE any'             '{CONTENT_TYPE}'       '.+'        $block
Try-Rule 'HTTP_CONTENT_TYPE multipart'  '{HTTP_CONTENT_TYPE}'  'multipart' $block
Try-Rule 'CONTENT_TYPE multipart'       '{CONTENT_TYPE}'       'multipart' $block
Try-Rule 'CONTENT_TYPE anchored'        '{CONTENT_TYPE}'       '^multipart/form-data' $block
Try-Rule 'shipped pattern HTTP_'          '{HTTP_CONTENT_TYPE}'  '^\s*multipart/form-data' $block ' ignoreCase="true"'
Try-Rule 'shipped pattern CT'             '{CONTENT_TYPE}'       '^\s*multipart/form-data' $block ' ignoreCase="true"'
Try-Rule 'shipped pattern, no ignoreCase' '{HTTP_CONTENT_TYPE}'  '^\s*multipart/form-data' $block
Try-Rule 'space class'                    '{HTTP_CONTENT_TYPE}'  '^ *multipart/form-data' $block ' ignoreCase="true"'
Try-Rule 'anchored + ignoreCase'          '{HTTP_CONTENT_TYPE}'  '^multipart/form-data' $block ' ignoreCase="true"'
$redirect = '<action type="Redirect" url="http://localhost/seen?v={C:1}" appendQueryString="false" redirectType="Temporary" />'
Try-Rule 'echo ALL_RAW'                 '{ALL_RAW}'            '(.*)'      $redirect
Try-Rule 'echo CONTENT_TYPE'            '{CONTENT_TYPE}'       '(.*)'      $redirect
Try-Rule 'echo HTTP_CONTENT_TYPE'       '{HTTP_CONTENT_TYPE}'  '(.*)'      $redirect
Remove-Item $webConfig -ErrorAction SilentlyContinue

# --- the shipped files themselves
$Repo = Split-Path -Parent $PSScriptRoot
$out = Join-Path $env:TEMP ('p2s-vp-' + [guid]::NewGuid().ToString('N'))
python "$Repo\php2shell_triage.py" --emit-virtual-patch $out --uploads no 2>&1 | Out-Null
Copy-Item (Join-Path $out 'iis\web.config.block-multipart.xml') $webConfig -Force
$r = Post-Multipart
Write-Host ("RESULT {0,-34} status={1}" -f 'shipped block-multipart.xml as-is', $r.Status)
Write-Host '--- as-is file:'; Get-Content $webConfig | Write-Host
Copy-Item (Join-Path $out 'iis\web.config.snippet.xml') $webConfig -Force
$r = Post-Multipart
Write-Host ("RESULT {0,-34} status={1}" -f 'shipped snippet.xml as-is', $r.Status)
$rule = [xml](Get-Content (Join-Path $out 'iis\web.config.block-multipart.xml') -Raw -Encoding UTF8)
$snip = [xml](Get-Content (Join-Path $out 'iis\web.config.snippet.xml') -Raw -Encoding UTF8)
$merged = [xml]'<?xml version="1.0" encoding="utf-8"?><configuration><system.webServer/></configuration>'
$target = $merged.SelectSingleNode('/configuration/system.webServer')
foreach ($doc in @($rule, $snip)) { foreach ($node in @($doc.SelectSingleNode('/configuration/system.webServer').ChildNodes)) { [void]$target.AppendChild($merged.ImportNode($node, $true)) } }
$merged.Save($webConfig)
$r = Post-Multipart
Write-Host ("RESULT {0,-34} status={1}" -f 'merged rule+snippet', $r.Status)
Write-Host '--- merged file:'; Get-Content $webConfig | Write-Host
Remove-Item $webConfig -ErrorAction SilentlyContinue
