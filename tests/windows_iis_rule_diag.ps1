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
function Try-Rule([string]$Name, [string]$Source, [string]$Pattern, [string]$Action) {
    $xml = '<?xml version="1.0" encoding="utf-8"?><configuration><system.webServer><rewrite><rules><rule name="d" stopProcessing="true"><match url=".*" /><conditions><add input="' + $Source + '" pattern="' + $Pattern + '" /></conditions>' + $Action + '</rule></rules></rewrite></system.webServer></configuration>'
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
$redirect = '<action type="Redirect" url="http://localhost/seen?v={C:1}" appendQueryString="false" redirectType="Temporary" />'
Try-Rule 'echo ALL_RAW'                 '{ALL_RAW}'            '(.*)'      $redirect
Try-Rule 'echo CONTENT_TYPE'            '{CONTENT_TYPE}'       '(.*)'      $redirect
Try-Rule 'echo HTTP_CONTENT_TYPE'       '{HTTP_CONTENT_TYPE}'  '(.*)'      $redirect
Remove-Item $webConfig -ErrorAction SilentlyContinue
