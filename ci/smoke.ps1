# Smoke test: auth gate + initialize + sys_info. Windows (pwsh).
$ErrorActionPreference = "Stop"

$tokenFile = Join-Path $env:RUNNER_TEMP "mcp-node-ci-token"
[System.IO.File]::WriteAllText($tokenFile, "ci-test-token")
$env:MCP_NODE_TOKEN_FILE = $tokenFile

$proc = Start-Process -FilePath ".\zig-out\bin\mcp-node.exe" -PassThru -NoNewWindow
$ready = $false
foreach ($i in 1..50) {
    try {
        $null = Invoke-WebRequest -Uri "http://127.0.0.1:8341/mcp" -UseBasicParsing -TimeoutSec 1
        $ready = $true
        break
    } catch {
        # Any HTTP response (including 401) means the server is up.
        # pwsh 7 throws HttpResponseException for 4xx, not WebException.
        if ($_.Exception.Response) { $ready = $true; break }
        Start-Sleep -Milliseconds 200
    }
}
if (-not $ready) { throw "server did not start listening in time" }

try {
    # 401 without token
    $resp = $null
    try {
        $resp = Invoke-WebRequest -Uri "http://127.0.0.1:8341/mcp" -Method POST `
            -ContentType "application/json" `
            -Body '{"jsonrpc":"2.0","id":1,"method":"initialize"}' `
            -UseBasicParsing
    } catch {
        $resp = $_.Exception.Response
    }
    $statusCode = [int]$resp.StatusCode
    if ($statusCode -ne 401) { throw "expected 401, got $statusCode" }

    # initialize with token
    $headers = @{ "x-node-token" = "ci-test-token" }
    $init = Invoke-RestMethod -Uri "http://127.0.0.1:8341/mcp" -Method POST `
        -ContentType "application/json" -Headers $headers `
        -Body '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"ci","version":"0"}}}'
    if ($init.result.protocolVersion -ne "2025-11-25") { throw "protocolVersion mismatch" }
    if ($init.result.serverInfo.name -ne "mcp-node") { throw "serverInfo.name mismatch" }

    # sys_info
    $sys = Invoke-RestMethod -Uri "http://127.0.0.1:8341/mcp" -Method POST `
        -ContentType "application/json" -Headers $headers `
        -Body '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"sys_info","arguments":{}}}'
    $sysJson = $sys | ConvertTo-Json -Depth 10 -Compress
    if ($sysJson -notmatch '"os"') { throw "sys_info missing os" }
    if ($sysJson -notmatch '"hostname"') { throw "sys_info missing hostname" }

    # bearer scheme accepted; 401 carries the WWW-Authenticate challenge
    $bearerHeaders = @{ "Authorization" = "Bearer ci-test-token" }
    $ping = Invoke-RestMethod -Uri "http://127.0.0.1:8341/mcp" -Method POST `
        -ContentType "application/json" -Headers $bearerHeaders `
        -Body '{"jsonrpc":"2.0","id":3,"method":"ping"}'
    if ($null -eq $ping.result) { throw "bearer ping failed" }

    $resp401 = $null
    try {
        $resp401 = Invoke-WebRequest -Uri "http://127.0.0.1:8341/mcp" -Method POST `
            -ContentType "application/json" -Headers @{ "Authorization" = "Basic d3Jvbmc=" } `
            -Body '{"jsonrpc":"2.0","id":4,"method":"initialize"}' `
            -UseBasicParsing
    } catch {
        $resp401 = $_.Exception.Response
    }
    if ([int]$resp401.StatusCode -ne 401) { throw "basic scheme must be 401" }
    # pwsh 7 surfaces a 4xx as HttpResponseException whose .Response is a bare
    # HttpResponseMessage: its Headers has no string indexer, so read the
    # challenge via GetValues (works on WebHeaderCollection too).
    $waHeader = $null
    try { $waHeader = ($resp401.Headers.GetValues("WWW-Authenticate") -join ", ") } catch { $waHeader = $null }
    if (-not $waHeader) { throw "401 without WWW-Authenticate" }

    Write-Host "smoke: OK"
} finally {
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
}
