# Smoke test: auth gate + initialize + sys_info. Windows (pwsh).
$ErrorActionPreference = "Stop"

$tokenFile = Join-Path $env:RUNNER_TEMP "mcp-node-ci-token"
[System.IO.File]::WriteAllText($tokenFile, "ci-test-token")
$env:MCP_NODE_TOKEN_FILE = $tokenFile

$proc = Start-Process -FilePath ".\zig-out\bin\mcp-node.exe" -PassThru -NoNewWindow
Start-Sleep -Seconds 3

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

    Write-Host "smoke: OK"
} finally {
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
}
