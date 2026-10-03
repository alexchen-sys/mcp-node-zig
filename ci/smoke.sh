#!/usr/bin/env bash
set -euo pipefail

TF="$RUNNER_TEMP/mcp-node-ci-token"
printf 'ci-test-token' > "$TF"
export MCP_NODE_TOKEN_FILE="$TF"
./zig-out/bin/mcp-node &
PID=$!
trap 'kill $PID 2>/dev/null || true' EXIT

for i in $(seq 1 50); do
  curl -s -o /dev/null http://127.0.0.1:8341/mcp && break || sleep 0.1
done

code=$(curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:8341/mcp \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize"}')
test "$code" = "401"

body=$(curl -fsS -X POST http://127.0.0.1:8341/mcp \
  -H 'Content-Type: application/json' \
  -H 'x-node-token: ci-test-token' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"ci","version":"0"}}}')
echo "$body" | grep -q protocolVersion
echo "$body" | grep -q mcp-node

sys=$(curl -fsS -X POST http://127.0.0.1:8341/mcp \
  -H 'Content-Type: application/json' \
  -H 'x-node-token: ci-test-token' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"sys_info","arguments":{}}}')
echo "$sys" | grep -q os
echo "$sys" | grep -q hostname

# Standard bearer auth is accepted alongside X-Node-Token.
scheme=Bearer
tok=$(cat "$TF")
bearer=$(curl -fsS -X POST http://127.0.0.1:8341/mcp \
  -H 'Content-Type: application/json' \
  -H "Authorization: ${scheme} ${tok}" \
  -d '{"jsonrpc":"2.0","id":3,"method":"ping"}')
echo "$bearer" | grep -q result

# A wrong bearer token gets 401 with a Bearer challenge.
hdrs=$(curl -s -o /dev/null -D - -X POST http://127.0.0.1:8341/mcp \
  -H 'Content-Type: application/json' \
  -H "Authorization: ${scheme} wrong-${tok}" \
  -d '{"jsonrpc":"2.0","id":4,"method":"ping"}')
echo "$hdrs" | head -n1 | grep -q ' 401 '
echo "$hdrs" | grep -qi '^www-authenticate: Bearer'

echo "smoke: OK"
