#!/usr/bin/env bash
# b07 — memory cost of extra agents.
# ours: one process, 20 keep-alive connections opened 5 at a time, RSS sampled
#       after each step -> marginal KiB per connection.
# rivals: every agent is a separate server process; we measure a full second
#       instance next to the first one.
set -euo pipefail
. "$(dirname "$0")/config.sh"

echo "== b07 per-connection RSS: ours (http, $B07_CONNECTIONS connections) ==" >&2
$NICE_CMD python3 "$HARNESS/agents_probe.py" --transport http \
    --port "$MCPNZ_PORT" --token-file "$TOKEN_FILE" \
    --connections "$B07_CONNECTIONS" --step "$B07_STEP" \
    --out "$RAW/b07_ours.json" -- "${MCPNZ_BIN:?set MCPNZ_BIN}"

echo "== b07 per-agent cost: tumf/mcp-shell-server (second instance) ==" >&2
tumf_env=()
for e in "${TUMF_ENV[@]}"; do tumf_env+=(-E "$e"); done
$NICE_CMD python3 "$HARNESS/agents_probe.py" --transport stdio \
    "${tumf_env[@]}" --out "$RAW/b07_tumf.json" -- "${TUMF_ARGV[@]}"

echo "== b07 per-agent cost: g0t4/mcp-server-commands (second instance) ==" >&2
$NICE_CMD python3 "$HARNESS/agents_probe.py" --transport stdio \
    --out "$RAW/b07_g0t4.json" -- "${G0T4_ARGV[@]}"

python3 "$BENCH_DIR/lib/collect.py" \
    --metric b07_per_connection --label "ours: 1 process x N connections; rivals: N processes x full RSS" \
    ours "$RAW/b07_ours.json" tumf "$RAW/b07_tumf.json" g0t4 "$RAW/b07_g0t4.json" \
    > "$RESULTS/b07_per_connection.json"
echo "wrote $RESULTS/b07_per_connection.json" >&2
