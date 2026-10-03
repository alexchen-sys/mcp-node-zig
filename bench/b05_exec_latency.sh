#!/usr/bin/env bash
# b05 — exec round-trip latency on a warm server, one channel per participant
# (keep-alive HTTP for ours, stdio pipes for the rivals — each agent's native
# transport; the asymmetry is disclosed in BENCHMARKS.md caveats).
# Same child work for everyone: tools/call with argv ["uname", "-a"].
# N=200 samples -> p50/p95/p99 + mean/sigma/min/max.
set -euo pipefail
. "$(dirname "$0")/config.sh"

echo "== b05 exec latency: ours (http, keep-alive, N=$B05_RUNS) ==" >&2
$NICE_CMD python3 "$HARNESS/mcp_probe.py" latency \
    --transport http --runs "$B05_RUNS" --warmup "$B05_WARMUP" \
    --port "$MCPNZ_PORT" --token-file "$TOKEN_FILE" \
    --out "$RAW/b05_ours.json" -- "${MCPNZ_BIN:?set MCPNZ_BIN}"

echo "== b05 exec latency: tumf/mcp-shell-server (stdio, N=$B05_RUNS) ==" >&2
tumf_env=()
for e in "${TUMF_ENV[@]}"; do tumf_env+=(-E "$e"); done
$NICE_CMD python3 "$HARNESS/mcp_probe.py" latency \
    --transport stdio --runs "$B05_RUNS" --warmup "$B05_WARMUP" \
    --tool "$TUMF_TOOL" --tool-key "$TUMF_TOOL_KEY" "${tumf_env[@]}" \
    --out "$RAW/b05_tumf.json" -- "${TUMF_ARGV[@]}"

echo "== b05 exec latency: g0t4/mcp-server-commands (stdio, N=$B05_RUNS) ==" >&2
$NICE_CMD python3 "$HARNESS/mcp_probe.py" latency \
    --transport stdio --runs "$B05_RUNS" --warmup "$B05_WARMUP" \
    --tool "$G0T4_TOOL" --tool-key "$G0T4_TOOL_KEY" \
    --out "$RAW/b05_g0t4.json" -- "${G0T4_ARGV[@]}"

python3 "$BENCH_DIR/lib/collect.py" \
    --metric b05_exec_latency --label "warm server, tools/call exec argv [uname -a], N=$B05_RUNS round-trips" \
    ours "$RAW/b05_ours.json" tumf "$RAW/b05_tumf.json" g0t4 "$RAW/b05_g0t4.json" \
    > "$RESULTS/b05_exec_latency.json"
echo "wrote $RESULTS/b05_exec_latency.json" >&2
