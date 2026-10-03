#!/usr/bin/env bash
# b01 — cold start to the first successful MCP response.
# Full cycle per run: spawn -> initialize -> tools/list -> one exec -> shutdown.
# No warmup BY DESIGN (this is the cold metric); installer caches of the
# rivals must be warmed beforehand (run_all.sh does this before calling us).
# N runs per participant; reports median/mean/sigma/min/max/p95 + 95% CI.
set -euo pipefail
. "$(dirname "$0")/config.sh"

run_participant() {
    local name="$1" transport="$2" out="$3"; shift 3
    $NICE_CMD python3 "$HARNESS/mcp_probe.py" bootstrap \
        --transport "$transport" --runs "$B01_RUNS" \
        --out "$out" \
        --port "$MCPNZ_PORT" \
        "$@"
}

echo "== b01 cold start: ours (http, $B01_RUNS runs) ==" >&2
run_participant ours http "$RAW/b01_ours.json" \
    --token-file "$TOKEN_FILE" -- "${MCPNZ_BIN:?set MCPNZ_BIN or let run_all.sh build}"

echo "== b01 cold start: tumf/mcp-shell-server (stdio, $B01_RUNS runs) ==" >&2
env_args=()
for e in "${TUMF_ENV[@]}"; do env_args+=(-E "$e"); done
run_participant tumf stdio "$RAW/b01_tumf.json" \
    --tool "$TUMF_TOOL" --tool-key "$TUMF_TOOL_KEY" "${env_args[@]}" -- "${TUMF_ARGV[@]}"

echo "== b01 cold start: g0t4/mcp-server-commands (stdio, $B01_RUNS runs) ==" >&2
run_participant g0t4 stdio "$RAW/b01_g0t4.json" \
    --tool "$G0T4_TOOL" --tool-key "$G0T4_TOOL_KEY" -- "${G0T4_ARGV[@]}"

python3 "$BENCH_DIR/lib/collect.py" \
    --metric b01_cold_start --label "spawn -> first MCP response (initialize), full shutdown between runs" \
    ours "$RAW/b01_ours.json" tumf "$RAW/b01_tumf.json" g0t4 "$RAW/b01_g0t4.json" \
    > "$RESULTS/b01_cold_start.json"
echo "wrote $RESULTS/b01_cold_start.json" >&2
