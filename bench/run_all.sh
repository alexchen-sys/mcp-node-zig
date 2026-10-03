#!/usr/bin/env bash
# One command = the whole benchmark run (methodology: reproducibility).
#
#   ./bench/run_all.sh
#
# What it does, in order:
#   1. machine passport (env.json)
#   2. build mcp-node (ReleaseSafe) unless MCPNZ_BIN points at a binary
#   3. warm the rivals' INSTALLER caches (uvx/npx downloads) — before any
#      cold series, so cold measures the server, not the network
#   4. b01 cold start, b03 idle RSS, b05 exec latency, b07 per-connection
#      memory, b08 footprint — each under nice -n 10
#   5. render results/summary.md
#
# Requirements: bash, python3 (stdlib only), zig 0.16.x in PATH (or ZIG_BIN),
# uvx, npx, openssl, du, /usr/bin/time. Runs on the 183xx port range only.
set -euo pipefail
BENCH_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$BENCH_DIR/config.sh"
trap cleanup_workdir EXIT

echo "== [0/6] machine passport ==" >&2
mkdir -p "$RESULTS"
MCPNZ_BIN="${MCPNZ_BIN:-}" MCPNZ_BUILD_MODE="$MCPNZ_BUILD_MODE" ZIG_BIN="$ZIG_BIN" \
    python3 "$BENCH_DIR/lib/env_report.py" > "$RESULTS/env.json" || true

if [ -z "$MCPNZ_BIN" ]; then
    echo "== building mcp-node ($MCPNZ_BUILD_MODE) ==" >&2
    (cd "$REPO_DIR" && "$ZIG_BIN" build -Doptimize="$MCPNZ_BUILD_MODE")
    MCPNZ_BIN="$REPO_DIR/zig-out/bin/mcp-node"
    # refresh the passport now that the binary exists
    MCPNZ_BIN="$MCPNZ_BIN" MCPNZ_BUILD_MODE="$MCPNZ_BUILD_MODE" ZIG_BIN="$ZIG_BIN" \
        python3 "$BENCH_DIR/lib/env_report.py" > "$RESULTS/env.json" || true
fi
export MCPNZ_BIN

echo "== [1/6] warming rival installer caches (BEFORE cold series) ==" >&2
$NICE_CMD python3 "$HARNESS/mcp_probe.py" warmup --transport stdio \
    -E "ALLOW_COMMANDS=uname" -- "${TUMF_ARGV[@]}" > "$RAW/warmup_tumf.json"
$NICE_CMD python3 "$HARNESS/mcp_probe.py" warmup --transport stdio \
    -- "${G0T4_ARGV[@]}" > "$RAW/warmup_g0t4.json"

bash "$BENCH_DIR/b01_cold_start.sh"
bash "$BENCH_DIR/b03_rss_idle.sh"
bash "$BENCH_DIR/b05_exec_latency.sh"
bash "$BENCH_DIR/b07_per_connection.sh"
bash "$BENCH_DIR/b08_footprint.sh"

python3 "$BENCH_DIR/lib/summarize.py" "$RESULTS" > "$RESULTS/summary.md"
echo "== done: $RESULTS/summary.md ==" >&2
cat "$RESULTS/summary.md"
