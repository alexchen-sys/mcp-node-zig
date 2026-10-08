#!/usr/bin/env bash
# Shared knobs for the bench suite. Override any of these via environment.
# All server configurations live HERE (token, port, env, run counts) — nothing
# is set by hand between scripts (methodology: reproducibility).

BENCH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$BENCH_DIR/.." && pwd)"
HARNESS="$BENCH_DIR/harness"

ZIG_BIN="${ZIG_BIN:-zig}"
MCPNZ_BIN="${MCPNZ_BIN:-}"            # empty -> run_all.sh builds ReleaseSafe
MCPNZ_BUILD_MODE="${MCPNZ_BUILD_MODE:-ReleaseSafe}"
MCPNZ_PORT="${MCPNZ_PORT:-18341}"     # 183xx range, see bench/README.md

UVX_BIN="${UVX_BIN:-uvx}"
NPX_BIN="${NPX_BIN:-npx}"

# Two profiles (methodology: same N for every timed series, ours and rivals):
# - publication: N=10000 per timed series, the numbers BENCHMARKS.md publishes
#   (~5 h wall clock, dominated by rival cold starts; raw samples stream to
#   JSONL so a crash does not lose the evidence).
# - quick: dev iteration profile (~10 min).
# Individual env vars override the profile value (the profile sets defaults).
BENCH_PROFILE="${BENCH_PROFILE:-publication}"
case "$BENCH_PROFILE" in
    publication)
        _P_B01_RUNS=10000; _P_B05_RUNS=10000; _P_B05_WARMUP=100
        _P_B02_HANDSHAKES=10000; _P_B02_NODE_RUNS=1000
        ;;
    quick)
        _P_B01_RUNS=200; _P_B05_RUNS=1000; _P_B05_WARMUP=10
        _P_B02_HANDSHAKES=500; _P_B02_NODE_RUNS=100
        ;;
    *)
        echo "BENCH_PROFILE must be 'publication' or 'quick' (got '$BENCH_PROFILE')" >&2
        exit 1
        ;;
esac

B01_RUNS="${B01_RUNS:-$_P_B01_RUNS}"              # cold-start runs
B05_RUNS="${B05_RUNS:-$_P_B05_RUNS}"              # exec latency round-trips
B05_WARMUP="${B05_WARMUP:-$_P_B05_WARMUP}"
B02_HANDSHAKES="${B02_HANDSHAKES:-$_P_B02_HANDSHAKES}"   # b02 client TLS handshakes
B02_NODE_RUNS="${B02_NODE_RUNS:-$_P_B02_NODE_RUNS}"      # b02 node spawn->registered runs
B03_SAMPLES="${B03_SAMPLES:-20}"
B03_INTERVAL="${B03_INTERVAL:-0.5}"
B07_CONNECTIONS="${B07_CONNECTIONS:-20}"
B07_STEP="${B07_STEP:-5}"

# b02 ports: hub MCP API (client token) + TLS node-link listener, 183xx range.
B02_HUB_PORT="${B02_HUB_PORT:-18351}"
B02_LINK_PORT="${B02_LINK_PORT:-18352}"

NICE_CMD="${NICE_CMD:-nice -n 10}"    # benchmarks run niced per methodology

# Results directory. RESULTS env override: absolute path, or a path relative
# to the repo root (the committed evidence run uses
# RESULTS=bench/results/publication-2026-10).
RESULTS="${RESULTS:-$BENCH_DIR/results}"
case "$RESULTS" in
    /*) ;;
    *) RESULTS="$REPO_DIR/$RESULTS" ;;
esac
RAW="$RESULTS/raw"
mkdir -p "$RAW"

WORKDIR="$(mktemp -d /tmp/mcpnz-bench.XXXXXX)"
TOKEN_FILE="$WORKDIR/token"
openssl rand -hex 32 > "$TOKEN_FILE"

# Rivals in their documented launch channels.
# tumf/mcp-shell-server: uvx + ALLOW_COMMANDS (their README's allowlist env)
TUMF_ARGV=("$UVX_BIN" "mcp-shell-server")
TUMF_ENV=("ALLOW_COMMANDS=uname")
TUMF_TOOL="shell_execute"
TUMF_TOOL_KEY="command"
# g0t4/mcp-server-commands: npx -y, executable-mode run_process
G0T4_ARGV=("$NPX_BIN" "-y" "mcp-server-commands")
G0T4_TOOL="run_process"
G0T4_TOOL_KEY="argv"

cleanup_workdir() {
    rm -rf "$WORKDIR"
}
# every script that sources this file (run_all.sh AND each bNN metric script)
# gets its own mktemp workdir; register the cleanup here so no scratch dirs
# survive any exit path, error or success.
trap cleanup_workdir EXIT
