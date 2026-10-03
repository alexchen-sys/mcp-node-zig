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

B01_RUNS="${B01_RUNS:-50}"            # cold-start runs (min 50 per methodology)
B05_RUNS="${B05_RUNS:-200}"           # exec latency round-trips
B05_WARMUP="${B05_WARMUP:-10}"
B03_SAMPLES="${B03_SAMPLES:-20}"
B03_INTERVAL="${B03_INTERVAL:-0.5}"
B07_CONNECTIONS="${B07_CONNECTIONS:-20}"
B07_STEP="${B07_STEP:-5}"

NICE_CMD="${NICE_CMD:-nice -n 10}"    # benchmarks run niced per methodology

RESULTS="$BENCH_DIR/results"
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
