#!/usr/bin/env bash
# b03 — idle RSS after a warmup initialize, sampled over the whole process tree.
# 20 samples x 0.5 s -> median + max (RSS and PSS). /usr/bin/time -v Max RSS is
# recorded for the single-process (ours) case as an orthogonal check.
#
# Settle differs per launch channel: a static binary is stable the moment it
# serves initialize, while launcher trees (uvx -> python, npx -> node) keep
# shedding memory for several seconds after the handshake (bytecode caches,
# lazy requires, gc). 2.0 s for ours, 20.0 s for launcher trees — a 2 s settle
# was measured to cut through the rivals' settling phase (their series drop
# ~5-9 MiB mid-window), which overstates their idle footprint.
set -euo pipefail
. "$(dirname "$0")/config.sh"

B03_SETTLE="${B03_SETTLE:-2.0}"                 # single static binary
B03_SETTLE_LAUNCHER="${B03_SETTLE_LAUNCHER:-20.0}"  # uvx/npx process trees

echo "== b03 idle RSS: ours ==" >&2
$NICE_CMD python3 "$HARNESS/rss_probe.py" --transport http \
    --port "$MCPNZ_PORT" --token-file "$TOKEN_FILE" \
    --settle "$B03_SETTLE" --samples "$B03_SAMPLES" --interval "$B03_INTERVAL" \
    --jsonl "$RAW/b03_ours.jsonl" --series b03 --participant ours \
    --time-v-out "$RAW/b03_ours_time_v.txt" \
    --out "$RAW/b03_ours.json" -- "${MCPNZ_BIN:?set MCPNZ_BIN}"

echo "== b03 idle RSS: tumf/mcp-shell-server ==" >&2
tumf_env=()
for e in "${TUMF_ENV[@]}"; do tumf_env+=(-E "$e"); done
$NICE_CMD python3 "$HARNESS/rss_probe.py" --transport stdio \
    --settle "$B03_SETTLE_LAUNCHER" --samples "$B03_SAMPLES" --interval "$B03_INTERVAL" \
    --jsonl "$RAW/b03_tumf.jsonl" --series b03 --participant tumf \
    "${tumf_env[@]}" --out "$RAW/b03_tumf.json" -- "${TUMF_ARGV[@]}"

echo "== b03 idle RSS: g0t4/mcp-server-commands ==" >&2
$NICE_CMD python3 "$HARNESS/rss_probe.py" --transport stdio \
    --settle "$B03_SETTLE_LAUNCHER" --samples "$B03_SAMPLES" --interval "$B03_INTERVAL" \
    --jsonl "$RAW/b03_g0t4.jsonl" --series b03 --participant g0t4 \
    --out "$RAW/b03_g0t4.json" -- "${G0T4_ARGV[@]}"

python3 "$BENCH_DIR/lib/collect.py" \
    --metric b03_rss_idle --label "idle RSS after initialize (tree sum; median of 20 x 0.5s samples)" \
    ours "$RAW/b03_ours.json" tumf "$RAW/b03_tumf.json" g0t4 "$RAW/b03_g0t4.json" \
    > "$RESULTS/b03_rss_idle.json"
echo "wrote $RESULTS/b03_rss_idle.json" >&2
