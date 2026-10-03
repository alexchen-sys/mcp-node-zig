#!/usr/bin/env bash
# b03 — idle RSS after a warmup initialize, sampled over the whole process tree.
# 20 samples x 0.5 s -> median + max (RSS and PSS). /usr/bin/time -v Max RSS is
# recorded for the single-process (ours) case as an orthogonal check.
set -euo pipefail
. "$(dirname "$0")/config.sh"

echo "== b03 idle RSS: ours ==" >&2
$NICE_CMD python3 "$HARNESS/rss_probe.py" --transport http \
    --port "$MCPNZ_PORT" --token-file "$TOKEN_FILE" \
    --settle 2.0 --samples "$B03_SAMPLES" --interval "$B03_INTERVAL" \
    --time-v-out "$RAW/b03_ours_time_v.txt" \
    --out "$RAW/b03_ours.json" -- "${MCPNZ_BIN:?set MCPNZ_BIN}"

echo "== b03 idle RSS: tumf/mcp-shell-server ==" >&2
tumf_env=()
for e in "${TUMF_ENV[@]}"; do tumf_env+=(-E "$e"); done
$NICE_CMD python3 "$HARNESS/rss_probe.py" --transport stdio \
    --settle 2.0 --samples "$B03_SAMPLES" --interval "$B03_INTERVAL" \
    "${tumf_env[@]}" --out "$RAW/b03_tumf.json" -- "${TUMF_ARGV[@]}"

echo "== b03 idle RSS: g0t4/mcp-server-commands ==" >&2
$NICE_CMD python3 "$HARNESS/rss_probe.py" --transport stdio \
    --settle 2.0 --samples "$B03_SAMPLES" --interval "$B03_INTERVAL" \
    --out "$RAW/b03_g0t4.json" -- "${G0T4_ARGV[@]}"

python3 "$BENCH_DIR/lib/collect.py" \
    --metric b03_rss_idle --label "idle RSS after initialize (tree sum; median of 20 x 0.5s samples)" \
    ours "$RAW/b03_ours.json" tumf "$RAW/b03_tumf.json" g0t4 "$RAW/b03_g0t4.json" \
    > "$RESULTS/b03_rss_idle.json"
echo "wrote $RESULTS/b03_rss_idle.json" >&2
