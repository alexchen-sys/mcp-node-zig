#!/usr/bin/env bash
# b08 — delivery footprint: what you must put on the target machine.
# ours: one static binary (stat). rivals: package environment laid down by
# their documented install channel (uvx venv / npx cache) + the language
# runtime that interprets them; paths are resolved from a live process.
set -euo pipefail
. "$(dirname "$0")/config.sh"

$NICE_CMD python3 "$HARNESS/footprint_probe.py" \
    --ours-bin "${MCPNZ_BIN:?set MCPNZ_BIN}" \
    --build-mode "$MCPNZ_BUILD_MODE" \
    --out "$RESULTS/b08_footprint.json"
echo "wrote $RESULTS/b08_footprint.json" >&2
