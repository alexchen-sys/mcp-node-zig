#!/usr/bin/env bash
# b02 — TLS 1.3 node-link handshakes (ours only: the rivals ship no TLS link).
# Client side: N handshakes against the hub's TLS node-link listener
# (tcp_connect / tls_handshake / total per sample, throwaway EC CA).
# Node side: N spawn->registered cycles => link_established_ms.
# Skips cleanly (exit 0, note in the aggregate JSON) when the binary was
# built without -Dtls-server or openssl is unavailable.
set -euo pipefail
. "$(dirname "$0")/config.sh"

echo "== b02 TLS node-link handshake: ours (N=$B02_HANDSHAKES client, N=$B02_NODE_RUNS node) ==" >&2
$NICE_CMD python3 "$HARNESS/tls_probe.py" \
    --binary "${MCPNZ_BIN:?set MCPNZ_BIN or let run_all.sh build}" \
    --handshakes "$B02_HANDSHAKES" --node-runs "$B02_NODE_RUNS" \
    --api-port "$B02_HUB_PORT" --link-port "$B02_LINK_PORT" \
    --jsonl-client "$RAW/b02_client_ours.jsonl" \
    --jsonl-node "$RAW/b02_node_ours.jsonl" \
    --out "$RESULTS/b02_tls_handshake.json"
echo "wrote $RESULTS/b02_tls_handshake.json" >&2
