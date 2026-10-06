# Audit log

A tamper-evident, append-only JSONL log of everything the daemon does that
can change a machine or reveal data: every tool call on the node, and every
relay decision plus link lifecycle event on the hub. One JSON object per
line, fields in a fixed order, chained with HMAC-SHA256 so edits, deletions
and reordering of past records are detectable.

Off by default. Set `MCP_NODE_AUDIT_FILE` to turn it on.

## Setup

```sh
openssl rand -hex 32 > audit-key
chmod 600 audit-key
MCP_NODE_AUDIT_FILE=/var/log/mcp-node-audit.jsonl \
MCP_NODE_AUDIT_KEY_FILE=./audit-key \
  ./mcp-node
```

| Variable | Default |
| --- | --- |
| `MCP_NODE_AUDIT_FILE` | unset; audit off, zero overhead |
| `MCP_NODE_AUDIT_KEY_FILE` | unset; records are written but not chained (`"chain":false` in the start record) |
| `MCP_NODE_AUDIT_ARGS` | `summary`; `full` logs full argv and paths |
| `MCP_NODE_AUDIT_ON_FULL` | `block`; `drop` sheds records under a stuck disk and logs a chained `dropped` record with the count |
| `MCP_NODE_AUDIT_MAX_BYTES` | `67108864` (64 MiB); past this size the file is renamed to `<file>.<first-seq>` and the chain continues in a fresh file opened with a `rotate` record |

The key file must be `0600` on POSIX; anything group/other-readable fails
startup. The audit key is separate from the HTTP token and the link secret
on purpose: a reader of the audit key must not get a shell. Setting the key
without the file is a startup error (typo guard).

With `block` (default), a full disk or a stalled writer makes tool calls
wait: an unlogged action is considered worse than a slow one. Pick `drop`
when availability beats completeness; the gap stays visible as a `dropped`
record inside the chain.

## What is logged

Node, per `tools/call` (`tool.call`), plus `tool.start` before dispatch for
the long tools (`exec`, `exec_start`, `exec_shell`) so a crash mid-call
still leaves a trace:

- `tool`, `transport` (`http`/`stdio`/`link`), `client` (HTTP peer address,
  `stdio`, or `hub:<host>:<port>`), `session` (sha256 prefix of the
  `Mcp-Session-Id` header, never the id itself), `req_id` (the JSON-RPC id,
  truncated to 64 bytes), `link_sid` on the reverse link,
  `args_digest` (sha256 of the canonical arguments JSON),
  `args_summary` (per-tool allowlist, below), `ok`, `exit_code`, `error`
  (error name only), `duration_ms`, `out_bytes`.

Hub: `link.up` (node name, source address), `link.fail` (source, error
name), `link.ban` (source key, seconds), `link.down` (name, reason), and
`relay` (client address, node name, JSON-RPC method, tool name for
tools/call, `req_id`, `ok`, `duration_ms`, `bytes_in`, `bytes_out`). The
hub `relay` and the node `tool.call` share `req_id` and `link_sid`, so the
two files join.

Both roles log `start` (with a sha256 fingerprint of the effective config;
secrets are replaced by their file paths, so a changed allowlist shows up)
and `stop`.

Argument summaries are an allowlist, per tool:

| Tool | Logged |
| --- | --- |
| `exec`, `exec_start` | `argv[0]` and argc; full argv with `MCP_NODE_AUDIT_ARGS=full` |
| `exec_shell` | shell name and script length, never the script |
| `read_file`, `list_dir` | path |
| `write_file` | path and decoded size, never the content |
| `exec_poll`, `exec_wait`, `exec_write`, `exec_kill`, `exec_close` | session id |
| everything else | `{}` |

Scripts, file contents and stdout are never logged in any mode.

## Chain format

```
{"v":1,"seq":42,"ts":"2026-10-06T12:00:00.123Z","host":"node-a","role":"node","event":"tool.call",...,"prev":"<hex>","mac":"<hex>"}
```

`seq` starts at 0 per process chain and increments by 1; a gap means a
deletion. `prev` is the MAC of the previous line, `mac` is
HMAC-SHA256(key, line without the `,"mac":"..."}` suffix). The writer
emits fields in a fixed order with no optional whitespace, so the verifier
recomputes over the exact bytes on disk without re-serializing JSON.

Writes are `O_APPEND`, mode `0600`, batched fsync (50 ms or 64 records).
On startup the daemon reads the tail of an existing file, verifies the
chain over the tail window and continues `seq`/`prev`, so a restart —
including kill -9 between batches — continues the same chain. A torn final
line is truncated; a tail that fails verification is renamed to
`<file>.corrupt-<epoch ms>` and the new file starts with a `chain.break`
record.

## Verifying

```sh
mcp-node audit-verify /var/log/mcp-node-audit.jsonl
mcp-node audit-verify /var/log/mcp-node-audit.jsonl.0 /var/log/mcp-node-audit.jsonl
mcp-node audit-verify --anchor /var/log/mcp-node-audit.jsonl
```

Rotated files verify together when passed oldest-first; the chain crosses
the rename.

Exit 0 when the chain is intact, 1 when broken, printing the seq of the
first broken record. The key comes from `MCP_NODE_AUDIT_KEY_FILE`, same as
the daemon; verifying a chained file without the key fails closed.
`--anchor` prints `seq mac` of the last record: store that pair off-box
(ticket, chat, another machine) to pin the chain.

## Threat model

Detected by verification alone: editing any record, deleting or reordering
records, truncating the file in the middle, splicing two chains.

Detected only against an off-box anchor: truncating the *tail* of the log
(the attacker rewrites history from some point and the new chain verifies
end to end). An anchor pins a `(seq, mac)` pair; any rewrite before it
breaks the comparison.

Not covered: a root attacker on the machine can stop logging, delete the
file, or — with the audit key — forge a fresh chain from scratch. Keep the
key off the audited machine when that matters, and anchor regularly. The
`block`/`drop` choice above is the availability trade-off under a full
disk; `block` can stall tool calls, `drop` loses records with a visible
chained gap.
