# mcp-node-zig

A tiny, self-contained MCP node for remote machine operations, written in Zig.

It exposes a single streamable-HTTP JSON-RPC endpoint (`POST /mcp`) with practical tools:

- `sys_info` — hostname, OS, load, memory, uptime
- `exec` — run an argv array directly, with no shell layer, and wait for completion
- `exec_start` — start a long-running argv process as a session with piped stdin/stdout/stderr
- `exec_poll` — poll session output by byte offsets, with done/exit_code/truncation flags
- `exec_write` — write base64 bytes to session stdin; `eof=true` closes stdin
- `exec_kill` — kill the whole session process group
- `exec_close` — join session threads and free session state
- `exec_shell` — run one script through `bash`/`sh`/`fish`/`zsh -c`
- `read_file` — UTF-8 text read with replacement, character offset/limit
- `write_file` — base64 write with mkdirs and SHA-256 receipt
- `list_dir` — directory listing with type/size/mtime

The design goal is a small trusted edge agent: static binary, explicit token auth, explicit Host allowlist, no framework sprawl.

## Status

Early `0.1.0`. The contract is intentionally narrow: a fixed tool set, explicit auth, and no framework dependencies. JSON-RPC parse errors return HTTP 400 with `-32700`; notifications without `id` return HTTP 202 with an empty body; tool domain errors return `{ok:false,...}` with `isError=false`; unknown tools return `isError=true`.

## Build

Requires Zig 0.16.x.

```sh
zig build test
zig build -Doptimize=ReleaseSafe
```

Binary: `zig-out/bin/mcp-node`.

## Run

```sh
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > token
MCP_NODE_PORT=8341 MCP_NODE_NAME=mcp-node ./zig-out/bin/mcp-node
```

Configuration is environment-only:

- `MCP_NODE_NAME` — serverInfo name, default `mcp-node`
- `MCP_NODE_HOST` — bind host IP literal, default `127.0.0.1`
- `MCP_NODE_PORT` — bind port, default `8341`
- `MCP_NODE_TOKEN_FILE` — token file path, default `./token`
- `MCP_NODE_ALLOWED_HOSTS` — comma list, default `127.0.0.1:*,localhost:*,[::1]:*`
- `MCP_NODE_ALLOWED_ORIGINS` — comma list enforced when an `Origin` header is present, default `http://127.0.0.1:*,http://localhost:*,http://[::1]:*`
- `MCP_NODE_MAX_OUT` — per-stream stdout/stderr cap, default `400000`
- `MCP_NODE_SOCKET_TIMEOUT_S` — per-read and total request deadline, default `60` (`0` -> `60`)
- `MCP_NODE_MAX_CONN` — max concurrent TCP connections, default `128` (`0` -> `128`)
- `MCP_NODE_MAX_SESSIONS` — max live exec sessions, default `64` (`0` -> `64`)
- `MCP_NODE_INSECURE=1` — allow startup with a missing token file (not recommended)

Auth header: `X-Node-Token: <token>`.

## Example

```sh
curl -sS http://127.0.0.1:8341/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -H "X-Node-Token: $(cat token)" \
  --data '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"exec","arguments":{"argv":["uname","-a"]}}}'
```

## Async process sessions

`exec_start` spawns argv as a session (own process group, piped stdin/stdout/stderr) and returns `session_id`. Then:

- `exec_poll` — output deltas by byte offsets, `done`, `exit_code`, truncation flags.
- `exec_wait` — long-poll until completion or `timeout` (default 30s, max 300s); same payload as `exec_poll`.
- `exec_write` — base64 bytes to stdin; `eof: true` closes stdin.
- `exec_kill` — SIGKILL the whole process group.
- `exec_close` — reap and free; idempotent (`already_closed: true`).
- `exec_list` — live sessions with id, pid, argv, state, timestamps.

Finished sessions are reaped automatically after `MCP_NODE_SESSION_TTL_S` seconds (default 600), and a full store lazily evicts finished sessions before refusing new ones.

## Session lifecycle guarantees

- Sessions are reference-counted; `exec_close` is idempotent (`already_closed: true` on repeat/late close) and safe to race against in-flight `exec_poll`/`exec_write`/`exec_kill` from other connections.
- Session processes start in their own process group; `exec_kill`/`exec_close` kill the whole group (`SIGKILL` on `-pid`).
- Output buffers are capped per stream (`MCP_NODE_MAX_OUT`, default 400000 bytes); overflow sets `truncated_stdout`/`truncated_stderr`.
- `exec_poll` deltas never split a multi-byte UTF-8 sequence at the chunk edge while the process is alive; the returned offsets always point at the next unconsumed byte.
- Full session store (`MCP_NODE_MAX_SESSIONS`, default 64) lazily evicts finished sessions before refusing new ones.

## Security notes

- Missing or empty token fails closed unless `MCP_NODE_INSECURE=1` is set.
- `Host` is validated before JSON parsing; unknown hosts get HTTP 421.
- A present `Origin` header is validated against `MCP_NODE_ALLOWED_ORIGINS`; unknown origins get HTTP 403.
- Requests over 32 MiB get HTTP 413; conflicting duplicate `Content-Length` headers are rejected.
- `Expect: 100-continue` is answered before the body is read.
- `GET /mcp` gets HTTP 405; only `POST /mcp` is served.
- `exec`/`exec_shell` timeouts are clamped to `[1, 1800]` seconds.
- Connections are handled one thread per connection, capped by `MCP_NODE_MAX_CONN`; excess connections get HTTP 503.
- HTTP/1.1 keep-alive is supported for sequential requests on one connection; `Connection: close` closes after the response.
- `exec_start` sessions run in their own process group; `exec_kill`/`exec_close` kill the group so shell children cannot hold pipes open.
- Session stdout/stderr are capped by `MCP_NODE_MAX_OUT`; overflow sets `truncated_*` instead of failing the process.
- `exec` does not pass through a shell; shell metacharacters are data.
- `exec_shell` is intentionally one explicit shell layer for pipelines and redirects.
- `write_file` returns a SHA-256 digest for verification.

## License

MIT
