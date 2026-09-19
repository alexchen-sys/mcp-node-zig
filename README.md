# mcp-node-zig

[![ci](https://github.com/alexchen-sys/mcp-node-zig/actions/workflows/ci.yml/badge.svg)](https://github.com/alexchen-sys/mcp-node-zig/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A tiny, self-contained MCP node for remote machine operations, written in Zig.

It exposes a single streamable-HTTP JSON-RPC endpoint (`POST /mcp`) with a fixed set of practical tools:

- `sys_info` — hostname, OS, load, memory, uptime
- `exec` — run an argv array directly, with no shell layer, and wait for completion
- `exec_shell` — run one script through `bash`/`sh`/`fish`/`zsh -c`
- `exec_start` — start a long-running argv process as a session with piped stdin/stdout/stderr
- `exec_poll` — poll session output by byte offsets, with done/exit_code/truncation flags
- `exec_wait` — long-poll a session to completion or `timeout` (default 30s, max 300s)
- `exec_write` — write base64 bytes to session stdin; `eof=true` closes stdin
- `exec_kill` — kill the whole session process group
- `exec_close` — join session threads and free session state; idempotent
- `exec_list` — list live sessions with id, pid, argv, done, exit_code, timestamps
- `read_file` — UTF-8 text read with replacement, character offset/limit
- `write_file` — base64 write with mkdirs and SHA-256 receipt
- `list_dir` — directory listing with type/size/mtime, sorted by name

Full input schemas are introspectable at runtime via `tools/list`.

The design goal is a small trusted edge agent: static binary, explicit token auth, explicit Host allowlist, no framework sprawl.

[Build](#build) • [Run](#run) • [Client setup](#mcp-client-setup) • [Examples](#examples) • [Troubleshooting](#troubleshooting)

## Status

Early `0.1.0`; the contract may evolve.

## Build

Requires Zig 0.16.x. Linux only (uses `/proc` and POSIX process groups).

```sh
git clone https://github.com/alexchen-sys/mcp-node-zig
cd mcp-node-zig
zig build test
zig build -Doptimize=ReleaseSafe
```

Binary: `zig-out/bin/mcp-node` (statically linked, no libc).

There are no prebuilt releases yet; the build above takes seconds and yields a single static binary.

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
- `MCP_NODE_SESSION_TTL_S` — finished-session reap delay, default `600` (`0` -> `600`)
- `MCP_NODE_INSECURE=1` — allow startup with a missing token file (not recommended)

Auth header: `X-Node-Token: <token>`.

## MCP client setup

The server speaks streamable HTTP with a token header, so any MCP client with HTTP transport support can attach:

```sh
claude mcp add --transport http mcp-node http://127.0.0.1:8341/mcp \
  --header "X-Node-Token: $(cat token)"
```

Equivalent JSON (Claude Code, or any client that supports HTTP servers with headers):

```json
{
  "mcpServers": {
    "mcp-node": {
      "type": "http",
      "url": "http://127.0.0.1:8341/mcp",
      "headers": {
        "X-Node-Token": "<token>"
      }
    }
  }
}
```

Clients that only speak stdio need a bridge (e.g. `mcp-remote`) in front of this endpoint.

## Examples

One-shot call:

```sh
curl -sS http://127.0.0.1:8341/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -H "X-Node-Token: $(cat token)" \
  --data '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"exec","arguments":{"argv":["uname","-a"]}}}'
```

Long-running work goes through sessions. With a small helper to keep the tour readable:

```sh
mcp() {
  curl -sS http://127.0.0.1:8341/mcp \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json' \
    -H "X-Node-Token: $(cat token)" \
    --data "$1"
}
```

Start a session; the reply carries an integer `session_id`:

```sh
mcp '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"exec_start","arguments":{"argv":["bash","-c","for i in 1 2 3; do echo tick$i; sleep 5; done"]}}}'
```

Block until it exits (or until `timeout` seconds pass), then drain output incrementally — offsets resume where the previous poll left off:

```sh
mcp '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"exec_wait","arguments":{"session_id":1,"timeout":30}}}'
mcp '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"exec_poll","arguments":{"session_id":1,"stdout_offset":0,"stderr_offset":0}}}'
```

Free the session state (`exec_close` is idempotent):

```sh
mcp '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"exec_close","arguments":{"session_id":1}}}'
```

## Async process sessions

`exec_start` spawns argv as a session (own process group, piped stdin/stdout/stderr) and returns `session_id`; drive it with `exec_poll`/`exec_wait`/`exec_write`/`exec_kill`/`exec_close`, and inspect the live set with `exec_list`.

- Sessions are reference-counted; `exec_close` is idempotent (`already_closed: true` on repeat/late close) and safe to race against in-flight `exec_poll`/`exec_write`/`exec_kill` from other connections.
- `exec_kill`/`exec_close` kill the whole process group (`SIGKILL` on `-pid`), so shell children cannot hold pipes open.
- Output buffers are capped per stream (`MCP_NODE_MAX_OUT`); overflow sets `truncated_stdout`/`truncated_stderr` instead of failing the process.
- `exec_poll` deltas never split a multi-byte UTF-8 sequence at the chunk edge while the process is alive; the returned offsets always point at the next unconsumed byte.
- Finished sessions are reaped automatically after `MCP_NODE_SESSION_TTL_S` seconds; a full store (`MCP_NODE_MAX_SESSIONS`) lazily evicts finished sessions before refusing new ones.

## Protocol notes

- JSON-RPC parse errors return HTTP 400 with `-32700`; notifications without `id` return HTTP 202 with an empty body.
- Tool domain errors return `{ok:false,...}` with `isError=false`; unknown tools return `isError=true`.
- HTTP/1.1 keep-alive is supported for sequential requests on one connection; `Connection: close` closes after the response.

## Security notes

- Auth is a constant-time SHA-256 comparison of the `X-Node-Token` header; a missing token or a wrong one gets HTTP 401, and a missing/empty token file fails closed unless `MCP_NODE_INSECURE=1`.
- `Host` is validated before JSON parsing; unknown hosts get HTTP 421. A present `Origin` header is validated against `MCP_NODE_ALLOWED_ORIGINS`; unknown origins get HTTP 403.
- Requests over 32 MiB get HTTP 413; conflicting duplicate `Content-Length` headers are rejected. `Expect: 100-continue` is answered before the body is read. Only `POST /mcp` with `Content-Type: application/json` is served (405/415 otherwise).
- `exec`/`exec_shell` timeouts are clamped to `[1, 1800]` seconds (default 120s).
- Connections are handled one thread per connection, capped by `MCP_NODE_MAX_CONN`; excess connections get HTTP 503.
- `exec` does not pass through a shell; shell metacharacters are data. `exec_shell` is intentionally one explicit shell layer for pipelines and redirects.
- `write_file` returns a SHA-256 digest for verification.

## Troubleshooting

- **HTTP 401** — missing or wrong `X-Node-Token`; the server also refuses to start with a missing/empty token file unless `MCP_NODE_INSECURE=1`.
- **HTTP 421** — the request's `Host` header is not in `MCP_NODE_ALLOWED_HOSTS`; add the `host:port` you actually connect through (anything but loopback needs an explicit entry).
- **HTTP 403** — an `Origin` header was present (browser-originated call) and is not in `MCP_NODE_ALLOWED_ORIGINS`.

## License

MIT — see [LICENSE](LICENSE).
