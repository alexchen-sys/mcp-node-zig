# mcp-node-zig

[![CI](https://github.com/alexchen-sys/mcp-node-zig/actions/workflows/ci.yml/badge.svg)](https://github.com/alexchen-sys/mcp-node-zig/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/alexchen-sys/mcp-node-zig)](https://github.com/alexchen-sys/mcp-node-zig/releases)
[![Platforms](https://img.shields.io/badge/platform-Linux%20%C2%B7%20macOS%20%C2%B7%20Windows-blue)](#status)
[![Built in Zig](https://img.shields.io/badge/built%20in-Zig-f7a41d)](#building-from-source)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

English | [Русский](README.ru.md)

A tiny, trusted edge agent that gives AI hands on your machines — one static binary, no runtime, no SSH.

<!-- TODO: session demo gif -->

Run it on any machine you want your AI to reach — a build box, a homelab server, a Windows host, a small fleet of VPSes. It serves a single streamable-HTTP MCP endpoint with token auth, a Host allowlist, and process sessions that outlive any single HTTP request. Your agent runs commands, drives long-running processes, and reads and writes files.

SSH bridges need keys and OpenSSH. Runtimes need Node or Python on every box. mcp-node-zig needs neither.

[Quickstart](#quickstart) • [Client setup](#mcp-client-setup) • [Why not SSH](#why-not-ssh-based-mcp) • [Configuration](#configuration) • [Examples](#examples) • [Security](#security-notes) • [Limitations](#limitations) • [Troubleshooting](#troubleshooting) • [Building from source](#building-from-source)

## Quickstart

Four commands to a working node (Linux, x86_64):

```sh
curl -L https://github.com/alexchen-sys/mcp-node-zig/releases/download/v0.1.1/mcp-node-v0.1.1-x86_64-linux.tar.gz | tar xz
openssl rand -hex 32 > token
./mcp-node-v0.1.1-x86_64-linux/mcp-node &
curl -sS http://127.0.0.1:8341/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -H "X-Node-Token: $(cat token)" \
  --data '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"sys_info","arguments":{}}}'
```

You should see something like this (pretty-printed; the real reply is one line and also carries a `content` text block mirroring `structuredContent`; your values will differ):

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "structuredContent": {
      "node": "mcp-node",
      "hostname": "your-machine",
      "os": "Linux",
      "machine": "x86_64",
      "loadavg_raw": "0.31 0.26 0.19 ...",
      "uptime_raw": "86400.00 ...",
      "mem": { "MemTotal": 16384000, "MemAvailable": 8192000 }
    },
    "isError": false
  }
}
```

No `openssl`? `head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > token` works too.

**macOS (Apple Silicon)** — same flow with the aarch64 archive:

```sh
curl -L https://github.com/alexchen-sys/mcp-node-zig/releases/download/v0.1.1/mcp-node-v0.1.1-aarch64-macos.tar.gz | tar xz
openssl rand -hex 32 > token
./mcp-node-v0.1.1-aarch64-macos/mcp-node &
```

then the same `curl` verify as on Linux. ARM64 Linux: swap in `mcp-node-v0.1.1-aarch64-linux.tar.gz`. Intel Macs: [build from source](#building-from-source).

**Windows (PowerShell)** — run the server in one window:

```powershell
curl.exe -L -o mcp-node.zip https://github.com/alexchen-sys/mcp-node-zig/releases/download/v0.1.1/mcp-node-v0.1.1-x86_64-windows.zip
Expand-Archive mcp-node.zip
[guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N') | Set-Content -NoNewline -Encoding Ascii token
.\mcp-node-v0.1.1-x86_64-windows\mcp-node.exe
```

and verify from a second window:

```powershell
$sys = Invoke-RestMethod -Uri http://127.0.0.1:8341/mcp -Method Post -ContentType "application/json" `
  -Headers @{ "X-Node-Token" = (Get-Content token) } `
  -Body '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"sys_info","arguments":{}}}'
$sys.result.structuredContent
```

Every release carries a `SHA256SUMS.txt` manifest — check your archive against it (`sha256sum` on Linux, `shasum -a 256` on macOS, `Get-FileHash` on Windows).

## Tools

A fixed set of practical tools, exposed over a single streamable-HTTP JSON-RPC endpoint (`POST /mcp`):

- `sys_info` — hostname, OS, load, memory, uptime
- `exec` — run an argv array directly, with no shell layer, and wait for completion
- `exec_shell` — run one script through a shell (`bash`/`sh`/`fish`/`zsh -c`; `cmd`/`powershell` on Windows)
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

## MCP client setup

Any MCP client with HTTP transport support can attach. Pick yours:

### Claude Code

```sh
claude mcp add --transport http mcp-node http://127.0.0.1:8341/mcp \
  --header "X-Node-Token: $(cat token)"
```

### Cursor

Save as `.cursor/mcp.json` in the project, or `~/.cursor/mcp.json` for a global server (Settings → MCP → Add new global MCP server):

```json
{
  "mcpServers": {
    "mcp-node": {
      "url": "http://127.0.0.1:8341/mcp",
      "headers": { "X-Node-Token": "<token>" }
    }
  }
}
```

### VS Code

Save as `.vscode/mcp.json` in the workspace, or open the Command Palette → “MCP: Open User Configuration” for the user-level file:

```json
{
  "servers": {
    "mcp-node": {
      "type": "http",
      "url": "http://127.0.0.1:8341/mcp",
      "headers": { "X-Node-Token": "<token>" }
    }
  }
}
```

### Codex

Add to `~/.codex/config.toml` and restart Codex:

```toml
[mcp_servers.mcp-node]
url = "http://127.0.0.1:8341/mcp"
http_headers = { "X-Node-Token" = "<token>" }
```

### Claude Desktop and other JSON clients

```json
{
  "mcpServers": {
    "mcp-node": {
      "type": "http",
      "url": "http://127.0.0.1:8341/mcp",
      "headers": {
        "Authorization": "Bearer <token>"
      }
    }
  }
}
```

The standard Bearer scheme works everywhere; `X-Node-Token` above is the alternative for clients that cannot set an `Authorization` header. A request that carries both must send the same value.

### stdio-only clients

Bridge the HTTP endpoint with [mcp-remote](https://github.com/geelen/mcp-remote):

```sh
npx mcp-remote http://127.0.0.1:8341/mcp --header "X-Node-Token: <token>"
```

Now ask your agent:

> “Run sys_info on mcp-node and show me the memory usage.”

## Why not SSH-based MCP

SSH bridges are a solid, honest choice when every target already runs OpenSSH and you are fine keeping SSH keys in each MCP client. mcp-node-zig exists for the machines where that is not true — Windows hosts without OpenSSH, containers, closed network segments, fleets where distributing SSH keys is exactly the thing you want to avoid.

| | SSH-based MCP bridge | Local stdio server | mcp-node-zig |
| --- | --- | --- | --- |
| Install on the target machine | none (OpenSSH only) | runtime + server (Node/Python) | one static binary |
| Runtime on the target | OpenSSH | Node or Python | none |
| Auth model | SSH keys in each client | client OS-user permissions | one token, constant-time compare |
| Long-running processes | tied to the SSH connection | tied to the client process | sessions survive requests |
| Windows without OpenSSH | needs OpenSSH set up | needs a runtime | works out of the box |
| NAT / closed networks | needs a reachable SSH port | local only | any HTTP path (reverse tunnel, VPN) |

The SSH column is not a straw man: if you already run OpenSSH everywhere, a bridge may well be the simpler answer. The trade only pays where SSH is missing, unwanted, or expensive to maintain.

## Configuration

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
- `MCP_NODE_INSECURE=1` — allow startup without a token (not recommended); on Windows a missing token file always fails startup, so create an empty one instead

Auth header: the standard Bearer scheme most MCP clients send, or `X-Node-Token: <token>`. If a request carries both, they must match; otherwise it gets 401.

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
- `exec_kill`/`exec_close` kill the whole process tree (process-group `SIGKILL` on POSIX, Job Object termination on Windows), so shell children cannot hold pipes open.
- Output buffers are capped per stream (`MCP_NODE_MAX_OUT`); overflow sets `truncated_stdout`/`truncated_stderr` instead of failing the process.
- `exec_poll` deltas never split a multi-byte UTF-8 sequence at the chunk edge while the process is alive; the returned offsets always point at the next unconsumed byte.
- Finished sessions are reaped automatically after `MCP_NODE_SESSION_TTL_S` seconds; a full store (`MCP_NODE_MAX_SESSIONS`) lazily evicts finished sessions before refusing new ones.

## Status

Early `0.1.x`; the contract may evolve.

Platform support: **Linux**, **macOS**, and **Windows** — all three are built, unit-tested, and smoke-tested (auth gate, `initialize`, `sys_info`) on every push by the CI matrix. Linux is the primary production target. On Windows, process trees are managed with Job Objects and socket timeouts use overlapped AFD I/O with software deadlines.

## Protocol notes

- JSON-RPC parse errors return HTTP 400 with `-32700`; notifications without `id` return HTTP 202 with an empty body.
- Tool domain errors return `{ok:false,...}` with `isError=false`; unknown tools return `isError=true`.
- HTTP/1.1 keep-alive is supported for sequential requests on one connection; `Connection: close` closes after the response.

## Security notes

- Auth is a constant-time SHA-256 comparison of the token from the standard Bearer header or `X-Node-Token`; a missing token, a wrong one, a non-Bearer scheme, or two headers that disagree gets HTTP 401 with `WWW-Authenticate: Bearer`. A repeated `Authorization` header is rejected with 400, and a missing/empty token file fails closed unless `MCP_NODE_INSECURE=1`.
- `Host` is validated before JSON parsing; unknown hosts get HTTP 421. A present `Origin` header is validated against `MCP_NODE_ALLOWED_ORIGINS`; unknown origins get HTTP 403.
- Requests over 32 MiB get HTTP 413; conflicting duplicate `Content-Length` headers are rejected. `Expect: 100-continue` is answered before the body is read. Only `POST /mcp` with `Content-Type: application/json` is served (404/405/415 otherwise; headers over 64 KiB get 431).
- `exec`/`exec_shell` timeouts are clamped to `[1, 1800]` seconds (default 120s).
- Connections are handled one thread per connection, capped by `MCP_NODE_MAX_CONN`; excess connections get HTTP 503.
- `exec` does not pass through a shell; shell metacharacters are data. `exec_shell` is intentionally one explicit shell layer for pipelines and redirects.
- `write_file` returns a SHA-256 digest for verification.

## Limitations

- **No TLS built in.** The endpoint speaks plain HTTP. Keep it on loopback and terminate TLS in front — with Caddy it is one line: `caddy reverse-proxy --from node.example.com --to 127.0.0.1:8341` — or reach it through a tunnel or VPN in closed networks.
- **No PTY.** Session stdin/stdout/stderr are pipes, so interactive TUI programs are not covered.
- **No audit log yet** — planned (see [Roadmap](#roadmap)).

## Roadmap

- [ ] Built-in TLS termination (until then: the Caddy/tunnel recipe above)
- [ ] PTY support for interactive programs
- [ ] Structured audit log

## Troubleshooting

- **HTTP 401** — missing or wrong token. Check that the header is `X-Node-Token: <token>` or the standard Bearer header, and that a client sending both sends the same value; the server also refuses to start with a missing/empty token file unless `MCP_NODE_INSECURE=1`.
- **HTTP 421** — the request's `Host` header is not in `MCP_NODE_ALLOWED_HOSTS`; add the `host:port` you actually connect through (anything but loopback needs an explicit entry).
- **HTTP 403** — an `Origin` header was present (browser-originated call) and is not in `MCP_NODE_ALLOWED_ORIGINS`.
- **HTTP 415** — the POST is missing `Content-Type: application/json`.
- **Connection refused / empty reply** — the server is not listening on that address:port. Check `MCP_NODE_HOST` (default `127.0.0.1`, which is not reachable from other machines) and `MCP_NODE_PORT`, and confirm the process is alive.
- **Server exits at startup** — the token file is missing or empty (fail-closed by design). Create it first; on Windows the token file must exist even with `MCP_NODE_INSECURE=1` set (an empty one is fine there).

## Upgrade and uninstall

- **Upgrade** — download the newer release archive, replace the binary, restart the node.
- **Uninstall** — stop the process, then delete the binary, the token file, and any service unit you created.

<!-- Used by: reserved for the first external user story (quote + link). -->

## Building from source

Requires Zig 0.16.x. Linux, macOS, and Windows targets (see [Status](#status)).

```sh
git clone https://github.com/alexchen-sys/mcp-node-zig
cd mcp-node-zig
zig build test
zig build -Doptimize=ReleaseSafe
```

Binary: `zig-out/bin/mcp-node` (on Linux statically linked with no libc; macOS links libSystem, Windows links kernel32/ntdll — no other dependencies).

## License

MIT — see [LICENSE](LICENSE).
