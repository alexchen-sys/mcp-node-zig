# mcp-node-zig

[![CI](https://github.com/alexchen-sys/mcp-node-zig/actions/workflows/ci.yml/badge.svg)](https://github.com/alexchen-sys/mcp-node-zig/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/alexchen-sys/mcp-node-zig)](https://github.com/alexchen-sys/mcp-node-zig/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

English | [Русский](README.ru.md) | [中文](README.zh.md)

Give your AI agent a shell on any machine. One binary, no runtime, no SSH.

![mcp-node-zig: a node behind NAT dials out to a hub, the hub runs a command on it](assets/demo.gif)

**1.9 ms** cold start · **0.62 MiB** idle RSS · **8.70 MiB** on disk · **0.7 ms** p50 exec round-trip ([benchmarks](BENCHMARKS.md))

mcp-node-zig is a remote execution node that speaks MCP: put one static binary on a machine and your agent can run commands, drive long-running sessions and read or write files there. Since v0.2.0 the node can dial out to a hub instead of listening, so a box behind NAT or someone else's firewall is reachable with no inbound ports and no SSH. It answers its first MCP request 1.9 ms after start and idles at 0.62 MiB, which makes leaving one on every machine basically free.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/alexchen-sys/mcp-node-zig/main/install.sh | sh
```

The script detects the platform, downloads the latest release, verifies it against `SHA256SUMS.txt` and installs to `/usr/local/bin` (or `~/.local/bin`). Pin a version with `MCP_NODE_VERSION=0.2.0`, change the target directory with `PREFIX=/some/dir`.

Manual install, Linux x86_64:

```sh
curl -L https://github.com/alexchen-sys/mcp-node-zig/releases/download/v0.2.1/mcp-node-v0.2.1-x86_64-linux.tar.gz | tar xz
```

Other targets on the [releases page](https://github.com/alexchen-sys/mcp-node-zig/releases): `aarch64-linux`, `aarch64-macos`, `x86_64-windows`. Each release ships `SHA256SUMS.txt`.

## Quickstart

```sh
openssl rand -hex 32 > token
./mcp-node-v0.2.1-x86_64-linux/mcp-node &

curl -sS http://127.0.0.1:8341/mcp \
  -H 'Content-Type: application/json' \
  -H "X-Node-Token: $(cat token)" \
  --data '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"sys_info","arguments":{}}}'
```

You get back hostname, OS, load, memory and uptime as JSON. Now attach your agent:

```sh
claude mcp add --transport http mcp-node http://127.0.0.1:8341/mcp \
  --header "X-Node-Token: $(cat token)"
```

<details>
<summary>Windows (PowerShell)</summary>

```powershell
curl.exe -L -o mcp-node.zip https://github.com/alexchen-sys/mcp-node-zig/releases/download/v0.2.1/mcp-node-v0.2.1-x86_64-windows.zip
Expand-Archive mcp-node.zip
[guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N') | Set-Content -NoNewline -Encoding Ascii token
.\mcp-node-v0.2.1-x86_64-windows\mcp-node.exe
```

From a second window:

```powershell
Invoke-RestMethod -Uri http://127.0.0.1:8341/mcp -Method Post -ContentType "application/json" `
  -Headers @{ "X-Node-Token" = (Get-Content token) } `
  -Body '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"sys_info","arguments":{}}}'
```

</details>

## Why

- **Nothing to provision.** No Node, no Python, no OpenSSH, no keys to distribute. Copy one file and run it.
- **Processes outlive requests.** Start a build, disconnect, come back and read the output by offset.
- **Cheap to keep running.** Under 1 MiB idle. Each extra connected agent adds about 288 KiB, not a second ~190 MiB server process.
- **No shell unless you ask.** `exec` passes argv verbatim. `exec_shell` is the one explicit shell layer.
- **Kills the whole tree.** Process groups on POSIX, Job Objects on Windows. No orphaned children holding pipes.
- **Linux, macOS, Windows.** All three are built and smoke-tested in CI on every push.

## How is this different from SSH?

They solve different problems, and they work well together.

SSH is a secure transport and a terminal for people. It has encryption, key management, agent forwarding, PTYs, scp/sftp/rsync and decades of hardening. Keep using it for all of that.

mcp-node is an execution API for agents. Through SSH, an agent gets one string that a remote shell parses again, plus raw bytes and an exit status. Here it gets:

- **argv without a shell.** No second round of quoting for a remote shell to reparse. A shell is used only when you ask for `exec_shell`.
- **Structured results.** `stdout`, `stderr`, `exit_code`, `truncated_*` and timings as JSON, with per-call timeouts.
- **Sessions that outlive the request.** `exec_start`, then `exec_poll` by byte offset, `exec_write` to stdin, `exec_wait` up to 300 s, `exec_kill` for the whole tree. A dropped connection doesn't kill the build.
- **Verified file writes.** `write_file` takes base64 and returns the SHA-256 of what landed on disk.
- **A self-describing interface.** Any MCP client discovers the tools from `tools/list`; nothing to teach the agent.

Speed isn't the argument: on an open connection both are fast. The mcp-node HTTP server has no encryption of its own, so for remote machines the usual setup is both together: the node listens on `127.0.0.1` and you reach it through an SSH tunnel (`ssh -L 8341:127.0.0.1:8341 host`), a VPN or a TLS reverse proxy.

## Reverse connect (no inbound ports)

For machines behind NAT or without sshd, run the node with
`--connect hub:port`: it dials out to a hub (the same binary with
`MCP_NODE_HUB_LISTEN`), and clients reach it at `/n/<name>/mcp` on the hub.
The default setup wraps the link in TLS: the hub's link port stays on
`127.0.0.1` behind a TLS terminator (nginx `stream`, stunnel, HAProxy), and
the node dials it with `MCP_NODE_CONNECT_TLS=1`:

```sh
# hub; nginx/stunnel terminates TLS on :8400 and forwards to 127.0.0.1:8401
MCP_NODE_HUB_LISTEN=127.0.0.1:8401 MCP_NODE_HUB_SECRET_FILE=nodes ./mcp-node
# node; `nodes` on the hub holds the line laptop:<secret>, `secret` here holds <secret>
MCP_NODE_NAME=laptop MCP_NODE_CONNECT_SECRET_FILE=secret MCP_NODE_CONNECT_TLS=1 \
  ./mcp-node --connect hub.example.com:8400
```

A binary built with `-Dtls-server` can serve TLS on the link port itself
(`MCP_NODE_HUB_TLS_CERT_FILE` / `MCP_NODE_HUB_TLS_KEY_FILE`), with no
terminator in front; the hub then sees the real peer addresses, so its
per-source handshake limits apply as written.

Full setup, a terminator config and the plain TCP variant for trusted
networks are in [docs/reverse-connect.md](docs/reverse-connect.md).

## stdio mode

Clients that spawn their servers as subprocesses can run the node directly
with `--stdio` (or `MCP_NODE_STDIO=1`). Messages are newline-delimited
JSON-RPC: one request per line on stdin, one response per line on stdout.
There is no listener and no token, since whoever holds the pipes started the
process. Logs go to stderr only; the node exits 0 when stdin closes and kills
any sessions still running.

```json
{
  "mcpServers": {
    "mcp-node": {
      "command": "mcp-node",
      "args": ["--stdio"]
    }
  }
}
```

`--stdio` can't be combined with `--connect` or `MCP_NODE_HUB_LISTEN`.

## Audit log

Set `MCP_NODE_AUDIT_FILE` and every tool call leaves one append-only JSONL
record, chained with HMAC-SHA256 so edits, deletions and reordering of past
records are detectable offline:

```sh
openssl rand -hex 32 > audit-key && chmod 600 audit-key
MCP_NODE_AUDIT_FILE=/var/log/mcp-node.jsonl MCP_NODE_AUDIT_KEY_FILE=./audit-key ./mcp-node
mcp-node audit-verify --anchor /var/log/mcp-node.jsonl
```

The node records each `tools/call` (tool, transport, peer, per-tool argument
summary, result), the hub records `relay` routing plus link lifecycle; the
two join by `req_id`. Scripts, file contents and stdout are never logged.
Details and the threat model: [docs/audit-log.md](docs/audit-log.md).

## Tools

| Tool | Does |
| --- | --- |
| `sys_info` | hostname, OS, load, memory, uptime |
| `exec` | run argv to completion, no shell |
| `exec_shell` | run a script via `bash`/`sh`/`fish`/`zsh`, or `cmd`/`powershell` on Windows |
| `exec_start` | start a long-running process as a session |
| `exec_poll` | read session output from byte offsets |
| `exec_wait` | block until the session exits or `timeout` (default 30 s, max 300 s) |
| `exec_write` | write base64 bytes to stdin; `eof=true` closes it |
| `exec_kill` | kill the session's process tree |
| `exec_close` | free the session; idempotent |
| `exec_list` | list live sessions |
| `read_file` | read UTF-8 text with offset/limit |
| `write_file` | write base64 content, create parent dirs, return SHA-256 |
| `list_dir` | list entries with type, size, mtime |

Full schemas via `tools/list`. `exec` and `exec_shell` timeouts default to 120 s, clamped to 1–1800 s.

## Clients

Every client below uses the same URL and token. `Authorization: Bearer <token>` works everywhere; `X-Node-Token: <token>` is accepted for clients that can't set `Authorization`.

Cursor (`.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "mcp-node": {
      "url": "http://127.0.0.1:8341/mcp",
      "headers": { "Authorization": "Bearer <token>" }
    }
  }
}
```

VS Code (`.vscode/mcp.json`):

```json
{
  "servers": {
    "mcp-node": {
      "type": "http",
      "url": "http://127.0.0.1:8341/mcp",
      "headers": { "Authorization": "Bearer <token>" }
    }
  }
}
```

Codex (`~/.codex/config.toml`):

```toml
[mcp_servers.mcp-node]
url = "http://127.0.0.1:8341/mcp"
http_headers = { "Authorization" = "Bearer <token>" }
```

Claude Desktop and other JSON clients: same as Cursor, plus `"type": "http"`.

Clients that only speak stdio: run the node itself with `--stdio` (see [stdio mode](#stdio-mode)), or bridge to a remote node over HTTP with `npx mcp-remote http://127.0.0.1:8341/mcp --header "Authorization: Bearer <token>"`

## Security

- **Token required.** The server refuses to start with a missing or empty token file. Comparison is constant-time.
- **Loopback by default.** It binds `127.0.0.1`. To expose it, set `MCP_NODE_HOST` and add the `host:port` clients use to `MCP_NODE_ALLOWED_HOSTS`.
- **Host and Origin checked** before the body is parsed: unknown Host gets 421, unknown Origin gets 403.
- **No built-in TLS server.** Put it behind a reverse proxy, tunnel or VPN, for example `caddy reverse-proxy --from node.example.com --to 127.0.0.1:8341`.
- **The token is a shell as the user the node runs as.** Run it under an account scoped to what the agent should touch.

## Security model

- **Whoever holds the client token runs commands.** On a plain node that means the node; on a hub the token reaches every connected node, so treat the hub token as the sum of them.
- **The hub sees everything.** TLS ends on it (or in front of it), so it handles every request and response in plaintext, and a hub that holds a node's secret can run anything on that node.
- **A node secret is a shell on that node and owns its name.** With `name:secret` lines each name has its own secret; a single shared secret lets any holder connect under any name, including one not yet taken.
- **The handshake authenticates, it does not protect the link.** Hub and node prove the secret with HMAC-SHA256 over fresh nonces, but later frames are neither encrypted nor integrity-protected: over plain TCP an active relay can read and change them.
- **Use TLS across anything you don't control.** `MCP_NODE_CONNECT_TLS=1` makes the node verify the certificate chain and server name, with no switch to turn that off. A binary built with `-Dtls-server` serves TLS on the hub's link port itself (see [Reverse connect](#reverse-connect-no-inbound-ports)); otherwise terminate TLS in front of that port and keep it on loopback.
- **Plain TCP links are for the same host or a trusted LAN.**
- **Handshake limits are per source address.** The hub runs at most 16 unauthenticated handshakes in total and 4 from one IPv4 address or IPv6 /64; 8 failed handshakes within a minute block that source for a minute. 127.0.0.1 and ::1 are exempt, so behind a local TLS terminator every peer looks the same: set per-IP limits there (nginx `limit_conn`) and firewall the public port to known sources where you can. With the built-in TLS server the hub sees the real peer address, so these limits work fully.
- **Out of scope:** per-tool or per-path permissions, sandboxing, and a compromised hub or node host. The node runs with the full rights of its OS user. (The audit log detects record tampering; it cannot defend against an attacker who controls the host.)

## Configuration

Environment variables only.

| Variable | Default |
| --- | --- |
| `MCP_NODE_HOST` | `127.0.0.1` (IP literal) |
| `MCP_NODE_PORT` | `8341` |
| `MCP_NODE_TOKEN_FILE` | `./token` |
| `MCP_NODE_ALLOWED_HOSTS` | `127.0.0.1:*,localhost:*,[::1]:*` |
| `MCP_NODE_ALLOWED_ORIGINS` | `http://127.0.0.1:*,http://localhost:*,http://[::1]:*` |
| `MCP_NODE_NAME` | `mcp-node` (serverInfo name) |
| `MCP_NODE_MAX_OUT` | `400000` bytes per output stream, then `truncated_*` |
| `MCP_NODE_MAX_CONN` | `128` concurrent connections, then 503 |
| `MCP_NODE_MAX_SESSIONS` | `64` live sessions |
| `MCP_NODE_SESSION_TTL_S` | `600`, reap delay for finished sessions |
| `MCP_NODE_SOCKET_TIMEOUT_S` | `60` |
| `MCP_NODE_MAX_INFLIGHT_BYTES` | `67108864`, total in-flight request bodies |
| `MCP_NODE_TEXT_MIRROR` | `1`; `0` returns `structuredContent` only, halving response size |
| `MCP_NODE_INSECURE` | unset; `1` allows an empty token (avoid) |
| `MCP_NODE_STDIO` | unset; `1` serves one client over stdin/stdout, no listener (same as `--stdio`) |
| `MCP_NODE_AUDIT_FILE` | unset; enables the [audit log](docs/audit-log.md) at this path |
| `MCP_NODE_AUDIT_KEY_FILE` | unset; HMAC key for the audit chain (0600), separate from token and link secret |
| `MCP_NODE_AUDIT_ARGS` | `summary`; `full` logs full argv and paths, never contents |
| `MCP_NODE_AUDIT_ON_FULL` | `block`; `drop` sheds records under a stuck disk with a chained `dropped` marker |
| `MCP_NODE_AUDIT_MAX_BYTES` | `67108864`; past this the file rotates to `<file>.<first-seq>` and the chain continues |

`mcp-node --version` prints the version, `--help` the flags; any other
argument than these, `--connect` and `--stdio` is an error. The one
subcommand is `mcp-node audit-verify [--anchor] <file>...`, which checks an
audit log chain offline.

Reverse-connect variables (`MCP_NODE_CONNECT*`, `MCP_NODE_HUB_*`) are listed in
[docs/reverse-connect.md](docs/reverse-connect.md).

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| 401 | Wrong or missing token. If you send both headers, they must match. |
| 421 | Add the `host:port` you connect through to `MCP_NODE_ALLOWED_HOSTS`. |
| 403 | Browser `Origin` not in `MCP_NODE_ALLOWED_ORIGINS`. |
| 415 | Send `Content-Type: application/json`. |
| Connection refused | Check `MCP_NODE_HOST`/`MCP_NODE_PORT`; loopback isn't reachable from other machines. |
| Exits at startup | Create a non-empty token file. |

## Limitations

Plain HTTP only, no PTY (interactive TUIs won't work). Both are on the roadmap. The API is `0.1.x` and may change.

## Build from source

Requires Zig 0.16.

```sh
git clone https://github.com/alexchen-sys/mcp-node-zig
cd mcp-node-zig
zig build test
zig build -Doptimize=ReleaseSafe   # → zig-out/bin/mcp-node
```

On Linux the binary is static with no libc. macOS links only libSystem; Windows only kernel32/ntdll.

## License

MIT
