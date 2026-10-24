# mcp-node-zig

[![CI](https://github.com/alexchen-sys/mcp-node-zig/actions/workflows/ci.yml/badge.svg)](https://github.com/alexchen-sys/mcp-node-zig/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/alexchen-sys/mcp-node-zig)](https://github.com/alexchen-sys/mcp-node-zig/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

English | [Русский](README.ru.md) | [中文](README.zh.md)

Your servers call home. Your agent gets a structured shell on any machine, even behind NAT; you keep the keys, the perimeter and the kill switch.

![mcp-node-zig: cold start, an exec round-trip and a live session listing against a local node (v0.5.0)](assets/demo.gif)

mcp-node-zig is one static binary that speaks MCP. Put it on a machine and your agent can run commands, drive long-running sessions and read or write files there. The node dials out to a hub you run (the same binary), so the machine opens no inbound ports, no SSH key ever reaches the agent, and no third-party cloud sits in the path. The link is mutually authenticated with HMAC-SHA256 and runs over TLS, the hub rate-limits handshakes per source, and every tool call can land in a tamper-evident audit log.

**2.0 ms** cold start · **1.2 ms** p50 exec round-trip · **1.57 MiB** idle RSS · **9.6 MiB** binary ([benchmarks](BENCHMARKS.md))

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/alexchen-sys/mcp-node-zig/main/install.sh | sh
```

The script detects the platform, downloads the latest release, verifies it against `SHA256SUMS.txt` and installs to `/usr/local/bin` (or `~/.local/bin`). For a hub with the built-in TLS server, add `MCP_NODE_FLAVOR=tls` (Linux and macOS releases). Pin a version with `MCP_NODE_VERSION=0.5.0`, change the target directory with `PREFIX=/some/dir`.

Manual install, Linux x86_64:

```sh
curl -L https://github.com/alexchen-sys/mcp-node-zig/releases/download/v0.5.0/mcp-node-v0.5.0-x86_64-linux.tar.gz | tar xz
```

Other targets on the [releases page](https://github.com/alexchen-sys/mcp-node-zig/releases): `aarch64-linux`, `aarch64-macos`, `x86_64-windows`. Each release ships `SHA256SUMS.txt`, signed with [cosign](https://github.com/sigstore/cosign) keyless (Sigstore); `install.sh` verifies the signature when cosign is on your PATH.

## Quickstart

```sh
openssl rand -hex 32 > token
./mcp-node-v0.5.0-x86_64-linux/mcp-node &

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
curl.exe -L -o mcp-node.zip https://github.com/alexchen-sys/mcp-node-zig/releases/download/v0.5.0/mcp-node-v0.5.0-x86_64-windows.zip
Expand-Archive mcp-node.zip
[guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N') | Set-Content -NoNewline -Encoding Ascii token
.\mcp-node-v0.5.0-x86_64-windows\mcp-node.exe
```

From a second window:

```powershell
Invoke-RestMethod -Uri http://127.0.0.1:8341/mcp -Method Post -ContentType "application/json" `
  -Headers @{ "X-Node-Token" = (Get-Content token) } `
  -Body '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"sys_info","arguments":{}}}'
```

</details>

## Why

- **Keys stay with you.** The agent holds a token for the node, never an SSH key. Stop the node and access is gone; rotate the token and every old copy stops working.
- **Nothing to provision.** No Node, no Python, no OpenSSH, no keys to distribute. Copy one file and run it.
- **Processes outlive requests.** Start a build, disconnect, come back and read the output by offset.
- **Cheap to keep running.** 1.57 MiB idle. Each extra connected agent adds about 304 KiB, not a second ~100–150 MiB server process.
- **No shell unless you ask.** `exec` passes argv verbatim. `exec_shell` is the one explicit shell layer.
- **Kills the whole tree.** Process groups on POSIX, Job Objects on Windows. No orphaned children holding pipes.
- **Every call on the record.** Turn on the audit log and each tool call leaves an HMAC-chained JSONL line that `audit-verify` checks offline.
- **Linux, macOS, Windows.** All three are built and smoke-tested in CI on every push.

## How is this different from SSH?

They solve different problems, and they work well together.

SSH is a secure transport and a terminal for people. It has encryption, key management, agent forwarding, PTYs, scp/sftp/rsync and decades of hardening. Keep using it for all of that.

mcp-node is an execution API for agents. Through SSH, an agent gets one string that a remote shell parses again, plus raw bytes and an exit status. Here it gets:

- **argv without a shell.** No second round of quoting for a remote shell to reparse. A shell is used only when you ask for `exec_shell`.
- **Structured results.** `stdout`, `stderr`, `exit_code`, `truncated_*` and timings as JSON, with per-call timeouts.
- **Sessions that outlive the request.** `exec_start`, then `exec_poll` by byte offset, `exec_write` to stdin, `exec_wait` up to 300 s, `exec_kill` for the whole tree. A dropped connection doesn't kill the build.
- **Verified file writes.** `write_file` takes plain text or base64 and returns the SHA-256 of what landed on disk.
- **A self-describing interface.** Any MCP client discovers the tools from `tools/list`; nothing to teach the agent.

For remote machines, [reverse connect](#reverse-connect-no-inbound-ports) replaces the tunnel: no sshd on the target and no key in the agent's hands. Where SSH is already in place, the two pair up: the node listens on `127.0.0.1` and you forward the port (`ssh -L 8341:127.0.0.1:8341 host`).

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

The `-tls` release build (or any binary built with `-Dtls-server`) can serve TLS on the link port itself
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
any non-durable sessions still running (durable sessions are exactly the
opt-in exception: they detach and survive, see
[Durable sessions](#durable-sessions)).

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
| `exec` | run argv to completion, no shell; `max_bytes`/`head_lines`/`tail_lines` shape long output |
| `exec_shell` | run a script via `bash`/`sh`/`fish`/`zsh`, or `cmd`/`powershell` on Windows; same shaping as `exec` |
| `exec_start` | start a long-running process as a session |
| `exec_poll` | read session output from byte offsets, `max_bytes` pages |
| `exec_wait` | block until the session exits or `timeout` (default 30 s, max 300 s) |
| `exec_write` | write base64 bytes to stdin; `eof=true` closes it |
| `exec_kill` | kill the session's process tree |
| `exec_close` | free the session; idempotent |
| `exec_list` | list live sessions |
| `read_file` | read UTF-8 text with offset/limit or `line_offset`/`line_limit` line windows |
| `write_file` | write plain text (`content`) or base64 (`content_b64`), create parent dirs, return SHA-256 |
| `list_dir` | list entries with type, size, mtime |
| `copy_path` | copy a file or directory tree to an exact new destination; staged and atomically published, never overwrites |

Full schemas via `tools/list`. `exec` and `exec_shell` timeouts default to 120 s, clamped to 1–1800 s.

## Durable sessions

Exec sessions live in the node process, not in any connection. A session
survives a hub<->node link drop, a hub restart and any client disconnect:
capture keeps running while nobody polls, and after a reconnect the same
`session_id` continues from the byte offsets of your last reply (no gaps,
no duplicates). `exec_list` recovers ids when a reply was lost.

By default, sessions live in memory (`unknown_session` after a node process
restart such as a crash, OOM kill or reboot). Output per stream is capped at `MCP_NODE_MAX_OUT`
bytes; once the cap is hit the head is kept, `truncated_*` is set,
and `lost_*_bytes` reports how many subsequent bytes were dropped.
Finished sessions are reaped `MCP_NODE_SESSION_TTL_S` after completion;
running sessions are not reaped by time.

### Opt-in disk durability (`durable: true`)

With `MCP_NODE_STATE_DIR` (or `--state-dir`) configured, `exec_start` accepts
`"durable": true`: the child's stdout/stderr are appended to per-session log
files on disk from the moment of spawn, and the session record commits before
the child starts writing. After a node restart the node recovers the session:
`exec_poll` on the same id returns `recovered: true` with byte-exact deltas
from your offsets, and `exec_kill` continues to work because every signal is gated on a
verified process identity (PID + start-time + boot id). The leader is
signaled through pidfd, which cannot target a recycled PID. A narrow race
remains if a process group is torn down and its ID is recreated between the
identity check and the group signal.

Data at rest: `argv`, `cwd` and the full stdout/stderr logs persist in
**plaintext** under the state dir (treat it like shell history when commands may output secrets).
It stays on the local disk and requires `0700` permissions.

Recovered sessions report degraded capabilities explicitly in their status fields:
`stdin_available: false` (`exec_write` returns `StdinUnavailable`), and when
an orphaned child exited while the node was down, `exit_code` is `null`
with `completion_reason: "orphaned_exit"`. Records bound to another
token remain isolated by owner hash. Owner binding applies to
policy-token identities; with no policy configured every request shares the
default zero owner. A durable session closed
or reaped returns `unknown_session` with `expired: true` for a bounded
recency window. `durable: true` without a state dir is refused as
`DurabilityDisabled`; the state dir itself must be private (`0700`) and is
locked against concurrent node processes (`StateDirLocked`). `MCP_NODE_STATE_MAX_BYTES`
(default 64 MiB) caps total local state storage. In v0.5.0 durable sessions are Linux-only; other
platforms return `DurabilityUnsupported`.

An unknown or expired `session_id` returns
`{"ok": false, "error": "unknown_session", "session_id": ..., "expired": ..., "message": ...}`
as a structured tool result (`isError: true`) rather than a protocol-level JSON-RPC `-32602`. `expired: true`
means this node recently held the session and closed, reaped or evicted
it (a bounded recency window: ids removed long ago are forgotten and
answer `expired: false`, as do ids this node never had or that pre-date a
node restart; the message says so). `exec_close` keeps its idempotent
`{"ok": true, "already_closed": true}` for the same case.

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
- **Per-token argument gating (optional).** `MCP_NODE_POLICY_FILE` constrains what each client token may do at the argument level: argv[0] allowlists, path prefixes for reads/writes/cwd, timeout and write-mode caps, token-owned sessions. See [argument gating](docs/arg-gating.md).
- **Loopback by default.** It binds `127.0.0.1`. To expose it, set `MCP_NODE_HOST` and add the `host:port` clients use to `MCP_NODE_ALLOWED_HOSTS`.
- **Host and Origin checked** before the body is parsed: unknown Host gets 421, unknown Origin gets 403.
- **TLS on the wire.** The node link runs over TLS, served by the hub itself in a `-Dtls-server` build or by any terminator. The local HTTP API stays on loopback; to expose it, front it with a reverse proxy, tunnel or VPN, for example `caddy reverse-proxy --from node.example.com --to 127.0.0.1:8341`.
- **The token is a shell as the user the node runs as.** Run it under an account scoped to what the agent should touch.

## Security model

- **Whoever holds the client token runs commands.** On a plain node that means the node; on a hub the token reaches every connected node, so treat the hub token as the sum of them.
- **The hub sees everything.** TLS ends on it (or in front of it), so it handles every request and response in plaintext, and a hub that holds a node's secret can run anything on that node.
- **A node secret is a shell on that node and owns its name.** With `name:secret` lines each name has its own secret; a single shared secret lets any holder connect under any name, including one not yet taken.
- **The handshake authenticates, and every later frame is tagged.** Hub and node prove the secret with HMAC-SHA256 over fresh nonces, and post-handshake frames carry per-direction HMAC-SHA256 tags with strict sequence numbers, so an active relay cannot forge, reorder, or replay them. Plain TCP frames are still not encrypted: a relay can read (not change) them.
- **Use TLS across anything you don't control.** `MCP_NODE_CONNECT_TLS=1` makes the node verify the certificate chain and server name, with no switch to turn that off. A binary built with `-Dtls-server` serves TLS on the hub's link port itself (see [Reverse connect](#reverse-connect-no-inbound-ports)); otherwise terminate TLS in front of that port and keep it on loopback.
- **Plain TCP links are for the same host or a trusted LAN.**
- **Handshake limits are per source address.** The hub runs at most 16 unauthenticated handshakes in total and 4 from one IPv4 address or IPv6 /64; 8 failed handshakes within a minute block that source for a minute. 127.0.0.1 and ::1 are exempt, so behind a local TLS terminator every peer looks the same: set per-IP limits there (nginx `limit_conn`) and firewall the public port to known sources where you can. With the built-in TLS server the hub sees the real peer address, so these limits work fully.
- **Scopes are opt-in, not a sandbox.** Without `MCP_NODE_POLICY_FILE` every token can call every tool; with it, each token gets its own tool list and argument limits ([argument gating](docs/arg-gating.md)). An allowed interpreter is still arbitrary code.
- **Out of scope:** sandboxing and a compromised hub or node host. The node runs with the full rights of its OS user. (The audit log detects record tampering; it cannot defend against an attacker who controls the host.)

## Token permissions

`MCP_NODE_POLICY_FILE` turns one shared token into a set of tokens, each
with its own tool list and argument boundaries:

```json
{
  "version": 1,
  "tokens": [
    {
      "file": "/etc/mcp-node/tokens/build",
      "tools": ["sys_info", "exec", "read_file", "list_dir"],
      "exec_argv0": ["/usr/bin/git", "/usr/bin/make"],
      "exec_cwd": ["/srv/build"],
      "max_timeout_s": 120,
      "read_paths": ["/srv/build"],
      "read_deny": ["/srv/build/keys"]
    },
    {"file": "/etc/mcp-node/tokens/admin", "allow_all": true}
  ]
}
```

The node checks every call before anything runs: a denied `exec` never
starts, a denied write never opens the file. Policy bounds argv[0], `cwd`,
read and write paths, the timeout ceiling and the mode of created files.
Paths are canonicalized (symlinks, `..`) and compared per whole segment.
Sessions belong to the token that opened them. A denial comes back as
`{"ok": false, "error": "PolicyDenied", "reason": ...}` and lands in the
audit log as a `policy.deny` event. Token values never appear in the
policy or the log.

Without the variable the node behaves as before. With a policy set, the
node's own token (`MCP_NODE_TOKEN_FILE`) must itself be one of the
`tokens[].file` entries; the node refuses to start with `InvalidConfig`
otherwise. The parser is strict: an
unknown key or a contradiction stops startup. A hub does not take a
policy, because the `/n/<name>/mcp` route forwards bodies to nodes
verbatim; policy lives on each node. An allowed interpreter (`python3`,
`bash`) still means arbitrary code. Details and limits:
[docs/arg-gating.md](docs/arg-gating.md).

## Configuration

Environment variables, plus two command-line flags: `--connect` (reverse
connect target) and `--state-dir` (durable session journal; same as
`MCP_NODE_STATE_DIR`, the flag wins).

| Variable | Default |
| --- | --- |
| `MCP_NODE_STATE_DIR` | unset; when set (or `--state-dir` given), `exec_start` accepts `durable:true` and sessions survive a node restart. The directory must be private (`0700`), node-owned, and is locked for the node's lifetime |
| `MCP_NODE_STATE_MAX_BYTES` | `67108864` (64 MiB); aggregate admission budget for durable sessions (per-session reservation: 2 x output cap + 80 KiB; the node checks spool sizes on every refresh and on a 1 Hz sweep, and a session whose combined logs outgrow the reservation is killed with a verified identity and answers `completion_reason: "output_cap"`. The cap is best-effort: a writer can overshoot between checks, and output written while the node is down is reconciled, not prevented, at the next start) |
| `MCP_NODE_HOST` | `127.0.0.1` (IP literal) |
| `MCP_NODE_PORT` | `8341` |
| `MCP_NODE_TOKEN_FILE` | `./token` |
| `MCP_NODE_POLICY_FILE` | unset (no argument gating; see [docs/arg-gating.md](docs/arg-gating.md)) |
| `MCP_NODE_ALLOWED_HOSTS` | `127.0.0.1:*,localhost:*,[::1]:*` |
| `MCP_NODE_ALLOWED_ORIGINS` | `http://127.0.0.1:*,http://localhost:*,http://[::1]:*` |
| `MCP_NODE_NAME` | `mcp-node` (serverInfo name) |
| `MCP_NODE_MAX_OUT` | `400000` bytes per output stream, then `truncated_*` + `lost_*_bytes` |
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
| `MCP_NODE_AUDIT_MAX_BYTES` | `67108864`; past this the file rotates to `<file>.<chain-gen>.<first-seq>` (never replacing an existing file) and the chain continues |

`mcp-node --version` prints the version, `--help` the flags; any other
argument than these, `--connect`, `--stdio` and `--state-dir` is an error. The one
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

## Roadmap

Shipped: reverse connect with a mutual HMAC handshake plus authenticated, sequence-checked frames, TLS on the node link (every platform), per-source handshake limits, the tamper-evident audit log, per-token tool and argument scopes, exec sessions that survive a dropped link or hub restart, durable exec sessions that survive a node restart (opt-in, Linux), cosign-signed releases with build provenance.

Next: per-node keypairs instead of shared secrets, durable sessions on macOS/Windows, and a PTY for interactive TUIs. The API is `0.x` and may still change before 1.0.

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

MIT. The node, the hub, scopes and the audit log stay MIT for good; if a paid offering ever appears, it will be a hosted control plane, not features taken out of this binary.
