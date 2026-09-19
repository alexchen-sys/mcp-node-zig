# mcp-node-zig

A tiny, self-contained MCP node for remote machine operations, written in Zig.

It exposes a single streamable-HTTP JSON-RPC endpoint (`POST /mcp`) with six practical tools:

- `sys_info` — hostname, OS, load, memory, uptime
- `exec` — run an argv array directly, with no shell layer
- `exec_shell` — run one script through `bash`/`sh`/`fish`/`zsh -c`
- `read_file` — UTF-8 text read with replacement, character offset/limit
- `write_file` — base64 write with mkdirs and SHA-256 receipt
- `list_dir` — directory listing with type/size/mtime

The design goal is a small trusted edge agent: static binary, explicit token auth, explicit Host allowlist, no framework sprawl.

## Status

Early `0.1.0`. The contract is intentionally narrow: a fixed tool set, explicit auth, and no framework dependencies.

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
- `MCP_NODE_ALLOWED_ORIGINS` — comma list reserved for future Origin checks
- `MCP_NODE_MAX_OUT` — per-stream stdout/stderr cap, default `400000`
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

## Security notes

- Missing token fails closed unless `MCP_NODE_INSECURE=1` is set.
- `Host` is validated before JSON parsing; unknown hosts get HTTP 421.
- `exec` does not pass through a shell; shell metacharacters are data.
- `exec_shell` is intentionally one explicit shell layer for pipelines and redirects.
- `write_file` returns a SHA-256 digest for verification.

## License

MIT
