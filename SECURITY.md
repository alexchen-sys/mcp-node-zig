# Security Policy

mcp-node is, by design, a remote execution daemon: whoever holds the token can
run arbitrary commands on the host. Take the deployment notes below seriously —
most real-world risk comes from exposure, not from the code.

## Supported Versions

| Version        | Supported          |
| -------------- | ------------------ |
| latest release | :white_check_mark: |
| older releases | :x:                |

Security fixes land on `main` and are tagged as a new patch/minor release. Only
the most recent release line receives fixes; there is no LTS.

## Reporting a Vulnerability

Please report vulnerabilities privately — do **not** open a public issue.

- Preferred: GitHub private vulnerability reporting (Security tab → "Report a
  vulnerability"), enabled on the public repository. This opens a private
  advisory where we can coordinate a fix and disclosure.
- Always available: email `l46983284@gmail.com` with the subject
  `mcp-node security`.

Include the affected version/commit, a reproduction (curl or tool call), and
your impact assessment. This is a solo-maintainer project: expect an
acknowledgement within a few days and a best-effort fix timeline — there is no
formal SLA.

## Scope

In scope:

- Authentication bypass (reaching any tool without a valid token)
- `Host` / `Origin` allowlist bypass
- HTTP request-smuggling or desync (e.g. `Content-Length` confusion) in the
  built-in HTTP/1.1 layer
- Breaking the documented resource caps (`MCP_NODE_MAX_OUT`,
  `MCP_NODE_MAX_CONN`, `MCP_NODE_MAX_SESSIONS`, request size limit) in a way
  that yields memory/FD exhaustion beyond configured bounds
- Cross-session isolation breaks (one exec session reading or killing another
  session's state without its id)

Out of scope (documented trust model):

- "A token holder can execute commands / read files / write files anywhere" —
  that is the product. `read_file`/`write_file` are deliberately not jailed.
- Token theft from the operator's own infrastructure
- DoS caused by an authenticated caller within configured limits
- `MCP_NODE_INSECURE=1` deployments (the flag opts out of the token requirement
  on purpose)

## Deployment guidance

- Bind to `127.0.0.1` (default) or to a VPN/management interface; if you must
  expose it beyond localhost, put it behind a TLS-terminating reverse proxy —
  the built-in HTTP layer is plaintext.
- Keep the token file at mode `0600`; rotate it on any suspicion of exposure.
- Keep `MCP_NODE_ALLOWED_HOSTS` / `MCP_NODE_ALLOWED_ORIGINS` at their tight
  defaults unless you have a concrete reason to widen them.
- Run under a dedicated user with least privilege; the daemon does not need
  root for its own operation.
