# Security Policy

mcp-node runs commands for whoever holds the token. Treat the token like a root password.

## Reporting

Please don't open a public issue. Report privately:

- GitHub: Security tab → **Report a vulnerability**
- Email: `l46983284@gmail.com`, subject `mcp-node security`

Include the version or commit, steps to reproduce, and the impact.

You'll get a reply within a few days. Fixes ship as a new patch release.

## Supported versions

Only the latest release gets security fixes.

## Scope

In scope:

- Reaching any tool without a valid token
- Bypassing the `Host` or `Origin` allowlist
- Request smuggling or desync in the HTTP layer
- Exceeding the configured resource caps (output, connections, sessions, request size)
- One session reading or killing another without its id

Out of scope:

- A token holder running commands or reading and writing any file. That's the product.
- DoS by an authenticated caller within configured limits
- Token theft from your own infrastructure
- Deployments with `MCP_NODE_INSECURE=1`

## Deploying safely

- Keep the default `127.0.0.1` bind. For remote access, put TLS in front or use a VPN. The built-in HTTP is plaintext.
- Keep the token file at `0600` and rotate it if exposed.
- Leave `MCP_NODE_ALLOWED_HOSTS` and `MCP_NODE_ALLOWED_ORIGINS` at their defaults unless you need more.
- Run as a dedicated, unprivileged user. Root isn't needed.
