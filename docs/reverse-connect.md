# Reverse connect

A machine behind NAT, CGNAT or a firewall, or a Windows box without sshd, can
still be reached: the node dials **out** to a hub, and MCP clients talk to the
hub. The node opens no listening port. The same binary plays both roles.

```
MCP client --HTTP+token--> hub :8341  /n/<name>/mcp
                           hub :8400  <--outbound link-- node (behind NAT)
```

## Quickstart

On the hub (a host the node can reach):

```sh
printf '%s' "$(openssl rand -hex 32)" > token          # client token, as before
printf 'laptop:%s\n' "$(openssl rand -hex 32)" > nodes  # one line per node
MCP_NODE_HUB_LISTEN=0.0.0.0:8400 MCP_NODE_HUB_SECRET_FILE=nodes ./mcp-node
```

On the node (`secret` holds only the part after `laptop:`):

```sh
MCP_NODE_NAME=laptop MCP_NODE_CONNECT_SECRET_FILE=secret \
  ./mcp-node --connect hub.example.com:8400
```

Clients point at `http://127.0.0.1:8341/n/laptop/mcp` with the usual token.
`POST /n` lists connected nodes (`name`, `connected_s`, `inflight`).

## Configuration

| Variable | Role | Meaning |
| --- | --- | --- |
| `MCP_NODE_CONNECT` / `--connect` | node | `host:port` of the hub link port |
| `MCP_NODE_NAME` | node | node name, `[A-Za-z0-9._-]{1,64}` |
| `MCP_NODE_CONNECT_SECRET_FILE` | node | file with this node's secret |
| `MCP_NODE_CONNECT_TLS` | node | `1` wraps the link in TLS (see below) |
| `MCP_NODE_CONNECT_CA_FILE` | node | PEM bundle to trust; default: system store |
| `MCP_NODE_CONNECT_SERVER_NAME` | node | name to verify; default: host part of connect |
| `MCP_NODE_HUB_LISTEN` | hub | `ip:port` for node links |
| `MCP_NODE_HUB_SECRET_FILE` | hub | one shared secret, or `name:secret` lines |

Connect and hub modes are mutually exclusive. A node needs no client token
file: it never accepts connections. With neither variable set, the binary
behaves exactly as before and serves only `/mcp`.

A single-line secret file without `:` is a shared secret for any node name.
With `name:secret` lines, only listed names may connect, each with its own
secret; prefer this. In single-secret mode every holder of the secret can
connect under any name, and can hold a name before its owner does, so use
`name:secret` lines as soon as there is more than one node.

## Protocol

One long-lived TCP (or TLS) connection per node carries length-prefixed frames:
`u32 length (big endian) | u8 type | u32 stream id | payload`. Types:
CHALLENGE, HELLO, WELCOME, REQ, RESP, PING, PONG, GOAWAY.

The handshake is mutual: each side proves it holds the secret, over both
sides' fresh nonces.

1. The hub sends CHALLENGE with a 32-byte random `hub_nonce`.
2. The node draws its own 32-byte `node_nonce` and answers HELLO
   `{"v":1,"name":..,"nonce":hex(node_nonce),"auth":..}` with
   `HMAC-SHA256(secret, "mcp-node-reverse-v1 node" | hub_nonce | node_nonce | name)`.
3. The hub checks the MAC in constant time and replies GOAWAY, or WELCOME
   `{"v":1,"auth":..}` with
   `HMAC-SHA256(secret, "mcp-node-reverse-v1 hub" | hub_nonce | node_nonce | name)`.
   An unknown name and a wrong MAC get the same answer and the same work.
   HELLO must arrive within 10 s; at most 16 handshakes run at once.
4. The node checks the WELCOME MAC in constant time before it accepts any
   other frame. A missing or wrong MAC, or any other frame first, ends the
   link with "hub authentication failed" and the node backs off and redials.

Nonces are fixed-length and the name comes last, so the MAC input is
unambiguous; the distinct `node`/`hub` labels stop a proof from being
reflected back as the other side's.

Each client request becomes a REQ with a fresh stream id; the node runs it
through the same JSON-RPC handler as `/mcp` and answers RESP with that id, so
many requests share one link concurrently. The node bounds parallel work by
`MCP_NODE_MAX_CONN` and `MCP_NODE_MAX_INFLIGHT_BYTES`.

Both sides PING every 15 s; 45 s of silence drops the link. The node
reconnects with full-jitter backoff from 0.5 s up to 30 s, reset after 60 s of
healthy link. A new HELLO with an already connected name first probes the old
link with a PING. If it answers within 3 s, the newcomer gets GOAWAY `name in
use by a live link` and retries at its backoff; both sides log it. If it stays
silent (crashed node, half-open TCP), the new link replaces it at once.

## Failure behaviour

| Event | Client sees |
| --- | --- |
| Unknown node name | 404 `unknown_node` |
| Link drops while a request is in flight | 502 `node_disconnected` |
| No response before the deadline | 504 `node_timeout` |
| Hub restart | requests fail until the node redials (seconds) |
| Node restart | the dead link is replaced; sessions on the node are gone |
| Second live node under one name | it is refused, the first keeps the name |

`exec_start` sessions live in the node, not the hub. They survive a hub
restart or link drop and can be polled with the same `session_id` once the
node has reconnected. A request in flight at the moment of the drop is lost;
its outcome is unknown to the client, so retry only idempotent calls. Sessions
do not survive a node restart.

## Security

- The hub client surface is unchanged: token, Host and Origin checks, loopback
  by default. Keep `MCP_NODE_HOST` on loopback or behind your own access
  control; anyone with the client token reaches every connected node.
- Node and hub prove the secret to each other with keyed MACs over fresh
  nonces from both sides: a recorded handshake cannot be replayed, and a hub
  without the secret (a spoofed address, a hijacked DNS name) is refused
  before it can send a single request.
- The handshake does **not** encrypt or integrity-protect the frames that
  follow. Over plain TCP, an active relay on the path can pass the handshake
  through between two genuine endpoints and then read and alter traffic.
  Mutual authentication stops impersonation without the secret, not that
  relay. Across untrusted networks use TLS (`MCP_NODE_CONNECT_TLS=1`).
- `MCP_NODE_CONNECT_TLS=1` makes the node a TLS client (Zig std TLS 1.2/1.3)
  that always verifies the certificate chain and server name; there is no
  insecure switch. The hub has no TLS server of its own: terminate TLS in front
  of the link port, for example with stunnel, HAProxy or nginx `stream`.
- Beyond the secret (and the certificate, with TLS) there is no further
  identity check. A secret is a shell on that node; store it with `0600`
  permissions.

## Limits

- The hub keeps at most 16 unauthenticated handshakes at once; further
  connections are closed at once. If the link port is reachable from the
  internet, firewall it to known sources.
- Each link has one write lock, so a large response delays the other
  frames on the same link until it is written.
- A relayed request waits for its node up to max(socket timeout, 1 h).
- Control frames are capped: PING, PONG and CHALLENGE at 64 bytes,
  WELCOME and GOAWAY at 256 bytes. A larger frame drops the link.
- On a TLS link the node does not answer a TLS 1.3 KeyUpdate request with
  its own KeyUpdate (std limitation). A terminator that insists on one may
  drop the link; the node then reconnects.

## What it deliberately does not do

- No TLS server in the hub, no own cryptography beyond std HMAC and TLS.
- No hub clustering, persistence or request replay.
- No streaming of partial output across the link; each RPC is one request and
  one response, as on `/mcp`.
- No node-to-node routing; clients only reach nodes through the hub.

## Cost

Measured on x86_64 Linux, ReleaseSafe:

- binary: 4.62 MB before this feature, 8.62 MB with the link, hub and TLS
  client (+4.0 MB, almost all of it std TLS and X.509 parsing; the link and
  hub alone added about 0.6 MB);
- idle RSS after 6 s: plain node 0.5 MB, hub with one node 1.0 MB, plain
  listen mode 0.5 MB (512 kB before this feature, 520 kB after); threads:
  hub 4, node 2, listen 1.
