# bench results summary

### Cold start → first MCP response (b01)
spawn -> first MCP response (initialize), full shutdown between runs
| participant | p50 ms | p90 ms | p95 ms | p99 ms | mean ± σ ms | min…max ms | CV% | runs ok |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| mcp-node-zig | 2.0 | 2.4 | 3.0 | 6.7 | 2.1 ± 1.2 | 0.6…63.4 | 59.1 | 10000/10000 |
| tumf/mcp-shell-server | 551.6 | 600.7 | 624.0 | 707.2 | 560.3 ± 46.5 | 487.9…2269.8 | 8.3 | 10000/10000 |
| g0t4/mcp-server-commands | 540.5 | 664.4 | 715.6 | 816.0 | 564.2 ± 93.4 | 463.5…4907.1 | 16.6 | 10000/10000 |
_mcp-node-zig cold-start histogram (ms, [floor, ceil) count): [0, 1) 715; [1, 2) 4861; [2, 4) 4152; [4, 8) 232; [8, 16) 35; [16, 32) 3; [32, 64) 2_
_tumf/mcp-shell-server cold-start histogram (ms, [floor, ceil) count): [256, 512) 150; [512, 1024) 9838; [1024, 2048) 11; [2048, 4096) 1_
_g0t4/mcp-server-commands cold-start histogram (ms, [floor, ceil) count): [256, 512) 2177; [512, 1024) 7805; [1024, 2048) 14; [2048, 4096) 3; [4096, 8192) 1_

#### Cold-start decomposition (b01, http transport)
| participant | boot→listen p50/p90/p99 ms | listen→initialize p50/p90/p99 ms | mean sum ms |
| --- | --- | --- | --- |
| mcp-node-zig | 1.2 / 1.4 / 3.1 | 0.8 / 1.2 / 3.6 | 1.1 + 0.9 |
_stdio participants: spawn→first response is atomic over pipes, no decomposition (bundled in the table above)._
### TLS node-link handshake (b02)
| phase | N ok | failures | p50 ms | p90 ms | p95 ms | p99 ms | min…max ms | mean ± σ ms | CV% |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| TCP connect | 10000 | 0 | 0.1 | 0.2 | 0.2 | 0.4 | 0.1…4.0 | 0.1 ± 0.1 | 87.0 |
| TLS 1.3 handshake | 10000 | 0 | 3.3 | 5.2 | 6.0 | 8.4 | 2.7…144.5 | 3.8 ± 2.5 | 65.2 |
| total (connect+handshake) | 10000 | 0 | 3.4 | 5.3 | 6.1 | 8.6 | 2.8…144.6 | 3.9 ± 2.5 | 63.6 |
| node link established (spawn→registered) | 1000 | 0 | 9.5 | 12.2 | 13.5 | 16.6 | 7.0…29.1 | 10.0 ± 1.9 | 19.2 |
_negotiated: {"TLSv1.3": 10000}; ciphers: {"TLS_CHACHA20_POLY1305_SHA256": 10000}_
_handshake histogram (ms, [floor, ceil) count): [2, 4) 7764; [4, 8) 2115; [8, 16) 93; [16, 32) 17; [32, 64) 9; [64, 128) 1; [128, 256) 1_
### Idle RSS (b03)
| participant | RSS median MiB | RSS max MiB | PSS median MiB | PSS max MiB |
| --- | --- | --- | --- | --- |
| mcp-node-zig | 1.57 | 1.57 | 1.57 | 1.57 |
| tumf/mcp-shell-server | 97.20 | 97.20 | 92.36 | 92.36 |
| g0t4/mcp-server-commands | 133.19 | 133.19 | 79.12 | 79.12 |
### Exec round-trip latency (b05)
| participant | p50 ms | p90 ms | p95 ms | p99 ms | mean ± σ ms | min…max ms | CV% |
| --- | --- | --- | --- | --- | --- | --- | --- |
| mcp-node-zig | 1.2 | 1.8 | 2.2 | 5.2 | 1.4 ± 1.4 | 0.9…77.5 | 96.3 |
| tumf/mcp-shell-server | 5.1 | 8.3 | 9.2 | 11.2 | 5.7 ± 1.8 | 3.1…32.2 | 32.1 |
| g0t4/mcp-server-commands | 2.1 | 4.3 | 5.2 | 7.3 | 2.6 ± 1.4 | 1.4…22.3 | 51.7 |
_mcp-node-zig histogram (ms, [floor, ceil) count): [0, 1) 703; [1, 2) 8641; [2, 4) 510; [4, 8) 85; [8, 16) 48; [16, 32) 11; [32, 64) 1; [64, 128) 1_
_tumf/mcp-shell-server histogram (ms, [floor, ceil) count): [2, 4) 1155; [4, 8) 7690; [8, 16) 1145; [16, 32) 9; [32, 64) 1_
_g0t4/mcp-server-commands histogram (ms, [floor, ceil) count): [1, 2) 4511; [2, 4) 4179; [4, 8) 1241; [8, 16) 62; [16, 32) 7_
### Memory per additional agent (b07)
- mcp-node-zig: base RSS 1916 KiB; ΔRSS per connection ≈ 304.0 KiB over 20 connections; after closing all: 1612 KiB (304 KiB below base)
- tumf/mcp-shell-server: second agent = second process, 126856 KiB tree RSS
- g0t4/mcp-server-commands: second agent = second process, 151400 KiB tree RSS
### Delivery footprint (b08)
| participant | artifact | env MiB | runtime MiB |
| --- | --- | --- | --- |
| mcp-node-zig | one binary 9.6 MiB | 0 | 0 |
| tumf/mcp-shell-server | venv 33.3 MiB | 33.3 (materialized venv) | 99.6 |
| g0t4/mcp-server-commands | npx env 10.0 MiB | 10.0 | 129.2 |

_env is the per-package environment the launch channel materializes (uvx venv / npx cache dir); host-wide shared caches and unrelated global installs are not billed to a participant. runtime is the language interpreter the channel needs (uv-managed CPython; system Node.js = node binary + the npm/corepack the Node.js package ships)._
stand: 2 vCPU Intel Xeon Processor (Cascadelake), ~4 GiB RAM; kernel 6.8.0-147-generic; 2026-10-24T07:55:40Z
