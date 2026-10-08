# bench results summary

### Cold start → first MCP response (b01)
spawn -> first MCP response (initialize), full shutdown between runs
| participant | median ms | p90 ms | p95 ms | p99 ms | mean ± σ ms | min…max ms | CV% | runs ok |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| mcp-node-zig | 2.0 | 2.3 | 2.4 | 3.0 | 2.0 ± 0.3 | 0.7…8.6 | 15.8 (!) | 10000/10000 |
| tumf/mcp-shell-server | 656.4 | 680.7 | 689.2 | 712.7 | 658.2 ± 18.3 | 611.1…804.8 | 2.8 | 10000/10000 |
| g0t4/mcp-server-commands | 504.2 | 541.3 | 554.3 | 580.6 | 509.2 ± 24.3 | 455.7…774.3 | 4.8 | 10000/10000 |

#### Cold-start decomposition (b01, http transport)
| participant | boot→listen p50/p90/p99 ms | listen→initialize p50/p90/p99 ms | mean sum ms |
| --- | --- | --- | --- |
| mcp-node-zig | 1.2 / 1.3 / 1.6 | 0.8 / 1.1 / 1.3 | 1.2 + 0.8 |
_stdio participants: spawn→first response is atomic over pipes, no decomposition (bundled in the table above)._
### TLS node-link handshake (b02)
| phase | N ok | failures | p50 ms | p90 ms | p99 ms | min…max ms | mean ± σ ms |
| --- | --- | --- | --- | --- | --- | --- | --- |
| TCP connect | 10000 | 0 | 0.1 | 0.1 | 0.1 | 0.0…0.6 | 0.1 ± 0.0 |
| TLS 1.3 handshake | 10000 | 0 | 3.1 | 3.8 | 4.6 | 1.7…9.1 | 2.9 ± 0.9 |
| total (connect+handshake) | 10000 | 0 | 3.2 | 3.9 | 4.7 | 1.7…9.1 | 3.0 ± 0.9 |
| node link established (spawn→registered) | 1000 | 0 | 6.6 | 10.4 | 12.1 | 5.4…13.2 | 7.5 ± 1.7 |
_negotiated: {"TLSv1.3": 10000}; ciphers: {"TLS_CHACHA20_POLY1305_SHA256": 10000}_
_handshake histogram (ms, [floor, ceil) count): [1, 2) 2671; [2, 4) 6712; [4, 8) 615; [8, 16) 2_
### Idle RSS (b03)
| participant | RSS median MiB | RSS max MiB | PSS median MiB | PSS max MiB |
| --- | --- | --- | --- | --- |
| mcp-node-zig | 2.30 | 2.30 | 1.87 | 1.87 |
| tumf/mcp-shell-server | 111.84 | 111.84 | 108.54 | 108.54 |
| g0t4/mcp-server-commands | 152.60 | 152.60 | 109.26 | 109.26 |
### Exec round-trip latency (b05)
| participant | p50 ms | p90 ms | p95 ms | p99 ms | mean ± σ ms | min…max ms | CV% |
| --- | --- | --- | --- | --- | --- | --- | --- |
| mcp-node-zig | 1.6 | 2.0 | 2.2 | 2.5 | 1.5 ± 0.4 | 0.8…4.5 | 28.2 (!) |
| tumf/mcp-shell-server | 2.5 | 3.0 | 3.2 | 3.8 | 2.6 ± 0.4 | 2.0…18.6 | 15.1 (!) |
| g0t4/mcp-server-commands | 2.4 | 3.1 | 3.3 | 3.7 | 2.4 ± 0.6 | 1.3…5.9 | 25.1 (!) |
### Memory per additional agent (b07)
- mcp-node-zig: base RSS 2704 KiB; ΔRSS per connection ≈ 192.0 KiB over 20 connections; after closing all: 4800 KiB (still +2096 KiB above base)
- tumf/mcp-shell-server: second agent = second process, 97940 KiB tree RSS
- g0t4/mcp-server-commands: second agent = second process, 159896 KiB tree RSS
### Delivery footprint (b08)
| participant | artifact | env MiB | runtime MiB |
| --- | --- | --- | --- |
| mcp-node-zig | one binary 10.60 MiB | 0 | 0 |
| tumf/mcp-shell-server | venv 28.3 MiB | 122.1 (venv + uv cache) | 0.0 |
| g0t4/mcp-server-commands | npx env 10.2 MiB | 10.2 | 111.9 |
stand: ec3584d1-aec2-4477-b7a7-b8902778ab9a — AMD EPYC 9254 24-Core Processor, 48 cores, governor schedutil, observed 1593.8-4025.0 MHz; kernel 6.8.0-94-generic; 2026-10-08T09:45:29Z
end of run: governor schedutil, observed 1500.0-4031.8 MHz (start: schedutil, 1593.8-4025.0 MHz; DRIFT: observed frequency range changed: 1593.8-4025.0 MHz -> 1500.0-4031.8 MHz (!))
