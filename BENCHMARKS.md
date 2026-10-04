# Benchmarks

mcp-node-zig serves its first MCP response in **1.86 ms** and idles at **0.98 MiB**: 239 ± 34× and 469 ± 75× faster to first response than the uvx and npx command servers, from one 4.30 MiB static binary with no runtime.

| | mcp-node-zig 0.1.0 | tumf/mcp-shell-server 1.30.0 | g0t4/mcp-server-commands 0.8.2 |
| --- | --- | --- | --- |
| launch | static binary, HTTP `POST /mcp` | `uvx mcp-shell-server` | `npx -y mcp-server-commands` |
| cold start → first response, median | **1.86 ms** | 463.50 ms | 887.87 ms |
| spawn → first completed tool call, median | **3.27 ms** | 469.5 ms | 894.6 ms |
| idle RSS, process tree¹ | **0.98 MiB** | 197.11 MiB | 189.30 MiB |
| exec round-trip p50 / p95 | **0.66 / 1.23 ms** | 3.65 / 4.20 ms | 1.63 / 2.58 ms |
| each additional agent | **≈ 576 KiB** (connection) | 196.3 MiB (process) | 193.6 MiB (process) |
| installed footprint | **4.30 MiB**, no runtime | 111.6 MiB + 86.4 MiB CPython | 9.9 MiB + 83.1 MiB Node.js |

Environment: Intel Core i3-9100F (4 cores, powersave governor), 8 GiB RAM, CachyOS, kernel 7.2.5; Zig 0.16.0 ReleaseSafe, CPython 3.11.14 via uvx 0.10.6, Node 26.8.2 via npx 12.0.2; 2026-10-03.

## Reproduce

```sh
./bench/run_all.sh
```

Builds ReleaseSafe, warms the rivals' installer caches, runs every series and writes `bench/results/` (`summary.md`, per-metric JSON, raw samples, machine passport). Requirements and options: [bench/README.md](bench/README.md).

## Methodology

- Every participant is launched through its documented channel and spoken to over its native transport, by the same Python stdlib harness; timing is `perf_counter_ns` around the child only.
- Cold start: N = 50 full cycles (spawn → `initialize` → `tools/list` → one `exec` → shutdown), no warmup; rival installer caches are warmed beforehand, so downloads are excluded. Latency: N = 200 `tools/call` on one warm server after 10 warmup calls. 0 failures in every series.
- Every exec runs the same `argv ["uname", "-a"]`, no shell layer, for all three servers.
- Memory is RSS summed over the whole process tree from `/proc` (20 samples × 0.5 s after a 2 s settle); the per-connection figure comes from 20 keep-alive connections opened 5 at a time, all memory returned on close.
- All series run under `nice -n 10`; the machine is reported, not tuned.

¹ mcp-node-zig speaks HTTP on loopback, the rivals stdio: each is measured in its own attachment mode. Rival trees include their launcher (`uv` 146.5 MiB, `npm exec` 136.4 MiB), which stays resident for as long as the server runs.
