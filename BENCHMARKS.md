# Benchmarks

mcp-node-zig serves its first MCP response in **1.9 ms** and idles at **0.62 MiB**: 251× and 452× faster to first response than the uvx and npx command servers, from one 8.70 MiB static binary with no runtime.

| | mcp-node-zig 0.2.0 | tumf/mcp-shell-server 1.30.0 | g0t4/mcp-server-commands 0.8.2 |
| --- | --- | --- | --- |
| launch | static binary, HTTP `POST /mcp` | `uvx mcp-shell-server` | `npx -y mcp-server-commands` |
| cold start → first response, median | **1.9 ms** | 477.0 ms | 858.4 ms |
| spawn → first completed tool call, median | **3.60 ms** | 483.0 ms | 865.8 ms |
| idle RSS, process tree¹ | **0.62 MiB** | 124.31 MiB | 189.22 MiB |
| exec round-trip p50 / p95 | **0.7 / 1.1 ms** | 3.7 / 4.8 ms | 1.8 / 2.9 ms |
| each additional agent | **≈ 288 KiB** (connection) | 126.2 MiB (process) | 190.5 MiB (process) |
| installed footprint | **8.70 MiB**, no runtime | 146.0 MiB venv+cache + 86.4 MiB CPython | 9.9 MiB + 83.1 MiB Node.js |

Environment: Intel Core i3-9100F (4 cores, powersave governor), 8 GiB RAM, CachyOS, kernel 7.2.5; Zig 0.16.0 ReleaseSafe, CPython 3.11.14 via uvx 0.10.6, Node 26.8.2 via npx 12.0.2; mcp-node-zig 0.2.0 is the x86_64 baseline ReleaseSafe build (9 117 968-byte binary). All three columns come from one full run on 2026-10-05: N = 100 cold cycles per participant, N = 200 latency calls; 0 failures in every series.

## Reproduce

```sh
./bench/run_all.sh
```

Builds ReleaseSafe, warms the rivals' installer caches, runs every series and writes `bench/results/` (`summary.md`, per-metric JSON, raw samples, machine passport). Requirements and options: [bench/README.md](bench/README.md).

## Methodology

- Every participant is launched through its documented channel and spoken to over its native transport, by the same Python stdlib harness; timing is `perf_counter_ns` around the child only.
- Cold start: N = 100 full cycles (spawn → `initialize` → `tools/list` → one `exec` → shutdown), no warmup; rival installer caches are warmed beforehand, so downloads are excluded. Latency: N = 200 `tools/call` on one warm server after 10 warmup calls. 0 failures in every series.
- Every exec runs the same `argv ["uname", "-a"]`, no shell layer, for all three servers.
- Memory is RSS summed over the whole process tree from `/proc` (20 samples × 0.5 s after a 2 s settle); the per-connection figure comes from 20 keep-alive connections opened 5 at a time, all memory returned on close.
- All series run under `nice -n 10`; the machine is reported, not tuned.

¹ mcp-node-zig speaks HTTP on loopback, the rivals stdio: each is measured in its own attachment mode. Rival trees include their launcher (`uv` 146.5 MiB, `npm exec` 136.4 MiB), which stays resident for as long as the server runs.
