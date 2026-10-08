# Benchmarks

mcp-node-zig answers its first MCP response from one static binary in single-digit milliseconds and idles below one MiB of RSS; the same command served through `uvx` and `npx` needs hundreds of milliseconds and well over a hundred MiB before the first tool call. Every table below carries the full distribution — p50/p90/p95/p99, min/max, mean ± σ, exact N and failure counts — and the raw samples for every series are committed under `bench/results/` as JSONL (one object per sample), so any number can be re-derived or challenged without re-running anything.

## Methodology

- One Python-stdlib harness (`bench/harness/`) drives every participant through its documented launch channel and spoken to over its native transport; timing is `perf_counter_ns` around the child only.
- Profiles: `publication` (default) runs N=10000 for every timed series — cold start, exec latency, TLS handshakes — plus 1000 node-link cycles, with the same N for ours and both rivals; `quick` cuts each series to dev-iteration size (~10 min). Individual env vars override any profile value; knobs are in [bench/README.md](bench/README.md).
- Cold start: full cycles (spawn → `initialize` → `tools/list` → one `exec` → shutdown), no warmup; rival installer caches are warmed beforehand so downloads are excluded. The http cold cycle is decomposed into boot→listen (process spawn through the port accepting) and listen→initialize; stdio participants report the bundled spawn→first-response because that split is not observable over pipes.
- TLS (b02): a throwaway EC CA and localhost server certificate are generated per run; client handshakes verify against that CA, and node-side link establishment is measured by polling the hub registry at ~1 ms. The MCP client surface (`POST /mcp`) has no TLS by design (loopback + token) — b02 covers the node-link path only.
- Every sample streams to JSONL as the sample completes, so a crash mid-series keeps all completed evidence on disk. Aggregates add p50/p90/p95/p99 (linear-interpolation percentiles), min/max, mean ± σ (sample stddev), a 95% CI of the mean (Student's t), a CV flag above 10%, and a fixed log2-bucket histogram.
- Memory is RSS/PSS summed over the whole process tree from `/proc`; the per-connection figure comes from keep-alive connections opened step by step, and the after-close RSS is reported as measured (returned or not). Rival trees include their launchers (`uv`, `npm exec`), which stay resident for as long as the server runs.
- All series run under `nice -n 10`. The machine is reported, never tuned: `env.json` (start) and `env_end.json` (end of run) record the CPU governor and observed per-CPU frequencies, and the tables flag drift between them.

## Reproduce

```sh
./bench/run_all.sh                      # publication profile (~5 h wall clock)
BENCH_PROFILE=quick ./bench/run_all.sh  # quick profile (~10 min)
```

Builds ReleaseSafe, warms the rivals' installer caches, runs every series and writes `bench/results/` (summary, per-metric aggregates, raw JSONL/JSON, machine passports at start and end). Requirements and options: [bench/README.md](bench/README.md). To regenerate the tables below from a results directory:

```sh
python3 bench/lib/summarize.py <results-dir> --benchmarks --update BENCHMARKS.md
```

## Results

<!-- bench:tables:start -->
## Results

### Cold start → first MCP response (b01)
_spawn -> first MCP response (initialize), full shutdown between runs_
| participant | N ok | failures | p50 ms | p90 ms | p95 ms | p99 ms | min…max ms | mean ± σ ms | CV% |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| mcp-node-zig | 10000 | 0 | 2.0 | 2.3 | 2.4 | 3.0 | 0.7…8.6 | 2.0 ± 0.3 | 15.8 (!) |
| tumf/mcp-shell-server | 10000 | 0 | 656.4 | 680.7 | 689.2 | 712.7 | 611.1…804.8 | 658.2 ± 18.3 | 2.8 |
| g0t4/mcp-server-commands | 10000 | 0 | 504.2 | 541.3 | 554.3 | 580.6 | 455.7…774.3 | 509.2 ± 24.3 | 4.8 |

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

### Exec round-trip latency (b05)
| participant | N ok | failures | p50 ms | p90 ms | p95 ms | p99 ms | min…max ms | mean ± σ ms | CV% |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| mcp-node-zig | 10000 | 0 | 1.6 | 2.0 | 2.2 | 2.5 | 0.8…4.5 | 1.5 ± 0.4 | 28.2 (!) |
| mcp-node-zig histogram (ms) | | | | | | | [0, 1) 1732; [1, 2) 7240; [2, 4) 1026; [4, 8) 2 | | |
| tumf/mcp-shell-server | 10000 | 0 | 2.5 | 3.0 | 3.2 | 3.8 | 2.0…18.6 | 2.6 ± 0.4 | 15.1 (!) |
| tumf/mcp-shell-server histogram (ms) | | | | | | | [2, 4) 9931; [4, 8) 68; [16, 32) 1 | | |
| g0t4/mcp-server-commands | 10000 | 0 | 2.4 | 3.1 | 3.3 | 3.7 | 1.3…5.9 | 2.4 ± 0.6 | 25.1 (!) |
| g0t4/mcp-server-commands histogram (ms) | | | | | | | [1, 2) 2745; [2, 4) 7208; [4, 8) 47 | | |

### Idle RSS (b03)
| participant | RSS median MiB | RSS max MiB | PSS median MiB | PSS max MiB |
| --- | --- | --- | --- | --- |
| mcp-node-zig | 2.30 | 2.30 | 1.87 | 1.87 |
| tumf/mcp-shell-server | 111.84 | 111.84 | 108.54 | 108.54 |
| g0t4/mcp-server-commands | 152.60 | 152.60 | 109.26 | 109.26 |

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

### Environment

- Stand: ec3584d1-aec2-4477-b7a7-b8902778ab9a — AMD EPYC 9254 24-Core Processor, 48 cores, governor schedutil, observed 1593.8-4025.0 MHz; kernel 6.8.0-94-generic; binary sha256 32a2e5ca4e805f32269b298527fa27f374f39985a7b2f81be5179291a8d64e33; passports: 2026-10-08T09:45:29Z.
- End of run: governor schedutil, observed 1500.0-4031.8 MHz; start was governor schedutil, 1593.8-4025.0 MHz — DRIFT: observed frequency range changed: 1593.8-4025.0 MHz -> 1500.0-4031.8 MHz
<!-- bench:tables:end -->

## Honest limits

- Self-measured on one machine, loopback only. These are ratios, not records.
- Absolute values shift across hosts, compilers and OS releases; the claims worth checking are the ratios and the shape of the distributions.
- Evidence runs execute in shared environments; noisy neighbors can inflate absolute numbers, and the governor/frequency drift check in the Environment section says when the machine moved under the run.
- stdio rivals bundle launcher startup in their cold start by the nature of their launch channel; that is disclosed, not hidden — the raw JSONL lets anyone re-slice the numbers differently.
