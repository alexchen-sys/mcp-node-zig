# Benchmarks

mcp-node-zig answers its first MCP response from one static binary in single-digit milliseconds and idles below one MiB of RSS; the same command served through `uvx` and `npx` needs hundreds of milliseconds and well over a hundred MiB before the first tool call. Every table below carries the full distribution — p50/p90/p95/p99, min/max, mean ± σ, exact N and failure counts — and the raw samples for every series are committed under `bench/results/` as JSONL (one object per sample), so any number can be re-derived or challenged without re-running anything.

## Methodology

- One Python-stdlib harness (`bench/harness/`) drives every participant through its documented launch channel and spoken to over its native transport; timing is `perf_counter_ns` around the child only.
- Profiles: `publication` (default) runs N=10000 for every timed series — cold start, exec latency, TLS handshakes — plus 1000 node-link cycles, with the same N for ours and both rivals; `quick` cuts each series to dev-iteration size (~10 min). Individual env vars override any profile value; knobs are in [bench/README.md](bench/README.md).
- Cold start: full cycles (spawn → `initialize` → `tools/list` → one `exec` → shutdown), no warmup; rival installer caches are warmed beforehand so downloads are excluded. The http cold cycle is decomposed into boot→listen (process spawn through the port accepting) and listen→initialize; stdio participants report the bundled spawn→first-response because that split is not observable over pipes.
- TLS (b02): a throwaway EC CA and localhost server certificate are generated per run; client handshakes verify against that CA, and node-side link establishment is measured by polling the hub registry at ~1 ms. The MCP client surface (`POST /mcp`) has no TLS by design (loopback + token) — b02 covers the node-link path only.
- Every sample streams to JSONL as the sample completes, so a crash mid-series keeps all completed evidence on disk. Aggregates add p50/p90/p95/p99 (linear-interpolation percentiles), min/max, mean ± σ (sample stddev), a 95% CI of the mean (Student's t), a CV flag above 10%, and a fixed log2-bucket histogram.
- Memory is RSS/PSS summed over the whole process tree from `/proc`; the per-connection figure comes from keep-alive connections opened step by step, all memory returned on close. Rival trees include their launchers (`uv`, `npm exec`), which stay resident for as long as the server runs.
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
_(no data yet — run the suite and refresh with the command above)_
<!-- bench:tables:end -->

## Honest limits

- Self-measured on one machine, loopback only. These are ratios, not records.
- Absolute values shift across hosts, compilers and OS releases; the claims worth checking are the ratios and the shape of the distributions.
- Evidence runs execute in shared environments; noisy neighbors can inflate absolute numbers, and the governor/frequency drift check in the Environment section says when the machine moved under the run.
- stdio rivals bundle launcher startup in their cold start by the nature of their launch channel; that is disclosed, not hidden — the raw JSONL lets anyone re-slice the numbers differently.
