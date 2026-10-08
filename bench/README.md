# bench

Benchmark suite for mcp-node-zig against stdio MCP servers launched through `uvx` and `npx`. Results: [BENCHMARKS.md](../BENCHMARKS.md).

## Run

```sh
./bench/run_all.sh                      # publication profile (~5 h wall clock)
BENCH_PROFILE=quick ./bench/run_all.sh  # quick profile (~10 min)
```

Requires bash, `python3` (stdlib only), `zig` 0.16.x, `uvx`, `npx`, `openssl`, `du`, `/usr/bin/time`. Binds only `127.0.0.1` in the 183xx port range; every process and temp file is cleaned up on exit.

The publication profile (default) runs N=10000 for every timed series — cold start, exec latency, TLS handshakes — plus 1000 node-link cycles, with the same N for ours and both rivals; expect roughly five hours, dominated by rival cold starts. The quick profile (200 cold / 1000 latency / 500 TLS / 100 node cycles) fits dev iteration in about ten minutes.

Output in `bench/results/` (gitignored except the committed evidence directory, see below):

- `summary.md`: rendered tables
- `b01…b08_*.json`: per-metric aggregates (summaries with p50/p90/p95/p99, histograms)
- `raw/*.json`: every probe output
- `raw/*.jsonl`: one flat JSON object per sample, streamed as each sample completes (crash-safe for multi-hour runs)
- `env.json` / `env_end.json`: machine passport at start and end of run (CPU governor and observed frequencies, drift check)

## Options

All knobs live in `config.sh` and can be overridden from the environment; individual values override the profile defaults.

| variable | default | |
| --- | --- | --- |
| `BENCH_PROFILE` | `publication` | `publication` or `quick`; sets the N defaults below |
| `MCPNZ_BIN` | empty | benchmark this binary instead of building |
| `MCPNZ_BUILD_MODE` | `ReleaseSafe` | `zig build -Doptimize=` mode |
| `ZIG_BIN` | `zig` | Zig compiler |
| `MCPNZ_PORT` | `18341` | loopback port, keep in the 183xx range |
| `UVX_BIN` / `NPX_BIN` | `uvx` / `npx` | rival launchers |
| `B01_RUNS` | `10000` / `200` | cold-start runs (publication / quick) |
| `B05_RUNS` / `B05_WARMUP` | `10000` / `100` · `1000` / `10` | latency round-trips / warmup calls |
| `B02_HANDSHAKES` | `10000` / `500` | b02 client-side TLS handshakes |
| `B02_NODE_RUNS` | `1000` / `100` | b02 node spawn→registered cycles |
| `B02_HUB_PORT` / `B02_LINK_PORT` | `18351` / `18352` | b02 hub API port / TLS node-link port |
| `B03_SAMPLES` / `B03_INTERVAL` | `20` / `0.5` | idle RSS samples / seconds between them |
| `B07_CONNECTIONS` / `B07_STEP` | `20` / `5` | keep-alive connections / opened per step |
| `RESULTS` | `bench/results` | results directory (absolute or repo-relative) |
| `NICE_CMD` | `nice -n 10` | scheduling wrapper for every series |

## Metrics

| id | metric | script |
| --- | --- | --- |
| b01 | cold start → first MCP response (decomposed: boot→listen, listen→initialize) | `b01_cold_start.sh` |
| b02 | TLS 1.3 node-link handshakes + node link establishment | `b02_tls_handshake.sh` |
| b03 | idle RSS of the process tree | `b03_rss_idle.sh` |
| b05 | exec round-trip latency, warm server | `b05_exec_latency.sh` |
| b07 | memory per additional agent | `b07_per_connection.sh` |
| b08 | installed footprint | `b08_footprint.sh` |

## Rules

- One harness (`harness/mcp_probe.py`) for every participant, each on its native transport; samples time the child only.
- Rival installer caches are warmed before any cold series, so cold start measures the server, not the network.
- Every exec is `argv ["uname", "-a"]` with no shell: `exec` (ours), `shell_execute` with `ALLOW_COMMANDS=uname` (tumf), `run_process` (g0t4).
- Every timed series streams one flat JSON object per sample to `raw/<series>_<participant>.jsonl` as the sample completes; each line carries `series` and `participant`. b01 lines carry `boot_listen_ms`/`initialize_handshake_ms` (http only — stdio spawn→first-response is atomic over pipes, the fields are null there); b02 lines carry `tcp_connect_ms`/`tls_handshake_ms`/`total_ms` (client) or `link_established_ms` (node); b03/b07 stream their memory samples/steps.
- N, σ, min…max and percentiles (p50/p90/p95/p99) are always reported; series with CV > 10% are flagged `(!)`; latency summaries carry a fixed log2-bucket histogram.
- The machine passport is written at start and end; governor and observed CPU frequency drift between them is flagged, never tuned.
- b02 needs the `-Dtls-server` build; with a default build it skips cleanly (exit 0, reason recorded in the aggregate).

## Committed evidence

`bench/.gitignore` keeps `results/*` ignored except `results/publication-2026-10/` — the publication evidence run lands there (env passports, aggregates, raw JSONL/JSON, summary) so the published numbers can be re-derived from the repo. The tables in [BENCHMARKS.md](../BENCHMARKS.md) regenerate from a results directory:

```sh
python3 bench/lib/summarize.py <results-dir> --benchmarks --update BENCHMARKS.md
```

## Adding a participant

Add its launch argv (`--transport stdio -- <argv…>`, or HTTP flags) to the relevant `bNN_*.sh` next to the existing ones and re-run `run_all.sh`.
