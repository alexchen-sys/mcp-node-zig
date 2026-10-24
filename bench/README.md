# bench

Benchmark suite for mcp-node-zig against stdio MCP servers launched through `uvx` and `npx`. Results: [BENCHMARKS.md](../BENCHMARKS.md).

## Run

```sh
./bench/run_all.sh                      # publication profile (~3.5 h full / ~18 min mcp-node only)
BENCH_PROFILE=quick ./bench/run_all.sh  # quick profile (~10 min)
```

Requires bash, `python3` (stdlib only), `zig` 0.16.x, `uvx`, `npx`, `openssl`, `du`, `/usr/bin/time`. Binds only `127.0.0.1` in the 183xx port range; every process and temp file is cleaned up on exit. Unless `MCPNZ_BIN` points at a prebuilt binary, `run_all.sh` builds with `-Dtls-server` (b02 needs it; the first such build fetches mbedTLS through `zig fetch`, so it needs network once) and falls back to the plain build if the TLS build is unavailable, in which case b02 skips cleanly. The published evidence measures the **plain** release build for every series except b02; to reproduce those numbers, build plain (`zig build -Doptimize=ReleaseSafe`) and pass `MCPNZ_BIN=zig-out/bin/mcp-node`.

The publication profile (default) runs N=10000 for every timed series (`b01` cold start, `b05` exec latency, `b02` TLS handshakes) plus 1000 node-link cycles. Running `mcp-node` across all series takes ~18 minutes; running the two external launchers (`uvx` and `npx`, ~550 ms per cold start across 10,000 runs each) adds ~3 hours. The quick profile (200 cold / 1000 latency / 500 TLS / 100 node cycles) completes in ~10 minutes.

Output in `bench/results/` (gitignored except the committed evidence directory, see below):

- `summary.md`: rendered tables
- `b01…b08_*.json`: per-metric aggregates (summaries with p50/p90/p95/p99, histograms)
- `raw/*.json`: every probe output
- `raw/*.jsonl`: one flat JSON object per sample, streamed as each sample completes (crash-safe for multi-hour runs)
- `env.json` / `env_end.json`: machine passports (at start and end of run) with CPU governor and observed frequencies, drift check

## Options

All knobs live in `config.sh` and can be overridden from the environment; individual values override the profile defaults.

| variable | default | notes |
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
| `B03_SETTLE` / `B03_SETTLE_LAUNCHER` | `2.0` / `20.0` | idle settle seconds: static binary / launcher trees (uvx, npx) — launchers keep shedding memory for several seconds after initialize, so their settle is longer |
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
- Every timed series streams one flat JSON object per sample to `raw/<series>_<participant>.jsonl` as the sample completes; each line carries `series` and `participant`. b01 lines carry `boot_listen_ms`/`initialize_handshake_ms` (http only — stdio spawn→first-response is atomic over pipes, the fields are null there); b02 lines carry `tcp_connect_ms`/`tls_handshake_ms`/`total_ms` (client) or `link_established_ms` (node; timed from just before the spawn call, so the spawn itself is included); b03/b07 stream their memory samples/steps.
- N, σ, min…max, CV%, and percentiles (p50/p90/p95/p99) are always reported for timed latency series; latency summaries carry a fixed log2-bucket histogram.
- The machine passport is written at start and end; governor and observed CPU frequency drift between them is flagged, never tuned.
- b02 needs the `-Dtls-server` build (the default, see above); without it b02 skips cleanly (exit 0, reason recorded in the aggregate).
- JSONL files are append-only: re-running into the same `RESULTS` directory appends new samples to the existing files (aggregates are rewritten). Use a fresh `RESULTS` for a clean series.

## Committed evidence

`bench/.gitignore` keeps `results/*` ignored except `results/publication-2026-10/`, which stores the publication evidence (`env.json`/`env_end.json` for the 18-minute `mcp-node` v0.5.0 capture window, plus the participant aggregates, raw JSONL/JSON samples, and rendered summary) so the published numbers can be re-derived from the repo. The tables in [BENCHMARKS.md](../BENCHMARKS.md) regenerate from a results directory:

```sh
python3 bench/lib/summarize.py <results-dir> --benchmarks --update BENCHMARKS.md
```

## Adding a participant

Add its launch argv (`--transport stdio -- <argv…>`, or HTTP flags) to the relevant `bNN_*.sh` next to the existing ones and re-run `run_all.sh`.
