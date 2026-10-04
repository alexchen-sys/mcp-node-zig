# bench

Benchmark suite for mcp-node-zig against stdio MCP servers launched through `uvx` and `npx`. Results: [BENCHMARKS.md](../BENCHMARKS.md).

## Run

```sh
./bench/run_all.sh
```

Requires bash, `python3` (stdlib only), `zig` 0.16.x, `uvx`, `npx`, `openssl`, `du`, `/usr/bin/time`. Binds only `127.0.0.1:18341`; every process and temp file is cleaned up on exit.

Output in `bench/results/` (gitignored):

- `summary.md`: rendered tables
- `b01…b08_*.json`: per-metric aggregates
- `raw/*.json`: every sample and probe output
- `env.json`: machine passport (CPU, RAM, kernel, governor, tool versions, binary sha256)

## Options

All knobs live in `config.sh` and can be overridden from the environment.

| variable | default | |
| --- | --- | --- |
| `MCPNZ_BIN` | empty | benchmark this binary instead of building |
| `MCPNZ_BUILD_MODE` | `ReleaseSafe` | `zig build -Doptimize=` mode |
| `ZIG_BIN` | `zig` | Zig compiler |
| `MCPNZ_PORT` | `18341` | loopback port, keep in the 183xx range |
| `UVX_BIN` / `NPX_BIN` | `uvx` / `npx` | rival launchers |
| `B01_RUNS` | `50` | cold-start runs |
| `B05_RUNS` / `B05_WARMUP` | `200` / `10` | latency round-trips / warmup calls |
| `B03_SAMPLES` / `B03_INTERVAL` | `20` / `0.5` | idle RSS samples / seconds between them |
| `B07_CONNECTIONS` / `B07_STEP` | `20` / `5` | keep-alive connections / opened per step |
| `NICE_CMD` | `nice -n 10` | scheduling wrapper for every series |

## Metrics

| id | metric | script |
| --- | --- | --- |
| b01 | cold start → first MCP response | `b01_cold_start.sh` |
| b03 | idle RSS of the process tree | `b03_rss_idle.sh` |
| b05 | exec round-trip latency, warm server | `b05_exec_latency.sh` |
| b07 | memory per additional agent | `b07_per_connection.sh` |
| b08 | installed footprint | `b08_footprint.sh` |

## Rules

- One harness (`harness/mcp_probe.py`) for every participant, each on its native transport; samples time the child only.
- Rival installer caches are warmed before any cold series, so cold start measures the server, not the network.
- Every exec is `argv ["uname", "-a"]` with no shell: `exec` (ours), `shell_execute` with `ALLOW_COMMANDS=uname` (tumf), `run_process` (g0t4).
- N, σ, min…max and percentiles are always reported; series with CV > 10% are flagged `(!)`.

## Adding a participant

Add its launch argv (`--transport stdio -- <argv…>`, or HTTP flags) to the relevant `bNN_*.sh` next to the existing ones and re-run `run_all.sh`.
