# Benchmarks

Reproducible benchmark suite for mcp-node-zig against stdio MCP servers
launched by their documented channels (`uvx`/`npx`).

## One command

```sh
./bench/run_all.sh
```

Requirements: bash, `python3` (standard library only — no psutil/hyperfine),
`zig` 0.16.x (or `ZIG_BIN=/path/to/zig`), `uvx`, `npx`, `openssl`, `du`,
`/usr/bin/time`. The suite binds only to `127.0.0.1:18341` (override with
`MCPNZ_PORT`, keep it in the 183xx range) and cleans up every process and
temp file it creates (`trap` + process-group kill).

Everything the run produces lands in `bench/results/` (gitignored):

- `env.json` — machine passport (CPU, RAM, kernel, governor, tool versions,
  binary sha256)
- `raw/*.json` — every per-run sample, every probe output
- `b01…b08_*.json` — per-metric aggregates
- `summary.md` — rendered tables

`MCPNZ_BIN=/path/to/mcp-node` skips the build and benchmarks that binary.

## What is measured (this run: b01, b03, b05, b07, b08)

| id | metric | question it answers |
| --- | --- | --- |
| b01 | cold start → first MCP response | how long until a freshly spawned node can serve? |
| b03 | idle RSS (tree, median of 20×0.5s samples) | what does a running node cost in memory? |
| b05 | exec round-trip latency, warm server (N=200) | how fast does one command round-trip? |
| b07 | ΔRSS per keep-alive connection / per agent | what does the second agent cost? |
| b08 | delivery footprint | what must be installed on the target machine? |

b02 (warm start), b04 (RSS under load) and b06 (HTTP throughput) are not part
of this run; the slots are reserved in the numbering for future extensions.

## Fairness rules

- **One measuring arm for everyone.** `harness/mcp_probe.py` spawns every
  participant the same way and speaks each one's native transport (stdio for
  rivals, HTTP for mcp-node-zig). The python process startup never lands
  inside a sample: each sample is `perf_counter_ns` around the child
  lifecycle only.
- **Cold means cold, warm means warm.** Cold series have no warmup by
  definition; the rivals' *installer* caches (uvx/npx downloads) are warmed
  before the cold series by `run_all.sh`, so a cold run measures the server
  waking up, not the network.
- **Same child work.** Every exec latency sample runs the same
  `argv ["uname", "-a"]` on every participant — no shell layer anywhere
  (ours: `exec`; tumf: `shell_execute` argv mode; g0t4: `run_process` argv
  mode).
- **Rivals run in their documented configuration**: `uvx mcp-shell-server`
  with `ALLOW_COMMANDS=uname` (their allowlist env) and
  `npx -y mcp-server-commands`.
- **N, σ, min…max, percentiles are always reported**; a series with CV > 10%
  is flagged `(!)` in the summary rather than silently dropped.
- **Benchmarks run under `nice -n 10`** and never change the machine (CPU
  governor is reported, not touched).

## Adding a participant

Give `harness/mcp_probe.py` a new `--transport stdio -- tool argv…` (or HTTP
flags), add the invocation to the relevant `bNN_*.sh` script next to the
existing ones, and re-run `run_all.sh`.

## Interpreting results

Raw JSON beats prose: every number in `BENCHMARKS.md` traces to
`results/raw/*.json`. If a number does not reproduce on your machine, the
`env.json` passport plus the exact commands above are the repro kit — issues
with those are welcome.
