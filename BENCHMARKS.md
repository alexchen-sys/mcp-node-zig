# Benchmarks

Measured: **cold start to first MCP response, idle RSS, exec round-trip latency,
per-connection memory, delivery footprint** — mcp-node-zig against two stdio
MCP command servers, launched exactly the way their READMEs document:

- **mcp-node-zig 0.1.0** — one static binary, streamable-HTTP `POST /mcp`
- **tumf/mcp-shell-server 1.30.0** — `uvx mcp-shell-server` (Python, uv-managed CPython 3.11.14)
- **g0t4/mcp-server-commands 0.8.2** — `npx -y mcp-server-commands` (Node 26.8.2)

The question these numbers answer: *what does it cost to put a command-running
MCP agent on a machine — to install it, to start it, to keep it idle, to talk
to it, and to attach a second agent to the same box?*

Everything here is produced by `./bench/run_all.sh` (one command; scripts and
raw JSON protocol in [bench/](bench/)). Every number below traces to a raw
JSON sample file. If it does not reproduce on your machine, please open an
issue with your hardware and the command output — benchmark reports are the
start of a conversation, not a verdict.

## Stand

```
cpu:      Intel(R) Core(TM) i3-9100F CPU @ 3.60GHz (4 cores, up to 4.2 GHz)
          governor: powersave (reported, not changed)
ram:      8 GiB total, ~3.4 GiB available during the run
os:       CachyOS (Arch-based), kernel 7.2.5-1-cachyos
fs:       binary and caches on btrfs (/home); scratch on tmpfs (/tmp)
load:     0.23 / 0.38 / 0.40 during the run, 2 ssh sessions
date:     2026-10-03 (UTC timestamps inside raw JSON)
schedule: all benchmark processes run under `nice -n 10`
```

Participants, measured arm and versions:

- harness: python 3.12.8, standard library only (`perf_counter_ns`, `/proc` reads)
- ours: `zig build -Doptimize=ReleaseSafe`, binary 4,494,584 bytes
  (sha256 `f6e46e8e…d3ad649`), no runtime installed
- rivals: their documented launch channel; package caches warmed BEFORE the
  cold series (`uvx 0.10.6`, `npx 12.0.2`), so cold measures the server, not
  the network
- measurement tools: hyperfine / oha / psutil were not installed on this
  stand; the harness implements the same protocol directly (wall-clock around
  the child lifecycle, percentile statistics, `/proc/<pid>/status` +
  `smaps_rollup` sampling — the same files psutil reads)

## b01 — cold start to the first MCP response

Full cycle per run: spawn → `initialize` → `tools/list` → one `exec` →
shutdown. No warmup (this is the cold metric). N = 50 runs each; every run of
every participant succeeded (0 failures), same child command
(`argv ["uname", "-a"]`) everywhere.

| participant | median ms | mean ± σ ms | min … max ms | p95 ms | CV % |
| --- | --- | --- | --- | --- | --- |
| mcp-node-zig (http) | **1.86** | 1.94 ± 0.27 | 1.74 … 3.59 | 2.19 | 14.0 (!) |
| tumf/mcp-shell-server (uvx) | 463.50 | 463.31 ± 5.43 | 454.49 … 476.14 | 472.02 | 1.2 |
| g0t4/mcp-server-commands (npx) | 887.87 | 909.39 ± 69.05 | 832.57 … 1243.83 | 1030.43 | 7.6 |

Relative (95% CI of the means do not overlap in either pair):

- mcp-node-zig vs tumf: **239 ± 34×** faster to first response
- mcp-node-zig vs g0t4: **469 ± 75×** faster to first response

“Ready to serve” (spawn → first completed tool call, includes the exec above):
3.27 ms / 469.5 ms / 894.6 ms median.

The `(!)` on our CV: the 50-sample spread of a 2 ms operation under a
powersave governor. The series median is stable (first run of the series is
the 3.6 ms outlier — page cache; the other 49 sit between 1.74 and 2.2 ms).
Rival CV is low because their floor is two orders of magnitude higher.

## b03 — idle RSS

Spawn → initialize → settle 2 s → 20 samples × 0.5 s, summed over the whole
process tree (rivals are two-process trees: launcher + interpreter).
Median = max for all participants (idle is flat).

| participant | tree RSS median MiB | tree PSS median MiB | tree composition (RSS) |
| --- | --- | --- | --- |
| mcp-node-zig | **0.98** | 0.97 | 1 process |
| tumf/mcp-shell-server | 197.11 | 186.52 | `uv` 146.5 + `python` 55.3 |
| g0t4/mcp-server-commands | 189.30 | 143.90 | `npm exec` 136.4 + `node` 57.5 |

Orthogonal check for the single-process case: `/usr/bin/time -v` Maximum
resident set size for mcp-node over its full lifecycle: **1104 KiB**.

The launcher processes are not an accounting trick — a server started as
`uvx mcp-shell-server` or `npx mcp-server-commands` really holds both
processes resident for as long as it runs. PSS is reported alongside RSS so
shared-library double counting is visible.

## b05 — exec round-trip latency, warm server

One warm server per participant, one channel per participant (keep-alive
HTTP for ours — an agent’s normal attachment; stdio pipes for the rivals —
theirs). N = 200 identical `tools/call` round-trips, 10 warmup calls first.
0 failures for everyone.

| participant | p50 ms | p95 ms | p99 ms | mean ± σ ms | min … max ms |
| --- | --- | --- | --- | --- | --- |
| mcp-node-zig (http, keep-alive) | **0.66** | 1.23 | 1.81 | 0.75 ± 0.26 | 0.51 … 2.11 |
| tumf/mcp-shell-server (stdio) | 3.65 | 4.20 | 4.82 | 3.67 ± 0.37 | 3.08 … 5.25 |
| g0t4/mcp-server-commands (stdio) | 1.63 | 2.58 | 2.83 | 1.73 ± 0.40 | 1.18 … 3.04 |

Every sample spawns the same child (`uname -a`) on every participant, so the
child-process cost is a common floor, not a variable. For reference, our
pure-JSON-RPC `initialize` round-trip on the same connection is ~0.5 ms.

## b07 — the cost of the second agent

Ours: one process; agents are keep-alive connections. 20 connections opened
5 at a time, tree RSS sampled after each step.

| connections | tree RSS KiB |
| --- | --- |
| 1 (base) | 1292 |
| 6 | 4660 |
| 11 | 6100 |
| 16 | 9368 |
| 21 | 12812 |

≈ **576 KiB per connection** (11.2 MiB for 20 idle agents), and after closing
all 20 connections the process returns to **1004 KiB — below the base line**
(threads and buffers are released; the growth is allocator slabs, not a
leak).

Rivals: every agent is a separate server process. Two instances side by side:

| participant | second agent costs | two agents total |
| --- | --- | --- |
| tumf/mcp-shell-server | 196.3 MiB | 391.1 MiB |
| g0t4/mcp-server-commands | 193.6 MiB | 385.2 MiB |

Scaled to 20 attached agents: mcp-node-zig holds one process at ~12.5 MiB;
the stdio model holds 20 full trees ≈ 3.8 GiB.

## b08 — delivery footprint (what you put on the machine)

| participant | package artifact | package env MiB | runtime MiB |
| --- | --- | --- | --- |
| mcp-node-zig | one static binary — 4.30 MiB | 0 | **0** (no interpreter, no libc) |
| tumf/mcp-shell-server | venv 33.1 MiB | + uv cache 78.5 → 111.6 | 86.4 (uv-managed CPython 3.11.14) |
| g0t4/mcp-server-commands | npx env 9.9 MiB | 9.9 | 83.1 (system Node.js 26.8.2) |

Paths resolved from a live process (`/proc/*/cmdline`, `exe`), sized with
`du -sb`: uvx materializes the venv under `~/.cache/uv/archive-v0/…` and
resolves its own CPython under `~/.local/share/uv/python/…`; npx keeps the
package under `~/.npm/_npx/…`. The runtime column is the interpreter an
already-clean machine must install to run the rival at all.

## Honest failures and soft spots

- **Binary size: 4.3 MiB** against the 2–3 MiB internal target for this
  metric. ReleaseSafe with checks on; it is 46× smaller than the smallest
  rival stack (npx env + Node) and needs nothing else installed, but the
  absolute number misses the target we set ourselves.
- **ΔRSS per connection: 576 KiB** — the upper edge of the “hundreds of KiB”
  corridor we consider decent. The step series shows slab-like growth
  (not per-connection linear), and everything is returned on close; a leaner
  per-connection budget is real future work.
- **Our CV on the millisecond metrics** (14% cold, 35% latency p50 spread)
  is high in relative terms because the absolute numbers are sub-2 ms on a
  powersave governor. Medians and CI are reported; rival series would show
  the same relative jitter if their floor were this low.
- **Not measured here**: warm-start series (b02), RSS under load (b04), HTTP
  throughput/concurrency (b06, incl. the mcpo bridge for the stdio rivals).
  The slots are reserved; the harness arms exist for all three.

## Caveats (read before quoting a number)

- **Transport asymmetry**: mcp-node-zig speaks HTTP on loopback, rivals speak
  stdio pipes. b01/b03/b05/b07 compare *what a client experiences from its
  native attachment mode* — each participant’s own documented transport. An
  apples-to-apples HTTP plane for the rivals would require the mcpo bridge
  (b06, not in this run).
- **One machine, one day**: single-user desktop, btrfs + tmpfs, powersave
  governor, load < 0.5. Different FS/governor/silicon will move absolute
  numbers; the order-of-magnitude gaps are the robust part.
- **Installer caches were warm** for the rivals before every cold series
  (downloads excluded on purpose); our binary was read from btrfs with the
  page cache warm after the first run.
- **Versions matter**: Node 26.8.2, CPython 3.11.14 (uv-managed), uvx 0.10.6,
  npx 12.0.2, Zig 0.16.0 ReleaseSafe. Rivals may shrink or grow with their
  next releases — these are their current documented channels.
- **RSS of rivals includes their launchers** (`uv`, `npm exec`): that is the
  real resident cost of running them the documented way, and the tree
  composition is broken out per process so you can subtract it yourself.

## Reproducing

```sh
./bench/run_all.sh          # builds ReleaseSafe, warms rival caches, runs
                            # b01/b03/b05/b07/b08, writes bench/results/
```

Raw JSON for every table above (per-run samples, per-step RSS, env passport)
was produced by that command on 2026-10-03 and is attached to the release
post; rerun it locally to regenerate `bench/results/raw/*.json`.

## Errata

- 2026-10-03 (first revision): an earlier same-day run reported ours idle RSS
  as 2.88 MiB — the `/usr/bin/time` wrapper had been counted inside the
  measured process tree, and tumf’s venv path failed to resolve. Both were
  harness defects, fixed before these numbers; corrected idle RSS is
  0.98 MiB.
