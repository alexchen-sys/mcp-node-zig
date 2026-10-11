# Changelog

Notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.4.0] - 2026-10-11

### Added

- Per-token argument gating: `MCP_NODE_POLICY_FILE` gives each client token
  its own tool list and argument limits (argv[0] allowlists, `cwd` and
  read/write path prefixes with deny lists, timeout and file-mode caps).
  Paths are canonicalised before matching, sessions are owned by the token
  that started them, and denials return `PolicyDenied` before dispatch and
  are written to the audit log as `policy.deny`. Unset, the node behaves as
  in 0.3.1. See `docs/arg-gating.md`.
- Durable exec sessions: sessions live in the node process, so they survive
  a dropped hub link, a hub restart or a client disconnect. Reattach with
  the same `session_id` from the byte offsets of the last response; output
  over `MCP_NODE_MAX_OUT` sets `truncated_*` and counts `lost_*_bytes`.
  Unknown or expired ids return a structured `unknown_session` result.
- Benchmark harness rigor upgrade: `publication`/`quick` profiles
  (N=10,000 per timed series in the publication profile), p90/p99 in every
  summary and log2-bucket histograms in latency summaries, raw per-sample
  JSONL streaming
  under `bench/results/`, cold-start decomposition (boot→listen and
  listen→first-response), a new TLS node-link handshake series
  (`bench/b02_tls_handshake.sh`), start/end machine passports with CPU
  governor/frequency drift detection, and a generated tables section in
  `BENCHMARKS.md` (`bench/lib/summarize.py --benchmarks`).
