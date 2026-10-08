# Changelog

Notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Benchmark harness rigor upgrade: `publication`/`quick` profiles
  (N=10,000 per timed series in the publication profile), p90/p99 and
  log2-bucket histograms in every summary, raw per-sample JSONL streaming
  under `bench/results/`, cold-start decomposition (boot→listen and
  listen→first-response), a new TLS node-link handshake series
  (`bench/b02_tls_handshake.sh`), start/end machine passports with CPU
  governor/frequency drift detection, and a generated tables section in
  `BENCHMARKS.md` (`bench/lib/summarize.py --benchmarks`).
