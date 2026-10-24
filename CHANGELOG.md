# Changelog

Notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.5.0] - 2026-10-24

### Changed

- MCP envelope error signaling: a tool result whose payload is `ok:false`
  now sets `result.isError: true` (and always keeps the text mirror, even
  with `MCP_NODE_TEXT_MIRROR=0`), replacing the v0 quirk where tool-domain
  errors arrived as `isError:false` envelopes. Clients can branch on the
  envelope instead of parsing inner JSON. Protocol errors (-32602 etc.) are
  unchanged. Note that `exec`/`exec_shell` report a nonzero command exit as
  `ok:false` (this predates v0.5.0), so a failed command now also surfaces
  as `isError:true`; `isError` follows the `ok` flag, whatever drove it.

### Added

- Opt-in durable exec sessions (Linux in v0.5.0): with `MCP_NODE_STATE_DIR`
  (or `--state-dir`) configured, `exec_start` accepts `"durable": true`.
  Child stdout/stderr append to per-session log files from spawn, the session
  record commits before the child starts writing, and after a
  node restart the session is recovered: `exec_poll` returns
  `recovered: true` with byte-exact deltas and `exec_kill` still works —
  every signal is gated on a verified process identity (PID + start-time +
  boot id; the leader is signaled through pidfd, and a narrow race remains
  between the identity check and the numeric process-group signal).
  Degradation is explicit:
  `stdin_available: false` and `StdinUnavailable` on `exec_write` for
  recovered sessions, `exit_code: null` with `completion_reason:
  "orphaned_exit"` when an orphaned child exited while the node was down.
  Records are bound to the owning token; closed or reaped durable sessions
  answer `unknown_session` with `expired: true` inside a bounded recency
  window. New error names: `DurabilityDisabled` (no state dir configured),
  `StateDirLocked` (a second node on the same dir), `DurableMetadataTooLarge`
  (12 KiB / 256 argv record cap), `DurabilityUnsupported` (non-Linux).
  `MCP_NODE_STATE_MAX_BYTES` (default 64 MiB) caps the journal. The state
  directory requires `0700`, is locked for the node lifetime, and every
  metadata write is tmp + fsync + rename + dir-fsync. With no state dir the
  feature is compiled inert: zero added syscalls or allocations on the
  ephemeral path. Covered by a real SIGKILL-and-restart e2e
  (`ci/test_durable_restart.py`).
- `copy_path`: bulk local copy of a file or directory tree to an exact new
  destination. Both ends are authorized independently through the policy
  gate (source needs read access, destination write access), traversal runs
  on pinned dirfd descriptors with no-follow semantics (symlink escapes and
  `..` components are refused, never normalized), and the tree is staged
  privately and atomically published; a crashed or refused copy never
  leaves a partial destination. Responses carry `files`/`directories`/
  `bytes` counts and a `sha256` (`content-sha256` for one file,
  `mcp-tree-v1` digest for a tree). Ceilings: `max_bytes` (default 64 MiB),
  `max_entries` (default 2000), `timeout` (default 30 s). Directories
  require `recursive=true` and a policy mode cap including 0700; existing
  destinations are never overwritten (`DestinationExists`); Windows answers
  `AtomicPublishUnsupported` before touching the filesystem.
  Every `copy_path` refusal carries an actionable `message` (what to fix:
  existing destination, missing destination parent, which budget, symlinks,
  platform gaps), and the manifest documents the root-inclusive directory
  count, both checksum encodings, and the private destination permissions
  (files 0600, directories 0700; source modes are not preserved).
- Node-side exec output shaping: `exec` and `exec_shell` accept `max_bytes`
  (per-stream raw byte cap, also bounded by `MCP_NODE_MAX_OUT`), `head_lines`
  and `tail_lines` (line selection before byte capping; mutually exclusive,
  LF-delimited, a final partial line counts). Shaped responses carry
  `truncated_*`, `output_complete`, `total_*_bytes`, `returned_*_bytes` and
  `omitted_*_bytes`, so long output no longer forces shell-side `| head` /
  `| tail` pipes or trips `OutputTooLong`. `exec_poll` and `exec_wait` accept
  `max_bytes` as a per-stream page size with `has_more_*` / `page_limited`
  markers; offsets advance only by consumed bytes.
- `read_file` line windows: optional `line_offset` (1-based) and `line_limit`
  return exactly the requested lines plus `total_lines`, so large files can
  be paged without downloading them whole.
- `write_file` plain-text content: `content` (UTF-8) is accepted as an
  exactly-one-of alternative to `content_b64`; passing both or neither fails
  with a structured error before any write.
- Durable session output is served from the on-disk spool: `exec_poll` /
  `exec_wait` on a durable session accept any absolute offset into the
  session's `stdout.log` / `stderr.log` (page-sized by `max_bytes`), so output
  beyond the in-memory window stays readable after the fact; `lost_*_bytes`
  is always 0 for durable sessions and `output_complete` never lies about it.
- `exec_poll` / `exec_wait` exit pages with undrained output (`done:true` with
  `has_more:true`) now carry an explicit `message` telling the caller to keep
  polling until `has_more` is false; the manifest documents the contract.
- Actionable `message` hints now cover `BadOffset`, `OutputTooLong`,
  `DurabilityDisabled`, `DurableMetadataTooLarge`, `StdinUnavailable` and
  `MissingArgv` (in addition to the codes that already carried them).
- Policy loading accepts absolute shell paths in `exec_argv0` by basename
  (e.g. `/bin/sh` satisfies the `exec_shell` spawnable-shell check), matching
  what the runtime gate always accepted; the refusal message names acceptable
  spellings.
- Durable session robustness, hardening pass: recovery quarantines
  any per-entry failure (an interrupted admission no longer aborts node
  startup); the per-session log cap is enforced on the combined stdout+stderr
  spool (matching the admission reservation) at refresh time and on a 1 Hz
  sweep, killing live over-budget sessions with a verified identity and
  `completion_reason: "output_cap"`; done sessions stay monitored (late
  growth is journaled and flagged, never signaled); `output_complete`
  additionally requires the settle window to have passed.

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
