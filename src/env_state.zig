//! The daemon's single process-global: the environment snapshot.
//! It is written exactly once, in `main`, before the first connection
//! thread spawns, and only read afterwards (see the contract comment on
//! `process_environ`).

const std = @import("std");

/// Process environment snapshot, loaded once in `main` before any
/// connection thread spawns and only read afterwards (the daemon never
/// calls setenv), so sharing it across threads needs no synchronization.
pub var process_environ: std.process.Environ = .empty;
