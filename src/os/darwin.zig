//! macOS platform path.
//!
//! The generic POSIX implementation in `posix.zig` already covers Darwin:
//! Apple targets always link libSystem, so the `std.c` externs used there
//! resolve. This module is the seam for future Darwin-specific work and
//! today simply re-exports the shared POSIX implementation.

const posix = @import("posix.zig");

pub const fd_t = posix.fd_t;
pub const closeFd = posix.closeFd;
pub const sleepMs = posix.sleepMs;
pub const stderrFd = posix.stderrFd;
pub const writeAllFd = posix.writeAllFd;
pub const WriteAllError = posix.WriteAllError;
