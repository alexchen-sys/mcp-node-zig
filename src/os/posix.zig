//! Shared POSIX implementation of the platform OS layer.
//!
//! Covers Linux (raw syscalls, no libc dependency) and the libc-backed
//! POSIX targets (macOS reaches this file through `darwin.zig`, which
//! re-exports this API; Darwin always links libSystem, so `std.c` externs
//! are safe there).
//!
//! Scope: `closeFd`, `sleepMs`, `writeAllFd` only. Process control,
//! sockets and sysinfo live in their own modules and must not be added here.

const std = @import("std");
const builtin = @import("builtin");

pub const fd_t = std.posix.fd_t;

/// Close a file descriptor, result intentionally discarded.
///
/// Matches the previous raw `_ = std.os.linux.close(fd)` call sites: on
/// Linux a failed close (incl. EINTR) leaves nothing recoverable to do, so
/// the error is swallowed by design.
pub fn closeFd(fd: fd_t) void {
    if (comptime builtin.os.tag == .linux) {
        _ = std.os.linux.close(fd);
    } else {
        // libc POSIX path (macOS et al.).
        _ = std.c.close(fd);
    }
}

/// Sleep approximately `ms` milliseconds on the calling thread.
///
/// Deliberately keeps the semantics of the two replaced raw-nanosleep call
/// sites (accept backoff, exec_wait poll tick): a single nanosleep shot,
/// early return on EINTR is tolerated because both callers re-check their
/// conditions in a loop. No Io handle required.
pub fn sleepMs(ms: u64) void {
    const sec = ms / 1000;
    const nsec = (ms % 1000) * std.time.ns_per_ms;
    if (comptime builtin.os.tag == .linux) {
        var ts = std.os.linux.timespec{ .sec = @intCast(sec), .nsec = @intCast(nsec) };
        _ = std.os.linux.nanosleep(&ts, null);
    } else {
        // libc POSIX path (macOS et al.).
        var ts = std.c.timespec{ .sec = @intCast(sec), .nsec = @intCast(nsec) };
        _ = std.c.nanosleep(&ts, null);
    }
}

/// File descriptor of the process standard error stream.
/// POSIX guarantees STDERR_FILENO == 2 on every POSIX target.
pub fn stderrFd() fd_t {
    return std.posix.STDERR_FILENO;
}

pub const WriteAllError = error{WriteFailed};

/// Write the whole buffer to `fd`, looping over short writes and EINTR.
///
/// Linux keeps the exact raw-syscall loop the daemon had in `main.zig`
/// (`std.os.linux.write` + errno switch) so behavior is bit-identical.
pub fn writeAllFd(fd: fd_t, bytes: []const u8) WriteAllError!void {
    var off: usize = 0;
    while (off < bytes.len) {
        if (comptime builtin.os.tag == .linux) {
            const rc = std.os.linux.write(fd, bytes.ptr + off, bytes.len - off);
            switch (std.os.linux.errno(rc)) {
                .SUCCESS => off += rc,
                .INTR => continue,
                else => return error.WriteFailed,
            }
        } else {
            // libc POSIX path (macOS et al.).
            // TODO(darwin): grade errno (EINTR retry vs hard failure) like the
            // Linux branch once the Darwin port lands; NOCANCEL is not applied
            // to write(2), so EINTR is theoretically reachable.
            const rc = std.c.write(fd, bytes.ptr + off, bytes.len - off);
            if (rc <= 0) return error.WriteFailed;
            off += @intCast(rc);
        }
    }
}
