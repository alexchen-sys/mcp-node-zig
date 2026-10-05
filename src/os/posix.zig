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
/// A failed close (incl. EINTR) leaves nothing recoverable to do, so the
/// error is swallowed by design.
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
/// A single nanosleep shot; an early return on EINTR is fine because both
/// callers (accept backoff, exec_wait poll tick) re-check their conditions
/// in a loop. No Io handle required.
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

/// File descriptor of the process standard output stream.
pub fn stdoutFd() fd_t {
    return std.posix.STDOUT_FILENO;
}

/// File descriptor of the process standard error stream.
/// POSIX guarantees STDERR_FILENO == 2 on every POSIX target.
pub fn stderrFd() fd_t {
    return std.posix.STDERR_FILENO;
}

pub const WriteAllError = error{WriteFailed};

/// Write the whole buffer to `fd`, looping over short writes and EINTR.
///
/// Linux uses the raw syscall (`std.os.linux.write` + errno switch).
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
            // Linux branch; write(2) here is not the NOCANCEL variant, so
            // EINTR is theoretically reachable.
            const rc = std.c.write(fd, bytes.ptr + off, bytes.len - off);
            if (rc <= 0) return error.WriteFailed;
            off += @intCast(rc);
        }
    }
}
