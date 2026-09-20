//! Cross-platform process environment access.
//!
//! The daemon touches its environment in exactly three ways:
//!   * `loadEnviron(gpa)`            — one snapshot at startup, handed to
//!                                     `std.Io.Threaded` (child inheritance)
//!                                     and kept for all later lookups;
//!   * `environGet(arena, env, key)` — unified lookup over that snapshot;
//!   * `homeDir(arena, env)`         — source for "~" expansion.
//!
//! Snapshot source per platform:
//!   * Linux:   `/proc/self/environ`, read with a 1 MiB cap, degrading to
//!              empty on any read error.
//!   * macOS:   the `std.c.environ` extern, borrowed without copying. Apple
//!              targets always link libSystem, so the extern resolves, and
//!              the array lives for the whole process. Same counting pattern
//!              as `std.start`.
//!   * Windows: the global environment block (`std.process.Environ` with
//!              `.block = .global`). The PEB block is WTF-16 and may move
//!              when the environment changes, so std re-reads it under the
//!              PEB lock per lookup; all WTF-16 <-> WTF-8 conversion is
//!              std's (`Environ.getAlloc` / `createMap`), never hand-rolled.
//!
//! The environment is treated as immutable after startup (the daemon never
//! calls setenv), so one snapshot is sufficient and safe to share across
//! connection threads read-only.

const std = @import("std");
const builtin = @import("builtin");

const Allocator = std.mem.Allocator;

/// Upper bound on the Linux environ blob; the real environment is a few KB.
const ENVIRON_MAX_BYTES: usize = 1 << 20;

/// Linux procfs path supplying the initial process environment.
const ENVIRON_PROC_PATH = "/proc/self/environ";

/// Scratch size for the Linux read loop.
const READ_SCRATCH_SIZE: usize = 16 * 1024;

/// Snapshot the process environment once at startup.
///
/// Only allocation failure is propagated (`main` does
/// `try loadEnviron(...)`); every read/parse problem on Linux
/// degrades to `.empty`.
pub fn loadEnviron(gpa: Allocator) error{OutOfMemory}!std.process.Environ {
    switch (builtin.os.tag) {
        .linux => {
            const data = readFileAlloc(gpa, ENVIRON_PROC_PATH, ENVIRON_MAX_BYTES) catch return .empty;
            // `data` is intentionally never freed: the parsed block points
            // into it and the snapshot lives until process exit.
            if (data.len == 0) return .empty;
            // Parse loop: count NUL-terminated entries (skipping empty
            // runs), then build a sentinel slice of pointers into `data`.
            var count: usize = 0;
            var start: usize = 0;
            for (data, 0..) |b, i| {
                if (b != 0) continue;
                if (i > start) count += 1;
                start = i + 1;
            }
            if (count == 0) return .empty;
            const slice = try gpa.allocSentinel(?[*:0]const u8, count, null);
            var idx: usize = 0;
            start = 0;
            for (data, 0..) |b, i| {
                if (b != 0) continue;
                if (i > start) {
                    slice[idx] = @ptrCast(data.ptr + start);
                    idx += 1;
                }
                start = i + 1;
            }
            return .{ .block = .{ .slice = slice } };
        },
        .macos => {
            // Borrow the libSystem-owned array; no allocation, no copy.
            const c_environ = std.c.environ;
            var len: usize = 0;
            while (c_environ[len] != null) : (len += 1) {}
            return .{ .block = .{ .slice = c_environ[0..len :null] } };
        },
        .windows => {
            // WTF-16 global block from the PEB; std handles locking and
            // conversion at lookup time.
            return .{ .block = .global };
        },
        else => @compileError("os/env: unsupported target OS"),
    }
}

/// Unified environment lookup over the snapshot.
///
/// POSIX: zero-allocation walk of the stored block; the returned slice
/// borrows the snapshot and therefore outlives `arena`. Windows: std's
/// `Environ.getAlloc` does the WTF-16 -> WTF-8 conversion and the
/// case-insensitive match, allocating the value into `arena` (a full map
/// build per call — acceptable at startup and for the occasional "~"
/// expansion; revisit with a cached map if a hot path ever needs it).
///
/// Any failure (missing key, conversion error, OOM on Windows) degrades to
/// null, matching the Linux semantics where an unreadable environ
/// was indistinguishable from a missing variable.
pub fn environGet(arena: Allocator, environ: std.process.Environ, key: []const u8) ?[]const u8 {
    if (comptime builtin.os.tag == .windows) {
        return environ.getAlloc(arena, key) catch null;
    } else {
        // `arena` is referenced by the (comptime-dead) Windows branch above,
        // which the compiler counts as a use — an explicit discard would be
        // a "pointless discard" error. On POSIX it is simply never needed:
        // the returned slice borrows the process-lifetime snapshot.
        return environ.getPosix(key);
    }
}

/// Home directory used for "~" expansion.
///
/// POSIX: `$HOME` as-is; an empty value yields null. Windows:
/// `%USERPROFILE%` when set and non-empty, else `%HOMEDRIVE%` +
/// `%HOMEPATH%` concatenated (both required and non-empty), else null.
pub fn homeDir(arena: Allocator, environ: std.process.Environ) ?[]const u8 {
    if (comptime builtin.os.tag == .windows) {
        if (environGet(arena, environ, "USERPROFILE")) |profile| {
            if (profile.len > 0) return profile;
        }
        const drive = environGet(arena, environ, "HOMEDRIVE") orelse return null;
        const home_path = environGet(arena, environ, "HOMEPATH") orelse return null;
        if (drive.len == 0 or home_path.len == 0) return null;
        return std.mem.concat(arena, u8, &.{ drive, home_path }) catch null;
    } else {
        return environGet(arena, environ, "HOME");
    }
}

/// Read a whole small file, capped at `limit` bytes.
///
/// Referenced only from the `.linux` branch of `loadEnviron`, so it is
/// analyzed solely on Linux where these `std.posix` calls lower to raw
/// syscalls; macOS/Windows never see it (same lazy-analysis contract the
/// lazy-analysis call sites rely on in `main.zig`).
fn readFileAlloc(gpa: Allocator, path: []const u8, limit: usize) ![]u8 {
    const fd = try std.posix.openat(std.posix.AT.FDCWD, path, .{ .CLOEXEC = true }, 0);
    // std.posix.close was removed in 0.16; raw syscall result discarded,
    // matching the daemon's existing closeFd semantics.
    defer _ = std.os.linux.close(fd);
    var out: std.ArrayList(u8) = .empty;
    var buf: [READ_SCRATCH_SIZE]u8 = undefined;
    while (true) {
        const n = try std.posix.read(fd, &buf);
        if (n == 0) break;
        if (out.items.len + n > limit) return error.StreamTooLong;
        try out.appendSlice(gpa, buf[0..n]);
    }
    return out.toOwnedSlice(gpa);
}
