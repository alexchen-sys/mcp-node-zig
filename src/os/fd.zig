//! Cross-platform file I/O helpers.
//!
//! `readFileAlloc` is implemented entirely over the `std.Io` interface and
//! therefore works on every target. `writeFile` carries real platform
//! knowledge: POSIX applies the permission bits exactly via openat(2),
//! Windows goes through `Io.Dir.createFile` and ignores the mode (NTFS
//! permissions are ACL-based; a new file inherits the directory's ACLs).

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const Io = std.Io;

const posix_impl = @import("posix.zig");

/// Read an entire file into `arena`, failing with `error.StreamTooLong`
/// once the content exceeds `limit` bytes.
///
/// Reads until EOF instead of trusting the stat size: Linux /proc entries
/// report a zero size yet yield content, so any size-based fast path would
/// silently return empty data there. EOF is delivered by the Io interface
/// as `error.EndOfStream`.
///
/// Relative paths resolve against the process cwd (legacy AT.FDCWD
/// semantics). `Io.Dir.cwd().openFile` is exactly what
/// `Io.Dir.openFileAbsolute` calls (minus its absolute-path assert), and
/// handles absolute paths correctly on POSIX and Windows alike, so both
/// path shapes keep working.
pub fn readFileAlloc(arena: Allocator, io: Io, path: []const u8, limit: usize) ![]u8 {
    const file = try std.Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    var out: std.ArrayList(u8) = .empty;
    var buf: [16 * 1024]u8 = undefined;
    while (true) {
        const n = file.readStreaming(io, &.{buf[0..]}) catch |err| switch (err) {
            error.EndOfStream => break,
            else => |e| return e,
        };
        if (n == 0) continue; // 0 is legal mid-stream; only EndOfStream ends the file
        if (out.items.len + n > limit) return error.StreamTooLong;
        try out.appendSlice(arena, buf[0..n]);
    }
    return out.items;
}

/// Create-or-truncate `path` and write `data` in full.
///
/// `mode` is the requested permission set, validated by the caller to
/// 0..0o7777 (the tool layer rejects wider values with `error.BadMode`).
///
/// * POSIX (Linux, macOS): `mode` is applied exactly as the openat(2)
///   creation mode, subject to the process umask — identical to the
///   pre-port behavior.
/// * Windows: `mode` is IGNORED. NTFS has no POSIX permission bits; the
///   file inherits the containing directory's ACLs. Callers must not rely
///   on `mode` having any effect on this target.
pub fn writeFile(io: Io, path: []const u8, data: []const u8, mode: std.posix.mode_t) !void {
    // Split bodies rather than a comptime-if with a `_ = mode` discard: the
    // discard check is ZIR-level and would fire on POSIX (mode used) while
    // the unused-parameter check would fire on Windows without it.
    if (comptime builtin.os.tag == .windows) {
        return writeFileWindows(io, path, data);
    }
    return writeFilePosix(path, data, mode);
}

/// Windows: NTFS has no POSIX permission bits; the created file inherits the
/// containing directory's ACLs and `mode` is intentionally dropped by the
/// dispatcher above (documented no-op).
///
/// createFile via cwd() handles both absolute and relative paths
/// (createFileAbsolute asserts the absolute shape). truncate=true and
/// exclusive=false are the defaults — O_CREAT|O_TRUNC semantics.
fn writeFileWindows(io: Io, path: []const u8, data: []const u8) !void {
    const file = try std.Io.Dir.cwd().createFile(io, path, .{});
    defer file.close(io);
    try file.writeStreamingAll(io, data);
}

/// POSIX (Linux, macOS): openat(2) applies `mode` exactly, subject to the
/// process umask — bit-identical to the pre-port daemon.
fn writeFilePosix(path: []const u8, data: []const u8, mode: std.posix.mode_t) !void {
    const file_fd = try std.posix.openat(std.posix.AT.FDCWD, path, .{
        .ACCMODE = .WRONLY,
        .CREAT = true,
        .TRUNC = true,
        .CLOEXEC = true,
    }, mode);
    defer posix_impl.closeFd(file_fd);
    try posix_impl.writeAllFd(file_fd, data);
}
