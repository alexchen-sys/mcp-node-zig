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
///   creation mode, subject to the process umask (open(2) semantics).
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
/// process umask.
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

// ---------------------------------------------------------------------------
// Append-mode log file primitives (audit log)
// ---------------------------------------------------------------------------

/// An append-only log file handle. POSIX relies on O_APPEND (the kernel
/// positions every write at the end); Windows tracks the end offset and
/// issues positioned writes, which a single-writer file makes equivalent.
pub const AppendLog = struct {
    fd: std.posix.fd_t,
    /// End-of-file offset, maintained for positioned writes (Windows) and
    /// for the writer's size accounting; refreshed from the OS at open.
    pos: u64,
};

/// Open `path` for appending, creating it with mode 0600 when missing.
/// The descriptor is also readable (O_RDWR) so the startup tail recovery
/// can pread(2) without a second open. Windows goes through
/// `Io.Dir.createFile` without truncation; NTFS ignores the mode (the file
/// inherits the directory ACLs), as documented on writeFile.
pub fn appendOpen(io: Io, path: []const u8) !AppendLog {
    if (comptime builtin.os.tag == .windows) {
        const file = try std.Io.Dir.cwd().createFile(io, path, .{ .truncate = false, .read = true });
        return .{ .fd = file.handle, .pos = try fileLength(io, file.handle) };
    }
    const fd = try std.posix.openat(std.posix.AT.FDCWD, path, .{
        .ACCMODE = .RDWR,
        .CREAT = true,
        .APPEND = true,
        .CLOEXEC = true,
    }, 0o600);
    return .{ .fd = fd, .pos = try fileLength(io, fd) };
}

/// Write `bytes` at the end of the log. POSIX relies on O_APPEND; Windows
/// issues a positioned write at the tracked end offset (equivalent for the
/// single-writer log).
pub fn appendWrite(io: Io, log: *AppendLog, bytes: []const u8) !void {
    if (comptime builtin.os.tag == .windows) {
        const file: std.Io.File = .{ .handle = log.fd, .flags = .{ .nonblocking = false } };
        try file.writePositionalAll(io, bytes, log.pos);
    } else {
        try posix_impl.writeAllFd(log.fd, bytes);
    }
    log.pos += bytes.len;
}

/// fsync(2) / FlushFileBuffers: flush file content and metadata to disk.
pub fn syncFile(fd: std.posix.fd_t) !void {
    if (comptime builtin.os.tag == .windows) {
        return windowsFlushFileBuffers(fd);
    } else if (comptime builtin.os.tag == .linux) {
        while (true) {
            const rc = std.os.linux.fsync(fd);
            switch (std.os.linux.errno(rc)) {
                .SUCCESS => return,
                .INTR => continue,
                else => return error.SyncFailed,
            }
        }
    } else {
        if (std.c.fsync(fd) != 0) return error.SyncFailed;
    }
}

/// Current size of the open file `fd` in bytes, via the Io stat vtable
/// (fstat/statx under the hood; works on every target).
pub fn fileLength(io: Io, fd: std.posix.fd_t) !u64 {
    const file: std.Io.File = .{ .handle = fd, .flags = .{ .nonblocking = false } };
    const st = try file.stat(io);
    return st.size;
}

/// Read up to `buf.len` bytes from `offset` without moving the write
/// position (pread(2)/positional ReadFile via the Io vtable).
pub fn preadAt(io: Io, fd: std.posix.fd_t, buf: []u8, offset: u64) !usize {
    const file: std.Io.File = .{ .handle = fd, .flags = .{ .nonblocking = false } };
    return file.readPositional(io, &.{buf}, offset);
}

/// Truncate the open file `fd` to `len` bytes (drop a torn tail record).
pub fn truncFile(fd: std.posix.fd_t, len: u64) !void {
    if (comptime builtin.os.tag == .windows) {
        try windowsSetFilePos(fd, len);
        if (SetEndOfFile(fd) == 0) return error.TruncateFailed;
        return;
    } else if (comptime builtin.os.tag == .linux) {
        while (true) {
            const rc = std.os.linux.ftruncate(fd, @intCast(len));
            switch (std.os.linux.errno(rc)) {
                .SUCCESS => return,
                .INTR => continue,
                else => return error.TruncateFailed,
            }
        }
    } else {
        if (std.c.ftruncate(fd, @intCast(len)) != 0) return error.TruncateFailed;
    }
}

/// Rename `old_path` to `new_path`, replacing an existing target.
pub fn renamePath(io: Io, old_path: []const u8, new_path: []const u8) !void {
    if (comptime builtin.os.tag == .windows) {
        _ = io;
        return windowsMoveFile(old_path, new_path);
    }
    // The raw syscalls want sentinel-terminated paths.
    var old_buf: [std.fs.max_path_bytes + 1]u8 = undefined;
    var new_buf: [std.fs.max_path_bytes + 1]u8 = undefined;
    if (old_path.len > std.fs.max_path_bytes or new_path.len > std.fs.max_path_bytes)
        return error.NameTooLong;
    @memcpy(old_buf[0..old_path.len], old_path);
    old_buf[old_path.len] = 0;
    @memcpy(new_buf[0..new_path.len], new_path);
    new_buf[new_path.len] = 0;
    const old_z: [*:0]const u8 = old_buf[0..old_path.len :0];
    const new_z: [*:0]const u8 = new_buf[0..new_path.len :0];
    if (comptime builtin.os.tag == .linux) {
        const rc = std.os.linux.renameat(std.posix.AT.FDCWD, old_z, std.posix.AT.FDCWD, new_z);
        switch (std.os.linux.errno(rc)) {
            .SUCCESS => return,
            else => return error.RenameFailed,
        }
    } else {
        if (std.c.rename(old_z, new_z) != 0) return error.RenameFailed;
    }
}

/// Fail when `path` exists and grants group/other access: key material must
/// be 0600. POSIX only; on Windows (NTFS ACLs) the check is a documented
/// no-op, same rule as the mode parameter of writeFile.
pub fn checkPrivateFileMode(io: Io, path: []const u8) !void {
    // Two functions like writeFile: the discard check is ZIR-level, so the
    // Windows no-op must not share a body with the POSIX use of the params.
    if (comptime builtin.os.tag == .windows) {
        return checkPrivateFileModeWindows(io, path);
    }
    return checkPrivateFileModePosix(io, path);
}

fn checkPrivateFileModeWindows(io: Io, path: []const u8) !void {
    _ = io;
    _ = path;
}

fn checkPrivateFileModePosix(io: Io, path: []const u8) !void {
    const file = std.Io.Dir.cwd().openFile(io, path, .{}) catch |err| switch (err) {
        error.FileNotFound => return, // creation will apply 0600
        else => return err,
    };
    defer file.close(io);
    const st = try file.stat(io);
    if (st.permissions.toMode() & 0o077 != 0) return error.InsecurePermissions;
}

// --- Windows kernel32 helpers (kept here: the file-I/O platform seam) ------

extern "kernel32" fn FlushFileBuffers(hFile: std.os.windows.HANDLE) callconv(.winapi) i32;
extern "kernel32" fn SetEndOfFile(hFile: std.os.windows.HANDLE) callconv(.winapi) i32;
extern "kernel32" fn SetFilePointerEx(
    hFile: std.os.windows.HANDLE,
    liDistanceToMove: i64,
    lpNewFilePointer: ?*i64,
    dwMoveMethod: u32,
) callconv(.winapi) i32;
extern "kernel32" fn MoveFileExA(
    lpExistingFileName: [*:0]const u8,
    lpNewFileName: [*:0]const u8,
    dwFlags: u32,
) callconv(.winapi) i32;
fn windowsFlushFileBuffers(fd: std.posix.fd_t) !void {
    if (FlushFileBuffers(fd) == 0) return error.SyncFailed;
}

fn windowsSetFilePos(fd: std.posix.fd_t, pos: u64) !void {
    if (SetFilePointerEx(fd, @bitCast(pos), null, 0) == 0) return error.SeekFailed;
}

fn windowsMoveFile(old_path: []const u8, new_path: []const u8) !void {
    var old_buf: [std.fs.max_path_bytes + 1]u8 = undefined;
    var new_buf: [std.fs.max_path_bytes + 1]u8 = undefined;
    if (old_path.len > std.fs.max_path_bytes or new_path.len > std.fs.max_path_bytes)
        return error.NameTooLong;
    @memcpy(old_buf[0..old_path.len], old_path);
    old_buf[old_path.len] = 0;
    @memcpy(new_buf[0..new_path.len], new_path);
    new_buf[new_path.len] = 0;
    // MOVEFILE_REPLACE_EXISTING = 0x1.
    if (MoveFileExA(old_buf[0..old_path.len :0], new_buf[0..new_path.len :0], 0x1) == 0)
        return error.RenameFailed;
}
