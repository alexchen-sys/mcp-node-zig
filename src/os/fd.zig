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

/// fstat the freshly opened descriptor and refuse anything but a regular
/// file. A FIFO created by a local writer would park the calling thread
/// forever in open(2)/read(2); directories keep the legacy IsDir
/// taxonomy; every other kind answers
/// NotRegularFile.
fn fdRequireRegular(io: Io, fd: std.posix.fd_t) error{ IsDir, NotRegularFile, Unexpected }!void {
    const file: std.Io.File = .{ .handle = fd, .flags = .{ .nonblocking = false } };
    const st = file.stat(io) catch return error.Unexpected; // unverifiable: fail closed
    return switch (st.kind) {
        .file => {},
        .directory => error.IsDir,
        else => error.NotRegularFile,
    };
}

/// Drop O_NONBLOCK (set for the open so a FIFO target cannot park the
/// thread) before the blocking read/write loop. Regular files ignore the
/// flag entirely.
fn fdClearNonblock(fd: std.posix.fd_t) error{Unexpected}!void {
    if (comptime builtin.os.tag == .linux) {
        const rc = std.os.linux.fcntl(fd, std.posix.F.GETFL, 0);
        if (std.os.linux.errno(rc) != .SUCCESS) return error.Unexpected;
        const nonblock: usize = @as(u32, @bitCast(std.os.linux.O{ .NONBLOCK = true }));
        if (rc & nonblock == 0) return; // already blocking
        const rc2 = std.os.linux.fcntl(fd, std.posix.F.SETFL, rc & ~nonblock);
        if (std.os.linux.errno(rc2) != .SUCCESS) return error.Unexpected;
        return;
    }
    // Darwin (libc): the same F_GETFL/F_SETFL pair (variadic: the literal
    // command argument needs a fixed-size type).
    const fl = std.c.fcntl(@intCast(fd), std.posix.F.GETFL, @as(c_int, 0));
    if (fl == -1) return error.Unexpected;
    const nonblock: c_int = @bitCast(@as(u32, @bitCast(std.posix.O{ .NONBLOCK = true })));
    if (fl & nonblock == 0) return;
    const rc2 = std.c.fcntl(@intCast(fd), std.posix.F.SETFL, fl & ~nonblock);
    if (rc2 == -1) return error.Unexpected;
}

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
///
/// Non-regular targets (FIFO, socket, device) are
/// refused with `error.NotRegularFile` before the read loop instead of
/// parking the calling thread forever; a directory still answers IsDir.
pub fn readFileAlloc(arena: Allocator, io: Io, path: []const u8, limit: usize) ![]u8 {
    if (comptime builtin.os.tag == .windows) {
        const file = try std.Io.Dir.cwd().openFile(io, path, .{});
        defer file.close(io);
        // Windows: only disk files reach the read loop — a named-pipe
        // target answers NotRegularFile.
        if (!windowsHandleIsDiskFile(file.handle)) return error.NotRegularFile;
        return readFdLoop(arena, io, file.handle, limit);
    }
    // POSIX: O_NONBLOCK keeps a FIFO from parking this thread inside
    // open(2); the fstat check refuses non-regular targets and the flag
    // is dropped before the blocking read loop.
    const fd = try std.posix.openat(std.posix.AT.FDCWD, path, .{
        .ACCMODE = .RDONLY,
        .CLOEXEC = true,
        .NONBLOCK = true,
    }, 0);
    defer posix_impl.closeFd(fd);
    try fdRequireRegular(io, fd);
    try fdClearNonblock(fd);
    return readFdLoop(arena, io, fd, limit);
}

/// The EOF-delimited read loop shared by both arms of readFileAlloc.
fn readFdLoop(arena: Allocator, io: Io, fd: std.posix.fd_t, limit: usize) ![]u8 {
    const file: std.Io.File = .{ .handle = fd, .flags = .{ .nonblocking = false } };
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
    return writeFilePosix(io, path, data, mode);
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
    // Windows: only disk files reach the write loop —
    // a named-pipe target answers NotRegularFile.
    if (!windowsHandleIsDiskFile(file.handle)) return error.NotRegularFile;
    try file.writeStreamingAll(io, data);
}

/// POSIX (Linux, macOS): openat(2) applies `mode` exactly, subject to the
/// process umask.
fn writeFilePosix(io: Io, path: []const u8, data: []const u8, mode: std.posix.mode_t) !void {
    // O_NONBLOCK keeps a FIFO target from parking this
    // thread inside open(2); the fstat check refuses non-regular targets
    // and the flag is dropped before the write loop (regular files ignore
    // O_NONBLOCK, and O_TRUNC applied to them at open exactly as before).
    const file_fd = std.posix.openat(std.posix.AT.FDCWD, path, .{
        .ACCMODE = .WRONLY,
        .CREAT = true,
        .TRUNC = true,
        .CLOEXEC = true,
        .NONBLOCK = true,
    }, mode) catch |err| switch (err) {
        // ENXIO from O_WRONLY|O_NONBLOCK: the target exists but is a FIFO
        // with no reader — by definition not a regular file. The refusal
        // is prompt either way (that is the DoS fix); this keeps the
        // taxonomy uniform with the fstat path.
        error.NoDevice => return error.NotRegularFile,
        else => return err,
    };
    defer posix_impl.closeFd(file_fd);
    try fdRequireRegular(io, file_fd);
    try fdClearNonblock(file_fd);
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
        // The length probe below can fail; the freshly created handle must
        // not leak past this function on that path.
        errdefer file.close(io);
        return .{ .fd = file.handle, .pos = try fileLength(io, file.handle) };
    }
    const fd = try std.posix.openat(std.posix.AT.FDCWD, path, .{
        .ACCMODE = .RDWR,
        .CREAT = true,
        .APPEND = true,
        .CLOEXEC = true,
    }, 0o600);
    // Same leak guard: fileLength hits the OS (fstat) and can fail after the
    // open already succeeded.
    errdefer posix_impl.closeFd(fd);
    return .{ .fd = fd, .pos = try fileLength(io, fd) };
}

/// Exclusive-create open: fails with error.PathAlreadyExists when anything
/// already sits at `path`. Used for the fresh file after a rename (rotation,
/// quarantine): the pathname was deliberately removed, so finding a file
/// there means another writer — never append to a file we did not create.
pub fn createOpenExcl(io: Io, path: []const u8) !AppendLog {
    if (comptime builtin.os.tag == .windows) {
        const file = try std.Io.Dir.cwd().createFile(io, path, .{ .exclusive = true, .read = true });
        errdefer file.close(io);
        return .{ .fd = file.handle, .pos = 0 };
    }
    const fd = try std.posix.openat(std.posix.AT.FDCWD, path, .{
        .ACCMODE = .RDWR,
        .CREAT = true,
        .EXCL = true,
        .APPEND = true,
        .CLOEXEC = true,
    }, 0o600);
    errdefer posix_impl.closeFd(fd);
    return .{ .fd = fd, .pos = 0 };
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

/// fsync(2) the directory containing `path`: a rename/create of the entry
/// is metadata and needs its own flush to survive a crash. No-op on
/// Windows (no userspace directory sync; volume flush needs privileges).
pub fn syncParentDir(io: Io, path: []const u8) !void {
    _ = io;
    if (comptime builtin.os.tag == .windows) return;
    const parent = std.fs.path.dirname(path) orelse ".";
    const fd = try std.posix.openat(std.posix.AT.FDCWD, parent, .{
        .ACCMODE = .RDONLY,
        .DIRECTORY = true,
        .CLOEXEC = true,
    }, 0);
    defer posix_impl.closeFd(fd);
    return syncFile(fd);
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

/// Rename `old_path` to `new_path`, failing with error.TargetExists when
/// the target already exists instead of silently replacing it. Audit
/// history files are append-only evidence: overwriting one is always a
/// bug. Linux uses renameat2(RENAME_NOREPLACE) with a link+unlink fallback
/// for kernels without it; Darwin uses renamex_np(RENAME_EXCL); Windows
/// uses MoveFileExA without MOVEFILE_REPLACE_EXISTING.
pub fn renamePathNoReplace(io: Io, old_path: []const u8, new_path: []const u8) !void {
    _ = io;
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
    if (comptime builtin.os.tag == .windows) {
        // flags = 0: no MOVEFILE_REPLACE_EXISTING.
        if (MoveFileExA(old_z, new_z, 0) != 0) return;
        return switch (std.os.windows.GetLastError()) {
            .FILE_EXISTS, .ALREADY_EXISTS => error.TargetExists,
            else => error.RenameFailed,
        };
    }
    if (comptime builtin.os.tag == .linux) {
        const rc = std.os.linux.renameat2(std.posix.AT.FDCWD, old_z, std.posix.AT.FDCWD, new_z, .{ .NOREPLACE = true });
        switch (std.os.linux.errno(rc)) {
            .SUCCESS => return,
            .EXIST => return error.TargetExists,
            .NOSYS => return linkUnlinkNoReplace(old_z, new_z), // ancient kernel
            else => return error.RenameFailed,
        }
    }
    if (comptime builtin.os.tag == .macos) {
        // RENAME_EXCL = 0x4.
        if (renamex_np(old_z, new_z, 0x4) == 0) return;
        return switch (std.posix.errno(-1)) {
            .EXIST => error.TargetExists,
            else => error.RenameFailed,
        };
    }
    return linkUnlinkNoReplace(old_z, new_z);
}

/// POSIX no-replace rename via link(2)+unlink(2): link fails EEXIST when
/// the target is taken, and the unlink only runs after the link landed.
/// Raw syscalls on Linux (the default build links no libc), libc elsewhere.
fn linkUnlinkNoReplace(old_z: [*:0]const u8, new_z: [*:0]const u8) !void {
    if (comptime builtin.os.tag == .linux) {
        const rc = std.os.linux.link(old_z, new_z);
        switch (std.os.linux.errno(rc)) {
            .SUCCESS => {},
            .EXIST => return error.TargetExists,
            else => return error.RenameFailed,
        }
        const uc = std.os.linux.unlink(old_z);
        if (std.os.linux.errno(uc) != .SUCCESS) return error.RenameFailed;
        return;
    }
    if (std.c.link(old_z, new_z) != 0) {
        return switch (std.posix.errno(-1)) {
            .EXIST => error.TargetExists,
            else => error.RenameFailed,
        };
    }
    if (std.c.unlink(old_z) != 0) return error.RenameFailed;
}

extern "c" fn renamex_np(from: [*:0]const u8, to: [*:0]const u8, flags: c_uint) c_int;

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
extern "kernel32" fn GetFileType(hFile: std.os.windows.HANDLE) callconv(.winapi) u32;
extern "kernel32" fn SetFilePointerEx(
    hFile: std.os.windows.HANDLE,
    liDistanceToMove: i64,
    lpNewFilePointer: ?*i64,
    dwMoveMethod: u32,
) callconv(.winapi) i32;

/// FILE_TYPE_DISK (winbase.h): the only handle kind the legacy read/write
/// loops accept (a named-pipe or char device target would park the
/// calling thread).
const W_FILE_TYPE_DISK: u32 = 0x0001;

/// Windows-only body; the POSIX arms of readFileAlloc/writeFile never
/// reference it (comptime-gated call sites keep the extern out of the
/// non-Windows links).
fn windowsHandleIsDiskFile(handle: std.posix.fd_t) bool {
    if (comptime builtin.os.tag != .windows) return false; // unreachable
    return GetFileType(handle) == W_FILE_TYPE_DISK;
}

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

// ---------------------------------------------------------------------------
// Tests (Linux execution; other targets skip — CI runs them on Linux)
// ---------------------------------------------------------------------------

/// mkfifo(3) via mknod(S_IFIFO) — same fixture rationale as secure.zig.
fn mkfifoLinuxTest(path: []const u8) !void {
    var buf: [std.fs.max_path_bytes + 1]u8 = undefined;
    if (path.len > std.fs.max_path_bytes) return error.NameTooLong;
    @memcpy(buf[0..path.len], path);
    buf[path.len] = 0;
    const rc = std.os.linux.mknod(buf[0..path.len :0], 0o010000 | 0o644, 0);
    switch (std.os.linux.errno(rc)) {
        .SUCCESS, .EXIST => return,
        else => return error.Unexpected,
    }
}

/// Hang watchdog: true once the worker reported. A blocked open(2)/read(2)
/// on a FIFO never completes; the watchdog turns that into a test failure
/// instead of a wedged CI.
const WatchOutcomeFd = struct {
    err: ?anyerror = null,
    done: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
};

fn watchReportFd(out: *WatchOutcomeFd, err: ?anyerror) void {
    out.err = err;
    out.done.store(true, .release);
}

fn waitOutcomeTest(out: *WatchOutcomeFd, timeout_ms: u64) bool {
    var waited: u64 = 0;
    while (waited < timeout_ms) {
        if (out.done.load(.acquire)) return true;
        posix_impl.sleepMs(5);
        waited += 5;
    }
    return out.done.load(.acquire);
}

test "fd: readFileAlloc refuses a fifo promptly instead of hanging" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = Io.Threaded.global_single_threaded.io();
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const root = try arena.dupe(u8, buf[0..try tmp.dir.realPathFile(io, ".", &buf)]);
    const fifo_path = try std.mem.concat(arena, u8, &.{ root, "/pipe" });
    try mkfifoLinuxTest(fifo_path);

    // A plain open+read on a FIFO with no writer parks the calling
    // thread forever; the reader must refuse non-regular targets
    // promptly.
    var outcome = WatchOutcomeFd{};
    const t = try std.Thread.spawn(.{}, struct {
        fn run(io_: Io, arena_: std.mem.Allocator, path: []const u8, out: *WatchOutcomeFd) void {
            if (readFileAlloc(arena_, io_, path, 1 << 20)) |data| {
                watchReportFd(out, error.TestUnexpectedResult);
                _ = data;
            } else |err| watchReportFd(out, err);
        }
    }.run, .{ io, arena, fifo_path, &outcome });
    t.detach();
    try std.testing.expect(waitOutcomeTest(&outcome, 2000)); // never a hang
    try std.testing.expectEqual(@as(anyerror, error.NotRegularFile), outcome.err.?);
}

test "fd: writeFile refuses a fifo promptly instead of hanging" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = Io.Threaded.global_single_threaded.io();

    var buf: [std.fs.max_path_bytes]u8 = undefined;
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const root = try arena.dupe(u8, buf[0..try tmp.dir.realPathFile(io, ".", &buf)]);
    const fifo_path = try std.mem.concat(arena, u8, &.{ root, "/pipe" });
    try mkfifoLinuxTest(fifo_path);

    // Write side of the same defect: O_WRONLY|O_CREAT on a FIFO with no
    // reader blocks forever; the legacy writer must refuse non-regular
    // targets promptly.
    var outcome = WatchOutcomeFd{};
    const t = try std.Thread.spawn(.{}, struct {
        fn run(io_: Io, path: []const u8, out: *WatchOutcomeFd) void {
            writeFile(io_, path, "x", 0o644) catch |err| {
                watchReportFd(out, err);
                return;
            };
            watchReportFd(out, error.TestUnexpectedResult);
        }
    }.run, .{ io, fifo_path, &outcome });
    t.detach();
    try std.testing.expect(waitOutcomeTest(&outcome, 2000)); // never a hang
    try std.testing.expectEqual(@as(anyerror, error.NotRegularFile), outcome.err.?);
}
