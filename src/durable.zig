//! Version-one durable session records. Wire offsets are independent of ABI alignment.
const std = @import("std");
const builtin = @import("builtin");
const os = @import("os.zig");
const linux = std.os.linux;
const fd_t = std.posix.fd_t;

pub const HEADER_SIZE = 160;
pub const INDEX_SIZE = 8192;
pub const REGION_LIMIT = 12 * 1024;
pub const OsTag = enum(u8) { linux, macos, windows };
pub const State = enum(u8) { running, done, interrupted };
pub const CompletionReason = enum { output_cap };
pub const OUTPUT_CAP_FLAG: u8 = 16;
pub const Reason = enum(u8) { reaped_ttl, closed_by_client, killed, evicted_capacity };
const zeros32 = [_]u8{0} ** 32;
const Corrupt = error.CorruptDurableRecord;

fn put(comptime T: type, bytes: []u8, off: usize, value: T) void {
    std.mem.writeInt(T, bytes[off..][0..@sizeOf(T)], value, .little);
}

fn get(comptime T: type, bytes: []const u8, off: usize) T {
    return std.mem.readInt(T, bytes[off..][0..@sizeOf(T)], .little);
}

fn zero(bytes: []const u8) bool {
    for (bytes) |b| if (b != 0) return false;
    return true;
}

fn seal(bytes: []u8) void {
    std.crypto.hash.sha2.Sha256.hash(bytes[0 .. bytes.len - 32], bytes[bytes.len - 32 ..][0..32], .{});
}

fn verified(bytes: []const u8) bool {
    if (bytes.len < 32) return false;
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes[0 .. bytes.len - 32], &digest, .{});
    return std.mem.eql(u8, &digest, bytes[bytes.len - 32 ..]);
}

pub const Tombstone = struct {
    id: u64 = 0,
    owner_hash: [32]u8 = zeros32,
    reason: Reason = .reaped_ttl,
};

pub const Index = struct {
    next_id: u64 = 1,
    tombstones: [128]Tombstone = @splat(.{}),

    pub fn push(self: *Index, t: Tombstone) void {
        std.mem.copyBackwards(Tombstone, self.tombstones[1..], self.tombstones[0..127]);
        self.tombstones[0] = t;
    }

    pub fn expired(self: *const Index, id: u64, owner: [32]u8) bool {
        if (id == 0) return false;
        for (self.tombstones) |t| if (t.id == id) return std.mem.eql(u8, &owner, &t.owner_hash);
        return false;
    }

    pub fn encode(self: *const Index) [INDEX_SIZE]u8 {
        var bytes: [INDEX_SIZE]u8 = @splat(0);
        @memcpy(bytes[0..4], "MCNI");
        put(u32, &bytes, 4, 1);
        put(u64, &bytes, 8, self.next_id);
        for (self.tombstones, 0..) |t, i| {
            const off = 32 + i * 48;
            put(u64, &bytes, off, t.id);
            @memcpy(bytes[off + 8 ..][0..32], &t.owner_hash);
            bytes[off + 40] = @intFromEnum(t.reason);
        }
        seal(&bytes);
        return bytes;
    }

    pub fn decode(bytes: []const u8) !Index {
        if (bytes.len != INDEX_SIZE or !verified(bytes)) return Corrupt;
        if (!std.mem.eql(u8, bytes[0..4], "MCNI") or get(u32, bytes, 4) != 1) return Corrupt;
        if (!zero(bytes[16..32]) or !zero(bytes[6176..8160])) return Corrupt;
        var idx: Index = .{ .next_id = get(u64, bytes, 8) };
        if (idx.next_id == 0) return Corrupt;
        for (&idx.tombstones, 0..) |*t, i| {
            const off = 32 + i * 48;
            if (!zero(bytes[off + 41 ..][0..7]) or bytes[off + 40] > 3) return Corrupt;
            t.* = .{ .id = get(u64, bytes, off), .owner_hash = bytes[off + 8 ..][0..32].*, .reason = @enumFromInt(bytes[off + 40]) };
            if (t.id == 0 and (!zero(&t.owner_hash) or t.reason != .reaped_ttl)) return Corrupt;
        }
        return idx;
    }
};

pub const Meta = struct {
    state: State = .running,
    flags: u8 = 0,
    os_tag: OsTag = .linux,
    session_id: u64 = 1,
    pid: i64 = 0,
    pgid: i64 = 0,
    start_time_ticks: u64 = 0,
    boot_id: [16]u8 = @splat(0),
    started_us: i64 = 0,
    ended_us: i64 = 0,
    exit_code: i64 = 0,
    max_out: u64 = 0,
    final_stdout_total: u64 = 0,
    final_stderr_total: u64 = 0,
    owner_hash: [32]u8 = zeros32,

    pub fn regionSize(cwd: []const u8, argv: []const []const u8) !usize {
        if (argv.len > 256 or cwd.len > REGION_LIMIT) return error.DurableMetadataTooLarge;
        var size = cwd.len;
        for (argv) |arg| {
            if (arg.len > REGION_LIMIT or size > REGION_LIMIT - 4 or arg.len > REGION_LIMIT - size - 4) return error.DurableMetadataTooLarge;
            size += 4 + arg.len;
        }
        return size;
    }

    pub fn encode(self: Meta, a: std.mem.Allocator, cwd: []const u8, argv: []const []const u8) ![]u8 {
        const size = try regionSize(cwd, argv);
        const bytes = try a.alloc(u8, HEADER_SIZE + size + 32);
        @memset(bytes, 0);
        @memcpy(bytes[0..4], "MCPS");
        put(u16, bytes, 4, 1);
        bytes[6] = @intFromEnum(self.state);
        bytes[7] = self.flags;
        bytes[8] = @intFromEnum(self.os_tag);
        put(u64, bytes, 10, self.session_id);
        put(i64, bytes, 18, self.pid);
        put(i64, bytes, 26, self.pgid);
        put(u64, bytes, 34, self.start_time_ticks);
        @memcpy(bytes[42..58], &self.boot_id);
        put(i64, bytes, 58, self.started_us);
        put(i64, bytes, 66, self.ended_us);
        put(i64, bytes, 74, if (self.flags & 1 != 0) self.exit_code else 0);
        put(u64, bytes, 82, self.max_out);
        put(u64, bytes, 90, self.final_stdout_total);
        put(u64, bytes, 98, self.final_stderr_total);
        @memcpy(bytes[106..138], &self.owner_hash);
        put(u32, bytes, 138, @intCast(argv.len));
        put(u32, bytes, 142, @intCast(cwd.len));
        @memcpy(bytes[160..][0..cwd.len], cwd);
        var off: usize = 160 + cwd.len;
        for (argv) |arg| {
            put(u32, bytes, off, @intCast(arg.len));
            off += 4;
            @memcpy(bytes[off..][0..arg.len], arg);
            off += arg.len;
        }
        seal(bytes);
        return bytes;
    }

    pub const Decoded = struct { meta: Meta, cwd: []const u8, argv_region: []const u8, argc: u32 };
    pub fn decode(bytes: []const u8) !Decoded {
        if (bytes.len < 192 or bytes.len > 192 + REGION_LIMIT or !verified(bytes)) return Corrupt;
        if (!std.mem.eql(u8, bytes[0..4], "MCPS") or get(u16, bytes, 4) != 1) return Corrupt;
        if (bytes[6] > 2 or bytes[7] & 0xe0 != 0 or bytes[8] > 2 or bytes[9] != 0 or !zero(bytes[146..160])) return Corrupt;
        if (bytes[8] == 2 and !zero(bytes[50..58])) return Corrupt;
        if (bytes[7] & 1 == 0 and get(i64, bytes, 74) != 0) return Corrupt;
        const argc = get(u32, bytes, 138);
        const cwd_len = get(u32, bytes, 142);
        const end = bytes.len - 32;
        if (argc > 256 or cwd_len > end - 160 or get(u64, bytes, 10) == 0) return Corrupt;
        var off: usize = 160 + cwd_len;
        for (0..argc) |_| {
            if (end - off < 4) return Corrupt;
            const len = get(u32, bytes, off);
            off += 4;
            if (len > end - off) return Corrupt;
            off += len;
        }
        if (off != end) return Corrupt;
        return .{ .cwd = bytes[160..][0..cwd_len], .argc = argc, .argv_region = bytes[160 + cwd_len .. end], .meta = .{
            .state = @enumFromInt(bytes[6]),
            .flags = bytes[7],
            .os_tag = @enumFromInt(bytes[8]),
            .session_id = get(u64, bytes, 10),
            .pid = get(i64, bytes, 18),
            .pgid = get(i64, bytes, 26),
            .start_time_ticks = get(u64, bytes, 34),
            .boot_id = bytes[42..58].*,
            .started_us = get(i64, bytes, 58),
            .ended_us = get(i64, bytes, 66),
            .exit_code = get(i64, bytes, 74),
            .max_out = get(u64, bytes, 82),
            .final_stdout_total = get(u64, bytes, 90),
            .final_stderr_total = get(u64, bytes, 98),
            .owner_hash = bytes[106..138].*,
        } };
    }
};

pub fn uuidBootId(raw: []const u8) ![16]u8 {
    const text = std.mem.trim(u8, raw, "\r\n");
    if (text.len != 36) return error.InvalidBootId;
    var result: [16]u8 = undefined;
    var n: usize = 0;
    var i: usize = 0;
    while (i < text.len) {
        if (i == 8 or i == 13 or i == 18 or i == 23) {
            if (text[i] != '-') return error.InvalidBootId;
            i += 1;
        } else {
            result[n] = std.fmt.parseInt(u8, text[i..][0..2], 16) catch return error.InvalidBootId;
            n += 1;
            i += 2;
        }
    }
    return result;
}

pub fn windowsBootId(time: u64) [16]u8 {
    var result: [16]u8 = @splat(0);
    put(u64, &result, 0, time);
    return result;
}

pub fn reservation(cap: u64) !u64 {
    const twice = std.math.mul(u64, cap, 2) catch return error.DurableCapacityExceeded;
    return std.math.add(u64, twice, 80 * 1024) catch return error.DurableCapacityExceeded;
}

pub const Disk = struct {
    io: std.Io,
    root: fd_t,
    sessions: fd_t,
    lock: fd_t,
    index: Index,
    max_bytes: u64,
    reserved: u64 = 0,
    failed: bool = false,
    test_available_bytes: ?u64 = null,
    mutex: std.Io.Mutex = .init,

    pub fn open(io: std.Io, path: []const u8, max_bytes: u64) !Disk {
        if (comptime builtin.os.tag != .linux) return error.DurabilityUnsupported;
        if (!std.fs.path.isAbsolute(path)) return error.InvalidConfig;
        // Walk each component without following links; the final object is
        // checked through its descriptor, not by a separate pathname stat.
        var current = try std.posix.openat(std.posix.AT.FDCWD, "/", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true, .NOFOLLOW = true }, 0);
        errdefer os.closeFd(current);
        var parts = std.mem.tokenizeScalar(u8, path, '/');
        while (parts.next()) |part| {
            if (std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, "..")) return error.InvalidConfig;
            const last = parts.peek() == null;
            if (last) try makeDir(current, part);
            const next = try std.posix.openat(current, part, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true, .NOFOLLOW = true }, 0);
            os.closeFd(current);
            current = next;
        }
        try checkPrivate(current, true);
        const lock = try openFile(current, "lock", true);
        errdefer os.closeFd(lock);
        if (linux.errno(linux.flock(lock, 2 | 4)) != .SUCCESS) return error.StateDirLocked;
        try makeDir(current, "sessions");
        const sessions = try openDir(current, "sessions");
        errdefer os.closeFd(sessions);
        var disk: Disk = .{ .io = io, .root = current, .sessions = sessions, .lock = lock, .index = .{}, .max_bytes = max_bytes };
        const bytes = disk.readRecord(current, "index.bin", INDEX_SIZE) catch |err| switch (err) {
            error.FileNotFound => {
                // A missing index is only fresh when there are no job dirs.
                var dir: std.Io.Dir = .{ .handle = sessions };
                var it = dir.iterate();
                if (try it.next(io) != null) return error.CorruptDurableRecord;
                try disk.writeIndex();
                return disk;
            },
            else => return err,
        };
        defer std.heap.page_allocator.free(bytes);
        disk.index = try Index.decode(bytes);
        return disk;
    }

    pub fn close(self: *Disk) void {
        os.closeFd(self.sessions);
        os.closeFd(self.lock);
        os.closeFd(self.root);
    }

    pub fn allocId(self: *Disk) !u64 {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.failed) return error.DurableStorageFailed;
        const id = self.index.next_id;
        if (id >= std.math.maxInt(i64)) return error.DurableCapacityExceeded;
        self.index.next_id += 1;
        try self.writeIndex();
        return id;
    }

    pub fn writeIndex(self: *Disk) !void {
        const bytes = self.index.encode();
        self.atomicWrite(self.root, "index.tmp", "index.bin", &bytes) catch |err| {
            self.failed = true;
            return err;
        };
    }

    pub fn reserve(self: *Disk, cap: u64) !void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const bytes = try reservation(cap);
        if (self.failed) return error.DurableStorageFailed;
        if (self.reserved > self.max_bytes or bytes > self.max_bytes - self.reserved) return error.DurableCapacityExceeded;
        const available = if (builtin.is_test and self.test_available_bytes != null)
            self.test_available_bytes.?
        else
            try filesystemAvailable(self.root);
        if (available < bytes) return error.DurabilityFull;
        self.reserved += bytes;
    }

    pub fn unreserve(self: *Disk, cap: u64) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.reserved -|= reservation(cap) catch return;
    }

    pub fn atomicWrite(self: *Disk, dir: fd_t, tmp: [:0]const u8, name: [:0]const u8, bytes: []const u8) !void {
        if (comptime builtin.os.tag != .linux) return error.DurabilityUnsupported;
        // EXCL prevents stale or attacker-created tmp objects from becoming
        // writable aliases. A stale private regular tmp is safely unlinked.
        if (openFile(dir, tmp, false)) |stale| {
            os.closeFd(stale);
            if (linux.errno(linux.unlinkat(dir, tmp, 0)) != .SUCCESS) return error.DurableStorageFailed;
        } else |err| if (err != error.FileNotFound) return err;
        const fd = try std.posix.openat(dir, tmp, .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .NOFOLLOW = true, .CLOEXEC = true }, 0o600);
        defer os.closeFd(fd);
        try checkPrivate(fd, false);
        try os.writeAllFd(fd, bytes);
        try syncFd(fd);
        if (linux.errno(linux.renameat(dir, tmp, dir, name)) != .SUCCESS) return error.DurableStorageFailed;
        try syncFd(dir);
        _ = self;
    }

    pub fn readRecord(self: *Disk, dir: fd_t, name: []const u8, limit: usize) ![]u8 {
        const fd = try openFile(dir, name, false);
        defer os.closeFd(fd);
        const file = asFile(fd);
        const size = (try file.stat(self.io)).size;
        if (size > limit) return Corrupt;
        const bytes = try std.heap.page_allocator.alloc(u8, @intCast(size));
        errdefer std.heap.page_allocator.free(bytes);
        if (try file.readPositionalAll(self.io, bytes, 0) != bytes.len) return Corrupt;
        return bytes;
    }
};

pub fn asFile(fd: fd_t) std.Io.File {
    return .{ .handle = fd, .flags = .{ .nonblocking = false } };
}

pub fn syncFd(fd: fd_t) !void {
    if (comptime builtin.os.tag != .linux) return error.DurabilityUnsupported;
    while (true) switch (linux.errno(linux.fsync(fd))) {
        .SUCCESS => return,
        .INTR => continue,
        else => return error.DurableStorageFailed,
    };
}

pub fn checkPrivate(fd: fd_t, directory: bool) !void {
    if (comptime builtin.os.tag != .linux) return error.DurabilityUnsupported;
    var stat: linux.Statx = undefined;
    if (linux.errno(linux.statx(fd, "", linux.AT.EMPTY_PATH, .{ .TYPE = true, .MODE = true, .UID = true, .NLINK = true }, &stat)) != .SUCCESS) return error.DurableStorageFailed;
    if (stat.uid != linux.geteuid() or stat.mode & 0o077 != 0) return error.InsecureStatePermissions;
    const kind = stat.mode & 0o170000;
    if (kind != (if (directory) @as(u16, 0o040000) else @as(u16, 0o100000))) return error.InvalidStateObject;
    if (!directory and stat.nlink != 1) return error.InvalidStateObject;
}

pub fn makeDir(parent: fd_t, name: []const u8) !void {
    if (comptime builtin.os.tag != .linux) return error.DurabilityUnsupported;
    var buf: [4096]u8 = undefined;
    const z = std.fmt.bufPrintZ(&buf, "{s}", .{name}) catch return error.NameTooLong;
    switch (linux.errno(linux.mkdirat(parent, z, 0o700))) {
        .SUCCESS => try syncFd(parent),
        .EXIST => {},
        else => return error.DurableStorageFailed,
    }
}

pub fn openDir(parent: fd_t, name: []const u8) !fd_t {
    if (comptime builtin.os.tag != .linux) return error.DurabilityUnsupported;
    const fd = try std.posix.openat(parent, name, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }, 0);
    errdefer os.closeFd(fd);
    try checkPrivate(fd, true);
    return fd;
}

pub fn openFile(parent: fd_t, name: []const u8, create: bool) !fd_t {
    if (comptime builtin.os.tag != .linux) return error.DurabilityUnsupported;
    const fd = try std.posix.openat(parent, name, .{ .ACCMODE = .RDWR, .CREAT = create, .APPEND = true, .NOFOLLOW = true, .CLOEXEC = true, .NONBLOCK = true }, 0o600);
    errdefer os.closeFd(fd);
    try checkPrivate(fd, false);
    return fd;
}

// Linux statvfs is a libc conversion of statfs. Use the same kernel fields
// through the pinned state descriptor (no path lookup or libc dependency).
fn filesystemAvailable(fd: fd_t) !u64 {
    if (comptime builtin.os.tag != .linux) return error.DurabilityUnsupported;
    const Statfs = extern struct {
        kind: isize,
        bsize: isize,
        blocks: usize,
        bfree: usize,
        bavail: usize,
        files: usize,
        ffree: usize,
        fsid: [2]i32,
        namelen: isize,
        frsize: isize,
        flags: isize,
        spare: [4]isize,
    };
    var stat: Statfs = undefined;
    if (linux.errno(linux.syscall2(.fstatfs, @intCast(fd), @intFromPtr(&stat))) != .SUCCESS or stat.bsize <= 0) return error.DurableStorageFailed;
    return std.math.mul(u64, stat.bavail, @intCast(stat.bsize)) catch std.math.maxInt(u64);
}

test "durable index exact budget round trip and checksum rejection" {
    var idx: Index = .{};
    idx.next_id = 91;
    idx.push(.{ .id = 90, .owner_hash = [_]u8{7} ** 32, .reason = .closed_by_client });
    var bytes = idx.encode();
    try std.testing.expectEqual(@as(usize, 8192), bytes.len);
    const decoded = try Index.decode(&bytes);
    try std.testing.expectEqual(@as(u64, 91), decoded.next_id);
    try std.testing.expectEqualDeep(idx, decoded);
    bytes[40] ^= 1;
    try std.testing.expectError(error.CorruptDurableRecord, Index.decode(&bytes));
}

test "durable tombstone newest first eviction and owner anti oracle" {
    var idx: Index = .{};
    const owner = [_]u8{9} ** 32;
    for (1..131) |id| idx.push(.{ .id = id, .owner_hash = owner, .reason = .reaped_ttl });
    try std.testing.expectEqual(@as(u64, 130), idx.tombstones[0].id);
    try std.testing.expectEqual(@as(u64, 3), idx.tombstones[127].id);
    try std.testing.expect(idx.expired(3, owner));
    try std.testing.expect(!idx.expired(2, owner));
    try std.testing.expect(!idx.expired(130, [_]u8{0} ** 32));
    try std.testing.expect(!idx.expired(0, [_]u8{0} ** 32));
}

test "durable meta exact header offsets round trip and checksum rejection" {
    const a = std.testing.allocator;
    const meta: Meta = .{ .session_id = 7, .pid = 42, .pgid = 42, .start_time_ticks = 99, .owner_hash = [_]u8{3} ** 32, .started_us = 1700000000000000, .max_out = 400000 };
    const bytes = try meta.encode(a, "/tmp", &.{ "echo", "hello" });
    defer a.free(bytes);
    try std.testing.expectEqual(@as(usize, 160 + 4 + 8 + 9 + 32), bytes.len);
    try std.testing.expectEqual(@as(u64, 7), std.mem.readInt(u64, bytes[10..18], .little));
    try std.testing.expectEqual(@as(u32, 2), std.mem.readInt(u32, bytes[138..142], .little));
    const decoded = try Meta.decode(bytes);
    try std.testing.expectEqualDeep(meta, decoded.meta);
    try std.testing.expectEqualStrings("/tmp", decoded.cwd);
    try std.testing.expectEqual(@as(u32, 2), decoded.argc);
    bytes[161] ^= 1;
    try std.testing.expectError(error.CorruptDurableRecord, Meta.decode(bytes));
}

test "durable metadata cap counts argv length prefixes" {
    const a = std.testing.allocator;
    const large = try a.alloc(u8, 12 * 1024);
    defer a.free(large);
    @memset(large, 'a');
    try std.testing.expectError(error.DurableMetadataTooLarge, (Meta{}).encode(a, "", &.{large}));
    const bytes = try (Meta{}).encode(a, "", &.{large[0 .. large.len - 4]});
    defer a.free(bytes);
    _ = try Meta.decode(bytes);
    const args = [_][]const u8{""} ** 257;
    try std.testing.expectError(error.DurableMetadataTooLarge, (Meta{}).encode(a, "", &args));
}

test "durable boot id UUID uses RFC bytes and Windows rejects trailing half" {
    const uuid = try uuidBootId("00112233-4455-6677-8899-aabbccddeeff\n");
    try std.testing.expectEqualSlices(u8, &.{ 0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }, &uuid);
    try std.testing.expectError(error.InvalidBootId, uuidBootId("00112233445566778899aabbccddeeff"));
    var meta: Meta = .{ .os_tag = .windows, .boot_id = windowsBootId(0x1122334455667788) };
    try std.testing.expectEqualSlices(u8, &.{ 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11 }, meta.boot_id[0..8]);
    const bytes = try meta.encode(std.testing.allocator, "", &.{});
    defer std.testing.allocator.free(bytes);
    _ = try Meta.decode(bytes);
    bytes[50] = 1;
    seal(bytes);
    try std.testing.expectError(error.CorruptDurableRecord, Meta.decode(bytes));
}

test "durable records reject reserved bytes even with valid checksum" {
    var idx = (Index{}).encode();
    idx[16] = 1;
    seal(&idx);
    try std.testing.expectError(error.CorruptDurableRecord, Index.decode(&idx));
    const bytes = try (Meta{}).encode(std.testing.allocator, "", &.{});
    defer std.testing.allocator.free(bytes);
    bytes[146] = 1;
    seal(bytes);
    try std.testing.expectError(error.CorruptDurableRecord, Meta.decode(bytes));
}

test "durable reservation uses checked arithmetic" {
    try std.testing.expectEqual(@as(u64, 81920 + 800000), try reservation(400000));
    try std.testing.expectError(error.DurableCapacityExceeded, reservation(std.math.maxInt(u64)));
}

test "durable state directory pins private objects and holds exclusive lock" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    const io = std.Io.Threaded.global_single_threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const parent = try tmp.dir.realPathFileAlloc(io, ".", std.testing.allocator);
    defer std.testing.allocator.free(parent);
    const path = try std.fmt.allocPrint(std.testing.allocator, "{s}/state", .{parent});
    defer std.testing.allocator.free(path);
    var disk = try Disk.open(io, path, 64 * 1024 * 1024);
    defer disk.close();
    try std.testing.expectError(error.StateDirLocked, Disk.open(io, path, 64 * 1024 * 1024));
    try std.testing.expectEqual(@as(u64, 1), try disk.allocId());
    try std.testing.expectEqual(@as(u64, 2), try disk.allocId());
    const raw = try disk.readRecord(disk.root, "index.bin", INDEX_SIZE);
    defer std.heap.page_allocator.free(raw);
    try std.testing.expectEqual(@as(u64, 3), (try Index.decode(raw)).next_id);
}

test "durable admission refuses insufficient filesystem space without reserving" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var disk: Disk = undefined;
    disk.io = io;
    disk.mutex = .init;
    disk.failed = false;
    disk.reserved = 0;
    disk.max_bytes = 1024 * 1024;
    disk.test_available_bytes = 1;
    try std.testing.expectError(error.DurabilityFull, disk.reserve(1024));
    try std.testing.expectEqual(@as(u64, 0), disk.reserved);
    disk.test_available_bytes = 1024 * 1024;
    try disk.reserve(1024);
    try std.testing.expectEqual(try reservation(1024), disk.reserved);
}
