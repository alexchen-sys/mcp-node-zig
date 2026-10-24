//! Bounded, staged local copies with no-replace publication.
const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const secure = @import("os/secure.zig");
const policy = @import("policy.zig");
const util = @import("util.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const Options = struct {
    recursive: bool = false,
    max_bytes: u64 = 64 * 1024 * 1024,
    max_entries: u32 = 2000,
    timeout_ms: u64 = 30000,
    mode_cap: u32 = 0o700,
    // The caller passes its configured state root through this explicit
    // boundary: the copy helpers never read the process environment.
    state_dir: ?[]const u8 = null,
    hooks: if (builtin.is_test) Hooks else void = if (builtin.is_test) .{} else {},
};

const Hooks = struct {
    context: ?*anyopaque = null,
    after_eof: ?*const fn (?*anyopaque) anyerror!void = null,
    before_publish: ?*const fn (?*anyopaque) anyerror!void = null,
    unsupported_publish: bool = false,
    cleanup_failure: bool = false,
};

pub const Result = struct {
    kind: enum { file, directory } = .file,
    files: u64 = 0,
    directories: u64 = 0,
    bytes: u64 = 0,
    digest: [32]u8 = undefined,
    duration_ms: u64 = 0,
};
var occupied = std.atomic.Value(bool).init(false);

fn file(fd: secure.fd_t) Io.File {
    return .{ .handle = fd, .flags = .{ .nonblocking = true } };
}

fn under(path: []const u8, raw_root: []const u8) bool {
    const root = if (raw_root.len > 1) std.mem.trimEnd(u8, raw_root, "/") else raw_root;
    return std.mem.eql(u8, path, root) or (std.mem.startsWith(u8, path, root) and
        (std.mem.eql(u8, root, "/") or (path.len > root.len and path[root.len] == '/')));
}

fn overlap(a: []const u8, b: []const u8) bool {
    return under(a, b) or under(b, a);
}

fn denied(pin: secure.Pin, path: []const u8) !void {
    if (!under(path, pin.prefix)) return error.PathEscape;
    for (pin.deny) |d| if (under(path, d)) return error.PathDenied;
}

fn unchanged(a: Io.File.Stat, b: Io.File.Stat) bool {
    return a.inode == b.inode and a.nlink == b.nlink and a.size == b.size and
        a.kind == b.kind and std.meta.eql(a.mtime, b.mtime) and std.meta.eql(a.ctime, b.ctime);
}

fn record(h: *Sha256, kind: u8, path: []const u8, size: u64, digest: [32]u8) void {
    var len: [4]u8 = undefined;
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u32, &len, @intCast(path.len), .little);
    std.mem.writeInt(u64, &bytes, size, .little);
    h.update(&.{kind});
    h.update(&len);
    h.update(path);
    h.update(&bytes);
    h.update(&digest);
}

const Frame = struct {
    source: secure.fd_t,
    destination: secure.fd_t,
    relative: []const u8,
    names: [][]const u8,
    index: usize = 0,
    before: Io.File.Stat,
};

const Operation = struct {
    a: Allocator,
    io: Io,
    pins: policy.CopyPins,
    opts: Options,
    start: Io.Timestamp,
    result: Result = .{},
    tree: Sha256 = Sha256.init(.{}),
    buffer: [65536]u8 = undefined,
    frames: [65]Frame = undefined,
    depth: usize = 0,
    discovered: u32 = 1,

    fn deadline(op: *Operation) !void {
        if (op.start.untilNow(op.io, .awake).toMilliseconds() >= op.opts.timeout_ms) return error.CopyTimeout;
    }

    fn elapsed(op: *Operation) u64 {
        return @intCast(@max(0, op.start.untilNow(op.io, .awake).toMilliseconds()));
    }

    fn paths(op: *Operation, fd: secure.fd_t, rel: []const u8) !void {
        var src_buf: [std.fs.max_path_bytes]u8 = undefined;
        var dst_buf: [std.fs.max_path_bytes]u8 = undefined;
        const s = if (rel.len == 0) op.pins.source.canon else std.fmt.bufPrint(&src_buf, "{s}/{s}", .{ op.pins.source.canon, rel }) catch return error.NameTooLong;
        const d = if (rel.len == 0) op.pins.destination.canon else std.fmt.bufPrint(&dst_buf, "{s}/{s}", .{ op.pins.destination.canon, rel }) catch return error.NameTooLong;
        try denied(op.pins.source, s);
        try denied(op.pins.destination, d);
        try secure.copyVerify(op.io, fd, s);
    }

    fn names(op: *Operation, fd: secure.fd_t) ![][]const u8 {
        var list: std.ArrayList([]const u8) = .empty;
        errdefer {
            for (list.items) |n| op.a.free(n);
            list.deinit(op.a);
        }
        var it = (Io.Dir{ .handle = fd }).iterate();
        while (try it.next(op.io)) |entry| {
            try op.deadline();
            if (op.discovered >= op.opts.max_entries) return error.CopyLimitExceeded;
            op.discovered += 1;
            const n = try op.a.dupe(u8, entry.name);
            errdefer op.a.free(n);
            try list.append(op.a, n);
        }
        std.mem.sort([]const u8, list.items, {}, struct {
            fn less(_: void, a: []const u8, b: []const u8) bool {
                return std.mem.lessThan(u8, a, b);
            }
        }.less);
        return list.toOwnedSlice(op.a);
    }

    fn pop(op: *Operation) void {
        op.depth -= 1;
        const f = op.frames[op.depth];
        file(f.source).close(op.io);
        file(f.destination).close(op.io);
        for (f.names) |n| op.a.free(n);
        op.a.free(f.names);
        op.a.free(f.relative);
    }

    // Consumes source on every path; destination files are closed here,
    // destination directories remain pinned until their frame completes.
    fn visit(op: *Operation, source: secure.fd_t, parent: secure.fd_t, name: []const u8, rel: []const u8) !void {
        var retained = false;
        defer if (!retained) file(source).close(op.io);
        try op.deadline();
        try op.paths(source, rel);
        if (op.depth > 64) return error.CopyDepthExceeded;
        const st = try file(source).stat(op.io);
        if (st.kind == .directory) {
            if (!op.opts.recursive) return error.DirectoryRequiresRecursive;
            if (op.depth == op.frames.len) return error.CopyDepthExceeded;
            const dir = Io.Dir{ .handle = parent };
            try dir.createDir(op.io, name, .fromMode(0o700));
            const dst = try secure.copyOpenChild(op.io, parent, name, false);
            errdefer file(dst).close(op.io);
            const ns = try op.names(source);
            errdefer {
                for (ns) |n| op.a.free(n);
                op.a.free(ns);
            }
            const relative = try op.a.dupe(u8, rel);
            op.frames[op.depth] = .{ .source = source, .destination = dst, .relative = relative, .names = ns, .before = st };
            op.depth += 1;
            retained = true;
            op.result.directories += 1;
            record(&op.tree, 2, rel, 0, [_]u8{0} ** 32);
        } else if (st.kind == .file and st.nlink == 1) {
            if (st.size > op.opts.max_bytes - op.result.bytes) return error.CopyLimitExceeded;
            const dst = try secure.copyOpenChild(op.io, parent, name, true);
            defer file(dst).close(op.io);
            var h = Sha256.init(.{});
            var offset: u64 = 0;
            var kernel_copy = true;
            while (true) {
                try op.deadline();
                try op.paths(source, rel);
                const room = op.opts.max_bytes - op.result.bytes;
                const n = try secure.copyChunk(op.io, source, dst, offset, op.buffer[0..@min(op.buffer.len, room + 1)], &kernel_copy);
                if (n == 0) break;
                if (n > room) return error.CopyLimitExceeded;
                h.update(op.buffer[0..n]);
                offset += n;
                op.result.bytes += n;
            }
            if (builtin.is_test) if (op.opts.hooks.after_eof) |hook| try hook(op.opts.hooks.context);
            if (offset != st.size or !unchanged(st, try file(source).stat(op.io))) return error.SourceChanged;
            try op.paths(source, rel);
            try file(dst).setPermissions(op.io, .fromMode(@intCast(0o600 & op.opts.mode_cap)));
            var digest: [32]u8 = undefined;
            h.final(&digest);
            if (rel.len == 0) op.result.digest = digest;
            record(&op.tree, 1, rel, offset, digest);
            op.result.files += 1;
        } else return error.UnsupportedFileType;
    }

    fn walk(op: *Operation, source: secure.fd_t, stage: secure.fd_t) !void {
        try op.visit(source, stage, "payload", "");
        while (op.depth != 0) {
            try op.deadline();
            const f = &op.frames[op.depth - 1];
            try op.paths(f.source, f.relative);
            if (f.index == f.names.len) {
                if (!unchanged(f.before, try file(f.source).stat(op.io))) return error.SourceChanged;
                op.pop();
                continue;
            }
            const name = f.names[f.index];
            f.index += 1;
            const rel = if (f.relative.len == 0) try op.a.dupe(u8, name) else try std.fmt.allocPrint(op.a, "{s}/{s}", .{ f.relative, name });
            defer op.a.free(rel);
            const fd = try secure.copyOpenChild(op.io, f.source, name, false);
            try op.visit(fd, f.destination, name, rel);
        }
    }
};

pub fn run(a: Allocator, io: Io, pins: policy.CopyPins, opts: Options) !Result {
    // Unsupported platforms refuse before any filesystem changes.
    if (comptime builtin.os.tag != .linux and builtin.os.tag != .macos) return error.AtomicPublishUnsupported;
    if (occupied.cmpxchgStrong(false, true, .acq_rel, .acquire) != null) return error.CopyBusy;
    defer occupied.store(false, .release);
    var op = Operation{ .a = a, .io = io, .pins = pins, .opts = opts, .start = Io.Clock.awake.now(io) };
    defer {
        while (op.depth != 0) op.pop();
    }
    if (opts.max_entries == 0 or opts.max_entries > 10000 or opts.max_bytes > 1073741824) return error.CopyLimitExceeded;
    try op.deadline();
    try denied(pins.source, pins.source.canon);
    try denied(pins.destination, pins.destination.canon);
    if (overlap(pins.source.canon, pins.destination.canon)) return error.PathOverlap;
    if (opts.state_dir) |state| {
        if (overlap(pins.source.canon, state) or overlap(pins.destination.canon, state)) return error.StatePathForbidden;
    }

    const parent_path = std.fs.path.dirname(pins.destination.canon) orelse return error.BadPathName;
    const name = std.fs.path.basename(pins.destination.canon);
    if (!secure.copyValidName(name)) return error.BadPathName;
    const parent_pin: secure.Pin = if (under(parent_path, pins.destination.prefix)) .{
        .prefix = pins.destination.prefix,
        .canon = parent_path,
        .rel = if (std.mem.eql(u8, parent_path, pins.destination.prefix)) "" else parent_path[pins.destination.prefix.len + @as(usize, if (std.mem.eql(u8, pins.destination.prefix, "/")) 0 else 1) ..],
        .deny = pins.destination.deny,
    } else .{ .prefix = parent_path, .canon = parent_path, .rel = "", .deny = &.{} };
    const parent = try secure.copyOpenPin(io, parent_pin);
    defer file(parent).close(io);
    try secure.copyVerify(io, parent, parent_path);
    const parent_dir = Io.Dir{ .handle = parent };
    if (parent_dir.statFile(io, name, .{ .follow_symlinks = false })) |existing| {
        if (existing.kind == .sym_link) return error.SymlinkNotAllowed;
        return error.DestinationExists;
    } else |err| if (err != error.FileNotFound) return err;
    const source = try secure.copyOpenPin(io, pins.source);
    var source_owned = true;
    defer if (source_owned) file(source).close(io);
    try op.paths(source, "");
    const st = try file(source).stat(io);
    if (st.kind == .directory) {
        if (!opts.recursive) return error.DirectoryRequiresRecursive;
        // POSIX directory rename requires owner write access to update '..'.
        // Refuse restrictive caps rather than briefly publish excess rights.
        if (opts.mode_cap & 0o700 != 0o700) return error.CopyModeUnsupported;
        try secure.copyCheckAncestors(io, source, parent);
        op.result.kind = .directory;
    }
    var state_fd: ?secure.fd_t = null;
    defer if (state_fd) |fd| file(fd).close(io);
    if (opts.state_dir) |state| {
        state_fd = secure.copyOpenRoot(io, state) catch |err| switch (err) {
            error.FileNotFound => null,
            else => return error.StatePathForbidden,
        };
        if (state_fd) |fd| {
            secure.copyVerify(io, fd, state) catch return error.StatePathForbidden;
            // Catch namespace aliases as well as lexical overlap. A source
            // directory containing state is just as forbidden as a child.
            secure.copyCheckAncestors(io, fd, parent) catch return error.StatePathForbidden;
            if (st.kind == .directory) {
                secure.copyCheckAncestors(io, fd, source) catch return error.StatePathForbidden;
                secure.copyCheckAncestors(io, source, fd) catch return error.StatePathForbidden;
            } else {
                const src_parent = secure.copyOpenRoot(io, std.fs.path.dirname(pins.source.canon) orelse "/") catch return error.StatePathForbidden;
                defer file(src_parent).close(io);
                secure.copyCheckAncestors(io, fd, src_parent) catch return error.StatePathForbidden;
            }
        }
    }
    try scavenge(&op, parent_dir, parent_path);
    var random: [16]u8 = undefined;
    io.random(&random);
    var stage_buf: [64]u8 = undefined;
    const stage_name = try std.fmt.bufPrint(&stage_buf, ".mcpnz-copy-{s}", .{std.fmt.bytesToHex(random, .lower)});
    try parent_dir.createDir(io, stage_name, .fromMode(0o700));
    const stage = secure.copyOpenChild(io, parent, stage_name, false) catch |err| {
        parent_dir.deleteDir(io, stage_name) catch return error.CopyCleanupFailed;
        return err;
    };
    defer file(stage).close(io);
    const marker = secure.copyOpenChild(io, stage, "marker", true) catch |err| {
        try cleanup(&op, parent_dir, stage_name);
        return err;
    };
    defer file(marker).close(io);
    const marker_result = writeMarker(io, marker, stage, parent);
    marker_result catch |err| {
        try cleanup(&op, parent_dir, stage_name);
        return err;
    };
    op.tree.update("MCPNZ-TREE-v1\x00");
    source_owned = false;
    op.walk(source, stage) catch |err| {
        try cleanup(&op, parent_dir, stage_name);
        return err;
    };
    if (builtin.is_test) if (opts.hooks.before_publish) |hook| hook(opts.hooks.context) catch |err| {
        try cleanup(&op, parent_dir, stage_name);
        return err;
    };

    const ready = struct {
        fn check(o: *Operation, p: secure.fd_t, path: []const u8) !void {
            try o.deadline();
            try secure.copyVerify(o.io, p, path);
            if (builtin.is_test) if (o.opts.hooks.unsupported_publish) return error.AtomicPublishUnsupported;
        }
    }.check(&op, parent, parent_path);
    ready catch |err| {
        try cleanup(&op, parent_dir, stage_name);
        return err;
    };
    secure.copyPublish(stage, parent, name) catch |err| {
        try cleanup(&op, parent_dir, stage_name);
        return err;
    };
    (Io.Dir{ .handle = stage }).deleteFile(io, "marker") catch return error.CopyCleanupFailed;
    parent_dir.deleteDir(io, stage_name) catch return error.CopyCleanupFailed;
    if (op.result.kind == .directory) op.tree.final(&op.result.digest);
    op.result.duration_ms = op.elapsed();
    return op.result;
}

fn cleanup(op: *Operation, parent: Io.Dir, name: []const u8) !void {
    if (builtin.is_test) if (op.opts.hooks.cleanup_failure) return error.CopyCleanupFailed;
    parent.deleteTree(op.io, name) catch return error.CopyCleanupFailed;
}

const marker_magic = "MCPNZ-COPY-v1\x00";
const Marker = [marker_magic.len + 32]u8;
fn markerBytes(io: Io, stage: secure.fd_t, parent: secure.fd_t) !Marker {
    var bytes: Marker = undefined;
    @memcpy(bytes[0..marker_magic.len], marker_magic);
    const s = try secure.copyIdentity(io, stage);
    const p = try secure.copyIdentity(io, parent);
    inline for (.{ s.device, s.inode, p.device, p.inode }, 0..) |n, i| {
        std.mem.writeInt(u64, bytes[marker_magic.len + 8 * i ..][0..8], n, .little);
    }
    return bytes;
}

fn writeMarker(io: Io, marker: secure.fd_t, stage: secure.fd_t, parent: secure.fd_t) !void {
    if (!secure.copyPrivateOwner(stage, true) or !secure.copyPrivateOwner(marker, false) or !secure.copyTryLock(marker)) return error.CopyBusy;
    try file(marker).writePositionalAll(io, &try markerBytes(io, stage, parent), 0);
}

fn scavenge(op: *Operation, parent: Io.Dir, path: []const u8) !void {
    // Open a separate enumeration handle: never disturb the publication fd.
    const enum_fd = try secure.copyOpenRoot(op.io, path);
    defer file(enum_fd).close(op.io);
    try secure.copyVerify(op.io, enum_fd, path);
    var it = (Io.Dir{ .handle = enum_fd }).iterate();
    var examined: usize = 0;
    while (try it.next(op.io)) |e| {
        try op.deadline();
        examined += 1;
        // Recovery is bounded independently of the payload's entry budget.
        if (examined > 10000) break;
        if (!std.mem.startsWith(u8, e.name, ".mcpnz-copy-") or e.name.len != 44) continue;
        var valid = true;
        for (e.name[12..]) |c| if (!std.ascii.isHex(c)) {
            valid = false;
            break;
        };
        if (!valid) continue;
        const stage = secure.copyOpenChild(op.io, parent.handle, e.name, false) catch continue;
        defer file(stage).close(op.io);
        if (!secure.copyPrivateOwner(stage, true)) continue;
        const marker = secure.copyOpenChild(op.io, stage, "marker", false) catch continue;
        defer file(marker).close(op.io);
        if (!secure.copyPrivateOwner(marker, false) or !secure.copyTryLock(marker)) continue;
        const st = file(marker).stat(op.io) catch continue;
        if (st.size != @sizeOf(Marker)) continue;
        var bytes: Marker = undefined;
        if ((file(marker).readPositionalAll(op.io, &bytes, 0) catch continue) != bytes.len) continue;
        const expected = try markerBytes(op.io, stage, parent.handle);
        if (!std.mem.eql(u8, &bytes, &expected)) continue;
        const stage_path = try std.fmt.allocPrint(op.a, "{s}/{s}", .{ path, e.name });
        defer op.a.free(stage_path);
        try secure.copyVerify(op.io, stage, stage_path);
        try secure.copyVerify(op.io, parent.handle, path);
        // Unknown siblings remain untouched. deleteTree does not follow links.
        parent.deleteTree(op.io, e.name) catch return error.CopyCleanupFailed;
    }
}

fn integer(args: std.json.Value, name: []const u8, default: u64, min: u64, max: u64) !u64 {
    const v = util.objGet(args, name) orelse return default;
    if (v != .integer or v.integer < 0) return error.InvalidParams;
    const n: u64 = @intCast(v.integer);
    if (n < min or n > max) return error.InvalidParams;
    return n;
}

pub fn tool(a: Allocator, io: Io, cfg: *const @import("config.zig").Config, args: std.json.Value, out: *std.ArrayList(u8), authorized: ?policy.CopyPins, pol: ?*const policy.TokenPolicy) !void {
    const src = (try util.optStrArg(args, "source")) orelse return error.InvalidParams;
    const dst = (try util.optStrArg(args, "destination")) orelse return error.InvalidParams;
    if (src.len == 0 or dst.len == 0) return error.InvalidParams;
    if (args == .object) {
        var keys = args.object.iterator();
        while (keys.next()) |kv| {
            var known = false;
            inline for (.{ "source", "destination", "recursive", "max_bytes", "max_entries", "timeout" }) |key| {
                if (std.mem.eql(u8, kv.key_ptr.*, key)) known = true;
            }
            if (!known) return error.InvalidParams;
        }
    }
    if (util.objGet(args, "recursive")) |v| if (v != .bool) return error.InvalidParams;
    const opts = Options{
        .recursive = (try util.optBoolArg(args, "recursive")) orelse false,
        .max_bytes = try integer(args, "max_bytes", cfg.copy_max_bytes, 0, cfg.copy_max_bytes),
        .max_entries = @intCast(try integer(args, "max_entries", cfg.copy_max_entries, 1, cfg.copy_max_entries)),
        .timeout_ms = 1000 * try integer(args, "timeout", 30, 1, 300),
        .mode_cap = if (pol) |p| p.write_max_mode orelse 0o700 else 0o700,
        .state_dir = if (@hasField(@import("config.zig").Config, "state_dir")) cfg.state_dir else null,
    };

    const pins = authorized orelse policy.CopyPins{
        .source = try policy.authorizePath(a, io, pol, src, .read),
        .destination = try policy.authorizePath(a, io, pol, dst, .write),
    };

    const r = try run(a, io, pins, opts);
    try out.appendSlice(a, "{\"ok\":true,\"source\":");
    try util.appendJsonString(out, a, pins.source.canon);
    try out.appendSlice(a, ",\"destination\":");
    try util.appendJsonString(out, a, pins.destination.canon);
    try out.print(a, ",\"kind\":\"{s}\",\"files\":{d},\"directories\":{d},\"bytes\":{d},\"sha256\":", .{ @tagName(r.kind), r.files, r.directories, r.bytes });
    try util.appendHexLower(out, a, &r.digest);
    try out.print(a, ",\"checksum_format\":\"{s}\",\"consistency\":\"per-file-checked\",\"atomic_publish\":true,\"crash_durable\":false,\"duration_ms\":{d}}}", .{ if (r.kind == .file) "content-sha256" else "mcp-tree-v1", r.duration_ms });
}

test {
    _ = @import("copy_test.zig");
}
