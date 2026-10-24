//! Native copy contract tests. Fixtures contain only disposable local data.
const std = @import("std");
const builtin = @import("builtin");
const copy = @import("copy.zig");
const policy = @import("policy.zig");
const secure = @import("os/secure.zig");
const t = std.testing;
const io = std.Io.Threaded.global_single_threaded.io();

const Fixture = struct {
    tmp: t.TmpDir,
    arena: std.heap.ArenaAllocator,
    fn init() !Fixture {
        if (builtin.os.tag != .linux) return error.SkipZigTest;
        return .{ .tmp = t.tmpDir(.{ .iterate = true }), .arena = std.heap.ArenaAllocator.init(t.allocator) };
    }

    fn deinit(f: *Fixture) void {
        f.tmp.cleanup();
        f.arena.deinit();
    }

    fn path(f: *Fixture, name: []const u8) ![]const u8 {
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const n = try f.tmp.dir.realPath(io, &buf);
        return std.fmt.allocPrint(f.arena.allocator(), "{s}/{s}", .{ buf[0..n], name });
    }

    fn pins(f: *Fixture, src: []const u8, dst: []const u8) !policy.CopyPins {
        return .{ .source = try f.pin(src), .destination = try f.pin(dst) };
    }

    fn pin(f: *Fixture, name: []const u8) !secure.Pin {
        const p = try f.path(name);
        return .{ .canon = p, .prefix = std.fs.path.dirname(p).?, .rel = std.fs.path.basename(p), .deny = &.{} };
    }

    fn write(f: *Fixture, name: []const u8, data: []const u8) !void {
        try f.tmp.dir.writeFile(io, .{ .sub_path = name, .data = data });
    }

    fn run(f: *Fixture, opts: copy.Options) !copy.Result {
        return copy.run(f.arena.allocator(), io, try f.pins("src", "dst"), opts);
    }

    fn absent(f: *Fixture, name: []const u8) !void {
        try t.expectError(error.FileNotFound, f.tmp.dir.statFile(io, name, .{ .follow_symlinks = false }));
        var it = f.tmp.dir.iterate();
        while (try it.next(io)) |e| try t.expect(!std.mem.startsWith(u8, e.name, ".mcpnz-copy-"));
    }
};

test "copy: root file content digest" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.write("src", "abc");
    const r = try f.run(.{});
    try t.expectEqual(@as(u64, 3), r.bytes);
    try t.expectEqual(@as(u64, 1), r.files);
    try t.expectEqualStrings("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", &std.fmt.bytesToHex(r.digest, .lower));
    var b: [8]u8 = undefined;
    try t.expectEqualStrings("abc", try f.tmp.dir.readFile(io, "dst", &b));
}

test "copy: root directory sorted digest golden fixture" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.tmp.dir.createDirPath(io, "src/z");
    try f.write("src/b", "B");
    try f.write("src/a", "abc");
    const r = try f.run(.{ .recursive = true });
    try t.expectEqual(@as(u64, 2), r.files);
    try t.expectEqual(@as(u64, 2), r.directories);
    try t.expectEqualStrings("c62af920d54688130d5f06b96dd44e0c7736dc7eb6bdbfde4c312570ffa502d8", &std.fmt.bytesToHex(r.digest, .lower));
}

test "copy: destination exists never overwritten" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.write("src", "new");
    try f.write("dst", "old");
    try t.expectError(error.DestinationExists, f.run(.{}));
    var b: [8]u8 = undefined;
    try t.expectEqualStrings("old", try f.tmp.dir.readFile(io, "dst", &b));
}

test "copy: recursive required" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.tmp.dir.createDirPath(io, "src");
    try t.expectError(error.DirectoryRequiresRecursive, f.run(.{}));
    try f.absent("dst");
}

test "copy: zero byte budget accepts empty file" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.write("src", "");
    const r = try f.run(.{ .max_bytes = 0 });
    try t.expectEqual(@as(u64, 0), r.bytes);
}

test "copy: both pins retain separate deny lists" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.write("src", "abc");
    var p = try f.pins("src", "dst");
    p.source.deny = &.{p.source.canon};
    try t.expectError(error.PathDenied, copy.run(f.arena.allocator(), io, p, .{}));
    p.source.deny = &.{};
    p.destination.deny = &.{p.destination.canon};
    try t.expectError(error.PathDenied, copy.run(f.arena.allocator(), io, p, .{}));
    try f.absent("dst");
}

test "copy: child read deny aborts stage" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.tmp.dir.createDirPath(io, "src");
    try f.write("src/a", "ok");
    try f.write("src/z", "secret");
    var p = try f.pins("src", "dst");
    p.source.deny = &.{try f.path("src/z")};
    try t.expectError(error.PathDenied, copy.run(f.arena.allocator(), io, p, .{ .recursive = true }));
    try f.absent("dst");
}

test "copy: child write deny aborts stage" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.tmp.dir.createDirPath(io, "src");
    try f.write("src/a", "ok");
    try f.write("src/z", "no");
    var p = try f.pins("src", "dst");
    p.destination.deny = &.{try f.path("dst/z")};
    try t.expectError(error.PathDenied, copy.run(f.arena.allocator(), io, p, .{ .recursive = true }));
    try f.absent("dst");
}

test "copy: fixed file mode masked by policy cap" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.write("src", "abc");
    _ = try f.run(.{ .mode_cap = 0o400 });
    const st = try f.tmp.dir.statFile(io, "dst", .{});
    try t.expectEqual(@as(u32, 0o400), st.permissions.toMode() & 0o7777);
}

test "copy: root symlink refused" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.write("real", "abc");
    try f.tmp.dir.symLink(io, "real", "src", .{});
    try t.expectError(error.SymlinkNotAllowed, f.run(.{}));
    try f.absent("dst");
}

test "copy: descendant symlink refused" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.tmp.dir.createDirPath(io, "src");
    try f.tmp.dir.symLink(io, "missing", "src/link", .{});
    try t.expectError(error.SymlinkNotAllowed, f.run(.{ .recursive = true }));
    try f.absent("dst");
}

test "copy: destination symlink never followed" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.write("src", "abc");
    try f.tmp.dir.symLink(io, "missing", "dst", .{});
    try t.expectError(error.SymlinkNotAllowed, f.run(.{}));
    try f.absent("missing");
}

test "copy: hardlink source refused" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.write("src", "abc");
    const rc = std.os.linux.linkat(f.tmp.dir.handle, "src", f.tmp.dir.handle, "alias", 0);
    try t.expectEqual(std.os.linux.E.SUCCESS, std.os.linux.errno(rc));
    try t.expectError(error.UnsupportedFileType, f.run(.{}));
    try f.absent("dst");
}

test "copy: overlap and identity ancestor guard" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.tmp.dir.createDirPath(io, "src/child");
    try t.expectError(error.PathOverlap, copy.run(f.arena.allocator(), io, try f.pins("src", "src/child/dst"), .{ .recursive = true }));
    try t.expectError(error.PathOverlap, copy.run(f.arena.allocator(), io, try f.pins("src", "src"), .{ .recursive = true }));
    const s = try secure.copyOpenRoot(io, try f.path("src"));
    defer std.Io.File.close(.{ .handle = s, .flags = .{ .nonblocking = true } }, io);
    const d = try secure.copyOpenRoot(io, try f.path("src/child"));
    defer std.Io.File.close(.{ .handle = d, .flags = .{ .nonblocking = true } }, io);
    try t.expectError(error.PathOverlap, secure.copyCheckAncestors(io, s, d));
}

fn mutate(ctx: ?*anyopaque) anyerror!void {
    const f: *Fixture = @ptrCast(@alignCast(ctx.?));
    try f.write("src", "changed after EOF");
}

test "copy: source change discards stage" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.write("src", "abc");
    try t.expectError(error.SourceChanged, f.run(.{ .hooks = .{ .after_eof = mutate, .context = &f } }));
    try f.absent("dst");
}

test "copy: byte cap discards stage and releases gate" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.write("src", "abc");
    try t.expectError(error.CopyLimitExceeded, f.run(.{ .max_bytes = 2 }));
    try f.absent("dst");
    _ = try f.run(.{});
}

test "copy: entry cap counts root and empty directories" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.tmp.dir.createDirPath(io, "src/empty");
    try t.expectError(error.CopyLimitExceeded, f.run(.{ .recursive = true, .max_entries = 1 }));
    try f.absent("dst");
}

test "copy: depth cap refuses sixty fifth descendant" {
    var f = try Fixture.init();
    defer f.deinit();
    var path: std.ArrayList(u8) = .empty;
    const a = f.arena.allocator();
    try path.appendSlice(a, "src");
    for (0..65) |_| try path.appendSlice(a, "/d");
    try f.tmp.dir.createDirPath(io, path.items);
    try t.expectError(error.CopyDepthExceeded, f.run(.{ .recursive = true }));
    try f.absent("dst");
}

fn publishRace(ctx: ?*anyopaque) anyerror!void {
    const f: *Fixture = @ptrCast(@alignCast(ctx.?));
    try f.write("dst", "winner");
}

test "copy: publication race preserves concurrent destination" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.write("src", "abc");
    try t.expectError(error.DestinationExists, f.run(.{ .hooks = .{ .before_publish = publishRace, .context = &f } }));
    var b: [16]u8 = undefined;
    try t.expectEqualStrings("winner", try f.tmp.dir.readFile(io, "dst", &b));
}

test "copy: unsupported atomic publish has no rename fallback" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.write("src", "abc");
    try t.expectError(error.AtomicPublishUnsupported, f.run(.{ .hooks = .{ .unsupported_publish = true } }));
    try f.absent("dst");
}

test "copy: expired deadline cleans stage and releases gate" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.write("src", "abc");
    try t.expectError(error.CopyTimeout, f.run(.{ .timeout_ms = 0 }));
    try f.absent("dst");
    _ = try f.run(.{});
}

fn busy(ctx: ?*anyopaque) anyerror!void {
    const f: *Fixture = @ptrCast(@alignCast(ctx.?));
    try t.expectError(error.CopyBusy, f.run(.{}));
}

test "copy: node wide gate rejects concurrent operation" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.write("src", "abc");
    _ = try f.run(.{ .hooks = .{ .before_publish = busy, .context = &f } });
}

test "copy: streaming memory independent of payload size" {
    var f = try Fixture.init();
    defer f.deinit();
    const file = try f.tmp.dir.createFile(io, "src", .{});
    defer file.close(io);
    const chunk = [_]u8{'x'} ** 65536;
    for (0..256) |_| try file.writeStreamingAll(io, &chunk);
    var mem: [128 * 1024]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&mem);
    const r = try copy.run(fixed.allocator(), io, try f.pins("src", "dst"), .{});
    try t.expectEqual(@as(u64, 16 * 1024 * 1024), r.bytes);
}

test "copy: missing parent never created" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.write("src", "abc");
    try t.expectError(error.FileNotFound, copy.run(f.arena.allocator(), io, try f.pins("src", "missing/dst"), .{}));
    try f.absent("missing");
}

test "copy: state directory overlap refused" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.tmp.dir.createDirPath(io, "src/state");
    try t.expectError(error.StatePathForbidden, f.run(.{ .recursive = true, .state_dir = try f.path("src/state") }));
    try f.absent("dst");
}

test "copy: policy gate preserves symlink spelling" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.write("real", "abc");
    try f.tmp.dir.symLink(io, "real", "src", .{});
    const p = try policy.authorizePath(f.arena.allocator(), io, null, try f.path("src"), .read);
    try t.expectEqualStrings(try f.path("src"), p.canon);
    try t.expectError(error.SymlinkNotAllowed, copy.run(f.arena.allocator(), io, .{ .source = p, .destination = try f.pin("dst") }, .{}));
    try f.absent("dst");
}

test "copy: parent traversal rejected before normalization" {
    var f = try Fixture.init();
    defer f.deinit();
    try t.expectError(error.BadPathName, policy.copyPath(f.arena.allocator(), io, "missing/../src"));
}

test "copy: fifo source refuses without blocking" {
    var f = try Fixture.init();
    defer f.deinit();
    const rc = std.os.linux.mknodat(f.tmp.dir.handle, "src", 0o010600, 0);
    try t.expectEqual(std.os.linux.E.SUCCESS, std.os.linux.errno(rc));
    try t.expectError(error.UnsupportedFileType, f.run(.{}));
    try f.absent("dst");
}

test "copy: fallback transfer hashes staged bytes" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.write("src", "fallback");
    const src = try secure.copyOpenRoot(io, try f.path("src"));
    defer std.Io.File.close(.{ .handle = src, .flags = .{ .nonblocking = true } }, io);
    const dst = try secure.copyOpenChild(io, f.tmp.dir.handle, "dst", true);
    defer std.Io.File.close(.{ .handle = dst, .flags = .{ .nonblocking = true } }, io);
    var kernel = false;
    var buf: [64]u8 = undefined;
    const n = try secure.copyChunk(io, src, dst, 0, &buf, &kernel);
    try t.expectEqualStrings("fallback", buf[0..n]);
    try t.expectEqual(@as(usize, 0), try secure.copyChunk(io, src, dst, n, &buf, &kernel));
}

test "copy: cleanup failure is explicit and marked stage recovered" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.write("src", "abc");
    try t.expectError(error.CopyCleanupFailed, f.run(.{ .hooks = .{ .unsupported_publish = true, .cleanup_failure = true } }));
    try t.expectError(error.FileNotFound, f.tmp.dir.statFile(io, "dst", .{}));
    var it = f.tmp.dir.iterate();
    var marked: usize = 0;
    while (try it.next(io)) |e| if (std.mem.startsWith(u8, e.name, ".mcpnz-copy-")) {
        marked += 1;
    };
    try t.expectEqual(@as(usize, 1), marked);
    _ = try f.run(.{});
    try f.absent("missing");
}

test "copy: unknown stage directory is never scavenged" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.write("src", "abc");
    const stage = ".mcpnz-copy-00000000000000000000000000000000";
    try f.tmp.dir.createDir(io, stage, .fromMode(0o700));
    _ = try f.run(.{});
    _ = try f.tmp.dir.statFile(io, stage, .{});
}

test "copy: forged stage marker is never scavenged" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.write("src", "abc");
    const stage = ".mcpnz-copy-00000000000000000000000000000000";
    try f.tmp.dir.createDir(io, stage, .fromMode(0o700));
    try f.write(stage ++ "/marker", "MCPNZ-COPY-v1");
    _ = try f.run(.{});
    _ = try f.tmp.dir.statFile(io, stage ++ "/marker", .{});
}

test "copy: unpublishable directory mode cap refuses before staging" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.tmp.dir.createDirPath(io, "src/empty");
    try t.expectError(error.CopyModeUnsupported, f.run(.{ .recursive = true, .mode_cap = 0o500 }));
    try f.absent("dst");
}

test "copy: state overlap covers destination and ancestor" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.write("src", "abc");
    try t.expectError(error.StatePathForbidden, f.run(.{ .state_dir = try f.path("dst/state") }));
    try t.expectError(error.StatePathForbidden, f.run(.{ .state_dir = try f.path("") }));
    try f.absent("dst");
}

test "copy: empty directory digest includes root record" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.tmp.dir.createDirPath(io, "src");
    const r = try f.run(.{ .recursive = true });
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("MCPNZ-TREE-v1\x00");
    h.update(&.{2});
    h.update(&([_]u8{0} ** 44));
    var expected: [32]u8 = undefined;
    h.final(&expected);
    try t.expectEqualSlices(u8, &expected, &r.digest);
}

test "copy: policy gate emits independent read and write pins" {
    var f = try Fixture.init();
    defer f.deinit();
    const root = std.mem.trimEnd(u8, try f.path(""), "/");
    const src = try f.path("src");
    const dst = try f.path("dst");
    var pol = policy.TokenPolicy{
        .file = "",
        .token_hash = [_]u8{0} ** 32,
        .tools = &.{"copy_path"},
        .exec_argv0 = &.{},
        .exec_cwd = &.{},
        .cwd_deny = &.{},
        .read_paths = &.{root},
        .write_paths = &.{root},
        .read_deny = &.{try f.path("read-secret")},
        .write_deny = &.{try f.path("write-secret")},
        .write_max_mode = 0o700,
        .max_timeout_s = 30,
    };

    const a = f.arena.allocator();
    const json = try std.fmt.allocPrint(a, "{{\"source\":\"{s}\",\"destination\":\"{s}\"}}", .{ src, dst });
    const args = try std.json.parseFromSlice(std.json.Value, a, json, .{ .allocate = .alloc_always });
    var pins: ?policy.CopyPins = null;
    try t.expect(policy.checkCopyArgs(a, io, &pol, args.value, &pins) == null);
    try t.expectEqualStrings(pol.read_deny[0], pins.?.source.deny[0]);
    try t.expectEqualStrings(pol.write_deny[0], pins.?.destination.deny[0]);
    pol.write_paths = &.{try f.path("elsewhere")};
    const deny = policy.checkCopyArgs(a, io, &pol, args.value, &pins).?;
    try t.expectEqualStrings("destination", deny.field);
    try t.expect(pins == null);
}

test "copy: timeout cap and tool membership gate before pins" {
    var f = try Fixture.init();
    defer f.deinit();
    const a = f.arena.allocator();
    const args = try std.json.parseFromSlice(std.json.Value, a, "{\"source\":\"src\",\"destination\":\"dst\",\"timeout\":31}", .{});
    var pol = policy.TokenPolicy{
        .file = "",
        .token_hash = [_]u8{0} ** 32,
        .tools = &.{"copy_path"},
        .exec_argv0 = &.{},
        .exec_cwd = &.{},
        .cwd_deny = &.{},
        .read_paths = &.{"/"},
        .write_paths = &.{"/"},
        .read_deny = &.{},
        .write_deny = &.{},
        .max_timeout_s = 30,
    };
    var pins: ?policy.CopyPins = null;
    try t.expectEqualStrings("timeout_exceeds_cap", policy.checkCopyArgs(a, io, &pol, args.value, &pins).?.reason_tag);
    pol.tools = &.{"read_file"};
    try t.expectEqualStrings("tool_not_allowed", policy.checkCopyArgs(a, io, &pol, args.value, &pins).?.reason_tag);
    try t.expect(pins == null);
}

test "copy: gate passes absent or empty paths through to the tool shape error" {
    var f = try Fixture.init();
    defer f.deinit();
    const a = f.arena.allocator();
    var pol = policy.TokenPolicy{
        .file = "",
        .token_hash = [_]u8{0} ** 32,
        .tools = &.{"copy_path"},
        .exec_argv0 = &.{},
        .exec_cwd = &.{},
        .cwd_deny = &.{},
        .read_paths = &.{"/"},
        .write_paths = &.{"/"},
        .read_deny = &.{},
        .write_deny = &.{},
        .max_timeout_s = 30,
    };
    var pins: ?policy.CopyPins = null;
    // Absent destination: the tool answers InvalidParams, not the gate
    // (uniform shape errors with and without a policy file).
    const missing = try std.json.parseFromSlice(std.json.Value, a, "{\"source\":\"src\"}", .{});
    try t.expect(policy.checkCopyArgs(a, io, &pol, missing.value, &pins) == null);
    // Empty source: same pass-through.
    const empty = try std.json.parseFromSlice(std.json.Value, a, "{\"source\":\"\",\"destination\":\"dst\"}", .{});
    try t.expect(policy.checkCopyArgs(a, io, &pol, empty.value, &pins) == null);
    // Wrong-typed source: the gate still refuses.
    const bad = try std.json.parseFromSlice(std.json.Value, a, "{\"source\":7,\"destination\":\"dst\"}", .{});
    const deny = policy.checkCopyArgs(a, io, &pol, bad.value, &pins).?;
    try t.expectEqualStrings("bad_argument_type", deny.reason_tag);
    try t.expectEqualStrings("source", deny.field);
    try t.expect(pins == null);
}

test "copy: symlink ancestor remains forbidden without policy" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.tmp.dir.createDirPath(io, "real");
    try f.write("real/a", "abc");
    try f.tmp.dir.symLink(io, "real", "src", .{ .is_directory = true });
    try t.expectError(error.SymlinkNotAllowed, copy.run(f.arena.allocator(), io, try f.pins("src/a", "dst"), .{}));
    try f.absent("dst");
}

test "copy: destination parent symlink is refused" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.write("src", "abc");
    try f.tmp.dir.createDirPath(io, "real");
    try f.tmp.dir.symLink(io, "real", "parent", .{ .is_directory = true });
    try t.expectError(error.SymlinkNotAllowed, copy.run(f.arena.allocator(), io, try f.pins("src", "parent/dst"), .{}));
    try f.absent("real/dst");
}

test "copy: empty file digest is standard SHA256" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.write("src", "");
    const r = try f.run(.{});
    try t.expectEqualStrings("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", &std.fmt.bytesToHex(r.digest, .lower));
}

test "copy: accounting hard ceilings reject before side effects" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.write("src", "abc");
    try t.expectError(error.CopyLimitExceeded, f.run(.{ .max_bytes = std.math.maxInt(u64) }));
    try t.expectError(error.CopyLimitExceeded, f.run(.{ .max_entries = 10001 }));
    try t.expectError(error.CopyLimitExceeded, f.run(.{ .max_entries = 0 }));
    try f.absent("dst");
}

test "copy: component validation rejects traversal and NUL" {
    try t.expect(!secure.copyValidName(".."));
    try t.expect(!secure.copyValidName("."));
    try t.expect(!secure.copyValidName("a/b"));
    try t.expect(!secure.copyValidName("a\x00b"));
    try t.expect(secure.copyValidName("ordinary"));
}

test "copy: audit summaries include both paths but never contents" {
    const audit = @import("audit.zig");
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const args = try std.json.parseFromSlice(std.json.Value, arena.allocator(), "{\"source\":\"/read/a\",\"destination\":\"/write/b\",\"max_bytes\":1024,\"content\":\"private payload\"}", .{});
    inline for (.{ audit.ArgsMode.summary, audit.ArgsMode.full }) |mode| {
        var buf: audit.Buf = undefined;
        buf.reset();
        audit.appendArgsSummary(&buf, "copy_path", args.value, mode);
        const parsed = try std.json.parseFromSlice(std.json.Value, arena.allocator(), buf.slice(), .{});
        try t.expectEqualStrings("/read/a", parsed.value.object.get("source").?.string);
        try t.expectEqualStrings("/write/b", parsed.value.object.get("destination").?.string);
        try t.expectEqual(@as(i64, 1024), parsed.value.object.get("max_bytes").?.integer);
        try t.expect(std.mem.indexOf(u8, buf.slice(), "private payload") == null);
    }
}

test "copy: depth cap also applies to regular file descendants" {
    var f = try Fixture.init();
    defer f.deinit();
    var path: std.ArrayList(u8) = .empty;
    const a = f.arena.allocator();
    try path.appendSlice(a, "src");
    for (0..64) |_| try path.appendSlice(a, "/d");
    try f.tmp.dir.createDirPath(io, path.items);
    try path.appendSlice(a, "/a");
    try f.write(path.items, "abc");
    try t.expectError(error.CopyDepthExceeded, f.run(.{ .recursive = true }));
    try f.absent("dst");
}
