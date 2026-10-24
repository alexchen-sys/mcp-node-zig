//! File-backed backend. No pipe readers and no supervisor: child output is
//! written by the kernel directly to the append-only log descriptors.
const std = @import("std");
const builtin = @import("builtin");
const disk_mod = @import("durable.zig");
const sessions = @import("session.zig");
const proc = @import("os/proc.zig");
const os = @import("os.zig");
const audit = @import("audit.zig");
const a = std.heap.page_allocator;

pub const Backend = struct {
    disk: *disk_mod.Disk,
    dir: std.posix.fd_t,
    stdout: std.posix.fd_t,
    stderr: std.posix.fd_t,
    meta: disk_mod.Meta,
    recovered: bool = false,
    retired: bool = false,
    leader_reaped: bool = false,
    output_settling: bool = false,
    writer: ?*audit.Writer = null,

    pub fn completionReason(self: *const Backend) ?disk_mod.CompletionReason {
        return if (self.meta.flags & disk_mod.OUTPUT_CAP_FLAG != 0) .output_cap else null;
    }

    pub fn identity(self: *const Backend) proc.ProcessIdentity {
        return .{ .pid = self.meta.pid, .pgid = self.meta.pgid, .start_time_ticks = self.meta.start_time_ticks, .boot_id = self.meta.boot_id };
    }

    pub fn commit(self: *Backend, s: *sessions.Session) !void {
        const bytes = try self.meta.encode(a, s.cwd, s.argv);
        defer a.free(bytes);
        try self.disk.atomicWrite(self.dir, "meta.tmp", "meta.bin", bytes);
    }

    pub fn deinit(self: *Backend) void {
        os.closeFd(self.stdout);
        os.closeFd(self.stderr);
        os.closeFd(self.dir);
        a.destroy(self);
    }
};

pub fn event(w: ?*audit.Writer, name: []const u8, key: []const u8, value: []const u8) void {
    const writer = w orelse return;
    var b: audit.Buf = undefined;
    b.reset();
    b.append("\"event\":");
    b.jsonStrCap(name, 64);
    b.append(",");
    b.jsonStrCap(key, 32);
    b.append(":");
    b.jsonStrCap(value, 64);
    writer.enqueueInner(b.slice());
}

pub var test_fail_after_stdout: bool = false;

pub fn create(disk: *disk_mod.Disk, id: u64, cap: usize, owner: [32]u8) !*Backend {
    if (comptime builtin.os.tag != .linux) return error.DurabilityUnsupported;
    try disk.reserve(cap);
    errdefer disk.unreserve(cap);
    var name_buf: [32]u8 = undefined;
    const name = try std.fmt.bufPrint(&name_buf, "{d}", .{id});
    errdefer abortAdmission(disk, id, owner) catch {
        disk.failed = true;
    };
    try disk_mod.makeDir(disk.sessions, name);
    const dir = try disk_mod.openDir(disk.sessions, name);
    errdefer os.closeFd(dir);
    const stdout = try disk_mod.openFile(dir, "stdout.log", true);
    errdefer os.closeFd(stdout);
    if (builtin.is_test and test_fail_after_stdout) return error.InjectedCreateFailure;
    const stderr = try disk_mod.openFile(dir, "stderr.log", true);
    errdefer os.closeFd(stderr);
    const b = try a.create(Backend);
    b.* = .{ .disk = disk, .dir = dir, .stdout = stdout, .stderr = stderr, .meta = .{ .session_id = id, .max_out = cap } };
    return b;
}

fn capture(io: std.Io, fd: std.posix.fd_t, cap: u64, list: *std.ArrayList(u8), lost: *u64, truncated: *bool) !u64 {
    const file = disk_mod.asFile(fd);
    const total = (try file.stat(io)).size;
    const retained: usize = @intCast(@min(total, cap));
    try list.resize(a, retained);
    if (try file.readPositionalAll(io, list.items, 0) != retained) return error.DurableStorageFailed;
    // The prefix is only a cache. The spool remains the complete record.
    lost.* = 0;
    _ = truncated; // Cap-kill truncation is sticky, not cache truncation.
    return total;
}

pub const SpoolPage = struct {
    raw: []const u8,
    total: u64,
    remaining: u64,
};

/// Read through the descriptor pinned by create/recovery, never a pathname.
/// The caller holds the session mutex and has reconciled completion first.
/// Three lookahead bytes let the shared renderer trim a crossing codepoint
/// without allocating in proportion to the spool or sanitizing bytes twice.
pub fn readPage(allocator: std.mem.Allocator, io: std.Io, fd: std.posix.fd_t, offset: i64, cap: usize) !SpoolPage {
    if (offset < 0) return error.BadOffset;
    const file = disk_mod.asFile(fd);
    const total = (try file.stat(io)).size;
    const start: u64 = @intCast(offset);
    if (start > total) return error.BadOffset;
    const remaining = total - start;
    const raw = try allocator.alloc(u8, @intCast(@min(remaining, cap +| 3)));
    errdefer allocator.free(raw);
    if (try file.readPositionalAll(io, raw, start) != raw.len) return error.DurableStorageFailed;
    return .{ .raw = raw, .total = total, .remaining = remaining };
}

/// Cheap live-session check: stat only the two pinned spool descriptors.
/// Never limit unrelated child files, trim logs, or signal an unverified PID.
/// The caller holds the session mutex, also serializing owner reaping.
pub fn enforceLogCapLocked(s: *sessions.Session, io: std.Io) !void {
    const b = s.durable orelse return;
    if (b.retired) return;
    // The reservation covers BOTH streams (2*max_out + slack total): a
    // per-file check would admit 4x max_out against that budget, so the kill
    // threshold is the combined spool size. Per-stream truncation flags
    // still track each stream against
    // its own max_out share.
    const cap = std.math.mul(u64, b.meta.max_out, 2) catch return error.DurableCapacityExceeded;
    const out_size = (try disk_mod.asFile(b.stdout).stat(io)).size;
    const err_size = (try disk_mod.asFile(b.stderr).stat(io)).size;
    const combined = std.math.add(u64, out_size, err_size) catch return error.DurableCapacityExceeded;
    if (combined <= cap) return;
    s.truncated_stdout = s.truncated_stdout or out_size > b.meta.max_out;
    s.truncated_stderr = s.truncated_stderr or err_size > b.meta.max_out;
    if (!s.done) {
        sessions.killTreeGuarded(s, io);
        // An indeterminate/dead identity never authorizes a signal or a claim
        // that the node killed it. Retry on the next refresh/sweep if needed.
        if (!s.tree_killed.load(.acquire)) return;
    }

    // Done sessions stay monitored: an orphaned descendant holding the spool
    // descriptors can keep appending after the leader exit, and the leader's
    // death makes the group unsafe to signal — so the overrun is journaled
    // and flagged (readable bytes stay pollable) instead of killed.
    const flags = b.meta.flags | disk_mod.OUTPUT_CAP_FLAG |
        (if (s.truncated_stdout) @as(u8, 4) else 0) |
        (if (s.truncated_stderr) @as(u8, 8) else 0) |
        (if (s.tree_killed.load(.acquire)) @as(u8, 2) else 0);
    if (flags != b.meta.flags) {
        b.meta.flags = flags;
        try b.commit(s);
    }
}

/// Called with the session mutex held. Completion is journaled before it is
/// exposed; a storage error stays visible to the caller, never a false done.
/// `full` requests the prefix rescan; the sweep passes false so a live
/// leader skips the re-read of up to 2 x max_out per stream on that path
/// (the per-tick total is the cap-check fstats plus one identity check).
pub fn refreshLocked(s: *sessions.Session, io: std.Io, full: bool) !void {
    const b = s.durable orelse return;
    if (b.retired) return;
    try enforceLogCapLocked(s, io);
    if (!s.done and !b.leader_reaped and proc.verifyProcessIdentity(b.identity()) != .dead) {
        if (!full) return;
    }
    var out_total = try capture(io, b.stdout, b.meta.max_out, &s.stdout, &s.lost_stdout_bytes, &s.truncated_stdout);
    var err_total = try capture(io, b.stderr, b.meta.max_out, &s.stderr, &s.lost_stderr_bytes, &s.truncated_stderr);
    if (s.done) {
        if (out_total < b.meta.final_stdout_total or err_total < b.meta.final_stderr_total) return error.CorruptDurableRecord;
        if (out_total != b.meta.final_stdout_total or err_total != b.meta.final_stderr_total) {
            b.meta.final_stdout_total = out_total;
            b.meta.final_stderr_total = err_total;
            try b.commit(s);
        }
        return;
    }
    if (!b.leader_reaped and proc.verifyProcessIdentity(b.identity()) != .dead) return;
    if (!b.recovered and !b.leader_reaped) {
        // Only our unreaped child may be waited here. It remains registered
        // against the generic stray sweep until this exact owner reaps it.
        const term = try s.child.wait(io);
        s.exit_code = sessions.termExitCode(term);
        proc.unregisterSpawnPid(io, s.pid, s.registry_tag);
    } else event(b.writer, "session.orphan_skip", "reason", "pid_reused_or_dead");
    b.leader_reaped = true;
    // Reap first, then sample again: no leader write can race these totals.
    out_total = try capture(io, b.stdout, b.meta.max_out, &s.stdout, &s.lost_stdout_bytes, &s.truncated_stdout);
    err_total = try capture(io, b.stderr, b.meta.max_out, &s.stderr, &s.lost_stderr_bytes, &s.truncated_stderr);
    os.sleepMs(100);
    const settled_out = try capture(io, b.stdout, b.meta.max_out, &s.stdout, &s.lost_stdout_bytes, &s.truncated_stdout);
    const settled_err = try capture(io, b.stderr, b.meta.max_out, &s.stderr, &s.lost_stderr_bytes, &s.truncated_stderr);
    b.output_settling = settled_out != out_total or settled_err != err_total;
    if (b.output_settling) return; // Descendant still writing; retry next poll.
    b.meta.state = .done;
    b.meta.ended_us = sessions.nowUs(io);
    b.meta.final_stdout_total = out_total;
    b.meta.final_stderr_total = err_total;
    b.meta.flags = (b.meta.flags & disk_mod.OUTPUT_CAP_FLAG) | (if (s.exit_code != null) @as(u8, 1) else 0) |
        (if (s.tree_killed.load(.acquire)) @as(u8, 2) else 0) |
        (if (s.truncated_stdout) @as(u8, 4) else 0) |
        (if (s.truncated_stderr) @as(u8, 8) else 0);
    b.meta.exit_code = s.exit_code orelse 0;
    try disk_mod.syncFd(b.stdout);
    try disk_mod.syncFd(b.stderr);
    try b.commit(s);
    s.done = true;
    s.ended_us = b.meta.ended_us;
    s.done_event.set(io);
}

pub fn refresh(s: *sessions.Session, io: std.Io) !void {
    if (s.durable == null) return;
    s.mutex.lockUncancelable(io);
    defer s.mutex.unlock(io);
    try refreshLocked(s, io, true);
}

/// Persist the owner-bound tombstone before unlinking any files. A crash at
/// any later step cannot resurrect a closed session. The wire state has no
/// 'closed' value: closed_by_client is represented by the index tombstone.
pub fn retire(s: *sessions.Session, reason: disk_mod.Reason, io: std.Io) !void {
    if (comptime builtin.os.tag != .linux) return error.DurabilityUnsupported;
    const b = s.durable orelse return;
    s.mutex.lockUncancelable(io);
    defer s.mutex.unlock(io);
    if (b.retired) return;
    try disk_mod.syncFd(b.stdout);
    try disk_mod.syncFd(b.stderr);
    b.disk.mutex.lockUncancelable(io);
    defer b.disk.mutex.unlock(io);
    b.disk.index.push(.{ .id = s.id, .owner_hash = s.owner_hash, .reason = reason });
    try b.disk.writeIndex();
    b.retired = true;
    b.disk.reserved -|= try disk_mod.reservation(b.meta.max_out);
    for ([_][:0]const u8{ "meta.bin", "meta.tmp", "stdout.log", "stderr.log" }) |name| {
        const rc = std.os.linux.unlinkat(b.dir, name, 0);
        if (std.os.linux.errno(rc) != .SUCCESS and std.os.linux.errno(rc) != .NOENT) return error.DurableStorageFailed;
    }
    try disk_mod.syncFd(b.dir);
    var buf: [32]u8 = undefined;
    const name = try std.fmt.bufPrintZ(&buf, "{d}", .{s.id});
    if (std.os.linux.errno(std.os.linux.unlinkat(b.disk.sessions, name, std.os.linux.AT.REMOVEDIR)) != .SUCCESS) return error.DurableStorageFailed;
    try disk_mod.syncFd(b.disk.sessions);
}

fn recoverOne(store: *sessions.SessionStore, disk: *disk_mod.Disk, name: []const u8, id: u64, writer: ?*audit.Writer) !void {
    const dir = try disk_mod.openDir(disk.sessions, name);
    errdefer os.closeFd(dir);
    const bytes = try disk.readRecord(dir, "meta.bin", 192 + disk_mod.REGION_LIMIT);
    defer a.free(bytes);
    const decoded = try disk_mod.Meta.decode(bytes);
    var meta = decoded.meta;
    if (meta.session_id != id or id >= disk.index.next_id or meta.os_tag != .linux or meta.pid <= 0 or meta.pid > std.math.maxInt(i32) or meta.pgid != meta.pid or meta.max_out > std.math.maxInt(usize)) return error.CorruptDurableRecord;
    const stdout = try disk_mod.openFile(dir, "stdout.log", false);
    errdefer os.closeFd(stdout);
    const stderr = try disk_mod.openFile(dir, "stderr.log", false);
    errdefer os.closeFd(stderr);
    const out_size = (try disk_mod.asFile(stdout).stat(store.io)).size;
    const err_size = (try disk_mod.asFile(stderr).stat(store.io)).size;
    if (meta.state != .running and (out_size < meta.final_stdout_total or err_size < meta.final_stderr_total)) return error.CorruptDurableRecord;
    const argv = try a.alloc([]const u8, decoded.argc);
    var filled: usize = 0;
    errdefer {
        for (argv[0..filled]) |arg| a.free(arg);
        a.free(argv);
    }
    var off: usize = 0;
    for (argv) |*arg| {
        const len = std.mem.readInt(u32, decoded.argv_region[off..][0..4], .little);
        off += 4;
        arg.* = try a.dupe(u8, decoded.argv_region[off..][0..len]);
        filled += 1;
        off += len;
    }

    const cwd = try a.dupe(u8, decoded.cwd);
    errdefer a.free(cwd);
    const b = try a.create(Backend);
    errdefer a.destroy(b);
    b.* = .{ .disk = disk, .dir = dir, .stdout = stdout, .stderr = stderr, .meta = meta, .recovered = true, .writer = writer };
    const s = try a.create(sessions.Session);
    errdefer a.destroy(s);
    s.* = .{ .id = id, .pid = @intCast(meta.pid), .argv = argv, .cwd = cwd, .child = undefined, .stdin_fd = null, .started_us = meta.started_us, .ended_us = if (meta.state != .running) meta.ended_us else null, .done = meta.state != .running, .exit_code = if (meta.flags & 1 != 0) meta.exit_code else null, .owner_hash = meta.owner_hash, .durable = b };
    errdefer {
        s.stdout.deinit(a);
        s.stderr.deinit(a);
    }
    s.tree_killed.store(meta.flags & 2 != 0, .release);
    s.truncated_stdout = meta.flags & 4 != 0;
    s.truncated_stderr = meta.flags & 8 != 0;
    if (meta.state == .running and !std.mem.eql(u8, &meta.boot_id, &(proc.readBootId() catch meta.boot_id))) {
        meta.state = .interrupted;
        meta.flags &= ~@as(u8, 1);
        meta.exit_code = 0;
        meta.ended_us = sessions.nowUs(store.io);
        meta.final_stdout_total = out_size;
        meta.final_stderr_total = err_size;
        b.meta = meta;
        try b.commit(s);
        s.done = true;
        s.exit_code = null;
        s.ended_us = meta.ended_us;
        event(writer, "session.interrupted", "reason", "boot_changed");
    }
    try refreshLocked(s, store.io, true);
    if (s.done) s.done_event.set(store.io);
    const reserved = try disk_mod.reservation(meta.max_out);
    const total = std.math.add(u64, disk.reserved, reserved) catch return error.DurableCapacityExceeded;
    // Recovery keeps over-cap sessions visible; new admissions remain blocked.
    try store.map.put(id, s);
    disk.reserved = total;
    event(writer, "session.recover", "status", if (s.done) "finished" else if (proc.verifyProcessIdentity(b.identity()) == .indeterminate) "kept_not_signaled" else "running");
}

pub fn recover(store: *sessions.SessionStore, disk: *disk_mod.Disk, writer: ?*audit.Writer) !void {
    if (comptime builtin.os.tag != .linux) return error.DurabilityUnsupported;
    var dir: std.Io.Dir = .{ .handle = disk.sessions };
    var it = dir.iterate();
    var count: usize = 0;
    while (try it.next(store.io)) |entry| {
        if (entry.name.len == 0 or entry.name[0] == '0') continue;
        var decimal = true;
        for (entry.name) |c| if (c < '0' or c > '9') {
            decimal = false;
            break;
        };
        if (!decimal) continue;
        const id = std.fmt.parseInt(u64, entry.name, 10) catch continue;
        count += 1;
        if (count > 65536) return error.DurableCapacityExceeded;
        var retired = false;
        for (disk.index.tombstones) |t| if (t.id == id) {
            retired = true;
            break;
        };
        if (retired) {
            // Finish the deferred cleanup: a leftover whose tombstone evicts
            // from the ring would otherwise be re-admitted on a later
            // restart. Best-effort, pinned-parent, name-only
            // unlinks; a failure leaves the tombstone in place and the next
            // restart retries.
            var name_buf: [32]u8 = undefined;
            const zname = std.fmt.bufPrintZ(&name_buf, "{d}", .{id}) catch continue;
            if (disk_mod.openDir(disk.sessions, entry.name)) |d| {
                for ([_][:0]const u8{ "meta.bin", "meta.tmp", "stdout.log", "stderr.log" }) |f|
                    _ = std.os.linux.unlinkat(d, f, 0);
                os.closeFd(d);
            } else |_| {}
            _ = std.os.linux.unlinkat(disk.sessions, zname, std.os.linux.AT.REMOVEDIR);
            continue;
        }
        recoverOne(store, disk, entry.name, id, writer) catch |err| {
            // Classification matters: a missing piece
            // (interrupted admission, externally removed spool) or a corrupt
            // record can never become recoverable — quarantine it. Anything
            // else (fd pressure, allocation, transient I/O) is operational:
            // propagate so the node refuses to start and a later restart
            // retries with the directory intact.
            switch (err) {
                // FileNotFound: crash-window admission or removed spool.
                // CorruptDurableRecord: content failed validation. Both are
                // provably unrecoverable entries. DurableStorageFailed and
                // everything else (fd pressure, ENOSPC/EIO, allocation) is
                // operational: propagate, refuse to start, let a later
                // restart retry with the directory intact — the generic
                // storage error must never retire a healthy record.
                error.FileNotFound, error.CorruptDurableRecord => {},
                else => return err,
            }
            event(writer, "session.quarantine", "reason", @errorName(err));
            // Rename the directory itself through the pinned parent. Never
            // follow it and never inspect a PID after a validation failure.
            var src_buf: [32]u8 = undefined;
            var dst_buf: [64]u8 = undefined;
            const src = try std.fmt.bufPrintZ(&src_buf, "{d}", .{id});
            const dst = try std.fmt.bufPrintZ(&dst_buf, "quarantine-{d}", .{id});
            const rename_rc = std.os.linux.errno(std.os.linux.renameat(disk.sessions, src, disk.sessions, dst));
            // An entry that vanished between the scan and here needs no
            // quarantine at all; every other rename failure is operational.
            if (rename_rc == .NOENT) continue;
            if (rename_rc != .SUCCESS) return error.DurableStorageFailed;
            try disk_mod.syncFd(disk.sessions);
            // Retire the id so the next restart skips the quarantined entry
            // instead of re-attempting the rename onto an existing dir.
            disk.index.push(.{ .id = id, .owner_hash = [_]u8{0} ** 32, .reason = .closed_by_client });
            try disk.writeIndex();
            event(writer, "session.recover", "status", "corrupt_dropped");
        };
    }
    store.reapDone();
}

/// Roll back every created object only after the durable anti-resurrection
/// marker is committed. A failed marker makes future admissions fail closed.
pub fn abortAdmission(disk: *disk_mod.Disk, id: u64, owner: [32]u8) !void {
    disk.mutex.lockUncancelable(disk.io);
    defer disk.mutex.unlock(disk.io);
    disk.index.push(.{ .id = id, .owner_hash = owner, .reason = .closed_by_client });
    try disk.writeIndex();
    var buf: [32]u8 = undefined;
    const name = try std.fmt.bufPrintZ(&buf, "{d}", .{id});
    const dir = try disk_mod.openDir(disk.sessions, name);
    defer os.closeFd(dir);
    for ([_][:0]const u8{ "meta.bin", "meta.tmp", "stdout.log", "stderr.log" }) |file| {
        const err = std.os.linux.errno(std.os.linux.unlinkat(dir, file, 0));
        if (err != .SUCCESS and err != .NOENT) return error.DurableStorageFailed;
    }
    if (std.os.linux.errno(std.os.linux.unlinkat(disk.sessions, name, std.os.linux.AT.REMOVEDIR)) != .SUCCESS) return error.DurableStorageFailed;
    try disk_mod.syncFd(disk.sessions);
}
