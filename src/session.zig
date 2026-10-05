//! Process-session lifecycle: Session state and ref counting, the
//! SessionStore map with join-before-free eviction and TTL reaping,
//! pipe reader and waiter thread bodies, guarded process-tree kills,
//! and UTF-8-safe session state rendering. Tool-call orchestration
//! (exec_start and friends) lives in tools.zig.

const std = @import("std");
const builtin = @import("builtin");

const Allocator = std.mem.Allocator;
const Io = std.Io;
const os = @import("os.zig");
const proc = @import("os/proc.zig");
const util = @import("util.zig");

const REAP_BATCH_SIZE: usize = 8; // sessions freed per SessionStore sweep
const READER_POLL_MS: i32 = 100; // session pipe poll tick; bounds exec_close reap latency
const DRAIN_GRACE_MS: i64 = 1000; // bounded post-kill window for readers to collect available output when an escaped grandchild holds the pipes
const READER_EXIT_MS: i64 = 10 * READER_POLL_MS; // hard cap waiting for readers to observe closing before reap closes their fds

const DEFAULT_SESSION_TTL_MS: i64 = 600_000;

pub const Session = struct {
    id: u64,
    /// Integer pid on every OS (display-only on Windows; control goes
    /// through the job/handle). See os/proc.zig.
    pid: proc.ProcessId,
    argv: [][]const u8,
    cwd: []const u8,
    child: std.process.Child,
    stdin_fd: ?std.posix.fd_t,
    /// Windows: Job Object owning the whole process tree (KILL_ON_JOB_CLOSE).
    /// void on POSIX. Closed in freeSession.
    job: proc.JobField = proc.no_job,
    stdin_mutex: std.Io.Mutex = .init,
    stdout_thread: ?std.Thread = null,
    stderr_thread: ?std.Thread = null,
    waiter_thread: ?std.Thread = null,
    mutex: std.Io.Mutex = .init,
    stdout: std.ArrayList(u8) = .empty,
    stderr: std.ArrayList(u8) = .empty,
    done: bool = false,
    exit_code: ?i64 = null,
    truncated_stdout: bool = false,
    truncated_stderr: bool = false,
    /// Session start on the real clock, in microseconds (sub-ms sessions
    /// would render duration_ms: 0; duration_us keeps the precision).
    started_us: i64,
    ended_us: ?i64 = null,
    // Lifecycle: store holds 1 ref while the session is in the map; every
    // in-flight tool call holds +1 via sessionFromArgs/defer sessionRelease.
    // freeSession runs only when refs hit 0 (always after thread joins).
    refs: std.atomic.Value(u32) = std.atomic.Value(u32).init(1),
    closing: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// Set once the whole process tree is known dead (POSIX: the waiter
    /// killed the process group while the leader zombie still pinned the
    /// pgid, so the kill could never hit a recycled group). exec_kill /
    /// exec_close test-and-skip on this so a late SIGKILL can never land on
    /// a recycled process group.
    tree_killed: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// Serializes the kill decision against the waiter's reap: killers hold
    /// this across {tree_killed check, killTree, tree_killed store} (see
    /// killTreeGuarded); the waiter holds it across child.wait() once the
    /// leader is known dead. A bare tree_killed bool leaves a check/kill/reap
    /// race: load(false) → context switch → waiter kill+reap → late kill at
    /// a recycled pgid.
    kill_mutex: std.Io.Mutex = .init,
    /// Number of pipe-reader threads that finished draining (stdout/stderr).
    /// The waiter gates done=true on this so `done` implies final output is
    /// fully drained.
    readers_done: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
};

pub const SessionStore = struct {
    mutex: std.Io.Mutex = .init,
    io: Io,
    map: std.AutoHashMap(u64, *Session),
    next_id: u64 = 1,
    max: u16,
    ttl_ms: i64 = DEFAULT_SESSION_TTL_MS,

    pub fn init(io: Io, max_sessions: u16) SessionStore {
        return .{ .io = io, .map = std.AutoHashMap(u64, *Session).init(std.heap.page_allocator), .max = max_sessions };
    }

    pub fn put(self: *SessionStore, session: *Session) !void {
        self.reapDone();
        // Lazy evict: pick a finished victim under the lock, but join/free it
        // AFTER unlocking so other connections are not blocked for the join.
        var victim: ?*Session = null;
        {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            if (self.map.count() >= self.max) {
                var it = self.map.iterator();
                while (it.next()) |kv| {
                    const s = kv.value_ptr.*;
                    s.mutex.lockUncancelable(self.io);
                    const is_done = s.done;
                    s.mutex.unlock(self.io);
                    if (!is_done) continue;
                    _ = self.map.fetchRemove(kv.key_ptr.*);
                    victim = s;
                    break;
                }
                if (victim == null) return error.TooManySessions;
            }
            self.map.put(session.id, session) catch |err| {
                // Insert failed after an evict: don't strand the victim. Its
                // session is done, so these joins return immediately.
                if (victim) |s| {
                    s.closing.store(true, .release);
                    if (s.waiter_thread) |t| t.join();
                    if (s.stdout_thread) |t| t.join();
                    if (s.stderr_thread) |t| t.join();
                    sessionRelease(s);
                }
                return err;
            };
        }
        if (victim) |s| {
            s.closing.store(true, .release);
            if (s.waiter_thread) |t| t.join();
            if (s.stdout_thread) |t| t.join();
            if (s.stderr_thread) |t| t.join();
            sessionRelease(s); // drop the store's ref
        }
    }

    pub fn get(self: *SessionStore, id: u64) ?*Session {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const session = self.map.get(id) orelse return null;
        _ = session.refs.fetchAdd(1, .acq_rel);
        return session;
    }

    pub fn remove(self: *SessionStore, id: u64) ?*Session {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const kv = self.map.fetchRemove(id) orelse return null;
        return kv.value;
    }

    pub fn reapDone(self: *SessionStore) void {
        // Sweep sessions that finished more than ttl_ms ago. Removal happens
        // under the lock, joins/frees outside it (victim threads are done or
        // exit within one 100ms reader tick via the closing flag).
        var victims: [REAP_BATCH_SIZE]*Session = undefined;
        var n: usize = 0;
        {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            while (n < victims.len) {
                var found_key: ?u64 = null;
                var found_s: ?*Session = null;
                var it = self.map.iterator();
                while (it.next()) |kv| {
                    const s = kv.value_ptr.*;
                    s.mutex.lockUncancelable(self.io);
                    const is_done = s.done;
                    const ended = s.ended_us;
                    s.mutex.unlock(self.io);
                    if (!is_done) continue;
                    const ended_v = ended orelse continue;
                    if (nowUs(self.io) - ended_v < @as(i64, self.ttl_ms) * std.time.us_per_ms) continue;
                    found_key = kv.key_ptr.*;
                    found_s = s;
                    break;
                }
                if (found_key == null) break;
                _ = self.map.fetchRemove(found_key.?);
                victims[n] = found_s.?;
                n += 1;
            }
        }
        for (victims[0..n]) |s| {
            s.closing.store(true, .release);
            if (s.waiter_thread) |t| t.join();
            if (s.stdout_thread) |t| t.join();
            if (s.stderr_thread) |t| t.join();
            sessionRelease(s); // drop the store's ref
        }
    }

    pub fn allocId(self: *SessionStore) u64 {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const id = self.next_id;
        self.next_id += 1;
        return id;
    }

    /// Kill the process tree of every session still in the store. Used at
    /// shutdown by transports that end (stdio EOF): sessions run in their
    /// own process group, so without this they would outlive the server.
    /// Nothing is freed; the process is about to exit.
    pub fn killAll(self: *SessionStore) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        var it = self.map.iterator();
        while (it.next()) |kv| killTreeGuarded(kv.value_ptr.*, self.io);
    }
};

pub fn nowUs(io: Io) i64 {
    return std.Io.Clock.real.now(io).toMicroseconds();
}

/// Child.id is a HANDLE on Windows: resolve the real integer pid through
/// NtQueryInformationProcess (display-only). POSIX passes the pid through.
pub fn childPidOrZero(id: ?std.process.Child.Id) proc.ProcessId {
    if (comptime builtin.os.tag == .windows) {
        const handle = id orelse return 0;
        return proc.queryProcessId(handle) orelse 0;
    } else {
        return id orelse 0;
    }
}

/// ProcessId is an integer on every OS (pid_t on POSIX, u32 on Windows), so
/// pid JSON rendering works everywhere.
pub fn pidJsonValue(pid: proc.ProcessId) u64 {
    return @intCast(pid);
}

fn termExitCode(term: std.process.Child.Term) i64 {
    return switch (term) {
        .exited => |code| code,
        .signal => |sig| 128 + @as(i64, @intCast(@intFromEnum(sig))),
        .stopped => |sig| 128 + @as(i64, @intCast(@intFromEnum(sig))),
        .unknown => |code| @as(i64, @intCast(code)),
    };
}

fn appendSessionOutput(list: *std.ArrayList(u8), bytes: []const u8, max_out: usize, truncated: *bool) void {
    if (list.items.len >= max_out) {
        truncated.* = true;
        return;
    }
    const avail = max_out - list.items.len;
    const take = @min(avail, bytes.len);
    if (take > 0) {
        list.appendSlice(std.heap.page_allocator, bytes[0..take]) catch {
            truncated.* = true;
            return;
        };
    }
    if (take < bytes.len) truncated.* = true;
}

pub fn sessionReaderMain(session: *Session, fd: std.posix.fd_t, is_stdout: bool, max_out: usize, io: Io) void {
    defer _ = session.readers_done.fetchAdd(1, .acq_rel);
    if (comptime builtin.os.tag == .windows) {
        // Blocking NtReadFile loop (no poll tick on this OS). Termination is
        // guaranteed by the Job Object: exec_kill/exec_close run
        // TerminateJobObject, the waiter terminates the job when the child
        // exits, and grandchildren auto-join the job (Win8+) — so every write
        // end of the pipe eventually closes and the pending read completes
        // with PIPE_BROKEN (EOF). session.closing is still honored between
        // reads for the already-EOF fast path.
        var wbuf: [util.IO_BUF_SIZE]u8 = undefined;
        while (true) {
            if (session.closing.load(.acquire)) break;
            const n = proc.readPipeBlocking(fd, &wbuf) orelse break;
            if (n == 0) break;
            session.mutex.lockUncancelable(io);
            if (is_stdout) {
                appendSessionOutput(&session.stdout, wbuf[0..n], max_out, &session.truncated_stdout);
            } else {
                appendSessionOutput(&session.stderr, wbuf[0..n], max_out, &session.truncated_stderr);
            }
            session.mutex.unlock(io);
        }
        return;
    }
    // POSIX path: poll-tick loop.
    {
        var buf: [util.IO_BUF_SIZE]u8 = undefined;
        while (true) {
            // Poll instead of blind blocking read: exec_close must be able to reap
            // the session even if a grandchild escaped the process group and holds
            // the pipe write-end open forever.
            if (session.closing.load(.acquire)) break;
            var pfd = [_]std.posix.pollfd{.{ .fd = fd, .events = std.posix.POLL.IN, .revents = 0 }};
            const ready = std.posix.poll(&pfd, READER_POLL_MS) catch break;
            if (ready == 0) continue;
            if (pfd[0].revents & (std.posix.POLL.ERR | std.posix.POLL.NVAL) != 0) break;
            const n = std.posix.read(fd, &buf) catch break;
            if (n == 0) break;
            session.mutex.lockUncancelable(io);
            if (is_stdout) {
                appendSessionOutput(&session.stdout, buf[0..n], max_out, &session.truncated_stdout);
            } else {
                appendSessionOutput(&session.stderr, buf[0..n], max_out, &session.truncated_stderr);
            }
            session.mutex.unlock(io);
        }
    }
}

pub fn sessionWaiterMain(session: *Session, io: Io) void {
    if (comptime builtin.os.tag == .windows) {
        const term = session.child.wait(io) catch {
            // done=true must imply the job is dead, so close/reap joins of
            // the blocking readers can never hang.
            if (session.job) |j| proc.terminateJob(j);
            session.tree_killed.store(true, .release);
            session.mutex.lockUncancelable(io);
            session.done = true;
            session.exit_code = null;
            session.ended_us = nowUs(io);
            session.mutex.unlock(io);
            return;
        };
        const code = termExitCode(term);
        // The child is gone; terminate the Job Object so grandchildren cannot
        // outlive the session pinning the pipe write ends open (the blocking
        // readers have no poll tick — EOF is their only exit). done=true
        // published after this point implies the whole tree is dead.
        if (session.job) |j| proc.terminateJob(j);
        session.tree_killed.store(true, .release);
        session.mutex.lockUncancelable(io);
        session.done = true;
        session.exit_code = code;
        session.ended_us = nowUs(io);
        session.mutex.unlock(io);
        return;
    }
    // POSIX: done=true must imply (a) the whole process tree is dead and
    // (b) every buffered byte has been drained from the pipes.
    //
    // Step 1: detect the leader's exit WITHOUT reaping it. The unreaped
    // zombie keeps its pid — and therefore the process-group id it led —
    // allocated, so the group kill below can never hit a recycled pgid
    // (the classic PID/PGID reuse race).
    const no_reap_ok = if (proc.waitChildExitNoReap(session.pid)) |_| true else |_| false;
    if (no_reap_ok) {
        // Step 2: kill the tree while the zombie pins the group. SIGKILL
        // reaches every in-group descendant; the leader zombie ignores it.
        proc.killTree(session.pid, session.job);
        session.tree_killed.store(true, .release);
        // Step 3: done must mean the available output is drained. After the
        // group kill every in-group pipe writer is dead, so EOF lets both
        // readers finish quickly. An escaped (setsid) grandchild holding a
        // pipe write end open makes EOF impossible: give the readers a
        // bounded grace to collect everything already written, then force
        // finalization — done=true is guaranteed within DRAIN_GRACE_MS plus
        // one reader tick even for pipe-holding escapees, instead of the
        // session never finalizing.
        var expected_readers: u32 = 0;
        if (session.stdout_thread != null) expected_readers += 1;
        if (session.stderr_thread != null) expected_readers += 1;
        const drain_deadline = nowUs(io) + DRAIN_GRACE_MS * std.time.us_per_ms;
        while (session.readers_done.load(.acquire) < expected_readers) {
            if (session.closing.load(.acquire)) break;
            if (nowUs(io) >= drain_deadline) break;
            os.sleepMs(1);
        }
        // Step 4: child.wait() cleanup closes the parent pipe ends, so the
        // readers must be fully out of their poll/read loop BEFORE the reap
        // (a reader's defer bumps readers_done only after its last fd
        // touch). If the drain ended on the deadline or an external closing,
        // the readers are still inside a poll tick: tell them to stop and
        // wait them out. Bounded by construction — readers observe closing
        // within one READER_POLL_MS tick; the hard cap only backstops a
        // wedged kernel and is never reached in practice.
        if (session.readers_done.load(.acquire) < expected_readers) {
            session.closing.store(true, .release);
            const exit_deadline = nowUs(io) + READER_EXIT_MS * std.time.us_per_ms;
            while (session.readers_done.load(.acquire) < expected_readers) {
                if (nowUs(io) >= exit_deadline) break;
                os.sleepMs(1);
            }
        }
        // Step 5: reap with the child already dead, so child.wait() returns
        // immediately. The kill_mutex critical section serializes the reap
        // against killTreeGuarded callers: their tree_killed check + kill
        // complete either strictly before this reap (leader zombie still
        // pins the pgid — safe) or strictly after it (they observe
        // tree_killed == true and skip). A bare bool left a load(false) →
        // waiter kill+reap → late kill at a recycled pgid race.
        session.kill_mutex.lockUncancelable(io);
        const term = session.child.wait(io) catch {
            session.kill_mutex.unlock(io);
            session.mutex.lockUncancelable(io);
            session.done = true;
            session.exit_code = null;
            session.ended_us = nowUs(io);
            session.mutex.unlock(io);
            return;
        };
        session.kill_mutex.unlock(io);
        const code = termExitCode(term);
        session.mutex.lockUncancelable(io);
        session.done = true;
        session.exit_code = code;
        session.ended_us = nowUs(io);
        session.mutex.unlock(io);
        return;
    }
    // Fallback after a waitid failure: block on the child WITHOUT holding
    // kill_mutex — exec_kill must be able to unblock this wait. The
    // post-reap kill keeps its documented pid-reuse window (the gap the
    // WNOWAIT path exists to close), but a late kill is still strictly
    // better than a leaked tree.
    const term = session.child.wait(io) catch {
        killTreeGuarded(session, io);
        session.mutex.lockUncancelable(io);
        session.done = true;
        session.exit_code = null;
        session.ended_us = nowUs(io);
        session.mutex.unlock(io);
        return;
    };
    const code = termExitCode(term);
    killTreeGuarded(session, io);
    session.mutex.lockUncancelable(io);
    session.done = true;
    session.exit_code = code;
    session.ended_us = nowUs(io);
    session.mutex.unlock(io);
}

fn freeSession(session: *Session) void {
    // Called only after all session threads were joined (close/evict/error
    // paths), i.e. always after child.wait() already closed child.stdout/
    // stderr via std cleanup. child.stdin is null by construction on both
    // platforms — POSIX spawns with `.file` stdio (child.stdin starts null),
    // Windows nulls it in the post-spawn takeover — so std cleanup never
    // holds a stdin handle and closing Session.stdin_fd here is the single
    // owner's close, never a double-close.
    if (session.stdin_fd) |fd| os.closeFd(fd);
    // Windows: release the Job Object. The tree is already dead (waiter ran
    // TerminateJobObject), so KILL_ON_JOB_CLOSE is a no-op here.
    if (comptime builtin.os.tag == .windows) {
        if (session.job) |j| os.closeFd(j);
    }
    for (session.argv) |arg| std.heap.page_allocator.free(arg);
    std.heap.page_allocator.free(session.argv);
    std.heap.page_allocator.free(session.cwd);
    session.stdout.deinit(std.heap.page_allocator);
    session.stderr.deinit(std.heap.page_allocator);
    std.heap.page_allocator.destroy(session);
}

pub fn sessionRelease(session: *Session) void {
    if (session.refs.fetchSub(1, .acq_rel) == 1) freeSession(session);
}

fn utf8CompletePrefix(bytes: []const u8) []const u8 {
    // Longest prefix ending on a UTF-8 codepoint boundary; invalid start bytes
    // are left to the lossy renderer, only a partial valid tail is held back.
    var end: usize = 0;
    var i: usize = 0;
    while (i < bytes.len) {
        const n = std.unicode.utf8ByteSequenceLength(bytes[i]) catch {
            i += 1;
            end = i;
            continue;
        };
        if (i + n > bytes.len) break;
        _ = std.unicode.utf8Decode(bytes[i..][0..n]) catch {
            i += 1;
            end = i;
            continue;
        };
        i += n;
        end = i;
    }
    return bytes[0..end];
}

fn sliceFromOffset(items: []const u8, offset_i: i64) ![]const u8 {
    if (offset_i < 0) return error.BadOffset;
    const offset: usize = @intCast(offset_i);
    if (offset > items.len) return error.BadOffset;
    return items[offset..];
}

pub fn renderSessionState(arena: Allocator, store: *SessionStore, session: *Session, stdout_offset: i64, stderr_offset: i64, out: *std.ArrayList(u8)) !void {
    session.mutex.lockUncancelable(store.io);
    defer session.mutex.unlock(store.io);
    const stdout_raw = try sliceFromOffset(session.stdout.items, stdout_offset);
    const stderr_raw = try sliceFromOffset(session.stderr.items, stderr_offset);
    // While the process is alive never split a multi-byte UTF-8 sequence at
    // the delta edge: hold the partial tail back; reported offsets let the
    // client re-fetch it once completed.
    const stdout_delta = if (session.done) stdout_raw else utf8CompletePrefix(stdout_raw);
    const stderr_delta = if (session.done) stderr_raw else utf8CompletePrefix(stderr_raw);
    const stdout_text = try util.utf8LossyAlloc(arena, stdout_delta);
    const stderr_text = try util.utf8LossyAlloc(arena, stderr_delta);
    // Elapsed kept in microseconds: sub-millisecond sessions would flatten
    // to duration_ms: 0, while duration_us preserves the resolution.
    // duration_ms is still emitted (floor of the same value) for the
    // frozen v0 consumers.
    const ended_us = session.ended_us orelse nowUs(store.io);
    const elapsed_us = ended_us - session.started_us;
    try out.appendSlice(arena, "{\"ok\":true,\"done\":");
    try out.appendSlice(arena, if (session.done) "true" else "false");
    try out.appendSlice(arena, ",\"exit_code\":");
    if (session.exit_code) |code| try out.print(arena, "{d}", .{code}) else try out.appendSlice(arena, "null");
    try out.appendSlice(arena, ",\"stdout\":");
    try util.appendJsonString(out, arena, stdout_text);
    try out.appendSlice(arena, ",\"stderr\":");
    try util.appendJsonString(out, arena, stderr_text);
    try out.appendSlice(arena, ",\"stdout_offset\":");
    try out.print(arena, "{d}", .{stdout_offset + @as(i64, @intCast(stdout_delta.len))});
    try out.appendSlice(arena, ",\"stderr_offset\":");
    try out.print(arena, "{d}", .{stderr_offset + @as(i64, @intCast(stderr_delta.len))});
    try out.appendSlice(arena, ",\"truncated_stdout\":");
    try out.appendSlice(arena, if (session.truncated_stdout) "true" else "false");
    try out.appendSlice(arena, ",\"truncated_stderr\":");
    try out.appendSlice(arena, if (session.truncated_stderr) "true" else "false");
    try out.appendSlice(arena, ",\"duration_ms\":");
    try out.print(arena, "{d}", .{@divTrunc(elapsed_us, std.time.us_per_ms)});
    try out.appendSlice(arena, ",\"duration_us\":");
    try out.print(arena, "{d}", .{elapsed_us});
    try out.appendSlice(arena, "}");
}

/// Serialized check-and-kill. The tree_killed check, the kill and the store
/// are atomic with respect to the waiter's reap (sessionWaiterMain holds
/// kill_mutex across child.wait() once the leader is known dead): a guarded
/// kill either lands while the leader zombie still pins the process group —
/// safe — or observes tree_killed == true after the reap and skips. A bare
/// bool could not give that: load(false) → context switch → waiter kill+reap
/// → late kill would fire into a possibly recycled process group.
pub fn killTreeGuarded(session: *Session, io: Io) void {
    session.kill_mutex.lockUncancelable(io);
    defer session.kill_mutex.unlock(io);
    if (!session.tree_killed.load(.acquire)) {
        proc.killTree(session.pid, session.job);
        session.tree_killed.store(true, .release);
    }
}

// Sessions in these tests are synthetic: no process is ever spawned here
// (tools.zig owns spawn coverage), so child stays undefined and neither
// store operations nor renderSessionState touch it. A session inserted
// into the store is owned by the store's single reference and freed by
// evict, reap or remove plus sessionRelease; a session never inserted is
// freed through freeSession directly, mirroring the store's free path.

fn newSyntheticSession(io: Io, id: u64) !*Session {
    const alloc = std.heap.page_allocator;
    const argv = try alloc.alloc([]const u8, 1);
    errdefer alloc.free(argv);
    argv[0] = try alloc.dupe(u8, "synthetic");
    errdefer alloc.free(argv[0]);
    const cwd = try alloc.dupe(u8, ".");
    errdefer alloc.free(cwd);
    const session = try alloc.create(Session);
    session.* = .{
        .id = id,
        .pid = 0,
        .argv = argv,
        .cwd = cwd,
        .child = undefined,
        .stdin_fd = null,
        .started_us = nowUs(io),
    };
    return session;
}

test "session store allocates monotonic ids and tracks sessions" {
    const io = Io.Threaded.global_single_threaded.io();
    var store = SessionStore.init(io, 8);
    defer store.map.deinit();

    try std.testing.expectEqual(@as(u64, 1), store.allocId());
    try std.testing.expectEqual(@as(u64, 2), store.allocId());
    try std.testing.expectEqual(@as(u64, 3), store.allocId());

    const session = try newSyntheticSession(io, store.allocId());
    try store.put(session);
    try std.testing.expect(store.map.count() == 1);
    // put() transfers ownership of the initial reference to the store map.
    try std.testing.expectEqual(@as(u32, 1), session.refs.load(.monotonic));

    // get() returns the same pointer and takes a reference for the caller.
    const got = store.get(session.id).?;
    try std.testing.expect(got == session);
    try std.testing.expectEqual(@as(u32, 2), session.refs.load(.monotonic));
    sessionRelease(got);
    try std.testing.expectEqual(@as(u32, 1), session.refs.load(.monotonic));

    // Unknown ids and repeated removals are inert.
    try std.testing.expect(store.get(9999) == null);
    const removed = store.remove(session.id).?;
    try std.testing.expect(removed == session);
    try std.testing.expect(store.remove(session.id) == null);
    try std.testing.expect(store.get(session.id) == null);

    // Dropping the removed session's reference frees it and empties the map.
    sessionRelease(removed);
    try std.testing.expect(store.map.count() == 0);
}

test "session store put rejects overflow and evicts a done session" {
    const io = Io.Threaded.global_single_threaded.io();
    var store = SessionStore.init(io, 1);
    defer store.map.deinit();

    const live = try newSyntheticSession(io, store.allocId());
    try store.put(live);

    // A full store with no finished session has no evict candidate: the
    // second put must fail and leave the store untouched.
    const next = try newSyntheticSession(io, store.allocId());
    try std.testing.expectError(error.TooManySessions, store.put(next));
    try std.testing.expect(store.map.count() == 1);

    // Finish the live session: the next put evicts it (reader and waiter
    // threads are null, so the joins return instantly and the store's
    // reference is released, freeing the session) instead of failing.
    live.done = true;
    live.ended_us = nowUs(io);
    const live_id = live.id;
    try store.put(next);
    try std.testing.expect(store.map.count() == 1);
    try std.testing.expect(store.get(live_id) == null);

    const got = store.get(next.id).?;
    sessionRelease(got);
    sessionRelease(store.remove(next.id).?);
    try std.testing.expect(store.map.count() == 0);
}

test "session store reaps finished sessions past the ttl" {
    const io = Io.Threaded.global_single_threaded.io();
    var store = SessionStore.init(io, 8);
    defer store.map.deinit();
    store.ttl_ms = 0;

    const first = try newSyntheticSession(io, store.allocId());
    try store.put(first);
    const second = try newSyntheticSession(io, store.allocId());
    try store.put(second);
    try std.testing.expect(store.map.count() == 2);

    // Finish the first session one second in the past: with ttl_ms = 0 the
    // next sweep must drop it (put calls reapDone before inserting).
    first.done = true;
    first.ended_us = nowUs(io) - 1_000_000;
    const first_id = first.id;

    const third = try newSyntheticSession(io, store.allocId());
    try store.put(third);
    try std.testing.expect(store.map.count() == 2);
    try std.testing.expect(store.get(first_id) == null);

    // A direct reapDone sweep reaps the same way.
    second.done = true;
    second.ended_us = nowUs(io) - 1_000_000;
    const second_id = second.id;
    store.reapDone();
    try std.testing.expect(store.map.count() == 1);
    try std.testing.expect(store.get(second_id) == null);

    const got = store.get(third.id).?;
    sessionRelease(got);
    sessionRelease(store.remove(third.id).?);
    try std.testing.expect(store.map.count() == 0);
}

test "render session state emits the full status snapshot" {
    const io = Io.Threaded.global_single_threaded.io();
    var store = SessionStore.init(io, 8);
    defer store.map.deinit();
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const session = try newSyntheticSession(io, 4);
    defer freeSession(session);
    session.done = true;
    session.exit_code = 7;
    session.started_us = 1_700_000_000_000_000;
    session.ended_us = session.started_us + 1_500_000;
    session.truncated_stdout = true;
    try session.stdout.appendSlice(std.heap.page_allocator, "abcdef");
    try session.stderr.appendSlice(std.heap.page_allocator, "ghijkl");

    var out: std.ArrayList(u8) = .empty;
    try renderSessionState(arena, &store, session, 0, 0, &out);

    const parsed = try std.json.parseFromSliceLeaky(std.json.Value, arena, out.items, .{});
    try std.testing.expect(parsed == .object);
    const obj = parsed.object;
    try std.testing.expect(obj.get("ok").?.bool);
    try std.testing.expect(obj.get("done").?.bool);
    try std.testing.expectEqual(@as(i64, 7), obj.get("exit_code").?.integer);
    try std.testing.expectEqualStrings("abcdef", obj.get("stdout").?.string);
    try std.testing.expectEqualStrings("ghijkl", obj.get("stderr").?.string);
    try std.testing.expectEqual(@as(i64, 6), obj.get("stdout_offset").?.integer);
    try std.testing.expectEqual(@as(i64, 6), obj.get("stderr_offset").?.integer);
    try std.testing.expect(obj.get("truncated_stdout").?.bool);
    try std.testing.expect(!obj.get("truncated_stderr").?.bool);
    try std.testing.expectEqual(@as(i64, 1500), obj.get("duration_ms").?.integer);
    try std.testing.expectEqual(@as(i64, 1_500_000), obj.get("duration_us").?.integer);
}

test "render session state applies byte offsets and rejects bad ones" {
    const io = Io.Threaded.global_single_threaded.io();
    var store = SessionStore.init(io, 8);
    defer store.map.deinit();
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const session = try newSyntheticSession(io, 5);
    defer freeSession(session);
    try session.stdout.appendSlice(std.heap.page_allocator, "abcdef");
    try session.stderr.appendSlice(std.heap.page_allocator, "xyz");

    // The delta starts at the requested byte offset and the reported
    // offset advances by the delta length.
    {
        var out: std.ArrayList(u8) = .empty;
        try renderSessionState(arena, &store, session, 2, 0, &out);
        const parsed = try std.json.parseFromSliceLeaky(std.json.Value, arena, out.items, .{});
        const obj = parsed.object;
        try std.testing.expectEqualStrings("cdef", obj.get("stdout").?.string);
        try std.testing.expectEqual(@as(i64, 6), obj.get("stdout_offset").?.integer);
        try std.testing.expectEqualStrings("xyz", obj.get("stderr").?.string);
        try std.testing.expectEqual(@as(i64, 3), obj.get("stderr_offset").?.integer);
    }

    // An offset equal to the length is legal: the delta is empty and the
    // offset stays pinned at the end.
    {
        var out: std.ArrayList(u8) = .empty;
        try renderSessionState(arena, &store, session, 6, 3, &out);
        const parsed = try std.json.parseFromSliceLeaky(std.json.Value, arena, out.items, .{});
        const obj = parsed.object;
        try std.testing.expectEqualStrings("", obj.get("stdout").?.string);
        try std.testing.expectEqual(@as(i64, 6), obj.get("stdout_offset").?.integer);
        try std.testing.expectEqualStrings("", obj.get("stderr").?.string);
        try std.testing.expectEqual(@as(i64, 3), obj.get("stderr_offset").?.integer);
    }

    // Negative and past-the-end offsets are rejected on both streams.
    var sink: std.ArrayList(u8) = .empty;
    try std.testing.expectError(error.BadOffset, renderSessionState(arena, &store, session, -1, 0, &sink));
    try std.testing.expectError(error.BadOffset, renderSessionState(arena, &store, session, 7, 0, &sink));
    try std.testing.expectError(error.BadOffset, renderSessionState(arena, &store, session, 0, -1, &sink));
    try std.testing.expectError(error.BadOffset, renderSessionState(arena, &store, session, 0, 4, &sink));
}

test "render session state holds back a partial utf8 tail while alive" {
    const io = Io.Threaded.global_single_threaded.io();
    var store = SessionStore.init(io, 8);
    defer store.map.deinit();
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const session = try newSyntheticSession(io, 6);
    defer freeSession(session);
    try session.stdout.appendSlice(std.heap.page_allocator, "ab\xc3");

    // Alive: the dangling lead byte of a two-byte sequence must not be
    // split; the reported offset stops at the last complete boundary.
    {
        var out: std.ArrayList(u8) = .empty;
        try renderSessionState(arena, &store, session, 0, 0, &out);
        const parsed = try std.json.parseFromSliceLeaky(std.json.Value, arena, out.items, .{});
        const obj = parsed.object;
        try std.testing.expect(!obj.get("done").?.bool);
        try std.testing.expect(obj.get("exit_code").? == .null);
        try std.testing.expectEqualStrings("ab", obj.get("stdout").?.string);
        try std.testing.expectEqual(@as(i64, 2), obj.get("stdout_offset").?.integer);
    }

    // Done: the partial tail is flushed through the lossy renderer (the
    // dangling lead byte becomes one U+FFFD) and the offset covers it.
    session.done = true;
    {
        var out: std.ArrayList(u8) = .empty;
        try renderSessionState(arena, &store, session, 0, 0, &out);
        const parsed = try std.json.parseFromSliceLeaky(std.json.Value, arena, out.items, .{});
        const obj = parsed.object;
        try std.testing.expect(obj.get("done").?.bool);
        try std.testing.expectEqualStrings("ab\xef\xbf\xbd", obj.get("stdout").?.string);
        try std.testing.expectEqual(@as(i64, 3), obj.get("stdout_offset").?.integer);
    }

    // Complete multi-byte sequences pass through untouched while alive.
    const complete = try newSyntheticSession(io, 7);
    defer freeSession(complete);
    try complete.stdout.appendSlice(std.heap.page_allocator, "a\xc3\xa9z");
    {
        var out: std.ArrayList(u8) = .empty;
        try renderSessionState(arena, &store, complete, 0, 0, &out);
        const parsed = try std.json.parseFromSliceLeaky(std.json.Value, arena, out.items, .{});
        const obj = parsed.object;
        try std.testing.expectEqualStrings("a\xc3\xa9z", obj.get("stdout").?.string);
        try std.testing.expectEqual(@as(i64, 4), obj.get("stdout_offset").?.integer);
    }
}

test "render session state replaces invalid utf8 with replacement chars" {
    const io = Io.Threaded.global_single_threaded.io();
    var store = SessionStore.init(io, 8);
    defer store.map.deinit();
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const session = try newSyntheticSession(io, 8);
    defer freeSession(session);
    try session.stdout.appendSlice(std.heap.page_allocator, "a\xffb");

    // Alive: invalid bytes are not held back (only partial tails are), so
    // the lossy renderer replaces them the same way in both modes.
    {
        var out: std.ArrayList(u8) = .empty;
        try renderSessionState(arena, &store, session, 0, 0, &out);
        const parsed = try std.json.parseFromSliceLeaky(std.json.Value, arena, out.items, .{});
        try std.testing.expectEqualStrings("a\xef\xbf\xbdb", parsed.object.get("stdout").?.string);
    }

    session.done = true;
    {
        var out: std.ArrayList(u8) = .empty;
        try renderSessionState(arena, &store, session, 0, 0, &out);
        const parsed = try std.json.parseFromSliceLeaky(std.json.Value, arena, out.items, .{});
        try std.testing.expectEqualStrings("a\xef\xbf\xbdb", parsed.object.get("stdout").?.string);
    }
}

test "utf8 prefix and offset slicing helpers" {
    // Complete ASCII and multi-byte prefixes pass through in full.
    try std.testing.expectEqualStrings("", utf8CompletePrefix(""));
    try std.testing.expectEqualStrings("ab", utf8CompletePrefix("ab"));
    try std.testing.expectEqualStrings("a\xc3\xa9z", utf8CompletePrefix("a\xc3\xa9z"));
    try std.testing.expectEqualStrings("\xf0\x9f\x92\xa9", utf8CompletePrefix("\xf0\x9f\x92\xa9"));

    // A partial multi-byte tail is held back at the last complete boundary.
    try std.testing.expectEqualStrings("ab", utf8CompletePrefix("ab\xc3"));
    try std.testing.expectEqualStrings("", utf8CompletePrefix("\xe4\xb8"));

    // Invalid bytes stay in the prefix for the lossy renderer to replace.
    try std.testing.expectEqualStrings("a\xffb", utf8CompletePrefix("a\xffb"));
    try std.testing.expectEqualStrings("\xc3\x28", utf8CompletePrefix("\xc3\x28"));

    // Offsets slice by raw byte count; out-of-range values are rejected.
    try std.testing.expectEqualStrings("cdef", try sliceFromOffset("abcdef", 2));
    try std.testing.expectEqualStrings("abcdef", try sliceFromOffset("abcdef", 0));
    try std.testing.expectEqualStrings("", try sliceFromOffset("abcdef", 6));
    try std.testing.expectError(error.BadOffset, sliceFromOffset("abcdef", -1));
    try std.testing.expectError(error.BadOffset, sliceFromOffset("abcdef", 7));
}
