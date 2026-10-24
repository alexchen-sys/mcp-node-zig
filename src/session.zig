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
const durable = @import("durable_session.zig");

const REAP_BATCH_SIZE: usize = 8; // sessions freed per SessionStore sweep
const READER_POLL_MS: i32 = 100; // session pipe poll tick; latency fallback only — the wake pipe (below) is the fast path
const DRAIN_GRACE_MS: i64 = 1000; // bounded post-kill window for readers to collect available output when an escaped grandchild holds the pipes

const DEFAULT_SESSION_TTL_MS: i64 = 600_000;

pub const Session = struct {
    durable: ?*durable.Backend = null,
    id: u64,
    /// Integer pid on every OS (display-only on Windows; control goes
    /// through the job/handle). See os/proc.zig.
    pid: proc.ProcessId,
    /// Owned-child registry tag (proc.zig): the waiter removes exactly this
    /// (pid, tag) pair after its reap is confirmed — pid reuse can never
    /// delete a newer owner's registration. POSIX only; 0 on Windows.
    registry_tag: u64 = 0,
    argv: [][]const u8,
    cwd: []const u8,
    child: std.process.Child,
    stdin_fd: ?std.posix.fd_t,
    /// Windows: Job Object owning the whole process tree (KILL_ON_JOB_CLOSE).
    job: proc.JobField = proc.no_job,
    /// Argument gating: sha256 of the client token that started this
    /// session (zeroes when no policy is active). The session-control tools
    /// compare it against the calling request's owner; see policy.zig.
    owner_hash: [32]u8 = [_]u8{0} ** 32,
    stdin_mutex: std.Io.Mutex = .init,
    stdout_thread: ?std.Thread = null,
    stderr_thread: ?std.Thread = null,
    waiter_thread: ?std.Thread = null,
    mutex: std.Io.Mutex = .init,
    stdout: std.ArrayList(u8) = .empty,
    stderr: std.ArrayList(u8) = .empty,
    done: bool = false,
    /// Level-triggered wake for exec_wait: set exactly when `done` flips
    /// true (see `sessionFinish`). Level semantics make a lost wakeup
    /// impossible — a waiter that checks after the set sees `is_set`
    /// immediately, one already parked is woken by the futex wake — and
    /// `done` is one-way, so the event is never reset.
    done_event: std.Io.Event = .unset,
    exit_code: ?i64 = null,
    truncated_stdout: bool = false,
    truncated_stderr: bool = false,
    /// Total bytes read from the child but dropped because the captured
    /// buffer had already reached max_out. Guarded by `mutex` together
    /// with the buffers and the truncated flags, so a poll reply can never
    /// report a lost count that lags behind the bytes it just returned.
    lost_stdout_bytes: u64 = 0,
    lost_stderr_bytes: u64 = 0,
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
    /// Number of pipe-reader threads that finished draining (stdout/stderr)
    /// AND closed their pipe read end. The waiter gates done=true on this
    /// (a reader's defer closes its fd first, then bumps this), so `done`
    /// implies final output is fully drained and no reader will ever touch
    /// a session fd again.
    readers_done: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    /// Reader-wake plumbing (see `sessionRequestClose`). POSIX keeps both
    /// ends of a CLOEXEC self-pipe: readers poll the read end alongside the
    /// pipe, so a close request wakes a parked poll instantly instead of at
    /// the next 100ms tick. Windows keeps a manual-reset event readers wait
    /// alongside the pipe handle (CancelIoEx cancels a pending read; see
    /// os/proc.zig). Null on a creation failure: readers then rely on the
    /// poll tick / EOF alone, which costs latency, never correctness.
    /// fd_t is HANDLE on Windows, so one field type serves both platforms.
    wake_wfd: ?std.posix.fd_t = null,
    wake_rfd: ?std.posix.fd_t = null,
    wake_event: ?std.posix.fd_t = null,
};

/// Test-only hook: when non-zero, the FIRST reader that gets poll(POLLIN)
/// sleeps this many milliseconds between poll and read (simulating a reader
/// delayed exactly in the poll→read gap the fd-lifetime protocol must
/// survive). `swap` semantics make it one-shot; zero in production.
pub var test_reader_delay_ms: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

/// How many recently finished/removed session ids the store remembers for
/// the unknown_session error contract. Fixed size: a full ring overwrites
/// the oldest entry, so memory is bounded no matter how many sessions a
/// process reaps over its lifetime.
pub const TOMBSTONE_SLOTS: usize = 128;

pub const SessionStore = struct {
    mutex: std.Io.Mutex = .init,
    io: Io,
    map: std.AutoHashMap(u64, *Session),
    disk: ?*@import("durable.zig").Disk = null,
    sweep_thread: ?std.Thread = null,
    sweep_stop: std.Io.Event = .unset,
    next_id: u64 = 1,
    max: u16,
    ttl_ms: i64 = DEFAULT_SESSION_TTL_MS,
    /// Ring of ids this store once held but no longer does (TTL-reaped,
    /// closed by a client, or evicted). Lets exec_poll answer "expired"
    /// instead of "never existed" for recent ids, in constant memory.
    tombstones: [TOMBSTONE_SLOTS]u64 = [_]u64{0} ** TOMBSTONE_SLOTS,
    tombstone_next: usize = 0,

    pub fn init(io: Io, max_sessions: u16) SessionStore {
        return .{ .io = io, .map = std.AutoHashMap(u64, *Session).init(std.heap.page_allocator), .max = max_sessions };
    }

    /// Start only after the store has its final address. Failure is fatal:
    /// durable writers must never be admitted without node-side monitoring.
    pub fn startDurableSweep(self: *SessionStore) !void {
        if (self.sweep_thread != null) return;
        self.sweep_stop = .unset;
        self.sweep_thread = try std.Thread.spawn(.{}, durableSweepMain, .{self});
    }

    pub fn stopDurableSweep(self: *SessionStore) void {
        const thread = self.sweep_thread orelse return;
        self.sweep_stop.set(self.io);
        thread.join();
        self.sweep_thread = null;
    }

    fn durableSweepMain(self: *SessionStore) void {
        while (!self.sweep_stop.isSet()) {
            self.sweep_stop.waitTimeout(self.io, .{
                .duration = .{ .raw = .{ .nanoseconds = std.time.ns_per_s }, .clock = .awake },
            }) catch {};
            if (self.sweep_stop.isSet()) return;
            self.sweepDurableLogs();
        }
    }

    pub fn sweepDurableLogs(self: *SessionStore) void {
        // Collect live durable sessions under the store lock, then do ALL
        // enforcement work outside it: refresh can sleep (the settle window)
        // and fsync, and that must never stall unrelated connections behind
        // the registry-wide mutex. A short ref keeps each session alive
        // while the store lock is dropped. The batch is sized to the live
        // map: a fixed cap with a stable hash order would starve every
        // session past the cap.
        var batch: []*Session = &.{};
        var n: usize = 0;
        {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            if (self.map.count() > 0) {
                batch = std.heap.page_allocator.alloc(*Session, self.map.count()) catch return;
                var it = self.map.valueIterator();
                while (it.next()) |ptr| {
                    const s = ptr.*;
                    s.mutex.lockUncancelable(self.io);
                    const take = if (s.durable) |b| !b.retired else false;
                    s.mutex.unlock(self.io);
                    if (!take) continue;
                    _ = s.refs.fetchAdd(1, .acq_rel);
                    batch[n] = s;
                    n += 1;
                }
            }
        }
        defer {
            for (batch[0..n]) |s| sessionRelease(s);
            if (batch.len > 0) std.heap.page_allocator.free(batch);
        }
        // Stop every oversized writer before doing any completion work.
        // No log reads: just two fstats per live durable session.
        for (batch[0..n]) |s| {
            s.mutex.lockUncancelable(self.io);
            durable.enforceLogCapLocked(s, self.io) catch {};
            s.mutex.unlock(self.io);
        }
        // Completion work second: a kill from the first pass lands before
        // any finalize in the same tick.
        for (batch[0..n]) |s| {
            s.mutex.lockUncancelable(self.io);
            // Refresh every unfinished durable session: since the eviction
            // and TTL paths no longer refresh under the registry lock, this
            // tick is what finalizes leader-dead sessions, journals
            // completion, and keeps late growth reconciled even when the
            // owner never polls again. A live leader costs the cap check
            // (two fstats) plus one identity check here, with no prefix
            // rescan; only a dying session pays the settle window.
            if (s.durable != null and !s.done) durable.refreshLocked(s, self.io, false) catch {};
            s.mutex.unlock(self.io);
        }
    }

    /// Record `id` as recently removed (tombstone). Slot 0 is the "empty"
    /// marker, so a real id 0 can collide only with an unused slot — the
    /// allocator starts at 1 and no real session id is ever 0.
    fn tombstone(self: *SessionStore, id: u64) void {
        self.tombstones[self.tombstone_next] = id;
        self.tombstone_next = (self.tombstone_next + 1) % TOMBSTONE_SLOTS;
    }

    /// True when `id` was recently held by this store and has since been
    /// removed (TTL reap, exec_close, or overflow eviction). Best-effort
    /// recency signal: the ring is fixed-size, so ids removed more than
    /// TOMBSTONE_SLOTS removals ago are forgotten and answer false. The
    /// scan runs under the store mutex: writers (put/remove/reapDone)
    /// mutate the ring under the same lock, so no torn or mid-write slot
    /// is ever observed.
    pub fn sawOwnedSession(self: *SessionStore, id: u64, owner: [32]u8) bool {
        if (self.sawSession(id)) return true;
        if (self.disk) |disk| {
            disk.mutex.lockUncancelable(self.io);
            defer disk.mutex.unlock(self.io);
            return disk.index.expired(id, owner);
        }
        return self.sawSession(id);
    }

    pub fn sawSession(self: *SessionStore, id: u64) bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        for (self.tombstones) |t| {
            if (t == id and id != 0) return true;
        }
        return false;
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
                    // Cheap state read only: refresh (settle sleep, fsync)
                    // never runs under the registry lock; the 1 Hz sweep and
                    // the poll/wait paths finalize durable sessions.
                    const is_done = s.done;
                    s.mutex.unlock(self.io);
                    if (!is_done) continue;
                    // Capture the key before the map mutation: the iterator
                    // pointer is invalidated by fetchRemove (reapDone does
                    // the same).
                    if (s.durable != null) durable.retire(s, .evicted_capacity, self.io) catch continue;
                    const key = kv.key_ptr.*;
                    _ = self.map.fetchRemove(key);
                    if (s.durable == null) self.tombstone(key);
                    victim = s;
                    break;
                }
                if (victim == null) return error.TooManySessions;
            }
            self.map.put(session.id, session) catch |err| {
                // Insert failed after an evict: don't strand the victim. Its
                // session is done, so these joins return immediately.
                if (victim) |s| {
                    sessionRequestClose(s);
                    if (s.waiter_thread) |t| t.join();
                    if (s.stdout_thread) |t| t.join();
                    if (s.stderr_thread) |t| t.join();
                    sessionRelease(s);
                }
                return err;
            };
        }
        if (victim) |s| {
            sessionRequestClose(s);
            if (s.waiter_thread) |t| t.join();
            if (s.stdout_thread) |t| t.join();
            if (s.stderr_thread) |t| t.join();
            sessionRelease(s); // drop the store's ref
        }
    }

    pub fn publishDurable(self: *SessionStore, s: *Session, gated: *proc.GatedChild, released: *bool) !void {
        self.reapDone();
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.map.count() >= self.max) return error.TooManySessions;
        try self.map.ensureUnusedCapacity(1);
        // No allocator or capacity failure is possible after the gate opens.
        released.* = true;
        try gated.release();
        self.map.putAssumeCapacity(s.id, s);
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
        if (kv.value.durable == null) self.tombstone(id);
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
                    // Same rule as put: no refresh under the registry lock.
                    const is_done = s.done;
                    const ended = s.ended_us;
                    s.mutex.unlock(self.io);
                    if (!is_done) continue;
                    const ended_v = ended orelse continue;
                    if (nowUs(self.io) - ended_v < @as(i64, self.ttl_ms) * std.time.us_per_ms) continue;
                    if (s.durable != null) durable.retire(s, .reaped_ttl, self.io) catch continue;
                    found_key = kv.key_ptr.*;
                    found_s = s;
                    break;
                }
                if (found_key == null) break;
                _ = self.map.fetchRemove(found_key.?);
                if (found_s.?.durable == null) self.tombstone(found_key.?);
                victims[n] = found_s.?;
                n += 1;
            }
        }
        for (victims[0..n]) |s| {
            sessionRequestClose(s);
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
        while (it.next()) |kv| {
            if (kv.value_ptr.*.durable == null) killTreeGuarded(kv.value_ptr.*, self.io);
        }
    }

    /// Full teardown of every session still in the store: request close,
    /// kill the tree, JOIN waiter+reader threads, release the store's ref.
    /// Transports that return to main must use this, not killAll: the
    /// threads borrow the Io that main's defers destroy right after the
    /// transport returns. Same kill/join order as toolExecClose.
    /// No timeout: joining is the only proof a borrower has exited.
    pub fn shutdownAll(self: *SessionStore) void {
        self.stopDurableSweep();
        self.mutex.lockUncancelable(self.io);
        var old = self.map;
        self.map = std.AutoHashMap(u64, *Session).init(std.heap.page_allocator);
        self.mutex.unlock(self.io);
        defer old.deinit();
        var it = old.iterator();
        while (it.next()) |kv| {
            const session = kv.value_ptr.*;
            sessionRequestClose(session);
            if (session.durable == null) killTreeGuarded(session, self.io);
            if (session.waiter_thread) |t| t.join();
            if (session.stdout_thread) |t| t.join();
            if (session.stderr_thread) |t| t.join();
            sessionRelease(session); // store's ref
        }
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

pub fn termExitCode(term: std.process.Child.Term) i64 {
    return switch (term) {
        .exited => |code| code,
        .signal => |sig| 128 + @as(i64, @intCast(@intFromEnum(sig))),
        .stopped => |sig| 128 + @as(i64, @intCast(@intFromEnum(sig))),
        .unknown => |code| @as(i64, @intCast(code)),
    };
}

fn appendSessionOutput(list: *std.ArrayList(u8), bytes: []const u8, max_out: usize, truncated: *bool, lost: *u64) void {
    if (list.items.len >= max_out) {
        truncated.* = true;
        lost.* += bytes.len;
        return;
    }
    const avail = max_out - list.items.len;
    const take = @min(avail, bytes.len);
    if (take > 0) {
        list.appendSlice(std.heap.page_allocator, bytes[0..take]) catch {
            truncated.* = true;
            lost.* += bytes.len;
            return;
        };
    }
    if (take < bytes.len) {
        truncated.* = true;
        lost.* += bytes.len - take;
    }
}

pub fn sessionReaderMain(session: *Session, fd: std.posix.fd_t, is_stdout: bool, max_out: usize, io: Io) void {
    // fd ownership: the spawn layer transferred this pipe end to THIS
    // thread (child.stdout/stderr were nulled in toolExecStart), so the
    // reader is the single owner and the only closer. Close first, bump
    // readers_done after: readers_done == expected therefore implies no
    // thread will ever touch the fd again, which is what lets the waiter
    // (and only then) reap and publish done. std's child.wait cleanup can
    // never close these fds — on either platform.
    defer {
        os.closeFd(fd);
        _ = session.readers_done.fetchAdd(1, .acq_rel);
    }
    if (comptime builtin.os.tag == .windows) {
        // Blocking NtReadFile loop. Termination is guaranteed by two
        // independent mechanisms: (1) the Job Object — exec_kill/exec_close
        // and the waiter run TerminateJobObject, and grandchildren
        // auto-join the job (Win8+) — so every write end of the pipe
        // eventually closes and the pending read completes with
        // PIPE_BROKEN (EOF); (2) the wake event: a close request (see
        // sessionRequestClose) sets `closing` AND sets the event the
        // read below waits alongside the pipe handle (WaitAny — one of
        // them suffices), so a parked read is cancelled (CancelIoEx)
        // instead of relying on EOF alone.
        // session.closing is still honored between reads for the
        // already-EOF fast path. The loop head check is what makes the
        // waiter's drain phase work: `closing` is NOT set during the
        // drain grace (see sessionWaiterMain Windows Step 3), so readers
        // keep reading buffered output until EOF; only after the grace
        // does sessionRequestClose arm the closing+wake stop.
        var wbuf: [util.IO_BUF_SIZE]u8 = undefined;
        while (true) {
            if (session.closing.load(.acquire)) break;
            switch (proc.readPipeBlocking(fd, session.wake_event, &wbuf)) {
                .bytes => |n| {
                    if (n == 0) break; // zero-byte read == EOF on this pipe
                    session.mutex.lockUncancelable(io);
                    if (is_stdout) {
                        appendSessionOutput(&session.stdout, wbuf[0..n], max_out, &session.truncated_stdout, &session.lost_stdout_bytes);
                    } else {
                        appendSessionOutput(&session.stderr, wbuf[0..n], max_out, &session.truncated_stderr, &session.lost_stderr_bytes);
                    }
                    session.mutex.unlock(io);
                },
                // EOF: every write end is gone and the pipe is drained —
                // the normal exit; all buffered output was collected.
                .eof => break,
                // Forced stop: the wake event fired mid-read, so the read
                // was cancelled and whatever was still buffered in the
                // pipe is dropped. How much is unknowable (the read never
                // returned it) — the POSIX wake-only poll exit drops it
                // the same way, and lost_* stays a max_out-overflow
                // metric on both platforms.
                .woken => break,
                .failed => break,
            }
        }
        return;
    }
    // POSIX path: poll-tick loop with the wake pipe in the poll set.
    {
        var buf: [util.IO_BUF_SIZE]u8 = undefined;
        const wake_fd = session.wake_rfd;
        while (true) {
            // Poll instead of blind blocking read: exec_close must be able to reap
            // the session even if a grandchild escaped the process group and holds
            // the pipe write-end open forever. The wake pipe read end rides in
            // the same poll: sessionRequestClose stores `closing` and writes a
            // byte, so a parked poll returns immediately — the 100ms tick is the
            // latency fallback for a missing wake pipe, never the correctness.
            if (session.closing.load(.acquire)) break;
            var pfds: [2]std.posix.pollfd = .{
                .{ .fd = fd, .events = std.posix.POLL.IN, .revents = 0 },
                .{ .fd = wake_fd orelse -1, .events = if (wake_fd != null) std.posix.POLL.IN else 0, .revents = 0 },
            };
            const n_fds: usize = if (wake_fd != null) 2 else 1;
            const ready = std.posix.poll(pfds[0..n_fds], READER_POLL_MS) catch break;
            if (ready == 0) continue;
            const pipe_ev = pfds[0].revents;
            if (pipe_ev & (std.posix.POLL.ERR | std.posix.POLL.NVAL) != 0) break;
            const data_ready = pipe_ev & std.posix.POLL.IN != 0;
            const writer_gone = pipe_ev & std.posix.POLL.HUP != 0;
            if (!data_ready and !writer_gone) break; // wake-only event: stop requested
            // Test-only: delay the reader inside the poll→read gap
            // (one-shot; see test_reader_delay_ms).
            const delay_ms = test_reader_delay_ms.swap(0, .acq_rel);
            if (delay_ms != 0) os.sleepMs(delay_ms);
            // Safe even while a stop was requested: POLLIN/HUP means bytes
            // or EOF sit in the pipe buffer right now, and this pipe has
            // exactly one reader, so the read always returns immediately —
            // take the trailing data with us, exit on the next iteration.
            const n = std.posix.read(fd, &buf) catch break;
            if (n == 0) break;
            session.mutex.lockUncancelable(io);
            if (is_stdout) {
                appendSessionOutput(&session.stdout, buf[0..n], max_out, &session.truncated_stdout, &session.lost_stdout_bytes);
            } else {
                appendSessionOutput(&session.stderr, buf[0..n], max_out, &session.truncated_stderr, &session.lost_stderr_bytes);
            }
            session.mutex.unlock(io);
        }
    }
}

/// Ask the reader threads to stop, and wake them. ONE-SHOT: the first
/// caller flips `closing` (atomic swap) and delivers the wake — POSIX
/// writes a single byte into the nonblocking wake pipe, Windows sets the
/// manual-reset event. Every later caller sees `closing` already true and
/// returns without touching the pipe: nobody ever drains the wake pipe
/// (readers exit on the first byte; both ends live until freeSession), so
/// a write per call would eventually fill it (~64K requests) and park the
/// caller on a blocking write forever. The pipe is created nonblocking
/// (createWakePipe), so even a stray full pipe answers EAGAIN — mapped to
/// a write error here and swallowed as "already signaled". Windows stays
/// idempotent the way it always was: SetEvent on a manual-reset event
/// nobody resets. With no wake plumbing (creation failure) this degrades
/// to the plain store: readers still observe `closing` within one
/// READER_POLL_MS tick / at EOF. Callers must treat `closing == true` as
/// "readers are asked to exit", NEVER as "readers have exited" — only
/// readers_done proves that.
pub fn sessionRequestClose(session: *Session) void {
    // Swap, not store: exactly the caller that flips false→true delivers
    // the wake. acq_rel keeps the flip a full barrier — readers that
    // acquire the flag observe everything the first caller did.
    if (session.closing.swap(true, .acq_rel)) return;
    if (comptime builtin.os.tag == .windows) {
        if (session.wake_event) |ev| proc.setWakeEvent(ev);
    } else {
        if (session.wake_wfd) |wfd| {
            var byte = [_]u8{1};
            // EAGAIN (full, already-signaled pipe) or any other failure is
            // "already signaled": readers see `closing` within one tick.
            os.writeAllFd(wfd, &byte) catch {};
        }
    }
}

/// Publish the finished state (`done`, exit code, end time) under the
/// session mutex, then wake every exec_wait parked on this session. Called
/// from every exit path of `sessionWaiterMain`. The event is set AFTER the
/// state store: `set` is a release-store and `isSet`/the wake acquire, so
/// a woken exec_wait is guaranteed to observe `done == true`; a waiter
/// that entered before the store is woken by the futex broadcast. With
/// `session.mutex` NOT held on entry.
fn sessionFinish(session: *Session, io: Io, exit_code: ?i64) void {
    session.mutex.lockUncancelable(io);
    session.done = true;
    session.exit_code = exit_code;
    session.ended_us = nowUs(io);
    session.mutex.unlock(io);
    session.done_event.set(io);
}

/// One-tick decision of the post-kill drain grace (POSIX Step 3 and the
/// Windows waiter's Step 3 share it): keep giving readers time to reach
/// EOF on their own while the grace window is still open and no explicit
/// close request arrived; stop once every reader already finished, a
/// close raced in (exec_close/exec_kill), or the deadline passed. Pure
/// function so Linux CI unit-tests every branch — the waiter loops only
/// add the sleep and the atomics.
fn drainGraceContinue(readers_done: u32, expected_readers: u32, closing: bool, now_us: i64, deadline_us: i64) bool {
    if (readers_done >= expected_readers) return false;
    if (closing) return false;
    return now_us < deadline_us;
}

/// Bounded drain grace after the tree kill (both platforms): with every
/// in-tree pipe writer dead, EOF reaches both readers almost immediately
/// and they finish on their own; an escaped grandchild holding a write
/// end open makes EOF impossible, and this grace is the bounded window in
/// which readers still collect everything already buffered in the pipe
/// BEFORE `closing` is set — the waiter calls this strictly before
/// sessionRequestClose/finishAfterReaders, so the readers' loop-head
/// closing check never fires with undrained output in the pipe.
fn drainReadersGrace(session: *Session, io: Io) void {
    var expected_readers: u32 = 0;
    if (session.stdout_thread != null) expected_readers += 1;
    if (session.stderr_thread != null) expected_readers += 1;
    const deadline_us = nowUs(io) + DRAIN_GRACE_MS * std.time.us_per_ms;
    while (drainGraceContinue(
        session.readers_done.load(.acquire),
        expected_readers,
        session.closing.load(.acquire),
        nowUs(io),
        deadline_us,
    )) os.sleepMs(1);
}

pub fn sessionWaiterMain(session: *Session, io: Io) void {
    if (comptime builtin.os.tag == .windows) {
        // Step 1: reap the child handle. std's cleanup closes child.stdin
        // only — the stdout/stderr pipe ends were transferred to the reader
        // threads at spawn (toolExecStart nulled the fields), so this wait
        // can never yank a live reader's handle out from under it.
        const term = session.child.wait(io) catch {
            // done=true must imply the job is dead AND the readers are out,
            // so close/reap joins of the blocking readers can never hang.
            if (session.job) |j| proc.terminateJob(j);
            session.tree_killed.store(true, .release);
            drainReadersGrace(session, io);
            finishAfterReaders(session, io, null);
            return;
        };
        const code = termExitCode(term);
        // Step 2: the child is gone; terminate the Job Object so
        // grandchildren cannot outlive the session pinning the pipe write
        // ends open. Every job member dies, every pipe write end closes,
        // and the readers' pending reads complete with PIPE_BROKEN (EOF).
        if (session.job) |j| proc.terminateJob(j);
        session.tree_killed.store(true, .release);
        // Step 3 (drain grace — the mirror of the POSIX Step 3): the job
        // kill closed every in-tree write end, so both readers hit EOF on
        // their own within one read and finish with the output drained. A
        // grandchild that escaped the Job Object can still pin a write end
        // open — give the readers the same bounded DRAIN_GRACE_MS window
        // the POSIX side gives them to collect everything already buffered
        // in the pipe BEFORE closing is armed. Going straight to
        // finishAfterReaders here (the old shape) meant
        // sessionRequestClose fired first: the readers' loop-head
        // `if (closing) break` then exited them with output still sitting
        // in the pipe buffer — readers_done proved "handles closed", not
        // "output drained", and done was published with an empty stdout
        // at truncated=false.
        drainReadersGrace(session, io);
        // Step 4: stop the readers (closing + wake event cancels a parked
        // read) and wait for their actual exit, then publish done. done
        // therefore still means "the tree is dead AND the output is
        // drained" — including everything the readers had in flight.
        finishAfterReaders(session, io, code);
        return;
    }
    // POSIX: done=true must imply (a) the whole process tree is dead, (b)
    // every buffered byte has been drained from the pipes, and (c) the
    // reader threads are fully out — the pipe read ends are reader-owned
    // (see sessionReaderMain), so nobody closes them before readers_done.
    //
    // Step 1: detect the leader's exit WITHOUT reaping it. The unreaped
    // zombie keeps its pid — and therefore the process-group id it led —
    // allocated, so the kill below can never hit a recycled pgid
    // (the classic PID/PGID reuse race).
    const no_reap_ok = if (proc.waitChildExitNoReap(session.pid)) |_| true else |_| false;
    if (no_reap_ok) {
        // Step 2: kill the tree while the zombie pins the group. SIGKILL
        // reaches every in-group descendant; the leader zombie ignores it.
        proc.killTree(session.pid, session.job);
        session.tree_killed.store(true, .release);
        // Step 3 (drain grace): after the group kill every in-group pipe
        // writer is dead, so EOF lets both readers finish quickly. An
        // escaped (setsid) grandchild holding a pipe write end open makes
        // EOF impossible: give the readers a bounded grace to collect
        // everything already written before asking them to stop. The
        // loop lives in drainReadersGrace, shared with the Windows
        // waiter's Step 3 so both platforms follow identical drain rules.
        var expected_readers: u32 = 0;
        if (session.stdout_thread != null) expected_readers += 1;
        if (session.stderr_thread != null) expected_readers += 1;
        drainReadersGrace(session, io);
        // Step 4: stop the readers (closing + wake byte) and wait for their
        // actual exit without a timeout, ensuring no reader remains between
        // its closing check, poll, and read when the pipe fds are closed.
        // The wait is progress-guaranteed instead of time-bounded: the readers' poll
        // includes the wake pipe (a parked poll returns the moment the wake
        // byte lands; the 100ms tick covers a missing wake pipe), and a
        // read after POLLIN/HUP on this single-reader pipe always has data
        // or EOF available, so it cannot block indefinitely. The wait is
        // therefore bounded by the scheduler, not by a timer that would
        // have to break the "done ⇒ drained" promise to fire.
        sessionRequestClose(session);
        while (session.readers_done.load(.acquire) < expected_readers) os.sleepMs(1);
        // Step 5: reap with the child already dead, so child.wait() returns
        // immediately — and closes nothing the readers own: stdin is null
        // by construction, stdout/stderr were transferred to the readers.
        // The kill_mutex critical section serializes the reap against
        // killTreeGuarded callers: their tree_killed check + kill complete
        // either strictly before this reap (leader zombie still pins the
        // pgid — safe) or strictly after it (they observe tree_killed ==
        // true and skip). A bare bool left a load(false) → waiter
        // kill+reap → late kill at a recycled pgid race.
        session.kill_mutex.lockUncancelable(io);
        const term = session.child.wait(io) catch {
            session.kill_mutex.unlock(io);
            sessionFinish(session, io, null);
            return;
        };
        session.kill_mutex.unlock(io);
        // Owner reap confirmed: release the registry protection. Exact
        // (pid, tag) removal — a recycled pid keeps its new registration.
        proc.unregisterSpawnPid(io, session.pid, session.registry_tag);
        const code = termExitCode(term);
        sessionFinish(session, io, code);
        return;
    }
    // Fallback after a waitid failure: block on the child WITHOUT holding
    // kill_mutex — exec_kill must be able to unblock this wait. The
    // post-reap kill keeps its documented pid-reuse window (the gap the
    // WNOWAIT path exists to close), but a late kill is still strictly
    // better than a leaked tree. Reader fds stay reader-owned through this
    // path too, so the reap cannot close them out from under a live
    // reader; the kill unblocks EOF and finishAfterReaders does the
    // stop/wait/publish sequence.
    const term = session.child.wait(io) catch {
        killTreeGuarded(session, io);
        finishAfterReaders(session, io, null);
        return;
    };
    // Owner reap confirmed: release the registry protection (see above).
    proc.unregisterSpawnPid(io, session.pid, session.registry_tag);
    const code = termExitCode(term);
    killTreeGuarded(session, io);
    finishAfterReaders(session, io, code);
}

/// Terminal half of the waiter protocol (both platforms): ask the readers
/// to stop (closing + wake), wait until every reader thread has actually
/// finished (readers_done == expected — the count of spawned reader
/// threads), then publish done. Deadlock-free by ownership: readers never
/// hold session.mutex across their fd operations, and each reader is
/// guaranteed to observe the stop request (wake pipe / wake event /
/// 100ms poll tick / job-object EOF — see sessionReaderMain). `done`
/// is therefore published strictly after the final output is drained.
fn finishAfterReaders(session: *Session, io: Io, exit_code: ?i64) void {
    sessionRequestClose(session);
    var expected_readers: u32 = 0;
    if (session.stdout_thread != null) expected_readers += 1;
    if (session.stderr_thread != null) expected_readers += 1;
    while (session.readers_done.load(.acquire) < expected_readers) os.sleepMs(1);
    sessionFinish(session, io, exit_code);
}

fn freeSession(session: *Session) void {
    if (session.durable) |b| b.deinit();
    // Called only after all session threads were joined (close/evict/error
    // paths), i.e. always after the waiter already reaped the child. The
    // stdout/stderr pipe ends were reader-owned and closed by the reader
    // threads themselves (sessionReaderMain's defer), so nothing here or
    // in std's child cleanup can double-close them. child.stdin is null by
    // construction on both platforms — POSIX spawns with `.file` stdio
    // (child.stdin starts null), Windows nulls it in the post-spawn
    // takeover — so closing Session.stdin_fd here is the single owner's
    // close, never a double-close.
    if (session.stdin_fd) |fd| os.closeFd(fd);
    // Wake plumbing: no reader is alive at this point (all threads joined),
    // so closing the write/read ends (or the event) can never race a poll
    // or a pending NtReadFile.
    if (comptime builtin.os.tag == .windows) {
        if (session.wake_event) |ev| os.closeFd(ev);
        // Windows: release the Job Object. The tree is already dead (waiter
        // ran TerminateJobObject), so KILL_ON_JOB_CLOSE is a no-op here.
        if (session.job) |j| os.closeFd(j);
    } else {
        if (session.wake_wfd) |fd| os.closeFd(fd);
        if (session.wake_rfd) |fd| os.closeFd(fd);
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

fn pageDelta(raw: []const u8, page: ?usize, done: bool) []const u8 {
    if (page) |cap| {
        if (raw.len > cap) return raw[0..@import("output_shape.zig").trimEnd(raw, cap)];
    }
    return if (done) raw else utf8CompletePrefix(raw);
}

pub fn renderSessionState(arena: Allocator, store: *SessionStore, session: *Session, stdout_offset: i64, stderr_offset: i64, out: *std.ArrayList(u8)) !void {
    return renderSessionPage(arena, store, session, stdout_offset, stderr_offset, null, out);
}

pub fn renderSessionPage(arena: Allocator, store: *SessionStore, session: *Session, stdout_offset: i64, stderr_offset: i64, page: ?usize, out: *std.ArrayList(u8)) !void {
    session.mutex.lockUncancelable(store.io);
    defer session.mutex.unlock(store.io);
    try durable.refreshLocked(session, store.io, true);
    // Durable no-limit calls still return a bounded page and advertise the
    // remaining backlog. Ephemeral calls retain their exact legacy shape.
    const effective_page = if (session.durable) |b| page orelse @as(usize, @intCast(@min(b.meta.max_out, 1024 * 1024))) else page;
    const stdout_page: durable.SpoolPage = if (session.durable) |b|
        try durable.readPage(arena, store.io, b.stdout, stdout_offset, effective_page.?)
    else blk: {
        const raw = try sliceFromOffset(session.stdout.items, stdout_offset);
        break :blk .{ .raw = raw, .total = session.stdout.items.len + session.lost_stdout_bytes, .remaining = raw.len };
    };
    defer if (session.durable != null) arena.free(stdout_page.raw);
    const stderr_page: durable.SpoolPage = if (session.durable) |b|
        try durable.readPage(arena, store.io, b.stderr, stderr_offset, effective_page.?)
    else blk: {
        const raw = try sliceFromOffset(session.stderr.items, stderr_offset);
        break :blk .{ .raw = raw, .total = session.stderr.items.len + session.lost_stderr_bytes, .remaining = raw.len };
    };
    defer if (session.durable != null) arena.free(stderr_page.raw);
    // While the process is alive never split a multi-byte UTF-8 sequence at
    // the delta edge: hold the partial tail back; reported offsets let the
    // client re-fetch it once completed.
    const stdout_delta = pageDelta(stdout_page.raw, effective_page, session.done);
    const stderr_delta = pageDelta(stderr_page.raw, effective_page, session.done);
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
    try out.appendSlice(arena, ",\"lost_stdout_bytes\":");
    try out.print(arena, "{d}", .{session.lost_stdout_bytes});
    try out.appendSlice(arena, ",\"lost_stderr_bytes\":");
    try out.print(arena, "{d}", .{session.lost_stderr_bytes});
    try out.appendSlice(arena, ",\"duration_ms\":");
    try out.print(arena, "{d}", .{@divTrunc(elapsed_us, std.time.us_per_ms)});
    try out.appendSlice(arena, ",\"duration_us\":");
    try out.print(arena, "{d}", .{elapsed_us});
    if (effective_page) |cap| {
        const more_out = stdout_delta.len < stdout_page.remaining;
        const more_err = stderr_delta.len < stderr_page.remaining;
        try out.print(arena, ",\"has_more_stdout\":{},\"has_more_stderr\":{},\"has_more\":{},\"page_limited\":{},\"total_stdout_bytes\":{d},\"total_stderr_bytes\":{d}", .{
            more_out,                                                   more_err,          more_out or more_err,
            stdout_page.remaining > cap or stderr_page.remaining > cap, stdout_page.total, stderr_page.total,
        });
        // Exit-page contract: done reports process
        // exit, not drained output; say so on the page where both are true.
        if (session.done and (more_out or more_err) and (session.durable == null or session.durable.?.completionReason() == null)) try out.appendSlice(arena, ",\"message\":\"process exited; has_more=true means buffered output remains - keep polling until has_more is false\"");
    }
    if (session.durable) |b| {
        try out.print(arena, ",\"recovered\":{},\"stdin_available\":{},\"output_complete\":{},\"tree_state\":\"{s}\"", .{ b.recovered, !b.recovered and session.stdin_fd != null, session.done and !b.output_settling and b.completionReason() == null, if (session.tree_killed.load(.acquire)) @as([]const u8, "killed") else "unknown" });
        if (b.completionReason()) |reason| {
            try out.print(arena, ",\"completion_reason\":\"{s}\",\"message\":\"output exceeded the durable per-session log cap (2x MCP_NODE_MAX_OUT); a live session is killed with a verified identity, already-written output remains pollable\"", .{@tagName(reason)});
        } else if (b.output_settling) try out.appendSlice(arena, ",\"completion_reason\":\"output_settling\"") else if (b.meta.state == .interrupted) try out.appendSlice(arena, ",\"completion_reason\":\"interrupted\"") else if (session.done and session.exit_code == null) try out.appendSlice(arena, ",\"completion_reason\":\"orphaned_exit\"");
    }
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
    if (session.durable) |b| {
        if (b.meta.state == .interrupted or session.tree_killed.load(.acquire)) return;
        if (proc.killRecoveredTreeVerified(b.identity())) session.tree_killed.store(true, .release) else durable.event(b.writer, "session.orphan_skip", "reason", "pid_reused_or_dead");
        return;
    }
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

test "sessionFinish publishes the finished state and arms the done event" {
    const io = Io.Threaded.global_single_threaded.io();
    const session = try newSyntheticSession(io, 1);
    defer freeSession(session);

    try std.testing.expect(!session.done_event.isSet());
    sessionFinish(session, io, 42);

    session.mutex.lockUncancelable(io);
    const done = session.done;
    const exit_code = session.exit_code;
    const ended = session.ended_us;
    session.mutex.unlock(io);
    try std.testing.expect(done);
    try std.testing.expectEqual(@as(?i64, 42), exit_code);
    try std.testing.expect(ended != null);
    try std.testing.expect(session.done_event.isSet());

    // exec_wait's entry contract: a session already finished before the
    // wait starts returns without ever parking — waitTimeout on a set
    // event must succeed immediately, not burn a timeout (or a 50ms tick).
    session.done_event.waitTimeout(io, .{
        .duration = .{ .raw = .{ .nanoseconds = std.time.ns_per_s }, .clock = .real },
    }) catch return error.SetEventMustWakeImmediately;
}

test "done event wakes a parked waiter without the 50ms poll quantum" {
    if (builtin.os.tag != .linux) return error.SkipZigTest; // threading + futex timing asserted on the CI target
    var threaded = Io.Threaded.init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const session = try newSyntheticSession(io, 1);

    const Setter = struct {
        fn run(s: *Session, thread_io: Io) void {
            os.sleepMs(5);
            sessionFinish(s, thread_io, 0);
        }
    };
    const setter = try std.Thread.spawn(.{}, Setter.run, .{ session, io });
    defer setter.join();

    // The exact wait loop toolExecWait runs: isSet pre-check, remaining-
    // time waitTimeout, Timeout re-check (spurious wakes fall through).
    const start = nowUs(io);
    const deadline = start + 10 * std.time.us_per_s;
    while (true) {
        if (session.done_event.isSet()) break;
        const now = nowUs(io);
        if (now >= deadline) break;
        const remaining_ns: i96 = @as(i96, deadline - now) * std.time.ns_per_us;
        session.done_event.waitTimeout(io, .{
            .duration = .{ .raw = .{ .nanoseconds = remaining_ns }, .clock = .real },
        }) catch {};
    }
    const elapsed_us = nowUs(io) - start;
    // The setter finishes at ~5ms; the event wake must return well under
    // the old 50ms sleep tick (the poll loop could never beat its own
    // quantum: done was always set inside the first sleeping tick). 45ms
    // keeps an order-of-magnitude margin over the ~5ms expected wake.
    try std.testing.expect(session.done_event.isSet());
    try std.testing.expect(elapsed_us < 45_000);

    freeSession(session);
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
    session.lost_stdout_bytes = 4096;
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
    try std.testing.expectEqual(@as(i64, 4096), obj.get("lost_stdout_bytes").?.integer);
    try std.testing.expectEqual(@as(i64, 0), obj.get("lost_stderr_bytes").?.integer);
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

test "drainGraceContinue bounds the post-kill drain window" {
    // Pure decision function shared by the POSIX and Windows waiter Step 3.
    // All branch shapes live here so Linux CI
    // covers the full drain semantics; the waiter loops only add the
    // sleep and the atomics around this call.
    const deadline: i64 = 1_000_000; // 1s in µs after the kill

    // Mid-grace with readers still alive: keep draining.
    try std.testing.expect(drainGraceContinue(0, 2, false, 0, deadline));
    // The last tick before the deadline still counts as grace time.
    try std.testing.expect(drainGraceContinue(1, 2, false, deadline - 1, deadline));

    // All readers finished (EOF reached): stop waiting immediately.
    try std.testing.expect(!drainGraceContinue(2, 2, false, 0, deadline));
    // No readers were spawned at all: nothing to drain.
    try std.testing.expect(!drainGraceContinue(0, 0, false, 0, deadline));

    // An exec_close/exec_kill racing in (closing already armed): the
    // forced-stop path takes over, the grace is abandoned.
    try std.testing.expect(!drainGraceContinue(0, 2, true, 0, deadline));

    // Deadline reached or passed: grace is over regardless.
    try std.testing.expect(!drainGraceContinue(0, 2, false, deadline, deadline));
    try std.testing.expect(!drainGraceContinue(0, 2, false, deadline + 5, deadline));
}

test "appendSessionOutput counts dropped bytes past the cap" {
    // Under the cap everything is kept and nothing is lost.
    {
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(std.heap.page_allocator);
        var truncated = false;
        var lost: u64 = 0;
        appendSessionOutput(&list, "abcdef", 10, &truncated, &lost);
        try std.testing.expectEqualStrings("abcdef", list.items);
        try std.testing.expect(!truncated);
        try std.testing.expectEqual(@as(u64, 0), lost);
    }
    // A single write crossing the cap keeps the head and counts the tail.
    {
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(std.heap.page_allocator);
        var truncated = false;
        var lost: u64 = 0;
        appendSessionOutput(&list, "0123456789", 6, &truncated, &lost);
        try std.testing.expectEqualStrings("012345", list.items);
        try std.testing.expect(truncated);
        try std.testing.expectEqual(@as(u64, 4), lost);
    }
    // Once the buffer is full every further byte is dropped and counted.
    {
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(std.heap.page_allocator);
        var truncated = false;
        var lost: u64 = 0;
        appendSessionOutput(&list, "0123456789", 6, &truncated, &lost);
        appendSessionOutput(&list, "ab", 6, &truncated, &lost);
        appendSessionOutput(&list, "cde", 6, &truncated, &lost);
        try std.testing.expectEqualStrings("012345", list.items);
        try std.testing.expect(truncated);
        try std.testing.expectEqual(@as(u64, 9), lost); // 4 + 2 + 3
    }
}

test "session store tombstones distinguish expired from never-existed" {
    const io = Io.Threaded.global_single_threaded.io();
    var store = SessionStore.init(io, 8);
    defer store.map.deinit();

    // Nothing was ever removed: sawSession is false for anything.
    try std.testing.expect(!store.sawSession(1));
    try std.testing.expect(!store.sawSession(9999));

    const first = try newSyntheticSession(io, store.allocId());
    try store.put(first);
    const first_id = first.id;
    try std.testing.expect(!store.sawSession(first_id)); // live: not a tombstone

    // Close-path removal marks the id.
    const removed = store.remove(first_id).?;
    try std.testing.expect(store.sawSession(first_id));
    sessionRelease(removed);
    try std.testing.expect(store.sawSession(first_id)); // still remembered after free

    // TTL reap marks too.
    const second = try newSyntheticSession(io, store.allocId());
    try store.put(second);
    second.done = true;
    second.ended_us = nowUs(io) - 1_000_000;
    store.ttl_ms = 0;
    const second_id = second.id;
    store.reapDone();
    try std.testing.expect(store.sawSession(second_id));

    // A never-seen id stays false.
    try std.testing.expect(!store.sawSession(424242));
}

test "session store tombstone ring wraps at the fixed size" {
    const io = Io.Threaded.global_single_threaded.io();
    var store = SessionStore.init(io, 4);
    defer store.map.deinit();
    store.ttl_ms = 0;

    // Fill and reap sessions so ids 1..135 are reaped (the last one stays
    // live in the map): the ring must keep only the most recent
    // TOMBSTONE_SLOTS of them, overwriting the oldest.
    var i: u64 = 0;
    while (i < TOMBSTONE_SLOTS + 8) : (i += 1) {
        // max=4 and ttl=0: every put() first reaps all stale done sessions,
        // so the map never overflows and every previous id is tombstoned.
        const s = try newSyntheticSession(io, store.allocId());
        s.done = true;
        s.ended_us = nowUs(io) - 1_000_000;
        try store.put(s);
    }
    // Reaped ids are 1..135 (135 > 128 slots): the ring keeps 8..135.
    var remembered: usize = 0;
    i = 1;
    while (i <= TOMBSTONE_SLOTS + 7) : (i += 1) {
        if (store.sawSession(i)) remembered += 1;
    }
    try std.testing.expectEqual(TOMBSTONE_SLOTS, remembered);
    try std.testing.expect(!store.sawSession(1));
    try std.testing.expect(!store.sawSession(7));
    try std.testing.expect(store.sawSession(8));
    try std.testing.expect(store.sawSession(TOMBSTONE_SLOTS + 7));
    // The final session (id 136) is still live in the map, not a tombstone.
    try std.testing.expect(!store.sawSession(TOMBSTONE_SLOTS + 8));
    // get() is acquiring: it bumps refs. Release the acquired reference
    // (and the store's own one via remove) or the session leaks one
    // reference past the test.
    const live = store.get(TOMBSTONE_SLOTS + 8);
    try std.testing.expect(live != null);
    sessionRelease(live.?);
    sessionRelease(store.remove(TOMBSTONE_SLOTS + 8).?);
}

test "sessionRequestClose is one-shot: repeated calls write exactly one wake byte" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest; // POSIX wake-pipe plumbing
    // Only the fields sessionRequestClose touches are initialized: the
    // function must never reach into anything else.
    var s: Session = undefined;
    s.closing = std.atomic.Value(bool).init(false);
    const pair = proc.createWakePipe() orelse return error.SkipZigTest;
    defer os.closeFd(pair[0]);
    defer os.closeFd(pair[1]);
    s.wake_wfd = pair[1];
    s.wake_rfd = pair[0];

    sessionRequestClose(&s);
    sessionRequestClose(&s);
    sessionRequestClose(&s);

    // Exactly one byte landed: the read end is nonblocking (createWakePipe
    // sets NONBLOCK), so after consuming the single byte the next read
    // answers EAGAIN — mapped to ReadFailed — instead of blocking; a
    // per-call write would have left more bytes behind.
    var buf: [8]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), try os.readFd(pair[0], &buf));
    try std.testing.expectEqual(@as(u8, 1), buf[0]);
    try std.testing.expectError(error.ReadFailed, os.readFd(pair[0], &buf));
    // The one-shot flag is visible to every caller and every reader.
    try std.testing.expect(s.closing.load(.acquire));
}

test "session pages progress across UTF-8 without capture loss" {
    const io = Io.Threaded.global_single_threaded.io();
    var store = SessionStore.init(io, 8);
    defer store.map.deinit();
    var state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer state.deinit();
    const a = state.allocator();
    const session = try newSyntheticSession(io, 7);
    defer freeSession(session);
    const raw = "a💩é中z";
    try session.stdout.appendSlice(std.heap.page_allocator, raw);
    try session.stderr.appendSlice(std.heap.page_allocator, "123456");
    session.done = true;
    var offset: i64 = 0;
    var err_offset: i64 = 0;
    var joined: std.ArrayList(u8) = .empty;
    var pages: usize = 0;
    while (true) {
        var out: std.ArrayList(u8) = .empty;
        try renderSessionPage(a, &store, session, offset, err_offset, 4, &out);
        const obj = (try std.json.parseFromSliceLeaky(std.json.Value, a, out.items, .{})).object;
        try joined.appendSlice(a, obj.get("stdout").?.string);
        const next = obj.get("stdout_offset").?.integer;
        if (offset < raw.len) try std.testing.expect(next > offset);
        offset = next;
        err_offset = obj.get("stderr_offset").?.integer;
        try std.testing.expect(!obj.get("truncated_stdout").?.bool);
        try std.testing.expectEqual(@as(i64, 0), obj.get("lost_stdout_bytes").?.integer);
        try std.testing.expectEqual(@as(i64, raw.len), obj.get("total_stdout_bytes").?.integer);
        pages += 1;
        if (!obj.get("has_more").?.bool) {
            // The final page carries no exit-page message.
            try std.testing.expect(obj.get("message") == null);
            break;
        }
        // done (exit) may arrive with has_more (undrained pages) —
        // the payload must then say so explicitly.
        try std.testing.expect(obj.get("done").?.bool);
        try std.testing.expectEqualStrings("process exited; has_more=true means buffered output remains - keep polling until has_more is false", obj.get("message").?.string);
        try std.testing.expect(pages < 10);
    }
    try std.testing.expectEqualStrings(raw, joined.items);
    try std.testing.expectEqual(@as(usize, 4), pages);
    session.truncated_stdout = true;
    session.lost_stdout_bytes = 42;
    var out: std.ArrayList(u8) = .empty;
    try renderSessionPage(a, &store, session, 0, 0, 4, &out);
    const obj = (try std.json.parseFromSliceLeaky(std.json.Value, a, out.items, .{})).object;
    try std.testing.expect(obj.get("truncated_stdout").?.bool);
    try std.testing.expectEqual(@as(i64, 42), obj.get("lost_stdout_bytes").?.integer);
    try std.testing.expectEqual(@as(i64, raw.len + 42), obj.get("total_stdout_bytes").?.integer);
}

test "session page holds live partial UTF-8 but flushes malformed EOF" {
    try std.testing.expectEqualStrings("abc", pageDelta("abc💩", 4, true));
    try std.testing.expectEqualStrings("abc\xff", pageDelta("abc\xffz", 4, true));
    try std.testing.expectEqualStrings("a", pageDelta("a\xf0\x9f", 4, false));
    try std.testing.expectEqualStrings("a\xf0\x9f", pageDelta("a\xf0\x9f", 4, true));
    try std.testing.expectEqualStrings("", pageDelta("", 4, true));
}

test "state enabled tombstones preserve ephemeral expiry and durable ownership" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var store = SessionStore.init(io, 4);
    defer store.map.deinit();
    var disk: @import("durable.zig").Disk = undefined;
    disk.mutex = .init;
    disk.index = .{};
    store.disk = &disk;
    store.tombstone(1);
    disk.index.push(.{ .id = 2, .owner_hash = @splat(7), .reason = .closed_by_client });
    try std.testing.expect(store.sawOwnedSession(1, @splat(0)));
    try std.testing.expect(store.sawOwnedSession(2, @splat(7)));
    try std.testing.expect(!store.sawOwnedSession(2, @splat(0)));
}

test "ephemeral overflow preserves head kept offsets and lost counters" {
    const io = Io.Threaded.global_single_threaded.io();
    var store = SessionStore.init(io, 8);
    defer store.map.deinit();
    var state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer state.deinit();
    const a = state.allocator();
    const s = try newSyntheticSession(io, 1);
    defer freeSession(s);
    appendSessionOutput(&s.stdout, "head-tail", 4, &s.truncated_stdout, &s.lost_stdout_bytes);
    appendSessionOutput(&s.stdout, "-more", 4, &s.truncated_stdout, &s.lost_stdout_bytes);
    appendSessionOutput(&s.stderr, "err-tail", 4, &s.truncated_stderr, &s.lost_stderr_bytes);
    s.done = true;
    var out: std.ArrayList(u8) = .empty;
    try renderSessionPage(a, &store, s, 0, 0, 4, &out);
    const obj = (try std.json.parseFromSliceLeaky(std.json.Value, a, out.items, .{})).object;
    try std.testing.expectEqualStrings("head", obj.get("stdout").?.string);
    try std.testing.expectEqualStrings("err-", obj.get("stderr").?.string);
    try std.testing.expectEqual(@as(i64, 10), obj.get("lost_stdout_bytes").?.integer);
    try std.testing.expectEqual(@as(i64, 4), obj.get("lost_stderr_bytes").?.integer);
    try std.testing.expectEqual(@as(i64, 14), obj.get("total_stdout_bytes").?.integer);
    try std.testing.expect(obj.get("truncated_stdout").?.bool);
    try std.testing.expect(!obj.get("has_more").?.bool);
    try std.testing.expect(obj.get("output_complete") == null);
    out = .empty;
    try renderSessionState(a, &store, s, 4, 4, &out);
    const eof = (try std.json.parseFromSliceLeaky(std.json.Value, a, out.items, .{})).object;
    try std.testing.expectEqualStrings("", eof.get("stdout").?.string);
    try std.testing.expectEqual(@as(i64, 10), eof.get("lost_stdout_bytes").?.integer);
    try std.testing.expect(eof.get("total_stdout_bytes") == null);
    try std.testing.expectError(error.BadOffset, renderSessionPage(a, &store, s, 5, 0, 4, &out));
}
