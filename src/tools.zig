//! The 13 MCP tool implementations (exec, exec_start, exec_poll,
//! exec_write, exec_kill, exec_close, exec_wait, exec_list, exec_shell,
//! sys_info, read_file, write_file, list_dir) plus their private
//! helpers: session resolution from tool arguments, `~` path expansion,
//! and the tool-scoped limits. Routing by tool name (dispatchTool)
//! still lives in main.zig.

const std = @import("std");
const builtin = @import("builtin");

const Allocator = std.mem.Allocator;
const Io = std.Io;
const Value = std.json.Value;
const os = @import("os.zig");
const proc = @import("os/proc.zig");
const util = @import("util.zig");
const session_mod = @import("session.zig");
const config = @import("config.zig");
const env_state = @import("env_state.zig");

const LIST_DIR_MAX_ENTRIES: usize = 2000;
const WAIT_POLL_MS: u64 = 50; // exec_wait sleep tick
const EXEC_DEFAULT_TIMEOUT_S: i64 = 120; // mirrored in TOOLS_JSON prose (rpc.zig)
const EXEC_MAX_TIMEOUT_S: i64 = 1800;
const WAIT_DEFAULT_TIMEOUT_S: i64 = 30; // mirrored in TOOLS_JSON prose (rpc.zig)
const WAIT_MAX_TIMEOUT_S: i64 = 300;
const READ_FILE_MAX_BYTES: usize = 64 * 1024 * 1024;
const READ_FILE_DEFAULT_LIMIT_CHARS: i64 = 200_000; // chars, not bytes

// --- exec spawn hygiene (see os/proc.zig) -----------------------------------
//
// std's POSIX spawn error path never reaps the child (processSpawnPosix
// returns the execve failure without waitpid), so every failed exec/exec_start
// leaks a defunct child. The pre-flight resolves argv[0]/cwd BEFORE forking
// (deterministic no-fork path for missing programs/permissions/cwd); the
// stray sweep below is the backstop for residual execve errors (ENOEXEC,
// E2BIG, ...). Concurrency contract of the three globals:
//
//   * exec_gate serializes (a) exec-family tool entry/exit bookkeeping,
//     (b) exec_start's fork+publish section, and (c) sweeps, so a sweep can
//     never observe a child before it is registered as protected.
//   * exec_inflight counts exec-family tool calls (exec, exec_shell,
//     exec_start). A sweep runs only on the exit that brings the count to
//     zero: by then no std.process.run child can be inside its
//     exit-but-not-yet-waited window (run() reaps synchronously inside the
//     call), so a sweep can never steal a wait std itself owns.
//   * pending_pids (under exec_gate) tracks session children from fork until
//     their waiter's reap is confirmed (compaction drops entries whose pid
//     no longer answers waitid). It covers the whole publish/drain/close
//     lifecycle, so the sweep never reaps a pid a session waiter will wait
//     for — stealing that wait would surface as ECHILD inside std's
//     childWait and degrade the session's exit_code.

var exec_gate: std.Io.Mutex = .init;
var exec_inflight: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);
/// Set (under exec_gate) whenever a fork actually failed. The failed child
/// writes the exec error to the pipe BEFORE _exit, so the parent can observe
/// the error while the child is still dying; the exit sweep settles briefly
/// to let it land before reaping.
var spawn_error_pending: bool = false;

/// PID type of the pending registry: POSIX pid_t; on Windows the registry is
/// never written (comptime-gated call sites) and pid_t is not meaningful
/// there, so u32 stands in purely to keep the declaration portable.
const SpawnPid = if (builtin.os.tag == .windows) u32 else std.posix.pid_t;
var pending_pids: std.ArrayList(SpawnPid) = .empty;

fn execCallEnter(io: Io) void {
    exec_gate.lockUncancelable(io);
    _ = exec_inflight.fetchAdd(1, .acq_rel);
    exec_gate.unlock(io);
}

/// Exit half of the exec-family gate: the LAST call to leave sweeps strays.
/// Runs as a defer, i.e. after the tool's own resource errdefers.
fn execCallExit(io: Io) void {
    exec_gate.lockUncancelable(io);
    defer exec_gate.unlock(io);
    if (exec_inflight.fetchSub(1, .acq_rel) != 1) return;
    if (comptime builtin.os.tag == .windows) return;
    if (spawn_error_pending) {
        spawn_error_pending = false;
        // The failed child reports the exec error through the pipe before
        // _exit; give it a moment to land so this sweep reaps it now instead
        // of on the next exec call's exit.
        os.sleepMs(2);
    }
    // Compaction first: drop entries whose child is fully reaped and gone
    // (waitid answers ECHILD once the owner's wait has consumed the zombie).
    var kept: usize = 0;
    for (pending_pids.items) |pid| {
        if (proc.childStillTracked(pid)) {
            pending_pids.items[kept] = pid;
            kept += 1;
        }
    }
    pending_pids.shrinkRetainingCapacity(kept);
    _ = proc.reapStrayChildren(pending_pids.items);
}

/// Pre-flight the spawn POSIX-side. Windows needs no pre-flight: spawn
/// failure there never leaves a half-forked child (CreateProcess is atomic).
fn preflightSpawn(arena: Allocator, io: Io, argv0: []const u8, cwd: []const u8) !void {
    if (comptime builtin.os.tag == .windows) return;
    const path_env = os.env.environGet(arena, env_state.process_environ, "PATH");
    return proc.preflightExec(arena, io, argv0, cwd, path_env);
}

pub fn toolExec(arena: Allocator, io: Io, cfg: *const config.Config, args: Value, out: *std.ArrayList(u8)) !void {
    const argv_v = util.objGet(args, "argv") orelse return error.MissingArgv;
    if (argv_v != .array) return error.BadArgv;
    if (argv_v.array.items.len == 0) return error.BadArgv;
    var argv = try arena.alloc([]const u8, argv_v.array.items.len);
    for (argv_v.array.items, 0..) |item, i| {
        if (item != .string) return error.BadArgv;
        argv[i] = item.string;
    }
    const cwd = (try util.optStrArg(args, "cwd")) orelse "";
    var timeout_s = (try util.optIntArg(args, "timeout")) orelse EXEC_DEFAULT_TIMEOUT_S;
    if (timeout_s < 1) timeout_s = 1;
    if (timeout_s > EXEC_MAX_TIMEOUT_S) timeout_s = EXEC_MAX_TIMEOUT_S;
    // Failed-spawn hygiene: enter the exec-family gate and pre-flight the
    // spawn so the common failures never fork at all (os/proc.zig explains
    // why both layers exist).
    execCallEnter(io);
    defer execCallExit(io);
    try preflightSpawn(arena, io, argv[0], cwd);
    const started = std.Io.Clock.awake.now(io);
    const result = std.process.run(arena, io, .{
        .argv = argv,
        .cwd = if (cwd.len == 0) .inherit else .{ .path = cwd },
        .stdout_limit = .limited(cfg.max_out),
        .stderr_limit = .limited(cfg.max_out),
        .timeout = .{ .duration = .{ .clock = .awake, .raw = std.Io.Duration.fromSeconds(timeout_s) } },
    }) catch |err| switch (err) {
        // Long-running / partial-output needs are served by exec_start;
        // here we surface a machine-readable timeout flag.
        error.Timeout => {
            out.clearRetainingCapacity();
            try out.appendSlice(arena, "{\"ok\":false,\"timeout\":true,\"error\":\"CommandTimeout\"}");
            return;
        },
        error.StreamTooLong => return error.OutputTooLong,
        else => {
            // A real spawn-side failure (the pre-flight already rejected the
            // no-fork cases): a forked child is dying somewhere — mark it so
            // the exit sweep settles before reaping.
            exec_gate.lockUncancelable(io);
            spawn_error_pending = true;
            exec_gate.unlock(io);
            return err;
        },
    };
    const elapsed = started.untilNow(io, .awake);
    const exit_code: i32 = switch (result.term) {
        .exited => |code| code,
        .signal => |sig| 128 + @as(i32, @intCast(@intFromEnum(sig))),
        .stopped => |sig| 128 + @as(i32, @intCast(@intFromEnum(sig))),
        .unknown => |code| @as(i32, @intCast(code)),
    };
    // Same UTF-8 contract as read_file and the session tools: stdout/stderr
    // are byte streams that may contain invalid UTF-8; they are decoded
    // lossily (U+FFFD per bad byte) instead of silently dropping bytes in
    // the JSON encoder.
    const stdout_text = try util.utf8LossyAlloc(arena, result.stdout);
    const stderr_text = try util.utf8LossyAlloc(arena, result.stderr);
    try out.appendSlice(arena, "{\"ok\":");
    try out.appendSlice(arena, if (exit_code == 0) "true" else "false");
    try out.appendSlice(arena, ",\"exit_code\":");
    try out.print(arena, "{d}", .{exit_code});
    try out.appendSlice(arena, ",\"stdout\":");
    try util.appendJsonString(out, arena, stdout_text);
    try out.appendSlice(arena, ",\"stderr\":");
    try util.appendJsonString(out, arena, stderr_text);
    try out.appendSlice(arena, ",\"duration_ms\":");
    try out.print(arena, "{d}", .{elapsed.toMilliseconds()});
    // Same measurement, microsecond resolution: sub-millisecond commands
    // would render duration_ms: 0 and look like a measurement failure.
    try out.appendSlice(arena, ",\"duration_us\":");
    try out.print(arena, "{d}", .{elapsed.toMicroseconds()});
    try out.appendSlice(arena, "}");
}

pub fn toolExecShell(arena: Allocator, io: Io, cfg: *const config.Config, args: Value, out: *std.ArrayList(u8)) !void {
    const script = (try util.optStrArg(args, "script")) orelse return error.MissingScript;
    const default_shell: []const u8 = if (comptime builtin.os.tag == .windows) "cmd" else "bash";
    const shell = (try util.optStrArg(args, "shell")) orelse default_shell;
    // Comptime platform allowlist: POSIX shells on POSIX, cmd/powershell on
    // Windows (mirrored in TOOLS_JSON prose).
    const shell_ok = if (comptime builtin.os.tag == .windows)
        (std.mem.eql(u8, shell, "cmd") or std.mem.eql(u8, shell, "powershell"))
    else
        (std.mem.eql(u8, shell, "bash") or std.mem.eql(u8, shell, "sh") or std.mem.eql(u8, shell, "fish") or std.mem.eql(u8, shell, "zsh"));
    if (!shell_ok) return error.UnsupportedShell;
    const cwd = (try util.optStrArg(args, "cwd")) orelse "";
    const timeout_s = (try util.optIntArg(args, "timeout")) orelse EXEC_DEFAULT_TIMEOUT_S;
    var new_args: std.ArrayList(u8) = .empty;
    try new_args.appendSlice(arena, "{\"argv\":[");
    try util.appendJsonString(&new_args, arena, shell);
    // cmd takes /c; every other supported shell (incl. powershell) takes -c.
    const script_flag: []const u8 = if (std.mem.eql(u8, shell, "cmd")) "/c" else "-c";
    try new_args.appendSlice(arena, ",");
    try util.appendJsonString(&new_args, arena, script_flag);
    try new_args.appendSlice(arena, ",");
    try util.appendJsonString(&new_args, arena, script);
    try new_args.appendSlice(arena, "]");
    if (cwd.len != 0) {
        try new_args.appendSlice(arena, ",\"cwd\":");
        try util.appendJsonString(&new_args, arena, cwd);
    }
    try new_args.appendSlice(arena, ",\"timeout\":");
    try new_args.print(arena, "{d}", .{timeout_s});
    try new_args.appendSlice(arena, "}");
    const parsed = try std.json.parseFromSliceLeaky(Value, arena, new_args.items, .{});
    return toolExec(arena, io, cfg, parsed, out);
}

/// Resolve session_id to a live Session with +1 ref. Caller MUST balance
/// with `defer session_mod.sessionRelease(session)` — the store ref alone does not
/// protect against concurrent exec_close freeing the session.
fn sessionFromArgs(cfg: *const config.Config, args: Value) !*session_mod.Session {
    const store = cfg.sessions orelse return error.SessionsDisabled;
    const id_i = (try util.optIntArg(args, "session_id")) orelse return error.MissingSession;
    if (id_i <= 0) return error.BadSession;
    return store.get(@as(u64, @intCast(id_i))) orelse error.UnknownSession;
}

/// Spawn a session process (piped stdio, own process group) and publish it.
/// Ownership: argv/cwd/stdin_fd transfer to the Session on success; on any
/// error path the errdefers free them exactly once. The child is always
/// reaped — either by the session waiter thread or by the error path.
pub fn toolExecStart(arena: Allocator, io: Io, cfg: *const config.Config, args: Value, out: *std.ArrayList(u8)) !void {
    const store = cfg.sessions orelse return error.SessionsDisabled;
    const argv_v = util.objGet(args, "argv") orelse return error.MissingArgv;
    if (argv_v != .array) return error.BadArgv;
    if (argv_v.array.items.len == 0) return error.BadArgv;

    const argv = try std.heap.page_allocator.alloc([]const u8, argv_v.array.items.len);
    var argv_filled: usize = 0;
    // Ownership transfers to the Session once it is created; the flags keep
    // errdefers from double-freeing what session_mod.freeSession (via
    // session_mod.sessionRelease) freed.
    var argv_owned = false;
    errdefer {
        if (!argv_owned) {
            for (argv[0..argv_filled]) |arg| std.heap.page_allocator.free(arg);
            std.heap.page_allocator.free(argv);
        }
    }
    for (argv_v.array.items, 0..) |item, i| {
        if (item != .string) return error.BadArgv;
        argv[i] = try std.heap.page_allocator.dupe(u8, item.string);
        argv_filled += 1;
    }
    const cwd_s = (try util.optStrArg(args, "cwd")) orelse "";
    const cwd = try std.heap.page_allocator.dupe(u8, cwd_s);
    var cwd_owned = false;
    errdefer {
        if (!cwd_owned) std.heap.page_allocator.free(cwd);
    }

    // Failed-spawn hygiene: gate + pre-flight (see the exec globals above).
    execCallEnter(io);
    defer execCallExit(io);
    try preflightSpawn(arena, io, argv[0], cwd);

    // Stdin wiring splits by platform (see the src/os/proc.zig header).
    // POSIX — parent-owned pipe: the read end goes to the child as `.file`
    // stdio (std dups it in), the write end becomes session_mod.Session.stdin_fd, and
    // std.process.Child.stdin stays null, so child.wait() cleanup can never
    // close the write end from under exec_write. Windows — `.file` stdio
    // re-opens the pipe read end via NtCreateFile with an empty path, which
    // a named pipe answers with STATUS_PIPE_NOT_AVAILABLE (error.NoDevice),
    // so spawn with `.pipe` and let std create the
    // pipe; the parent write end comes back as child.stdin and is taken
    // over into stdin_fd right after the spawn.
    const is_windows = builtin.os.tag == .windows;
    const stdin_pipe: if (is_windows) void else proc.StdinPipe =
        if (is_windows) {} else try proc.createStdinPipe();
    var stdin_read_open: if (is_windows) void else bool = if (is_windows) {} else true;
    var stdin_fd: std.posix.fd_t = undefined;
    // Windows fills stdin_fd only after the spawn (takeover from
    // child.stdin), so the close-defer is gated on validity rather than on
    // the (still undefined) declaration.
    var stdin_fd_valid = false;
    var stdin_owned = false;
    errdefer if (stdin_fd_valid and !stdin_owned) os.closeFd(stdin_fd);
    errdefer if (!is_windows) {
        if (stdin_read_open) os.closeFd(stdin_pipe.read);
    };
    if (!is_windows) {
        stdin_fd = stdin_pipe.write;
        stdin_fd_valid = true;
    }

    // Windows: the Job Object exists before the process so the
    // assign-before-resume sequence can never leak an untracked tree.
    const job: proc.JobField = if (comptime builtin.os.tag == .windows) try proc.createKillOnCloseJob() else proc.no_job;
    var job_owned = false;
    errdefer {
        if (comptime builtin.os.tag == .windows) {
            if (!job_owned) {
                if (job) |j| os.closeFd(j);
            }
        }
    }

    // Fork + publish under the exec gate: a concurrent stray sweep (which
    // holds the same gate) can never observe this child before its pid is
    // registered as protected. On spawn error there is no pid to register —
    // the forked child is an unowned stray, and the exit sweep reaps it.
    exec_gate.lockUncancelable(io);
    var child = std.process.spawn(io, .{
        .argv = argv,
        .cwd = if (cwd.len == 0) .inherit else .{ .path = cwd },
        .stdin = if (is_windows) .pipe else .{ .file = proc.stdinFile(&stdin_pipe) },
        .stdout = .pipe,
        .stderr = .pipe,
        // POSIX: child becomes process-group leader (kill(-pgid) reaches the
        // tree). Windows: null (pid_t is a HANDLE there) — the Job Object
        // takes over the tree role.
        .pgid = proc.child_pgid,
        // Windows only: CREATE_SUSPENDED so the child lands in the job before
        // it can spawn anything. POSIX keeps running-start semantics.
        .start_suspended = proc.spawn_suspended,
    }) catch |err| {
        spawn_error_pending = true; // under exec_gate (see the exit sweep)
        exec_gate.unlock(io);
        return err;
    };
    if (comptime builtin.os.tag != .windows) {
        // A page-allocator miss here would leave the child unprotected; the
        // sweep would then race the waiter's reap. Degradation is bounded
        // (one session may report exit_code null), never a crash, and a
        // single pid append does not realistically fail.
        pending_pids.append(std.heap.page_allocator, child.id.?) catch {};
    }
    exec_gate.unlock(io);
    // Never leak a running child if session allocation fails after spawn.
    // Declared before the stdin takeover: its failure return runs this
    // errdefer too.
    var child_owned = false;
    errdefer {
        if (!child_owned) {
            proc.killTree(session_mod.childPidOrZero(child.id), job);
            _ = child.wait(io) catch null;
        }
    }

    if (is_windows) {
        // std created the stdin pipe for `.pipe` stdio and handed the parent
        // write end back as child.stdin (a synchronous handle — the
        // NtWriteFile loop in writeAllFd works unchanged). Take it over:
        // null the field so childCleanupWindows (behind every child.wait())
        // can never close our write end, then adopt it as stdin_fd.
        const f = child.stdin orelse {
            // Not in the job yet (assignToJob runs below): a job kill would
            // miss the suspended child and the errdefer's child.wait() would
            // hang. Kill by handle.
            proc.terminateHandle(child.id.?);
            return error.StdinPipeTakeoverFailed;
        };
        child.stdin = null;
        stdin_fd = f.handle;
        stdin_fd_valid = true;
    } else {
        // The child owns its stdin read end from here on; drop the parent's
        // copy.
        os.closeFd(stdin_pipe.read);
        stdin_read_open = false;
    }

    if (comptime builtin.os.tag == .windows) {
        proc.assignToJob(job.?, child.id.?) catch |err| {
            // Not in the job yet: a job kill would miss the suspended child
            // and the errdefer's child.wait() would hang. Kill by handle.
            proc.terminateHandle(child.id.?);
            return err;
        };
        try proc.resumeProcess(child.id.?);
    }

    const session = try std.heap.page_allocator.create(session_mod.Session);
    session.* = .{
        .id = store.allocId(),
        .pid = session_mod.childPidOrZero(child.id),
        .argv = argv,
        .cwd = cwd,
        .child = child,
        .stdin_fd = stdin_fd,
        .job = job,
        .started_us = session_mod.nowUs(io),
    };
    argv_owned = true;
    cwd_owned = true;
    child_owned = true;
    stdin_owned = true;
    job_owned = true;

    // Creator reference: store.put() publishes the session, after which a
    // concurrent exec_close may drop the store's ref and free the session
    // while this call is still writing the response. Hold our own ref until
    // the response is fully formed.
    _ = session.refs.fetchAdd(1, .acq_rel);
    defer session_mod.sessionRelease(session); // creator ref

    // Spawn threads before publishing: a session visible in the store always
    // has its threads running, so concurrent exec_close can never see null
    // thread handles and skip the join while exec_start keeps writing.
    session.stdout_thread = std.Thread.spawn(.{}, session_mod.sessionReaderMain, .{ session, session.child.stdout.?.handle, true, cfg.max_out, io }) catch null;
    session.stderr_thread = std.Thread.spawn(.{}, session_mod.sessionReaderMain, .{ session, session.child.stderr.?.handle, false, cfg.max_out, io }) catch null;
    session.waiter_thread = std.Thread.spawn(.{}, session_mod.sessionWaiterMain, .{ session, io }) catch null;
    if (session.stdout_thread == null or session.stderr_thread == null or session.waiter_thread == null) {
        session.closing.store(true, .release);
        session_mod.killTreeGuarded(session, io);
        if (session.waiter_thread) |t| {
            t.join();
        } else {
            _ = session.child.wait(io) catch null;
        }
        if (session.stdout_thread) |t| t.join();
        if (session.stderr_thread) |t| t.join();
        session_mod.sessionRelease(session); // store-side ref was never published
        return error.SessionThreadFailed;
    }

    store.put(session) catch |err| {
        session.closing.store(true, .release);
        session_mod.killTreeGuarded(session, io);
        if (session.waiter_thread) |t| t.join();
        if (session.stdout_thread) |t| t.join();
        if (session.stderr_thread) |t| t.join();
        session_mod.sessionRelease(session); // store-side ref was never published
        return err;
    };

    try out.appendSlice(arena, "{\"ok\":true,\"session_id\":");
    try out.print(arena, "{d}", .{session.id});
    try out.appendSlice(arena, ",\"pid\":");
    try out.print(arena, "{d}", .{session_mod.pidJsonValue(session.pid)});
    try out.appendSlice(arena, "}");
}

pub fn toolExecPoll(arena: Allocator, io: Io, cfg: *const config.Config, args: Value, out: *std.ArrayList(u8)) !void {
    _ = io;
    const session = try sessionFromArgs(cfg, args);
    defer session_mod.sessionRelease(session);
    const stdout_offset = (try util.optIntArg(args, "stdout_offset")) orelse 0;
    const stderr_offset = (try util.optIntArg(args, "stderr_offset")) orelse 0;
    try session_mod.renderSessionState(arena, cfg.sessions.?, session, stdout_offset, stderr_offset, out);
}

pub fn toolExecWait(arena: Allocator, io: Io, cfg: *const config.Config, args: Value, out: *std.ArrayList(u8)) !void {
    _ = io;
    const session = try sessionFromArgs(cfg, args);
    defer session_mod.sessionRelease(session);
    const stdout_offset = (try util.optIntArg(args, "stdout_offset")) orelse 0;
    const stderr_offset = (try util.optIntArg(args, "stderr_offset")) orelse 0;
    var timeout_s = (try util.optIntArg(args, "timeout")) orelse WAIT_DEFAULT_TIMEOUT_S;
    if (timeout_s < 1) timeout_s = 1;
    if (timeout_s > WAIT_MAX_TIMEOUT_S) timeout_s = WAIT_MAX_TIMEOUT_S;
    const store = cfg.sessions.?;
    const deadline = session_mod.nowUs(store.io) + @as(i64, timeout_s) * std.time.us_per_s;
    while (true) {
        session.mutex.lockUncancelable(store.io);
        const done = session.done;
        session.mutex.unlock(store.io);
        if (done) break;
        if (session_mod.nowUs(store.io) >= deadline) break;
        os.sleepMs(WAIT_POLL_MS);
    }
    try session_mod.renderSessionState(arena, store, session, stdout_offset, stderr_offset, out);
}

pub fn toolExecList(arena: Allocator, io: Io, cfg: *const config.Config, out: *std.ArrayList(u8)) !void {
    _ = io;
    const store = cfg.sessions orelse return error.SessionsDisabled;
    store.reapDone();
    store.mutex.lockUncancelable(store.io);
    defer store.mutex.unlock(store.io);
    try out.appendSlice(arena, "{\"ok\":true,\"sessions\":[");
    var it = store.map.iterator();
    var first = true;
    while (it.next()) |kv| {
        const s = kv.value_ptr.*;
        s.mutex.lockUncancelable(store.io);
        const done = s.done;
        const exit_code = s.exit_code;
        const pid = s.pid;
        const started = s.started_us;
        const ended = s.ended_us;
        s.mutex.unlock(store.io);
        if (!first) try out.appendSlice(arena, ",");
        first = false;
        try out.appendSlice(arena, "{\"session_id\":");
        try out.print(arena, "{d}", .{s.id});
        try out.appendSlice(arena, ",\"pid\":");
        try out.print(arena, "{d}", .{session_mod.pidJsonValue(pid)});
        try out.appendSlice(arena, ",\"argv\":[");
        for (s.argv, 0..) |arg, i| {
            if (i != 0) try out.appendSlice(arena, ",");
            try util.appendJsonString(out, arena, arg);
        }
        try out.appendSlice(arena, "],\"done\":");
        try out.appendSlice(arena, if (done) "true" else "false");
        try out.appendSlice(arena, ",\"exit_code\":");
        if (exit_code) |code| try out.print(arena, "{d}", .{code}) else try out.appendSlice(arena, "null");
        // started_ms/ended_ms keep their v0 names and units; the session
        // internally tracks microseconds since the duration_us work.
        try out.appendSlice(arena, ",\"started_ms\":");
        try out.print(arena, "{d}", .{@divTrunc(started, std.time.us_per_ms)});
        try out.appendSlice(arena, ",\"ended_ms\":");
        if (ended) |e| try out.print(arena, "{d}", .{@divTrunc(e, std.time.us_per_ms)}) else try out.appendSlice(arena, "null");
        try out.appendSlice(arena, "}");
    }
    try out.appendSlice(arena, "]}");
}

pub fn toolExecWrite(arena: Allocator, io: Io, cfg: *const config.Config, args: Value, out: *std.ArrayList(u8)) !void {
    _ = io;
    // Validate protocol-level argument types before resolving the session:
    // a wrong-typed argument is -32602 regardless of whether the session id
    // happens to exist.
    const data_b64 = (try util.optStrArg(args, "data_b64")) orelse return error.MissingData;
    const eof = (try util.optBoolArg(args, "eof")) orelse false;
    const session = try sessionFromArgs(cfg, args);
    defer session_mod.sessionRelease(session);
    const size = try std.base64.standard.Decoder.calcSizeForSlice(data_b64);
    const data = try std.heap.page_allocator.alloc(u8, size);
    defer std.heap.page_allocator.free(data);
    try std.base64.standard.Decoder.decode(data, data_b64);

    const sio = (cfg.sessions.?).io;
    session.stdin_mutex.lockUncancelable(sio);
    defer session.stdin_mutex.unlock(sio);
    const fd = session.stdin_fd orelse return error.StdinClosed;
    session.mutex.lockUncancelable(sio);
    const exited = session.done;
    session.mutex.unlock(sio);
    if (exited) return error.ProcessExited;
    if (data.len != 0) try proc.writeAllFd(fd, data);
    if (eof) {
        os.closeFd(fd);
        session.stdin_fd = null;
    }
    try out.appendSlice(arena, "{\"ok\":true,\"bytes\":");
    try out.print(arena, "{d}", .{data.len});
    try out.appendSlice(arena, ",\"eof\":");
    try out.appendSlice(arena, if (eof) "true" else "false");
    try out.appendSlice(arena, "}");
}

pub fn toolExecKill(arena: Allocator, io: Io, cfg: *const config.Config, args: Value, out: *std.ArrayList(u8)) !void {
    const session = try sessionFromArgs(cfg, args);
    defer session_mod.sessionRelease(session);
    // session_mod.killTreeGuarded serializes check+kill against the waiter's reap: the
    // kill either lands while the leader zombie still pins the process group
    // or is skipped because the tree is already known dead.
    session_mod.killTreeGuarded(session, io);
    try out.appendSlice(arena, "{\"ok\":true}");
}

/// Idempotent session teardown: kill if running, join all session threads,
/// drop the store's ref. Safe against concurrent exec_close — the loser of
/// the removal race reports already_closed and frees nothing.
pub fn toolExecClose(arena: Allocator, io: Io, cfg: *const config.Config, args: Value, out: *std.ArrayList(u8)) !void {
    const store = cfg.sessions orelse return error.SessionsDisabled;
    const session = sessionFromArgs(cfg, args) catch |err| switch (err) {
        error.UnknownSession => {
            // Idempotent close: already removed from the map.
            try out.appendSlice(arena, "{\"ok\":true,\"already_closed\":true}");
            return;
        },
        else => return err,
    };
    defer session_mod.sessionRelease(session); // caller's ref
    const removed = store.remove(session.id) orelse {
        // A concurrent exec_close won the removal race and owns kill+join.
        try out.appendSlice(arena, "{\"ok\":true,\"already_closed\":true}");
        return;
    };
    session.closing.store(true, .release);
    // Same serialized guard as exec_kill: once the waiter (or a previous
    // kill/close) killed the tree, never signal the group again.
    session_mod.killTreeGuarded(session, io);
    if (session.waiter_thread) |t| t.join();
    if (session.stdout_thread) |t| t.join();
    if (session.stderr_thread) |t| t.join();
    session_mod.sessionRelease(removed); // store's ref; frees once the last holder releases
    try out.appendSlice(arena, "{\"ok\":true}");
}

pub fn toolSysInfo(arena: Allocator, io: Io, cfg: *const config.Config, out: *std.ArrayList(u8)) !void {
    _ = cfg;
    // Per-OS fetchers live in os.sysinfo; every field
    // degrades independently to ""/0.
    const info = os.sysinfo.fetch(arena, io);
    try out.appendSlice(arena, "{\"node\":");
    try util.appendJsonString(out, arena, info.hostname);
    try out.appendSlice(arena, ",\"hostname\":");
    try util.appendJsonString(out, arena, info.hostname);
    try out.appendSlice(arena, ",\"os\":\"" ++ os.sysinfo.os_name ++ "\",\"machine\":\"" ++ os.sysinfo.machine ++ "\",\"loadavg_raw\":");
    try util.appendJsonString(out, arena, info.loadavg_raw);
    try out.appendSlice(arena, ",\"uptime_raw\":");
    try util.appendJsonString(out, arena, info.uptime_raw);
    try out.appendSlice(arena, ",\"mem\":{\"MemTotal\":");
    try out.print(arena, "{d}", .{info.mem_total});
    try out.appendSlice(arena, ",\"MemAvailable\":");
    try out.print(arena, "{d}", .{info.mem_available});
    try out.appendSlice(arena, "},\"disk_root\":{\"total\":");
    try out.print(arena, "{d}", .{info.disk_root.total});
    try out.appendSlice(arena, ",\"used\":");
    try out.print(arena, "{d}", .{info.disk_root.used});
    try out.appendSlice(arena, ",\"free\":");
    try out.print(arena, "{d}", .{info.disk_root.free});
    try out.appendSlice(arena, "}}");
}

pub fn toolReadFile(arena: Allocator, io: Io, cfg: *const config.Config, args: Value, out: *std.ArrayList(u8)) !void {
    _ = cfg;
    const path = try expandPath(arena, io, (try util.optStrArg(args, "path")) orelse return error.MissingPath);
    const offset = (try util.optIntArg(args, "offset")) orelse 0;
    const limit = (try util.optIntArg(args, "limit")) orelse READ_FILE_DEFAULT_LIMIT_CHARS;
    if (offset < 0 or limit < 0) return error.BadOffset;
    const data = os.fd.readFileAlloc(arena, io, path, READ_FILE_MAX_BYTES) catch |err| {
        // The read path is cross-platform, so the mapping holds
        // on every target. error.IsDir surfaces at read time (opening a
        // directory read-only succeeds, the first read fails).
        switch (err) {
            error.FileNotFound => return error.FileNotFound,
            error.IsDir => return error.IsDirectory,
            error.StreamTooLong => return error.FileTooLarge,
            else => return err,
        }
    };
    const text = try util.utf8LossyAlloc(arena, data);
    const slice = try util.utf8CharSlice(text, @intCast(offset), @intCast(limit));
    try out.appendSlice(arena, "{\"ok\":true,\"path\":");
    try util.appendJsonString(out, arena, path);
    try out.appendSlice(arena, ",\"size\":");
    try out.print(arena, "{d}", .{data.len});
    try out.appendSlice(arena, ",\"offset\":");
    try out.print(arena, "{d}", .{offset});
    try out.appendSlice(arena, ",\"content\":");
    try util.appendJsonString(out, arena, slice.text);
    try out.appendSlice(arena, ",\"has_more\":");
    try out.appendSlice(arena, if (slice.has_more) "true" else "false");
    try out.appendSlice(arena, "}");
}

pub fn toolWriteFile(arena: Allocator, io: Io, cfg: *const config.Config, args: Value, out: *std.ArrayList(u8)) !void {
    _ = cfg;
    const path = try expandPath(arena, io, (try util.optStrArg(args, "path")) orelse return error.MissingPath);
    const content_b64 = (try util.optStrArg(args, "content_b64")) orelse return error.MissingContent;
    const mode_i = (try util.optIntArg(args, "mode")) orelse 0o644;
    const mkdirs = (try util.optBoolArg(args, "mkdirs")) orelse true;
    if (mode_i < 0 or mode_i > 0o7777) return error.BadMode;

    const size = try std.base64.standard.Decoder.calcSizeForSlice(content_b64);
    const data = try arena.alloc(u8, size);
    try std.base64.standard.Decoder.decode(data, content_b64);

    if (mkdirs) {
        if (std.fs.path.dirname(path)) |parent| {
            if (parent.len != 0 and !std.mem.eql(u8, parent, ".")) {
                try std.Io.Dir.createDirPath(.cwd(), io, parent);
            }
        }
    }
    const mode: std.posix.mode_t = @intCast(mode_i);
    // POSIX applies `mode` exactly via openat(2); on Windows the
    // mode is ignored (NTFS ACLs, not POSIX permission bits) — both paths and
    // the rationale live in os.fd.writeFile.
    try os.fd.writeFile(io, path, data, mode);

    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update(data);
    var digest: [32]u8 = undefined;
    h.final(&digest);
    try out.appendSlice(arena, "{\"ok\":true,\"path\":");
    try util.appendJsonString(out, arena, path);
    try out.appendSlice(arena, ",\"size\":");
    try out.print(arena, "{d}", .{data.len});
    try out.appendSlice(arena, ",\"sha256\":");
    try util.appendHexLower(out, arena, &digest);
    try out.appendSlice(arena, "}");
}

pub fn toolListDir(arena: Allocator, io: Io, cfg: *const config.Config, args: Value, out: *std.ArrayList(u8)) !void {
    _ = cfg;
    const path = try expandPath(arena, io, (try util.optStrArg(args, "path")) orelse ".");
    var dir = std.Io.Dir.openDir(.cwd(), io, path, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => return error.FileNotFound,
        error.NotDir => return error.NotDirectory,
        else => return err,
    };
    defer dir.close(io);
    var it = dir.iterate();
    const Item = struct { name: []const u8, kind: []const u8, size: i64, mtime: i64 };
    var items: std.ArrayList(Item) = .empty;
    var truncated = false;
    while (try it.next(io)) |entry| {
        if (items.items.len >= LIST_DIR_MAX_ENTRIES) {
            // One more entry exists beyond the cap: the listing is partial.
            truncated = true;
            break;
        }
        const kind: []const u8 = switch (entry.kind) {
            .directory => "d",
            .sym_link => "l",
            .file => "f",
            else => "?",
        };
        var size: i64 = -1;
        var mtime: i64 = 0;
        if (dir.statFile(io, entry.name, .{})) |st| {
            size = @intCast(st.size);
            mtime = st.mtime.toSeconds();
        } else |_| {}
        try items.append(arena, .{ .name = try arena.dupe(u8, entry.name), .kind = kind, .size = size, .mtime = mtime });
    }
    // Sort by name: listings must be deterministic across calls.
    std.mem.sort(Item, items.items, {}, struct {
        fn lt(_: void, a: Item, b: Item) bool {
            return std.mem.order(u8, a.name, b.name) == .lt;
        }
    }.lt);
    try out.appendSlice(arena, "{\"ok\":true,\"path\":");
    try util.appendJsonString(out, arena, path);
    try out.appendSlice(arena, ",\"items\":[");
    for (items.items, 0..) |item, i| {
        if (i != 0) try out.appendSlice(arena, ",");
        try out.appendSlice(arena, "{\"name\":");
        try util.appendJsonString(out, arena, item.name);
        try out.appendSlice(arena, ",\"type\":");
        try util.appendJsonString(out, arena, item.kind);
        try out.appendSlice(arena, ",\"size\":");
        try out.print(arena, "{d}", .{item.size});
        try out.appendSlice(arena, ",\"mtime\":");
        try out.print(arena, "{d}", .{item.mtime});
        try out.appendSlice(arena, "}");
    }
    try out.appendSlice(arena, "],\"count\":");
    try out.print(arena, "{d}", .{items.items.len});
    // Frozen contract: `truncated` and `has_more` carry the same fact (at
    // least one entry exists beyond the returned page); both names are
    // emitted so clients can rely on either spelling. No paging is offered:
    // the returned set is the first LIST_DIR_MAX_ENTRIES entries, sorted by
    // name for determinism.
    try out.appendSlice(arena, ",\"truncated\":");
    try out.appendSlice(arena, if (truncated) "true" else "false");
    try out.appendSlice(arena, ",\"has_more\":");
    try out.appendSlice(arena, if (truncated) "true" else "false");
    try out.appendSlice(arena, "}");
}

fn expandPath(arena: Allocator, io: Io, path: []const u8) ![]const u8 {
    _ = io;
    // Expand "~" and "~/x" to the user's home directory; leave "~user" and
    // everything else untouched. Home resolution is cross-platform
    // via the OS layer ($HOME on POSIX; %USERPROFILE% with a
    // %HOMEDRIVE%%HOMEPATH% fallback on Windows).
    if (path.len == 0 or path[0] != '~') return path;
    if (path.len > 1 and path[1] != '/') return path; // "~user" unsupported
    const home = os.homeDir(arena, env_state.process_environ) orelse return path;
    if (home.len == 0) return path;
    return std.mem.concat(arena, u8, &.{ home, path[1..] });
}

// --- tests ------------------------------------------------------------------
//
// Behavioral tests drive the public tool entry points with JSON arguments
// and parse the JSON responses back — the same contract the RPC layer
// exposes. Each test builds its own `Io.Threaded` instance (std's
// `global_single_threaded` carries a failing allocator, which breaks
// process spawning and directory creation) and, where HOME or PATH
// semantics matter, a synthetic environment snapshot saved and restored
// around the test.

fn testConfig(arena: Allocator) !config.Config {
    return .{
        .name = "test-node",
        .host = "127.0.0.1",
        .port = 1,
        .token = "",
        .allowed_hosts = try util.splitCsv(arena, "127.0.0.1:*"),
        .allowed_origins = try util.splitCsv(arena, "http://127.0.0.1:*"),
        .max_out = 1024 * 1024,
        .socket_timeout_s = 1,
        .max_conn = 4,
        .max_sessions = 8,
        .session_ttl_s = 600,
        .max_inflight_bytes = 64 * 1024 * 1024,
    };
}

fn parseArgs(arena: Allocator, json: []const u8) !Value {
    return std.json.parseFromSliceLeaky(Value, arena, json, .{});
}

fn runTool(
    arena: Allocator,
    io: Io,
    cfg: *const config.Config,
    comptime tool: anytype,
    args_json: []const u8,
    out: *std.ArrayList(u8),
) !void {
    const args = try parseArgs(arena, args_json);
    try tool(arena, io, cfg, args, out);
}

fn b64Alloc(arena: Allocator, data: []const u8) ![]const u8 {
    const enc = std.base64.standard.Encoder;
    const buf = try arena.alloc(u8, enc.calcSize(data.len));
    return enc.encode(buf, data);
}

fn hexLowerAlloc(arena: Allocator, bytes: []const u8) ![]const u8 {
    const digits = "0123456789abcdef";
    const buf = try arena.alloc(u8, bytes.len * 2);
    for (bytes, 0..) |b, i| {
        buf[i * 2] = digits[b >> 4];
        buf[i * 2 + 1] = digits[b & 0xf];
    }
    return buf;
}

fn getBool(v: Value, key: []const u8) bool {
    return v.object.get(key).?.bool;
}

fn getInt(v: Value, key: []const u8) i64 {
    return v.object.get(key).?.integer;
}

fn getStr(v: Value, key: []const u8) []const u8 {
    return v.object.get(key).?.string;
}

test "expandPath expands tilde against HOME from the environ snapshot" {
    if (builtin.os.tag != .linux) return error.SkipZigTest; // CI runs unit tests on Linux only
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = Io.Threaded.global_single_threaded.io();

    const saved = env_state.process_environ;
    defer env_state.process_environ = saved;
    const slice = try arena.allocSentinel(?[*:0]const u8, 2, null);
    slice[0] = "HOME=/envhome/tester";
    slice[1] = "PATH=/usr/bin:/bin";
    env_state.process_environ = .{ .block = .{ .slice = slice } };

    try std.testing.expectEqualStrings("/envhome/tester", try expandPath(arena, io, "~"));
    try std.testing.expectEqualStrings("/envhome/tester/", try expandPath(arena, io, "~/"));
    try std.testing.expectEqualStrings("/envhome/tester/x", try expandPath(arena, io, "~/x"));
    try std.testing.expectEqualStrings("/envhome/tester/a/b", try expandPath(arena, io, "~/a/b"));
    // "~user" is unsupported and left untouched, as are empty, relative
    // and absolute paths.
    try std.testing.expectEqualStrings("~root", try expandPath(arena, io, "~root"));
    try std.testing.expectEqualStrings("~root/x", try expandPath(arena, io, "~root/x"));
    try std.testing.expectEqualStrings("", try expandPath(arena, io, ""));
    try std.testing.expectEqualStrings("/abs", try expandPath(arena, io, "/abs"));
    try std.testing.expectEqualStrings("rel/path", try expandPath(arena, io, "rel/path"));

    // Without HOME the tilde is not expandable: the input comes back
    // unchanged instead of failing.
    env_state.process_environ = .empty;
    try std.testing.expectEqualStrings("~", try expandPath(arena, io, "~"));
    try std.testing.expectEqualStrings("~/x", try expandPath(arena, io, "~/x"));
}

test "tool exec runs commands and reports exit codes" {
    if (builtin.os.tag != .linux) return error.SkipZigTest; // CI runs unit tests on Linux only
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var threaded = Io.Threaded.init(std.heap.page_allocator, .{ .environ = env_state.process_environ });
    defer threaded.deinit();
    const io = threaded.io();
    const cfg = try testConfig(arena);

    var out: std.ArrayList(u8) = .empty;
    try runTool(arena, io, &cfg, toolExec, "{\"argv\":[\"/bin/echo\",\"hello\",\"world\"]}", &out);
    var v = try parseArgs(arena, out.items);
    try std.testing.expect(getBool(v, "ok"));
    try std.testing.expectEqual(@as(i64, 0), getInt(v, "exit_code"));
    try std.testing.expectEqualStrings("hello world\n", getStr(v, "stdout"));
    try std.testing.expectEqualStrings("", getStr(v, "stderr"));

    // stderr and a nonzero exit code both surface (ok mirrors the code).
    out = .empty;
    try runTool(arena, io, &cfg, toolExec, "{\"argv\":[\"/bin/cat\",\"/nonexistent-mcpnz-input\"]}", &out);
    v = try parseArgs(arena, out.items);
    try std.testing.expect(!getBool(v, "ok"));
    try std.testing.expectEqual(@as(i64, 1), getInt(v, "exit_code"));
    try std.testing.expect(std.mem.indexOf(u8, getStr(v, "stderr"), "No such file") != null);

    // The spawn pre-flight rejects a missing program without forking.
    out = .empty;
    try std.testing.expectError(
        error.FileNotFound,
        runTool(arena, io, &cfg, toolExec, "{\"argv\":[\"/nonexistent/mcpnz-prog\"]}", &out),
    );
}

test "tool exec timeout surfaces CommandTimeout payload" {
    if (builtin.os.tag != .linux) return error.SkipZigTest; // CI runs unit tests on Linux only
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var threaded = Io.Threaded.init(std.heap.page_allocator, .{ .environ = env_state.process_environ });
    defer threaded.deinit();
    const io = threaded.io();
    const cfg = try testConfig(arena);

    var out: std.ArrayList(u8) = .empty;
    try runTool(arena, io, &cfg, toolExec, "{\"argv\":[\"/bin/sleep\",\"30\"],\"timeout\":1}", &out);
    const v = try parseArgs(arena, out.items);
    try std.testing.expect(!getBool(v, "ok"));
    try std.testing.expect(getBool(v, "timeout"));
    try std.testing.expectEqualStrings("CommandTimeout", getStr(v, "error"));

    // A timeout below the 1-second floor is clamped up to 1, never 0:
    // the payload is the same machine-readable timeout fact.
    out = .empty;
    try runTool(arena, io, &cfg, toolExec, "{\"argv\":[\"/bin/sleep\",\"30\"],\"timeout\":0}", &out);
    const clamped = try parseArgs(arena, out.items);
    try std.testing.expect(getBool(clamped, "timeout"));
    try std.testing.expectEqualStrings("CommandTimeout", getStr(clamped, "error"));
}

test "tool exec shell runs bash pipelines and rejects unsupported shells" {
    if (builtin.os.tag != .linux) return error.SkipZigTest; // CI runs unit tests on Linux only
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // "bash" (no slash) resolves through PATH: both the pre-flight and
    // the spawn layer read the process environment snapshot.
    const saved = env_state.process_environ;
    defer env_state.process_environ = saved;
    const slice = try arena.allocSentinel(?[*:0]const u8, 2, null);
    slice[0] = "PATH=/usr/bin:/bin";
    slice[1] = "HOME=/envhome/tester";
    env_state.process_environ = .{ .block = .{ .slice = slice } };
    var threaded = Io.Threaded.init(std.heap.page_allocator, .{ .environ = env_state.process_environ });
    defer threaded.deinit();
    const io = threaded.io();
    const cfg = try testConfig(arena);

    var out: std.ArrayList(u8) = .empty;
    try runTool(arena, io, &cfg, toolExecShell, "{\"script\":\"echo hi | tr a-z A-Z\",\"shell\":\"bash\"}", &out);
    var v = try parseArgs(arena, out.items);
    try std.testing.expect(getBool(v, "ok"));
    try std.testing.expectEqual(@as(i64, 0), getInt(v, "exit_code"));
    try std.testing.expectEqualStrings("HI\n", getStr(v, "stdout"));

    // Omitting the shell defaults to bash on POSIX.
    out = .empty;
    try runTool(arena, io, &cfg, toolExecShell, "{\"script\":\"echo default\"}", &out);
    v = try parseArgs(arena, out.items);
    try std.testing.expectEqualStrings("default\n", getStr(v, "stdout"));

    // A shell outside the platform allowlist is refused before spawning.
    out = .empty;
    try std.testing.expectError(
        error.UnsupportedShell,
        runTool(arena, io, &cfg, toolExecShell, "{\"script\":\"true\",\"shell\":\"powershell\"}", &out),
    );
}

test "write file and read file roundtrip with sha256 and mode" {
    if (builtin.os.tag != .linux) return error.SkipZigTest; // CI runs unit tests on Linux only
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var threaded = Io.Threaded.init(std.heap.page_allocator, .{ .environ = env_state.process_environ });
    defer threaded.deinit();
    const io = threaded.io();
    const cfg = try testConfig(arena);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [4096]u8 = undefined;
    const root_len = try tmp.dir.realPath(io, &path_buf);
    const root = try arena.dupe(u8, path_buf[0..root_len]);
    const content = "hello world";

    var out: std.ArrayList(u8) = .empty;
    const file_path = try std.fmt.allocPrint(arena, "{s}/roundtrip.txt", .{root});
    var args = try std.fmt.allocPrint(arena, "{{\"path\":\"{s}\",\"content_b64\":\"{s}\",\"mode\":{d}}}", .{
        file_path, try b64Alloc(arena, content), @as(i64, 0o600),
    });
    try runTool(arena, io, &cfg, toolWriteFile, args, &out);
    var v = try parseArgs(arena, out.items);
    try std.testing.expect(getBool(v, "ok"));
    try std.testing.expectEqualStrings(file_path, getStr(v, "path"));
    try std.testing.expectEqual(@as(i64, @intCast(content.len)), getInt(v, "size"));
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(content, &digest, .{});
    try std.testing.expectEqualStrings(try hexLowerAlloc(arena, &digest), getStr(v, "sha256"));

    // The permission bits reach the filesystem on POSIX (0o600 has no
    // group/other bits, so no sane umask can strip it).
    const st = try std.Io.Dir.statFile(.cwd(), io, file_path, .{});
    try std.testing.expectEqual(@as(std.posix.mode_t, 0o600), st.permissions.toMode() & 0o777);

    // Reading the file back through the tool.
    out = .empty;
    args = try std.fmt.allocPrint(arena, "{{\"path\":\"{s}\"}}", .{file_path});
    try runTool(arena, io, &cfg, toolReadFile, args, &out);
    v = try parseArgs(arena, out.items);
    try std.testing.expect(getBool(v, "ok"));
    try std.testing.expectEqualStrings(file_path, getStr(v, "path"));
    try std.testing.expectEqual(@as(i64, @intCast(content.len)), getInt(v, "size"));
    try std.testing.expectEqual(@as(i64, 0), getInt(v, "offset"));
    try std.testing.expectEqualStrings(content, getStr(v, "content"));
    try std.testing.expect(!getBool(v, "has_more"));

    // offset/limit are character positions: slice "cde" out of "abcdef".
    const slice_path = try std.fmt.allocPrint(arena, "{s}/slice.txt", .{root});
    out = .empty;
    args = try std.fmt.allocPrint(arena, "{{\"path\":\"{s}\",\"content_b64\":\"{s}\"}}", .{
        slice_path, try b64Alloc(arena, "abcdef"),
    });
    try runTool(arena, io, &cfg, toolWriteFile, args, &out);

    out = .empty;
    args = try std.fmt.allocPrint(arena, "{{\"path\":\"{s}\",\"offset\":2,\"limit\":3}}", .{slice_path});
    try runTool(arena, io, &cfg, toolReadFile, args, &out);
    v = try parseArgs(arena, out.items);
    try std.testing.expectEqualStrings("cde", getStr(v, "content"));
    try std.testing.expect(getBool(v, "has_more"));
    try std.testing.expectEqual(@as(i64, 2), getInt(v, "offset"));
    try std.testing.expectEqual(@as(i64, 6), getInt(v, "size"));

    // Negative offset/limit are rejected before any read happens.
    out = .empty;
    args = try std.fmt.allocPrint(arena, "{{\"path\":\"{s}\",\"offset\":-1}}", .{slice_path});
    try std.testing.expectError(error.BadOffset, runTool(arena, io, &cfg, toolReadFile, args, &out));
    out = .empty;
    args = try std.fmt.allocPrint(arena, "{{\"path\":\"{s}\",\"limit\":-1}}", .{slice_path});
    try std.testing.expectError(error.BadOffset, runTool(arena, io, &cfg, toolReadFile, args, &out));

    // Missing files and directories map to distinct errors.
    out = .empty;
    args = try std.fmt.allocPrint(arena, "{{\"path\":\"{s}/missing.txt\"}}", .{root});
    try std.testing.expectError(error.FileNotFound, runTool(arena, io, &cfg, toolReadFile, args, &out));
    out = .empty;
    args = try std.fmt.allocPrint(arena, "{{\"path\":\"{s}\"}}", .{root});
    try std.testing.expectError(error.IsDirectory, runTool(arena, io, &cfg, toolReadFile, args, &out));
}

test "write file validates mode base64 and parent creation" {
    if (builtin.os.tag != .linux) return error.SkipZigTest; // CI runs unit tests on Linux only
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var threaded = Io.Threaded.init(std.heap.page_allocator, .{ .environ = env_state.process_environ });
    defer threaded.deinit();
    const io = threaded.io();
    const cfg = try testConfig(arena);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [4096]u8 = undefined;
    const root_len = try tmp.dir.realPath(io, &path_buf);
    const root = try arena.dupe(u8, path_buf[0..root_len]);

    // mode is bounded to 0..0o7777.
    var out: std.ArrayList(u8) = .empty;
    var args = try std.fmt.allocPrint(arena, "{{\"path\":\"{s}/mode.txt\",\"content_b64\":\"eA==\",\"mode\":{d}}}", .{
        root, @as(i64, 0o10000),
    });
    try std.testing.expectError(error.BadMode, runTool(arena, io, &cfg, toolWriteFile, args, &out));
    out = .empty;
    args = try std.fmt.allocPrint(arena, "{{\"path\":\"{s}/mode.txt\",\"content_b64\":\"eA==\",\"mode\":-1}}", .{root});
    try std.testing.expectError(error.BadMode, runTool(arena, io, &cfg, toolWriteFile, args, &out));

    // Invalid base64 fails with the decoder's own errors before any file
    // is touched: an illegal character and a bad length are distinct.
    out = .empty;
    args = try std.fmt.allocPrint(arena, "{{\"path\":\"{s}/b64.txt\",\"content_b64\":\"!!!!\"}}", .{root});
    try std.testing.expectError(error.InvalidCharacter, runTool(arena, io, &cfg, toolWriteFile, args, &out));
    out = .empty;
    args = try std.fmt.allocPrint(arena, "{{\"path\":\"{s}/b64.txt\",\"content_b64\":\"ABCDE\"}}", .{root});
    try std.testing.expectError(error.InvalidPadding, runTool(arena, io, &cfg, toolWriteFile, args, &out));

    // mkdirs=false keeps a missing parent an error.
    out = .empty;
    args = try std.fmt.allocPrint(arena, "{{\"path\":\"{s}/no_parent/f.txt\",\"content_b64\":\"eA==\",\"mkdirs\":false}}", .{root});
    try std.testing.expectError(error.FileNotFound, runTool(arena, io, &cfg, toolWriteFile, args, &out));

    // The default mkdirs=true creates every missing parent.
    out = .empty;
    args = try std.fmt.allocPrint(arena, "{{\"path\":\"{s}/deep/nested/f.txt\",\"content_b64\":\"{s}\"}}", .{
        root, try b64Alloc(arena, "nested"),
    });
    try runTool(arena, io, &cfg, toolWriteFile, args, &out);
    const nested = try parseArgs(arena, out.items);
    try std.testing.expect(getBool(nested, "ok"));
    try std.testing.expectEqual(@as(i64, 6), getInt(nested, "size"));

    out = .empty;
    args = try std.fmt.allocPrint(arena, "{{\"path\":\"{s}/deep/nested/f.txt\"}}", .{root});
    try runTool(arena, io, &cfg, toolReadFile, args, &out);
    const read = try parseArgs(arena, out.items);
    try std.testing.expectEqualStrings("nested", getStr(read, "content"));
}

test "list dir sorts entries and reports types" {
    if (builtin.os.tag != .linux) return error.SkipZigTest; // CI runs unit tests on Linux only
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var threaded = Io.Threaded.init(std.heap.page_allocator, .{ .environ = env_state.process_environ });
    defer threaded.deinit();
    const io = threaded.io();
    const cfg = try testConfig(arena);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [4096]u8 = undefined;
    const root_len = try tmp.dir.realPath(io, &path_buf);
    const root = try arena.dupe(u8, path_buf[0..root_len]);

    // Fixtures: two files written through the write tool plus one plain
    // subdirectory, deliberately created out of sorted order.
    var out: std.ArrayList(u8) = .empty;
    var args = try std.fmt.allocPrint(arena, "{{\"path\":\"{s}/b.txt\",\"content_b64\":\"{s}\"}}", .{
        root, try b64Alloc(arena, "bbb"),
    });
    try runTool(arena, io, &cfg, toolWriteFile, args, &out);
    out = .empty;
    args = try std.fmt.allocPrint(arena, "{{\"path\":\"{s}/a.txt\",\"content_b64\":\"{s}\"}}", .{
        root, try b64Alloc(arena, "a"),
    });
    try runTool(arena, io, &cfg, toolWriteFile, args, &out);
    const sub = try std.fmt.allocPrint(arena, "{s}/sub", .{root});
    try std.Io.Dir.createDirPath(.cwd(), io, sub);

    out = .empty;
    args = try std.fmt.allocPrint(arena, "{{\"path\":\"{s}\"}}", .{root});
    try runTool(arena, io, &cfg, toolListDir, args, &out);
    const v = try parseArgs(arena, out.items);
    try std.testing.expect(getBool(v, "ok"));
    const items = v.object.get("items").?.array.items;
    try std.testing.expectEqual(@as(usize, 3), items.len);
    try std.testing.expectEqualStrings("a.txt", getStr(items[0], "name"));
    try std.testing.expectEqualStrings("f", getStr(items[0], "type"));
    try std.testing.expectEqual(@as(i64, 1), getInt(items[0], "size"));
    try std.testing.expectEqualStrings("b.txt", getStr(items[1], "name"));
    try std.testing.expectEqualStrings("f", getStr(items[1], "type"));
    try std.testing.expectEqual(@as(i64, 3), getInt(items[1], "size"));
    try std.testing.expectEqualStrings("sub", getStr(items[2], "name"));
    try std.testing.expectEqualStrings("d", getStr(items[2], "type"));
    try std.testing.expectEqual(@as(i64, 3), getInt(v, "count"));
    try std.testing.expect(!getBool(v, "has_more"));
    try std.testing.expect(!getBool(v, "truncated"));

    // A missing directory and a plain file are distinct errors.
    out = .empty;
    args = try std.fmt.allocPrint(arena, "{{\"path\":\"{s}/missing-dir\"}}", .{root});
    try std.testing.expectError(error.FileNotFound, runTool(arena, io, &cfg, toolListDir, args, &out));
    out = .empty;
    args = try std.fmt.allocPrint(arena, "{{\"path\":\"{s}/a.txt\"}}", .{root});
    try std.testing.expectError(error.NotDirectory, runTool(arena, io, &cfg, toolListDir, args, &out));
}

test "exec session lifecycle start write wait poll close" {
    if (builtin.os.tag != .linux) return error.SkipZigTest; // CI runs unit tests on Linux only
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const saved = env_state.process_environ;
    defer env_state.process_environ = saved;
    const slice = try arena.allocSentinel(?[*:0]const u8, 2, null);
    slice[0] = "PATH=/usr/bin:/bin";
    slice[1] = "HOME=/envhome/tester";
    env_state.process_environ = .{ .block = .{ .slice = slice } };
    var threaded = Io.Threaded.init(std.heap.page_allocator, .{ .environ = env_state.process_environ });
    defer threaded.deinit();
    const io = threaded.io();

    var cfg = try testConfig(arena);
    const store = try std.heap.page_allocator.create(session_mod.SessionStore);
    store.* = session_mod.SessionStore.init(io, 8);
    cfg.sessions = store;

    // exec_start publishes the session before returning.
    var out: std.ArrayList(u8) = .empty;
    try runTool(arena, io, &cfg, toolExecStart, "{\"argv\":[\"/bin/cat\"]}", &out);
    const start = try parseArgs(arena, out.items);
    try std.testing.expect(getBool(start, "ok"));
    const sid = getInt(start, "session_id");
    try std.testing.expect(sid > 0);
    try std.testing.expect(getInt(start, "pid") > 0);

    // exec_list shows the live session with its argv.
    out = .empty;
    try toolExecList(arena, io, &cfg, &out);
    const list = try parseArgs(arena, out.items);
    try std.testing.expect(getBool(list, "ok"));
    var listed = false;
    for (list.object.get("sessions").?.array.items) |item| {
        if (getInt(item, "session_id") == sid) {
            listed = true;
            try std.testing.expect(!getBool(item, "done"));
            try std.testing.expectEqualStrings("/bin/cat", item.object.get("argv").?.array.items[0].string);
        }
    }
    try std.testing.expect(listed);

    // exec_write feeds stdin; eof closes it, which lets cat exit.
    out = .empty;
    var args = try std.fmt.allocPrint(arena, "{{\"session_id\":{d},\"data_b64\":\"aGVsbG8=\",\"eof\":true}}", .{sid});
    try runTool(arena, io, &cfg, toolExecWrite, args, &out);
    const write = try parseArgs(arena, out.items);
    try std.testing.expect(getBool(write, "ok"));
    try std.testing.expectEqual(@as(i64, 5), getInt(write, "bytes"));
    try std.testing.expect(getBool(write, "eof"));

    // exec_wait blocks until the session finishes.
    out = .empty;
    args = try std.fmt.allocPrint(arena, "{{\"session_id\":{d},\"timeout\":5}}", .{sid});
    try runTool(arena, io, &cfg, toolExecWait, args, &out);
    const wait = try parseArgs(arena, out.items);
    try std.testing.expect(getBool(wait, "ok"));
    try std.testing.expect(getBool(wait, "done"));
    try std.testing.expectEqual(@as(i64, 0), getInt(wait, "exit_code"));
    try std.testing.expectEqualStrings("hello", getStr(wait, "stdout"));
    try std.testing.expectEqual(@as(i64, 5), getInt(wait, "stdout_offset"));

    // exec_poll replays deltas from the requested byte offset.
    out = .empty;
    args = try std.fmt.allocPrint(arena, "{{\"session_id\":{d},\"stdout_offset\":0}}", .{sid});
    try runTool(arena, io, &cfg, toolExecPoll, args, &out);
    var poll = try parseArgs(arena, out.items);
    try std.testing.expect(getBool(poll, "done"));
    try std.testing.expectEqualStrings("hello", getStr(poll, "stdout"));
    try std.testing.expectEqual(@as(i64, 5), getInt(poll, "stdout_offset"));

    out = .empty;
    args = try std.fmt.allocPrint(arena, "{{\"session_id\":{d},\"stdout_offset\":3}}", .{sid});
    try runTool(arena, io, &cfg, toolExecPoll, args, &out);
    poll = try parseArgs(arena, out.items);
    try std.testing.expectEqualStrings("lo", getStr(poll, "stdout"));
    try std.testing.expectEqual(@as(i64, 5), getInt(poll, "stdout_offset"));

    // exec_close frees the session; the second close is idempotent and a
    // later poll reports the session as unknown.
    out = .empty;
    args = try std.fmt.allocPrint(arena, "{{\"session_id\":{d}}}", .{sid});
    try runTool(arena, io, &cfg, toolExecClose, args, &out);
    const first_close = try parseArgs(arena, out.items);
    try std.testing.expect(getBool(first_close, "ok"));
    try std.testing.expect(first_close.object.get("already_closed") == null);

    out = .empty;
    try runTool(arena, io, &cfg, toolExecClose, args, &out);
    const second_close = try parseArgs(arena, out.items);
    try std.testing.expect(getBool(second_close, "ok"));
    try std.testing.expect(getBool(second_close, "already_closed"));

    out = .empty;
    try std.testing.expectError(error.UnknownSession, runTool(arena, io, &cfg, toolExecPoll, args, &out));
}

test "exec close kills a running session and frees it" {
    if (builtin.os.tag != .linux) return error.SkipZigTest; // CI runs unit tests on Linux only
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const saved = env_state.process_environ;
    defer env_state.process_environ = saved;
    const slice = try arena.allocSentinel(?[*:0]const u8, 2, null);
    slice[0] = "PATH=/usr/bin:/bin";
    slice[1] = "HOME=/envhome/tester";
    env_state.process_environ = .{ .block = .{ .slice = slice } };
    var threaded = Io.Threaded.init(std.heap.page_allocator, .{ .environ = env_state.process_environ });
    defer threaded.deinit();
    const io = threaded.io();

    var cfg = try testConfig(arena);
    const store = try std.heap.page_allocator.create(session_mod.SessionStore);
    store.* = session_mod.SessionStore.init(io, 8);
    cfg.sessions = store;

    var out: std.ArrayList(u8) = .empty;
    try runTool(arena, io, &cfg, toolExecStart, "{\"argv\":[\"/bin/sleep\",\"30\"]}", &out);
    const start = try parseArgs(arena, out.items);
    try std.testing.expect(getBool(start, "ok"));
    const sid = getInt(start, "session_id");

    // While the process runs, exec_wait times out with done=false and a
    // null exit code.
    out = .empty;
    var args = try std.fmt.allocPrint(arena, "{{\"session_id\":{d},\"timeout\":1}}", .{sid});
    try runTool(arena, io, &cfg, toolExecWait, args, &out);
    const wait = try parseArgs(arena, out.items);
    try std.testing.expect(getBool(wait, "ok"));
    try std.testing.expect(!getBool(wait, "done"));
    try std.testing.expect(wait.object.get("exit_code").? == .null);

    // Closing a live session kills the tree, joins the session threads
    // and frees the state.
    out = .empty;
    args = try std.fmt.allocPrint(arena, "{{\"session_id\":{d}}}", .{sid});
    try runTool(arena, io, &cfg, toolExecClose, args, &out);
    const closed = try parseArgs(arena, out.items);
    try std.testing.expect(getBool(closed, "ok"));

    // Idempotent: the second close reports already_closed, and polling
    // the freed id fails with UnknownSession.
    out = .empty;
    try runTool(arena, io, &cfg, toolExecClose, args, &out);
    const again = try parseArgs(arena, out.items);
    try std.testing.expect(getBool(again, "ok"));
    try std.testing.expect(getBool(again, "already_closed"));
    out = .empty;
    try std.testing.expectError(error.UnknownSession, runTool(arena, io, &cfg, toolExecPoll, args, &out));
}

test "tool argument validation errors" {
    if (builtin.os.tag != .linux) return error.SkipZigTest; // CI runs unit tests on Linux only
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var threaded = Io.Threaded.init(std.heap.page_allocator, .{ .environ = env_state.process_environ });
    defer threaded.deinit();
    const io = threaded.io();
    var cfg = try testConfig(arena);

    var out: std.ArrayList(u8) = .empty;
    // argv validation: missing, wrong type, empty, non-string element.
    try std.testing.expectError(error.MissingArgv, runTool(arena, io, &cfg, toolExec, "{}", &out));
    try std.testing.expectError(error.BadArgv, runTool(arena, io, &cfg, toolExec, "{\"argv\":\"not-an-array\"}", &out));
    try std.testing.expectError(error.BadArgv, runTool(arena, io, &cfg, toolExec, "{\"argv\":[]}", &out));
    try std.testing.expectError(error.BadArgv, runTool(arena, io, &cfg, toolExec, "{\"argv\":[7]}", &out));
    try std.testing.expectError(error.MissingScript, runTool(arena, io, &cfg, toolExecShell, "{}", &out));

    // Session tools require a configured store.
    try std.testing.expectError(error.SessionsDisabled, runTool(arena, io, &cfg, toolExecStart, "{\"argv\":[\"/bin/cat\"]}", &out));
    try std.testing.expectError(error.SessionsDisabled, runTool(arena, io, &cfg, toolExecPoll, "{\"session_id\":1}", &out));

    // With a store: malformed and unknown session ids.
    const store = try std.heap.page_allocator.create(session_mod.SessionStore);
    store.* = session_mod.SessionStore.init(io, 8);
    cfg.sessions = store;
    try std.testing.expectError(error.BadSession, runTool(arena, io, &cfg, toolExecPoll, "{\"session_id\":0}", &out));
    try std.testing.expectError(error.BadSession, runTool(arena, io, &cfg, toolExecPoll, "{\"session_id\":-2}", &out));
    try std.testing.expectError(error.UnknownSession, runTool(arena, io, &cfg, toolExecPoll, "{\"session_id\":424242}", &out));

    // exec_write validates the protocol types before resolving the session.
    try std.testing.expectError(error.InvalidParams, runTool(arena, io, &cfg, toolExecWrite, "{\"session_id\":1,\"data_b64\":7}", &out));

    // File tools require their payload arguments.
    try std.testing.expectError(error.MissingPath, runTool(arena, io, &cfg, toolReadFile, "{}", &out));
    try std.testing.expectError(error.MissingPath, runTool(arena, io, &cfg, toolWriteFile, "{}", &out));
    try std.testing.expectError(error.MissingContent, runTool(arena, io, &cfg, toolWriteFile, "{\"path\":\"unused.txt\"}", &out));
}
