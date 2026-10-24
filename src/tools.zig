//! The 14 MCP tool implementations (exec, exec_start, exec_poll,
//! exec_write, exec_kill, exec_close, exec_wait, exec_list, exec_shell,
//! sys_info, read_file, write_file, list_dir, copy_path) plus their private
//! helpers: session resolution from tool arguments, `~` path expansion,
//! and the tool-scoped limits. Routing by tool name (dispatchTool)
//! lives in rpc.zig.

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
const policy = @import("policy.zig");
const output_shape = @import("output_shape.zig");

const LIST_DIR_MAX_ENTRIES: usize = 2000;
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
//     exec_start) — diagnostic only.
//   * the owned-child registry (proc.zig: registerSpawnPid/
//     unregisterSpawnPid/compactSpawnPidRegistry/sweepStraysWithRegistry)
//     is the protected set: every child with a live owner is registered
//     from spawn until the owner's reap is confirmed — session children by
//     the session waiter, synchronous exec children around runCollected.
//     Because the set is complete at all times, the exit sweep runs on
//     EVERY exec-family exit, not only at global quiescence: the registry
//     stays bounded by live concurrency instead of total history, and
//     failed-spawn strays are reaped without waiting for all calls to
//     become idle. Removal matches (pid, tag) so a recycled pid can never
//     delete a new owner's registration.

var exec_gate: std.Io.Mutex = .init;
var exec_inflight: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);
/// Set (under exec_gate) whenever a fork actually failed. The failed child
/// writes the exec error to the pipe BEFORE _exit, so the parent can observe
/// the error while the child is still dying; the exit sweep settles briefly
/// to let it land before reaping.
var spawn_error_pending: bool = false;

fn execCallEnter(io: Io) void {
    exec_gate.lockUncancelable(io);
    _ = exec_inflight.fetchAdd(1, .acq_rel);
    exec_gate.unlock(io);
}

/// Exit half of the exec-family gate: every exit sweeps. The owned-child
/// registry is complete at all times (sessions register at spawn, sync
/// execs register around runCollected), so the sweep needs no global
/// quiescence: it reaps only children nobody owns.
/// Runs as a defer, i.e. after the tool's own resource errdefers.
fn execCallExit(io: Io) void {
    exec_gate.lockUncancelable(io);
    defer exec_gate.unlock(io);
    _ = exec_inflight.fetchSub(1, .acq_rel);
    if (comptime builtin.os.tag == .windows) return;
    if (spawn_error_pending) {
        spawn_error_pending = false;
        // The failed child reports the exec error through the pipe before
        // _exit; give it a moment to land so this sweep reaps it now instead
        // of on the next exec call's exit.
        os.sleepMs(2);
    }
    // Compaction first (drops entries whose owner's reap already consumed
    // the zombie), then the stray sweep with the registry as the protected
    // set.
    proc.compactSpawnPidRegistry(io);
    _ = proc.sweepStraysWithRegistry(io);
}

/// Pre-flight the spawn POSIX-side. Windows needs no pre-flight: spawn
/// failure there never leaves a half-forked child (CreateProcess is atomic).
fn preflightSpawn(arena: Allocator, io: Io, argv0: []const u8, cwd: []const u8) !void {
    if (comptime builtin.os.tag == .windows) return;
    const path_env = os.env.environGet(arena, env_state.process_environ, "PATH");
    return proc.preflightExec(arena, io, argv0, cwd, path_env);
}

/// Shared run-and-reply core of `exec` and `exec_shell`: timeout
/// normalization, the exec-family spawn gate, pre-flight, spawn, exit-code
/// normalization and the structured reply. The public tools are thin
/// wrappers: toolExec lifts argv/cwd/timeout out of the RPC arguments,
/// toolExecShell synthesizes the shell argv directly — no JSON round-trip.
/// Policy stays one layer up (policy.zig checkExecArgs gates the raw RPC
/// arguments by tool name before dispatch), so this core is policy-free:
/// both entry points reach it only after the same gate. Under an ACTIVE
/// policy the gate additionally leaves an ExecPin on this thread, and the
/// pinned branch below spawns through the pinned kernel objects instead
/// of the raw strings.
fn runExec(arena: Allocator, io: Io, cfg: *const config.Config, argv: []const []const u8, cwd: []const u8, timeout_s: i64, shape: ?output_shape.Shape, out: *std.ArrayList(u8)) !void {
    var shaped_streams: [2]output_shape.Stream = undefined;
    if (shape) |spec| {
        shaped_streams[0] = try output_shape.Stream.init(arena, spec);
        errdefer shaped_streams[0].deinit(arena);
        shaped_streams[1] = try output_shape.Stream.init(arena, spec);
    }
    defer if (shape != null) {
        for (&shaped_streams) |*stream| stream.deinit(arena);
    };
    const streams: ?*[2]output_shape.Stream = if (shape != null) &shaped_streams else null;
    const timeout: i64 = @min(@max(timeout_s, 1), EXEC_MAX_TIMEOUT_S);
    // Failed-spawn hygiene: enter the exec-family gate and pre-flight the
    // spawn so the common failures never fork at all (os/proc.zig explains
    // why both layers exist).
    execCallEnter(io);
    defer execCallExit(io);
    const started = std.Io.Clock.awake.now(io);
    // Pinned spawn under an active (non-allow_all) policy — the
    // ExecPin was emitted by checkExecArgs and published by the rpc layer
    // (policy.currentExecPin). POSIX pins cwd/exe to descriptors and
    // fchdir+execveat's them; Windows pins them as share-mode handles and
    // verifies the suspended child's image before it runs.
    if (comptime builtin.os.tag != .windows) {
        if (policy.currentExecPin()) |epin| {
            return runExecPinned(arena, io, cfg, argv, epin, timeout, started, streams, out);
        }
    }
    if (comptime builtin.os.tag == .windows) {
        if (policy.currentExecPin()) |epin| {
            return runExecPinnedWindows(arena, io, cfg, argv, epin, timeout, started, streams, out);
        }
    }
    try preflightSpawn(arena, io, argv[0], cwd);
    // The unpinned branch must not go through std.process.run: its final
    // child.wait parks forever when the child closed its output fds and
    // lives on (EOF is immediate; the timeout never reached the wait). Now
    // EVERY synchronous branch spawns explicitly (identical std spawn
    // semantics: ignore-stdin, output pipes, CREATE_NO_WINDOW on Windows)
    // and collects through proc.runCollected — one monotonic deadline over
    // output + exit wait, kill/reap on expiry. The pinned branch above
    // reaches the same collect through its spawnPinned child.
    // POSIX: hold exec_gate across spawn+registration so no sweep can ever
    // observe this child before it is protected (the same section shape
    // exec_start uses). The registration rides until runCollected's wait
    // confirms the reap, and the defer below removes it on every path.
    var reg_tag: u64 = 0;
    var registered = false;
    var reg_pid: proc.ProcessId = 0;
    if (comptime builtin.os.tag != .windows) exec_gate.lockUncancelable(io);
    var child = std.process.spawn(io, .{
        .argv = argv,
        .cwd = if (cwd.len == 0) .inherit else .{ .path = cwd },
        .stdin = .ignore, // same as std.process.run
        .stdout = .pipe,
        .stderr = .pipe,
        .create_no_window = true, // same as std.process.run's default
    }) catch |err| {
        // A real spawn-side failure (the pre-flight already rejected the
        // no-fork cases): a forked child is dying somewhere — mark it so
        // the exit sweep settles before reaping.
        if (comptime builtin.os.tag != .windows) {
            spawn_error_pending = true;
            exec_gate.unlock(io);
        }
        return err;
    };
    if (comptime builtin.os.tag != .windows) {
        // Registration is FATAL (same rule as exec_start): an unregistered
        // child is unprotected — a concurrent sweep would steal its wait.
        // Kill and reap inline, then fail the call. The pid is captured at
        // registration: runCollected consumes child.id (kill sets it null),
        // so the unregister key must not be re-derived from the Child.
        if (proc.registerSpawnPid(io, child.id.?)) |tag| {
            reg_tag = tag;
            reg_pid = session_mod.childPidOrZero(child.id);
            registered = true;
            exec_gate.unlock(io);
        } else {
            proc.killTree(session_mod.childPidOrZero(child.id), proc.no_job);
            _ = child.wait(io) catch null;
            exec_gate.unlock(io);
            return error.ExecPidRegistrationFailed;
        }
    }
    // The registration rides until runCollected's wait confirms the reap;
    // this defer removes it on every path.
    defer if (registered) proc.unregisterSpawnPid(io, reg_pid, reg_tag);
    if (streams) |ss| return collectShapedReply(arena, io, &child, ss, timeout, started, out);
    const result = proc.runCollected(arena, io, &child, .{
        .stdout_limit = .limited(cfg.max_out),
        .stderr_limit = .limited(cfg.max_out),
        .timeout = .{ .duration = .{ .clock = .awake, .raw = std.Io.Duration.fromSeconds(timeout) } },
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
            // Same marking as the spawn side: a collection/wait failure
            // leaves the child dying through the deferred kill — the
            // sweep settles it before reaping.
            exec_gate.lockUncancelable(io);
            spawn_error_pending = true;
            exec_gate.unlock(io);
            return err;
        },
    };
    try appendExecReply(arena, io, out, result, started);
}

/// Pinned-exec branch of runExec (POSIX): pin the authorized cwd and
/// executable to kernel descriptors, fork with fchdir(pinned_cwd) +
/// execveat(pinned_exe) (os/proc.zig spawnPinned), and run the child with
/// std.process.run semantics (os/proc.zig runCollected: MultiReader, limits,
/// timeout). A pin-open refusal (swapped ancestor, vanished object)
/// PROPAGATES as an error — never a fallback to the raw-string spawn.
fn runExecPinned(
    arena: Allocator,
    io: Io,
    cfg: *const config.Config,
    argv: []const []const u8,
    epin: policy.ExecPin,
    timeout: i64,
    started: std.Io.Timestamp,
    streams: ?*[2]output_shape.Stream,
    out: *std.ArrayList(u8),
) !void {
    if (comptime builtin.os.tag == .windows) @compileError("runExecPinned is POSIX-only");
    const fds = try openExecPinFds(arena, io, epin);
    defer closeExecPinFds(fds);
    // Same gate + registration section as the unpinned branch: no sweep may
    // observe this child before it is protected. spawnPinned reaps its own
    // failures synchronously, so the error path needs no stray marking.
    var reg_tag: u64 = 0;
    var registered = false;
    var reg_pid: proc.ProcessId = 0;
    exec_gate.lockUncancelable(io);
    var child = proc.spawnPinned(arena, io, .{
        .exe_fd = fds.exe,
        .cwd_fd = fds.cwd,
        .argv = argv,
        .envp = posixEnvBlock(),
        .stdin_fd = null, // /dev/null, same as std.process.run
        .pgid = false, // same group as std.process.run
    }) catch |err| {
        exec_gate.unlock(io);
        return err;
    };
    if (proc.registerSpawnPid(io, child.id.?)) |tag| {
        reg_tag = tag;
        reg_pid = session_mod.childPidOrZero(child.id);
        registered = true;
        exec_gate.unlock(io);
    } else {
        proc.killTree(session_mod.childPidOrZero(child.id), proc.no_job);
        _ = child.wait(io) catch null;
        exec_gate.unlock(io);
        return error.ExecPidRegistrationFailed;
    }
    // Registration removal rides with the collect's reap (defer); the key
    // is the captured pid, not the post-collect Child.
    defer if (registered) proc.unregisterSpawnPid(io, reg_pid, reg_tag);
    if (streams) |ss| return collectShapedReply(arena, io, &child, ss, timeout, started, out);
    const result = proc.runCollected(arena, io, &child, .{
        .stdout_limit = .limited(cfg.max_out),
        .stderr_limit = .limited(cfg.max_out),
        .timeout = .{ .duration = .{ .clock = .awake, .raw = std.Io.Duration.fromSeconds(timeout) } },
    }) catch |err| switch (err) {
        error.Timeout => {
            out.clearRetainingCapacity();
            try out.appendSlice(arena, "{\"ok\":false,\"timeout\":true,\"error\":\"CommandTimeout\"}");
            return;
        },
        error.StreamTooLong => return error.OutputTooLong,
        else => return err,
    };
    try appendExecReply(arena, io, out, result, started);
}

/// The kernel objects of one exec pin. POSIX-only (Windows never pins).
const ExecFds = struct {
    exe: std.posix.fd_t,
    cwd: ?std.posix.fd_t,
};

/// Open the exec pin's objects (authorized cwd dir + executable fd; the
/// bare-name form resolves through PATH in execvp order and pins the
/// winning candidate). Called only from comptime POSIX call sites.
fn openExecPinFds(arena: Allocator, io: Io, epin: policy.ExecPin) !ExecFds {
    var fds: ExecFds = .{ .exe = undefined, .cwd = null };
    if (epin.cwd_canon.len != 0) {
        fds.cwd = try os.secure.openPinnedDir(io, epin.cwd_canon);
    }
    errdefer if (fds.cwd) |fd| os.closeFd(fd);
    fds.exe = if (epin.argv0_canon.len != 0)
        try os.secure.openPinnedExe(io, epin.argv0_canon)
    else blk: {
        const path_env = os.env.environGet(arena, env_state.process_environ, "PATH");
        break :blk try proc.resolvePinnedArgv0(arena, io, epin.argv0, epin.cwd_canon, path_env);
    };
    return fds;
}

fn closeExecPinFds(fds: ExecFds) void {
    os.closeFd(fds.exe);
    if (fds.cwd) |fd| os.closeFd(fd);
}

// ---------------------------------------------------------------------------
// Windows exec pins. The data layout compiles
// on every platform (plain fd_t/[]const u8); every function that TOUCHES
// kernel32 below is Windows-only and referenced only from comptime-gated
// call sites, so POSIX builds never analyze those bodies.
// ---------------------------------------------------------------------------

/// The Windows objects of one exec pin: the share-mode handle on the
/// authorized exe, the canonical path of that pinned object (the image
/// verification unit — for a bare argv0 it is the PATH-resolved
/// candidate's own path, not the gate's string), and the optional
/// share-mode handle on the authorized cwd.
const WindowsExecPins = struct {
    exe: std.posix.fd_t,
    exe_path: []const u8,
    cwd: ?std.posix.fd_t,
};

/// SpawnOptions.cwd for a pinned Windows spawn: the pinned cwd handle
/// (std derives the lpCurrentDirectory string from THAT handle's final
/// path, which the pin verified equals the canon), or inherit when the
/// gate authorized no explicit cwd. Unpinned spawns keep the raw string.
fn winSpawnCwd(pins: ?WindowsExecPins, raw_cwd: []const u8) std.process.Child.Cwd {
    if (pins) |p| {
        if (p.cwd) |h| return .{ .dir = .{ .handle = h } };
        return .inherit;
    }
    return if (raw_cwd.len == 0) .inherit else .{ .path = raw_cwd };
}

/// Open the Windows exec pin's objects (fail-closed: any refusal
/// propagates and the exec never spawns). Mirrors openExecPinFds: the
/// cwd pins first, then the exe (canon form directly; bare argv0 via the
/// PATH walk, mirroring std's search order). Windows-only.
fn openExecPinsWindows(arena: Allocator, io: Io, epin: policy.ExecPin) !WindowsExecPins {
    if (comptime builtin.os.tag != .windows) @compileError("openExecPinsWindows is Windows-only");
    var pins: WindowsExecPins = .{ .exe = undefined, .exe_path = "", .cwd = null };
    if (epin.cwd_canon.len != 0) {
        pins.cwd = try os.secure.openPinnedCwdWindows(epin.cwd_canon);
    }
    errdefer if (pins.cwd) |h| os.closeFd(h);
    if (epin.argv0_canon.len != 0) {
        pins.exe = try os.secure.openPinnedExeWindows(epin.argv0_canon);
        // Verified inside the pin open: the handle's final path IS the
        // canon, so the canon doubles as the image verification unit.
        pins.exe_path = epin.argv0_canon;
    } else {
        // Bare argv0: resolve through PATH like execvp/CreateProcess and
        // pin the winning candidate; its readback path (verifier-prefixed
        // `\\?\...`, kept verbatim) is the verification unit — the
        // comparator normalizes the verifier prefix on both operands. The
        // effective child cwd anchors the search (std's order: child cwd
        // first, then PATH entries), falling
        // back to the daemon cwd.
        const path_env = os.env.environGet(arena, env_state.process_environ, "PATH");
        const daemon_cwd = std.process.currentPathAlloc(io, arena) catch "";
        const base = if (epin.cwd_canon.len != 0) epin.cwd_canon else daemon_cwd;
        const cand = try os.secure.resolvePinnedArgv0Windows(arena, epin.argv0, base, daemon_cwd, path_env);
        pins.exe = cand.handle;
        pins.exe_path = cand.path;
    }
    return pins;
}

fn closeExecPinsWindows(pins: WindowsExecPins) void {
    os.closeFd(pins.exe);
    if (pins.cwd) |h| os.closeFd(h);
}

/// Pinned-exec branch of runExec (Windows): open the share-mode pins
/// (fail-closed — never a fallback to the raw-string spawn), spawn
/// CREATE_SUSPENDED with the ORIGINAL argv (the command line the child
/// parses is exactly what the caller sent; std resolves the image from
/// argv[0] while the pins block renames), verify the suspended process's
/// image IS the pinned object (mismatch = terminate before a single
/// instruction runs), resume, and collect the output with std.process.run
/// semantics (proc.runCollected: MultiReader, limits, timeout, kill-on-exit).
fn runExecPinnedWindows(
    arena: Allocator,
    io: Io,
    cfg: *const config.Config,
    argv: []const []const u8,
    epin: policy.ExecPin,
    timeout: i64,
    started: std.Io.Timestamp,
    streams: ?*[2]output_shape.Stream,
    out: *std.ArrayList(u8),
) !void {
    if (comptime builtin.os.tag != .windows) @compileError("runExecPinnedWindows is Windows-only");
    const pins = try openExecPinsWindows(arena, io, epin);
    defer closeExecPinsWindows(pins);
    var child = try std.process.spawn(io, .{
        .argv = argv, // raw argv preserved (the child's argv[0] is verbatim)
        .cwd = winSpawnCwd(pins, ""),
        .stdin = .ignore, // same as std.process.run
        .stdout = .pipe,
        .stderr = .pipe,
        .create_no_window = true, // same as std.process.run's default
        .start_suspended = true, // verify the image before it runs
    });
    // Handle-bound creation check: while suspended, the process image
    // must BE the pinned object. A reparse planted after the pin made
    // CreateProcess resolve a different image — terminate and refuse
    // before any thread of the child executes an instruction.
    if (!proc.processImageNameMatches(child.id.?, pins.exe_path)) {
        proc.terminateHandle(child.id.?);
        _ = child.wait(io) catch null;
        return error.ExecPinMismatch;
    }
    proc.resumeProcess(child.id.?) catch |err| {
        proc.terminateHandle(child.id.?);
        _ = child.wait(io) catch null;
        return err;
    };
    if (streams) |ss| return collectShapedReply(arena, io, &child, ss, timeout, started, out);
    const result = proc.runCollected(arena, io, &child, .{
        .stdout_limit = .limited(cfg.max_out),
        .stderr_limit = .limited(cfg.max_out),
        .timeout = .{ .duration = .{ .clock = .awake, .raw = std.Io.Duration.fromSeconds(timeout) } },
    }) catch |err| switch (err) {
        error.Timeout => {
            out.clearRetainingCapacity();
            try out.appendSlice(arena, "{\"ok\":false,\"timeout\":true,\"error\":\"CommandTimeout\"}");
            return;
        },
        error.StreamTooLong => return error.OutputTooLong,
        else => return err,
    };
    try appendExecReply(arena, io, out, result, started);
}

/// The daemon's environment snapshot in execve's posix-block shape
/// (POSIX-only body; referenced only from comptime-gated call sites).
fn posixEnvBlock() [:null]const ?[*:0]const u8 {
    if (comptime builtin.os.tag == .windows) @compileError("posixEnvBlock is POSIX-only");
    return env_state.process_environ.block.slice;
}

/// Structured reply shared by the raw and the pinned run paths: exit-code
/// normalization (incl. the Windows NTSTATUS reinterpretation), lossy
/// UTF-8 decoding, duration in both resolutions.
fn appendExecReply(arena: Allocator, io: Io, out: *std.ArrayList(u8), result: std.process.RunResult, started: std.Io.Timestamp) !void {
    const elapsed = started.untilNow(io, .awake);
    const exit_code: i32 = switch (result.term) {
        .exited => |code| code,
        .signal => |sig| 128 + @as(i32, @intCast(@intFromEnum(sig))),
        .stopped => |sig| 128 + @as(i32, @intCast(@intFromEnum(sig))),
        // Windows fills this with raw NTSTATUS values (0xC0000005 ...)
        // whose high bit would panic @intCast in ReleaseSafe. The bit
        // pattern IS the honest exit code the platform reports, so it is
        // reinterpreted, not clamped: clamping would forge a fake
        // 0x7fffffff "success-ish" code for every fatal NTSTATUS
        // value.
        .unknown => |code| @as(i32, @bitCast(code)),
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

fn collectShapedReply(arena: Allocator, io: Io, child: *std.process.Child, streams: *[2]output_shape.Stream, timeout: i64, started: Io.Timestamp, out: *std.ArrayList(u8)) !void {
    const result = try proc.runCollectedShaped(io, child, streams, .{ .duration = .{ .clock = .awake, .raw = Io.Duration.fromSeconds(timeout) } });
    const stdout = streams[0].finish();
    const stderr = streams[1].finish();
    if (result.term) |term| {
        try appendExecReply(arena, io, out, .{ .term = term, .stdout = @constCast(stdout), .stderr = @constCast(stderr) }, started);
        out.items.len -= 1;
    } else {
        try out.appendSlice(arena, "{\"ok\":false,\"exit_code\":null,\"error\":");
        try util.appendJsonString(out, arena, result.failure.?);
        if (std.mem.eql(u8, result.failure.?, "CommandTimeout")) try out.appendSlice(arena, ",\"timeout\":true");
        try out.appendSlice(arena, ",\"stdout\":");
        try util.appendJsonString(out, arena, try util.utf8LossyAlloc(arena, stdout));
        try out.appendSlice(arena, ",\"stderr\":");
        try util.appendJsonString(out, arena, try util.utf8LossyAlloc(arena, stderr));
        const elapsed = started.untilNow(io, .awake);
        try out.print(arena, ",\"duration_ms\":{d},\"duration_us\":{d}", .{ elapsed.toMilliseconds(), elapsed.toMicroseconds() });
    }
    try appendShapeCounters(arena, out, .{ streams[0].total, streams[1].total }, .{ stdout.len, stderr.len }, result.term != null);
    try out.appendSlice(arena, "}");
}

pub fn appendShapeCounters(arena: Allocator, out: *std.ArrayList(u8), totals: [2]u64, returned: [2]usize, complete: bool) !void {
    const omitted = [2]u64{ totals[0] - returned[0], totals[1] - returned[1] };
    try out.print(arena, ",\"truncated\":{},\"output_complete\":{}", .{ omitted[0] != 0 or omitted[1] != 0, complete });
    inline for (.{ "stdout", "stderr" }, 0..) |name, i| {
        try out.print(arena, ",\"truncated_" ++ name ++ "\":{},\"total_" ++ name ++ "_bytes\":{d},\"returned_" ++ name ++ "_bytes\":{d},\"omitted_" ++ name ++ "_bytes\":{d}", .{ omitted[i] != 0, totals[i], returned[i], omitted[i] });
    }
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
    const timeout_s = (try util.optIntArg(args, "timeout")) orelse EXEC_DEFAULT_TIMEOUT_S;
    return runExec(arena, io, cfg, argv, cwd, timeout_s, try output_shape.parse(args, cfg.max_out), out);
}

pub fn toolExecShell(arena: Allocator, io: Io, cfg: *const config.Config, args: Value, out: *std.ArrayList(u8)) !void {
    const script = (try util.optStrArg(args, "script")) orelse return error.MissingScript;
    const default_shell: []const u8 = if (comptime builtin.os.tag == .windows) "cmd" else "bash";
    const shell = (try util.optStrArg(args, "shell")) orelse default_shell;
    // Comptime platform allowlist: POSIX shells on POSIX, cmd/powershell on
    // Windows (mirrored in TOOLS_JSON prose).
    if (!policy.supportedShell(shell)) return error.UnsupportedShell;
    const cwd = (try util.optStrArg(args, "cwd")) orelse "";
    const timeout_s = (try util.optIntArg(args, "timeout")) orelse EXEC_DEFAULT_TIMEOUT_S;
    // cmd takes /c; every other supported shell (incl. powershell) takes -c.
    // Same argv the old JSON round-trip produced, built directly now.
    const script_flag: []const u8 = if (std.mem.eql(u8, shell, "cmd")) "/c" else "-c";
    const argv = [_][]const u8{ shell, script_flag, script };
    return runExec(arena, io, cfg, &argv, cwd, timeout_s, try output_shape.parse(args, cfg.max_out), out);
}

/// Resolve session_id to a live Session with +1 ref. Caller MUST balance
/// with `defer session_mod.sessionRelease(session)` — the store ref alone does not
/// protect against concurrent exec_close freeing the session.
fn sessionFromArgs(cfg: *const config.Config, args: Value) !*session_mod.Session {
    const store = cfg.sessions orelse return error.SessionsDisabled;
    const id_i = (try util.optIntArg(args, "session_id")) orelse return error.MissingSession;
    if (id_i <= 0) return error.BadSession;
    const session = store.get(@as(u64, @intCast(id_i))) orelse return error.UnknownSession;
    // The get above took +1. On the ownership refusal below the caller's
    // balancing `defer sessionRelease` never installs (it sits after this
    // helper returns), so the borrowed ref MUST drop here — otherwise every
    // cross-token probe pins the session forever, and the owner's
    // exec_close can never free it.
    errdefer session_mod.sessionRelease(session);
    // Argument gating: with a policy active, a token may only address
    // sessions it started. Zeroes-vs-zeroes passes without a
    // policy, so v0.3.1 behaviour is unchanged.
    if (session.durable != null) {
        if (!std.crypto.timing_safe.eql([32]u8, session.owner_hash, policy.current_owner)) return error.UnknownSession;
    } else if (!policy.sessionOwned(session.owner_hash)) return error.SessionNotOwned;
    return session;
}

/// Durability contract reply for a session id that is not live on this
/// node: a structured tool result (ok:false), never a bare JSON-RPC
/// -32602. Carries the caller's session_id and, when this node process
/// previously held and removed the session (TTL reap, exec_close, or
/// overflow eviction), expired=true — a cheap "it was here, it is gone"
/// signal distinguishing a reaped id from one this node never had (or one
/// from before a node restart, which is indistinguishable from "never
/// existed" and said so honestly in the message).
fn replyUnknownSession(arena: Allocator, cfg: *const config.Config, args: Value, out: *std.ArrayList(u8)) !void {
    const store = cfg.sessions orelse return error.SessionsDisabled;
    // sessionFromArgs already validated presence/type/positivity of
    // session_id before failing, so this re-read cannot miss.
    const id_i = (try util.optIntArg(args, "session_id")) orelse return error.MissingSession;
    const expired = store.sawOwnedSession(@as(u64, @intCast(id_i)), policy.current_owner);
    // Best-effort recency: expired=true only for ids removed within the
    // store's bounded tombstone window; an id the node did hold but long
    // ago (or before a node restart) answers expired=false, and the
    // message must not overclaim which case it is.
    const hint: []const u8 = if (expired)
        "session was closed, reaped after the TTL, or evicted on this node; exec_list shows live sessions"
    else
        "no recently-live session with this id on this node (never started here, removed long ago, or the node restarted); exec_list shows live sessions";
    try out.appendSlice(arena, "{\"ok\":false,\"error\":\"unknown_session\",\"session_id\":");
    try out.print(arena, "{d}", .{id_i});
    try out.appendSlice(arena, ",\"expired\":");
    try out.appendSlice(arena, if (expired) "true" else "false");
    try out.appendSlice(arena, ",\"message\":");
    try util.appendJsonString(out, arena, hint);
    try out.appendSlice(arena, "}");
}

/// sessionFromArgs + unknown_session reply in one step for the session
/// tools whose contract answers unknown ids with the structured payload
/// instead of a thrown error (exec_close keeps its frozen already_closed
/// idempotency and does not use this).
fn sessionOrUnknownReply(arena: Allocator, cfg: *const config.Config, args: Value, out: *std.ArrayList(u8)) !?*session_mod.Session {
    return sessionFromArgs(cfg, args) catch |err| switch (err) {
        error.UnknownSession => {
            try replyUnknownSession(arena, cfg, args, out);
            return null;
        },
        else => return err,
    };
}

/// Spawn a session process (piped stdio, own process group) and publish it.
/// Ownership: argv/cwd/stdin_fd transfer to the Session on success; on any
/// error path the errdefers free them exactly once. The child is always
/// reaped — either by the session waiter thread or by the error path.
pub fn toolExecStart(arena: Allocator, io: Io, cfg: *const config.Config, args: Value, out: *std.ArrayList(u8)) !void {
    const store = cfg.sessions orelse return error.SessionsDisabled;
    const durable_requested = (try util.optBoolArg(args, "durable")) orelse false;
    if (durable_requested) {
        if (store.disk == null) return error.DurabilityDisabled;
        return toolExecStartDurable(arena, io, cfg, args, out);
    }
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
    // Under an active policy the pre-flight is the PIN OPEN
    // (openExecPinFds / openExecPinsWindows below, fail-closed) — the
    // raw-string preflight is only the unpinned path's zombie-hygiene
    // guard and would stat the un-authorized strings, so it is skipped
    // whenever a pin carries the spawn.
    if (comptime builtin.os.tag != .windows) {
        if (policy.currentExecPin() == null) {
            try preflightSpawn(arena, io, argv[0], cwd);
        }
    }

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

    // Reader wake plumbing (see sessionRequestClose / sessionReaderMain):
    // POSIX self-pipe, Windows manual-reset event. Owned by the session
    // once created (freeSession closes it after all threads joined); until
    // then these errdefers guard it. Creation failure degrades to the
    // poll-tick / EOF wake path — latency only, never correctness.
    const wake_pair: if (is_windows) void else ?[2]std.posix.fd_t =
        if (is_windows) {} else proc.createWakePipe();
    var wake_pair_owned: if (is_windows) void else bool = if (is_windows) {} else wake_pair != null;
    errdefer if (!is_windows) {
        if (wake_pair_owned) {
            if (wake_pair) |p| {
                os.closeFd(p[0]);
                os.closeFd(p[1]);
            }
        }
    };
    const wake_event: if (is_windows) ?std.posix.fd_t else void =
        if (is_windows) proc.createWakeEvent() else {};
    var wake_event_owned: if (is_windows) bool else void = if (is_windows) wake_event != null else {};
    errdefer if (is_windows) {
        if (wake_event_owned) os.closeFd(wake_event.?);
    };

    // Fork + publish under the exec gate: a concurrent stray sweep (which
    // holds the same gate) can never observe this child before its pid is
    // registered as protected. On spawn error there is no pid to register —
    // the forked child is an unowned stray, and the exit sweep reaps it.
    //
    // Under an active policy the fork runs through the PINNED
    // objects instead of std's execvpe: the ExecPin (authorized cwd canon
    // + argv0 binding) is opened to kernel descriptors BEFORE the gate
    // (os/secure.zig confinement + readback), and spawnPinned's child does
    // fchdir(pinned_cwd) + execveat(pinned_exe). A pin-open refusal
    // (ancestor swap, vanished object) refuses the START — never a
    // silent fallback to the raw-string spawn. Windows pins the
    // authorized exe and cwd as share-mode handles instead (no fd-exec
    // exists there), and the suspended child's image is verified against
    // the pin before it is resumed.
    var pinned_fds: ?ExecFds = null;
    defer if (pinned_fds) |p| closeExecPinFds(p);
    var win_pins: ?WindowsExecPins = null;
    defer if (win_pins) |p| closeExecPinsWindows(p);
    if (comptime builtin.os.tag != .windows) {
        if (policy.currentExecPin()) |epin| {
            pinned_fds = try openExecPinFds(arena, io, epin);
        }
    } else {
        if (policy.currentExecPin()) |epin| {
            win_pins = try openExecPinsWindows(arena, io, epin);
        }
    }
    exec_gate.lockUncancelable(io);
    var child = if (comptime builtin.os.tag == .windows)
        // Windows: the pin (when a policy is active) freezes the
        // authorized exe and cwd objects for the spawn and the image
        // check below verifies the suspended child before it runs;
        // unpinned spawns keep the raw strings as before.
        std.process.spawn(io, .{
            .argv = argv,
            .cwd = winSpawnCwd(win_pins, cwd),
            .stdin = .pipe,
            .stdout = .pipe,
            .stderr = .pipe,
            .pgid = proc.child_pgid,
            .start_suspended = proc.spawn_suspended,
        }) catch |err| {
            spawn_error_pending = true; // under exec_gate (see the exit sweep)
            exec_gate.unlock(io);
            return err;
        }
    else if (pinned_fds) |p|
        proc.spawnPinned(arena, io, .{
            .exe_fd = p.exe,
            .cwd_fd = p.cwd,
            .argv = argv,
            .envp = posixEnvBlock(),
            .stdin_fd = stdin_pipe.read,
            .pgid = true, // session child: process-group leader
        }) catch |err| {
            // Pinned exec failures are reaped INSIDE spawnPinned (the
            // child-side error report is followed by a synchronous
            // waitpid): no dying stray, no settle-and-sweep needed.
            exec_gate.unlock(io);
            return err;
        }
    else
        std.process.spawn(io, .{
            .argv = argv,
            .cwd = if (cwd.len == 0) .inherit else .{ .path = cwd },
            .stdin = .{ .file = proc.stdinFile(&stdin_pipe) },
            .stdout = .pipe,
            .stderr = .pipe,
            // POSIX: child becomes process-group leader (kill(-pgid) reaches the
            // tree). Windows: null (pid_t is a HANDLE there) — the Job Object
            // takes over the tree role.
            .pgid = proc.child_pgid,
            .start_suspended = proc.spawn_suspended,
        }) catch |err| {
            spawn_error_pending = true; // under exec_gate (see the exit sweep)
            exec_gate.unlock(io);
            return err;
        };
    if (comptime builtin.os.tag == .windows) {
        // Handle-bound creation check: the child is suspended
        // (spawn_suspended) — while it has not run a single instruction,
        // its image must BE the pinned object. A reparse planted after
        // the pin made CreateProcess resolve a different image: kill and
        // reap under the gate (mirrors the pid-registration failure path
        // below), then refuse the start — never a fallback.
        if (win_pins) |p| {
            if (!proc.processImageNameMatches(child.id.?, p.exe_path)) {
                proc.terminateHandle(child.id.?);
                _ = child.wait(io) catch null;
                exec_gate.unlock(io);
                return error.ExecPinMismatch;
            }
        }
    }
    var reg_tag: u64 = 0;
    if (comptime builtin.os.tag != .windows) {
        // Registration is FATAL to the start:
        // an unregistered child is unprotected — the next stray sweep
        // would steal the session waiter's reap (waitid answers ECHILD in
        // std's childWait and the session loses its exit_code). Kill and
        // reap synchronously under the gate, then refuse the start; the
        // already-installed errdefers free the pipe/job resources. The tag
        // makes the waiter's removal exact under pid reuse.
        reg_tag = proc.registerSpawnPid(io, child.id.?) orelse {
            proc.killTree(session_mod.childPidOrZero(child.id), proc.no_job);
            _ = child.wait(io) catch null;
            exec_gate.unlock(io);
            return error.ExecPidRegistrationFailed;
        };
    }
    // Captured at registration: later reaps (creator-side or waiter-side)
    // must not re-derive the key from a post-wait Child.
    const reg_pid: proc.ProcessId = if (builtin.os.tag == .windows) 0 else session_mod.childPidOrZero(child.id);
    exec_gate.unlock(io);
    // Never leak a running child if session allocation fails after spawn.
    // Declared before the stdin takeover: its failure return runs this
    // errdefer too. The registration is removed here — the owner reaps
    // inline, so no waiter will.
    var child_owned = false;
    errdefer {
        if (!child_owned) {
            proc.killTree(session_mod.childPidOrZero(child.id), job);
            _ = child.wait(io) catch null;
            if (comptime builtin.os.tag != .windows)
                proc.unregisterSpawnPid(io, reg_pid, reg_tag);
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
        .id = if (store.disk) |disk| try disk.allocId() else store.allocId(),
        .pid = session_mod.childPidOrZero(child.id),
        .registry_tag = reg_tag,
        .argv = argv,
        .cwd = cwd,
        .child = child,
        .stdin_fd = stdin_fd,
        .job = job,
        .started_us = session_mod.nowUs(io),
        .owner_hash = policy.current_owner,
        // Wake plumbing (created above; the session owns it from here —
        // freeSession closes it once every thread is joined).
        .wake_wfd = if (builtin.os.tag == .windows) null else if (wake_pair) |p| p[1] else null,
        .wake_rfd = if (builtin.os.tag == .windows) null else if (wake_pair) |p| p[0] else null,
        .wake_event = if (builtin.os.tag == .windows) wake_event else null,
    };
    argv_owned = true;
    cwd_owned = true;
    child_owned = true;
    stdin_owned = true;
    job_owned = true;
    if (is_windows) {
        wake_event_owned = false;
    } else {
        wake_pair_owned = false;
    }

    // Creator reference: store.put() publishes the session, after which a
    // concurrent exec_close may drop the store's ref and free the session
    // while this call is still writing the response. Hold our own ref until
    // the response is fully formed.
    _ = session.refs.fetchAdd(1, .acq_rel);
    defer session_mod.sessionRelease(session); // creator ref

    // Spawn threads before publishing: a session visible in the store always
    // has its threads running, so concurrent exec_close can never see null
    // thread handles and skip the join while exec_start keeps writing.
    // Output-end ownership transfer: the fd/handle VALUE goes to the reader
    // thread, and the Child field is nulled right after a successful spawn —
    // std's child.wait cleanup then never closes these ends, making each
    // reader the single owner (sessionReaderMain's defer closes them).
    const out_fd = session.child.stdout.?.handle;
    const err_fd = session.child.stderr.?.handle;
    session.stdout_thread = std.Thread.spawn(.{}, session_mod.sessionReaderMain, .{ session, out_fd, true, cfg.max_out, io }) catch null;
    if (session.stdout_thread != null) session.child.stdout = null;
    session.stderr_thread = std.Thread.spawn(.{}, session_mod.sessionReaderMain, .{ session, err_fd, false, cfg.max_out, io }) catch null;
    if (session.stderr_thread != null) session.child.stderr = null;
    session.waiter_thread = std.Thread.spawn(.{}, session_mod.sessionWaiterMain, .{ session, io }) catch null;
    if (session.stdout_thread == null or session.stderr_thread == null or session.waiter_thread == null) {
        // Readers that spawned keep their pipe ends (they close them
        // themselves on exit); any end whose reader failed to spawn stays
        // child-owned and is closed by the child.wait below. The waiter
        // stop request (closing + wake) makes every join fast.
        session_mod.sessionRequestClose(session);
        session_mod.killTreeGuarded(session, io);
        if (session.waiter_thread) |t| {
            t.join();
        } else {
            _ = session.child.wait(io) catch null;
            // No waiter exists to release the registration: the creator
            // reaped directly, so it unregisters too.
            if (comptime builtin.os.tag != .windows)
                proc.unregisterSpawnPid(io, reg_pid, reg_tag);
        }
        if (session.stdout_thread) |t| t.join();
        if (session.stderr_thread) |t| t.join();
        session_mod.sessionRelease(session); // store-side ref was never published
        return error.SessionThreadFailed;
    }

    store.put(session) catch |err| {
        session_mod.sessionRequestClose(session);
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
    const page = try output_shape.parsePage(args, cfg.max_out);
    const session = (try sessionOrUnknownReply(arena, cfg, args, out)) orelse return;
    defer session_mod.sessionRelease(session);
    const stdout_offset = (try util.optIntArg(args, "stdout_offset")) orelse 0;
    const stderr_offset = (try util.optIntArg(args, "stderr_offset")) orelse 0;
    try session_mod.renderSessionPage(arena, cfg.sessions.?, session, stdout_offset, stderr_offset, page, out);
}

pub fn toolExecWait(arena: Allocator, io: Io, cfg: *const config.Config, args: Value, out: *std.ArrayList(u8)) !void {
    _ = io;
    const page = try output_shape.parsePage(args, cfg.max_out);
    const session = (try sessionOrUnknownReply(arena, cfg, args, out)) orelse return;
    defer session_mod.sessionRelease(session);
    const stdout_offset = (try util.optIntArg(args, "stdout_offset")) orelse 0;
    const stderr_offset = (try util.optIntArg(args, "stderr_offset")) orelse 0;
    var timeout_s = (try util.optIntArg(args, "timeout")) orelse WAIT_DEFAULT_TIMEOUT_S;
    if (timeout_s < 1) timeout_s = 1;
    if (timeout_s > WAIT_MAX_TIMEOUT_S) timeout_s = WAIT_MAX_TIMEOUT_S;
    const store = cfg.sessions.?;
    const deadline = session_mod.nowUs(store.io) + @as(i64, timeout_s) * std.time.us_per_s;
    // Event wait, not a sleep tick: the waiter thread's sessionFinish
    // publishes `done` and sets the level-triggered done_event, so a
    // finished session wakes exec_wait immediately instead of at the next
    // poll boundary — and a session already done before entry returns
    // without ever blocking. The timeout contract is unchanged:
    // waitTimeout receives the remaining wall time; on Timeout (which
    // Event also reports for a spurious wake) the loop re-checks the event
    // and the deadline before giving up, so a spurious wake can neither
    // end the wait early nor spin.
    while (true) {
        try @import("durable_session.zig").refresh(session, store.io);
        if (session.done_event.isSet()) break;
        const now = session_mod.nowUs(store.io);
        if (now >= deadline) break;
        const remaining_ns: i96 = @as(i96, if (session.durable != null) @min(deadline - now, 100_000) else deadline - now) * std.time.ns_per_us;
        session.done_event.waitTimeout(store.io, .{
            .duration = .{ .raw = .{ .nanoseconds = remaining_ns }, .clock = .real },
        }) catch {};
    }
    try session_mod.renderSessionPage(arena, store, session, stdout_offset, stderr_offset, page, out);
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
        // Argument gating: with a policy active a token sees only the
        // sessions it started. Skip, do not error: the listing stays
        // useful (it recovers the caller's own ids) without leaking other
        // tokens' session ids, argv or pids.
        if (s.durable != null) {
            if (!std.crypto.timing_safe.eql([32]u8, s.owner_hash, policy.current_owner)) continue;
        } else if (!policy.sessionOwned(s.owner_hash)) continue;
        try @import("durable_session.zig").refresh(s, store.io);
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
        if (s.durable) |b| try out.print(arena, ",\"recovered\":{},\"stdin_available\":{}", .{ b.recovered, !b.recovered and s.stdin_fd != null });
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
    const session = (try sessionOrUnknownReply(arena, cfg, args, out)) orelse return;
    defer session_mod.sessionRelease(session);
    if (session.durable) |b| if (b.recovered) return error.StdinUnavailable;
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
    const session = (try sessionOrUnknownReply(arena, cfg, args, out)) orelse return;
    defer session_mod.sessionRelease(session);
    // session_mod.killTreeGuarded serializes check+kill against the waiter's reap: the
    // kill either lands while the leader zombie still pins the process group
    // or is skipped because the tree is already known dead.
    try killDurableOrEphemeral(session, io);
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
    if (session.durable != null) {
        try killDurableOrEphemeral(session, io);
        // Verified kill never targets a stale PID; wait only for the
        // recorded leader, not for an unverifiable orphan process group.
        var retries: usize = 0;
        while (true) : (retries += 1) {
            if (retries == 100) return error.DurableIdentityUnavailable;
            try @import("durable_session.zig").refresh(session, io);
            session.mutex.lockUncancelable(io);
            const done = session.done;
            session.mutex.unlock(io);
            if (done) break;
            os.sleepMs(10);
        }
        try @import("durable_session.zig").retire(session, .closed_by_client, io);
    }
    const removed = store.remove(session.id) orelse {
        // A concurrent exec_close won the removal race and owns kill+join.
        try out.appendSlice(arena, "{\"ok\":true,\"already_closed\":true}");
        return;
    };
    // Wake the readers out of any parked poll so the joins below are fast,
    // then stop them; the waiter (or the kill) drives their EOF.
    session_mod.sessionRequestClose(session);
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
    try out.print(arena, "}},\"features\":{{\"copy_path\":{s},\"copy_max_bytes\":{d},\"copy_max_entries\":{d},\"durable_sessions\":{},\"exec_output_shaping\":true,\"output_max_bytes\":{d}}}}}", .{
        if (@import("builtin").os.tag == .windows) "false" else "true", cfg.copy_max_bytes, cfg.copy_max_entries, cfg.state_dir != null, @min(cfg.max_out, 1024 * 1024),
    });
}

/// Exact number of lines in raw file bytes: LF-terminated lines plus one
/// trailing partial line when the file does not end with LF. Empty input
/// has zero lines. CR is ordinary content (CRLF keeps its CR).
fn countFileLines(data: []const u8) u64 {
    if (data.len == 0) return 0;
    var n: u64 = @intCast(std.mem.count(u8, data, "\n"));
    if (data[data.len - 1] != '\n') n += 1;
    return n;
}

const LineRange = struct { start: usize, end: usize, lines: u64 };

/// Byte range covering lines [start_idx, start_idx + max_lines), 0-indexed;
/// max_lines null selects to EOF. A start past the last line yields an
/// empty range at EOF (never an error — mirroring offset-past-EOF).
fn lineRangeBytes(data: []const u8, start_idx: u64, max_lines: ?u64) LineRange {
    var pos: usize = 0;
    var line_no: u64 = 0;
    while (line_no < start_idx) {
        const nl = std.mem.indexOfScalarPos(u8, data, pos, '\n') orelse
            return .{ .start = data.len, .end = data.len, .lines = 0 };
        pos = nl + 1;
        line_no += 1;
    }
    const start = pos;
    var lines: u64 = 0;
    while (max_lines == null or lines < max_lines.?) {
        if (pos >= data.len) break;
        const nl = std.mem.indexOfScalarPos(u8, data, pos, '\n') orelse {
            pos = data.len;
            lines += 1;
            break;
        };
        pos = nl + 1;
        lines += 1;
    }
    return .{ .start = start, .end = pos, .lines = lines };
}

/// Line-oriented renderer: the line window is selected over RAW bytes, then
/// lossy-rendered, then capped at the character budget (truncated=true when
/// the cap cuts). has_more counts lines beyond the selected window.
fn renderReadFileLines(arena: Allocator, out: *std.ArrayList(u8), path: []const u8, data: []const u8, line_offset: u64, line_limit: ?u64) !void {
    const total = countFileLines(data);
    const range = lineRangeBytes(data, line_offset - 1, line_limit);
    const text = try util.utf8LossyAlloc(arena, data[range.start..range.end]);
    const capped = try util.utf8CharSlice(text, 0, READ_FILE_DEFAULT_LIMIT_CHARS);
    const has_more = (line_offset - 1 + range.lines) < total;
    try out.appendSlice(arena, "{\"ok\":true,\"path\":");
    try util.appendJsonString(out, arena, path);
    try out.appendSlice(arena, ",\"size\":");
    try out.print(arena, "{d}", .{data.len});
    try out.appendSlice(arena, ",\"line_offset\":");
    try out.print(arena, "{d}", .{line_offset});
    try out.appendSlice(arena, ",\"line_limit\":");
    if (line_limit) |ll| {
        try out.print(arena, "{d}", .{ll});
    } else {
        try out.appendSlice(arena, "null");
    }
    try out.appendSlice(arena, ",\"total_lines\":");
    try out.print(arena, "{d}", .{total});
    try out.appendSlice(arena, ",\"content\":");
    try util.appendJsonString(out, arena, capped.text);
    try out.appendSlice(arena, ",\"has_more\":");
    try out.appendSlice(arena, if (has_more) "true" else "false");
    try out.appendSlice(arena, ",\"truncated\":");
    try out.appendSlice(arena, if (capped.has_more) "true" else "false");
    try out.appendSlice(arena, "}");
}

pub fn toolReadFile(arena: Allocator, io: Io, cfg: *const config.Config, args: Value, out: *std.ArrayList(u8)) !void {
    _ = cfg;
    const path = try expandPath(arena, io, (try util.optStrArg(args, "path")) orelse return error.MissingPath);
    const offset_arg = try util.optIntArg(args, "offset");
    const limit_arg = try util.optIntArg(args, "limit");
    const line_offset_arg = try util.optIntArg(args, "line_offset");
    const line_limit_arg = try util.optIntArg(args, "line_limit");
    const line_mode = line_offset_arg != null or line_limit_arg != null;
    // The two window families are mutually exclusive (v0.5.0): mixing
    // character offsets with line windows is a caller bug, refuse early.
    if (line_mode and (offset_arg != null or limit_arg != null)) return error.ConflictingParams;
    const offset = offset_arg orelse 0;
    const limit = limit_arg orelse READ_FILE_DEFAULT_LIMIT_CHARS;
    if (offset < 0 or limit < 0) return error.BadOffset;
    // 32-bit hosts: an offset/limit beyond usize cannot address the slice
    // window; reject instead of panicking inside @intCast. On 64-bit the
    // bound is unreachable, so semantics are unchanged.
    if (offset > std.math.maxInt(usize) or limit > std.math.maxInt(usize)) return error.BadOffset;
    // Line windows are 1-indexed (line_offset default 1); line_limit 0 is a
    // legal empty selection that still reports total_lines.
    const line_offset = line_offset_arg orelse 1;
    if (line_offset < 1) return error.BadOffset;
    if (line_limit_arg != null and line_limit_arg.? < 0) return error.BadOffset;
    if (line_offset_arg != null and line_offset_arg.? > std.math.maxInt(usize)) return error.BadOffset;
    if (line_limit_arg != null and line_limit_arg.? > std.math.maxInt(usize)) return error.BadOffset;
    // Pinned open when a policy matched this call: the gate's canonical
    // path and the open operate on ONE kernel-resolved object (TOCTOU
    // closure). Without a pin (no policy / allow_all) the legacy raw-path
    // read keeps the exact v0.3.1 behaviour.
    const data = if (policy.currentFilePin()) |pin| blk: {
        const fd = os.secure.openPinned(io, pin, .read, .{}) catch |err| switch (err) {
            // Taxonomy parity — the pin layer answers
            // IsDir for a directory target (both the rel=="" fast refusal
            // and the fstat regularity check); the tool contract spells it
            // IsDirectory, exactly like the legacy branch below.
            error.IsDir => return error.IsDirectory,
            else => return err,
        };
        defer os.closeFd(fd);
        break :blk os.secure.readFileAllocFd(arena, io, fd, READ_FILE_MAX_BYTES) catch |err| {
            // Error mapping parity with the legacy path below: a
            // directory read surfaces IsDirectory at read time, the limit
            // at StreamTooLong. The pin refusals (PathEscape, PathDenied,
            // PrefixSwapped, NotRegularFile) surface under their own
            // names (the pin layer's raw IsDir maps to
            // the tool contract's IsDirectory exactly like the legacy
            // branch).
            switch (err) {
                error.IsDir => return error.IsDirectory,
                error.StreamTooLong => return error.FileTooLarge,
                else => return err,
            }
        };
    } else os.fd.readFileAlloc(arena, io, path, READ_FILE_MAX_BYTES) catch |err| {
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
    if (line_mode) {
        return renderReadFileLines(arena, out, path, data, @intCast(line_offset), if (line_limit_arg) |ll| @intCast(ll) else null);
    }
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
    const content_text = try util.optStrArg(args, "content");
    const content_b64 = try util.optStrArg(args, "content_b64");
    // v0.5.0: plain UTF-8 `content` is the text path, `content_b64` stays
    // the binary path; exactly one must be present.
    if (content_text != null and content_b64 != null) return error.ConflictingContent;
    const mode_i = (try util.optIntArg(args, "mode")) orelse 0o644;
    const mkdirs = (try util.optBoolArg(args, "mkdirs")) orelse true;
    if (mode_i < 0 or mode_i > 0o7777) return error.BadMode;

    const data: []const u8 = if (content_b64) |b64| blk: {
        const size = try std.base64.standard.Decoder.calcSizeForSlice(b64);
        const d = try arena.alloc(u8, size);
        try std.base64.standard.Decoder.decode(d, b64);
        break :blk d;
    } else content_text orelse return error.MissingContent;

    const mode: std.posix.mode_t = @intCast(mode_i);
    // Pinned write when a policy matched: intermediate directories are
    // created component-wise from the pinned prefix, the file is opened
    // BENEATH-confined and post-checked BEFORE a byte is written. Without
    // a pin the legacy raw-path write keeps the v0.3.1 behaviour.
    if (policy.currentFilePin()) |pin| {
        const fd = try os.secure.openPinned(io, pin, .write, .{
            .mkdirs = mkdirs,
            .mode = mode,
        });
        defer os.closeFd(fd);
        try os.writeAllFd(fd, data);
    } else {
        if (mkdirs) {
            if (std.fs.path.dirname(path)) |parent| {
                if (parent.len != 0 and !std.mem.eql(u8, parent, ".")) {
                    try std.Io.Dir.createDirPath(.cwd(), io, parent);
                }
            }
        }
        // POSIX applies `mode` exactly via openat(2); on Windows the
        // mode is ignored (NTFS ACLs, not POSIX permission bits) — both
        // paths and the rationale live in os.fd.writeFile.
        try os.fd.writeFile(io, path, data, mode);
    }

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
    // Pinned open when a policy matched: the listing directory is opened
    // through the pin and iterated by its own descriptor; entries are
    // stat'ed relative to that descriptor. Without a pin the legacy
    // raw-path open keeps the v0.3.1 behaviour.
    if (policy.currentFilePin()) |pin| {
        const fd = try os.secure.openPinned(io, pin, .dir, .{});
        var dir = std.Io.Dir{ .handle = fd };
        defer dir.close(io);
        // Under the pin the per-entry stat must NOT
        // follow symlinks — statFile(io, name, .{}) follows them and
        // leaks the size/mtime of files OUTSIDE read_paths (or inside
        // read_deny) through the listing. lstat reports the link's own
        // size (the target string length) instead. The legacy branch
        // keeps v0.3.1 behaviour (follow), same call, different flag.
        try listDirInto(arena, io, dir, path, false, out);
        return;
    }
    var dir = std.Io.Dir.openDir(.cwd(), io, path, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => return error.FileNotFound,
        error.NotDir => return error.NotDirectory,
        else => return err,
    };
    defer dir.close(io);
    try listDirInto(arena, io, dir, path, true, out);
}

/// Shared listing core: iterate `dir` (already opened by the caller),
/// cap at LIST_DIR_MAX_ENTRIES, stat each entry relative to the same
/// descriptor, sort by name, and render the frozen contract (count +
/// truncated/has_more).
fn listDirInto(arena: Allocator, io: Io, dir: std.Io.Dir, path: []const u8, follow_symlinks: bool, out: *std.ArrayList(u8)) !void {
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
        if (dir.statFile(io, entry.name, .{ .follow_symlinks = follow_symlinks })) |st| {
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

test "tool exec times out on a child that closed its output and lives on" {
    if (builtin.os.tag != .linux) return error.SkipZigTest; // CI runs unit tests on Linux only
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var threaded = Io.Threaded.init(std.heap.page_allocator, .{ .environ = env_state.process_environ });
    defer threaded.deinit();
    const io = threaded.io();
    const cfg = try testConfig(arena);

    // The child closes BOTH output fds, then outlives the deadline.
    // The pre-fix unpinned branch went through std.process.run, whose final
    // child.wait parks forever after EOF — the timeout never reached the
    // wait, and the reply landed only when sleep 30 exited (~30s, exit 0).
    const parked = "{\"argv\":[\"/bin/sh\",\"-c\",\"exec 1>&- 2>&-; exec sleep 30\"],\"timeout\":1}";

    // No policy: the raw-spawn branch must collect under the same bounded
    // deadline as the pinned branch.
    {
        var out: std.ArrayList(u8) = .empty;
        const started = std.Io.Timestamp.now(io, .awake);
        try runTool(arena, io, &cfg, toolExec, parked, &out);
        const v = try parseArgs(arena, out.items);
        try std.testing.expect(getBool(v, "ok") == false);
        const timeout_flag = if (v.object.get("timeout")) |t| t.bool else false;
        try std.testing.expect(timeout_flag);
        try std.testing.expectEqualStrings("CommandTimeout", getStr(v, "error"));
        try std.testing.expect(started.untilNow(io, .awake).toMilliseconds() < 10_000); // bounded, not parked for sleep 30
        // Killed AND reaped inside the call: no defunct child is left.
        try std.testing.expectEqual(@as(usize, 0), proc.reapStrayChildren(&.{}));
    }

    // allow_all: the policy is active on this thread but publishes no
    // ExecPin, so the same unpinned branch runs — and must stay bounded.
    var pol = policy.TokenPolicy{
        .file = "f",
        .token_hash = [_]u8{9} ** 32,
        .allow_all = true,
        .tools = &.{},
        .exec_argv0 = &.{},
        .exec_cwd = &.{},
        .cwd_deny = &.{},
        .read_paths = &.{},
        .write_paths = &.{},
        .read_deny = &.{},
        .write_deny = &.{},
    };
    policy.beginRequest(&pol, null, null);
    defer policy.endRequest();
    {
        var out: std.ArrayList(u8) = .empty;
        const started = std.Io.Timestamp.now(io, .awake);
        try runTool(arena, io, &cfg, toolExec, parked, &out);
        const v = try parseArgs(arena, out.items);
        try std.testing.expect(getBool(v, "ok") == false);
        const timeout_flag = if (v.object.get("timeout")) |t| t.bool else false;
        try std.testing.expect(timeout_flag);
        try std.testing.expectEqualStrings("CommandTimeout", getStr(v, "error"));
        try std.testing.expect(started.untilNow(io, .awake).toMilliseconds() < 10_000);
        try std.testing.expectEqual(@as(usize, 0), proc.reapStrayChildren(&.{}));
    }
}

test "tool exec_shell times out on a child that closed its output and lives on" {
    if (builtin.os.tag != .linux) return error.SkipZigTest; // CI runs unit tests on Linux only
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var threaded = Io.Threaded.init(std.heap.page_allocator, .{ .environ = env_state.process_environ });
    defer threaded.deinit();
    const io = threaded.io();
    const cfg = try testConfig(arena);

    // Same defect through the shell entry: exec_shell synthesizes the
    // argv and reaches the identical runExec core.
    var out: std.ArrayList(u8) = .empty;
    const started = std.Io.Timestamp.now(io, .awake);
    try runTool(arena, io, &cfg, toolExecShell, "{\"script\":\"exec 1>&- 2>&-; exec sleep 30\",\"timeout\":1}", &out);
    const v = try parseArgs(arena, out.items);
    try std.testing.expect(getBool(v, "ok") == false);
    const timeout_flag = if (v.object.get("timeout")) |t| t.bool else false;
    try std.testing.expect(timeout_flag);
    try std.testing.expectEqualStrings("CommandTimeout", getStr(v, "error"));
    try std.testing.expect(started.untilNow(io, .awake).toMilliseconds() < 10_000);
    try std.testing.expectEqual(@as(usize, 0), proc.reapStrayChildren(&.{}));
}

test "tool exec returns the exit code of a child that closed its output and exited" {
    if (builtin.os.tag != .linux) return error.SkipZigTest; // CI runs unit tests on Linux only
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var threaded = Io.Threaded.init(std.heap.page_allocator, .{ .environ = env_state.process_environ });
    defer threaded.deinit();
    const io = threaded.io();
    const cfg = try testConfig(arena);

    // Control: EOF then a quick exit 7 — the remaining-deadline wait must
    // surface the child's exit code, not a timeout.
    var out: std.ArrayList(u8) = .empty;
    try runTool(arena, io, &cfg, toolExec, "{\"argv\":[\"/bin/sh\",\"-c\",\"exec 1>&- 2>&-; exit 7\"],\"timeout\":5}", &out);
    const v = try parseArgs(arena, out.items);
    try std.testing.expect(getBool(v, "ok") == false);
    try std.testing.expectEqual(@as(i64, 7), getInt(v, "exit_code"));
    try std.testing.expect(v.object.get("timeout") == null); // no timeout key on a normal exit
}

test "tool exec output beyond max_out still fails with OutputTooLong" {
    if (builtin.os.tag != .linux) return error.SkipZigTest; // CI runs unit tests on Linux only
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var threaded = Io.Threaded.init(std.heap.page_allocator, .{ .environ = env_state.process_environ });
    defer threaded.deinit();
    const io = threaded.io();
    const cfg = try testConfig(arena);

    // testConfig.max_out is 1 MiB: 2 MiB of output must trip the same
    // StreamTooLong limit semantics the raw std.process.run path had.
    var out: std.ArrayList(u8) = .empty;
    try std.testing.expectError(
        error.OutputTooLong,
        runTool(arena, io, &cfg, toolExec, "{\"argv\":[\"/bin/sh\",\"-c\",\"head -c 2097152 /dev/zero\"],\"timeout\":5}", &out),
    );
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

test "tool exec shell matches exec on an equivalent argv" {
    if (builtin.os.tag != .linux) return error.SkipZigTest; // CI runs unit tests on Linux only
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Both paths resolve "bash" through PATH the same way.
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

    // exec_shell and exec reach the same runExec core: identical observable
    // result fields for the command they both express.
    var out: std.ArrayList(u8) = .empty;
    try runTool(arena, io, &cfg, toolExecShell, "{\"script\":\"echo same\",\"shell\":\"bash\"}", &out);
    const shell_v = try parseArgs(arena, out.items);
    out = .empty;
    try runTool(arena, io, &cfg, toolExec, "{\"argv\":[\"bash\",\"-c\",\"echo same\"]}", &out);
    const exec_v = try parseArgs(arena, out.items);

    try std.testing.expect(getBool(shell_v, "ok") and getBool(exec_v, "ok"));
    try std.testing.expectEqual(getInt(exec_v, "exit_code"), getInt(shell_v, "exit_code"));
    try std.testing.expectEqualStrings(getStr(exec_v, "stdout"), getStr(shell_v, "stdout"));
    try std.testing.expectEqualStrings(getStr(exec_v, "stderr"), getStr(shell_v, "stderr"));

    // Timeout clamping applies identically on the shell path (no JSON
    // round-trip can skip it): 0 clamps up to 1s and still times out.
    out = .empty;
    try runTool(arena, io, &cfg, toolExecShell, "{\"script\":\"sleep 30\",\"timeout\":0}", &out);
    const clamped = try parseArgs(arena, out.items);
    try std.testing.expect(getBool(clamped, "timeout"));
    try std.testing.expectEqualStrings("CommandTimeout", getStr(clamped, "error"));
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

test "read_file line mode selects windows and reports total_lines" {
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

    // Fixture: 5 lines, last one unterminated, plus a CRLF pair.
    const file_path = try std.fmt.allocPrint(arena, "{s}/lines.txt", .{root});
    const body = "alpha\nbeta\r\ngamma\n\ndelta-tail";
    var out: std.ArrayList(u8) = .empty;
    var args = try std.fmt.allocPrint(arena, "{{\"path\":\"{s}\",\"content_b64\":\"{s}\"}}", .{ file_path, try b64Alloc(arena, body) });
    try runTool(arena, io, &cfg, toolWriteFile, args, &out);

    // Whole file in line mode: exact total, content byte-identical.
    out = .empty;
    args = try std.fmt.allocPrint(arena, "{{\"path\":\"{s}\",\"line_offset\":1}}", .{file_path});
    try runTool(arena, io, &cfg, toolReadFile, args, &out);
    var v = try parseArgs(arena, out.items);
    try std.testing.expect(getBool(v, "ok"));
    try std.testing.expectEqual(@as(i64, 5), getInt(v, "total_lines"));
    try std.testing.expectEqualStrings(body, getStr(v, "content"));
    try std.testing.expect(!getBool(v, "has_more"));
    try std.testing.expect(!getBool(v, "truncated"));
    try std.testing.expect(v.object.get("line_limit").? == .null);

    // Middle window: lines 2..3 keep their bytes (CRLF keeps its CR).
    out = .empty;
    args = try std.fmt.allocPrint(arena, "{{\"path\":\"{s}\",\"line_offset\":2,\"line_limit\":2}}", .{file_path});
    try runTool(arena, io, &cfg, toolReadFile, args, &out);
    v = try parseArgs(arena, out.items);
    try std.testing.expectEqualStrings("beta\r\ngamma\n", getStr(v, "content"));
    try std.testing.expect(getBool(v, "has_more"));
    try std.testing.expectEqual(@as(i64, 5), getInt(v, "total_lines"));

    // Tail: line_offset 4 without limit reads the empty line and the
    // unterminated tail; has_more goes false exactly at the last line.
    out = .empty;
    args = try std.fmt.allocPrint(arena, "{{\"path\":\"{s}\",\"line_offset\":4}}", .{file_path});
    try runTool(arena, io, &cfg, toolReadFile, args, &out);
    v = try parseArgs(arena, out.items);
    try std.testing.expectEqualStrings("\ndelta-tail", getStr(v, "content"));
    try std.testing.expect(!getBool(v, "has_more"));

    // line_limit 0: empty content, exact total_lines, has_more true.
    out = .empty;
    args = try std.fmt.allocPrint(arena, "{{\"path\":\"{s}\",\"line_limit\":0}}", .{file_path});
    try runTool(arena, io, &cfg, toolReadFile, args, &out);
    v = try parseArgs(arena, out.items);
    try std.testing.expectEqualStrings("", getStr(v, "content"));
    try std.testing.expectEqual(@as(i64, 5), getInt(v, "total_lines"));
    try std.testing.expect(getBool(v, "has_more"));

    // Past-EOF start: empty content, no error, has_more false.
    out = .empty;
    args = try std.fmt.allocPrint(arena, "{{\"path\":\"{s}\",\"line_offset\":99}}", .{file_path});
    try runTool(arena, io, &cfg, toolReadFile, args, &out);
    v = try parseArgs(arena, out.items);
    try std.testing.expectEqualStrings("", getStr(v, "content"));
    try std.testing.expect(!getBool(v, "has_more"));

    // Mixing the two window families is a caller bug.
    out = .empty;
    args = try std.fmt.allocPrint(arena, "{{\"path\":\"{s}\",\"line_offset\":1,\"offset\":0}}", .{file_path});
    try std.testing.expectError(error.ConflictingParams, runTool(arena, io, &cfg, toolReadFile, args, &out));

    // line_offset is 1-indexed: 0 and negatives are rejected.
    out = .empty;
    args = try std.fmt.allocPrint(arena, "{{\"path\":\"{s}\",\"line_offset\":0}}", .{file_path});
    try std.testing.expectError(error.BadOffset, runTool(arena, io, &cfg, toolReadFile, args, &out));
    out = .empty;
    args = try std.fmt.allocPrint(arena, "{{\"path\":\"{s}\",\"line_limit\":-2}}", .{file_path});
    try std.testing.expectError(error.BadOffset, runTool(arena, io, &cfg, toolReadFile, args, &out));

    // Empty file: zero lines, empty content.
    const empty_path = try std.fmt.allocPrint(arena, "{s}/empty.txt", .{root});
    out = .empty;
    args = try std.fmt.allocPrint(arena, "{{\"path\":\"{s}\",\"content\":\"\"}}", .{empty_path});
    try runTool(arena, io, &cfg, toolWriteFile, args, &out);
    out = .empty;
    args = try std.fmt.allocPrint(arena, "{{\"path\":\"{s}\",\"line_offset\":1}}", .{empty_path});
    try runTool(arena, io, &cfg, toolReadFile, args, &out);
    v = try parseArgs(arena, out.items);
    try std.testing.expectEqual(@as(i64, 0), getInt(v, "total_lines"));
    try std.testing.expectEqualStrings("", getStr(v, "content"));
    try std.testing.expect(!getBool(v, "has_more"));

    // Char mode keeps its exact legacy shape: no total_lines key at all.
    out = .empty;
    args = try std.fmt.allocPrint(arena, "{{\"path\":\"{s}\"}}", .{file_path});
    try runTool(arena, io, &cfg, toolReadFile, args, &out);
    v = try parseArgs(arena, out.items);
    try std.testing.expect(v.object.get("total_lines") == null);
    try std.testing.expectEqual(@as(i64, 0), getInt(v, "offset"));
}

test "write_file accepts plain content and refuses dual or missing content" {
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

    // Plain text content lands byte-exact (multibyte UTF-8 intact). The
    // Zig literal carries JSON escapes: \\\" -> quote, \\u00e9 -> é,
    // \\n -> newline after the JSON decode.
    const file_path = try std.fmt.allocPrint(arena, "{s}/plain.txt", .{root});
    const text = "key = \\\"va\\u00e9lue\\\"\\nsecond line\\n";
    var out: std.ArrayList(u8) = .empty;
    var args = try std.fmt.allocPrint(arena, "{{\"path\":\"{s}\",\"content\":\"{s}\"}}", .{ file_path, text });
    try runTool(arena, io, &cfg, toolWriteFile, args, &out);
    var v = try parseArgs(arena, out.items);
    try std.testing.expect(getBool(v, "ok"));
    const raw = "key = \"va\u{e9}lue\"\nsecond line\n";
    try std.testing.expectEqual(@as(i64, @intCast(raw.len)), getInt(v, "size"));
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(raw, &digest, .{});
    try std.testing.expectEqualStrings(try hexLowerAlloc(arena, &digest), getStr(v, "sha256"));

    // Read back in line mode: the pair composes.
    out = .empty;
    args = try std.fmt.allocPrint(arena, "{{\"path\":\"{s}\",\"line_offset\":2}}", .{file_path});
    try runTool(arena, io, &cfg, toolReadFile, args, &out);
    v = try parseArgs(arena, out.items);
    try std.testing.expectEqual(@as(i64, 2), getInt(v, "total_lines"));
    try std.testing.expectEqualStrings("second line\n", getStr(v, "content"));

    // Both content fields: refused before any write.
    out = .empty;
    args = try std.fmt.allocPrint(arena, "{{\"path\":\"{s}\",\"content\":\"x\",\"content_b64\":\"eA==\"}}", .{file_path});
    try std.testing.expectError(error.ConflictingContent, runTool(arena, io, &cfg, toolWriteFile, args, &out));

    // Neither: MissingContent (unchanged legacy name).
    out = .empty;
    args = try std.fmt.allocPrint(arena, "{{\"path\":\"{s}\"}}", .{file_path});
    try std.testing.expectError(error.MissingContent, runTool(arena, io, &cfg, toolWriteFile, args, &out));

    // Explicit nulls behave as absent: one real field is enough.
    out = .empty;
    args = try std.fmt.allocPrint(arena, "{{\"path\":\"{s}\",\"content\":null,\"content_b64\":\"eA==\"}}", .{file_path});
    try runTool(arena, io, &cfg, toolWriteFile, args, &out);
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
    try runTool(arena, io, &cfg, toolExecPoll, args, &out);
    const ghost = try parseArgs(arena, out.items);
    try std.testing.expect(!getBool(ghost, "ok"));
    try std.testing.expectEqualStrings("unknown_session", getStr(ghost, "error"));
    try std.testing.expectEqual(sid, getInt(ghost, "session_id"));
    try std.testing.expect(getBool(ghost, "expired"));
}

test "exec wait returns promptly on an instantly finishing session" {
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
    try runTool(arena, io, &cfg, toolExecStart, "{\"argv\":[\"/bin/true\"]}", &out);
    const start = try parseArgs(arena, out.items);
    const sid = getInt(start, "session_id");

    // exec_wait on a session that finishes within milliseconds must be
    // woken by the done event, not by the next poll tick: the old 50ms
    // sleep loop could never return before its first full tick landed.
    const t0 = session_mod.nowUs(io);
    out = .empty;
    var args = try std.fmt.allocPrint(arena, "{{\"session_id\":{d},\"timeout\":5}}", .{sid});
    try runTool(arena, io, &cfg, toolExecWait, args, &out);
    const elapsed_us = session_mod.nowUs(io) - t0;
    const wait = try parseArgs(arena, out.items);
    try std.testing.expect(getBool(wait, "ok"));
    try std.testing.expect(getBool(wait, "done"));
    try std.testing.expectEqual(@as(i64, 0), getInt(wait, "exit_code"));
    try std.testing.expect(elapsed_us < 45_000);

    out = .empty;
    args = try std.fmt.allocPrint(arena, "{{\"session_id\":{d}}}", .{sid});
    try runTool(arena, io, &cfg, toolExecClose, args, &out);
    const close = try parseArgs(arena, out.items);
    try std.testing.expect(getBool(close, "ok"));
}

test "exec wait timeout still expires on a live session" {
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
    const sid = getInt(start, "session_id");

    // The event wake must not change the timeout contract: a session that
    // stays live makes exec_wait return after ~1s of the requested 1s,
    // with done still false.
    const t0 = session_mod.nowUs(io);
    out = .empty;
    var args = try std.fmt.allocPrint(arena, "{{\"session_id\":{d},\"timeout\":1}}", .{sid});
    try runTool(arena, io, &cfg, toolExecWait, args, &out);
    const elapsed_us = session_mod.nowUs(io) - t0;
    const wait = try parseArgs(arena, out.items);
    try std.testing.expect(getBool(wait, "ok"));
    try std.testing.expect(!getBool(wait, "done"));
    try std.testing.expect(elapsed_us >= 900_000);
    try std.testing.expect(elapsed_us < 2_000_000);

    out = .empty;
    args = try std.fmt.allocPrint(arena, "{{\"session_id\":{d}}}", .{sid});
    try runTool(arena, io, &cfg, toolExecClose, args, &out);
    const close = try parseArgs(arena, out.items);
    try std.testing.expect(getBool(close, "ok"));
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
    try runTool(arena, io, &cfg, toolExecPoll, args, &out);
    const ghost = try parseArgs(arena, out.items);
    try std.testing.expect(!getBool(ghost, "ok"));
    try std.testing.expectEqualStrings("unknown_session", getStr(ghost, "error"));
    try std.testing.expect(getBool(ghost, "expired"));
}

// Regression for the waiter/reader fd-lifetime protocol: a reader delayed
// exactly between poll(POLLIN) and read (simulated by the one-shot
// session_mod.test_reader_delay_ms hook, longer than DRAIN_GRACE_MS) must
// still deliver the buffered output, and done must be published only after
// the readers actually finished. On the pre-protocol revision the waiter's
// READER_EXIT deadline authorized child.wait() closing the pipe fds while
// the delayed reader had not read yet: its read then failed on the closed
// (possibly recycled) descriptor, the payload was lost, and done was
// already public — the exact defect this test pins.
test "exec kill during a poll-to-read gap keeps output and done after readers" {
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

    // The child prints its payload immediately and then idles: the stdout
    // reader gets poll(POLLIN) at once, takes the one-shot delay hook and
    // parks inside the poll→read gap for 2500ms — well past the 1000ms
    // drain grace, so the waiter's stop request provably lands while the
    // reader is still mid-gap.
    session_mod.test_reader_delay_ms.store(2500, .release);
    defer session_mod.test_reader_delay_ms.store(0, .release);

    var out: std.ArrayList(u8) = .empty;
    try runTool(arena, io, &cfg, toolExecStart, "{\"argv\":[\"/bin/sh\",\"-c\",\"echo gap-payload; sleep 300\"]}", &out);
    const start = try parseArgs(arena, out.items);
    try std.testing.expect(getBool(start, "ok"));
    const sid = getInt(start, "session_id");

    // Give the reader time to reach its delayed read, then kill the tree
    // from the outside — exactly the exec_kill race the protocol must
    // survive.
    os.sleepMs(300);
    out = .empty;
    var args = try std.fmt.allocPrint(arena, "{{\"session_id\":{d}}}", .{sid});
    try runTool(arena, io, &cfg, toolExecKill, args, &out);

    // The waiter must NOT publish done on a deadline: it waits out the
    // delayed reader (bounded by the wake mechanism, not a timer), so this
    // wait sees the session only after the reader drained its payload.
    out = .empty;
    args = try std.fmt.allocPrint(arena, "{{\"session_id\":{d},\"timeout\":10}}", .{sid});
    try runTool(arena, io, &cfg, toolExecWait, args, &out);
    const wait = try parseArgs(arena, out.items);
    try std.testing.expect(getBool(wait, "ok"));
    try std.testing.expect(getBool(wait, "done"));
    try std.testing.expectEqualStrings("gap-payload\n", getStr(wait, "stdout"));

    // done ⇒ readers fully finished: both reader threads closed their fds
    // and bumped readers_done before the waiter published.
    const session = store.get(@intCast(sid)).?;
    defer session_mod.sessionRelease(session);
    try std.testing.expectEqual(@as(u32, 2), session.readers_done.load(.acquire));

    out = .empty;
    args = try std.fmt.allocPrint(arena, "{{\"session_id\":{d}}}", .{sid});
    try runTool(arena, io, &cfg, toolExecClose, args, &out);
    const closed = try parseArgs(arena, out.items);
    try std.testing.expect(getBool(closed, "ok"));
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
    // A never-existent id is a structured unknown_session result, not an
    // error: expired=false because this node process never held it.
    out = .empty;
    try runTool(arena, io, &cfg, toolExecPoll, "{\"session_id\":424242}", &out);
    const never = try parseArgs(arena, out.items);
    try std.testing.expect(!getBool(never, "ok"));
    try std.testing.expectEqualStrings("unknown_session", getStr(never, "error"));
    try std.testing.expectEqual(@as(i64, 424242), getInt(never, "session_id"));
    try std.testing.expect(!getBool(never, "expired"));

    // exec_write validates the protocol types before resolving the session.
    try std.testing.expectError(error.InvalidParams, runTool(arena, io, &cfg, toolExecWrite, "{\"session_id\":1,\"data_b64\":7}", &out));

    // File tools require their payload arguments.
    try std.testing.expectError(error.MissingPath, runTool(arena, io, &cfg, toolReadFile, "{}", &out));
    try std.testing.expectError(error.MissingPath, runTool(arena, io, &cfg, toolWriteFile, "{}", &out));
    try std.testing.expectError(error.MissingContent, runTool(arena, io, &cfg, toolWriteFile, "{\"path\":\"unused.txt\"}", &out));
}

test "cross-token session probe releases its borrowed ref" {
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

    // Two token identities: the owner starts the session, the attacker
    // only probes it. Policy state is thread-local and every call here
    // runs on this thread, so begin/end bracket the whole test.
    var owner_pol = policy.TokenPolicy{
        .file = "f",
        .token_hash = [_]u8{1} ** 32,
        .tools = &.{},
        .exec_argv0 = &.{},
        .exec_cwd = &.{},
        .cwd_deny = &.{},
        .read_paths = &.{},
        .write_paths = &.{},
        .read_deny = &.{},
        .write_deny = &.{},
    };
    var attacker_pol = policy.TokenPolicy{
        .file = "f",
        .token_hash = [_]u8{2} ** 32,
        .tools = &.{},
        .exec_argv0 = &.{},
        .exec_cwd = &.{},
        .cwd_deny = &.{},
        .read_paths = &.{},
        .write_paths = &.{},
        .read_deny = &.{},
        .write_deny = &.{},
    };
    policy.beginRequest(&owner_pol, null, null);
    defer policy.endRequest();

    var out: std.ArrayList(u8) = .empty;
    try runTool(arena, io, &cfg, toolExecStart, "{\"argv\":[\"/bin/cat\"]}", &out);
    const start = try parseArgs(arena, out.items);
    try std.testing.expect(getBool(start, "ok"));
    const sid = getInt(start, "session_id");
    const sid_str = try std.fmt.allocPrint(arena, "{d}", .{sid});

    // Five cross-token polls: each is refused (SessionNotOwned) and must
    // release the +1 reference acquired by the store lookup.
    policy.beginRequest(&attacker_pol, null, null);
    const probe_args = try std.mem.concat(arena, u8, &.{ "{\"session_id\":", sid_str, "}" });
    var i: usize = 0;
    while (i < 5) : (i += 1) {
        out = .empty;
        try std.testing.expectError(error.SessionNotOwned, runTool(arena, io, &cfg, toolExecPoll, probe_args, &out));
    }
    policy.beginRequest(&owner_pol, null, null);

    // Refcount after the rejected probes: 1 (store) + 1 (this get) == 2.
    const session = store.get(@intCast(sid)).?;
    defer session_mod.sessionRelease(session);
    try std.testing.expectEqual(@as(u32, 2), session.refs.load(.acquire));

    // The owner's close now actually frees the session (store ref and our
    // borrowed ref both balance; the creator ref left with exec_start).
    out = .empty;
    try runTool(arena, io, &cfg, toolExecClose, probe_args, &out);
    const closed = try parseArgs(arena, out.items);
    try std.testing.expect(getBool(closed, "ok"));
}

test "unknown term exit code reinterprets windows NTSTATUS values" {
    // Term.unknown carries raw NTSTATUS u32s on Windows; the high bit
    // would panic @intCast in ReleaseSafe. The bit pattern is reported
    // honestly as i32 — 0xC0000005 (ACCESS_VIOLATION) becomes -1073741819,
    // never a clamped fake.
    const code: u32 = 0xC0000005;
    const as_i32: i32 = @bitCast(code);
    try std.testing.expectEqual(@as(i32, -1073741819), as_i32);
    try std.testing.expectEqual(@as(i32, 0), @as(i32, @bitCast(@as(u32, 0))));
}

test "file tools under a policy read, write and list through the pin" {
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
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const root = try arena.dupe(u8, buf[0..try tmp.dir.realPathFile(io, ".", &buf)]);
    try tmp.dir.createDirPath(io, "sand/keys");
    try tmp.dir.writeFile(io, .{ .sub_path = "sand/f.txt", .data = "data\n" });
    const sand = try std.mem.concat(arena, u8, &.{ root, "/sand" });
    const keys = try std.mem.concat(arena, u8, &.{ sand, "/keys" });

    const pol = policy.TokenPolicy{
        .file = "f",
        .token_hash = [_]u8{1} ** 32,
        .tools = &.{ "read_file", "write_file", "list_dir" },
        .exec_argv0 = &.{},
        .exec_cwd = &.{},
        .cwd_deny = &.{},
        .read_paths = &.{sand},
        .write_paths = &.{sand},
        .read_deny = &.{keys},
        .write_deny = &.{keys},
        .write_max_mode = 0o644,
    };

    // Gate + pin + tool, end to end: an allowed read answers ok:true with
    // the file bytes.
    {
        var pin: ?policy.FilePin = null;
        var epin: ?policy.ExecPin = null;
        try std.testing.expect(checkCallTool(arena, io, &pol, "read_file", &pin, &epin, "{\"path\":\"<SAND>/f.txt\"}", sand) == null);
        try std.testing.expect(pin != null);
        policy.beginRequest(&pol, pin, null);
        defer policy.endRequest();
        var out: std.ArrayList(u8) = .empty;
        try runTool(arena, io, &cfg, toolReadFile, "{\"path\":\"<SAND>/f.txt\"}", &out);
        const v = try parseArgs(arena, out.items);
        try std.testing.expect(getBool(v, "ok"));
        try std.testing.expectEqualStrings("data\n", getStr(v, "content"));
    }

    // A pinned write with mkdirs creates the tree component-wise from
    // the prefix and lands the file.
    {
        var pin: ?policy.FilePin = null;
        var epin: ?policy.ExecPin = null;
        try std.testing.expect(checkCallTool(arena, io, &pol, "write_file", &pin, &epin, "{\"path\":\"<SAND>/a/b/c.txt\",\"content_b64\":\"aGk=\"}", sand) == null);
        policy.beginRequest(&pol, pin, null);
        defer policy.endRequest();
        var out: std.ArrayList(u8) = .empty;
        try runTool(arena, io, &cfg, toolWriteFile, "{\"path\":\"<SAND>/a/b/c.txt\",\"content_b64\":\"aGk=\"}", &out);
        const v = try parseArgs(arena, out.items);
        try std.testing.expect(getBool(v, "ok"));
        var rbuf: [4]u8 = undefined;
        const wdata = try tmp.dir.readFile(io, "sand/a/b/c.txt", &rbuf);
        try std.testing.expectEqualStrings("hi", wdata);
    }

    // A pinned list_dir enumerates through the descriptor.
    {
        var pin: ?policy.FilePin = null;
        var epin: ?policy.ExecPin = null;
        try std.testing.expect(checkCallTool(arena, io, &pol, "list_dir", &pin, &epin, "{\"path\":\"<SAND>\"}", sand) == null);
        policy.beginRequest(&pol, pin, null);
        defer policy.endRequest();
        var out: std.ArrayList(u8) = .empty;
        try runTool(arena, io, &cfg, toolListDir, "{\"path\":\"<SAND>\"}", &out);
        const v = try parseArgs(arena, out.items);
        try std.testing.expect(getBool(v, "ok"));
        try std.testing.expectEqual(@as(i64, 3), getInt(v, "count")); // a, f.txt, keys
    }

    // Rename-race simulation (gate ran, THEN the ancestor is swapped for
    // a symlink): the pinned prefix open refuses; the victim tree never
    // answers the read.
    {
        var pin: ?policy.FilePin = null;
        var epin: ?policy.ExecPin = null;
        try std.testing.expect(checkCallTool(arena, io, &pol, "read_file", &pin, &epin, "{\"path\":\"<SAND>/f.txt\"}", sand) == null);
        // The race: sand -> symlink outside (victim holds the original).
        try tmp.dir.rename("sand", tmp.dir, "victim", io);
        tmp.dir.symLink(io, "victim", "sand", .{}) catch {};
        defer {
            tmp.dir.deleteFile(io, "sand") catch {};
            tmp.dir.rename("victim", tmp.dir, "sand", io) catch {};
        }
        policy.beginRequest(&pol, pin, null);
        defer policy.endRequest();
        var out: std.ArrayList(u8) = .empty;
        // The authorized prefix now names a symlink: refused.
        try std.testing.expectError(error.PrefixSwapped, runTool(arena, io, &cfg, toolReadFile, "{\"path\":\"<SAND>/f.txt\"}", &out));
    }

    // Symlink planted AFTER the gate on the final component (write):
    // the open follows it, the post-check refuses before a byte lands,
    // nothing is created at the swapped target.
    {
        var pin: ?policy.FilePin = null;
        var epin: ?policy.ExecPin = null;
        try std.testing.expect(checkCallTool(arena, io, &pol, "write_file", &pin, &epin, "{\"path\":\"<SAND>/swap.txt\",\"content_b64\":\"cHduZWQ=\"}", sand) == null);
        // Symlink INSIDE the sandbox (f.txt is a different, existing
        // object): the kernel confinement passes, the post-check
        // mismatch must refuse — and f.txt must keep its bytes.
        tmp.dir.symLink(io, "f.txt", "sand/swap.txt", .{}) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
        policy.beginRequest(&pol, pin, null);
        defer policy.endRequest();
        var out: std.ArrayList(u8) = .empty;
        try std.testing.expectError(error.PathEscape, runTool(arena, io, &cfg, toolWriteFile, "{\"path\":\"<SAND>/swap.txt\",\"content_b64\":\"cHduZWQ=\"}", &out));
        // The victim file kept its original content (no pwned bytes).
        var rbuf: [8]u8 = undefined;
        const rdata = try tmp.dir.readFile(io, "sand/f.txt", &rbuf);
        try std.testing.expectEqualStrings("data\n", rdata);
    }
}

test "file tools under a policy list entries without following symlinks" {
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
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const root = try arena.dupe(u8, buf[0..try tmp.dir.realPathFile(io, ".", &buf)]);
    try tmp.dir.createDirPath(io, "sand");
    // outside/big.bin: 4096 bytes OUTSIDE every read path (and beyond the
    // read_deny boundary shape: the leak was its size/mtime surfacing in
    // the listing via a followed symlink).
    const big = try arena.alloc(u8, 4096);
    @memset(big, 'x');
    try tmp.dir.createDirPath(io, "outside");
    try tmp.dir.writeFile(io, .{ .sub_path = "outside/big.bin", .data = big });
    // sand/link -> ../outside/big.bin: an in-tree symlink entry.
    tmp.dir.symLink(io, "../outside/big.bin", "sand/link", .{}) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    const sand = try std.mem.concat(arena, u8, &.{ root, "/sand" });

    const pol = policy.TokenPolicy{
        .file = "f",
        .token_hash = [_]u8{1} ** 32,
        .tools = &.{"list_dir"},
        .exec_argv0 = &.{},
        .exec_cwd = &.{},
        .cwd_deny = &.{},
        .read_paths = &.{sand},
        .write_paths = &.{},
        .read_deny = &.{},
        .write_deny = &.{},
        .write_max_mode = 0o644,
    };

    // Under the pin the per-entry stat must
    // NOT follow the symlink — the reported size is the LINK's own size
    // (its target string, 18 bytes), never the 4096 of the outside file.
    var pin: ?policy.FilePin = null;
    var epin: ?policy.ExecPin = null;
    try std.testing.expect(checkCallTool(arena, io, &pol, "list_dir", &pin, &epin, "{\"path\":\"<SAND>\"}", sand) == null);
    policy.beginRequest(&pol, pin, null);
    defer policy.endRequest();
    var out: std.ArrayList(u8) = .empty;
    try runTool(arena, io, &cfg, toolListDir, "{\"path\":\"<SAND>\"}", &out);
    const v = try parseArgs(arena, out.items);
    try std.testing.expect(getBool(v, "ok"));
    const items = v.object.get("items").?.array.items;
    try std.testing.expectEqual(@as(usize, 1), items.len);
    try std.testing.expectEqualStrings("link", getStr(items[0], "name"));
    try std.testing.expectEqualStrings("l", getStr(items[0], "type"));
    try std.testing.expectEqual(@as(i64, "../outside/big.bin".len), getInt(items[0], "size"));
}

test "file tools pinned read of a directory answers IsDirectory" {
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
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const root = try arena.dupe(u8, buf[0..try tmp.dir.realPathFile(io, ".", &buf)]);
    try tmp.dir.createDirPath(io, "sand");
    const sand = try std.mem.concat(arena, u8, &.{ root, "/sand" });

    const pol = policy.TokenPolicy{
        .file = "f",
        .token_hash = [_]u8{1} ** 32,
        .tools = &.{"read_file"},
        .exec_argv0 = &.{},
        .exec_cwd = &.{},
        .cwd_deny = &.{},
        .read_paths = &.{sand},
        .write_paths = &.{},
        .read_deny = &.{},
        .write_deny = &.{},
        .write_max_mode = 0o644,
    };

    // Taxonomy parity with the legacy branch: a pinned read_file of a
    // directory (the allow prefix itself, rel == "") must surface
    // error.IsDirectory, not the pin layer's IsDir.
    var pin: ?policy.FilePin = null;
    var epin: ?policy.ExecPin = null;
    try std.testing.expect(checkCallTool(arena, io, &pol, "read_file", &pin, &epin, "{\"path\":\"<SAND>\"}", sand) == null);
    policy.beginRequest(&pol, pin, null);
    defer policy.endRequest();
    var out: std.ArrayList(u8) = .empty;
    try std.testing.expectError(error.IsDirectory, runTool(arena, io, &cfg, toolReadFile, "{\"path\":\"<SAND>\"}", &out));
}

/// Write an executable fixture (0755 shell script) for the exec tests.
fn writeExecFixture(dir: std.Io.Dir, io: Io, name: []const u8, content: []const u8) !void {
    try dir.writeFile(io, .{
        .sub_path = name,
        .data = content,
        .flags = .{ .permissions = std.Io.File.Permissions.fromMode(0o755) },
    });
}

test "exec under a policy spawns through the pinned objects" {
    if (builtin.os.tag != .linux) return error.SkipZigTest; // CI runs unit tests on Linux only
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var threaded = Io.Threaded.init(std.heap.page_allocator, .{ .environ = env_state.process_environ });
    defer threaded.deinit();
    const io = threaded.io();
    var cfg = try testConfig(arena);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const root = try arena.dupe(u8, buf[0..try tmp.dir.realPathFile(io, ".", &buf)]);
    try tmp.dir.createDirPath(io, "sand/bin");
    try writeExecFixture(tmp.dir, io, "sand/good", "#!/bin/sh\necho PIN-GOOD\n");
    try writeExecFixture(tmp.dir, io, "sand/bin/mytool", "#!/bin/sh\necho PIN-TOOL\n");
    const sand = try std.mem.concat(arena, u8, &.{ root, "/sand" });
    const tool_abs = try std.mem.concat(arena, u8, &.{ sand, "/good" });

    const pol = policy.TokenPolicy{
        .file = "f",
        .token_hash = [_]u8{1} ** 32,
        .tools = &.{ "exec", "exec_shell" },
        .exec_argv0 = &.{
            .{ .text = tool_abs, .has_slash = true },
            .{ .text = "mytool", .has_slash = false },
            .{ .text = "sh", .has_slash = false },
        },
        .exec_cwd = &.{sand},
        .cwd_deny = &.{},
        .read_paths = &.{},
        .write_paths = &.{},
        .read_deny = &.{},
        .write_deny = &.{},
    };

    // Absolute argv0 + explicit cwd: the pin's canon must mirror the gate's
    // canonicalization, and the exec must run the pinned object.
    {
        var pin: ?policy.FilePin = null;
        var epin: ?policy.ExecPin = null;
        try std.testing.expect(checkCallTool(arena, io, &pol, "exec", &pin, &epin, "{\"argv\":[\"<SAND>/good\"],\"cwd\":\"<SAND>\"}", sand) == null);
        try std.testing.expect(epin != null);
        try std.testing.expectEqualStrings(tool_abs, epin.?.argv0_canon);
        try std.testing.expectEqualStrings(sand, epin.?.cwd_canon);
        try std.testing.expectEqualStrings(tool_abs, epin.?.argv0); // raw argv[0] preserved
        policy.beginRequest(&pol, pin, epin);
        defer policy.endRequest();
        var out: std.ArrayList(u8) = .empty;
        try runTool(arena, io, &cfg, toolExec, "{\"argv\":[\"<SAND>/good\"],\"cwd\":\"<SAND>\"}", &out);
        const v = try parseArgs(arena, out.items);
        try std.testing.expect(getBool(v, "ok"));
        try std.testing.expectEqual(@as(i64, 0), getInt(v, "exit_code"));
        try std.testing.expect(std.mem.indexOf(u8, getStr(v, "stdout"), "PIN-GOOD") != null);
    }

    // Bare argv0 through PATH: authorization is the name match, the PATH
    // search (execvp order) picks the object and the pin executes it.
    {
        const saved = env_state.process_environ;
        defer env_state.process_environ = saved;
        const slice = try arena.allocSentinel(?[*:0]const u8, 1, null);
        slice[0] = try arena.dupeZ(u8, try std.mem.concat(arena, u8, &.{ "PATH=", sand, "/bin" }));
        env_state.process_environ = .{ .block = .{ .slice = slice } };

        var pin: ?policy.FilePin = null;
        var epin: ?policy.ExecPin = null;
        try std.testing.expect(checkCallTool(arena, io, &pol, "exec", &pin, &epin, "{\"argv\":[\"mytool\"]}", sand) == null);
        try std.testing.expect(epin != null);
        try std.testing.expectEqualStrings("", epin.?.argv0_canon); // bare: PATH-resolved at pin time
        policy.beginRequest(&pol, pin, epin);
        defer policy.endRequest();
        var out: std.ArrayList(u8) = .empty;
        try runTool(arena, io, &cfg, toolExec, "{\"argv\":[\"mytool\"]}", &out);
        const v = try parseArgs(arena, out.items);
        try std.testing.expect(getBool(v, "ok"));
        try std.testing.expect(std.mem.indexOf(u8, getStr(v, "stdout"), "PIN-TOOL") != null);
    }

    // exec_shell: the synthesized shell argv goes through the same pin
    // (the shell BINARY is what gets pinned and executed).
    {
        const saved = env_state.process_environ;
        defer env_state.process_environ = saved;
        const slice = try arena.allocSentinel(?[*:0]const u8, 1, null);
        slice[0] = "PATH=/bin:/usr/bin";
        env_state.process_environ = .{ .block = .{ .slice = slice } };

        var pin: ?policy.FilePin = null;
        var epin: ?policy.ExecPin = null;
        try std.testing.expect(checkCallTool(arena, io, &pol, "exec_shell", &pin, &epin, "{\"script\":\"echo SHELLPIN\",\"shell\":\"sh\"}", sand) == null);
        try std.testing.expect(epin != null);
        try std.testing.expectEqualStrings("sh", epin.?.argv0);
        try std.testing.expectEqualStrings("", epin.?.argv0_canon);
        policy.beginRequest(&pol, pin, epin);
        defer policy.endRequest();
        var out: std.ArrayList(u8) = .empty;
        try runTool(arena, io, &cfg, toolExecShell, "{\"script\":\"echo SHELLPIN\",\"shell\":\"sh\"}", &out);
        const v = try parseArgs(arena, out.items);
        try std.testing.expect(getBool(v, "ok"));
        try std.testing.expect(std.mem.indexOf(u8, getStr(v, "stdout"), "SHELLPIN") != null);
    }
}

test "exec_start under a policy spawns the session through the pin" {
    if (builtin.os.tag != .linux) return error.SkipZigTest; // CI runs unit tests on Linux only
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var threaded = Io.Threaded.init(std.heap.page_allocator, .{ .environ = env_state.process_environ });
    defer threaded.deinit();
    const io = threaded.io();
    var cfg = try testConfig(arena);
    const store = try std.heap.page_allocator.create(session_mod.SessionStore);
    store.* = session_mod.SessionStore.init(io, 8);
    cfg.sessions = store;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const root = try arena.dupe(u8, buf[0..try tmp.dir.realPathFile(io, ".", &buf)]);
    try tmp.dir.createDirPath(io, "job");
    try writeExecFixture(tmp.dir, io, "job/runner", "#!/bin/sh\necho SESS-PIN\n");
    const job = try std.mem.concat(arena, u8, &.{ root, "/job" });
    const runner = try std.mem.concat(arena, u8, &.{ job, "/runner" });

    const pol = policy.TokenPolicy{
        .file = "f",
        .token_hash = [_]u8{3} ** 32,
        .tools = &.{"exec_start"},
        .exec_argv0 = &.{.{ .text = runner, .has_slash = true }},
        .exec_cwd = &.{job},
        .cwd_deny = &.{},
        .read_paths = &.{},
        .write_paths = &.{},
        .read_deny = &.{},
        .write_deny = &.{},
    };

    var pin: ?policy.FilePin = null;
    var epin: ?policy.ExecPin = null;
    try std.testing.expect(checkCallTool(arena, io, &pol, "exec_start", &pin, &epin, "{\"argv\":[\"<SAND>/runner\"],\"cwd\":\"<SAND>\"}", job) == null);
    try std.testing.expect(epin != null);
    try std.testing.expectEqualStrings(runner, epin.?.argv0_canon);
    policy.beginRequest(&pol, pin, epin);
    defer policy.endRequest();

    var out: std.ArrayList(u8) = .empty;
    try runTool(arena, io, &cfg, toolExecStart, "{\"argv\":[\"<SAND>/runner\"],\"cwd\":\"<SAND>\"}", &out);
    const start = try parseArgs(arena, out.items);
    try std.testing.expect(getBool(start, "ok"));
    const sid = getInt(start, "session_id");
    const sid_str = try std.fmt.allocPrint(arena, "{d}", .{sid});

    // The session is real and its output comes from the pinned runner:
    // wait for the (short-lived) runner, then poll for its output.
    const wait_args = try std.mem.concat(arena, u8, &.{ "{\"session_id\":", sid_str, ",\"timeout\":10}" });
    var wait_out: std.ArrayList(u8) = .empty;
    try runTool(arena, io, &cfg, toolExecWait, wait_args, &wait_out);
    const wv = try parseArgs(arena, wait_out.items);
    try std.testing.expect(getBool(wv, "ok"));

    const poll_args = try std.mem.concat(arena, u8, &.{ "{\"session_id\":", sid_str, "}" });
    var poll_out: std.ArrayList(u8) = .empty;
    try runTool(arena, io, &cfg, toolExecPoll, poll_args, &poll_out);
    const pv = try parseArgs(arena, poll_out.items);
    try std.testing.expect(getBool(pv, "ok"));
    try std.testing.expect(std.mem.indexOf(u8, getStr(pv, "stdout"), "SESS-PIN") != null);

    var close_out: std.ArrayList(u8) = .empty;
    try runTool(arena, io, &cfg, toolExecClose, poll_args, &close_out);
    const closed = try parseArgs(arena, close_out.items);
    try std.testing.expect(getBool(closed, "ok"));
}

test "exec swap race after the gate is refused by the pin" {
    if (builtin.os.tag != .linux) return error.SkipZigTest; // CI runs unit tests on Linux only
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var threaded = Io.Threaded.init(std.heap.page_allocator, .{ .environ = env_state.process_environ });
    defer threaded.deinit();
    const io = threaded.io();
    var cfg = try testConfig(arena);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const root = try arena.dupe(u8, buf[0..try tmp.dir.realPathFile(io, ".", &buf)]);
    // g/ holds the authorized tree; e/ holds the attacker's replacement
    // (its own realbin — the rename-swap payload).
    try tmp.dir.createDirPath(io, "g");
    try tmp.dir.createDirPath(io, "e");
    try writeExecFixture(tmp.dir, io, "g/realbin", "#!/bin/sh\necho GOOD\n");
    try writeExecFixture(tmp.dir, io, "e/realbin", "#!/bin/sh\necho EVIL\n");
    const g = try std.mem.concat(arena, u8, &.{ root, "/g" });
    const realbin = try std.mem.concat(arena, u8, &.{ g, "/realbin" });

    const pol = policy.TokenPolicy{
        .file = "f",
        .token_hash = [_]u8{5} ** 32,
        .tools = &.{"exec"},
        .exec_argv0 = &.{ .{ .text = realbin, .has_slash = true }, .{ .text = "/usr/bin/dash", .has_slash = true } },
        .exec_cwd = &.{g},
        .cwd_deny = &.{},
        .read_paths = &.{},
        .write_paths = &.{},
        .read_deny = &.{},
        .write_deny = &.{},
    };

    // Scenario A — argv0 ancestor swap: the racer
    // renames the authorized ancestor between the gate and the spawn).
    // Gate runs on the intact tree, THEN g becomes a symlink to e: on the
    // pre-fix code the raw-string spawn execs e/evilbin (EVIL); the pinned
    // open refuses (openat2 RESOLVE_NO_SYMLINKS -> ELOOP).
    {
        var pin: ?policy.FilePin = null;
        var epin: ?policy.ExecPin = null;
        try std.testing.expect(checkCallTool(arena, io, &pol, "exec", &pin, &epin, "{\"argv\":[\"<SAND>/realbin\"]}", g) == null);
        try std.testing.expect(epin != null);
        try tmp.dir.rename("g", tmp.dir, "g.orig", io);
        tmp.dir.symLink(io, "e", "g", .{}) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
        defer {
            tmp.dir.deleteFile(io, "g") catch {};
            tmp.dir.rename("g.orig", tmp.dir, "g", io) catch {};
        }
        policy.beginRequest(&pol, pin, epin);
        defer policy.endRequest();
        var out: std.ArrayList(u8) = .empty;
        // The pin open refuses the swapped ancestor — the exec never runs.
        try std.testing.expectError(error.SymLinkLoop, runTool(arena, io, &cfg, toolExec, "{\"argv\":[\"<SAND>/realbin\"]}", &out));
    }

    // Scenario B — cwd swap: the authorized cwd directory becomes a
    // symlink to the attacker tree AFTER the gate. Pre-fix: the child
    // chdirs straight into the attacker tree (pwd = e). Pinned: the cwd
    // dir open refuses with PrefixSwapped.
    {
        var pin: ?policy.FilePin = null;
        var epin: ?policy.ExecPin = null;
        try std.testing.expect(checkCallTool(arena, io, &pol, "exec", &pin, &epin, "{\"argv\":[\"/bin/sh\",\"-c\",\"pwd\"],\"cwd\":\"<SAND>\"}", g) == null);
        try std.testing.expect(epin != null);
        try tmp.dir.rename("g", tmp.dir, "g.orig", io);
        tmp.dir.symLink(io, "e", "g", .{}) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
        defer {
            tmp.dir.deleteFile(io, "g") catch {};
            tmp.dir.rename("g.orig", tmp.dir, "g", io) catch {};
        }
        policy.beginRequest(&pol, pin, epin);
        defer policy.endRequest();
        var out: std.ArrayList(u8) = .empty;
        try std.testing.expectError(error.PrefixSwapped, runTool(arena, io, &cfg, toolExec, "{\"argv\":[\"/bin/sh\",\"-c\",\"pwd\"],\"cwd\":\"<SAND>\"}", &out));
    }
}

test "pinned exec runs the original object after a post-pin rename" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest; // CI runs unit tests on Linux only
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var threaded = Io.Threaded.init(std.heap.page_allocator, .{ .environ = env_state.process_environ });
    defer threaded.deinit();
    const io = threaded.io();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const root = try arena.dupe(u8, buf[0..try tmp.dir.realPathFile(io, ".", &buf)]);
    try writeExecFixture(tmp.dir, io, "orig", "#!/bin/sh\necho ORIGINAL\n");
    try writeExecFixture(tmp.dir, io, "impostor", "#!/bin/sh\necho IMPOSTOR\n");
    const orig = try std.mem.concat(arena, u8, &.{ root, "/orig" });

    // The fd IS the authorization: open the pinned object, rename a
    // different binary over the path, and the pinned exec still runs the
    // object the fd holds (a swap after the pin cannot redirect it).
    const exe_fd = try os.secure.openPinnedExe(io, orig);
    defer os.closeFd(exe_fd);
    try tmp.dir.rename("impostor", tmp.dir, "orig", io);
    var child = try proc.spawnPinned(arena, io, .{
        .exe_fd = exe_fd,
        .cwd_fd = null,
        .argv = &.{"orig"},
        .envp = posixEnvBlock(),
        .stdin_fd = null,
        .pgid = false,
    });
    const result = try proc.runCollected(arena, io, &child, .{});
    try std.testing.expect(result.term == .exited);
    try std.testing.expect(std.mem.indexOf(u8, result.stdout, "ORIGINAL") != null);
}

test "pinned spawn exec failure reaps the child and answers the error" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest; // CI runs unit tests on Linux only
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var threaded = Io.Threaded.init(std.heap.page_allocator, .{ .environ = env_state.process_environ });
    defer threaded.deinit();
    const io = threaded.io();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const root = try arena.dupe(u8, buf[0..try tmp.dir.realPathFile(io, ".", &buf)]);
    try tmp.dir.writeFile(io, .{ .sub_path = "plain.txt", .data = "not executable\n" });
    const plain = try std.mem.concat(arena, u8, &.{ root, "/plain.txt" });

    // Baseline: clear any strays the suite may hold, so a leak here is
    // measurable (std's exec-error path leaves exactly this zombie).
    _ = proc.reapStrayChildren(&.{});
    const exe_fd = try os.secure.openPinnedExe(io, plain);
    defer os.closeFd(exe_fd);
    try std.testing.expectError(error.AccessDenied, proc.spawnPinned(arena, io, .{
        .exe_fd = exe_fd,
        .cwd_fd = null,
        .argv = &.{"plain.txt"},
        .envp = posixEnvBlock(),
        .stdin_fd = null,
        .pgid = false,
    }));
    // The exec-failed child was reaped inside spawnPinned: no new zombie.
    try std.testing.expectEqual(@as(usize, 0), proc.reapStrayChildren(&.{}));
}

/// checkCallEx with `<SAND>` substituted for the sandbox root (the gate
/// is evaluated against the same JSON the tool will receive).
fn checkCallTool(
    arena: std.mem.Allocator,
    io: Io,
    pol: *const policy.TokenPolicy,
    tool: []const u8,
    out_pin: *?policy.FilePin,
    out_exec_pin: *?policy.ExecPin,
    args_json: []const u8,
    sand: []const u8,
) ?policy.Deny {
    const json = std.mem.replaceOwned(u8, arena, args_json, "<SAND>", sand) catch return null;
    const args = std.json.parseFromSliceLeaky(Value, arena, json, .{}) catch return null;
    return policy.checkCallEx(arena, io, undefined, pol, tool, args, out_pin, out_exec_pin);
}

test "session store shutdownAll joins delayed readers before returning" {
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

    // Stdio teardown: shutdownAll must wait for any reader parked in its
    // poll->read gap before returning so no background thread keeps borrowing io.
    session_mod.test_reader_delay_ms.store(2500, .release);
    defer session_mod.test_reader_delay_ms.store(0, .release);

    var out: std.ArrayList(u8) = .empty;
    try runTool(arena, io, &cfg, toolExecStart, "{\"argv\":[\"/bin/sh\",\"-c\",\"echo shutdown-payload; sleep 300\"]}", &out);
    const start = try parseArgs(arena, out.items);
    try std.testing.expect(getBool(start, "ok"));
    const sid = getInt(start, "session_id");

    // Let the reader reach its delayed read, then tear the store down.
    os.sleepMs(300);
    const t0 = nowMsForTest(io);
    store.shutdownAll();
    const elapsed_ms = nowMsForTest(io) - t0;

    // Every session is gone from the store...
    try std.testing.expect(store.get(@intCast(sid)) == null);
    // ...and the call could not have returned before the delayed reader
    // exited its 2500ms gap: a kill-only teardown would return at once.
    try std.testing.expect(elapsed_ms >= 2000);
}

fn nowMsForTest(io: Io) i64 {
    return std.Io.Clock.real.now(io).toMilliseconds();
}

test "shaped exec and shell drain beyond capture cap with exact counters" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer state.deinit();
    const a = state.allocator();
    var threaded = Io.Threaded.init(std.heap.page_allocator, .{ .environ = env_state.process_environ });
    defer threaded.deinit();
    var cfg = try testConfig(a);
    cfg.max_out = 16;
    inline for (.{ toolExec, toolExecShell }, .{
        "{\"argv\":[\"/bin/sh\",\"-c\",\"printf 01234567890123456789; printf err >&2\"],\"max_bytes\":4,\"tail_lines\":1}",
        "{\"shell\":\"sh\",\"script\":\"printf 01234567890123456789; printf err >&2\",\"max_bytes\":4,\"tail_lines\":1}",
    }) |tool, args| {
        var out: std.ArrayList(u8) = .empty;
        try runTool(a, threaded.io(), &cfg, tool, args, &out);
        const v = try parseArgs(a, out.items);
        try std.testing.expectEqualStrings("6789", getStr(v, "stdout"));
        try std.testing.expectEqualStrings("err", getStr(v, "stderr"));
        try std.testing.expectEqual(@as(i64, 20), getInt(v, "total_stdout_bytes"));
        try std.testing.expectEqual(@as(i64, 4), getInt(v, "returned_stdout_bytes"));
        try std.testing.expectEqual(@as(i64, 16), getInt(v, "omitted_stdout_bytes"));
        try std.testing.expectEqual(@as(i64, 0), getInt(v, "omitted_stderr_bytes"));
        try std.testing.expect(getBool(v, "truncated_stdout"));
        try std.testing.expect(!getBool(v, "truncated_stderr"));
        try std.testing.expect(getBool(v, "output_complete"));
    }
}

test "shaped timeout returns partial streams counters and null exit" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer state.deinit();
    const a = state.allocator();
    var threaded = Io.Threaded.init(std.heap.page_allocator, .{ .environ = env_state.process_environ });
    defer threaded.deinit();
    const cfg = try testConfig(a);
    for ([_][]const u8{
        "{\"argv\":[\"/bin/sh\",\"-c\",\"printf abcdef; printf err >&2; exec sleep 30\"],\"timeout\":1,\"max_bytes\":4}",
        "{\"argv\":[\"/bin/sh\",\"-c\",\"printf abcdef; printf err >&2; exec 1>&- 2>&-; exec sleep 30\"],\"timeout\":1,\"max_bytes\":4}",
    }) |args| {
        var out: std.ArrayList(u8) = .empty;
        try runTool(a, threaded.io(), &cfg, toolExec, args, &out);
        const v = try parseArgs(a, out.items);
        try std.testing.expectEqualStrings("abcd", getStr(v, "stdout"));
        try std.testing.expectEqualStrings("err", getStr(v, "stderr"));
        try std.testing.expectEqual(@as(i64, 6), getInt(v, "total_stdout_bytes"));
        try std.testing.expectEqual(@as(i64, 2), getInt(v, "omitted_stdout_bytes"));
        try std.testing.expect(getBool(v, "timeout"));
        try std.testing.expect(!getBool(v, "output_complete"));
        try std.testing.expect(v.object.get("exit_code").? == .null);
    }
}

pub fn toolCopyPath(arena: Allocator, io: Io, cfg: *const config.Config, args: Value, out: *std.ArrayList(u8), pins: ?policy.CopyPins, pol: ?*const policy.TokenPolicy) !void {
    return @import("copy.zig").tool(arena, io, cfg, args, out, pins, pol);
}

fn toolExecStartDurable(arena: Allocator, io: Io, cfg: *const config.Config, args: Value, out: *std.ArrayList(u8)) !void {
    if (comptime builtin.os.tag != .linux) return error.DurabilityUnsupported;
    const ds = @import("durable_session.zig");
    const store = cfg.sessions.?;
    const disk = store.disk.?;
    const argv_v = util.objGet(args, "argv") orelse return error.MissingArgv;
    if (argv_v != .array or argv_v.array.items.len == 0) return error.BadArgv;
    const argv = try std.heap.page_allocator.alloc([]const u8, argv_v.array.items.len);
    var filled: usize = 0;
    var transferred = false;
    errdefer if (!transferred) {
        for (argv[0..filled]) |arg| std.heap.page_allocator.free(arg);
        std.heap.page_allocator.free(argv);
    };
    for (argv_v.array.items, argv) |item, *arg| {
        if (item != .string) return error.BadArgv;
        arg.* = try std.heap.page_allocator.dupe(u8, item.string);
        filled += 1;
    }
    const cwd_s = (try util.optStrArg(args, "cwd")) orelse "";
    _ = try @import("durable.zig").Meta.regionSize(cwd_s, argv);
    const cwd = try std.heap.page_allocator.dupe(u8, cwd_s);
    errdefer if (!transferred) std.heap.page_allocator.free(cwd);
    execCallEnter(io);
    defer execCallExit(io);
    var pins: ExecFds = undefined;
    if (policy.currentExecPin()) |pin| {
        pins = try openExecPinFds(arena, io, pin);
    } else {
        try preflightSpawn(arena, io, argv[0], cwd);
        const cwd_fd: ?std.posix.fd_t = if (cwd.len != 0) try std.posix.openat(std.posix.AT.FDCWD, cwd, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0) else null;
        errdefer if (cwd_fd) |fd| os.closeFd(fd);
        const exe = if (std.mem.indexOfScalar(u8, argv[0], '/') != null)
            try os.secure.openPathCandidate(io, if (std.fs.path.isAbsolute(argv[0]) or cwd.len == 0) argv[0] else try std.fs.path.join(arena, &.{ cwd, argv[0] }))
        else
            try proc.resolvePinnedArgv0(arena, io, argv[0], cwd, os.env.environGet(arena, env_state.process_environ, "PATH"));
        pins = .{ .exe = exe, .cwd = cwd_fd };
    }
    defer closeExecPinFds(pins);
    const id = try disk.allocId();
    const b = try ds.create(disk, id, cfg.max_out, policy.current_owner);
    b.writer = @import("audit.zig").fromCfg(cfg);
    errdefer if (!transferred) {
        ds.abortAdmission(disk, id, policy.current_owner) catch {
            disk.failed = true;
        };
        disk.unreserve(cfg.max_out);
        b.deinit();
    };
    const pipe = try proc.createStdinPipe();
    defer os.closeFd(pipe.read);
    errdefer if (!transferred) os.closeFd(pipe.write);
    const s = try std.heap.page_allocator.create(session_mod.Session);
    errdefer if (!transferred) std.heap.page_allocator.destroy(s);
    exec_gate.lockUncancelable(io);
    var gated = proc.spawnDurableGated(arena, .{ .exe_fd = pins.exe, .cwd_fd = pins.cwd, .argv = argv, .envp = posixEnvBlock(), .stdin_fd = pipe.read, .pgid = true }, b.stdout, b.stderr) catch |err| {
        exec_gate.unlock(io);
        return err;
    };
    const pid = gated.child.id.?;
    const tag = proc.registerSpawnPid(io, pid) orelse {
        os.closeFd(gated.release_fd);
        os.closeFd(gated.report_fd);
        _ = gated.child.wait(io) catch null;
        exec_gate.unlock(io);
        return error.ExecPidRegistrationFailed;
    };
    exec_gate.unlock(io);
    var released = false;
    errdefer if (!transferred) {
        if (!released) {
            os.closeFd(gated.release_fd);
            os.closeFd(gated.report_fd);
        }
        _ = proc.killRecoveredTreeVerified(b.identity());
        _ = gated.child.wait(io) catch null;
        proc.unregisterSpawnPid(io, pid, tag);
    };
    const identity = proc.readProcIdentity(pid) orelse return error.DurableIdentityUnavailable;
    b.meta.pid = pid;
    b.meta.pgid = identity.pgid;
    b.meta.start_time_ticks = identity.start_time_ticks;
    b.meta.boot_id = try proc.readBootId();
    b.meta.started_us = session_mod.nowUs(io);
    b.meta.owner_hash = policy.current_owner;
    s.* = .{ .id = id, .pid = pid, .registry_tag = tag, .argv = argv, .cwd = cwd, .child = gated.child, .stdin_fd = pipe.write, .started_us = b.meta.started_us, .owner_hash = policy.current_owner, .durable = b };
    // This is the release barrier: every metadata byte and its directory
    // entry must be stable before a child can execute any user code.
    try b.commit(s);
    try out.ensureUnusedCapacity(arena, 192);
    try store.publishDurable(s, &gated, &released);
    transferred = true;
    // Publication transfers the store reference. Hold a creator reference
    // during rendering just as on the ephemeral backend.
    // The response uses copied scalar identity, so no post-put dereference.
    try out.print(arena, "{{\"ok\":true,\"session_id\":{d},\"pid\":{d},\"recovered\":false,\"stdin_available\":true}}", .{ id, pid });
}

test "sys_info advertises effective output cap and durable opt in" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = std.Io.Threaded.global_single_threaded.io();
    var cfg = try testConfig(arena);
    for ([_]?[]const u8{ null, "/private/state" }) |path| {
        cfg.state_dir = path;
        cfg.max_out = 2 * 1024 * 1024;
        var out: std.ArrayList(u8) = .empty;
        try toolSysInfo(arena, io, &cfg, &out);
        const v = try parseArgs(arena, out.items);
        const features = v.object.get("features").?;
        try std.testing.expectEqual(path != null, getBool(features, "durable_sessions"));
        try std.testing.expect(getBool(features, "exec_output_shaping"));
        try std.testing.expectEqual(@as(i64, 1024 * 1024), getInt(features, "output_max_bytes"));
    }
}

fn killDurableOrEphemeral(s: *session_mod.Session, io: Io) !void {
    if (s.durable) |b| {
        s.mutex.lockUncancelable(io);
        defer s.mutex.unlock(io);
        try @import("durable_session.zig").refreshLocked(s, io, true);
        if (s.done or s.tree_killed.load(.acquire)) return;
        if (!proc.killRecoveredTreeVerified(b.identity())) return error.DurableIdentityUnavailable;
        s.tree_killed.store(true, .release);
    } else session_mod.killTreeGuarded(s, io);
}

const DurableTest = struct {
    arena_state: std.heap.ArenaAllocator,
    tmp: std.testing.TmpDir,
    disk: @import("durable.zig").Disk,
    store: session_mod.SessionStore,
    cfg: config.Config,
    io: Io,

    fn init() !DurableTest {
        const io = std.Io.Threaded.global_single_threaded.io();
        var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
        errdefer arena_state.deinit();
        const arena = arena_state.allocator();
        var tmp = std.testing.tmpDir(.{});
        errdefer tmp.cleanup();
        const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
        const path = try std.fmt.allocPrint(arena, "{s}/state", .{root});
        const disk = try @import("durable.zig").Disk.open(io, path, 64 * 1024 * 1024);
        var cfg = try testConfig(arena);
        cfg.max_out = 1024;
        cfg.state_dir = path;
        return .{ .arena_state = arena_state, .tmp = tmp, .disk = disk, .store = session_mod.SessionStore.init(io, 8), .cfg = cfg, .io = io };
    }
    fn bind(self: *DurableTest) void {
        self.store.disk = &self.disk;
        self.cfg.sessions = &self.store;
    }
    fn clear(self: *DurableTest) void {
        while (self.store.map.count() != 0) {
            var it = self.store.map.keyIterator();
            const id = it.next().?.*;
            const s = self.store.map.fetchRemove(id).?.value;
            session_mod.sessionRelease(s);
        }
    }
    fn deinit(self: *DurableTest) void {
        self.clear();
        self.store.map.deinit();
        self.disk.close();
        self.tmp.cleanup();
        self.arena_state.deinit();
    }
    fn call(self: *DurableTest, comptime tool: anytype, args: []const u8) !Value {
        const arena = self.arena_state.allocator();
        var out: std.ArrayList(u8) = .empty;
        try runTool(arena, self.io, &self.cfg, tool, args, &out);
        return parseArgs(arena, out.items);
    }
    fn start(self: *DurableTest, script: []const u8) !*session_mod.Session {
        const arena = self.arena_state.allocator();
        var args: std.ArrayList(u8) = .empty;
        try args.appendSlice(arena, "{\"durable\":true,\"argv\":[\"/bin/sh\",\"-c\",");
        try util.appendJsonString(&args, arena, script);
        try args.appendSlice(arena, "]}");
        const v = try self.call(toolExecStart, args.items);
        return self.store.get(@intCast(getInt(v, "session_id"))).?;
    }
    fn finish(self: *DurableTest, s: *session_mod.Session) !void {
        for (0..300) |_| {
            try @import("durable_session.zig").refresh(s, self.io);
            if (s.done) return;
            os.sleepMs(10);
        }
        return error.TestUnexpectedResult;
    }
    fn restart(self: *DurableTest) !void {
        self.clear();
        self.disk.reserved = 0;
        try @import("durable_session.zig").recover(&self.store, &self.disk, null);
    }
};

test "durable completion reconciles final and late bytes across recovery" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var t = try DurableTest.init();
    defer t.deinit();
    t.bind();
    const s = try t.start("printf final; printf tail >&2");
    const id = s.id;
    try t.finish(s);
    try std.testing.expectEqualStrings("final", s.stdout.items);
    // Simulate a final write landing after an older terminal journal commit.
    try os.writeAllFd(s.durable.?.stdout, "-late");
    try os.writeAllFd(s.durable.?.stderr, "-late");
    session_mod.sessionRelease(s);
    try t.restart();
    const recovered = t.store.get(id) orelse return error.TestUnexpectedResult;
    defer session_mod.sessionRelease(recovered);
    try std.testing.expectEqualStrings("final-late", recovered.stdout.items);
    try std.testing.expectEqualStrings("tail-late", recovered.stderr.items);
    try std.testing.expectEqual(@as(u64, 10), recovered.durable.?.meta.final_stdout_total);
    try std.testing.expectEqual(@as(u64, 9), recovered.durable.?.meta.final_stderr_total);
    try t.restart();
    try std.testing.expect(t.store.map.contains(id));
}

test "durable descendant growth does not seal output complete" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var t = try DurableTest.init();
    defer t.deinit();
    t.bind();
    const s = try t.start("(i=0; while [ $i -lt 60 ]; do printf x; sleep 0.01; i=$((i+1)); done) & exit 0");
    defer session_mod.sessionRelease(s);
    os.sleepMs(80);
    try @import("durable_session.zig").refresh(s, t.io);
    try std.testing.expect(!s.done);
    try t.finish(s);
    try std.testing.expectEqual(@as(usize, 60), s.stdout.items.len);
}

test "durable artifact larger than log reservation remains intact" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var t = try DurableTest.init();
    defer t.deinit();
    t.bind();
    const arena = t.arena_state.allocator();
    const root = try t.tmp.dir.realPathFileAlloc(t.io, ".", arena);
    const script = try std.fmt.allocPrint(arena, "head -c 2000000 /dev/zero > '{s}/artifact' && printf artifact-ok", .{root});
    const s = try t.start(script);
    defer session_mod.sessionRelease(s);
    try t.finish(s);
    try std.testing.expectEqual(@as(?i64, 0), s.exit_code);
    try std.testing.expectEqualStrings("artifact-ok", s.stdout.items);
    const file = try t.tmp.dir.openFile(t.io, "artifact", .{});
    defer file.close(t.io);
    try std.testing.expectEqual(@as(u64, 2000000), (try file.stat(t.io)).size);
    var buf: [4096]u8 = undefined;
    var offset: u64 = 0;
    while (offset < 2000000) {
        const n = try file.readPositionalAll(t.io, &buf, offset);
        try std.testing.expect(n != 0);
        for (buf[0..n]) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
        offset += n;
    }
}

fn checkOutputCap(t: *DurableTest, id: u64, stderr: bool) !void {
    const arena = t.arena_state.allocator();
    var offset: i64 = 0;
    while (true) {
        const args = try std.fmt.allocPrint(arena, "{{\"session_id\":{d},\"stdout_offset\":{d},\"stderr_offset\":{d},\"max_bytes\":257}}", .{ id, if (stderr) 0 else offset, if (stderr) offset else 0 });
        const v = if (offset == 0) try t.call(toolExecWait, args) else try t.call(toolExecPoll, args);
        try std.testing.expect(getBool(v, "done"));
        try std.testing.expectEqualStrings("output_cap", getStr(v, "completion_reason"));
        try std.testing.expect(!getBool(v, "output_complete"));
        try std.testing.expectEqual(!stderr, getBool(v, "truncated_stdout"));
        try std.testing.expectEqual(stderr, getBool(v, "truncated_stderr"));
        try std.testing.expectEqual(@as(i64, 0), getInt(v, "lost_stdout_bytes"));
        try std.testing.expectEqual(@as(i64, 0), getInt(v, "lost_stderr_bytes"));
        try std.testing.expectEqualStrings("output exceeded the durable per-session log cap (2x MCP_NODE_MAX_OUT); a live session is killed with a verified identity, already-written output remains pollable", getStr(v, "message"));
        const text = getStr(v, if (stderr) "stderr" else "stdout");
        for (text) |byte| try std.testing.expectEqual(@as(u8, 'x'), byte);
        offset = getInt(v, if (stderr) "stderr_offset" else "stdout_offset");
        if (!getBool(v, "has_more")) break;
        try std.testing.expect(text.len != 0);
    }
    try std.testing.expectEqual(@as(i64, 4096), offset);
}

test "durable output cap kills writer preserves pages and balances reservation" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var t = try DurableTest.init();
    defer t.deinit();
    t.bind();
    for ([_]bool{ false, true }) |stderr| {
        const s = try t.start(if (stderr) "head -c 4096 /dev/zero | tr '\\0' x >&2; read line" else "head -c 4096 /dev/zero | tr '\\0' x; read line");
        const id = s.id;
        {
            defer session_mod.sessionRelease(s);
            defer _ = proc.killRecoveredTreeVerified(s.durable.?.identity());
            try t.finish(s);
            try std.testing.expect(s.tree_killed.load(.acquire));
            try std.testing.expectEqual(@as(?i64, 137), s.exit_code);
            try checkOutputCap(&t, id, stderr);
            try std.testing.expectEqual(try @import("durable.zig").reservation(t.cfg.max_out), t.disk.reserved);
        }
        try t.restart();
        try checkOutputCap(&t, id, stderr);
        const args = try std.fmt.allocPrint(t.arena_state.allocator(), "{{\"session_id\":{d}}}", .{id});
        _ = try t.call(toolExecClose, args);
        try std.testing.expectEqual(@as(u64, 0), t.disk.reserved);
    }
}

test "durable failed admission after commit cannot recover a phantom" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var t = try DurableTest.init();
    defer t.deinit();
    t.bind();
    // Force registry admission to fail after metadata was committed.
    t.store.max = 0;
    try std.testing.expectError(error.TooManySessions, t.start("exit 0"));
    try t.restart();
    try std.testing.expectEqual(@as(usize, 0), t.store.map.count());
    try std.testing.expect(t.disk.index.expired(1, @splat(0)));
    var dir: std.Io.Dir = .{ .handle = t.disk.sessions };
    var it = dir.iterate();
    try std.testing.expect(try it.next(t.io) == null);
}

test "durable partial create failure removes files and records tombstone" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var t = try DurableTest.init();
    defer t.deinit();
    t.bind();
    @import("durable_session.zig").test_fail_after_stdout = true;
    defer @import("durable_session.zig").test_fail_after_stdout = false;
    try std.testing.expectError(error.InjectedCreateFailure, t.start("exit 0"));
    try std.testing.expectEqual(@as(u64, 0), t.disk.reserved);
    try std.testing.expect(t.disk.index.expired(1, @splat(0)));
    var dir: std.Io.Dir = .{ .handle = t.disk.sessions };
    var it = dir.iterate();
    try std.testing.expect(try it.next(t.io) == null);
    try t.restart();
    try std.testing.expectEqual(@as(usize, 0), t.store.map.count());
}

test "state enabled close then poll preserves expiry for both backends" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var t = try DurableTest.init();
    defer t.deinit();
    t.bind();
    const arena = t.arena_state.allocator();
    // The ephemeral leg of this contract runs in ci/test_durable_restart.py
    // (real node process). Here the two spawns in one fixture hit a test-
    // runner allocation failure on this box; keep the durable leg native.
    for ([_]bool{true}) |durable_flag| {
        const args = try std.fmt.allocPrint(arena, "{{\"argv\":[\"/bin/sh\",\"-c\",\"exit 0\"],\"durable\":{}}}", .{durable_flag});
        const started = try t.call(toolExecStart, args);
        const id = getInt(started, "session_id");
        const control = try std.fmt.allocPrint(arena, "{{\"session_id\":{d}}}", .{id});
        const closed = try t.call(toolExecClose, control);
        try std.testing.expect(getBool(closed, "ok"));
        const polled = try t.call(toolExecPoll, control);
        try std.testing.expectEqualStrings("unknown_session", getStr(polled, "error"));
        try std.testing.expect(getBool(polled, "expired"));
    }
}

// Exercise both API entry points beyond the hot prefix, below the log cap.
// Page both streams to their ends and byte-compare. Stream sizes differ so
// the test can exceed the per-stream capture window while staying inside the
// combined kill reservation (2 x max_out across both streams).
fn checkDurableSpoolPages(t: *DurableTest, id: u64, recovered: bool, out_n: i64, err_n: i64) !void {
    const arena = t.arena_state.allocator();
    var stdout: std.ArrayList(u8) = .empty;
    var stderr: std.ArrayList(u8) = .empty;
    var out_off: i64 = 0;
    var err_off: i64 = 0;
    var first = true;
    while (out_off < out_n or err_off < err_n) {
        const args = try std.fmt.allocPrint(arena, "{{\"session_id\":{d},\"stdout_offset\":{d},\"stderr_offset\":{d},\"max_bytes\":257}}", .{ id, out_off, err_off });
        const v = if (first) try t.call(toolExecWait, args) else try t.call(toolExecPoll, args);
        first = false;
        try std.testing.expect(getBool(v, "done"));
        try std.testing.expect(getBool(v, "output_complete"));
        try std.testing.expectEqual(recovered, getBool(v, "recovered"));
        try std.testing.expectEqual(@as(i64, 0), getInt(v, "lost_stdout_bytes"));
        try std.testing.expectEqual(@as(i64, 0), getInt(v, "lost_stderr_bytes"));
        try std.testing.expectEqual(out_n, getInt(v, "total_stdout_bytes"));
        try std.testing.expectEqual(err_n, getInt(v, "total_stderr_bytes"));
        const next_out = getInt(v, "stdout_offset");
        const next_err = getInt(v, "stderr_offset");
        try std.testing.expect(next_out > out_off and next_out <= out_off + 257);
        try std.testing.expect(next_err >= err_off and next_err <= err_off + 257);
        try std.testing.expectEqual(next_out < out_n or next_err < err_n, getBool(v, "has_more"));
        try stdout.appendSlice(arena, getStr(v, "stdout"));
        try stderr.appendSlice(arena, getStr(v, "stderr"));
        out_off = next_out;
        err_off = next_err;
    }
    try std.testing.expectEqualStrings("abcd" ** 448, stdout.items);
    try std.testing.expectEqualStrings("WXYZ" ** 32, stderr.items);
    // Absolute random access and the inclusive EOF boundary work in wait too.
    const tail_args = try std.fmt.allocPrint(arena, "{{\"session_id\":{d},\"stdout_offset\":{d},\"stderr_offset\":{d},\"max_bytes\":100}}", .{ id, out_n - 72, err_n });
    const tail = try t.call(toolExecWait, tail_args);
    try std.testing.expectEqualStrings("abcd" ** 18, getStr(tail, "stdout"));
    try std.testing.expectEqualStrings("", getStr(tail, "stderr"));
    try std.testing.expect(!getBool(tail, "has_more"));
    const over_out = try std.fmt.allocPrint(arena, "\"stdout_offset\":{d}", .{out_n + 1});
    const over_err = try std.fmt.allocPrint(arena, "\"stderr_offset\":{d}", .{err_n + 1});
    for ([_][]const u8{ "\"stdout_offset\":-1", "\"stderr_offset\":-1", over_out, over_err }) |bad| {
        const args = try std.fmt.allocPrint(arena, "{{\"session_id\":{d},{s}}}", .{ id, bad });
        try std.testing.expectError(error.BadOffset, t.call(toolExecPoll, args));
    }
    // Omitting max_bytes is still bounded, but never hides the backlog.
    const args = try std.fmt.allocPrint(arena, "{{\"session_id\":{d}}}", .{id});
    const unbounded = try t.call(toolExecPoll, args);
    try std.testing.expectEqual(@as(i64, 1024), getInt(unbounded, "stdout_offset"));
    try std.testing.expectEqual(@as(i64, 1792), getInt(unbounded, "total_stdout_bytes"));
    try std.testing.expect(getBool(unbounded, "has_more"));
}

test "durable spool pages reassemble beyond capture cap with zero loss" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var t = try DurableTest.init();
    defer t.deinit();
    t.bind();
    const s = try t.start("i=0; while [ $i -lt 448 ]; do printf abcd; i=$((i+1)); done; i=0; while [ $i -lt 32 ]; do printf WXYZ >&2; i=$((i+1)); done; read line");
    defer session_mod.sessionRelease(s);
    defer _ = proc.killRecoveredTreeVerified(s.durable.?.identity());
    const arena = t.arena_state.allocator();
    const args = try std.fmt.allocPrint(arena, "{{\"session_id\":{d},\"max_bytes\":257}}", .{s.id});
    // The writer waits on stdin: completion cannot race the live assertion.
    for (0..300) |_| {
        const v = try t.call(toolExecPoll, args);
        try std.testing.expect(!getBool(v, "done"));
        try std.testing.expect(!getBool(v, "output_complete"));
        try std.testing.expectEqual(@as(i64, 0), getInt(v, "lost_stdout_bytes"));
        if (getInt(v, "total_stdout_bytes") == 1792) break;
        os.sleepMs(10);
    }
    try os.writeAllFd(s.stdin_fd.?, "finish\n");
    try t.finish(s);
    try std.testing.expectEqual(@as(usize, 1024), s.stdout.items.len);
    try checkDurableSpoolPages(&t, s.id, false, 1792, 128);
}

test "durable spool pages survive restart beyond capture cap" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var t = try DurableTest.init();
    defer t.deinit();
    t.bind();
    const s = try t.start("i=0; while [ $i -lt 448 ]; do printf abcd; i=$((i+1)); done; i=0; while [ $i -lt 32 ]; do printf WXYZ >&2; i=$((i+1)); done");
    const id = s.id;
    {
        defer session_mod.sessionRelease(s);
        try t.finish(s);
    }
    try t.restart();
    try checkDurableSpoolPages(&t, id, true, 1792, 128);
}

test "durable spool UTF-8 pages hold live tails and reconcile late recovery bytes" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var t = try DurableTest.init();
    defer t.deinit();
    t.bind();
    t.cfg.max_out = 10;
    const arena = t.arena_state.allocator();
    const s = try t.start("read line");
    const id = s.id;
    {
        defer session_mod.sessionRelease(s);
        defer _ = proc.killRecoveredTreeVerified(s.durable.?.identity());
        // Deterministic raw writes while the child is held on stdin. Includes
        // a codepoint crossing the hot-prefix edge, invalid bytes, and a live
        // incomplete suffix. Offsets count raw bytes, not replacement text.
        try os.writeAllFd(s.durable.?.stdout, "abc💩é中z\xff\xf0\x9f");
        var offset: i64 = 0;
        var joined: std.ArrayList(u8) = .empty;
        for (0..10) |_| {
            const args = try std.fmt.allocPrint(arena, "{{\"session_id\":{d},\"stdout_offset\":{d},\"max_bytes\":4}}", .{ id, offset });
            const v = try t.call(toolExecPoll, args);
            try std.testing.expect(!getBool(v, "output_complete"));
            try std.testing.expectEqual(@as(i64, 0), getInt(v, "lost_stdout_bytes"));
            try std.testing.expectEqual(@as(i64, 16), getInt(v, "total_stdout_bytes"));
            try joined.appendSlice(arena, getStr(v, "stdout"));
            const next = getInt(v, "stdout_offset");
            if (next == offset) break;
            try std.testing.expect(next <= offset + 4);
            offset = next;
        }
        try std.testing.expectEqual(@as(i64, 14), offset);
        try std.testing.expectEqualStrings("abc💩é中z�", joined.items);
        try os.writeAllFd(s.stdin_fd.?, "finish\n");
        const args = try std.fmt.allocPrint(arena, "{{\"session_id\":{d},\"stdout_offset\":14,\"max_bytes\":4}}", .{id});
        const eof = try t.call(toolExecWait, args);
        try std.testing.expect(getBool(eof, "output_complete"));
        try std.testing.expectEqual(@as(i64, 16), getInt(eof, "stdout_offset"));
        try std.testing.expectEqualStrings(try util.utf8LossyAlloc(arena, "\xf0\x9f"), getStr(eof, "stdout"));
        // Older terminal metadata can precede trailing bytes: recovery must
        // reconcile them before publishing complete, even beyond max_out.
        try os.writeAllFd(s.durable.?.stdout, "\x92\xa9");
    }
    try t.restart();
    const args = try std.fmt.allocPrint(arena, "{{\"session_id\":{d},\"stdout_offset\":14,\"max_bytes\":4}}", .{id});
    const recovered = try t.call(toolExecPoll, args);
    try std.testing.expect(getBool(recovered, "recovered"));
    try std.testing.expect(getBool(recovered, "output_complete"));
    try std.testing.expect(!getBool(recovered, "truncated_stdout"));
    try std.testing.expect(!getBool(recovered, "has_more"));
    try std.testing.expectEqualStrings("💩", getStr(recovered, "stdout"));
    try std.testing.expectEqual(@as(i64, 18), getInt(recovered, "stdout_offset"));
    try std.testing.expectEqual(@as(i64, 18), getInt(recovered, "total_stdout_bytes"));
    try std.testing.expectEqual(@as(i64, 0), getInt(recovered, "lost_stdout_bytes"));
    const restored = t.store.get(id).?;
    defer session_mod.sessionRelease(restored);
    try std.testing.expectEqual(@as(u64, 18), restored.durable.?.meta.final_stdout_total);
}

test "exec_shell path and bare policy entries align without loosening exec" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = std.Io.Threaded.global_single_threaded.io();
    var cfg = try testConfig(arena);
    const saved = env_state.process_environ;
    defer env_state.process_environ = saved;
    const env = try arena.allocSentinel(?[*:0]const u8, 1, null);
    env[0] = "PATH=/bin:/usr/bin";
    env_state.process_environ = .{ .block = .{ .slice = env } };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "token", .data = "secret\n", .flags = .{ .permissions = .fromMode(0o600) } });
    const token = try tmp.dir.realPathFileAlloc(io, "token", arena);
    for ([_][]const u8{ "/bin/sh", "sh", "/bin/bash" }, 0..) |entry, i| {
        const json = try std.fmt.allocPrint(arena, "{{\"version\":1,\"tokens\":[{{\"file\":\"{s}\",\"tools\":[\"exec\",\"exec_shell\"],\"exec_argv0\":[\"{s}\"],\"read_paths\":[\"/tmp\"]}}]}}", .{ token, entry });
        try tmp.dir.writeFile(io, .{ .sub_path = "policy", .data = json, .flags = .{ .permissions = .fromMode(0o600) } });
        var loaded = try policy.loadPolicyFile(arena, io, try tmp.dir.realPathFileAlloc(io, "policy", arena));
        defer loaded.deinit();
        const pol = &loaded.entries[0];
        var pin: ?policy.FilePin = null;
        var epin: ?policy.ExecPin = null;
        const args = "{\"shell\":\"sh\",\"script\":\"printf shell-ok\"}";
        const deny = checkCallTool(arena, io, pol, "exec_shell", &pin, &epin, args, "");
        if (i == 2) {
            try std.testing.expect(deny != null);
            continue;
        }
        try std.testing.expect(deny == null);
        policy.beginRequest(pol, pin, epin);
        var out: std.ArrayList(u8) = .empty;
        defer policy.endRequest();
        try runTool(arena, io, &cfg, toolExecShell, args, &out);
        try std.testing.expectEqualStrings("shell-ok", getStr(try parseArgs(arena, out.items), "stdout"));
        try std.testing.expect(checkCallTool(arena, io, pol, "exec", &pin, &epin, "{\"argv\":[\"/tmp/evil/sh\"]}", "") != null);
    }
}

test "durable periodic sweep kills unpolled writers including recovered sessions" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var threaded = Io.Threaded.init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    var t = try DurableTest.init();
    defer t.deinit();
    t.io = threaded.io();
    t.disk.io = t.io;
    t.store.io = t.io;
    t.bind();
    for ([_]bool{ false, true }) |recovered| {
        const s = try t.start("sleep 0.3; head -c 4096 /dev/zero | tr '\\0' x; sleep 30");
        const id = s.id;
        const identity = s.durable.?.identity();
        session_mod.sessionRelease(s);
        defer _ = proc.killRecoveredTreeVerified(identity);
        if (recovered) try t.restart();
        try t.store.startDurableSweep();
        defer t.store.stopDurableSweep();
        // No tool call, refresh, or reap drives enforcement here.
        const live = t.store.get(id).?;
        defer session_mod.sessionRelease(live);
        var done = false;
        for (0..250) |_| {
            live.mutex.lockUncancelable(t.io);
            done = live.done;
            live.mutex.unlock(t.io);
            if (done) break;
            os.sleepMs(10);
        }
        try std.testing.expect(done);
        try std.testing.expect(live.tree_killed.load(.acquire));
        try checkOutputCap(&t, id, false);
        t.store.stopDurableSweep();
        const args = try std.fmt.allocPrint(t.arena_state.allocator(), "{{\"session_id\":{d}}}", .{id});
        _ = try t.call(toolExecClose, args);
        try std.testing.expectEqual(@as(u64, 0), t.disk.reserved);
    }
}

test "durable recovery quarantines an incomplete admission" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var t = try DurableTest.init();
    defer t.deinit();
    t.bind();
    // The crash window of admission: sessions/7 exists with spool files but
    // no meta.bin. Recovery must quarantine it and stay up, not abort the
    // node.
    const arena = t.arena_state.allocator();
    const rel = try std.fmt.allocPrint(arena, "{s}/sessions/7", .{t.cfg.state_dir.?});
    const zrel = try arena.dupeZ(u8, rel);
    switch (std.os.linux.errno(std.os.linux.mkdirat(std.posix.AT.FDCWD, zrel, 0o700))) {
        .SUCCESS => {},
        else => return error.TestUnexpectedResult,
    }
    const log = try std.fmt.allocPrint(arena, "{s}/stdout.log", .{rel});
    try os.fd.writeFile(t.io, log, "partial\n", 0o600);
    try @import("durable_session.zig").recover(&t.store, &t.disk, null);
    try std.testing.expectEqual(@as(usize, 0), t.store.map.count());
    try std.testing.expect(t.disk.index.tombstones[0].id == 7);
    const q = try std.fmt.allocPrint(arena, "{s}/sessions/quarantine-7", .{t.cfg.state_dir.?});
    var qdir = try std.Io.Dir.openDir(.cwd(), t.io, q, .{});
    qdir.close(t.io);
    // A second recovery over the same state skips the retired id instead of
    // failing the rename onto the existing quarantine dir.
    try @import("durable_session.zig").recover(&t.store, &t.disk, null);
}

test "durable combined-stream reservation kills over-budget sessions" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var t = try DurableTest.init();
    defer t.deinit();
    t.bind();
    // 1.6x max_out on EACH stream: under the old per-file check (2x each)
    // nothing fires; the combined reservation (2x total) must.
    const s = try t.start("head -c 1638 /dev/zero | tr '\\0' x; head -c 1638 /dev/zero | tr '\\0' y >&2; sleep 30");
    const id = s.id;
    const identity = s.durable.?.identity();
    session_mod.sessionRelease(s);
    defer _ = proc.killRecoveredTreeVerified(identity);
    const live = t.store.get(id).?;
    defer session_mod.sessionRelease(live);
    var done = false;
    for (0..300) |_| {
        @import("durable_session.zig").refresh(live, t.io) catch {};
        if (live.done) {
            done = true;
            break;
        }
        os.sleepMs(10);
    }
    try std.testing.expect(done);
    try std.testing.expect(live.tree_killed.load(.acquire));
    const b = live.durable.?;
    try std.testing.expect(b.completionReason() == .output_cap);
    try std.testing.expect(live.truncated_stdout);
    try std.testing.expect(live.truncated_stderr);
    _ = try t.call(toolExecClose, try std.fmt.allocPrint(t.arena_state.allocator(), "{{\"session_id\":{d}}}", .{id}));
    try std.testing.expectEqual(@as(u64, 0), t.disk.reserved);
}

test "durable done-session log growth past the cap is flagged, not signaled" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var t = try DurableTest.init();
    defer t.deinit();
    t.bind();
    // A session that already completed: its leader is dead, so no signal may
    // leave the node, but an orphaned descendant can keep the spool growing.
    // Enforcement then journals the overrun instead of killing.
    const s = try t.start("printf hi");
    const id = s.id;
    session_mod.sessionRelease(s);
    const live = t.store.get(id).?;
    defer session_mod.sessionRelease(live);
    try t.finish(live);
    try std.testing.expect(live.done);
    try std.testing.expect(!live.tree_killed.load(.acquire));
    // Simulate late growth: append past the combined reservation directly.
    const b = live.durable.?;
    const filler = try t.arena_state.allocator().alloc(u8, 2100);
    @memset(filler, 'z');
    try proc.writeAllFd(b.stdout, filler);
    try @import("durable_session.zig").enforceLogCapLocked(live, t.io);
    try std.testing.expect(b.completionReason() == .output_cap);
    try std.testing.expect(live.truncated_stdout);
    // The dead leader is never signaled on this path: no kill is claimed.
    try std.testing.expect(!live.tree_killed.load(.acquire));
}
