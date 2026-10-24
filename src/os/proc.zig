//! Process control layer.
//!
//! Owns every platform difference in the daemon's session/process machinery:
//!
//!   * `ProcessId` — an integer pid on every OS. Windows resolves it from
//!     the child HANDLE via NtQueryInformationProcess; it is display-only
//!     (exec JSON output), never a control token.
//!   * `JobField`/`no_job` — the per-session Windows Job Object handle
//!     (void on POSIX, where the process group is the tree unit).
//!   * `createStdinPipe`/`stdinFile` — the POSIX stdin wiring: a
//!     parent-owned pipe whose read end is handed to the child via
//!     `SpawnOptions.stdin = .file` (std dups it into the child), so
//!     `std.process.Child.stdin` stays null and `child.wait()` cleanup can
//!     never close the write end from under `exec_write`. Windows cannot
//!     use `.file` for a pipe handle: std re-opens it via NtCreateFile with
//!     an empty path, which a named pipe answers with
//!     STATUS_PIPE_NOT_AVAILABLE (`error.NoDevice`). There the daemon
//!     spawns with `.pipe` stdio instead and takes the parent write end
//!     over from `child.stdin` (see toolExecStart), so these helpers are
//!     POSIX-only.
//!   * `child_pgid`/`spawn_suspended` — comptime SpawnOptions gates: process
//!     group leader on POSIX (the `0` literal is not expressible on Windows,
//!     where pid_t is a HANDLE), CREATE_SUSPENDED only on Windows (so the
//!     process lands in its Job Object before running a single instruction).
//!   * Job Object API (std 0.16 has no bindings): createKillOnCloseJob,
//!     assignToJob, resumeProcess (own NtResumeProcess extern),
//!     terminateJob, terminateHandle.
//!   * `killTree` — POSIX: SIGKILL to the process group and the leader.
//!     Windows: TerminateJobObject — children of job members auto-join the
//!     job (Windows 8+), so the whole tree dies; that is also what
//!     guarantees EOF in the blocking pipe readers.
//!   * `readPipeBlocking` — NtReadFile plus wait-on-handle for the session
//!     reader threads. The std-created stdout/stderr pipe ends are
//!     asynchronous handles, so reads go STATUS_PENDING and complete when
//!     data arrives or every write end closes (pipe broken = EOF).
//!   * `writeAllFd` — full-buffer write; POSIX delegates to the shared os
//!     layer, Windows loops NtWriteFile on the synchronous stdin pipe end.

const std = @import("std");
const builtin = @import("builtin");
const native_os = builtin.os.tag;
const os_layer = @import("../os.zig");
const Io = std.Io;

/// Real integer process id on every supported OS.
pub const ProcessId = switch (native_os) {
    .windows => u32,
    else => std.posix.pid_t,
};

/// Windows: the Job Object owning the session's process tree (null = none).
/// POSIX: void — killTree works through the process group instead.
pub const JobField = if (native_os == .windows) ?std.os.windows.HANDLE else void;

/// Default JobField value: no job.
pub const no_job: JobField = if (native_os == .windows) null else {};

/// SpawnOptions.pgid value: `0` makes the child a process-group leader on
/// POSIX so kill(-pgid) reaches the whole tree. The literal is not
/// expressible on Windows (pid_t is a HANDLE there); the field stays null
/// and the Job Object takes over the tree role.
pub const child_pgid: ?std.posix.pid_t = if (native_os == .windows) null else 0;

/// SpawnOptions.start_suspended: Windows spawns suspended so the child can be
/// assigned to its Job Object before it runs (a running process could spawn
/// a grandchild first and escape the job). POSIX must not use it: std
/// implements it as a pre-exec SIGSTOP, which would hang the session.
pub const spawn_suspended: bool = native_os == .windows;

/// Both ends of the child's stdin pipe, owned by the parent. POSIX only:
/// Windows hands the stdin pipe lifecycle to std (`.pipe` stdio plus the
/// post-spawn takeover in toolExecStart — see the header note).
pub const StdinPipe = struct {
    /// Read end; handed to the child during spawn (`.file` stdio).
    read: std.posix.fd_t,
    /// Write end; becomes Session.stdin_fd.
    write: std.posix.fd_t,
};

/// Create the session's stdin pipe with the same end roles std itself uses
/// for `.pipe` stdin: both ends CLOEXEC, so concurrent spawns from other
/// connection threads can never inherit them (the child's dup2 target loses
/// CLOEXEC automatically). POSIX only — on Windows `.file` stdio cannot
/// re-open a pipe handle (STATUS_PIPE_NOT_AVAILABLE → error.NoDevice), so
/// toolExecStart spawns with std `.pipe` stdio instead and never calls this.
pub fn createStdinPipe() !StdinPipe {
    // Darwin fork gate (see the block above): covers the pipe()→fcntl
    // window inside std's non-atomic pipe2 fallback so a concurrent fork
    // can never inherit the fresh fds without CLOEXEC. Comptime no-op on
    // Linux (atomic pipe2) and Windows (no fork).
    darwinPipeGateEnter();
    defer darwinPipeGateExit();
    const fds = try std.Io.Threaded.pipe2(.{ .CLOEXEC = true });
    return .{ .read = fds[0], .write = fds[1] };
}

/// The `.file` stdio view of the pipe's read end, for SpawnOptions.stdin
/// (POSIX only — see createStdinPipe).
pub fn stdinFile(pipe: *const StdinPipe) std.Io.File {
    return .{ .handle = pipe.read, .flags = .{ .nonblocking = false } };
}

// ---------------------------------------------------------------------------
// Darwin CLOEXEC fork gate.
//
// XNU has no pipe2(2), so std's pipe2(.{ .CLOEXEC = true }) on Darwin is a
// fallback: pipe() followed by one fcntl(F_SETFD, FD_CLOEXEC) per end. In a
// threaded daemon that leaves a real window: while thread A sits between
// pipe() and its fcntls, thread B's fork+exec (another session's spawn, or
// the exec tool's raw spawn) copies the fd table and inherits A's
// fresh fds WITHOUT CLOEXEC — the exec'd process then holds, say, another
// session's stdin write end or wake-pipe end open forever (cross-session
// stdin injection / lost EOF / wedged readers). Linux needs none of this
// (pipe2 sets the flags atomically) and Windows has no fork.
//
// Chosen scheme — the same one libuv uses on macOS: a process-wide gate
// plus pthread_atfork hooks. Every fork on Darwin goes through libSystem's
// fork(), which runs the atfork chain: our prepare handler locks the gate
// before the fork, the parent handler unlocks right after it. Pipe
// creation takes the same gate, so the two can never overlap: either the
// fcntls complete before the fork copies the fd table (the child inherits
// CLOEXEC fds, which exec closes), or the pipe is created only after the
// fork (the child never saw the fds). Holding the gate is deliberately
// restricted to fd creation — no code path forks while holding it, so the
// prepare handler can never self-deadlock, and long-running spawns never
// serialize against each other. std's own internal exec-error pipe has the
// same upstream limitation inside std's un-gated fallback; our session
// fds — the audit surface — are fully covered.
//
// The gate is a spin lock rather than std.Io.Mutex: the atfork handlers
// carry no Io instance, and the critical sections are a few syscalls.
// ---------------------------------------------------------------------------

/// 0 = free, 1 = held. Referenced from Darwin-only call sites (comptime
/// no-op wrappers below), so other targets never codegen the spin.
var darwin_fork_gate: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);

/// Atfork handler signatures (libSystem pthread_atfork).
const AtForkFn = *const fn () callconv(.c) void;
extern "c" fn pthread_atfork(prepare: ?AtForkFn, parent: ?AtForkFn, child: ?AtForkFn) c_int;

fn darwinForkGateLock() void {
    while (darwin_fork_gate.cmpxchgStrong(0, 1, .acquire, .monotonic)) |_| {
        std.Thread.yield() catch {};
    }
}

fn darwinForkGateUnlock() void {
    const prev = darwin_fork_gate.swap(0, .release);
    std.debug.assert(prev == 1);
}

/// Atfork prepare: runs in the forking thread before the fd table is
/// copied. Locking here blocks the fork until any in-flight pipe creation
/// has finished setting CLOEXEC.
fn darwinForkPrepare() callconv(.c) void {
    darwinForkGateLock();
}

/// Atfork parent half: release right after the fork so the next pipe
/// creation (blocked in darwinPipeGateEnter) proceeds with a fd table the
/// already-forked child never shares. No child handler: the forked child
/// immediately execs (or _exits on exec failure) and nothing in it ever
/// touches the gate — the stale locked copy dies with the exec.
fn darwinForkParent() callconv(.c) void {
    darwinForkGateUnlock();
}

/// Take the fork gate around fd creation. Comptime no-op outside Darwin
/// (plus a test-only balance counter maintained on every target so the
/// error-injection tests can prove the Enter/Exit pairing — see
/// gatedPipe).
fn darwinPipeGateEnter() void {
    if (comptime native_os == .macos) darwinForkGateLock();
    if (comptime builtin.is_test) gate_balance += 1;
}

/// Release the fork gate. Comptime no-op outside Darwin.
fn darwinPipeGateExit() void {
    if (comptime native_os == .macos) darwinForkGateUnlock();
    if (comptime builtin.is_test) gate_balance -= 1;
}

/// Test-only net Enter/Exit balance of the fork gate. Zero after every
/// balanced acquisition window; a non-zero value after a call that
/// returned an error means the gate is stuck — on Darwin that is a
/// PERMANENT deadlock of every later fork/pipe operation (the atfork
/// prepare handler spins forever). Checked by the error-injection tests.
var gate_balance: i32 = 0;

/// Install the Darwin fork gate (pthread_atfork hooks). Must run once from
/// single-threaded startup (main.zig) before any connection thread can
/// race pipe creation against a fork — comptime no-op on every other
/// target. Registration failure is surfaced as an error: without the hooks
/// the pipe-creation window above would reopen, so startup must not
/// silently continue in the degraded state.
pub fn installDarwinForkGate() error{AtForkFailed}!void {
    if (comptime native_os == .macos) {
        if (pthread_atfork(darwinForkPrepare, darwinForkParent, null) != 0) {
            return error.AtForkFailed;
        }
    }
}

// ---------------------------------------------------------------------------
// Windows Job Objects. std 0.16 ships no bindings; the externs below are the
// whole surface the daemon needs (create / set limit / assign / resume /
// terminate). Everything in this section is referenced only from
// comptime-gated call sites, so POSIX builds never codegen it.
// ---------------------------------------------------------------------------

const windows = std.os.windows;

const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x0000_2000;
/// JOBOBJECTINFOCLASS value for JOBOBJECT_EXTENDED_LIMIT_INFORMATION.
const JobObjectExtendedLimitInformation: c_int = 9;
const PROCESS_TERMINATE: u32 = 0x0001;

const JOBOBJECT_BASIC_LIMIT_INFORMATION = extern struct {
    PerProcessUserTimeLimit: i64 = 0,
    PerJobUserTimeLimit: i64 = 0,
    LimitFlags: u32 = 0,
    MinimumWorkingSetSize: usize = 0,
    MaximumWorkingSetSize: usize = 0,
    ActiveProcessLimit: u32 = 0,
    Affinity: usize = 0,
    PriorityClass: u32 = 0,
    SchedulingClass: u32 = 0,
};

const IO_COUNTERS = extern struct {
    ReadOperationCount: u64 = 0,
    WriteOperationCount: u64 = 0,
    OtherOperationCount: u64 = 0,
    ReadTransferCount: u64 = 0,
    WriteTransferCount: u64 = 0,
    OtherTransferCount: u64 = 0,
};

const JOBOBJECT_EXTENDED_LIMIT_INFORMATION = extern struct {
    BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION = .{},
    IoInfo: IO_COUNTERS = .{},
    ProcessMemoryLimit: usize = 0,
    JobMemoryLimit: usize = 0,
    PeakProcessMemoryUsed: usize = 0,
    PeakJobMemoryUsed: usize = 0,
};

extern "kernel32" fn CreateJobObjectW(lpJobAttributes: ?*const anyopaque, lpName: ?[*:0]const u16) ?windows.HANDLE;
extern "kernel32" fn SetInformationJobObject(hJob: windows.HANDLE, JobObjectInformationClass: c_int, lpJobObjectInfo: *const anyopaque, cbJobObjectInfoLength: u32) windows.BOOL;
extern "kernel32" fn AssignProcessToJobObject(hJob: windows.HANDLE, hProcess: windows.HANDLE) windows.BOOL;
extern "kernel32" fn TerminateJobObject(hJob: windows.HANDLE, uExitCode: u32) windows.BOOL;
extern "kernel32" fn OpenProcess(dwDesiredAccess: u32, bInheritHandle: windows.BOOL, dwProcessId: u32) ?windows.HANDLE;
extern "kernel32" fn TerminateProcess(hProcess: windows.HANDLE, uExitCode: u32) windows.BOOL;
// NtResumeProcess is intentionally absent from std's ntdll bindings.
extern "ntdll" fn NtResumeProcess(ProcessHandle: windows.HANDLE) windows.NTSTATUS;
// QueryFullProcessImageNameW is likewise absent from std's kernel32
// bindings; the exec-pin image check needs it. The
// comparator it feeds is pure and lives in os/secure.zig
// (windowsPathMatchesUtf8), so the contract is unit-tested on every CI
// platform, not just where kernel32 exists.
extern "kernel32" fn QueryFullProcessImageNameW(
    hProcess: windows.HANDLE,
    dwFlags: u32,
    lpExeName: [*]u16,
    lpdwSize: *u32,
) callconv(.winapi) windows.BOOL;

/// True when the image of the (possibly CREATE_SUSPENDED) process
/// `process` is the pinned executable `exe_path` (the daemon's exec pins
/// pass the share-mode-pinned object's canonical path). Fail-closed: any
/// query failure answers false, which the caller treats as a mismatch —
/// terminate the child before it runs a single instruction. Windows-only
/// body (referenced from comptime-gated call sites in tools.zig).
pub fn processImageNameMatches(process: windows.HANDLE, exe_path: []const u8) bool {
    if (comptime native_os == .windows) {
        var buf: [windows.PATH_MAX_WIDE]u16 = undefined;
        var size: u32 = buf.len;
        if (!QueryFullProcessImageNameW(process, 0, &buf, &size).toBool()) return false;
        if (size > buf.len) return false;
        return os_layer.secure.windowsPathMatchesUtf8(buf[0..size], exe_path);
    }
    return false; // unreachable: no comptime-gated call site
}

// Reader-wake support (see sessionRequestClose): a manual-reset event the
// session readers wait alongside their pipe handle, plus the I/O
// cancellation needed to unwind a pending NtReadFile on that handle.
// None of these are in std's bindings either; all are referenced only
// from comptime-gated Windows call sites, so POSIX builds never codegen them.
extern "kernel32" fn CreateEventW(lpEventAttributes: ?*const anyopaque, bManualReset: windows.BOOL, bInitialState: windows.BOOL, lpName: ?[*:0]const u16) ?windows.HANDLE;
extern "kernel32" fn SetEvent(hEvent: windows.HANDLE) windows.BOOL;
extern "kernel32" fn CancelIoEx(hFile: windows.HANDLE, lpOverlapped: ?*anyopaque) windows.BOOL;
// NtWaitForMultipleObjects: WaitType takes the native WAIT_TYPE values —
// see NtWaitType below for the WaitAll=0 / WaitAny=1 contract.
extern "ntdll" fn NtWaitForMultipleObjects(Count: u32, Handles: [*]const windows.HANDLE, WaitType: u32, Alertable: u8, Timeout: ?*const windows.LARGE_INTEGER) windows.NTSTATUS;

/// WAIT_TYPE from the native NT API (winternl.h / ntifs.h): WaitAll = 0,
/// WaitAny = 1. The numeric order is the REVERSE of what the Win32
/// WaitForMultipleObjects(bWaitAll: BOOL) name suggests, which is exactly
/// how a reader call site was once "fixed" back to 0: the reader then
/// waited for BOTH the pipe handle and the wake event to be signaled,
/// and since the wake event is only ever set at close time, any child
/// that simply wrote a full pipe deadlocked the session (read completed,
/// reader parked, waiter blocked in child.wait). Do not "simplify" these
/// values back to a bare 0 — they mirror the kernel contract.
const NtWaitType = enum(u32) {
    WAIT_ALL = 0,
    WAIT_ANY = 1,
};

/// Outcome of NtWaitForMultipleObjects(2, [pipe, wake], WaitAny, ...).
/// With WaitAny the kernel returns STATUS_WAIT_0 + the index of the
/// lowest-indexed signaled handle: 0 = the pipe handle (the overlapped
/// read is done), 1 = the wake event (close requested). Pure function so
/// the mapping is unit-tested on every CI platform, not just where
/// ntdll exists.
pub const WaitAnyOutcome = enum { pipe_ready, wake_signaled, failed };

pub fn decodeWaitAnyStatus(st: windows.NTSTATUS) WaitAnyOutcome {
    return switch (st) {
        .SUCCESS => .pipe_ready, // STATUS_WAIT_0 + 0 → handles[0] = pipe
        .WAIT_1 => .wake_signaled, // STATUS_WAIT_0 + 1 → handles[1] = wake event
        else => .failed,
    };
}

/// Reader wake plumbing. POSIX: both ends of a CLOEXEC self-pipe (the
/// readers poll the read end; sessionRequestClose writes a byte). Windows:
/// a manual-reset event shared by the session's readers (set by
/// sessionRequestClose; waited alongside the pipe handle in
/// readPipeBlocking). Each helper returns null when the object cannot be
/// created — the callers then run without the fast wake path, which costs
/// one poll tick of latency, never correctness.
pub fn createWakePipe() ?[2]std.posix.fd_t {
    // Darwin fork gate (see the block above): same CLOEXEC-window coverage
    // as createStdinPipe. Comptime no-op on Linux/Windows.
    darwinPipeGateEnter();
    defer darwinPipeGateExit();
    // NONBLOCK (both ends — pipe2 flags are per-call): nobody ever drains
    // the wake pipe, and sessionRequestClose is one-shot, but a stale
    // non-drained byte plus an unrestricted writer could still park a
    // caller on a full pipe (see sessionRequestClose); with NONBLOCK an
    // EAGAIN write simply means "already signaled" and is swallowed by
    // the caller. Readers only poll + read, so a nonblocking read end
    // never blocks them either.
    return std.Io.Threaded.pipe2(.{ .CLOEXEC = true, .NONBLOCK = true }) catch null;
}

/// Windows-only companion to createWakePipe (same role, different object).
/// Referenced from comptime-gated Windows call sites only.
pub fn createWakeEvent() ?windows.HANDLE {
    return CreateEventW(null, .TRUE, .FALSE, null);
}

/// Pulse the reader wake event. Idempotent: manual-reset events stay set
/// until reset, and nobody resets this one.
pub fn setWakeEvent(ev: windows.HANDLE) void {
    _ = SetEvent(ev);
}

/// Create an anonymous Job Object with KILL_ON_JOB_CLOSE: when the last
/// handle to the job closes (including daemon teardown), every assigned
/// process is terminated. The session keeps exactly one handle, closed in
/// freeSession after the tree is already dead.
pub fn createKillOnCloseJob() error{JobObjectFailed}!windows.HANDLE {
    const job = CreateJobObjectW(null, null) orelse return error.JobObjectFailed;
    errdefer windows.CloseHandle(job);
    var info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = .{};
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &info, @sizeOf(JOBOBJECT_EXTENDED_LIMIT_INFORMATION)).toBool()) {
        return error.JobObjectFailed;
    }
    return job;
}

/// Assign a (still suspended) child to the job. Must run before
/// resumeProcess so the process can never spawn an untracked grandchild.
pub fn assignToJob(job: windows.HANDLE, process: windows.HANDLE) error{JobObjectFailed}!void {
    if (!AssignProcessToJobObject(job, process).toBool()) return error.JobObjectFailed;
}

/// Resume a CREATE_SUSPENDED process (all its threads).
pub fn resumeProcess(process: windows.HANDLE) error{ResumeFailed}!void {
    switch (NtResumeProcess(process)) {
        .SUCCESS => {},
        else => return error.ResumeFailed,
    }
}

/// Terminate a process by handle (exit code 1). Used on the spawn error path
/// where the suspended child is not in any job yet, so a job kill would miss
/// it and the subsequent child.wait() would hang forever.
pub fn terminateHandle(process: windows.HANDLE) void {
    _ = windows.ntdll.NtTerminateProcess(process, @enumFromInt(1));
}

/// Terminate every process in the job (exit code 1), grandchildren included.
/// Idempotent for the daemon's purposes: terminating an empty or dead job is
/// a harmless no-op.
pub fn terminateJob(job: windows.HANDLE) void {
    _ = TerminateJobObject(job, 1);
}

/// Resolve the real process id behind a child HANDLE. Display-only: exec
/// JSON output reports it, control always goes through the handle/job.
pub fn queryProcessId(process: windows.HANDLE) ?u32 {
    var info: windows.PROCESS.BASIC_INFORMATION = undefined;
    switch (windows.ntdll.NtQueryInformationProcess(
        process,
        .BasicInformation,
        &info,
        @sizeOf(windows.PROCESS.BASIC_INFORMATION),
        null,
    )) {
        .SUCCESS => return std.math.lossyCast(u32, info.UniqueProcessId),
        else => return null,
    }
}

/// Kill the session's whole process tree. POSIX: SIGKILL the process group
/// (the child is a group leader via child_pgid) and the leader itself.
/// Windows: TerminateJobObject on the session job — every process that ever
/// belonged to the tree dies (children of job members auto-join the job on
/// Windows 8+), which in turn closes every pipe write end and lets the
/// blocking readers observe EOF. The pid-only fallback covers the
/// theoretical no-job case and should never run for a live session.
pub fn killTree(pid: ProcessId, job: JobField) void {
    if (comptime native_os == .windows) {
        if (job) |j| {
            terminateJob(j);
            return;
        }
        if (pid == 0) return;
        if (OpenProcess(PROCESS_TERMINATE, .FALSE, pid)) |h| {
            _ = TerminateProcess(h, 1);
            windows.CloseHandle(h);
        }
        return;
    } else {
        if (pid <= 0) return;
        std.posix.kill(-pid, std.posix.SIG.KILL) catch {};
        std.posix.kill(pid, std.posix.SIG.KILL) catch {};
    }
}

/// XNU idtype_t (bsd/sys/wait.h): typedef enum idtype { P_ALL, P_PID,
/// P_PGID } — declaration order makes P_ALL=0, P_PID=1, P_PGID=2. Linux call
/// sites use the typed std.os.linux.P instead; this enum exists so the
/// Darwin call site can never pass a bare integer again (0 was P_ALL:
/// waitid matched ANY exited child of the daemon, so one finishing session
/// killed every parallel session's tree).
const DarwinIdType = enum(c_uint) {
    all = 0,
    pid = 1,
    pgid = 2,
};

/// XNU waitid options used below: WEXITED (0x4) | WNOWAIT (0x20).
const darwin_wexited_nowait: c_int = 0x4 | 0x20;

/// Block until the direct child `pid` exits WITHOUT reaping it
/// (waitid(WNOWAIT)). The unreaped zombie keeps its pid — and therefore the
/// process-group id it led — allocated, so a kill(-pgid) issued after this
/// returns can never hit a recycled process group. The caller must reap the
/// child afterwards (std.process.Child.wait).
///
/// POSIX only; Windows sessions are supervised by the Job Object instead
/// (this function is referenced from comptime-gated POSIX paths only).
pub fn waitChildExitNoReap(pid: ProcessId) error{WaitFailed}!void {
    if (comptime native_os == .linux) {
        while (true) {
            var info: std.os.linux.siginfo_t = undefined;
            const rc = std.os.linux.waitid(.PID, pid, &info, std.os.linux.W.EXITED | std.os.linux.W.NOWAIT, null);
            switch (std.os.linux.errno(rc)) {
                .SUCCESS => return,
                .INTR => continue,
                else => return error.WaitFailed,
            }
        }
    } else {
        // Darwin: libSystem waitid (POSIX.1-2008); std.c ships no binding.
        // XNU: P_ALL=0, P_PID=1, P_PGID=2 (see DarwinIdType); WEXITED=0x4,
        // WNOWAIT=0x20.
        var retries: u32 = 0;
        while (true) {
            var info: std.c.siginfo_t = undefined;
            const rc = waitid(@intFromEnum(DarwinIdType.pid), pid, &info, darwin_wexited_nowait);
            if (rc == 0) {
                // Identity check: the reported child must be the one we were
                // asked about. A regression to P_ALL semantics (or a kernel
                // surprise) must fail into the caller's fallback — which
                // blocks on OUR child — never kill our own live tree on
                // someone else's exit.
                if (info.pid != pid) return error.WaitFailed;
                return;
            }
            if (comptime @hasDecl(std.c, "_errno")) {
                if (std.c._errno().* == @intFromEnum(std.c.E.INTR)) continue;
                return error.WaitFailed;
            } else {
                // No errno accessor: EINTR is the only transient failure;
                // permanent errors burn a bounded retry budget, then the
                // caller falls back to the post-reap kill path.
                retries += 1;
                if (retries > 1024) return error.WaitFailed;
            }
        }
    }
}

// Darwin's libSystem waitid (POSIX.1-2008): no std.c binding in 0.16.
// Referenced only from the macOS branch of waitChildExitNoReap, so on other
// targets it is never codegen'd or linked.
extern "c" fn waitid(idtype: c_uint, id: c_int, infop: *std.c.siginfo_t, options: c_int) c_int;

// -----------------------------------------------------------------------
// Failed-spawn hygiene (POSIX only).
//
// std 0.16 processSpawnPosix reads the exec failure from the child's error
// pipe and returns the error WITHOUT waitpid and WITHOUT the pid: the fork
// succeeded, the child reported the execve failure and exited, and nobody
// can ever reap it by address because its pid was never surfaced. Every
// failed spawn therefore leaks a defunct child for the daemon's lifetime.
// Three layers close this:
//   * preflightExec — resolve argv[0] and cwd exactly the way the child's
//     execvpe will, BEFORE forking, so the common failures (missing program,
//     missing execute permission, missing cwd) never fork at all and keep
//     their std error names (FileNotFound, AccessDenied, NotDir).
//   * reapStrayChildren — the stray sweep. PRIMARY (Linux): waitid(P_ALL)
//     collects free zombies. A /proc fallback runs only after skipped
//     protected children or a full 64-entry waitid round; it does not run
//     on every exec. Each zombie is reaped ADDRESSALLY (waitid P_PID), so
//     correctness never depends on kernel enumeration order.
//     (Non-Linux POSIX uses waitid(P_ALL) alone: no /proc there.)
//   * pending_pids (tools.zig) — the protected set: session children from
//     fork until their waiter's reap, so the sweep never steals a wait a
//     session owns.
// Everything below is referenced only from comptime-gated POSIX call sites,
// so Windows builds never codegen it.
// ----------------------------------------------------------------------

/// Mirror of std.Io.Threaded.default_PATH: the PATH fallback used by the
/// spawn layer when the environment carries no PATH.
const default_path_env = "/usr/local/bin:/bin/:/usr/bin";

/// Resolve `rel` the way the child would after its pre-exec chdir: relative
/// to the requested cwd (which is itself relative to the daemon's cwd when
/// not absolute). An empty cwd means the child inherits the daemon's cwd, so
/// `rel` stays daemon-cwd-relative — identical resolution, no getcwd needed.
fn childRelative(arena: std.mem.Allocator, cwd: []const u8, rel: []const u8) ![]const u8 {
    if (cwd.len == 0) return rel;
    return try std.mem.concat(arena, u8, &.{ cwd, "/", rel });
}

/// stat + access(X_OK) one resolved path. `eacces` set true when the path
/// exists but is not executable (or not a regular file): execve would fail
/// with EACCES there, which std's PATH loop remembers and continues past.
fn probeCandidate(io: Io, path: []const u8, eacces: *bool) !bool {
    const st = std.Io.Dir.statFile(.cwd(), io, path, .{}) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => return false,
        error.AccessDenied, error.PermissionDenied => {
            eacces.* = true;
            return false;
        },
        else => return err,
    };
    if (st.kind != .file) {
        // A directory (or device/fifo) passes access(X_OK) but execve
        // refuses it with EACCES.
        eacces.* = true;
        return false;
    }
    std.Io.Dir.access(.cwd(), io, path, .{ .execute = true }) catch |err| switch (err) {
        error.FileNotFound => return false, // raced away between stat and access
        error.AccessDenied, error.PermissionDenied => {
            eacces.* = true;
            return false;
        },
        else => return err,
    };
    return true;
}

/// Pre-flight the exec layer's process creation: resolve argv[0] against the
/// child's future cwd exactly like the child's execvpe will, and verify the
/// result is an executable regular file. Mirrors std's posixExecv loop
/// (tokenize drops empty PATH entries; EACCES candidates are remembered,
/// ENOENT/ENOTDIR skipped; a final failure reports EACCES if any candidate
/// denied access, FileNotFound otherwise). Also verifies the requested cwd
/// is an existing directory (a failed child-side chdir would otherwise leak
/// a zombie with a confusing error). Error names match what std's spawn
/// would have surfaced (FileNotFound, AccessDenied, NotDir, ...), so
/// callers and fixtures see no taxonomy drift.
///
/// `path_env` is the daemon's PATH (the child inherits it); null mirrors
/// std's default_PATH fallback. Format-level failures (ENOEXEC etc.) are
/// NOT pre-flighted: those still fork, fail, and are reaped by
/// reapStrayChildren.
pub fn preflightExec(arena: std.mem.Allocator, io: Io, argv0: []const u8, cwd: []const u8, path_env: ?[]const u8) !void {
    if (cwd.len != 0) {
        const st = std.Io.Dir.statFile(.cwd(), io, cwd, .{}) catch |err| return err;
        if (st.kind != .directory) return error.NotDir;
    }
    if (std.mem.indexOfScalar(u8, argv0, '/') != null) {
        const path = if (std.fs.path.isAbsolute(argv0))
            argv0
        else
            try childRelative(arena, cwd, argv0);
        var eacces = false;
        if (try probeCandidate(io, path, &eacces)) return;
        if (eacces) return error.AccessDenied;
        return error.FileNotFound;
    }
    var eacces = false;
    const path_value = path_env orelse default_path_env;
    var it = std.mem.tokenizeScalar(u8, path_value, ':');
    while (it.next()) |entry| {
        const joined = try std.mem.concat(arena, u8, &.{ entry, "/", argv0 });
        // A relative PATH entry resolves against the child's post-chdir cwd,
        // same as every other relative path here.
        const candidate = if (entry.len != 0 and entry[0] == '/')
            joined
        else
            try childRelative(arena, cwd, joined);
        if (try probeCandidate(io, candidate, &eacces)) return;
    }
    if (eacces) return error.AccessDenied;
    return error.FileNotFound;
}

// ---------------------------------------------------------------------------
// Pinned exec spawn.
//
// std's spawn path resolves argv[0] through execvpe at exec time — the RAW
// string, re-resolved after the policy gate already authorized a canonical
// one. A racer with rename rights on an ancestor could swap the path
// between the gate and the spawn. spawnPinned closes that window: the
// caller (tools.zig) opens the authorized cwd directory and executable
// through os/secure.zig BEFORE the fork (openat2 confinement + fd readback
// == the gate's canonical string), and this layer forks with:
//
//   dup2(stdio) -> fchdir(pinned_cwd_fd) -> setpgid(0,0) -> execveat(fd)
//
// The child never resolves a pathname again: fchdir lands in the pinned
// directory descriptor, execveat(AT_EMPTY_PATH) replaces the image with
// the pinned file object. A symlink/rename swap after the pins cannot
// redirect either one. argv[0] stays the user's raw string (busybox $0
// semantics); the exec TARGET is exe_fd, not argv[0].
//
// Platform split: Linux uses the raw execveat syscall (O_PATH fds are
// accepted, which keeps execute-only binaries working); Darwin uses libc
// fexecve on an O_RDONLY fd. Windows never reaches this code (comptime
// gate in tools.zig; CreateProcess has no fd-exec and the boundary is
// documented there).
//
// Zombie hygiene: unlike std's processSpawnPosix (which returns the
// exec-errored child without waitpid — see the header comment above), the
// error protocol here REAPS the dying child before returning the error:
// a 4-byte error report on the CLOEXEC pipe is followed by the child's
// _exit, and the parent waitpids it away. No stray, no sweep dependency.
// ---------------------------------------------------------------------------

/// Inputs of one pinned spawn. The fds are borrowed for the duration of
/// the call: the fork copies the table (CLOEXEC survives the copy and is
/// only dropped at the exec the child itself performs), the parent closes
/// nothing it did not create itself.
pub const PinnedSpawn = struct {
    /// Pre-pinned executable descriptor: the execveat/fexecve target.
    exe_fd: std.posix.fd_t,
    /// Pre-pinned cwd descriptor; null = inherit the daemon cwd.
    cwd_fd: ?std.posix.fd_t,
    /// argv exactly as the tool received it — argv[0] is NOT the exec path.
    argv: []const []const u8,
    /// Child environment, posix block shape (env_state snapshot).
    envp: [:null]const ?[*:0]const u8,
    /// fd dup2'd into the child's stdin; null = /dev/null (run semantics).
    stdin_fd: ?std.posix.fd_t,
    /// Make the child a process-group leader (session spawns; exec keeps
    /// the daemon's group, exactly like std's process.run).
    pgid: bool,
};

/// errno-reported child-side failures, one int over the pipe. The Zig
/// error round-trip (@intFromError/@errorFromInt) is exact within this
/// binary, and the child only reports errors from the fixed sets below.
const ChildExecError = error{
    AccessDenied,
    PermissionDenied,
    FileNotFound,
    NotDir,
    IsDir,
    NameTooLong,
    SystemResources,
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
    InvalidExe,
    FileSystem,
    FileBusy,
    Unexpected,
    InvalidUserId,
    ProcessAlreadyExec,
    InvalidProcessGroupId,
    ResourceLimitReached,
    SymLinkLoop,
};

/// execveat(2) with AT_EMPTY_PATH on the pinned descriptor. Only ever
/// returns on failure (Linux raw syscall; the EXECVEAT flag struct lives
/// in std.os.linux).
fn execPinnedLinux(
    exe_fd: std.posix.fd_t,
    argv: [*:null]const ?[*:0]const u8,
    envp: [*:null]const ?[*:0]const u8,
) ChildExecError {
    const rc = std.os.linux.execveat(exe_fd, "", argv, envp, .{ .EMPTY_PATH = true, .SYMLINK_NOFOLLOW = false });
    switch (std.os.linux.errno(rc)) {
        .FAULT => return error.Unexpected, // bad pointer parameter: our bug
        .@"2BIG" => return error.SystemResources,
        .MFILE => return error.ProcessFdQuotaExceeded,
        .NAMETOOLONG => return error.NameTooLong,
        .NFILE => return error.SystemFdQuotaExceeded,
        .NOMEM => return error.SystemResources,
        .ACCES => return error.AccessDenied,
        .PERM => return error.PermissionDenied,
        .INVAL => return error.InvalidExe,
        .NOEXEC => return error.InvalidExe,
        .IO => return error.FileSystem,
        .LOOP => return error.SymLinkLoop,
        .ISDIR => return error.IsDir,
        .NOENT => return error.FileNotFound,
        .NOTDIR => return error.NotDir,
        .TXTBSY => return error.FileBusy,
        else => return error.Unexpected,
    }
}

/// macOS has NO fexecve (it is a glibc/BSD extension; Darwin libSystem
/// never shipped it — the cross-compilation to aarch64-macos failed on
/// the undefined _fexecve symbol). The portable emulation is
/// execve("/dev/fd/<n>"): the child execs the descriptor's path, which
/// resolves to the pinned object. The exe fd must be O_RDONLY for this
/// (see openPinnedExe's Darwin branch) and must NOT be CLOEXEC.
extern "c" fn execve(
    path: [*:0]const u8,
    argv: [*:null]const ?[*:0]const u8,
    envp: [*:null]const ?[*:0]const u8,
) c_int;

fn execPinnedDarwin(
    exe_fd: std.posix.fd_t,
    argv: [*:null]const ?[*:0]const u8,
    envp: [*:null]const ?[*:0]const u8,
) ChildExecError {
    var pbuf: [32]u8 = undefined;
    const path = std.fmt.bufPrintZ(&pbuf, "/dev/fd/{d}", .{@as(c_int, @intCast(exe_fd))}) catch
        return error.Unexpected;
    const rc = execve(path.ptr, argv, envp);
    _ = rc; // execve returns only on failure; fall through to errno
    switch (@as(std.c.E, @enumFromInt(std.c._errno().*))) {
        .ACCES => return error.AccessDenied,
        .PERM => return error.PermissionDenied,
        .@"2BIG" => return error.SystemResources,
        .MFILE => return error.ProcessFdQuotaExceeded,
        .NAMETOOLONG => return error.NameTooLong,
        .NFILE => return error.SystemFdQuotaExceeded,
        .NOMEM => return error.SystemResources,
        .INVAL => return error.InvalidExe,
        .NOEXEC => return error.InvalidExe,
        .IO => return error.FileSystem,
        .LOOP => return error.SymLinkLoop,
        .ISDIR => return error.IsDir,
        .NOENT => return error.FileNotFound,
        .NOTDIR => return error.NotDir,
        .TXTBSY => return error.FileBusy,
        else => return error.Unexpected,
    }
}

/// Child-side bail: report the failure over the error pipe and die. Runs
/// between fork and exec — syscalls only, no allocation, no locks. The
/// write is one 2-byte little-endian int (the error int is u16); the parent reads it while the
/// child is on its way out and reaps the zombie before returning.
/// Exit strategy mirrors std's forkBail: libc `_exit` (never `exit` —
/// atexit handlers deadlock in a fork child), else exit_group on Linux,
/// else the raw system exit.
fn forkBailPinned(ep1: std.posix.fd_t, err: ChildExecError) noreturn {
    // @intFromError's integer type is u16 by default: a 2-byte report.
    const code: u16 = @intFromError(err);
    var bytes: [2]u8 = .{
        @truncate(code),
        @truncate(code >> 8),
    };
    if (comptime builtin.link_libc) {
        _ = std.c.write(ep1, &bytes, bytes.len);
        std.c._exit(127);
    } else if (comptime native_os == .linux) {
        _ = std.os.linux.write(ep1, &bytes, bytes.len);
        std.os.linux.exit_group(127);
    } else {
        _ = std.posix.system.write(ep1, &bytes, bytes.len);
        std.posix.system.exit(127);
    }
}

/// Child-side dup2 with EINTR retry; failures bail through the pipe.
/// Linux: raw syscall; else libc dup2 (both errno-decoded the way the
/// platform's system layer expects).
fn childDup2(ep1: std.posix.fd_t, old: std.posix.fd_t, new: std.posix.fd_t) void {
    while (true) {
        if (comptime native_os == .linux) {
            const rc = std.os.linux.dup2(old, new);
            switch (std.posix.errno(rc)) {
                .SUCCESS => return,
                .INTR => continue,
                .MFILE => forkBailPinned(ep1, error.ProcessFdQuotaExceeded),
                else => forkBailPinned(ep1, error.Unexpected),
            }
        } else {
            const rc = std.c.dup2(old, new);
            if (rc == -1) {
                switch (@as(std.c.E, @enumFromInt(std.c._errno().*))) {
                    .INTR => continue,
                    .MFILE => forkBailPinned(ep1, error.ProcessFdQuotaExceeded),
                    else => forkBailPinned(ep1, error.Unexpected),
                }
            }
            return;
        }
    }
}

/// Child-side fchdir onto the pinned cwd descriptor.
fn childFchdir(ep1: std.posix.fd_t, fd: std.posix.fd_t) void {
    while (true) {
        if (comptime native_os == .linux) {
            const rc = std.os.linux.fchdir(fd);
            switch (std.posix.errno(rc)) {
                .SUCCESS => return,
                .INTR => continue,
                .ACCES, .PERM => forkBailPinned(ep1, error.AccessDenied),
                .NOENT => forkBailPinned(ep1, error.FileNotFound),
                .NOTDIR => forkBailPinned(ep1, error.NotDir),
                .NAMETOOLONG => forkBailPinned(ep1, error.NameTooLong),
                else => forkBailPinned(ep1, error.Unexpected),
            }
        } else {
            const rc = std.c.fchdir(fd);
            if (rc == -1) {
                switch (@as(std.c.E, @enumFromInt(std.c._errno().*))) {
                    .INTR => continue,
                    .ACCES, .PERM => forkBailPinned(ep1, error.AccessDenied),
                    .NOENT => forkBailPinned(ep1, error.FileNotFound),
                    .NOTDIR => forkBailPinned(ep1, error.NotDir),
                    .NAMETOOLONG => forkBailPinned(ep1, error.NameTooLong),
                    else => forkBailPinned(ep1, error.Unexpected),
                }
            }
            return;
        }
    }
}

/// Child-side setpgid(0,0): the session child becomes its own group
/// leader, exactly like std's spawn with pgid=0.
fn childSetpgid(ep1: std.posix.fd_t) void {
    while (true) {
        if (comptime native_os == .linux) {
            const rc = std.os.linux.setpgid(0, 0);
            switch (std.posix.errno(rc)) {
                .SUCCESS => return,
                .INTR => continue,
                .ACCES => forkBailPinned(ep1, error.ProcessAlreadyExec),
                .INVAL => forkBailPinned(ep1, error.InvalidProcessGroupId),
                .PERM => forkBailPinned(ep1, error.AccessDenied),
                else => forkBailPinned(ep1, error.Unexpected),
            }
        } else {
            const rc = std.c.setpgid(0, 0);
            if (rc == -1) {
                switch (@as(std.c.E, @enumFromInt(std.c._errno().*))) {
                    .INTR => continue,
                    .ACCES => forkBailPinned(ep1, error.ProcessAlreadyExec),
                    .INVAL => forkBailPinned(ep1, error.InvalidProcessGroupId),
                    .PERM => forkBailPinned(ep1, error.AccessDenied),
                    else => forkBailPinned(ep1, error.Unexpected),
                }
            }
            return;
        }
    }
}

/// Child-side FD_CLOEXEC clear on the pinned exe fd.
/// The parent opens the exe pin CLOEXEC (secure.zig openPinnedExe /
/// openPathCandidate) so a concurrent fork+exec in ANOTHER thread can
/// never inherit a live O_PATH handle on a foreign binary. The pinned
/// child clears the flag on ITS OWN copy before execveat: a #!-script's
/// interpreter re-opens the script through /dev/fd/<n> AFTER the exec, so
/// the fd must survive it — in the child that executes it, and only
/// there. Runs between fork and exec: syscalls only, bails through the
/// error pipe like every other child step.
fn childClearCloexec(ep1: std.posix.fd_t, fd: std.posix.fd_t) void {
    while (true) {
        if (comptime native_os == .linux) {
            const rc = std.os.linux.fcntl(fd, std.posix.F.SETFD, 0);
            switch (std.posix.errno(rc)) {
                .SUCCESS => return,
                .INTR => continue,
                else => forkBailPinned(ep1, error.Unexpected),
            }
        } else {
            const rc = std.c.fcntl(@intCast(fd), std.posix.F.SETFD, @as(c_int, 0));
            if (rc == -1) {
                switch (@as(std.c.E, @enumFromInt(std.c._errno().*))) {
                    .INTR => continue,
                    else => forkBailPinned(ep1, error.Unexpected),
                }
            }
            return;
        }
    }
}

/// Full pinned spawn: pipes, fork, child setup, error handshake. On
/// success returns a hand-built std.process.Child carrying the pid and
/// the parent-held pipe ends — everything downstream (wait/kill, session
/// readers, the run replica below) operates on it exactly like a std
/// spawn. On child-side failure the child is reaped HERE (no zombie) and
/// the mapped error is returned.
///
/// fd discipline:
///   * every acquisition runs under the Darwin fork gate with a
///     STRUCTURAL Enter/`defer` Exit pairing (gatedPipe below), and each
///     acquired resource is boxed with an errdefer IMMEDIATELY, so an
///     error between two acquisitions (stderr pipe2 failing after the
///     stdout pipe succeeded) can neither leave the gate held nor leak
///     the earlier pipe.
///   * after the fork the parent drops its child-facing ends by
///     an explicit close that marks the FdBox slot not-owned; the
///     errdefer sweep on later error returns then closes only the slots
///     still owned (the read ends). A blind errdefer that re-closes
///     already-closed numbers would, in a multithreaded daemon, close a
///     FOREIGN descriptor that another thread reused the fd number for.
///     The read ends leave this function ONLY on the success path.
pub fn spawnPinned(
    arena: std.mem.Allocator,
    io: Io,
    spec: PinnedSpawn,
) std.process.SpawnError!std.process.Child {
    return spawnPinnedCreator(arena, io, spec, realPipeCreator);
}

/// spawnPinned with the pipe creator injected: the production entry
/// always uses the real syscall layer; the error-injection tests drive
/// the acquisition-failure paths (a later pipe failing after an earlier
/// one succeeded) through a scripted creator instead.
fn spawnPinnedCreator(
    arena: std.mem.Allocator,
    io: Io,
    spec: PinnedSpawn,
    creator: PipeCreator,
) std.process.SpawnError!std.process.Child {
    _ = io;
    if (comptime native_os == .windows) @compileError("spawnPinned is POSIX-only");

    // All allocation happens before the fork (POSIX: no malloc between
    // fork and exec — see std's spawnPosix note about the musl deadlock).
    const argv_buf = try arena.allocSentinel(?[*:0]const u8, spec.argv.len, null);
    for (spec.argv, 0..) |arg, i| argv_buf[i] = (try arena.dupeZ(u8, arg)).ptr;
    const envp = spec.envp.ptr;

    // stdout/stderr pipes (CLOEXEC so concurrent forks never inherit the
    // parent ends; dup2 drops CLOEXEC on the copies the child keeps).
    // errdefer registers right after each acquisition — the second
    // creation failing closes the first pipe exactly once.
    const stdout_pipe = try gatedPipe(creator);
    var stdout_w = FdBox.of(stdout_pipe[1]);
    var stdout_r = FdBox.of(stdout_pipe[0]);
    errdefer stdout_w.close();
    errdefer stdout_r.close();

    const stderr_pipe = try gatedPipe(creator);
    var stderr_w = FdBox.of(stderr_pipe[1]);
    var stderr_r = FdBox.of(stderr_pipe[0]);
    errdefer stderr_w.close();
    errdefer stderr_r.close();

    // /dev/null for the run-semantics stdin (session callers pass a pipe
    // fd). Refusing up front (std's NoDevice for StdIo.ignore) instead of
    // the old `catch null`, which left a latent `devnull.?` unwrap in the
    // forked child — an allocation-free zone that must never panic.
    var devnull = FdBox.empty();
    if (spec.stdin_fd == null) {
        devnull = FdBox.of(gatedOpenDevnull() orelse return error.NoDevice);
    }
    errdefer devnull.close();

    // Error-reporting pipe: CLOEXEC; the child holds the write end only
    // until the exec succeeds (kernel closes it), which is the success
    // signal — the parent reads EOF.
    const err_pipe = try gatedPipe(creator);
    var errp_w = FdBox.of(err_pipe[1]);
    var errp_r = FdBox.of(err_pipe[0]);
    errdefer errp_w.close();
    errdefer errp_r.close();

    const pid: std.posix.pid_t = pid: {
        const rc = std.posix.system.fork();
        switch (std.posix.errno(rc)) {
            .SUCCESS => break :pid @intCast(rc),
            .AGAIN => return error.SystemResources,
            .NOMEM => return error.SystemResources,
            .NOSYS => return error.OperationUnsupported,
            else => return error.Unexpected,
        }
    };

    if (pid == 0) {
        // Child. Raw syscalls only, every failure bails through the pipe
        // (forkBailPinned reports + _exit's). EINTR retries inline. The
        // child never unwinds, so no errdefer in this branch ever runs;
        // the boxes above are parent-side bookkeeping only.
        const ep1 = err_pipe[1];
        const in_fd = spec.stdin_fd orelse devnull.fd.?;
        childDup2(ep1, in_fd, std.posix.STDIN_FILENO);
        childDup2(ep1, stdout_pipe[1], std.posix.STDOUT_FILENO);
        childDup2(ep1, stderr_pipe[1], std.posix.STDERR_FILENO);
        if (spec.cwd_fd) |fd| childFchdir(ep1, fd);
        if (spec.pgid) childSetpgid(ep1);
        // The exe pin is CLOEXEC in the parent; the
        // child clears it on its own copy before execveat so a #!-script
        // interpreter can still re-open /dev/fd/<n> after the exec.
        childClearCloexec(ep1, spec.exe_fd);
        if (comptime native_os == .linux) {
            forkBailPinned(ep1, execPinnedLinux(spec.exe_fd, argv_buf.ptr, envp));
        } else {
            forkBailPinned(ep1, execPinnedDarwin(spec.exe_fd, argv_buf.ptr, envp));
        }
    }

    // Parent. The fork copied the fd table: the CHILD owns its copies of
    // these ends, and the parent's copies are closed here — the explicit
    // close marks each box not-owned, so the errdefer sweep on any error
    // return below cannot double-close a recycled fd number.
    errp_w.close();
    stdout_w.close();
    stderr_w.close();
    devnull.close();

    // Error handshake: EOF = exec succeeded; 2 bytes = the child's mapped
    // failure, and the child has _exit(127)'d — reap it now so a pinned
    // spawn NEVER leaks a zombie (std's exec-error path does; see the
    // header comment of this file).
    var report: [2]u8 = undefined;
    const n = readReportFdRaw(errp_r.fd.?, &report);
    errp_r.close();
    if (n >= 2) {
        const code: u16 = std.mem.readInt(u16, &report, .little);
        const child_err: ChildExecError = @errorCast(@errorFromInt(code));
        // Reap the dying child (it already _exit'ed; EINTR retried like
        // std's childKillPosix wait). The report proves the exec failed.
        while (true) {
            var status: u32 = undefined;
            const rc = std.posix.system.waitpid(pid, @ptrCast(&status), 0);
            switch (std.posix.errno(rc)) {
                .SUCCESS => break,
                .INTR => continue,
                else => break, // ECHILD: somebody reaped it already
            }
        }
        // The ONLY fds still owned here are the two read ends; the
        // errdefer sweep closes exactly those and nothing else.
        return mapChildErr(child_err);
    }

    // Success: the read ends are the only fds that leave this function,
    // and only via this path (take hands ownership to the Child).
    return .{
        .id = pid,
        .thread_handle = {},
        .stdin = null,
        .stdout = .{ .handle = stdout_r.take(), .flags = .{ .nonblocking = false } },
        .stderr = .{ .handle = stderr_r.take(), .flags = .{ .nonblocking = false } },
        .request_resource_usage_statistics = false,
    };
}

// ---------------------------------------------------------------------------
// Acquisition helpers for spawnPinned.
// ---------------------------------------------------------------------------

/// One parent-held descriptor with explicit ownership tracking. `close`
/// is idempotent and a slot handed away via `take` (or already closed)
/// is never closed again — the property the double-close guard leans
// on: in a multithreaded daemon a second close of a
// freed fd number closes whatever FOREIGN descriptor another thread
// opened on that number.
const FdBox = struct {
    fd: ?std.posix.fd_t,

    fn of(fd: std.posix.fd_t) FdBox {
        return .{ .fd = fd };
    }

    fn empty() FdBox {
        return .{ .fd = null };
    }

    /// Hand the descriptor away (to the returned Child): the errdefer
    /// sweep must not close it.
    fn take(box: *FdBox) std.posix.fd_t {
        const fd = box.fd.?;
        box.fd = null;
        return fd;
    }

    /// Close a still-owned descriptor and mark the slot not-owned;
    /// already-handed-away or already-closed slots are a no-op.
    fn close(box: *FdBox) void {
        if (box.fd) |fd| {
            os_layer.closeFd(fd);
            box.fd = null;
        }
    }
};

/// Injectable CLOEXEC pipe creator: the error-injection tests drive the
/// acquisition-failure paths (the second creation failing after the
/// first succeeded) without touching the real syscall layer.
const PipeCreator = *const fn () std.process.SpawnError![2]std.posix.fd_t;

/// The production creator: std pipe2 with CLOEXEC (atomic on Linux; on
/// Darwin the pipe()+fcntl fallback whose CLOEXEC window the fork gate
/// exists to cover). pipe2's error set is a subset of SpawnError.
fn realPipeCreator() std.process.SpawnError![2]std.posix.fd_t {
    return std.Io.Threaded.pipe2(.{ .CLOEXEC = true });
}

/// Create ONE CLOEXEC pipe under the Darwin fork gate. The pairing is
/// structural: Enter pairs with `defer` Exit, so EVERY exit
/// path — success or the creator's error — releases the gate; an error
/// return can never strand it held (a held gate deadlocks every later
/// darwin fork/pipe operation through the atfork prepare hook). The gate
/// is always released BEFORE the fork: no code path forks while holding.
fn gatedPipe(creator: PipeCreator) std.process.SpawnError![2]std.posix.fd_t {
    darwinPipeGateEnter();
    defer darwinPipeGateExit();
    return creator();
}

/// /dev/null for the run-semantics stdin, acquired under the same
/// balanced gate (openat sets O_CLOEXEC atomically; the gate is kept for
/// one uniform acquisition discipline). Failure answers null — the
/// caller turns it into a spawn refusal.
fn gatedOpenDevnull() ?std.posix.fd_t {
    darwinPipeGateEnter();
    defer darwinPipeGateExit();
    return std.posix.openat(std.posix.AT.FDCWD, "/dev/null", .{ .ACCMODE = .RDWR, .CLOEXEC = true }, 0) catch null;
}

/// Map a child-side syscall error into the report set. std.posix errors
/// used between fork and exec are a subset of ChildExecError plus a few
/// names this narrows deliberately (chdir/setpgid/dup failures carry no
/// signal beyond "refused").
fn mapChildErr(err: anyerror) ChildExecError {
    return switch (err) {
        error.AccessDenied, error.PermissionDenied => error.AccessDenied,
        error.FileNotFound => error.FileNotFound,
        error.NotDir => error.NotDir,
        error.IsDir => error.IsDir,
        error.NameTooLong => error.NameTooLong,
        error.SystemResources => error.SystemResources,
        error.ProcessFdQuotaExceeded => error.ProcessFdQuotaExceeded,
        error.SystemFdQuotaExceeded => error.SystemFdQuotaExceeded,
        error.SymLinkLoop => error.SymLinkLoop,
        error.ProcessAlreadyExec => error.ProcessAlreadyExec,
        error.InvalidProcessGroupId => error.InvalidProcessGroupId,
        error.ResourceLimitReached => error.ResourceLimitReached,
        error.InvalidUserId => error.InvalidUserId,
        else => error.Unexpected,
    };
}

/// Blocking full read over a raw fd. Returns the number of bytes read
/// until EOF; used only for the 4-byte child report (a read error counts
/// as success-unknown, matching std's processSpawnPosix posture).
fn readReportFdRaw(fd: std.posix.fd_t, buf: []u8) usize {
    var got: usize = 0;
    while (got < buf.len) {
        const n = std.posix.read(fd, buf[got..]) catch return got;
        if (n == 0) break; // EOF: exec succeeded (CLOEXEC closed the write end)
        got += n;
    }
    return got;
}

/// Resolve a bare-name argv0 through PATH and PIN the found candidate:
/// same walk order as std's posixExecv and preflightExec (tokenize drops
/// empty entries; EACCES candidates remembered and skipped; ENOENT/ENOTDIR
/// skipped), but instead of stat-probing and forgetting, the candidate is
/// OPENED (os.secure.openPathCandidate: O_PATH, symlink-following — execvp
/// semantics, the gate authorized the name) and the descriptor becomes the
/// exec target. The probe keeps the execvp loop behavior (a non-executable
/// shadowing file does not stop the search); the open then pins whatever
/// object sits at the winning path.
pub fn resolvePinnedArgv0(
    arena: std.mem.Allocator,
    io: Io,
    argv0: []const u8,
    cwd: []const u8,
    path_env: ?[]const u8,
) !std.posix.fd_t {
    if (comptime native_os == .windows) @compileError("resolvePinnedArgv0 is POSIX-only");
    var eacces = false;
    const path_value = path_env orelse default_path_env;
    var it = std.mem.tokenizeScalar(u8, path_value, ':');
    while (it.next()) |entry| {
        const joined = try std.mem.concat(arena, u8, &.{ entry, "/", argv0 });
        // A relative PATH entry resolves against the child's post-chdir
        // cwd (the pinned cwd canon for pinned spawns).
        const candidate = if (entry.len != 0 and entry[0] == '/')
            joined
        else
            try childRelative(arena, cwd, joined);
        if (try probeCandidate(io, candidate, &eacces)) {
            const fd = os_layer.secure.openPathCandidate(io, candidate) catch |err| {
                // Raced away between probe and open: execvp would answer
                // ENOENT for the exec attempt and continue the loop.
                if (err == error.FileNotFound or err == error.NotDir) continue;
                // Darwin arm: the probe's
                // pathname stat raced — the open landed on a FIFO (or
                // another non-regular object). execvp's execve would
                // answer EACCES there, so the loop remembers and keeps
                // searching instead of failing the whole resolution.
                if (err == error.NotRegularFile or err == error.IsDir) {
                    eacces = true;
                    continue;
                }
                return err;
            };
            return fd;
        }
    }
    if (eacces) return error.AccessDenied;
    return error.FileNotFound;
}

/// Bounded collect semantics over an already-spawned child: a faithful local
/// replica of std.process.run's body — MultiReader over the two pipes with
/// the caller's limits and timeout, then wait. The defer child.kill covers
/// every error exit (timeout included), exactly like std's run.
///
/// ONE monotonic deadline covers output
/// collection AND the exit wait. std's run (and this replica before it)
/// blocked forever in the final `child.wait` when the child closed its
/// stdout/stderr and kept living — the defer kill never ran while the
/// wait was parked. Here the deadline is anchored once at entry, the
/// fill loop consumes `.deadline` (not a per-fill re-armed duration), and
/// the post-EOF wait polls only for the REMAINDER of the same deadline;
/// on expiry the tree is killed and reaped through std's own child
/// machinery, and the caller gets error.Timeout — the same error the
/// output phase surfaces, which runExec maps to its machine-readable
/// {"ok":false,"timeout":true} reply.
///
/// The collect is the shared implementation for every synchronous exec
/// branch, pinned and unpinned alike, so both paths enforce the same
/// deadline across output drain and child wait. The caller decides how the
/// child was spawned (spawnPinned with execveat/fchdir pins, or std's raw
/// spawn).
pub const CollectedRunOptions = struct {
    stdout_limit: Io.Limit = .unlimited,
    stderr_limit: Io.Limit = .unlimited,
    reserve_amount: usize = 64,
    timeout: Io.Timeout = .none,
};

pub fn runCollected(
    gpa: std.mem.Allocator,
    io: Io,
    child: *std.process.Child,
    options: CollectedRunOptions,
) std.process.RunError!std.process.RunResult {
    defer child.kill(io);

    // Anchor the single deadline once: a `.duration` becomes a timestamp
    // here (fromNow), so the fill loop below and the exit wait share one
    // monotonic budget instead of each re-arming the full window.
    const deadline: ?Io.Clock.Timestamp = switch (options.timeout) {
        .none => null,
        .duration => |d| Io.Clock.Timestamp.fromNow(io, d),
        .deadline => |d| d,
    };
    const fill_timeout: Io.Timeout = if (deadline) |dl| .{ .deadline = dl } else .none;

    var multi_reader_buffer: Io.File.MultiReader.Buffer(2) = undefined;
    var multi_reader: Io.File.MultiReader = undefined;
    multi_reader.init(gpa, io, multi_reader_buffer.toStreams(), &.{ child.stdout.?, child.stderr.? });
    defer multi_reader.deinit();

    const stdout_reader = multi_reader.reader(0);
    const stderr_reader = multi_reader.reader(1);

    while (multi_reader.fill(options.reserve_amount, fill_timeout)) |_| {
        if (options.stdout_limit.toInt()) |limit| {
            if (stdout_reader.buffered().len > limit) return error.StreamTooLong;
        }
        if (options.stderr_limit.toInt()) |limit| {
            if (stderr_reader.buffered().len > limit) return error.StreamTooLong;
        }
    } else |err| switch (err) {
        error.EndOfStream => {}, // EOF: output complete, the child may still live
        else => |e| return e,
    }

    try multi_reader.checkAnyError();

    const term = switch (try waitCollectedChild(io, child, deadline)) {
        .timed_out => return error.Timeout,
        .term => |t| t,
    };

    const stdout_slice = try multi_reader.toOwnedSlice(0);
    errdefer gpa.free(stdout_slice);

    const stderr_slice = try multi_reader.toOwnedSlice(1);
    errdefer gpa.free(stderr_slice);

    return .{
        .stdout = stdout_slice,
        .stderr = stderr_slice,
        .term = term,
    };
}

/// Fixed read buffers are resubmitted only after consumption. No output-sized
/// MultiReader allocations or background collector threads are needed.
pub fn runCollectedShaped(
    io: Io,
    child: *std.process.Child,
    streams: *[2]@import("../output_shape.zig").Stream,
    timeout: Io.Timeout,
) !struct { term: ?std.process.Child.Term, failure: ?[]const u8 = null } {
    defer child.kill(io);
    const deadline: ?Io.Clock.Timestamp = switch (timeout) {
        .none => null,
        .duration => |d| Io.Clock.Timestamp.fromNow(io, d),
        .deadline => |d| d,
    };
    const fill_timeout: Io.Timeout = if (deadline) |dl| .{ .deadline = dl } else .none;
    var buffers: [2][4096]u8 = undefined;
    var vectors = [2][1][]u8{ .{&buffers[0]}, .{&buffers[1]} };
    var storage: [2]Io.Operation.Storage = undefined;
    var batch: Io.Batch = .init(&storage);
    // Cancellation can race a successful read. Account those completions too,
    // before the caller renders partial streams; never discard observed bytes.
    defer {
        batch.cancel(io);
        while (batch.next()) |operation| {
            const n = operation.result.file_read_streaming catch continue;
            streams[operation.index].feed(buffers[operation.index][0..n]) catch {};
        }
    }
    const files = [2]Io.File{ child.stdout.?, child.stderr.? };
    for (files, 0..) |file, i| batch.addAt(@intCast(i), .{ .file_read_streaming = .{ .file = file, .data = &vectors[i] } });
    var active: usize = 2;
    while (active != 0) {
        batch.awaitConcurrent(io, fill_timeout) catch |err| {
            return .{ .term = null, .failure = if (err == error.Timeout) "CommandTimeout" else @errorName(err) };
        };
        while (batch.next()) |operation| {
            const i = operation.index;
            const n = operation.result.file_read_streaming catch |err| {
                if (err == error.EndOfStream) {
                    active -= 1;
                    continue;
                }
                return .{ .term = null, .failure = @errorName(err) };
            };
            if (n == 0) {
                active -= 1;
                continue;
            }
            streams[i].feed(buffers[i][0..n]) catch |err| {
                return .{ .term = null, .failure = @errorName(err) };
            };
            // Never read beyond the per-stream drain ceiling.
            const remaining = @import("../output_shape.zig").DRAIN_LIMIT - streams[i].total;
            vectors[i][0] = buffers[i][0..@min(buffers[i].len, remaining)];
            batch.addAt(i, .{ .file_read_streaming = .{ .file = files[i], .data = &vectors[i] } });
        }
    }
    return switch (try waitCollectedChild(io, child, deadline)) {
        .timed_out => .{ .term = null, .failure = "CommandTimeout" },
        .term => |term| .{ .term = term },
    };
}

/// Outcome of the post-EOF exit wait: the child's term, or the deadline
/// expiring with the child still alive (already killed and reaped when
/// this is returned).
const WaitOutcome = union(enum) {
    term: std.process.Child.Term,
    timed_out: void,
};

/// Wait for `child` to exit, bounded by `deadline` (null = wait
/// forever, the no-timeout semantics). On expiry the child is killed
/// (the whole tree where the child leads one) and reaped THROUGH std's
/// own child machinery, so the deferred `child.kill` in runCollected stays
/// a no-op and no later std wait can hit the debug-only ECHILD panic.
///
/// POSIX: poll waitid(WEXITED|WNOHANG|WNOWAIT) — detection WITHOUT
/// reaping, so `child.wait` stays the single owner of the reap — and on
/// expiry killTree first (SIGKILL is not ignorable, the following wait
/// returns promptly). Windows: a bounded NtWaitForSingleObject on the
/// process handle, then std's wait; expiry goes through child.kill
/// (terminate + wait + cleanup).
fn sleepNs(ns: u64) void {
    const sec = ns / std.time.ns_per_s;
    const nsec = ns % std.time.ns_per_s;
    if (comptime native_os == .linux) {
        var ts = std.os.linux.timespec{ .sec = @intCast(sec), .nsec = @intCast(nsec) };
        _ = std.os.linux.nanosleep(&ts, null);
    } else {
        var ts = std.c.timespec{ .sec = @intCast(sec), .nsec = @intCast(nsec) };
        _ = std.c.nanosleep(&ts, null);
    }
}

fn waitCollectedChild(io: Io, child: *std.process.Child, deadline: ?Io.Clock.Timestamp) std.process.Child.WaitError!WaitOutcome {
    const dl = deadline orelse return .{ .term = try child.wait(io) };
    if (comptime native_os == .windows) {
        return waitCollectedChildWindows(io, child, dl);
    } else {
        const pid = child.id.?;
        var timed_out = false;
        var poll_ns: u64 = 20 * std.time.ns_per_us;
        while (true) {
            // Exited already? WNOWAIT keeps the zombie for child.wait.
            if (childExitPending(pid)) break;
            const rem_ns = dl.durationFromNow(io).raw.nanoseconds;
            if (rem_ns <= 0) {
                // Deadline gone: kill the tree (group when the child leads
                // one, the leader itself always), then reap below. A
                // child that merely closed its pipes gets exactly the
                // timeout the caller asked for, never a parked wait.
                killTree(pid, no_job);
                timed_out = true;
                break;
            }
            const sleep_ns: u64 = @min(poll_ns, @as(u64, @intCast(rem_ns)));
            sleepNs(sleep_ns);
            poll_ns = @min(poll_ns * 2, 10 * std.time.ns_per_ms);
        }
        // The reap goes through std's child.wait either way: after a
        // natural exit it returns the real term; after the SIGKILL above
        // it returns promptly with the kill term (discarded — the caller
        // sees error.Timeout, the same error the output phase surfaces).
        const term = try child.wait(io);
        return if (timed_out) .timed_out else .{ .term = term };
    }
}

/// Windows half of the bounded exit wait (referenced from the comptime
/// Windows branch above only). The NT timeout is a negative relative
/// value in 100ns units (minInt = infinite, hence the loop's bounded
/// slices); STATUS_TIMEOUT means the deadline slice elapsed, not that
/// the process died.
fn waitCollectedChildWindows(io: Io, child: *std.process.Child, dl: Io.Clock.Timestamp) std.process.Child.WaitError!WaitOutcome {
    const handle = child.id.?;
    const tick_ns: i96 = 50 * std.time.ns_per_ms;
    while (true) {
        const remaining = dl.durationFromNow(io).raw.nanoseconds;
        if (remaining <= 0) {
            child.kill(io); // terminate + wait + cleanup (id := null)
            return .timed_out;
        }
        const slice = @min(remaining, tick_ns);
        var li: windows.LARGE_INTEGER = @intCast(@divTrunc(-slice, 100)); // relative, 100ns units
        switch (windows.ntdll.NtWaitForSingleObject(handle, .FALSE, &li)) {
            .SUCCESS => return .{ .term = try child.wait(io) }, // signaled: exited
            .TIMEOUT => continue, // this slice elapsed: re-check the deadline
            else => return .{ .term = try child.wait(io) }, // wait failure: let std's wait surface the state
        }
    }
}

/// True when the direct child `pid` has terminated (exited or killed)
/// without being reaped: waitid(WEXITED|WNOHANG|WNOWAIT) reports si_pid
/// only when the termination is already pending. Pure detection — the
/// zombie is deliberately left for `child.wait` to reap, so std stays
/// the single owner of the reap.
fn childExitPending(pid: std.posix.pid_t) bool {
    if (comptime native_os == .linux) {
        while (true) {
            var info: std.os.linux.siginfo_t = undefined;
            const rc = std.os.linux.waitid(.PID, pid, &info, std.os.linux.W.EXITED | std.os.linux.W.NOWAIT | std.os.linux.W.NOHANG, null);
            switch (std.os.linux.errno(rc)) {
                .SUCCESS => return info.fields.common.first.piduid.pid != 0,
                .INTR => continue,
                else => return false, // ECHILD/other: let the caller's wait decide
            }
        }
    } else {
        // Darwin (and other POSIX): the extern waitid declared above;
        // WNOHANG=1, WEXITED=4, WNOWAIT=0x20 (see darwin_wexited_nowait).
        while (true) {
            var info: std.c.siginfo_t = std.mem.zeroes(std.c.siginfo_t);
            const rc = waitid(@intFromEnum(DarwinIdType.pid), pid, &info, 0x1 | 0x4 | 0x20);
            if (rc == 0) return info.pid != 0;
            if (comptime @hasDecl(std.c, "_errno")) {
                if (std.c._errno().* == @intFromEnum(std.c.E.INTR)) continue;
                return false;
            } else {
                return false;
            }
        }
    }
}

fn protectedPid(protected: []const std.posix.pid_t, pid: std.posix.pid_t) bool {
    for (protected) |p| {
        if (p == pid) return true;
    }
    return false;
}

/// Enumerate one pending (exited, unreaped) child WITHOUT reaping it.
/// Returns 0 when nothing is pending; null when there is nothing to report
/// at all (no children / transient error).
fn enumeratePendingChild() ?std.posix.pid_t {
    if (comptime native_os == .linux) {
        while (true) {
            var info: std.os.linux.siginfo_t = undefined;
            const rc = std.os.linux.waitid(
                .ALL,
                0,
                &info,
                std.os.linux.W.EXITED | std.os.linux.W.NOWAIT | std.os.linux.W.NOHANG,
                null,
            );
            switch (std.os.linux.errno(rc)) {
                .SUCCESS => return info.fields.common.first.piduid.pid,
                .INTR => continue,
                else => return null,
            }
        }
    } else {
        // Darwin: the extern waitid declared above; WNOHANG=1, WEXITED=4,
        // WNOWAIT=0x20 (see darwin_wexited_nowait).
        while (true) {
            var info: std.c.siginfo_t = std.mem.zeroes(std.c.siginfo_t);
            const rc = waitid(@intFromEnum(DarwinIdType.all), 0, &info, 0x1 | 0x4 | 0x20);
            if (rc == 0) return info.pid;
            if (comptime @hasDecl(std.c, "_errno")) {
                if (std.c._errno().* == @intFromEnum(std.c.E.INTR)) continue;
                return null;
            } else {
                return null;
            }
        }
    }
}

/// Reap one specific child, non-blocking. True when this call consumed the
/// zombie; false when it was already gone (ECHILD) — both outcomes leave no
/// zombie behind.
fn reapChild(pid: std.posix.pid_t) bool {
    if (comptime native_os == .linux) {
        while (true) {
            var info: std.os.linux.siginfo_t = undefined;
            const rc = std.os.linux.waitid(.PID, pid, &info, std.os.linux.W.EXITED | std.os.linux.W.NOHANG, null);
            switch (std.os.linux.errno(rc)) {
                .SUCCESS => return info.fields.common.first.piduid.pid != 0,
                .INTR => continue,
                else => return false,
            }
        }
    } else {
        while (true) {
            var info: std.c.siginfo_t = std.mem.zeroes(std.c.siginfo_t);
            const rc = waitid(@intFromEnum(DarwinIdType.pid), pid, &info, 0x1 | 0x4);
            if (rc == 0) return info.pid != 0;
            if (comptime @hasDecl(std.c, "_errno")) {
                if (std.c._errno().* == @intFromEnum(std.c.E.INTR)) continue;
                return false;
            } else {
                return false;
            }
        }
    }
}

/// Decision for one enumerated zombie inside `reapStrayChildren`, factored
/// out so the pass logic is unit-testable without real children:
///   * `reap` — unprotected pid: consume the zombie now.
///   * `skip` — protected pid seen for the first time in this pass: leave
///     the zombie to the session that owns it, and remember the skip.
///   * `stop` — protected pid already skipped in this pass: waitid(.ALL,
///     WNOWAIT) hands zombies out in unspecified order and keeps
///     re-reporting skipped ones, so a repeat means the enumeration has
///     wrapped — every zombie was already offered once.
const ReapAction = enum { reap, skip, stop };

fn reapAction(protected: []const std.posix.pid_t, pid: std.posix.pid_t, skipped: []const std.posix.pid_t) ReapAction {
    if (!protectedPid(protected, pid)) return .reap;
    for (skipped) |sp| {
        if (sp == pid) return .stop;
    }
    return .skip;
}

/// Reap zombie children that no session machinery owns. `protected` holds
/// pids somebody else is responsible for reaping (session children from
/// fork until their waiter's wait).
///
/// Linux: `reapStraysFromWaitAll` runs first; when no protected zombie was
/// skipped and the 64-round cap was not hit, `waitid(P_ALL, WNOHANG)` proves in
/// one syscall that no pending zombies remain. Only when a protected zombie was
/// skipped (or the round cap was reached) does the sweep fall through to
/// `reapStraysFromProc` — an address-based walk of `/proc` that reaps any
/// unprotected zombie hidden behind a protected one in `waitid(P_ALL)`.
/// The `/proc` walk has no ordering hazard on skipped protected entries, and
/// non-Linux POSIX targets use `reapStraysFromWaitAll` as their sole mechanism
/// (no `/proc` there).
/// Returns the number of strays reaped.
pub fn reapStrayChildren(protected: []const std.posix.pid_t) usize {
    const pass = reapStraysFromWaitAll(protected);
    var reaped: usize = pass.reaped;
    if (comptime native_os == .linux) {
        if (pass.needs_proc_walk) reaped += reapStraysFromProc(protected);
    }
    return reaped;
}

// ---------------------------------------------------------------------------
// Owned-child registry (the sweep's protected set). POSIX only; the Windows
// Job Object owns its tree and the call sites are comptime-gated.
//
// Every child with a live owner is registered from spawn until the owner's
// reap is confirmed: session children (registered by toolExecStart, removed
// by the session waiter after child.wait) and synchronous exec children
// (registered by runExec/runExecPinned, removed when runCollected's wait
// returns). Because the protected set is complete at all times, a stray
// sweep may run at ANY moment — no global-quiescence precondition — which
// keeps the registry bounded by live concurrency instead of total history.
//
// Removal matches the (pid, tag) pair: after an owner reaps, the pid may be
// recycled into a new registration before the old owner's removal runs, and
// only the monotonically increasing tag tells the stale entry apart.
// ---------------------------------------------------------------------------

var pending_mutex: std.Io.Mutex = .init;
var pending_pids: std.ArrayList(ProcessId) = .empty;
var pending_tags: std.ArrayList(u64) = .empty;
var pending_tag_counter: u64 = 0;

/// Register a freshly spawned owned child. Returns the removal tag, or null
/// when the append failed — the caller must then kill+reap the child inline
/// (an unregistered child is unprotected: a sweep could steal its wait).
pub fn registerSpawnPid(io: Io, pid: ProcessId) ?u64 {
    if (comptime builtin.os.tag == .windows) return null;
    pending_mutex.lockUncancelable(io);
    defer pending_mutex.unlock(io);
    pending_tag_counter +%= 1;
    const tag = pending_tag_counter;
    pending_pids.append(std.heap.page_allocator, pid) catch return null;
    pending_tags.append(std.heap.page_allocator, tag) catch {
        _ = pending_pids.pop();
        return null;
    };
    return tag;
}

/// Remove exactly the (pid, tag) registration — a recycled pid with a
/// different tag is a different owner and must survive.
pub fn unregisterSpawnPid(io: Io, pid: ProcessId, tag: u64) void {
    if (comptime builtin.os.tag == .windows) return;
    pending_mutex.lockUncancelable(io);
    defer pending_mutex.unlock(io);
    var i = pending_pids.items.len;
    while (i > 0) {
        i -= 1;
        if (pending_pids.items[i] == pid and pending_tags.items[i] == tag) {
            _ = pending_pids.orderedRemove(i);
            _ = pending_tags.orderedRemove(i);
            return;
        }
    }
}

/// Backstop compaction: drop registrations whose child is fully reaped and
/// gone (waitid answers ECHILD once the owner's wait consumed the zombie).
/// Owner-driven removal keeps this list short between sweeps.
pub fn compactSpawnPidRegistry(io: Io) void {
    if (comptime builtin.os.tag == .windows) return;
    pending_mutex.lockUncancelable(io);
    defer pending_mutex.unlock(io);
    var kept: usize = 0;
    for (pending_pids.items, pending_tags.items) |pid, tag| {
        if (childStillTracked(pid)) {
            pending_pids.items[kept] = pid;
            pending_tags.items[kept] = tag;
            kept += 1;
        }
    }
    pending_pids.shrinkRetainingCapacity(kept);
    pending_tags.shrinkRetainingCapacity(kept);
}

/// Run the stray sweep with the registry as the protected set. The registry
/// mutex is held across the sweep so the protected slice cannot change
/// mid-walk.
pub fn sweepStraysWithRegistry(io: Io) usize {
    if (comptime builtin.os.tag == .windows) return 0;
    pending_mutex.lockUncancelable(io);
    defer pending_mutex.unlock(io);
    return reapStrayChildren(pending_pids.items);
}

/// Test/diagnostic view: live registration count.
pub fn spawnPidRegistryLen(io: Io) usize {
    if (comptime builtin.os.tag == .windows) return 0;
    pending_mutex.lockUncancelable(io);
    defer pending_mutex.unlock(io);
    return pending_pids.items.len;
}

/// True when `stat` (the content of /proc/<pid>/stat, which embeds the
/// comm field in parens — possibly with spaces — so parsing starts after
/// the LAST ')' exactly like procps does) describes a zombie whose parent
/// is `parent_pid`. Pure function, unit-tested separately.
fn statIsZombieChild(stat: []const u8, parent_pid: i32) bool {
    const close_paren = std.mem.lastIndexOfScalar(u8, stat, ')') orelse return false;
    var it = std.mem.tokenizeScalar(u8, stat[close_paren + 1 ..], ' ');
    const state = it.next() orelse return false;
    if (state.len == 0 or state[0] != 'Z') return false;
    const ppid_text = it.next() orelse return false;
    const ppid = std.fmt.parseInt(i32, ppid_text, 10) catch return false;
    return ppid == parent_pid;
}

/// Raw getdents64 reader contract: takes the directory fd and a buffer,
/// answers the kernel's raw return — a byte count on success, 0 at EOF,
/// or an errno packed as a negative value inside the unsigned usize
/// (std.os.linux.errno decodes exactly that). Injectable as a function
/// pointer so tests drive the error paths without a real directory.
const RawDirReader = *const fn (fd: std.posix.fd_t, buf: []u8) usize;

/// The production reader: the raw getdents64 syscall.
fn rawGetdents64(fd: std.posix.fd_t, buf: []u8) usize {
    return std.os.linux.getdents64(fd, buf.ptr, buf.len);
}

/// Linux `/proc` stray sweep (when `waitid(P_ALL)` skipped a protected zombie):
/// enumerate `/proc`, and for every numeric pid whose `/proc/<pid>/stat` says
/// "zombie child of this process", reap it addressally unless protected.
/// Zombies are terminal states, so the usual readdir/stat races cannot
/// misclassify one (a pid that exits after its stat was read is not a zombie
/// yet — the next sweep picks it up). Returns the number reaped.
///
/// The getdents64 loop checks errno BEFORE touching the returned records:
/// a failed call answers -errno encoded in the unsigned return value, so a
/// bare `n <= 0` guard misreads an error (≈maxInt) as a huge batch count
/// and walks uninitialized dir bytes — OOB reads, safety traps, or an
/// infinite loop on a reclen==0 record (openRaw in this file decodes the
/// same raw-errno convention via @bitCast; getdents64 needs the switch
/// form because EINTR must retry). EINTR retries; any other error stops
/// the sweep and returns the strays already collected — the sweep is
/// best-effort and must never take the daemon down. `reader` injects the
/// syscall so the unit tests drive the errno paths (see the test block
/// near the bottom of this file).
fn reapStraysFromProcReader(protected: []const std.posix.pid_t, reader: RawDirReader) usize {
    const flags: std.os.linux.O = .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true };
    const dir_fd = openRaw("/proc", flags) orelse return 0;
    defer _ = std.os.linux.close(dir_fd);

    var reaped: usize = 0;
    const my_pid = std.os.linux.getpid();
    var stat_buf: [512]u8 = undefined;
    var dir_buf: [4096]u8 = undefined;
    while (true) {
        const n = reader(dir_fd, &dir_buf);
        switch (std.os.linux.errno(n)) {
            .SUCCESS => {},
            .INTR => continue,
            // Persistent error (EIO, EPERM, ...): return what this sweep
            // already collected instead of parsing error-valued bytes.
            else => return reaped,
        }
        if (n == 0) break; // end of directory
        reaped += reapProcBatch(dir_buf[0..n], protected, my_pid, &stat_buf);
    }
    return reaped;
}

fn reapStraysFromProc(protected: []const std.posix.pid_t) usize {
    return reapStraysFromProcReader(protected, rawGetdents64);
}

/// Parse one getdents64 batch (the `n` valid kernel bytes in `batch`) and
/// reap every unprotected zombie child of `my_pid` named in it. Split out
/// from the syscall loop so the record walk is unit-testable on its own.
/// Memory safety does not lean on kernel record guarantees: a record with
/// reclen 0, a reclen shorter than the fixed header, a reclen overrunning
/// the batch, or a name missing its NUL inside the record stops/skips that
/// record instead of walking past the buffer.
fn reapProcBatch(batch: []u8, protected: []const std.posix.pid_t, my_pid: std.posix.pid_t, stat_buf: []u8) usize {
    var reaped: usize = 0;
    const name_off = @offsetOf(std.os.linux.dirent64, "name");
    var off: usize = 0;
    while (off + name_off <= batch.len) {
        const entry: *align(1) const std.os.linux.dirent64 = @ptrCast(batch[off..].ptr);
        const reclen: usize = entry.reclen;
        // reclen < name_off covers 0 (infinite loop) AND any header-truncated
        // record: for those the name slice below would start past its end
        // (start > end), a ReleaseSafe safety trap.
        if (reclen < name_off or off + reclen > batch.len) break;
        off += reclen;
        // dirent64.name is a flexible array: the name bytes (NUL included)
        // live inside the record, bounded by reclen — never past batch.
        const name_region = batch[off - reclen + name_off .. off];
        const nul = std.mem.indexOfScalar(u8, name_region, 0) orelse continue;
        const name = name_region[0..nul];
        // /proc mixes pid dirs with non-numeric entries (self, thread
        // dirs, loadavg...): only numeric ones can be processes.
        const pid = std.fmt.parseInt(std.posix.pid_t, name, 10) catch continue;
        var path_buf: [64]u8 = undefined;
        const path = std.fmt.bufPrintZ(&path_buf, "/proc/{d}/stat", .{pid}) catch continue;
        const stat_fd = openRaw(path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }) orelse continue;
        defer _ = std.os.linux.close(stat_fd);
        const stat_len = readAllFdRaw(stat_fd, stat_buf) orelse continue;
        if (!statIsZombieChild(stat_buf[0..stat_len], my_pid)) continue;
        if (protectedPid(protected, pid)) continue;
        if (reapChild(pid)) reaped += 1;
    }
    return reaped;
}

/// Raw-syscall open: raw linux.open returns -errno packed into usize, which
/// must be reinterpreted (not intCast) before the sign check, or a failed
/// open panics on the cast instead of failing. `path` is a sentinel slice
/// (string literals and bufPrintZ results coerce to it). Returns the fd or
/// null on failure.
fn openRaw(path: [:0]const u8, flags: std.os.linux.O) ?std.posix.fd_t {
    const rc = std.os.linux.open(path.ptr, flags, 0);
    const signed: isize = @bitCast(rc);
    if (signed < 0) return null;
    return @intCast(signed);
}

/// Read the whole small /proc file into `buf` with raw Linux syscalls
/// (EINTR-retried); returns the byte count or null on error. The stray
/// sweep runs without an allocator, so it cannot use the Io layer.
fn readAllFdRaw(fd: std.posix.fd_t, buf: []u8) ?usize {
    var total: usize = 0;
    while (total < buf.len) {
        const rc = std.os.linux.read(fd, buf.ptr + total, buf.len - total);
        switch (std.os.linux.errno(rc)) {
            .SUCCESS => {
                if (rc == 0) return total;
                total += rc;
            },
            .INTR => continue,
            else => return if (total > 0) total else null,
        }
    }
    return total;
}

/// The waitid(P_ALL) backstop pass (see reapStrayChildren). Protected
/// zombies are passed over and remembered;
/// when the same protected pid comes back the pass exits instead of
/// spinning. The skip registry only ever holds protected pids (an
/// unprotected zombie is reaped, i.e. consumed, on first sight), so its
/// natural bound is the protected set; the fixed buffer is the
/// no-allocation cap (a protected set larger than it bails out), and the
/// round counter is a defensive backstop against a kernel that would keep
/// handing back a pid no reap consumes. Returns the number of strays
/// reaped.
const WaitAllResult = struct {
    reaped: usize,
    needs_proc_walk: bool,
};

fn reapStraysFromWaitAll(protected: []const std.posix.pid_t) WaitAllResult {
    var skipped: [64]std.posix.pid_t = undefined;
    var skipped_n: usize = 0;
    var reaped: usize = 0;
    var round: usize = 0;
    while (round < 64) : (round += 1) {
        const pid = enumeratePendingChild() orelse break;
        if (pid == 0) break;
        switch (reapAction(protected, pid, skipped[0..skipped_n])) {
            .reap => {
                if (reapChild(pid)) reaped += 1;
            },
            .skip => {
                if (skipped_n == skipped.len) break; // registry full: cannot track more, bail out
                skipped[skipped_n] = pid;
                skipped_n += 1;
            },
            .stop => break,
        }
    }
    return .{
        .reaped = reaped,
        .needs_proc_walk = skipped_n > 0 or round == 64,
    };
}

/// True while `pid` is still a child of this process (running, or a zombie
/// pending its owner's reap). Once the owner reaps it, waitid answers ECHILD
/// and the entry can be dropped from the protected set. Pid recycling is
/// safe in the other direction too: a recycled pid belongs to somebody else
/// (ECHILD, dropped) until a fresh registration re-adds it.
pub fn childStillTracked(pid: std.posix.pid_t) bool {
    if (comptime native_os == .linux) {
        while (true) {
            var info: std.os.linux.siginfo_t = undefined;
            const rc = std.os.linux.waitid(.PID, pid, &info, std.os.linux.W.EXITED | std.os.linux.W.NOWAIT | std.os.linux.W.NOHANG, null);
            switch (std.os.linux.errno(rc)) {
                .SUCCESS => return true, // pending zombie, or running (0 would mean "no event" — still ours)
                .INTR => continue,
                else => return false, // ECHILD: fully reaped (or recycled away)
            }
        }
    } else {
        while (true) {
            var info: std.c.siginfo_t = std.mem.zeroes(std.c.siginfo_t);
            const rc = waitid(@intFromEnum(DarwinIdType.pid), pid, &info, 0x1 | 0x4 | 0x20);
            if (rc == 0) return true;
            if (comptime @hasDecl(std.c, "_errno")) {
                if (std.c._errno().* == @intFromEnum(std.c.E.INTR)) continue;
                return false;
            } else {
                return false;
            }
        }
    }
}

/// Result of one blocking pipe read for the Windows session readers.
pub const PipeRead = union(enum) {
    /// The read delivered `n` bytes into the caller's buffer.
    bytes: usize,
    /// EOF: every pipe write end is gone (PIPE_BROKEN / END_OF_FILE —
    /// the job kill closed the writers). The output is complete.
    eof,
    /// The wake event fired with the read still pending: forced stop.
    /// The pending read was cancelled (CancelIoEx), so whatever was
    /// still buffered in the pipe is dropped — unknowable how much, the
    /// same as the POSIX wake-only poll exit. Mirrors that path; the
    /// lost_* counters stay max_out-overflow metrics on both platforms.
    woken,
    /// The read (or the wait) failed outright.
    failed,
};

/// Blocking read from an asynchronous pipe handle (the std-created child
/// stdout/stderr ends are opened with MODE.IO.ASYNCHRONOUS). Issues
/// NtReadFile; on STATUS_PENDING waits (WaitAny — see NtWaitType) on BOTH
/// the pipe handle and, when provided, the wake event: whichever is
/// signaled FIRST ends the wait. The kernel signals the file handle when
/// the overlapped operation completes; a close request sets the wake
/// event (see sessionRequestClose), the wait returns on it, the pending
/// read is cancelled from this same thread (CancelIoEx with no OVERLAPPED
/// cancels every I/O this thread issued on the handle) and the
/// cancellation is waited out before the caller closes the handle — the
/// returned Nt status is checked so the wait can only be abandoned on an
/// already-terminal handle. A synchronous (non-PENDING) return is
/// classified from the NtReadFile status itself: the kernel does not
/// guarantee the iosb was touched on an immediate failure, and EOF on a
/// writer-less pipe arrives as a direct PIPE_BROKEN / END_OF_FILE return.
pub fn readPipeBlocking(handle: windows.HANDLE, wake: ?windows.HANDLE, buf: []u8) PipeRead {
    var iosb: windows.IO_STATUS_BLOCK = undefined;
    switch (windows.ntdll.NtReadFile(
        handle,
        null, // event: wait on the file handle itself instead
        null, // apc routine
        null, // apc context
        &iosb,
        buf.ptr,
        @intCast(buf.len),
        null, // byte offset: pipes are sequential
        null, // key
    )) {
        .SUCCESS => {},
        .PENDING => {
            if (wake) |ev| {
                var handles = [2]windows.HANDLE{ handle, ev };
                // WaitAny (NtWaitType above): return as soon as EITHER
                // the overlapped read completes OR the wake event is
                // set. With WaitAll=0 this would park until BOTH are
                // signaled — a read completing would NOT be enough, the
                // wake is only set at close time, and a plain child
                // filling the pipe would deadlock the reader (the exact
                // bug the typed enum exists to prevent).
                const st = NtWaitForMultipleObjects(2, &handles, @intFromEnum(NtWaitType.WAIT_ANY), 0, null);
                switch (decodeWaitAnyStatus(st)) {
                    .pipe_ready => {}, // the read completed: fall through to the iosb
                    .wake_signaled => {
                        // Wake signal: cancel the pending read issued by
                        // this thread and let the cancellation complete
                        // before the reader closes the handle.
                        _ = CancelIoEx(handle, null);
                        switch (windows.ntdll.NtWaitForSingleObject(handle, .FALSE, null)) {
                            .SUCCESS => {},
                            // The handle is already terminal (or the read
                            // completed between the wake and the cancel);
                            // either way there is nothing left to wait for.
                            else => {},
                        }
                        return .woken;
                    },
                    .failed => return .failed,
                }
            } else {
                _ = windows.ntdll.NtWaitForSingleObject(handle, .FALSE, null); // infinite
            }
        },
        // Synchronous EOF: no write end is left, so there will never be
        // more output — drain is complete.
        .PIPE_BROKEN, .END_OF_FILE => return .eof,
        // Synchronous failure: the iosb is not guaranteed to be valid
        // here, the call status itself is the verdict.
        else => return .failed,
    }
    return switch (iosb.u.Status) {
        .SUCCESS => .{ .bytes = iosb.Information },
        // The overlapped read completed as EOF (writer side died with the
        // job): same meaning as the synchronous case above.
        .PIPE_BROKEN, .END_OF_FILE => .eof,
        else => .failed,
    };
}

pub const WriteAllError = os_layer.WriteAllError;

/// Full-buffer write with short-write loop. POSIX delegates to the shared os
/// layer. Windows loops NtWriteFile
/// on the synchronous stdin pipe end; a dead child surfaces as an error
/// (PIPE_BROKEN), matching EPIPE on POSIX.
pub fn writeAllFd(fd: std.posix.fd_t, bytes: []const u8) WriteAllError!void {
    if (comptime native_os == .windows) {
        var off: usize = 0;
        while (off < bytes.len) {
            var iosb: windows.IO_STATUS_BLOCK = undefined;
            const chunk: u32 = @intCast(@min(bytes.len - off, std.math.maxInt(u32)));
            switch (windows.ntdll.NtWriteFile(fd, null, null, null, &iosb, bytes.ptr + off, chunk, null, null)) {
                .SUCCESS => {
                    // Zero progress with a non-empty chunk would spin forever.
                    if (iosb.Information == 0) return error.WriteFailed;
                    off += iosb.Information;
                },
                else => return error.WriteFailed,
            }
        }
        return;
    } else {
        return os_layer.writeAllFd(fd, bytes);
    }
}

// ---------------------------------------------------------------------------
// Unit tests. The pre-flight is stat-only: no process is ever spawned, so
// every fixture is just files and directories under a testing tmp dir. CI
// runs unit tests on Linux only (same SkipZigTest gate as sysinfo.zig);
// bodies stay analyzable on every target — the platform-only helpers below
// split their bodies at comptime, mirroring os.fd.writeFile's dispatcher.
// ---------------------------------------------------------------------------

/// Relative path of `sub_path` inside a testing tmp dir, resolved against
/// the test binary's cwd (std.testing.tmpDir nests under .zig-cache/tmp
/// there) — the same cwd preflightExec resolves relative paths against.
fn tmpRelPath(arena: std.mem.Allocator, tmp: *const std.testing.TmpDir, sub_path: []const u8) ![]const u8 {
    return std.fmt.allocPrint(arena, ".zig-cache/tmp/{s}/{s}", .{ tmp.sub_path, sub_path });
}

/// Write a fixture file at a cwd-relative `path` with the requested
/// permission bits on Linux (openat applies them, subject to umask); other
/// targets never execute these tests and get a plain write so every mode_t
/// flavor stays compilable.
fn writeFixtureFile(io: Io, path: []const u8, data: []const u8, mode: u32) !void {
    // No `_ = mode` discard in the fallback branch: the unused/discard
    // checks are ZIR-level and see both comptime branches, so the parameter
    // must simply appear used somewhere in the body (same reason os.fd
    // splits its writeFile bodies the way it does).
    if (comptime native_os == .linux) {
        return os_layer.fd.writeFile(io, path, data, mode);
    } else {
        return os_layer.fd.writeFile(io, path, data, 0);
    }
}

/// Absolute location of the test binary's cwd via the raw getcwd syscall
/// (0.16 std ships no allocating wrapper). Returns null when the kernel
/// answer fails or does not fit; callers then skip the affected assertion.
fn testCwdInto(buf: []u8) ?[]const u8 {
    if (comptime native_os != .linux) return null;
    const rc = std.os.linux.getcwd(buf.ptr, buf.len);
    if (std.os.linux.errno(rc) != .SUCCESS) return null;
    const end = @min(rc, buf.len);
    const nul = std.mem.indexOfScalar(u8, buf[0..end], 0) orelse end;
    return buf[0..nul];
}

test "preflightExec resolves a tool through relative and absolute PATH entries" {
    if (builtin.os.tag != .linux) return error.SkipZigTest; // CI runs unit tests on Linux only
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = Io.Threaded.global_single_threaded.io();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const bin_dir = try tmp.dir.createDirPathOpen(io, "bin", .{});
    defer bin_dir.close(io);
    const tool_rel = try tmpRelPath(arena, &tmp, "bin/mytool");
    try writeFixtureFile(io, tool_rel, "#!/bin/sh\nexit 0\n", 0o755);

    // A relative PATH entry resolves against the daemon cwd — here the test
    // binary's cwd, which is exactly where the tmp tree lives.
    const bin_rel = try tmpRelPath(arena, &tmp, "bin");
    try preflightExec(arena, io, "mytool", "", bin_rel);

    // An absolute PATH entry is used verbatim, no cwd join.
    var cwd_buf: [4096]u8 = undefined;
    const cwd_abs = testCwdInto(&cwd_buf) orelse return error.SkipZigTest;
    const bin_abs = try std.fmt.allocPrint(arena, "{s}/{s}", .{ cwd_abs, bin_rel });
    try preflightExec(arena, io, "mytool", "", bin_abs);

    // A tool missing from every PATH entry is pure ENOENT, so the taxonomy
    // stays FileNotFound even after the full loop.
    try std.testing.expectError(
        error.FileNotFound,
        preflightExec(arena, io, "definitely-missing-tool-xqz", "", bin_rel),
    );
}

test "preflightExec reports AccessDenied for non-executable files and directories" {
    if (builtin.os.tag != .linux) return error.SkipZigTest; // CI runs unit tests on Linux only
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = Io.Threaded.global_single_threaded.io();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const bin_dir = try tmp.dir.createDirPathOpen(io, "bin", .{});
    defer bin_dir.close(io);

    // Present but without any execute bit: access(X_OK) fails, the EACCES
    // candidate is remembered across the PATH loop and surfaces as
    // AccessDenied — the same error the execvpe loop would report.
    const plain_rel = try tmpRelPath(arena, &tmp, "bin/plain");
    try writeFixtureFile(io, plain_rel, "data\n", 0o644);
    const bin_rel = try tmpRelPath(arena, &tmp, "bin");
    try std.testing.expectError(
        error.AccessDenied,
        preflightExec(arena, io, "plain", "", bin_rel),
    );

    // A directory where a program is expected: execve refuses it with
    // EACCES even though stat succeeds (probeCandidate maps non-regular
    // files into the EACCES candidate set).
    const sub_dir = try tmp.dir.createDirPathOpen(io, "somedir", .{});
    defer sub_dir.close(io);
    const dir_rel = try tmpRelPath(arena, &tmp, "somedir");
    try std.testing.expectError(
        error.AccessDenied,
        preflightExec(arena, io, dir_rel, "", null),
    );
}

test "preflightExec handles slash-containing argv0 and validates the cwd" {
    if (builtin.os.tag != .linux) return error.SkipZigTest; // CI runs unit tests on Linux only
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = Io.Threaded.global_single_threaded.io();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const bin_dir = try tmp.dir.createDirPathOpen(io, "bin", .{});
    defer bin_dir.close(io);
    const tool_rel = try tmpRelPath(arena, &tmp, "bin/mytool");
    try writeFixtureFile(io, tool_rel, "#!/bin/sh\nexit 0\n", 0o755);

    // An argv0 with slashes but no leading slash joins the (empty) cwd:
    // identical resolution against the daemon cwd.
    try preflightExec(arena, io, tool_rel, "", null);

    // An absolute argv0 probes the path directly; PATH never participates.
    var cwd_buf: [4096]u8 = undefined;
    const cwd_abs = testCwdInto(&cwd_buf) orelse return error.SkipZigTest;
    const tool_abs = try std.fmt.allocPrint(arena, "{s}/{s}", .{ cwd_abs, tool_rel });
    try preflightExec(arena, io, tool_abs, "", null);
    try std.testing.expectError(
        error.FileNotFound,
        preflightExec(arena, io, "/definitely/missing-xqz/tool", "", null),
    );

    // A relative argv0 joined onto a non-empty relative cwd: the child's
    // post-chdir view, which is what childRelative models.
    const tmp_root = try std.fmt.allocPrint(arena, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    try preflightExec(arena, io, "bin/mytool", tmp_root, null);

    // The cwd is validated before any resolution: missing → FileNotFound.
    try std.testing.expectError(
        error.FileNotFound,
        preflightExec(arena, io, "sh", "/definitely/missing-xqz", null),
    );

    // A cwd that exists but is a regular file → NotDir.
    try std.testing.expectError(
        error.NotDir,
        preflightExec(arena, io, "sh", tool_rel, null),
    );
}

test "preflightExec falls back to the default PATH when path_env is null" {
    if (builtin.os.tag != .linux) return error.SkipZigTest; // CI runs unit tests on Linux only
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = Io.Threaded.global_single_threaded.io();

    // null mirrors std's default PATH fallback; "sh" lives in /bin on every
    // Linux the host and CI run.
    try preflightExec(arena, io, "sh", "", null);
    try std.testing.expectError(
        error.FileNotFound,
        preflightExec(arena, io, "no-such-mcpnz-tool-xqz", "", null),
    );
}

test "childRelative mirrors the child's post-chdir path resolution" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Empty cwd inherits the daemon cwd: rel passes through untouched.
    try std.testing.expectEqualStrings("x", try childRelative(arena, "", "x"));
    // Absolute and relative cwds both join with a single slash.
    try std.testing.expectEqualStrings("/a/b", try childRelative(arena, "/a", "b"));
    try std.testing.expectEqualStrings("rel/b", try childRelative(arena, "rel", "b"));
}

/// Build a pid_t from a small number on every target: pid_t is an integer on
/// POSIX but a HANDLE (*anyopaque) on Windows, where a bare literal does not
/// coerce.
fn testPid(n: usize) std.posix.pid_t {
    return if (comptime native_os == .windows) @ptrFromInt(n) else @intCast(n);
}

test "protectedPid flags exactly the listed pids" {
    const protected = [_]std.posix.pid_t{ testPid(10), testPid(20), testPid(30) };
    try std.testing.expect(protectedPid(&protected, testPid(20)));
    try std.testing.expect(!protectedPid(&protected, testPid(99)));
    try std.testing.expect(!protectedPid(&[_]std.posix.pid_t{}, testPid(1)));
}

test "reapAction skips protected zombies and stops when the enumeration wraps" {
    const protected = [_]std.posix.pid_t{ testPid(10), testPid(20) };
    // Unprotected pid: consume the zombie now.
    try std.testing.expectEqual(ReapAction.reap, reapAction(&protected, testPid(30), &[_]std.posix.pid_t{}));
    // Protected pid, first sight this pass: pass over it and remember.
    try std.testing.expectEqual(ReapAction.skip, reapAction(&protected, testPid(10), &[_]std.posix.pid_t{}));
    // Same protected pid again: WNOWAIT re-reported it, enumeration wrapped.
    const skipped_once = [_]std.posix.pid_t{testPid(10)};
    try std.testing.expectEqual(ReapAction.stop, reapAction(&protected, testPid(10), &skipped_once));
    // A different protected pid is still a first sight even after others
    // were skipped: the pass must keep walking, not stop at the first skip.
    try std.testing.expectEqual(ReapAction.skip, reapAction(&protected, testPid(20), &skipped_once));
    // An empty protected set never skips: everything enumerated is a stray.
    try std.testing.expectEqual(ReapAction.reap, reapAction(&[_]std.posix.pid_t{}, testPid(10), &skipped_once));
}

test "statIsZombieChild parses state and ppid after the comm field" {
    // comm may contain spaces and parens: parsing must start after the
    // LAST ')', exactly like procps.
    try std.testing.expect(statIsZombieChild("12 (a b)c) Z 1000 1 ...", 1000));
    try std.testing.expect(!statIsZombieChild("12 (a b)c) R 1000 1 ...", 1000));
    try std.testing.expect(!statIsZombieChild("12 (a b)c) Z 999 1 ...", 1000));
    // Non-zombie child of us, zombie of somebody else: both rejected.
    try std.testing.expect(!statIsZombieChild("12 (sh) Z 1 1 ...", 1000));
    try std.testing.expect(!statIsZombieChild("12 (sh) S 1000 1 ...", 1000));
    // Malformed content never classifies as a zombie child.
    try std.testing.expect(!statIsZombieChild("", 1000));
    try std.testing.expect(!statIsZombieChild("12 (sh)", 1000));
    try std.testing.expect(!statIsZombieChild("12 (sh) Z notapid 1", 1000));
    // ppid field is the token after state — trailing fields are ignored.
    try std.testing.expect(statIsZombieChild("12 (sh) Z 1000 1 0 0 0", 1000));
}

test "NtWaitType encodes the native WAIT_TYPE contract (WaitAll=0, WaitAny=1)" {
    // winternl.h WAIT_TYPE: WaitAll = 0, WaitAny = 1 — the numeric order
    // is the reverse of the Win32 bWaitAll BOOL convention. A reader
    // "fixing" this back to 0 makes the reader wait for BOTH the pipe
    // and the wake event; the wake is only ever set at close time, so
    // any child that fills the pipe deadlocks the session. Pure enum
    // arithmetic — runs on every CI platform, no ntdll needed.
    try std.testing.expectEqual(@as(u32, 0), @intFromEnum(NtWaitType.WAIT_ALL));
    try std.testing.expectEqual(@as(u32, 1), @intFromEnum(NtWaitType.WAIT_ANY));
}

test "decodeWaitAnyStatus maps WaitAny NTSTATUS codes to pipe/wake/failed" {
    // With WaitAny the kernel returns STATUS_WAIT_0 + the index of the
    // lowest-indexed signaled handle: handles[0] is the pipe (the
    // overlapped read completed), handles[1] is the wake event (close
    // requested). Anything else — a higher wait index, a real failure —
    // is not a handle outcome and must not be mistaken for one.
    try std.testing.expectEqual(WaitAnyOutcome.pipe_ready, decodeWaitAnyStatus(.SUCCESS)); // STATUS_WAIT_0 + 0
    try std.testing.expectEqual(WaitAnyOutcome.wake_signaled, decodeWaitAnyStatus(.WAIT_1)); // STATUS_WAIT_0 + 1
    // Out-of-range wait indices (no third handle was passed) and
    // genuine wait failures both decode to .failed.
    try std.testing.expectEqual(WaitAnyOutcome.failed, decodeWaitAnyStatus(.WAIT_2));
    try std.testing.expectEqual(WaitAnyOutcome.failed, decodeWaitAnyStatus(.INVALID_HANDLE));
    try std.testing.expectEqual(WaitAnyOutcome.failed, decodeWaitAnyStatus(.ACCESS_VIOLATION));
}

/// Real fork + immediate exit_group: leaves a genuine zombie child of the
/// test binary without any std machinery in between. The child only calls
/// exit_group, which is async-signal-safe even in a forked multithreaded
/// process. Returns the child pid, or null when fork failed.
fn forkZombieChild() ?std.posix.pid_t {
    if (comptime native_os != .linux) return null;
    const rc = std.os.linux.fork();
    if (rc == 0) std.os.linux.exit_group(0);
    const signed: isize = @bitCast(rc);
    if (signed <= 0) return null;
    return @intCast(signed);
}

/// True when `pid` is a child of this process that has exited but not been
/// reaped yet (a pending zombie). Test-side view of childExitPending
/// (Linux only: the CI hosts run the unit tests there).
fn pendingZombie(pid: std.posix.pid_t) bool {
    if (comptime native_os != .linux) return false;
    return childExitPending(pid);
}

// Regression for the stray-reap rework: an unprotected zombie B forked
// AFTER a protected zombie A must still be collected, even though
// waitid(P_ALL, WNOWAIT) is not a cursor and the kernel may re-report A
// (the first eligible zombie) on every call — the pre-rework skip→stop
// enumeration left exactly this B stranded while A lived. The /proc
// registry sweeps by address, so B is reaped; A stays untouched for its
// owner.
test "reapStrayChildren collects an unprotected zombie behind a protected one" {
    if (builtin.os.tag != .linux) return error.SkipZigTest; // CI runs unit tests on Linux only
    const pid_a = forkZombieChild() orelse return error.SkipZigTest; // fork failed: environment cannot host this test
    const pid_b = forkZombieChild() orelse {
        _ = reapChild(pid_a); // cleanup the first zombie before bailing
        return error.SkipZigTest;
    };
    // Wait until both children actually exited (bounded poll; they only
    // call exit_group, so this settles in one tick).
    var spins: u32 = 0;
    while (!(pendingZombie(pid_a) and pendingZombie(pid_b))) : (spins += 1) {
        if (spins > 2000) return error.TestTimedOut;
        os_layer.sleepMs(5);
    }

    const reaped = reapStrayChildren(&[_]std.posix.pid_t{pid_a});
    // B was reaped (at least once — the count is a lower bound because
    // the P_ALL backstop may also fire).
    try std.testing.expect(reaped >= 1);
    // A is protected: still a pending zombie, left to its owner.
    try std.testing.expect(pendingZombie(pid_a));
    // B is gone: waitid now answers ECHILD for it.
    try std.testing.expect(!pendingZombie(pid_b));

    // Cleanup: this test IS pid_a's owner — reap it so nothing leaks.
    try std.testing.expect(reapChild(pid_a));
}

test "child tracking answers false for pids that are not our children" {
    if (builtin.os.tag != .linux) return error.SkipZigTest; // CI runs unit tests on Linux only
    // pid 1 is nobody's child, and a pid far beyond anything the test binary
    // could have spawned is equally foreign: waitid answers ECHILD for both,
    // so the protected-set bookkeeping drops them.
    try std.testing.expect(!childStillTracked(1));
    try std.testing.expect(!childStillTracked(999999));

    // Crash-safety sweep only: the reaped count depends on whether earlier
    // exec tests in this binary left zombies behind, so the value itself is
    // deliberately not asserted — reaping a stray is always safe (a stray
    // by definition has no owner left to steal a reap from).
    _ = reapStrayChildren(&[_]std.posix.pid_t{});
}

// ---------------------------------------------------------------------------
// getdents64 error-path regressions (reapStraysFromProcReader). A raw
// getdents64 failure answers -errno inside the unsigned return value, so
// the sweep must classify errno BEFORE parsing records — the scripted
// reader below replays exactly those raw values against a hand-built
// dirent64 batch holding a REAL zombie of this test binary, proving the
// parse step only ever runs on valid kernel-shaped bytes.
// ---------------------------------------------------------------------------

/// Scripted raw-errno value: -errno packed into usize, the exact wire form
/// the kernel (and our injected reader) hands the sweep.
fn testRawErrno(e: std.os.linux.E) usize {
    return @bitCast(-@as(isize, @intCast(@intFromEnum(e))));
}

/// Scripted-reader state (function pointers cannot capture context).
var test_script: []const usize = &.{};
var test_script_i: usize = 0;
var test_calls: usize = 0;
var test_batch: []const u8 = &.{};

fn scriptedGetdents(fd: std.posix.fd_t, buf: []u8) usize {
    _ = fd;
    test_calls += 1;
    const rc = if (test_script_i < test_script.len) test_script[test_script_i] else 0;
    test_script_i += 1;
    // Serve the batch bytes only for a success answer: no path may enter
    // the parser with error-valued bytes, and the copy itself must not
    // fabricate a readable buffer behind an error code.
    if (std.os.linux.errno(rc) == .SUCCESS and rc > 0 and rc <= buf.len) {
        std.debug.assert(test_batch.len >= rc);
        @memcpy(buf[0..rc], test_batch[0..rc]);
    }
    return rc;
}

/// Append one kernel-shaped dirent64 record for `name` at `off` in `buf`;
/// returns the record's reclen (name NUL-terminated, padded to 8 like the
/// kernel does — the parser only relies on NUL + reclen).
fn testAppendDirent(buf: []u8, off: usize, name: []const u8) usize {
    const e: *align(1) std.os.linux.dirent64 = @ptrCast(buf[off..].ptr);
    const name_off = @offsetOf(std.os.linux.dirent64, "name");
    var reclen: usize = name_off + name.len + 1;
    reclen = (reclen + 7) & ~@as(usize, 7);
    e.ino = 1;
    e.off = 0;
    e.reclen = @intCast(reclen);
    e.type = 4; // DT_DIR
    @memcpy(buf[off + name_off .. off + name_off + name.len], name);
    buf[off + name_off + name.len] = 0;
    return reclen;
}

test "reapStraysFromProc retries EINTR and parses the following batch" {
    if (builtin.os.tag != .linux) return error.SkipZigTest; // CI runs unit tests on Linux only
    const pid = forkZombieChild() orelse return error.SkipZigTest;
    var spins: u32 = 0;
    while (!pendingZombie(pid)) : (spins += 1) {
        if (spins > 2000) return error.TestTimedOut;
        os_layer.sleepMs(5);
    }

    var dir_buf: [4096]u8 = undefined;
    var name_buf: [32]u8 = undefined;
    const pid_text = try std.fmt.bufPrint(&name_buf, "{d}", .{pid});
    const r1 = testAppendDirent(&dir_buf, 0, pid_text);
    // A non-numeric entry rides along: the parser must skip it.
    const r2 = testAppendDirent(&dir_buf, r1, "self");
    const batch_len = r1 + r2;

    test_batch = dir_buf[0..batch_len];
    test_script = &.{ testRawErrno(.INTR), testRawErrno(.INTR), batch_len, 0 };
    test_script_i = 0;
    test_calls = 0;

    const reaped = reapStraysFromProcReader(&[_]std.posix.pid_t{}, scriptedGetdents);
    // The zombie in the batch was reaped; EINTR was retried, not fatal.
    try std.testing.expectEqual(@as(usize, 1), reaped);
    try std.testing.expect(!pendingZombie(pid));
    // EINTR + EINTR + batch + EOF: exactly four reader invocations.
    try std.testing.expectEqual(@as(usize, 4), test_calls);
}

test "reapStraysFromProc exits safely when getdents fails persistently" {
    if (builtin.os.tag != .linux) return error.SkipZigTest; // CI runs unit tests on Linux only
    const pid = forkZombieChild() orelse return error.SkipZigTest;
    var spins: u32 = 0;
    while (!pendingZombie(pid)) : (spins += 1) {
        if (spins > 2000) return error.TestTimedOut;
        os_layer.sleepMs(5);
    }

    // Error BEFORE any batch: the parser never runs — the zombie survives
    // untouched and the sweep answers 0 instead of walking an error value
    // (≈maxInt) as a byte count through uninitialized dir bytes.
    test_batch = &.{};
    test_script = &.{testRawErrno(.IO)};
    test_script_i = 0;
    test_calls = 0;
    try std.testing.expectEqual(@as(usize, 0), reapStraysFromProcReader(&[_]std.posix.pid_t{}, scriptedGetdents));
    try std.testing.expect(pendingZombie(pid));
    try std.testing.expectEqual(@as(usize, 1), test_calls);

    // Error AFTER a successful batch: only the valid batch bytes are
    // parsed (the zombie is reaped), the loop exits on the error, and the
    // accumulated count is returned, not lost.
    var dir_buf: [4096]u8 = undefined;
    var name_buf: [32]u8 = undefined;
    const pid_text = try std.fmt.bufPrint(&name_buf, "{d}", .{pid});
    const batch_len = testAppendDirent(&dir_buf, 0, pid_text);
    test_batch = dir_buf[0..batch_len];
    test_script = &.{ batch_len, testRawErrno(.PERM) };
    test_script_i = 0;
    test_calls = 0;
    const reaped = reapStraysFromProcReader(&[_]std.posix.pid_t{}, scriptedGetdents);
    try std.testing.expectEqual(@as(usize, 1), reaped);
    try std.testing.expect(!pendingZombie(pid));
    // Batch + error: the loop stopped on the error (no third call).
    try std.testing.expectEqual(@as(usize, 2), test_calls);
}

test "reapProcBatch stops on malformed records instead of walking past the batch" {
    if (builtin.os.tag != .linux) return error.SkipZigTest; // CI runs unit tests on Linux only
    // A pid that cannot exist: the parse walk reaches the classification
    // step, /proc lookup fails, nothing is reaped — the batch shape is
    // otherwise fully valid.
    const fake_pid = "999999999";
    var stat_buf: [512]u8 = undefined;

    // reclen == 0: without the guard this record loops forever.
    var dir_buf: [4096]u8 = undefined;
    const r1 = testAppendDirent(&dir_buf, 0, fake_pid);
    const zero_reclen: *align(1) std.os.linux.dirent64 = @ptrCast(dir_buf[r1..].ptr);
    zero_reclen.reclen = 0;
    const hdr = @offsetOf(std.os.linux.dirent64, "name");
    try std.testing.expectEqual(@as(usize, 0), reapProcBatch(dir_buf[0 .. r1 + hdr], &[_]std.posix.pid_t{}, 1, &stat_buf));

    // reclen overrunning the batch: the walk stops at the batch edge
    // instead of reading past it.
    const r2 = testAppendDirent(&dir_buf, 0, fake_pid);
    const huge_reclen: *align(1) std.os.linux.dirent64 = @ptrCast(dir_buf[r2..].ptr);
    huge_reclen.reclen = 4096;
    try std.testing.expectEqual(@as(usize, 0), reapProcBatch(dir_buf[0 .. r2 + hdr], &[_]std.posix.pid_t{}, 1, &stat_buf));

    // reclen 1..name_off-1: the name slice would start past its end
    // (off - reclen + name_off > off) — a ReleaseSafe safety trap without
    // the short-reclen guard. The real kernel never sends these, but the
    // parser must not lean on that.
    var short_buf: [4096]u8 = undefined;
    var short_len: usize = 1;
    while (short_len < hdr) : (short_len += 1) {
        const r = testAppendDirent(&short_buf, 0, fake_pid);
        const short_reclen: *align(1) std.os.linux.dirent64 = @ptrCast(short_buf[0..].ptr);
        short_reclen.reclen = @intCast(short_len);
        try std.testing.expectEqual(@as(usize, 0), reapProcBatch(short_buf[0 .. r + hdr], &[_]std.posix.pid_t{}, 1, &stat_buf));
    }
}

// ---------------------------------------------------------------------------
// fd ownership across error injection, gate balance under the scripted
// pipe creator, and the bounded post-EOF exit wait.
// ---------------------------------------------------------------------------

/// True when the raw kernel still considers `fd` open (F_GETFD probe).
fn fdIsOpenLinux(fd: std.posix.fd_t) bool {
    if (comptime native_os != .linux) return false;
    return std.os.linux.errno(std.os.linux.fcntl(fd, std.os.linux.F.GETFD, 0)) == .SUCCESS;
}

/// Sorted snapshot of every open fd of this process (F_GETFD probes over
/// the low range). Used to prove the acquisition-failure paths close
/// exactly what they opened: no leak AND no collateral close of a number
/// the failure path did not own (the double-close shape).
fn snapshotOpenFds(arena: std.mem.Allocator) ![]std.posix.fd_t {
    var list: std.ArrayList(std.posix.fd_t) = .empty;
    var fd: std.posix.fd_t = 0;
    while (fd < 256) : (fd += 1) {
        if (fdIsOpenLinux(fd)) try list.append(arena, fd);
    }
    std.mem.sort(std.posix.fd_t, list.items, {}, std.sort.asc(std.posix.fd_t));
    return list.items;
}

test "FdBox: an explicit close is never repeated (fd numbers get reused)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest; // CI runs unit tests on Linux only
    const fds = try std.Io.Threaded.pipe2(.{ .CLOEXEC = true });
    defer os_layer.closeFd(fds[1]);

    var box = FdBox.of(fds[0]);
    box.close(); // owned: closed and the slot invalidated
    // The kernel reuses freed numbers immediately: dup answers with the
    // LOWEST free fd — exactly the number box just closed. A blind
    // second close (an errdefer re-closing a slot the
    // code already closed explicitly) would kill this FOREIGN descriptor.
    const reused: std.posix.fd_t = @intCast(std.os.linux.dup(fds[1]));
    box.close(); // idempotent by contract: `reused` must survive it
    try std.testing.expect(fdIsOpenLinux(reused));
    os_layer.closeFd(reused);

    // take() hands ownership away: the sweep must not close it either.
    var box2 = FdBox.of(fds[1]);
    const taken = box2.take();
    try std.testing.expectEqual(fds[1], taken);
    box2.close(); // handed away: no-op
    try std.testing.expect(fdIsOpenLinux(taken)); // closed by the defer above
}

/// Scripted creator state (function pointers cannot capture context):
/// real pipes for the first `ok_calls` calls, then a failure.
var scripted_ok_calls: usize = 0;
var scripted_calls: usize = 0;

fn scriptedCreator() std.process.SpawnError![2]std.posix.fd_t {
    scripted_calls += 1;
    if (scripted_calls > scripted_ok_calls) return error.SystemResources;
    return realPipeCreator();
}

test "pinned spawn pipe failure keeps the fork gate balanced and leaks nothing" {
    if (builtin.os.tag != .linux) return error.SkipZigTest; // CI runs unit tests on Linux only
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = Io.Threaded.global_single_threaded.io();
    const envp = try arena.allocSentinel(?[*:0]const u8, 0, null);

    const spec = PinnedSpawn{
        .exe_fd = 0, // never reached: the acquisition fails before the fork
        .cwd_fd = null,
        .argv = &.{"x"},
        .envp = envp,
        .stdin_fd = null,
        .pgid = false,
    };

    // Scenario A — the SECOND pipe (stderr) fails after stdout succeeded:
    // the earlier pipe must be closed exactly once, and the fork gate
    // must be released (a held gate is a permanent darwin fork deadlock;
    // on Linux the test-only balance counter proves the pairing).
    {
        const before = try snapshotOpenFds(arena);
        scripted_ok_calls = 1;
        scripted_calls = 0;
        try std.testing.expectError(error.SystemResources, spawnPinnedCreator(arena, io, spec, scriptedCreator));
        try std.testing.expectEqual(@as(i32, 0), gate_balance);
        try std.testing.expectEqualSlices(std.posix.fd_t, before, try snapshotOpenFds(arena));
    }

    // Scenario B — the THIRD acquisition (the error-reporting pipe)
    // fails: stdout, stderr AND /dev/null must all be closed again.
    {
        const before = try snapshotOpenFds(arena);
        scripted_ok_calls = 2;
        scripted_calls = 0;
        try std.testing.expectError(error.SystemResources, spawnPinnedCreator(arena, io, spec, scriptedCreator));
        try std.testing.expectEqual(@as(i32, 0), gate_balance);
        try std.testing.expectEqualSlices(std.posix.fd_t, before, try snapshotOpenFds(arena));
    }

    // A failing single creation alone leaves the gate balanced too.
    {
        scripted_ok_calls = 0;
        scripted_calls = 0;
        _ = spawnPinnedCreator(arena, io, spec, scriptedCreator) catch {};
        try std.testing.expectEqual(@as(i32, 0), gate_balance);
    }
}

test "pinned spawn error path after the fork closes each fd exactly once" {
    if (builtin.os.tag != .linux) return error.SkipZigTest; // CI runs unit tests on Linux only
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var threaded = Io.Threaded.init(std.heap.page_allocator, .{ .environ = .empty });
    defer threaded.deinit();
    const io = threaded.io();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const root = try arena.dupe(u8, buf[0..try tmp.dir.realPathFile(io, ".", &buf)]);
    try tmp.dir.writeFile(io, .{ .sub_path = "plain.txt", .data = "not executable\n" });
    const plain = try std.mem.concat(arena, u8, &.{ root, "/plain.txt" });

    // The exec fails child-side (AccessDenied on a non-executable pin):
    // the error return unwinds through every errdefer AFTER the parent
    // already closed its copies — the boxes own only the read ends, so
    // the sweep closes exactly those and nothing double-closes.
    const exe_fd = try os_layer.secure.openPinnedExe(io, plain);
    defer os_layer.closeFd(exe_fd);
    const before = try snapshotOpenFds(arena);
    const envp = try arena.allocSentinel(?[*:0]const u8, 0, null);
    try std.testing.expectError(error.AccessDenied, spawnPinned(arena, io, .{
        .exe_fd = exe_fd,
        .cwd_fd = null,
        .argv = &.{"plain.txt"},
        .envp = envp,
        .stdin_fd = null,
        .pgid = false,
    }));
    try std.testing.expectEqual(@as(i32, 0), gate_balance);
    try std.testing.expectEqualSlices(std.posix.fd_t, before, try snapshotOpenFds(arena));
}

test "runCollected times out on a child that closed its output and lives on" {
    if (builtin.os.tag != .linux) return error.SkipZigTest; // CI runs unit tests on Linux only
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var threaded = Io.Threaded.init(std.heap.page_allocator, .{ .environ = .empty });
    defer threaded.deinit();
    const io = threaded.io();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const root = try arena.dupe(u8, buf[0..try tmp.dir.realPathFile(io, ".", &buf)]);
    // The child closes BOTH output fds, then outlives the deadline: the
    // pre-fix runPinned (now runCollected) parked forever in the final child.wait (the
    // defer kill never ran while the wait was blocked).
    try tmp.dir.writeFile(io, .{
        .sub_path = "lives-on",
        .data = "#!/bin/sh\nexec 1>&- 2>&-\nsleep 30\n",
        .flags = .{ .permissions = std.Io.File.Permissions.fromMode(0o755) },
    });
    try tmp.dir.writeFile(io, .{
        .sub_path = "exits-quiet",
        .data = "#!/bin/sh\nexec 1>&- 2>&-\nexit 7\n",
        .flags = .{ .permissions = std.Io.File.Permissions.fromMode(0o755) },
    });
    const lives = try std.mem.concat(arena, u8, &.{ root, "/lives-on" });
    const quiet = try std.mem.concat(arena, u8, &.{ root, "/exits-quiet" });
    const envp = try arena.allocSentinel(?[*:0]const u8, 0, null);
    const one_second = Io.Timeout{ .duration = .{ .clock = .awake, .raw = std.Io.Duration.fromSeconds(1) } };

    // EOF then a living child: bounded by the deadline, killed and
    // reaped, and surfaced as error.Timeout (runExec maps exactly this
    // error to its {"ok":false,"timeout":true} reply). pgid=true makes
    // the child a group leader so killTree takes the whole tree — the
    // sh->sleep grandchild dies too instead of orphaning.
    {
        const exe_fd = try os_layer.secure.openPinnedExe(io, lives);
        defer os_layer.closeFd(exe_fd);
        var child = try spawnPinned(arena, io, .{
            .exe_fd = exe_fd,
            .cwd_fd = null,
            .argv = &.{"lives-on"},
            .envp = envp,
            .stdin_fd = null,
            .pgid = true,
        });
        const pid = child.id.?;
        const started = std.Io.Timestamp.now(io, .awake);
        try std.testing.expectError(error.Timeout, runCollected(arena, io, &child, .{ .timeout = one_second }));
        const elapsed = started.untilNow(io, .awake);
        try std.testing.expect(elapsed.toMilliseconds() < 10_000); // bounded, not parked for sleep 30
        // Killed AND reaped: the pid is nobody's child anymore.
        try std.testing.expect(!childStillTracked(pid));
    }

    // Control — EOF then a quick exit: the remaining-deadline wait
    // returns the child's term, not a timeout.
    {
        const exe_fd = try os_layer.secure.openPinnedExe(io, quiet);
        defer os_layer.closeFd(exe_fd);
        var child = try spawnPinned(arena, io, .{
            .exe_fd = exe_fd,
            .cwd_fd = null,
            .argv = &.{"exits-quiet"},
            .envp = envp,
            .stdin_fd = null,
            .pgid = false,
        });
        const result = try runCollected(arena, io, &child, .{ .timeout = one_second });
        try std.testing.expect(result.term == .exited);
        try std.testing.expectEqual(@as(u8, 7), result.term.exited);
    }
}

test "spawn pid registry removes by exact pid and tag pair" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    // Bookkeeping only: the pids need not exist. Two registrations of the
    // SAME pid simulate a recycle: the stale tag must not delete the new
    // owner's entry.
    const pid: ProcessId = 424242;
    const io = Io.Threaded.global_single_threaded.io();
    const t1 = registerSpawnPid(io, pid).?;
    const t2 = registerSpawnPid(io, pid).?;
    try std.testing.expect(t1 != t2);
    try std.testing.expect(spawnPidRegistryLen(io) >= 2);
    unregisterSpawnPid(io, pid, t1);
    // t2's registration survived the stale removal.
    try std.testing.expect(spawnPidRegistryLen(io) >= 1);
    unregisterSpawnPid(io, pid, t2);
    // Removing a pair that no longer exists is a harmless no-op.
    unregisterSpawnPid(io, pid, t2);
}

test "registered zombie survives the sweep until its owner unregisters" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const pid = forkZombieChild() orelse return error.SkipZigTest;
    var spins: u32 = 0;
    while (!pendingZombie(pid)) : (spins += 1) {
        if (spins > 2000) return error.TestTimedOut;
        os_layer.sleepMs(5);
    }
    const io = Io.Threaded.global_single_threaded.io();
    const tag = registerSpawnPid(io, pid).?;
    // The sweep may run at any moment (no quiescence gate): the registered
    // zombie is protected and survives.
    _ = sweepStraysWithRegistry(io);
    try std.testing.expect(pendingZombie(pid));
    // The owner reaps and unregisters; the next sweep finds nothing to do
    // for this pid (already gone), and no entry lingers.
    try std.testing.expect(reapChild(pid));
    unregisterSpawnPid(io, pid, tag);
    try std.testing.expect(!pendingZombie(pid));
    _ = sweepStraysWithRegistry(io);
}

test "durable proc stat identity uses last parenthesis and field 22" {
    const stat = try parseProcStatIdentity("42 (a tricky ) name) S 1 42 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 98765 0");
    try std.testing.expectEqual(@as(i64, 1), stat.ppid);
    try std.testing.expectEqual(@as(i64, 42), stat.pgid);
    try std.testing.expectEqual(@as(u64, 98765), stat.start_time_ticks);
    try std.testing.expectEqual(@as(u8, 'S'), stat.state);
    try std.testing.expectError(error.InvalidProcStat, parseProcStatIdentity("42 (bad) S 1"));
}

test "durable identity tri state and boot mismatch never authorize signals" {
    const expected: ProcessIdentity = .{ .pid = 42, .pgid = 42, .start_time_ticks = 99, .boot_id = @splat(1) };
    var actual: ProcStatIdentity = .{ .state = 'S', .ppid = 1, .pgid = 42, .start_time_ticks = 99 };
    try std.testing.expectEqual(IdentityStatus.alive, compareProcessIdentity(expected, actual, @splat(1)));
    actual.state = 'Z';
    try std.testing.expectEqual(IdentityStatus.dead, compareProcessIdentity(expected, actual, @splat(1)));
    actual.state = 'X';
    try std.testing.expectEqual(IdentityStatus.dead, compareProcessIdentity(expected, actual, @splat(1)));
    actual.state = 'S';
    actual.start_time_ticks = 100;
    try std.testing.expectEqual(IdentityStatus.dead, compareProcessIdentity(expected, actual, @splat(1)));
    actual.start_time_ticks = 99;
    try std.testing.expectEqual(IdentityStatus.dead, compareProcessIdentity(expected, actual, @splat(2)));
    try std.testing.expectEqual(IdentityStatus.indeterminate, compareProcessIdentity(expected, null, @splat(1)));
}

pub const ProcessIdentity = struct {
    pid: i64,
    pgid: i64,
    start_time_ticks: u64,
    boot_id: [16]u8,
};
pub const ProcStatIdentity = struct { state: u8, ppid: i64, pgid: i64, start_time_ticks: u64 };
pub const IdentityStatus = enum { alive, dead, indeterminate };

pub fn parseProcStatIdentity(bytes: []const u8) !ProcStatIdentity {
    const end = std.mem.lastIndexOfScalar(u8, bytes, ')') orelse return error.InvalidProcStat;
    var it = std.mem.tokenizeAny(u8, bytes[end + 1 ..], " \n\t");
    const state = it.next() orelse return error.InvalidProcStat;
    if (state.len != 1) return error.InvalidProcStat;
    const ppid = std.fmt.parseInt(i64, it.next() orelse return error.InvalidProcStat, 10) catch return error.InvalidProcStat;
    const pgid = std.fmt.parseInt(i64, it.next() orelse return error.InvalidProcStat, 10) catch return error.InvalidProcStat;
    for (6..22) |_| _ = it.next() orelse return error.InvalidProcStat;
    const ticks = std.fmt.parseInt(u64, it.next() orelse return error.InvalidProcStat, 10) catch return error.InvalidProcStat;
    return .{ .state = state[0], .ppid = ppid, .pgid = pgid, .start_time_ticks = ticks };
}

pub fn compareProcessIdentity(expected: ProcessIdentity, actual: ?ProcStatIdentity, boot: [16]u8) IdentityStatus {
    if (!std.mem.eql(u8, &expected.boot_id, &boot)) return .dead;
    const stat = actual orelse return .indeterminate;
    if (expected.pid <= 0 or stat.start_time_ticks != expected.start_time_ticks or stat.pgid != expected.pgid) return .dead;
    return if (stat.state == 'Z' or stat.state == 'X') .dead else .alive;
}

pub fn readBootId() ![16]u8 {
    const codec = @import("../durable.zig");
    if (comptime native_os == .linux) {
        const fd = try std.posix.openat(std.posix.AT.FDCWD, "/proc/sys/kernel/random/boot_id", .{ .ACCMODE = .RDONLY, .CLOEXEC = true, .NOFOLLOW = true }, 0);
        defer os_layer.closeFd(fd);
        var buf: [64]u8 = undefined;
        const n = try os_layer.readFd(fd, &buf);
        return codec.uuidBootId(buf[0..n]);
    } else if (comptime native_os == .macos) {
        var buf: [64]u8 = undefined;
        var len: usize = buf.len;
        if (std.c.sysctlbyname("kern.bootsessionuuid", &buf, &len, null, 0) != 0) return error.BootIdUnavailable;
        return codec.uuidBootId(std.mem.trimEnd(u8, buf[0..len], "\x00"));
    } else {
        var info: [48]u8 align(8) = undefined;
        const Api = struct {
            extern "ntdll" fn NtQuerySystemInformation(u32, *anyopaque, u32, ?*u32) callconv(.winapi) i32;
        };
        if (Api.NtQuerySystemInformation(3, &info, info.len, null) < 0) return error.BootIdUnavailable;
        return codec.windowsBootId(std.mem.readInt(u64, info[0..8], .little));
    }
}

pub fn readProcIdentity(pid: i64) ?ProcStatIdentity {
    return readProcIdentityChecked(pid) catch null;
}

fn readProcIdentityChecked(pid: i64) !ProcStatIdentity {
    if (comptime native_os != .linux) return error.DurabilityUnsupported;
    if (pid <= 0 or pid > std.math.maxInt(i32)) return error.InvalidProcStat;
    var path: [64]u8 = undefined;
    const name = try std.fmt.bufPrint(&path, "/proc/{d}/stat", .{pid});
    const fd = try std.posix.openat(std.posix.AT.FDCWD, name, .{ .ACCMODE = .RDONLY, .CLOEXEC = true, .NOFOLLOW = true }, 0);
    defer os_layer.closeFd(fd);
    var buf: [4096]u8 = undefined;
    const n = try os_layer.readFd(fd, &buf);
    return parseProcStatIdentity(buf[0..n]);
}

const IdentityOps = struct {
    fn open(pid: i32) usize {
        return std.os.linux.pidfd_open(pid, 0);
    }
    fn close(fd: i32) void {
        _ = std.os.linux.close(fd);
    }
    const boot = readBootId;
    const stat = readProcIdentityChecked;
};

fn verifyIdentityWith(identity: ProcessIdentity, comptime ops: type) IdentityStatus {
    if (identity.pid <= 0 or identity.pid > std.math.maxInt(i32)) return .dead;
    const rc = ops.open(@intCast(identity.pid));
    const err = std.os.linux.errno(rc);
    if (err == .SRCH) return .dead;
    if (err != .SUCCESS and err != .NOSYS) return .indeterminate;
    defer {
        if (err == .SUCCESS) ops.close(@intCast(rc));
    }
    const boot = ops.boot() catch return .indeterminate;
    if (!std.mem.eql(u8, &identity.boot_id, &boot)) return .dead;
    const stat = ops.stat(identity.pid) catch |e| return if (e == error.FileNotFound) .dead else .indeterminate;
    return compareProcessIdentity(identity, stat, boot);
}

pub fn verifyProcessIdentity(identity: ProcessIdentity) IdentityStatus {
    if (comptime native_os != .linux) return .indeterminate;
    return verifyIdentityWith(identity, IdentityOps);
}

fn durableSignalHasPidfd(err: std.os.linux.E) bool {
    return err == .SUCCESS;
}

pub fn killRecoveredTreeVerified(identity: ProcessIdentity) bool {
    if (comptime native_os != .linux) return false;
    if (identity.pid <= 0 or identity.pid > std.math.maxInt(i32) or identity.pgid != identity.pid) return false;
    const linux = std.os.linux;
    const rc = linux.pidfd_open(@intCast(identity.pid), 0);
    const err = linux.errno(rc);
    if (!durableSignalHasPidfd(err)) return false;
    defer {
        if (err == .SUCCESS) _ = linux.close(@intCast(rc));
    }
    const boot = readBootId() catch return false;
    if (compareProcessIdentity(identity, readProcIdentity(identity.pid), boot) != .alive) return false;
    // The held pidfd guarantees the leader signal cannot target a reused PID.
    // Accepted residual race: group teardown and numeric group-ID reuse can
    // occur between the identity check and this numeric group signal.
    const group = linux.kill(-@as(i32, @intCast(identity.pgid)), .KILL);
    if (err == .SUCCESS) _ = linux.pidfd_send_signal(@intCast(rc), .KILL, null, 0);
    return linux.errno(group) == .SUCCESS;
}

/// Parent owns the release writer. EOF before the single release byte makes
/// the pre-exec child exit without ever running the requested executable.
pub const GatedChild = struct {
    child: std.process.Child,
    release_fd: std.posix.fd_t,
    report_fd: std.posix.fd_t,

    pub fn release(self: *GatedChild) !void {
        defer os_layer.closeFd(self.report_fd);
        {
            defer os_layer.closeFd(self.release_fd);
            try os_layer.writeAllFd(self.release_fd, &.{1});
        }
        var report: [2]u8 = undefined;
        if (readReportFdRaw(self.report_fd, &report) != 0) return error.DurableExecFailed;
    }
};

pub fn spawnDurableGated(a: std.mem.Allocator, spec: PinnedSpawn, stdout_fd: std.posix.fd_t, stderr_fd: std.posix.fd_t) !GatedChild {
    if (comptime native_os != .linux) return error.DurabilityUnsupported;
    const argv = try a.allocSentinel(?[*:0]const u8, spec.argv.len, null);
    for (spec.argv, 0..) |arg, i| argv[i] = (try a.dupeZ(u8, arg)).ptr;
    const gate = try realPipeCreator();
    errdefer {
        os_layer.closeFd(gate[0]);
        os_layer.closeFd(gate[1]);
    }
    const report = try realPipeCreator();
    errdefer {
        os_layer.closeFd(report[0]);
        os_layer.closeFd(report[1]);
    }
    const rc = std.posix.system.fork();
    if (std.posix.errno(rc) != .SUCCESS) return error.SystemResources;
    const pid: std.posix.pid_t = @intCast(rc);
    if (pid == 0) {
        os_layer.closeFd(gate[1]);
        os_layer.closeFd(report[0]);
        childDup2(report[1], spec.stdin_fd.?, 0);
        childDup2(report[1], stdout_fd, 1);
        childDup2(report[1], stderr_fd, 2);
        if (spec.cwd_fd) |fd| childFchdir(report[1], fd);
        childSetpgid(report[1]);
        var byte = [_]u8{1};
        if (std.os.linux.write(report[1], &byte, 1) != 1) std.os.linux.exit_group(127);
        while (true) {
            const n = std.os.linux.read(gate[0], &byte, 1);
            if (std.os.linux.errno(n) == .INTR) continue;
            if (n != 1 or byte[0] != 1) std.os.linux.exit_group(127);
            break;
        }
        os_layer.closeFd(gate[0]);
        childClearCloexec(report[1], spec.exe_fd);
        forkBailPinned(report[1], execPinnedLinux(spec.exe_fd, argv.ptr, spec.envp.ptr));
    }
    // Do not install an error defer after these closes: the child-facing
    // descriptor numbers may already have been reused by another thread.
    var ready: [1]u8 = undefined;
    const n = readReportFdRaw(report[0], &ready);
    if (n != 1 or ready[0] != 1) {
        _ = std.os.linux.kill(pid, .KILL);
        var status: u32 = 0;
        while (std.posix.errno(std.posix.system.waitpid(pid, @ptrCast(&status), 0)) == .INTR) {}
        return error.DurableExecFailed;
    }
    os_layer.closeFd(gate[0]);
    os_layer.closeFd(report[1]);
    return .{ .child = .{
        .id = pid,
        .thread_handle = {},
        .stdin = null,
        .stdout = null,
        .stderr = null,
        .request_resource_usage_statistics = false,
    }, .release_fd = gate[1], .report_fd = report[0] };
}

test "durable identity resource and read failures remain indeterminate" {
    const Fake = struct {
        var failure: enum { resource, missing, unsupported, boot, stat, malformed, alive } = .resource;
        fn open(_: i32) usize {
            return switch (failure) {
                .resource => @bitCast(-@as(isize, @intFromEnum(std.os.linux.E.MFILE))),
                .missing => @bitCast(-@as(isize, @intFromEnum(std.os.linux.E.SRCH))),
                .unsupported => @bitCast(-@as(isize, @intFromEnum(std.os.linux.E.NOSYS))),
                else => 42,
            };
        }
        fn close(_: i32) void {}
        fn boot() ![16]u8 {
            if (failure == .boot) return error.AccessDenied;
            return @splat(1);
        }
        fn stat(_: i64) !ProcStatIdentity {
            if (failure == .stat) return error.AccessDenied;
            if (failure == .malformed) return error.InvalidProcStat;
            return .{ .state = 'S', .ppid = 1, .pgid = 42, .start_time_ticks = 99 };
        }
    };
    const expected: ProcessIdentity = .{ .pid = 42, .pgid = 42, .start_time_ticks = 99, .boot_id = @splat(1) };
    inline for (.{ .resource, .boot, .stat, .malformed }) |failure| {
        Fake.failure = failure;
        try std.testing.expectEqual(IdentityStatus.indeterminate, verifyIdentityWith(expected, Fake));
    }
    Fake.failure = .missing;
    try std.testing.expectEqual(IdentityStatus.dead, verifyIdentityWith(expected, Fake));
    Fake.failure = .unsupported;
    try std.testing.expectEqual(IdentityStatus.alive, verifyIdentityWith(expected, Fake));
    try std.testing.expect(!durableSignalHasPidfd(.NOSYS));
    try std.testing.expect(!durableSignalHasPidfd(.MFILE));
    try std.testing.expect(durableSignalHasPidfd(.SUCCESS));
}
