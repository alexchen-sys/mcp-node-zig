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
    const fds = try std.Io.Threaded.pipe2(.{ .CLOEXEC = true });
    return .{ .read = fds[0], .write = fds[1] };
}

/// The `.file` stdio view of the pipe's read end, for SpawnOptions.stdin
/// (POSIX only — see createStdinPipe).
pub fn stdinFile(pipe: *const StdinPipe) std.Io.File {
    return .{ .handle = pipe.read, .flags = .{ .nonblocking = false } };
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

// ---------------------------------------------------------------------------
// Failed-spawn hygiene (POSIX only).
//
// std 0.16 processSpawnPosix reads the exec failure from the child's error
// pipe and returns the error WITHOUT waitpid: the fork succeeded, the child
// reported the execve failure and exited, and nobody ever reaps it, so every
// failed spawn leaks a defunct child for the daemon's lifetime. Two layers
// close this:
//   * preflightExec — resolve argv[0] and cwd exactly the way the child's
//     execvpe will, BEFORE forking, so the common failures (missing program,
//     missing execute permission, missing cwd) never fork at all and keep
//     their std error names (FileNotFound, AccessDenied, NotDir).
//   * reapStrayChildren — a backstop sweep for residual execve errors no
//     pre-flight can see (ENOEXEC/E2BIG/ENOMEM/...): reaps zombie children
//     that no session owns, never touching pids the session machinery is
//     still responsible for (the tools layer passes the protected set).
// Everything below is referenced only from comptime-gated POSIX call sites,
// so Windows builds never codegen it.
// ---------------------------------------------------------------------------

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

/// Reap zombie children that no session machinery owns. `protected` holds
/// pids somebody else is responsible for reaping (session children from fork
/// until their waiter's wait); the sweep stops at the first protected pid —
/// waitid(WNOWAIT) would keep re-reporting it — and leaves the rest for the
/// next round. Returns the number of strays reaped.
pub fn reapStrayChildren(protected: []const std.posix.pid_t) usize {
    var reaped: usize = 0;
    var round: usize = 0;
    while (round < 64) : (round += 1) {
        const pid = enumeratePendingChild() orelse break;
        if (pid == 0) break;
        if (protectedPid(protected, pid)) break;
        if (reapChild(pid)) reaped += 1;
    }
    return reaped;
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

/// Blocking read from an asynchronous pipe handle (the std-created child
/// stdout/stderr ends are opened with MODE.IO.ASYNCHRONOUS). Issues
/// NtReadFile; on STATUS_PENDING waits on the file handle itself, which the
/// kernel signals when the overlapped operation completes. Returns the byte
/// count, or null on EOF (PIPE_BROKEN when the last write end dies with the
/// job) and on any error — the reader thread treats both as terminal.
pub fn readPipeBlocking(handle: windows.HANDLE, buf: []u8) ?usize {
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
        .PENDING => _ = windows.ntdll.NtWaitForSingleObject(handle, .FALSE, null), // infinite
        else => return null,
    }
    return switch (iosb.u.Status) {
        .SUCCESS => iosb.Information,
        else => null,
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

test "protectedPid flags exactly the listed pids" {
    const protected = [_]std.posix.pid_t{ 10, 20, 30 };
    try std.testing.expect(protectedPid(&protected, 20));
    try std.testing.expect(!protectedPid(&protected, 99));
    try std.testing.expect(!protectedPid(&[_]std.posix.pid_t{}, 1));
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
