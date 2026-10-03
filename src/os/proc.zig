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
