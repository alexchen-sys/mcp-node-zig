//! Secure-open subsystem: the authorization and the access operate on ONE
//! kernel-resolved object (closes the TOCTOU race between the policy gate's
//! string check and the tool's raw-path open).
//!
//! Threat being closed: a local racer with rename/symlink rights on an
//! ANCESTOR of an allow prefix (e.g. /srv) swaps /srv/sandbox for a symlink
//! to /etc between checkCall and the open. The gate authorized the
//! canonical string, the tool then opens whatever the path now resolves
//! to — a different object.
//!
//! Architecture (who opens, who checks, in which order):
//!
//!   1. The policy gate (policy.zig checkCallEx) still decides on the
//!      canonical STRING, but emits a `Pin`: the matched allow prefix, the
//!      canonical target path, and the deny list of that path kind.
//!   2. `openPinned` opens the allow prefix and re-validates it is the
//!      pinned directory (Linux: openat2 + /proc/self/fd readback; Darwin:
//!      openat + F_GETPATH; Windows: openDir + GetFinalPathNameByHandleW).
//!   3. The target is opened RELATIVE to that pinned directory fd:
//!      Linux openat2(RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS) — a symlink
//!      leading outside the prefix fails with EXDEV in the kernel itself;
//!      non-Linux walks component-by-component with O_NOFOLLOW on every
//!      intermediate component; Windows opens relative to the prefix
//!      handle.
//!   4. Post-check: the /proc/self/fd (or F_GETPATH / final-path) readback
//!      of the OPENED descriptor is compared against the pin — a deny
//!      subtree hit refuses with PathDenied, any other mismatch with
//!      PathEscape. The readback races nothing: the descriptor is already
//!      pinned to one object.
//!   5. Only after all checks pass does the caller read/write the fd.
//!
//! Contract notes (observable behavior changes under a policy):
//!   * A symlink inside the allow tree is still FOLLOWED (read_file on
//!     allow/link works when the gate canonicalised it inside the allow
//!     tree); the kernel confinement refuses the escape, the post-check
//!     refuses symlink-after-gate swaps to a different object.
//!   * write_file follows a FINAL symlink like before; a symlink planted
//!     after the gate is caught by the post-check mismatch.
//!   * allow_all tokens skip the pin entirely (admin escape hatch, the
//!     pre-subsystem raw-path behaviour).
//!
//! Platform boundaries (documented, compile-checked):
//!   * Linux: full guarantee (openat2 confinement + fd readback pin).
//!     A kernel/procfs without /proc/self/fd fails CLOSED on the
//!     post-check (unverifiable = refused).
//!   * Darwin: component walk with O_NOFOLLOW confines intermediates;
//!     F_GETPATH readback pins both prefix and target. Automount-alias
//!     divergence between realpath and F_GETPATH would fail closed.
//!   * Windows: handle-relative opens chain the prefix; the target pin is
//!     GetFinalPathNameByHandleW. The prefix open itself follows reparse
//!     points (std.Io has no O_NOFOLLOW dir open), so the prefix handle
//!     gets its OWN final-path readback right after the open — before
//!     the empty-rel return, the mkdirs walk, or any relative open — and
//!     the target post-check then refuses a
//!     swapped target object before any read/write (fail closed), while
//!     an un-swapped chain is confined by the handle relation. The write
//!     branch's mkdirs walks one verified
//!     component at a time, so a reparse component
//!     can never leave directories outside the allow tree behind. The
//!     exec pins are share-mode handles plus a suspended-spawn
//!     QueryFullProcessImageNameW check — see the Windows exec pinning
//!     section below.
//!   * Other POSIX: unreachable (os.zig rejects unsupported targets).

const std = @import("std");
const builtin = @import("builtin");

const Io = std.Io;

const posix_impl = @import("posix.zig");

pub const fd_t = std.posix.fd_t;
pub const mode_t = std.posix.mode_t;

/// Authorization binding produced by the policy gate for one file-tool
/// call. All strings belong to the request arena and stay alive for the
/// duration of the call.
pub const Pin = struct {
    /// Canonical (already realpath-resolved) allow prefix that matched.
    prefix: []const u8,
    /// `canon` relative to `prefix`: no leading '/', no "..", no symlinks
    /// (canonicalisation resolved them); empty when canon == prefix.
    rel: []const u8,
    /// Canonical target path the gate authorized.
    canon: []const u8,
    /// Deny prefixes of the same path kind, for the post-check.
    deny: []const []const u8,
};

pub const Access = enum { read, write, dir };

pub const WriteOpts = struct {
    /// Create missing intermediate directories (write_file mkdirs:true).
    mkdirs: bool = false,
    /// Creation mode, applied exactly like the legacy writeFile (openat
    /// semantics; ignored on Windows).
    mode: mode_t = 0o644,
};

/// Errors surfaced to the tool layer. PathEscape/PathDenied/PrefixSwapped
/// are the security refusals; NotRegularFile refuses non-regular targets
/// (FIFO/socket/device) before a blocking read/write can park the thread;
/// the rest mirror the legacy open errors so the tool contracts
/// (FileNotFound, IsDirectory, ...) stay identical.
pub const OpenError = std.posix.OpenError || error{
    PathEscape,
    PathDenied,
    PrefixSwapped,
    NotRegularFile,
    UnsupportedPlatform,
};

/// Host path grammar for this module's matchers (kept local so this module
/// never imports policy.zig): on Windows the boundary separator may be '/'
/// or '\' and the comparison folds ASCII case — the same rule as the gate's
/// pathHasPrefixSty.
const host_path_seps: []const u8 = if (builtin.os.tag == .windows) "/\\" else "/";
const host_path_fold: bool = builtin.os.tag == .windows;

fn hostFold(c: u8) u8 {
    if (c >= 'A' and c <= 'Z') return c + 32;
    return c;
}

/// Style-parameterised segment-aligned prefix match (same rule as the
/// policy gate's pathHasPrefixSty). Pure: the Linux CI pins the Windows
/// grammar directly.
pub fn pathUnderPrefixSty(path: []const u8, prefix: []const u8, seps: []const u8, fold: bool) bool {
    if (prefix.len == 0) return false;
    if (path.len < prefix.len) return false;
    if (fold) {
        for (path[0..prefix.len], prefix) |a, b| {
            if (hostFold(a) != hostFold(b)) return false;
        }
    } else if (!std.mem.eql(u8, path[0..prefix.len], prefix)) return false;
    if (path.len == prefix.len) return true;
    if (std.mem.indexOfScalar(u8, seps, prefix[prefix.len - 1]) != null) return true;
    return std.mem.indexOfScalar(u8, seps, path[prefix.len]) != null;
}

/// Segment-aligned prefix match (same rule as the policy gate's
/// pathHasPrefix, kept local so this module never imports policy.zig).
/// Host-grammar wrapper: backslash boundaries and ASCII case fold on
/// Windows.
fn pathUnderPrefix(path: []const u8, prefix: []const u8) bool {
    return pathUnderPrefixSty(path, prefix, host_path_seps, host_path_fold);
}

/// Copy `path` into `buf` as a NUL-terminated C string.
fn pathZ(path: []const u8, buf: *[std.fs.max_path_bytes + 1]u8) OpenError![*:0]const u8 {
    if (path.len > std.fs.max_path_bytes) return error.NameTooLong;
    @memcpy(buf[0..path.len], path);
    buf[path.len] = 0;
    return buf[0..path.len :0];
}

/// Read an entire already-open descriptor into `arena`, failing with
/// `error.StreamTooLong` past `limit` (same loop as os.fd.readFileAlloc:
/// EOF-delimited, /proc-friendly, never trusts a stat size).
pub fn readFileAllocFd(arena: std.mem.Allocator, io: Io, fd: fd_t, limit: usize) ![]u8 {
    const file: std.Io.File = .{ .handle = fd, .flags = .{ .nonblocking = false } };
    var out: std.ArrayList(u8) = .empty;
    var buf: [16 * 1024]u8 = undefined;
    while (true) {
        const n = file.readStreaming(io, &.{buf[0..]}) catch |err| switch (err) {
            error.EndOfStream => break,
            else => |e| return e,
        };
        if (n == 0) continue; // 0 is legal mid-stream; only EndOfStream ends
        if (out.items.len + n > limit) return error.StreamTooLong;
        try out.appendSlice(arena, buf[0..n]);
    }
    return out.items;
}

/// fstat the freshly opened descriptor and refuse anything but a regular
/// file. A local writer can mkfifo inside a
/// directory covered by read_paths: a plain open(2) on that FIFO parks
/// the connection thread until a peer appears — one FIFO per thread,
/// max_conn threads, node-wide DoS. Directories keep the legacy IsDir
/// taxonomy (the tool layer maps it to IsDirectory); every other kind —
/// FIFO, socket, character/block device — answers NotRegularFile.
/// Runs AFTER the (non-blocking) security post-check and BEFORE any side
/// effect (truncate, deny readback ordering is post-check's own business):
/// the object type is a property of the already-pinned descriptor, and no
/// side effect may precede the refusal. Security refusals keep priority
/// over this taxonomy: a denied target must answer PathDenied, not IsDir.
fn checkRegularTarget(io: Io, fd: fd_t) OpenError!void {
    const file: std.Io.File = .{ .handle = fd, .flags = .{ .nonblocking = false } };
    const st = file.stat(io) catch return error.Unexpected; // unverifiable: fail closed
    return switch (st.kind) {
        .file => {},
        .directory => error.IsDir,
        else => error.NotRegularFile,
    };
}

/// Drop the O_NONBLOCK used for the open (so a FIFO target cannot park
/// the thread in open(2)) before the descriptor reaches the caller's
/// blocking read/write loop. Regular files ignore O_NONBLOCK entirely;
/// the flag only ever mattered for the open itself.
fn clearNonblock(fd: fd_t) OpenError!void {
    if (comptime builtin.os.tag == .linux) {
        const rc = std.os.linux.fcntl(fd, std.posix.F.GETFL, 0);
        if (std.os.linux.errno(rc) != .SUCCESS) return error.Unexpected;
        const nonblock: usize = @as(u32, @bitCast(std.os.linux.O{ .NONBLOCK = true }));
        if (rc & nonblock == 0) return; // already blocking
        const rc2 = std.os.linux.fcntl(fd, std.posix.F.SETFL, rc & ~nonblock);
        if (std.os.linux.errno(rc2) != .SUCCESS) return error.Unexpected;
        return;
    }
    if (comptime builtin.os.tag == .windows) {
        return; // unreachable: Windows opens never set NONBLOCK
    }
    // Darwin (libc): the same F_GETFL/F_SETFL pair (variadic: the literal
    // command argument needs a fixed-size type).
    const fl = std.c.fcntl(@intCast(fd), std.posix.F.GETFL, @as(c_int, 0));
    if (fl == -1) return error.Unexpected;
    const nonblock: c_int = @bitCast(@as(u32, @bitCast(std.posix.O{ .NONBLOCK = true })));
    if (fl & nonblock == 0) return;
    const rc2 = std.c.fcntl(@intCast(fd), std.posix.F.SETFL, fl & ~nonblock);
    if (rc2 == -1) return error.Unexpected;
}

/// Open the target described by `pin` with the given access. The returned
/// descriptor is pinned (all four steps above passed); close it with
/// os.closeFd / std.Io close. For `.dir` the fd can be wrapped as
/// `std.Io.Dir{ .handle = fd }` for iteration.
pub fn openPinned(io: Io, pin: Pin, access: Access, wopts: WriteOpts) OpenError!fd_t {
    // Defensive: trim a trailing '/' off rel (canonicalisation never
    // produces one, but the invariant is worth not silently violating).
    var rel = pin.rel;
    while (rel.len > 0 and rel[rel.len - 1] == '/') rel = rel[0 .. rel.len - 1];

    if (comptime builtin.os.tag == .linux) {
        return openPinnedLinux(io, .{ .prefix = pin.prefix, .rel = rel, .canon = pin.canon, .deny = pin.deny }, access, wopts);
    }
    if (comptime builtin.os.tag == .windows) {
        return openPinnedWindows(io, .{ .prefix = pin.prefix, .rel = rel, .canon = pin.canon, .deny = pin.deny }, access, wopts);
    }
    return openPinnedDarwin(io, .{ .prefix = pin.prefix, .rel = rel, .canon = pin.canon, .deny = pin.deny }, access, wopts);
}

// ---------------------------------------------------------------------------
// Linux: openat2 pipeline
// ---------------------------------------------------------------------------

/// struct open_how for the openat2(2) syscall (Linux >= 5.6).
const OPEN_HOW = extern struct {
    flags: u64 = 0,
    mode: u64 = 0,
    resolve: u64 = 0,
};

/// openat2 RESOLVE_* bits (uapi/linux/fcntl.h; stable ABI values).
const RESOLVE_BENEATH: u64 = 0x08;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;

/// std.posix.O (packed struct) -> the u64 flag word openat2 expects.
fn oU64(f: std.posix.O) u64 {
    return @as(u64, @as(u32, @bitCast(f)));
}

/// Raw openat2 syscall wrapper. XDEV (a RESOLVE_BENEATH violation: a
/// symlink, "..", or absolute component escaping the dirfd) maps to
/// PathEscape — that is the kernel-side confinement failure.
fn openat2Linux(dirfd: fd_t, path_z: [*:0]const u8, flags: u64, mode: u64, resolve: u64) OpenError!fd_t {
    var how = OPEN_HOW{ .flags = flags, .mode = mode, .resolve = resolve };
    while (true) {
        const rc = std.os.linux.syscall4(
            .openat2,
            @as(usize, @as(u32, @bitCast(dirfd))),
            @intFromPtr(path_z),
            @intFromPtr(&how),
            @sizeOf(OPEN_HOW),
        );
        switch (std.os.linux.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            // BENEATH violation: the kernel refused to resolve outside
            // the pinned directory. Security refusal, not a system error.
            .XDEV => return error.PathEscape,
            .LOOP => return error.SymLinkLoop,
            .NOENT => return error.FileNotFound,
            .NOTDIR => return error.NotDir,
            .ISDIR => return error.IsDir,
            .NAMETOOLONG => return error.NameTooLong,
            .ACCES, .PERM => return error.AccessDenied,
            .MFILE => return error.ProcessFdQuotaExceeded,
            .NFILE => return error.SystemFdQuotaExceeded,
            .NOMEM => return error.SystemResources,
            .INVAL => return error.BadPathName,
            .EXIST => return error.PathAlreadyExists,
            .FBIG, .OVERFLOW => return error.FileTooBig,
            .NODEV => return error.NoDevice,
            // O_WRONLY|O_NONBLOCK on a FIFO with no reader answers ENXIO:
            // the target exists but is not a regular file — the write
            // callers map NoDevice to NotRegularFile.
            .NXIO => return error.NoDevice,
            else => return error.Unexpected,
        }
    }
}

/// mkdirat(2) against a walked dirfd. EEXIST is success (the directory
/// races in between two calls of a concurrent writer — the following
/// openat2 re-verifies what actually sits there).
fn mkdiratLinux(dirfd: fd_t, name_z: [*:0]const u8, mode: mode_t) OpenError!void {
    while (true) {
        const rc = std.os.linux.mkdirat(dirfd, name_z, mode);
        switch (std.os.linux.errno(rc)) {
            .SUCCESS, .EXIST => return,
            .INTR => continue,
            .NOENT => return error.FileNotFound,
            .ACCES, .PERM => return error.AccessDenied,
            .NOTDIR => return error.NotDir,
            .NAMETOOLONG => return error.NameTooLong,
            else => return error.Unexpected,
        }
    }
}

/// Truncate the (pinned, post-checked) descriptor to zero — the
/// write_file create-or-replace semantics, applied only AFTER the
/// access checks passed so a swapped target is never truncated.
fn truncateFd(fd: fd_t) OpenError!void {
    if (comptime builtin.os.tag == .linux) {
        while (true) {
            const rc = std.os.linux.ftruncate(fd, 0);
            switch (std.os.linux.errno(rc)) {
                .SUCCESS => return,
                .INTR => continue,
                .INVAL => return error.IsDir,
                else => return error.Unexpected,
            }
        }
    }
    if (comptime builtin.os.tag == .windows) {
        if (SetFilePointerEx(fd, 0, null, 0) == 0) return error.Unexpected;
        if (SetEndOfFile(fd) == 0) return error.Unexpected;
        return;
    }
    if (std.c.ftruncate(fd, 0) != 0) return error.Unexpected;
}

/// readlink("/proc/self/fd/<fd>") — the kernel's answer for which object
/// the descriptor is pinned to. Fails closed at the caller: any error
/// means the pin is unverifiable and the access is refused.
fn fdRealPathLinux(io: Io, fd: fd_t, buf: []u8) !usize {
    var abuf: [48]u8 = undefined;
    const proc_path = std.fmt.bufPrint(&abuf, "/proc/self/fd/{d}", .{fd}) catch return error.Unexpected;
    return std.Io.Dir.cwd().readLink(io, proc_path, buf);
}

/// Post-check (step 4): the opened descriptor's real path must hit no
/// deny prefix and must BE the authorized canonical path. The readback
/// races nothing — the fd already pins the object.
fn postCheckLinux(io: Io, fd: fd_t, pin: Pin) error{ PathDenied, PathEscape }!void {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = fdRealPathLinux(io, fd, &buf) catch return error.PathEscape; // fail closed
    const real = buf[0..n];
    // Belt one (audit directive): deny subtrees.
    for (pin.deny) |d| {
        if (pathUnderPrefix(real, d)) return error.PathDenied;
    }
    // Belt two (strict pin): the opened object must BE the authorized
    // path. A symlink planted after the gate, a renamed parent, anything
    // that opened a different object ends here, before a byte moves.
    if (!std.mem.eql(u8, real, pin.canon)) return error.PathEscape;
}

/// Step 2: open the allow prefix itself and pin it.
///   * O_NOFOLLOW: the final component swapped for a symlink refuses
///     with ELOOP -> PrefixSwapped (the rename-race simulation).
///   * RESOLVE_NO_SYMLINKS: any symlink on the way to the prefix refuses
///     — a canonical prefix resolves through no symlinks, so a symlink
///     visible here is an ancestor swap.
///   * readback == prefix: the opened directory IS the authorized one.
fn openPrefixLinux(io: Io, prefix: []const u8, pbuf: *[std.fs.max_path_bytes + 1]u8) OpenError!fd_t {
    const prefix_z = try pathZ(prefix, pbuf);
    const fd = openat2Linux(
        std.posix.AT.FDCWD,
        prefix_z,
        oU64(.{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }),
        0,
        RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
    ) catch |err| return switch (err) {
        // A NOFOLLOW/NO_SYMLINKS refusal at the prefix is by definition
        // an ancestor swap; name it precisely for the audit surface.
        // ENOTDIR (not ELOOP) is what O_DIRECTORY|O_NOFOLLOW returns for
        // a final component swapped to a symlink or file: the prefix is
        // no longer the authorized directory either way.
        error.SymLinkLoop, error.NotDir => error.PrefixSwapped,
        else => err,
    };
    errdefer posix_impl.closeFd(fd);
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = fdRealPathLinux(io, fd, &buf) catch return error.PrefixSwapped; // fail closed
    if (!std.mem.eql(u8, buf[0..n], prefix)) return error.PrefixSwapped;
    return fd;
}

fn openPinnedLinux(io: Io, pin: Pin, access: Access, wopts: WriteOpts) OpenError!fd_t {
    var pbuf: [std.fs.max_path_bytes + 1]u8 = undefined;
    const prefix_fd = try openPrefixLinux(io, pin.prefix, &pbuf);

    // The target IS the prefix directory.
    if (pin.rel.len == 0) {
        switch (access) {
            // Ownership of prefix_fd transfers to the caller (wrap as
            // std.Io.Dir{ .handle = fd } for iteration).
            .dir => return prefix_fd,
            // Matches the legacy contract: read/write of a directory
            // surfaces IsDir (the raw open succeeded, the first read
            // failed; write never opened with WRONLY).
            else => {
                posix_impl.closeFd(prefix_fd);
                return error.IsDir;
            },
        }
    }

    switch (access) {
        .read, .dir => {
            const rel_z = try pathZ(pin.rel, &pbuf);
            const flags: std.posix.O = if (access == .dir)
                .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }
            else
                // NONBLOCK so a FIFO target (mkfifo by
                // a local writer inside read_paths) cannot park this
                // thread in open(2); the fstat check below refuses
                // non-regular targets and clearNonblock restores the
                // blocking semantics for regular files.
                .{ .ACCMODE = .RDONLY, .CLOEXEC = true, .NONBLOCK = true };
            // The final symlink is followed (read_file contract); an
            // escape outside the prefix is refused by the kernel
            // (EXDEV), a post-gate swap by the post-check below.
            const fd = openat2Linux(prefix_fd, rel_z, oU64(flags), 0, RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS) catch |err| {
                posix_impl.closeFd(prefix_fd);
                return err;
            };
            posix_impl.closeFd(prefix_fd);
            // Ordering: the security post-check runs FIRST — a
            // swapped/denied target must surface PathEscape/PathDenied, not
            // be masked by the object-type taxonomy (a symlink into a deny
            // subtree opens a directory; IsDir would hide the refusal).
            // The readback never blocks (readlink on the pinned fd), so
            // the contract — no blocking syscall before the refusal —
            // still holds. FIFO/socket/device targets answer
            // right after it, before any read can block.
            postCheckLinux(io, fd, pin) catch |err| {
                posix_impl.closeFd(fd);
                return err;
            };
            if (access == .read) {
                checkRegularTarget(io, fd) catch |err| {
                    posix_impl.closeFd(fd);
                    return err;
                };
                clearNonblock(fd) catch |err| {
                    posix_impl.closeFd(fd);
                    return err;
                };
            }
            return fd;
        },
        .write => {
            // Component walk from the pinned prefix: every intermediate
            // component is created (mkdirs) and opened O_NOFOLLOW
            // relative to the previous pinned directory, then the final
            // component is created/truncated from the parent dirfd.
            var it = std.mem.splitScalar(u8, pin.rel, '/');
            var comp_opt = it.next();
            var cur = prefix_fd;
            while (comp_opt) |comp| {
                const next_opt = it.next();
                if (next_opt == null) {
                    // Final component: open WRONLY|CREAT (NO TRUNC —
                    // truncation is a side effect, and it happens only
                    // AFTER the post-check, over the pinned descriptor,
                    // via ftruncate below) from the parent dirfd, still
                    // BENEATH-confined. The final component is opened
                    // with RESOLVE_NO_SYMLINKS: a canonical rel never
                    // names a symlink, so a final symlink is a post-gate
                    // plant and is refused (PathEscape) BEFORE anything
                    // is created or truncated.
                    if (comp.len == 0) {
                        // rel collapsed to a trailing '/' — a directory
                        // target; matches the legacy IsDir refusal.
                        posix_impl.closeFd(cur);
                        return error.IsDir;
                    }
                    const comp_z = try pathZ(comp, &pbuf);
                    // RESOLVE_NO_SYMLINKS on the FINAL
                    // component. A canonical rel never ends in a symlink
                    // (realpath resolved it), so a symlink sitting here was
                    // planted AFTER the gate — the old O_CREAT|follow open
                    // created the deny-subtree file BEFORE the post-check
                    // refused. The kernel now refuses ELOOP before a byte
                    // of the deny tree exists; a legit overwrite (a real
                    // file at the canon path, whenever it appeared) still
                    // opens and the post-check readback verifies the object.
                    // NONBLOCK so a planted FIFO cannot
                    // park this thread in open(2); the fstat below refuses
                    // non-regular targets before the truncate.
                    const fd = openat2Linux(cur, comp_z, oU64(.{
                        .ACCMODE = .WRONLY,
                        .CREAT = true,
                        .CLOEXEC = true,
                        .NONBLOCK = true,
                    }), wopts.mode, RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS) catch |err| {
                        posix_impl.closeFd(cur);
                        return switch (err) {
                            // A final-component symlink under write is by
                            // definition a post-gate plant (the canon never
                            // names one): ELOOP maps to PathEscape.
                            error.SymLinkLoop => error.PathEscape,
                            // ENXIO: the target exists but is a FIFO with
                            // no reader (O_WRONLY|O_NONBLOCK) or a device
                            // with no driver — never a regular file.
                            error.NoDevice => error.NotRegularFile,
                            else => err,
                        };
                    };
                    posix_impl.closeFd(cur);
                    // fd is the single owned object from here: the errdefer owns fd through the return to the caller
                    // so a failure below (including truncate) closes the pinned descriptor.
                    errdefer posix_impl.closeFd(fd);
                    // Same ordering as the read branch: security readback
                    // first (readlink never blocks), object type second —
                    // both strictly before the truncate side effect.
                    try postCheckLinux(io, fd, pin);
                    try checkRegularTarget(io, fd);
                    try clearNonblock(fd);
                    // All checks passed: NOW the truncate the legacy
                    // O_TRUNC would have applied, over the pinned fd.
                    try truncateFd(fd);
                    return fd;
                }
                // Intermediate component. A canonical rel never contains
                // a symlink, so NOFOLLOW here only fires on a post-gate
                // swap — refused before anything is created or written.
                if (comp.len == 0) {
                    comp_opt = next_opt;
                    continue; // "//" — the kernel skips these too
                }
                if (wopts.mkdirs) {
                    const comp_z = try pathZ(comp, &pbuf);
                    mkdiratLinux(cur, comp_z, 0o777) catch |err| {
                        posix_impl.closeFd(cur);
                        return err;
                    };
                }
                const comp_z = try pathZ(comp, &pbuf);
                const next = openat2Linux(cur, comp_z, oU64(.{
                    .ACCMODE = .RDONLY,
                    .DIRECTORY = true,
                    .NOFOLLOW = true,
                    .CLOEXEC = true,
                }), 0, RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS) catch |err| {
                    posix_impl.closeFd(cur);
                    return err;
                };
                posix_impl.closeFd(cur);
                cur = next;
                comp_opt = next_opt;
            }
            // Unreachable: rel.len > 0 guarantees one component.
            posix_impl.closeFd(cur);
            return error.BadPathName;
        },
    }
}

// ---------------------------------------------------------------------------
// Darwin (libc): component walk + F_GETPATH readback
// ---------------------------------------------------------------------------

/// fcntl(2) with F_GETPATH (Darwin): writes the vnode path of `fd`.
const F_GETPATH: c_int = 50;
extern "c" fn fcntl(fd: c_int, cmd: c_int, arg: ?[*]u8) callconv(.c) c_int;

extern "c" fn mkdirat(dirfd: c_int, path: [*:0]const u8, mode: std.c.mode_t) callconv(.c) c_int;

/// Darwin kernel hard limit for F_GETPATH output: path + NUL (MAXPATHLEN,
/// sys/syslimits.h). std.fs.max_path_bytes is 1024 on Darwin; the comptime
/// check in fdRealPathDarwin locks every call-site buffer at >= MAXPATHLEN.
const darwin_max_path_len = 1024;

/// Decode an fcntl(F_GETPATH) result per the Darwin fcntl(2) contract:
/// success returns 0 with the path written into `buf` as a NUL-terminated
/// string — there is no length in the return value; failure returns -1
/// with errno set. Pure, so the contract is unit-testable off-Darwin.
/// Anything unverifiable (nonzero rc, no NUL, empty path) fails closed.
fn decodeGetPath(rc: c_int, buf: []const u8) error{PathEscape}!usize {
    if (rc != 0) return error.PathEscape; // -1/errno, or a value outside the contract
    const nul = std.mem.indexOfScalar(u8, buf, 0) orelse return error.PathEscape;
    if (nul == 0) return error.PathEscape; // empty path: unverifiable
    return nul;
}

/// The vnode path of `fd` into `buf`; fails closed at the caller.
fn fdRealPathDarwin(fd: fd_t, buf: *[std.fs.max_path_bytes]u8) !usize {
    comptime if (std.fs.max_path_bytes < darwin_max_path_len)
        @compileError("F_GETPATH buffer below MAXPATHLEN: bump the call-site buffers");
    const rc = fcntl(@intCast(fd), F_GETPATH, buf[0..].ptr);
    return decodeGetPath(rc, buf);
}

fn mkdiratDarwin(dirfd: fd_t, name_z: [*:0]const u8, mode: mode_t) OpenError!void {
    const rc = mkdirat(@intCast(dirfd), name_z, mode);
    if (rc == 0) return;
    switch (@as(std.c.E, @enumFromInt(std.c._errno().*))) {
        .EXIST => return,
        .INTR => return, // one shot; the following openat re-verifies
        .NOENT => return error.FileNotFound,
        .ACCES, .PERM => return error.AccessDenied,
        .NOTDIR => return error.NotDir,
        .NAMETOOLONG => return error.NameTooLong,
        else => return error.Unexpected,
    }
}

fn openPrefixDarwin(io: Io, prefix: []const u8) OpenError!fd_t {
    _ = io;
    const fd = try std.posix.openat(std.posix.AT.FDCWD, prefix, .{
        .ACCMODE = .RDONLY,
        .DIRECTORY = true,
        .NOFOLLOW = true,
        .CLOEXEC = true,
    }, 0);
    errdefer posix_impl.closeFd(fd);
    // Pin the prefix via F_GETPATH: a swapped intermediate ancestor opens
    // a different vnode, whose path is not the authorized prefix.
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = fdRealPathDarwin(fd, &buf) catch return error.PrefixSwapped;
    if (!std.mem.eql(u8, buf[0..n], prefix)) return error.PrefixSwapped;
    return fd;
}

fn postCheckDarwin(fd: fd_t, pin: Pin) error{ PathDenied, PathEscape }!void {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = fdRealPathDarwin(fd, &buf) catch |err| {
        if (builtin.is_test) std.debug.print("F_GETPATH failed: {s}, canon='{s}'\n", .{ @errorName(err), pin.canon });
        return error.PathEscape;
    };
    const real = buf[0..n];
    for (pin.deny) |d| {
        if (pathUnderPrefix(real, d)) return error.PathDenied;
    }
    if (!std.mem.eql(u8, real, pin.canon)) {
        if (builtin.is_test) std.debug.print("Darwin pin mismatch: real='{s}', canon='{s}'\n", .{ real, pin.canon });
        return error.PathEscape;
    }
}

fn openPinnedDarwin(io: Io, pin: Pin, access: Access, wopts: WriteOpts) OpenError!fd_t {
    const prefix_fd = try openPrefixDarwin(io, pin.prefix);

    if (pin.rel.len == 0) {
        switch (access) {
            .dir => return prefix_fd,
            else => {
                posix_impl.closeFd(prefix_fd);
                return error.IsDir;
            },
        }
    }

    // Component walk for every access: no RESOLVE_BENEATH on libc, so
    // confinement comes from opening each intermediate relative to the
    // pinned parent with O_NOFOLLOW; the final component follows
    // symlinks (read/write contract) and is pinned by F_GETPATH.
    var zbuf: [std.fs.max_path_bytes + 1]u8 = undefined; // mkdirat needs C strings
    var it = std.mem.splitScalar(u8, pin.rel, '/');
    var comp_opt = it.next();
    var cur = prefix_fd;
    while (comp_opt) |comp| {
        const next_opt = it.next();
        if (comp.len == 0) {
            comp_opt = next_opt;
            if (next_opt == null) {
                posix_impl.closeFd(cur);
                return error.IsDir; // trailing '/' — directory target
            }
            continue;
        }
        const is_final = next_opt == null;
        if (!is_final) {
            if (wopts.mkdirs) {
                mkdiratDarwin(cur, try pathZ(comp, &zbuf), 0o777) catch |err| {
                    posix_impl.closeFd(cur);
                    return err;
                };
            }
            const next = std.posix.openat(cur, comp, .{
                .ACCMODE = .RDONLY,
                .DIRECTORY = true,
                .NOFOLLOW = true,
                .CLOEXEC = true,
            }, 0) catch |err| {
                posix_impl.closeFd(cur);
                return err;
            };
            posix_impl.closeFd(cur);
            cur = next;
            comp_opt = next_opt;
            continue;
        }
        // Final component.
        const flags: std.posix.O = switch (access) {
            // NONBLOCK for read/write targets — a FIFO
            // must not park this thread in open(2); the fstat below
            // refuses non-regular targets and clearNonblock restores the
            // blocking semantics for regular files.
            .read => .{ .ACCMODE = .RDONLY, .CLOEXEC = true, .NONBLOCK = true },
            .dir => .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true },
            // NO TRUNC: truncation happens after the post-check (see
            // openPinnedLinux's write branch for the rationale).
            // NOFOLLOW — a canonical rel never ends in
            // a symlink, so a final symlink is a post-gate plant and is
            // refused (PathEscape) before O_CREAT can create anything at
            // its target.
            .write => .{ .ACCMODE = .WRONLY, .CREAT = true, .CLOEXEC = true, .NONBLOCK = true, .NOFOLLOW = true },
        };
        const fd = std.posix.openat(cur, comp, flags, wopts.mode) catch |err| {
            posix_impl.closeFd(cur);
            return switch (err) {
                // Final-component symlink under write = post-gate plant:
                // same refusal class as the post-check readback.
                error.SymLinkLoop => if (access == .write) error.PathEscape else err,
                // ENXIO: FIFO with no reader (O_WRONLY|O_NONBLOCK) — the
                // non-regular-target taxonomy.
                error.NoDevice => if (access == .write) error.NotRegularFile else err,
                else => err,
            };
        };
        posix_impl.closeFd(cur);
        // fd is the single owned object from here: the errdefer owns fd through the return to the caller
        // so a failure below (including truncate) closes the pinned descriptor.
        errdefer posix_impl.closeFd(fd);
        // Same ordering as openPinnedLinux: the security readback (never
        // blocking) precedes the object-type taxonomy, and both precede
        // the truncate side effect.
        try postCheckDarwin(fd, pin);
        if (access != .dir) {
            try checkRegularTarget(io, fd);
            try clearNonblock(fd);
        }
        if (access == .write) try truncateFd(fd);
        return fd;
    }
    posix_impl.closeFd(cur);
    return error.BadPathName;
}

// ---------------------------------------------------------------------------
// Windows: handle-relative opens + final-path readback
// ---------------------------------------------------------------------------

extern "kernel32" fn GetFinalPathNameByHandleW(
    hFile: std.os.windows.HANDLE,
    lpFilePath: [*]u16,
    dwFilePathLen: u32,
    dwFlags: u32,
) callconv(.winapi) u32;

extern "kernel32" fn SetFilePointerEx(
    hFile: std.os.windows.HANDLE,
    liDistanceToMove: i64,
    lpNewFilePointer: ?*i64,
    dwMoveMethod: u32,
) callconv(.winapi) i32;

extern "kernel32" fn SetEndOfFile(hFile: std.os.windows.HANDLE) callconv(.winapi) i32;

extern "kernel32" fn GetFileType(hFile: std.os.windows.HANDLE) callconv(.winapi) u32;

/// FILE_TYPE_DISK (winbase.h): the only handle kind the file tools may
/// read or write — a named pipe or char device would park the connection
/// thread.
const W_FILE_TYPE_DISK: u32 = 0x0001;

fn windowsHandleIsDisk(handle: fd_t) bool {
    return GetFileType(handle) == W_FILE_TYPE_DISK;
}

/// Post-check (Windows): the final path of the opened handle must BE the
/// authorized canonical path. The readback races nothing; a swapped
/// prefix (the openDir follows reparse points) lands here as a mismatch
/// and is refused before any read/write.
/// The comparison goes through the symmetric case-insensitive
/// normalizer (windowsPathMatchesUtf8). The old form blindly sliced the
/// 4-unit \\?\ prefix off the readback and compared case-SENSITIVELY:
/// a canon whose case spelling differed from the readback (NTFS answers
/// the on-disk spelling, the pin canon may carry the gate's spelling)
/// was a deterministic PathEscape for a legal open, and a UNC canon
/// never matched the \\?\UNC readback at all. The normalizer folds
/// ASCII case and equates
/// both namespace spellings on BOTH operands; unsupported namespace
/// forms fail closed (null -> mismatch -> PathEscape).
fn postCheckWindows(handle: fd_t, pin: Pin) error{PathEscape}!void {
    var wbuf: [std.fs.max_path_bytes * 2 + 2]u16 = undefined;
    const n = GetFinalPathNameByHandleW(handle, &wbuf, @intCast(wbuf.len), 0);
    if (n == 0 or n > wbuf.len) return error.PathEscape; // fail closed
    if (!windowsPathMatchesUtf8(wbuf[0..n], pin.canon)) return error.PathEscape;
}

fn mapDirOpenError(err: anyerror) OpenError {
    return switch (err) {
        error.FileNotFound => error.FileNotFound,
        error.NotDir => error.NotDir,
        error.AccessDenied => error.AccessDenied,
        error.SymLinkLoop => error.PrefixSwapped,
        error.NameTooLong => error.NameTooLong,
        else => error.Unexpected,
    };
}

fn openPinnedWindows(io: Io, pin: Pin, access: Access, wopts: WriteOpts) OpenError!fd_t {
    // Step 2: the prefix as a directory handle. std.Io has no
    // no-reparse open, so a prefix swapped at this instant follows the
    // reparse point. Everything below is opened RELATIVE to this handle.
    var base = std.Io.Dir.cwd().openDir(io, pin.prefix, .{ .iterate = true }) catch |err|
        return mapDirOpenError(err);

    // verify the prefix handle IMMEDIATELY
    // after the open — before any of its three uses: the empty-rel
    // ownership return, the mkdirs walk, the relative target open.
    // The rel=="" branch (list_dir on the allow prefix itself) returns
    // base.handle directly, so verifying the prefix handle here prevents
    // a junction planted on the prefix from exposing a foreign directory's
    // listing. The readback (GetFinalPathNameByHandleW) answers the
    // object the handle actually pins; anything but the authorized
    // prefix (namespace- and case-folded — the same comparator the
    // mkdirs walk uses per component) is closed and refused.
    if (!verifyHandlePathWindows(base.handle, pin.prefix)) {
        base.close(io);
        return error.PrefixSwapped;
    }

    if (pin.rel.len == 0) {
        switch (access) {
            // Ownership of the handle transfers to the caller.
            .dir => return base.handle,
            else => {
                base.close(io);
                return error.IsDir;
            },
        }
    }

    // Walk cursor for the write branch (mkdirs): starts at the pinned
    // prefix handle and descends one verified component at a time.
    var cur = base;

    switch (access) {
        .read => {
            const f = base.openFile(io, pin.rel, .{}) catch |err| {
                base.close(io);
                return mapDirOpenError(err);
            };
            base.close(io);
            postCheckWindows(f.handle, pin) catch |err| {
                f.close(io);
                return err;
            };
            // Windows: only disk files reach the read loop — a
            // named-pipe target answers NotRegularFile
            // instead of parking the connection thread.
            if (!windowsHandleIsDisk(f.handle)) {
                f.close(io);
                return error.NotRegularFile;
            }
            return f.handle;
        },
        .dir => {
            const d = base.openDir(io, pin.rel, .{ .iterate = true }) catch |err| {
                base.close(io);
                return mapDirOpenError(err);
            };
            base.close(io);
            postCheckWindows(d.handle, pin) catch |err| {
                d.close(io);
                return err;
            };
            return d.handle;
        },
        .write => {
            // The mkdirs side effect is component-
            // confined now. The old one-shot createDirPath over the parent
            // chain followed reparse points: a junction planted on an
            // intermediate component made the directories land OUTSIDE the
            // allow tree, and the file post-check refused only AFTER those
            // (unremovable) directories existed. The walk below creates and
            // opens every intermediate component RELATIVE to the verified
            // parent handle and verifies each opened directory's final path
            // against the authorized canon prefix — a reparse component is
            // refused before any deeper directory is created, so the only
            // surviving side effect of a refused call is at most the one
            // component the authorized string itself names.
            var file_comp: []const u8 = pin.rel; // single-component rel: the file IS rel
            if (wopts.mkdirs) {
                const total = winCountComponents(pin.rel);
                if (total > 1) {
                    var steps = winMkdirsWalk(pin.canon, pin.rel);
                    var idx: usize = 0;
                    while (steps.next()) |st| {
                        idx += 1;
                        if (idx == total) {
                            // The final component is the file, created below
                            // relative to the walked (verified) directory.
                            file_comp = st.comp;
                            break;
                        }
                        if (st.comp.len == 0) continue; // defensive: canon rel has no "//"
                        cur.createDir(io, st.comp, .default_dir) catch |err| switch (err) {
                            // existed vs created both proceed: the open below
                            // re-verifies what actually sits at the path.
                            error.PathAlreadyExists => {},
                            else => {
                                cur.close(io);
                                return mapDirOpenError(err);
                            },
                        };
                        const next = cur.openDir(io, st.comp, .{ .iterate = true }) catch |err| {
                            cur.close(io);
                            return mapDirOpenError(err);
                        };
                        if (!verifyHandlePathWindows(next.handle, pin.canon[0..st.canon_len])) {
                            // The component is (or resolves through) a
                            // reparse point to a different object: refuse
                            // before creating anything deeper.
                            next.close(io);
                            cur.close(io);
                            return error.PathEscape;
                        }
                        cur.close(io);
                        cur = next;
                    }
                }
            }
            // NTFS has no POSIX permission bits: the created file
            // inherits the directory ACLs and `mode` is a documented
            // no-op here, same rule as os.fd.writeFile.
            const f = cur.createFile(io, file_comp, .{
                // NO truncate: the truncate happens after the post-check
                // (see openPinnedLinux's write branch for the rationale).
                .truncate = false,
            }) catch |err| {
                cur.close(io);
                return mapDirOpenError(err);
            };
            cur.close(io);
            // f is the single owned object from here: the errdefer owns the handle through the return to the caller
            // so a failure below (including SetFilePointerEx/SetEndOfFile truncate) closes the pinned handle.
            errdefer f.close(io);
            try postCheckWindows(f.handle, pin);
            // Windows: the type check precedes the
            // truncate — a non-disk handle never reaches SetEndOfFile.
            if (!windowsHandleIsDisk(f.handle)) return error.NotRegularFile;
            try truncateFd(f.handle);
            return f.handle;
        },
    }
}

// ---------------------------------------------------------------------------
// Windows shared helpers (pure, unit-tested on every CI platform)
// ---------------------------------------------------------------------------

/// True for both Windows path separators — canon/rel produced by the
/// canonicalisation pipeline may carry either.
fn winIsSep(c: u8) bool {
    return c == '/' or c == '\\';
}

/// Number of non-empty path components in `rel`. Pure: the Linux CI pins
/// the arithmetic the Windows mkdirs walk relies on.
pub fn winCountComponents(rel: []const u8) usize {
    var n: usize = 0;
    var in_comp = false;
    for (rel) |c| {
        if (winIsSep(c)) {
            in_comp = false;
        } else if (!in_comp) {
            in_comp = true;
            n += 1;
        }
    }
    return n;
}

/// One step of the Windows mkdirs walk: a component of `rel` plus the
/// length of the canon prefix the opened directory handle must verify
/// against. `rel` is a literal byte-suffix of `canon` (filePin slices it
/// out), so a component ending at rel index i ends in canon at
/// `canon.len - rel.len + i` — regardless of which separator spelling
/// either side carries.
pub const WinWalkStep = struct { comp: []const u8, canon_len: usize };

const WinMkdirsWalk = struct {
    rel: []const u8,
    /// Where rel begins inside canon (canon.len - rel.len).
    base: usize,
    i: usize = 0,

    fn next(self: *WinMkdirsWalk) ?WinWalkStep {
        while (self.i < self.rel.len and winIsSep(self.rel[self.i])) self.i += 1;
        if (self.i >= self.rel.len) return null;
        const start = self.i;
        while (self.i < self.rel.len and !winIsSep(self.rel[self.i])) self.i += 1;
        return .{ .comp = self.rel[start..self.i], .canon_len = self.base + self.i };
    }
};

fn winMkdirsWalk(canon: []const u8, rel: []const u8) WinMkdirsWalk {
    return .{ .rel = rel, .base = canon.len - rel.len };
}

/// ASCII case fold for one WTF-16LE code unit. Non-ASCII units compare
/// exactly: NTFS case rules beyond ASCII are not approximated — a
/// mismatch simply refuses (fail closed).
fn foldAsciiW16(c: u16) u16 {
    if (c >= 'A' and c <= 'Z') return c + 32;
    return c;
}

/// Case-insensitive WTF-16LE equality.
pub fn w16EqlIgnoreCase(a: []const u16, b: []const u16) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (x == y) continue;
        if (foldAsciiW16(x) != foldAsciiW16(y)) return false;
    }
    return true;
}

/// Recognized absolute path namespaces after normalization: a DOS drive
/// path (`C:\...`) or a UNC share path (`\\server\share\...`). Each has a
/// verifier-prefixed spelling (`\\?\C:\...`, `\\?\UNC\server\share\...`).
const WinPathNs = enum { dos, unc };

fn winIsDriveLetter(c: u16) bool {
    return (c >= 'A' and c <= 'Z') or (c >= 'a' and c <= 'z');
}

/// Normalize one WTF-16LE Windows path to a namespace plus a body: a DOS
/// body is the whole `C:\...` spelling (drive letter included), a UNC
/// body is `server\share\...` (the leading `\\` dropped). Two absolute
/// paths name the same object exactly when namespace and body match
/// case-insensitively — on EITHER spelling of the same namespace.
/// `null` marks everything the exec contract cannot underwrite:
/// unsupported namespace forms behind `\\?\` (GLOBALROOT, `Volume{...}`,
/// device objects), NT `\??\` native paths, and relative/non-path
/// inputs. Callers fail closed on `null`, never guess a spelling.
/// Pure: unit-tested on every CI platform.
fn winNormalizePathW16(p: []const u16) ?struct { ns: WinPathNs, body: []const u16 } {
    const volspec = [_]u16{ '\\', '\\', '?', '\\' };
    if (std.mem.startsWith(u16, p, &volspec)) {
        // `\\?\UNC\server\share` is the verifier-prefixed spelling of
        // `\\server\share`: the body drops BOTH prefixes (8 units). UNC
        // is a namespace decision, never a blind 4-unit slice — slicing
        // 4 would leave `UNC\server\share` and silently never match the
        // plain spelling.
        const uncspec = [_]u16{ 'U', 'N', 'C', '\\' };
        if (std.mem.startsWith(u16, p[4..], &uncspec)) return .{ .ns = .unc, .body = p[8..] };
        // `\\?\C:\...` is the prefixed spelling of `C:\...`: drop the
        // 4-unit prefix. Anything else behind `\\?\` is an object-manager
        // path the pin contract cannot bind — unsupported, fail closed.
        if (p.len >= 6 and winIsDriveLetter(p[4]) and p[5] == ':')
            return .{ .ns = .dos, .body = p[4..] };
        return null;
    }
    if (p.len >= 2 and p[0] == '\\' and p[1] == '\\') return .{ .ns = .unc, .body = p[2..] };
    if (p.len >= 2 and winIsDriveLetter(p[0]) and p[1] == ':') return .{ .ns = .dos, .body = p };
    return null; // relative or non-path input: unverifiable, fail closed
}

/// Compare two WTF-16LE Windows paths with SYMMETRIC normalization:
/// either operand may carry the `\\?\` verifier prefix or the
/// `\\?\UNC\` spelling (GetFinalPathNameByHandleW answers prefixed,
/// QueryFullProcessImageNameW answers plain, the gate canon is plain) —
/// both sides are brought to the same namespace+body form before the
/// ASCII case-insensitive compare. Windows name matching is
/// case-insensitive beyond ASCII's reach only exactly: NTFS rules are
/// not approximated, a mismatch simply refuses (fail closed). Any
/// unsupported namespace form fails closed (false), on either operand.
/// Pure: the contract is unit-tested on every CI platform.
pub fn windowsPathMatchesW16(handle_path: []const u16, expected: []const u16) bool {
    const a = winNormalizePathW16(handle_path) orelse return false;
    const b = winNormalizePathW16(expected) orelse return false;
    if (a.ns != b.ns) return false;
    return w16EqlIgnoreCase(a.body, b.body);
}

/// UTF-8 front for windowsPathMatchesW16: the gate canon arrives as a
/// UTF-8 string and is decoded (fail closed on any undecodable byte)
/// before the symmetric normalized comparison. The historical contract
/// — kernel-read WTF-16LE path vs canonical UTF-8 path — is unchanged;
/// the prefix handling is symmetric: the old form sliced `\\?\` off the
/// first operand only, so a bare-argv0 pin whose readback carried the
/// prefix could never match the plain QueryFullProcessImageNameW probe.
pub fn windowsPathMatchesUtf8(handle_path: []const u16, canon: []const u8) bool {
    var cbuf: [std.os.windows.PATH_MAX_WIDE]u16 = undefined;
    const clen = std.unicode.utf8ToUtf16Le(&cbuf, canon) catch return false;
    return windowsPathMatchesW16(handle_path, cbuf[0..clen]);
}

/// The image name CreateProcess resolves a bare argv0 to: ".exe" is
/// appended when the basename has no extension — CreateProcessW's own
/// lpApplicationName rule; a name ending in a period gets NO extension
/// appended and is used verbatim; an extensioned name is used verbatim.
/// (std's Windows spawn resolves argv[0] by exactly this rule first.)
/// Pure: unit-tested on every CI platform.
pub fn windowsArgv0ImageName(arena: std.mem.Allocator, argv0: []const u8) error{OutOfMemory}![]const u8 {
    var start: usize = 0;
    for (argv0, 0..) |c, i| {
        if (winIsSep(c)) start = i + 1;
    }
    const bn = argv0[start..];
    if (bn.len > 0 and bn[bn.len - 1] == '.') return argv0; // trailing period: no append
    const dot = std.mem.lastIndexOfScalar(u8, bn, '.');
    const has_ext = if (dot) |d| d + 1 < bn.len else false;
    if (has_ext) return argv0;
    return std.mem.concat(arena, u8, &.{ argv0, ".exe" });
}

// ---------------------------------------------------------------------------
// Windows exec pinning
// ---------------------------------------------------------------------------
//
// The exec gate authorizes canonical STRINGS; the spawn must run the
// AUTHORIZED OBJECT. Windows CreateProcess resolves names — there is no
// fd-exec — so the binding is built from share-mode pins plus a
// suspended-spawn image check (call sites in tools.zig):
//
//   * the exe is opened with CreateFileW sharing READ|WRITE but NOT
//     FILE_SHARE_DELETE (see W_PIN_SHARE): while the handle is open,
//     rename/delete of the file fails (Windows also refuses renaming a
//     directory that holds an open handle, so the ancestor chain is
//     frozen too). CreateProcess needs no share-mode cooperation from
//     third-party handles — the pin is the rename lock, nothing more;
//   * the cwd directory is opened the same way (FILE_LIST_DIRECTORY +
//     FILE_FLAG_BACKUP_SEMANTICS); the spawn receives the pinned handle
//     via SpawnOptions.cwd = .dir, and std derives the lpCurrentDirectory
//     string from THAT handle's final path;
//   * the child is spawned suspended (CREATE_SUSPENDED — the daemon
//     already does this for Job assignment), and QueryFullProcessImageNameW
//     on the process handle must equal the pinned exe path BEFORE the
//     first thread runs: a reparse planted after the pin makes
//     CreateProcess resolve a different image, the check fails, and the
//     child is terminated without executing a single instruction.
//
// Residual boundary (documented): an in-place CONTENT overwrite of the
// authorized exe (write access to the file itself) passes on Windows
// exactly like it passes on POSIX between pin-open and execveat — the
// path is the authorization unit; an attacker with content-write on the
// authorized binary is outside the rename/replay threat model. Bare
// argv[0] resolution follows CreateProcess's ".exe" append rule (see
// windowsArgv0ImageName): a bare name that only PATHEXT-aliases
// (.bat/.cmd, or a .com sibling of a missing .exe) refuses instead of
// running — fail-closed by design.

extern "kernel32" fn CreateFileW(
    lpFileName: [*]const u16,
    dwDesiredAccess: u32,
    dwShareMode: u32,
    lpSecurityAttributes: ?*const anyopaque,
    dwCreationDisposition: u32,
    dwFlagsAndAttributes: u32,
    hTemplateFile: ?std.os.windows.HANDLE,
) callconv(.winapi) std.os.windows.HANDLE;

extern "kernel32" fn GetLastError() callconv(.winapi) u32;

// CreateFileW access/share/disposition constants (winbase.h).
const W_GENERIC_READ: u32 = 0x8000_0000;
const W_FILE_LIST_DIRECTORY: u32 = 0x0000_0001;
const W_FILE_SHARE_READ: u32 = 0x0000_0001;
const W_FILE_SHARE_WRITE: u32 = 0x0000_0002;
const W_OPEN_EXISTING: u32 = 3;
const W_FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const W_FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;

/// Share mode for every pin handle (exe file, cwd directory, PATH
/// candidate): READ|WRITE shared, DELETE not. The unshared DELETE is the
/// rename lock — while the handle is open, rename/delete of the object
/// (and rename of any ancestor directory that holds an open handle)
/// fails. Windows has NO FILE_SHARE_EXECUTE bit: the valid share flags
/// are exactly READ=0x1 / WRITE=0x2 / DELETE=0x4, and any other bit
/// makes CreateFileW return ERROR_INVALID_PARAMETER.
/// CreateProcess imposes no share-mode requirement on third-party
/// handles — it opens the image file itself — so exe pins carry exactly
/// the same mask as directory pins.
const W_PIN_SHARE: u32 = W_FILE_SHARE_READ | W_FILE_SHARE_WRITE;

// Win32 error codes (winerror.h) for the CreateFileW failure map.
const W_ERROR_FILE_NOT_FOUND: u32 = 2;
const W_ERROR_PATH_NOT_FOUND: u32 = 3;
const W_ERROR_ACCESS_DENIED: u32 = 5;
const W_ERROR_SHARING_VIOLATION: u32 = 32;
const W_ERROR_INVALID_NAME: u32 = 123;
const W_ERROR_FILENAME_EXCED_RANGE: u32 = 206;

fn mapCreateFileErrorWin(rc: u32) OpenError {
    return switch (rc) {
        W_ERROR_FILE_NOT_FOUND, W_ERROR_PATH_NOT_FOUND => error.FileNotFound,
        W_ERROR_ACCESS_DENIED => error.AccessDenied,
        W_ERROR_SHARING_VIOLATION => error.FileBusy,
        W_ERROR_INVALID_NAME, W_ERROR_FILENAME_EXCED_RANGE => error.NameTooLong,
        else => error.Unexpected,
    };
}

/// Copy `path` into `buf` as a NUL-terminated WTF-16LE string, returning
/// the length in code units. Fails closed on any decoding problem (a
/// path the daemon cannot spell is unverifiable).
fn pathToW16Z(path: []const u8, buf: []u16) error{ NameTooLong, Unexpected }!usize {
    if (path.len + 1 > buf.len) return error.NameTooLong;
    const n = std.unicode.utf8ToUtf16Le(buf[0 .. buf.len - 1], path) catch return error.Unexpected;
    buf[n] = 0;
    return n;
}

/// Verify an opened (walk) directory handle against an expected canon
/// prefix. Any query failure is a mismatch (fail closed). Windows-only
/// body (referenced from openPinnedWindows's comptime-gated branch).
fn verifyHandlePathWindows(handle: fd_t, expected: []const u8) bool {
    var rbuf: [std.os.windows.PATH_MAX_WIDE]u16 = undefined;
    const n = GetFinalPathNameByHandleW(handle, &rbuf, @intCast(rbuf.len), 0);
    if (n == 0 or n > rbuf.len) return false;
    return windowsPathMatchesUtf8(rbuf[0..n], expected);
}

/// Pin one authorized object (exe file or cwd directory): CreateFileW
/// with everything shared EXCEPT delete — the open handle blocks
/// rename/delete of the object (and of any ancestor directory, which
/// Windows refuses to rename while the tree holds an open handle) for
/// the lifetime of the pin — then the final-path readback must BE the
/// authorized canon: a reparse point on the path opens a different
/// object whose path mismatches. Windows-only body; mirrors
/// openPinnedExe/openPinnedDir's POSIX contract.
fn openPinnedObjectWindows(canon: []const u8, is_dir: bool) OpenError!fd_t {
    var pbuf: [std.os.windows.PATH_MAX_WIDE]u16 = undefined;
    _ = try pathToW16Z(canon, &pbuf);
    const access: u32 = if (is_dir) W_FILE_LIST_DIRECTORY else W_GENERIC_READ;
    const flags: u32 = if (is_dir) W_FILE_FLAG_BACKUP_SEMANTICS else W_FILE_ATTRIBUTE_NORMAL;
    // Exe and directory pins share the same mask (W_PIN_SHARE): the
    // unshared DELETE is the rename lock; CreateProcess opens the image
    // itself and needs no share-mode cooperation from this handle.
    const h = CreateFileW(&pbuf, access, W_PIN_SHARE, null, W_OPEN_EXISTING, flags, null);
    if (h == std.os.windows.INVALID_HANDLE_VALUE) return mapCreateFileErrorWin(GetLastError());
    errdefer std.os.windows.CloseHandle(h);
    var rbuf: [std.os.windows.PATH_MAX_WIDE]u16 = undefined;
    const n = GetFinalPathNameByHandleW(h, &rbuf, @intCast(rbuf.len), 0);
    if (n == 0 or n > rbuf.len) return error.Unexpected; // unverifiable: fail closed
    if (!windowsPathMatchesUtf8(rbuf[0..n], canon))
        return if (is_dir) error.PrefixSwapped else error.PathEscape;
    return h;
}

/// Pin the authorized executable (Windows). Mirrors openPinnedExe's
/// POSIX contract: the readback path must equal `canon`. Off-Windows the
/// body is a dead arm (call sites are comptime-gated to Windows; the
/// guard keeps the kernel32 externs out of non-Windows links).
pub fn openPinnedExeWindows(canon: []const u8) OpenError!fd_t {
    if (comptime builtin.os.tag == .windows) {
        return openPinnedObjectWindows(canon, false);
    }
    return error.Unexpected; // unreachable: no comptime-gated call site
}

/// Pin the authorized child cwd (Windows). Mirrors openPinnedDir's POSIX
/// contract: the readback path must equal `canon`.
pub fn openPinnedCwdWindows(canon: []const u8) OpenError!fd_t {
    if (comptime builtin.os.tag == .windows) {
        return openPinnedObjectWindows(canon, true);
    }
    return error.Unexpected; // unreachable: no comptime-gated call site
}

/// One PATH-search candidate pinned for a bare argv0: the handle binds
/// whatever object sits at `path`; the readback path is returned as the
/// image-verification unit (there is no canon to compare against — the
/// open itself is the authorization binding, exactly like the POSIX
/// openPathCandidate). Windows-only body.
pub const WindowsPinnedCandidate = struct {
    handle: fd_t,
    /// Arena-owned final path of the pinned object, VERBATIM as
    /// GetFinalPathNameByHandleW answers it (`\\?\C:\...`,
    /// `\\?\UNC\...`): the kernel's own spelling is the truth being
    /// pinned. The comparator (windowsPathMatchesW16) normalizes the
    /// verifier prefix symmetrically on BOTH operands, so this raw
    /// spelling compares clean against the plain Win32 form the
    /// suspended-spawn image probe answers.
    path: []const u8,
};

pub fn openPathCandidateWindows(arena: std.mem.Allocator, path: []const u8) OpenError!WindowsPinnedCandidate {
    if (comptime builtin.os.tag == .windows) {
        var pbuf: [std.os.windows.PATH_MAX_WIDE]u16 = undefined;
        _ = try pathToW16Z(path, &pbuf);
        const h = CreateFileW(
            &pbuf,
            W_GENERIC_READ,
            W_PIN_SHARE,
            null,
            W_OPEN_EXISTING,
            W_FILE_ATTRIBUTE_NORMAL,
            null,
        );
        if (h == std.os.windows.INVALID_HANDLE_VALUE) return mapCreateFileErrorWin(GetLastError());
        errdefer std.os.windows.CloseHandle(h);
        var rbuf: [std.os.windows.PATH_MAX_WIDE]u16 = undefined;
        const n = GetFinalPathNameByHandleW(h, &rbuf, @intCast(rbuf.len), 0);
        if (n == 0 or n > rbuf.len) return error.Unexpected; // unverifiable: fail closed
        const path8 = std.unicode.utf16LeToUtf8Alloc(arena, rbuf[0..n]) catch return error.Unexpected;
        return .{ .handle = h, .path = path8 };
    }
    return error.Unexpected; // unreachable: no comptime-gated call site
}

/// Resolve a bare argv0 to a pinned executable, mirroring std's Windows
/// search order (the effective child cwd first, then every PATH entry —
/// relative entries anchor to the daemon cwd) and CreateProcess's ".exe"
/// append rule (windowsArgv0ImageName). ENOENT/ENOTDIR candidates are
/// skipped, EACCES is remembered — the same loop contract as the POSIX
/// resolvePinnedArgv0. Whatever std's spawn later resolves differently
/// is caught by the post-spawn image check (fail closed, the child is
/// terminated before running). Windows-only body.
pub fn resolvePinnedArgv0Windows(
    arena: std.mem.Allocator,
    argv0: []const u8,
    base: []const u8,
    daemon_cwd: []const u8,
    path_env: ?[]const u8,
) (error{OutOfMemory} || OpenError)!WindowsPinnedCandidate {
    var eacces = false;
    var dirs: std.ArrayList([]const u8) = .empty;
    if (base.len != 0) try dirs.append(arena, base);
    if (path_env) |pv| {
        var it = std.mem.tokenizeScalar(u8, pv, ';');
        while (it.next()) |entry| {
            if (entry.len == 0) continue;
            if (std.fs.path.isAbsolute(entry)) {
                try dirs.append(arena, entry);
            } else if (daemon_cwd.len != 0) {
                try dirs.append(arena, try std.mem.concat(arena, u8, &.{ daemon_cwd, "\\", entry }));
            }
        }
    }
    const name = try windowsArgv0ImageName(arena, argv0);
    for (dirs.items) |dir| {
        if (dir.len == 0) continue;
        const full = try std.mem.concat(arena, u8, &.{ dir, "\\", name });
        const cand = openPathCandidateWindows(arena, full) catch |err| switch (err) {
            // The candidate is not there (or not openable): keep
            // searching, exactly like the execvp loop.
            error.FileNotFound, error.NotDir => continue,
            error.AccessDenied => {
                eacces = true;
                continue;
            },
            else => return err,
        };
        return cand;
    }
    if (eacces) return error.AccessDenied;
    return error.FileNotFound;
}

// ---------------------------------------------------------------------------
// Exec pinning: the exec gate authorizes canonical STRINGS (argv0/cwd);
// spawning through the RAW strings would let a racer with rename rights
// on an ancestor swap the path between the gate and the spawn. These
// primitives pin the AUTHORIZED OBJECT instead: a directory fd the child
// fchdir()s into and an executable fd the child execveat()s /
// fexecve()s, both opened with the same confinement + readback contract
// as the file-tool pins above.
// Production callers use these primitives only on POSIX. Windows returns
// UnsupportedPlatform before the Darwin arm; unit-test discovery may still
// reference the public declarations on every target.
// ---------------------------------------------------------------------------

/// Pin the authorized child cwd: O_DIRECTORY|O_NOFOLLOW confined against
/// ancestor symlink swaps, then the fd readback must equal `canon` (the
/// gate's canonicalized string). Linux uses O_PATH so an execute-only
/// directory (0111: no read permission, chdir only needs +x) still pins —
/// fchdir accepts O_PATH descriptors.
pub fn openPinnedDir(io: Io, canon: []const u8) OpenError!fd_t {
    if (comptime builtin.os.tag == .linux) {
        var pbuf: [std.fs.max_path_bytes + 1]u8 = undefined;
        const canon_z = try pathZ(canon, &pbuf);
        // O_DIRECTORY makes a symlink final component fail with ENOTDIR
        // at open time (no O_PATH-symlink-fd ambiguity for directories).
        const fd = openat2Linux(
            std.posix.AT.FDCWD,
            canon_z,
            oU64(.{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }),
            0,
            RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
        ) catch |err| return switch (err) {
            // The canonical cwd component is gone or swapped: refuse.
            error.SymLinkLoop, error.NotDir => error.PrefixSwapped,
            else => err,
        };
        errdefer posix_impl.closeFd(fd);
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const n = fdRealPathLinux(io, fd, &buf) catch return error.PrefixSwapped; // fail closed
        if (!std.mem.eql(u8, buf[0..n], canon)) return error.PrefixSwapped;
        return fd;
    }
    if (comptime builtin.os.tag == .windows) return error.UnsupportedPlatform;
    // Darwin: no O_PATH; a plain O_DIRECTORY|O_NOFOLLOW open plus the
    // F_GETPATH readback pins the same object (an execute-only cwd fails
    // EACCES here — documented boundary, CI never executes this path).
    const fd = try std.posix.openat(std.posix.AT.FDCWD, canon, .{
        .ACCMODE = .RDONLY,
        .DIRECTORY = true,
        .NOFOLLOW = true,
        .CLOEXEC = true,
    }, 0);
    errdefer posix_impl.closeFd(fd);
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = fdRealPathDarwin(fd, &buf) catch return error.PrefixSwapped;
    if (!std.mem.eql(u8, buf[0..n], canon)) return error.PrefixSwapped;
    return fd;
}

/// Pin the authorized executable: the fd the spawned child will
/// execveat(AT_EMPTY_PATH). O_PATH on Linux (opens execute-only binaries
/// too; the kernel accepts O_PATH fds in execveat, verified on 6.8 for
/// ELF and #!-scripts alike, and /proc/self/fd readback works on O_PATH).
/// CLOEXEC: in a threaded daemon a concurrent fork+exec
/// in ANOTHER thread copies the fd table and would inherit a live O_PATH
/// handle on a foreign binary. The pinned CHILD clears the flag itself
/// right after the fork (proc.zig childClearCloexec, before execveat):
/// for a #!-script the kernel hands the interpreter the script path as
/// /dev/fd/<n>, and the interpreter re-opens it after the exec — so the
/// flag must be gone by exec time in the child that USES the fd, and only
/// there (verified on 6.8: with CLOEXEC left set the execveat of a script
/// fails ENOENT exactly as described; the child-side clear restores the
/// #! behavior while the parent and every foreign child stay protected).
/// RESOLVE_NO_SYMLINKS: a canonical path resolves through no symlinks, so
/// any symlink visible during this open is a post-gate plant; a final
/// symlink swap additionally fails the readback (same contract as the
/// file-tool post-check: the opened object must BE the authorized path).
/// A rename-in-place swap (same path, new inode) passes — the path is the
/// authorization unit, exactly like secure.zig's file pins.
/// Linux O_PATH opens never block on a FIFO target (open(2): the file
/// itself is not opened, only a handle is obtained), so this arm carries
/// no NONBLOCK/fd-regular precheck — a non-regular object is refused by
/// the child's execveat instead; the Darwin arm below does the precheck.
pub fn openPinnedExe(io: Io, canon: []const u8) OpenError!fd_t {
    if (comptime builtin.os.tag == .linux) {
        var pbuf: [std.fs.max_path_bytes + 1]u8 = undefined;
        const canon_z = try pathZ(canon, &pbuf);
        const fd = try openat2Linux(
            std.posix.AT.FDCWD,
            canon_z,
            oU64(.{ .PATH = true, .CLOEXEC = true }),
            0,
            RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
        );
        errdefer posix_impl.closeFd(fd);
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const n = fdRealPathLinux(io, fd, &buf) catch return error.PathEscape; // fail closed
        if (!std.mem.eql(u8, buf[0..n], canon)) return error.PathEscape;
        return fd;
    }
    if (comptime builtin.os.tag == .windows) return error.UnsupportedPlatform;
    // Darwin: O_RDONLY (fexecve ultimately execve()s the /dev/fd path, which
    // needs read access anyway). CLOEXEC here too: the pinned child
    // clears it before its execve so the interpreter can re-open the
    // script through /dev/fd; F_GETPATH readback pins the object.
    // Darwin canonical arm: NONBLOCK on the open — an
    // authorized canon that resolves to a writer-less FIFO must not park
    // this thread (and every session-start behind it) in open(2) — then
    // S_ISREG on the OPEN descriptor (a pathname stat the callers may do
    // earlier is not bound to this object), then the flag is cleared
    // before the fd is handed out. The Linux arm needs neither: it opens
    // O_PATH, and open(2) documents that an O_PATH open only obtains a
    // handle to the file without opening it, so a FIFO never blocks
    // there; a non-regular object is refused by the child's execveat.
    const fd = try std.posix.openat(std.posix.AT.FDCWD, canon, .{
        .ACCMODE = .RDONLY,
        .NOFOLLOW = true,
        .CLOEXEC = true,
        .NONBLOCK = true,
    }, 0);
    errdefer posix_impl.closeFd(fd);
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = fdRealPathDarwin(fd, &buf) catch return error.PathEscape;
    if (!std.mem.eql(u8, buf[0..n], canon)) return error.PathEscape;
    // Same ordering as the file-tool arms: the F_GETPATH readback never
    // blocks, so security goes first, the fd-bound object type second,
    // the flag clear last.
    try checkRegularTarget(io, fd);
    try clearNonblock(fd);
    return fd;
}

/// Open one PATH-search candidate for a bare-name argv0. The exec gate
/// authorizes bare NAMES only (no object), so the pin's job is narrower:
/// whatever object this open lands on is the object the child executes —
/// symlink-following matches execvp semantics (a PATH entry may legally
/// resolve through symlinks). No readback: there is no canonical string to
/// compare against; the open itself is the authorization binding.
pub fn openPathCandidate(io: Io, path: []const u8) OpenError!fd_t {
    if (comptime builtin.os.tag == .linux) {
        var pbuf: [std.fs.max_path_bytes + 1]u8 = undefined;
        const path_z = try pathZ(path, &pbuf);
        // Plain O_PATH open, resolve=0: follows symlinks exactly like the
        // execvp resolution the gate's name-match stands for. CLOEXEC:
        // the pin must not leak into concurrent
        // fork+execs of other threads; the pinned child clears the flag
        // before its own execveat so a #!-script candidate still survives
        // the exec for the interpreter's /dev/fd re-open (see
        // openPinnedExe and proc.zig childClearCloexec).
        // O_PATH never blocks on a FIFO either (open(2): the file itself
        // is not opened, only a handle is obtained) — no NONBLOCK or
        // fd-regular precheck on this arm; a non-regular candidate is
        // refused by the child's execveat instead.
        return openat2Linux(
            std.posix.AT.FDCWD,
            path_z,
            oU64(.{ .PATH = true, .CLOEXEC = true }),
            0,
            0,
        );
    }
    if (comptime builtin.os.tag == .windows) return error.UnsupportedPlatform;
    // Darwin PATH-candidate arm: NONBLOCK on the open — a FIFO planted
    // under a PATH entry after the pathname probe would otherwise park
    // this thread in open(2) — then S_ISREG on the OPEN
    // descriptor (the probe's pathname stat is not bound to the opened
    // object), then the flag is cleared. resolvePinnedArgv0's loop maps
    // the refusal like execvp's EACCES: remember and keep searching.
    const fd = try std.posix.openat(std.posix.AT.FDCWD, path, .{
        .ACCMODE = .RDONLY,
        .CLOEXEC = true,
        .NONBLOCK = true,
    }, 0);
    errdefer posix_impl.closeFd(fd);
    try checkRegularTarget(io, fd);
    try clearNonblock(fd);
    return fd;
}

// ---------------------------------------------------------------------------
// Tests (Linux execution; other targets skip — CI runs them on Linux)
// ---------------------------------------------------------------------------

const testing = std.testing;

test "secure: swapped prefix (symlink ancestor) is refused" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = Io.Threaded.global_single_threaded.io();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const root = try tmpAbsSecure(arena, &tmp, io, ".");
    try tmp.dir.createDirPath(io, "victim");
    try tmp.dir.writeFile(io, .{ .sub_path = "victim/secret.txt", .data = "top secret\n" });
    // The allow prefix "/tmp/.../swapped" is a symlink to victim: the
    // rename-race end state, held in place for the call.
    tmp.dir.symLink(io, "victim", "swapped", .{}) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    const prefix = try std.mem.concat(arena, u8, &.{ root, "/swapped" });
    const pin = Pin{
        .prefix = prefix,
        .rel = "secret.txt",
        .canon = try std.mem.concat(arena, u8, &.{ prefix, "/secret.txt" }),
        .deny = &.{},
    };
    // The pinned prefix open must refuse (O_NOFOLLOW on the final
    // component): the authorized string names a symlink now.
    try testing.expectError(error.PrefixSwapped, openPinned(io, pin, .read, .{}));

    // Intermediate-ancestor swap: prefix "/tmp/.../hop/far" where "hop"
    // is a symlink to another tree that also contains "far".
    try tmp.dir.createDirPath(io, "far");
    try tmp.dir.writeFile(io, .{ .sub_path = "far/f.txt", .data = "x" });
    try tmp.dir.createDirPath(io, "aliastree/far");
    try tmp.dir.writeFile(io, .{ .sub_path = "aliastree/far/f.txt", .data = "pwned" });
    tmp.dir.symLink(io, "aliastree", "hop", .{}) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    const prefix2 = try std.mem.concat(arena, u8, &.{ root, "/hop/far" });
    const pin2 = Pin{
        .prefix = prefix2,
        .rel = "f.txt",
        .canon = try std.mem.concat(arena, u8, &.{ prefix2, "/f.txt" }),
        .deny = &.{},
    };
    // RESOLVE_NO_SYMLINKS on the prefix open: the symlinked ancestor
    // refuses even though the final component is a real directory.
    try testing.expectError(error.PrefixSwapped, openPinned(io, pin2, .read, .{}));
}

test "secure: symlink escaping the allow tree is refused (EXDEV)" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = Io.Threaded.global_single_threaded.io();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const root = try tmpAbsSecure(arena, &tmp, io, ".");
    try tmp.dir.createDirPath(io, "allow");
    try tmp.dir.createDirPath(io, "outside");
    try tmp.dir.writeFile(io, .{ .sub_path = "outside/bounty.txt", .data = "outside\n" });
    // allow/esc -> ../outside: the kernel refuses the BENEATH escape.
    tmp.dir.symLink(io, "../outside", "allow/esc", .{}) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    const allow = try std.mem.concat(arena, u8, &.{ root, "/allow" });
    const pin = Pin{
        .prefix = allow,
        .rel = "esc/bounty.txt",
        .canon = try std.mem.concat(arena, u8, &.{ allow, "/esc/bounty.txt" }),
        .deny = &.{},
    };
    try testing.expectError(error.PathEscape, openPinned(io, pin, .read, .{}));
    // And a write-side escape (the dangling-symlink-tail shape): the
    // gate already refuses this string, the kernel now
    // refuses the open even if the gate verdict is replayed.
    const pin2 = Pin{
        .prefix = allow,
        .rel = "esc",
        .canon = try std.mem.concat(arena, u8, &.{ allow, "/esc" }),
        .deny = &.{},
    };
    try testing.expectError(error.PathEscape, openPinned(io, pin2, .dir, .{}));
}

test "secure: symlink into a denied subtree is refused by the post-check" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = Io.Threaded.global_single_threaded.io();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const root = try tmpAbsSecure(arena, &tmp, io, ".");
    try tmp.dir.createDirPath(io, "allow/keys");
    try tmp.dir.writeFile(io, .{ .sub_path = "allow/keys/k", .data = "secret\n" });
    // allow/link -> allow/keys: INSIDE the allow tree, so the kernel
    // confinement passes; the post-check readback must refuse (the
    // symlink planted after the gate — the canonicalised request never
    // saw it).
    tmp.dir.symLink(io, "keys", "allow/link", .{}) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    const allow = try std.mem.concat(arena, u8, &.{ root, "/allow" });
    const keys = try std.mem.concat(arena, u8, &.{ allow, "/keys" });
    const pin = Pin{
        .prefix = allow,
        .rel = "link",
        .canon = try std.mem.concat(arena, u8, &.{ allow, "/link" }),
        .deny = &.{keys},
    };
    try testing.expectError(error.PathDenied, openPinned(io, pin, .read, .{}));
    // The denied bytes were never handed out: the fd was closed unread.
    // (The refusal above happened before readFileAllocFd can run.)
}

test "secure: legal reads, writes, mkdirs and listing work" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = Io.Threaded.global_single_threaded.io();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const root = try tmpAbsSecure(arena, &tmp, io, ".");
    try tmp.dir.createDirPath(io, "allow");
    try tmp.dir.writeFile(io, .{ .sub_path = "allow/f.txt", .data = "hello\n" });
    const allow = try std.mem.concat(arena, u8, &.{ root, "/allow" });

    // read: an existing file through the pinned prefix.
    const pin_read = Pin{
        .prefix = allow,
        .rel = "f.txt",
        .canon = try std.mem.concat(arena, u8, &.{ allow, "/f.txt" }),
        .deny = &.{},
    };
    {
        const fd = try openPinned(io, pin_read, .read, .{});
        defer posix_impl.closeFd(fd);
        const data = try readFileAllocFd(arena, io, fd, 1 << 20);
        try testing.expectEqualStrings("hello\n", data);
    }

    // write: a new file (O_CREAT path, post-check readback of a fresh fd).
    const pin_new = Pin{
        .prefix = allow,
        .rel = "new.txt",
        .canon = try std.mem.concat(arena, u8, &.{ allow, "/new.txt" }),
        .deny = &.{},
    };
    {
        const fd = try openPinned(io, pin_new, .write, .{ .mode = 0o600 });
        defer posix_impl.closeFd(fd);
        try writeAllFdLinux(fd, "written\n");
    }
    {
        var buf: [16]u8 = undefined;
        const data = try tmp.dir.readFile(io, "allow/new.txt", &buf);
        try testing.expectEqualStrings("written\n", data);
    }

    // write with mkdirs: intermediate components created component-wise
    // from the pinned prefix, then the final file.
    const pin_deep = Pin{
        .prefix = allow,
        .rel = "a/b/c.txt",
        .canon = try std.mem.concat(arena, u8, &.{ allow, "/a/b/c.txt" }),
        .deny = &.{},
    };
    {
        const fd = try openPinned(io, pin_deep, .write, .{ .mkdirs = true, .mode = 0o644 });
        defer posix_impl.closeFd(fd);
        try writeAllFdLinux(fd, "deep\n");
    }
    // The deep file landed (statFile succeeds) after the mkdirs walk.
    _ = try tmp.dir.statFile(io, "allow/a/b/c.txt", .{});
    // list_dir: open the directory itself through the pipeline.
    const pin_dir = Pin{
        .prefix = allow,
        .rel = "",
        .canon = allow,
        .deny = &.{},
    };
    {
        const fd = try openPinned(io, pin_dir, .dir, .{});
        defer posix_impl.closeFd(fd);
        var dir = std.Io.Dir{ .handle = fd };
        var names: std.ArrayList([]const u8) = .empty;
        var it = dir.iterate();
        while (try it.next(io)) |entry| {
            try names.append(arena, try arena.dupe(u8, entry.name));
        }
        std.mem.sort([]const u8, names.items, {}, struct {
            fn lt(_: void, a: []const u8, b: []const u8) bool {
                return std.mem.order(u8, a, b) == .lt;
            }
        }.lt);
        try testing.expectEqual(@as(usize, 3), names.items.len);
        try testing.expectEqualStrings("a", names.items[0]);
        try testing.expectEqualStrings("f.txt", names.items[1]);
    }

    // write to a swapped-after-the-gate final symlink: the post-check
    // refuses BEFORE a byte lands outside the pin.
    try tmp.dir.createDirPath(io, "outside");
    const pin_swap = Pin{
        .prefix = allow,
        .rel = "swap.txt",
        .canon = try std.mem.concat(arena, u8, &.{ allow, "/swap.txt" }),
        .deny = &.{},
    };
    tmp.dir.symLink(io, "../outside/pwned.txt", "allow/swap.txt", .{}) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    try testing.expectError(error.PathEscape, openPinned(io, pin_swap, .write, .{ .mode = 0o644 }));
    // Nothing was created through the swapped symlink.
    try testing.expectError(error.FileNotFound, tmp.dir.statFile(io, "outside/pwned.txt", .{}));
}

test "secure: F_GETPATH decode returns the nul-terminated path length" {
    // Darwin fcntl(F_GETPATH) succeeds with rc == 0 and the path written
    // into buf as a NUL-terminated string — the length lives in the NUL
    // position, never in the return value. These cases pin that contract
    // and execute on every host (the decoder is pure).
    var buf: [64]u8 = undefined;
    @memset(buf[0..], 0xAA); // garbage past the NUL must not leak into the length
    const path = "/tmp/x";
    @memcpy(buf[0..path.len], path);
    buf[path.len] = 0; // the kernel writes the NUL; the test does too
    try testing.expectEqual(@as(usize, path.len), try decodeGetPath(0, &buf));
    // A path filling the buffer up to its last byte is a legal success.
    var full: [8]u8 = undefined;
    @memset(full[0..], 'a');
    full[full.len - 1] = 0;
    try testing.expectEqual(@as(usize, full.len - 1), try decodeGetPath(0, &full));
}

test "secure: F_GETPATH decode fails closed on contract violations" {
    var buf: [64]u8 = undefined;
    @memset(buf[0..], 0xAA); // no NUL anywhere in the buffer
    // Kernel failure: rc == -1 (errno set), buf contents undefined.
    try testing.expectError(error.PathEscape, decodeGetPath(-1, &buf));
    // Success rc but no NUL: the path length is unverifiable.
    try testing.expectError(error.PathEscape, decodeGetPath(0, &buf));
    // Empty path (NUL at index 0): not a usable vnode path.
    buf[0] = 0;
    try testing.expectError(error.PathEscape, decodeGetPath(0, &buf));
    // A positive rc is outside the F_GETPATH contract (the legacy code
    // misread it as a length): fail closed instead of trusting it.
    buf[0] = 'a';
    buf[5] = 0;
    try testing.expectError(error.PathEscape, decodeGetPath(5, &buf));
}

/// Full write loop over a raw fd (test-side helper; the tools use
/// os.writeAllFd).
fn writeAllFdLinux(fd: fd_t, bytes: []const u8) !void {
    var off: usize = 0;
    while (off < bytes.len) {
        const rc = std.os.linux.write(fd, bytes.ptr + off, bytes.len - off);
        switch (std.os.linux.errno(rc)) {
            .SUCCESS => off += rc,
            .INTR => continue,
            else => return error.WriteFailed,
        }
    }
}

fn tmpAbsSecure(arena: std.mem.Allocator, tmp: *const testing.TmpDir, io: Io, name: []const u8) ![]const u8 {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = try tmp.dir.realPathFile(io, name, &buf);
    return arena.dupe(u8, buf[0..n]);
}

// ---------------------------------------------------------------------------
// Windows-decision tests (pure functions; every CI platform runs them —
// the kernel32 surface itself is only cross-compiled, so the pure logic
// it feeds is pinned here)
// ---------------------------------------------------------------------------

/// Encode an ASCII test string as WTF-16LE (the Win32 *W APIs' paths).
fn utf16Ascii(comptime s: []const u8) []const u16 {
    return std.unicode.utf8ToUtf16LeStringLiteral(s);
}

test "secure: windows path matcher strips the verifier prefix and folds case" {
    // The kernel readback carries the \\?\ prefix; the canon does not.
    try testing.expect(windowsPathMatchesUtf8(utf16Ascii("\\\\?\\C:\\Allow\\Tool.exe"), "c:\\ALLOW\\tool.EXE"));
    // Bare readback (QueryFullProcessImageNameW form) matches directly.
    try testing.expect(windowsPathMatchesUtf8(utf16Ascii("C:\\a\\b"), "C:\\a\\b"));
    // Different object, longer/shorter canon, wrong path: all refuse.
    try testing.expect(!windowsPathMatchesUtf8(utf16Ascii("\\\\?\\C:\\a\\b"), "C:\\a\\c"));
    try testing.expect(!windowsPathMatchesUtf8(utf16Ascii("C:\\a\\b"), "C:\\a\\b\\c"));
    try testing.expect(!windowsPathMatchesUtf8(utf16Ascii("C:\\a\\b\\c"), "C:\\a\\b"));
    // Case folding is per code unit, never a prefix confusion.
    try testing.expect(!windowsPathMatchesUtf8(utf16Ascii("C:\\abc"), "C:\\abd"));
    // An undecodable canon fails closed (false), never an error escape.
    try testing.expect(!windowsPathMatchesUtf8(utf16Ascii("C:\\a"), "\xff\xfe\xfd"));
}

test "secure: windows path matcher normalizes both operands symmetrically" {
    // The bare-argv0 pin stores the
    // GetFinalPathNameByHandleW readback VERBATIM (`\\?\C:\...`), while
    // the suspended-spawn image probe (QueryFullProcessImageNameW)
    // answers the plain Win32 form — the old comparator sliced the
    // verifier prefix off the FIRST operand only, so every bare-name
    // exec on Windows died as ExecPinMismatch (fail closed, but dead).
    // Normalization is now symmetric: either operand may carry either
    // spelling of the same namespace.
    // (a) actual without the prefix vs expected with it (the defect's
    // exact production shape: image probe vs pin readback).
    try testing.expect(windowsPathMatchesUtf8(utf16Ascii("C:\\Tools\\program.exe"), "\\\\?\\C:\\Tools\\program.exe"));
    // (b) both operands carry the prefix.
    try testing.expect(windowsPathMatchesUtf8(utf16Ascii("\\\\?\\C:\\Tools\\program.exe"), "\\\\?\\C:\\Tools\\program.exe"));
    // (c) case differences fold after normalization, either side.
    try testing.expect(windowsPathMatchesUtf8(utf16Ascii("\\\\?\\c:\\TOOLS\\Program.exe"), "C:\\tools\\PROGRAM.EXE"));
    // (d) genuinely different paths stay different — different tail,
    // different drive, and a DOS path never equals a UNC body.
    try testing.expect(!windowsPathMatchesUtf8(utf16Ascii("C:\\Tools\\program.exe"), "\\\\?\\C:\\Tools\\program2.exe"));
    try testing.expect(!windowsPathMatchesUtf8(utf16Ascii("C:\\Tools\\program.exe"), "\\\\?\\D:\\Tools\\program.exe"));
    try testing.expect(!windowsPathMatchesUtf8(utf16Ascii("\\\\?\\UNC\\Tools\\program.exe"), "\\\\?\\C:\\Tools\\program.exe"));
    // (e) UNC both ways: `\\?\UNC\server\share\...` IS `\\server\share\...`
    // (namespace-aware, not a blind 4-unit slice), in either direction.
    try testing.expect(windowsPathMatchesUtf8(utf16Ascii("\\\\?\\UNC\\srv\\share\\tool.exe"), "\\\\srv\\share\\tool.exe"));
    try testing.expect(windowsPathMatchesUtf8(utf16Ascii("\\\\srv\\share\\tool.exe"), "\\\\?\\UNC\\srv\\share\\tool.exe"));
    try testing.expect(windowsPathMatchesUtf8(utf16Ascii("\\\\?\\UNC\\srv\\share\\tool.exe"), "\\\\?\\UNC\\srv\\share\\tool.exe"));
    // Different UNC server or share: still a different object.
    try testing.expect(!windowsPathMatchesUtf8(utf16Ascii("\\\\srv\\share\\tool.exe"), "\\\\?\\UNC\\srv\\share2\\tool.exe"));
    // (f) unsupported namespace forms fail closed on either operand:
    // GLOBALROOT, a volume GUID, and relative/non-path inputs are not
    // object paths the exec contract can underwrite.
    try testing.expect(!windowsPathMatchesUtf8(utf16Ascii("C:\\a\\b"), "\\\\?\\GLOBALROOT\\Device\\HarddiskVolume1\\a"));
    try testing.expect(!windowsPathMatchesUtf8(utf16Ascii("\\\\?\\GLOBALROOT\\Device\\a"), "C:\\a"));
    try testing.expect(!windowsPathMatchesUtf8(utf16Ascii("\\\\?\\Volume{11111111-2222-3333-4444-555555555555}\\a"), "C:\\a"));
    try testing.expect(!windowsPathMatchesUtf8(utf16Ascii("a\\b"), "a\\b"));
}

test "secure: windows path under prefix folds case and backslash boundaries" {
    // The post-check deny matcher is pinned to
    // the Windows grammar — backslash boundaries and ASCII case fold —
    // while the deny-wins semantics stay byte-for-byte. The POSIX
    // grammar parameters keep the historical exact rule.
    try testing.expect(pathUnderPrefixSty("C:\\a\\b", "C:\\a", "/\\", true));
    // Case folds both sides (the deny prefix keeps the operator's
    // spelling, the readback keeps the on-disk one).
    try testing.expect(pathUnderPrefixSty("C:\\Ab\\x", "c:\\ab", "/\\", true));
    // Sibling prefix: still no match.
    try testing.expect(!pathUnderPrefixSty("C:\\ab", "C:\\a", "/\\", true));
    try testing.expect(!pathUnderPrefixSty("C:\\a\\b", "D:\\a", "/\\", true));
    // UNC roots and descendants.
    try testing.expect(pathUnderPrefixSty("\\\\srv\\share\\x", "\\\\srv\\share", "/\\", true));
    try testing.expect(!pathUnderPrefixSty("\\\\srv\\share2\\x", "\\\\srv\\share", "/\\", true));
    // A prefix ending in a separator is a root and matches everything.
    try testing.expect(pathUnderPrefixSty("C:\\a\\b", "C:\\", "/\\", true));
    // POSIX grammar: no fold, no backslash boundary.
    try testing.expect(!pathUnderPrefixSty("C:\\a\\b", "C:\\a", "/", false));
    try testing.expect(pathUnderPrefixSty("/a/b", "/a", "/", false));
    try testing.expect(!pathUnderPrefixSty("/ab", "/a", "/", false));
}

test "secure: windows argv0 image name follows the CreateProcess extension rule" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    // No extension: ".exe" is appended (CreateProcessW's own rule).
    try testing.expectEqualStrings("cmd.exe", try windowsArgv0ImageName(arena, "cmd"));
    // Extension present (any): used verbatim.
    try testing.expectEqualStrings("tool.exe", try windowsArgv0ImageName(arena, "tool.exe"));
    try testing.expectEqualStrings("TOOL.EXE", try windowsArgv0ImageName(arena, "TOOL.EXE"));
    try testing.expectEqualStrings("run.bat", try windowsArgv0ImageName(arena, "run.bat"));
    // Trailing period: NO extension is appended.
    try testing.expectEqualStrings("foo.", try windowsArgv0ImageName(arena, "foo."));
    // The rule looks at the basename; the path is kept whole.
    try testing.expectEqualStrings("bin\\mytool.exe", try windowsArgv0ImageName(arena, "bin\\mytool"));
    try testing.expectEqualStrings("C:\\x\\y.exe", try windowsArgv0ImageName(arena, "C:\\x\\y"));
}

test "secure: windows mkdirs walk steps align canon and rel" {
    // rel is a literal canon suffix, so each step's canon_len slices the
    // authorized prefix the opened component must verify against.
    {
        var walk = winMkdirsWalk("C:\\p\\a\\b", "a\\b");
        const s1 = walk.next().?;
        try testing.expectEqualStrings("a", s1.comp);
        try testing.expectEqualStrings("C:\\p\\a", "C:\\p\\a\\b"[0..s1.canon_len]);
        const s2 = walk.next().?;
        try testing.expectEqualStrings("b", s2.comp);
        try testing.expectEqualStrings("C:\\p\\a\\b", "C:\\p\\a\\b"[0..s2.canon_len]);
        try testing.expect(walk.next() == null);
    }
    // A leading separator survives the alignment (filePin strips only
    // '/'; a '\' separator stays inside rel) — the arithmetic holds.
    {
        var walk = winMkdirsWalk("C:\\p\\a\\b", "\\a\\b");
        const s1 = walk.next().?;
        try testing.expectEqualStrings("a", s1.comp);
        try testing.expectEqualStrings("C:\\p\\a", "C:\\p\\a\\b"[0..s1.canon_len]);
        const s2 = walk.next().?;
        try testing.expectEqualStrings("C:\\p\\a\\b", "C:\\p\\a\\b"[0..s2.canon_len]);
        try testing.expect(walk.next() == null);
    }
    // Forward-slash canon aligns identically (either separator).
    {
        var walk = winMkdirsWalk("C:/p/a/b", "a/b");
        const s1 = walk.next().?;
        try testing.expectEqualStrings("C:/p/a", "C:/p/a/b"[0..s1.canon_len]);
    }
    // Component counting drives the walk's dir-vs-file decision.
    try testing.expectEqual(@as(usize, 0), winCountComponents(""));
    try testing.expectEqual(@as(usize, 1), winCountComponents("c.txt"));
    try testing.expectEqual(@as(usize, 2), winCountComponents("a\\c.txt"));
    try testing.expectEqual(@as(usize, 3), winCountComponents("a\\b/c"));
    try testing.expectEqual(@as(usize, 3), winCountComponents("\\a\\\\b\\c\\"));
}

test "secure: w16 case fold compares ascii units and nothing wider" {
    // Equal modulo ASCII case.
    try testing.expect(w16EqlIgnoreCase(utf16Ascii("CMD.EXE"), utf16Ascii("cmd.exe")));
    // Different lengths and different units refuse.
    try testing.expect(!w16EqlIgnoreCase(utf16Ascii("cmd"), utf16Ascii("cmd.")));
    try testing.expect(!w16EqlIgnoreCase(utf16Ascii("abc"), utf16Ascii("abd")));
    // Non-ASCII units compare exactly (no fold approximation).
    const wide: []const u16 = &[_]u16{ 0x0430, 0x0431 }; // Cyrillic lowercase a and be
    const caps: []const u16 = &[_]u16{ 0x0410, 0x0411 }; // Cyrillic uppercase A and Be
    try testing.expect(w16EqlIgnoreCase(wide, wide));
    try testing.expect(!w16EqlIgnoreCase(wide, caps));
}

test "secure: windows pin share mask is read+write and no invented bits" {
    // Windows has NO FILE_SHARE_EXECUTE:
    // the valid share bits are READ=0x1, WRITE=0x2, DELETE=0x4, and any
    // other bit makes CreateFileW return ERROR_INVALID_PARAMETER.
    // The pin mask is READ|WRITE == 0x3: the unshared
    // FILE_SHARE_DELETE IS the rename lock, and CreateProcess needs no
    // share-mode cooperation from third-party handles. Pure constant
    // logic — compiled and checked on every target, Windows included.
    comptime {
        if (W_PIN_SHARE != 0x3) @compileError("pin share mask must be exactly FILE_SHARE_READ|FILE_SHARE_WRITE");
        if (W_PIN_SHARE & 0x8 != 0) @compileError("FILE_SHARE_EXECUTE (0x8) does not exist on Windows");
        if (W_PIN_SHARE & 0x4 != 0) @compileError("FILE_SHARE_DELETE must stay unshared: it is the pin's rename lock");
    }
    try testing.expectEqual(@as(u32, 0x3), W_PIN_SHARE);
    try testing.expectEqual(@as(u32, 0), W_PIN_SHARE & 0x8);
    // The raw constants stay ABI-honest winbase.h values.
    try testing.expectEqual(@as(u32, 1), W_FILE_SHARE_READ);
    try testing.expectEqual(@as(u32, 2), W_FILE_SHARE_WRITE);
}

test "secure: write-branch failure paths own the target fd (structure)" {
    // Structural pin: all three write
    // branches (Linux/Darwin/Windows) must own the freshly opened target
    // through an errdefer from acquisition to the final return, so a
    // failure after the acquisition — the truncate included — cannot
    // leak the descriptor. A behavioral error injection is not reachable
    // on the test platform: truncateFd's Linux failure modes (EINVAL on
    // a non-writable or special descriptor) are all refused earlier by
    // the open flags or the regular-file check, and ftruncate succeeds
    // even on procfs files (verified live on /proc/self/oom_score_adj).
    // So the discipline is pinned structurally against this file's own
    // source: the needles are built by runtime concatenation so this
    // test's own text never matches, and the counts are exact.
    const src: []const u8 = @embedFile("secure.zig");
    const posix_needle = "the errdefer owns " ++ "fd through the return";
    var posix_sites: usize = 0;
    var rest: []const u8 = src;
    while (std.mem.indexOf(u8, rest, posix_needle)) |at| {
        posix_sites += 1;
        rest = rest[at + posix_needle.len ..];
    }
    // Linux + Darwin write branches.
    try testing.expectEqual(@as(usize, 2), posix_sites);
    const win_needle = "the errdefer owns " ++ "the handle through the return";
    try testing.expect(std.mem.indexOf(u8, src, win_needle) != null);
}

test "secure: windows prefix handle is verified before every use (structure)" {
    // openPinnedWindows must verify the
    // prefix handle (final-path readback against pin.prefix) IMMEDIATELY
    // after the openDir — before the empty-rel ownership return, before
    // the mkdirs walk, before the relative target open, so the rel==""
    // branch never returns an unverified handle. The
    // kernel32 surface is cross-compiled only, so the discipline is
    // pinned structurally against this file's own source (needles built
    // by runtime concatenation so this test's own text never matches;
    // counts and order are exact), plus the pure comparator logic the
    // branch runs.
    const src: []const u8 = @embedFile("secure.zig");
    const verify = "verifyHandlePathWindows(" ++ "base.handle, pin.prefix)";
    var sites: usize = 0;
    var rest: []const u8 = src;
    while (std.mem.indexOf(u8, rest, verify)) |at| {
        sites += 1;
        rest = rest[at + verify.len ..];
    }
    // Exactly one prefix verification; the mkdirs walk's per-component
    // check slices canon (not the whole prefix), so it cannot match.
    try testing.expectEqual(@as(usize, 1), sites);
    const verify_at = std.mem.indexOf(u8, src, verify) orelse return error.TestUnexpectedResult;
    // The verification precedes the empty-rel ownership transfer...
    const empty_rel = ".dir => return " ++ "base.handle";
    const empty_at = std.mem.indexOf(u8, src, empty_rel) orelse return error.TestUnexpectedResult;
    try testing.expect(verify_at < empty_at);
    // ...the mkdirs walk...
    const walk = "winMkdirsWalk(" ++ "pin.canon, pin.rel)";
    const walk_at = std.mem.indexOf(u8, src, walk) orelse return error.TestUnexpectedResult;
    try testing.expect(verify_at < walk_at);
    // ...and the relative target opens (the read branch shown; the dir
    // and write branches share the same base cursor).
    const rel_open = "base.openFile(" ++ "io, pin.rel, .{})";
    const rel_at = std.mem.indexOf(u8, src, rel_open) orelse return error.TestUnexpectedResult;
    try testing.expect(verify_at < rel_at);
    // The refusal closes the handle: no leak on a swapped prefix.
    const refuse = "return error.Prefix" ++ "Swapped;";
    const seg = src[verify_at..@min(verify_at + 400, src.len)];
    try testing.expect(std.mem.indexOf(u8, seg, refuse) != null);

    // Pure logic half (every platform runs it): for the empty-rel pin
    // (canon == prefix) the readback-vs-prefix comparison the new branch
    // performs accepts the authorized prefix in either namespace
    // spelling with ASCII case folded — and refuses a reparse-swapped
    // directory.
    try testing.expect(windowsPathMatchesUtf8(utf16Ascii("\\\\?\\C:\\Allow"), "c:\\allow"));
    try testing.expect(windowsPathMatchesUtf8(utf16Ascii("\\\\?\\UNC\\srv\\share"), "\\\\srv\\share"));
    try testing.expect(!windowsPathMatchesUtf8(utf16Ascii("\\\\?\\C:\\Evil"), "C:\\Allow"));
    try testing.expect(!windowsPathMatchesUtf8(utf16Ascii("\\\\?\\C:\\Allow2"), "C:\\Allow"));
}

test "secure: darwin exe and candidate opens verify fd regularity (structure)" {
    // Both Darwin exec-pin arms (the canonical openPinnedExe and the
    // PATH-candidate openPathCandidate) must open with NONBLOCK — a
    // writer-less FIFO at the authorized path cannot park the thread
    // (and session-start behind it) in open(2) — then verify S_ISREG on
    // the OPEN descriptor (a pathname stat is not bound to the opened
    // object), then clear the flag.
    // The Darwin libc surface is cross-compiled only, so each arm is
    // pinned by a marker comment whose segment's first occurrences must
    // be ordered: open flags, fd-bound regular check, flag clear.
    const src: []const u8 = @embedFile("secure.zig");
    const nb = ".NONBLOCK = " ++ "true";
    const reg = "checkRegular" ++ "Target(io, fd)";
    const clr = "clearNon" ++ "block(fd)";
    const markers = [_][]const u8{
        "Darwin canonical arm:",
        "Darwin PATH-candidate arm:",
    };
    for (markers) |m| {
        const at = std.mem.indexOf(u8, src, m) orelse return error.TestUnexpectedResult;
        const seg = src[at..@min(at + 2000, src.len)];
        const nb_at = std.mem.indexOf(u8, seg, nb) orelse return error.TestUnexpectedResult;
        const reg_at = std.mem.indexOf(u8, seg, reg) orelse return error.TestUnexpectedResult;
        const clr_at = std.mem.indexOf(u8, seg, clr) orelse return error.TestUnexpectedResult;
        // NONBLOCK is set on the open, the fd-bound type check follows,
        // and the flag clear comes last — before the fd is handed out.
        try testing.expect(nb_at < reg_at);
        try testing.expect(reg_at < clr_at);
    }
}

// ---------------------------------------------------------------------------
// Test helpers: mkfifo + a hang watchdog.
// ---------------------------------------------------------------------------

/// mkfifo(3) via mknod(S_IFIFO): the local-writer fixture for the
/// node-wide DoS receipt (a FIFO inside a read_paths-covered directory).
fn mkfifoLinux(path: []const u8) !void {
    var buf: [std.fs.max_path_bytes + 1]u8 = undefined;
    if (path.len > std.fs.max_path_bytes) return error.NameTooLong;
    @memcpy(buf[0..path.len], path);
    buf[path.len] = 0;
    // S_IFIFO = 0o010000; mknod applies the creation bits exactly.
    const rc = std.os.linux.mknod(buf[0..path.len :0], 0o010000 | 0o644, 0);
    switch (std.os.linux.errno(rc)) {
        .SUCCESS, .EXIST => return,
        else => return error.Unexpected,
    }
}

/// Worker outcome for the hang-watchdog tests: the error slot is written
/// BEFORE the done flag (release), the waiter reads it after the flag
/// (acquire) — ?anyerror itself is not an atomic-legal type.
const WatchOutcome = struct {
    err: ?anyerror = null,
    done: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
};

fn watchReport(out: *WatchOutcome, err: ?anyerror) void {
    out.err = err;
    out.done.store(true, .release);
}

/// True once the worker reported within `timeout_ms`. A blocked open(2)
/// on a FIFO never completes: the watchdog turns that hang into a test
/// FAILURE instead of a wedged CI (the detached worker dies with the
/// process at exit).
fn waitOutcome(out: *WatchOutcome, timeout_ms: u64) bool {
    var waited: u64 = 0;
    while (waited < timeout_ms) {
        if (out.done.load(.acquire)) return true;
        posix_impl.sleepMs(5);
        waited += 5;
    }
    return out.done.load(.acquire);
}

/// True when fd carries FD_CLOEXEC (fcntl F_GETFD): the property the exe
/// pins must hold in the PARENT so concurrent fork+exec in other threads
/// can never inherit the O_PATH pin on a foreign binary.
fn fdHasCloexecLinux(fd: fd_t) bool {
    const rc = std.os.linux.fcntl(fd, std.posix.F.GETFD, 0);
    if (std.os.linux.errno(rc) != .SUCCESS) return false;
    return (rc & std.posix.FD_CLOEXEC) != 0;
}

test "secure: fifo target is refused promptly instead of hanging" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = Io.Threaded.global_single_threaded.io();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // A read-only token's read_paths cover the directory holding a FIFO
    // planted by a local writer: the pinned
    // open must answer an error PROMPTLY — a plain open(2) would park the
    // connection thread forever, one FIFO per thread until max_conn.
    const root = try tmpAbsSecure(arena, &tmp, io, ".");
    const fifo_path = try std.mem.concat(arena, u8, &.{ root, "/pipe" });
    try mkfifoLinux(fifo_path);

    // Read side: O_RDONLY on a FIFO with no writer blocks forever.
    {
        var outcome = WatchOutcome{};
        const t = try std.Thread.spawn(.{}, struct {
            fn run(io_: Io, pin: Pin, out: *WatchOutcome) void {
                if (openPinned(io_, pin, .read, .{})) |_| {
                    watchReport(out, error.TestUnexpectedResult);
                } else |err| watchReport(out, err);
            }
        }.run, .{ io, Pin{ .prefix = root, .rel = "pipe", .canon = fifo_path, .deny = &.{} }, &outcome });
        t.detach();
        try testing.expect(waitOutcome(&outcome, 2000)); // never a hang
        try testing.expectEqual(@as(anyerror, error.NotRegularFile), outcome.err.?);
    }
    // Write side: O_WRONLY|O_CREAT on a FIFO with no reader blocks forever.
    {
        var outcome = WatchOutcome{};
        const t = try std.Thread.spawn(.{}, struct {
            fn run(io_: Io, pin: Pin, out: *WatchOutcome) void {
                if (openPinned(io_, pin, .write, .{ .mode = 0o644 })) |_| {
                    watchReport(out, error.TestUnexpectedResult);
                } else |err| watchReport(out, err);
            }
        }.run, .{ io, Pin{ .prefix = root, .rel = "pipe", .canon = fifo_path, .deny = &.{} }, &outcome });
        t.detach();
        try testing.expect(waitOutcome(&outcome, 2000)); // never a hang
        try testing.expectEqual(@as(anyerror, error.NotRegularFile), outcome.err.?);
    }
}

test "secure: exe pin fds are cloexec in the parent" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = Io.Threaded.global_single_threaded.io();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try tmp.dir.writeFile(io, .{ .sub_path = "tool", .data = "#!/bin/sh\n" });
    const root = try tmpAbsSecure(arena, &tmp, io, ".");
    const tool = try std.mem.concat(arena, u8, &.{ root, "/tool" });

    // openPinnedExe: the fd the spawned child
    // execveat()s. In the PARENT it must carry FD_CLOEXEC — a concurrent
    // fork+exec in another thread inherits the fd table and would
    // otherwise hand a foreign process an O_PATH handle on this binary.
    // (The pinned child itself clears the flag before execveat so a
    // #!-script interpreter can re-open /dev/fd/<n>: proc.zig.)
    {
        const fd = try openPinnedExe(io, tool);
        defer posix_impl.closeFd(fd);
        try testing.expect(fdHasCloexecLinux(fd));
    }
    // openPathCandidate: the same contract for PATH-resolved bare names.
    {
        const fd = try openPathCandidate(io, tool);
        defer posix_impl.closeFd(fd);
        try testing.expect(fdHasCloexecLinux(fd));
    }
}

test "secure: in-tree dangling symlink write refuses before creating" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = Io.Threaded.global_single_threaded.io();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // The gate saw allow/target ABSENT (the write
    // would create it). A racer then plants a dangling symlink there
    // whose target points INSIDE the write_deny subtree — BENEATH passes,
    // so the old O_CREAT|follow open CREATED the deny-subtree file before
    // the post-check refused. The write open must refuse BEFORE a byte of
    // the deny tree exists.
    const root = try tmpAbsSecure(arena, &tmp, io, ".");
    try tmp.dir.createDirPath(io, "allow/denydir");
    const allow = try std.mem.concat(arena, u8, &.{ root, "/allow" });
    const denydir = try std.mem.concat(arena, u8, &.{ allow, "/denydir" });
    tmp.dir.symLink(io, "denydir/new.txt", "allow/target", .{}) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    const pin = Pin{
        .prefix = allow,
        .rel = "target",
        .canon = try std.mem.concat(arena, u8, &.{ allow, "/target" }),
        .deny = &.{denydir},
    };
    try testing.expectError(error.PathEscape, openPinned(io, pin, .write, .{ .mode = 0o644 }));
    // Nothing was created through the planted symlink.
    try testing.expectError(error.FileNotFound, tmp.dir.statFile(io, "allow/denydir/new.txt", .{}));
}

// Copy-specific primitives deliberately do not reuse the legacy follow-final
// file opens. Every copy component is no-follow, including unrestricted calls.
pub fn copyVerify(io: Io, fd: fd_t, canon: []const u8) !void {
    const pin = Pin{ .prefix = canon, .rel = "", .canon = canon, .deny = &.{} };
    if (comptime builtin.os.tag == .linux) return postCheckLinux(io, fd, pin);
    if (comptime builtin.os.tag == .macos) return postCheckDarwin(fd, pin);
    return error.AtomicPublishUnsupported;
}

pub fn copyOpenRoot(io: Io, path: []const u8) !fd_t {
    if (comptime builtin.os.tag == .windows) return error.AtomicPublishUnsupported;
    var buf: [std.fs.max_path_bytes + 1]u8 = undefined;
    const flags: std.posix.O = .{ .ACCMODE = .RDONLY, .CLOEXEC = true, .NOFOLLOW = true, .NONBLOCK = true };
    if (comptime builtin.os.tag == .linux) {
        return openat2Linux(std.posix.AT.FDCWD, try pathZ(path, &buf), oU64(flags), 0, RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS) catch |err| switch (err) {
            error.SymLinkLoop => error.SymlinkNotAllowed,
            else => return err,
        };
    }
    // Darwin: retain each parent until the next component is open. Absolute
    // paths start at /; relative paths start at the actual cwd capability.
    var cur = try std.posix.openat(std.posix.AT.FDCWD, if (std.fs.path.isAbsolute(path)) "/" else ".", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
    errdefer posix_impl.closeFd(cur);
    var parts = std.mem.tokenizeScalar(u8, path, '/');
    while (parts.next()) |part| {
        const next = std.posix.openat(cur, part, flags, 0) catch |err| switch (err) {
            error.SymLinkLoop => return error.SymlinkNotAllowed,
            else => return err,
        };
        posix_impl.closeFd(cur);
        cur = next;
    }
    _ = io;
    return cur;
}

pub fn copyValidName(name: []const u8) bool {
    return name.len != 0 and !std.mem.eql(u8, name, ".") and !std.mem.eql(u8, name, "..") and
        std.mem.indexOfAny(u8, name, "/\x00") == null;
}

pub fn copyOpenChild(io: Io, parent: fd_t, name: []const u8, create: bool) !fd_t {
    if (comptime builtin.os.tag == .windows) return error.AtomicPublishUnsupported;
    if (!copyValidName(name)) return error.BadPathName;
    const flags: std.posix.O = .{ .ACCMODE = if (create) .RDWR else .RDONLY, .CLOEXEC = true, .NOFOLLOW = true, .NONBLOCK = true, .CREAT = create, .EXCL = create };
    const mode: mode_t = if (create) 0o600 else 0;
    if (comptime builtin.os.tag == .linux) {
        var buf: [std.fs.max_path_bytes + 1]u8 = undefined;
        return openat2Linux(parent, try pathZ(name, &buf), oU64(flags), mode, RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | 0x01) catch |err| switch (err) {
            error.SymLinkLoop => error.SymlinkNotAllowed,
            else => return err,
        };
    }
    const fd = std.posix.openat(parent, name, flags, mode) catch |err| switch (err) {
        error.SymLinkLoop => return error.SymlinkNotAllowed,
        else => return err,
    };
    errdefer posix_impl.closeFd(fd);
    const a = try copyIdentity(io, parent);
    const b = try copyIdentity(io, fd);
    if (a.device != b.device) return error.PathEscape;
    return fd;
}

pub const CopyIdentity = struct { device: u64, inode: u64 };
pub fn copyIdentity(io: Io, fd: fd_t) !CopyIdentity {
    _ = io;
    if (comptime builtin.os.tag == .linux) {
        var st: std.os.linux.Statx = undefined;
        const rc = std.os.linux.statx(fd, "", std.os.linux.AT.EMPTY_PATH, .{ .INO = true }, &st);
        if (std.os.linux.errno(rc) != .SUCCESS or !st.mask.INO) return error.PathEscape;
        return .{ .device = (@as(u64, st.dev_major) << 32) | st.dev_minor, .inode = st.ino };
    }
    if (comptime builtin.os.tag == .macos) {
        var st: std.c.Stat = undefined;
        if (std.c.fstat(fd, &st) != 0) return error.PathEscape;
        return .{ .device = @intCast(st.dev), .inode = st.ino };
    }
    return error.AtomicPublishUnsupported;
}

/// Identity, not spelling, catches bind/namespace aliases of the source in
/// the destination's ancestry. No writes occur before this walk finishes.
pub fn copyCheckAncestors(io: Io, source: fd_t, destination_parent: fd_t) !void {
    if (comptime builtin.os.tag == .windows) return error.AtomicPublishUnsupported;
    const wanted = try copyIdentity(io, source);
    var cur = try std.posix.openat(destination_parent, ".", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }, 0);
    defer posix_impl.closeFd(cur);
    for (0..1024) |_| {
        const here = try copyIdentity(io, cur);
        if (std.meta.eql(here, wanted)) return error.PathOverlap;
        const parent = try std.posix.openat(cur, "..", .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }, 0);
        const above = copyIdentity(io, parent) catch |err| {
            posix_impl.closeFd(parent);
            return err;
        };
        posix_impl.closeFd(cur);
        cur = parent;
        if (std.meta.eql(here, above)) return;
    }
    return error.CopyDepthExceeded;
}

extern "c" fn renameatx_np(c_int, [*:0]const u8, c_int, [*:0]const u8, c_uint) c_int;

/// No stat+rename emulation: unsupported filesystems must refuse safely.
pub fn copyPublish(stage: fd_t, parent: fd_t, name: []const u8) !void {
    if (comptime builtin.os.tag == .windows) return error.AtomicPublishUnsupported;
    var buf: [std.fs.max_path_bytes + 1]u8 = undefined;
    const z = try pathZ(name, &buf);
    if (comptime builtin.os.tag == .linux) {
        while (true) {
            const rc = std.os.linux.renameat2(stage, "payload", parent, z, .{ .NOREPLACE = true });
            switch (std.os.linux.errno(rc)) {
                .SUCCESS => return,
                .INTR => continue,
                .EXIST, .NOTEMPTY => return error.DestinationExists,
                .NOSYS, .OPNOTSUPP, .INVAL => return error.AtomicPublishUnsupported,
                else => return error.Unexpected,
            }
        }
    }
    if (renameatx_np(stage, "payload", parent, z, 0x4) == 0) return;
    switch (@as(std.c.E, @enumFromInt(std.c._errno().*))) {
        .EXIST, .NOTEMPTY => return error.DestinationExists,
        .NOSYS, .OPNOTSUPP, .INVAL => return error.AtomicPublishUnsupported,
        else => return error.Unexpected,
    }
}

/// Kernel transfer with a bounded caller-owned buffer for hashing the exact
/// staged bytes. Unsupported kernel/filesystem combinations use read/write.
pub fn copyChunk(io: Io, source: fd_t, destination: fd_t, offset: u64, buf: []u8, kernel_copy: *bool) !usize {
    if (comptime builtin.os.tag == .linux) {
        if (kernel_copy.*) {
            var src_off: i64 = @intCast(offset);
            var dst_off: i64 = @intCast(offset);
            const rc = std.os.linux.copy_file_range(source, &src_off, destination, &dst_off, buf.len, 0);
            switch (std.os.linux.errno(rc)) {
                .SUCCESS => {
                    if (rc == 0) return 0;
                    const dst: Io.File = .{ .handle = destination, .flags = .{ .nonblocking = true } };
                    const n = try dst.readPositionalAll(io, buf[0..rc], offset);
                    if (n != rc) return error.SourceChanged;
                    return n;
                },
                .INTR => return copyChunk(io, source, destination, offset, buf, kernel_copy),
                .XDEV, .NOSYS, .OPNOTSUPP, .INVAL => kernel_copy.* = false,
                else => return error.Unexpected,
            }
        }
    }
    const src: Io.File = .{ .handle = source, .flags = .{ .nonblocking = true } };
    const dst: Io.File = .{ .handle = destination, .flags = .{ .nonblocking = true } };
    const n = try src.readPositional(io, &.{buf}, offset);
    try dst.writePositionalAll(io, buf[0..n], offset);
    return n;
}

/// Open the authorized prefix first, then prohibit mount and symlink crossings
/// in every relative component. The final readback binds the capability.
pub fn copyOpenPin(io: Io, pin: Pin) !fd_t {
    if (comptime builtin.os.tag == .windows) return error.AtomicPublishUnsupported;
    var cur = try copyOpenRoot(io, pin.prefix);
    errdefer posix_impl.closeFd(cur);
    try copyVerify(io, cur, pin.prefix);
    var parts = std.mem.tokenizeScalar(u8, pin.rel, '/');
    while (parts.next()) |part| {
        const next = try copyOpenChild(io, cur, part, false);
        posix_impl.closeFd(cur);
        cur = next;
    }
    try copyVerify(io, cur, pin.canon);
    return cur;
}

/// Only our own private staging objects qualify for recovery. Ownership and
/// type are read from the pinned handle, never from an earlier pathname stat.
pub fn copyPrivateOwner(fd: fd_t, directory: bool) bool {
    if (comptime builtin.os.tag == .linux) {
        var st: std.os.linux.Statx = undefined;
        const rc = std.os.linux.statx(fd, "", std.os.linux.AT.EMPTY_PATH, .{ .TYPE = true, .MODE = true, .UID = true, .NLINK = true }, &st);
        if (std.os.linux.errno(rc) != .SUCCESS or !st.mask.TYPE or !st.mask.MODE or !st.mask.UID or !st.mask.NLINK) return false;
        return st.uid == std.os.linux.geteuid() and (st.mode & 0o7777) == (if (directory) @as(u16, 0o700) else @as(u16, 0o600)) and
            (st.mode & 0o170000) == (if (directory) @as(u16, 0o040000) else @as(u16, 0o100000)) and (directory or st.nlink == 1);
    }
    if (comptime builtin.os.tag == .macos) {
        var st: std.c.Stat = undefined;
        if (std.c.fstat(fd, &st) != 0) return false;
        return st.uid == std.c.geteuid() and (st.mode & 0o7777) == (if (directory) @as(u16, 0o700) else @as(u16, 0o600)) and
            (st.mode & 0o170000) == (if (directory) @as(u16, 0o040000) else @as(u16, 0o100000)) and (directory or st.nlink == 1);
    }
    return false;
}

pub fn copyTryLock(fd: fd_t) bool {
    if (comptime builtin.os.tag == .linux) return std.os.linux.errno(std.os.linux.flock(fd, 2 | 4)) == .SUCCESS;
    if (comptime builtin.os.tag == .macos) return std.c.flock(fd, 2 | 4) == 0;
    return false;
}
