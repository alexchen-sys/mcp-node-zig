//! Cross-platform socket layer for the HTTP transport.
//!
//! Owns everything `main.zig` needs from a connected stream socket:
//!   * `socketReadSome`  — one bounded read, 0 means clean EOF
//!   * `socketWriteAll`  — full-buffer write with short-write loop
//!   * `setSocketTimeouts` — RCVTIMEO/SNDTIMEO/TCP_NODELAY setup
//!
//! # Why POSIX does NOT route socket I/O through the Io vtable
//!
//! std 0.16 `netReadPosix`/`netWritePosix` (Io/Threaded.zig) map EAGAIN to
//! `errnoBug` — a debug panic and `error.Unexpected` in release. With
//! SO_RCVTIMEO/SO_SNDTIMEO armed (the daemon's slow-loris defense), EAGAIN
//! is a *normal* runtime condition: every idle keep-alive read timeout would
//! crash a debug daemon and rename the release error from `WouldBlock` to
//! `Unexpected`. Until std maps EAGAIN to `error.Timeout` for net I/O, POSIX
//! uses raw read/write syscalls: one OS branch here inside the os layer,
//! zero OS branches in `main.zig`.
//!
//! # Why Windows does NOT rely on AFD-sockopt RCVTIMEO
//!
//! SO_RCVTIMEO/SO_SNDTIMEO are winsock-level options implemented in user
//! mode by mswsock/ws2_32, not by the afd.sys transport driver. std 0.16
//! never routes them through `IOCTL.AFD.SOCKOPT` (its own
//! `socketOptionAfd`, Threaded.zig, is only used for address- and
//! protocol-level options), and no std code or bundled doc confirms that
//! afd.sys honors them. The Windows path therefore enforces the deadline
//! in software: every read/write is an overlapped AFD ioctl waited on with
//! `NtWaitForSingleObject(event, timeout)` and cancelled on expiry via
//! `NtCancelIoFileEx`. `setSocketTimeouts` on Windows sets only
//! TCP_NODELAY (a real transport-level option) and documents this.
//!
//! AFD socket handles are not file objects and reject `NtReadFile`, so the
//! equivalent overlapped primitive is `NtDeviceIoControlFile` with
//! `IOCTL.AFD.RECEIVE`/`IOCTL.AFD.SEND` — the same ioctls std's own
//! Threaded backend uses (with APC waits where we use event waits).

const std = @import("std");
const builtin = @import("builtin");

const posix_impl = @import("posix.zig");

/// Handle type of a connected stream socket: `c_int` fd on POSIX,
/// `HANDLE` on Windows. Same unification `std.Io.net.Socket` uses.
pub const Handle = std.Io.net.Socket.Handle;

pub const SetTimeoutError = error{SocketOptionFailed};

/// Arm per-operation timeouts and TCP_NODELAY on a freshly accepted socket.
///
/// Semantics per platform:
///   * linux   — raw `std.os.linux.setsockopt` (std.posix wraps
///               EBADF/ENOTSOCK in `unreachable`, which under accept churn
///               must never kill the daemon).
///   * darwin  — same setsockopt triple via libc (`std.c`); Darwin always
///               links libSystem so the externs resolve.
///   * windows — TCP_NODELAY via the AFD-sockopt ioctl only. RCVTIMEO and
///               SNDTIMEO are NOT sent: they are winsock user-mode options
///               with no confirmed afd.sys effect. Their defense is carried
///               by the software deadline in `socketReadSome`/
///               `socketWriteAll` (see the module doc).
pub fn setSocketTimeouts(handle: Handle, seconds: u16) SetTimeoutError!void {
    if (comptime builtin.os.tag == .linux) {
        const tv = std.posix.timeval{ .sec = @intCast(seconds), .usec = 0 };
        // Raw syscalls only: std.posix.setsockopt panics via `unreachable` on
        // EBADF/ENOTSOCK, and under accept churn that must never kill the daemon.
        const opt = std.mem.asBytes(&tv);
        const rcv = std.os.linux.setsockopt(handle, std.os.linux.SOL.SOCKET, std.os.linux.SO.RCVTIMEO, opt.ptr, @intCast(opt.len));
        if (std.os.linux.errno(rcv) != .SUCCESS) return error.SocketOptionFailed;
        const snd = std.os.linux.setsockopt(handle, std.os.linux.SOL.SOCKET, std.os.linux.SO.SNDTIMEO, opt.ptr, @intCast(opt.len));
        if (std.os.linux.errno(snd) != .SUCCESS) return error.SocketOptionFailed;
        // Disable Nagle: the 100-continue path writes two segments per request;
        // without TCP_NODELAY the second stalls until the first is ACKed (~1 RTT).
        const one = std.mem.asBytes(&@as(c_int, 1));
        const nodelay = std.os.linux.setsockopt(handle, std.os.linux.IPPROTO.TCP, std.os.linux.TCP.NODELAY, one.ptr, @intCast(one.len));
        if (std.os.linux.errno(nodelay) != .SUCCESS) return error.SocketOptionFailed;
    } else if (comptime builtin.os.tag == .windows) {
        const one: u32 = 1;
        socketOptionAfd(handle, std.os.windows.ws2_32.IPPROTO.TCP, std.os.windows.ws2_32.TCP.NODELAY, std.mem.asBytes(&one)) catch {
            return error.SocketOptionFailed;
        };
    } else {
        // libc POSIX path (macOS et al.): same triple through std.c.
        const tv = std.c.timeval{ .sec = @intCast(seconds), .usec = 0 };
        const opt = std.mem.asBytes(&tv);
        if (std.c.setsockopt(handle, std.c.SOL.SOCKET, std.c.SO.RCVTIMEO, opt.ptr, @intCast(opt.len)) != 0)
            return error.SocketOptionFailed;
        if (std.c.setsockopt(handle, std.c.SOL.SOCKET, std.c.SO.SNDTIMEO, opt.ptr, @intCast(opt.len)) != 0)
            return error.SocketOptionFailed;
        const one = std.mem.asBytes(&@as(c_int, 1));
        if (std.c.setsockopt(handle, std.c.IPPROTO.TCP, std.c.TCP.NODELAY, one.ptr, @intCast(one.len)) != 0)
            return error.SocketOptionFailed;
    }
}

/// Re-arm only the read-side deadline with millisecond precision.
///
/// The request pipeline enforces one absolute deadline per request and
/// re-arms the remaining budget before every read; whole-second
/// `setSocketTimeouts` would either round small remainders down to "no
/// timeout" (an unbounded read) or up past the deadline. Platform semantics:
///   * linux   — raw `std.os.linux.setsockopt` (same rationale as
///               `setSocketTimeouts`).
///   * darwin  — same setsockopt via libc (`std.c`).
///   * windows — no-op: the software deadline inside `socketReadSome` is
///               driven by its `timeout_ms` argument instead.
pub fn setSocketReadTimeoutMs(handle: Handle, milliseconds: u64) SetTimeoutError!void {
    const clamped: u64 = @min(milliseconds, @as(u64, std.math.maxInt(u32)));
    if (comptime builtin.os.tag == .linux) {
        const tv = std.posix.timeval{ .sec = @intCast(clamped / 1000), .usec = @intCast((clamped % 1000) * 1000) };
        const opt = std.mem.asBytes(&tv);
        const rcv = std.os.linux.setsockopt(handle, std.os.linux.SOL.SOCKET, std.os.linux.SO.RCVTIMEO, opt.ptr, @intCast(opt.len));
        if (std.os.linux.errno(rcv) != .SUCCESS) return error.SocketOptionFailed;
    } else if (comptime builtin.os.tag == .windows) {
        // No-op: the software deadline in socketReadSome carries the bound
        // (its timeout_ms argument). Nothing to arm at the socket level.
    } else {
        const tv = std.c.timeval{ .sec = @intCast(clamped / 1000), .usec = @intCast((clamped % 1000) * 1000) };
        const opt = std.mem.asBytes(&tv);

        if (std.c.setsockopt(handle, std.c.SOL.SOCKET, std.c.SO.RCVTIMEO, opt.ptr, @intCast(opt.len)) != 0)
            return error.SocketOptionFailed;
    }
}

/// SO_SNDTIMEO twin of `setSocketReadTimeoutMs`. POSIX `socketWriteAll`
/// carries the per-write bound as this socket option (its `timeout_ms`
/// parameter is only honored on Windows, where the software deadline in
/// the overlapped wait enforces it), so a caller that must cap one write
/// tighter than the accept-time bound tightens the option for that write.
/// Windows: no-op, same rationale as `setSocketReadTimeoutMs`.
pub fn setSocketSendTimeoutMs(handle: Handle, milliseconds: u64) SetTimeoutError!void {
    const clamped: u64 = @min(milliseconds, @as(u64, std.math.maxInt(u32)));
    if (comptime builtin.os.tag == .linux) {
        const tv = std.posix.timeval{ .sec = @intCast(clamped / 1000), .usec = @intCast((clamped % 1000) * 1000) };
        const opt = std.mem.asBytes(&tv);
        const snd = std.os.linux.setsockopt(handle, std.os.linux.SOL.SOCKET, std.os.linux.SO.SNDTIMEO, opt.ptr, @intCast(opt.len));
        if (std.os.linux.errno(snd) != .SUCCESS) return error.SocketOptionFailed;
    } else if (comptime builtin.os.tag == .windows) {
        // No-op: the software deadline in socketWriteAll carries the bound.
    } else {
        const tv = std.c.timeval{ .sec = @intCast(clamped / 1000), .usec = @intCast((clamped % 1000) * 1000) };
        const opt = std.mem.asBytes(&tv);
        if (std.c.setsockopt(handle, std.c.SOL.SOCKET, std.c.SO.SNDTIMEO, opt.ptr, @intCast(opt.len)) != 0)
            return error.SocketOptionFailed;
    }
}

/// Current SO_SNDTIMEO in milliseconds. Returns null where the option is
/// not how writes are bounded (Windows) or cannot be read back: callers
/// then keep the accept-time bound. A result of 0 means "no bound" (a
/// blocking send may wait forever) — treat it as larger than any budget.
pub fn getSocketSendTimeoutMs(handle: Handle) ?u64 {
    if (comptime builtin.os.tag == .linux) {
        var tv: std.posix.timeval = undefined;
        const opt = std.mem.asBytes(&tv);
        var len: std.os.linux.socklen_t = @intCast(opt.len);
        const rc = std.os.linux.getsockopt(handle, std.os.linux.SOL.SOCKET, std.os.linux.SO.SNDTIMEO, opt.ptr, &len);
        if (std.os.linux.errno(rc) != .SUCCESS) return null;
        return @as(u64, @intCast(tv.sec)) * 1000 + @as(u64, @intCast(tv.usec)) / 1000;
    } else if (comptime builtin.os.tag == .windows) {
        return null;
    } else {
        var tv: std.c.timeval = undefined;
        var len: std.c.socklen_t = @sizeOf(std.c.timeval);
        const opt = std.mem.asBytes(&tv);
        if (std.c.getsockopt(handle, std.c.SOL.SOCKET, std.c.SO.SNDTIMEO, opt.ptr, &len) != 0) return null;
        return @as(u64, @intCast(tv.sec)) * 1000 + @as(u64, @intCast(tv.usec)) / 1000;
    }
}

/// Read up to `buf.len` bytes from a connected socket. Returns 0 on clean
/// EOF (peer closed a keep-alive connection), exactly like read(2).
///
/// `timeout_ms` is the per-operation bound, mirroring SO_RCVTIMEO
/// semantics. On POSIX it is enforced by the socket option armed in
/// `setSocketTimeouts` (an expired read surfaces as `error.WouldBlock`
/// from `std.posix.read`), so the parameter is unused there. On Windows it
/// drives the overlapped wait; expiry yields `error.Timeout`.
pub fn socketReadSome(handle: Handle, buf: []u8, timeout_ms: u64) !usize {
    if (buf.len == 0) return 0;
    if (comptime builtin.os.tag == .windows) {
        var iov: [1]std.os.windows.AFD.WSABUF(.@"var") = .{.{
            .len = @intCast(@min(buf.len, max_ioctl_chunk)),
            .buf = buf.ptr,
        }};
        const info = std.os.windows.AFD.RECV_INFO{
            .BufferArray = &iov,
            .BufferCount = iov.len,
            .AfdFlags = .{ .NO_FAST_IO = true, .OVERLAPPED = true },
            .TdiFlags = .{ .NORMAL = true },
        };
        return afdSocketIo(handle, std.os.windows.IOCTL.AFD.RECEIVE, &info, timeout_ms);
    } else {
        // Per-operation bound is carried by SO_RCVTIMEO on the socket.
        return std.posix.read(handle, buf);
    }
}

/// True when a socketReadSome error is the read deadline expiring:
/// SO_RCVTIMEO expiry surfaces as WouldBlock on POSIX, the Windows
/// software deadline as Timeout. Compared by value on anyerror because each
/// name exists in only one target's concrete error set — typed switch
/// prongs cannot compile cross-target.
pub fn isReadTimeout(err: anyerror) bool {
    if (comptime builtin.os.tag == .windows) return err == error.Timeout;
    return err == error.WouldBlock;
}

/// Write the whole buffer to a connected socket, looping over short writes.
///
/// `timeout_ms` mirrors SO_SNDTIMEO: on POSIX the armed socket option
/// bounds each syscall; on Windows each overlapped send chunk is waited on
/// with that deadline. Error mapping:
/// any failure collapses to `error.WriteFailed`.
pub fn socketWriteAll(handle: Handle, bytes: []const u8, timeout_ms: u64) posix_impl.WriteAllError!void {
    if (comptime builtin.os.tag == .windows) {
        var off: usize = 0;
        while (off < bytes.len) {
            const chunk = bytes[off..@min(bytes.len, off + max_ioctl_chunk)];
            var iov: [1]std.os.windows.AFD.WSABUF(.@"const") = .{.{
                .len = @intCast(chunk.len),
                .buf = chunk.ptr,
            }};
            const info = std.os.windows.AFD.SEND_INFO{
                .BufferArray = &iov,
                .BufferCount = iov.len,
                .AfdFlags = .{ .NO_FAST_IO = true, .OVERLAPPED = true },
                .TdiFlags = .{},
            };
            const n = afdSocketIo(handle, std.os.windows.IOCTL.AFD.SEND, &info, timeout_ms) catch {
                return error.WriteFailed;
            };
            if (n == 0) return error.WriteFailed; // no forward progress
            off += n;
        }
    } else {
        // Per-operation bound is carried by SO_SNDTIMEO on the socket.
        return posix_impl.writeAllFd(handle, bytes);
    }
}

pub const ListenError = error{ AddressInUse, ListenFailed };

/// Listening TCP socket for a long-lived server port.
///
/// POSIX sets SO_REUSEADDR but never SO_REUSEPORT. std's `reuse_address`
/// sets both, and SO_REUSEPORT lets a second process co-bind the same port
/// and steal half of its connections. SO_REUSEADDR alone still lets a
/// restarted process bind over TIME_WAIT leftovers of its predecessor, while
/// a second live listener fails with `AddressInUse`. Windows uses std
/// without reuse: there SO_REUSEADDR would allow hijacking, and TIME_WAIT
/// does not block a fresh listener.
pub fn listenTcp(io: std.Io, addr: std.Io.net.IpAddress) ListenError!std.Io.net.Server {
    if (comptime builtin.os.tag == .windows) {
        return addr.listen(io, .{}) catch |err| switch (err) {
            error.AddressInUse => error.AddressInUse,
            else => error.ListenFailed,
        };
    }
    const posix = std.posix;
    const Threaded = std.Io.Threaded;
    const sys = posix.system;
    const family: u32 = switch (addr) {
        .ip4 => posix.AF.INET,
        .ip6 => posix.AF.INET6,
    };
    const cloexec: u32 = if (comptime builtin.os.tag.isDarwin()) 0 else posix.SOCK.CLOEXEC;
    const rc = sys.socket(family, posix.SOCK.STREAM | cloexec, posix.IPPROTO.TCP);
    if (posix.errno(rc) != .SUCCESS) return error.ListenFailed;
    const fd: posix.fd_t = @intCast(rc);
    errdefer posix_impl.closeFd(fd);
    if (comptime builtin.os.tag.isDarwin()) {
        if (posix.errno(sys.fcntl(fd, posix.F.SETFD, @as(c_int, posix.FD_CLOEXEC))) != .SUCCESS)
            return error.ListenFailed;
    }
    const one = std.mem.asBytes(&@as(c_int, 1));
    if (posix.errno(sys.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, one.ptr, @intCast(one.len))) != .SUCCESS)
        return error.ListenFailed;
    var storage: Threaded.PosixAddress = undefined;
    var len = Threaded.addressToPosix(&addr, &storage);
    switch (posix.errno(sys.bind(fd, &storage.any, len))) {
        .SUCCESS => {},
        .ADDRINUSE => return error.AddressInUse,
        else => return error.ListenFailed,
    }
    if (posix.errno(sys.listen(fd, std.Io.net.default_kernel_backlog)) != .SUCCESS) return error.ListenFailed;
    if (posix.errno(sys.getsockname(fd, &storage.any, &len)) != .SUCCESS) return error.ListenFailed;
    return .{
        .socket = .{ .handle = fd, .address = Threaded.addressFromPosix(&storage) },
        .options = {},
    };
}

/// Set a listen socket non-blocking (POSIX): the hub accept loop polls
/// before accepting, and a non-blocking listen fd turns the poll-to-accept
/// race (a reset drained the pending queue) into EAGAIN instead of a
/// parked thread. Linux accepted sockets do not inherit O_NONBLOCK; Darwin
/// clears the inherited flag in acceptNonBlocking before returning them.
/// POSIX-only: the Windows accept path keeps the blocking std call and the
/// self-connect wake.
pub fn setListenNonBlocking(handle: Handle) SetTimeoutError!void {
    if (comptime builtin.os.tag == .windows) {
        // std Windows sockets are AFD handles; FIONBIO accepts only SOCKET.
        // Hub.start uses std's blocking AFD accept on this target instead.
        return;
    }
    if (comptime builtin.os.tag == .linux) {
        const fl = std.os.linux.fcntl(handle, std.os.linux.F.GETFL, 0);
        if (std.os.linux.errno(fl) != .SUCCESS) return error.SocketOptionFailed;
        const nonblock: usize = 1 << @bitOffsetOf(std.os.linux.O, "NONBLOCK");
        const rc = std.os.linux.fcntl(handle, std.os.linux.F.SETFL, fl | nonblock);
        if (std.os.linux.errno(rc) != .SUCCESS) return error.SocketOptionFailed;
    } else {
        const fl = std.c.fcntl(handle, std.c.F.GETFL, @as(c_int, 0));
        if (fl == -1) return error.SocketOptionFailed;
        const nonblock: c_int = 1 << @bitOffsetOf(std.c.O, "NONBLOCK");
        if (std.c.fcntl(handle, std.c.F.SETFL, @as(c_int, fl | nonblock)) != 0) return error.SocketOptionFailed;
    }
}

// --- Windows socket polling (hub accept loop wake) --------------------------

/// Minimal WSAPoll binding (ws2_32 is always linked in networking builds).
/// The hub accept loop polls the listener together with a pre-created
/// loopback wake connection, so stop() retracts the thread without
/// allocating a socket at teardown time. POLLRDNORM on a listen
/// socket means a pending connection; on the wake receiver it means the
/// stop byte landed.
pub const WSAPOLLFD = extern struct {
    fd: Handle,
    events: c_short,
    revents: c_short,
};
pub const POLLRDNORM: c_short = 0x0100;
pub const POLLERR: c_short = 0x0001;
pub const POLLHUP: c_short = 0x0002;
pub const POLLNVAL: c_short = 0x0004;

extern "ws2_32" fn WSAPoll(fds: [*]WSAPOLLFD, nfds: c_ulong, timeout: c_int) c_int;

/// Raw winsock bindings for the hub accept loop on Windows: non-blocking
/// listen socket mode and raw accept, so the poll-to-accept race (queue
/// drained by a reset) returns "nothing pending" instead of parking the
/// accept thread beyond the reach of the shutdown wake.
const winsock = struct {
    const ws = std.os.windows.ws2_32;
    pub const invalid: std.os.windows.HANDLE = @ptrFromInt(~@as(usize, 0));
    pub const FIONBIO: c_long = -2147195266; // 0x8004667E as signed long
    pub extern "ws2_32" fn accept(s: std.os.windows.HANDLE, addr: ?*ws.sockaddr, addrlen: ?*c_int) std.os.windows.HANDLE;
    pub extern "ws2_32" fn ioctlsocket(s: std.os.windows.HANDLE, cmd: c_long, argp: *c_ulong) c_int;
    pub extern "ws2_32" fn WSAGetLastError() c_int;
    pub extern "ws2_32" fn WSAStartup(wVersionRequired: u16, lpWSAData: *anyopaque) c_int;
};

/// Peer address from a winsock sockaddr (accept-derived).
fn ipFromWsa(storage: *const std.os.windows.ws2_32.sockaddr.storage) std.Io.net.IpAddress {
    const ws = std.os.windows.ws2_32;
    if (storage.family == ws.AF.INET) {
        const in: *const ws.sockaddr.in = @ptrCast(@alignCast(storage));
        return .{ .ip4 = .{
            .bytes = @bitCast(in.addr),
            .port = std.mem.bigToNative(u16, in.port),
        } };
    }
    const in6: *const ws.sockaddr.in6 = @ptrCast(@alignCast(storage));
    return .{ .ip6 = .{
        .port = std.mem.bigToNative(u16, in6.port),
        .bytes = in6.addr,
        .flow = in6.flowinfo,
        .interface = .{ .index = in6.scope_id },
    } };
}

/// Poll sockets (Windows only). Returns the WSAPoll result: >0 ready
/// count, 0 tick, <0 failure (callers back off and re-check stopping).
pub fn wsaPoll(fds: []WSAPOLLFD, timeout_ms: c_int) c_int {
    if (comptime builtin.os.tag != .windows) @compileError("wsaPoll is Windows-only");
    return WSAPoll(fds.ptr, @intCast(fds.len), timeout_ms);
}

/// Raw non-blocking accept (POSIX) for the hub accept loop, called only
/// after poll reported the listener readable. null means the pending queue
/// drained first (a reset between poll and accept) — the caller loops back
/// to poll. NEVER routed through std's Io.net accept: its EAGAIN maps to a
/// debug panic (see the module doc). The accepted socket is blocking with
/// CLOEXEC, exactly like std's accept would produce.
pub fn acceptNonBlocking(listen_fd: Handle) ?std.Io.net.Stream {
    if (comptime builtin.os.tag == .windows) {
        return acceptWindowsAfd(listen_fd);
    }
    var storage: std.Io.Threaded.PosixAddress = undefined;
    var len: std.posix.socklen_t = @sizeOf(std.Io.Threaded.PosixAddress);
    if (comptime builtin.os.tag == .linux) {
        while (true) {
            const rc = std.os.linux.accept4(listen_fd, &storage.any, &len, std.os.linux.SOCK.CLOEXEC);
            switch (std.os.linux.errno(rc)) {
                .SUCCESS => return .{ .socket = .{
                    .handle = @intCast(rc),
                    .address = std.Io.Threaded.addressFromPosix(&storage),
                } },
                .INTR => continue,
                // AGAIN (queue drained) or any other failure: back to poll,
                // whose tick/backoff owns persistent-error behavior.
                else => return null,
            }
        }
    } else {
        while (true) {
            const fd = std.c.accept(listen_fd, &storage.any, &len);
            if (fd != -1) {
                // Darwin accept() inherits O_NONBLOCK from the listener, unlike
                // Linux. Blocking reads with per-operation deadlines are the
                // link/TLS contract; close an unfixable socket like any other
                // failed accept instead of exposing EAGAIN to those layers.
                const flags = std.c.fcntl(fd, std.c.F.GETFL, @as(c_int, 0));
                if (flags == -1) {
                    _ = std.c.close(fd);
                    return null;
                }
                const nonblock: c_int = 1 << @bitOffsetOf(std.c.O, "NONBLOCK");
                if (flags & nonblock != 0 and std.c.fcntl(fd, std.c.F.SETFL, @as(c_int, flags & ~nonblock)) != 0) {
                    _ = std.c.close(fd);
                    return null;
                }
                // Accepted sockets on Darwin do not inherit CLOEXEC.
                _ = std.c.fcntl(fd, std.c.F.SETFD, @as(c_int, std.c.FD_CLOEXEC));
                return .{ .socket = .{
                    .handle = fd,
                    .address = std.Io.Threaded.addressFromPosix(&storage),
                } };
            }
            if (comptime @hasDecl(std.c, "_errno")) {
                if (std.c._errno().* == @intFromEnum(std.c.E.INTR)) continue;
            }
            return null;
        }
    }
}

/// Half-close the send side (FIN after any queued response bytes) while the
/// receive side stays open. Best effort: a peer that already vanished makes
/// this fail, and the caller closes the socket either way.
///   * linux   — raw `std.os.linux.shutdown` (std.posix-free for the same
///               EBADF/ENOTSOCK rationale as `setSocketTimeouts`).
///   * darwin  — `shutdown(2)` via libc.
///   * windows — `IOCTL.AFD.PARTIAL_DISCONNECT` with SEND only, the same
///               ioctl std's Threaded backend issues for `Stream.shutdown`.
pub fn shutdownSend(handle: Handle) void {
    if (comptime builtin.os.tag == .linux) {
        _ = std.os.linux.shutdown(handle, std.os.linux.SHUT.WR);
    } else if (comptime builtin.os.tag == .windows) {
        const info = windows.AFD.PARTIAL_DISCONNECT_INFO{
            .DisconnectMode = .{ .SEND = true },
            .Timeout = -1,
        };
        _ = afdSocketIo(handle, windows.IOCTL.AFD.PARTIAL_DISCONNECT, &info, null) catch {};
    } else {
        _ = std.c.shutdown(handle, std.c.SHUT.WR);
    }
}

/// Upper bound for one AFD ioctl payload. Responses are bounded by
/// MCP_NODE_MAX_OUT, so a single chunk almost always suffices; the cap only
/// keeps the u32 length cast safe for pathological configs.
const max_ioctl_chunk: usize = 1 << 30;

const windows = std.os.windows;

fn openSocketAfd(family: windows.ws2_32.ADDRESS_FAMILY) !windows.HANDLE {
    var handle: windows.HANDLE = undefined;
    var iosb: windows.IO_STATUS_BLOCK = undefined;
    const status = windows.ntdll.NtCreateFile(
        &handle,
        .{ .STANDARD = .{ .RIGHTS = .{ .WRITE_DAC = true }, .SYNCHRONIZE = true }, .GENERIC = .{ .WRITE = true, .READ = true } },
        &.{ .ObjectName = @constCast(&windows.UNICODE_STRING.init(windows.AFD.DEVICE_NAME ++ .{ '\\', 'E', 'n', 'd', 'p', 'o', 'i', 'n', 't' })) },
        &iosb,
        null,
        .{},
        .{ .READ = true, .WRITE = true },
        .OPEN_IF,
        .{ .IO = .ASYNCHRONOUS },
        &windows.AFD.OPEN_PACKET.FULL_EA_INFORMATION{ .Value = .{
            .EndpointType = .{ .CONNECTIONLESS = false, .MESSAGEMODE = false, .RAW = false },
            .GroupID = 0,
            .AddressFamily = family,
            .SocketType = windows.ws2_32.SOCK.STREAM,
            .Protocol = windows.ws2_32.IPPROTO.TCP,
            .TransportDeviceNameLength = 0,
            .TransportDeviceName = undefined,
        } },
        @sizeOf(windows.AFD.OPEN_PACKET.FULL_EA_INFORMATION),
    );
    if (status != .SUCCESS) {
        return error.SocketOptionFailed;
    }
    return handle;
}

/// AFD's three-step accept, matching Zig 0.16's Threaded backend. This keeps
/// accepted handles compatible with the AFD read/write/shutdown helpers.
fn acceptWindowsAfd(listen_fd: Handle) ?std.Io.net.Stream {
    const Storage = extern struct {
        info: windows.AFD.LISTEN_RESPONSE_INFO,
        remote: std.Io.Threaded.PosixAddress,
    };
    var storage: Storage = undefined;
    _ = afdSocketIoOut(listen_fd, windows.IOCTL.AFD.WAIT_FOR_LISTEN, null, std.mem.asBytes(&storage), null) catch return null;
    const accepted = openSocketAfd(storage.remote.any.family) catch return null;
    var info = windows.AFD.ACCEPT_INFO{
        .UseSAN = .FALSE,
        .Sequence = storage.info.Sequence,
        .AcceptHandle = accepted,
    };
    _ = afdSocketIoOut(listen_fd, windows.IOCTL.AFD.ACCEPT, std.mem.asBytes(&info), null, null) catch {
        windows.CloseHandle(accepted);
        return null;
    };
    return .{ .socket = .{ .handle = accepted, .address = std.Io.Threaded.addressFromPosix(&storage.remote) } };
}

fn afdSocketIoOut(handle: windows.HANDLE, code: windows.CTL_CODE, in: ?[]const u8, out: ?[]u8, timeout_ms: ?u64) !usize {
    var event: windows.HANDLE = undefined;
    switch (windows.ntdll.NtCreateEvent(&event, windows.ACCESS_MASK.Specific.Event.ALL_ACCESS, null, .Notification, .FALSE)) {
        .SUCCESS => {},
        else => |status| return windows.unexpectedStatus(status),
    }
    defer windows.CloseHandle(event);
    var iosb: windows.IO_STATUS_BLOCK = undefined;
    const status = windows.ntdll.NtDeviceIoControlFile(handle, event, null, null, &iosb, code, if (in) |b| b.ptr else null, if (in) |b| @intCast(b.len) else 0, if (out) |b| b.ptr else null, if (out) |b| @intCast(b.len) else 0);
    switch (status) {
        .SUCCESS => return iosb.Information,
        .PENDING => {},
        else => |s| return windows.unexpectedStatus(s),
    }
    const timeout: ?windows.LARGE_INTEGER = if (timeout_ms) |ms| -@as(windows.LARGE_INTEGER, @intCast(ms * 10_000)) else null;
    switch (windows.ntdll.NtWaitForSingleObject(event, .FALSE, if (timeout) |*t| t else null)) {
        .SUCCESS => {},
        .TIMEOUT => {
            var cancel_iosb: windows.IO_STATUS_BLOCK = undefined;
            _ = windows.ntdll.NtCancelIoFileEx(handle, &iosb, &cancel_iosb);
            _ = windows.ntdll.NtWaitForSingleObject(event, .FALSE, null);
            return error.Timeout;
        },
        else => |s| return windows.unexpectedStatus(s),
    }
    if (iosb.u.Status != .SUCCESS) return windows.unexpectedStatus(iosb.u.Status);
    return iosb.Information;
}

/// Issue one overlapped AFD ioctl against a socket handle and wait for it
/// with an optional deadline. Returns the number of transferred bytes
/// (`IO_STATUS_BLOCK.Information`).
///
/// All buffers (`info`, its WSABUF array, the payload) are caller-stack
/// owned; this function never returns while the kernel may still touch
/// them: on timeout it cancels the request and drains the completion
/// before propagating `error.Timeout`.
///
/// Used for RECEIVE (read), SEND (write) and SOCKOPT (TCP_NODELAY). AFD
/// socket handles are opened asynchronous by std's Threaded backend, so
/// PENDING is the common case; a synchronously-completing ioctl takes the
/// fast path with no wait at all.
fn afdSocketIo(handle: windows.HANDLE, code: windows.CTL_CODE, info: anytype, timeout_ms: ?u64) !usize {
    var event: windows.HANDLE = undefined;
    switch (windows.ntdll.NtCreateEvent(
        &event,
        windows.ACCESS_MASK.Specific.Event.ALL_ACCESS,
        null,
        .Notification,
        .FALSE,
    )) {
        .SUCCESS => {},
        else => |status| return windows.unexpectedStatus(status),
    }
    defer windows.CloseHandle(event);

    var iosb: windows.IO_STATUS_BLOCK = undefined;
    switch (windows.ntdll.NtDeviceIoControlFile(
        handle,
        event,
        null, // no APC — event signaling is enough
        null,
        &iosb,
        code,
        @ptrCast(info),
        @sizeOf(@TypeOf(info.*)),
        null, // RECEIVE/SEND/SOCKOPT deliver data through the WSABUF/optval pointers
        0,
    )) {
        .SUCCESS => return iosb.Information,
        .PENDING => {},
        .INSUFFICIENT_RESOURCES => return error.SystemResources,
        .CONNECTION_RESET, .REMOTE_DISCONNECT => return error.ConnectionResetByPeer,
        .LOCAL_DISCONNECT, .GRACEFUL_DISCONNECT => return 0,
        else => |status| return windows.unexpectedStatus(status),
    }

    const timeout: ?windows.LARGE_INTEGER = if (timeout_ms) |ms|
        // Relative deadline in 100 ns units; negative = relative.
        -@as(windows.LARGE_INTEGER, @intCast(ms * 10_000))
    else
        null;
    switch (windows.ntdll.NtWaitForSingleObject(
        event,
        .FALSE,
        if (timeout) |*t| t else null,
    )) {
        .SUCCESS => {}, // completed; completion status is in iosb
        .TIMEOUT => {
            var cancel_iosb: windows.IO_STATUS_BLOCK = undefined;
            _ = windows.ntdll.NtCancelIoFileEx(handle, &iosb, &cancel_iosb);
            // The cancel may race a completed request; either way the event
            // is signaled once the kernel is done with our stack buffers.
            _ = windows.ntdll.NtWaitForSingleObject(event, .FALSE, null);
            return error.Timeout;
        },
        else => |status| return windows.unexpectedStatus(status),
    }
    return switch (iosb.u.Status) {
        .SUCCESS => iosb.Information,
        .INSUFFICIENT_RESOURCES => error.SystemResources,
        .CONNECTION_RESET, .REMOTE_DISCONNECT => error.ConnectionResetByPeer,
        .LOCAL_DISCONNECT, .GRACEFUL_DISCONNECT => 0,
        else => |status| windows.unexpectedStatus(status),
    };
}

/// Set one socket option through `IOCTL.AFD.SOCKOPT`, modeled on std's
/// private `socketOptionAfd` (Io/Threaded.zig). Used only for options with
/// real transport-level meaning (TCP_NODELAY); see the module doc for why
/// RCVTIMEO/SNDTIMEO deliberately do not go through here.
fn socketOptionAfd(handle: windows.HANDLE, level: i32, opt_name: u32, opt_val: []const u8) !void {
    var info = windows.AFD.SOCKOPT_INFO{
        .mode = .set,
        .level = level,
        .optname = opt_name,
        .optval = opt_val.ptr,
        .optlen = opt_val.len,
    };
    _ = try afdSocketIo(handle, windows.IOCTL.AFD.SOCKOPT, &info, null);
}

fn testNonblock(handle: Handle) !bool {
    if (comptime builtin.os.tag == .linux) {
        const flags = std.os.linux.fcntl(handle, std.os.linux.F.GETFL, 0);
        if (std.os.linux.errno(flags) != .SUCCESS) return error.SocketOptionFailed;
        return flags & (1 << @bitOffsetOf(std.os.linux.O, "NONBLOCK")) != 0;
    }
    const flags = std.c.fcntl(handle, std.c.F.GETFL, @as(c_int, 0));
    if (flags == -1) return error.SocketOptionFailed;
    return flags & (1 << @bitOffsetOf(std.c.O, "NONBLOCK")) != 0;
}

test "accepted POSIX sockets stay blocking on a nonblocking listener" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    const io = std.Io.Threaded.global_single_threaded.io();
    const loopback = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var listener = try listenTcp(io, loopback);
    defer listener.deinit(io);
    try setListenNonBlocking(listener.socket.handle);

    const client = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer client.close(io);
    const accepted = acceptNonBlocking(listener.socket.handle) orelse return error.AcceptFailed;
    defer accepted.close(io);
    try std.testing.expect(!(try testNonblock(accepted.socket.handle)));
}
