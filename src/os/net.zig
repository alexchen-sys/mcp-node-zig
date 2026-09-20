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
//! keeps the exact raw syscalls the daemon always used — one OS branch here
//! inside the os layer, zero OS branches in `main.zig`.
//!
//! # Why Windows does NOT rely on AFD-sockopt RCVTIMEO (task risk #3)
//!
//! SO_RCVTIMEO/SO_SNDTIMEO are winsock-level options implemented in user
//! mode by mswsock/ws2_32, not by the afd.sys transport driver. std 0.16
//! never routes them through `IOCTL.AFD.SOCKOPT` (its own
//! `socketOptionAfd`, Threaded.zig, is only used for address- and
//! protocol-level options), and no std code or bundled doc confirms that
//! afd.sys honors them, so deadlines are enforced in software below.
//! The Windows path therefore enforces the deadline in software: every
//! read/write is an overlapped AFD ioctl waited on with
//! `NtWaitForSingleObject(event, timeout)` and cancelled on expiry via
//! `NtCancelIoFileEx`. `setSocketTimeouts` on Windows sets only
//! TCP_NODELAY (a real transport-level option) and documents this.
//!
//! Note: AFD handles are not file objects, so `NtReadFile` does not apply; AFD
//! socket handles are not file objects and reject NtReadFile, so the
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
///               `socketWriteAll` (see module doc, task risk #3).
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

/// Upper bound for one AFD ioctl payload. Responses are bounded by
/// MCP_NODE_MAX_OUT, so a single chunk almost always suffices; the cap only
/// keeps the u32 length cast safe for pathological configs.
const max_ioctl_chunk: usize = 1 << 30;

const windows = std.os.windows;

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
