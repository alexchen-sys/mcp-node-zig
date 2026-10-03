const std = @import("std");
const builtin = @import("builtin");

const Allocator = std.mem.Allocator;
const Io = std.Io;
const Value = std.json.Value;
const os = @import("os.zig");
const proc = @import("os/proc.zig");
const util = @import("util.zig");
const http = @import("http.zig");
const session_mod = @import("session.zig");
const config = @import("config.zig");
const env_state = @import("env_state.zig");
const tools = @import("tools.zig");
const rpc_mod = @import("rpc.zig");

/// A peer disconnect must never kill the daemon via SIGPIPE. Protection is
/// real on two layers: Io.Threaded installs an ignore handler for
/// SIGPIPE, and on std versions honoring root's keep_sigpipe this opts out
/// explicitly. Writes to closed pipes surface as EPIPE errors instead.
pub const keep_sigpipe = false;

const ACCEPT_BACKOFF_MS: u64 = 50; // pause after accept failure

const ConnGate = struct {
    mutex: std.Io.Mutex = .init,
    io: Io,
    active: u32 = 0,
    max: u32,

    fn tryAcquire(self: *ConnGate) bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.active >= self.max) return false;
        self.active += 1;
        return true;
    }

    fn release(self: *ConnGate) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.active -= 1;
    }
};

const Connection = struct {
    io: Io,
    cfg: *const config.Config,
    gate: *ConnGate,
    stream: Io.net.Stream,
};

pub fn main() !void {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Cross-platform environment snapshot (linux: /proc/self/environ).
    env_state.process_environ = try os.loadEnviron(std.heap.page_allocator);
    var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{ .environ = env_state.process_environ });
    defer threaded.deinit();
    const io = threaded.io();

    var cfg = try config.loadConfig(arena, io);
    var sessions = session_mod.SessionStore.init(io, cfg.max_sessions);
    sessions.ttl_ms = @as(i64, cfg.session_ttl_s) * 1000;
    cfg.sessions = &sessions;
    var gate = ConnGate{ .io = io, .max = cfg.max_conn };
    var inflight = config.InflightGate{ .io = io, .max = cfg.max_inflight_bytes };
    cfg.inflight = &inflight;

    const addr = try Io.net.IpAddress.parse(cfg.host, cfg.port);
    var server = try addr.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);

    logLine("mcp-node listening", cfg.host, cfg.port);
    while (true) {
        var stream = server.accept(io) catch |err| {
            std.debug.print("accept failed: {s}\n", .{@errorName(err)});
            os.sleepMs(ACCEPT_BACKOFF_MS);
            continue;
        };
        if (!gate.tryAcquire()) {
            rejectBusy(&cfg, io, &stream);
            continue;
        }
        const conn = std.heap.page_allocator.create(Connection) catch {
            gate.release();
            stream.close(io);
            continue;
        };
        conn.* = .{ .io = io, .cfg = &cfg, .gate = &gate, .stream = stream };
        const thread = std.Thread.spawn(.{}, connectionThread, .{conn}) catch {
            gate.release();
            stream.close(io);
            std.heap.page_allocator.destroy(conn);
            continue;
        };
        thread.detach();
    }
}

fn connectionThread(conn: *Connection) void {
    defer std.heap.page_allocator.destroy(conn);
    defer conn.gate.release();
    defer conn.stream.close(conn.io);

    // Bytes a header-phase read over-fetched past the current request (the
    // coalesced head of a pipelined next request) seed the next iteration.
    var carry: std.ArrayList(u8) = .empty;
    defer carry.deinit(std.heap.page_allocator);

    while (true) {
        const keep = serveOneRequest(conn.io, conn.cfg, &conn.stream, &carry) catch |err| {
            std.debug.print("connection failed: {s}\n", .{@errorName(err)});
            break;
        };
        if (!keep) break;
    }
    lingerBeforeClose(conn.io, conn.stream.socket.handle);
}

/// Upper bounds for the post-response drain in `lingerBeforeClose`.
const LINGER_DRAIN_MS: u64 = 250;
const LINGER_DRAIN_BYTES: usize = 256 * 1024;

/// Closing a TCP socket that still has unread input makes the kernel answer
/// with RST instead of FIN, and an RST can destroy a response the peer has
/// not read yet. That is exactly the shape of every early rejection (401,
/// 404, 413, ...): it is answered from the head alone while the client may
/// still be streaming the body. Send FIN first, then discard whatever the
/// peer still sends until it closes, within a small byte and time budget,
/// so the response survives without ever buffering the rejected body.
fn lingerBeforeClose(io: Io, fd: std.posix.fd_t) void {
    os.net.shutdownSend(fd);
    const started = std.Io.Clock.awake.now(io);
    var sink: [util.IO_BUF_SIZE]u8 = undefined;
    var drained: usize = 0;
    while (drained < LINGER_DRAIN_BYTES) {
        const remaining = http.remainingMs(started, io, LINGER_DRAIN_MS) orelse return;
        const want = @min(sink.len, LINGER_DRAIN_BYTES - drained);
        const n = http.readWithDeadline(fd, sink[0..want], remaining) catch return;
        if (n == 0) return; // peer closed its side: a clean FIN exchange
        drained += n;
    }
}

fn rejectBusy(cfg: *const config.Config, io: Io, stream: *Io.net.Stream) void {
    var buf: [1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    const timeout_ms = @as(u64, cfg.socket_timeout_s) * 1000;
    http.sendHttpError(fba.allocator(), stream.socket.handle, 503, "busy", "too many connections", timeout_ms) catch {};
    stream.close(io);
}

fn logLine(msg: []const u8, host: []const u8, port: u16) void {
    var buf: [256]u8 = undefined;
    const line = std.fmt.bufPrint(&buf, "{s} on {s}:{d} path=/mcp\n", .{ msg, host, port }) catch return;
    os.writeAllFd(os.stderrFd(), line) catch {};
}

/// Serve one HTTP request on an accepted stream. Returns true while the
/// connection stays usable (keep-alive), false when the caller must close.
///
/// Pipeline: parse the head with strict HTTP/1.1 grammar -> answer every
/// security gate (host/origin/token/method/path/content-type) from the head
/// alone, before a single body byte is read or 100 Continue is sent -> check
/// the Content-Length cap and the global in-flight body budget -> read
/// exactly content_length body bytes -> dispatch. A rejected or
/// unauthenticated client can therefore never force a 32 MiB body read.
/// `carry` holds bytes that a header-phase read over-fetched past the
/// current request (the coalesced head of a pipelined next request); they
/// seed the next request on this connection instead of being dropped, which
/// is what keeps pipelined peers from desyncing.
fn serveOneRequest(io: Io, cfg: *const config.Config, stream: *Io.net.Stream, carry: *std.ArrayList(u8)) !bool {
    var req_arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer req_arena_state.deinit();
    const ra = req_arena_state.allocator();

    const fd = stream.socket.handle;
    const timeout_ms = @as(u64, cfg.socket_timeout_s) * 1000;
    os.net.setSocketTimeouts(fd, cfg.socket_timeout_s) catch {
        // No read timeout -> a silent client could pin a connection slot
        // forever; refuse the connection instead of serving unprotected.
        return error.SocketOptionFailed;
    };
    // One absolute deadline covers the whole request (head + body); every
    // read below is armed with the remaining budget, never a fresh timeout.
    const started = std.Io.Clock.awake.now(io);

    // ---- phase 1: request head (request line + headers), 64 KiB cap ----
    var data: std.ArrayList(u8) = .empty;
    if (carry.items.len > 0) {
        try data.appendSlice(ra, carry.items);
        carry.clearRetainingCapacity();
    }
    var buf: [util.IO_BUF_SIZE]u8 = undefined;
    var header_end: ?usize = null;
    while (header_end == null) {
        if (std.mem.indexOf(u8, data.items, "\r\n\r\n")) |idx| {
            header_end = idx + 4;
            break;
        }
        if (data.items.len >= http.MAX_HEADER_BYTES) {
            try http.sendHttpError(ra, fd, 431, "headers_too_large", "request headers too large", timeout_ms);
            return false;
        }
        const remaining = http.remainingMs(started, io, timeout_ms) orelse {
            try http.sendHttpError(ra, fd, 408, "request_timeout", "request timed out", timeout_ms);
            return false;
        };
        const n = http.readWithDeadline(fd, &buf, remaining) catch |err| switch (err) {
            error.RequestTimeout => {
                try http.sendHttpError(ra, fd, 408, "request_timeout", "request timed out", timeout_ms);
                return false;
            },
            else => return err,
        };
        if (n == 0) {
            // Clean EOF before any bytes: the peer just closed a keep-alive
            // connection. Not an error — answering here would write a zombie
            // 400 into a dying socket. A partial head followed by EOF falls
            // through to the BadHeaders answer below.
            if (data.items.len == 0) return false;
            break;
        }
        try data.appendSlice(ra, buf[0..n]);
    }
    const he = header_end orelse {
        try http.sendHttpError(ra, fd, 400, "bad_request", "BadHeaders", timeout_ms);
        return false;
    };
    // The in-loop checkpoint only fires when the accumulator is over the cap
    // WITHOUT the terminator: a single read that both crosses the cap and
    // delivers CRLFCRLF takes the `break` above and skips it (possible with
    // short reads, e.g. on Windows). Re-check the completed head length so
    // the 431 contract is independent of TCP chunking.
    if (he > http.MAX_HEADER_BYTES) {
        try http.sendHttpError(ra, fd, 431, "headers_too_large", "request headers too large", timeout_ms);
        return false;
    }
    const info = http.parseHead(data.items[0 .. he - 4]) catch |err| {
        const status: u16 = switch (err) {
            error.RequestTooLarge => 413,
            error.BadExpectation => 417,
            else => 400,
        };
        try http.sendHttpError(ra, fd, status, "bad_request", @errorName(err), timeout_ms);
        return false;
    };

    // ---- phase 2: gates, all answered from the head alone (before any body
    // byte is read, before 100 Continue) ----
    if (!http.hostAllowed(info.host, cfg.allowed_hosts)) {
        try http.sendHttpError(ra, fd, 421, "invalid_host", "Invalid Host header", timeout_ms);
        return false;
    }
    if (info.origin) |origin| {
        if (!http.originAllowed(origin, cfg.allowed_origins)) {
            try http.sendHttpError(ra, fd, 403, "forbidden_origin", "Forbidden Origin header", timeout_ms);
            return false;
        }
    }
    if (cfg.token.len != 0) {
        // Conflicting credentials count as a failed login, not as a choice.
        const presented = http.presentedToken(info) catch null;
        const got = presented orelse "";
        var got_hash: [32]u8 = undefined;
        var cfg_hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(got, &got_hash, .{});
        std.crypto.hash.sha2.Sha256.hash(cfg.token, &cfg_hash, .{});
        if (!std.crypto.timing_safe.eql([32]u8, got_hash, cfg_hash)) {
            try http.sendHttpError(ra, fd, 401, "unauthorized", "unauthorized", timeout_ms);
            return false;
        }
    }
    if (!std.mem.eql(u8, info.path, "/mcp")) {
        try http.sendHttpError(ra, fd, 404, "not_found", "not found", timeout_ms);
        return false;
    }
    if (!std.mem.eql(u8, info.method, "POST")) {
        try http.sendHttpError(ra, fd, 405, "method_not_allowed", "method not allowed", timeout_ms);
        return false;
    }
    const ct = info.content_type orelse {
        try http.sendHttpError(ra, fd, 415, "unsupported_media_type", "Invalid Content-Type header", timeout_ms);
        return false;
    };
    if (!http.contentTypeJson(ct)) {
        try http.sendHttpError(ra, fd, 415, "unsupported_media_type", "Invalid Content-Type header", timeout_ms);
        return false;
    }

    // ---- phase 3: global in-flight body budget. The per-request 32 MiB
    // Content-Length cap was already enforced in http.parseHead (-> 413). ----
    var reserved: usize = 0;
    if (cfg.inflight) |gate| {
        if (!gate.tryReserve(info.content_length)) {
            // Answered without reading the body: the budget counts in-flight
            // body bytes, and this request never becomes one.
            try http.sendHttpError(ra, fd, 503, "busy", "in-flight body budget exhausted", timeout_ms);
            return false;
        }
        reserved = info.content_length;
    }
    defer if (cfg.inflight) |gate| gate.release(reserved);

    // ---- phase 4: 100 Continue, only after every gate passed ----
    if (info.expect_continue and info.content_length > 0) {
        try os.net.socketWriteAll(fd, "HTTP/1.1 100 Continue\r\n\r\n", timeout_ms);
    }

    // ---- phase 5: body, exactly content_length bytes. Reads are capped at
    // the remaining body length, so pipelined bytes are never over-fetched
    // here; only the header-phase read can over-fetch. ----
    const body = try ra.alloc(u8, info.content_length);
    const after_head = data.items[he..];
    const prefix_len = @min(after_head.len, info.content_length);
    @memcpy(body[0..prefix_len], after_head[0..prefix_len]);
    var filled = prefix_len;
    while (filled < body.len) {
        const remaining = http.remainingMs(started, io, timeout_ms) orelse {
            try http.sendHttpError(ra, fd, 408, "request_timeout", "request timed out", timeout_ms);
            return false;
        };
        const want = @min(buf.len, body.len - filled);
        const n = http.readWithDeadline(fd, buf[0..want], remaining) catch |err| switch (err) {
            error.RequestTimeout => {
                try http.sendHttpError(ra, fd, 408, "request_timeout", "request timed out", timeout_ms);
                return false;
            },
            else => return err,
        };
        if (n == 0) {
            // Clean EOF mid-body: the declared body never fully arrived.
            try http.sendHttpError(ra, fd, 400, "bad_request", "ShortBody", timeout_ms);
            return false;
        }
        @memcpy(body[filled .. filled + n], buf[0..n]);
        filled += n;
    }

    // ---- phase 6: keep-alive bookkeeping. Bytes past the body are the
    // coalesced head of the next pipelined request: carry them over. When
    // they cannot be carried safely (peer asked for close, or the carry
    // budget would blow up), answer and close — never desync. ----
    const leftover = after_head[prefix_len..];
    var keep_alive = !http.connectionCloseRequested(info.connection);
    if (leftover.len > 0) {
        if (keep_alive and leftover.len <= http.MAX_HEADER_BYTES) {
            try carry.appendSlice(std.heap.page_allocator, leftover);
        } else {
            keep_alive = false;
        }
    }

    const rpc = try rpc_mod.handleRpc(ra, io, cfg, body);
    try http.sendHttpRawMode(ra, fd, rpc.status, "application/json", rpc.body, keep_alive, timeout_ms);
    return keep_alive;
}

test "discover module tests" {
    // Test builds analyze decls lazily per decl: a module not referenced by
    // any root test would have its test blocks silently skipped. Pull them in.
    std.testing.refAllDecls(@import("http.zig"));
    std.testing.refAllDecls(@import("rpc.zig"));
}
