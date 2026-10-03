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

/// A peer disconnect must never kill the daemon via SIGPIPE. Protection is
/// real on two layers: Io.Threaded installs an ignore handler for
/// SIGPIPE, and on std versions honoring root's keep_sigpipe this opts out
/// explicitly. Writes to closed pipes surface as EPIPE errors instead.
pub const keep_sigpipe = false;

const VERSION: []const u8 = @import("build_options").version;

const LIST_DIR_MAX_ENTRIES: usize = 2000;
const ACCEPT_BACKOFF_MS: u64 = 50; // pause after accept failure
const WAIT_POLL_MS: u64 = 50; // exec_wait sleep tick
const EXEC_DEFAULT_TIMEOUT_S: i64 = 120; // mirrored in TOOLS_JSON prose
const EXEC_MAX_TIMEOUT_S: i64 = 1800;
const WAIT_DEFAULT_TIMEOUT_S: i64 = 30; // mirrored in TOOLS_JSON prose
const WAIT_MAX_TIMEOUT_S: i64 = 300;
const TOKEN_FILE_MAX_BYTES: usize = 4096;
const READ_FILE_MAX_BYTES: usize = 64 * 1024 * 1024;
const READ_FILE_DEFAULT_LIMIT_CHARS: i64 = 200_000; // chars, not bytes
const MIN_INFLIGHT_BYTES: u64 = 1024 * 1024; // config floor: below this the in-flight budget is unusable

const Config = struct {
    name: []const u8,
    host: []const u8,
    port: u16,
    token: []const u8,
    allowed_hosts: [][]const u8,
    allowed_origins: [][]const u8,
    max_out: usize,
    socket_timeout_s: u16,
    max_conn: u16,
    max_sessions: u16,
    session_ttl_s: u32,
    max_inflight_bytes: u64,
    sessions: ?*session_mod.SessionStore = null,
    inflight: ?*InflightGate = null,
};

const RpcResponse = struct {
    status: u16,
    body: []const u8,
};

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

/// Global budget of in-flight request-body bytes (default 64 MiB via
/// MCP_NODE_MAX_INFLIGHT_BYTES). Bytes are reserved after the gates pass but
/// BEFORE the body allocation/read, and released on every exit path —
/// success, error, or disconnect. Only declared body bytes count (arena
/// growth and response buffers are not budgeted; the contract is in-flight
/// request bodies).
const InflightGate = struct {
    mutex: std.Io.Mutex = .init,
    io: Io,
    in_use: u64 = 0,
    max: u64,

    fn tryReserve(self: *InflightGate, bytes: usize) bool {
        if (bytes == 0) return true;
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (bytes > self.max - self.in_use) return false;
        self.in_use += bytes;
        return true;
    }

    fn release(self: *InflightGate, bytes: usize) void {
        if (bytes == 0) return;
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.in_use -= bytes;
    }
};

const Connection = struct {
    io: Io,
    cfg: *const Config,
    gate: *ConnGate,
    stream: Io.net.Stream,
};

pub fn main() !void {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Cross-platform environment snapshot (linux: /proc/self/environ).
    process_environ = try os.loadEnviron(std.heap.page_allocator);
    var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{ .environ = process_environ });
    defer threaded.deinit();
    const io = threaded.io();

    var cfg = try loadConfig(arena, io);
    var sessions = session_mod.SessionStore.init(io, cfg.max_sessions);
    sessions.ttl_ms = @as(i64, cfg.session_ttl_s) * 1000;
    cfg.sessions = &sessions;
    var gate = ConnGate{ .io = io, .max = cfg.max_conn };
    var inflight = InflightGate{ .io = io, .max = cfg.max_inflight_bytes };
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

fn rejectBusy(cfg: *const Config, io: Io, stream: *Io.net.Stream) void {
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

fn loadConfig(arena: Allocator, io: Io) !Config {
    const name = getEnv(arena, "MCP_NODE_NAME") orelse "mcp-node";
    const host = getEnv(arena, "MCP_NODE_HOST") orelse "127.0.0.1";
    const port_s = getEnv(arena, "MCP_NODE_PORT") orelse "8341";
    const port = try std.fmt.parseInt(u16, port_s, 10);
    const max_out_s = getEnv(arena, "MCP_NODE_MAX_OUT") orelse "400000";
    const max_out = try std.fmt.parseInt(usize, max_out_s, 10);
    const socket_timeout_s = getEnv(arena, "MCP_NODE_SOCKET_TIMEOUT_S") orelse "60";
    var socket_timeout = try std.fmt.parseInt(u16, socket_timeout_s, 10);
    if (socket_timeout == 0) socket_timeout = 60;
    const max_conn_s = getEnv(arena, "MCP_NODE_MAX_CONN") orelse "128";
    var max_conn = try std.fmt.parseInt(u16, max_conn_s, 10);
    if (max_conn == 0) max_conn = 128;
    const max_sessions_s = getEnv(arena, "MCP_NODE_MAX_SESSIONS") orelse "64";
    var max_sessions = try std.fmt.parseInt(u16, max_sessions_s, 10);
    if (max_sessions == 0) max_sessions = 64;
    const session_ttl_s = getEnv(arena, "MCP_NODE_SESSION_TTL_S") orelse "600";
    var session_ttl = try std.fmt.parseInt(u32, session_ttl_s, 10);
    if (session_ttl == 0) session_ttl = 600;
    // Global in-flight request-body budget. An invalid or unusably small
    // value is a config error (fail fast at startup), not a silent fallback.
    const inflight_s = getEnv(arena, "MCP_NODE_MAX_INFLIGHT_BYTES") orelse "67108864";
    const max_inflight_bytes = std.fmt.parseInt(u64, inflight_s, 10) catch {
        std.debug.print("MCP_NODE_MAX_INFLIGHT_BYTES must be an unsigned integer, got '{s}'\n", .{inflight_s});
        return error.InvalidConfig;
    };
    if (max_inflight_bytes < MIN_INFLIGHT_BYTES) {
        std.debug.print("MCP_NODE_MAX_INFLIGHT_BYTES must be at least {d}\n", .{MIN_INFLIGHT_BYTES});
        return error.InvalidConfig;
    }

    const token_path = getEnv(arena, "MCP_NODE_TOKEN_FILE") orelse "./token";
    const token_raw = os.fd.readFileAlloc(arena, io, token_path, TOKEN_FILE_MAX_BYTES) catch |err| token_blk: {
        // Fail-closed on Windows by design: a missing token
        // file fails startup there instead of degrading to insecure mode;
        // the FileNotFound recovery branch is compiled out with the read.
        if (comptime os.gate_posix_file_io) {
            return err;
        } else {
            break :token_blk switch (err) {
                error.FileNotFound => insecure_blk: {
                    const insecure = getEnv(arena, "MCP_NODE_INSECURE") orelse "0";
                    if (!std.mem.eql(u8, insecure, "1")) return error.TokenFileMissing;
                    break :insecure_blk try arena.dupe(u8, "");
                },
                else => return err,
            };
        }
    };
    const token = std.mem.trim(u8, token_raw, " \t\r\n");
    if (token.len == 0) {
        const insecure = getEnv(arena, "MCP_NODE_INSECURE") orelse "0";
        if (!std.mem.eql(u8, insecure, "1")) return error.TokenFileMissing;
    }

    const hosts_s = getEnv(arena, "MCP_NODE_ALLOWED_HOSTS") orelse "127.0.0.1:*,localhost:*,[::1]:*";
    const origins_s = getEnv(arena, "MCP_NODE_ALLOWED_ORIGINS") orelse "http://127.0.0.1:*,http://localhost:*,http://[::1]:*";
    return .{
        .name = name,
        .host = try arena.dupe(u8, host),
        .port = port,
        .token = try arena.dupe(u8, token),
        .allowed_hosts = try util.splitCsv(arena, hosts_s),
        .allowed_origins = try util.splitCsv(arena, origins_s),
        .max_out = max_out,
        .socket_timeout_s = socket_timeout,
        .max_conn = max_conn,
        .max_sessions = max_sessions,
        .session_ttl_s = session_ttl,
        .max_inflight_bytes = max_inflight_bytes,
    };
}

/// Process environment snapshot, loaded once in `main` before any
/// connection thread spawns and only read afterwards (the daemon never
/// calls setenv), so sharing it across threads needs no synchronization.
var process_environ: std.process.Environ = .empty;

/// All environment reads go through the OS layer's cross-platform
/// snapshot lookup. Linux reads `/proc/self/environ`
/// source, same parse, same degrade-to-null-on-missing semantics.
fn getEnv(arena: Allocator, key: []const u8) ?[]const u8 {
    return os.environGet(arena, process_environ, key);
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
fn serveOneRequest(io: Io, cfg: *const Config, stream: *Io.net.Stream, carry: *std.ArrayList(u8)) !bool {
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

    const rpc = try handleRpc(ra, io, cfg, body);
    try http.sendHttpRawMode(ra, fd, rpc.status, "application/json", rpc.body, keep_alive, timeout_ms);
    return keep_alive;
}

/// JSON-RPC 2.0 dispatch for one MCP request body. Returns the HTTP status
/// plus the serialized response body: transport errors (parse, shape) map to
/// HTTP 4xx, method-level errors stay inside a 200 JSON-RPC error object.
/// Notifications (no id, or method "notifications/*") get 202 with empty body.
fn handleRpc(arena: Allocator, io: Io, cfg: *const Config, body: []const u8) !RpcResponse {
    const req = std.json.parseFromSliceLeaky(Value, arena, body, .{}) catch {
        return .{ .status = 400, .body = try rpcError(arena, Value.null, -32700, "Parse error") };
    };
    if (req != .object) {
        return .{ .status = 400, .body = try rpcError(arena, Value.null, -32600, "Invalid Request") };
    }
    const id_opt = req.object.get("id");
    // Errors echo the id only when it is of a legal type (string/integer/
    // null); anything else renders the request itself invalid with id null.
    const err_id = validIdOrNull(id_opt);
    // The JSON-RPC 2.0 envelope member is mandatory and must equal "2.0";
    // anything else is an Invalid Request, never silently tolerated.
    const jsonrpc_v = req.object.get("jsonrpc") orelse {
        return .{ .status = 400, .body = try rpcError(arena, err_id, -32600, "Invalid Request") };
    };
    if (jsonrpc_v != .string or !std.mem.eql(u8, jsonrpc_v.string, "2.0")) {
        return .{ .status = 400, .body = try rpcError(arena, err_id, -32600, "Invalid Request") };
    }
    // id typing per JSON-RPC: string, integer, or null. A present null id is
    // a (discouraged but legal) request id, NOT a notification: it is
    // answered with the echoed null. Absent id is the notification marker.
    if (id_opt) |id_v| {
        switch (id_v) {
            .string, .integer, .number_string, .null => {},
            else => return .{ .status = 400, .body = try rpcError(arena, Value.null, -32600, "Invalid Request") },
        }
    }
    const method_v = req.object.get("method") orelse {
        return .{ .status = 400, .body = try rpcError(arena, err_id, -32600, "Invalid Request") };
    };
    if (method_v != .string) {
        return .{ .status = 400, .body = try rpcError(arena, err_id, -32600, "Invalid Request") };
    }
    const method = method_v.string;
    // params, when present, must be structured (object or array); null is
    // tolerated as "omitted" for client compatibility. A scalar params makes
    // the whole message an Invalid Request — including for notifications,
    // which must not unconditionally pass.
    if (req.object.get("params")) |params| {
        switch (params) {
            .object, .array, .null => {},
            else => return .{ .status = 400, .body = try rpcError(arena, err_id, -32600, "Invalid Request") },
        }
    }
    // A request without an id is a notification: 202 with no response body,
    // but only after the full shape validation above.
    if (id_opt == null) {
        return .{ .status = 202, .body = "" };
    }
    const id = id_opt.?;
    // MCP notifications/* are notifications by definition; carrying an id
    // makes the message an Invalid Request that must be answered — the
    // response must never be silently dropped with a 202.
    if (std.mem.startsWith(u8, method, "notifications/")) {
        return .{ .status = 400, .body = try rpcError(arena, id, -32600, "Invalid Request") };
    }

    if (std.mem.eql(u8, method, "initialize")) {
        var protocol_version: []const u8 = "2025-11-25";
        if (req.object.get("params")) |params| {
            if (params == .object) {
                if (params.object.get("protocolVersion")) |pv| {
                    if (pv == .string and supportedProtocolVersion(pv.string)) protocol_version = pv.string;
                }
            }
        }
        var out: std.ArrayList(u8) = .empty;
        try out.appendSlice(arena, "{\"jsonrpc\":\"2.0\",\"id\":");
        try util.appendJsonValue(&out, arena, id);
        try out.appendSlice(arena, ",\"result\":{\"protocolVersion\":");
        try util.appendJsonString(&out, arena, protocol_version);
        try out.appendSlice(arena, ",\"capabilities\":{\"tools\":{}},\"serverInfo\":{\"name\":");
        try util.appendJsonString(&out, arena, cfg.name);
        try out.appendSlice(arena, ",\"version\":");
        try util.appendJsonString(&out, arena, VERSION);
        try out.appendSlice(arena, "}}}");
        return .{ .status = 200, .body = out.items };
    }
    if (std.mem.eql(u8, method, "ping")) {
        var out: std.ArrayList(u8) = .empty;
        try out.appendSlice(arena, "{\"jsonrpc\":\"2.0\",\"id\":");
        try util.appendJsonValue(&out, arena, id);
        try out.appendSlice(arena, ",\"result\":{}}");
        return .{ .status = 200, .body = out.items };
    }
    if (std.mem.eql(u8, method, "tools/list")) {
        var out: std.ArrayList(u8) = .empty;
        try out.appendSlice(arena, "{\"jsonrpc\":\"2.0\",\"id\":");
        try util.appendJsonValue(&out, arena, id);
        try out.appendSlice(arena, ",\"result\":");
        try out.appendSlice(arena, TOOLS_JSON);
        try out.appendSlice(arena, "}");
        return .{ .status = 200, .body = out.items };
    }
    if (std.mem.eql(u8, method, "resources/list")) {
        var out: std.ArrayList(u8) = .empty;
        try out.appendSlice(arena, "{\"jsonrpc\":\"2.0\",\"id\":");
        try util.appendJsonValue(&out, arena, id);
        try out.appendSlice(arena, ",\"result\":{\"resources\":[]}}");
        return .{ .status = 200, .body = out.items };
    }
    if (std.mem.eql(u8, method, "prompts/list")) {
        var out: std.ArrayList(u8) = .empty;
        try out.appendSlice(arena, "{\"jsonrpc\":\"2.0\",\"id\":");
        try util.appendJsonValue(&out, arena, id);
        try out.appendSlice(arena, ",\"result\":{\"prompts\":[]}}");
        return .{ .status = 200, .body = out.items };
    }
    if (std.mem.eql(u8, method, "tools/call")) {
        return handleToolCall(arena, io, cfg, id, req.object.get("params"));
    }
    return .{ .status = 200, .body = try rpcError(arena, id, -32601, "Method not found") };
}

fn supportedProtocolVersion(v: []const u8) bool {
    return std.mem.eql(u8, v, "2024-11-05") or
        std.mem.eql(u8, v, "2025-03-26") or
        std.mem.eql(u8, v, "2025-06-18") or
        std.mem.eql(u8, v, "2025-11-25");
}

fn handleToolCall(arena: Allocator, io: Io, cfg: *const Config, id: Value, params_v: ?Value) !RpcResponse {
    const params = params_v orelse return .{ .status = 200, .body = try rpcError(arena, id, -32602, "Invalid params") };
    if (params != .object) return .{ .status = 200, .body = try rpcError(arena, id, -32602, "Invalid params") };
    const name_v = params.object.get("name") orelse return .{ .status = 200, .body = try rpcError(arena, id, -32602, "Invalid params") };
    if (name_v != .string) return .{ .status = 200, .body = try rpcError(arena, id, -32602, "Invalid params") };
    // arguments, when present, must be an object: anything else is a
    // protocol-level Invalid params (-32602), not a tool-domain error.
    const args_v = params.object.get("arguments");
    if (args_v) |a| {
        if (a != .object) return .{ .status = 200, .body = try rpcError(arena, id, -32602, "Invalid params") };
    }
    const args = args_v orelse Value.null;

    var payload: std.ArrayList(u8) = .empty;
    dispatchTool(arena, io, cfg, name_v.string, args, &payload) catch |err| {
        switch (err) {
            error.UnknownTool => return unknownToolResult(arena, id, name_v.string),
            // A present argument with the wrong JSON type is a protocol
            // error (-32602), never a silent default.
            error.InvalidParams => return .{ .status = 200, .body = try rpcError(arena, id, -32602, "Invalid params") },
            else => try buildErrorPayload(&payload, arena, @errorName(err)),
        }
        return .{ .status = 200, .body = try toolEnvelope(arena, id, payload.items, false, true) };
    };
    return .{ .status = 200, .body = try toolEnvelope(arena, id, payload.items, false, true) };
}

fn dispatchTool(arena: Allocator, io: Io, cfg: *const Config, name: []const u8, args: Value, out: *std.ArrayList(u8)) !void {
    if (std.mem.eql(u8, name, "exec")) return toolExec(arena, io, cfg, args, out);
    if (std.mem.eql(u8, name, "exec_start")) return toolExecStart(arena, io, cfg, args, out);
    if (std.mem.eql(u8, name, "exec_poll")) return toolExecPoll(arena, io, cfg, args, out);
    if (std.mem.eql(u8, name, "exec_write")) return toolExecWrite(arena, io, cfg, args, out);
    if (std.mem.eql(u8, name, "exec_kill")) return toolExecKill(arena, io, cfg, args, out);
    if (std.mem.eql(u8, name, "exec_close")) return toolExecClose(arena, io, cfg, args, out);
    if (std.mem.eql(u8, name, "exec_wait")) return toolExecWait(arena, io, cfg, args, out);
    if (std.mem.eql(u8, name, "exec_list")) return toolExecList(arena, io, cfg, out);
    if (std.mem.eql(u8, name, "exec_shell")) return toolExecShell(arena, io, cfg, args, out);
    if (std.mem.eql(u8, name, "sys_info")) return toolSysInfo(arena, io, cfg, out);
    if (std.mem.eql(u8, name, "read_file")) return toolReadFile(arena, io, cfg, args, out);
    if (std.mem.eql(u8, name, "write_file")) return toolWriteFile(arena, io, cfg, args, out);
    if (std.mem.eql(u8, name, "list_dir")) return toolListDir(arena, io, cfg, args, out);
    return error.UnknownTool;
}

fn toolEnvelope(arena: Allocator, id: Value, payload: []const u8, is_error: bool, structured: bool) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(arena, "{\"jsonrpc\":\"2.0\",\"id\":");
    try util.appendJsonValue(&out, arena, id);
    try out.appendSlice(arena, ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":");
    try util.appendJsonString(&out, arena, payload);
    try out.appendSlice(arena, "}]");
    if (structured) {
        try out.appendSlice(arena, ",\"structuredContent\":");
        try out.appendSlice(arena, payload);
    }
    try out.appendSlice(arena, ",\"isError\":");
    try out.appendSlice(arena, if (is_error) "true" else "false");
    try out.appendSlice(arena, "}}");
    return out.items;
}

fn unknownToolResult(arena: Allocator, id: Value, name: []const u8) !RpcResponse {
    var msg: std.ArrayList(u8) = .empty;
    try msg.appendSlice(arena, "Unknown tool: ");
    try msg.appendSlice(arena, name);
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(arena, "{\"jsonrpc\":\"2.0\",\"id\":");
    try util.appendJsonValue(&out, arena, id);
    try out.appendSlice(arena, ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":");
    try util.appendJsonString(&out, arena, msg.items);
    try out.appendSlice(arena, "}],\"isError\":true}}");
    return .{ .status = 200, .body = out.items };
}

fn validIdOrNull(id_opt: ?Value) Value {
    const v = id_opt orelse return Value.null;
    return switch (v) {
        .string, .integer, .number_string, .null => v,
        else => Value.null,
    };
}

fn rpcError(arena: Allocator, id: Value, code: i32, message: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(arena, "{\"jsonrpc\":\"2.0\",\"id\":");
    try util.appendJsonValue(&out, arena, id);
    try out.appendSlice(arena, ",\"error\":{\"code\":");
    try out.print(arena, "{d}", .{code});
    try out.appendSlice(arena, ",\"message\":");
    try util.appendJsonString(&out, arena, message);
    try out.appendSlice(arena, "}}");
    return out.items;
}

fn buildErrorPayload(out: *std.ArrayList(u8), arena: Allocator, msg: []const u8) !void {
    out.clearRetainingCapacity();
    try out.appendSlice(arena, "{\"ok\":false,\"error\":");
    try util.appendJsonString(out, arena, msg);
    try out.appendSlice(arena, "}");
}

fn toolExec(arena: Allocator, io: Io, cfg: *const Config, args: Value, out: *std.ArrayList(u8)) !void {
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
        else => return err,
    };
    const elapsed_ms = started.untilNow(io, .awake).toMilliseconds();
    const exit_code: i32 = switch (result.term) {
        .exited => |code| code,
        .signal => |sig| 128 + @as(i32, @intCast(@intFromEnum(sig))),
        .stopped => |sig| 128 + @as(i32, @intCast(@intFromEnum(sig))),
        .unknown => |code| @as(i32, @intCast(code)),
    };
    try out.appendSlice(arena, "{\"ok\":");
    try out.appendSlice(arena, if (exit_code == 0) "true" else "false");
    try out.appendSlice(arena, ",\"exit_code\":");
    try out.print(arena, "{d}", .{exit_code});
    try out.appendSlice(arena, ",\"stdout\":");
    try util.appendJsonString(out, arena, result.stdout);
    try out.appendSlice(arena, ",\"stderr\":");
    try util.appendJsonString(out, arena, result.stderr);
    try out.appendSlice(arena, ",\"truncated\":false,\"duration_ms\":");
    try out.print(arena, "{d}", .{elapsed_ms});
    try out.appendSlice(arena, "}");
}

fn toolExecShell(arena: Allocator, io: Io, cfg: *const Config, args: Value, out: *std.ArrayList(u8)) !void {
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
fn sessionFromArgs(cfg: *const Config, args: Value) !*session_mod.Session {
    const store = cfg.sessions orelse return error.SessionsDisabled;
    const id_i = (try util.optIntArg(args, "session_id")) orelse return error.MissingSession;
    if (id_i <= 0) return error.BadSession;
    return store.get(@as(u64, @intCast(id_i))) orelse error.UnknownSession;
}

/// Spawn a session process (piped stdio, own process group) and publish it.
/// Ownership: argv/cwd/stdin_fd transfer to the Session on success; on any
/// error path the errdefers free them exactly once. The child is always
/// reaped — either by the session waiter thread or by the error path.
fn toolExecStart(arena: Allocator, io: Io, cfg: *const Config, args: Value, out: *std.ArrayList(u8)) !void {
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

    // Stdin wiring splits by platform (see the src/os/proc.zig header).
    // POSIX — parent-owned pipe: the read end goes to the child as `.file`
    // stdio (std dups it in), the write end becomes session_mod.Session.stdin_fd, and
    // std.process.Child.stdin stays null, so child.wait() cleanup can never
    // close the write end from under exec_write. Windows — `.file` stdio
    // re-opens the pipe read end via NtCreateFile with an empty path, which
    // a named pipe answers with STATUS_PIPE_NOT_AVAILABLE (error.NoDevice —
    // every exec_start failed), so spawn with `.pipe` and let std create the
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

    var child = try std.process.spawn(io, .{
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
    });
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
        .started_ms = session_mod.nowMs(io),
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

fn toolExecPoll(arena: Allocator, io: Io, cfg: *const Config, args: Value, out: *std.ArrayList(u8)) !void {
    _ = io;
    const session = try sessionFromArgs(cfg, args);
    defer session_mod.sessionRelease(session);
    const stdout_offset = (try util.optIntArg(args, "stdout_offset")) orelse 0;
    const stderr_offset = (try util.optIntArg(args, "stderr_offset")) orelse 0;
    try session_mod.renderSessionState(arena, cfg.sessions.?, session, stdout_offset, stderr_offset, out);
}

fn toolExecWait(arena: Allocator, io: Io, cfg: *const Config, args: Value, out: *std.ArrayList(u8)) !void {
    _ = io;
    const session = try sessionFromArgs(cfg, args);
    defer session_mod.sessionRelease(session);
    const stdout_offset = (try util.optIntArg(args, "stdout_offset")) orelse 0;
    const stderr_offset = (try util.optIntArg(args, "stderr_offset")) orelse 0;
    var timeout_s = (try util.optIntArg(args, "timeout")) orelse WAIT_DEFAULT_TIMEOUT_S;
    if (timeout_s < 1) timeout_s = 1;
    if (timeout_s > WAIT_MAX_TIMEOUT_S) timeout_s = WAIT_MAX_TIMEOUT_S;
    const store = cfg.sessions.?;
    const deadline = session_mod.nowMs(store.io) + @as(i64, timeout_s) * 1000;
    while (true) {
        session.mutex.lockUncancelable(store.io);
        const done = session.done;
        session.mutex.unlock(store.io);
        if (done) break;
        if (session_mod.nowMs(store.io) >= deadline) break;
        os.sleepMs(WAIT_POLL_MS);
    }
    try session_mod.renderSessionState(arena, store, session, stdout_offset, stderr_offset, out);
}

fn toolExecList(arena: Allocator, io: Io, cfg: *const Config, out: *std.ArrayList(u8)) !void {
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
        const started = s.started_ms;
        const ended = s.ended_ms;
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
        try out.appendSlice(arena, ",\"started_ms\":");
        try out.print(arena, "{d}", .{started});
        try out.appendSlice(arena, ",\"ended_ms\":");
        if (ended) |e| try out.print(arena, "{d}", .{e}) else try out.appendSlice(arena, "null");
        try out.appendSlice(arena, "}");
    }
    try out.appendSlice(arena, "]}");
}

fn toolExecWrite(arena: Allocator, io: Io, cfg: *const Config, args: Value, out: *std.ArrayList(u8)) !void {
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

fn toolExecKill(arena: Allocator, io: Io, cfg: *const Config, args: Value, out: *std.ArrayList(u8)) !void {
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
fn toolExecClose(arena: Allocator, io: Io, cfg: *const Config, args: Value, out: *std.ArrayList(u8)) !void {
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

fn toolSysInfo(arena: Allocator, io: Io, cfg: *const Config, out: *std.ArrayList(u8)) !void {
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
    try out.appendSlice(arena, "}}");
}

fn toolReadFile(arena: Allocator, io: Io, cfg: *const Config, args: Value, out: *std.ArrayList(u8)) !void {
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

fn toolWriteFile(arena: Allocator, io: Io, cfg: *const Config, args: Value, out: *std.ArrayList(u8)) !void {
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

fn toolListDir(arena: Allocator, io: Io, cfg: *const Config, args: Value, out: *std.ArrayList(u8)) !void {
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
    const home = os.homeDir(arena, process_environ) orelse return path;
    if (home.len == 0) return path;
    return std.mem.concat(arena, u8, &.{ home, path[1..] });
}

const TOOLS_JSON =
    \\{"tools":[
    \\{"name":"sys_info","description":"Host summary: hostname, OS, load, memory, uptime.","inputSchema":{"type":"object","properties":{}}},
    \\{"name":"exec","description":"Run argv without a shell layer and wait for completion.","inputSchema":{"type":"object","properties":{"argv":{"type":"array","items":{"type":"string"}},"cwd":{"type":"string"},"timeout":{"type":"integer"}},"required":["argv"]}},
    \\{"name":"exec_start","description":"Start a long-running argv process as a session with piped stdin/stdout/stderr.","inputSchema":{"type":"object","properties":{"argv":{"type":"array","items":{"type":"string"}},"cwd":{"type":"string"}},"required":["argv"]}},
    \\{"name":"exec_poll","description":"Poll a session by byte offsets; returns output deltas, done, exit_code, truncation flags.","inputSchema":{"type":"object","properties":{"session_id":{"type":"integer"},"stdout_offset":{"type":"integer"},"stderr_offset":{"type":"integer"}},"required":["session_id"]}},
    \\{"name":"exec_write","description":"Write base64 bytes to a session stdin; eof=true closes stdin.","inputSchema":{"type":"object","properties":{"session_id":{"type":"integer"},"data_b64":{"type":"string"},"eof":{"type":"boolean"}},"required":["session_id","data_b64"]}},
    \\{"name":"exec_kill","description":"Kill a running session process with SIGKILL.","inputSchema":{"type":"object","properties":{"session_id":{"type":"integer"}},"required":["session_id"]}},
    \\{"name":"exec_close","description":"Kill if needed, join session threads, and free session state. Idempotent.","inputSchema":{"type":"object","properties":{"session_id":{"type":"integer"}},"required":["session_id"]}},
    \\{"name":"exec_wait","description":"Long-poll a session until it finishes or timeout (default 30s, max 300s); returns the same payload as exec_poll.","inputSchema":{"type":"object","properties":{"session_id":{"type":"integer"},"timeout":{"type":"integer"},"stdout_offset":{"type":"integer"},"stderr_offset":{"type":"integer"}},"required":["session_id"]}},
    \\{"name":"exec_list","description":"List live sessions with id, pid, argv, done, exit_code, timestamps.","inputSchema":{"type":"object","properties":{}}},
    \\{"name":"exec_shell","description":"Run one shell script layer via bash/sh/fish/zsh -c (cmd /c, powershell -c on Windows).","inputSchema":{"type":"object","properties":{"script":{"type":"string"},"shell":{"type":"string"},"timeout":{"type":"integer"},"cwd":{"type":"string"}},"required":["script"]}},
    \\{"name":"read_file","description":"Read a text file as UTF-8 with replacement. offset/limit are in characters.","inputSchema":{"type":"object","properties":{"path":{"type":"string"},"offset":{"type":"integer"},"limit":{"type":"integer"}},"required":["path"]}},
    \\{"name":"write_file","description":"Write base64 content to a file; returns sha256.","inputSchema":{"type":"object","properties":{"path":{"type":"string"},"content_b64":{"type":"string"},"mode":{"type":"integer"},"mkdirs":{"type":"boolean"}},"required":["path","content_b64"]}},
    \\{"name":"list_dir","description":"List a directory with name/type/size/mtime.","inputSchema":{"type":"object","properties":{"path":{"type":"string"}}}}
    \\]}
;

test "rpc parse error and notification semantics" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = Io.Threaded.global_single_threaded.io();
    const cfg = Config{
        .name = "test-node",
        .host = "127.0.0.1",
        .port = 1,
        .token = "",
        .allowed_hosts = try util.splitCsv(arena, "127.0.0.1:*"),
        .allowed_origins = try util.splitCsv(arena, "http://127.0.0.1:*"),
        .max_out = 1024,
        .socket_timeout_s = 1,
        .max_conn = 4,
        .max_sessions = 4,
        .session_ttl_s = 600,
        .max_inflight_bytes = 64 * 1024 * 1024,
    };

    const bad = try handleRpc(arena, io, &cfg, "{");
    try std.testing.expectEqual(@as(u16, 400), bad.status);
    const bad_parsed = try std.json.parseFromSliceLeaky(Value, arena, bad.body, .{});
    try std.testing.expectEqual(@as(i32, -32700), bad_parsed.object.get("error").?.object.get("code").?.integer);

    const note = try handleRpc(arena, io, &cfg, "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}");
    try std.testing.expectEqual(@as(u16, 202), note.status);
    try std.testing.expectEqual(@as(usize, 0), note.body.len);

    const ping = try handleRpc(arena, io, &cfg, "{\"jsonrpc\":\"2.0\",\"id\":\"p\",\"method\":\"ping\"}");
    try std.testing.expectEqual(@as(u16, 200), ping.status);
    const ping_parsed = try std.json.parseFromSliceLeaky(Value, arena, ping.body, .{});
    try std.testing.expect(ping_parsed.object.get("result").? == .object);
}

test "discover http.zig tests" {
    // Test builds analyze decls lazily per decl: a module not referenced by
    // any root test would have its test blocks silently skipped. Pull them in.
    std.testing.refAllDecls(@import("http.zig"));
}
