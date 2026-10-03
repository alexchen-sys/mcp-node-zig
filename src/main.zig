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

/// A peer disconnect must never kill the daemon via SIGPIPE. Protection is
/// real on two layers: Io.Threaded installs an ignore handler for
/// SIGPIPE, and on std versions honoring root's keep_sigpipe this opts out
/// explicitly. Writes to closed pipes surface as EPIPE errors instead.
pub const keep_sigpipe = false;

const VERSION: []const u8 = @import("build_options").version;

const ACCEPT_BACKOFF_MS: u64 = 50; // pause after accept failure

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

    const rpc = try handleRpc(ra, io, cfg, body);
    try http.sendHttpRawMode(ra, fd, rpc.status, "application/json", rpc.body, keep_alive, timeout_ms);
    return keep_alive;
}

/// JSON-RPC 2.0 dispatch for one MCP request body. Returns the HTTP status
/// plus the serialized response body: transport errors (parse, shape) map to
/// HTTP 4xx, method-level errors stay inside a 200 JSON-RPC error object.
/// Notifications (no id, or method "notifications/*") get 202 with empty body.
fn handleRpc(arena: Allocator, io: Io, cfg: *const config.Config, body: []const u8) !RpcResponse {
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

fn handleToolCall(arena: Allocator, io: Io, cfg: *const config.Config, id: Value, params_v: ?Value) !RpcResponse {
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

fn dispatchTool(arena: Allocator, io: Io, cfg: *const config.Config, name: []const u8, args: Value, out: *std.ArrayList(u8)) !void {
    if (std.mem.eql(u8, name, "exec")) return tools.toolExec(arena, io, cfg, args, out);
    if (std.mem.eql(u8, name, "exec_start")) return tools.toolExecStart(arena, io, cfg, args, out);
    if (std.mem.eql(u8, name, "exec_poll")) return tools.toolExecPoll(arena, io, cfg, args, out);
    if (std.mem.eql(u8, name, "exec_write")) return tools.toolExecWrite(arena, io, cfg, args, out);
    if (std.mem.eql(u8, name, "exec_kill")) return tools.toolExecKill(arena, io, cfg, args, out);
    if (std.mem.eql(u8, name, "exec_close")) return tools.toolExecClose(arena, io, cfg, args, out);
    if (std.mem.eql(u8, name, "exec_wait")) return tools.toolExecWait(arena, io, cfg, args, out);
    if (std.mem.eql(u8, name, "exec_list")) return tools.toolExecList(arena, io, cfg, out);
    if (std.mem.eql(u8, name, "exec_shell")) return tools.toolExecShell(arena, io, cfg, args, out);
    if (std.mem.eql(u8, name, "sys_info")) return tools.toolSysInfo(arena, io, cfg, out);
    if (std.mem.eql(u8, name, "read_file")) return tools.toolReadFile(arena, io, cfg, args, out);
    if (std.mem.eql(u8, name, "write_file")) return tools.toolWriteFile(arena, io, cfg, args, out);
    if (std.mem.eql(u8, name, "list_dir")) return tools.toolListDir(arena, io, cfg, args, out);
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
    const cfg = config.Config{
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
