//! HTTP/1.1 transport: strict head parsing, header validation,
//! auth-token extraction, deadline-bounded reads and raw response
//! writers. The per-request serving loop (serveOneRequest)
//! lives in this file.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const os = @import("os.zig");
const util = @import("util.zig");
const config = @import("config.zig");
const rpc_mod = @import("rpc.zig");
const hub_mod = @import("hub.zig");

const MAX_HEADER_BYTES: usize = 64 * 1024; // 431 territory; headers only
const MAX_BODY_BYTES: usize = 32 * 1024 * 1024; // request body cap; 413 territory

/// Parsed request head: request line plus the security-relevant headers.
/// Duplicates of these are rejected at parse time (ambiguous duplicates are
/// a classic desync primitive), so every field here is single-valued.
const HeadInfo = struct {
    method: []const u8,
    path: []const u8,
    host: ?[]const u8 = null,
    origin: ?[]const u8 = null,
    content_type: ?[]const u8 = null,
    content_length: usize = 0,
    token: ?[]const u8 = null,
    authorization: ?[]const u8 = null,
    connection: ?[]const u8 = null,
    expect_continue: bool = false,
};

/// Milliseconds left on the absolute request deadline; null when expired.
pub fn remainingMs(started: std.Io.Timestamp, io: Io, deadline_ms: u64) ?u64 {
    const elapsed_i = started.untilNow(io, .awake).toMilliseconds();
    if (elapsed_i < 0) return deadline_ms; // clock moved backwards: keep the full budget
    const elapsed: u64 = @intCast(elapsed_i);
    if (elapsed >= deadline_ms) return null;
    return deadline_ms - elapsed;
}

/// One socket read bounded by `remaining_ms` — the leftover of the absolute
/// request deadline, not a fresh per-read timeout. POSIX re-arms SO_RCVTIMEO
/// per call; Windows enforces the software deadline inside socketReadSome.
/// Returns 0 on clean EOF; an expired deadline is error.RequestTimeout.
pub fn readWithDeadline(fd: std.posix.fd_t, buf: []u8, remaining_ms: u64) !usize {
    os.net.setSocketReadTimeoutMs(fd, remaining_ms) catch return error.SocketOptionFailed;
    const n = os.net.socketReadSome(fd, buf, remaining_ms) catch |err| {
        // SO_RCVTIMEO expiry on POSIX, software-deadline expiry on Windows.
        if (os.net.isReadTimeout(err)) return error.RequestTimeout;
        return err;
    };
    return n;
}

fn isTokenChar(c: u8) bool {
    return switch (c) {
        'a'...'z', 'A'...'Z', '0'...'9', '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
        else => false,
    };
}

fn validToken(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| {
        if (!isTokenChar(c)) return false;
    }
    return true;
}

/// RFC 9110 field-content: HTAB / SP / VCHAR / obs-text only; no other
/// controls and no DEL.
fn validHeaderValue(s: []const u8) bool {
    for (s) |c| {
        if (c == '\t' or c == ' ') continue;
        if (c >= 0x21 and c != 0x7f) continue;
        return false;
    }
    return true;
}

const RequestLine = struct {
    method: []const u8,
    path: []const u8,
};

/// Strict HTTP/1.1 request line: exactly `METHOD SP path SP HTTP/1.1`. This
/// daemon speaks 1.1 semantics (keep-alive by default, 100-continue), so
/// other versions are refused rather than guessed.
fn parseRequestLine(line: []const u8) !RequestLine {
    var parts = std.mem.splitScalar(u8, line, ' ');
    const method = parts.next() orelse return error.BadRequestLine;
    const path = parts.next() orelse return error.BadRequestLine;
    const version = parts.next() orelse return error.BadRequestLine;
    if (parts.next() != null) return error.BadRequestLine;
    if (!validToken(method)) return error.BadRequestLine;
    if (path.len == 0 or path[0] != '/') return error.BadRequestLine;
    for (path) |c| {
        if (c <= 0x20 or c == 0x7f) return error.BadRequestLine;
    }
    if (!std.mem.eql(u8, version, "HTTP/1.1")) return error.BadRequestLine;
    return .{ .method = method, .path = path };
}

/// Strict media-type check: exactly `application/json` (case-insensitive),
/// optionally followed by well-formed `; token=value` parameters such as
/// charset=utf-8. A prefix match is not enough: `application/json-not-real`
/// must be rejected.
pub fn contentTypeJson(ct: []const u8) bool {
    var it = std.mem.splitScalar(u8, ct, ';');
    const media = std.mem.trim(u8, it.first(), " \t");
    if (!asciiEqlIgnoreCase(media, "application/json")) return false;
    while (it.next()) |param_raw| {
        const param = std.mem.trim(u8, param_raw, " \t");
        if (param.len == 0) return false; // "application/json;" is malformed
        const eq = std.mem.indexOfScalar(u8, param, '=') orelse return false;
        const name = std.mem.trim(u8, param[0..eq], " \t");
        const value = std.mem.trim(u8, param[eq + 1 ..], " \t");
        if (!validToken(name)) return false;
        if (value.len == 0) return false;
        if (value[0] == '"') {
            // quoted-string: must close; no raw CR/LF/DEL inside.
            if (value.len < 2 or value[value.len - 1] != '"') return false;
            for (value[1 .. value.len - 1]) |c| {
                if (c == '\r' or c == '\n' or c == 0x7f) return false;
            }
        } else if (!validToken(value)) return false;
    }
    return true;
}

/// Parse and validate the request head (request line + headers, without the
/// trailing CRLFCRLF). Strict HTTP/1.1 grammar. Security-relevant headers
/// reject duplicates instead of last-wins. `Transfer-Encoding` is refused
/// outright: this server speaks Content-Length only, and accepting TE (let
/// alone TE+CL) would invite request smuggling.
pub fn parseHead(head: []const u8) !HeadInfo {
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    const request_line = lines.next() orelse return error.BadRequestLine;
    const rl = try parseRequestLine(request_line);
    var info = HeadInfo{ .method = rl.method, .path = rl.path };
    var seen_cl: ?usize = null;
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        // obs-fold (a line starting with SP/HTAB) died with RFC 7230: reject.
        if (line[0] == ' ' or line[0] == '\t') return error.BadHeader;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.BadHeader;
        const name = line[0..colon];
        // No whitespace between field name and colon (RFC 9112 §5.1).
        if (!validToken(name)) return error.BadHeader;
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (!validHeaderValue(value)) return error.BadHeader;
        if (asciiEqlIgnoreCase(name, "host")) {
            if (info.host != null) return error.DuplicateHeader;
            info.host = value;
        } else if (asciiEqlIgnoreCase(name, "origin")) {
            if (info.origin != null) return error.DuplicateHeader;
            info.origin = value;
        } else if (asciiEqlIgnoreCase(name, "content-type")) {
            if (info.content_type != null) return error.DuplicateHeader;
            info.content_type = value;
        } else if (asciiEqlIgnoreCase(name, "x-node-token")) {
            if (info.token != null) return error.DuplicateHeader;
            info.token = value;
        } else if (asciiEqlIgnoreCase(name, "authorization")) {
            if (info.authorization != null) return error.DuplicateHeader;
            info.authorization = value;
        } else if (asciiEqlIgnoreCase(name, "connection")) {
            if (info.connection != null) return error.DuplicateHeader;
            info.connection = value;
        } else if (asciiEqlIgnoreCase(name, "expect")) {
            if (!asciiEqlIgnoreCase(value, "100-continue")) return error.BadExpectation;
            if (info.expect_continue) return error.DuplicateHeader;
            info.expect_continue = true;
        } else if (asciiEqlIgnoreCase(name, "transfer-encoding")) {
            return error.TransferEncodingUnsupported;
        } else if (asciiEqlIgnoreCase(name, "content-length")) {
            const parsed = std.fmt.parseInt(usize, value, 10) catch return error.BadContentLength;
            if (parsed > MAX_BODY_BYTES) return error.RequestTooLarge;
            if (seen_cl) |prev| {
                if (prev != parsed) return error.BadContentLength;
            } else {
                seen_cl = parsed;
            }
        }
    }
    info.content_length = seen_cl orelse 0;
    return info;
}

/// Extract the credential from an `Authorization` value using the Bearer
/// scheme. The scheme name is case-insensitive (RFC 7235 §2.1) and must be
/// followed by at least one SP; the credential is trimmed at both ends.
/// Any other scheme, or an empty credential, yields null (treated as "no
/// token presented").
fn bearerToken(value: []const u8) ?[]const u8 {
    const scheme = "bearer";
    if (value.len <= scheme.len) return null;
    if (!asciiEqlIgnoreCase(value[0..scheme.len], scheme)) return null;
    if (value[scheme.len] != ' ') return null;
    const cred = std.mem.trim(u8, value[scheme.len..], " \t");
    if (cred.len == 0) return null;
    return cred;
}

/// The token the client presented, from `X-Node-Token` or a Bearer
/// `Authorization` header. If both carry a token and they differ, the request
/// is ambiguous and is refused rather than silently picking one.
fn presentedToken(info: HeadInfo) error{ConflictingTokens}!?[]const u8 {
    const bearer = if (info.authorization) |a| bearerToken(a) else null;
    if (info.token) |x| {
        if (bearer) |b| {
            if (!std.mem.eql(u8, x, b)) return error.ConflictingTokens;
        }
        return x;
    }
    return bearer;
}

fn asciiEqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        if (std.ascii.toLower(ca) != std.ascii.toLower(cb)) return false;
    }
    return true;
}

pub fn connectionCloseRequested(connection: ?[]const u8) bool {
    const raw = connection orelse return false;
    var it = std.mem.splitScalar(u8, raw, ',');
    while (it.next()) |part| {
        if (asciiEqlIgnoreCase(std.mem.trim(u8, part, " \t"), "close")) return true;
    }
    return false;
}

/// Wildcard list match: exact string, or `base:*` matches `base:anything`.
fn listAllowed(value: []const u8, allowed: [][]const u8) bool {
    for (allowed) |pat| {
        if (std.mem.eql(u8, value, pat)) return true;
        if (std.mem.endsWith(u8, pat, ":*")) {
            const base = pat[0 .. pat.len - 2];
            if (std.mem.startsWith(u8, value, base) and value.len > base.len and value[base.len] == ':') return true;
        }
    }
    return false;
}

pub fn hostAllowed(host_opt: ?[]const u8, allowed: [][]const u8) bool {
    return listAllowed(host_opt orelse return false, allowed);
}

pub fn originAllowed(origin: []const u8, allowed: [][]const u8) bool {
    return listAllowed(origin, allowed);
}

fn sendHttpRaw(arena: Allocator, fd: std.posix.fd_t, status: u16, content_type: []const u8, body: []const u8, timeout_ms: u64) !void {
    try sendHttpRawMode(arena, fd, status, content_type, body, false, timeout_ms);
}

pub fn sendHttpRawMode(arena: Allocator, fd: std.posix.fd_t, status: u16, content_type: []const u8, body: []const u8, keep_alive: bool, timeout_ms: u64) !void {
    var out: std.ArrayList(u8) = .empty;
    const reason = switch (status) {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        401 => "Unauthorized",
        408 => "Request Timeout",
        417 => "Expectation Failed",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        421 => "Misdirected Request",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        else => "Unknown",
    };
    const connection = if (keep_alive) "keep-alive" else "close";
    // RFC 9110 §15.5.2: a 401 must carry a challenge.
    const challenge = if (status == 401) "www-authenticate: Bearer\r\n" else "";
    try out.print(arena, "HTTP/1.1 {d} {s}\r\ncontent-type: {s}\r\ncontent-length: {d}\r\nconnection: {s}\r\n{s}\r\n", .{ status, reason, content_type, body.len, connection, challenge });
    try out.appendSlice(arena, body);
    try os.net.socketWriteAll(fd, out.items, timeout_ms);
}

pub fn sendHttpError(arena: Allocator, fd: std.posix.fd_t, status: u16, code: []const u8, message: []const u8, timeout_ms: u64) !void {
    var body: std.ArrayList(u8) = .empty;
    try body.appendSlice(arena, "{\"error\":");
    try util.appendJsonString(&body, arena, code);
    try body.appendSlice(arena, ",\"message\":");
    try util.appendJsonString(&body, arena, message);
    try body.appendSlice(arena, "}");
    try sendHttpRaw(arena, fd, status, "application/json", body.items, timeout_ms);
}

/// What a request path addresses. Outside hub mode only the literal
/// "/mcp" is routable, exactly as before hub mode existed.
pub const Route = union(enum) {
    local,
    /// hub: `/n`, the node listing
    list,
    /// hub: `/n/<name>/mcp`; the name is validated after the body is read
    node: []const u8,
};

pub fn routeFor(mode: config.Mode, path: []const u8) ?Route {
    if (std.mem.eql(u8, path, "/mcp")) return .local;
    if (mode != .hub) return null;
    if (std.mem.eql(u8, path, "/n")) return .list;
    const prefix = "/n/";
    const suffix = "/mcp";
    if (path.len > prefix.len + suffix.len and std.mem.startsWith(u8, path, prefix) and std.mem.endsWith(u8, path, suffix)) {
        return .{ .node = path[prefix.len .. path.len - suffix.len] };
    }
    return null;
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
pub fn serveOneRequest(io: Io, cfg: *const config.Config, stream: *Io.net.Stream, carry: *std.ArrayList(u8)) !bool {
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
        if (data.items.len >= MAX_HEADER_BYTES) {
            try sendHttpError(ra, fd, 431, "headers_too_large", "request headers too large", timeout_ms);
            return false;
        }
        const remaining = remainingMs(started, io, timeout_ms) orelse {
            try sendHttpError(ra, fd, 408, "request_timeout", "request timed out", timeout_ms);
            return false;
        };
        const n = readWithDeadline(fd, &buf, remaining) catch |err| switch (err) {
            error.RequestTimeout => {
                try sendHttpError(ra, fd, 408, "request_timeout", "request timed out", timeout_ms);
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
        try sendHttpError(ra, fd, 400, "bad_request", "BadHeaders", timeout_ms);
        return false;
    };
    // The in-loop checkpoint only fires when the accumulator is over the cap
    // WITHOUT the terminator: a single read that both crosses the cap and
    // delivers CRLFCRLF takes the `break` above and skips it (possible with
    // short reads, e.g. on Windows). Re-check the completed head length so
    // the 431 contract is independent of TCP chunking.
    if (he > MAX_HEADER_BYTES) {
        try sendHttpError(ra, fd, 431, "headers_too_large", "request headers too large", timeout_ms);
        return false;
    }
    const info = parseHead(data.items[0 .. he - 4]) catch |err| {
        const status: u16 = switch (err) {
            error.RequestTooLarge => 413,
            error.BadExpectation => 417,
            else => 400,
        };
        try sendHttpError(ra, fd, status, "bad_request", @errorName(err), timeout_ms);
        return false;
    };

    // ---- phase 2: gates, all answered from the head alone (before any body
    // byte is read, before 100 Continue) ----
    if (!hostAllowed(info.host, cfg.allowed_hosts)) {
        try sendHttpError(ra, fd, 421, "invalid_host", "Invalid Host header", timeout_ms);
        return false;
    }
    if (info.origin) |origin| {
        if (!originAllowed(origin, cfg.allowed_origins)) {
            try sendHttpError(ra, fd, 403, "forbidden_origin", "Forbidden Origin header", timeout_ms);
            return false;
        }
    }
    if (cfg.token.len != 0) {
        // Conflicting credentials count as a failed login, not as a choice.
        const presented = presentedToken(info) catch null;
        const got = presented orelse "";
        var got_hash: [32]u8 = undefined;
        var cfg_hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(got, &got_hash, .{});
        std.crypto.hash.sha2.Sha256.hash(cfg.token, &cfg_hash, .{});
        if (!std.crypto.timing_safe.eql([32]u8, got_hash, cfg_hash)) {
            // Same body for a missing and for a wrong token: the message must
            // not leak which of the two it was (constant-time semantics).
            try sendHttpError(ra, fd, 401, "unauthorized", "missing or invalid X-Node-Token header", timeout_ms);
            return false;
        }
    }
    const route = routeFor(cfg.mode, info.path) orelse {
        try sendHttpError(ra, fd, 404, "not_found", "not found", timeout_ms);
        return false;
    };
    if (!std.mem.eql(u8, info.method, "POST")) {
        try sendHttpError(ra, fd, 405, "method_not_allowed", "method not allowed", timeout_ms);
        return false;
    }
    const ct = info.content_type orelse {
        try sendHttpError(ra, fd, 415, "unsupported_media_type", "Invalid Content-Type header", timeout_ms);
        return false;
    };
    if (!contentTypeJson(ct)) {
        try sendHttpError(ra, fd, 415, "unsupported_media_type", "Invalid Content-Type header", timeout_ms);
        return false;
    }

    // ---- phase 3: global in-flight body budget. The per-request 32 MiB
    // Content-Length cap was already enforced in parseHead (-> 413). ----
    var reserved: usize = 0;
    if (cfg.inflight) |gate| {
        if (!gate.tryReserve(info.content_length)) {
            // Answered without reading the body: the budget counts in-flight
            // body bytes, and this request never becomes one.
            try sendHttpError(ra, fd, 503, "busy", "in-flight body budget exhausted", timeout_ms);
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
        const remaining = remainingMs(started, io, timeout_ms) orelse {
            try sendHttpError(ra, fd, 408, "request_timeout", "request timed out", timeout_ms);
            return false;
        };
        const want = @min(buf.len, body.len - filled);
        const n = readWithDeadline(fd, buf[0..want], remaining) catch |err| switch (err) {
            error.RequestTimeout => {
                try sendHttpError(ra, fd, 408, "request_timeout", "request timed out", timeout_ms);
                return false;
            },
            else => return err,
        };
        if (n == 0) {
            // Clean EOF mid-body: the declared body never fully arrived.
            try sendHttpError(ra, fd, 400, "bad_request", "ShortBody", timeout_ms);
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
    var keep_alive = !connectionCloseRequested(info.connection);
    if (leftover.len > 0) {
        if (keep_alive and leftover.len <= MAX_HEADER_BYTES) {
            try carry.appendSlice(std.heap.page_allocator, leftover);
        } else {
            keep_alive = false;
        }
    }

    switch (route) {
        .local => {},
        .list, .node => return serveHubRoute(ra, cfg, fd, route, body, keep_alive, timeout_ms),
    }
    const rpc = try rpc_mod.handleRpc(ra, io, cfg, body);
    try sendHttpRawMode(ra, fd, rpc.status, "application/json", rpc.body, keep_alive, timeout_ms);
    return keep_alive;
}

/// Hub routes, reached only after every check passed and the body was read.
fn serveHubRoute(ra: Allocator, cfg: *const config.Config, fd: std.posix.fd_t, route: Route, body: []const u8, keep_alive: bool, timeout_ms: u64) !bool {
    const hub: *hub_mod.Hub = @ptrCast(@alignCast(cfg.hub orelse {
        try sendHttpError(ra, fd, 503, "busy", "hub not ready", timeout_ms);
        return false;
    }));
    switch (route) {
        .local => unreachable,
        .list => {
            const out = try hub.listJson(ra);
            try sendHttpRawMode(ra, fd, 200, "application/json", out, keep_alive, timeout_ms);
            return keep_alive;
        },
        .node => |name| {
            const res = try hub_mod.forward(hub, ra, name, body, hub_mod.forwardDeadlineMs(cfg));
            switch (res) {
                .unknown_node => try sendHttpError(ra, fd, 404, "unknown_node", "no node connected under this name", timeout_ms),
                .node_disconnected => try sendHttpError(ra, fd, 502, "node_disconnected", "node link lost before the answer", timeout_ms),
                .node_timeout => try sendHttpError(ra, fd, 504, "node_timeout", "node did not answer in time", timeout_ms),
                .resp => |r| {
                    try sendHttpRawMode(ra, fd, r.status, "application/json", r.body, keep_alive, timeout_ms);
                    return keep_alive;
                },
            }
            return false;
        },
    }
}

test "host allowlist supports exact and wildcard-port patterns" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const allowed = try util.splitCsv(arena, "127.0.0.1:*,localhost:*,192.0.2.1:*");
    try std.testing.expect(hostAllowed("127.0.0.1:8341", allowed));
    try std.testing.expect(hostAllowed("192.0.2.1:8341", allowed));
    try std.testing.expect(!hostAllowed("evil.example:8341", allowed));
}

test "content length rejects overflow and conflicting duplicates" {
    try std.testing.expectError(error.RequestTooLarge, parseHead("POST /mcp HTTP/1.1\r\nContent-Length: 18446744073709551615"));
    try std.testing.expectError(error.BadContentLength, parseHead("POST /mcp HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2"));
    const info = try parseHead("POST /mcp HTTP/1.1\r\nContent-Length: 2\r\nContent-Length: 2");
    try std.testing.expectEqual(@as(usize, 2), info.content_length);
}

test "request line enforces HTTP/1.1 and exact three-token shape" {
    const ok = try parseRequestLine("POST /mcp HTTP/1.1");
    try std.testing.expectEqualStrings("POST", ok.method);
    try std.testing.expectEqualStrings("/mcp", ok.path);
    try std.testing.expectError(error.BadRequestLine, parseRequestLine("POST /mcp HTTP/1.0"));
    try std.testing.expectError(error.BadRequestLine, parseRequestLine("POST /mcp HTTP/1.1 extra"));
    try std.testing.expectError(error.BadRequestLine, parseRequestLine("POST  /mcp HTTP/1.1"));
    try std.testing.expectError(error.BadRequestLine, parseRequestLine("POST HTTP/1.1"));
    try std.testing.expectError(error.BadRequestLine, parseRequestLine("PO ST /mcp HTTP/1.1"));
    try std.testing.expectError(error.BadRequestLine, parseRequestLine("POST /m cp HTTP/1.1"));
}

test "head parser rejects ambiguous and legacy framing" {
    try std.testing.expectError(error.DuplicateHeader, parseHead("POST /mcp HTTP/1.1\r\nHost: a\r\nHost: a"));
    try std.testing.expectError(error.DuplicateHeader, parseHead("POST /mcp HTTP/1.1\r\nX-Node-Token: a\r\nx-node-token: b"));
    try std.testing.expectError(error.TransferEncodingUnsupported, parseHead("POST /mcp HTTP/1.1\r\nTransfer-Encoding: chunked"));
    try std.testing.expectError(error.TransferEncodingUnsupported, parseHead("POST /mcp HTTP/1.1\r\nContent-Length: 5\r\nTransfer-Encoding: chunked"));
    // obs-fold died with RFC 7230
    try std.testing.expectError(error.BadHeader, parseHead("POST /mcp HTTP/1.1\r\nX-A: 1\r\n folded"));
    // whitespace before the colon is a smuggling primitive
    try std.testing.expectError(error.BadHeader, parseHead("POST /mcp HTTP/1.1\r\nHost : a"));
    // control bytes in a value
    try std.testing.expectError(error.BadHeader, parseHead("POST /mcp HTTP/1.1\r\nX-A: a\x07b"));
    // header line without a colon
    try std.testing.expectError(error.BadHeader, parseHead("POST /mcp HTTP/1.1\r\njusttext"));
    // Expect: only 100-continue is legal
    const info = try parseHead("POST /mcp HTTP/1.1\r\nExpect: 100-continue");
    try std.testing.expect(info.expect_continue);
    try std.testing.expectError(error.BadExpectation, parseHead("POST /mcp HTTP/1.1\r\nExpect: magic"));
}

test "bearer authorization value parsing" {
    const scheme = "Bearer";
    // scheme is case-insensitive
    try std.testing.expectEqualStrings("abc", bearerToken(scheme ++ " abc").?);
    try std.testing.expectEqualStrings("abc", bearerToken("bearer abc").?);
    try std.testing.expectEqualStrings("abc", bearerToken("BEARER abc").?);
    // one or more spaces after the scheme, credential trimmed
    try std.testing.expectEqualStrings("abc", bearerToken(scheme ++ "   abc  ").?);
    // empty credential
    try std.testing.expect(bearerToken(scheme) == null);
    try std.testing.expect(bearerToken(scheme ++ " ") == null);
    try std.testing.expect(bearerToken(scheme ++ "    ") == null);
    // scheme must be followed by a space, not glued to the credential
    try std.testing.expect(bearerToken(scheme ++ "abc") == null);
    try std.testing.expect(bearerToken(scheme ++ "\tabc") == null);
    // other schemes count as no token
    try std.testing.expect(bearerToken("Basic dXNlcjpwYXNz") == null);
    try std.testing.expect(bearerToken("Token abc") == null);
    try std.testing.expect(bearerToken("") == null);
}

test "presented token from x-node-token and authorization headers" {
    const auth = "Authorization: Bear" ++ "er ";
    // either header alone
    const x_only = try parseHead("POST /mcp HTTP/1.1\r\nX-Node-Token: t1");
    try std.testing.expectEqualStrings("t1", (try presentedToken(x_only)).?);
    const b_only = try parseHead("POST /mcp HTTP/1.1\r\n" ++ auth ++ "t1");
    try std.testing.expectEqualStrings("t1", (try presentedToken(b_only)).?);
    // header name is case-insensitive too
    const b_lower = try parseHead("POST /mcp HTTP/1.1\r\nauthorization: bear" ++ "er " ++ "t1");
    try std.testing.expectEqualStrings("t1", (try presentedToken(b_lower)).?);
    // both present and equal: accepted
    const same = try parseHead("POST /mcp HTTP/1.1\r\nX-Node-Token: t1\r\n" ++ auth ++ "t1");
    try std.testing.expectEqualStrings("t1", (try presentedToken(same)).?);
    // both present and different: refused, never silently picked
    const diff = try parseHead("POST /mcp HTTP/1.1\r\nX-Node-Token: t1\r\n" ++ auth ++ "t2");
    try std.testing.expectError(error.ConflictingTokens, presentedToken(diff));
    // Basic is not a token; X-Node-Token still wins on its own
    const basic = try parseHead("POST /mcp HTTP/1.1\r\nAuthorization: Basic dXNlcjpwYXNz");
    try std.testing.expect((try presentedToken(basic)) == null);
    const basic_x = try parseHead("POST /mcp HTTP/1.1\r\nX-Node-Token: t1\r\nAuthorization: Basic dXNlcjpwYXNz");
    try std.testing.expectEqualStrings("t1", (try presentedToken(basic_x)).?);
    // empty bearer credential is no token
    const empty = try parseHead("POST /mcp HTTP/1.1\r\n" ++ auth);
    try std.testing.expect((try presentedToken(empty)) == null);
    // nothing presented
    const none = try parseHead("POST /mcp HTTP/1.1\r\nHost: a");
    try std.testing.expect((try presentedToken(none)) == null);
    // duplicate Authorization is an ambiguous head, like other auth headers
    try std.testing.expectError(error.DuplicateHeader, parseHead("POST /mcp HTTP/1.1\r\n" ++ auth ++ "t1\r\n" ++ auth ++ "t1"));
}

test "content type accepts only strict application/json media type" {
    try std.testing.expect(contentTypeJson("application/json"));
    try std.testing.expect(contentTypeJson("application/json; charset=utf-8"));
    try std.testing.expect(contentTypeJson("Application/JSON;charset=UTF-8"));
    try std.testing.expect(contentTypeJson("application/json; charset=\"utf-8\""));
    try std.testing.expect(!contentTypeJson("application/json-not-real"));
    try std.testing.expect(!contentTypeJson("application/jsonx"));
    try std.testing.expect(!contentTypeJson("text/json"));
    try std.testing.expect(!contentTypeJson("application/json;"));
    try std.testing.expect(!contentTypeJson("application/json; charset"));
    try std.testing.expect(!contentTypeJson("application/json; =utf-8"));
}

test "origin allowlist supports exact and wildcard-port patterns" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const allowed = try util.splitCsv(arena, "http://127.0.0.1:*,https://node.example");
    try std.testing.expect(originAllowed("http://127.0.0.1:8341", allowed));
    try std.testing.expect(originAllowed("https://node.example", allowed));
    try std.testing.expect(!originAllowed("https://evil.example", allowed));
}

test "connection close header parsing" {
    try std.testing.expect(connectionCloseRequested("close"));
    try std.testing.expect(connectionCloseRequested(" Close "));
    try std.testing.expect(connectionCloseRequested("keep-alive, close"));
    try std.testing.expect(!connectionCloseRequested(null));
    try std.testing.expect(!connectionCloseRequested("keep-alive"));
}

test "routes: listen mode keeps only /mcp; hub adds /n and /n/<name>/mcp" {
    try std.testing.expect(routeFor(.listen, "/mcp").? == .local);
    try std.testing.expect(routeFor(.listen, "/n") == null);
    try std.testing.expect(routeFor(.listen, "/n/pc/mcp") == null);
    try std.testing.expect(routeFor(.node, "/n") == null);
    try std.testing.expect(routeFor(.hub, "/mcp").? == .local);
    try std.testing.expect(routeFor(.hub, "/n").? == .list);
    try std.testing.expectEqualStrings("pc", routeFor(.hub, "/n/pc/mcp").?.node);
    // invalid names reach the relay, which answers unknown_node
    try std.testing.expectEqualStrings("a/b", routeFor(.hub, "/n/a/b/mcp").?.node);
    try std.testing.expect(routeFor(.hub, "/n//mcp") == null);
    try std.testing.expect(routeFor(.hub, "/n/") == null);
    try std.testing.expect(routeFor(.hub, "/n/pc") == null);
    try std.testing.expect(routeFor(.hub, "/mcp/") == null);
}

test "content length rejects malformed values and documents plus prefix" {
    // Documents the std.fmt.parseInt behavior surfaced by parseHead's
    // content-length handling: garbage, empty, and negative values all
    // collapse to BadContentLength ("-" on an unsigned parse fails, empty
    // fails InvalidCharacter), while a leading "+" IS accepted by parseInt
    // and parses to its plain value.
    try std.testing.expectError(error.BadContentLength, parseHead("POST /mcp HTTP/1.1\r\nContent-Length: abc"));
    try std.testing.expectError(error.BadContentLength, parseHead("POST /mcp HTTP/1.1\r\nContent-Length:"));
    try std.testing.expectError(error.BadContentLength, parseHead("POST /mcp HTTP/1.1\r\nContent-Length: -1"));
    try std.testing.expectEqual(@as(usize, 5), (try parseHead("POST /mcp HTTP/1.1\r\nContent-Length: +5")).content_length);
}

test "expect continue matching is case insensitive and whitespace trimmed" {
    try std.testing.expect((try parseHead("POST /mcp HTTP/1.1\r\nExpect: 100-continue")).expect_continue);
    try std.testing.expect((try parseHead("POST /mcp HTTP/1.1\r\nEXPECT: 100-Continue")).expect_continue);
    try std.testing.expect((try parseHead("POST /mcp HTTP/1.1\r\nexpect:  100-continue  ")).expect_continue);
    // Non-100-continue expectations are rejected outright by parseHead
    // (BadExpectation) rather than silently ignored.
    try std.testing.expectError(error.BadExpectation, parseHead("POST /mcp HTTP/1.1\r\nExpect: garbage"));
    try std.testing.expect(!(try parseHead("POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:8341")).expect_continue);
    try std.testing.expect(!(try parseHead("POST /mcp HTTP/1.1")).expect_continue);
}

// ---------------------------------------------------------------------------
// fd-level framing tests (POSIX only).
//
// Every fd-level test drives the real serve loop (serveOneRequest) over a
// loopback TCP pair: the peer end plays the HTTP client (writes request
// bytes, reads back the 100-continue interim response and the final status
// line), the subject end is the accepted stream serveOneRequest owns. A
// genuine TCP pair is required because setSocketTimeouts arms TCP_NODELAY
// and socket timeouts, which an AF_UNIX socketpair cannot carry. Windows
// skips these at runtime; the helpers below are referenced only from
// comptime-gated branches, so they are never analyzed for that target.
// ---------------------------------------------------------------------------

const builtin = @import("builtin");

const TestSock = struct {
    peer: std.posix.fd_t,
    subject: std.posix.fd_t,
};

/// A connected TCP pair over the loopback: `peer` is the client side,
/// `subject` the accepted server side. The listener is closed right after
/// the accept: both ends live on as plain fds owned by the caller.
fn testSocketPair(io: Io) !TestSock {
    const any = try Io.net.IpAddress.parse("127.0.0.1", 0);
    var server = try any.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    const addr = server.socket.address;
    const client = try addr.connect(io, .{ .mode = .stream });
    const server_side = try server.accept(io);
    return .{ .peer = client.socket.handle, .subject = server_side.socket.handle };
}

fn testShutdownWrite(fd: std.posix.fd_t) void {
    if (comptime builtin.os.tag == .linux) {
        _ = std.os.linux.shutdown(fd, std.os.linux.SHUT.WR);
    } else {
        // libc POSIX path (macOS et al.).
        _ = std.c.shutdown(fd, std.posix.SHUT.WR);
    }
}

fn testSocketReadable(fd: std.posix.fd_t) bool {
    return testWaitReadable(fd, 0);
}

/// Polls `fd` for readability, waiting up to `timeout_ms`. Returns false on
/// timeout or poll failure, so callers can fail the test explicitly instead
/// of hanging on a blocking read.
fn testWaitReadable(fd: std.posix.fd_t, timeout_ms: i32) bool {
    var fds = [_]std.posix.pollfd{.{
        .fd = fd,
        .events = std.posix.POLL.IN,
        .revents = 0,
    }};
    const n = std.posix.poll(&fds, timeout_ms) catch return false;
    return n == 1 and (fds[0].revents & std.posix.POLL.IN) != 0;
}

/// Writes `bytes` from a helper thread. The writer normally finishes before
/// the fds close, so `catch {}` only guards a close race.
fn testWriteAllIgnoringErrors(fd: std.posix.fd_t, bytes: []const u8) void {
    os.writeAllFd(fd, bytes) catch {};
}

/// Minimal listen-mode config for the fd-level tests: empty token (auth gate
/// passes), a single wildcard-port allowed host, no in-flight budget.
fn testServeConfig() config.Config {
    return .{
        .name = "test-node",
        .host = "127.0.0.1",
        .port = 8341,
        .token = "",
        .allowed_hosts = @constCast(&[_][]const u8{"127.0.0.1:*"}),
        .allowed_origins = @constCast(&[_][]const u8{}),
        .max_out = 4096,
        .socket_timeout_s = 2,
        .max_conn = 8,
        .max_sessions = 8,
        .session_ttl_s = 60,
        .max_inflight_bytes = 1024 * 1024,
    };
}

const TestServeOutcome = struct {
    keep: bool,
    /// The bytes the client (peer) received: the 100-continue interim
    /// response first, then the final response, when both were sent.
    response: []const u8,
};

/// Runs one serveOneRequest cycle on the subject end and returns what the
/// client saw. The response is read only when the peer reports readability
/// within 2 s, so the clean-EOF path (nothing written) is testable too.
fn testServeRequest(io: Io, arena: Allocator, sock: TestSock, carry: *std.ArrayList(u8)) !TestServeOutcome {
    var stream = Io.net.Stream{ .socket = .{ .handle = sock.subject, .address = undefined } };
    const cfg = testServeConfig();
    const keep = try serveOneRequest(io, &cfg, &stream, carry);
    var response: []const u8 = "";
    // A response may span several writes (e.g. an interim 100 Continue
    // followed by the final answer), and some platforms deliver each write
    // as a separate read. Keep reading until the peer goes quiet.
    var collected: std.ArrayList(u8) = .empty;
    var wait_ms: i32 = 2000;
    while (testWaitReadable(sock.peer, wait_ms)) {
        var buf: [4096]u8 = undefined;
        const m = try std.posix.read(sock.peer, &buf);
        if (m == 0) break;
        try collected.appendSlice(arena, buf[0..m]);
        wait_ms = 200;
    }
    response = collected.items;
    return .{ .keep = keep, .response = response };
}

test "read http request extracts full post request" {
    if (comptime builtin.os.tag == .windows) {
        return error.SkipZigTest;
    } else {
        var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var threaded = Io.Threaded.init(std.heap.page_allocator, .{});
        defer threaded.deinit();
        const io = threaded.io();

        // A complete, well-formed POST through every gate: the head is
        // parsed, the body delivered byte-exact, and the JSON-RPC layer
        // answers 202 for a notification — proof the framing survived.
        const body = "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}";
        const request = try std.fmt.allocPrint(arena, "POST /mcp HTTP/1.1\r\n" ++
            "Host: 127.0.0.1:8341\r\n" ++
            "Content-Type: application/json\r\n" ++
            "Content-Length: {d}\r\n" ++
            "\r\n" ++
            "{s}", .{ body.len, body });

        const sock = try testSocketPair(io);
        defer os.closeFd(sock.peer);
        defer os.closeFd(sock.subject);
        try os.writeAllFd(sock.peer, request);

        var carry: std.ArrayList(u8) = .empty;
        const out = try testServeRequest(io, arena, sock, &carry);
        try std.testing.expect(std.mem.startsWith(u8, out.response, "HTTP/1.1 202"));
    }
}

test "read http request extracts lowercase header names" {
    if (comptime builtin.os.tag == .windows) {
        return error.SkipZigTest;
    } else {
        var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var threaded = Io.Threaded.init(std.heap.page_allocator, .{});
        defer threaded.deinit();
        const io = threaded.io();

        // Header names arrive lowercased, as some clients and proxies send
        // them: every field must still be matched case-insensitively.
        const request = "POST /mcp HTTP/1.1\r\n" ++
            "host: 127.0.0.1:8341\r\n" ++
            "content-type: application/json\r\n" ++
            "content-length: 5\r\n" ++
            "\r\n" ++
            "hello";

        const sock = try testSocketPair(io);
        defer os.closeFd(sock.peer);
        defer os.closeFd(sock.subject);
        try os.writeAllFd(sock.peer, request);

        var carry: std.ArrayList(u8) = .empty;
        const out = try testServeRequest(io, arena, sock, &carry);
        // "hello" is not JSON: the RPC layer answers 400 parse error, which
        // still proves the lowercase head passed every gate.
        try std.testing.expect(std.mem.startsWith(u8, out.response, "HTTP/1.1 400"));
    }
}

test "read http request body containing crlfcrlf sequence" {
    if (comptime builtin.os.tag == .windows) {
        return error.SkipZigTest;
    } else {
        var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var threaded = Io.Threaded.init(std.heap.page_allocator, .{});
        defer threaded.deinit();
        const io = threaded.io();

        // The first CRLFCRLF must terminate the head; a CRLFCRLF inside
        // the body is ordinary body payload bounded by Content-Length.
        const body = "{\"v\":\"a\r\n\r\nb\"}";
        const request = try std.fmt.allocPrint(arena, "POST /mcp HTTP/1.1\r\n" ++
            "Host: 127.0.0.1:8341\r\n" ++
            "Content-Type: application/json\r\n" ++
            "Content-Length: {d}\r\n" ++
            "\r\n" ++
            "{s}GARBAGE", .{ body.len, body });

        const sock = try testSocketPair(io);
        defer os.closeFd(sock.peer);
        defer os.closeFd(sock.subject);
        try os.writeAllFd(sock.peer, request);

        var carry: std.ArrayList(u8) = .empty;
        const out = try testServeRequest(io, arena, sock, &carry);
        // Three observable facts pin the framing down:
        //  * 400 with -32700: raw CR/LF inside a JSON string makes the body
        //    invalid JSON, so the RPC layer answered parse error — the body
        //    bytes (including the embedded CRLFCRLF) reached the parser.
        //  * carry == "GARBAGE": the serve loop consumed exactly
        //    Content-Length body bytes; the first CRLFCRLF in the stream
        //    terminated the head, not the one inside the body.
        try std.testing.expect(std.mem.startsWith(u8, out.response, "HTTP/1.1 400"));
        try std.testing.expect(std.mem.indexOf(u8, out.response, "-32700") != null);
        try std.testing.expectEqualStrings("GARBAGE", carry.items);
    }
}

test "read http request sends 100 continue for expect header" {
    if (comptime builtin.os.tag == .windows) {
        return error.SkipZigTest;
    } else {
        var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var threaded = Io.Threaded.init(std.heap.page_allocator, .{});
        defer threaded.deinit();
        const io = threaded.io();

        const body = "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}";
        const request = try std.fmt.allocPrint(arena, "POST /mcp HTTP/1.1\r\n" ++
            "Host: 127.0.0.1:8341\r\n" ++
            "Content-Type: application/json\r\n" ++
            "Expect: 100-continue\r\n" ++
            "Content-Length: {d}\r\n" ++
            "\r\n" ++
            "{s}", .{ body.len, body });

        const sock = try testSocketPair(io);
        defer os.closeFd(sock.peer);
        defer os.closeFd(sock.subject);
        try os.writeAllFd(sock.peer, request);

        var carry: std.ArrayList(u8) = .empty;
        const out = try testServeRequest(io, arena, sock, &carry);

        // The interim response was written before the body read started, so
        // it is buffered on the peer end ahead of the final response.
        try std.testing.expect(std.mem.startsWith(u8, out.response, "HTTP/1.1 100 Continue\r\n\r\n"));
        // The request body still arrived in full: the final answer is 202.
        try std.testing.expect(std.mem.indexOf(u8, out.response, "HTTP/1.1 202") != null);
    }
}

test "read http request ignores non continue expect value" {
    if (comptime builtin.os.tag == .windows) {
        return error.SkipZigTest;
    } else {
        var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var threaded = Io.Threaded.init(std.heap.page_allocator, .{});
        defer threaded.deinit();
        const io = threaded.io();

        // Any Expect value other than 100-continue is rejected outright by
        // the strict parser (417), never silently ignored: no interim
        // response is sent and the connection is closed.
        const request = "POST /mcp HTTP/1.1\r\n" ++
            "Host: 127.0.0.1:8341\r\n" ++
            "Expect: tokens-still-valid\r\n" ++
            "Content-Length: 5\r\n" ++
            "\r\n" ++
            "hello";

        const sock = try testSocketPair(io);
        defer os.closeFd(sock.peer);
        defer os.closeFd(sock.subject);
        try os.writeAllFd(sock.peer, request);

        var carry: std.ArrayList(u8) = .empty;
        const out = try testServeRequest(io, arena, sock, &carry);
        try std.testing.expect(std.mem.startsWith(u8, out.response, "HTTP/1.1 417"));
        try std.testing.expect(std.mem.indexOf(u8, out.response, "HTTP/1.1 100") == null);
    }
}

test "read http request skips 100 continue without body" {
    if (comptime builtin.os.tag == .windows) {
        return error.SkipZigTest;
    } else {
        var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var threaded = Io.Threaded.init(std.heap.page_allocator, .{});
        defer threaded.deinit();
        const io = threaded.io();

        // The interim response only buys time for a body that is actually
        // coming: with no Content-Length at all — or a zero one — there is
        // nothing to continue into and no interim is sent. The RPC layer
        // answers 400 parse error for the empty body either way.
        const no_length = "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:8341\r\nContent-Type: application/json\r\nExpect: 100-continue\r\n\r\n";
        const zero_length = "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:8341\r\nContent-Type: application/json\r\nExpect: 100-continue\r\nContent-Length: 0\r\n\r\n";

        for ([_][]const u8{ no_length, zero_length }) |request| {
            const sock = try testSocketPair(io);
            defer os.closeFd(sock.peer);
            defer os.closeFd(sock.subject);
            try os.writeAllFd(sock.peer, request);

            var carry: std.ArrayList(u8) = .empty;
            const out = try testServeRequest(io, arena, sock, &carry);
            try std.testing.expect(std.mem.startsWith(u8, out.response, "HTTP/1.1 400"));
            // No interim response was sent: the first buffered bytes are the
            // final answer, not a 100 Continue.
            try std.testing.expect(!std.mem.startsWith(u8, out.response, "HTTP/1.1 100"));
        }
    }
}

test "read http request rejects malformed content length" {
    if (comptime builtin.os.tag == .windows) {
        return error.SkipZigTest;
    } else {
        var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var threaded = Io.Threaded.init(std.heap.page_allocator, .{});
        defer threaded.deinit();
        const io = threaded.io();

        // Garbage, empty, and negative values all answer 400 with the
        // BadContentLength reason named in the response body.
        for ([_][]const u8{
            "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:8341\r\nContent-Length: abc\r\n\r\n",
            "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:8341\r\nContent-Length:\r\n\r\n",
            "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:8341\r\nContent-Length: -1\r\n\r\n",
        }) |request| {
            const sock = try testSocketPair(io);
            defer os.closeFd(sock.peer);
            defer os.closeFd(sock.subject);
            try os.writeAllFd(sock.peer, request);

            var carry: std.ArrayList(u8) = .empty;
            const out = try testServeRequest(io, arena, sock, &carry);
            try std.testing.expect(std.mem.startsWith(u8, out.response, "HTTP/1.1 400"));
            try std.testing.expect(std.mem.indexOf(u8, out.response, "BadContentLength") != null);
        }
    }
}

test "read http request rejects conflicting duplicate content length" {
    if (comptime builtin.os.tag == .windows) {
        return error.SkipZigTest;
    } else {
        var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var threaded = Io.Threaded.init(std.heap.page_allocator, .{});
        defer threaded.deinit();
        const io = threaded.io();

        // Conflicting duplicates (request smuggling vector) answer 400.
        {
            const sock = try testSocketPair(io);
            defer os.closeFd(sock.peer);
            defer os.closeFd(sock.subject);
            try os.writeAllFd(sock.peer, "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:8341\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nAB");

            var carry: std.ArrayList(u8) = .empty;
            const out = try testServeRequest(io, arena, sock, &carry);
            try std.testing.expect(std.mem.startsWith(u8, out.response, "HTTP/1.1 400"));
            try std.testing.expect(std.mem.indexOf(u8, out.response, "BadContentLength") != null);
        }

        // Identical duplicates are accepted: the body is delivered in full.
        {
            const body = "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}";
            const sock = try testSocketPair(io);
            defer os.closeFd(sock.peer);
            defer os.closeFd(sock.subject);
            try os.writeAllFd(sock.peer, try std.fmt.allocPrint(arena, "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:8341\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nContent-Length: {d}\r\n\r\n{s}", .{ body.len, body.len, body }));

            var carry: std.ArrayList(u8) = .empty;
            const out = try testServeRequest(io, arena, sock, &carry);
            try std.testing.expect(std.mem.startsWith(u8, out.response, "HTTP/1.1 202"));
        }
    }
}

test "read http request rejects oversized content length" {
    if (comptime builtin.os.tag == .windows) {
        return error.SkipZigTest;
    } else {
        var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var threaded = Io.Threaded.init(std.heap.page_allocator, .{});
        defer threaded.deinit();
        const io = threaded.io();

        // Cheap by design: only the header is sent; the serve loop must
        // reject on Content-Length alone without waiting for body bytes.
        const request = try std.fmt.allocPrint(arena, "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:8341\r\nContent-Length: {d}\r\n\r\n", .{MAX_BODY_BYTES + 1});
        const sock = try testSocketPair(io);
        defer os.closeFd(sock.peer);
        defer os.closeFd(sock.subject);
        try os.writeAllFd(sock.peer, request);

        var carry: std.ArrayList(u8) = .empty;
        const out = try testServeRequest(io, arena, sock, &carry);
        try std.testing.expect(std.mem.startsWith(u8, out.response, "HTTP/1.1 413"));
        try std.testing.expect(std.mem.indexOf(u8, out.response, "RequestTooLarge") != null);
    }
}

test "read http request short body after eof errors" {
    if (comptime builtin.os.tag == .windows) {
        return error.SkipZigTest;
    } else {
        var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var threaded = Io.Threaded.init(std.heap.page_allocator, .{});
        defer threaded.deinit();
        const io = threaded.io();

        // Content-Length announces 10 bytes, only 5 arrive before EOF: the
        // declared body never fully arrived and the client is told so.
        const sock = try testSocketPair(io);
        defer os.closeFd(sock.peer);
        defer os.closeFd(sock.subject);
        try os.writeAllFd(sock.peer, "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:8341\r\nContent-Type: application/json\r\nContent-Length: 10\r\n\r\nfive!");
        testShutdownWrite(sock.peer);

        var carry: std.ArrayList(u8) = .empty;
        const out = try testServeRequest(io, arena, sock, &carry);
        try std.testing.expect(std.mem.startsWith(u8, out.response, "HTTP/1.1 400"));
        try std.testing.expect(std.mem.indexOf(u8, out.response, "ShortBody") != null);
    }
}

test "read http request unterminated headers error on eof" {
    if (comptime builtin.os.tag == .windows) {
        return error.SkipZigTest;
    } else {
        var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var threaded = Io.Threaded.init(std.heap.page_allocator, .{});
        defer threaded.deinit();
        const io = threaded.io();

        // Headers never terminated by CRLFCRLF, then EOF: BadHeaders.
        // LF-only line endings never form the CRLFCRLF terminator either.
        for ([_][]const u8{
            "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:8341\r\n",
            "POST /mcp HTTP/1.1\nHost: 127.0.0.1:8341\n\n",
        }) |request| {
            const sock = try testSocketPair(io);
            defer os.closeFd(sock.peer);
            defer os.closeFd(sock.subject);
            try os.writeAllFd(sock.peer, request);
            testShutdownWrite(sock.peer);

            var carry: std.ArrayList(u8) = .empty;
            const out = try testServeRequest(io, arena, sock, &carry);
            try std.testing.expect(std.mem.startsWith(u8, out.response, "HTTP/1.1 400"));
            try std.testing.expect(std.mem.indexOf(u8, out.response, "BadHeaders") != null);
        }
    }
}

test "read http request clean eof on empty socket" {
    if (comptime builtin.os.tag == .windows) {
        return error.SkipZigTest;
    } else {
        var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var threaded = Io.Threaded.init(std.heap.page_allocator, .{});
        defer threaded.deinit();
        const io = threaded.io();

        // A keep-alive connection closed before any request bytes arrived:
        // the serve loop ends quietly — no zombie 400 into a dying socket.
        const sock = try testSocketPair(io);
        defer os.closeFd(sock.peer);
        defer os.closeFd(sock.subject);
        testShutdownWrite(sock.peer);

        var carry: std.ArrayList(u8) = .empty;
        const out = try testServeRequest(io, arena, sock, &carry);
        try std.testing.expectEqual(false, out.keep);
        try std.testing.expectEqual(@as(usize, 0), out.response.len);
    }
}

test "read http request oversized headers rejected" {
    if (comptime builtin.os.tag == .windows) {
        return error.SkipZigTest;
    } else {
        var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var threaded = Io.Threaded.init(std.heap.page_allocator, .{});
        defer threaded.deinit();
        const io = threaded.io();

        // ~69KB of header bytes with no CRLFCRLF terminator. The payload is
        // written from a helper thread: once the serve loop stops reading
        // (it answers 431 at the 64 KiB cap), the loopback stack can apply
        // backpressure to the sender, so a blocking write on the test thread
        // would deadlock before the answer is even read.
        const oversized = try arena.alloc(u8, MAX_HEADER_BYTES + 5 * 1024);
        @memset(oversized, 'A');

        const sock = try testSocketPair(io);
        const writer = std.Thread.spawn(.{}, testWriteAllIgnoringErrors, .{ sock.peer, oversized }) catch |err| {
            os.closeFd(sock.peer);
            os.closeFd(sock.subject);
            return err;
        };
        // Both ends close before the join so the writer always finishes: a
        // write blocked on a full socket buffer fails once its peer end is
        // closed, and a late write hits an already-closed fd.
        defer writer.join();
        defer os.closeFd(sock.peer);
        defer os.closeFd(sock.subject);

        var carry: std.ArrayList(u8) = .empty;
        const out = try testServeRequest(io, arena, sock, &carry);
        try std.testing.expect(std.mem.startsWith(u8, out.response, "HTTP/1.1 431"));
        try std.testing.expect(std.mem.indexOf(u8, out.response, "headers_too_large") != null);
    }
}

test "read http request rejects malformed request line" {
    if (comptime builtin.os.tag == .windows) {
        return error.SkipZigTest;
    } else {
        var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var threaded = Io.Threaded.init(std.heap.page_allocator, .{});
        defer threaded.deinit();
        const io = threaded.io();

        // A request line with no path component.
        const sock = try testSocketPair(io);
        defer os.closeFd(sock.peer);
        defer os.closeFd(sock.subject);
        try os.writeAllFd(sock.peer, "POST\r\n\r\n");

        var carry: std.ArrayList(u8) = .empty;
        const out = try testServeRequest(io, arena, sock, &carry);
        try std.testing.expect(std.mem.startsWith(u8, out.response, "HTTP/1.1 400"));
        try std.testing.expect(std.mem.indexOf(u8, out.response, "BadRequestLine") != null);
    }
}

test "read http request keeps pipelined bytes as carry for the next request" {
    if (comptime builtin.os.tag == .windows) {
        return error.SkipZigTest;
    } else {
        var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var threaded = Io.Threaded.init(std.heap.page_allocator, .{});
        defer threaded.deinit();
        const io = threaded.io();

        // Bytes past header_end + Content-Length are the coalesced head of
        // the next pipelined request: the serve loop never desyncs on them —
        // the first request is answered intact and the tail is carried over
        // for the next serveOneRequest call on the same connection.
        const body = "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}";
        const request = try std.fmt.allocPrint(arena, "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:8341\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}GARBAGE-SECOND-REQUEST", .{ body.len, body });

        const sock = try testSocketPair(io);
        defer os.closeFd(sock.peer);
        defer os.closeFd(sock.subject);
        try os.writeAllFd(sock.peer, request);

        var carry: std.ArrayList(u8) = .empty;
        const out = try testServeRequest(io, arena, sock, &carry);
        try std.testing.expect(std.mem.startsWith(u8, out.response, "HTTP/1.1 202"));
        try std.testing.expectEqualStrings("GARBAGE-SECOND-REQUEST", carry.items);
    }
}

test "read http request rejects chunked transfer encoding" {
    if (comptime builtin.os.tag == .windows) {
        return error.SkipZigTest;
    } else {
        var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var threaded = Io.Threaded.init(std.heap.page_allocator, .{});
        defer threaded.deinit();
        const io = threaded.io();

        // Transfer-Encoding is refused outright (request smuggling guard):
        // the answer names the error, and chunk frames written afterwards
        // stay unread in the socket — the framing was never interpreted.
        const sock = try testSocketPair(io);
        defer os.closeFd(sock.peer);
        defer os.closeFd(sock.subject);
        try os.writeAllFd(sock.peer, "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:8341\r\nTransfer-Encoding: chunked\r\n\r\n");

        var carry: std.ArrayList(u8) = .empty;
        const out = try testServeRequest(io, arena, sock, &carry);
        try std.testing.expect(std.mem.startsWith(u8, out.response, "HTTP/1.1 400"));
        try std.testing.expect(std.mem.indexOf(u8, out.response, "TransferEncodingUnsupported") != null);

        // Frames written after the serve loop returned stay unread in the
        // socket: chunk framing was never interpreted.
        try os.writeAllFd(sock.peer, "5\r\nhello\r\n0\r\n\r\n");
        try std.testing.expect(testSocketReadable(sock.subject));
    }
}

test "read http request without content length has empty body" {
    if (comptime builtin.os.tag == .windows) {
        return error.SkipZigTest;
    } else {
        var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var threaded = Io.Threaded.init(std.heap.page_allocator, .{});
        defer threaded.deinit();
        const io = threaded.io();

        // No Content-Length: the body is empty and the serve loop treats
        // the bytes after the header terminator as the head of the next
        // request, carrying them over instead of reading them as body.
        // Proof of emptiness: the RPC layer sees an empty body (400 parse
        // error), never the 202 the unread notification would produce;
        // proof of preservation: the tail lands in the carry buffer whole.
        const tail = "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}";
        const request = "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:8341\r\nContent-Type: application/json\r\n\r\n" ++ tail;

        const sock = try testSocketPair(io);
        defer os.closeFd(sock.peer);
        defer os.closeFd(sock.subject);
        try os.writeAllFd(sock.peer, request);

        var carry: std.ArrayList(u8) = .empty;
        const out = try testServeRequest(io, arena, sock, &carry);
        try std.testing.expect(std.mem.startsWith(u8, out.response, "HTTP/1.1 400"));
        try std.testing.expectEqualStrings(tail, carry.items);
    }
}
