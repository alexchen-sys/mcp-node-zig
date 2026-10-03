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
