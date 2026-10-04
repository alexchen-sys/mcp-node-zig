//! Outbound node mode: dial the hub, authenticate, then serve MCP requests
//! that arrive as REQ frames with the same rpc.handleRpc as the HTTP path.
//!
//! One link at a time. The dialing thread runs the handshake and then the
//! reader loop; a pinger thread sends PING every 15 s; every REQ runs on its
//! own worker thread, bounded by cfg.max_conn and by the shared in-flight
//! body budget, exactly like an HTTP request. RESP frames are written under
//! the per-link writer mutex. The link object is reference counted: workers
//! still running a long tool call when the link drops keep it alive, their
//! late RESP write simply fails, and the socket closes on the last release.
//! Exec sessions live in the SessionStore, not in the link, so they survive
//! a reconnect.
//!
//! Reconnect: full-jitter exponential backoff (random in [0, cap], cap from
//! 0.5 s doubling to 30 s), reset once a link stayed up for 60 s.

const std = @import("std");
const Io = std.Io;
const os = @import("os.zig");
const util = @import("util.zig");
const link = @import("link.zig");
const config = @import("config.zig");
const rpc_mod = @import("rpc.zig");

pub const PING_INTERVAL_MS: u64 = 15 * 1000;
pub const DEAD_AFTER_MS: u64 = 45 * 1000;
pub const HANDSHAKE_MS: u64 = 10 * 1000;
pub const BACKOFF_MIN_MS: u64 = 500;
pub const BACKOFF_MAX_MS: u64 = 30 * 1000;
pub const HEALTHY_AFTER_MS: u64 = 60 * 1000;
const PINGER_STEP_MS: u64 = 250;

/// Process-wide node state shared by consecutive links.
pub const Node = struct {
    io: Io,
    cfg: *const config.Config,
    /// REQ workers running across all links (old links included).
    workers: std.atomic.Value(u32) = .init(0),
};

/// Backoff ceiling for the given consecutive-failure count.
pub fn backoffCapMs(attempt: u32) u64 {
    const shift: u6 = @intCast(@min(attempt, 16));
    return @min(BACKOFF_MAX_MS, BACKOFF_MIN_MS << shift);
}

fn jitterMs(io: Io, cap: u64) u64 {
    var raw: [8]u8 = undefined;
    io.random(&raw);
    return std.mem.readInt(u64, &raw, .little) % (cap + 1);
}

/// Dial loop; never returns under normal operation.
pub fn run(node: *Node) void {
    const ep = node.cfg.connect orelse return;
    var attempt: u32 = 0;
    while (true) {
        const up_ms = connectOnce(node, ep) catch |err| blk: {
            std.debug.print("node link: {s}\n", .{@errorName(err)});
            break :blk 0;
        };
        if (up_ms >= HEALTHY_AFTER_MS) attempt = 0;
        const wait = jitterMs(node.io, backoffCapMs(attempt));
        if (attempt < 16) attempt += 1;
        os.sleepMs(wait);
    }
}

fn connectOnce(node: *Node, ep: config.Endpoint) !u64 {
    const stream = try dial(node.io, ep);
    std.debug.print("node link: connected to {s}:{d}\n", .{ ep.host, ep.port });
    return session(node, stream);
}

fn dial(io: Io, ep: config.Endpoint) !Io.net.Stream {
    if (Io.net.IpAddress.parse(ep.host, ep.port)) |addr| {
        return addr.connect(io, .{ .mode = .stream });
    } else |_| {}
    const host = try Io.net.HostName.init(ep.host);
    return host.connect(io, ep.port, .{ .mode = .stream });
}

/// Run one link on a connected stream (takes ownership). Returns how long
/// the link was up after WELCOME, in milliseconds.
pub fn session(node: *Node, stream: Io.net.Stream) !u64 {
    const io = node.io;
    const ln = std.heap.page_allocator.create(Link) catch {
        stream.close(io);
        return error.OutOfMemory;
    };
    ln.* = .{ .node = node, .stream = stream };
    defer ln.release();
    const fd = stream.socket.handle;
    const timeout_ms = @as(u64, node.cfg.socket_timeout_s) * 1000;
    os.net.setSocketTimeouts(fd, node.cfg.socket_timeout_s) catch return error.SocketOptionFailed;

    try handshake(node, fd, timeout_ms);
    const up_since = std.Io.Clock.awake.now(io);
    std.debug.print("node link: welcome as '{s}'\n", .{node.cfg.name});

    // The pinger is joined (it polls `dead` every 250 ms), so it never
    // outlives the session; only REQ workers can, via their reference.
    const ping_thread = try std.Thread.spawn(.{}, pinger, .{ln});
    defer ping_thread.join();
    defer ln.kill();

    readLoop(ln) catch |err| {
        std.debug.print("node link lost: {s}\n", .{@errorName(err)});
    };
    const up = up_since.untilNow(io, .awake).toMilliseconds();
    return if (up > 0) @intCast(up) else 0;
}

fn handshake(node: *Node, fd: os.net.Handle, timeout_ms: u64) !void {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const ch = try link.readFrame(arena, fd, link.MAX_HANDSHAKE_PAYLOAD, HANDSHAKE_MS);
    if (ch.kind != .challenge or ch.payload.len != link.NONCE_LEN) return error.BadChallenge;
    const nonce: *const [link.NONCE_LEN]u8 = ch.payload[0..link.NONCE_LEN];
    const hello = try link.buildHello(arena, node.cfg.connect_secret, nonce, node.cfg.name);
    try link.writeFrame(fd, .hello, 0, hello, timeout_ms);

    const reply = try link.readFrame(arena, fd, link.MAX_HANDSHAKE_PAYLOAD, HANDSHAKE_MS);
    switch (reply.kind) {
        .welcome => {},
        .goaway => {
            std.debug.print("node link: hub refused: {s}\n", .{reply.payload});
            return error.Refused;
        },
        else => return error.BadWelcome,
    }
}

const Link = struct {
    node: *Node,
    stream: Io.net.Stream,
    write_mutex: std.Io.Mutex = .init,
    refs: std.atomic.Value(u32) = .init(1),
    dead: std.atomic.Value(bool) = .init(false),

    fn retain(self: *Link) void {
        _ = self.refs.fetchAdd(1, .monotonic);
    }

    fn release(self: *Link) void {
        if (self.refs.fetchSub(1, .acq_rel) != 1) return;
        self.stream.close(self.node.io);
        std.heap.page_allocator.destroy(self);
    }

    /// Mark dead and wake the reader; the socket closes on the last release.
    fn kill(self: *Link) void {
        if (self.dead.swap(true, .acq_rel)) return;
        self.stream.shutdown(self.node.io, .both) catch {};
    }

    fn writeFrame(self: *Link, kind: link.FrameType, sid: u32, parts: []const []const u8) void {
        if (self.dead.load(.acquire)) return;
        const io = self.node.io;
        const timeout_ms = @as(u64, self.node.cfg.socket_timeout_s) * 1000;
        self.write_mutex.lockUncancelable(io);
        defer self.write_mutex.unlock(io);
        link.writeFrameParts(self.stream.socket.handle, kind, sid, parts, timeout_ms) catch self.kill();
    }

    fn writeResp(self: *Link, sid: u32, status: u16, body: []const u8) void {
        var prefix: [2]u8 = undefined;
        std.mem.writeInt(u16, &prefix, status, .big);
        self.writeFrame(.resp, sid, &.{ &prefix, body });
    }
};

fn readLoop(ln: *Link) !void {
    const gpa = std.heap.page_allocator;
    const fd = ln.stream.socket.handle;
    while (!ln.dead.load(.acquire)) {
        const frame = try link.readFrame(gpa, fd, link.MAX_PAYLOAD, DEAD_AFTER_MS);
        switch (frame.kind) {
            .req => dispatch(ln, frame.stream_id, frame.payload), // takes payload
            .ping => {
                defer gpa.free(frame.payload);
                ln.writeFrame(.pong, frame.stream_id, &.{frame.payload});
            },
            .pong => gpa.free(frame.payload),
            .goaway => {
                defer gpa.free(frame.payload);
                std.debug.print("node link: hub said goaway: {s}\n", .{frame.payload});
                return error.GoAway;
            },
            else => {
                gpa.free(frame.payload);
                return error.UnexpectedFrame;
            },
        }
    }
}

const Job = struct { ln: *Link, sid: u32, body: []u8, reserved: usize };

fn dispatch(ln: *Link, sid: u32, body: []u8) void {
    const gpa = std.heap.page_allocator;
    const node = ln.node;
    if (node.workers.fetchAdd(1, .acq_rel) >= node.cfg.max_conn) {
        _ = node.workers.fetchSub(1, .acq_rel);
        gpa.free(body);
        ln.writeResp(sid, 503, "{\"error\":\"busy\",\"message\":\"too many connections\"}");
        return;
    }
    var reserved: usize = 0;
    if (node.cfg.inflight) |budget| {
        if (!budget.tryReserve(body.len)) {
            _ = node.workers.fetchSub(1, .acq_rel);
            gpa.free(body);
            ln.writeResp(sid, 503, "{\"error\":\"busy\",\"message\":\"in-flight body budget exhausted\"}");
            return;
        }
        reserved = body.len;
    }
    const job = gpa.create(Job) catch {
        finishJob(.{ .ln = ln, .sid = sid, .body = body, .reserved = reserved });
        ln.writeResp(sid, 503, "{\"error\":\"busy\",\"message\":\"out of memory\"}");
        return;
    };
    ln.retain();
    job.* = .{ .ln = ln, .sid = sid, .body = body, .reserved = reserved };
    const t = std.Thread.spawn(.{}, worker, .{job}) catch {
        const copy = job.*;
        gpa.destroy(job);
        finishJob(copy);
        ln.writeResp(sid, 503, "{\"error\":\"busy\",\"message\":\"too many connections\"}");
        ln.release();
        return;
    };
    t.detach();
}

/// Release everything a dispatched REQ holds except the link reference.
fn finishJob(job: Job) void {
    finishJobOn(job.ln.node, job);
}

fn finishJobOn(node: *Node, job: Job) void {
    if (node.cfg.inflight) |budget| budget.release(job.reserved);
    std.heap.page_allocator.free(job.body);
    _ = node.workers.fetchSub(1, .acq_rel);
}

fn worker(job: *Job) void {
    const copy = job.*;
    std.heap.page_allocator.destroy(job);
    const node = copy.ln.node;
    // The worker count drops last, after the link reference is gone, so a
    // zero count means no worker still touches any link.
    defer finishJobOn(node, copy);
    defer copy.ln.release();

    // Same arena pattern as http.serveOneRequest: one arena per request.
    var req_arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer req_arena_state.deinit();
    const ra = req_arena_state.allocator();
    const rpc = rpc_mod.handleRpc(ra, node.io, node.cfg, copy.body) catch |err| {
        std.debug.print("node link request failed: {s}\n", .{@errorName(err)});
        copy.ln.writeResp(copy.sid, 500, "{\"error\":\"internal\",\"message\":\"request failed\"}");
        return;
    };
    copy.ln.writeResp(copy.sid, rpc.status, rpc.body);
}

fn pinger(ln: *Link) void {
    var seq: u64 = 0;
    while (true) {
        var waited: u64 = 0;
        while (waited < PING_INTERVAL_MS) : (waited += PINGER_STEP_MS) {
            if (ln.dead.load(.acquire)) return;
            os.sleepMs(PINGER_STEP_MS);
        }
        seq += 1;
        var payload: [8]u8 = undefined;
        std.mem.writeInt(u64, &payload, seq, .big);
        ln.writeFrame(.ping, 0, &.{&payload});
    }
}

// ---------------------------------------------------------------------------
// Tests: the test plays the hub on a loopback socket.
// ---------------------------------------------------------------------------

const testing = std.testing;
/// The shared in-flight body budget type, named via the config field.
const InflightBudget = @typeInfo(@typeInfo(@FieldType(config.Config, "inflight")).optional.child).pointer.child;

test "node link backoff cap doubles from 0.5 s to 30 s" {
    try testing.expectEqual(@as(u64, 500), backoffCapMs(0));
    try testing.expectEqual(@as(u64, 1000), backoffCapMs(1));
    try testing.expectEqual(@as(u64, 16000), backoffCapMs(5));
    try testing.expectEqual(@as(u64, 30000), backoffCapMs(6));
    try testing.expectEqual(@as(u64, 30000), backoffCapMs(1000));
}

fn testConfig(arena: std.mem.Allocator) !config.Config {
    return .{
        .name = "pc",
        .host = "127.0.0.1",
        .port = 1,
        .token = "",
        .allowed_hosts = try util.splitCsv(arena, "127.0.0.1:*"),
        .allowed_origins = try util.splitCsv(arena, "http://127.0.0.1:*"),
        .max_out = 1024,
        .socket_timeout_s = 5,
        .max_conn = 4,
        .max_sessions = 4,
        .session_ttl_s = 600,
        .max_inflight_bytes = 64 * 1024 * 1024,
        .mode = .node,
        .connect_secret = "s3cret",
    };
}

fn sessionThread(node: *Node, stream: Io.net.Stream, out: *anyerror!u64) void {
    out.* = session(node, stream);
}

test "node link serves REQ and PING over an authenticated link" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var threaded = Io.Threaded.init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var cfg = try testConfig(arena);
    var budget = InflightBudget{ .io = io, .max = cfg.max_inflight_bytes };
    cfg.inflight = &budget;
    var node = Node{ .io = io, .cfg = &cfg };

    const any = try Io.net.IpAddress.parse("127.0.0.1", 0);
    var server = try any.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    const addr = server.socket.address;
    const client = try addr.connect(io, .{ .mode = .stream });
    var hub_side = try server.accept(io);
    defer hub_side.close(io);
    const fd = hub_side.socket.handle;
    try os.net.setSocketTimeouts(fd, 5);

    var result: anyerror!u64 = error.NotRun;
    const t = try std.Thread.spawn(.{}, sessionThread, .{ &node, client, &result });

    var nonce: [link.NONCE_LEN]u8 = @splat(3);
    try link.writeFrame(fd, .challenge, 0, &nonce, 5000);
    const hello_frame = try link.readFrame(arena, fd, link.MAX_HANDSHAKE_PAYLOAD, 5000);
    try testing.expectEqual(link.FrameType.hello, hello_frame.kind);
    const hello = try link.parseHello(arena, hello_frame.payload);
    try testing.expectEqualStrings("pc", hello.name);
    try testing.expect(link.verifyAuth("s3cret", &nonce, hello.name, hello.auth));
    try link.writeFrame(fd, .welcome, 0, "{\"v\":1}", 5000);

    try link.writeFrame(fd, .req, 7, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}", 5000);
    const resp = try link.readFrame(arena, fd, link.MAX_PAYLOAD, 5000);
    try testing.expectEqual(link.FrameType.resp, resp.kind);
    try testing.expectEqual(@as(u32, 7), resp.stream_id);
    const r = try link.splitResp(resp.payload);
    try testing.expectEqual(@as(u16, 200), r.status);
    try testing.expect(std.mem.indexOf(u8, r.body, "\"id\":1") != null);

    try link.writeFrame(fd, .ping, 0, "12345678", 5000);
    const pong = try link.readFrame(arena, fd, link.MAX_HANDSHAKE_PAYLOAD, 5000);
    try testing.expectEqual(link.FrameType.pong, pong.kind);
    try testing.expectEqualStrings("12345678", pong.payload);

    try link.writeFrame(fd, .goaway, 0, "bye", 5000);
    t.join();
    _ = try result;
    // The REQ worker finishes (and drops its link reference) shortly after
    // its RESP went out; wait for it before the stack frame goes away.
    var spins: u32 = 0;
    while (node.workers.load(.acquire) != 0 and spins < 400) : (spins += 1) os.sleepMs(5);
    try testing.expectEqual(@as(u32, 0), node.workers.load(.acquire));
}

test "node link reports a hub refusal" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var threaded = Io.Threaded.init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const cfg = try testConfig(arena);
    var node = Node{ .io = io, .cfg = &cfg };
    const any = try Io.net.IpAddress.parse("127.0.0.1", 0);
    var server = try any.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    const client = try server.socket.address.connect(io, .{ .mode = .stream });
    var hub_side = try server.accept(io);
    defer hub_side.close(io);
    const fd = hub_side.socket.handle;
    try os.net.setSocketTimeouts(fd, 5);

    var result: anyerror!u64 = error.NotRun;
    const t = try std.Thread.spawn(.{}, sessionThread, .{ &node, client, &result });
    var nonce: [link.NONCE_LEN]u8 = @splat(9);
    try link.writeFrame(fd, .challenge, 0, &nonce, 5000);
    _ = try link.readFrame(arena, fd, link.MAX_HANDSHAKE_PAYLOAD, 5000);
    try link.writeFrame(fd, .goaway, 0, "bad auth", 5000);
    t.join();
    try testing.expectError(error.Refused, result);
}
