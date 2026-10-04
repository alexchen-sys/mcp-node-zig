//! Hub mode: accept node links, authenticate them, and relay client MCP
//! requests (`POST /n/<name>/mcp`) to the named node as REQ frames.
//!
//! Threads: one accept thread on the hub listener; one thread per accepted
//! link that first runs the handshake and then becomes the link reader; one
//! pinger for the whole hub. HTTP client threads call `forward`, which
//! registers a waiter under a fresh stream_id, writes the REQ under the
//! per-link writer mutex and blocks on the waiter until RESP, link loss or
//! the request deadline.
//!
//! Ownership: a Link is reference counted. The registry holds one reference,
//! the reader thread holds one, and every `forward` holds one while it runs.
//! The socket closes on the last release. Waiters live on the caller's
//! stack; they are only touched under the link's waiter mutex, and whoever
//! removes a waiter from the table (the reader on RESP, `kill` on loss, the
//! caller on timeout) is the only one who completes it.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const os = @import("os.zig");
const util = @import("util.zig");
const link = @import("link.zig");
const config = @import("config.zig");

pub const PING_INTERVAL_MS: u64 = 15 * 1000;
pub const DEAD_AFTER_MS: u64 = 45 * 1000;
pub const HANDSHAKE_MS: u64 = 10 * 1000;
pub const MAX_PENDING_HANDSHAKES: u32 = 16;
/// Floor for the relay deadline: a long tool call holds the line as long
/// as the client allows, like on a direct node.
pub const MIN_FORWARD_MS: u64 = 3600 * 1000;
const ACCEPT_BACKOFF_MS: u64 = 50;
const PINGER_STEP_MS: u64 = 250;

const gpa = std.heap.page_allocator;

pub const Hub = struct {
    io: Io,
    cfg: *const config.Config,
    secrets: link.SecretSet,
    mutex: Io.Mutex = .init,
    registry: std.StringHashMapUnmanaged(*Link) = .empty,
    /// Handshakes currently in progress (unauthenticated peers).
    handshakes: std.atomic.Value(u32) = .init(0),
    /// Live handshake/reader threads; tests wait for zero.
    threads: std.atomic.Value(u32) = .init(0),
    stopping: std.atomic.Value(bool) = .init(false),

    pub fn init(io: Io, cfg: *const config.Config, secrets: link.SecretSet) Hub {
        return .{ .io = io, .cfg = cfg, .secrets = secrets };
    }

    /// Insert an authenticated link. An existing link with the same name is
    /// replaced: it gets GOAWAY, is killed (its waiters fail) and released.
    fn register(self: *Hub, ln: *Link) !void {
        ln.retain();
        var old: ?*Link = null;
        {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            const gop = self.registry.getOrPut(gpa, ln.name) catch |err| {
                ln.release();
                return err;
            };
            if (gop.found_existing) old = gop.value_ptr.*;
            // The key borrows the link's name: repoint it at the new link
            // before the old one (and its name) can be freed.
            gop.key_ptr.* = ln.name;
            gop.value_ptr.* = ln;
        }
        if (old) |o| {
            o.writeFrame(.goaway, 0, &.{"replaced by a new link"});
            o.kill();
            o.release();
        }
    }

    /// Remove `ln` if it is still the registered link for its name.
    fn unregister(self: *Hub, ln: *Link) void {
        var removed = false;
        {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            if (self.registry.get(ln.name)) |cur| {
                if (cur == ln) {
                    _ = self.registry.remove(ln.name);
                    removed = true;
                }
            }
        }
        if (removed) ln.release();
    }

    /// The registered link for `name`, retained; caller releases.
    pub fn acquire(self: *Hub, name: []const u8) ?*Link {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const ln = self.registry.get(name) orelse return null;
        ln.retain();
        return ln;
    }

    /// Retained snapshot of every registered link; caller releases each.
    fn snapshot(self: *Hub, arena: Allocator) ![]*Link {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const out = try arena.alloc(*Link, self.registry.count());
        var it = self.registry.valueIterator();
        var i: usize = 0;
        while (it.next()) |v| : (i += 1) {
            v.*.retain();
            out[i] = v.*;
        }
        return out;
    }

    /// `{"nodes":[{"name":..,"connected_s":..,"inflight":..}]}`, by name.
    pub fn listJson(self: *Hub, arena: Allocator) ![]const u8 {
        const links = try self.snapshot(arena);
        defer for (links) |ln| ln.release();
        std.mem.sort(*Link, links, {}, struct {
            fn lt(_: void, a: *Link, b: *Link) bool {
                return std.mem.lessThan(u8, a.name, b.name);
            }
        }.lt);
        var out: std.ArrayList(u8) = .empty;
        try out.appendSlice(arena, "{\"nodes\":[");
        for (links, 0..) |ln, i| {
            if (i != 0) try out.append(arena, ',');
            try out.appendSlice(arena, "{\"name\":");
            try util.appendJsonString(&out, arena, ln.name);
            const up_ms = ln.connected_at.untilNow(self.io, .awake).toMilliseconds();
            const up_s: i64 = if (up_ms > 0) @divTrunc(up_ms, 1000) else 0;
            try out.print(arena, ",\"connected_s\":{d},\"inflight\":{d}}}", .{ up_s, ln.inflight.load(.acquire) });
        }
        try out.appendSlice(arena, "]}");
        return out.items;
    }

    /// Kill every registered link (tests and shutdown).
    pub fn killAll(self: *Hub) void {
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const links = self.snapshot(arena_state.allocator()) catch return;
        for (links) |ln| {
            ln.kill();
            ln.release();
        }
    }
};

const WaiterState = enum { pending, done, failed };

const Waiter = struct {
    event: Io.Event = .unset,
    state: WaiterState = .pending,
    /// RESP payload (u16 status + body), owned by page_allocator.
    payload: []u8 = &.{},
};

pub const Link = struct {
    hub: *Hub,
    stream: Io.net.Stream,
    name: []u8,
    connected_at: Io.Timestamp,
    write_mutex: Io.Mutex = .init,
    refs: std.atomic.Value(u32) = .init(1),
    dead: std.atomic.Value(bool) = .init(false),
    inflight: std.atomic.Value(u32) = .init(0),
    next_sid: std.atomic.Value(u32) = .init(1),
    waiters_mutex: Io.Mutex = .init,
    waiters: std.AutoHashMapUnmanaged(u32, *Waiter) = .empty,

    fn create(hub: *Hub, stream: Io.net.Stream, name: []const u8) !*Link {
        const owned = try gpa.dupe(u8, name);
        errdefer gpa.free(owned);
        const ln = try gpa.create(Link);
        ln.* = .{ .hub = hub, .stream = stream, .name = owned, .connected_at = Io.Clock.awake.now(hub.io) };
        return ln;
    }

    pub fn retain(self: *Link) void {
        _ = self.refs.fetchAdd(1, .monotonic);
    }

    pub fn release(self: *Link) void {
        if (self.refs.fetchSub(1, .acq_rel) != 1) return;
        self.stream.close(self.hub.io);
        self.waiters.deinit(gpa);
        gpa.free(self.name);
        gpa.destroy(self);
    }

    /// Mark dead, wake the reader and fail every waiter. Idempotent.
    pub fn kill(self: *Link) void {
        if (self.dead.swap(true, .acq_rel)) return;
        self.stream.shutdown(self.hub.io, .both) catch {};
        const io = self.hub.io;
        self.waiters_mutex.lockUncancelable(io);
        defer self.waiters_mutex.unlock(io);
        var it = self.waiters.valueIterator();
        while (it.next()) |w| {
            w.*.state = .failed;
            w.*.event.set(io);
        }
        self.waiters.clearRetainingCapacity();
    }

    fn writeFrame(self: *Link, kind: link.FrameType, sid: u32, parts: []const []const u8) void {
        if (self.dead.load(.acquire)) return;
        const io = self.hub.io;
        const timeout_ms = @as(u64, self.hub.cfg.socket_timeout_s) * 1000;
        self.write_mutex.lockUncancelable(io);
        defer self.write_mutex.unlock(io);
        // kill() never takes the write mutex, so calling it here is safe.
        link.writeFrameParts(self.stream.socket.handle, kind, sid, parts, timeout_ms) catch self.kill();
    }

    fn nextSid(self: *Link) u32 {
        while (true) {
            const sid = self.next_sid.fetchAdd(1, .monotonic);
            if (sid != 0) return sid;
        }
    }

    /// Add a waiter; fails once the link is dead (checked under the same
    /// mutex `kill` uses, so a waiter is never added after the fail sweep).
    fn addWaiter(self: *Link, sid: u32, w: *Waiter) !void {
        const io = self.hub.io;
        self.waiters_mutex.lockUncancelable(io);
        defer self.waiters_mutex.unlock(io);
        if (self.dead.load(.acquire)) return error.LinkDead;
        try self.waiters.put(gpa, sid, w);
    }

    /// Complete the waiter for `sid` with a RESP payload (ownership moves),
    /// or free the payload when nobody waits any more (late RESP).
    fn fulfil(self: *Link, sid: u32, payload: []u8) void {
        const io = self.hub.io;
        self.waiters_mutex.lockUncancelable(io);
        defer self.waiters_mutex.unlock(io);
        if (self.waiters.fetchRemove(sid)) |kv| {
            kv.value.payload = payload;
            kv.value.state = .done;
            kv.value.event.set(io);
        } else {
            gpa.free(payload);
        }
    }

    /// Caller gave up: take the waiter out unless someone completed it.
    /// Returns the state seen under the lock, so a completion that raced
    /// with the timeout is not lost (and its payload not leaked).
    fn abandon(self: *Link, sid: u32, w: *Waiter) WaiterState {
        const io = self.hub.io;
        self.waiters_mutex.lockUncancelable(io);
        defer self.waiters_mutex.unlock(io);
        _ = self.waiters.remove(sid);
        return w.state;
    }

    pub fn waiterCount(self: *Link) usize {
        const io = self.hub.io;
        self.waiters_mutex.lockUncancelable(io);
        defer self.waiters_mutex.unlock(io);
        return self.waiters.count();
    }
};

// ---------------------------------------------------------------------------
// Relay: one client request -> one REQ frame -> one RESP (or failure)
// ---------------------------------------------------------------------------

pub const Forwarded = union(enum) {
    unknown_node,
    node_disconnected,
    node_timeout,
    /// Node's HTTP status and JSON body (copied into the caller's arena).
    resp: struct { status: u16, body: []const u8 },
};

/// Relay deadline for a request: never below one hour, so long tool calls
/// behave as on a direct node.
pub fn forwardDeadlineMs(cfg: *const config.Config) u64 {
    return @max(@as(u64, cfg.socket_timeout_s) * 1000, MIN_FORWARD_MS);
}

/// Send `body` to node `name` and wait up to `deadline_ms` for its answer.
pub fn forward(hub: *Hub, arena: Allocator, name: []const u8, body: []const u8, deadline_ms: u64) !Forwarded {
    if (!link.validName(name)) return .unknown_node;
    const ln = hub.acquire(name) orelse return .unknown_node;
    defer ln.release();
    return forwardOn(ln, arena, body, deadline_ms);
}

fn forwardOn(ln: *Link, arena: Allocator, body: []const u8, deadline_ms: u64) !Forwarded {
    const io = ln.hub.io;
    _ = ln.inflight.fetchAdd(1, .acq_rel);
    defer _ = ln.inflight.fetchSub(1, .acq_rel);

    var w = Waiter{};
    const sid = ln.nextSid();
    ln.addWaiter(sid, &w) catch |err| switch (err) {
        error.LinkDead => return .node_disconnected,
        else => return err,
    };
    ln.writeFrame(.req, sid, &.{body});

    const deadline: Io.Clock.Timestamp = .fromNow(io, .{
        .raw = .fromMilliseconds(@intCast(@min(deadline_ms, std.math.maxInt(i64)))),
        .clock = .awake,
    });
    while (true) {
        w.event.waitTimeout(io, .{ .deadline = deadline }) catch |err| switch (err) {
            // Timeout also covers spurious wakeups: re-check the clock.
            error.Timeout => {
                if (deadline.durationFromNow(io).raw.nanoseconds > 0) continue;
            },
            error.Canceled => {},
        };
        break;
    }
    // Whoever removed the waiter from the table completed it; if nobody did
    // (timeout), take it out now so a late RESP is discarded.
    const state = if (w.event.isSet()) w.state else ln.abandon(sid, &w);
    switch (state) {
        .pending => return .node_timeout,
        .failed => return .node_disconnected,
        .done => {
            defer gpa.free(w.payload);
            const r = link.splitResp(w.payload) catch return .node_disconnected;
            return .{ .resp = .{ .status = r.status, .body = try arena.dupe(u8, r.body) } };
        },
    }
}

// ---------------------------------------------------------------------------
// Link lifecycle: handshake, reader, pinger, accept loop
// ---------------------------------------------------------------------------

/// Authenticate a freshly accepted peer. Returns the node name (in `arena`)
/// or an error after sending GOAWAY where that makes sense.
fn handshake(hub: *Hub, arena: Allocator, fd: os.net.Handle) ![]const u8 {
    const timeout_ms = @as(u64, hub.cfg.socket_timeout_s) * 1000;
    var nonce: [link.NONCE_LEN]u8 = undefined;
    try hub.io.randomSecure(&nonce);
    const started = Io.Clock.awake.now(hub.io);
    try link.writeFrame(fd, .challenge, 0, &nonce, timeout_ms);
    const frame = try link.readFrameWithin(arena, fd, link.MAX_HANDSHAKE_PAYLOAD, hub.io, started, HANDSHAKE_MS);
    if (frame.kind != .hello) {
        link.writeFrame(fd, .goaway, 0, "expected hello", timeout_ms) catch {};
        return error.BadHello;
    }
    const hello = link.parseHello(arena, frame.payload) catch |err| {
        link.writeFrame(fd, .goaway, 0, "bad hello", timeout_ms) catch {};
        return err;
    };
    const secret = hub.secrets.lookup(hello.name);
    // Unknown pinned names and bad MACs get the same answer.
    const ok = if (secret) |s| link.verifyAuth(s, &nonce, hello.name, hello.auth) else false;
    if (!ok) {
        link.writeFrame(fd, .goaway, 0, "auth failed", timeout_ms) catch {};
        return error.AuthFailed;
    }
    return hello.name;
}

const Accepted = struct { hub: *Hub, stream: Io.net.Stream };

fn linkThread(acc: *Accepted) void {
    const hub = acc.hub;
    const stream = acc.stream;
    gpa.destroy(acc);
    defer _ = hub.threads.fetchSub(1, .acq_rel);
    const ln = authenticate(hub, stream) orelse return;
    defer ln.release(); // the reader's reference
    defer hub.unregister(ln);
    defer ln.kill();
    readLoop(ln) catch |err| {
        if (!ln.dead.load(.acquire)) std.debug.print("hub link '{s}' lost: {s}\n", .{ ln.name, @errorName(err) });
    };
}

/// Handshake, WELCOME and registration; closes the stream on any failure.
/// The handshake slot is released before the link becomes a reader.
fn authenticate(hub: *Hub, stream: Io.net.Stream) ?*Link {
    defer _ = hub.handshakes.fetchSub(1, .acq_rel);
    const fd = stream.socket.handle;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    os.net.setSocketTimeouts(fd, hub.cfg.socket_timeout_s) catch {
        stream.close(hub.io);
        return null;
    };
    const name = handshake(hub, arena_state.allocator(), fd) catch |err| {
        std.debug.print("hub handshake failed: {s}\n", .{@errorName(err)});
        stream.close(hub.io);
        return null;
    };
    const ln = Link.create(hub, stream, name) catch {
        stream.close(hub.io);
        return null;
    };
    ln.writeFrame(.welcome, 0, &.{"{\"v\":1}"});
    if (ln.dead.load(.acquire)) {
        ln.release();
        return null;
    }
    hub.register(ln) catch {
        ln.release();
        return null;
    };
    std.debug.print("hub: node '{s}' connected\n", .{ln.name});
    return ln;
}

fn readLoop(ln: *Link) !void {
    const fd = ln.stream.socket.handle;
    while (!ln.dead.load(.acquire)) {
        // Any inbound frame refreshes liveness: the per-read idle bound is
        // the 45 s silence limit.
        const frame = try link.readFrame(gpa, fd, link.MAX_PAYLOAD, DEAD_AFTER_MS);
        switch (frame.kind) {
            .resp => ln.fulfil(frame.stream_id, frame.payload), // takes payload
            .ping => {
                defer gpa.free(frame.payload);
                ln.writeFrame(.pong, frame.stream_id, &.{frame.payload});
            },
            .pong => gpa.free(frame.payload),
            .goaway => {
                gpa.free(frame.payload);
                return error.GoAway;
            },
            else => {
                gpa.free(frame.payload);
                return error.UnexpectedFrame;
            },
        }
    }
}

fn pinger(hub: *Hub) void {
    var seq: u64 = 0;
    while (!hub.stopping.load(.acquire)) {
        var waited: u64 = 0;
        while (waited < PING_INTERVAL_MS) : (waited += PINGER_STEP_MS) {
            if (hub.stopping.load(.acquire)) return;
            os.sleepMs(PINGER_STEP_MS);
        }
        seq += 1;
        var payload: [8]u8 = undefined;
        std.mem.writeInt(u64, &payload, seq, .big);
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const links = hub.snapshot(arena_state.allocator()) catch continue;
        for (links) |ln| {
            ln.writeFrame(.ping, 0, &.{&payload});
            ln.release();
        }
    }
}

/// Hand an accepted stream to a link thread, or close it when the
/// handshake budget is spent.
pub fn adopt(hub: *Hub, stream: Io.net.Stream) void {
    if (hub.handshakes.fetchAdd(1, .acq_rel) >= MAX_PENDING_HANDSHAKES) {
        _ = hub.handshakes.fetchSub(1, .acq_rel);
        stream.close(hub.io);
        return;
    }
    const acc = gpa.create(Accepted) catch {
        _ = hub.handshakes.fetchSub(1, .acq_rel);
        stream.close(hub.io);
        return;
    };
    acc.* = .{ .hub = hub, .stream = stream };
    _ = hub.threads.fetchAdd(1, .acq_rel);
    const t = std.Thread.spawn(.{}, linkThread, .{acc}) catch {
        _ = hub.threads.fetchSub(1, .acq_rel);
        _ = hub.handshakes.fetchSub(1, .acq_rel);
        gpa.destroy(acc);
        stream.close(hub.io);
        return;
    };
    t.detach();
}

fn acceptLoop(hub: *Hub, server: *Io.net.Server) void {
    while (!hub.stopping.load(.acquire)) {
        const stream = server.accept(hub.io) catch |err| {
            if (hub.stopping.load(.acquire)) return;
            std.debug.print("hub accept failed: {s}\n", .{@errorName(err)});
            os.sleepMs(ACCEPT_BACKOFF_MS);
            continue;
        };
        adopt(hub, stream);
    }
}

/// Open the node-link listener and start the accept and pinger threads.
/// `server` must outlive the hub (main keeps it for the process lifetime).
pub fn start(hub: *Hub, server: *Io.net.Server) !void {
    const ep = hub.cfg.hub_listen orelse return error.NoHubListen;
    const addr = try Io.net.IpAddress.parse(ep.host, ep.port);
    server.* = try addr.listen(hub.io, .{ .reuse_address = true });
    const a = try std.Thread.spawn(.{}, acceptLoop, .{ hub, server });
    a.detach();
    const p = try std.Thread.spawn(.{}, pinger, .{hub});
    p.detach();
}

// ---------------------------------------------------------------------------
// Tests: loopback TCP pairs; the test plays the node or uses node_link.
// ---------------------------------------------------------------------------

const testing = std.testing;
const node_link = @import("node_link.zig");
const InflightBudget = @typeInfo(@typeInfo(@FieldType(config.Config, "inflight")).optional.child).pointer.child;

fn testConfig(arena: Allocator, mode: config.Mode) !config.Config {
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
        .mode = mode,
        .connect_secret = "s3cret",
    };
}

const Pair = struct { near: Io.net.Stream, far: Io.net.Stream };

/// A connected loopback pair: `near` is the accepted side, `far` the dialer.
fn tcpPair(io: Io, server: *Io.net.Server) !Pair {
    const far = try server.socket.address.connect(io, .{ .mode = .stream });
    const near = try server.accept(io);
    try os.net.setSocketTimeouts(near.socket.handle, 5);
    try os.net.setSocketTimeouts(far.socket.handle, 5);
    return .{ .near = near, .far = far };
}

fn waitZero(v: *std.atomic.Value(u32)) !void {
    var spins: u32 = 0;
    while (v.load(.acquire) != 0 and spins < 1000) : (spins += 1) os.sleepMs(5);
    try testing.expectEqual(@as(u32, 0), v.load(.acquire));
}

const Fixture = struct {
    threaded: Io.Threaded,
    arena_state: std.heap.ArenaAllocator,
    cfg: config.Config,
    hub: Hub,
    server: Io.net.Server,

    fn init(self: *Fixture, secrets: link.SecretSet) !void {
        self.threaded = Io.Threaded.init(std.heap.page_allocator, .{});
        self.arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        const io = self.threaded.io();
        self.cfg = try testConfig(self.arena_state.allocator(), .hub);
        self.hub = Hub.init(io, &self.cfg, secrets);
        const any = try Io.net.IpAddress.parse("127.0.0.1", 0);
        self.server = try any.listen(io, .{ .reuse_address = true });
    }

    fn deinit(self: *Fixture) void {
        self.hub.killAll();
        waitZero(&self.hub.threads) catch {};
        self.hub.registry.deinit(gpa);
        self.server.deinit(self.threaded.io());
        self.arena_state.deinit();
        self.threaded.deinit();
    }
};

test "hub registry: a new link for a name replaces the old one" {
    var fx: Fixture = undefined;
    try fx.init(.{ .single = "s" });
    defer fx.deinit();
    const io = fx.threaded.io();

    const p1 = try tcpPair(io, &fx.server);
    defer p1.far.close(io);
    const p2 = try tcpPair(io, &fx.server);
    defer p2.far.close(io);
    const a = try Link.create(&fx.hub, p1.near, "pc");
    const b = try Link.create(&fx.hub, p2.near, "pc");
    try fx.hub.register(a);
    try testing.expect(fx.hub.acquire("pc").? == a);
    a.release();

    var w = Waiter{};
    try a.addWaiter(5, &w);
    try fx.hub.register(b);
    // The old link is dead, its waiter failed, and it got GOAWAY.
    try testing.expect(a.dead.load(.acquire));
    try testing.expectEqual(WaiterState.failed, w.state);
    try testing.expect(w.event.isSet());
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const ga = try link.readFrame(arena_state.allocator(), p1.far.socket.handle, link.MAX_HANDSHAKE_PAYLOAD, 5000);
    try testing.expectEqual(link.FrameType.goaway, ga.kind);

    const cur = fx.hub.acquire("pc").?;
    try testing.expect(cur == b);
    cur.release();
    // A stale reader unregistering the old link must not drop the new one.
    fx.hub.unregister(a);
    const still = fx.hub.acquire("pc").?;
    try testing.expect(still == b);
    still.release();
    try testing.expect(fx.hub.acquire("nobody") == null);

    const listing = try fx.hub.listJson(arena_state.allocator());
    try testing.expect(std.mem.startsWith(u8, listing, "{\"nodes\":[{\"name\":\"pc\",\"connected_s\":"));
    try testing.expect(std.mem.endsWith(u8, listing, ",\"inflight\":0}]}"));

    a.release();
    b.release();
}

test "hub waiter: fulfil, timeout with late RESP, and link loss" {
    var fx: Fixture = undefined;
    try fx.init(.{ .single = "s" });
    defer fx.deinit();
    const io = fx.threaded.io();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const p = try tcpPair(io, &fx.server);
    defer p.far.close(io);
    const ln = try Link.create(&fx.hub, p.near, "pc");
    defer ln.release();
    const far = p.far.socket.handle;

    // Fulfil: a peer thread answers the REQ with the same stream_id.
    const Peer = struct {
        fn answer(owner: *Link, fd: os.net.Handle) void {
            const f = link.readFrame(gpa, fd, link.MAX_PAYLOAD, 5000) catch return;
            defer gpa.free(f.payload);
            const resp = gpa.alloc(u8, 2 + f.payload.len) catch return;
            std.mem.writeInt(u16, resp[0..2], 201, .big);
            @memcpy(resp[2..], f.payload);
            // Feed it straight to the hub side, as the reader would.
            owner.fulfil(f.stream_id, resp);
        }
    };
    const t = try std.Thread.spawn(.{}, Peer.answer, .{ ln, far });
    const ok = try forwardOn(ln, arena, "{\"x\":1}", 5000);
    t.join();
    try testing.expectEqual(@as(u16, 201), ok.resp.status);
    try testing.expectEqualStrings("{\"x\":1}", ok.resp.body);
    try testing.expectEqual(@as(usize, 0), ln.waiterCount());

    // Timeout: nobody answers; the waiter is removed and a late RESP for
    // that stream_id is dropped (freed) instead of being delivered.
    const before = ln.next_sid.load(.acquire);
    const late = try forwardOn(ln, arena, "{}", 50);
    try testing.expect(late == .node_timeout);
    try testing.expectEqual(@as(usize, 0), ln.waiterCount());
    const stale = try gpa.alloc(u8, 2);
    std.mem.writeInt(u16, stale[0..2], 200, .big);
    ln.fulfil(before, stale);
    try testing.expectEqual(@as(usize, 0), ln.waiterCount());
    // drain the REQ frame the peer side never answered
    _ = try link.readFrame(arena, far, link.MAX_PAYLOAD, 5000);

    // Loss: the link dies while a request waits.
    const Killer = struct {
        fn run(owner: *Link) void {
            os.sleepMs(50);
            owner.kill();
        }
    };
    const k = try std.Thread.spawn(.{}, Killer.run, .{ln});
    const lost = try forwardOn(ln, arena, "{}", 5000);
    k.join();
    try testing.expect(lost == .node_disconnected);
    // A dead link refuses new waiters outright.
    try testing.expect((try forwardOn(ln, arena, "{}", 5000)) == .node_disconnected);
}

test "hub relay deadline is at least one hour" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var cfg = try testConfig(arena_state.allocator(), .hub);
    try testing.expectEqual(MIN_FORWARD_MS, forwardDeadlineMs(&cfg));
    cfg.socket_timeout_s = 7200;
    try testing.expectEqual(@as(u64, 7200 * 1000), forwardDeadlineMs(&cfg));
}

fn nodeSessionThread(node: *node_link.Node, stream: Io.net.Stream, out: *anyerror!u64) void {
    out.* = node_link.session(node, stream);
}

fn waitRegistered(hub: *Hub, name: []const u8) !*Link {
    var spins: u32 = 0;
    while (spins < 1000) : (spins += 1) {
        if (hub.acquire(name)) |ln| return ln;
        os.sleepMs(5);
    }
    return error.NotRegistered;
}

test "hub handshake accepts a real node and relays a request end to end" {
    var fx: Fixture = undefined;
    try fx.init(.{ .single = "s3cret" });
    defer fx.deinit();
    const io = fx.threaded.io();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var ncfg = try testConfig(arena, .node);
    var budget = InflightBudget{ .io = io, .max = ncfg.max_inflight_bytes };
    ncfg.inflight = &budget;
    var node = node_link.Node{ .io = io, .cfg = &ncfg };

    const p = try tcpPair(io, &fx.server);
    adopt(&fx.hub, p.near);
    var result: anyerror!u64 = error.NotRun;
    const t = try std.Thread.spawn(.{}, nodeSessionThread, .{ &node, p.far, &result });

    const ln = try waitRegistered(&fx.hub, "pc");
    ln.release();
    try waitZero(&fx.hub.handshakes);

    const res = try forward(&fx.hub, arena, "pc", "{\"jsonrpc\":\"2.0\",\"id\":42,\"method\":\"ping\"}", 5000);
    try testing.expectEqual(@as(u16, 200), res.resp.status);
    try testing.expect(std.mem.indexOf(u8, res.resp.body, "\"id\":42") != null);
    try testing.expect((try forward(&fx.hub, arena, "other", "{}", 5000)) == .unknown_node);
    try testing.expect((try forward(&fx.hub, arena, "a/b", "{}", 5000)) == .unknown_node);

    // Dropping the link on the hub side ends the node session.
    fx.hub.killAll();
    t.join();
    _ = try result;
    try waitZero(&node.workers);
    try waitZero(&fx.hub.threads);
    try testing.expect(fx.hub.acquire("pc") == null);
}

test "hub handshake refuses a wrong secret and an unpinned name" {
    const cases = [_]link.SecretSet{
        .{ .single = "not-the-secret" },
        .{ .pinned = &.{.{ .name = "laptop", .secret = "s3cret" }} },
    };
    for (cases) |secrets| {
        var fx: Fixture = undefined;
        try fx.init(secrets);
        defer fx.deinit();
        const io = fx.threaded.io();
        var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena_state.deinit();
        const ncfg = try testConfig(arena_state.allocator(), .node);
        var node = node_link.Node{ .io = io, .cfg = &ncfg };

        const p = try tcpPair(io, &fx.server);
        adopt(&fx.hub, p.near);
        var result: anyerror!u64 = error.NotRun;
        const t = try std.Thread.spawn(.{}, nodeSessionThread, .{ &node, p.far, &result });
        t.join();
        try testing.expectError(error.Refused, result);
        try waitZero(&fx.hub.threads);
        try testing.expectEqual(@as(u32, 0), fx.hub.handshakes.load(.acquire));
        try testing.expect(fx.hub.acquire("pc") == null);
    }
}

test "hub handshake drops a peer that sends a non-hello frame" {
    var fx: Fixture = undefined;
    try fx.init(.{ .single = "s3cret" });
    defer fx.deinit();
    const io = fx.threaded.io();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const p = try tcpPair(io, &fx.server);
    defer p.far.close(io);
    adopt(&fx.hub, p.near);
    const fd = p.far.socket.handle;
    const ch = try link.readFrame(arena, fd, link.MAX_HANDSHAKE_PAYLOAD, 5000);
    try testing.expectEqual(link.FrameType.challenge, ch.kind);
    try testing.expectEqual(link.NONCE_LEN, ch.payload.len);
    try link.writeFrame(fd, .ping, 0, "12345678", 5000);
    const ga = try link.readFrame(arena, fd, link.MAX_HANDSHAKE_PAYLOAD, 5000);
    try testing.expectEqual(link.FrameType.goaway, ga.kind);
    try waitZero(&fx.hub.threads);
}

test "hub caps handshakes in progress" {
    var fx: Fixture = undefined;
    try fx.init(.{ .single = "s3cret" });
    defer fx.deinit();
    const io = fx.threaded.io();
    fx.hub.handshakes.store(MAX_PENDING_HANDSHAKES, .release);
    const p = try tcpPair(io, &fx.server);
    defer p.far.close(io);
    adopt(&fx.hub, p.near); // over budget: closed without a CHALLENGE
    var buf: [16]u8 = undefined;
    const n = os.net.socketReadSome(p.far.socket.handle, &buf, 5000) catch 0;
    try testing.expectEqual(@as(usize, 0), n);
    try testing.expectEqual(MAX_PENDING_HANDSHAKES, fx.hub.handshakes.load(.acquire));
    fx.hub.handshakes.store(0, .release);
}
