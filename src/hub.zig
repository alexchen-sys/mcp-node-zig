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

const build_options = @import("build_options");
const tls_server = if (build_options.tls_server) @import("tls_server.zig") else struct {};

/// Byte channel of one accepted link: the plain socket, or, in a
/// -Dtls-server build with MCP_NODE_HUB_TLS_* set, TLS over the same
/// socket (see tls_server.zig). Without the build option this alias is
/// exactly the plain FdConn, so the default build is unchanged.
const Conn = if (build_options.tls_server) union(enum) {
    plain: link.FdConn,
    tls: *tls_server.Conn,

    pub fn readSome(self: Conn, buf: []u8, timeout_ms: u64) !usize {
        return switch (self) {
            .plain => |p| p.readSome(buf, timeout_ms),
            .tls => |t| t.readSome(buf, timeout_ms),
        };
    }

    pub fn write(self: Conn, bytes: []const u8, timeout_ms: u64) !void {
        return switch (self) {
            .plain => |p| p.write(bytes, timeout_ms),
            .tls => |t| t.write(bytes, timeout_ms),
        };
    }

    pub fn flush(self: Conn, timeout_ms: u64) !void {
        return switch (self) {
            .plain => |p| p.flush(timeout_ms),
            .tls => |t| t.flush(timeout_ms),
        };
    }
} else link.FdConn;

fn plainConn(fd: os.net.Handle) Conn {
    return if (build_options.tls_server) .{ .plain = .{ .fd = fd } } else .{ .fd = fd };
}

/// Free the transport state of a conn that no Link took over (plain
/// sockets own nothing).
fn connDeinit(conn: Conn) void {
    if (build_options.tls_server) {
        if (conn == .tls) conn.tls.destroy();
    }
}

/// Hub.tls stays a void placeholder in default builds, so the struct
/// layout there is untouched.
const TlsField = if (build_options.tls_server) ?*tls_server.Server else void;
const defaultTls: TlsField = if (build_options.tls_server) null else {};

pub const PING_INTERVAL_MS: u64 = 15 * 1000;
pub const DEAD_AFTER_MS: u64 = 45 * 1000;
pub const HANDSHAKE_MS: u64 = 10 * 1000;
pub const MAX_PENDING_HANDSHAKES: u32 = 16;
/// How long a registered link has to answer a PING before a new HELLO
/// under the same name may take the name over.
pub const PROBE_MS: u64 = 3 * 1000;
const PROBE_STEP_MS: u64 = 50;
/// GOAWAY text for a node whose name is held by a live link.
pub const NAME_IN_USE = "name in use by a live link";
/// Floor for the relay deadline: a long tool call holds the line as long
/// as the client allows, like on a direct node.
pub const MIN_FORWARD_MS: u64 = 3600 * 1000;
const ACCEPT_BACKOFF_MS: u64 = 50;
const PINGER_STEP_MS: u64 = 250;
/// Handshakes in progress from one source, on top of the global cap.
pub const MAX_PENDING_PER_SOURCE: u8 = 4;
/// Failed handshakes from one source within AUTH_FAIL_WINDOW_MS that
/// make the hub refuse that source for AUTH_BAN_MS.
pub const AUTH_FAIL_LIMIT: u8 = 8;
pub const AUTH_FAIL_WINDOW_MS: i64 = 60 * 1000;
pub const AUTH_BAN_MS: i64 = 60 * 1000;
/// Sources tracked at once. Larger than MAX_PENDING_HANDSHAKES, so a
/// source with a handshake in progress always has its own entry.
pub const SOURCE_SLOTS: usize = 64;

const gpa = std.heap.page_allocator;

fn nowMs(io: Io) i64 {
    return Io.Clock.awake.now(io).toMilliseconds();
}

// ---------------------------------------------------------------------------
// Per-source accounting: a fixed table, no allocation
// ---------------------------------------------------------------------------

/// Where an accepted connection comes from. IPv4 (also IPv4-mapped IPv6)
/// is keyed by the full address, IPv6 by its /64, the smallest block one
/// host usually controls. 127.0.0.1 and ::1 are exempt: a local TLS
/// terminator dials from there, and limiting it would limit every node.
pub const Source = struct {
    key: [16]u8,
    exempt: bool,

    pub fn of(addr: Io.net.IpAddress) Source {
        var key = [_]u8{0} ** 16;
        switch (addr) {
            .ip4 => |a| {
                key[10] = 0xff;
                key[11] = 0xff;
                @memcpy(key[12..16], &a.bytes);
            },
            .ip6 => |a| {
                const mapped_prefix = [_]u8{0} ** 10 ++ [_]u8{ 0xff, 0xff };
                if (std.mem.eql(u8, a.bytes[0..12], &mapped_prefix)) {
                    key = a.bytes;
                } else {
                    const loopback6 = [_]u8{0} ** 15 ++ [_]u8{1};
                    if (std.mem.eql(u8, &a.bytes, &loopback6)) return .{ .key = a.bytes, .exempt = true };
                    @memcpy(key[0..8], a.bytes[0..8]);
                }
            },
        }
        const loopback4 = [_]u8{0} ** 10 ++ [_]u8{ 0xff, 0xff, 127, 0, 0, 1 };
        return .{ .key = key, .exempt = std.mem.eql(u8, &key, &loopback4) };
    }
};

pub const Admission = enum { admitted, busy, banned };

/// How a handshake ended, for the failure count of its source.
pub const Outcome = enum {
    /// The peer proved the secret (also when its name was then refused).
    authenticated,
    /// Bad or missing HELLO, wrong MAC, unknown name, deadline.
    failed,
    /// Local trouble (socket option, allocation): not the peer's fault.
    neutral,
};

const SourceEntry = struct {
    used: bool = false,
    key: [16]u8 = undefined,
    pending: u8 = 0,
    fails: u8 = 0,
    window_start_ms: i64 = 0,
    ban_until_ms: i64 = 0,
    last_ms: i64 = 0,

    fn idle(e: *const SourceEntry, now: i64) bool {
        return e.pending == 0 and e.ban_until_ms <= now and
            (e.fails == 0 or now - e.window_start_ms > AUTH_FAIL_WINDOW_MS);
    }
};

/// Pending handshakes and failure bans per source, in constant memory.
/// When every slot holds state, the least recently seen entry without a
/// handshake in progress is reused, so a flood of fresh addresses can
/// flush a ban early but never makes the table refuse a source it does
/// not track. The global handshake cap still applies to everyone.
pub const SourceTable = struct {
    entries: [SOURCE_SLOTS]SourceEntry = [_]SourceEntry{.{}} ** SOURCE_SLOTS,

    fn find(t: *SourceTable, key: [16]u8) ?*SourceEntry {
        for (&t.entries) |*e| {
            if (e.used and std.mem.eql(u8, &e.key, &key)) return e;
        }
        return null;
    }

    fn slotFor(t: *SourceTable, now: i64) ?*SourceEntry {
        var victim: ?*SourceEntry = null;
        for (&t.entries) |*e| {
            if (!e.used or e.idle(now)) return e;
            if (e.pending != 0) continue;
            if (victim == null or e.last_ms < victim.?.last_ms) victim = e;
        }
        return victim;
    }

    /// Count a new handshake from `key`, or say why it is refused.
    pub fn admit(t: *SourceTable, key: [16]u8, now: i64) Admission {
        const e = t.find(key) orelse blk: {
            // Unreachable while SOURCE_SLOTS > MAX_PENDING_HANDSHAKES;
            // if it ever happens, the global cap alone decides.
            const slot = t.slotFor(now) orelse return .admitted;
            slot.* = .{ .used = true, .key = key };
            break :blk slot;
        };
        e.last_ms = now;
        if (e.ban_until_ms > now) return .banned;
        if (e.pending >= MAX_PENDING_PER_SOURCE) return .busy;
        e.pending += 1;
        return .admitted;
    }

    /// End a handshake admitted for `key`. Returns true when this failure
    /// started a ban.
    pub fn finish(t: *SourceTable, key: [16]u8, outcome: Outcome, now: i64) bool {
        const e = t.find(key) orelse return false;
        if (e.pending > 0) e.pending -= 1;
        e.last_ms = now;
        switch (outcome) {
            .neutral => {},
            .authenticated => e.fails = 0,
            .failed => {
                if (e.fails == 0 or now - e.window_start_ms > AUTH_FAIL_WINDOW_MS) {
                    e.window_start_ms = now;
                    e.fails = 0;
                }
                e.fails += 1;
                if (e.fails >= AUTH_FAIL_LIMIT) {
                    e.fails = 0;
                    e.ban_until_ms = now + AUTH_BAN_MS;
                    return true;
                }
            },
        }
        return false;
    }
};

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
    /// Per-source pending counts and failure bans (fixed size).
    sources_mutex: Io.Mutex = .init,
    sources: SourceTable = .{},
    /// TLS server state for the node-link listener (MCP_NODE_HUB_TLS_*),
    /// or null when links stay plain TCP. `void` without -Dtls-server.
    tls: TlsField = defaultTls,

    pub fn init(io: Io, cfg: *const config.Config, secrets: link.SecretSet) Hub {
        return .{ .io = io, .cfg = cfg, .secrets = secrets };
    }

    fn admitSource(self: *Hub, src: Source) Admission {
        if (src.exempt) return .admitted;
        self.sources_mutex.lockUncancelable(self.io);
        defer self.sources_mutex.unlock(self.io);
        return self.sources.admit(src.key, nowMs(self.io));
    }

    fn finishSource(self: *Hub, src: Source, addr: Io.net.IpAddress, outcome: Outcome) void {
        if (src.exempt) return;
        const banned = blk: {
            self.sources_mutex.lockUncancelable(self.io);
            defer self.sources_mutex.unlock(self.io);
            break :blk self.sources.finish(src.key, outcome, nowMs(self.io));
        };
        if (banned) std.debug.print("hub: refusing {f} for {d} s after {d} failed handshakes\n", .{
            addr, @divTrunc(AUTH_BAN_MS, 1000), AUTH_FAIL_LIMIT,
        });
    }

    /// Insert an authenticated link. An existing link with the same name is
    /// replaced: it gets GOAWAY, is killed (its waiters fail) and released.
    /// `authenticate` only gets here when that link failed the probe.
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

    /// True when `name` is registered and its link answers within PROBE_MS.
    /// A silent link (crashed node, half-open TCP) does not hold the name.
    fn nameHeldByLiveLink(self: *Hub, name: []const u8) bool {
        const cur = self.acquire(name) orelse return false;
        defer cur.release();
        return cur.answersProbe();
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
    conn: Conn,
    name: []u8,
    connected_at: Io.Timestamp,
    write_mutex: Io.Mutex = .init,
    refs: std.atomic.Value(u32) = .init(1),
    dead: std.atomic.Value(bool) = .init(false),
    inflight: std.atomic.Value(u32) = .init(0),
    /// Frames received so far; the liveness probe watches it move.
    rx_frames: std.atomic.Value(u64) = .init(0),
    next_sid: std.atomic.Value(u32) = .init(1),
    waiters_mutex: Io.Mutex = .init,
    waiters: std.AutoHashMapUnmanaged(u32, *Waiter) = .empty,

    fn create(hub: *Hub, stream: Io.net.Stream, conn: Conn, name: []const u8) !*Link {
        const owned = try gpa.dupe(u8, name);
        errdefer gpa.free(owned);
        const ln = try gpa.create(Link);
        ln.* = .{ .hub = hub, .stream = stream, .conn = conn, .name = owned, .connected_at = Io.Clock.awake.now(hub.io) };
        return ln;
    }

    pub fn retain(self: *Link) void {
        _ = self.refs.fetchAdd(1, .monotonic);
    }

    pub fn release(self: *Link) void {
        if (self.refs.fetchSub(1, .acq_rel) != 1) return;
        connDeinit(self.conn);
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
        link.writeFramePartsOn(self.conn, kind, sid, parts, timeout_ms) catch self.kill();
    }

    /// PING the peer and wait up to PROBE_MS for any inbound frame.
    fn answersProbe(self: *Link) bool {
        const seen = self.rx_frames.load(.acquire);
        self.writeFrame(.ping, 0, &.{"probe"});
        var waited: u64 = 0;
        while (waited < PROBE_MS) : (waited += PROBE_STEP_MS) {
            if (self.dead.load(.acquire)) return false;
            if (self.rx_frames.load(.acquire) != seen) return true;
            os.sleepMs(PROBE_STEP_MS);
        }
        return false;
    }

    fn nextSid(self: *Link) u32 {
        while (true) {
            const sid = self.next_sid.fetchAdd(1, .monotonic);
            if (sid != 0) return sid;
        }
    }

    /// Add a waiter; fails once the link is dead (checked under the same
    /// mutex `kill` uses, so a waiter is never added after the fail sweep).
    /// Returns the stream id actually registered.
    fn addWaiter(self: *Link, sid: u32, w: *Waiter) !u32 {
        const io = self.hub.io;
        self.waiters_mutex.lockUncancelable(io);
        defer self.waiters_mutex.unlock(io);
        if (self.dead.load(.acquire)) return error.LinkDead;
        // After u32 wrap-around a sid may still be held by a long request:
        // never overwrite it, take the next free one instead.
        var id = sid;
        while (true) : (id = self.nextSid()) {
            const gop = try self.waiters.getOrPut(gpa, id);
            if (!gop.found_existing) {
                gop.value_ptr.* = w;
                return id;
            }
        }
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
    const sid = ln.addWaiter(ln.nextSid(), &w) catch |err| switch (err) {
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

const Authenticated = struct {
    name: []const u8,
    /// WELCOME payload carrying the hub's own proof of the secret.
    welcome: []const u8,
};

/// Key for the MAC computed when a pinned name is unknown, so that path
/// costs the same HMAC as a bad MAC for a known name.
const DUMMY_KEY = "mcp-node-reverse-unknown-name";

/// Authenticate a freshly accepted peer over `conn`. Returns the node name
/// and the WELCOME payload (in `arena`) or an error after sending GOAWAY
/// where that makes sense. `started` bounds the whole handshake phase
/// (transport setup included) to HANDSHAKE_MS.
fn handshake(hub: *Hub, arena: Allocator, conn: Conn, started: Io.Timestamp) !Authenticated {
    const timeout_ms = @as(u64, hub.cfg.socket_timeout_s) * 1000;
    var nonce: [link.NONCE_LEN]u8 = undefined;
    try hub.io.randomSecure(&nonce);
    try link.writeFramePartsOn(conn, .challenge, 0, &.{&nonce}, timeout_ms);
    const frame = try link.readFrameWithinOn(arena, conn, link.MAX_HANDSHAKE_PAYLOAD, hub.io, started, HANDSHAKE_MS);
    if (frame.kind != .hello) {
        link.writeFramePartsOn(conn, .goaway, 0, &.{"expected hello"}, timeout_ms) catch {};
        return error.BadHello;
    }
    const hello = link.parseHello(arena, frame.payload) catch |err| {
        link.writeFramePartsOn(conn, .goaway, 0, &.{"bad hello"}, timeout_ms) catch {};
        return err;
    };
    const secret = hub.secrets.lookup(hello.name);
    // Unknown pinned names and bad MACs get the same answer and the same
    // work: the unknown-name path still computes one HMAC, with a dummy key.
    const mac_ok = link.verifyAuth(.node, secret orelse DUMMY_KEY, &nonce, &hello.nonce, hello.name, hello.auth);
    if (!(mac_ok and secret != null)) {
        link.writeFramePartsOn(conn, .goaway, 0, &.{"auth failed"}, timeout_ms) catch {};
        return error.AuthFailed;
    }
    const welcome = try link.buildWelcome(arena, secret.?, &nonce, &hello.nonce, hello.name);
    return .{ .name = hello.name, .welcome = welcome };
}

const Accepted = struct { hub: *Hub, stream: Io.net.Stream, source: Source };

fn linkThread(acc: *Accepted) void {
    const hub = acc.hub;
    const stream = acc.stream;
    const source = acc.source;
    gpa.destroy(acc);
    defer _ = hub.threads.fetchSub(1, .acq_rel);
    const ln = authenticate(hub, stream, source) orelse return;
    defer ln.release(); // the reader's reference
    defer hub.unregister(ln);
    defer ln.kill();
    readLoop(ln) catch |err| {
        if (!ln.dead.load(.acquire)) std.debug.print("hub link '{s}' lost: {s}\n", .{ ln.name, @errorName(err) });
    };
}

/// Handshake, WELCOME and registration; closes the stream on any failure.
/// The handshake slot is released before the link becomes a reader.
fn authenticate(hub: *Hub, stream: Io.net.Stream, source: Source) ?*Link {
    // The peer address is read before any close below can free the socket.
    const peer = stream.socket.address;
    var outcome: Outcome = .neutral;
    defer _ = hub.handshakes.fetchSub(1, .acq_rel);
    defer hub.finishSource(source, peer, outcome);
    const fd = stream.socket.handle;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    os.net.setSocketTimeouts(fd, hub.cfg.socket_timeout_s) catch {
        stream.close(hub.io);
        return null;
    };
    // One deadline for the whole handshake phase: a transport handshake
    // (when the build has one) and the HELLO exchange share HANDSHAKE_MS.
    const started = Io.Clock.awake.now(hub.io);
    var conn = plainConn(fd);
    var conn_taken = false;
    defer if (!conn_taken) connDeinit(conn);
    if (build_options.tls_server) {
        if (hub.tls) |srv| {
            // TLS first; the HELLO exchange below then runs over it. A bad
            // TLS handshake is the peer's failure (garbage, no TLS, stale
            // deadline), local setup trouble is neutral — same rule the
            // protocol handshake below follows.
            const tc = tls_server.Conn.accept(srv, hub.io, fd, started, HANDSHAKE_MS) catch |err| {
                outcome = switch (@as(anyerror, err)) {
                    error.OutOfMemory, error.EntropyUnavailable, error.Canceled => .neutral,
                    else => .failed,
                };
                stream.close(hub.io);
                return null;
            };
            conn = .{ .tls = tc };
        }
    }
    const auth = handshake(hub, arena_state.allocator(), conn, started) catch |err| {
        std.debug.print("hub handshake failed: {s}\n", .{@errorName(err)});
        // Out of memory, no entropy or shutdown is ours; everything else
        // counts against the peer (no or bad HELLO, wrong MAC, unknown
        // name, deadline, reset mid-handshake).
        outcome = switch (@as(anyerror, err)) {
            error.OutOfMemory, error.EntropyUnavailable, error.Canceled => .neutral,
            else => .failed,
        };
        stream.close(hub.io);
        return null;
    };
    outcome = .authenticated;
    // Two live processes under one name would otherwise evict each other
    // forever. Keep the link that still answers; refuse the newcomer before
    // WELCOME, so it learns why and retries only at its backoff. Only an
    // authenticated peer gets this answer.
    if (hub.nameHeldByLiveLink(auth.name)) {
        std.debug.print("hub: refused a second link for '{s}': " ++ NAME_IN_USE ++ "\n", .{auth.name});
        const timeout_ms = @as(u64, hub.cfg.socket_timeout_s) * 1000;
        link.writeFramePartsOn(conn, .goaway, 0, &.{NAME_IN_USE}, timeout_ms) catch {};
        stream.close(hub.io);
        return null;
    }
    const ln = Link.create(hub, stream, conn, auth.name) catch {
        stream.close(hub.io);
        return null;
    };
    conn_taken = true; // the link owns the transport state from here on
    ln.writeFrame(.welcome, 0, &.{auth.welcome});
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
    while (!ln.dead.load(.acquire)) {
        // Any inbound frame refreshes liveness: the per-read idle bound is
        // the 45 s silence limit.
        const frame = try link.readFrameOn(gpa, ln.conn, link.MAX_PAYLOAD, DEAD_AFTER_MS);
        _ = ln.rx_frames.fetchAdd(1, .acq_rel);
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
/// handshake budget (global or per source) is spent or the source is
/// banned after repeated failed handshakes.
pub fn adopt(hub: *Hub, stream: Io.net.Stream) void {
    if (hub.handshakes.fetchAdd(1, .acq_rel) >= MAX_PENDING_HANDSHAKES) {
        _ = hub.handshakes.fetchSub(1, .acq_rel);
        stream.close(hub.io);
        return;
    }
    const source = Source.of(stream.socket.address);
    switch (hub.admitSource(source)) {
        .admitted => {},
        .busy, .banned => {
            _ = hub.handshakes.fetchSub(1, .acq_rel);
            stream.close(hub.io);
            return;
        },
    }
    const acc = gpa.create(Accepted) catch {
        hub.finishSource(source, stream.socket.address, .neutral);
        _ = hub.handshakes.fetchSub(1, .acq_rel);
        stream.close(hub.io);
        return;
    };
    acc.* = .{ .hub = hub, .stream = stream, .source = source };
    _ = hub.threads.fetchAdd(1, .acq_rel);
    const t = std.Thread.spawn(.{}, linkThread, .{acc}) catch {
        _ = hub.threads.fetchSub(1, .acq_rel);
        hub.finishSource(source, stream.socket.address, .neutral);
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
    if (build_options.tls_server) {
        if (hub.cfg.hub_tls_cert_file) |cert_file| {
            const srv = tls_server.Server.init(hub.io, cert_file, hub.cfg.hub_tls_key_file.?) catch |err| {
                std.debug.print("hub TLS setup failed: {s}\n", .{@errorName(err)});
                return error.TlsSetupFailed;
            };
            hub.tls = srv;
            std.debug.print("hub: serving TLS 1.3 node links (mbedTLS {s})\n", .{tls_server.version()});
        }
    }
    const addr = try Io.net.IpAddress.parse(ep.host, ep.port);
    server.* = try os.net.listenTcp(hub.io, addr); // no SO_REUSEPORT, see os.net
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
    const a = try Link.create(&fx.hub, p1.near, plainConn(p1.near.socket.handle), "pc");
    const b = try Link.create(&fx.hub, p2.near, plainConn(p2.near.socket.handle), "pc");
    try fx.hub.register(a);
    try testing.expect(fx.hub.acquire("pc").? == a);
    a.release();

    var w = Waiter{};
    try testing.expectEqual(@as(u32, 5), try a.addWaiter(5, &w));
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
    const ln = try Link.create(&fx.hub, p.near, plainConn(p.near.socket.handle), "pc");
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

test "source key: IPv4, mapped IPv4, IPv6 /64 and loopback exemption" {
    const a = Source.of(try Io.net.IpAddress.parse("192.0.2.7", 1));
    const b = Source.of(try Io.net.IpAddress.parse("::ffff:192.0.2.7", 2));
    try testing.expect(!a.exempt);
    try testing.expectEqualSlices(u8, &a.key, &b.key);
    const c = Source.of(try Io.net.IpAddress.parse("2001:db8:1:2:aaaa::1", 1));
    const d = Source.of(try Io.net.IpAddress.parse("2001:db8:1:2:bbbb::9", 1));
    const e = Source.of(try Io.net.IpAddress.parse("2001:db8:1:3::1", 1));
    try testing.expectEqualSlices(u8, &c.key, &d.key);
    try testing.expect(!std.mem.eql(u8, &c.key, &e.key));
    try testing.expect(!std.mem.eql(u8, &a.key, &c.key));
    try testing.expect(Source.of(try Io.net.IpAddress.parse("127.0.0.1", 1)).exempt);
    try testing.expect(Source.of(try Io.net.IpAddress.parse("::1", 1)).exempt);
    try testing.expect(Source.of(try Io.net.IpAddress.parse("::ffff:127.0.0.1", 1)).exempt);
    try testing.expect(!Source.of(try Io.net.IpAddress.parse("127.0.0.2", 1)).exempt);
}

fn keyOf(comptime text: []const u8) ![16]u8 {
    return Source.of(try Io.net.IpAddress.parse(text, 1)).key;
}

test "source table: per-source pending cap, others unaffected" {
    var t: SourceTable = .{};
    const a = try keyOf("192.0.2.1");
    const b = try keyOf("192.0.2.2");
    for (0..MAX_PENDING_PER_SOURCE) |_| try testing.expectEqual(Admission.admitted, t.admit(a, 0));
    try testing.expectEqual(Admission.busy, t.admit(a, 0));
    try testing.expectEqual(Admission.admitted, t.admit(b, 0));
    // One finished handshake frees one slot for that source.
    _ = t.finish(a, .authenticated, 1);
    try testing.expectEqual(Admission.admitted, t.admit(a, 2));
    try testing.expectEqual(Admission.busy, t.admit(a, 2));
}

test "source table: repeated failures ban a source for a while" {
    var t: SourceTable = .{};
    const a = try keyOf("198.51.100.9");
    var now: i64 = 1000;
    for (0..AUTH_FAIL_LIMIT) |i| {
        try testing.expectEqual(Admission.admitted, t.admit(a, now));
        const banned = t.finish(a, .failed, now);
        try testing.expectEqual(i + 1 == AUTH_FAIL_LIMIT, banned);
        now += 10;
    }
    try testing.expectEqual(Admission.banned, t.admit(a, now));
    try testing.expectEqual(Admission.banned, t.admit(a, now + AUTH_BAN_MS - 20));
    try testing.expectEqual(Admission.admitted, t.admit(a, now + AUTH_BAN_MS));
}

test "source table: success resets failures, old failures expire" {
    var t: SourceTable = .{};
    const a = try keyOf("198.51.100.10");
    for (0..AUTH_FAIL_LIMIT - 1) |_| {
        _ = t.admit(a, 0);
        try testing.expect(!t.finish(a, .failed, 0));
    }
    _ = t.admit(a, 0);
    try testing.expect(!t.finish(a, .authenticated, 0));
    for (0..AUTH_FAIL_LIMIT - 1) |_| {
        _ = t.admit(a, 0);
        try testing.expect(!t.finish(a, .failed, 0));
    }
    // Past the window the count starts over instead of banning.
    _ = t.admit(a, AUTH_FAIL_WINDOW_MS + 1);
    try testing.expect(!t.finish(a, .failed, AUTH_FAIL_WINDOW_MS + 1));
    // Neutral endings neither count nor reset.
    _ = t.admit(a, AUTH_FAIL_WINDOW_MS + 2);
    try testing.expect(!t.finish(a, .neutral, AUTH_FAIL_WINDOW_MS + 2));
    try testing.expectEqual(Admission.admitted, t.admit(a, AUTH_FAIL_WINDOW_MS + 3));
}

test "source table: constant size, busy entries are never evicted" {
    var t: SourceTable = .{};
    // Fill every slot with a banned source, one of them also pending.
    var keys: [SOURCE_SLOTS][16]u8 = undefined;
    for (&keys, 0..) |*k, i| {
        k.* = [_]u8{0} ** 10 ++ [_]u8{ 0xff, 0xff, 10, 0, 0, @intCast(i) };
        for (0..AUTH_FAIL_LIMIT) |_| {
            _ = t.admit(k.*, 0);
            _ = t.finish(k.*, .failed, 0);
        }
    }
    t.entries[0].ban_until_ms = 0;
    try testing.expectEqual(Admission.admitted, t.admit(keys[0], 1));
    t.entries[0].ban_until_ms = AUTH_BAN_MS;
    // A new source takes the least recently seen entry without a pending
    // handshake; entry 0 (pending) keeps its state.
    const fresh = try keyOf("203.0.113.5");
    try testing.expectEqual(Admission.admitted, t.admit(fresh, 2));
    try testing.expect(t.find(keys[0]) != null);
    try testing.expectEqual(@as(u8, 1), t.find(keys[0]).?.pending);
    try testing.expect(t.find(keys[1]) == null);
    try testing.expectEqual(Admission.banned, t.admit(keys[2], 3));
}

test "hub refuses a source over its pending cap while another is served" {
    var fx: Fixture = undefined;
    try fx.init(.{ .single = "s3cret" });
    defer fx.deinit();
    const io = fx.threaded.io();
    const a = Source.of(try Io.net.IpAddress.parse("192.0.2.1", 1));
    for (0..MAX_PENDING_PER_SOURCE) |_| try testing.expectEqual(Admission.admitted, fx.hub.admitSource(a));
    // The accepted loopback peer is exempt, so drive admission through a
    // stream whose recorded address is a non-loopback source.
    var p = try tcpPair(io, &fx.server);
    defer p.far.close(io);
    p.near.socket.address = try Io.net.IpAddress.parse("192.0.2.1", 4000);
    adopt(&fx.hub, p.near); // over the per-source cap: closed, no CHALLENGE
    var buf: [16]u8 = undefined;
    const n = os.net.socketReadSome(p.far.socket.handle, &buf, 5000) catch 0;
    try testing.expectEqual(@as(usize, 0), n);
    try testing.expectEqual(@as(u32, 0), fx.hub.handshakes.load(.acquire));

    var q = try tcpPair(io, &fx.server);
    defer q.far.close(io);
    q.near.socket.address = try Io.net.IpAddress.parse("192.0.2.2", 4000);
    adopt(&fx.hub, q.near); // another source still gets a CHALLENGE
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const ch = try link.readFrame(arena_state.allocator(), q.far.socket.handle, link.MAX_HANDSHAKE_PAYLOAD, 5000);
    try testing.expectEqual(link.FrameType.challenge, ch.kind);
    try link.writeFrame(q.far.socket.handle, .ping, 0, "12345678", 5000);
    try waitZero(&fx.hub.threads);
    for (0..MAX_PENDING_PER_SOURCE) |_| fx.hub.finishSource(a, try Io.net.IpAddress.parse("192.0.2.1", 1), .neutral);
}
