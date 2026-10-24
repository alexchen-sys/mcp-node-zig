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
const proc = @import("os/proc.zig");
const util = @import("util.zig");
const link = @import("link.zig");
const config = @import("config.zig");
const audit = @import("audit.zig");

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
/// Poll step of the probe's write-mutex admission loop: fine enough that
/// a holder releasing mid-budget is picked up at once, coarse enough that
/// the loop costs nothing next to the frame writes it waits behind.
const PROBE_MUTEX_STEP_MS: u64 = 5;
/// Budget of the replacement GOAWAY in Hub.register (mutex admission
/// included, see writeFrameByDeadline). The frame is pure courtesy — the
/// old link is killed right after whatever this spends — so unlike the
/// probe's PROBE_MS it must not hold the handshake slot on its own
/// account: a writer stuck on the old link's write mutex delays the
/// name takeover by at most this much.
const GOAWAY_BUDGET_MS: u64 = 500;
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

/// Time left before an absolute awake-clock deadline; 0 once it passed.
fn deadlineLeftMs(deadline_ms: i64, now_ms: i64) u64 {
    const left = deadline_ms - now_ms;
    return if (left > 0) @intCast(left) else 0;
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
    /// Infrastructure threads, joinable: start keeps the handles so
    /// stop/rollback can retract them instead of leaving detached threads
    /// pointing at startup state that is being unwound.
    accept_thread: ?std.Thread = null,
    pinger_thread: ?std.Thread = null,
    /// POSIX: the accept loop polls the listener together with this pipe,
    /// so stop() retracts the thread without allocating a new socket (a
    /// self-connect would fail under fd exhaustion). Null on Windows.
    wake_rfd: ?std.posix.fd_t = null,
    wake_wfd: ?std.posix.fd_t = null,
    /// Windows: the same guarantee through a loopback wake CONNECTION
    /// created at start (listener on 127.0.0.1:0 + connect + accept, then
    /// the tiny listener closes — the pair lives on). stop() sends one
    /// byte on wake_send; the accept loop WSAPolls wake_recv. Null on
    /// POSIX.
    wake_send: ?Io.net.Stream = null,
    wake_recv: ?Io.net.Stream = null,
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
        if (banned) {
            std.debug.print("hub: refusing {f} for {d} s after {d} failed handshakes\n", .{
                addr, @divTrunc(AUTH_BAN_MS, 1000), AUTH_FAIL_LIMIT,
            });
            audit.linkBan(audit.fromCfg(self.cfg), src.key, @intCast(@divTrunc(AUTH_BAN_MS, 1000)));
        }
    }

    /// Insert an authenticated link. An existing link with the same name is
    /// replaced: it gets a best-effort GOAWAY bounded by GOAWAY_BUDGET_MS,
    /// is killed (its waiters fail) and released. `authenticate` only gets
    /// here when that link failed the probe.
    ///
    /// Established-link admission: a NEW name is refused once the
    /// live registry population reaches cfg.max_node_links — the cap that
    /// bounds sockets, reader threads and TLS state for authenticated
    /// links (shared-secret mode authorizes arbitrary names, so the
    /// configured pin list is not an implicit bound). The check runs under
    /// the registry mutex, so admission and insertion are atomic against
    /// other admissions. Same-name replacement never consumes additional
    /// admission: the old link's registry slot — its credit — transfers.
    /// A replaced link is killed below, so its reader thread and socket
    /// teardown is prompt; residual reader/forward references drain with
    /// the in-flight work that holds them.
    fn register(self: *Hub, ln: *Link) !void {
        ln.retain();
        var old: ?*Link = null;
        {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            // Admission first, before any mutation: a new name past the
            // cap is refused without touching the registry. Registration
            // once stopping has begun is refused too — stop() set the flag
            // under this same mutex, so this check is serialized against
            // the kill sweep and no link can be registered after it.
            if (self.stopping.load(.acquire)) {
                ln.release();
                return error.HubStopping;
            }
            if (self.registry.get(ln.name) == null and self.registry.count() >= self.cfg.max_node_links) {
                ln.release();
                std.debug.print("hub: refusing node '{s}': established-link cap {d} reached\n", .{ ln.name, self.cfg.max_node_links });
                return error.LinkCapacityExceeded;
            }
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
            // The GOAWAY goes out under writeFrameByDeadline's
            // budget-bound mutex admission, never through writeFrame's
            // UNCANCELABLE lock. The writer that just failed the probe by
            // holding the old link's write mutex past PROBE_MS would
            // otherwise park register — and with it the handshake slot, the
            // start of the new link's reader, and every forward on the
            // already-registered new link — behind itself. If the budget
            // expires (or the link dies first) the GOAWAY is simply
            // skipped. kill() runs UNCONDITIONALLY after: its
            // shutdown(.both) breaks the stuck writer's blocked send, so
            // the holder frees the mutex through the failing syscall
            // instead of on its own clock. The object outlives this
            // release: reader/forward holders keep their own references,
            // this one is only the registry's.
            const deadline = nowMs(self.io) + @as(i64, @intCast(GOAWAY_BUDGET_MS));
            _ = o.writeFrameByDeadline(.goaway, 0, &.{"replaced by a new link"}, deadline);
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

    /// Kill every registered link (tests and shutdown). Iterates the
    /// registry directly under the mutex — no snapshot allocation — so the
    /// sweep cannot silently skip links under memory pressure.
    pub fn killAll(self: *Hub) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        var it = self.registry.valueIterator();
        while (it.next()) |v| v.*.kill();
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
    /// Frame-key state, installed after the WELCOME went out (untagged,
    /// like every handshake frame), so the tags start with the first
    /// post-handshake frame — on plaintext and TLS links alike (see
    /// link.zig); tx_seq is guarded by write_mutex, rx_seq by the reader
    /// thread.
    frame_auth: ?link.FrameAuth = null,
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
        if (self.frame_auth) |*fa| fa.secureZero();
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
        self.write_mutex.lockUncancelable(io);
        defer self.write_mutex.unlock(io);
        self.writeFrameLocked(kind, sid, parts, @as(u64, self.hub.cfg.socket_timeout_s) * 1000);
    }

    /// Write one frame with the caller's write budget; the write mutex must
    /// already be held (see writeFrame and writeFrameByDeadline). On POSIX
    /// the write bound is carried by SO_SNDTIMEO on the fd, not by the
    /// timeout parameter (see os.net socketWriteAll), so a budget below the
    /// accept-time bound is enforced by temporarily tightening the option —
    /// under the write mutex, which serializes every writer of this link,
    /// no other I/O can observe the temporary value. The TLS reader never
    /// writes and mbedtls reads do not use the send bound, so the
    /// tightening is invisible to it as well. The get/set calls themselves
    /// run on every platform: on Windows getSocketSendTimeoutMs returns
    /// null (its socketWriteAll already enforces the timeout_ms parameter
    /// in software through the overlapped wait) and setSocketSendTimeoutMs
    /// is a no-op, so the tightening never arms there — the budget rides
    /// the software deadline instead.
    fn writeFrameLocked(self: *Link, kind: link.FrameType, sid: u32, parts: []const []const u8, timeout_ms: u64) void {
        const auth: ?*link.FrameAuth = if (self.frame_auth) |*fa| fa else null;
        // kill() never takes the write mutex, so calling it here is safe.
        // For TLS links this same mutex is installed in the conn's `lock`
        // (see authenticate): the reader takes it only around
        // mbedtls_ssl_read (tls_server sslReadLocked), which never blocks
        // on the socket, so a frame write never queues behind an idle
        // reader's socket wait.
        var tightened_fd: ?os.net.Handle = null;
        var saved_send_ms: u64 = 0;
        if (self.connFd()) |fd| {
            if (os.net.getSocketSendTimeoutMs(fd)) |cur| {
                // 0 = "no bound": larger than any finite budget.
                const cur_ms: u64 = if (cur == 0) std.math.maxInt(u64) else cur;
                if (cur_ms > timeout_ms) {
                    if (os.net.setSocketSendTimeoutMs(fd, timeout_ms)) |_| {
                        tightened_fd = fd;
                        saved_send_ms = cur;
                    } else |_| {}
                }
            }
        }
        defer if (tightened_fd) |fd| {
            os.net.setSocketSendTimeoutMs(fd, saved_send_ms) catch {};
        };
        link.writeFramePartsOn(self.conn, auth, kind, sid, parts, timeout_ms) catch self.kill();
    }

    /// writeFrame bounded by one absolute awake-clock `deadline` on the
    /// WHOLE operation, mutex admission included: the probe's budget must
    /// also cover the time spent waiting for a slow (backpressured, mid
    /// large-frame) writer to release the link's write mutex, or the
    /// handshake slot would sit occupied past the window in which a new
    /// HELLO may take the name over. Admission is a tryLock loop polled on
    /// the awake clock with a small sleep — Mutex has no timed wait, and a
    /// futex park would not be cancelable by the deadline anyway; the
    /// holder releases within one frame write, so the poll is cheap.
    /// Returns false when the budget expired (or the link died) before the
    /// PING could go out — the link is dead in the probe's sense either
    /// way. After acquisition `dead` is rechecked and the transport write
    /// gets only the REMAINING budget, so partial writes cannot stretch
    /// the absolute deadline: the probe frame is a small single write, and
    /// SO_SNDTIMEO (POSIX) or the software deadline (Windows) bounds it by
    /// exactly that remainder.
    fn writeFrameByDeadline(self: *Link, kind: link.FrameType, sid: u32, parts: []const []const u8, deadline: i64) bool {
        const io = self.hub.io;
        while (!self.write_mutex.tryLock()) {
            if (self.dead.load(.acquire)) return false;
            if (nowMs(io) >= deadline) return false;
            os.sleepMs(PROBE_MUTEX_STEP_MS);
        }
        defer self.write_mutex.unlock(io);
        if (self.dead.load(.acquire)) return false;
        const left = deadlineLeftMs(deadline, nowMs(io));
        if (left == 0) return false;
        self.writeFrameLocked(kind, sid, parts, left);
        return true;
    }

    /// The fd carrying this link's socket I/O, for per-write send-bound
    /// adjustments in writeFrameLocked. Both conn variants expose it.
    fn connFd(self: *Link) ?os.net.Handle {
        if (build_options.tls_server) {
            return switch (self.conn) {
                .plain => |plain| plain.fd,
                .tls => |t| t.fd,
            };
        }
        return self.conn.fd;
    }

    /// PING the peer and wait up to PROBE_MS for any inbound frame.
    fn answersProbe(self: *Link) bool {
        return self.answersProbeWithin(PROBE_MS);
    }

    /// The probe deadline is measured on the awake clock, not by counting
    /// nominal sleep steps: a slow PING write (big frame ahead of ours, a
    /// full peer receive buffer) must not stretch the window in which a
    /// new HELLO may take the name over — the hub decides exactly
    /// PROBE_MS after the probe started, whatever the steps took. The
    /// budget therefore covers the WHOLE probe: the deadline is armed
    /// BEFORE anything else, the write mutex admission and the PING write
    /// are both capped by what is left of it (see writeFrameByDeadline),
    /// and the wait loop below only spends the remainder.
    fn answersProbeWithin(self: *Link, probe_ms: u64) bool {
        const io = self.hub.io;
        const deadline = nowMs(io) + @as(i64, @intCast(probe_ms));
        const seen = self.rx_frames.load(.acquire);
        if (!self.writeFrameByDeadline(.ping, 0, &.{"probe"}, deadline)) return false;
        while (true) {
            if (self.dead.load(.acquire)) return false;
            if (self.rx_frames.load(.acquire) != seen) return true;
            if (nowMs(io) >= deadline) return false;
            os.sleepMs(PROBE_STEP_MS);
        }
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
/// `out_sid`, when given, receives the link stream id the request went out
/// on (0 when nothing was sent); the audit relay record joins on it.
pub fn forward(hub: *Hub, arena: Allocator, name: []const u8, body: []const u8, deadline_ms: u64, out_sid: ?*u32) !Forwarded {
    if (!link.validName(name)) return .unknown_node;
    const ln = hub.acquire(name) orelse return .unknown_node;
    defer ln.release();
    return forwardOn(ln, arena, body, deadline_ms, out_sid);
}

fn forwardOn(ln: *Link, arena: Allocator, body: []const u8, deadline_ms: u64, out_sid: ?*u32) !Forwarded {
    const io = ln.hub.io;
    _ = ln.inflight.fetchAdd(1, .acq_rel);
    defer _ = ln.inflight.fetchSub(1, .acq_rel);

    var w = Waiter{};
    const sid = ln.addWaiter(ln.nextSid(), &w) catch |err| switch (err) {
        error.LinkDead => return .node_disconnected,
        else => return err,
    };
    if (out_sid) |p| p.* = sid;
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
    /// Frame-key state for the link (the caller installs it on the link
    /// once the (untagged) WELCOME went out) — armed on every link, TLS
    /// included: the wire format must not depend on the local transport,
    /// or a TLS terminator in front of a plaintext hub would leave the
    /// ends disagreeing after a handshake that still completes.
    frame_auth: link.FrameAuth,
};

/// Key for the MAC computed when a pinned name is unknown, so that path
/// costs the same HMAC as a bad MAC for a known name.
const DUMMY_KEY = "mcp-node-reverse-unknown-name";

/// Time left of a handshake window of `budget_ms` counted from `started`
/// on the awake clock; 0 once it passed. The handshake's reads already
/// measure this way (readFrameWithinOn); its writes measure the same.
fn handshakeLeftMs(hub: *Hub, started: Io.Timestamp, budget_ms: u64) u64 {
    const elapsed_i = started.untilNow(hub.io, .awake).toMilliseconds();
    const elapsed: u64 = if (elapsed_i > 0) @intCast(elapsed_i) else 0;
    return if (elapsed >= budget_ms) 0 else budget_ms - elapsed;
}

/// Best-effort refusal GOAWAY inside the handshake budget (see handshake):
/// what is left of the window bounds the write, a spent window skips it.
fn handshakeRefuse(hub: *Hub, conn: Conn, timeout_ms: u64, started: Io.Timestamp, budget_ms: u64, text: []const u8) void {
    const left = handshakeLeftMs(hub, started, budget_ms);
    if (left == 0) return;
    link.writeFramePartsOn(conn, null, .goaway, 0, &.{text}, @min(timeout_ms, left)) catch {};
}

/// Authenticate a freshly accepted peer over `conn`. Returns the node name
/// and the WELCOME payload (in `arena`) or an error after sending GOAWAY
/// where that makes sense. `started` bounds the HELLO exchange — reads AND
/// writes — to `budget_ms`; a transport (TLS) handshake, when the build has
/// one, runs before this on its own separate budget (see authenticate).
fn handshake(hub: *Hub, arena: Allocator, conn: Conn, started: Io.Timestamp, budget_ms: u64) !Authenticated {
    const timeout_ms = @as(u64, hub.cfg.socket_timeout_s) * 1000;
    var nonce: [link.NONCE_LEN]u8 = undefined;
    // The handshake's writes share its ONE budget with the
    // reads: the CHALLENGE and every refusal GOAWAY take what is left of
    // `budget_ms`, never the accept-armed socket timeout — mirroring the
    // node side, which bounds its HELLO send the same way
    // (handshakeWithin). A peer that stops reading must not stretch the
    // handshake slot through a blocked send; with the budget spent the
    // refusal write is skipped and the stream close carries the message.
    // (POSIX plain-socket caveat, the same one the node carries: the
    // syscall bound of socketWriteAll rides SO_SNDTIMEO there, so the
    // parameter tightens the write over TLS and on Windows; the
    // left == 0 skip holds on every platform.)
    const challenge_left = handshakeLeftMs(hub, started, budget_ms);
    if (challenge_left == 0) return error.LinkTimeout;
    try hub.io.randomSecure(&nonce);
    try link.writeFramePartsOn(conn, null, .challenge, 0, &.{&nonce}, @min(timeout_ms, challenge_left));
    const frame = try link.readFrameWithinOn(arena, conn, null, link.MAX_HANDSHAKE_PAYLOAD, hub.io, started, budget_ms);
    if (frame.kind != .hello) {
        handshakeRefuse(hub, conn, timeout_ms, started, budget_ms, "expected hello");
        return error.BadHello;
    }
    const hello = link.parseHello(arena, frame.payload) catch |err| {
        handshakeRefuse(hub, conn, timeout_ms, started, budget_ms, "bad hello");
        return err;
    };
    const secret = hub.secrets.lookup(hello.name);
    // Unknown pinned names and bad MACs get the same answer and the same
    // work: the unknown-name path still computes one HMAC, with a dummy key.
    const mac_ok = link.verifyAuth(.node, secret orelse DUMMY_KEY, &nonce, &hello.nonce, hello.name, hello.auth);
    if (!(mac_ok and secret != null)) {
        handshakeRefuse(hub, conn, timeout_ms, started, budget_ms, "auth failed");
        return error.AuthFailed;
    }
    const welcome = try link.buildWelcome(arena, secret.?, &nonce, &hello.nonce, hello.name);
    // Session keys for the frames that follow: both nonces bind them to
    // this exact handshake. Armed on every link, TLS included — the frame
    // format must not depend on the local transport (see link.zig).
    return .{
        .name = hello.name,
        .welcome = welcome,
        .frame_auth = link.FrameAuth.init(.hub, secret.?, &nonce, &hello.nonce),
    };
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
    var reason: []const u8 = "closed";
    readLoop(ln) catch |err| {
        reason = @errorName(err);
        if (!ln.dead.load(.acquire)) std.debug.print("hub link '{s}' lost: {s}\n", .{ ln.name, @errorName(err) });
    };
    audit.linkDown(audit.fromCfg(hub.cfg), ln.name, reason);
}

/// Handshake, WELCOME and registration; closes the stream on any failure.
/// The handshake slot is released before the link becomes a reader.
fn authenticate(hub: *Hub, stream: Io.net.Stream, source: Source) ?*Link {
    // The peer address is read before any close below can free the socket.
    const peer = stream.socket.address;
    var peer_buf: [96]u8 = undefined;
    const peer_s = std.fmt.bufPrint(&peer_buf, "{f}", .{peer}) catch "";
    const aw = audit.fromCfg(hub.cfg);
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
    // The transport handshake (when the build has one) gets its own full
    // HANDSHAKE_MS budget; the HELLO exchange below gets another full
    // budget counted from `link_started`. They are re-armed separately on
    // purpose: a slow but legitimate TLS handshake (say, 8 s on a bad
    // link) must not leave the protocol exchange with a spent deadline —
    // that would time out honest nodes and count as their failure toward
    // the per-source ban. Worst case for one unauthenticated peer is
    // therefore 2 x HANDSHAKE_MS, still bounded by the handshake slots.
    const started = Io.Clock.awake.now(hub.io);
    var link_started = started;
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
                audit.linkFail(aw, peer_s, @errorName(err));
                stream.close(hub.io);
                return null;
            };
            conn = .{ .tls = tc };
            // The transport handshake finished: the protocol handshake
            // gets a fresh budget from this moment, not TLS's leftovers.
            link_started = Io.Clock.awake.now(hub.io);
        }
    }
    var auth = handshake(hub, arena_state.allocator(), conn, link_started, HANDSHAKE_MS) catch |err| {
        std.debug.print("hub handshake failed: {s}\n", .{@errorName(err)});
        audit.linkFail(aw, peer_s, @errorName(err));
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
    // Zero the local copy of the frame keys once the link owns its own.
    defer auth.frame_auth.secureZero();
    // Two live processes under one name would otherwise evict each other
    // forever. Keep the link that still answers; refuse the newcomer before
    // WELCOME, so it learns why and retries only at its backoff. Only an
    // authenticated peer gets this answer.
    if (hub.nameHeldByLiveLink(auth.name)) {
        std.debug.print("hub: refused a second link for '{s}': " ++ NAME_IN_USE ++ "\n", .{auth.name});
        audit.linkFail(aw, peer_s, "NameInUse");
        // The refusal rides the SAME unified budget as the handshake's own
        // writes (see handshakeRefuse): what is left of the protocol
        // handshake window bounds the GOAWAY. The probe may have spent the
        // rest by then — in which case the peer learns the refusal from
        // the close alone.
        handshakeRefuse(hub, conn, @as(u64, hub.cfg.socket_timeout_s) * 1000, link_started, HANDSHAKE_MS, NAME_IN_USE);
        stream.close(hub.io);
        return null;
    }
    const ln = Link.create(hub, stream, conn, auth.name) catch {
        stream.close(hub.io);
        return null;
    };
    conn_taken = true; // the link owns the transport state from here on
    // The TLS conn's mbedTLS context is shared between the link reader and
    // every frame writer from this point on: install the link's write
    // mutex into the conn before anything else can reach the link (the
    // WELCOME write, registration). The reader takes it only around
    // mbedtls_ssl_read, which answers from the conn's ciphertext buffer
    // and never blocks on the socket (see tls_server.zig); the socket
    // wait itself (fillRaw) runs without it, so writers stay free.
    // Writers themselves already hold this same mutex in Link.writeFrame.
    if (build_options.tls_server) {
        if (conn == .tls) conn.tls.lock = &ln.write_mutex;
    }
    // The WELCOME is the last untagged frame: it is part of the handshake
    // (the node verifies it before it arms its own tags). Frame tags and
    // their sequence numbers start at 0 with the next frame, so the keys
    // are installed only after this write.
    ln.writeFrame(.welcome, 0, &.{auth.welcome});
    ln.frame_auth = auth.frame_auth;
    if (ln.dead.load(.acquire)) {
        ln.release();
        return null;
    }
    hub.register(ln) catch {
        ln.release();
        return null;
    };
    std.debug.print("hub: node '{s}' connected\n", .{ln.name});
    audit.linkUp(aw, ln.name, peer_s);
    return ln;
}

fn readLoop(ln: *Link) !void {
    const auth: ?*link.FrameAuth = if (ln.frame_auth) |*fa| fa else null;
    while (!ln.dead.load(.acquire)) {
        // Any inbound frame refreshes liveness: the per-read idle bound is
        // the 45 s silence limit.
        const frame = try link.readFrameOn(gpa, ln.conn, auth, link.MAX_PAYLOAD, DEAD_AFTER_MS);
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
    // A stop() may land between the accept loop's check and this call.
    if (hub.stopping.load(.acquire)) {
        stream.close(hub.io);
        return;
    }
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
        if (comptime builtin.os.tag != .windows) {
            // POSIX: poll the listener together with the stop wake pipe —
            // stop() retracts this thread without allocating a new socket
            // (a self-connect would fail under fd exhaustion). The listen
            // fd is non-blocking (set in start), so a queue drained by a
            // reset between poll and accept answers null, never a park.
            var pfds: [2]std.posix.pollfd = .{
                .{ .fd = server.socket.handle, .events = std.posix.POLL.IN, .revents = 0 },
                .{ .fd = hub.wake_rfd orelse -1, .events = std.posix.POLL.IN, .revents = 0 },
            };
            _ = std.posix.poll(&pfds, 1000) catch { // tick is a fallback
                if (!hub.stopping.load(.acquire)) os.sleepMs(ACCEPT_BACKOFF_MS);
                continue;
            };
            if (hub.stopping.load(.acquire)) return;
            if (pfds[1].revents & std.posix.POLL.IN != 0) return; // wake byte
            if (pfds[0].revents & std.posix.POLL.IN == 0) continue; // tick
            // Drain every pending connection before polling again.
            while (os.net.acceptNonBlocking(server.socket.handle)) |stream| {
                if (hub.stopping.load(.acquire)) {
                    stream.close(hub.io);
                    return;
                }
                adopt(hub, stream);
            }
            continue;
        }
        // Windows std sockets are AFD handles, not Winsock SOCKETs.
        // Use the matching backend for accept; stop() self-connects to
        // release this blocking call before joining the thread.
        const stream = server.accept(hub.io) catch |err| {
            if (hub.stopping.load(.acquire)) return;
            std.debug.print("hub accept failed: {s}\n", .{@errorName(err)});
            os.sleepMs(ACCEPT_BACKOFF_MS);
            continue;
        };
        if (hub.stopping.load(.acquire)) {
            stream.close(hub.io);
            return;
        }
        adopt(hub, stream);
    }
}

/// Open the node-link listener and start the accept and pinger threads.
/// Both threads are joinable (their handles live on the hub): a later
/// startup failure — here or in main — retracts them through stop()
/// instead of unwinding shared state under detached threads.
/// `server` must outlive the hub (main keeps it for the process lifetime).
pub fn start(hub: *Hub, server: *Io.net.Server) !void {
    const ep = hub.cfg.hub_listen orelse return error.NoHubListen;
    // One rollback owner for everything start() acquires — TLS state, the
    // wake channel, the listener, both threads. stop() tolerates each
    // piece being absent, so this single errdefer covers every failure,
    // including TLS setup and listener acquisition themselves.
    var server_opt: ?*Io.net.Server = null;
    errdefer stop(hub, server_opt);
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
    // POSIX uses a pre-created pipe because acceptLoop polls it with the
    // listener. Windows uses std's blocking AFD accept and stop() releases
    // it with a loopback self-connect.
    if (comptime builtin.os.tag != .windows) {
        const pair = proc.createWakePipe() orelse return error.WakePipeFailed;
        hub.wake_rfd = pair[0];
        hub.wake_wfd = pair[1];
    }
    server.* = try os.net.listenTcp(hub.io, addr); // no SO_REUSEPORT, see os.net
    server_opt = server;
    if (comptime builtin.os.tag != .windows) {
        // Drain-after-poll must never park when a reset empties the queue.
        try os.net.setListenNonBlocking(server.socket.handle);
    }
    const a = try std.Thread.spawn(.{}, acceptLoop, .{ hub, server });
    hub.accept_thread = a;
    const p = try std.Thread.spawn(.{}, pinger, .{hub});
    hub.pinger_thread = p;
}

/// Stop the hub's infrastructure and link threads, close the listener and
/// release TLS state. Called by start's own rollback (pinger spawn
/// failure) and by main's errdefer once the hub is up, so no startup
/// failure unwinds arenas or the Io while hub threads still borrow them.
pub fn stop(hub: *Hub, server: ?*Io.net.Server) void {
    // Set stopping under the registry mutex: a register either completes
    // before this section (and is swept by killAll below) or observes
    // stopping afterwards and is refused — no link can be registered
    // after the kill sweep.
    hub.mutex.lockUncancelable(hub.io);
    hub.stopping.store(true, .release);
    hub.mutex.unlock(hub.io);
    hub.killAll();
    // POSIX writes to the pre-created wake pipe. Windows releases std's
    // blocking AFD accept with one loopback connection; acceptLoop closes
    // that stream after observing `stopping`.
    if (comptime builtin.os.tag == .windows) {
        if (server) |srv| {
            if (srv.socket.address.connect(hub.io, .{ .mode = .stream })) |st2| {
                st2.close(hub.io);
            } else |_| {}
        }
    } else if (hub.wake_wfd) |wfd| {
        var byte = [_]u8{1};
        os.writeAllFd(wfd, &byte) catch {};
    }
    if (hub.accept_thread) |t| {
        t.join();
        hub.accept_thread = null;
    }
    if (hub.pinger_thread) |t| {
        t.join();
        hub.pinger_thread = null;
    }
    // Link/reader threads: progress-guaranteed exit, no deadline — killed
    // links break their sockets (readers fail out of readLoop), and
    // handshake-stage threads hold the bounded HANDSHAKE_MS budget, so
    // every borrower of hub/cfg/io exits on its own. A deadline here would
    // only authorize freeing state a live thread still borrows.
    while (hub.threads.load(.acquire) != 0) os.sleepMs(5);
    if (server) |srv| srv.deinit(hub.io);
    if (comptime builtin.os.tag == .windows) {
        if (hub.wake_send) |*st| {
            st.close(hub.io);
            hub.wake_send = null;
        }
        if (hub.wake_recv) |*st| {
            st.close(hub.io);
            hub.wake_recv = null;
        }
    } else {
        if (hub.wake_rfd) |fd| {
            os.closeFd(fd);
            hub.wake_rfd = null;
        }
        if (hub.wake_wfd) |fd| {
            os.closeFd(fd);
            hub.wake_wfd = null;
        }
    }
    if (build_options.tls_server) {
        if (hub.tls) |srv| {
            srv.deinit();
            hub.tls = null;
        }
    }
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
    // 15 s ceiling: the legitimate work this waits on can take ~3.5 s, and
    // CI runners under load add seconds of scheduling slack.
    var spins: u32 = 0;
    while (v.load(.acquire) != 0 and spins < 3000) : (spins += 1) os.sleepMs(5);
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
    const ga = try link.readFrame(arena_state.allocator(), p1.far.socket.handle, null, link.MAX_HANDSHAKE_PAYLOAD, 5000);
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
            const f = link.readFrame(gpa, fd, null, link.MAX_PAYLOAD, 5000) catch return;
            defer gpa.free(f.payload);
            const resp = gpa.alloc(u8, 2 + f.payload.len) catch return;
            std.mem.writeInt(u16, resp[0..2], 201, .big);
            @memcpy(resp[2..], f.payload);
            // Feed it straight to the hub side, as the reader would.
            owner.fulfil(f.stream_id, resp);
        }
    };
    const t = try std.Thread.spawn(.{}, Peer.answer, .{ ln, far });
    const ok = try forwardOn(ln, arena, "{\"x\":1}", 5000, null);
    t.join();
    try testing.expectEqual(@as(u16, 201), ok.resp.status);
    try testing.expectEqualStrings("{\"x\":1}", ok.resp.body);
    try testing.expectEqual(@as(usize, 0), ln.waiterCount());

    // Timeout: nobody answers; the waiter is removed and a late RESP for
    // that stream_id is dropped (freed) instead of being delivered.
    const before = ln.next_sid.load(.acquire);
    const late = try forwardOn(ln, arena, "{}", 50, null);
    try testing.expect(late == .node_timeout);
    try testing.expectEqual(@as(usize, 0), ln.waiterCount());
    const stale = try gpa.alloc(u8, 2);
    std.mem.writeInt(u16, stale[0..2], 200, .big);
    ln.fulfil(before, stale);
    try testing.expectEqual(@as(usize, 0), ln.waiterCount());
    // drain the REQ frame the peer side never answered
    _ = try link.readFrame(arena, far, null, link.MAX_PAYLOAD, 5000);

    // Loss: the link dies while a request waits.
    const Killer = struct {
        fn run(owner: *Link) void {
            os.sleepMs(50);
            owner.kill();
        }
    };
    const k = try std.Thread.spawn(.{}, Killer.run, .{ln});
    const lost = try forwardOn(ln, arena, "{}", 5000, null);
    k.join();
    try testing.expect(lost == .node_disconnected);
    // A dead link refuses new waiters outright.
    try testing.expect((try forwardOn(ln, arena, "{}", 5000, null)) == .node_disconnected);
}

test "hub relay deadline is at least one hour" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var cfg = try testConfig(arena_state.allocator(), .hub);
    try testing.expectEqual(MIN_FORWARD_MS, forwardDeadlineMs(&cfg));
    cfg.socket_timeout_s = 7200;
    try testing.expectEqual(@as(u64, 7200 * 1000), forwardDeadlineMs(&cfg));
}

test "hub probe deadline follows the awake clock" {
    var fx: Fixture = undefined;
    try fx.init(.{ .single = "s3cret" });
    defer fx.deinit();
    const io = fx.threaded.io();

    const p = try tcpPair(io, &fx.server);
    defer p.far.close(io);
    const ln = try Link.create(&fx.hub, p.near, plainConn(p.near.socket.handle), "pc");
    defer ln.release();

    // A silent peer: the probe fails at its awake deadline (not after a
    // counted number of nominal 50 ms steps, and not instantly either).
    const t0 = Io.Clock.awake.now(io);
    try testing.expect(!ln.answersProbeWithin(300));
    const took = t0.untilNow(io, .awake).toMilliseconds();
    try testing.expect(took >= 250);
    try testing.expect(took < 2_000);

    // A frame arriving inside the window answers the probe at once.
    const Bump = struct {
        fn run(owner: *Link) void {
            os.sleepMs(100);
            _ = owner.rx_frames.fetchAdd(1, .acq_rel);
        }
    };
    const t = try std.Thread.spawn(.{}, Bump.run, .{ln});
    try testing.expect(ln.answersProbeWithin(300));
    t.join();
}

test "hub probe budget covers the PING write" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    var fx: Fixture = undefined;
    try fx.init(.{ .single = "s3cret" });
    defer fx.deinit();
    const io = fx.threaded.io();
    // Old behavior: the PING write carried the whole socket timeout (2 s
    // here, fd-bound to 1 s below) and the probe deadline was armed only
    // AFTER the write returned, so a blocked write stretched the window
    // in which a new HELLO may take the name over.
    fx.cfg.socket_timeout_s = 2;

    const p = try tcpPair(io, &fx.server);
    defer p.far.close(io);
    const ln = try Link.create(&fx.hub, p.near, plainConn(p.near.socket.handle), "pc");
    defer ln.release();
    const near_fd = p.near.socket.handle;
    // 1 s send bound (below the 2 s socket timeout) and a shrunken pipe,
    // then fill it with junk the silent peer never reads. The fill loop
    // ends only on WriteFailed — a POSIX send with zero progress in a
    // whole SO_SNDTIMEO window — proving the kernel cannot take another
    // byte: whatever this link writes next must block.
    try os.net.setSocketTimeouts(near_fd, 1);
    try std.posix.setsockopt(near_fd, std.posix.SOL.SOCKET, std.posix.SO.SNDBUF, std.mem.asBytes(&@as(c_int, 8192)));
    try std.posix.setsockopt(near_fd, std.posix.SOL.SOCKET, std.posix.SO.RCVBUF, std.mem.asBytes(&@as(c_int, 8192)));
    var junk: [128 * 1024]u8 = undefined;
    @memset(&junk, 0x6a);
    while (true) {
        _ = (link.FdConn{ .fd = near_fd }).write(&junk, 1_000) catch break;
    }

    const t0 = Io.Clock.awake.now(io);
    try testing.expect(!ln.answersProbeWithin(250));
    const took = t0.untilNow(io, .awake).toMilliseconds();
    // Fixed behavior: the write is capped by the probe budget. It fails
    // ~250 ms in (the tightened SO_SNDTIMEO), the kill lands, and the
    // probe ends at its window. Old behavior red-lines this assert: the
    // PING blocked the full 1 s fd send bound (and the old deadline
    // arming then added the 250 ms wait on top), running ~4x over the
    // budget. With no reader the blocked send is deterministic — it fails
    // exactly at SO_SNDTIMEO; nothing drains the pipe, so no wake-up race.
    try testing.expect(took >= 150);
    try testing.expect(took < 700);
}

test "hub probe budget bounds the write mutex admission" {
    var fx: Fixture = undefined;
    try fx.init(.{ .single = "s3cret" });
    defer fx.deinit();
    const io = fx.threaded.io();

    const p = try tcpPair(io, &fx.server);
    defer p.far.close(io);
    const ln = try Link.create(&fx.hub, p.near, plainConn(p.near.socket.handle), "pc");
    defer ln.release();

    // The probe deadline must bound the time spent QUEUING
    // for the write mutex, not only the PING write and the wait. A helper
    // (a backpressured writer mid large frame) holds the mutex far past
    // the 300 ms probe budget; the probe must still decide within its
    // window, so the handshake slot frees for a new HELLO instead of
    // parking behind the stuck writer. Old behavior red-lines this: the
    // uncancelable lock parks the probe for the holder's full 2 s.
    const Holder = struct {
        fn run(owner: *Link) void {
            const holder_io = owner.hub.io;
            owner.write_mutex.lockUncancelable(holder_io);
            defer owner.write_mutex.unlock(holder_io);
            os.sleepMs(2000);
        }
    };
    const t = try std.Thread.spawn(.{}, Holder.run, .{ln});
    // Let the holder actually take the mutex before the probe starts.
    os.sleepMs(100);

    const t0 = Io.Clock.awake.now(io);
    try testing.expect(!ln.answersProbeWithin(300));
    const took = t0.untilNow(io, .awake).toMilliseconds();
    t.join();
    // It really spent its budget deciding (not an instant false)...
    try testing.expect(took >= 250);
    // ...and the budget, not the holder's 2 s, ended the probe.
    try testing.expect(took < 1000);
}

// The same stuck writer that fails the probe must not also
// park Hub.register: the replacement GOAWAY runs on a small deadline
// (mutex admission included) and kill() breaks the blocked send instead.
// Old behavior: register's writeFrame took the old link's write mutex
// with an UNCANCELABLE lock and waited out the holder — with the new link
// already in the registry, its reader not started, and the handshake slot
// occupied the whole while.
test "hub register does not park behind the old link's stuck writer" {
    var fx: Fixture = undefined;
    try fx.init(.{ .single = "s3cret" });
    defer fx.deinit();
    const io = fx.threaded.io();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // The old link for "pc": registered, its peer silent, its write mutex
    // held by a writer that outlives the probe budget AND the GOAWAY
    // budget — the exact writer that just failed the probe.
    const p1 = try tcpPair(io, &fx.server);
    defer p1.far.close(io);
    const a = try Link.create(&fx.hub, p1.near, plainConn(p1.near.socket.handle), "pc");
    try fx.hub.register(a);
    const Holder = struct {
        fn run(owner: *Link) void {
            const holder_io = owner.hub.io;
            owner.write_mutex.lockUncancelable(holder_io);
            defer owner.write_mutex.unlock(holder_io);
            os.sleepMs(PROBE_MS + GOAWAY_BUDGET_MS + 1200);
        }
    };
    const t = try std.Thread.spawn(.{}, Holder.run, .{a});
    os.sleepMs(100); // the holder really holds the mutex by now

    // A real node takes the name over: the probe on the old link fails at
    // its own budget, and register replaces the old link on GOAWAY_BUDGET
    // — not on the holder's clock.
    var ncfg = try testConfig(arena, .node);
    var budget = InflightBudget{ .io = io, .max = ncfg.max_inflight_bytes };
    ncfg.inflight = &budget;
    var node = node_link.Node{ .io = io, .cfg = &ncfg };
    const p2 = try tcpPair(io, &fx.server);
    adopt(&fx.hub, p2.near);
    var result: anyerror!u64 = error.NotRun;
    const tnode = try std.Thread.spawn(.{}, nodeSessionThread, .{ &node, p2.far, &result });

    const t0 = Io.Clock.awake.now(io);
    const ln = try waitRegistered(&fx.hub, "pc");
    ln.release();
    // handshakes back to 0 == authenticate really returned (register done).
    try waitZero(&fx.hub.handshakes);
    const took = t0.untilNow(io, .awake).toMilliseconds();
    // The probe spent its full budget deciding (the mutex never freed)...
    try testing.expect(took >= 2500);
    // ...and the takeover ended ≈PROBE_MS+GOAWAY+ε, NOT on the holder's
    // clock: old behavior parked register behind the stuck writer for the
    // whole ~4.7 s hold. The threshold sits between the two behaviors with
    // slack for loaded CI; the forward below is the timing-free half of the
    // same invariant (the new link serves while the old writer still holds).
    try testing.expect(took < 4600);

    // forward on the NEW link works while the old writer still holds.
    const res = try forward(&fx.hub, arena, "pc", "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"ping\"}", 5000, null);
    try testing.expectEqual(@as(u16, 200), res.resp.status);

    fx.hub.killAll();
    tnode.join();
    try testing.expectError(error.LinkClosed, result);
    try waitZero(&node.workers);
    try waitZero(&fx.hub.threads);
    // The holder releases the mutex before the object it guards is freed.
    t.join();
    a.release();
}

// The handshake's writes live inside the same window as its
// reads. A spent window sends no CHALLENGE at all (old behavior armed the
// write with the full socket timeout); a fresh one bounds the exchange.
test "hub handshake writes live inside the handshake budget" {
    var fx: Fixture = undefined;
    try fx.init(.{ .single = "s3cret" });
    defer fx.deinit();
    const io = fx.threaded.io();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const p = try tcpPair(io, &fx.server);
    defer p.far.close(io);
    const conn = plainConn(p.near.socket.handle);
    const fd = p.far.socket.handle;

    // Window spent before the CHALLENGE: the write is skipped, the call
    // fails on the deadline, and nothing reaches the peer.
    const stale = Io.Clock.awake.now(io);
    os.sleepMs(150);
    try testing.expectError(error.LinkTimeout, handshake(&fx.hub, arena, conn, stale, 100));
    var probe: [1]u8 = undefined;
    try testing.expectError(error.LinkTimeout, (link.FdConn{ .fd = fd }).readSome(&probe, 250));

    // Fresh window: the CHALLENGE goes out (peer sees it after the fact),
    // then the silent peer fails the HELLO read at the same small budget.
    const fresh = Io.Clock.awake.now(io);
    try testing.expectError(error.LinkTimeout, handshake(&fx.hub, arena, conn, fresh, 250));
    const ch = try link.readFrame(arena, fd, null, link.MAX_HANDSHAKE_PAYLOAD, 2000);
    try testing.expectEqual(link.FrameType.challenge, ch.kind);
    try testing.expectEqual(link.NONCE_LEN, ch.payload.len);
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

    const res = try forward(&fx.hub, arena, "pc", "{\"jsonrpc\":\"2.0\",\"id\":42,\"method\":\"ping\"}", 5000, null);
    try testing.expectEqual(@as(u16, 200), res.resp.status);
    try testing.expect(std.mem.indexOf(u8, res.resp.body, "\"id\":42") != null);
    try testing.expect((try forward(&fx.hub, arena, "other", "{}", 5000, null)) == .unknown_node);
    try testing.expect((try forward(&fx.hub, arena, "a/b", "{}", 5000, null)) == .unknown_node);

    // Dropping the link on the hub side ends the node session.
    fx.hub.killAll();
    t.join();
    // The node's reader saw EOF and reported it instead of a clean exit.
    try testing.expectError(error.LinkClosed, result);
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
    const ch = try link.readFrame(arena, fd, null, link.MAX_HANDSHAKE_PAYLOAD, 5000);
    try testing.expectEqual(link.FrameType.challenge, ch.kind);
    try testing.expectEqual(link.NONCE_LEN, ch.payload.len);
    try link.writeFrame(fd, null, .ping, 0, "12345678", 5000);
    const ga = try link.readFrame(arena, fd, null, link.MAX_HANDSHAKE_PAYLOAD, 5000);
    try testing.expectEqual(link.FrameType.goaway, ga.kind);
    try waitZero(&fx.hub.threads);
}

test "hub drops an injected RESP frame without a valid tag" {
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

    // Complete the handshake as a genuine node would (the MAC must check
    // out), then read the WELCOME and arm the node-side frame keys.
    const ch = try link.readFrame(arena, fd, null, link.MAX_HANDSHAKE_PAYLOAD, 5000);
    try testing.expectEqual(link.FrameType.challenge, ch.kind);
    const hub_nonce: *const [link.NONCE_LEN]u8 = ch.payload[0..link.NONCE_LEN];
    var node_nonce: [link.NONCE_LEN]u8 = @splat(7);
    const hello = try link.buildHello(arena, "s3cret", hub_nonce, &node_nonce, "pc");
    try link.writeFrame(fd, null, .hello, 0, hello, 5000);
    const welcome = try link.readFrame(arena, fd, null, link.MAX_HANDSHAKE_PAYLOAD, 5000);
    try testing.expectEqual(link.FrameType.welcome, welcome.kind);
    // Node-side frame keys: needed to verify the tagged REQ the hub sends.
    var auth = link.FrameAuth.init(.node, "s3cret", hub_nonce, &node_nonce);

    // A request in flight so the RESP has a waiter to hit.
    const WaitFwd = struct {
        fn run(hub: *Hub, a: Allocator, out: *?Forwarded) void {
            out.* = forward(hub, a, "pc", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}", 5000, null) catch null;
        }
    };
    var got: ?Forwarded = null;
    const fw = try std.Thread.spawn(.{}, WaitFwd.run, .{ &fx.hub, arena, &got });
    // Wait until the link holds a waiter, read the REQ the hub sent
    // (tagged, like every post-handshake frame), then inject the fake
    // RESP: an attacker without the secret cannot tag it, so the hub
    // drops the link and the request fails as node_disconnected instead
    // of being answered by injected bytes.
    const ln = try waitRegistered(&fx.hub, "pc");
    var spins: u32 = 0;
    while (ln.waiterCount() == 0 and spins < 1000) : (spins += 1) os.sleepMs(5);
    ln.release();
    const reqf = try link.readFrame(arena, fd, &auth, link.MAX_PAYLOAD, 5000);
    try testing.expectEqual(link.FrameType.req, reqf.kind);
    var resp_payload: [2 + 18]u8 = undefined;
    std.mem.writeInt(u16, resp_payload[0..2], 200, .big);
    @memcpy(resp_payload[2..], "{\"id\":1,\"ok\":true}");
    const forged_tag = [_]u8{0xAA} ** link.MAC_LEN;
    var hdr: [link.HEADER_LEN]u8 = undefined;
    link.encodeHeader(&hdr, .{ .len = @intCast(resp_payload.len), .kind = .resp, .stream_id = 1 });
    try os.net.socketWriteAll(fd, &hdr, 5000);
    try os.net.socketWriteAll(fd, &resp_payload, 5000);
    try os.net.socketWriteAll(fd, &forged_tag, 5000);

    fw.join();
    try testing.expect(got != null);
    try testing.expect(got.? == .node_disconnected);
    try waitZero(&fx.hub.threads);
    try testing.expect(fx.hub.acquire("pc") == null);
    // The hub shut the link down: nothing more arrives from its side.
    try testing.expectError(error.LinkClosed, link.readFrame(arena, fd, null, link.MAX_PAYLOAD, 5000));
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
    const ch = try link.readFrame(arena_state.allocator(), q.far.socket.handle, null, link.MAX_HANDSHAKE_PAYLOAD, 5000);
    try testing.expectEqual(link.FrameType.challenge, ch.kind);
    try link.writeFrame(q.far.socket.handle, null, .ping, 0, "12345678", 5000);
    try waitZero(&fx.hub.threads);
    for (0..MAX_PENDING_PER_SOURCE) |_| fx.hub.finishSource(a, try Io.net.IpAddress.parse("192.0.2.1", 1), .neutral);
}

test "hub refuses new-name links past the established-link cap" {
    var fx: Fixture = undefined;
    try fx.init(.{ .single = "s" });
    defer fx.deinit();
    const io = fx.threaded.io();
    fx.cfg.max_node_links = 1;

    const p1 = try tcpPair(io, &fx.server);
    defer p1.far.close(io);
    const p2 = try tcpPair(io, &fx.server);
    defer p2.far.close(io);
    const p3 = try tcpPair(io, &fx.server);
    defer p3.far.close(io);
    const p4 = try tcpPair(io, &fx.server);
    defer p4.far.close(io);
    const a = try Link.create(&fx.hub, p1.near, plainConn(p1.near.socket.handle), "alpha");
    const b = try Link.create(&fx.hub, p2.near, plainConn(p2.near.socket.handle), "beta");
    const a2 = try Link.create(&fx.hub, p3.near, plainConn(p3.near.socket.handle), "alpha");
    const d = try Link.create(&fx.hub, p4.near, plainConn(p4.near.socket.handle), "beta");

    try fx.hub.register(a);
    // A second distinct name exceeds the cap: refused, no reader state.
    try testing.expectError(error.LinkCapacityExceeded, fx.hub.register(b));
    b.release();
    try testing.expect(fx.hub.acquire("beta") == null);
    // Same-name replacement stays allowed at the cap: the slot transfers.
    // `a` keeps its caller reference until after the dead check — the
    // registry's replacement release must not leave us reading freed memory.
    try fx.hub.register(a2);
    a2.release();
    try testing.expect(a.dead.load(.acquire));
    a.release();
    const cur = fx.hub.acquire("alpha").?;
    try testing.expect(cur == a2);
    cur.release();
    // Removing the link frees the slot: the previously refused name fits.
    fx.hub.unregister(a2);
    try testing.expect(fx.hub.acquire("alpha") == null);
    try fx.hub.register(d);
    d.release();
    const got = fx.hub.acquire("beta").?;
    try testing.expect(got == d);
    got.release();
}

test "hub stop retracts infrastructure threads and closes the listener" {
    var fx: Fixture = undefined;
    try fx.init(.{ .single = "s" });
    defer fx.deinit();
    const io = fx.threaded.io();

    fx.cfg.hub_listen = .{ .host = "127.0.0.1", .port = 0 };
    var server: Io.net.Server = undefined;
    try start(&fx.hub, &server);
    try testing.expect(fx.hub.accept_thread != null);
    try testing.expect(fx.hub.pinger_thread != null);
    // The accept loop's wake does not depend on allocating a socket.
    try testing.expect(fx.hub.wake_wfd != null);
    const bound = server.socket.address;

    // The startup-rollback entry point: threads join, the listener closes.
    stop(&fx.hub, &server);
    try testing.expect(fx.hub.accept_thread == null);
    try testing.expect(fx.hub.pinger_thread == null);
    try testing.expectEqual(@as(u32, 0), fx.hub.threads.load(.acquire));
    // The listener is gone: a fresh connect is refused.
    if (bound.connect(io, .{ .mode = .stream })) |st| {
        st.close(io);
        return error.ListenerStillOpen;
    } else |_| {}
    // A late registration — racing the stop sweep — is refused: no link
    // may enter the registry after the kill sweep.
    const p = try tcpPair(io, &fx.server);
    defer p.far.close(io);
    const late = try Link.create(&fx.hub, p.near, plainConn(p.near.socket.handle), "late");
    try testing.expectError(error.HubStopping, fx.hub.register(late));
    late.release();
    try testing.expect(fx.hub.acquire("late") == null);
}
