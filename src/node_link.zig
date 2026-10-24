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
const build_options = @import("build_options");
const tls_server = if (build_options.tls_server) @import("tls_server.zig") else struct {};

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

fn nowMs(io: Io) i64 {
    return Io.Clock.awake.now(io).toMilliseconds();
}

/// Time left before an absolute awake-clock deadline; 0 once it passed.
/// The node-side TLS socket callbacks use it so one logical operation
/// (the whole TLS handshake, one buffered record) is bounded by one
/// deadline no matter how many separate socket reads it takes.
fn deadlineLeftMs(deadline_ms: i64, now_ms: i64) u64 {
    const left = deadline_ms - now_ms;
    return if (left > 0) @intCast(left) else 0;
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
    if (!node.cfg.connect_tls) return session(node, stream);
    const tls = TlsState.start(node, stream) catch |err| {
        stream.close(node.io);
        return err;
    };
    return sessionOn(node, stream, .{ .tls = tls });
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
    return sessionOn(node, stream, .{ .plain = .{ .fd = stream.socket.handle } });
}

fn sessionOn(node: *Node, stream: Io.net.Stream, conn: Conn) !u64 {
    const io = node.io;
    const ln = std.heap.page_allocator.create(Link) catch {
        conn.deinit();
        stream.close(io);
        return error.OutOfMemory;
    };
    ln.* = .{ .node = node, .stream = stream, .conn = conn };
    defer ln.release();
    switch (conn) {
        .tls => |t| t.lock = &ln.write_mutex,
        .plain => {},
    }
    const fd = stream.socket.handle;
    const timeout_ms = @as(u64, node.cfg.socket_timeout_s) * 1000;
    os.net.setSocketTimeouts(fd, node.cfg.socket_timeout_s) catch return error.SocketOptionFailed;

    // The handshake proves the hub; its return value arms the frame tags
    // on every link, TLS included: the wire format must not depend on the
    // local transport, or a TLS terminator between the node and a
    // plaintext hub would leave the ends disagreeing after a handshake
    // that still completes (see link.zig). From here on every frame in
    // both directions carries a tag.
    var frame_auth = try handshake(node, conn, timeout_ms);
    ln.frame_auth = frame_auth;
    frame_auth.secureZero(); // the local copy; the link's is live
    const up_since = std.Io.Clock.awake.now(io);
    std.debug.print("node link: welcome as '{s}'\n", .{node.cfg.name});

    // The pinger is joined (it polls `dead` every 250 ms), so it never
    // outlives the session; only REQ workers can, via their reference.
    const ping_thread = try std.Thread.spawn(.{}, pinger, .{ln});
    defer ping_thread.join();
    defer ln.kill();

    readLoop(ln) catch |err| {
        std.debug.print("node link lost: {s}\n", .{@errorName(err)});
        return err;
    };
    const up = up_since.untilNow(io, .awake).toMilliseconds();
    return if (up > 0) @intCast(up) else 0;
}

/// Run the mutual handshake. Returns the frame-key state the caller
/// installs on the link — on every link, TLS included: the tags ride
/// inside the TLS records, so a terminator between the node and a
/// plaintext hub changes nothing on the wire (see link.zig).
fn handshake(node: *Node, conn: Conn, timeout_ms: u64) !link.FrameAuth {
    return handshakeWithin(node, conn, timeout_ms, HANDSHAKE_MS);
}

/// The whole applied handshake — CHALLENGE read, HELLO send, WELCOME
/// read — runs under ONE absolute deadline of `budget_ms` on the awake
/// clock: a hub that dribbles one byte per read cannot stretch it into
/// idle_ms x reads (where readFrameOn hands every partial read a fresh idle
/// budget). What is left of the deadline
/// also bounds the HELLO send — and, over TLS, this phase's socket
/// writes and reads, via TlsState's own deadline fields.
fn handshakeWithin(node: *Node, conn: Conn, timeout_ms: u64, budget_ms: u64) !link.FrameAuth {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = node.io;
    const started = Io.Clock.awake.now(io);
    const deadline = nowMs(io) + @as(i64, @intCast(budget_ms));

    // Over TLS, bound this phase's writes by the same deadline: sockDrain
    // honors send_deadline while it is set. Plain writes take the time
    // left as their timeout below. Single-threaded here either way: the
    // link (and its writer mutex users) does not exist until WELCOME.
    const tls_state: ?*TlsState = switch (conn) {
        .tls => |t| t,
        .plain => null,
    };
    if (tls_state) |t| t.send_deadline = deadline;
    defer {
        if (tls_state) |t| t.send_deadline = null;
    }

    const ch = try link.readFrameWithinOn(arena, conn, null, link.MAX_HANDSHAKE_PAYLOAD, io, started, budget_ms);
    if (ch.kind != .challenge or ch.payload.len != link.NONCE_LEN) return error.BadChallenge;
    const hub_nonce: *const [link.NONCE_LEN]u8 = ch.payload[0..link.NONCE_LEN];
    var node_nonce: [link.NONCE_LEN]u8 = undefined;
    node.io.randomSecure(&node_nonce) catch return error.EntropyUnavailable;
    const secret = node.cfg.connect_secret;
    const hello = try link.buildHello(arena, secret, hub_nonce, &node_nonce, node.cfg.name);
    const left = deadlineLeftMs(deadline, nowMs(io));
    if (left == 0) return error.LinkTimeout;
    try link.writeFramePartsOn(conn, null, .hello, 0, &.{hello}, @min(timeout_ms, left));

    // The hub must prove the secret before any other frame is accepted:
    // nothing reaches the read loop (and so rpc.handleRpc) until then.
    const reply = try link.readFrameWithinOn(arena, conn, null, link.MAX_HANDSHAKE_PAYLOAD, io, started, budget_ms);
    switch (reply.kind) {
        .welcome => {
            if (!link.verifyWelcome(arena, secret, hub_nonce, &node_nonce, node.cfg.name, reply.payload)) {
                std.debug.print("node link: hub authentication failed\n", .{});
                return error.HubAuthFailed;
            }
        },
        .goaway => {
            var safe: [GOAWAY_PRINT_MAX]u8 = undefined;
            std.debug.print("node link: hub refused: {s}\n", .{printable(&safe, reply.payload)});
            return error.Refused;
        },
        else => {
            std.debug.print("node link: hub authentication failed\n", .{});
            return error.HubAuthFailed;
        },
    }
    // Session keys for the frames that follow: both nonces bind the keys
    // to this exact handshake, and the two directions get distinct keys.
    // Always armed, over TLS too — the frame format must not depend on
    // the local transport (see the module doc in link.zig).
    return link.FrameAuth.init(.node, secret, hub_nonce, &node_nonce);
}

const GOAWAY_PRINT_MAX = 200;

/// Copy hub-supplied text for the log: printable ASCII only (others become
/// '?'), at most GOAWAY_PRINT_MAX bytes, so a peer cannot inject terminal
/// escapes or flood the log.
fn printable(out: *[GOAWAY_PRINT_MAX]u8, text: []const u8) []const u8 {
    const n = @min(text.len, out.len);
    for (text[0..n], out[0..n]) |c, *o| o.* = if (c >= 0x20 and c <= 0x7e) c else '?';
    return out[0..n];
}

/// Byte channel of one link: the plain socket, or TLS over it.
const Conn = union(enum) {
    plain: link.FdConn,
    tls: *TlsState,

    pub fn readSome(self: Conn, buf: []u8, timeout_ms: u64) !usize {
        return switch (self) {
            .plain => |c| c.readSome(buf, timeout_ms),
            .tls => |t| t.readSome(buf, timeout_ms),
        };
    }

    pub fn write(self: Conn, bytes: []const u8, timeout_ms: u64) !void {
        return switch (self) {
            .plain => |c| c.write(bytes, timeout_ms),
            .tls => |t| t.write(bytes),
        };
    }

    pub fn flush(self: Conn, timeout_ms: u64) !void {
        return switch (self) {
            .plain => |c| c.flush(timeout_ms),
            .tls => |t| t.flush(),
        };
    }

    fn deinit(self: Conn) void {
        switch (self) {
            .plain => {},
            .tls => |t| t.destroy(),
        }
    }
};

/// TLS client state for one link (heap-pinned: the client keeps pointers
/// to the socket reader/writer). Ciphertext moves through the os.net
/// helpers, so read deadlines behave exactly like the plain path: every
/// socket read is armed with SO_RCVTIMEO (software deadline on Windows)
/// and a timeout surfaces as error.LinkTimeout. One logical operation —
/// the whole TLS handshake, or one record buffered for one read — is
/// bounded by one absolute deadline (read_deadline/send_deadline): each
/// socket read inside it is armed with the time left, so a dribbling
/// peer cannot stretch the budget.
///
/// Locking: writers run under the link write mutex. The std client is not
/// split into independent read and write halves: when a received TLS 1.3
/// KeyUpdate asks for an update, the read path rotates the client write
/// key and resets the write sequence number. Decrypting therefore also
/// runs under the write mutex. To keep socket waits out of the lock, the
/// reader first buffers one complete ciphertext record without the lock
/// (only the read path touches that input buffer), then decrypts exactly
/// that record under the lock, which needs no socket I/O. std does not
/// send the KeyUpdate reply the RFC asks for; a hub that requests one may
/// then fail to decrypt our records and drop the link, which reconnects.
const TlsState = struct {
    const tls = std.crypto.tls;
    const BUF = tls.Client.min_buffer_len;

    fd: os.net.Handle,
    io: Io,
    /// The link write mutex; null until the link exists (handshake is
    /// single-threaded).
    lock: ?*Io.Mutex = null,
    /// Deadline for the next socket read and the error behind ReadFailed.
    read_timeout_ms: u64 = HANDSHAKE_MS,
    read_err: ?anyerror = null,
    send_timeout_ms: u64,
    /// Absolute awake-clock deadline (ms) that bounds the whole logical
    /// read in progress — the entire TLS handshake, or one record
    /// buffered for one readSome call. While set, every socket read is
    /// armed with the time left before it instead of a fresh
    /// read_timeout_ms, so a hub that dribbles one segment per read
    /// cannot stretch one budget into many. Written only by the thread
    /// that owns the current read phase; cleared when that phase ends.
    read_deadline: ?i64 = null,
    /// Same for handshake writes: one deadline for the whole TLS
    /// handshake (single-threaded there). Null afterwards, when each
    /// write is bounded by send_timeout_ms.
    send_deadline: ?i64 = null,
    sock_in: Io.Reader,
    sock_out: Io.Writer,
    client: tls.Client = undefined,
    bundle: std.crypto.Certificate.Bundle = .empty,
    bundle_lock: Io.RwLock = .init,
    in_buf: [BUF]u8 = undefined,
    out_buf: [BUF]u8 = undefined,
    plain_in: [BUF]u8 = undefined,
    plain_out: [BUF]u8 = undefined,

    fn start(node: *Node, stream: Io.net.Stream) !*TlsState {
        const io = node.io;
        const cfg = node.cfg;
        const gpa = std.heap.page_allocator;
        const self = try gpa.create(TlsState);
        errdefer gpa.destroy(self);
        self.* = .{
            .fd = stream.socket.handle,
            .io = io,
            .send_timeout_ms = @as(u64, cfg.socket_timeout_s) * 1000,
            .sock_in = .{ .vtable = &.{ .stream = sockStream }, .buffer = &.{}, .seek = 0, .end = 0 },
            .sock_out = .{ .vtable = &.{ .drain = sockDrain }, .buffer = &.{} },
        };
        self.sock_in.buffer = &self.in_buf;
        self.sock_out.buffer = &self.out_buf;
        errdefer self.bundle.deinit(gpa);
        os.net.setSocketTimeouts(self.fd, cfg.socket_timeout_s) catch return error.SocketOptionFailed;

        const now = Io.Clock.real.now(io);
        if (cfg.connect_ca_file) |path| {
            const loaded = if (std.fs.path.isAbsolute(path))
                self.bundle.addCertsFromFilePathAbsolute(gpa, io, now, path)
            else
                self.bundle.addCertsFromFilePath(gpa, io, now, Io.Dir.cwd(), path);
            loaded catch |err| {
                std.debug.print("node link: cannot load MCP_NODE_CONNECT_CA_FILE: {s}\n", .{@errorName(err)});
                return error.CaFileUnusable;
            };
        } else {
            self.bundle.rescan(gpa, io, now) catch |err| {
                std.debug.print("node link: cannot load the system CA bundle: {s}\n", .{@errorName(err)});
                return error.CaBundleUnusable;
            };
        }

        var entropy: [tls.Client.Options.entropy_len]u8 = undefined;
        io.randomSecure(&entropy) catch return error.EntropyUnavailable;
        defer std.crypto.secureZero(u8, &entropy);
        // One absolute deadline for the whole TLS handshake. The std
        // client reads ServerHello, Certificate and Finished as separate
        // socket reads; arming each with the full read timeout would let
        // a hub that dribbles one byte per timeout park us forever (each
        // read resets the clock). Every socket read and write below is
        // armed with the time left of HANDSHAKE_MS instead.
        self.read_deadline = nowMs(io) + @as(i64, @intCast(HANDSHAKE_MS));
        self.send_deadline = self.read_deadline;
        defer {
            self.read_deadline = null;
            self.send_deadline = null;
        }
        self.client = tls.Client.init(&self.sock_in, &self.sock_out, .{
            .host = .{ .explicit = cfg.connect_server_name },
            .ca = .{ .bundle = .{ .gpa = gpa, .io = io, .lock = &self.bundle_lock, .bundle = &self.bundle } },
            .write_buffer = &self.plain_out,
            .read_buffer = &self.plain_in,
            .entropy = &entropy,
            .realtime_now = now,
        }) catch |err| {
            const cause: anyerror = switch (err) {
                error.ReadFailed => self.read_err orelse err,
                else => err,
            };
            std.debug.print("node link: TLS handshake failed: {s}\n", .{@errorName(cause)});
            return error.TlsHandshakeFailed;
        };
        return self;
    }

    fn destroy(self: *TlsState) void {
        self.bundle.deinit(std.heap.page_allocator);
        std.heap.page_allocator.destroy(self);
    }

    fn readSome(self: *TlsState, buf: []u8, timeout_ms: u64) !usize {
        if (buf.len == 0) return 0;
        const plain = &self.client.reader;
        self.read_timeout_ms = timeout_ms;
        self.read_err = null;
        // One absolute deadline covers the whole read: buffering one
        // ciphertext record may take several socket reads, and the loop
        // below may need more than one record before plaintext appears.
        // Each socket read is armed with the time left, so a peer that
        // dribbles one segment per read cannot stretch timeout_ms into
        // N times timeout_ms (the DEAD_AFTER_MS bound must stay a bound).
        self.read_deadline = nowMs(self.io) + @as(i64, @intCast(timeout_ms));
        defer self.read_deadline = null;
        while (true) {
            // Plaintext already decrypted: only this thread moves the
            // client reader's seek/end, so no lock is needed to copy it.
            const ready = plain.buffered();
            if (ready.len > 0) {
                const n = @min(ready.len, buf.len);
                @memcpy(buf[0..n], ready[0..n]);
                plain.toss(n);
                return n;
            }
            self.bufferRecord() catch return self.readError();
            self.decryptOne() catch |err| switch (err) {
                error.EndOfStream => return 0,
                error.ReadFailed => return self.readError(),
            };
        }
    }

    fn readError(self: *TlsState) error{ LinkTimeout, LinkClosed } {
        if (self.read_err) |e| {
            if (e == error.LinkTimeout) return error.LinkTimeout;
        }
        return error.LinkClosed;
    }

    /// Read ciphertext (no lock) until one whole record is buffered, the
    /// header announces an oversize record, or the socket hit EOF; the
    /// std client reports the last two on decrypt. Every socket read
    /// here is armed with the time left of the caller's absolute
    /// deadline (readSome or the TLS handshake), so a dribbling peer
    /// cannot stretch one record across many per-read timeouts.
    fn bufferRecord(self: *TlsState) error{ReadFailed}!void {
        const in = &self.sock_in;
        while (true) {
            const b = in.buffered();
            if (b.len >= tls.record_header_len) {
                const rec_len = std.mem.readInt(u16, b[3..5], .big);
                if (rec_len > tls.max_ciphertext_len) return;
                if (b.len >= tls.record_header_len + rec_len) return;
            }
            in.fillMore() catch |err| switch (err) {
                error.EndOfStream => return,
                error.ReadFailed => return error.ReadFailed,
            };
        }
    }

    /// Process the buffered record under the write mutex. With a whole
    /// record buffered the std client does not touch the socket here,
    /// except after EOF, where the read returns at once.
    fn decryptOne(self: *TlsState) Io.Reader.Error!void {
        if (self.lock) |m| m.lockUncancelable(self.io);
        defer if (self.lock) |m| m.unlock(self.io);
        try self.client.reader.fillMore();
    }

    fn write(self: *TlsState, bytes: []const u8) !void {
        self.client.writer.writeAll(bytes) catch return error.WriteFailed;
    }

    fn flush(self: *TlsState) !void {
        self.client.writer.flush() catch return error.WriteFailed;
        self.sock_out.flush() catch return error.WriteFailed;
    }

    fn sockStream(r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const self: *TlsState = @alignCast(@fieldParentPtr("sock_in", r));
        const dest = limit.slice(try w.writableSliceGreedy(1));
        const timeout_ms: u64 = if (self.read_deadline) |d| blk: {
            // The armed deadline rules, not the per-read timeout: what is
            // left of the whole logical read bounds this socket read.
            const left = deadlineLeftMs(d, nowMs(self.io));
            if (left == 0) {
                self.read_err = error.LinkTimeout;
                return error.ReadFailed;
            }
            break :blk left;
        } else self.read_timeout_ms;
        const n = (link.FdConn{ .fd = self.fd }).readSome(dest, timeout_ms) catch |err| {
            self.read_err = err;
            return error.ReadFailed;
        };
        if (n == 0) return error.EndOfStream;
        w.advance(n);
        return n;
    }

    fn sockDrain(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
        const self: *TlsState = @alignCast(@fieldParentPtr("sock_out", w));
        const t: u64 = if (self.send_deadline) |d| blk: {
            // During the TLS handshake the whole exchange shares one
            // deadline: each write gets the time left, expiry fails it.
            const left = deadlineLeftMs(d, nowMs(self.io));
            if (left == 0) return error.WriteFailed;
            break :blk left;
        } else self.send_timeout_ms;
        os.net.socketWriteAll(self.fd, w.buffer[0..w.end], t) catch return error.WriteFailed;
        w.end = 0;
        var n: usize = 0;
        for (data[0 .. data.len - 1]) |d| {
            os.net.socketWriteAll(self.fd, d, t) catch return error.WriteFailed;
            n += d.len;
        }
        const last = data[data.len - 1];
        for (0..splat) |_| {
            os.net.socketWriteAll(self.fd, last, t) catch return error.WriteFailed;
            n += last.len;
        }
        return n;
    }
};

const Link = struct {
    node: *Node,
    stream: Io.net.Stream,
    conn: Conn,
    /// Frame-key state, armed once after the handshake — on plaintext and
    /// TLS links alike (tags ride inside the TLS records; see link.zig).
    /// tx_seq is guarded by write_mutex, rx_seq by the reader.
    frame_auth: ?link.FrameAuth = null,
    write_mutex: std.Io.Mutex = .init,
    refs: std.atomic.Value(u32) = .init(1),
    dead: std.atomic.Value(bool) = .init(false),

    fn retain(self: *Link) void {
        _ = self.refs.fetchAdd(1, .monotonic);
    }

    fn release(self: *Link) void {
        if (self.refs.fetchSub(1, .acq_rel) != 1) return;
        if (self.frame_auth) |*fa| fa.secureZero();
        self.conn.deinit();
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
        const auth: ?*link.FrameAuth = if (self.frame_auth) |*fa| fa else null;
        link.writeFramePartsOn(self.conn, auth, kind, sid, parts, timeout_ms) catch self.kill();
    }

    fn writeResp(self: *Link, sid: u32, status: u16, body: []const u8) void {
        var prefix: [2]u8 = undefined;
        std.mem.writeInt(u16, &prefix, status, .big);
        self.writeFrame(.resp, sid, &.{ &prefix, body });
    }
};

fn readLoop(ln: *Link) !void {
    const gpa = std.heap.page_allocator;
    const auth: ?*link.FrameAuth = if (ln.frame_auth) |*fa| fa else null;
    while (!ln.dead.load(.acquire)) {
        const frame = try link.readFrameOn(gpa, ln.conn, auth, link.MAX_PAYLOAD, DEAD_AFTER_MS);
        switch (frame.kind) {
            .req => dispatch(ln, frame.stream_id, frame.payload), // takes payload
            .ping => {
                defer gpa.free(frame.payload);
                ln.writeFrame(.pong, frame.stream_id, &.{frame.payload});
            },
            .pong => gpa.free(frame.payload),
            .goaway => {
                defer gpa.free(frame.payload);
                var safe: [GOAWAY_PRINT_MAX]u8 = undefined;
                std.debug.print("node link: hub said goaway: {s}\n", .{printable(&safe, frame.payload)});
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
    var client_buf: [96]u8 = undefined;
    const client = if (node.cfg.connect) |ep|
        std.fmt.bufPrint(&client_buf, "hub:{s}:{d}", .{ ep.host, ep.port }) catch "hub"
    else
        "hub";
    const rpc = rpc_mod.handleRpcCtx(ra, node.io, node.cfg, copy.body, .{
        .transport = .link,
        .client = client,
        .link_sid = copy.sid,
    }) catch |err| {
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

test "node link goaway text is escaped and capped for the log" {
    var out: [GOAWAY_PRINT_MAX]u8 = undefined;
    try testing.expectEqualStrings("bye ?[2J?", printable(&out, "bye \x1b[2J\xff"));
    const long = "x" ** 300;
    try testing.expectEqual(@as(usize, GOAWAY_PRINT_MAX), printable(&out, long).len);
    try testing.expectEqualStrings("", printable(&out, ""));
}

test "node link backoff cap doubles from 0.5 s to 30 s" {
    try testing.expectEqual(@as(u64, 500), backoffCapMs(0));
    try testing.expectEqual(@as(u64, 1000), backoffCapMs(1));
    try testing.expectEqual(@as(u64, 16000), backoffCapMs(5));
    try testing.expectEqual(@as(u64, 30000), backoffCapMs(6));
    try testing.expectEqual(@as(u64, 30000), backoffCapMs(1000));
}

test "node link deadline math saturates at zero and counts down" {
    try testing.expectEqual(@as(u64, 500), deadlineLeftMs(10_000, 9_500));
    try testing.expectEqual(@as(u64, 1), deadlineLeftMs(10_000, 9_999));
    try testing.expectEqual(@as(u64, 0), deadlineLeftMs(10_000, 10_000));
    try testing.expectEqual(@as(u64, 0), deadlineLeftMs(10_000, 25_000));
}

test "node link bufferRecord is bounded by the absolute read deadline" {
    var threaded = Io.Threaded.init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const any = try Io.net.IpAddress.parse("127.0.0.1", 0);
    var server = try any.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    const far = try server.socket.address.connect(io, .{ .mode = .stream });
    defer far.close(io);
    const near = try server.accept(io);
    defer near.close(io);
    try os.net.setSocketTimeouts(near.socket.handle, 10);

    const gpa = std.heap.page_allocator;
    const self = try gpa.create(TlsState);
    defer gpa.destroy(self);
    self.* = .{
        .fd = near.socket.handle,
        .io = io,
        .send_timeout_ms = 10_000,
        .sock_in = .{ .vtable = &.{ .stream = TlsState.sockStream }, .buffer = &.{}, .seek = 0, .end = 0 },
        .sock_out = .{ .vtable = &.{ .drain = TlsState.sockDrain }, .buffer = &.{} },
    };
    self.sock_in.buffer = &self.in_buf;
    self.sock_out.buffer = &self.out_buf;

    // A record header announcing 32 bytes of body, with only 8 of them
    // ever arriving: bufferRecord must keep filling, but the armed
    // absolute deadline — not the per-read timeout — decides when to
    // give up. With the old per-read arming this would block for
    // read_timeout_ms (seconds); with the deadline it fails at ~300 ms.
    var head: [13]u8 = undefined;
    head[0] = 0x17;
    head[1] = 0x03;
    head[2] = 0x03;
    head[3] = 0x00;
    head[4] = 0x20;
    @memset(head[5..13], 0xaa);
    try os.net.socketWriteAll(far.socket.handle, &head, 5000);

    self.read_timeout_ms = HANDSHAKE_MS; // the old per-read bound
    self.read_deadline = nowMs(io) + 300; // what readSome/the handshake arm
    const t0 = Io.Clock.awake.now(io);
    try testing.expectError(error.ReadFailed, self.bufferRecord());
    const took = t0.untilNow(io, .awake).toMilliseconds();
    try testing.expectEqual(@as(anyerror, error.LinkTimeout), self.read_err.?);
    // It waited for the deadline (not a spurious early error)...
    try testing.expect(took >= 200);
    // ...and the deadline, not the per-read timeout, ended it.
    try testing.expect(took < 5_000);

    // With the rest of the record available the deadline does not fire
    // and bufferRecord completes normally.
    var rest: [24]u8 = @splat(0xbb);
    try os.net.socketWriteAll(far.socket.handle, &rest, 5000);
    self.read_deadline = nowMs(io) + 2_000;
    try self.bufferRecord();
}

test "node link handshake is bounded by one absolute deadline" {
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
    const far = try server.socket.address.connect(io, .{ .mode = .stream });
    defer far.close(io);
    const near = try server.accept(io);
    defer near.close(io);
    try os.net.setSocketTimeouts(near.socket.handle, 5);
    try os.net.setSocketTimeouts(far.socket.handle, 5);

    // A hub that dribbles the CHALLENGE one byte at a time, each pause
    // comfortably inside any per-read idle budget, but the whole frame
    // far past the handshake budget: the handshake must hit the ONE
    // absolute deadline, not idle x 41 partial reads.
    const Dribbler = struct {
        fn run(fd: os.net.Handle) void {
            var frame: [link.HEADER_LEN + link.NONCE_LEN]u8 = undefined;
            link.encodeHeader(frame[0..link.HEADER_LEN], .{
                .len = link.NONCE_LEN,
                .kind = .challenge,
                .stream_id = 0,
            });
            @memset(frame[link.HEADER_LEN..], 4);
            for (frame) |b| {
                var one = [1]u8{b};
                os.net.socketWriteAll(fd, &one, 5000) catch return;
                os.sleepMs(40); // 41 bytes x 40 ms = 1.6 s of dribble
            }
        }
    };
    const t = try std.Thread.spawn(.{}, Dribbler.run, .{far.socket.handle});

    const t0 = Io.Clock.awake.now(io);
    try testing.expectError(
        error.LinkTimeout,
        handshakeWithin(&node, .{ .plain = .{ .fd = near.socket.handle } }, 5000, 300),
    );
    const took = t0.untilNow(io, .awake).toMilliseconds();
    t.join();
    // It really waited for the deadline (not an early error)...
    try testing.expect(took >= 250);
    // ...and the deadline, not 1.6 s of dribbled idle reads, ended it.
    try testing.expect(took < 900);
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

/// A scripted hub peer for plaintext-link tests: it runs the real
/// handshake (CHALLENGE/HELLO/WELCOME) and ends up with the same frame
/// keys a genuine hub would derive, so the test can speak the tagged wire
/// format — or deliberately break it.
fn scriptedHubHandshake(arena: std.mem.Allocator, fd: os.net.Handle) !link.FrameAuth {
    var nonce: [link.NONCE_LEN]u8 = @splat(4);
    try link.writeFrame(fd, null, .challenge, 0, &nonce, 5000);
    const hello_frame = try link.readFrame(arena, fd, null, link.MAX_HANDSHAKE_PAYLOAD, 5000);
    const hello = try link.parseHello(arena, hello_frame.payload);
    const welcome = try link.buildWelcome(arena, "s3cret", &nonce, &hello.nonce, hello.name);
    try link.writeFrame(fd, null, .welcome, 0, welcome, 5000);
    return link.FrameAuth.init(.hub, "s3cret", &nonce, &hello.nonce);
}

/// Write one fully crafted post-handshake frame: header, payload, tag as
/// given (all bytes go on the wire exactly as provided).
fn writeRawFrame(fd: os.net.Handle, kind: link.FrameType, sid: u32, payload: []const u8, tag: *const [link.MAC_LEN]u8) !void {
    var hdr: [link.HEADER_LEN]u8 = undefined;
    link.encodeHeader(&hdr, .{ .len = @intCast(payload.len), .kind = kind, .stream_id = sid });
    try os.net.socketWriteAll(fd, &hdr, 5000);
    try os.net.socketWriteAll(fd, payload, 5000);
    try os.net.socketWriteAll(fd, tag, 5000);
}

const REQ_BODY = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}";

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

    // Handshake as a genuine hub would, then arm the frame keys: every
    // frame after WELCOME is tagged on both directions.
    var auth = try scriptedHubHandshake(arena, fd);
    try link.writeFrame(fd, &auth, .req, 7, REQ_BODY, 5000);
    const resp = try link.readFrame(arena, fd, &auth, link.MAX_PAYLOAD, 5000);
    try testing.expectEqual(link.FrameType.resp, resp.kind);
    try testing.expectEqual(@as(u32, 7), resp.stream_id);
    const r = try link.splitResp(resp.payload);
    try testing.expectEqual(@as(u16, 200), r.status);
    try testing.expect(std.mem.indexOf(u8, r.body, "\"id\":1") != null);

    try link.writeFrame(fd, &auth, .ping, 0, "12345678", 5000);
    const pong = try link.readFrame(arena, fd, &auth, link.MAX_HANDSHAKE_PAYLOAD, 5000);
    try testing.expectEqual(link.FrameType.pong, pong.kind);
    try testing.expectEqualStrings("12345678", pong.payload);

    try link.writeFrame(fd, &auth, .goaway, 0, "bye", 5000);
    t.join();
    try testing.expectError(error.GoAway, result);
    // The REQ worker finishes (and drops its link reference) shortly after
    // its RESP went out; wait for it before the stack frame goes away.
    var spins: u32 = 0;
    while (node.workers.load(.acquire) != 0 and spins < 400) : (spins += 1) os.sleepMs(5);
    try testing.expectEqual(@as(u32, 0), node.workers.load(.acquire));
}

// The frame format must not depend on the LOCAL
// transport. Topology under test — the terminator deployment:
//   node --TLS--> terminator (mbedTLS) --plain--> plaintext hub.
// Both ends derive and arm frame keys from the shared handshake transcript
// so every post-WELCOME frame is tagged end-to-end across the relay.
test "node link speaks tagged frames through a TLS terminator relay" {
    if (comptime !build_options.tls_server) return error.SkipZigTest; // mbedTLS only exists in -Dtls-server builds

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var threaded = Io.Threaded.init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var cfg = try testConfig(arena);
    const pems = try tls_server.writeTestPems(io, "term");
    defer std.heap.page_allocator.free(pems.cert);
    defer std.heap.page_allocator.free(pems.key);
    cfg.connect_tls = true;
    cfg.connect_ca_file = pems.cert;
    cfg.connect_server_name = "localhost"; // the test pair's CN
    var budget = InflightBudget{ .io = io, .max = cfg.max_inflight_bytes };
    cfg.inflight = &budget;
    var node = Node{ .io = io, .cfg = &cfg };

    const any = try Io.net.IpAddress.parse("127.0.0.1", 0);
    var server = try any.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    // Node-facing socket, accepted by the TLS terminator.
    const client = try server.socket.address.connect(io, .{ .mode = .stream });
    const term_side = try server.accept(io);
    // Terminator-to-hub plain socket pair.
    const hf = try server.socket.address.connect(io, .{ .mode = .stream });
    const hub_side = try server.accept(io);
    // Closed exactly once — explicitly at the end, or here on failure.
    var closed = false;
    defer if (!closed) {
        client.close(io);
        term_side.close(io);
        hf.close(io);
        hub_side.close(io);
    };
    try os.net.setSocketTimeouts(term_side.socket.handle, 5);
    try os.net.setSocketTimeouts(hf.socket.handle, 5);
    try os.net.setSocketTimeouts(hub_side.socket.handle, 5);
    const hub_fd = hub_side.socket.handle;

    const srv = try tls_server.Server.init(io, pems.cert, pems.key);
    defer srv.deinit();

    // The node session: a REAL TlsState.start (std TLS 1.3 client against
    // the terminator's certificate), then the protocol handshake, REQ
    // dispatch and the read loop — all through the relay below.
    const SessionTls = struct {
        fn run(n: *Node, stream: Io.net.Stream, out: *anyerror!u64) void {
            const t = TlsState.start(n, stream) catch |err| {
                stream.close(n.io);
                out.* = err;
                return;
            };
            out.* = sessionOn(n, stream, .{ .tls = t });
        }
    };
    var result: anyerror!u64 = error.NotRun;
    const ts = try std.Thread.spawn(.{}, SessionTls.run, .{ &node, client, &result });

    // The terminator: mbedTLS on the node-facing socket. The mutex
    // serializes its ssl_read against the relay's ssl_write, exactly the
    // role the hub's per-link write mutex plays in production.
    var relay_mutex: Io.Mutex = .init;
    const started = Io.Clock.awake.now(io);
    const conn = try tls_server.Conn.accept(srv, io, term_side.socket.handle, started, 5000);
    conn.lock = &relay_mutex;
    // The relay: decrypted plaintext flows raw toward the plaintext hub,
    // hub bytes get encrypted back toward the node. Joined by the defer
    // before the conn is destroyed.
    var relay: Relay = .{ .conn = conn, .plain_fd = hf.socket.handle, .mutex = &relay_mutex, .io = io };
    var up: std.Thread = undefined;
    var down: std.Thread = undefined;
    var relay_spawned = false;
    defer {
        relay.done.store(true, .release);
        if (relay_spawned) {
            up.join();
            down.join();
        }
        conn.destroy();
    }
    up = try std.Thread.spawn(.{}, Relay.runUp, .{&relay});
    down = try std.Thread.spawn(.{}, Relay.runDown, .{&relay});
    relay_spawned = true;

    // The plaintext hub: the real handshake, then the tagged wire format.
    var auth = try scriptedHubHandshake(arena, hub_fd);
    try link.writeFrame(hub_fd, &auth, .req, 7, REQ_BODY, 5000);
    const resp = try link.readFrame(arena, hub_fd, &auth, link.MAX_PAYLOAD, 5000);
    try testing.expectEqual(link.FrameType.resp, resp.kind);
    try testing.expectEqual(@as(u32, 7), resp.stream_id);
    const r = try link.splitResp(resp.payload);
    try testing.expectEqual(@as(u16, 200), r.status);
    try testing.expect(std.mem.indexOf(u8, r.body, "\"id\":1") != null);

    try link.writeFrame(hub_fd, &auth, .ping, 0, "12345678", 5000);
    const pong = try link.readFrame(arena, hub_fd, &auth, link.MAX_HANDSHAKE_PAYLOAD, 5000);
    try testing.expectEqual(link.FrameType.pong, pong.kind);
    try testing.expectEqualStrings("12345678", pong.payload);

    try link.writeFrame(hub_fd, &auth, .goaway, 0, "bye", 5000);
    ts.join();
    try testing.expectError(error.GoAway, result);
    var spins: u32 = 0;
    while (node.workers.load(.acquire) != 0 and spins < 400) : (spins += 1) os.sleepMs(5);
    try testing.expectEqual(@as(u32, 0), node.workers.load(.acquire));

    // The session thread owned and already closed `client`; only the
    // terminator- and hub-facing sockets are ours to close.
    term_side.close(io);
    hf.close(io);
    hub_side.close(io);
    closed = true;
}

/// Byte pump of the terminator test: one direction per thread. Downstream
/// writes take the terminator's mutex (ssl_write must be serialized
/// against ssl_read, and the send-deadline publication must not race the
/// read's), upstream reads park in conn.readSome, which releases the mutex
/// for its socket wait — the production lock split.
const Relay = struct {
    conn: *tls_server.Conn,
    plain_fd: os.net.Handle,
    mutex: *Io.Mutex,
    io: Io,
    done: std.atomic.Value(bool) = .init(false),

    fn runUp(self: *Relay) void {
        var buf: [16 * 1024]u8 = undefined;
        while (!self.done.load(.acquire)) {
            const n = self.conn.readSome(&buf, 500) catch |err| switch (err) {
                error.LinkTimeout => continue, // idle between frames
                else => return, // node closed or the link died
            };
            if (n == 0) return; // clean EOF from the node
            os.net.socketWriteAll(self.plain_fd, buf[0..n], 5000) catch return;
        }
    }

    fn runDown(self: *Relay) void {
        var buf: [16 * 1024]u8 = undefined;
        while (!self.done.load(.acquire)) {
            const n = (link.FdConn{ .fd = self.plain_fd }).readSome(&buf, 500) catch |err| switch (err) {
                error.LinkTimeout => continue, // idle between frames
                else => return,
            };
            if (n == 0) return;
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            self.conn.write(buf[0..n], 5000) catch return;
        }
    }
};

test "node link drops an injected REQ frame without a valid tag" {
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
    const client = try server.socket.address.connect(io, .{ .mode = .stream });
    var hub_side = try server.accept(io);
    defer hub_side.close(io);
    const fd = hub_side.socket.handle;
    try os.net.setSocketTimeouts(fd, 5);

    var result: anyerror!u64 = error.NotRun;
    const t = try std.Thread.spawn(.{}, sessionThread, .{ &node, client, &result });
    _ = try scriptedHubHandshake(arena, fd);

    // An on-path attacker without the secret relays the handshake and
    // then injects a REQ with made-up tag bytes: the node must fail the
    // frame, kill the link and never dispatch the request.
    const forged_tag = [_]u8{0xAA} ** link.MAC_LEN;
    try writeRawFrame(fd, .req, 1, REQ_BODY, &forged_tag);
    t.join();
    try testing.expectError(error.FrameAuthFailed, result);
    try testing.expectError(error.LinkClosed, link.readFrame(arena, fd, null, link.MAX_PAYLOAD, 5000));
    try testing.expectEqual(@as(u32, 0), node.workers.load(.acquire));
}

test "node link drops a frame whose payload was flipped after tagging" {
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
    const client = try server.socket.address.connect(io, .{ .mode = .stream });
    var hub_side = try server.accept(io);
    defer hub_side.close(io);
    const fd = hub_side.socket.handle;
    try os.net.setSocketTimeouts(fd, 5);

    var result: anyerror!u64 = error.NotRun;
    const t = try std.Thread.spawn(.{}, sessionThread, .{ &node, client, &result });
    const auth = try scriptedHubHandshake(arena, fd);

    // An honest tag over an honest frame, then one payload bit flipped
    // in flight: the tag no longer matches and the link dies.
    var hdr: [link.HEADER_LEN]u8 = undefined;
    link.encodeHeader(&hdr, .{ .len = @intCast(REQ_BODY.len), .kind = .req, .stream_id = 1 });
    var tag: [link.MAC_LEN]u8 = undefined;
    auth.computeTag(&tag, 0, &hdr, &.{REQ_BODY});
    var flipped: [REQ_BODY.len]u8 = undefined;
    @memcpy(&flipped, REQ_BODY);
    flipped[0] ^= 1;
    try writeRawFrame(fd, .req, 1, &flipped, &tag);
    t.join();
    try testing.expectError(error.FrameAuthFailed, result);
    try testing.expectEqual(@as(u32, 0), node.workers.load(.acquire));
}

test "node link drops a replayed frame with a stale sequence number" {
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
    const client = try server.socket.address.connect(io, .{ .mode = .stream });
    var hub_side = try server.accept(io);
    defer hub_side.close(io);
    const fd = hub_side.socket.handle;
    try os.net.setSocketTimeouts(fd, 5);

    var result: anyerror!u64 = error.NotRun;
    const t = try std.Thread.spawn(.{}, sessionThread, .{ &node, client, &result });
    var auth = try scriptedHubHandshake(arena, fd);

    // Frame 0 is honest and is served; then the exact same bytes are
    // replayed. The node's rx sequence is past 0, so the replay fails
    // and the link is closed.
    try link.writeFrame(fd, &auth, .req, 5, REQ_BODY, 5000);
    const resp = try link.readFrame(arena, fd, &auth, link.MAX_PAYLOAD, 5000);
    try testing.expectEqual(link.FrameType.resp, resp.kind);
    var spins: u32 = 0;
    while (node.workers.load(.acquire) != 0 and spins < 400) : (spins += 1) os.sleepMs(5);

    var hdr: [link.HEADER_LEN]u8 = undefined;
    link.encodeHeader(&hdr, .{ .len = @intCast(REQ_BODY.len), .kind = .req, .stream_id = 5 });
    var tag: [link.MAC_LEN]u8 = undefined;
    auth.computeTag(&tag, 0, &hdr, &.{REQ_BODY});
    try writeRawFrame(fd, .req, 5, REQ_BODY, &tag); // byte-identical replay
    t.join();
    try testing.expectError(error.FrameAuthFailed, result);
    try testing.expectEqual(@as(u32, 0), node.workers.load(.acquire));
}

test "node link drops frames that arrive out of order" {
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
    const client = try server.socket.address.connect(io, .{ .mode = .stream });
    var hub_side = try server.accept(io);
    defer hub_side.close(io);
    const fd = hub_side.socket.handle;
    try os.net.setSocketTimeouts(fd, 5);

    var result: anyerror!u64 = error.NotRun;
    const t = try std.Thread.spawn(.{}, sessionThread, .{ &node, client, &result });
    const auth = try scriptedHubHandshake(arena, fd);

    // Both frames carry honest tags for their own sequence numbers, but
    // the one for seq 1 arrives first. The node expects seq 0 exactly,
    // so the frame is refused and the link is closed.
    var hdr: [link.HEADER_LEN]u8 = undefined;
    link.encodeHeader(&hdr, .{ .len = @intCast(REQ_BODY.len), .kind = .req, .stream_id = 1 });
    var tag1: [link.MAC_LEN]u8 = undefined;
    auth.computeTag(&tag1, 1, &hdr, &.{REQ_BODY});
    try writeRawFrame(fd, .req, 1, REQ_BODY, &tag1);
    t.join();
    try testing.expectError(error.FrameAuthFailed, result);
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
    try link.writeFrame(fd, null, .challenge, 0, &nonce, 5000);
    _ = try link.readFrame(arena, fd, null, link.MAX_HANDSHAKE_PAYLOAD, 5000);
    try link.writeFrame(fd, null, .goaway, 0, "bad auth", 5000);
    t.join();
    try testing.expectError(error.Refused, result);
}

test "node link refuses a hub that cannot prove the secret" {
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

    const Bad = enum { missing_auth, wrong_secret, zero_auth, req_first, reflected_hello };
    for (std.enums.values(Bad)) |bad| {
        const client = try server.socket.address.connect(io, .{ .mode = .stream });
        var hub_side = try server.accept(io);
        defer hub_side.close(io);
        const fd = hub_side.socket.handle;
        try os.net.setSocketTimeouts(fd, 5);

        var result: anyerror!u64 = error.NotRun;
        const t = try std.Thread.spawn(.{}, sessionThread, .{ &node, client, &result });
        var nonce: [link.NONCE_LEN]u8 = @splat(4);
        try link.writeFrame(fd, null, .challenge, 0, &nonce, 5000);
        const hello_frame = try link.readFrame(arena, fd, null, link.MAX_HANDSHAKE_PAYLOAD, 5000);
        const hello = try link.parseHello(arena, hello_frame.payload);
        switch (bad) {
            .missing_auth => try link.writeFrame(fd, null, .welcome, 0, "{\"v\":1}", 5000),
            .wrong_secret => try link.writeFrame(fd, null, .welcome, 0, try link.buildWelcome(arena, "guess", &nonce, &hello.nonce, hello.name), 5000),
            .zero_auth => try link.writeFrame(fd, null, .welcome, 0, "{\"v\":1,\"auth\":\"" ++ "0" ** 64 ++ "\"}", 5000),
            .req_first => try link.writeFrame(fd, null, .req, 1, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}", 5000),
            .reflected_hello => {
                const w = try std.fmt.allocPrint(arena, "{{\"v\":1,\"auth\":\"{s}\"}}", .{hello.auth});
                try link.writeFrame(fd, null, .welcome, 0, w, 5000);
            },
        }
        t.join();
        try testing.expectError(error.HubAuthFailed, result);
        // The node closed without answering anything: the next read is EOF.
        try testing.expectError(error.LinkClosed, link.readFrame(arena, fd, null, link.MAX_PAYLOAD, 5000));
        try testing.expectEqual(@as(u32, 0), node.workers.load(.acquire));
    }
}
