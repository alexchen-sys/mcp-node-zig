//! Hub-side TLS server, compiled only in -Dtls-server builds, backed by
//! mbedTLS 3.6 LTS. One shared immutable Server (TLS config + certificate)
//! serves every link; each accepted socket gets a Conn that runs the TLS
//! 1.3 handshake and then carries link frames. All cryptography belongs to
//! mbedTLS; this file only wires sockets, deadlines and error mapping.
//!
//! Deadlines: the frame layer arms an absolute awake-clock deadline before
//! every operation (the rest of the 10 s handshake budget while
//! handshaking, the 45 s idle bound once linked). The BIO callbacks read
//! that armed deadline instead of mbedTLS's own timeout, so a dribbling
//! peer cannot stretch the budget, exactly like the plain-socket path.
//!
//! Threads: the config/certificate live read-only behind the shared
//! Server; every connection owns its mbedTLS context, and that context
//! is NOT safe for concurrent read/write: mbedtls_ssl_read itself can
//! write to the context (read counters, alert/close_notify sends,
//! key state on TLS 1.3 KeyUpdate), so it must be serialized against
//! mbedtls_ssl_write. The hub does that with its per-link writer mutex:
//! hub.zig installs it into Conn.lock right after the link is created
//! and before any other thread can reach the link; every frame writer
//! already holds that mutex (Link.writeFrame keeps header and payload
//! of one frame atomic under it).
//!
//! To keep that mutex OUT of socket waits, incoming ciphertext is
//! buffered outside mbedTLS as an OPAQUE byte stream: the mbedTLS
//! receive callback answers from an armed buffer only (empty ->
//! MBEDTLS_ERR_SSL_WANT_READ, never a socket read), and the buffer is
//! refilled with raw stream bytes by fillRaw, which runs WITHOUT the
//! lock and is bounded by the armed absolute deadline. Record
//! boundaries are mbedTLS's business alone: it consumes exact
//! record-sized asks through the callback (a refill can therefore
//! start mid-record), validates record headers and size limits
//! itself, and answers WANT_READ once the buffer is drained. The mutex
//! is taken only around mbedtls_ssl_read, which then never blocks on
//! the socket; on WANT_READ readSome releases the mutex and retries the
//! read while ciphertext is still buffered (mbedTLS answers WANT_READ
//! after silently ignoring a post-handshake message even with buffered
//! bytes left), refilling from the socket only once the buffer is
//! really empty.
//! An idle reader therefore parks in fillRaw, holding nothing, and a
//! frame writer (forward's REQ, the pinger, GOAWAY) gets the mutex in
//! milliseconds instead of after the reader's whole idle window. This
//! mirrors what the node side does in node_link.zig (bufferRecord
//! outside, decryptOne under the lock) - except the hub side hands the
//! stream to a full TLS stack and keeps no record bookkeeping of its
//! own.
//!
//! Deadlines are armed once per operation into local variables and
//! published into the shared deadline fields ONLY while holding the
//! writer mutex, so a concurrent writer (write/bioSend under the same
//! mutex) can neither race the publication nor leave the reader a
//! stale deadline. accept() runs before the link exists, on the single
//! handshake thread, with lock = null, and uses the same buffered
//! mechanics. mbedTLS's PSA core is made thread-safe by the OS mutex
//! bindings in tls/mcp_hub_threading.c (installed exactly once at the
//! first server/test init, see installThreading).

const std = @import("std");
const Io = std.Io;
const os = @import("os.zig");
const link = @import("link.zig");

pub const c = @cImport({
    @cDefine("MBEDTLS_CONFIG_FILE", "<mcp_hub_mbedtls_config.h>");
    // In optimizing builds zig translates with _FORTIFY_SOURCE on, and
    // mingw-w64's fortified string.h then defines static inlines calling
    // wcscat_s/wcscpy_s, which translate-c renders as unused local structs
    // (a hard error). The fortified view buys nothing here — the C library
    // keeps its own fortify at C-compile time regardless — so the import
    // view asks for the plain declarations.
    @cDefine("_FORTIFY_SOURCE", "0");
    @cInclude("mbedtls/ssl.h");
    @cInclude("mbedtls/x509_crt.h");
    @cInclude("mbedtls/pk.h");
    @cInclude("mbedtls/error.h");
    @cInclude("mbedtls/net_sockets.h"); // MBEDTLS_ERR_NET_* codes only
    @cInclude("mbedtls/psa_util.h"); // mbedtls_psa_get_random
    @cInclude("psa/crypto.h"); // psa_crypto_init
    @cInclude("mbedtls/build_info.h"); // MBEDTLS_VERSION_STRING
});

extern fn mcp_hub_mbedtls_threading_install() void;

const gpa = std.heap.page_allocator;

/// TLS record header on the wire: type, version, u16 length.
const TLS_HEADER_LEN = 5;
/// Largest ciphertext record ever buffered: 2^14 bytes of content plus
/// the worst protection overhead mbedTLS's own buffer math allows
/// (ssl_misc.h: IN_PAYLOAD <= CONTENT + 2048). This only sizes the
/// refill buffer: the wire limit itself is enforced by mbedTLS, whose
/// fetch_input refuses a record that does not fit its input buffer as
/// soon as the header has arrived.
const MAX_CIPHERTEXT_LEN = 16_384 + 2_048;

/// Install the mbedTLS threading (PSA) mutex bindings exactly once per
/// process. Server.init in production is single-shot, but tests build
/// many TestConns, possibly from several threads: a second install would
/// overwrite the global alt-mutex function pointers while other threads
/// are calling them. 0 = fresh, 1 = installing, 2 = done.
var threading_state = std.atomic.Value(u8).init(0);

fn installThreading() void {
    if (threading_state.load(.acquire) == 2) return;
    if (threading_state.cmpxchgStrong(0, 1, .acq_rel, .acquire) == null) {
        mcp_hub_mbedtls_threading_install();
        threading_state.store(2, .release);
        return;
    }
    // Another thread is installing: it is a handful of C calls, so
    // spinning until it is done is shorter than any sleep would be.
    while (threading_state.load(.acquire) != 2) std.atomic.spinLoopHint();
}

pub fn version() []const u8 {
    return std.mem.span(@as([*:0]const u8, c.MBEDTLS_VERSION_STRING));
}

fn nowMs(io: Io) i64 {
    return Io.Clock.awake.now(io).toMilliseconds();
}

/// Milliseconds left before the armed deadline; 0 when it has passed.
fn remainingMs(self: *const Conn) u64 {
    const left = self.deadline_ms - nowMs(self.io);
    return if (left > 0) @intCast(left) else 0;
}

/// Process-wide TLS server state: config plus the hub's certificate chain
/// and private key. Built once at hub startup; never mutated afterwards.
pub const Server = struct {
    conf: c.mbedtls_ssl_config,
    cert: c.mbedtls_x509_crt,
    key: c.mbedtls_pk_context,

    pub fn init(io: Io, cert_path: []const u8, key_path: []const u8) !*Server {
        _ = io;
        installThreading();
        if (c.psa_crypto_init() != c.PSA_SUCCESS) return error.EntropyUnavailable;

        const self = try gpa.create(Server);
        c.mbedtls_ssl_config_init(&self.conf);
        c.mbedtls_x509_crt_init(&self.cert);
        c.mbedtls_pk_init(&self.key);
        errdefer {
            c.mbedtls_pk_free(&self.key);
            c.mbedtls_x509_crt_free(&self.cert);
            c.mbedtls_ssl_config_free(&self.conf);
            gpa.destroy(self);
        }

        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const cert_z = try arena.dupeZ(u8, cert_path);
        const key_z = try arena.dupeZ(u8, key_path);

        var rc = c.mbedtls_x509_crt_parse_file(&self.cert, cert_z);
        if (rc != 0) return logMbedErr("cannot load the TLS certificate", rc, error.TlsCertUnusable);
        rc = c.mbedtls_pk_parse_keyfile(&self.key, key_z, null, c.mbedtls_psa_get_random, null);
        if (rc != 0) return logMbedErr("cannot load the TLS private key", rc, error.TlsKeyUnusable);
        rc = c.mbedtls_pk_check_pair(&self.cert.pk, &self.key, c.mbedtls_psa_get_random, null);
        if (rc != 0) return logMbedErr("TLS certificate and key do not match", rc, error.TlsKeyMismatch);

        rc = c.mbedtls_ssl_config_defaults(&self.conf, c.MBEDTLS_SSL_IS_SERVER, c.MBEDTLS_SSL_TRANSPORT_STREAM, c.MBEDTLS_SSL_PRESET_DEFAULT);
        if (rc != 0) return logMbedErr("mbedtls_ssl_config_defaults", rc, error.TlsSetupFailed);
        c.mbedtls_ssl_conf_rng(&self.conf, c.mbedtls_psa_get_random, null);
        c.mbedtls_ssl_conf_min_tls_version(&self.conf, c.MBEDTLS_SSL_VERSION_TLS1_3);
        c.mbedtls_ssl_conf_max_tls_version(&self.conf, c.MBEDTLS_SSL_VERSION_TLS1_3);
        c.mbedtls_ssl_conf_authmode(&self.conf, c.MBEDTLS_SSL_VERIFY_NONE);
        // No session ticket callback is ever installed, so the server sends
        // no NewSessionTicket (ssl_tls13_server.c skips NST when
        // f_ticket_write == NULL) — the std client expects no such records.
        rc = c.mbedtls_ssl_conf_own_cert(&self.conf, &self.cert, &self.key);
        if (rc != 0) return logMbedErr("mbedtls_ssl_conf_own_cert", rc, error.TlsSetupFailed);
        return self;
    }

    pub fn deinit(self: *Server) void {
        c.mbedtls_pk_free(&self.key);
        c.mbedtls_x509_crt_free(&self.cert);
        c.mbedtls_ssl_config_free(&self.conf);
        gpa.destroy(self);
    }
};

fn logMbedErr(what: []const u8, rc: c_int, err: anyerror) anyerror {
    var buf: [128]u8 = undefined;
    c.mbedtls_strerror(rc, &buf, buf.len);
    std.debug.print("hub TLS: {s}: {s}\n", .{ what, std.mem.sliceTo(&buf, 0) });
    return err;
}

/// One accepted link's TLS state: an mbedTLS context bound to the socket.
pub const Conn = struct {
    fd: os.net.Handle,
    io: Io,
    ssl: c.mbedtls_ssl_context,
    /// Absolute awake-clock deadline (ms) armed before each operation.
    /// Reader-owned: published under the writer mutex (see sslReadLocked),
    /// read without it only by the reader's own fillRaw.
    deadline_ms: i64 = 0,
    /// Absolute awake-clock deadline (ms) for the current write. Published
    /// under the writer mutex by both sides (readSome for read-path alert
    /// sends, write for frame writes), so publication never races.
    send_deadline_ms: i64 = 0,
    /// The hub's per-link writer mutex, installed by hub.zig (authenticate)
    /// as soon as the link exists and before any other thread can reach
    /// this conn. It is taken ONLY around mbedtls_ssl_read
    /// (sslReadLocked), which never blocks on the socket because the
    /// receive callback answers from the buffer below; frame writers
    /// already run under this same mutex in hub.zig Link.writeFrame, so
    /// write() here deliberately does NOT lock (double-locking the
    /// non-recursive mutex would deadlock). Socket waits live in
    /// fillRaw, which runs without the lock. null also covers
    /// accept(): the handshake runs single-threaded before the link
    /// exists.
    lock: ?*Io.Mutex = null,
    /// Incoming ciphertext: an opaque prefix of the TLS byte stream
    /// (one TCP segment may span record boundaries). Only the read path
    /// touches it: the mbedTLS receive callback (bioRecvTimeout) answers
    /// from it and NEVER reads the socket; fillRaw pulls more raw bytes
    /// into it without the writer lock, under the armed absolute
    /// deadline. Record boundaries live exclusively inside mbedTLS.
    in_rec: [TLS_HEADER_LEN + MAX_CIPHERTEXT_LEN]u8 = undefined,
    in_len: usize = 0,
    /// The socket reported clean EOF (0 from read): serve what is left,
    /// then hand mbedTLS the EOF. Set together with recv_err on a hard
    /// socket error.
    in_eof: bool = false,
    /// Why the last fill failed (timeout / hard socket error), so
    /// readSome/accept can map it back to LinkTimeout vs LinkClosed.
    recv_err: ?anyerror = null,

    /// Run the TLS 1.3 server handshake on an accepted socket, within the
    /// rest of the handshake budget counted from `started`.
    pub fn accept(server: *Server, io: Io, fd: os.net.Handle, started: Io.Timestamp, budget_ms: u64) !*Conn {
        const self = try gpa.create(Conn);
        // Both defers fire on every error path; declared in this order so
        // the ssl context is freed before the Conn holding it (LIFO).
        var conn_taken = false;
        defer if (!conn_taken) gpa.destroy(self);
        self.* = .{ .fd = fd, .io = io, .ssl = undefined };
        c.mbedtls_ssl_init(&self.ssl);
        var ssl_taken = false;
        defer if (!ssl_taken) c.mbedtls_ssl_free(&self.ssl);

        const rc = c.mbedtls_ssl_setup(&self.ssl, &server.conf);
        if (rc != 0)
            return logMbedErr("mbedtls_ssl_setup", rc, error.OutOfMemory);
        c.mbedtls_ssl_set_bio(&self.ssl, self, bioSend, null, bioRecvTimeout);

        const elapsed_i = started.untilNow(io, .awake).toMilliseconds();
        const elapsed: u64 = if (elapsed_i > 0) @intCast(elapsed_i) else 0;
        const left: u64 = if (elapsed >= budget_ms) 0 else budget_ms - elapsed;
        self.deadline_ms = nowMs(io) + @as(i64, @intCast(left));
        self.send_deadline_ms = self.deadline_ms;

        while (true) {
            const hrc = c.mbedtls_ssl_handshake(&self.ssl);
            if (hrc == 0) {
                ssl_taken = true;
                conn_taken = true;
                return self;
            }
            switch (hrc) {
                c.MBEDTLS_ERR_SSL_WANT_READ => {
                    if (remainingMs(self) == 0) return error.LinkTimeout;
                    // Same buffered mechanics as readSome, single-threaded
                    // here (lock is null, the link does not exist yet):
                    // mbedTLS may answer WANT_READ with ciphertext still
                    // buffered (it stops after one processed flight
                    // instead of draining the buffer), so retry the
                    // handshake pass first and pull raw stream bytes only
                    // once the buffer is really empty.
                    if (self.in_len > 0) continue;
                    self.fillRaw(self.deadline_ms) catch |err| switch (err) {
                        error.LinkTimeout => return error.LinkTimeout,
                        // EOF or reset: the callback reports it (0 or
                        // NET_RECV_FAILED) on the next handshake pass.
                        error.LinkClosed => {},
                    };
                    continue;
                },
                c.MBEDTLS_ERR_SSL_WANT_WRITE => {
                    if (remainingMs(self) == 0) return error.LinkTimeout;
                    continue;
                },
                c.MBEDTLS_ERR_SSL_ALLOC_FAILED => return error.OutOfMemory,
                c.MBEDTLS_ERR_SSL_TIMEOUT => return error.LinkTimeout,
                else => {
                    var buf: [128]u8 = undefined;
                    c.mbedtls_strerror(hrc, &buf, buf.len);
                    std.debug.print("hub TLS handshake failed: {s}\n", .{std.mem.sliceTo(&buf, 0)});
                    return error.TlsHandshakeFailed;
                },
            }
        }
    }

    pub fn destroy(self: *Conn) void {
        c.mbedtls_ssl_free(&self.ssl);
        gpa.destroy(self);
    }

    pub fn readSome(self: *Conn, buf: []u8, timeout_ms: u64) !usize {
        if (buf.len == 0) return 0;
        // A read timeout is a property of THIS call's budget, not of the
        // conn: fillOnce records it in recv_err only so the failing call
        // can map it. The next call comes with a fresh budget and must
        // stay readable — the same contract FdConn.readSome provides
        // (its socket timeout is per-call and retryable) and the one the
        // node side implements (node_link TlsState.readSome clears its
        // read_err on entry): bytes that arrive after a timeout are
        // still served. Hard socket errors and EOF stay sticky — the
        // conn really is finished then (fillRaw refuses, readSome
        // reports LinkClosed).
        if (self.recv_err) |e| {
            if (e == error.LinkTimeout) self.recv_err = null;
        }
        // The deadline is computed ONCE, into a local: the shared fields
        // are published only under the writer mutex (sslReadLocked), so
        // a concurrent writer never races the publication and neither
        // side inherits the other's stale deadline.
        const deadline = nowMs(self.io) + @as(i64, @intCast(timeout_ms));
        while (true) {
            const rc = self.sslReadLocked(buf, deadline);
            if (rc > 0) return @intCast(rc);
            switch (rc) {
                0 => return 0,
                c.MBEDTLS_ERR_SSL_WANT_READ => {
                    if (deadline - nowMs(self.io) <= 0) return error.LinkTimeout;
                    // mbedTLS can answer WANT_READ while OUR buffer still
                    // holds unconsumed ciphertext: it returns WANT_READ
                    // after silently ignoring a post-handshake message
                    // (KeyUpdate, NewSessionTicket) instead of continuing
                    // into the next buffered record. Retry the read FIRST
                    // and let the receive callback feed what is buffered;
                    // only when the buffer is really empty does the socket
                    // wait below run — otherwise it would park on the
                    // socket with a full application record already in
                    // hand, stalling the link until the deadline.
                    if (self.in_len > 0) continue;
                    // mbedTLS consumed the buffered ciphertext and wants
                    // more: pull RAW stream bytes WITHOUT the lock so the
                    // socket wait does not block frame writers
                    // (forward's REQ, the pinger, GOAWAY).
                    self.fillRaw(deadline) catch |err| switch (err) {
                        error.LinkTimeout => return error.LinkTimeout,
                        error.LinkClosed => {
                            // Hard socket error fails the read; clean EOF
                            // is reported as 0, exactly what the old
                            // callback path mapped CONN_EOF to.
                            if (self.recv_err != null) return error.LinkClosed;
                            return 0;
                        },
                    };
                    continue;
                },
                c.MBEDTLS_ERR_SSL_WANT_WRITE => {
                    // bioSend is all-or-error, so this is unreachable in
                    // practice; if it ever fired, retry with the
                    // deadline checked above.
                    if (deadline - nowMs(self.io) <= 0) return error.LinkTimeout;
                    continue;
                },
                c.MBEDTLS_ERR_SSL_TIMEOUT => return error.LinkTimeout,
                c.MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY, c.MBEDTLS_ERR_SSL_CONN_EOF => return 0,
                else => return error.LinkClosed,
            }
        }
    }

    /// One mbedtls_ssl_read under the writer mutex. The mutex is held
    /// ONLY here: with the receive callback answering from the buffer,
    /// this call never blocks on the socket. The armed deadlines are
    /// published under the same mutex (fresh send_deadline_ms, so a
    /// read-path alert never inherits a deadline left over from an older
    /// write), and expiry is checked BEFORE entering mbedTLS.
    fn sslReadLocked(self: *Conn, buf: []u8, deadline: i64) c_int {
        if (self.lock) |m| m.lockUncancelable(self.io);
        defer if (self.lock) |m| m.unlock(self.io);
        self.deadline_ms = deadline;
        self.send_deadline_ms = deadline;
        if (deadline - nowMs(self.io) <= 0) return c.MBEDTLS_ERR_SSL_TIMEOUT;
        return c.mbedtls_ssl_read(&self.ssl, buf.ptr, buf.len);
    }

    /// Read one socket chunk into the buffer, under the absolute
    /// `deadline`. No lock: this is where an idle reader parks, so a
    /// frame writer must stay free to run meanwhile. Timeout and hard
    /// errors are recorded in recv_err for the caller's error mapping.
    fn fillOnce(self: *Conn, deadline: i64) error{ LinkTimeout, LinkClosed }!void {
        const left = deadline - nowMs(self.io);
        if (left <= 0) {
            self.recv_err = error.LinkTimeout;
            return error.LinkTimeout;
        }
        const n = (link.FdConn{ .fd = self.fd }).readSome(self.in_rec[self.in_len..], @intCast(left)) catch |err| {
            if (err == error.LinkTimeout) {
                self.recv_err = error.LinkTimeout;
                return error.LinkTimeout;
            }
            self.recv_err = err;
            self.in_eof = true;
            return error.LinkClosed;
        };
        if (n == 0) {
            self.in_eof = true;
            return error.LinkClosed;
        }
        self.in_len += n;
    }

    /// Pull more raw ciphertext bytes from the socket, without the writer
    /// mutex and bounded by the absolute `deadline`. The buffer is an
    /// OPAQUE prefix of the ciphertext stream: no record parsing happens
    /// here. mbedTLS alone splits the stream into records and enforces
    /// their size limit — an oversize header fails its own bound check in
    /// fetch_input right after the five header bytes arrive, so nothing
    /// waits for bytes that may never come.
    ///
    /// The old record-aware refill broke on plain TCP segmentation: one
    /// read can deliver record A plus the prefix of record B; the receive
    /// callback hands that prefix to mbedTLS, which consumes it into its
    /// partial record assembly and asks for more; the refill then started
    /// mid-record, and parsing the continuation bytes as a fresh header
    /// produced a garbage length — a spurious oversize refusal, or a wait
    /// for bytes that would never align.
    ///
    /// Invariant: refills only run after mbedTLS answered WANT_READ, and
    /// the receive callback answers WANT_READ only when the buffer is
    /// empty, so in_len is 0 here and the read below starts a fresh
    /// prefix of the stream (no compaction needed). Capacity is one
    /// maximal record plus its header: a refill reads at most that much,
    /// and the callback hands mbedTLS at least one byte whenever the
    /// buffer is non-empty (its asks are never zero), so the buffer is
    /// always drained again; observing it full means the stream position
    /// is beyond any record an honest peer sends.
    fn fillRaw(self: *Conn, deadline: i64) error{ LinkTimeout, LinkClosed }!void {
        if (self.in_eof or self.recv_err != null) return error.LinkClosed;
        if (self.in_len == self.in_rec.len) {
            // Full and unconsumed: above any honest record — refuse
            // instead of wedging.
            self.recv_err = error.LinkClosed;
            return error.LinkClosed;
        }
        try self.fillOnce(deadline);
    }

    /// No lock here on purpose: the hub's Link.writeFrame already holds the
    /// per-link write mutex (the same mutex installed into `lock`) across
    /// the whole frame — header and payload — which keeps concurrent frame
    /// writes atomic, serializes the send_deadline_ms publication against
    /// sslReadLocked, and rules out taking the mutex again here (that
    /// would self-deadlock on the non-recursive mutex). Handshake-phase
    /// writes run single-threaded with lock = null.
    pub fn write(self: *Conn, bytes: []const u8, timeout_ms: u64) !void {
        self.send_deadline_ms = nowMs(self.io) + @as(i64, @intCast(timeout_ms));
        var off: usize = 0;
        while (off < bytes.len) {
            const rc = c.mbedtls_ssl_write(&self.ssl, bytes.ptr + off, bytes.len - off);
            if (rc > 0) {
                off += @intCast(rc);
                continue;
            }
            switch (rc) {
                c.MBEDTLS_ERR_SSL_WANT_READ, c.MBEDTLS_ERR_SSL_WANT_WRITE => {
                    const left = self.send_deadline_ms - nowMs(self.io);
                    if (left <= 0) return error.LinkTimeout;
                    continue;
                },
                c.MBEDTLS_ERR_SSL_TIMEOUT => return error.LinkTimeout,
                else => return error.LinkClosed,
            }
        }
    }

    pub fn flush(self: *Conn, timeout_ms: u64) !void {
        // No-op, exactly like FdConn.flush: a successful mbedtls_ssl_write
        // has already pushed the whole record through f_send (bioSend is
        // all-or-error, never WANT_WRITE), so nothing is left buffered.
        // A stalled peer fails the write itself with LinkTimeout instead.
        _ = self;
        _ = timeout_ms;
    }
};

fn bioSend(ctx: ?*anyopaque, buf: [*c]const u8, len: usize) callconv(.c) c_int {
    const self: *Conn = @ptrCast(@alignCast(ctx.?));
    const left = self.send_deadline_ms - nowMs(self.io);
    if (left <= 0) return c.MBEDTLS_ERR_SSL_TIMEOUT;
    os.net.socketWriteAll(self.fd, buf[0..len], @intCast(left)) catch
        return c.MBEDTLS_ERR_NET_SEND_FAILED;
    return @intCast(len);
}

fn bioRecvTimeout(ctx: ?*anyopaque, buf: [*c]u8, len: usize, timeout_ms: u32) callconv(.c) c_int {
    const self: *Conn = @ptrCast(@alignCast(ctx.?));
    // mbedTLS asks, the armed buffer answers: this callback NEVER touches
    // the socket. That is the heart of the lock split — mbedtls_ssl_read
    // (run under the writer mutex) can never park on socket I/O, because
    // its only source of bytes is the buffer filled by fillRaw, which
    // runs without the lock.
    _ = timeout_ms;
    if (self.in_len == 0) {
        if (self.in_eof) {
            // A hard socket error (recorded in recv_err) is reported as
            // NET_RECV_FAILED; a clean EOF as 0, which mbedTLS maps to
            // MBEDTLS_ERR_SSL_CONN_EOF.
            if (self.recv_err) |e| {
                if (e != error.LinkTimeout) return c.MBEDTLS_ERR_NET_RECV_FAILED;
            }
            return 0;
        }
        return c.MBEDTLS_ERR_SSL_WANT_READ;
    }
    const n = @min(len, self.in_len);
    @memcpy(buf[0..n], self.in_rec[0..n]);
    std.mem.copyForwards(u8, self.in_rec[0 .. self.in_len - n], self.in_rec[n..self.in_len]);
    self.in_len -= n;
    return @intCast(n);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "tls_server remainingMs respects the armed deadline" {
    var threaded = Io.Threaded.init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var conn: Conn = .{ .fd = undefined, .io = io, .ssl = undefined };
    conn.deadline_ms = nowMs(io) + 10_000;
    try testing.expect(remainingMs(&conn) > 9_000);
    conn.deadline_ms = nowMs(io) - 1;
    try testing.expectEqual(@as(u64, 0), remainingMs(&conn));
}

/// A Conn whose ssl context exists (init + setup with a bare config) but
/// never handshaked: whatever mbedtls_ssl_read answers about such a
/// socket, readSome still has to acquire `lock` first, which is exactly
/// what these tests observe. No certificate is needed for that.
const TestConn = struct {
    conn: Conn,
    conf: c.mbedtls_ssl_config,

    fn init(self: *TestConn, io: Io, fd: os.net.Handle) !void {
        installThreading();
        if (c.psa_crypto_init() != c.PSA_SUCCESS) return error.EntropyUnavailable;
        c.mbedtls_ssl_config_init(&self.conf);
        errdefer c.mbedtls_ssl_config_free(&self.conf);
        const rc = c.mbedtls_ssl_config_defaults(&self.conf, c.MBEDTLS_SSL_IS_SERVER, c.MBEDTLS_SSL_TRANSPORT_STREAM, c.MBEDTLS_SSL_PRESET_DEFAULT);
        if (rc != 0) return error.TlsSetupFailed;
        // ssl_setup refuses a config without an RNG; the same PSA-backed
        // one the real server uses works here.
        c.mbedtls_ssl_conf_rng(&self.conf, c.mbedtls_psa_get_random, null);
        self.conn = .{ .fd = fd, .io = io, .ssl = undefined };
        c.mbedtls_ssl_init(&self.conn.ssl);
        errdefer c.mbedtls_ssl_free(&self.conn.ssl);
        if (c.mbedtls_ssl_setup(&self.conn.ssl, &self.conf) != 0) return error.TlsSetupFailed;
        c.mbedtls_ssl_set_bio(&self.conn.ssl, &self.conn, bioSend, null, bioRecvTimeout);
    }

    fn deinit(self: *TestConn) void {
        c.mbedtls_ssl_free(&self.conn.ssl);
        c.mbedtls_ssl_config_free(&self.conf);
    }
};

test "tls_server readSome waits for the link writer mutex" {
    var threaded = Io.Threaded.init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const any = try Io.net.IpAddress.parse("127.0.0.1", 0);
    var server = try any.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    const far = try server.socket.address.connect(io, .{ .mode = .stream });
    const near = try server.accept(io);
    defer near.close(io);

    var tc: TestConn = undefined;
    try tc.init(io, near.socket.handle);
    defer tc.deinit();

    // EOF is already pending on the socket, so an unlocked readSome would
    // answer at once; with the writer mutex held it must block instead.
    far.close(io);
    var mutex: Io.Mutex = .init;
    tc.conn.lock = &mutex;
    mutex.lockUncancelable(io);

    var done = std.atomic.Value(bool).init(false);
    const Reader = struct {
        fn run(cn: *Conn, flag: *std.atomic.Value(bool)) void {
            var buf: [16]u8 = undefined;
            _ = cn.readSome(&buf, 500) catch {};
            flag.store(true, .release);
        }
    };
    const t = try std.Thread.spawn(.{}, Reader.run, .{ &tc.conn, &done });
    os.sleepMs(200);
    // Still waiting on the mutex, not reading the socket.
    try testing.expect(!done.load(.acquire));
    mutex.unlock(io);
    t.join();
    // Whatever the ssl layer concluded about the closed socket, it could
    // only do so after the writer released the mutex.
    try testing.expect(done.load(.acquire));
}

test "tls_server readSome arms the send deadline before reading" {
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

    var tc: TestConn = undefined;
    try tc.init(io, near.socket.handle);
    defer tc.deinit();

    // A stale write deadline from some long-gone write: readSome must
    // replace it before touching the ssl context, because an alert sent
    // from inside mbedtls_ssl_read goes through bioSend, which reads
    // send_deadline_ms — a stale one would fail the send instantly.
    tc.conn.send_deadline_ms = 0;
    const before = nowMs(io);
    var buf: [16]u8 = undefined;
    _ = tc.conn.readSome(&buf, 400) catch {};
    try testing.expect(tc.conn.deadline_ms >= before + 300);
    try testing.expect(tc.conn.send_deadline_ms >= before + 300);
}

test "tls_server idle readSome leaves the writer mutex free while waiting" {
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

    var tc: TestConn = undefined;
    try tc.init(io, near.socket.handle);
    defer tc.deinit();

    var mutex: Io.Mutex = .init;
    tc.conn.lock = &mutex;

    // The peer is silent, so the reader parks waiting for more
    // ciphertext bytes — in fillRaw, WITHOUT the writer mutex. A frame writer
    // (forward's REQ, the pinger, GOAWAY) must then take the mutex in
    // milliseconds; the old design, which held the mutex across the
    // blocking socket read, made it wait out the reader's whole idle
    // window instead (answersProbe expires before the PING even goes
    // out).
    var done = std.atomic.Value(bool).init(false);
    const Reader = struct {
        fn run(cn: *Conn, flag: *std.atomic.Value(bool)) void {
            var buf: [16]u8 = undefined;
            _ = cn.readSome(&buf, 800) catch {};
            flag.store(true, .release);
        }
    };
    const t = try std.Thread.spawn(.{}, Reader.run, .{ &tc.conn, &done });
    os.sleepMs(150); // the reader is parked on the socket by now
    const t0 = Io.Clock.awake.now(io);
    mutex.lockUncancelable(io);
    const lock_ms = t0.untilNow(io, .awake).toMilliseconds();
    mutex.unlock(io);
    // Still parked on the socket (the 800 ms idle window), and the
    // writer's lock came in milliseconds, not after ~650 ms of parking.
    try testing.expect(!done.load(.acquire));
    try testing.expect(lock_ms < 300);
    t.join();
    try testing.expect(done.load(.acquire));
}

test "tls_server threading install is idempotent under concurrent callers" {
    const N = 4;
    const Inst = struct {
        fn run() void {
            for (0..25) |_| installThreading();
        }
    };
    var ts: [N]std.Thread = undefined;
    for (&ts) |*t| t.* = try std.Thread.spawn(.{}, Inst.run, .{});
    for (&ts) |*t| t.join();
    // One install won the race, the rest saw it through: the alt-mutex
    // function pointers were set exactly once, not overwritten under
    // the feet of the threads that were already using them.
    try testing.expectEqual(@as(u8, 2), threading_state.load(.acquire));
}

// ---------------------------------------------------------------------------
// Real-session fixtures: a throwaway certificate pair and a std TLS client
// wrapper, used by the segmentation tests below.
// ---------------------------------------------------------------------------

const tls = std.crypto.tls;

/// A throwaway self-signed EC P-256 certificate (CN=localhost) and its key,
/// generated offline and embedded ONLY for the tests below: the hub side
/// needs a real certificate chain to run a real TLS 1.3 handshake, and a
/// fixed embedded pair keeps the tests hermetic — nothing is generated at
/// test time and no external tool is needed. The pair guards no real host;
/// it is test data, not a credential.
const TEST_CERT_PEM =
    \\-----BEGIN CERTIFICATE-----
    \\MIIBfzCCASWgAwIBAgIUecZgTNsLXfd0x5FpknCnrK/Fbf4wCgYIKoZIzj0EAwIw
    \\FDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI2MTAxNjA2MDEyNVoYDzIxMjYwOTIy
    \\MDYwMTI1WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjO
    \\PQMBBwNCAAScZ03qpT1K3j+mtPv4d+jR/b2Surmy0Rdt8afs5Huz2yVJfAoDiJdk
    \\jBee1+n869GFNeT3o2RxkvxWbnxDnnkRo1MwUTAdBgNVHQ4EFgQUOheF5kcPHHFc
    \\Xxy9wsZJr0wvtNgwHwYDVR0jBBgwFoAUOheF5kcPHHFcXxy9wsZJr0wvtNgwDwYD
    \\VR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiBvOMcIGyOreqGzQPoOloQk
    \\rdKbUL3SU78fow/pskNfHAIhALl/y9IJC6REgtiEga0XQCMINDlwRWpRn7ExUcWg
    \\4Ksv
    \\-----END CERTIFICATE-----
;
const TEST_KEY_PEM =
    \\-----BEGIN EC PRIVATE KEY-----
    \\MHcCAQEEIInDSOC4j8uqhNlK2sZZ3GjlQ7qPcQfg7VTR03Gz8bM5oAoGCCqGSM49
    \\AwEHoUQDQgAEnGdN6qU9St4/prT7+Hfo0f29krq5stEXbfGn7OR7s9slSXwKA4iX
    \\ZIwXntfp/OvRhTXk96NkcZL8Vm58Q555EQ==
    \\-----END EC PRIVATE KEY-----
;

/// Materialise the embedded PEMs under /tmp and return their absolute
/// paths. mbedTLS parses certificates from files, so each test drops the
/// pair into its own /tmp subdirectory (mbedTLS C code needs paths, and
/// the directory survives only as long as the test run).
pub fn writeTestPems(io: Io, tag: []const u8) !struct { cert: []u8, key: []u8 } {
    const a = std.heap.page_allocator;
    const base = try std.fmt.allocPrint(a, "/tmp/mcpnz-tls-{s}", .{tag});
    if (Io.Dir.cwd().createDirPathOpen(io, base, .{})) |*d| {
        d.close(io);
    } else |_| {} // exists already; writeFile will surface real problems
    const cert = try std.fmt.allocPrint(a, "{s}/cert.pem", .{base});
    errdefer a.free(cert);
    const key = try std.fmt.allocPrint(a, "{s}/key.pem", .{base});
    errdefer a.free(key);
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = cert, .data = TEST_CERT_PEM });
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = key, .data = TEST_KEY_PEM });
    return .{ .cert = cert, .key = key };
}

/// The std TLS 1.3 client used by the real-session tests: a mirror of
/// node_link.zig's TlsState with the timeout policy simplified to fixed
/// per-I/O budgets — these tests exercise the HUB side, not client timing.
const TlsPeer = struct {
    fd: os.net.Handle,
    io: Io,
    sock_in: Io.Reader,
    sock_out: Io.Writer,
    client: tls.Client = undefined,
    in_buf: [tls.Client.min_buffer_len]u8 = undefined,
    out_buf: [tls.Client.min_buffer_len]u8 = undefined,
    plain_in: [tls.Client.min_buffer_len]u8 = undefined,
    plain_out: [tls.Client.min_buffer_len]u8 = undefined,

    const IO_MS = 10_000;

    fn prepare(self: *TlsPeer, io: Io, fd: os.net.Handle) !void {
        self.* = .{
            .fd = fd,
            .io = io,
            .sock_in = .{ .vtable = &.{ .stream = peerStream }, .buffer = &.{}, .seek = 0, .end = 0 },
            .sock_out = .{ .vtable = &.{ .drain = peerDrain }, .buffer = &.{} },
        };
        self.sock_in.buffer = &self.in_buf;
        self.sock_out.buffer = &self.out_buf;
    }

    fn handshake(self: *TlsPeer) !void {
        var entropy: [tls.Client.Options.entropy_len]u8 = undefined;
        self.io.randomSecure(&entropy) catch return error.EntropyUnavailable;
        defer std.crypto.secureZero(u8, &entropy);
        self.client = tls.Client.init(&self.sock_in, &self.sock_out, .{
            .host = .no_verification,
            .ca = .no_verification,
            .write_buffer = &self.plain_out,
            .read_buffer = &self.plain_in,
            .entropy = &entropy,
            .realtime_now = Io.Clock.real.now(self.io),
        }) catch |err| return switch (err) {
            error.ReadFailed => error.TlsHandshakeFailed,
            else => err,
        };
    }

    fn writeAll(self: *TlsPeer, bytes: []const u8) !void {
        self.client.writer.writeAll(bytes) catch return error.WriteFailed;
        self.client.writer.flush() catch return error.WriteFailed;
        self.sock_out.flush() catch return error.WriteFailed;
    }

    fn readSome(self: *TlsPeer, buf: []u8) !usize {
        const plain = &self.client.reader;
        if (plain.buffered().len == 0)
            plain.fillMore() catch |err| switch (err) {
                error.EndOfStream => return 0,
                else => return err,
            };
        const ready = plain.buffered();
        const n = @min(ready.len, buf.len);
        @memcpy(buf[0..n], ready[0..n]);
        plain.toss(n);
        return n;
    }

    fn peerStream(r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const self: *TlsPeer = @alignCast(@fieldParentPtr("sock_in", r));
        const dest = limit.slice(try w.writableSliceGreedy(1));
        const n = os.net.socketReadSome(self.fd, dest, IO_MS) catch return error.ReadFailed;
        if (n == 0) return error.EndOfStream;
        w.advance(n);
        return n;
    }

    fn peerDrain(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
        const self: *TlsPeer = @alignCast(@fieldParentPtr("sock_out", w));
        os.net.socketWriteAll(self.fd, w.buffer[0..w.end], IO_MS) catch return error.WriteFailed;
        w.end = 0;
        var n: usize = 0;
        for (data[0 .. data.len - 1]) |d| {
            os.net.socketWriteAll(self.fd, d, IO_MS) catch return error.WriteFailed;
            n += d.len;
        }
        const last = data[data.len - 1];
        for (0..splat) |_| {
            os.net.socketWriteAll(self.fd, last, IO_MS) catch return error.WriteFailed;
            n += last.len;
        }
        return n;
    }
};

test "tls_server completes a real handshake and echoes plaintext with the std client" {
    var threaded = Io.Threaded.init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const any = try Io.net.IpAddress.parse("127.0.0.1", 0);
    var listener = try any.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const far = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer far.close(io);
    const near = try listener.accept(io);
    defer near.close(io);
    try os.net.setSocketTimeouts(near.socket.handle, 5);
    try os.net.setSocketTimeouts(far.socket.handle, 5);

    const pems = try writeTestPems(io, "probe");
    defer std.heap.page_allocator.free(pems.cert);
    defer std.heap.page_allocator.free(pems.key);
    const srv = try Server.init(io, pems.cert, pems.key);
    defer srv.deinit();

    var peer: TlsPeer = undefined;
    try peer.prepare(io, far.socket.handle);
    const Hs = struct {
        fn run(p: *TlsPeer, out: *anyerror!void) void {
            out.* = p.handshake();
        }
    };
    var hs_result: anyerror!void = {};
    const t = try std.Thread.spawn(.{}, Hs.run, .{ &peer, &hs_result });
    const started = Io.Clock.awake.now(io);
    const conn = try Conn.accept(srv, io, near.socket.handle, started, 5000);
    defer conn.destroy();
    t.join();
    try hs_result;

    const msg = "c4r3-interoperability-probe";
    try peer.writeAll(msg);
    var up: [64]u8 = undefined;
    const n = try conn.readSome(&up, 2000);
    try testing.expectEqualStrings(msg, up[0..n]);
    try conn.write(msg, 2000);
    var down: [64]u8 = undefined;
    const m = try peer.readSome(&down);
    try testing.expectEqualStrings(msg, down[0..m]);
}

// A read timeout must not poison the conn. fillOnce records LinkTimeout
// in recv_err; without the entry-clear in readSome the NEXT read goes
// WANT_READ -> fillRaw -> sticky recv_err -> LinkClosed, silently
// turning a retryable timeout into a hard close. The node side
// (node_link TlsState.readSome) already implements the retryable
// contract; this pins the hub side to the same one — and pins that hard
// errors stay sticky.
test "tls_server readSome timeout is retryable and hard errors stay sticky" {
    var threaded = Io.Threaded.init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const any = try Io.net.IpAddress.parse("127.0.0.1", 0);
    var listener = try any.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const far = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer far.close(io);
    const near = try listener.accept(io);
    defer near.close(io);
    try os.net.setSocketTimeouts(near.socket.handle, 5);
    try os.net.setSocketTimeouts(far.socket.handle, 5);

    const pems = try writeTestPems(io, "retrytmo");
    defer std.heap.page_allocator.free(pems.cert);
    defer std.heap.page_allocator.free(pems.key);
    const srv = try Server.init(io, pems.cert, pems.key);
    defer srv.deinit();

    var peer: TlsPeer = undefined;
    try peer.prepare(io, far.socket.handle);
    const Hs = struct {
        fn run(p: *TlsPeer, out: *anyerror!void) void {
            out.* = p.handshake();
        }
    };
    var hs_result: anyerror!void = {};
    const ths = try std.Thread.spawn(.{}, Hs.run, .{ &peer, &hs_result });
    const started = Io.Clock.awake.now(io);
    const conn = try Conn.accept(srv, io, near.socket.handle, started, 5000);
    defer conn.destroy();
    ths.join();
    try hs_result;

    var buf: [64]u8 = undefined;
    // 1) A silent peer: the read ends in LinkTimeout (fillOnce recorded
    //    it in recv_err).
    try testing.expectError(error.LinkTimeout, conn.readSome(&buf, 150));

    // 2) The retry is NOT dead: bytes arriving after the timeout must
    //    still be read. Old behavior red-lines here with error.LinkClosed
    //    (fillRaw saw the sticky recv_err).
    try peer.writeAll("late-but-readable");
    const n = try conn.readSome(&buf, 2_000);
    try testing.expectEqualStrings("late-but-readable", buf[0..n]);

    // 3) A hard socket error stays sticky: every later read fails with
    //    LinkClosed, never a "retryable" timeout.
    conn.recv_err = error.ConnectionResetByPeer;
    try testing.expectError(error.LinkClosed, conn.readSome(&buf, 100));
    try testing.expectError(error.LinkClosed, conn.readSome(&buf, 100));
}

// ---------------------------------------------------------------------------
// Segmentation regressions: the refill path must treat the buffered
// ciphertext as an opaque byte stream. mbedTLS consumes records through the
// receive callback in exact record-sized asks, so after a refill the buffer
// can hold the CONTINUATION of a record mbedTLS has already partially
// consumed; re-parsing that continuation as a fresh record header breaks
// valid sessions on plain TCP segmentation (one record plus the prefix of
// the next in a single read).
// ---------------------------------------------------------------------------

/// Fill a buffer with a deterministic, position-dependent byte pattern.
fn fillPattern(buf: []u8) void {
    for (buf, 0..) |*b, i| b.* = @truncate(i *% 73 +% 41);
}

// The deterministic detector: no TLS peer needed. mbedTLS (handshaking,
// no certificate required) is fed a handshake record carrying the first
// fragment of an over-long ClientHello plus the PREFIX of its
// continuation record; once it has consumed both, the socket dribbles
// 0xff continuation bytes. A refill that parses those bytes as a record
// header sees an announced length of 0xffff and fails the link at once;
// the opaque-stream contract keeps waiting and ends at the read's own
// absolute deadline instead.
test "tls_server refill never parses a mid-record continuation as a record header" {
    var threaded = Io.Threaded.init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const any = try Io.net.IpAddress.parse("127.0.0.1", 0);
    var listener = try any.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const far = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer far.close(io);
    const near = try listener.accept(io);
    defer near.close(io);

    var tc: TestConn = undefined;
    try tc.init(io, near.socket.handle);
    defer tc.deinit();

    // Record 1: handshake type, 16 body bytes = ClientHello message header
    // (240 bytes total) + 12 fragment bytes. Record 2 (its continuation):
    // header announcing 48 body bytes, of which 10 arrive in the burst.
    var burst: [5 + 16 + 5 + 10]u8 = undefined;
    burst[0] = 0x16;
    burst[1] = 0x03;
    burst[2] = 0x03;
    burst[3] = 0x00;
    burst[4] = 0x10;
    burst[5] = 0x01; // handshake: client_hello
    burst[6] = 0x00;
    burst[7] = 0x00;
    burst[8] = 0xf0; // 240 bytes of message, never completed
    @memset(burst[9 .. 5 + 16], 0xaa);
    burst[21] = 0x16;
    burst[22] = 0x03;
    burst[23] = 0x03;
    burst[24] = 0x00;
    burst[25] = 0x30;
    @memset(burst[26..], 0xbb);
    try os.net.socketWriteAll(far.socket.handle, &burst, 2000);

    // 150 ms later: more CONTINUATION bytes of record 2. 0xff is not a
    // header any honest peer announces, but on the stream contract these
    // are just record-2 body bytes.
    const Dribble = struct {
        fn run(fd: os.net.Handle) void {
            os.sleepMs(150);
            var tail: [8]u8 = undefined;
            @memset(&tail, 0xff);
            os.net.socketWriteAll(fd, &tail, 2000) catch {};
        }
    };
    const t = try std.Thread.spawn(.{}, Dribble.run, .{far.socket.handle});

    const t0 = Io.Clock.awake.now(io);
    var buf: [64]u8 = undefined;
    const err = tc.conn.readSome(&buf, 400) catch |e| e;
    const took = t0.untilNow(io, .awake).toMilliseconds();
    t.join();
    // The record never completes, so the read must end at its own absolute
    // deadline — not die early on a misparsed 0xffff "header".
    try testing.expectEqual(@as(anyerror, error.LinkTimeout), err);
    try testing.expect(took >= 300);
}

// Boundary pin: a peer that dribbles body bytes of one incomplete record
// must not stretch the read budget — the read fails at its own deadline
// on both sides of the refill contract.
test "tls_server segmented read keeps the absolute deadline" {
    var threaded = Io.Threaded.init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const any = try Io.net.IpAddress.parse("127.0.0.1", 0);
    var listener = try any.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const far = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer far.close(io);
    const near = try listener.accept(io);
    defer near.close(io);

    var tc: TestConn = undefined;
    try tc.init(io, near.socket.handle);
    defer tc.deinit();

    // A handshake record announcing 32 body bytes, of which 16 are
    // delivered; the rest dribbles in one byte per 100 ms.
    var burst: [5 + 16]u8 = undefined;
    burst[0] = 0x16;
    burst[1] = 0x03;
    burst[2] = 0x03;
    burst[3] = 0x00;
    burst[4] = 0x20;
    burst[5] = 0x01;
    burst[6] = 0x00;
    burst[7] = 0x00;
    burst[8] = 0xf0;
    @memset(burst[9..], 0x00);
    try os.net.socketWriteAll(far.socket.handle, &burst, 2000);

    const Dribble = struct {
        fn run(fd: os.net.Handle) void {
            var one = [1]u8{0x00};
            for (0..20) |_| {
                os.sleepMs(100);
                os.net.socketWriteAll(fd, &one, 2000) catch return;
            }
        }
    };
    const t = try std.Thread.spawn(.{}, Dribble.run, .{far.socket.handle});

    const t0 = Io.Clock.awake.now(io);
    var buf: [64]u8 = undefined;
    const err = tc.conn.readSome(&buf, 400) catch |e| e;
    const took = t0.untilNow(io, .awake).toMilliseconds();
    t.join();
    try testing.expectEqual(@as(anyerror, error.LinkTimeout), err);
    try testing.expect(took >= 300);
    try testing.expect(took < 1_200);
}

/// A relay between the std TLS client and the hub Conn that splits the
/// client->hub stream at scripted points, so the hub's reads see record
/// fragments deterministically instead of whatever the kernel coalesces.
///
/// app_split: relay everything until `app_phase` is set, forward only
/// `split_at` bytes of the app stream, then hold until the down-thread
/// has relayed hub->client bytes (the test's echo — proof the hub consumed
/// the first forwarded record), then relay raw.
///
/// first_record_hold: forward the first complete record, then 8 more
/// bytes (mid-record in either client-flight layout), pause 250 ms so the
/// hub consumes them as a continuation, then relay raw.
const ScriptedRelay = struct {
    client_fd: os.net.Handle,
    hub_fd: os.net.Handle,
    mode: Mode,
    split_at: usize = 0,
    app_phase: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    echo_seen: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    const Mode = enum { app_split, first_record_hold };
    /// 5 s: bounds relay WRITES too (SO_SNDTIMEO is armed by the test via
    /// setSocketTimeouts on the relay sockets).
    const IO_MS = 5_000;
    /// Short per-read bound: the relay must wake regularly to re-check its
    /// script state (echo_seen), not park forever in a socket read — on
    /// POSIX the bound comes from the armed socket option, which
    /// FdConn.readSome arms per call.
    const READ_MS = 200;

    fn forwardHub(self: *ScriptedRelay, bytes: []const u8) !void {
        try os.net.socketWriteAll(self.hub_fd, bytes, IO_MS);
    }

    const UpMode = enum { first_record, first_hold_8, app_split, app_wait_echo, relay };

    fn runUp(self: *ScriptedRelay) void {
        const a = std.heap.page_allocator;
        var pending: std.ArrayList(u8) = .empty;
        defer pending.deinit(a);
        var off: usize = 0; // forwarded prefix of `pending`
        var chunk: [16 * 1024]u8 = undefined;
        var mode: UpMode = switch (self.mode) {
            .app_split => .app_split,
            .first_record_hold => .first_record,
        };
        var app_fwd: usize = 0; // app_split: bytes forwarded since the app phase began

        while (true) {
            const rest = pending.items[off..];
            if (rest.len > 0) switch (mode) {
                .relay => {
                    self.forwardHub(rest) catch return;
                    off += rest.len;
                },
                .first_record => {
                    if (rest.len >= 5) {
                        const rec_len: usize = @as(usize, rest[3]) << 8 | @as(usize, rest[4]);
                        const whole = 5 + rec_len;
                        if (rest.len >= whole) {
                            self.forwardHub(rest[0..whole]) catch return;
                            off += whole;
                            mode = .first_hold_8;
                        }
                    }
                },
                .first_hold_8 => {
                    if (rest.len >= 8) {
                        self.forwardHub(rest[0..8]) catch return;
                        off += 8;
                        // The hub consumes those bytes in microseconds;
                        // the pause guarantees the continuation arrives as
                        // a separate read.
                        os.sleepMs(250);
                        mode = .relay;
                    }
                },
                .app_split => {
                    if (!self.app_phase.load(.acquire)) {
                        self.forwardHub(rest) catch return;
                        off += rest.len;
                    } else {
                        const allowed = self.split_at -| app_fwd;
                        const take = @min(rest.len, allowed);
                        if (take > 0) {
                            self.forwardHub(rest[0..take]) catch return;
                            off += take;
                            app_fwd += take;
                        }
                        if (app_fwd >= self.split_at) mode = .app_wait_echo;
                    }
                },
                .app_wait_echo => {
                    if (self.echo_seen.load(.acquire)) {
                        self.forwardHub(rest) catch return;
                        off += rest.len;
                        mode = .relay;
                    }
                },
            };
            if (off > 0 and off == pending.items.len) {
                pending.clearRetainingCapacity();
                off = 0;
            }
            const n = (link.FdConn{ .fd = self.client_fd }).readSome(&chunk, READ_MS) catch |err| switch (err) {
                // A read timeout is a poll tick, not an error: loop around
                // and re-check the script state.
                error.LinkTimeout => continue,
                else => break,
            };
            if (n == 0) break;
            pending.appendSlice(a, chunk[0..n]) catch break;
        }
    }

    fn runDown(self: *ScriptedRelay) void {
        var chunk: [16 * 1024]u8 = undefined;
        while (true) {
            const n = (link.FdConn{ .fd = self.hub_fd }).readSome(&chunk, READ_MS) catch |err| switch (err) {
                error.LinkTimeout => continue,
                else => break,
            };
            if (n == 0) break;
            os.net.socketWriteAll(self.client_fd, chunk[0..n], IO_MS) catch break;
            if (self.mode == .app_split and self.app_phase.load(.acquire))
                self.echo_seen.store(true, .release);
        }
    }
};

// Scenario (b): the hub's first read of a 40 KiB burst is capped by the
// buffer size, so it returns one whole 16 KiB record plus the prefix of
// the next; mbedTLS ends up mid-record and the refill must feed it raw
// continuation bytes. All 40 KiB are queued in the socket before the
// hub's first read, which makes the boundary-spanning first read
// deterministic.
test "tls_server read spans record boundaries without misparsing" {
    var threaded = Io.Threaded.init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const any = try Io.net.IpAddress.parse("127.0.0.1", 0);
    var listener = try any.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const far = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer far.close(io);
    const near = try listener.accept(io);
    defer near.close(io);
    try os.net.setSocketTimeouts(near.socket.handle, 5);
    try os.net.setSocketTimeouts(far.socket.handle, 5);

    const pems = try writeTestPems(io, "boundary");
    defer std.heap.page_allocator.free(pems.cert);
    defer std.heap.page_allocator.free(pems.key);
    const srv = try Server.init(io, pems.cert, pems.key);
    defer srv.deinit();

    var peer: TlsPeer = undefined;
    try peer.prepare(io, far.socket.handle);
    const Hs = struct {
        fn run(p: *TlsPeer, out: *anyerror!void) void {
            out.* = p.handshake();
        }
    };
    var hs_result: anyerror!void = {};
    const t = try std.Thread.spawn(.{}, Hs.run, .{ &peer, &hs_result });
    const started = Io.Clock.awake.now(io);
    const conn = try Conn.accept(srv, io, near.socket.handle, started, 5000);
    defer conn.destroy();
    t.join();
    try hs_result;

    const payload = try std.heap.page_allocator.alloc(u8, 40_000);
    defer std.heap.page_allocator.free(payload);
    fillPattern(payload);
    // 40 KiB of plaintext leaves as three records (~16.4 KiB ciphertext
    // each); all of it is in the socket queue before the hub reads.
    try peer.writeAll(payload);

    var got: usize = 0;
    var rbuf: [16 * 1024]u8 = undefined;
    while (got < payload.len) {
        const n = try conn.readSome(&rbuf, 3_000);
        try testing.expect(n > 0);
        try testing.expectEqualSlices(u8, payload[got..][0..n], rbuf[0..n]);
        got += n;
    }
    try testing.expectEqual(payload.len, got);
}

// Scenario (a): record A complete plus the first 3 bytes of record B's
// header in one read, the rest of B after the hub proves it consumed A
// (by echoing A's plaintext). The refill then starts on B's remaining
// header bytes — a partial record boundary the refill must hold
// faithfully.
test "tls_server holds a partial next-record header across refills" {
    var threaded = Io.Threaded.init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const any = try Io.net.IpAddress.parse("127.0.0.1", 0);
    var listener = try any.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const cf = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer cf.close(io);
    const relay_client = try listener.accept(io);
    const hf = try listener.socket.address.connect(io, .{ .mode = .stream });
    const relay_hub = try listener.accept(io);
    // Closed exactly once — by the phase block on every path, or here if
    // the test fails before the block runs.
    var relay_closed = false;
    defer if (!relay_closed) {
        relay_client.close(io);
        hf.close(io);
        relay_hub.close(io);
    };
    try os.net.setSocketTimeouts(relay_hub.socket.handle, 5);
    try os.net.setSocketTimeouts(cf.socket.handle, 5);
    // The relay's own two sockets need armed timeouts too: POSIX bounds
    // socketWriteAll by SO_SNDTIMEO, and the relay threads loop on reads.
    try os.net.setSocketTimeouts(relay_client.socket.handle, 5);
    try os.net.setSocketTimeouts(hf.socket.handle, 5);

    const pems = try writeTestPems(io, "hdrhold");
    defer std.heap.page_allocator.free(pems.cert);
    defer std.heap.page_allocator.free(pems.key);
    const srv = try Server.init(io, pems.cert, pems.key);
    defer srv.deinit();

    // 16_384 + 100 bytes of plaintext = one maximal record plus a small
    // second one; split after the maximal record plus 3 header bytes.
    const payload = try std.heap.page_allocator.alloc(u8, 16_484);
    defer std.heap.page_allocator.free(payload);
    fillPattern(payload);
    var relay = ScriptedRelay{
        .client_fd = relay_client.socket.handle,
        .hub_fd = hf.socket.handle,
        .mode = .app_split,
        .split_at = 16_406 + 3,
    };
    const up = try std.Thread.spawn(.{}, ScriptedRelay.runUp, .{&relay});
    const down = try std.Thread.spawn(.{}, ScriptedRelay.runDown, .{&relay});

    var peer: TlsPeer = undefined;
    try peer.prepare(io, cf.socket.handle);
    const Hs = struct {
        fn run(p: *TlsPeer, out: *anyerror!void) void {
            out.* = p.handshake();
        }
    };
    var hs_result: anyerror!void = {};
    const ths = try std.Thread.spawn(.{}, Hs.run, .{ &peer, &hs_result });
    const started = Io.Clock.awake.now(io);
    const conn = try Conn.accept(srv, io, relay_hub.socket.handle, started, 5000);
    phase: {
        defer {
            if (!relay_closed) {
                relay_client.close(io);
                hf.close(io);
                relay_hub.close(io);
                relay_closed = true;
            }
            up.join();
            down.join();
            conn.destroy();
        }
        ths.join();
        try hs_result;
        relay.app_phase.store(true, .release);

        // The client writes the whole payload, then collects the echo.
        const ClientApp = struct {
            fn run(p: *TlsPeer, pl: []const u8, ok: *bool) void {
                p.writeAll(pl) catch {
                    ok.* = false;
                    return;
                };
                var got: usize = 0;
                var rbuf: [16 * 1024]u8 = undefined;
                while (got < pl.len) {
                    const n = p.readSome(&rbuf) catch {
                        ok.* = false;
                        return;
                    };
                    if (n == 0) {
                        ok.* = false;
                        return;
                    }
                    if (!std.mem.eql(u8, rbuf[0..n], pl[got..][0..n])) {
                        ok.* = false;
                        return;
                    }
                    got += n;
                }
                ok.* = true;
            }
        };
        var client_ok = false;
        const tapp = try std.Thread.spawn(.{}, ClientApp.run, .{ &peer, payload, &client_ok });

        // Hub side: read the payload and echo every chunk back — the echo
        // is what tells the relay the hub consumed the first record.
        var got: usize = 0;
        var rbuf: [16 * 1024]u8 = undefined;
        while (got < payload.len) {
            const n = try conn.readSome(&rbuf, 3_000);
            try testing.expect(n > 0);
            try testing.expectEqualSlices(u8, payload[got..][0..n], rbuf[0..n]);
            try conn.write(rbuf[0..n], 3_000);
            got += n;
        }
        tapp.join();
        try testing.expect(client_ok);
        break :phase;
    }
}

// Scenario (c), handshake phase: the client's second flight reaches the
// hub split mid-record (8 bytes after the first record, then the rest a
// quarter-second later), so the handshake itself runs over a segmented
// stream; it must still complete and carry unchanged plaintext.
test "tls_server handshake completes over a segmented client flight" {
    var threaded = Io.Threaded.init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const any = try Io.net.IpAddress.parse("127.0.0.1", 0);
    var listener = try any.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const cf = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer cf.close(io);
    const relay_client = try listener.accept(io);
    const hf = try listener.socket.address.connect(io, .{ .mode = .stream });
    const relay_hub = try listener.accept(io);
    // Closed exactly once — explicitly at the end, or here on failure.
    var relay_closed = false;
    defer if (!relay_closed) {
        relay_client.close(io);
        hf.close(io);
        relay_hub.close(io);
    };
    try os.net.setSocketTimeouts(relay_hub.socket.handle, 5);
    try os.net.setSocketTimeouts(cf.socket.handle, 5);
    // The relay's own two sockets need armed timeouts too: POSIX bounds
    // socketWriteAll by SO_SNDTIMEO, and the relay threads loop on reads.
    try os.net.setSocketTimeouts(relay_client.socket.handle, 5);
    try os.net.setSocketTimeouts(hf.socket.handle, 5);

    const pems = try writeTestPems(io, "hsplit");
    defer std.heap.page_allocator.free(pems.cert);
    defer std.heap.page_allocator.free(pems.key);
    const srv = try Server.init(io, pems.cert, pems.key);
    defer srv.deinit();

    var relay = ScriptedRelay{
        .client_fd = relay_client.socket.handle,
        .hub_fd = hf.socket.handle,
        .mode = .first_record_hold,
    };
    const up = try std.Thread.spawn(.{}, ScriptedRelay.runUp, .{&relay});
    const down = try std.Thread.spawn(.{}, ScriptedRelay.runDown, .{&relay});

    var peer: TlsPeer = undefined;
    try peer.prepare(io, cf.socket.handle);
    const Hs = struct {
        fn run(p: *TlsPeer, out: *anyerror!void) void {
            out.* = p.handshake();
        }
    };
    var hs_result: anyerror!void = {};
    const ths = try std.Thread.spawn(.{}, Hs.run, .{ &peer, &hs_result });
    const started = Io.Clock.awake.now(io);
    const conn = try Conn.accept(srv, io, relay_hub.socket.handle, started, 5_000);
    defer conn.destroy();
    ths.join();
    try hs_result;

    // Application data over the same still-relaying conn: plaintext comes
    // through whole.
    const msg = "handshake-segmentation-regression-payload";
    try peer.writeAll(msg);
    var up_buf: [64]u8 = undefined;
    const n = try conn.readSome(&up_buf, 3_000);
    try testing.expectEqualStrings(msg, up_buf[0..n]);
    try conn.write(msg, 3_000);
    var down_buf: [64]u8 = undefined;
    const m = try peer.readSome(&down_buf);
    try testing.expectEqualStrings(msg, down_buf[0..m]);

    relay_client.close(io);
    hf.close(io);
    relay_hub.close(io);
    relay_closed = true;
    up.join();
    down.join();
}

test "tls_server WANT_READ retries the buffered read before the socket wait (structure)" {
    // Structural pin: mbedTLS 3.6 answers WANT_READ after
    // silently ignoring a post-handshake message (KeyUpdate,
    // NewSessionTicket) even while our in_rec buffer still holds
    // unconsumed ciphertext — the receive callback hands that ciphertext
    // over only on the NEXT ssl_read pass. Every WANT_READ loop must
    // therefore retry the mbedTLS call FIRST while bytes are buffered,
    // and only a really empty buffer may reach the socket wait in
    // fillRaw; otherwise the read parks on the socket with a whole
    // application record already in hand and the link stalls until the
    // deadline. Behavioral injection is not reachable on the test
    // platform: a genuine client KeyUpdate cannot be crafted without the
    // client's application traffic keys, which the std client does not
    // expose. So the discipline is pinned structurally against this
    // file's own source: needles are built by runtime concatenation so
    // this test's own text never matches, the counts are exact, and each
    // guard must precede its branch's fillRaw call in file order.
    const src: []const u8 = @embedFile("tls_server.zig");
    const guard_needle = "if (self.in_" ++ "len > 0) continue;";
    const guard1 = std.mem.indexOf(u8, src, guard_needle);
    try testing.expect(guard1 != null);
    const guard2 = if (guard1) |g1| std.mem.indexOfPos(u8, src, g1 + guard_needle.len, guard_needle) else null;
    try testing.expect(guard2 != null); // readSome AND the accept handshake loop
    const fill1 = std.mem.indexOf(u8, src, "self.fillRaw(self.deadline_" ++ "ms)");
    const fill2 = std.mem.indexOf(u8, src, "self.fillRaw(deadline" ++ ")");
    try testing.expect(fill1 != null);
    try testing.expect(fill2 != null);
    // Each guard sits before its own branch's socket refill.
    try testing.expect(guard1.? < fill1.?);
    try testing.expect(guard2.? < fill2.?);
    // No third WANT_READ loop exists that skips the guard.
    const guard3 = if (guard2) |g2| std.mem.indexOfPos(u8, src, g2 + guard_needle.len, guard_needle) else null;
    try testing.expect(guard3 == null);
}
