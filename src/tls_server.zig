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
//! Server; every connection owns its mbedTLS context. As documented by
//! mbedTLS, one thread may read while another writes on the same context —
//! the hub's reader loop and its writers rely on that, and mbedTLS's PSA
//! core is made thread-safe by the OS mutex bindings in
//! tls/mcp_hub_threading.c (installed once at server init).

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
        mcp_hub_mbedtls_threading_install();
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
    deadline_ms: i64 = 0,
    /// Absolute awake-clock deadline (ms) for the current write.
    send_deadline_ms: i64 = 0,

    /// Run the TLS 1.3 server handshake on an accepted socket, within the
    /// rest of the handshake budget counted from `started`.
    pub fn accept(server: *Server, io: Io, fd: os.net.Handle, started: Io.Timestamp, budget_ms: u64) !*Conn {
        const self = try gpa.create(Conn);
        self.* = .{ .fd = fd, .io = io, .ssl = undefined };
        c.mbedtls_ssl_init(&self.ssl);
        var ssl_live = true;
        defer if (!ssl_live) c.mbedtls_ssl_free(&self.ssl);
        errdefer gpa.destroy(self);

        const rc = c.mbedtls_ssl_setup(&self.ssl, &server.conf);
        if (rc != 0) {
            ssl_live = false;
            return logMbedErr("mbedtls_ssl_setup", rc, error.OutOfMemory);
        }
        c.mbedtls_ssl_set_bio(&self.ssl, self, bioSend, null, bioRecvTimeout);

        const elapsed_i = started.untilNow(io, .awake).toMilliseconds();
        const elapsed: u64 = if (elapsed_i > 0) @intCast(elapsed_i) else 0;
        const left: u64 = if (elapsed >= budget_ms) 0 else budget_ms - elapsed;
        self.deadline_ms = nowMs(io) + @as(i64, @intCast(left));
        self.send_deadline_ms = self.deadline_ms;

        while (true) {
            const hrc = c.mbedtls_ssl_handshake(&self.ssl);
            if (hrc == 0) return self;
            switch (hrc) {
                c.MBEDTLS_ERR_SSL_WANT_READ, c.MBEDTLS_ERR_SSL_WANT_WRITE => {
                    if (remainingMs(self) == 0) return error.LinkTimeout;
                    continue;
                },
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
        self.deadline_ms = nowMs(self.io) + @as(i64, @intCast(timeout_ms));
        while (true) {
            const rc = c.mbedtls_ssl_read(&self.ssl, buf.ptr, buf.len);
            if (rc > 0) return @intCast(rc);
            switch (rc) {
                0 => return 0,
                c.MBEDTLS_ERR_SSL_WANT_READ, c.MBEDTLS_ERR_SSL_WANT_WRITE => {
                    if (remainingMs(self) == 0) return error.LinkTimeout;
                    continue;
                },
                c.MBEDTLS_ERR_SSL_TIMEOUT => return error.LinkTimeout,
                c.MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY, c.MBEDTLS_ERR_SSL_CONN_EOF => return 0,
                else => return error.LinkClosed,
            }
        }
    }

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
    // The armed deadline rules, not mbedTLS's own (retransmit) timeout.
    _ = timeout_ms;
    const left = remainingMs(self);
    if (left == 0) return c.MBEDTLS_ERR_SSL_TIMEOUT;
    const n = (link.FdConn{ .fd = self.fd }).readSome(buf[0..len], left) catch |err| switch (err) {
        error.LinkTimeout => return c.MBEDTLS_ERR_SSL_TIMEOUT,
        else => return c.MBEDTLS_ERR_NET_RECV_FAILED,
    };
    if (n == 0) return 0; // EOF: mbedtls maps it to MBEDTLS_ERR_SSL_CONN_EOF
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
