//! Node link wire protocol shared by the outbound node mode and the hub.
//!
//! Framing: a 9-byte big-endian header followed by the payload:
//!   u32 len (payload bytes), u8 type, u32 stream_id.
//! Handshake (mutual): the hub sends CHALLENGE (32 random bytes, hub_nonce);
//! the node answers HELLO {"v":1,"name":..,"nonce":hex(node_nonce),
//! "auth":hex(HMAC-SHA256(secret, "<DOMAIN> node" || hub_nonce ||
//! node_nonce || name))}; the hub checks it in constant time and answers
//! WELCOME {"v":1,"auth":hex(HMAC-SHA256(secret, "<DOMAIN> hub" ||
//! hub_nonce || node_nonce || name))} or GOAWAY. The node verifies the
//! WELCOME MAC before it accepts any other frame, so a peer without the
//! secret can never issue REQs. The secret never crosses the wire and each
//! side's fresh nonce prevents replay of a captured proof.
//!
//! This module holds only the codec, the MAC, name validation, secret-file
//! parsing and blocking frame I/O over a connected socket; the dial loop
//! lives in node_link.zig and the relay in hub.zig.

const std = @import("std");
const Allocator = std.mem.Allocator;
const os = @import("os.zig");
const util = @import("util.zig");

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

pub const PROTOCOL_VERSION: u32 = 1;
pub const HEADER_LEN: usize = 9;
/// Payload cap: the 32 MiB request-body cap plus room for the RESP status
/// prefix and JSON framing. A peer announcing more is dropped.
pub const MAX_PAYLOAD: u32 = 32 * 1024 * 1024 + 64 * 1024;
/// Handshake frames are tiny; a larger one is hostile.
pub const MAX_HANDSHAKE_PAYLOAD: u32 = 4096;
pub const NONCE_LEN: usize = 32;
pub const MAC_LEN: usize = HmacSha256.mac_length;
pub const MAX_NAME_LEN: usize = 64;
pub const SECRET_FILE_MAX_BYTES: usize = 64 * 1024;
const AUTH_DOMAIN = "mcp-node-reverse-v1";

pub const FrameType = enum(u8) {
    hello = 1,
    challenge = 2,
    welcome = 3,
    req = 4,
    resp = 5,
    ping = 6,
    pong = 7,
    goaway = 8,
};

pub const Header = struct {
    len: u32,
    kind: FrameType,
    stream_id: u32,
};

pub fn encodeHeader(out: *[HEADER_LEN]u8, h: Header) void {
    std.mem.writeInt(u32, out[0..4], h.len, .big);
    out[4] = @intFromEnum(h.kind);
    std.mem.writeInt(u32, out[5..9], h.stream_id, .big);
}

pub const DecodeError = error{ UnknownFrameType, FrameTooLarge };

/// Per-type payload ceiling. Control frames are tiny by construction, so a
/// peer announcing more is dropped before anything is allocated.
pub fn typeCap(kind: FrameType) u32 {
    return switch (kind) {
        .ping, .pong, .challenge => 64,
        .goaway, .welcome => 256,
        .hello => MAX_HANDSHAKE_PAYLOAD,
        .req, .resp => MAX_PAYLOAD,
    };
}

pub fn decodeHeader(in: *const [HEADER_LEN]u8, max_payload: u32) DecodeError!Header {
    const len = std.mem.readInt(u32, in[0..4], .big);
    if (len > max_payload) return error.FrameTooLarge;
    const kind = std.enums.fromInt(FrameType, in[4]) orelse return error.UnknownFrameType;
    if (len > typeCap(kind)) return error.FrameTooLarge;
    return .{ .len = len, .kind = kind, .stream_id = std.mem.readInt(u32, in[5..9], .big) };
}

/// Node names: [A-Za-z0-9._-]{1,64}. Safe in URL paths and JSON without
/// escaping, and unambiguous as the left side of a `name:secret` line.
pub fn validName(name: []const u8) bool {
    if (name.len == 0 or name.len > MAX_NAME_LEN) return false;
    for (name) |c| {
        switch (c) {
            'a'...'z', 'A'...'Z', '0'...'9', '.', '_', '-' => {},
            else => return false,
        }
    }
    return true;
}

/// Which side a MAC proves. The two directions use distinct domain
/// strings, so a node MAC can never be reflected back as a hub MAC.
pub const Direction = enum {
    node,
    hub,

    fn domain(self: Direction) []const u8 {
        return switch (self) {
            .node => AUTH_DOMAIN ++ " node",
            .hub => AUTH_DOMAIN ++ " hub",
        };
    }
};

/// HMAC-SHA256(secret, domain || hub_nonce || node_nonce || name).
/// The domain is fixed per direction and both nonces are fixed-length, so
/// the variable-length name last makes the concatenation unambiguous.
pub fn computeAuth(dir: Direction, secret: []const u8, hub_nonce: *const [NONCE_LEN]u8, node_nonce: *const [NONCE_LEN]u8, name: []const u8) [MAC_LEN]u8 {
    var mac: [MAC_LEN]u8 = undefined;
    var h = HmacSha256.init(secret);
    h.update(dir.domain());
    h.update(hub_nonce);
    h.update(node_nonce);
    h.update(name);
    h.final(&mac);
    return mac;
}

/// Constant-time check of a hex-encoded MAC against the expected value.
/// Malformed hex is a mismatch, never an error the caller could leak.
pub fn verifyAuth(dir: Direction, secret: []const u8, hub_nonce: *const [NONCE_LEN]u8, node_nonce: *const [NONCE_LEN]u8, name: []const u8, auth_hex: []const u8) bool {
    const expected = computeAuth(dir, secret, hub_nonce, node_nonce, name);
    var got: [MAC_LEN]u8 = @splat(0);
    const well_formed = auth_hex.len == MAC_LEN * 2 and
        if (std.fmt.hexToBytes(&got, auth_hex)) |_| true else |_| false;
    const same = std.crypto.timing_safe.eql([MAC_LEN]u8, got, expected);
    return well_formed and same;
}

pub fn buildHello(arena: Allocator, secret: []const u8, hub_nonce: *const [NONCE_LEN]u8, node_nonce: *const [NONCE_LEN]u8, name: []const u8) ![]const u8 {
    const mac = computeAuth(.node, secret, hub_nonce, node_nonce, name);
    const hex = std.fmt.bytesToHex(mac, .lower);
    const nonce_hex = std.fmt.bytesToHex(node_nonce.*, .lower);
    var out: std.ArrayList(u8) = .empty;
    try out.print(arena, "{{\"v\":{d},\"name\":", .{PROTOCOL_VERSION});
    try util.appendJsonString(&out, arena, name);
    try out.appendSlice(arena, ",\"nonce\":\"");
    try out.appendSlice(arena, &nonce_hex);
    try out.appendSlice(arena, "\",\"auth\":\"");
    try out.appendSlice(arena, &hex);
    try out.appendSlice(arena, "\"}");
    return out.items;
}

pub const Hello = struct {
    name: []const u8,
    auth: []const u8,
    /// The node's own fresh nonce, decoded.
    nonce: [NONCE_LEN]u8,
};

const HelloWire = struct {
    v: u32,
    name: []const u8,
    nonce: []const u8,
    auth: []const u8,
};

pub fn parseHello(arena: Allocator, payload: []const u8) !Hello {
    const wire = std.json.parseFromSliceLeaky(HelloWire, arena, payload, .{}) catch return error.BadHello;
    if (wire.v != PROTOCOL_VERSION) return error.UnsupportedVersion;
    if (!validName(wire.name)) return error.BadName;
    var nonce: [NONCE_LEN]u8 = undefined;
    if (wire.nonce.len != NONCE_LEN * 2) return error.BadHello;
    _ = std.fmt.hexToBytes(&nonce, wire.nonce) catch return error.BadHello;
    return .{ .name = wire.name, .auth = wire.auth, .nonce = nonce };
}

/// WELCOME payload: the hub proves the secret back to the node.
pub fn buildWelcome(arena: Allocator, secret: []const u8, hub_nonce: *const [NONCE_LEN]u8, node_nonce: *const [NONCE_LEN]u8, name: []const u8) ![]const u8 {
    const mac = computeAuth(.hub, secret, hub_nonce, node_nonce, name);
    const hex = std.fmt.bytesToHex(mac, .lower);
    return std.fmt.allocPrint(arena, "{{\"v\":{d},\"auth\":\"{s}\"}}", .{ PROTOCOL_VERSION, &hex });
}

/// Node-side check of a WELCOME payload. Anything other than a v1 object
/// carrying the right hub MAC is a failure.
pub fn verifyWelcome(arena: Allocator, secret: []const u8, hub_nonce: *const [NONCE_LEN]u8, node_nonce: *const [NONCE_LEN]u8, name: []const u8, payload: []const u8) bool {
    const Welcome = struct { v: u32, auth: []const u8 };
    const w = std.json.parseFromSliceLeaky(Welcome, arena, payload, .{}) catch return false;
    if (w.v != PROTOCOL_VERSION) return false;
    return verifyAuth(.hub, secret, hub_nonce, node_nonce, name, w.auth);
}

/// Hub-side secrets. `single`: one secret, any valid name may connect.
/// `pinned`: each name is bound to its own secret; unknown names are refused.
pub const SecretSet = union(enum) {
    single: []const u8,
    pinned: []const Entry,

    pub const Entry = struct { name: []const u8, secret: []const u8 };

    pub fn lookup(self: SecretSet, name: []const u8) ?[]const u8 {
        switch (self) {
            .single => |s| return s,
            .pinned => |entries| {
                for (entries) |e| {
                    if (std.mem.eql(u8, e.name, name)) return e.secret;
                }
                return null;
            },
        }
    }
};

/// Parse a hub secret file. Blank lines and `#` comments are ignored.
/// Exactly one line without a colon is a single shared secret; otherwise
/// every line must be `name:secret` with a valid, unique name and a
/// non-empty secret. A single shared secret therefore must not contain ':'.
pub fn parseSecretFile(arena: Allocator, content: []const u8) !SecretSet {
    var entries: std.ArrayList(SecretSet.Entry) = .empty;
    var single: ?[]const u8 = null;
    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        if (std.mem.indexOfScalar(u8, line, ':')) |colon| {
            if (single != null) return error.MixedSecretFile;
            const name = std.mem.trim(u8, line[0..colon], " \t");
            const secret = std.mem.trim(u8, line[colon + 1 ..], " \t");
            if (!validName(name)) return error.BadSecretName;
            if (secret.len == 0) return error.EmptySecret;
            for (entries.items) |e| {
                if (std.mem.eql(u8, e.name, name)) return error.DuplicateSecretName;
            }
            try entries.append(arena, .{ .name = try arena.dupe(u8, name), .secret = try arena.dupe(u8, secret) });
        } else {
            if (single != null) return error.MultipleSecrets;
            if (entries.items.len != 0) return error.MixedSecretFile;
            single = try arena.dupe(u8, line);
        }
    }
    if (single) |s| return .{ .single = s };
    if (entries.items.len == 0) return error.EmptySecret;
    return .{ .pinned = entries.items };
}

/// Node-side secret file: the whole trimmed content is the secret.
pub fn parseNodeSecret(content: []const u8) ![]const u8 {
    const secret = std.mem.trim(u8, content, " \t\r\n");
    if (secret.len == 0) return error.EmptySecret;
    return secret;
}

/// RESP payload: u16 big-endian HTTP status, then the JSON body.
pub fn splitResp(payload: []const u8) !struct { status: u16, body: []const u8 } {
    if (payload.len < 2) return error.BadResp;
    return .{ .status = std.mem.readInt(u16, payload[0..2], .big), .body = payload[2..] };
}

// ---------------------------------------------------------------------------
// Blocking frame I/O over a connected socket
// ---------------------------------------------------------------------------

/// The frame functions below work on any byte channel with
///   readSome(buf, timeout_ms) !usize   (0 = EOF; error.LinkTimeout when
///                                        nothing arrived in timeout_ms)
///   write(bytes, timeout_ms) !void
///   flush(timeout_ms) !void              (end of one frame)
/// FdConn is the plain-socket channel; the node side adds a TLS one.
pub const FdConn = struct {
    fd: os.net.Handle,

    pub fn readSome(self: FdConn, buf: []u8, timeout_ms: u64) !usize {
        os.net.setSocketReadTimeoutMs(self.fd, timeout_ms) catch return error.SocketOptionFailed;
        return os.net.socketReadSome(self.fd, buf, timeout_ms) catch |err| {
            if (os.net.isReadTimeout(err)) return error.LinkTimeout;
            return error.LinkClosed;
        };
    }

    pub fn write(self: FdConn, bytes: []const u8, timeout_ms: u64) !void {
        return os.net.socketWriteAll(self.fd, bytes, timeout_ms);
    }

    pub fn flush(_: FdConn, _: u64) !void {}
};

/// Write one frame. Callers serialize writers per link (one mutex per
/// link): header and payload go out as separate writes, so two concurrent
/// writers would interleave. Small frames are coalesced into one write.
pub fn writeFrame(fd: os.net.Handle, kind: FrameType, stream_id: u32, payload: []const u8, timeout_ms: u64) !void {
    try writeFramePartsOn(FdConn{ .fd = fd }, kind, stream_id, &.{payload}, timeout_ms);
}

/// Write one frame whose payload is the concatenation of `parts`.
pub fn writeFrameParts(fd: os.net.Handle, kind: FrameType, stream_id: u32, parts: []const []const u8, timeout_ms: u64) !void {
    try writeFramePartsOn(FdConn{ .fd = fd }, kind, stream_id, parts, timeout_ms);
}

pub fn writeFramePartsOn(conn: anytype, kind: FrameType, stream_id: u32, parts: []const []const u8, timeout_ms: u64) !void {
    var total: usize = 0;
    for (parts) |p| total += p.len;
    if (total > MAX_PAYLOAD) return error.FrameTooLarge;
    var small: [HEADER_LEN + 512]u8 = undefined;
    encodeHeader(small[0..HEADER_LEN], .{ .len = @intCast(total), .kind = kind, .stream_id = stream_id });
    if (total <= small.len - HEADER_LEN) {
        var off: usize = HEADER_LEN;
        for (parts) |p| {
            @memcpy(small[off .. off + p.len], p);
            off += p.len;
        }
        try conn.write(small[0..off], timeout_ms);
        return conn.flush(timeout_ms);
    }
    try conn.write(small[0..HEADER_LEN], timeout_ms);
    for (parts) |p| try conn.write(p, timeout_ms);
    try conn.flush(timeout_ms);
}

pub const Frame = struct {
    kind: FrameType,
    stream_id: u32,
    payload: []u8,
};

/// Fill `buf` completely. `idle_ms` bounds each read (no inbound byte for
/// that long -> error.LinkTimeout); EOF mid-buffer -> error.LinkClosed.
fn readExact(conn: anytype, buf: []u8, idle_ms: u64) !void {
    var filled: usize = 0;
    while (filled < buf.len) {
        const n = try conn.readSome(buf[filled..], idle_ms);
        if (n == 0) return error.LinkClosed;
        filled += n;
    }
}

/// Read one frame; the payload is allocated from `gpa` (caller frees).
pub fn readFrame(gpa: Allocator, fd: os.net.Handle, max_payload: u32, idle_ms: u64) !Frame {
    return readFrameOn(gpa, FdConn{ .fd = fd }, max_payload, idle_ms);
}

pub fn readFrameOn(gpa: Allocator, conn: anytype, max_payload: u32, idle_ms: u64) !Frame {
    var hdr: [HEADER_LEN]u8 = undefined;
    try readExact(conn, &hdr, idle_ms);
    const h = try decodeHeader(&hdr, max_payload);
    const payload = try gpa.alloc(u8, h.len);
    errdefer gpa.free(payload);
    try readExact(conn, payload, idle_ms);
    return .{ .kind = h.kind, .stream_id = h.stream_id, .payload = payload };
}

/// Read one frame under one absolute deadline of `budget_ms` counted from
/// `started`: a peer dribbling one byte per read cannot stretch it. Used
/// for the handshake, where an unauthenticated peer must finish in time.
pub fn readFrameWithin(gpa: Allocator, fd: os.net.Handle, max_payload: u32, io: std.Io, started: std.Io.Timestamp, budget_ms: u64) !Frame {
    return readFrameWithinOn(gpa, FdConn{ .fd = fd }, max_payload, io, started, budget_ms);
}

pub fn readFrameWithinOn(gpa: Allocator, conn: anytype, max_payload: u32, io: std.Io, started: std.Io.Timestamp, budget_ms: u64) !Frame {
    var hdr: [HEADER_LEN]u8 = undefined;
    try readExactWithin(conn, &hdr, io, started, budget_ms);
    const h = try decodeHeader(&hdr, max_payload);
    const payload = try gpa.alloc(u8, h.len);
    errdefer gpa.free(payload);
    try readExactWithin(conn, payload, io, started, budget_ms);
    return .{ .kind = h.kind, .stream_id = h.stream_id, .payload = payload };
}

fn readExactWithin(conn: anytype, buf: []u8, io: std.Io, started: std.Io.Timestamp, budget_ms: u64) !void {
    var filled: usize = 0;
    while (filled < buf.len) {
        const elapsed_i = started.untilNow(io, .awake).toMilliseconds();
        const elapsed: u64 = if (elapsed_i > 0) @intCast(elapsed_i) else 0;
        if (elapsed >= budget_ms) return error.LinkTimeout;
        const remaining = budget_ms - elapsed;
        // Every read is armed with what is left of the one deadline.
        const n = try conn.readSome(buf[filled..], remaining);
        if (n == 0) return error.LinkClosed;
        filled += n;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "link header round-trips and rejects unknown types and oversize" {
    var buf: [HEADER_LEN]u8 = undefined;
    encodeHeader(&buf, .{ .len = 0x01020304, .kind = .resp, .stream_id = 0xA0B0C0D0 });
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4, 5, 0xA0, 0xB0, 0xC0, 0xD0 }, &buf);
    const h = try decodeHeader(&buf, std.math.maxInt(u32));
    try testing.expectEqual(@as(u32, 0x01020304), h.len);
    try testing.expectEqual(FrameType.resp, h.kind);
    try testing.expectEqual(@as(u32, 0xA0B0C0D0), h.stream_id);
    try testing.expectError(error.FrameTooLarge, decodeHeader(&buf, 1024));
    buf[4] = 0;
    try testing.expectError(error.UnknownFrameType, decodeHeader(&buf, std.math.maxInt(u32)));
    buf[4] = 9;
    try testing.expectError(error.UnknownFrameType, decodeHeader(&buf, std.math.maxInt(u32)));
}

test "link control frames are capped per type before allocation" {
    var buf: [HEADER_LEN]u8 = undefined;
    const cases = [_]struct { kind: FrameType, ok: u32 }{
        .{ .kind = .ping, .ok = 64 },
        .{ .kind = .pong, .ok = 64 },
        .{ .kind = .challenge, .ok = 64 },
        .{ .kind = .goaway, .ok = 256 },
        .{ .kind = .welcome, .ok = 256 },
        .{ .kind = .hello, .ok = MAX_HANDSHAKE_PAYLOAD },
    };
    for (cases) |c| {
        encodeHeader(&buf, .{ .len = c.ok, .kind = c.kind, .stream_id = 0 });
        _ = try decodeHeader(&buf, MAX_PAYLOAD);
        encodeHeader(&buf, .{ .len = c.ok + 1, .kind = c.kind, .stream_id = 0 });
        try testing.expectError(error.FrameTooLarge, decodeHeader(&buf, MAX_PAYLOAD));
    }
    encodeHeader(&buf, .{ .len = 1 << 20, .kind = .req, .stream_id = 1 });
    _ = try decodeHeader(&buf, MAX_PAYLOAD);
}

test "link oversize ping is refused on the read path without reading the body" {
    // A header announcing a 1 MiB PING followed by nothing: the read must
    // fail on the header alone instead of waiting for (and allocating) it.
    const Fake = struct {
        bytes: []const u8,
        off: usize = 0,
        pub fn readSome(self: *@This(), out: []u8, _: u64) !usize {
            const n = @min(out.len, self.bytes.len - self.off);
            @memcpy(out[0..n], self.bytes[self.off .. self.off + n]);
            self.off += n;
            return n;
        }
    };
    var hdr: [HEADER_LEN]u8 = undefined;
    encodeHeader(&hdr, .{ .len = 1 << 20, .kind = .ping, .stream_id = 0 });
    var fake = Fake{ .bytes = &hdr };
    try testing.expectError(error.FrameTooLarge, readFrameOn(testing.allocator, &fake, MAX_PAYLOAD, 1000));
}

test "link node names follow the documented alphabet and length" {
    try testing.expect(validName("pc-1"));
    try testing.expect(validName("a.b_c-D9"));
    try testing.expect(validName("x" ** 64));
    try testing.expect(!validName("x" ** 65));
    try testing.expect(!validName(""));
    try testing.expect(!validName("a/b"));
    try testing.expect(!validName("a:b"));
    try testing.expect(!validName("a b"));
    try testing.expect(!validName("caf\xc3\xa9"));
}

test "link hello round-trip verifies, and any tampering fails" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var nonce: [NONCE_LEN]u8 = @splat(7);
    var node_nonce: [NONCE_LEN]u8 = @splat(0x5a);
    const payload = try buildHello(arena, "s3cret", &nonce, &node_nonce, "pc");
    const hello = try parseHello(arena, payload);
    try testing.expectEqualStrings("pc", hello.name);
    try testing.expectEqualSlices(u8, &node_nonce, &hello.nonce);
    try testing.expect(verifyAuth(.node, "s3cret", &nonce, &hello.nonce, hello.name, hello.auth));
    // wrong secret, wrong name, fresh nonce (replay), malformed hex
    try testing.expect(!verifyAuth(.node, "other", &nonce, &hello.nonce, hello.name, hello.auth));
    try testing.expect(!verifyAuth(.node, "s3cret", &nonce, &hello.nonce, "pc2", hello.auth));
    var nonce2 = nonce;
    nonce2[0] ^= 1;
    try testing.expect(!verifyAuth(.node, "s3cret", &nonce2, &hello.nonce, hello.name, hello.auth));
    var node_nonce2 = node_nonce;
    node_nonce2[31] ^= 1;
    try testing.expect(!verifyAuth(.node, "s3cret", &nonce, &node_nonce2, hello.name, hello.auth));
    try testing.expect(!verifyAuth(.node, "s3cret", &nonce, &hello.nonce, hello.name, "zz"));
    try testing.expect(!verifyAuth(.node, "s3cret", &nonce, &hello.nonce, hello.name, "g" ** 64));
    // A node MAC is not a hub MAC: reflecting HELLO's auth as WELCOME fails.
    try testing.expect(!verifyAuth(.hub, "s3cret", &nonce, &hello.nonce, hello.name, hello.auth));
}

test "link welcome proves the hub, and a wrong or missing auth fails" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const hub_nonce: [NONCE_LEN]u8 = @splat(1);
    const node_nonce: [NONCE_LEN]u8 = @splat(2);
    const good = try buildWelcome(arena, "s3cret", &hub_nonce, &node_nonce, "pc");
    try testing.expect(verifyWelcome(arena, "s3cret", &hub_nonce, &node_nonce, "pc", good));
    try testing.expect(!verifyWelcome(arena, "other", &hub_nonce, &node_nonce, "pc", good));
    try testing.expect(!verifyWelcome(arena, "s3cret", &hub_nonce, &node_nonce, "pc2", good));
    // a WELCOME bound to another node nonce (relayed from a different link)
    var other_nonce = node_nonce;
    other_nonce[0] ^= 1;
    try testing.expect(!verifyWelcome(arena, "s3cret", &hub_nonce, &other_nonce, "pc", good));
    try testing.expect(!verifyWelcome(arena, "s3cret", &hub_nonce, &node_nonce, "pc", "{\"v\":1}"));
    try testing.expect(!verifyWelcome(arena, "s3cret", &hub_nonce, &node_nonce, "pc", "{\"v\":1,\"auth\":\"\"}"));
    try testing.expect(!verifyWelcome(arena, "s3cret", &hub_nonce, &node_nonce, "pc", "{\"v\":1,\"auth\":\"" ++ "0" ** 64 ++ "\"}"));
    try testing.expect(!verifyWelcome(arena, "s3cret", &hub_nonce, &node_nonce, "pc", "not json"));
}

test "link hello parser rejects bad versions, names and shapes" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const n64 = "ab" ** 32;
    try testing.expectError(error.UnsupportedVersion, parseHello(arena, "{\"v\":2,\"name\":\"a\",\"nonce\":\"" ++ n64 ++ "\",\"auth\":\"\"}"));
    try testing.expectError(error.BadName, parseHello(arena, "{\"v\":1,\"name\":\"a/b\",\"nonce\":\"" ++ n64 ++ "\",\"auth\":\"\"}"));
    try testing.expectError(error.BadHello, parseHello(arena, "{\"v\":1,\"name\":\"a\",\"auth\":\"\"}"));
    try testing.expectError(error.BadHello, parseHello(arena, "{\"v\":1,\"name\":\"a\",\"nonce\":\"abcd\",\"auth\":\"\"}"));
    try testing.expectError(error.BadHello, parseHello(arena, "{\"v\":1,\"name\":\"a\",\"nonce\":\"" ++ "zz" ** 32 ++ "\",\"auth\":\"\"}"));
    try testing.expectError(error.BadHello, parseHello(arena, "{\"v\":1}"));
    try testing.expectError(error.BadHello, parseHello(arena, "not json"));
}

test "link secret file: single, pinned, and malformed variants" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const single = try parseSecretFile(arena, "\n# comment\n  shared-secret \r\n");
    try testing.expectEqualStrings("shared-secret", single.lookup("anyone").?);

    const pinned = try parseSecretFile(arena, "pc:one\n# x\nlaptop : two\n");
    try testing.expectEqualStrings("one", pinned.lookup("pc").?);
    try testing.expectEqualStrings("two", pinned.lookup("laptop").?);
    try testing.expect(pinned.lookup("other") == null);

    try testing.expectError(error.EmptySecret, parseSecretFile(arena, ""));
    try testing.expectError(error.EmptySecret, parseSecretFile(arena, "# only\n"));
    try testing.expectError(error.EmptySecret, parseSecretFile(arena, "pc:\n"));
    try testing.expectError(error.MultipleSecrets, parseSecretFile(arena, "a\nb\n"));
    try testing.expectError(error.MixedSecretFile, parseSecretFile(arena, "a\npc:b\n"));
    try testing.expectError(error.MixedSecretFile, parseSecretFile(arena, "pc:b\na\n"));
    try testing.expectError(error.BadSecretName, parseSecretFile(arena, "a b:c\n"));
    try testing.expectError(error.DuplicateSecretName, parseSecretFile(arena, "pc:a\npc:b\n"));

    try testing.expectEqualStrings("k", try parseNodeSecret(" k\n"));
    try testing.expectError(error.EmptySecret, parseNodeSecret(" \n"));
}

test "link resp payload split" {
    const r = try splitResp(&.{ 0x01, 0xF6, '{', '}' });
    try testing.expectEqual(@as(u16, 502), r.status);
    try testing.expectEqualStrings("{}", r.body);
    try testing.expectError(error.BadResp, splitResp(&.{0x01}));
}
