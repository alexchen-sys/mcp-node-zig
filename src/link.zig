//! Node link wire protocol shared by the outbound node mode and the hub.
//!
//! Framing: a 9-byte big-endian header followed by the payload:
//!   u32 len (payload bytes), u8 type, u32 stream_id.
//! Handshake: the hub sends CHALLENGE (32 random bytes); the node answers
//! HELLO {"v":1,"name":..,"auth":hex(HMAC-SHA256(secret, DOMAIN || nonce ||
//! name))}; the hub recomputes the MAC, compares in constant time and
//! answers WELCOME {"v":1} or GOAWAY. The secret never crosses the wire and
//! the fresh nonce prevents replay of a captured HELLO.
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

pub fn decodeHeader(in: *const [HEADER_LEN]u8, max_payload: u32) DecodeError!Header {
    const len = std.mem.readInt(u32, in[0..4], .big);
    if (len > max_payload) return error.FrameTooLarge;
    const kind = std.enums.fromInt(FrameType, in[4]) orelse return error.UnknownFrameType;
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

pub fn computeAuth(secret: []const u8, nonce: *const [NONCE_LEN]u8, name: []const u8) [MAC_LEN]u8 {
    var mac: [MAC_LEN]u8 = undefined;
    var h = HmacSha256.init(secret);
    h.update(AUTH_DOMAIN);
    h.update(nonce);
    h.update(name);
    h.final(&mac);
    return mac;
}

/// Constant-time check of a hex-encoded MAC against the expected value.
/// Malformed hex is a mismatch, never an error the caller could leak.
pub fn verifyAuth(secret: []const u8, nonce: *const [NONCE_LEN]u8, name: []const u8, auth_hex: []const u8) bool {
    const expected = computeAuth(secret, nonce, name);
    if (auth_hex.len != MAC_LEN * 2) return false;
    var got: [MAC_LEN]u8 = undefined;
    _ = std.fmt.hexToBytes(&got, auth_hex) catch return false;
    return std.crypto.timing_safe.eql([MAC_LEN]u8, got, expected);
}

pub fn buildHello(arena: Allocator, secret: []const u8, nonce: *const [NONCE_LEN]u8, name: []const u8) ![]const u8 {
    const mac = computeAuth(secret, nonce, name);
    const hex = std.fmt.bytesToHex(mac, .lower);
    var out: std.ArrayList(u8) = .empty;
    try out.print(arena, "{{\"v\":{d},\"name\":", .{PROTOCOL_VERSION});
    try util.appendJsonString(&out, arena, name);
    try out.appendSlice(arena, ",\"auth\":\"");
    try out.appendSlice(arena, &hex);
    try out.appendSlice(arena, "\"}");
    return out.items;
}

pub const Hello = struct {
    v: u32,
    name: []const u8,
    auth: []const u8,
};

pub fn parseHello(arena: Allocator, payload: []const u8) !Hello {
    const hello = std.json.parseFromSliceLeaky(Hello, arena, payload, .{}) catch return error.BadHello;
    if (hello.v != PROTOCOL_VERSION) return error.UnsupportedVersion;
    if (!validName(hello.name)) return error.BadName;
    return hello;
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

/// Write one frame. Callers serialize writers per link (one mutex per
/// link): header and payload go out as separate writes, so two concurrent
/// writers would interleave. Small frames are coalesced into one write.
pub fn writeFrame(fd: os.net.Handle, kind: FrameType, stream_id: u32, payload: []const u8, timeout_ms: u64) !void {
    try writeFrameParts(fd, kind, stream_id, &.{payload}, timeout_ms);
}

/// Write one frame whose payload is the concatenation of `parts`.
pub fn writeFrameParts(fd: os.net.Handle, kind: FrameType, stream_id: u32, parts: []const []const u8, timeout_ms: u64) !void {
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
        return os.net.socketWriteAll(fd, small[0..off], timeout_ms);
    }
    try os.net.socketWriteAll(fd, small[0..HEADER_LEN], timeout_ms);
    for (parts) |p| try os.net.socketWriteAll(fd, p, timeout_ms);
}

pub const Frame = struct {
    kind: FrameType,
    stream_id: u32,
    payload: []u8,
};

/// Fill `buf` completely. `idle_ms` bounds each read (no inbound byte for
/// that long -> error.LinkTimeout); EOF mid-buffer -> error.LinkClosed.
fn readExact(fd: os.net.Handle, buf: []u8, idle_ms: u64) !void {
    var filled: usize = 0;
    while (filled < buf.len) {
        os.net.setSocketReadTimeoutMs(fd, idle_ms) catch return error.SocketOptionFailed;
        const n = os.net.socketReadSome(fd, buf[filled..], idle_ms) catch |err| {
            if (os.net.isReadTimeout(err)) return error.LinkTimeout;
            return error.LinkClosed;
        };
        if (n == 0) return error.LinkClosed;
        filled += n;
    }
}

/// Read one frame; the payload is allocated from `gpa` (caller frees).
pub fn readFrame(gpa: Allocator, fd: os.net.Handle, max_payload: u32, idle_ms: u64) !Frame {
    var hdr: [HEADER_LEN]u8 = undefined;
    try readExact(fd, &hdr, idle_ms);
    const h = try decodeHeader(&hdr, max_payload);
    const payload = try gpa.alloc(u8, h.len);
    errdefer gpa.free(payload);
    try readExact(fd, payload, idle_ms);
    return .{ .kind = h.kind, .stream_id = h.stream_id, .payload = payload };
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
    const payload = try buildHello(arena, "s3cret", &nonce, "pc");
    const hello = try parseHello(arena, payload);
    try testing.expectEqualStrings("pc", hello.name);
    try testing.expect(verifyAuth("s3cret", &nonce, hello.name, hello.auth));
    // wrong secret, wrong name, fresh nonce (replay), malformed hex
    try testing.expect(!verifyAuth("other", &nonce, hello.name, hello.auth));
    try testing.expect(!verifyAuth("s3cret", &nonce, "pc2", hello.auth));
    var nonce2 = nonce;
    nonce2[0] ^= 1;
    try testing.expect(!verifyAuth("s3cret", &nonce2, hello.name, hello.auth));
    try testing.expect(!verifyAuth("s3cret", &nonce, hello.name, "zz"));
    try testing.expect(!verifyAuth("s3cret", &nonce, hello.name, "g" ** 64));
}

test "link hello parser rejects bad versions, names and shapes" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try testing.expectError(error.UnsupportedVersion, parseHello(arena, "{\"v\":2,\"name\":\"a\",\"auth\":\"\"}"));
    try testing.expectError(error.BadName, parseHello(arena, "{\"v\":1,\"name\":\"a/b\",\"auth\":\"\"}"));
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
