//! Leaf helpers with zero project-type dependencies: JSON value/string
//! encoding, UTF-8 sequence scanning and lossy decoding, optional
//! tool-argument extraction, CSV allowlist splitting, hex rendering.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Value = std.json.Value;

pub const IO_BUF_SIZE: usize = 16 * 1024; // shared read scratch: HTTP, session pipes, files

pub fn splitCsv(arena: Allocator, s: []const u8) ![][]const u8 {
    var list: std.ArrayList([]const u8) = .empty;
    var it = std.mem.splitScalar(u8, s, ',');
    while (it.next()) |part| {
        const trimmed = std.mem.trim(u8, part, " \t\r\n");
        if (trimmed.len == 0) continue;
        try list.append(arena, trimmed);
    }
    return list.toOwnedSlice(arena);
}

pub fn objGet(v: Value, key: []const u8) ?Value {
    if (v != .object) return null;
    return v.object.get(key);
}

/// Optional string argument: absent/null -> null; a present value of the
/// wrong JSON type is a strict error (error.InvalidParams -> -32602), never
/// a silent default.
pub fn optStrArg(args: Value, key: []const u8) !?[]const u8 {
    const v = objGet(args, key) orelse return null;
    if (v == .null) return null;
    if (v != .string) return error.InvalidParams;
    return v.string;
}

/// Optional integer argument: absent/null -> null; wrong type, non-integral
/// float, or unrepresentable number -> strict error.
pub fn optIntArg(args: Value, key: []const u8) !?i64 {
    const v = objGet(args, key) orelse return null;
    if (v == .null) return null;
    return switch (v) {
        .integer => |i| i,
        .float => |f| blk: {
            const i = floatToI64(f) orelse return error.InvalidParams;
            // Reject fractional floats that a bare cast would truncate.
            if (@as(f64, @floatFromInt(i)) != f) return error.InvalidParams;
            break :blk i;
        },
        .number_string => |s| std.fmt.parseInt(i64, s, 10) catch return error.InvalidParams,
        else => return error.InvalidParams,
    };
}

/// Optional boolean argument: absent/null -> null; wrong type -> strict error.
pub fn optBoolArg(args: Value, key: []const u8) !?bool {
    const v = objGet(args, key) orelse return null;
    if (v == .null) return null;
    return switch (v) {
        .bool => |b| b,
        else => return error.InvalidParams,
    };
}

pub fn floatToI64(f: f64) ?i64 {
    if (!std.math.isFinite(f)) return null;
    if (f >= 9223372036854775808.0 or f < -9223372036854775808.0) return null;
    return @as(i64, @intFromFloat(f));
}

pub fn appendJsonValue(out: *std.ArrayList(u8), arena: Allocator, v: Value) !void {
    switch (v) {
        .null => try out.appendSlice(arena, "null"),
        .bool => |b| try out.appendSlice(arena, if (b) "true" else "false"),
        .integer => |i| try out.print(arena, "{d}", .{i}),
        .float => |f| try out.print(arena, "{d}", .{f}),
        .number_string => |s| try out.appendSlice(arena, s),
        .string => |s| try appendJsonString(out, arena, s),
        else => try out.appendSlice(arena, "null"),
    }
}

pub fn appendJsonString(out: *std.ArrayList(u8), arena: Allocator, s: []const u8) !void {
    try out.append(arena, '"');
    var i: usize = 0;
    while (i < s.len) {
        const c = s[i];
        switch (c) {
            '"' => try out.appendSlice(arena, "\\\""),
            '\\' => try out.appendSlice(arena, "\\\\"),
            '\n' => try out.appendSlice(arena, "\\n"),
            '\r' => try out.appendSlice(arena, "\\r"),
            '\t' => try out.appendSlice(arena, "\\t"),
            0x00...0x08, 0x0b, 0x0c, 0x0e...0x1f => try out.print(arena, "\\u{x:0>4}", .{c}),
            else => {
                if (c < 0x80) {
                    try out.append(arena, c);
                    i += 1;
                    continue;
                }
                const seq_len = utf8SeqLen(s[i..]) orelse {
                    try out.appendSlice(arena, "\xef\xbf\xbd"); // U+FFFD
                    i += 1;
                    continue;
                };
                if (i + seq_len > s.len or !validUtf8Seq(s[i .. i + seq_len])) {
                    try out.appendSlice(arena, "\xef\xbf\xbd"); // U+FFFD
                    i += 1;
                    continue;
                }
                try out.appendSlice(arena, s[i .. i + seq_len]);
                i += seq_len;
                continue;
            },
        }
        i += 1;
    }
    try out.append(arena, '"');
}

pub fn utf8SeqLen(s: []const u8) ?usize {
    if (s.len == 0) return null;
    const b0 = s[0];
    if (b0 < 0x80) return 1;
    if (b0 >= 0xc2 and b0 <= 0xdf) return 2;
    if (b0 >= 0xe0 and b0 <= 0xef) return 3;
    if (b0 >= 0xf0 and b0 <= 0xf4) return 4;
    return null;
}

pub fn validUtf8Seq(s: []const u8) bool {
    if (s.len == 0) return false;
    const b0 = s[0];
    if (b0 < 0x80) return true;
    for (s[1..]) |b| {
        if ((b & 0xc0) != 0x80) return false;
    }
    switch (s.len) {
        2 => return true,
        3 => {
            if (b0 == 0xe0 and s[1] < 0xa0) return false;
            if (b0 == 0xed and s[1] > 0x9f) return false;
            return true;
        },
        4 => {
            if (b0 == 0xf0 and s[1] < 0x90) return false;
            if (b0 == 0xf4 and s[1] > 0x8f) return false;
            return true;
        },
        else => return false,
    }
}

pub fn utf8LossyAlloc(arena: Allocator, data: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < data.len) {
        const c = data[i];
        if (c < 0x80) {
            try out.append(arena, c);
            i += 1;
            continue;
        }
        const seq_len = utf8SeqLen(data[i..]) orelse {
            try out.appendSlice(arena, "\xef\xbf\xbd"); // U+FFFD
            i += 1;
            continue;
        };
        if (i + seq_len > data.len or !validUtf8Seq(data[i .. i + seq_len])) {
            try out.appendSlice(arena, "\xef\xbf\xbd"); // U+FFFD
            i += 1;
            continue;
        }
        try out.appendSlice(arena, data[i .. i + seq_len]);
        i += seq_len;
    }
    return out.items;
}

pub const CharSlice = struct { text: []const u8, has_more: bool };

pub fn utf8CharSlice(s: []const u8, offset_chars: usize, limit_chars: usize) !CharSlice {
    var char_idx: usize = 0;
    var byte_idx: usize = 0;
    var start_byte: usize = 0;
    var end_byte: usize = s.len;
    var have_start = false;
    while (byte_idx < s.len) {
        if (char_idx == offset_chars and !have_start) {
            start_byte = byte_idx;
            have_start = true;
        }
        if (have_start and char_idx == offset_chars + limit_chars) {
            end_byte = byte_idx;
            return .{ .text = s[start_byte..end_byte], .has_more = true };
        }
        const len = utf8SeqLen(s[byte_idx..]) orelse 1;
        byte_idx += len;
        char_idx += 1;
    }
    if (!have_start) return .{ .text = "", .has_more = false };
    return .{ .text = s[start_byte..], .has_more = false };
}

pub fn appendHexLower(out: *std.ArrayList(u8), arena: Allocator, bytes: []const u8) !void {
    const alphabet = "0123456789abcdef";
    try out.append(arena, '"');
    for (bytes) |b| {
        try out.append(arena, alphabet[b >> 4]);
        try out.append(arena, alphabet[b & 0x0f]);
    }
    try out.append(arena, '"');
}

test "json string escaping keeps poison literal" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var out: std.ArrayList(u8) = .empty;
    try appendJsonString(&out, arena, "single ' double \" dollar $HOME backtick `tick` newline\n");
    const parsed = try std.json.parseFromSliceLeaky(Value, arena, out.items, .{});
    try std.testing.expect(parsed == .string);
    try std.testing.expectEqualStrings("single ' double \" dollar $HOME backtick `tick` newline\n", parsed.string);
}

test "utf8 lossy replaces invalid bytes with U+FFFD" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const s = try utf8LossyAlloc(arena, "a\xffb");
    try std.testing.expectEqualStrings("a\xef\xbf\xbdb", s);
}

test "float to int rejects non finite and out of range values" {
    try std.testing.expect(floatToI64(std.math.inf(f64)) == null);
    try std.testing.expect(floatToI64(std.math.nan(f64)) == null);
    try std.testing.expect(floatToI64(1e300) == null);
    try std.testing.expectEqual(@as(i64, 42), floatToI64(42.0).?);
}

test "json string encoder replaces invalid utf8 with replacement char" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // A lone invalid byte: one U+FFFD per offending byte.
    {
        var out: std.ArrayList(u8) = .empty;
        try appendJsonString(&out, arena, "a\xffb");
        try std.testing.expectEqualStrings("\"a\xef\xbf\xbdb\"", out.items);
    }

    // A truncated 3-byte sequence at end of input: each offending byte
    // (lead and continuation) yields its own U+FFFD.
    {
        var out: std.ArrayList(u8) = .empty;
        try appendJsonString(&out, arena, "ok\xe4\xb8");
        try std.testing.expectEqualStrings("\"ok\xef\xbf\xbd\xef\xbf\xbd\"", out.items);
    }

    // An invalid continuation after a lead byte: the lead becomes U+FFFD
    // and the following ASCII bytes survive.
    {
        var out: std.ArrayList(u8) = .empty;
        try appendJsonString(&out, arena, "\xe4x");
        try std.testing.expectEqualStrings("\"\xef\xbf\xbdx\"", out.items);
    }
    {
        var out: std.ArrayList(u8) = .empty;
        try appendJsonString(&out, arena, "\xe4xy");
        try std.testing.expectEqualStrings("\"\xef\xbf\xbdxy\"", out.items);
    }

    // Valid multi-byte input is preserved byte-for-byte.
    {
        var out: std.ArrayList(u8) = .empty;
        try appendJsonString(&out, arena, "h\xc3\xa9llo");
        try std.testing.expectEqualStrings("\"h\xc3\xa9llo\"", out.items);
    }

    // The encoded output round-trips through the JSON parser to the lossy
    // decoding of the same input.
    const inputs = [_][]const u8{
        "a\xffb", "ok\xe4\xb8", "\xe4x", "\xe4xy", "h\xc3\xa9llo", "mixed\xff\xc3\xa9\x80tail",
    };
    for (inputs) |input| {
        var out: std.ArrayList(u8) = .empty;
        try appendJsonString(&out, arena, input);
        const parsed = try std.json.parseFromSliceLeaky(Value, arena, out.items, .{});
        try std.testing.expect(parsed == .string);
        try std.testing.expectEqualStrings(try utf8LossyAlloc(arena, input), parsed.string);
    }
}
