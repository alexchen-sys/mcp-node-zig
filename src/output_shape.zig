const std = @import("std");
const util = @import("util.zig");

pub const MAX_BYTES = 1024 * 1024;
pub const DRAIN_LIMIT = 64 * 1024 * 1024;

pub const Shape = struct {
    cap: usize,
    head: ?u64 = null,
    tail: ?u64 = null,
};

fn nonnegative(args: std.json.Value, key: []const u8) !?u64 {
    const value = util.objGet(args, key) orelse return null;
    if (value == .null) return null;
    if (value != .integer or value.integer < 0) return error.InvalidParams;
    return @intCast(value.integer);
}

pub fn parse(args: std.json.Value, max_out: usize) !?Shape {
    const cap = try nonnegative(args, "max_bytes");
    const head = try nonnegative(args, "head_lines");
    const tail = try nonnegative(args, "tail_lines");
    if (head != null and tail != null) return error.ConflictingOutputSelection;
    if (cap == null and head == null and tail == null) return null;
    const limit = @min(max_out, MAX_BYTES);
    if (cap != null and cap.? > limit) return error.BadOutputLimit;
    return .{ .cap = @intCast(cap orelse limit), .head = head, .tail = tail };
}

pub fn parsePage(args: std.json.Value, max_out: usize) !?usize {
    if (util.objGet(args, "head_lines") != null or util.objGet(args, "tail_lines") != null)
        return error.InvalidParams;
    const cap = (try nonnegative(args, "max_bytes")) orelse return null;
    if (cap < 4 or cap > @min(max_out, MAX_BYTES)) return error.BadOutputLimit;
    return @intCast(cap);
}

/// Trim only a proven valid codepoint crossing an artificial boundary.
/// Invalid bytes and incomplete natural EOF remain for the lossy renderer.
pub fn trimEnd(bytes: []const u8, cut: usize) usize {
    var i = cut -| 3;
    while (i < cut) : (i += 1) {
        const n = std.unicode.utf8ByteSequenceLength(bytes[i]) catch continue;
        if (i + n <= cut or i + n > bytes.len) continue;
        _ = std.unicode.utf8Decode(bytes[i..][0..n]) catch continue;
        return i;
    }
    return cut;
}

pub fn trimStart(bytes: []const u8, cut: usize) usize {
    var i = cut -| 3;
    while (i < cut) : (i += 1) {
        const n = std.unicode.utf8ByteSequenceLength(bytes[i]) catch continue;
        if (i + n <= cut or i + n > bytes.len) continue;
        _ = std.unicode.utf8Decode(bytes[i..][0..n]) catch continue;
        return i + n;
    }
    return cut;
}

/// Fixed-capacity prefix or suffix window, with three bytes of lookaround.
/// Storage never grows with the observed output; finish rotates in place.
pub const Stream = struct {
    spec: Shape,
    storage: []u8,
    lookaround: [3]u8 = undefined,
    len: usize = 0,
    start: usize = 0,
    total: u64 = 0,
    lines: u64 = 0,

    pub fn init(a: std.mem.Allocator, spec: Shape) !Stream {
        return .{ .spec = spec, .storage = try a.alloc(u8, spec.cap) };
    }

    pub fn deinit(self: *Stream, a: std.mem.Allocator) void {
        a.free(self.storage);
    }

    pub fn feed(self: *Stream, bytes: []const u8) !void {
        self.total += bytes.len;
        for (bytes) |b| {
            const selected = if (self.spec.head) |n| self.lines < n else true;
            if (selected) {
                if (self.len < self.capacity()) {
                    self.set(self.len, b);
                    self.len += 1;
                } else if (self.spec.tail != null) {
                    self.set(self.start, b);
                    self.start = (self.start + 1) % self.capacity();
                }
            }
            if (b == '\n') self.lines += 1;
        }
        if (self.total >= DRAIN_LIMIT) return error.OutputDrainLimit;
    }

    fn capacity(self: *const Stream) usize {
        return self.storage.len + 3;
    }

    fn get(self: *const Stream, i: usize) u8 {
        return if (i < self.storage.len) self.storage[i] else self.lookaround[i - self.storage.len];
    }

    fn set(self: *Stream, i: usize, b: u8) void {
        if (i < self.storage.len) self.storage[i] = b else self.lookaround[i - self.storage.len] = b;
    }

    fn reverse(self: *Stream, first: usize, last: usize) void {
        var a = first;
        var b = last;
        while (a < b) {
            b -= 1;
            const tmp = self.get(a);
            self.set(a, self.get(b));
            self.set(b, tmp);
            a += 1;
        }
    }

    fn boundary(self: *const Stream, cut: usize, start: bool) usize {
        const first = cut -| 3;
        const last = @min(self.len, cut + 3);
        var scratch: [6]u8 = undefined;
        for (first..last) |i| scratch[i - first] = self.get(i);
        const bytes = scratch[0 .. last - first];
        return first + if (start) trimStart(bytes, cut - first) else trimEnd(bytes, cut - first);
    }

    pub fn finish(self: *Stream) []const u8 {
        if (self.start != 0) {
            self.reverse(0, self.start);
            self.reverse(self.start, self.len);
            self.reverse(0, self.len);
            self.start = 0;
        }
        if (self.spec.tail) |n| {
            if (n == 0 or self.len == 0) return self.storage[0..0];
            var begin: usize = 0;
            var lines: u64 = 0;
            var i = self.len - @as(usize, if (self.get(self.len - 1) == '\n') 1 else 0);
            while (i > 0) {
                i -= 1;
                if (self.get(i) == '\n') {
                    lines += 1;
                    if (lines == n) {
                        begin = i + 1;
                        break;
                    }
                }
            }
            begin = self.boundary(@max(begin, self.len -| self.spec.cap), true);
            const len = self.len - begin;
            for (0..len) |j| self.storage[j] = self.get(begin + j);
            return self.storage[0..len];
        }
        return self.storage[0..self.boundary(@min(self.len, self.spec.cap), false)];
    }
};

fn check(input: []const u8, spec: Shape, expected: []const u8) !void {
    var stream = try Stream.init(std.testing.allocator, spec);
    defer stream.deinit(std.testing.allocator);
    // One-byte feeds deliberately split every possible UTF-8 sequence.
    for (input) |b| try stream.feed(&.{b});
    try std.testing.expectEqualStrings(expected, stream.finish());
    try std.testing.expectEqual(input.len, stream.total);
}

test "output shaping XOR includes zero" {
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, "{\"head_lines\":0,\"tail_lines\":0}", .{});
    defer parsed.deinit();
    try std.testing.expectError(error.ConflictingOutputSelection, parse(parsed.value, 100));
}

test "output shaping empty stream and zero selection" {
    try check("", .{ .cap = 4 }, "");
    try check("abc\n", .{ .cap = 4, .head = 0 }, "");
    try check("abc\n", .{ .cap = 4, .tail = 0 }, "");
    try check("abc", .{ .cap = 0 }, "");
}

test "output shaping unterminated line and CRLF" {
    try check("a\r\nb\r\nc", .{ .cap = 20, .head = 1 }, "a\r\n");
    try check("a\r\nb\r\nc", .{ .cap = 20, .tail = 2 }, "b\r\nc");
    try check("a\nb\n", .{ .cap = 20, .tail = 1 }, "b\n");
}

test "output shaping oversized single line and tail ring" {
    try check("0123456789", .{ .cap = 4, .head = 1 }, "0123");
    try check("0123456789", .{ .cap = 4, .tail = 1 }, "6789");
    try check("a\nb\nc\n", .{ .cap = 3, .tail = 2 }, "\nc\n");
}

test "output shaping UTF-8 cuts and chunk boundary splits" {
    for ([_][]const u8{ "é", "中", "💩" }) |cp| {
        for (1..cp.len) |n| {
            try check(cp, .{ .cap = n }, "");
            try check(cp, .{ .cap = n, .tail = 1 }, "");
        }
        try check(cp, .{ .cap = cp.len }, cp);
    }
}

test "output shaping preserves malformed UTF-8 and natural EOF" {
    try check("a\xffb", .{ .cap = 2 }, "a\xff");
    try check("\xf0\x9f", .{ .cap = 4 }, "\xf0\x9f");
    try check("\xf0x\x9f", .{ .cap = 2, .tail = 1 }, "x\x9f");
    try check("\xed\xa0\x80", .{ .cap = 1 }, "\xed");
}

test "output shaping strict parameter types and effective cap" {
    const a = std.testing.allocator;
    for ([_][]const u8{ "-1", "1.5", "1.0", "true", "\"2\"", "[]", "{}", "9223372036854775808" }) |value| {
        const json = try std.fmt.allocPrint(a, "{{\"max_bytes\":{s}}}", .{value});
        defer a.free(json);
        const parsed = try std.json.parseFromSlice(std.json.Value, a, json, .{});
        defer parsed.deinit();
        try std.testing.expectError(error.InvalidParams, parse(parsed.value, 100));
    }
    const parsed = try std.json.parseFromSlice(std.json.Value, a, "{\"max_bytes\":101}", .{});
    defer parsed.deinit();
    try std.testing.expectError(error.BadOutputLimit, parse(parsed.value, 100));
    const large = try std.json.parseFromSlice(std.json.Value, a, "{\"max_bytes\":1048577}", .{});
    defer large.deinit();
    try std.testing.expectError(error.BadOutputLimit, parse(large.value, 2 * MAX_BYTES));
}

test "output shaping absent and null preserve legacy selection" {
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, "{\"max_bytes\":null,\"head_lines\":null}", .{});
    defer parsed.deinit();
    try std.testing.expectEqual(@as(?Shape, null), try parse(parsed.value, 100));
}

test "output shaping bounded heap retention and drain ceiling" {
    var stream = try Stream.init(std.testing.allocator, .{ .cap = 7, .tail = 1 });
    defer stream.deinit(std.testing.allocator);
    const chunk = [_]u8{'a'} ** 4096;
    for (0..100) |_| try stream.feed(&chunk);
    try std.testing.expectEqual(@as(usize, 7), stream.storage.len);
    try std.testing.expectEqualStrings("aaaaaaa", stream.finish());
    stream.total = DRAIN_LIMIT - 1;
    try std.testing.expectError(error.OutputDrainLimit, stream.feed("b"));
    try std.testing.expectEqual(@as(u64, DRAIN_LIMIT), stream.total);
}

test "output page validation excludes selectors and small limits" {
    for ([_][]const u8{ "{\"max_bytes\":0}", "{\"max_bytes\":3}", "{\"max_bytes\":101}" }) |json| {
        const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, json, .{});
        defer parsed.deinit();
        try std.testing.expectError(error.BadOutputLimit, parsePage(parsed.value, 100));
    }
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, "{\"head_lines\":0}", .{});
    defer parsed.deinit();
    try std.testing.expectError(error.InvalidParams, parsePage(parsed.value, 100));
}

test "output shaping independent streams and omitted algebra" {
    var stdout = try Stream.init(std.testing.allocator, .{ .cap = 4, .tail = 1 });
    defer stdout.deinit(std.testing.allocator);
    var stderr = try Stream.init(std.testing.allocator, .{ .cap = 4, .tail = 1 });
    defer stderr.deinit(std.testing.allocator);
    try stdout.feed("abc\ndefgh");
    try stderr.feed("é");
    const out = stdout.finish();
    const err = stderr.finish();
    try std.testing.expectEqualStrings("efgh", out);
    try std.testing.expectEqualStrings("é", err);
    try std.testing.expectEqual(@as(u64, 5), stdout.total - out.len);
    try std.testing.expectEqual(@as(u64, 0), stderr.total - err.len);
}

test "output shaping matches full stream selection across ring wraps" {
    const a = std.testing.allocator;
    var random = std.Random.DefaultPrng.init(0x42);
    const rng = random.random();
    var bytes: [257]u8 = undefined;
    for (0..300) |_| {
        rng.bytes(&bytes);
        // Add both line delimiters and valid multi-byte runs to binary data.
        for (0..20) |_| bytes[rng.uintLessThan(usize, bytes.len)] = '\n';
        @memcpy(bytes[100..104], "💩");
        const cap = rng.uintLessThan(usize, 64);
        const lines = rng.uintLessThan(u64, 8);
        for ([_]bool{ false, true }) |tail| {
            const spec: Shape = if (tail) .{ .cap = cap, .tail = lines } else .{ .cap = cap, .head = lines };
            var begin: usize = 0;
            var end = bytes.len;
            if (lines == 0) {
                end = 0;
            } else if (tail) {
                var n: u64 = 0;
                var i = bytes.len - @as(usize, if (bytes[bytes.len - 1] == '\n') 1 else 0);
                while (i > 0) {
                    i -= 1;
                    if (bytes[i] == '\n') {
                        n += 1;
                        if (n == lines) {
                            begin = i + 1;
                            break;
                        }
                    }
                }
            } else {
                var n: u64 = 0;
                for (bytes, 0..) |b, i| {
                    if (b == '\n') {
                        n += 1;
                        if (n == lines) {
                            end = i + 1;
                            break;
                        }
                    }
                }
            }
            if (tail) {
                begin = trimStart(bytes[0..end], @max(begin, end -| cap));
            } else {
                end = trimEnd(bytes[0..end], @min(end, cap));
            }
            var stream = try Stream.init(a, spec);
            defer stream.deinit(a);
            for (0..bytes.len) |i| try stream.feed(bytes[i..][0..1]);
            try std.testing.expectEqualSlices(u8, bytes[begin..end], stream.finish());
        }
    }
}
