//! stdio transport: newline-delimited JSON-RPC over the process's own
//! stdin/stdout, the transport MCP clients use when they launch the server
//! as a subprocess.
//!
//! Framing: one JSON-RPC message per line on stdin, one response per line
//! on stdout. There is no Content-Length header (that is LSP framing, not
//! MCP). stdout carries nothing but response lines; every log line goes to
//! stderr. Messages are handled in order, one at a time, through the same
//! rpc.handleRpc dispatcher the HTTP and node-link paths use, so tool
//! behavior is identical across transports.
//!
//! The transport trusts its peer: whoever holds the pipes started the
//! process, so there is no token, no Host/Origin check and no listener.
//!
//! End of input (the client closed stdin) ends the loop: live exec
//! sessions are killed and the process exits with status 0.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const os = @import("os.zig");
const config = @import("config.zig");
const rpc = @import("rpc.zig");

/// Upper bound for one message line, the same cap the HTTP path puts on a
/// request body. A longer line is dropped whole and answered with an error.
pub const MAX_LINE_BYTES: usize = 32 * 1024 * 1024;

const READ_CHUNK: usize = 64 * 1024;

const OVERSIZE_ERROR = "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32600,\"message\":\"Request too large\"}}";
const INTERNAL_ERROR = "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32603,\"message\":\"Internal error\"}}";

/// Where a response line goes. Production writes to the stdout handle;
/// tests collect into a buffer.
pub const Sink = struct {
    ctx: *anyopaque,
    writeFn: *const fn (ctx: *anyopaque, bytes: []const u8) anyerror!void,

    /// Write `body` as exactly one line. Some response bodies are shared
    /// with the HTTP path and pretty-printed (tools/list), so they carry raw
    /// line breaks. JSON forbids unescaped CR/LF inside strings, which makes
    /// every raw CR/LF insignificant whitespace: dropping them here keeps
    /// the framing intact without touching the HTTP bytes.
    fn writeLine(self: Sink, body: []const u8) !void {
        var rest = body;
        while (std.mem.indexOfAny(u8, rest, "\r\n")) |i| {
            if (i > 0) try self.writeFn(self.ctx, rest[0..i]);
            rest = rest[i + 1 ..];
        }
        if (rest.len > 0) try self.writeFn(self.ctx, rest);
        try self.writeFn(self.ctx, "\n");
    }
};

/// Splits a byte stream into lines, enforcing MAX_LINE_BYTES without ever
/// buffering more than that: an oversized line is skipped up to its
/// newline and reported once.
pub const LineSplitter = struct {
    buf: std.ArrayList(u8) = .empty,
    /// True while discarding the rest of an oversized line.
    skipping: bool = false,
    max: usize = MAX_LINE_BYTES,

    pub const Event = union(enum) { line: []const u8, oversize };

    pub fn deinit(self: *LineSplitter, gpa: Allocator) void {
        self.buf.deinit(gpa);
    }

    /// Feed `chunk` and call `handler.onEvent` for every complete line or
    /// oversize event, in input order.
    pub fn feed(self: *LineSplitter, gpa: Allocator, chunk: []const u8, handler: anytype) !void {
        var rest = chunk;
        while (rest.len > 0) {
            const nl = std.mem.indexOfScalar(u8, rest, '\n');
            const piece = if (nl) |i| rest[0..i] else rest;
            if (!self.skipping) {
                if (self.buf.items.len + piece.len > self.max) {
                    self.buf.clearRetainingCapacity();
                    self.skipping = true;
                    try handler.onEvent(.oversize);
                } else {
                    try self.buf.appendSlice(gpa, piece);
                }
            }
            if (nl) |i| {
                if (!self.skipping) try handler.onEvent(.{ .line = self.buf.items });
                self.buf.clearRetainingCapacity();
                self.skipping = false;
                rest = rest[i + 1 ..];
            } else break;
        }
    }

    /// End of input: a final line without a trailing newline still counts.
    pub fn finish(self: *LineSplitter, handler: anytype) !void {
        if (!self.skipping and self.buf.items.len > 0) try handler.onEvent(.{ .line = self.buf.items });
        self.buf.clearRetainingCapacity();
        self.skipping = false;
    }
};

/// Handles one framed message: dispatch and, when a response is due,
/// write it as one line. Blank lines are ignored; a trailing CR is
/// tolerated for clients that write CRLF.
pub const Dispatcher = struct {
    io: Io,
    cfg: *const config.Config,
    sink: Sink,

    pub fn onEvent(self: *Dispatcher, ev: LineSplitter.Event) !void {
        switch (ev) {
            .oversize => try self.sink.writeLine(OVERSIZE_ERROR),
            .line => |raw| {
                const line = std.mem.trimEnd(u8, raw, "\r");
                if (std.mem.trim(u8, line, " \t").len == 0) return;
                var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
                defer arena_state.deinit();
                const resp = rpc.handleRpcCtx(arena_state.allocator(), self.io, self.cfg, line, .{
                    .transport = .stdio,
                    .client = "stdio",
                }) catch |err| {
                    std.debug.print("stdio request failed: {s}\n", .{@errorName(err)});
                    try self.sink.writeLine(INTERNAL_ERROR);
                    return;
                };
                // Notifications (and only they) come back with an empty
                // body: nothing is written for them. Every other status,
                // errors included, carries a JSON-RPC response.
                if (resp.body.len == 0) return;
                try self.sink.writeLine(resp.body);
            },
        }
    }
};

fn writeStdout(ctx: *anyopaque, bytes: []const u8) anyerror!void {
    _ = ctx;
    try os.writeAllFd(os.stdoutFd(), bytes);
}

/// Serve stdin until end of input. Returns normally on EOF and when stdout
/// is gone (the client exited), so the caller exits with status 0.
pub fn run(io: Io, cfg: *const config.Config) void {
    os.writeAllFd(os.stderrFd(), "mcp-node serving MCP over stdio\n") catch {};
    var dummy: u8 = 0;
    var dispatcher = Dispatcher{ .io = io, .cfg = cfg, .sink = .{ .ctx = &dummy, .writeFn = writeStdout } };
    const gpa = std.heap.page_allocator;
    var splitter: LineSplitter = .{};
    defer splitter.deinit(gpa);
    var chunk: [READ_CHUNK]u8 = undefined;
    const in = os.stdinFd();
    while (true) {
        const n = os.readFd(in, &chunk) catch |err| {
            std.debug.print("stdin read failed: {s}\n", .{@errorName(err)});
            break;
        };
        if (n == 0) {
            splitter.finish(&dispatcher) catch {};
            break;
        }
        splitter.feed(gpa, chunk[0..n], &dispatcher) catch |err| {
            std.debug.print("stdout write failed: {s}\n", .{@errorName(err)});
            break;
        };
    }
    if (cfg.sessions) |store| store.killAll();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const util = @import("util.zig");

const Collector = struct {
    out: std.ArrayList(u8) = .empty,

    fn write(ctx: *anyopaque, bytes: []const u8) anyerror!void {
        const self: *Collector = @ptrCast(@alignCast(ctx));
        try self.out.appendSlice(testing.allocator, bytes);
    }

    fn sink(self: *Collector) Sink {
        return .{ .ctx = self, .writeFn = write };
    }
};

const EventLog = struct {
    lines: std.ArrayList([]const u8) = .empty,
    oversize: usize = 0,
    arena: Allocator,

    fn onEvent(self: *EventLog, ev: LineSplitter.Event) !void {
        switch (ev) {
            .line => |l| try self.lines.append(self.arena, try self.arena.dupe(u8, l)),
            .oversize => self.oversize += 1,
        }
    }
};

test "stdio line splitter: chunk boundaries, final unterminated line, oversize skip" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var log = EventLog{ .arena = arena_state.allocator() };
    var sp: LineSplitter = .{ .max = 8 };
    defer sp.deinit(testing.allocator);

    try sp.feed(testing.allocator, "ab", &log);
    try sp.feed(testing.allocator, "c\nde\n\nf", &log);
    // 12 bytes without a newline overflow the 8-byte cap: one event, and
    // the remainder of that line is discarded up to its newline.
    try sp.feed(testing.allocator, "ghijklmnopqr", &log);
    try sp.feed(testing.allocator, "stu\nok\n", &log);
    try sp.feed(testing.allocator, "tail", &log);
    try sp.finish(&log);

    try testing.expectEqual(@as(usize, 1), log.oversize);
    const want = [_][]const u8{ "abc", "de", "", "ok", "tail" };
    try testing.expectEqual(want.len, log.lines.items.len);
    for (want, log.lines.items) |w, got| try testing.expectEqualStrings(w, got);
}

fn testConfig(arena: Allocator) !config.Config {
    return .{
        .name = "stdio-test",
        .host = "127.0.0.1",
        .port = 1,
        .token = "",
        .allowed_hosts = try util.splitCsv(arena, "127.0.0.1:*"),
        .allowed_origins = try util.splitCsv(arena, "http://127.0.0.1:*"),
        .max_out = 4096,
        .socket_timeout_s = 5,
        .max_conn = 4,
        .max_sessions = 4,
        .session_ttl_s = 600,
        .max_inflight_bytes = 64 * 1024 * 1024,
        .mode = .stdio,
    };
}

test "stdio dispatcher: responses one per line, notifications silent, parse errors answered" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const cfg = try testConfig(arena);

    var col: Collector = .{};
    defer col.out.deinit(testing.allocator);
    var d = Dispatcher{ .io = threaded.io(), .cfg = &cfg, .sink = col.sink() };
    var sp: LineSplitter = .{};
    defer sp.deinit(testing.allocator);

    const input =
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\r\n" ++
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n" ++
        "   \n" ++
        "{not json\n" ++
        "{\"jsonrpc\":\"2.0\",\"id\":\"x\",\"method\":\"no/such\"}\n";
    try sp.feed(testing.allocator, input, &d);
    try sp.finish(&d);

    var it = std.mem.splitScalar(u8, col.out.items, '\n');
    try testing.expectEqualStrings("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}", it.next().?);
    try testing.expectEqualStrings("{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32700,\"message\":\"Parse error\"}}", it.next().?);
    try testing.expectEqualStrings("{\"jsonrpc\":\"2.0\",\"id\":\"x\",\"error\":{\"code\":-32601,\"message\":\"Method not found\"}}", it.next().?);
    try testing.expectEqualStrings("", it.next().?);
    try testing.expect(it.next() == null);
}

test "stdio dispatcher: pretty-printed bodies (tools/list) still go out as one line" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const cfg = try testConfig(arena_state.allocator());
    var col: Collector = .{};
    defer col.out.deinit(testing.allocator);
    var d = Dispatcher{ .io = threaded.io(), .cfg = &cfg, .sink = col.sink() };
    var sp: LineSplitter = .{};
    defer sp.deinit(testing.allocator);
    try sp.feed(testing.allocator, "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n", &d);

    const out = col.out.items;
    try testing.expect(out.len > 1 and out[out.len - 1] == '\n');
    const line = out[0 .. out.len - 1];
    try testing.expect(std.mem.indexOfAny(u8, line, "\r\n") == null);
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, line, .{});
    defer parsed.deinit();
    const tools = parsed.value.object.get("result").?.object.get("tools").?.array;
    try testing.expectEqual(@as(usize, 13), tools.items.len);
}

test "stdio dispatcher: oversize line gets one Invalid Request error" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const cfg = try testConfig(arena_state.allocator());
    var col: Collector = .{};
    defer col.out.deinit(testing.allocator);
    var d = Dispatcher{ .io = threaded.io(), .cfg = &cfg, .sink = col.sink() };
    var sp: LineSplitter = .{ .max = 16 };
    defer sp.deinit(testing.allocator);
    try sp.feed(testing.allocator, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n", &d);
    try testing.expectEqualStrings(OVERSIZE_ERROR ++ "\n", col.out.items);
}
