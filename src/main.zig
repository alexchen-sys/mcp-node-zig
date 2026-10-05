const std = @import("std");

const Io = std.Io;
const os = @import("os.zig");
const util = @import("util.zig");
const http = @import("http.zig");
const session_mod = @import("session.zig");
const config = @import("config.zig");
const env_state = @import("env_state.zig");
const node_link = @import("node_link.zig");
const hub_mod = @import("hub.zig");
const stdio = @import("stdio.zig");

/// A peer disconnect must never kill the daemon via SIGPIPE. Protection is
/// real on two layers: Io.Threaded installs an ignore handler for
/// SIGPIPE, and on std versions honoring root's keep_sigpipe this opts out
/// explicitly. Writes to closed pipes surface as EPIPE errors instead.
pub const keep_sigpipe = false;

const ACCEPT_BACKOFF_MS: u64 = 50; // pause after accept failure

const ConnGate = struct {
    mutex: std.Io.Mutex = .init,
    io: Io,
    active: u32 = 0,
    max: u32,

    fn tryAcquire(self: *ConnGate) bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.active >= self.max) return false;
        self.active += 1;
        return true;
    }

    fn release(self: *ConnGate) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.active -= 1;
    }
};

const Connection = struct {
    io: Io,
    cfg: *const config.Config,
    gate: *ConnGate,
    stream: Io.net.Stream,
};

pub fn main(init: std.process.Init.Minimal) !void {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Cross-platform environment snapshot (linux: /proc/self/environ).
    env_state.process_environ = try os.loadEnviron(std.heap.page_allocator);
    var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{ .environ = env_state.process_environ });
    defer threaded.deinit();
    const io = threaded.io();

    const cli = switch (try parseArgs(try init.args.toSlice(arena))) {
        .run => |c| c,
        .version => return printOut("mcp-node " ++ VERSION ++ "\n"),
        .help => return printOut(USAGE),
    };
    var cfg = try config.loadConfigCli(arena, io, cli);
    var sessions = session_mod.SessionStore.init(io, cfg.max_sessions);
    sessions.ttl_ms = @as(i64, cfg.session_ttl_s) * 1000;
    cfg.sessions = &sessions;
    var gate = ConnGate{ .io = io, .max = cfg.max_conn };
    var inflight = config.InflightGate{ .io = io, .max = cfg.max_inflight_bytes };
    cfg.inflight = &inflight;

    if (cfg.mode == .stdio) {
        // stdio mode: no listener and no token; stdout carries only
        // JSON-RPC response lines, every log line goes to stderr.
        stdio.run(io, &cfg);
        return;
    }

    if (cfg.mode == .node) {
        // Node mode opens no listener: every request arrives over the link.
        const ep = cfg.connect.?;
        logLine("mcp-node connecting", ep.host, ep.port);
        var node = node_link.Node{ .io = io, .cfg = &cfg };
        node_link.run(&node);
        return;
    }

    // Hub mode: node links on their own listener; clients keep this one.
    var hub = hub_mod.Hub.init(io, &cfg, cfg.hub_secrets orelse .{ .single = "" });
    var hub_server: Io.net.Server = undefined;
    if (cfg.mode == .hub) {
        try hub_mod.start(&hub, &hub_server);
        cfg.hub = &hub;
        const ep = cfg.hub_listen.?;
        logLine("mcp-node hub accepting node links", ep.host, ep.port);
    }

    const addr = try Io.net.IpAddress.parse(cfg.host, cfg.port);
    // Not std's reuse_address: it also sets SO_REUSEPORT, which lets a
    // second instance co-bind this port instead of failing (see os.net).
    var server = try os.net.listenTcp(io, addr);
    defer server.deinit(io);

    logLine("mcp-node listening", cfg.host, cfg.port);
    while (true) {
        var stream = server.accept(io) catch |err| {
            std.debug.print("accept failed: {s}\n", .{@errorName(err)});
            os.sleepMs(ACCEPT_BACKOFF_MS);
            continue;
        };
        if (!gate.tryAcquire()) {
            rejectBusy(&cfg, io, &stream);
            continue;
        }
        const conn = std.heap.page_allocator.create(Connection) catch {
            gate.release();
            stream.close(io);
            continue;
        };
        conn.* = .{ .io = io, .cfg = &cfg, .gate = &gate, .stream = stream };
        const thread = std.Thread.spawn(.{}, connectionThread, .{conn}) catch {
            gate.release();
            stream.close(io);
            std.heap.page_allocator.destroy(conn);
            continue;
        };
        thread.detach();
    }
}

fn connectionThread(conn: *Connection) void {
    defer std.heap.page_allocator.destroy(conn);
    defer conn.gate.release();
    defer conn.stream.close(conn.io);

    // Bytes a header-phase read over-fetched past the current request (the
    // coalesced head of a pipelined next request) seed the next iteration.
    var carry: std.ArrayList(u8) = .empty;
    defer carry.deinit(std.heap.page_allocator);

    while (true) {
        const keep = http.serveOneRequest(conn.io, conn.cfg, &conn.stream, &carry) catch |err| {
            std.debug.print("connection failed: {s}\n", .{@errorName(err)});
            break;
        };
        if (!keep) break;
    }
    lingerBeforeClose(conn.io, conn.stream.socket.handle);
}

/// Upper bounds for the post-response drain in `lingerBeforeClose`.
const LINGER_DRAIN_MS: u64 = 250;
const LINGER_DRAIN_BYTES: usize = 256 * 1024;

/// Closing a TCP socket that still has unread input makes the kernel answer
/// with RST instead of FIN, and an RST can destroy a response the peer has
/// not read yet. That is exactly the shape of every early rejection (401,
/// 404, 413, ...): it is answered from the head alone while the client may
/// still be streaming the body. Send FIN first, then discard whatever the
/// peer still sends until it closes, within a small byte and time budget,
/// so the response survives without ever buffering the rejected body.
fn lingerBeforeClose(io: Io, fd: std.posix.fd_t) void {
    os.net.shutdownSend(fd);
    const started = std.Io.Clock.awake.now(io);
    var sink: [util.IO_BUF_SIZE]u8 = undefined;
    var drained: usize = 0;
    while (drained < LINGER_DRAIN_BYTES) {
        const remaining = http.remainingMs(started, io, LINGER_DRAIN_MS) orelse return;
        const want = @min(sink.len, LINGER_DRAIN_BYTES - drained);
        const n = http.readWithDeadline(fd, sink[0..want], remaining) catch return;
        if (n == 0) return; // peer closed its side: a clean FIN exchange
        drained += n;
    }
}

fn rejectBusy(cfg: *const config.Config, io: Io, stream: *Io.net.Stream) void {
    var buf: [1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    const timeout_ms = @as(u64, cfg.socket_timeout_s) * 1000;
    http.sendHttpError(fba.allocator(), stream.socket.handle, 503, "busy", "too many connections", timeout_ms) catch {};
    stream.close(io);
}

fn logLine(msg: []const u8, host: []const u8, port: u16) void {
    var buf: [256]u8 = undefined;
    const line = std.fmt.bufPrint(&buf, "{s} on {s}:{d} path=/mcp\n", .{ msg, host, port }) catch return;
    os.writeAllFd(os.stderrFd(), line) catch {};
}

/// Command line: `--connect host:port` (or `--connect=host:port`) and
/// `--stdio`. Anything else is rejected (see parseArgs).
const VERSION: []const u8 = @import("build_options").version;

const USAGE =
    \\Usage: mcp-node [--connect host:port | --stdio]
    \\
    \\MCP server that gives an agent a shell on this machine.
    \\Configuration comes from MCP_NODE_* environment variables.
    \\
    \\  --connect host:port  dial out to a hub instead of listening
    \\                       (same as MCP_NODE_CONNECT)
    \\  --stdio              serve one client over stdin/stdout instead of
    \\                       HTTP; no listener, no token (same as
    \\                       MCP_NODE_STDIO=1)
    \\  -h, --help           show this help and exit
    \\  -V, --version        print the version and exit
    \\
    \\Docs: https://github.com/alexchen-sys/mcp-node-zig
    \\
;

const Args = union(enum) {
    run: config.Cli,
    version,
    help,
};

fn printOut(text: []const u8) void {
    os.writeAllFd(os.stdoutFd(), text) catch {};
}

/// Unknown arguments are an error: a typo such as `--conect` must not start
/// a listener the user did not ask for.
fn parseArgs(argv: []const [:0]const u8) !Args {
    var cli: config.Cli = .{};
    var i: usize = 1;
    while (i < argv.len) : (i += 1) {
        const a: []const u8 = argv[i];
        if (std.mem.eql(u8, a, "-h") or std.mem.eql(u8, a, "--help")) {
            return .help;
        } else if (std.mem.eql(u8, a, "-V") or std.mem.eql(u8, a, "--version")) {
            return .version;
        } else if (std.mem.eql(u8, a, "--stdio")) {
            cli.stdio = true;
        } else if (std.mem.eql(u8, a, "--connect")) {
            if (i + 1 >= argv.len) {
                std.debug.print("--connect needs host:port\n", .{});
                return error.InvalidConfig;
            }
            i += 1;
            cli.connect = argv[i];
        } else if (std.mem.startsWith(u8, a, "--connect=")) {
            cli.connect = a["--connect=".len..];
        } else {
            std.debug.print("unknown argument '{s}' (see --help)\n", .{a});
            return error.InvalidConfig;
        }
    }
    return .{ .run = cli };
}

test "command line: --connect, --stdio, --help, --version, unknown arguments" {
    const plain = (try parseArgs(&.{"mcp-node"})).run;
    try std.testing.expect(plain.connect == null and !plain.stdio);
    try std.testing.expectEqualStrings("h:1", (try parseArgs(&.{ "mcp-node", "--connect", "h:1" })).run.connect.?);
    try std.testing.expectEqualStrings("h:2", (try parseArgs(&.{ "mcp-node", "--connect=h:2" })).run.connect.?);
    const st = (try parseArgs(&.{ "mcp-node", "--stdio" })).run;
    try std.testing.expect(st.stdio and st.connect == null);
    try std.testing.expectError(error.InvalidConfig, parseArgs(&.{ "mcp-node", "--stdio=1" }));
    try std.testing.expectError(error.InvalidConfig, parseArgs(&.{ "mcp-node", "--connect" }));
    try std.testing.expectError(error.InvalidConfig, parseArgs(&.{ "mcp-node", "-x" }));
    try std.testing.expectError(error.InvalidConfig, parseArgs(&.{ "mcp-node", "--conect", "h:1" }));
    try std.testing.expect((try parseArgs(&.{ "mcp-node", "--version" })) == .version);
    try std.testing.expect((try parseArgs(&.{ "mcp-node", "-V" })) == .version);
    try std.testing.expect((try parseArgs(&.{ "mcp-node", "--help" })) == .help);
    try std.testing.expect((try parseArgs(&.{ "mcp-node", "-h", "--bogus" })) == .help);
}

test "discover module tests" {
    // Test builds analyze decls lazily per decl: a module not referenced by
    // any root test would have its test blocks silently skipped. Pull them in.
    std.testing.refAllDecls(@import("http.zig"));
    std.testing.refAllDecls(@import("rpc.zig"));
    std.testing.refAllDecls(@import("link.zig"));
    std.testing.refAllDecls(@import("node_link.zig"));
    std.testing.refAllDecls(@import("hub.zig"));
    std.testing.refAllDecls(@import("stdio.zig"));
}
