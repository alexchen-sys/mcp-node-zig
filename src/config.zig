//! Runtime configuration: the `Config` snapshot assembled from the
//! environment, the global in-flight request-body budget gate, and the
//! loader. Environment reads go through the process-wide snapshot in
//! env_state.zig.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const os = @import("os.zig");
const util = @import("util.zig");
const session_mod = @import("session.zig");
const env_state = @import("env_state.zig");
const link = @import("link.zig");

const TOKEN_FILE_MAX_BYTES: usize = 4096;
const MIN_INFLIGHT_BYTES: u64 = 1024 * 1024; // config floor: below this the in-flight budget is unusable

/// `host:port` as given by the operator. `host` is an IP literal or a DNS
/// name (brackets stripped from `[v6]:port`).
pub const Endpoint = struct {
    host: []const u8,
    port: u16,
};

/// Process role. `listen` is the historical default and the only mode that
/// existed before node links; the other two are opt-in via env/CLI.
pub const Mode = enum { listen, node, hub };

pub const Config = struct {
    name: []const u8,
    host: []const u8,
    port: u16,
    token: []const u8,
    allowed_hosts: [][]const u8,
    allowed_origins: [][]const u8,
    max_out: usize,
    socket_timeout_s: u16,
    max_conn: u16,
    max_sessions: u16,
    session_ttl_s: u32,
    max_inflight_bytes: u64,
    /// Emit the JSON payload as `content[0].text` (text mirror) in addition
    /// to `structuredContent`. Default true = the MCP 2025-06-18
    /// backward-compat recommendation. `MCP_NODE_TEXT_MIRROR=0` opts
    /// structured-capable clients into a single-copy result.
    /// Errors (`isError: true`) always carry text regardless of this flag.
    text_mirror: bool = true,
    sessions: ?*session_mod.SessionStore = null,
    inflight: ?*InflightGate = null,
    mode: Mode = .listen,
    /// node mode: hub address to dial and the shared secret for HELLO.
    connect: ?Endpoint = null,
    connect_secret: []const u8 = "",
    /// hub mode: node-link listener and the secrets nodes authenticate with.
    hub_listen: ?Endpoint = null,
    hub_secrets: ?link.SecretSet = null,
    /// hub mode: the live node registry (set by main, read by http).
    hub: ?*anyopaque = null,
};

/// Global budget of in-flight request-body bytes (default 64 MiB via
/// MCP_NODE_MAX_INFLIGHT_BYTES). Bytes are reserved after the gates pass but
/// BEFORE the body allocation/read, and released on every exit path —
/// success, error, or disconnect. Only declared body bytes count (arena
/// growth and response buffers are not budgeted; the contract is in-flight
/// request bodies).
pub const InflightGate = struct {
    mutex: std.Io.Mutex = .init,
    io: Io,
    in_use: u64 = 0,
    max: u64,

    pub fn tryReserve(self: *InflightGate, bytes: usize) bool {
        if (bytes == 0) return true;
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (bytes > self.max - self.in_use) return false;
        self.in_use += bytes;
        return true;
    }

    pub fn release(self: *InflightGate, bytes: usize) void {
        if (bytes == 0) return;
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.in_use -= bytes;
    }
};

pub fn loadConfig(arena: Allocator, io: Io) !Config {
    return loadConfigMode(arena, io, null);
}

/// Full loader. `cli_connect` is the value of `--connect` (it wins over
/// MCP_NODE_CONNECT). With neither MCP_NODE_CONNECT, `--connect` nor
/// MCP_NODE_HUB_LISTEN set, the result is exactly what loadConfig always
/// returned: mode `.listen` and no link fields.
pub fn loadConfigMode(arena: Allocator, io: Io, cli_connect: ?[]const u8) !Config {
    const connect_s: ?[]const u8 = cli_connect orelse getEnv(arena, "MCP_NODE_CONNECT");
    const hub_s = getEnv(arena, "MCP_NODE_HUB_LISTEN");
    if (connect_s != null and hub_s != null) {
        std.debug.print("MCP_NODE_CONNECT/--connect and MCP_NODE_HUB_LISTEN are mutually exclusive\n", .{});
        return error.InvalidConfig;
    }
    const mode: Mode = if (connect_s != null) .node else if (hub_s != null) .hub else .listen;

    const name = getEnv(arena, "MCP_NODE_NAME") orelse "mcp-node";
    const host = getEnv(arena, "MCP_NODE_HOST") orelse "127.0.0.1";
    const port_s = getEnv(arena, "MCP_NODE_PORT") orelse "8341";
    const port = try std.fmt.parseInt(u16, port_s, 10);
    const max_out_s = getEnv(arena, "MCP_NODE_MAX_OUT") orelse "400000";
    const max_out = try std.fmt.parseInt(usize, max_out_s, 10);
    const socket_timeout_s = getEnv(arena, "MCP_NODE_SOCKET_TIMEOUT_S") orelse "60";
    var socket_timeout = try std.fmt.parseInt(u16, socket_timeout_s, 10);
    if (socket_timeout == 0) socket_timeout = 60;
    const max_conn_s = getEnv(arena, "MCP_NODE_MAX_CONN") orelse "128";
    var max_conn = try std.fmt.parseInt(u16, max_conn_s, 10);
    if (max_conn == 0) max_conn = 128;
    const max_sessions_s = getEnv(arena, "MCP_NODE_MAX_SESSIONS") orelse "64";
    var max_sessions = try std.fmt.parseInt(u16, max_sessions_s, 10);
    if (max_sessions == 0) max_sessions = 64;
    const session_ttl_s = getEnv(arena, "MCP_NODE_SESSION_TTL_S") orelse "600";
    var session_ttl = try std.fmt.parseInt(u32, session_ttl_s, 10);
    if (session_ttl == 0) session_ttl = 600;
    // Global in-flight request-body budget. An invalid or unusably small
    // value is a config error (fail fast at startup), not a silent fallback.
    const inflight_s = getEnv(arena, "MCP_NODE_MAX_INFLIGHT_BYTES") orelse "67108864";
    const max_inflight_bytes = std.fmt.parseInt(u64, inflight_s, 10) catch {
        std.debug.print("MCP_NODE_MAX_INFLIGHT_BYTES must be an unsigned integer, got '{s}'\n", .{inflight_s});
        return error.InvalidConfig;
    };
    if (max_inflight_bytes < MIN_INFLIGHT_BYTES) {
        std.debug.print("MCP_NODE_MAX_INFLIGHT_BYTES must be at least {d}\n", .{MIN_INFLIGHT_BYTES});
        return error.InvalidConfig;
    }

    // Node mode opens no client listener, so the client token is unused;
    // the link is authenticated by its own secret instead.
    const token = if (mode == .node) "" else try loadToken(arena, io);

    // Text-mirror gate for tool results. Only the exact value "0" turns
    // the mirror off; anything else (including unset) keeps the default
    // spec-recommended behavior, so a typo cannot silently strip the
    // text channel for legacy clients.
    const mirror_s = getEnv(arena, "MCP_NODE_TEXT_MIRROR") orelse "1";
    const text_mirror = !std.mem.eql(u8, mirror_s, "0");

    const hosts_s = getEnv(arena, "MCP_NODE_ALLOWED_HOSTS") orelse "127.0.0.1:*,localhost:*,[::1]:*";
    const origins_s = getEnv(arena, "MCP_NODE_ALLOWED_ORIGINS") orelse "http://127.0.0.1:*,http://localhost:*,http://[::1]:*";
    var cfg: Config = .{
        .name = name,
        .host = try arena.dupe(u8, host),
        .port = port,
        .token = try arena.dupe(u8, token),
        .allowed_hosts = try util.splitCsv(arena, hosts_s),
        .allowed_origins = try util.splitCsv(arena, origins_s),
        .max_out = max_out,
        .socket_timeout_s = socket_timeout,
        .max_conn = max_conn,
        .max_sessions = max_sessions,
        .session_ttl_s = session_ttl,
        .max_inflight_bytes = max_inflight_bytes,
        .text_mirror = text_mirror,
        .mode = mode,
    };
    switch (mode) {
        .listen => {},
        .node => {
            cfg.connect = parseEndpoint(arena, connect_s.?) catch {
                std.debug.print("MCP_NODE_CONNECT/--connect must be host:port, got '{s}'\n", .{connect_s.?});
                return error.InvalidConfig;
            };
            if (!link.validName(name)) {
                std.debug.print("MCP_NODE_NAME must match [A-Za-z0-9._-]{{1,64}} in connect mode, got '{s}'\n", .{name});
                return error.InvalidConfig;
            }
            const path = getEnv(arena, "MCP_NODE_CONNECT_SECRET_FILE") orelse {
                std.debug.print("MCP_NODE_CONNECT_SECRET_FILE is required in connect mode\n", .{});
                return error.InvalidConfig;
            };
            const raw = try readSecretFile(arena, io, "MCP_NODE_CONNECT_SECRET_FILE", path);
            cfg.connect_secret = link.parseNodeSecret(raw) catch {
                std.debug.print("MCP_NODE_CONNECT_SECRET_FILE is empty\n", .{});
                return error.InvalidConfig;
            };
        },
        .hub => {
            cfg.hub_listen = parseEndpoint(arena, hub_s.?) catch {
                std.debug.print("MCP_NODE_HUB_LISTEN must be ip:port, got '{s}'\n", .{hub_s.?});
                return error.InvalidConfig;
            };
            const path = getEnv(arena, "MCP_NODE_HUB_SECRET_FILE") orelse {
                std.debug.print("MCP_NODE_HUB_SECRET_FILE is required in hub mode\n", .{});
                return error.InvalidConfig;
            };
            const raw = try readSecretFile(arena, io, "MCP_NODE_HUB_SECRET_FILE", path);
            cfg.hub_secrets = link.parseSecretFile(arena, raw) catch |err| {
                std.debug.print("MCP_NODE_HUB_SECRET_FILE is invalid: {s}\n", .{@errorName(err)});
                return error.InvalidConfig;
            };
        },
    }
    return cfg;
}

fn readSecretFile(arena: Allocator, io: Io, key: []const u8, path: []const u8) ![]u8 {
    return os.fd.readFileAlloc(arena, io, path, link.SECRET_FILE_MAX_BYTES) catch |err| {
        std.debug.print("{s}: cannot read '{s}': {s}\n", .{ key, path, @errorName(err) });
        return error.InvalidConfig;
    };
}

/// `host:port`, `[v6]:port`. The port is mandatory and non-zero.
pub fn parseEndpoint(arena: Allocator, s: []const u8) !Endpoint {
    const colon = std.mem.lastIndexOfScalar(u8, s, ':') orelse return error.BadEndpoint;
    var host = s[0..colon];
    const port = std.fmt.parseInt(u16, s[colon + 1 ..], 10) catch return error.BadEndpoint;
    if (port == 0) return error.BadEndpoint;
    if (host.len >= 2 and host[0] == '[' and host[host.len - 1] == ']') {
        host = host[1 .. host.len - 1];
    } else if (std.mem.indexOfScalar(u8, host, ':') != null) {
        return error.BadEndpoint; // bare v6 needs brackets
    }
    if (host.len == 0) return error.BadEndpoint;
    return .{ .host = try arena.dupe(u8, host), .port = port };
}

fn loadToken(arena: Allocator, io: Io) ![]const u8 {
    const token_path = getEnv(arena, "MCP_NODE_TOKEN_FILE") orelse "./token";
    const token_raw = os.fd.readFileAlloc(arena, io, token_path, TOKEN_FILE_MAX_BYTES) catch |err| token_blk: {
        // Fail-closed on Windows by design: a missing token
        // file fails startup there instead of degrading to insecure mode;
        // the FileNotFound recovery branch is compiled out with the read.
        if (comptime os.gate_posix_file_io) {
            return err;
        } else {
            break :token_blk switch (err) {
                error.FileNotFound => insecure_blk: {
                    const insecure = getEnv(arena, "MCP_NODE_INSECURE") orelse "0";
                    if (!std.mem.eql(u8, insecure, "1")) return error.TokenFileMissing;
                    break :insecure_blk try arena.dupe(u8, "");
                },
                else => return err,
            };
        }
    };
    const token = std.mem.trim(u8, token_raw, " \t\r\n");
    if (token.len == 0) {
        const insecure = getEnv(arena, "MCP_NODE_INSECURE") orelse "0";
        if (!std.mem.eql(u8, insecure, "1")) return error.TokenFileMissing;
    }
    return token;
}

/// All environment reads go through the OS layer's snapshot lookup
/// (`/proc/self/environ` on Linux); a missing or unreadable variable
/// yields null.
fn getEnv(arena: Allocator, key: []const u8) ?[]const u8 {
    return os.environGet(arena, env_state.process_environ, key);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// Every test drives loadConfig through a synthetic process environment: the
// daemon reads env vars exclusively through env_state.process_environ, so
// installing a hand-built snapshot with the same shape os/env.zig
// loadEnviron produces on POSIX makes each call observe exactly the entries
// below and nothing inherited from the test runner. Tests share one
// process, so every test restores the global to the pristine empty
// snapshot on exit.

const builtin = @import("builtin");
const testing = std.testing;

/// One "KEY=VALUE" entry of a synthetic environment snapshot.
const EnvVar = struct { key: []const u8, value: []const u8 };

/// Build a synthetic snapshot the way os/env.zig loadEnviron does on POSIX:
/// NUL-terminated "KEY=VALUE" strings behind a sentinel slice of pointers.
/// Windows reads its environment from the PEB global block, where this
/// shape is meaningless, so those targets skip the env-driven tests.
fn makeEnviron(arena: Allocator, entries: []const EnvVar) !std.process.Environ {
    if (comptime builtin.os.tag == .windows) {
        return error.SkipZigTest;
    } else {
        const slice = try arena.allocSentinel(?[*:0]const u8, entries.len, null);
        for (entries, slice) |entry, *slot| {
            const line = try std.fmt.allocPrint(arena, "{s}={s}", .{ entry.key, entry.value });
            const line_z = try arena.dupeZ(u8, line);
            slot.* = line_z.ptr;
        }
        return .{ .block = .{ .slice = slice } };
    }
}

/// Relative path of `sub_path` inside a testing tmp dir. std.testing.tmpDir
/// nests its fresh directory under .zig-cache/tmp relative to the test
/// binary's cwd, and loadConfig resolves token paths against the same cwd,
/// so this relative shape reaches the file.
fn tmpRelPath(arena: Allocator, tmp: *const testing.TmpDir, sub_path: []const u8) ![]const u8 {
    return std.fmt.allocPrint(arena, ".zig-cache/tmp/{s}/{s}", .{ tmp.sub_path, sub_path });
}

test "config defaults when env carries only the token file" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = Io.Threaded.global_single_threaded.io();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "token", .data = "secret\n" });

    env_state.process_environ = try makeEnviron(arena, &.{
        .{ .key = "MCP_NODE_TOKEN_FILE", .value = try tmpRelPath(arena, &tmp, "token") },
    });
    defer env_state.process_environ = .empty;

    const cfg = try loadConfig(arena, io);

    try testing.expectEqualStrings("mcp-node", cfg.name);
    try testing.expectEqualStrings("127.0.0.1", cfg.host);
    try testing.expectEqual(@as(u16, 8341), cfg.port);
    try testing.expectEqualStrings("secret", cfg.token);
    try testing.expectEqual(@as(usize, 400000), cfg.max_out);
    try testing.expectEqual(@as(u16, 60), cfg.socket_timeout_s);
    try testing.expectEqual(@as(u16, 128), cfg.max_conn);
    try testing.expectEqual(@as(u16, 64), cfg.max_sessions);
    try testing.expectEqual(@as(u32, 600), cfg.session_ttl_s);
    try testing.expectEqual(@as(u64, 67108864), cfg.max_inflight_bytes);
    try testing.expect(cfg.text_mirror);
    try testing.expectEqual(@as(usize, 3), cfg.allowed_hosts.len);
    try testing.expectEqualStrings("127.0.0.1:*", cfg.allowed_hosts[0]);
    try testing.expectEqualStrings("localhost:*", cfg.allowed_hosts[1]);
    try testing.expectEqualStrings("[::1]:*", cfg.allowed_hosts[2]);
    try testing.expectEqual(@as(usize, 3), cfg.allowed_origins.len);
    try testing.expectEqualStrings("http://127.0.0.1:*", cfg.allowed_origins[0]);
    try testing.expectEqualStrings("http://localhost:*", cfg.allowed_origins[1]);
    try testing.expectEqualStrings("http://[::1]:*", cfg.allowed_origins[2]);
}

test "config env overrides land in the snapshot" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = Io.Threaded.global_single_threaded.io();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "token", .data = "override-secret\n" });

    env_state.process_environ = try makeEnviron(arena, &.{
        .{ .key = "MCP_NODE_NAME", .value = "zed-node" },
        .{ .key = "MCP_NODE_HOST", .value = "0.0.0.0" },
        .{ .key = "MCP_NODE_PORT", .value = "9399" },
        .{ .key = "MCP_NODE_MAX_OUT", .value = "123456" },
        .{ .key = "MCP_NODE_SOCKET_TIMEOUT_S", .value = "7" },
        .{ .key = "MCP_NODE_MAX_CONN", .value = "9" },
        .{ .key = "MCP_NODE_MAX_SESSIONS", .value = "17" },
        .{ .key = "MCP_NODE_SESSION_TTL_S", .value = "77" },
        .{ .key = "MCP_NODE_MAX_INFLIGHT_BYTES", .value = "1073741824" },
        .{ .key = "MCP_NODE_TOKEN_FILE", .value = try tmpRelPath(arena, &tmp, "token") },
    });
    defer env_state.process_environ = .empty;

    const cfg = try loadConfig(arena, io);

    try testing.expectEqualStrings("zed-node", cfg.name);
    try testing.expectEqualStrings("0.0.0.0", cfg.host);
    try testing.expectEqual(@as(u16, 9399), cfg.port);
    try testing.expectEqualStrings("override-secret", cfg.token);
    try testing.expectEqual(@as(usize, 123456), cfg.max_out);
    try testing.expectEqual(@as(u16, 7), cfg.socket_timeout_s);
    try testing.expectEqual(@as(u16, 9), cfg.max_conn);
    try testing.expectEqual(@as(u16, 17), cfg.max_sessions);
    try testing.expectEqual(@as(u32, 77), cfg.session_ttl_s);
    try testing.expectEqual(@as(u64, 1073741824), cfg.max_inflight_bytes);
}

test "config zero values are clamped to the documented defaults" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = Io.Threaded.global_single_threaded.io();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "token", .data = "clamp-secret\n" });

    env_state.process_environ = try makeEnviron(arena, &.{
        .{ .key = "MCP_NODE_SOCKET_TIMEOUT_S", .value = "0" },
        .{ .key = "MCP_NODE_MAX_CONN", .value = "0" },
        .{ .key = "MCP_NODE_MAX_SESSIONS", .value = "0" },
        .{ .key = "MCP_NODE_SESSION_TTL_S", .value = "0" },
        .{ .key = "MCP_NODE_TOKEN_FILE", .value = try tmpRelPath(arena, &tmp, "token") },
    });
    defer env_state.process_environ = .empty;

    const cfg = try loadConfig(arena, io);

    try testing.expectEqual(@as(u16, 60), cfg.socket_timeout_s);
    try testing.expectEqual(@as(u16, 128), cfg.max_conn);
    try testing.expectEqual(@as(u16, 64), cfg.max_sessions);
    try testing.expectEqual(@as(u32, 600), cfg.session_ttl_s);
}

test "config max inflight bytes fails fast on invalid and below-floor values" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = Io.Threaded.global_single_threaded.io();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "token", .data = "budget-secret\n" });
    const token: EnvVar = .{ .key = "MCP_NODE_TOKEN_FILE", .value = try tmpRelPath(arena, &tmp, "token") };
    defer env_state.process_environ = .empty;

    // Garbage is a startup error, not a silent fallback to the default.
    env_state.process_environ = try makeEnviron(arena, &.{
        token,
        .{ .key = "MCP_NODE_MAX_INFLIGHT_BYTES", .value = "abc" },
    });
    try testing.expectError(error.InvalidConfig, loadConfig(arena, io));

    // A valid number below the 1 MiB floor is still unusable: reject.
    env_state.process_environ = try makeEnviron(arena, &.{
        token,
        .{ .key = "MCP_NODE_MAX_INFLIGHT_BYTES", .value = "100" },
    });
    try testing.expectError(error.InvalidConfig, loadConfig(arena, io));

    // One byte below the floor stays rejected...
    env_state.process_environ = try makeEnviron(arena, &.{
        token,
        .{ .key = "MCP_NODE_MAX_INFLIGHT_BYTES", .value = "1048575" },
    });
    try testing.expectError(error.InvalidConfig, loadConfig(arena, io));

    // ...while exactly the floor is the smallest accepted value.
    env_state.process_environ = try makeEnviron(arena, &.{
        token,
        .{ .key = "MCP_NODE_MAX_INFLIGHT_BYTES", .value = "1048576" },
    });
    const cfg = try loadConfig(arena, io);
    try testing.expectEqual(@as(u64, 1048576), cfg.max_inflight_bytes);
}

test "config token file matrix: missing, blank and the insecure escape hatch" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = Io.Threaded.global_single_threaded.io();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const missing = try tmpRelPath(arena, &tmp, "token");
    defer env_state.process_environ = .empty;

    // Missing token file, no escape hatch: fail closed at startup.
    env_state.process_environ = try makeEnviron(arena, &.{
        .{ .key = "MCP_NODE_TOKEN_FILE", .value = missing },
    });
    try testing.expectError(error.TokenFileMissing, loadConfig(arena, io));

    // Only the exact value "1" is the escape hatch; a typo keeps the
    // fail-closed behavior.
    env_state.process_environ = try makeEnviron(arena, &.{
        .{ .key = "MCP_NODE_TOKEN_FILE", .value = missing },
        .{ .key = "MCP_NODE_INSECURE", .value = "yes" },
    });
    try testing.expectError(error.TokenFileMissing, loadConfig(arena, io));

    // Missing file with the escape hatch: startup proceeds with an empty
    // token (explicitly insecure mode).
    env_state.process_environ = try makeEnviron(arena, &.{
        .{ .key = "MCP_NODE_TOKEN_FILE", .value = missing },
        .{ .key = "MCP_NODE_INSECURE", .value = "1" },
    });
    const insecure_cfg = try loadConfig(arena, io);
    try testing.expectEqualStrings("", insecure_cfg.token);

    // Present but empty: the same fail-closed rule applies after trimming.
    try tmp.dir.writeFile(io, .{ .sub_path = "empty", .data = "" });
    env_state.process_environ = try makeEnviron(arena, &.{
        .{ .key = "MCP_NODE_TOKEN_FILE", .value = try tmpRelPath(arena, &tmp, "empty") },
    });
    try testing.expectError(error.TokenFileMissing, loadConfig(arena, io));

    // Whitespace-only content trims to empty; only the escape hatch
    // admits it.
    try tmp.dir.writeFile(io, .{ .sub_path = "blank", .data = " \t\r\n" });
    env_state.process_environ = try makeEnviron(arena, &.{
        .{ .key = "MCP_NODE_TOKEN_FILE", .value = try tmpRelPath(arena, &tmp, "blank") },
        .{ .key = "MCP_NODE_INSECURE", .value = "1" },
    });
    const blank_cfg = try loadConfig(arena, io);
    try testing.expectEqualStrings("", blank_cfg.token);

    // Real content: surrounding whitespace is trimmed away.
    try tmp.dir.writeFile(io, .{ .sub_path = "padded", .data = "  padded-secret \r\n" });
    env_state.process_environ = try makeEnviron(arena, &.{
        .{ .key = "MCP_NODE_TOKEN_FILE", .value = try tmpRelPath(arena, &tmp, "padded") },
    });
    const padded_cfg = try loadConfig(arena, io);
    try testing.expectEqualStrings("padded-secret", padded_cfg.token);
}

test "config token read errors other than FileNotFound stay fatal" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = Io.Threaded.global_single_threaded.io();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    defer env_state.process_environ = .empty;

    // A regular file used as a directory component: the open fails with
    // NotDir, which the INSECURE escape hatch does not cover (only
    // FileNotFound does).
    try tmp.dir.writeFile(io, .{ .sub_path = "regular", .data = "x" });
    env_state.process_environ = try makeEnviron(arena, &.{
        .{ .key = "MCP_NODE_TOKEN_FILE", .value = try tmpRelPath(arena, &tmp, "regular/token") },
        .{ .key = "MCP_NODE_INSECURE", .value = "1" },
    });
    try testing.expectError(error.NotDir, loadConfig(arena, io));

    // A token file past the 4 KiB read cap is equally fatal: no escape
    // hatch for oversized files.
    const oversized: [5000]u8 = @splat('x');
    try tmp.dir.writeFile(io, .{ .sub_path = "oversized", .data = &oversized });
    env_state.process_environ = try makeEnviron(arena, &.{
        .{ .key = "MCP_NODE_TOKEN_FILE", .value = try tmpRelPath(arena, &tmp, "oversized") },
        .{ .key = "MCP_NODE_INSECURE", .value = "1" },
    });
    try testing.expectError(error.StreamTooLong, loadConfig(arena, io));
}

test "config text mirror flag is typo-safe" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = Io.Threaded.global_single_threaded.io();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "token", .data = "mirror-secret\n" });
    const token: EnvVar = .{ .key = "MCP_NODE_TOKEN_FILE", .value = try tmpRelPath(arena, &tmp, "token") };
    defer env_state.process_environ = .empty;

    // Only the exact "0" opts out of the text mirror.
    env_state.process_environ = try makeEnviron(arena, &.{
        token,
        .{ .key = "MCP_NODE_TEXT_MIRROR", .value = "0" },
    });
    const off_cfg = try loadConfig(arena, io);
    try testing.expect(!off_cfg.text_mirror);

    // "1" keeps it on...
    env_state.process_environ = try makeEnviron(arena, &.{
        token,
        .{ .key = "MCP_NODE_TEXT_MIRROR", .value = "1" },
    });
    const on_cfg = try loadConfig(arena, io);
    try testing.expect(on_cfg.text_mirror);

    // ...and so does any other value: a typo must not silently strip the
    // legacy text channel.
    env_state.process_environ = try makeEnviron(arena, &.{
        token,
        .{ .key = "MCP_NODE_TEXT_MIRROR", .value = "garbage" },
    });
    const typo_cfg = try loadConfig(arena, io);
    try testing.expect(typo_cfg.text_mirror);

    // Unset keeps the spec-recommended default.
    env_state.process_environ = try makeEnviron(arena, &.{
        token,
    });
    const unset_cfg = try loadConfig(arena, io);
    try testing.expect(unset_cfg.text_mirror);
}

test "config allowed hosts and origins override split and trim csv" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = Io.Threaded.global_single_threaded.io();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "token", .data = "csv-secret\n" });

    env_state.process_environ = try makeEnviron(arena, &.{
        .{ .key = "MCP_NODE_ALLOWED_HOSTS", .value = "a.example:*, b.example:8443" },
        .{ .key = "MCP_NODE_ALLOWED_ORIGINS", .value = " https://a.example , ,https://b.example:8443 " },
        .{ .key = "MCP_NODE_TOKEN_FILE", .value = try tmpRelPath(arena, &tmp, "token") },
    });
    defer env_state.process_environ = .empty;

    const cfg = try loadConfig(arena, io);

    // Hosts: comma split, whitespace trimmed, empty parts dropped.
    try testing.expectEqual(@as(usize, 2), cfg.allowed_hosts.len);
    try testing.expectEqualStrings("a.example:*", cfg.allowed_hosts[0]);
    try testing.expectEqualStrings("b.example:8443", cfg.allowed_hosts[1]);

    // Origins: same semantics, including the dropped empty middle part.
    try testing.expectEqual(@as(usize, 2), cfg.allowed_origins.len);
    try testing.expectEqualStrings("https://a.example", cfg.allowed_origins[0]);
    try testing.expectEqualStrings("https://b.example:8443", cfg.allowed_origins[1]);

    // Everything untouched by the override keeps its default.
    try testing.expectEqual(@as(u16, 8341), cfg.port);
}

test "inflight gate tracks the global body budget" {
    const io = Io.Threaded.global_single_threaded.io();
    var gate = InflightGate{ .io = io, .max = 100 };

    // Zero-byte reservations are always free and never touch the counter.
    try testing.expect(gate.tryReserve(0));
    try testing.expectEqual(@as(u64, 0), gate.in_use);

    // The budget is inclusive: the exact remaining amount fits, one byte
    // more does not.
    try testing.expect(gate.tryReserve(60));
    try testing.expect(!gate.tryReserve(41));
    try testing.expect(gate.tryReserve(40));
    try testing.expect(!gate.tryReserve(1));
    try testing.expectEqual(@as(u64, 100), gate.in_use);

    // Release returns bytes to the budget.
    gate.release(100);
    gate.release(0);
    try testing.expectEqual(@as(u64, 0), gate.in_use);
    try testing.expect(gate.tryReserve(100));
}

test "config numeric env parsing rejects garbage with raw parse errors" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = Io.Threaded.global_single_threaded.io();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "token", .data = "port-secret\n" });
    const token: EnvVar = .{ .key = "MCP_NODE_TOKEN_FILE", .value = try tmpRelPath(arena, &tmp, "token") };
    defer env_state.process_environ = .empty;

    // Unlike the in-flight budget (wrapped as InvalidConfig with a
    // message), plain numeric fields surface the raw parseInt error.
    env_state.process_environ = try makeEnviron(arena, &.{
        token,
        .{ .key = "MCP_NODE_PORT", .value = "not-a-port" },
    });
    try testing.expectError(error.InvalidCharacter, loadConfig(arena, io));

    // Out-of-range values fail with Overflow instead.
    env_state.process_environ = try makeEnviron(arena, &.{
        token,
        .{ .key = "MCP_NODE_PORT", .value = "70000" },
    });
    try testing.expectError(error.Overflow, loadConfig(arena, io));
}

test "config endpoint parsing" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const a = try parseEndpoint(arena, "hub.example:8443");
    try testing.expectEqualStrings("hub.example", a.host);
    try testing.expectEqual(@as(u16, 8443), a.port);
    const b = try parseEndpoint(arena, "[::1]:9000");
    try testing.expectEqualStrings("::1", b.host);
    try testing.expectError(error.BadEndpoint, parseEndpoint(arena, "::1:9000"));
    try testing.expectError(error.BadEndpoint, parseEndpoint(arena, "hub"));
    try testing.expectError(error.BadEndpoint, parseEndpoint(arena, ":80"));
    try testing.expectError(error.BadEndpoint, parseEndpoint(arena, "hub:0"));
    try testing.expectError(error.BadEndpoint, parseEndpoint(arena, "hub:x"));
}

test "config link modes: connect, hub, exclusivity and fatal secrets" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = Io.Threaded.global_single_threaded.io();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "token", .data = "tok\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "nsec", .data = "node-secret\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "hsec", .data = "pc:one\nlaptop:two\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "blank", .data = "\n" });
    const token: EnvVar = .{ .key = "MCP_NODE_TOKEN_FILE", .value = try tmpRelPath(arena, &tmp, "token") };
    const nsec: EnvVar = .{ .key = "MCP_NODE_CONNECT_SECRET_FILE", .value = try tmpRelPath(arena, &tmp, "nsec") };
    const hsec: EnvVar = .{ .key = "MCP_NODE_HUB_SECRET_FILE", .value = try tmpRelPath(arena, &tmp, "hsec") };
    defer env_state.process_environ = .empty;

    // Default: plain listener, no link fields.
    env_state.process_environ = try makeEnviron(arena, &.{token});
    const plain = try loadConfig(arena, io);
    try testing.expectEqual(Mode.listen, plain.mode);
    try testing.expect(plain.connect == null and plain.hub_listen == null and plain.hub_secrets == null);

    // Node mode from env; the client token file is not needed.
    env_state.process_environ = try makeEnviron(arena, &.{
        nsec,
        .{ .key = "MCP_NODE_NAME", .value = "pc" },
        .{ .key = "MCP_NODE_CONNECT", .value = "hub.example:8443" },
    });
    const node = try loadConfig(arena, io);
    try testing.expectEqual(Mode.node, node.mode);
    try testing.expectEqualStrings("hub.example", node.connect.?.host);
    try testing.expectEqualStrings("node-secret", node.connect_secret);

    // --connect wins over the env value.
    const cli = try loadConfigMode(arena, io, "10.0.0.1:7000");
    try testing.expectEqualStrings("10.0.0.1", cli.connect.?.host);
    try testing.expectEqual(@as(u16, 7000), cli.connect.?.port);

    // Missing or empty node secret is fatal; so is an invalid link name.
    env_state.process_environ = try makeEnviron(arena, &.{
        .{ .key = "MCP_NODE_CONNECT", .value = "hub:1" },
    });
    try testing.expectError(error.InvalidConfig, loadConfig(arena, io));
    env_state.process_environ = try makeEnviron(arena, &.{
        .{ .key = "MCP_NODE_CONNECT", .value = "hub:1" },
        .{ .key = "MCP_NODE_CONNECT_SECRET_FILE", .value = try tmpRelPath(arena, &tmp, "missing") },
    });
    try testing.expectError(error.InvalidConfig, loadConfig(arena, io));
    env_state.process_environ = try makeEnviron(arena, &.{
        .{ .key = "MCP_NODE_CONNECT", .value = "hub:1" },
        .{ .key = "MCP_NODE_CONNECT_SECRET_FILE", .value = try tmpRelPath(arena, &tmp, "blank") },
    });
    try testing.expectError(error.InvalidConfig, loadConfig(arena, io));
    env_state.process_environ = try makeEnviron(arena, &.{
        nsec,
        .{ .key = "MCP_NODE_NAME", .value = "bad name" },
        .{ .key = "MCP_NODE_CONNECT", .value = "hub:1" },
    });
    try testing.expectError(error.InvalidConfig, loadConfig(arena, io));

    // Hub mode: keeps the client token, parses pinned secrets.
    env_state.process_environ = try makeEnviron(arena, &.{
        token,
        hsec,
        .{ .key = "MCP_NODE_HUB_LISTEN", .value = "0.0.0.0:8443" },
    });
    const hub = try loadConfig(arena, io);
    try testing.expectEqual(Mode.hub, hub.mode);
    try testing.expectEqualStrings("tok", hub.token);
    try testing.expectEqualStrings("two", hub.hub_secrets.?.lookup("laptop").?);

    // Hub without a secret file is fatal.
    env_state.process_environ = try makeEnviron(arena, &.{
        token,
        .{ .key = "MCP_NODE_HUB_LISTEN", .value = "0.0.0.0:8443" },
    });
    try testing.expectError(error.InvalidConfig, loadConfig(arena, io));

    // Both roles at once: refused, whichever source carries connect.
    env_state.process_environ = try makeEnviron(arena, &.{
        token,
        nsec,
        hsec,
        .{ .key = "MCP_NODE_HUB_LISTEN", .value = "0.0.0.0:8443" },
        .{ .key = "MCP_NODE_CONNECT", .value = "hub:1" },
    });
    try testing.expectError(error.InvalidConfig, loadConfig(arena, io));
    env_state.process_environ = try makeEnviron(arena, &.{
        token,
        hsec,
        .{ .key = "MCP_NODE_HUB_LISTEN", .value = "0.0.0.0:8443" },
    });
    try testing.expectError(error.InvalidConfig, loadConfigMode(arena, io, "hub:1"));
}
