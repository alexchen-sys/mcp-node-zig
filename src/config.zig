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

const TOKEN_FILE_MAX_BYTES: usize = 4096;
const MIN_INFLIGHT_BYTES: u64 = 1024 * 1024; // config floor: below this the in-flight budget is unusable

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
    sessions: ?*session_mod.SessionStore = null,
    inflight: ?*InflightGate = null,
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

    const hosts_s = getEnv(arena, "MCP_NODE_ALLOWED_HOSTS") orelse "127.0.0.1:*,localhost:*,[::1]:*";
    const origins_s = getEnv(arena, "MCP_NODE_ALLOWED_ORIGINS") orelse "http://127.0.0.1:*,http://localhost:*,http://[::1]:*";
    return .{
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
    };
}

/// All environment reads go through the OS layer's cross-platform
/// snapshot lookup. Linux reads `/proc/self/environ`
/// source, same parse, same degrade-to-null-on-missing semantics.
fn getEnv(arena: Allocator, key: []const u8) ?[]const u8 {
    return os.environGet(arena, env_state.process_environ, key);
}
