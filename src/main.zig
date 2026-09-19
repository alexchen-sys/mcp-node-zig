const std = @import("std");

const Allocator = std.mem.Allocator;
const Io = std.Io;
const Value = std.json.Value;

const VERSION = "0.1.0";
const DEFAULT_MAX_OUT: usize = 400_000;
const MAX_REQUEST_BYTES: usize = 32 * 1024 * 1024;

const Config = struct {
    name: []const u8,
    host: []const u8,
    port: u16,
    token: []const u8,
    allowed_hosts: [][]const u8,
    allowed_origins: [][]const u8,
    max_out: usize,
};

const Request = struct {
    method: []const u8,
    path: []const u8,
    host: ?[]const u8,
    content_type: ?[]const u8,
    content_length: usize,
    token: ?[]const u8,
    body: []const u8,
};

pub fn main() !void {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const environ = try loadPosixEnviron(std.heap.page_allocator);
    var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{ .environ = environ });
    defer threaded.deinit();
    const io = threaded.io();

    const cfg = try loadConfig(arena, io);

    const addr = try Io.net.IpAddress.parse(cfg.host, cfg.port);
    var server = try addr.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);

    logLine("mcp-node listening", cfg.host, cfg.port);
    while (true) {
        var stream = server.accept(io) catch |err| {
            std.debug.print("accept failed: {s}\n", .{@errorName(err)});
            continue;
        };
        handleConnection(arena, io, &cfg, &stream) catch |err| {
            std.debug.print("connection failed: {s}\n", .{@errorName(err)});
        };
        stream.close(io);
    }
}

fn logLine(msg: []const u8, host: []const u8, port: u16) void {
    var buf: [256]u8 = undefined;
    const line = std.fmt.bufPrint(&buf, "{s} on {s}:{d} path=/mcp\n", .{ msg, host, port }) catch return;
    writeAllFd(2, line) catch {};
}

fn loadConfig(arena: Allocator, io: Io) !Config {
    const name = getEnv(arena, io, "MCP_NODE_NAME") orelse "mcp-node";
    const host = getEnv(arena, io, "MCP_NODE_HOST") orelse "127.0.0.1";
    const port_s = getEnv(arena, io, "MCP_NODE_PORT") orelse "8341";
    const port = try std.fmt.parseInt(u16, port_s, 10);
    const max_out_s = getEnv(arena, io, "MCP_NODE_MAX_OUT") orelse "400000";
    const max_out = try std.fmt.parseInt(usize, max_out_s, 10);

    const token_path = getEnv(arena, io, "MCP_NODE_TOKEN_FILE") orelse "./token";
    const token_raw = readFileAllocMaybe(arena, io, token_path, 4096) catch |err| switch (err) {
        error.FileNotFound => blk: {
            const insecure = getEnv(arena, io, "MCP_NODE_INSECURE") orelse "0";
            if (!std.mem.eql(u8, insecure, "1")) return error.TokenFileMissing;
            break :blk try arena.dupe(u8, "");
        },
        else => return err,
    };
    const token = std.mem.trim(u8, token_raw, " \t\r\n");

    const hosts_s = getEnv(arena, io, "MCP_NODE_ALLOWED_HOSTS") orelse "127.0.0.1:*,localhost:*,[::1]:*";
    const origins_s = getEnv(arena, io, "MCP_NODE_ALLOWED_ORIGINS") orelse "http://127.0.0.1:*,http://localhost:*,http://[::1]:*";
    return .{
        .name = tokenName(arena, name),
        .host = try arena.dupe(u8, host),
        .port = port,
        .token = try arena.dupe(u8, token),
        .allowed_hosts = try splitCsv(arena, hosts_s),
        .allowed_origins = try splitCsv(arena, origins_s),
        .max_out = max_out,
    };
}

fn tokenName(arena: Allocator, name: []const u8) []const u8 {
    _ = arena;
    return name;
}

fn getEnv(arena: Allocator, io: Io, key: []const u8) ?[]const u8 {
    const data = readFileAllocMaybe(arena, io, "/proc/self/environ", 1 << 20) catch return null;
    var it = std.mem.splitScalar(u8, data, 0);
    while (it.next()) |entry| {
        if (entry.len <= key.len) continue;
        if (!std.mem.eql(u8, entry[0..key.len], key)) continue;
        if (entry[key.len] != '=') continue;
        return entry[key.len + 1 ..];
    }
    return null;
}

fn loadPosixEnviron(gpa: Allocator) !std.process.Environ {
    if (@import("builtin").os.tag != .linux) return .empty;
    const data = readFileAllocMaybe(gpa, Io.Threaded.global_single_threaded.io(), "/proc/self/environ", 1 << 20) catch return .empty;
    if (data.len == 0) return .empty;
    var count: usize = 0;
    var start: usize = 0;
    for (data, 0..) |b, i| {
        if (b != 0) continue;
        if (i > start) count += 1;
        start = i + 1;
    }
    if (count == 0) return .empty;
    const slice = try gpa.allocSentinel(?[*:0]const u8, count, null);
    var idx: usize = 0;
    start = 0;
    for (data, 0..) |b, i| {
        if (b != 0) continue;
        if (i > start) {
            slice[idx] = @ptrCast(data.ptr + start);
            idx += 1;
        }
        start = i + 1;
    }
    return .{ .block = .{ .slice = slice } };
}

fn splitCsv(arena: Allocator, s: []const u8) ![][]const u8 {
    var list: std.ArrayList([]const u8) = .empty;
    var it = std.mem.splitScalar(u8, s, ',');
    while (it.next()) |part| {
        const trimmed = std.mem.trim(u8, part, " \t\r\n");
        if (trimmed.len == 0) continue;
        try list.append(arena, trimmed);
    }
    return list.toOwnedSlice(arena);
}

fn handleConnection(arena: Allocator, io: Io, cfg: *const Config, stream: *Io.net.Stream) !void {
    var req_arena_state = std.heap.ArenaAllocator.init(arena);
    defer req_arena_state.deinit();
    const ra = req_arena_state.allocator();

    const fd = stream.socket.handle;
    const req = readHttpRequest(ra, fd) catch |err| {
        try sendHttpError(ra, fd, 400, "bad_request", @errorName(err));
        return;
    };

    if (!hostAllowed(req.host, cfg.allowed_hosts)) {
        try sendHttpError(ra, fd, 421, "invalid_host", "Invalid Host header");
        return;
    }
    if (cfg.token.len != 0) {
        const got = req.token orelse "";
        if (!std.mem.eql(u8, got, cfg.token)) {
            try sendHttpError(ra, fd, 401, "unauthorized", "unauthorized");
            return;
        }
    }
    if (!std.mem.eql(u8, req.method, "POST") or !std.mem.eql(u8, req.path, "/mcp")) {
        try sendHttpError(ra, fd, 404, "not_found", "not found");
        return;
    }
    if (req.content_type) |ct| {
        if (!std.mem.startsWith(u8, ct, "application/json")) {
            try sendHttpError(ra, fd, 400, "bad_content_type", "Invalid Content-Type header");
            return;
        }
    } else {
        try sendHttpError(ra, fd, 400, "bad_content_type", "Invalid Content-Type header");
        return;
    }

    const response = try handleRpc(ra, io, cfg, req.body);
    if (response.len == 0) {
        try sendHttpRaw(ra, fd, 202, "application/json", "");
    } else {
        try sendHttpRaw(ra, fd, 200, "application/json", response);
    }
}

fn readHttpRequest(arena: Allocator, fd: std.posix.fd_t) !Request {
    var data: std.ArrayList(u8) = .empty;
    var header_end: ?usize = null;
    var content_length: usize = 0;
    var buf: [16384]u8 = undefined;

    while (true) {
        if (data.items.len >= MAX_REQUEST_BYTES) return error.RequestTooLarge;
        const n = try std.posix.read(fd, &buf);
        if (n == 0) break;
        try data.appendSlice(arena, buf[0..n]);
        if (header_end == null) {
            if (std.mem.indexOf(u8, data.items, "\r\n\r\n")) |idx| {
                header_end = idx + 4;
                content_length = try parseContentLength(data.items[0..idx]);
            }
        }
        if (header_end) |he| {
            if (data.items.len >= he + content_length) break;
        }
    }
    const he = header_end orelse return error.BadHeaders;
    if (data.items.len < he + content_length) return error.ShortBody;
    const head = data.items[0 .. he - 4];
    const body = data.items[he .. he + content_length];

    var lines = std.mem.splitSequence(u8, head, "\r\n");
    const request_line = lines.next() orelse return error.BadRequestLine;
    var parts = std.mem.splitScalar(u8, request_line, ' ');
    const method = parts.next() orelse return error.BadRequestLine;
    const path = parts.next() orelse return error.BadRequestLine;

    var req = Request{
        .method = method,
        .path = path,
        .host = null,
        .content_type = null,
        .content_length = content_length,
        .token = null,
        .body = body,
    };
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const name = std.mem.trim(u8, line[0..colon], " \t");
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (asciiEqlIgnoreCase(name, "host")) req.host = value;
        if (asciiEqlIgnoreCase(name, "content-type")) req.content_type = value;
        if (asciiEqlIgnoreCase(name, "x-node-token")) req.token = value;
    }
    return req;
}

fn parseContentLength(head: []const u8) !usize {
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    _ = lines.next();
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const name = std.mem.trim(u8, line[0..colon], " \t");
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (asciiEqlIgnoreCase(name, "content-length")) {
            return std.fmt.parseInt(usize, value, 10) catch error.BadContentLength;
        }
    }
    return 0;
}

fn asciiEqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        if (std.ascii.toLower(ca) != std.ascii.toLower(cb)) return false;
    }
    return true;
}

fn hostAllowed(host_opt: ?[]const u8, allowed: [][]const u8) bool {
    const host = host_opt orelse return false;
    for (allowed) |pat| {
        if (std.mem.eql(u8, host, pat)) return true;
        if (std.mem.endsWith(u8, pat, ":*")) {
            const base = pat[0 .. pat.len - 2];
            if (std.mem.startsWith(u8, host, base) and host.len > base.len and host[base.len] == ':') return true;
        }
    }
    return false;
}

fn handleRpc(arena: Allocator, io: Io, cfg: *const Config, body: []const u8) ![]const u8 {
    const req = std.json.parseFromSliceLeaky(Value, arena, body, .{}) catch return error.InvalidJson;
    if (req != .object) return error.InvalidJson;
    const id = req.object.get("id") orelse Value.null;
    const method_v = req.object.get("method") orelse return rpcError(arena, id, -32600, "Invalid Request");
    if (method_v != .string) return rpcError(arena, id, -32600, "Invalid Request");
    const method = method_v.string;

    if (std.mem.eql(u8, method, "notifications/initialized")) {
        return try arena.dupe(u8, "");
    }
    if (std.mem.eql(u8, method, "initialize")) {
        var out: std.ArrayList(u8) = .empty;
        try out.appendSlice(arena, "{\"jsonrpc\":\"2.0\",\"id\":");
        try appendJsonValue(&out, arena, id);
        try out.appendSlice(arena, ",\"result\":{\"protocolVersion\":\"2025-03-26\",\"capabilities\":{\"tools\":{}},\"serverInfo\":{\"name\":");
        try appendJsonString(&out, arena, cfg.name);
        try out.appendSlice(arena, ",\"version\":");
        try appendJsonString(&out, arena, VERSION);
        try out.appendSlice(arena, "}}}");
        return out.items;
    }
    if (std.mem.eql(u8, method, "tools/list")) {
        var out: std.ArrayList(u8) = .empty;
        try out.appendSlice(arena, "{\"jsonrpc\":\"2.0\",\"id\":");
        try appendJsonValue(&out, arena, id);
        try out.appendSlice(arena, ",\"result\":");
        try out.appendSlice(arena, TOOLS_JSON);
        try out.appendSlice(arena, "}");
        return out.items;
    }
    if (std.mem.eql(u8, method, "tools/call")) {
        return handleToolCall(arena, io, cfg, id, req.object.get("params"));
    }
    return rpcError(arena, id, -32601, "Method not found");
}

fn handleToolCall(arena: Allocator, io: Io, cfg: *const Config, id: Value, params_v: ?Value) ![]const u8 {
    const params = params_v orelse return rpcError(arena, id, -32602, "Invalid params");
    if (params != .object) return rpcError(arena, id, -32602, "Invalid params");
    const name_v = params.object.get("name") orelse return rpcError(arena, id, -32602, "Invalid params");
    if (name_v != .string) return rpcError(arena, id, -32602, "Invalid params");
    const args = params.object.get("arguments") orelse Value.null;

    var payload: std.ArrayList(u8) = .empty;
    var is_error = false;
    if (std.mem.eql(u8, name_v.string, "exec")) {
        toolExec(arena, io, cfg, args, &payload) catch |err| {
            is_error = true;
            try buildErrorPayload(&payload, arena, @errorName(err));
        };
    } else if (std.mem.eql(u8, name_v.string, "exec_shell")) {
        toolExecShell(arena, io, cfg, args, &payload) catch |err| {
            is_error = true;
            try buildErrorPayload(&payload, arena, @errorName(err));
        };
    } else if (std.mem.eql(u8, name_v.string, "sys_info")) {
        toolSysInfo(arena, io, cfg, &payload) catch |err| {
            is_error = true;
            try buildErrorPayload(&payload, arena, @errorName(err));
        };
    } else if (std.mem.eql(u8, name_v.string, "read_file")) {
        toolReadFile(arena, io, cfg, args, &payload) catch |err| {
            is_error = true;
            try buildErrorPayload(&payload, arena, @errorName(err));
        };
    } else if (std.mem.eql(u8, name_v.string, "write_file")) {
        toolWriteFile(arena, io, cfg, args, &payload) catch |err| {
            is_error = true;
            try buildErrorPayload(&payload, arena, @errorName(err));
        };
    } else if (std.mem.eql(u8, name_v.string, "list_dir")) {
        toolListDir(arena, io, cfg, args, &payload) catch |err| {
            is_error = true;
            try buildErrorPayload(&payload, arena, @errorName(err));
        };
    } else {
        return rpcError(arena, id, -32602, "Unknown tool");
    }

    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(arena, "{\"jsonrpc\":\"2.0\",\"id\":");
    try appendJsonValue(&out, arena, id);
    try out.appendSlice(arena, ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":");
    try appendJsonString(&out, arena, payload.items);
    try out.appendSlice(arena, "}],\"structuredContent\":");
    try out.appendSlice(arena, payload.items);
    try out.appendSlice(arena, ",\"isError\":");
    try out.appendSlice(arena, if (is_error) "true" else "false");
    try out.appendSlice(arena, "}}");
    return out.items;
}

fn rpcError(arena: Allocator, id: Value, code: i32, message: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(arena, "{\"jsonrpc\":\"2.0\",\"id\":");
    try appendJsonValue(&out, arena, id);
    try out.appendSlice(arena, ",\"error\":{\"code\":");
    try out.print(arena, "{d}", .{code});
    try out.appendSlice(arena, ",\"message\":");
    try appendJsonString(&out, arena, message);
    try out.appendSlice(arena, "}}");
    return out.items;
}

fn buildErrorPayload(out: *std.ArrayList(u8), arena: Allocator, msg: []const u8) !void {
    out.clearRetainingCapacity();
    try out.appendSlice(arena, "{\"ok\":false,\"error\":");
    try appendJsonString(out, arena, msg);
    try out.appendSlice(arena, "}");
}

fn toolExec(arena: Allocator, io: Io, cfg: *const Config, args: Value, out: *std.ArrayList(u8)) !void {
    const argv_v = objGet(args, "argv") orelse return error.MissingArgv;
    if (argv_v != .array) return error.BadArgv;
    if (argv_v.array.items.len == 0) return error.BadArgv;
    var argv = try arena.alloc([]const u8, argv_v.array.items.len);
    for (argv_v.array.items, 0..) |item, i| {
        if (item != .string) return error.BadArgv;
        argv[i] = item.string;
    }
    const cwd = strArg(args, "cwd") orelse "";
    const timeout_s = intArg(args, "timeout") orelse 120;
    const started = std.Io.Clock.awake.now(io);
    const result = std.process.run(arena, io, .{
        .argv = argv,
        .cwd = if (cwd.len == 0) .inherit else .{ .path = cwd },
        .stdout_limit = .limited(cfg.max_out),
        .stderr_limit = .limited(cfg.max_out),
        .timeout = if (timeout_s <= 0) .none else .{ .duration = .{ .clock = .awake, .raw = std.Io.Duration.fromSeconds(timeout_s) } },
    }) catch |err| switch (err) {
        error.Timeout => return error.CommandTimeout,
        error.StreamTooLong => return error.OutputTooLong,
        else => return err,
    };
    const elapsed_ms = started.untilNow(io, .awake).toMilliseconds();
    const exit_code: i32 = switch (result.term) {
        .exited => |code| code,
        .signal => |sig| 128 + @as(i32, @intCast(@intFromEnum(sig))),
        .stopped => |sig| 128 + @as(i32, @intCast(@intFromEnum(sig))),
        .unknown => |code| @as(i32, @intCast(code)),
    };
    try out.appendSlice(arena, "{\"ok\":");
    try out.appendSlice(arena, if (exit_code == 0) "true" else "false");
    try out.appendSlice(arena, ",\"exit_code\":");
    try out.print(arena, "{d}", .{exit_code});
    try out.appendSlice(arena, ",\"stdout\":");
    try appendJsonString(out, arena, result.stdout);
    try out.appendSlice(arena, ",\"stderr\":");
    try appendJsonString(out, arena, result.stderr);
    try out.appendSlice(arena, ",\"truncated\":false,\"duration_ms\":");
    try out.print(arena, "{d}", .{elapsed_ms});
    try out.appendSlice(arena, "}");
}

fn toolExecShell(arena: Allocator, io: Io, cfg: *const Config, args: Value, out: *std.ArrayList(u8)) !void {
    const script = strArg(args, "script") orelse return error.MissingScript;
    const shell = strArg(args, "shell") orelse "bash";
    if (!std.mem.eql(u8, shell, "bash") and !std.mem.eql(u8, shell, "sh") and !std.mem.eql(u8, shell, "fish") and !std.mem.eql(u8, shell, "zsh")) return error.UnsupportedShell;
    const cwd = strArg(args, "cwd") orelse "";
    const timeout_s = intArg(args, "timeout") orelse 120;
    var new_args: std.ArrayList(u8) = .empty;
    try new_args.appendSlice(arena, "{\"argv\":[");
    try appendJsonString(&new_args, arena, shell);
    try new_args.appendSlice(arena, ",\"-c\",");
    try appendJsonString(&new_args, arena, script);
    try new_args.appendSlice(arena, "]");
    if (cwd.len != 0) {
        try new_args.appendSlice(arena, ",\"cwd\":");
        try appendJsonString(&new_args, arena, cwd);
    }
    try new_args.appendSlice(arena, ",\"timeout\":");
    try new_args.print(arena, "{d}", .{timeout_s});
    try new_args.appendSlice(arena, "}");
    const parsed = try std.json.parseFromSliceLeaky(Value, arena, new_args.items, .{});
    return toolExec(arena, io, cfg, parsed, out);
}

fn toolSysInfo(arena: Allocator, io: Io, cfg: *const Config, out: *std.ArrayList(u8)) !void {
    _ = cfg;
    const hostname = std.mem.trim(u8, readFileAllocMaybe(arena, io, "/proc/sys/kernel/hostname", 256) catch "", "\r\n ");
    const loadavg = std.mem.trim(u8, readFileAllocMaybe(arena, io, "/proc/loadavg", 256) catch "", "\r\n ");
    const uptime_s = std.mem.trim(u8, readFileAllocMaybe(arena, io, "/proc/uptime", 256) catch "", "\r\n ");
    const meminfo = readFileAllocMaybe(arena, io, "/proc/meminfo", 16384) catch "";
    var mem_total: u64 = 0;
    var mem_avail: u64 = 0;
    var it = std.mem.splitScalar(u8, meminfo, '\n');
    while (it.next()) |line| {
        if (std.mem.startsWith(u8, line, "MemTotal:")) mem_total = parseKbLine(line);
        if (std.mem.startsWith(u8, line, "MemAvailable:")) mem_avail = parseKbLine(line);
    }
    try out.appendSlice(arena, "{\"node\":");
    try appendJsonString(out, arena, hostname);
    try out.appendSlice(arena, ",\"hostname\":");
    try appendJsonString(out, arena, hostname);
    try out.appendSlice(arena, ",\"os\":\"Linux\",\"machine\":\"x86_64\",\"loadavg_raw\":");
    try appendJsonString(out, arena, loadavg);
    try out.appendSlice(arena, ",\"uptime_raw\":");
    try appendJsonString(out, arena, uptime_s);
    try out.appendSlice(arena, ",\"mem\":{\"MemTotal\":");
    try out.print(arena, "{d}", .{mem_total * 1024});
    try out.appendSlice(arena, ",\"MemAvailable\":");
    try out.print(arena, "{d}", .{mem_avail * 1024});
    try out.appendSlice(arena, "}}");
}

fn parseKbLine(line: []const u8) u64 {
    var it = std.mem.tokenizeScalar(u8, line, ' ');
    _ = it.next();
    const num = it.next() orelse return 0;
    return std.fmt.parseInt(u64, num, 10) catch 0;
}

fn toolReadFile(arena: Allocator, io: Io, cfg: *const Config, args: Value, out: *std.ArrayList(u8)) !void {
    _ = cfg;
    const path = strArg(args, "path") orelse return error.MissingPath;
    const offset = intArg(args, "offset") orelse 0;
    const limit = intArg(args, "limit") orelse 200_000;
    const data = readFileAllocMaybe(arena, io, path, 64 * 1024 * 1024) catch |err| switch (err) {
        error.FileNotFound => return error.FileNotFound,
        error.IsDir => return error.IsDirectory,
        error.StreamTooLong => return error.FileTooLarge,
        else => return err,
    };
    const text = try utf8LossyAlloc(arena, data);
    const slice = try utf8CharSlice(text, @intCast(offset), @intCast(limit));
    try out.appendSlice(arena, "{\"ok\":true,\"path\":");
    try appendJsonString(out, arena, path);
    try out.appendSlice(arena, ",\"size\":");
    try out.print(arena, "{d}", .{data.len});
    try out.appendSlice(arena, ",\"offset\":");
    try out.print(arena, "{d}", .{offset});
    try out.appendSlice(arena, ",\"content\":");
    try appendJsonString(out, arena, slice.text);
    try out.appendSlice(arena, ",\"has_more\":");
    try out.appendSlice(arena, if (slice.has_more) "true" else "false");
    try out.appendSlice(arena, "}");
}

fn toolWriteFile(arena: Allocator, io: Io, cfg: *const Config, args: Value, out: *std.ArrayList(u8)) !void {
    _ = cfg;
    const path = strArg(args, "path") orelse return error.MissingPath;
    const content_b64 = strArg(args, "content_b64") orelse return error.MissingContent;
    const mode_i = intArg(args, "mode") orelse 0o644;
    const mkdirs = boolArg(args, "mkdirs") orelse true;

    const size = try std.base64.standard.Decoder.calcSizeForSlice(content_b64);
    const data = try arena.alloc(u8, size);
    try std.base64.standard.Decoder.decode(data, content_b64);

    if (mkdirs) {
        if (std.fs.path.dirname(path)) |parent| {
            if (parent.len != 0 and !std.mem.eql(u8, parent, ".")) {
                try std.Io.Dir.createDirPath(.cwd(), io, parent);
            }
        }
    }
    const mode: std.posix.mode_t = @intCast(mode_i);
    const fd = try std.posix.openat(std.posix.AT.FDCWD, path, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, mode);
    defer _ = std.os.linux.close(fd);
    try writeAllFd(fd, data);

    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update(data);
    var digest: [32]u8 = undefined;
    h.final(&digest);
    try out.appendSlice(arena, "{\"ok\":true,\"path\":");
    try appendJsonString(out, arena, path);
    try out.appendSlice(arena, ",\"size\":");
    try out.print(arena, "{d}", .{data.len});
    try out.appendSlice(arena, ",\"sha256\":");
    try appendHexLower(out, arena, &digest);
    try out.appendSlice(arena, "}");
}

fn toolListDir(arena: Allocator, io: Io, cfg: *const Config, args: Value, out: *std.ArrayList(u8)) !void {
    _ = cfg;
    const path = strArg(args, "path") orelse ".";
    var dir = std.Io.Dir.openDir(.cwd(), io, path, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => return error.FileNotFound,
        error.NotDir => return error.NotDirectory,
        else => return err,
    };
    defer dir.close(io);
    var it = dir.iterate();
    var count: usize = 0;
    try out.appendSlice(arena, "{\"ok\":true,\"path\":");
    try appendJsonString(out, arena, path);
    try out.appendSlice(arena, ",\"items\":[");
    var first = true;
    while (try it.next(io)) |entry| {
        if (count >= 2000) break;
        count += 1;
        if (!first) try out.appendSlice(arena, ",");
        first = false;
        const kind = switch (entry.kind) {
            .directory => "d",
            .sym_link => "l",
            .file => "f",
            else => "?",
        };
        var size: i64 = -1;
        var mtime: i64 = 0;
        if (dir.statFile(io, entry.name, .{})) |st| {
            size = @intCast(st.size);
            mtime = st.mtime.toSeconds();
        } else |_| {}
        try out.appendSlice(arena, "{\"name\":");
        try appendJsonString(out, arena, entry.name);
        try out.appendSlice(arena, ",\"type\":");
        try appendJsonString(out, arena, kind);
        try out.appendSlice(arena, ",\"size\":");
        try out.print(arena, "{d}", .{size});
        try out.appendSlice(arena, ",\"mtime\":");
        try out.print(arena, "{d}", .{mtime});
        try out.appendSlice(arena, "}");
    }
    try out.appendSlice(arena, "],\"count\":");
    try out.print(arena, "{d}", .{count});
    try out.appendSlice(arena, "}");
}

fn objGet(v: Value, key: []const u8) ?Value {
    if (v != .object) return null;
    return v.object.get(key);
}

fn strArg(args: Value, key: []const u8) ?[]const u8 {
    const v = objGet(args, key) orelse return null;
    if (v != .string) return null;
    return v.string;
}

fn intArg(args: Value, key: []const u8) ?i64 {
    const v = objGet(args, key) orelse return null;
    return switch (v) {
        .integer => |i| i,
        .float => |f| @as(i64, @intFromFloat(f)),
        .number_string => |s| std.fmt.parseInt(i64, s, 10) catch null,
        else => null,
    };
}

fn boolArg(args: Value, key: []const u8) ?bool {
    const v = objGet(args, key) orelse return null;
    return switch (v) {
        .bool => |b| b,
        else => null,
    };
}

fn appendJsonValue(out: *std.ArrayList(u8), arena: Allocator, v: Value) !void {
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

fn appendJsonString(out: *std.ArrayList(u8), arena: Allocator, s: []const u8) !void {
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
                    try out.appendSlice(arena, "");
                    i += 1;
                    continue;
                };
                if (i + seq_len > s.len or !validUtf8Seq(s[i .. i + seq_len])) {
                    try out.appendSlice(arena, "");
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

fn utf8SeqLen(s: []const u8) ?usize {
    if (s.len == 0) return null;
    const b0 = s[0];
    if (b0 < 0x80) return 1;
    if (b0 >= 0xc2 and b0 <= 0xdf) return 2;
    if (b0 >= 0xe0 and b0 <= 0xef) return 3;
    if (b0 >= 0xf0 and b0 <= 0xf4) return 4;
    return null;
}

fn validUtf8Seq(s: []const u8) bool {
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

fn utf8LossyAlloc(arena: Allocator, data: []const u8) ![]const u8 {
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
            try out.appendSlice(arena, "");
            i += 1;
            continue;
        };
        if (i + seq_len > data.len or !validUtf8Seq(data[i .. i + seq_len])) {
            try out.appendSlice(arena, "");
            i += 1;
            continue;
        }
        try out.appendSlice(arena, data[i .. i + seq_len]);
        i += seq_len;
    }
    return out.items;
}

const CharSlice = struct { text: []const u8, has_more: bool };

fn utf8CharSlice(s: []const u8, offset_chars: usize, limit_chars: usize) !CharSlice {
    if (offset_chars == 0 and limit_chars == 0) return .{ .text = s, .has_more = false };
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

fn appendHexLower(out: *std.ArrayList(u8), arena: Allocator, bytes: []const u8) !void {
    const alphabet = "0123456789abcdef";
    try out.append(arena, '"');
    for (bytes) |b| {
        try out.append(arena, alphabet[b >> 4]);
        try out.append(arena, alphabet[b & 0x0f]);
    }
    try out.append(arena, '"');
}

fn readFileAllocMaybe(arena: Allocator, io: Io, path: []const u8, limit: usize) ![]u8 {
    _ = io;
    const fd = try std.posix.openat(std.posix.AT.FDCWD, path, .{}, 0);
    defer _ = std.os.linux.close(fd);
    var out: std.ArrayList(u8) = .empty;
    var buf: [16384]u8 = undefined;
    while (true) {
        const n = try std.posix.read(fd, &buf);
        if (n == 0) break;
        if (out.items.len + n > limit) return error.StreamTooLong;
        try out.appendSlice(arena, buf[0..n]);
    }
    return out.items;
}

fn writeAllFd(fd: std.posix.fd_t, bytes: []const u8) !void {
    var off: usize = 0;
    while (off < bytes.len) {
        const rc = std.os.linux.write(fd, bytes.ptr + off, bytes.len - off);
        const errno = std.os.linux.errno(rc);
        switch (errno) {
            .SUCCESS => off += rc,
            .INTR => continue,
            else => return error.WriteFailed,
        }
    }
}

fn sendHttpRaw(arena: Allocator, fd: std.posix.fd_t, status: u16, content_type: []const u8, body: []const u8) !void {
    var out: std.ArrayList(u8) = .empty;
    const reason = switch (status) {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        413 => "Payload Too Large",
        421 => "Misdirected Request",
        431 => "Request Header Fields Too Large",
        else => "OK",
    };
    try out.print(arena, "HTTP/1.1 {d} {s}\r\ncontent-type: {s}\r\ncontent-length: {d}\r\nconnection: close\r\n\r\n", .{ status, reason, content_type, body.len });
    try out.appendSlice(arena, body);
    try writeAllFd(fd, out.items);
}

fn sendHttpError(arena: Allocator, fd: std.posix.fd_t, status: u16, code: []const u8, message: []const u8) !void {
    var body: std.ArrayList(u8) = .empty;
    try body.appendSlice(arena, "{\"error\":");
    try appendJsonString(&body, arena, code);
    try body.appendSlice(arena, ",\"message\":");
    try appendJsonString(&body, arena, message);
    try body.appendSlice(arena, "}");
    try sendHttpRaw(arena, fd, status, "application/json", body.items);
}

const TOOLS_JSON =
    \\{"tools":[
    \\{"name":"sys_info","description":"Host summary: hostname, OS, load, memory, uptime.","inputSchema":{"type":"object","properties":{}}},
    \\{"name":"exec","description":"Run argv without a shell layer.","inputSchema":{"type":"object","properties":{"argv":{"type":"array","items":{"type":"string"}},"cwd":{"type":"string"},"timeout":{"type":"integer"}},"required":["argv"]}},
    \\{"name":"exec_shell","description":"Run one shell script layer via bash/sh/fish/zsh -c.","inputSchema":{"type":"object","properties":{"script":{"type":"string"},"shell":{"type":"string"},"timeout":{"type":"integer"},"cwd":{"type":"string"}},"required":["script"]}},
    \\{"name":"read_file","description":"Read a text file as UTF-8 with replacement. offset/limit are in characters.","inputSchema":{"type":"object","properties":{"path":{"type":"string"},"offset":{"type":"integer"},"limit":{"type":"integer"}},"required":["path"]}},
    \\{"name":"write_file","description":"Write base64 content to a file; returns sha256.","inputSchema":{"type":"object","properties":{"path":{"type":"string"},"content_b64":{"type":"string"},"mode":{"type":"integer"},"mkdirs":{"type":"boolean"}},"required":["path","content_b64"]}},
    \\{"name":"list_dir","description":"List a directory with name/type/size/mtime.","inputSchema":{"type":"object","properties":{"path":{"type":"string"}}}}
    \\]}
;

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

test "host allowlist supports exact and wildcard-port patterns" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const allowed = try splitCsv(arena, "127.0.0.1:*,localhost:*,192.0.2.1:*");
    try std.testing.expect(hostAllowed("127.0.0.1:8341", allowed));
    try std.testing.expect(hostAllowed("192.0.2.1:8341", allowed));
    try std.testing.expect(!hostAllowed("evil.example:8341", allowed));
}

test "utf8 lossy replaces invalid bytes" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const s = try utf8LossyAlloc(arena, "a\xffb");
    try std.testing.expectEqualStrings("ab", s);
}
