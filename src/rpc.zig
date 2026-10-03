//! JSON-RPC 2.0 layer: request shape validation, method dispatch,
//! response and error envelopes, and the tools/list manifest
//! (TOOLS_JSON). The HTTP transport (serveOneRequest) still lives
//! in main.zig.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Value = std.json.Value;
const util = @import("util.zig");
const config = @import("config.zig");
const tools = @import("tools.zig");

const VERSION: []const u8 = @import("build_options").version;

const RpcResponse = struct {
    status: u16,
    body: []const u8,
};

/// JSON-RPC 2.0 dispatch for one MCP request body. Returns the HTTP status
/// plus the serialized response body: transport errors (parse, shape) map to
/// HTTP 4xx, method-level errors stay inside a 200 JSON-RPC error object.
/// Notifications (no id, or method "notifications/*") get 202 with empty body.
pub fn handleRpc(arena: Allocator, io: Io, cfg: *const config.Config, body: []const u8) !RpcResponse {
    const req = std.json.parseFromSliceLeaky(Value, arena, body, .{}) catch {
        return .{ .status = 400, .body = try rpcError(arena, Value.null, -32700, "Parse error") };
    };
    if (req != .object) {
        return .{ .status = 400, .body = try rpcError(arena, Value.null, -32600, "Invalid Request") };
    }
    const id_opt = req.object.get("id");
    // Errors echo the id only when it is of a legal type (string/integer/
    // null); anything else renders the request itself invalid with id null.
    const err_id = validIdOrNull(id_opt);
    // The JSON-RPC 2.0 envelope member is mandatory and must equal "2.0";
    // anything else is an Invalid Request, never silently tolerated.
    const jsonrpc_v = req.object.get("jsonrpc") orelse {
        return .{ .status = 400, .body = try rpcError(arena, err_id, -32600, "Invalid Request") };
    };
    if (jsonrpc_v != .string or !std.mem.eql(u8, jsonrpc_v.string, "2.0")) {
        return .{ .status = 400, .body = try rpcError(arena, err_id, -32600, "Invalid Request") };
    }
    // id typing per JSON-RPC: string, integer, or null. A present null id is
    // a (discouraged but legal) request id, NOT a notification: it is
    // answered with the echoed null. Absent id is the notification marker.
    if (id_opt) |id_v| {
        switch (id_v) {
            .string, .integer, .number_string, .null => {},
            else => return .{ .status = 400, .body = try rpcError(arena, Value.null, -32600, "Invalid Request") },
        }
    }
    const method_v = req.object.get("method") orelse {
        return .{ .status = 400, .body = try rpcError(arena, err_id, -32600, "Invalid Request") };
    };
    if (method_v != .string) {
        return .{ .status = 400, .body = try rpcError(arena, err_id, -32600, "Invalid Request") };
    }
    const method = method_v.string;
    // params, when present, must be structured (object or array); null is
    // tolerated as "omitted" for client compatibility. A scalar params makes
    // the whole message an Invalid Request — including for notifications,
    // which must not unconditionally pass.
    if (req.object.get("params")) |params| {
        switch (params) {
            .object, .array, .null => {},
            else => return .{ .status = 400, .body = try rpcError(arena, err_id, -32600, "Invalid Request") },
        }
    }
    // A request without an id is a notification: 202 with no response body,
    // but only after the full shape validation above.
    if (id_opt == null) {
        return .{ .status = 202, .body = "" };
    }
    const id = id_opt.?;
    // MCP notifications/* are notifications by definition; carrying an id
    // makes the message an Invalid Request that must be answered — the
    // response must never be silently dropped with a 202.
    if (std.mem.startsWith(u8, method, "notifications/")) {
        return .{ .status = 400, .body = try rpcError(arena, id, -32600, "Invalid Request") };
    }

    if (std.mem.eql(u8, method, "initialize")) {
        var protocol_version: []const u8 = "2025-11-25";
        if (req.object.get("params")) |params| {
            if (params == .object) {
                if (params.object.get("protocolVersion")) |pv| {
                    if (pv == .string and supportedProtocolVersion(pv.string)) protocol_version = pv.string;
                }
            }
        }
        var out: std.ArrayList(u8) = .empty;
        try out.appendSlice(arena, "{\"jsonrpc\":\"2.0\",\"id\":");
        try util.appendJsonValue(&out, arena, id);
        try out.appendSlice(arena, ",\"result\":{\"protocolVersion\":");
        try util.appendJsonString(&out, arena, protocol_version);
        try out.appendSlice(arena, ",\"capabilities\":{\"tools\":{}},\"serverInfo\":{\"name\":");
        try util.appendJsonString(&out, arena, cfg.name);
        try out.appendSlice(arena, ",\"version\":");
        try util.appendJsonString(&out, arena, VERSION);
        try out.appendSlice(arena, "}}}");
        return .{ .status = 200, .body = out.items };
    }
    if (std.mem.eql(u8, method, "ping")) {
        var out: std.ArrayList(u8) = .empty;
        try out.appendSlice(arena, "{\"jsonrpc\":\"2.0\",\"id\":");
        try util.appendJsonValue(&out, arena, id);
        try out.appendSlice(arena, ",\"result\":{}}");
        return .{ .status = 200, .body = out.items };
    }
    if (std.mem.eql(u8, method, "tools/list")) {
        var out: std.ArrayList(u8) = .empty;
        try out.appendSlice(arena, "{\"jsonrpc\":\"2.0\",\"id\":");
        try util.appendJsonValue(&out, arena, id);
        try out.appendSlice(arena, ",\"result\":");
        try out.appendSlice(arena, TOOLS_JSON);
        try out.appendSlice(arena, "}");
        return .{ .status = 200, .body = out.items };
    }
    if (std.mem.eql(u8, method, "resources/list")) {
        var out: std.ArrayList(u8) = .empty;
        try out.appendSlice(arena, "{\"jsonrpc\":\"2.0\",\"id\":");
        try util.appendJsonValue(&out, arena, id);
        try out.appendSlice(arena, ",\"result\":{\"resources\":[]}}");
        return .{ .status = 200, .body = out.items };
    }
    if (std.mem.eql(u8, method, "prompts/list")) {
        var out: std.ArrayList(u8) = .empty;
        try out.appendSlice(arena, "{\"jsonrpc\":\"2.0\",\"id\":");
        try util.appendJsonValue(&out, arena, id);
        try out.appendSlice(arena, ",\"result\":{\"prompts\":[]}}");
        return .{ .status = 200, .body = out.items };
    }
    if (std.mem.eql(u8, method, "tools/call")) {
        return handleToolCall(arena, io, cfg, id, req.object.get("params"));
    }
    return .{ .status = 200, .body = try rpcError(arena, id, -32601, "Method not found") };
}

fn supportedProtocolVersion(v: []const u8) bool {
    return std.mem.eql(u8, v, "2024-11-05") or
        std.mem.eql(u8, v, "2025-03-26") or
        std.mem.eql(u8, v, "2025-06-18") or
        std.mem.eql(u8, v, "2025-11-25");
}

fn handleToolCall(arena: Allocator, io: Io, cfg: *const config.Config, id: Value, params_v: ?Value) !RpcResponse {
    const params = params_v orelse return .{ .status = 200, .body = try rpcError(arena, id, -32602, "Invalid params") };
    if (params != .object) return .{ .status = 200, .body = try rpcError(arena, id, -32602, "Invalid params") };
    const name_v = params.object.get("name") orelse return .{ .status = 200, .body = try rpcError(arena, id, -32602, "Invalid params") };
    if (name_v != .string) return .{ .status = 200, .body = try rpcError(arena, id, -32602, "Invalid params") };
    // arguments, when present, must be an object: anything else is a
    // protocol-level Invalid params (-32602), not a tool-domain error.
    const args_v = params.object.get("arguments");
    if (args_v) |a| {
        if (a != .object) return .{ .status = 200, .body = try rpcError(arena, id, -32602, "Invalid params") };
    }
    const args = args_v orelse Value.null;

    var payload: std.ArrayList(u8) = .empty;
    dispatchTool(arena, io, cfg, name_v.string, args, &payload) catch |err| {
        switch (err) {
            error.UnknownTool => return unknownToolResult(arena, id, name_v.string),
            // A present argument with the wrong JSON type is a protocol
            // error (-32602), never a silent default.
            error.InvalidParams => return .{ .status = 200, .body = try rpcError(arena, id, -32602, "Invalid params") },
            else => try buildErrorPayload(&payload, arena, @errorName(err)),
        }
        return .{ .status = 200, .body = try toolEnvelope(arena, id, payload.items, false, true) };
    };
    return .{ .status = 200, .body = try toolEnvelope(arena, id, payload.items, false, true) };
}

fn dispatchTool(arena: Allocator, io: Io, cfg: *const config.Config, name: []const u8, args: Value, out: *std.ArrayList(u8)) !void {
    if (std.mem.eql(u8, name, "exec")) return tools.toolExec(arena, io, cfg, args, out);
    if (std.mem.eql(u8, name, "exec_start")) return tools.toolExecStart(arena, io, cfg, args, out);
    if (std.mem.eql(u8, name, "exec_poll")) return tools.toolExecPoll(arena, io, cfg, args, out);
    if (std.mem.eql(u8, name, "exec_write")) return tools.toolExecWrite(arena, io, cfg, args, out);
    if (std.mem.eql(u8, name, "exec_kill")) return tools.toolExecKill(arena, io, cfg, args, out);
    if (std.mem.eql(u8, name, "exec_close")) return tools.toolExecClose(arena, io, cfg, args, out);
    if (std.mem.eql(u8, name, "exec_wait")) return tools.toolExecWait(arena, io, cfg, args, out);
    if (std.mem.eql(u8, name, "exec_list")) return tools.toolExecList(arena, io, cfg, out);
    if (std.mem.eql(u8, name, "exec_shell")) return tools.toolExecShell(arena, io, cfg, args, out);
    if (std.mem.eql(u8, name, "sys_info")) return tools.toolSysInfo(arena, io, cfg, out);
    if (std.mem.eql(u8, name, "read_file")) return tools.toolReadFile(arena, io, cfg, args, out);
    if (std.mem.eql(u8, name, "write_file")) return tools.toolWriteFile(arena, io, cfg, args, out);
    if (std.mem.eql(u8, name, "list_dir")) return tools.toolListDir(arena, io, cfg, args, out);
    return error.UnknownTool;
}

fn toolEnvelope(arena: Allocator, id: Value, payload: []const u8, is_error: bool, structured: bool) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(arena, "{\"jsonrpc\":\"2.0\",\"id\":");
    try util.appendJsonValue(&out, arena, id);
    try out.appendSlice(arena, ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":");
    try util.appendJsonString(&out, arena, payload);
    try out.appendSlice(arena, "}]");
    if (structured) {
        try out.appendSlice(arena, ",\"structuredContent\":");
        try out.appendSlice(arena, payload);
    }
    try out.appendSlice(arena, ",\"isError\":");
    try out.appendSlice(arena, if (is_error) "true" else "false");
    try out.appendSlice(arena, "}}");
    return out.items;
}

fn unknownToolResult(arena: Allocator, id: Value, name: []const u8) !RpcResponse {
    var msg: std.ArrayList(u8) = .empty;
    try msg.appendSlice(arena, "Unknown tool: ");
    try msg.appendSlice(arena, name);
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(arena, "{\"jsonrpc\":\"2.0\",\"id\":");
    try util.appendJsonValue(&out, arena, id);
    try out.appendSlice(arena, ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":");
    try util.appendJsonString(&out, arena, msg.items);
    try out.appendSlice(arena, "}],\"isError\":true}}");
    return .{ .status = 200, .body = out.items };
}

fn validIdOrNull(id_opt: ?Value) Value {
    const v = id_opt orelse return Value.null;
    return switch (v) {
        .string, .integer, .number_string, .null => v,
        else => Value.null,
    };
}

fn rpcError(arena: Allocator, id: Value, code: i32, message: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(arena, "{\"jsonrpc\":\"2.0\",\"id\":");
    try util.appendJsonValue(&out, arena, id);
    try out.appendSlice(arena, ",\"error\":{\"code\":");
    try out.print(arena, "{d}", .{code});
    try out.appendSlice(arena, ",\"message\":");
    try util.appendJsonString(&out, arena, message);
    try out.appendSlice(arena, "}}");
    return out.items;
}

fn buildErrorPayload(out: *std.ArrayList(u8), arena: Allocator, msg: []const u8) !void {
    out.clearRetainingCapacity();
    try out.appendSlice(arena, "{\"ok\":false,\"error\":");
    try util.appendJsonString(out, arena, msg);
    try out.appendSlice(arena, "}");
}

const TOOLS_JSON =
    \\{"tools":[
    \\{"name":"sys_info","description":"Host summary: hostname, OS, load, memory, uptime.","inputSchema":{"type":"object","properties":{}}},
    \\{"name":"exec","description":"Run argv without a shell layer and wait for completion.","inputSchema":{"type":"object","properties":{"argv":{"type":"array","items":{"type":"string"}},"cwd":{"type":"string"},"timeout":{"type":"integer"}},"required":["argv"]}},
    \\{"name":"exec_start","description":"Start a long-running argv process as a session with piped stdin/stdout/stderr.","inputSchema":{"type":"object","properties":{"argv":{"type":"array","items":{"type":"string"}},"cwd":{"type":"string"}},"required":["argv"]}},
    \\{"name":"exec_poll","description":"Poll a session by byte offsets; returns output deltas, done, exit_code, truncation flags.","inputSchema":{"type":"object","properties":{"session_id":{"type":"integer"},"stdout_offset":{"type":"integer"},"stderr_offset":{"type":"integer"}},"required":["session_id"]}},
    \\{"name":"exec_write","description":"Write base64 bytes to a session stdin; eof=true closes stdin.","inputSchema":{"type":"object","properties":{"session_id":{"type":"integer"},"data_b64":{"type":"string"},"eof":{"type":"boolean"}},"required":["session_id","data_b64"]}},
    \\{"name":"exec_kill","description":"Kill a running session process with SIGKILL.","inputSchema":{"type":"object","properties":{"session_id":{"type":"integer"}},"required":["session_id"]}},
    \\{"name":"exec_close","description":"Kill if needed, join session threads, and free session state. Idempotent.","inputSchema":{"type":"object","properties":{"session_id":{"type":"integer"}},"required":["session_id"]}},
    \\{"name":"exec_wait","description":"Long-poll a session until it finishes or timeout (default 30s, max 300s); returns the same payload as exec_poll.","inputSchema":{"type":"object","properties":{"session_id":{"type":"integer"},"timeout":{"type":"integer"},"stdout_offset":{"type":"integer"},"stderr_offset":{"type":"integer"}},"required":["session_id"]}},
    \\{"name":"exec_list","description":"List live sessions with id, pid, argv, done, exit_code, timestamps.","inputSchema":{"type":"object","properties":{}}},
    \\{"name":"exec_shell","description":"Run one shell script layer via bash/sh/fish/zsh -c (cmd /c, powershell -c on Windows).","inputSchema":{"type":"object","properties":{"script":{"type":"string"},"shell":{"type":"string"},"timeout":{"type":"integer"},"cwd":{"type":"string"}},"required":["script"]}},
    \\{"name":"read_file","description":"Read a text file as UTF-8 with replacement. offset/limit are in characters.","inputSchema":{"type":"object","properties":{"path":{"type":"string"},"offset":{"type":"integer"},"limit":{"type":"integer"}},"required":["path"]}},
    \\{"name":"write_file","description":"Write base64 content to a file; returns sha256.","inputSchema":{"type":"object","properties":{"path":{"type":"string"},"content_b64":{"type":"string"},"mode":{"type":"integer"},"mkdirs":{"type":"boolean"}},"required":["path","content_b64"]}},
    \\{"name":"list_dir","description":"List a directory with name/type/size/mtime.","inputSchema":{"type":"object","properties":{"path":{"type":"string"}}}}
    \\]}
;

test "rpc parse error and notification semantics" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = Io.Threaded.global_single_threaded.io();
    const cfg = config.Config{
        .name = "test-node",
        .host = "127.0.0.1",
        .port = 1,
        .token = "",
        .allowed_hosts = try util.splitCsv(arena, "127.0.0.1:*"),
        .allowed_origins = try util.splitCsv(arena, "http://127.0.0.1:*"),
        .max_out = 1024,
        .socket_timeout_s = 1,
        .max_conn = 4,
        .max_sessions = 4,
        .session_ttl_s = 600,
        .max_inflight_bytes = 64 * 1024 * 1024,
    };

    const bad = try handleRpc(arena, io, &cfg, "{");
    try std.testing.expectEqual(@as(u16, 400), bad.status);
    const bad_parsed = try std.json.parseFromSliceLeaky(Value, arena, bad.body, .{});
    try std.testing.expectEqual(@as(i32, -32700), bad_parsed.object.get("error").?.object.get("code").?.integer);

    const note = try handleRpc(arena, io, &cfg, "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}");
    try std.testing.expectEqual(@as(u16, 202), note.status);
    try std.testing.expectEqual(@as(usize, 0), note.body.len);

    const ping = try handleRpc(arena, io, &cfg, "{\"jsonrpc\":\"2.0\",\"id\":\"p\",\"method\":\"ping\"}");
    try std.testing.expectEqual(@as(u16, 200), ping.status);
    const ping_parsed = try std.json.parseFromSliceLeaky(Value, arena, ping.body, .{});
    try std.testing.expect(ping_parsed.object.get("result").? == .object);
}
