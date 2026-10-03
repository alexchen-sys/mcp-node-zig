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
        try out.appendSlice(arena, "},\"instructions\":");
        try util.appendJsonString(&out, arena, SERVER_INSTRUCTIONS);
        try out.appendSlice(arena, "}}");
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
        return .{ .status = 200, .body = try toolEnvelope(arena, cfg, id, payload.items, false) };
    };
    return .{ .status = 200, .body = try toolEnvelope(arena, cfg, id, payload.items, false) };
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

/// MCP tool-result envelope. The payload is emitted as `structuredContent`
/// (the primary channel for clients) and, unless the text mirror was
/// switched off via `MCP_NODE_TEXT_MIRROR=0`, again as the JSON-escaped
/// `content[0].text` text mirror that pre-structured clients read.
/// `isError` results always carry the text mirror: errors are read by
/// every client, old and new alike.
fn toolEnvelope(arena: Allocator, cfg: *const config.Config, id: Value, payload: []const u8, is_error: bool) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(arena, "{\"jsonrpc\":\"2.0\",\"id\":");
    try util.appendJsonValue(&out, arena, id);
    try out.appendSlice(arena, ",\"result\":{");
    if (cfg.text_mirror or is_error) {
        try out.appendSlice(arena, "\"content\":[{\"type\":\"text\",\"text\":");
        try util.appendJsonString(&out, arena, payload);
        try out.appendSlice(arena, "}],");
    }
    try out.appendSlice(arena, "\"structuredContent\":");
    try out.appendSlice(arena, payload);
    try out.appendSlice(arena, ",\"isError\":");
    try out.appendSlice(arena, if (is_error) "true" else "false");
    try out.appendSlice(arena, "}}");
    return out.items;
}

fn unknownToolResult(arena: Allocator, id: Value, name: []const u8) !RpcResponse {
    var msg: std.ArrayList(u8) = .empty;
    try msg.appendSlice(arena, "Unknown tool: ");
    try msg.appendSlice(arena, name);
    // Actionable tail: let the agent self-recover with one tools/list call
    // instead of hitting a dead end.
    try msg.appendSlice(arena, "; call tools/list for available tools");
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

/// Server-level usage notes returned as `instructions` in the initialize
/// result (the MCP-standard channel for a server-side usage mandate).
/// Kept to a few sentences: agents read it once per session.
const SERVER_INSTRUCTIONS = "This node runs commands and file operations directly on the host it is deployed on. Prefer exec over exec_shell: exec passes argv verbatim without a shell, so metacharacters are data; use exec_shell only for pipelines, redirects and other shell syntax. Use exec_start for long-running or interactive processes, then poll with exec_poll and always release sessions with exec_close - sessions survive across HTTP requests. Every request must carry the node token in the X-Node-Token header (or Authorization: Bearer).";

/// The static tools/list manifest. Order is part of the frozen v0 contract
/// (deterministic order is also cache-friendly for clients); property
/// descriptions mirror the defaults and clamps implemented in tools.zig.
const TOOLS_JSON =
    \\{"tools":[
    \\{"name":"sys_info","title":"System Info","description":"Host summary: hostname, OS, load, memory, root filesystem usage (disk_root: total/used/free bytes) and uptime. Read-only, takes no arguments; a safe first call to verify connectivity before running commands.","inputSchema":{"type":"object","properties":{}},"annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false}},
    \\{"name":"exec","title":"Run Command (no shell)","description":"Run an argv array to completion and wait for exit - no shell layer, argv is passed verbatim, shell metacharacters are data. Best for one-shot commands. For pipelines, redirects or other shell syntax use exec_shell; for long-running or interactive processes use exec_start. timeout is in seconds, default 120, clamped to [1, 1800].","inputSchema":{"type":"object","properties":{"argv":{"type":"array","items":{"type":"string"},"description":"Full argument vector including the program name, e.g. [\"df\", \"-h\", \"/\"]. Passed verbatim - no shell, no quoting."},"cwd":{"type":"string","description":"Working directory for the child (absolute path recommended); omit to inherit."},"timeout":{"type":"integer","description":"Seconds to wait before killing the process (1..1800, default 120)."}},"required":["argv"]},"annotations":{"readOnlyHint":false,"destructiveHint":true,"idempotentHint":false,"openWorldHint":true}},
    \\{"name":"exec_start","title":"Start Session","description":"Start a long-running or interactive process as a session and return session_id immediately. Use this instead of exec when the process outlives the call, produces output over time, or needs stdin (then exec_write). Poll with exec_poll, block with exec_wait, kill with exec_kill, free with exec_close. Sessions survive across HTTP requests; finished sessions are reaped after the node's session TTL.","inputSchema":{"type":"object","properties":{"argv":{"type":"array","items":{"type":"string"},"description":"Full argument vector including the program name, e.g. [\"python3\", \"-i\"]. Passed verbatim - no shell."},"cwd":{"type":"string","description":"Working directory for the child (absolute path recommended); omit to inherit."}},"required":["argv"]},"annotations":{"readOnlyHint":false,"destructiveHint":true,"idempotentHint":false,"openWorldHint":true}},
    \\{"name":"exec_poll","title":"Poll Session","description":"Read new output from a session by byte offsets; returns stdout/stderr deltas, done, exit_code and truncation flags. Example: {\"session_id\":1,\"stdout_offset\":0,\"stderr_offset\":0} - pass the offsets returned by the previous call to resume where you stopped. Same payload shape as exec_wait.","inputSchema":{"type":"object","properties":{"session_id":{"type":"integer","description":"Session id returned by exec_start (positive integer)."},"stdout_offset":{"type":"integer","description":"Byte offset to resume reading stdout from; use the offset returned by the previous poll (default 0)."},"stderr_offset":{"type":"integer","description":"Byte offset to resume reading stderr from; use the offset returned by the previous poll (default 0)."}},"required":["session_id"]},"annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false}},
    \\{"name":"exec_write","title":"Write To Session","description":"Write bytes to a session's stdin; set eof=true to close stdin after writing (signals end of input). data_b64 is standard base64. Combine with exec_start for interactive programs (REPLs, prompts).","inputSchema":{"type":"object","properties":{"session_id":{"type":"integer","description":"Session id returned by exec_start (positive integer)."},"data_b64":{"type":"string","description":"Standard base64 of the bytes to write to the process stdin; empty string allowed."},"eof":{"type":"boolean","description":"Set true to close stdin after writing this data (default false)."}},"required":["session_id","data_b64"]},"annotations":{"readOnlyHint":false,"destructiveHint":false,"idempotentHint":false,"openWorldHint":false}},
    \\{"name":"exec_kill","title":"Kill Session","description":"Kill a running session's process tree (SIGKILL to the process group on POSIX, job-object termination on Windows); safe to call on an already-dead session. The session stays pollable afterwards; free it with exec_close.","inputSchema":{"type":"object","properties":{"session_id":{"type":"integer","description":"Session id returned by exec_start (positive integer)."}},"required":["session_id"]},"annotations":{"readOnlyHint":false,"destructiveHint":true,"idempotentHint":false,"openWorldHint":false}},
    \\{"name":"exec_close","title":"Close Session","description":"Kill if still running, join the session threads, and free session state. Idempotent: closing an already-closed session returns ok with already_closed=true. Always close sessions you started once you are done - sessions survive across HTTP requests.","inputSchema":{"type":"object","properties":{"session_id":{"type":"integer","description":"Session id returned by exec_start (positive integer)."}},"required":["session_id"]},"annotations":{"readOnlyHint":false,"destructiveHint":true,"idempotentHint":true,"openWorldHint":false}},
    \\{"name":"exec_wait","title":"Wait For Session","description":"Long-poll a session until it finishes or the timeout elapses (default 30s, max 300s); returns the same payload as exec_poll, including output deltas from the given offsets.","inputSchema":{"type":"object","properties":{"session_id":{"type":"integer","description":"Session id returned by exec_start (positive integer)."},"timeout":{"type":"integer","description":"Seconds to wait for completion before returning (1..300, default 30)."},"stdout_offset":{"type":"integer","description":"Byte offset to resume reading stdout from (default 0)."},"stderr_offset":{"type":"integer","description":"Byte offset to resume reading stderr from (default 0)."}},"required":["session_id"]},"annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false}},
    \\{"name":"exec_list","title":"List Sessions","description":"List live sessions with session_id, pid, argv, done, exit_code and timestamps; takes no arguments. Useful to rediscover session ids after a lost reply.","inputSchema":{"type":"object","properties":{}},"annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false}},
    \\{"name":"exec_shell","title":"Run Shell Script","description":"Run one script through a single explicit shell layer (bash/sh/fish/zsh -c on POSIX; cmd /c or powershell -c on Windows). Use ONLY when shell syntax (pipes, redirects, &&, globs) is required; otherwise prefer exec, which passes argv verbatim and treats metacharacters as data. timeout is in seconds, default 120, clamped to [1, 1800].","inputSchema":{"type":"object","properties":{"script":{"type":"string","description":"Script text handed to the shell's -c flag, e.g. \"du -sh /var/log | sort -h\"."},"shell":{"type":"string","description":"Shell to use: bash (default), sh, fish or zsh on POSIX; cmd or powershell on Windows."},"timeout":{"type":"integer","description":"Seconds to wait before killing the process (1..1800, default 120)."},"cwd":{"type":"string","description":"Working directory for the child (absolute path recommended); omit to inherit."}},"required":["script"]},"annotations":{"readOnlyHint":false,"destructiveHint":true,"idempotentHint":false,"openWorldHint":true}},
    \\{"name":"read_file","title":"Read File","description":"Read a text file as UTF-8 (invalid bytes replaced) and return size, offset, content and has_more. offset/limit are in characters, not bytes - safe mid-file slicing. Default limit is 200000 characters; files above 64 MiB are rejected.","inputSchema":{"type":"object","properties":{"path":{"type":"string","description":"File path to read; \"~\" expands to the home directory."},"offset":{"type":"integer","description":"Character offset to start reading from (default 0)."},"limit":{"type":"integer","description":"Maximum characters to return (default 200000)."}},"required":["path"]},"annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false}},
    \\{"name":"write_file","title":"Write File","description":"Write base64 content to a file (overwrites), creating parent directories by default; returns the size and sha256 of the written bytes. mode is POSIX permission bits (ignored on Windows).","inputSchema":{"type":"object","properties":{"path":{"type":"string","description":"File path to write; \"~\" expands to the home directory."},"content_b64":{"type":"string","description":"Standard base64 of the file content to write."},"mode":{"type":"integer","description":"POSIX permission bits for the new file, 0..0o7777 (default 0o644; ignored on Windows)."},"mkdirs":{"type":"boolean","description":"Create parent directories when missing (default true)."}},"required":["path","content_b64"]},"annotations":{"readOnlyHint":false,"destructiveHint":true,"idempotentHint":false,"openWorldHint":false}},
    \\{"name":"list_dir","title":"List Directory","description":"List one directory's entries with name, type (d=folder, l=symlink, f=file), size in bytes and mtime in Unix seconds, sorted by name; at most 2000 entries per call (truncated=true when more exist).","inputSchema":{"type":"object","properties":{"path":{"type":"string","description":"Directory path to list; \"~\" expands to the home directory; defaults to the working directory."}}},"annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false}}
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

test "tool result text mirror flag" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = Io.Threaded.global_single_threaded.io();
    var cfg = config.Config{
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
    // read_file on a missing path walks the full toolEnvelope path with a
    // non-throwing payload ({"ok":false,"error":"FileNotFound"}).
    const req = "{\"jsonrpc\":\"2.0\",\"id\":\"m\",\"method\":\"tools/call\"," ++
        "\"params\":{\"name\":\"read_file\",\"arguments\":{\"path\":\"/nonexistent-mcpnz-mirror\"}}}";

    // Default: spec-recommended mirror — text and structured both present.
    const on = try handleRpc(arena, io, &cfg, req);
    try std.testing.expect(std.mem.indexOf(u8, on.body, "\"content\":[{\"type\":\"text\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, on.body, "\"structuredContent\":") != null);

    // Mirror off: structured-only for regular results...
    cfg.text_mirror = false;
    const off = try handleRpc(arena, io, &cfg, req);
    try std.testing.expect(std.mem.indexOf(u8, off.body, "\"content\":") == null);
    try std.testing.expect(std.mem.indexOf(u8, off.body, "\"structuredContent\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, off.body, "\"isError\":false") != null);

    // ...but isError results keep the text channel open for every client.
    const unknown_req = "{\"jsonrpc\":\"2.0\",\"id\":\"u\",\"method\":\"tools/call\"," ++
        "\"params\":{\"name\":\"no_such_tool\",\"arguments\":{}}}";
    const unknown = try handleRpc(arena, io, &cfg, unknown_req);
    try std.testing.expect(std.mem.indexOf(u8, unknown.body, "\"content\":[{\"type\":\"text\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, unknown.body, "\"isError\":true") != null);
}
