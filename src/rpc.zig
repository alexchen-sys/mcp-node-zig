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
const audit = @import("audit.zig");

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
    return handleRpcCtx(arena, io, cfg, body, .{ .transport = .http });
}

/// Same as handleRpc, with the transport context the audit log records.
pub fn handleRpcCtx(arena: Allocator, io: Io, cfg: *const config.Config, body: []const u8, ctx: audit.CallCtx) !RpcResponse {
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
        return handleToolCall(arena, io, cfg, id, req.object.get("params"), ctx);
    }
    return .{ .status = 200, .body = try rpcError(arena, id, -32601, "Method not found") };
}

fn supportedProtocolVersion(v: []const u8) bool {
    return std.mem.eql(u8, v, "2024-11-05") or
        std.mem.eql(u8, v, "2025-03-26") or
        std.mem.eql(u8, v, "2025-06-18") or
        std.mem.eql(u8, v, "2025-11-25");
}

fn handleToolCall(arena: Allocator, io: Io, cfg: *const config.Config, id: Value, params_v: ?Value, ctx: audit.CallCtx) !RpcResponse {
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

    // Audit: one tool.call record per call (plus tool.start for the long
    // tools, so a crash mid-call still leaves a trace). The writer is null
    // and the calls no-op when audit is off.
    const aw = audit.fromCfg(cfg);
    var ctx2 = ctx;
    var id_buf: audit.Buf = undefined;
    id_buf.reset();
    audit.renderReqId(&id_buf, id);
    ctx2.req_id = if (id_buf.overflow) "null" else id_buf.slice();
    const long_tool = std.mem.eql(u8, name_v.string, "exec") or
        std.mem.eql(u8, name_v.string, "exec_start") or
        std.mem.eql(u8, name_v.string, "exec_shell");
    if (long_tool) audit.toolStart(aw, ctx2, name_v.string, args);
    const started = Io.Clock.awake.now(io);

    var payload: std.ArrayList(u8) = .empty;
    dispatchTool(arena, io, cfg, name_v.string, args, &payload) catch |err| {
        const dur_ms: u64 = @intCast(@max(0, started.untilNow(io, .awake).toMilliseconds()));
        audit.toolCall(aw, ctx2, name_v.string, args, false, null, @errorName(err), dur_ms, payload.items.len);
        switch (err) {
            error.UnknownTool => return unknownToolResult(arena, id, name_v.string),
            // A present argument with the wrong JSON type is a protocol
            // error (-32602), never a silent default.
            error.InvalidParams => return .{ .status = 200, .body = try rpcError(arena, id, -32602, "Invalid params") },
            else => try buildErrorPayload(&payload, arena, @errorName(err)),
        }
        return .{ .status = 200, .body = try toolEnvelope(arena, cfg, id, payload.items, false) };
    };
    const dur_ms: u64 = @intCast(@max(0, started.untilNow(io, .awake).toMilliseconds()));
    const facts = payloadFacts(payload.items);
    audit.toolCall(aw, ctx2, name_v.string, args, facts.ok orelse true, facts.exit_code, facts.err, dur_ms, payload.items.len);
    return .{ .status = 200, .body = try toolEnvelope(arena, cfg, id, payload.items, false) };
}

/// The ok/exit_code/error facts of a tool payload. All tool writers emit
/// them as the first fields of a flat object, so the scan window is the
/// first 160 bytes — output text (which could contain the same bytes)
/// never enters the window.
const PayloadFacts = struct { ok: ?bool, exit_code: ?i32, err: ?[]const u8 };

fn payloadFacts(payload: []const u8) PayloadFacts {
    var f: PayloadFacts = .{ .ok = null, .exit_code = null, .err = null };
    const head = payload[0..@min(payload.len, 160)];
    if (!std.mem.startsWith(u8, head, "{\"ok\":")) return f;
    if (std.mem.startsWith(u8, head[5..], "true")) {
        f.ok = true;
    } else if (std.mem.startsWith(u8, head[5..], "false")) {
        f.ok = false;
    }
    if (std.mem.indexOf(u8, head, ",\"exit_code\":")) |at| {
        var i = at + ",\"exit_code\":".len;
        var v: i64 = 0;
        var neg = false;
        if (i < head.len and head[i] == '-') {
            neg = true;
            i += 1;
        }
        var digits: usize = 0;
        while (i < head.len and head[i] >= '0' and head[i] <= '9') : (i += 1) {
            v = v * 10 + (head[i] - '0');
            digits += 1;
            if (digits > 9) break;
        }
        if (digits > 0 and digits <= 9) {
            if (neg) v = -v;
            f.exit_code = @intCast(v);
        }
    }
    if (std.mem.indexOf(u8, head, ",\"error\":\"")) |at| {
        const start = at + ",\"error\":\"".len;
        // Error names are identifier-shaped (@errorName): no escapes.
        if (std.mem.indexOfScalarPos(u8, head, start, '"')) |end| {
            if (end - start <= 64) f.err = head[start..end];
        }
    }
    return f;
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
    if (errHint(msg)) |hint| {
        try out.appendSlice(arena, ",\"message\":");
        try util.appendJsonString(out, arena, hint);
    }
    try out.appendSlice(arena, "}");
}

/// Human-readable hints for the few error names whose raw form is cryptic
/// to a JSON client (Zig's base64 taxonomy, argv shape validation).
/// Additive: the machine-readable name stays in "error"; "message" is
/// only emitted for names listed here, so the payload shape of every
/// other error is unchanged.
fn errHint(name: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, name, "BadArgv")) return "argv must be a non-empty array of strings";
    if (std.mem.eql(u8, name, "InvalidPadding")) return "value is not valid standard base64 (bad length or padding)";
    if (std.mem.eql(u8, name, "InvalidCharacter")) return "value is not valid standard base64 (illegal character)";
    if (std.mem.eql(u8, name, "InvalidLength")) return "value is not valid standard base64 (bad length)";
    return null;
}

/// Server-level usage notes returned as `instructions` in the initialize
/// result (the MCP-standard channel for a server-side usage mandate).
/// Kept to a few sentences: agents read it once per session.
const SERVER_INSTRUCTIONS = "Runs commands and file operations on this host. Prefer exec (argv, no shell) over exec_shell (pipes, redirects, shell syntax). For long-running or interactive processes: exec_start, then exec_poll; always exec_close, sessions persist across requests. Auth: X-Node-Token header or Authorization: Bearer.";

/// The static tools/list manifest. Order is part of the frozen v0 contract
/// (deterministic order is also cache-friendly for clients); property
/// descriptions mirror the defaults and clamps implemented in tools.zig.
const TOOLS_JSON =
    \\{"tools":[
    \\{"name":"sys_info","title":"System Info","description":"Host summary: hostname, OS, load, memory, root disk (disk_root: total/used/free bytes), uptime. No arguments, read-only; use as a connectivity check.","inputSchema":{"type":"object","properties":{}},"outputSchema":{"type":"object","properties":{"node":{"type":"string"},"hostname":{"type":"string"},"os":{"type":"string"},"machine":{"type":"string"},"loadavg_raw":{"type":"string"},"uptime_raw":{"type":"string"},"mem":{"type":"object","properties":{"MemTotal":{"type":"integer"},"MemAvailable":{"type":"integer"}},"required":["MemTotal","MemAvailable"]},"disk_root":{"type":"object","properties":{"total":{"type":"integer"},"used":{"type":"integer"},"free":{"type":"integer"}},"required":["total","used","free"]}},"required":["node","hostname","os","machine","loadavg_raw","uptime_raw","mem","disk_root"]},"annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false}},
    \\{"name":"exec","title":"Run Command (no shell)","description":"Run argv to exit, no shell: metacharacters are data. Shell syntax: exec_shell. Long-running or interactive: exec_start. timeout in seconds, default 120, clamped to [1, 1800]. Invalid UTF-8 in stdout/stderr becomes U+FFFD.","inputSchema":{"type":"object","properties":{"argv":{"type":"array","items":{"type":"string"},"description":"Program and arguments, e.g. [\"df\", \"-h\", \"/\"]. Passed verbatim."},"cwd":{"type":"string","description":"Child working directory; omit to inherit."},"timeout":{"type":"integer","description":"Kill after this many seconds (1..1800, default 120)."}},"required":["argv"]},"outputSchema":{"type":"object","properties":{"ok":{"type":"boolean"},"exit_code":{"type":"integer"},"stdout":{"type":"string"},"stderr":{"type":"string"},"duration_ms":{"type":"integer"},"duration_us":{"type":"integer"},"timeout":{"type":"boolean"},"error":{"type":"string"}},"required":["ok"]},"annotations":{"readOnlyHint":false,"destructiveHint":true,"idempotentHint":false,"openWorldHint":true}},
    \\{"name":"exec_start","title":"Start Session","description":"Start a process as a session; returns session_id at once. Use when it outlives the call, streams output or reads stdin (exec_write). Then exec_poll, exec_wait, exec_kill, exec_close. Sessions persist across requests; finished ones are reaped after the session TTL.","inputSchema":{"type":"object","properties":{"argv":{"type":"array","items":{"type":"string"},"description":"Program and arguments, e.g. [\"python3\", \"-i\"]. Passed verbatim."},"cwd":{"type":"string","description":"Child working directory; omit to inherit."}},"required":["argv"]},"outputSchema":{"type":"object","properties":{"ok":{"type":"boolean"},"session_id":{"type":"integer"},"pid":{"type":"integer"},"error":{"type":"string"}},"required":["ok"]},"annotations":{"readOnlyHint":false,"destructiveHint":true,"idempotentHint":false,"openWorldHint":true}},
    \\{"name":"exec_poll","title":"Poll Session","description":"Read new session output from byte offsets: stdout/stderr deltas, done, exit_code, truncation flags. Pass back the offsets from the previous reply to resume. Same payload as exec_wait.","inputSchema":{"type":"object","properties":{"session_id":{"type":"integer","description":"Positive id from exec_start."},"stdout_offset":{"type":"integer","description":"Stdout byte offset to resume from, as returned by the previous poll (default 0)."},"stderr_offset":{"type":"integer","description":"Stderr byte offset to resume from, as returned by the previous poll (default 0)."}},"required":["session_id"]},"outputSchema":{"type":"object","properties":{"ok":{"type":"boolean"},"done":{"type":"boolean"},"exit_code":{"type":["integer","null"]},"stdout":{"type":"string"},"stderr":{"type":"string"},"stdout_offset":{"type":"integer"},"stderr_offset":{"type":"integer"},"truncated_stdout":{"type":"boolean"},"truncated_stderr":{"type":"boolean"},"duration_ms":{"type":"integer"},"duration_us":{"type":"integer"},"error":{"type":"string"}},"required":["ok"]},"annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false}},
    \\{"name":"exec_write","title":"Write To Session","description":"Write bytes to session stdin; eof=true closes stdin afterwards. For interactive programs started by exec_start.","inputSchema":{"type":"object","properties":{"session_id":{"type":"integer","description":"Positive id from exec_start."},"data_b64":{"type":"string","description":"Standard base64 of bytes for stdin; may be empty."},"eof":{"type":"boolean","description":"Close stdin after writing (default false)."}},"required":["session_id","data_b64"]},"outputSchema":{"type":"object","properties":{"ok":{"type":"boolean"},"bytes":{"type":"integer"},"eof":{"type":"boolean"},"error":{"type":"string"}},"required":["ok"]},"annotations":{"readOnlyHint":false,"destructiveHint":false,"idempotentHint":false,"openWorldHint":false}},
    \\{"name":"exec_kill","title":"Kill Session","description":"Kill the session's process tree (POSIX: SIGKILL to the process group; Windows: job object). Safe on a dead session. Output stays pollable; free with exec_close.","inputSchema":{"type":"object","properties":{"session_id":{"type":"integer","description":"Positive id from exec_start."}},"required":["session_id"]},"outputSchema":{"type":"object","properties":{"ok":{"type":"boolean"},"error":{"type":"string"}},"required":["ok"]},"annotations":{"readOnlyHint":false,"destructiveHint":true,"idempotentHint":false,"openWorldHint":false}},
    \\{"name":"exec_close","title":"Close Session","description":"Kill if running, join threads, free the session. Idempotent: repeat calls return ok, already_closed=true. Close every session you start; sessions persist across requests.","inputSchema":{"type":"object","properties":{"session_id":{"type":"integer","description":"Positive id from exec_start."}},"required":["session_id"]},"outputSchema":{"type":"object","properties":{"ok":{"type":"boolean"},"already_closed":{"type":"boolean"},"error":{"type":"string"}},"required":["ok"]},"annotations":{"readOnlyHint":false,"destructiveHint":true,"idempotentHint":true,"openWorldHint":false}},
    \\{"name":"exec_wait","title":"Wait For Session","description":"Block until the session exits or timeout elapses (default 30s, max 300s). Returns the exec_poll payload with deltas from the given offsets.","inputSchema":{"type":"object","properties":{"session_id":{"type":"integer","description":"Positive id from exec_start."},"timeout":{"type":"integer","description":"Max seconds to wait (1..300, default 30)."},"stdout_offset":{"type":"integer","description":"Stdout byte offset to resume from (default 0)."},"stderr_offset":{"type":"integer","description":"Stderr byte offset to resume from (default 0)."}},"required":["session_id"]},"outputSchema":{"type":"object","properties":{"ok":{"type":"boolean"},"done":{"type":"boolean"},"exit_code":{"type":["integer","null"]},"stdout":{"type":"string"},"stderr":{"type":"string"},"stdout_offset":{"type":"integer"},"stderr_offset":{"type":"integer"},"truncated_stdout":{"type":"boolean"},"truncated_stderr":{"type":"boolean"},"duration_ms":{"type":"integer"},"duration_us":{"type":"integer"},"error":{"type":"string"}},"required":["ok"]},"annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false}},
    \\{"name":"exec_list","title":"List Sessions","description":"List live sessions: session_id, pid, argv, done, exit_code, timestamps. No arguments. Recovers ids after a lost reply.","inputSchema":{"type":"object","properties":{}},"outputSchema":{"type":"object","properties":{"ok":{"type":"boolean"},"sessions":{"type":"array","items":{"type":"object","properties":{"session_id":{"type":"integer"},"pid":{"type":"integer"},"argv":{"type":"array","items":{"type":"string"}},"done":{"type":"boolean"},"exit_code":{"type":["integer","null"]},"started_ms":{"type":"integer"},"ended_ms":{"type":["integer","null"]}},"required":["session_id","pid","argv","done","exit_code","started_ms","ended_ms"]}},"error":{"type":"string"}},"required":["ok"]},"annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false}},
    \\{"name":"exec_shell","title":"Run Shell Script","description":"Run one script through one shell (POSIX: bash/sh/fish/zsh -c; Windows: cmd /c, powershell -c). Only for shell syntax: pipes, redirects, &&, globs; otherwise exec. timeout in seconds, default 120, clamped to [1, 1800]. Invalid UTF-8 in stdout/stderr becomes U+FFFD.","inputSchema":{"type":"object","properties":{"script":{"type":"string","description":"Script passed to the shell, e.g. \"du -sh /var/log | sort -h\"."},"shell":{"type":"string","description":"POSIX: bash (default), sh, fish, zsh. Windows: cmd (default), powershell."},"timeout":{"type":"integer","description":"Kill after this many seconds (1..1800, default 120)."},"cwd":{"type":"string","description":"Child working directory; omit to inherit."}},"required":["script"]},"outputSchema":{"type":"object","properties":{"ok":{"type":"boolean"},"exit_code":{"type":"integer"},"stdout":{"type":"string"},"stderr":{"type":"string"},"duration_ms":{"type":"integer"},"duration_us":{"type":"integer"},"timeout":{"type":"boolean"},"error":{"type":"string"}},"required":["ok"]},"annotations":{"readOnlyHint":false,"destructiveHint":true,"idempotentHint":false,"openWorldHint":true}},
    \\{"name":"read_file","title":"Read File","description":"Read a text file as UTF-8 (invalid bytes replaced): size, offset, content, has_more. offset/limit count characters, not bytes. Default limit 200000; files over 64 MiB are rejected.","inputSchema":{"type":"object","properties":{"path":{"type":"string","description":"File path; \"~\" expands to home."},"offset":{"type":"integer","description":"Start character (default 0)."},"limit":{"type":"integer","description":"Max characters (default 200000)."}},"required":["path"]},"outputSchema":{"type":"object","properties":{"ok":{"type":"boolean"},"path":{"type":"string"},"size":{"type":"integer"},"offset":{"type":"integer"},"content":{"type":"string"},"has_more":{"type":"boolean"},"error":{"type":"string"}},"required":["ok"]},"annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false}},
    \\{"name":"write_file","title":"Write File","description":"Write base64 content to a file, overwriting; creates parent dirs by default. Returns size and sha256 of the written bytes.","inputSchema":{"type":"object","properties":{"path":{"type":"string","description":"File path; \"~\" expands to home."},"content_b64":{"type":"string","description":"Standard base64 file content."},"mode":{"type":"integer","description":"POSIX permission bits for the new file, 0..0o7777 (default 0o644; ignored on Windows)."},"mkdirs":{"type":"boolean","description":"Create missing parent directories (default true)."}},"required":["path","content_b64"]},"outputSchema":{"type":"object","properties":{"ok":{"type":"boolean"},"path":{"type":"string"},"size":{"type":"integer"},"sha256":{"type":"string"},"error":{"type":"string"}},"required":["ok"]},"annotations":{"readOnlyHint":false,"destructiveHint":true,"idempotentHint":false,"openWorldHint":false}},
    \\{"name":"list_dir","title":"List Directory","description":"List directory entries sorted by name: name, type (d dir, l symlink, f file), size in bytes, mtime in Unix seconds. Max 2000 per call; truncated=true if more.","inputSchema":{"type":"object","properties":{"path":{"type":"string","description":"Directory; \"~\" expands to home; default: working directory."}}},"outputSchema":{"type":"object","properties":{"ok":{"type":"boolean"},"path":{"type":"string"},"items":{"type":"array","items":{"type":"object","properties":{"name":{"type":"string"},"type":{"type":"string"},"size":{"type":"integer"},"mtime":{"type":"integer"}},"required":["name","type","size","mtime"]}},"count":{"type":"integer"},"truncated":{"type":"boolean"},"has_more":{"type":"boolean"},"error":{"type":"string"}},"required":["ok"]},"annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false}}
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

// ---------------------------------------------------------------------------
// Shape-validation matrix: envelope/id/params/method rules, the initialize
// protocolVersion contract, the tools/list manifest shape, and the errHint
// payload contract for tool-domain errors.
// ---------------------------------------------------------------------------

test "rpc request envelope validation matrix" {
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

    // Every envelope-level rejection is a 400 with -32600; the id is echoed
    // when its own type is legal and rendered as null otherwise.
    const H = struct {
        fn expectInvalidRequest(a: Allocator, i: Io, c: *const config.Config, req: []const u8) !Value {
            const resp = try handleRpc(a, i, c, req);
            try std.testing.expectEqual(@as(u16, 400), resp.status);
            const parsed = try std.json.parseFromSliceLeaky(Value, a, resp.body, .{});
            try std.testing.expect(parsed.object.get("error") != null);
            try std.testing.expectEqual(@as(i32, -32600), parsed.object.get("error").?.object.get("code").?.integer);
            return parsed;
        }
    };

    {
        // Wrong jsonrpc version.
        const parsed = try H.expectInvalidRequest(arena, io, &cfg, "{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"ping\"}");
        try std.testing.expectEqual(@as(i64, 1), parsed.object.get("id").?.integer);
    }
    {
        // Missing jsonrpc member.
        const parsed = try H.expectInvalidRequest(arena, io, &cfg, "{\"id\":1,\"method\":\"ping\"}");
        try std.testing.expectEqual(@as(i64, 1), parsed.object.get("id").?.integer);
    }
    {
        // Non-string jsonrpc member (2.0 as a number).
        const parsed = try H.expectInvalidRequest(arena, io, &cfg, "{\"jsonrpc\":2.0,\"id\":1,\"method\":\"ping\"}");
        try std.testing.expectEqual(@as(i64, 1), parsed.object.get("id").?.integer);
    }
    {
        // Non-object request bodies are invalid with a null id.
        const parsed = try H.expectInvalidRequest(arena, io, &cfg, "[1,2,3]");
        try std.testing.expect(parsed.object.get("id").? == .null);
        const parsed_str = try H.expectInvalidRequest(arena, io, &cfg, "\"x\"");
        try std.testing.expect(parsed_str.object.get("id").? == .null);
    }
    {
        // Missing method member.
        const parsed = try H.expectInvalidRequest(arena, io, &cfg, "{\"jsonrpc\":\"2.0\",\"id\":1}");
        try std.testing.expectEqual(@as(i64, 1), parsed.object.get("id").?.integer);
    }
    {
        // Non-string method member.
        const parsed = try H.expectInvalidRequest(arena, io, &cfg, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":42}");
        try std.testing.expectEqual(@as(i64, 1), parsed.object.get("id").?.integer);
    }
    {
        // Scalar params make the whole message invalid, even for a known method.
        const parsed = try H.expectInvalidRequest(arena, io, &cfg, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\",\"params\":42}");
        try std.testing.expectEqual(@as(i64, 1), parsed.object.get("id").?.integer);
    }
    {
        // params:null is tolerated as "omitted": ping still succeeds.
        const resp = try handleRpc(arena, io, &cfg, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\",\"params\":null}");
        try std.testing.expectEqual(@as(u16, 200), resp.status);
        const parsed = try std.json.parseFromSliceLeaky(Value, arena, resp.body, .{});
        try std.testing.expect(parsed.object.get("result").? == .object);
        try std.testing.expect(parsed.object.get("error") == null);
    }
    {
        // An array params is shape-legal at the envelope level; ping ignores it.
        const resp = try handleRpc(arena, io, &cfg, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\",\"params\":[]}");
        try std.testing.expectEqual(@as(u16, 200), resp.status);
        const parsed = try std.json.parseFromSliceLeaky(Value, arena, resp.body, .{});
        try std.testing.expect(parsed.object.get("result").? == .object);
    }
}

test "rpc id typing rules" {
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

    {
        // An object id is illegal: the error envelope carries a null id.
        const resp = try handleRpc(arena, io, &cfg, "{\"jsonrpc\":\"2.0\",\"id\":{},\"method\":\"ping\"}");
        try std.testing.expectEqual(@as(u16, 400), resp.status);
        const parsed = try std.json.parseFromSliceLeaky(Value, arena, resp.body, .{});
        try std.testing.expectEqual(@as(i32, -32600), parsed.object.get("error").?.object.get("code").?.integer);
        try std.testing.expect(parsed.object.get("id").? == .null);
    }
    {
        // An array id is equally illegal.
        const resp = try handleRpc(arena, io, &cfg, "{\"jsonrpc\":\"2.0\",\"id\":[],\"method\":\"ping\"}");
        try std.testing.expectEqual(@as(u16, 400), resp.status);
        const parsed = try std.json.parseFromSliceLeaky(Value, arena, resp.body, .{});
        try std.testing.expectEqual(@as(i32, -32600), parsed.object.get("error").?.object.get("code").?.integer);
        try std.testing.expect(parsed.object.get("id").? == .null);
    }
    {
        // A string id is echoed back.
        const resp = try handleRpc(arena, io, &cfg, "{\"jsonrpc\":\"2.0\",\"id\":\"echo\",\"method\":\"ping\"}");
        try std.testing.expectEqual(@as(u16, 200), resp.status);
        const parsed = try std.json.parseFromSliceLeaky(Value, arena, resp.body, .{});
        try std.testing.expectEqualStrings("echo", parsed.object.get("id").?.string);
        try std.testing.expect(parsed.object.get("result").? == .object);
    }
    {
        // An integer id is echoed back.
        const resp = try handleRpc(arena, io, &cfg, "{\"jsonrpc\":\"2.0\",\"id\":42,\"method\":\"ping\"}");
        try std.testing.expectEqual(@as(u16, 200), resp.status);
        const parsed = try std.json.parseFromSliceLeaky(Value, arena, resp.body, .{});
        try std.testing.expectEqual(@as(i64, 42), parsed.object.get("id").?.integer);
        try std.testing.expect(parsed.object.get("result").? == .object);
    }
    {
        // A present null id is a discouraged but legal id: answered with the
        // echoed null, never treated as a notification.
        const resp = try handleRpc(arena, io, &cfg, "{\"jsonrpc\":\"2.0\",\"id\":null,\"method\":\"ping\"}");
        try std.testing.expectEqual(@as(u16, 200), resp.status);
        const parsed = try std.json.parseFromSliceLeaky(Value, arena, resp.body, .{});
        try std.testing.expect(parsed.object.get("id") != null);
        try std.testing.expect(parsed.object.get("id").? == .null);
        try std.testing.expect(parsed.object.get("result").? == .object);
    }
    {
        // An absent id is the notification marker: 202 with an empty body.
        const resp = try handleRpc(arena, io, &cfg, "{\"jsonrpc\":\"2.0\",\"method\":\"ping\"}");
        try std.testing.expectEqual(@as(u16, 202), resp.status);
        try std.testing.expectEqual(@as(usize, 0), resp.body.len);
    }
}

test "rpc notifications carrying an id are invalid requests" {
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

    {
        // notifications/* with an integer id must be answered 400/-32600,
        // never silently dropped via 202.
        const resp = try handleRpc(arena, io, &cfg, "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"notifications/progress\"}");
        try std.testing.expectEqual(@as(u16, 400), resp.status);
        const parsed = try std.json.parseFromSliceLeaky(Value, arena, resp.body, .{});
        try std.testing.expectEqual(@as(i32, -32600), parsed.object.get("error").?.object.get("code").?.integer);
        try std.testing.expectEqual(@as(i64, 5), parsed.object.get("id").?.integer);
    }
    {
        // Same rule with a string id, on a different notifications method.
        const resp = try handleRpc(arena, io, &cfg, "{\"jsonrpc\":\"2.0\",\"id\":\"n\",\"method\":\"notifications/initialized\"}");
        try std.testing.expectEqual(@as(u16, 400), resp.status);
        const parsed = try std.json.parseFromSliceLeaky(Value, arena, resp.body, .{});
        try std.testing.expectEqual(@as(i32, -32600), parsed.object.get("error").?.object.get("code").?.integer);
        try std.testing.expectEqualStrings("n", parsed.object.get("id").?.string);
    }
    {
        // Without an id the same method is a notification: 202, empty body.
        const resp = try handleRpc(arena, io, &cfg, "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}");
        try std.testing.expectEqual(@as(u16, 202), resp.status);
        try std.testing.expectEqual(@as(usize, 0), resp.body.len);
    }
}

test "rpc unknown method and empty list results" {
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

    {
        // Unknown method is a method-level error: HTTP 200, -32601, id echoed.
        const resp = try handleRpc(arena, io, &cfg, "{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"no/such/method\"}");
        try std.testing.expectEqual(@as(u16, 200), resp.status);
        const parsed = try std.json.parseFromSliceLeaky(Value, arena, resp.body, .{});
        const err_obj = parsed.object.get("error").?;
        try std.testing.expectEqual(@as(i32, -32601), err_obj.object.get("code").?.integer);
        try std.testing.expectEqualStrings("Method not found", err_obj.object.get("message").?.string);
        try std.testing.expectEqual(@as(i64, 9), parsed.object.get("id").?.integer);
    }
    {
        // ping answers with an empty result object.
        const resp = try handleRpc(arena, io, &cfg, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}");
        try std.testing.expectEqual(@as(u16, 200), resp.status);
        const parsed = try std.json.parseFromSliceLeaky(Value, arena, resp.body, .{});
        const result = parsed.object.get("result").?;
        try std.testing.expect(result == .object);
        try std.testing.expectEqual(@as(usize, 0), result.object.count());
    }
    {
        // resources/list answers with an empty resources array.
        const resp = try handleRpc(arena, io, &cfg, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"resources/list\"}");
        try std.testing.expectEqual(@as(u16, 200), resp.status);
        const parsed = try std.json.parseFromSliceLeaky(Value, arena, resp.body, .{});
        const resources = parsed.object.get("result").?.object.get("resources").?;
        try std.testing.expect(resources == .array);
        try std.testing.expectEqual(@as(usize, 0), resources.array.items.len);
    }
    {
        // prompts/list answers with an empty prompts array.
        const resp = try handleRpc(arena, io, &cfg, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"prompts/list\"}");
        try std.testing.expectEqual(@as(u16, 200), resp.status);
        const parsed = try std.json.parseFromSliceLeaky(Value, arena, resp.body, .{});
        const prompts = parsed.object.get("result").?.object.get("prompts").?;
        try std.testing.expect(prompts == .array);
        try std.testing.expectEqual(@as(usize, 0), prompts.array.items.len);
    }
}

test "rpc initialize protocol version matrix" {
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

    {
        // No params: the node answers with its default protocol version and
        // the full result shape.
        const resp = try handleRpc(arena, io, &cfg, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}");
        try std.testing.expectEqual(@as(u16, 200), resp.status);
        const parsed = try std.json.parseFromSliceLeaky(Value, arena, resp.body, .{});
        try std.testing.expectEqualStrings("2.0", parsed.object.get("jsonrpc").?.string);
        try std.testing.expectEqual(@as(i64, 1), parsed.object.get("id").?.integer);
        const result = parsed.object.get("result").?;
        try std.testing.expectEqualStrings("2025-11-25", result.object.get("protocolVersion").?.string);
        const capabilities = result.object.get("capabilities").?;
        try std.testing.expect(capabilities == .object);
        try std.testing.expect(capabilities.object.get("tools").? == .object);
        const server_info = result.object.get("serverInfo").?;
        try std.testing.expect(server_info == .object);
        try std.testing.expectEqualStrings("test-node", server_info.object.get("name").?.string);
        try std.testing.expect(server_info.object.get("version").? == .string);
        const instructions = result.object.get("instructions").?;
        try std.testing.expect(instructions == .string);
        try std.testing.expect(instructions.string.len > 0);
    }
    {
        // Each supported version is echoed back verbatim.
        const supported = [_][]const u8{ "2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25" };
        for (supported) |ver| {
            const req = try std.fmt.allocPrint(arena, "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{{\"protocolVersion\":\"{s}\"}}}}", .{ver});
            const resp = try handleRpc(arena, io, &cfg, req);
            try std.testing.expectEqual(@as(u16, 200), resp.status);
            const parsed = try std.json.parseFromSliceLeaky(Value, arena, resp.body, .{});
            try std.testing.expectEqualStrings(ver, parsed.object.get("result").?.object.get("protocolVersion").?.string);
        }
    }
    {
        // Unsupported versions fall back to the default instead of failing.
        const resp = try handleRpc(arena, io, &cfg, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"1999-01-01\"}}");
        try std.testing.expectEqual(@as(u16, 200), resp.status);
        const parsed = try std.json.parseFromSliceLeaky(Value, arena, resp.body, .{});
        try std.testing.expectEqualStrings("2025-11-25", parsed.object.get("result").?.object.get("protocolVersion").?.string);
    }
    {
        // A non-string protocolVersion is ignored: default.
        const resp = try handleRpc(arena, io, &cfg, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":42}}");
        try std.testing.expectEqual(@as(u16, 200), resp.status);
        const parsed = try std.json.parseFromSliceLeaky(Value, arena, resp.body, .{});
        try std.testing.expectEqualStrings("2025-11-25", parsed.object.get("result").?.object.get("protocolVersion").?.string);
    }
    {
        // params:null is tolerated and yields the default version.
        const resp = try handleRpc(arena, io, &cfg, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":null}");
        try std.testing.expectEqual(@as(u16, 200), resp.status);
        const parsed = try std.json.parseFromSliceLeaky(Value, arena, resp.body, .{});
        try std.testing.expectEqualStrings("2025-11-25", parsed.object.get("result").?.object.get("protocolVersion").?.string);
    }
}

test "rpc tools list manifest shape" {
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

    {
        const resp = try handleRpc(arena, io, &cfg, "{\"jsonrpc\":\"2.0\",\"id\":\"t\",\"method\":\"tools/list\"}");
        try std.testing.expectEqual(@as(u16, 200), resp.status);
        const parsed = try std.json.parseFromSliceLeaky(Value, arena, resp.body, .{});
        try std.testing.expectEqualStrings("t", parsed.object.get("id").?.string);
        const tools_v = parsed.object.get("result").?.object.get("tools").?;
        try std.testing.expect(tools_v == .array);
        // The frozen v0 manifest carries 13 tools in a deterministic order.
        try std.testing.expectEqual(@as(usize, 13), tools_v.array.items.len);
        for (tools_v.array.items) |entry| {
            try std.testing.expect(entry == .object);
            const name = entry.object.get("name").?;
            try std.testing.expect(name == .string);
            try std.testing.expect(name.string.len > 0);
            const schema = entry.object.get("inputSchema").?;
            try std.testing.expect(schema == .object);
        }
    }
}

test "rpc tools call params shape validation" {
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

    const H = struct {
        fn expectInvalidParams(a: Allocator, i: Io, c: *const config.Config, req: []const u8) !void {
            const resp = try handleRpc(a, i, c, req);
            try std.testing.expectEqual(@as(u16, 200), resp.status);
            const parsed = try std.json.parseFromSliceLeaky(Value, a, resp.body, .{});
            try std.testing.expect(parsed.object.get("error") != null);
            try std.testing.expectEqual(@as(i32, -32602), parsed.object.get("error").?.object.get("code").?.integer);
        }
    };

    // params missing / not an object / null.
    try H.expectInvalidParams(arena, io, &cfg, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\"}");
    try H.expectInvalidParams(arena, io, &cfg, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":[1]}");
    try H.expectInvalidParams(arena, io, &cfg, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":null}");
    // name missing / not a string.
    try H.expectInvalidParams(arena, io, &cfg, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{}}");
    try H.expectInvalidParams(arena, io, &cfg, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":7}}");
    // arguments present but not an object.
    try H.expectInvalidParams(arena, io, &cfg, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"exec\",\"arguments\":5}}");
    {
        // One representative error: code, message and id echo.
        const resp = try handleRpc(arena, io, &cfg, "{\"jsonrpc\":\"2.0\",\"id\":\"ip\",\"method\":\"tools/call\"}");
        try std.testing.expectEqual(@as(u16, 200), resp.status);
        const parsed = try std.json.parseFromSliceLeaky(Value, arena, resp.body, .{});
        const err_obj = parsed.object.get("error").?;
        try std.testing.expectEqual(@as(i32, -32602), err_obj.object.get("code").?.integer);
        try std.testing.expectEqualStrings("Invalid params", err_obj.object.get("message").?.string);
        try std.testing.expectEqualStrings("ip", parsed.object.get("id").?.string);
    }
    {
        // Unknown tool: isError result with a self-recovery hint.
        const resp = try handleRpc(arena, io, &cfg, "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\",\"params\":{\"name\":\"no_such_tool\",\"arguments\":{}}}");
        try std.testing.expectEqual(@as(u16, 200), resp.status);
        const parsed = try std.json.parseFromSliceLeaky(Value, arena, resp.body, .{});
        try std.testing.expectEqual(@as(i64, 7), parsed.object.get("id").?.integer);
        const result = parsed.object.get("result").?;
        try std.testing.expect(result.object.get("isError") != null);
        try std.testing.expect(result.object.get("isError").?.bool);
        const text = result.object.get("content").?.array.items[0].object.get("text").?.string;
        try std.testing.expect(std.mem.indexOf(u8, text, "Unknown tool:") != null);
        try std.testing.expect(std.mem.indexOf(u8, text, "tools/list") != null);
    }
}

test "rpc tool error payload hints" {
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

    const H = struct {
        // Run one tools/call and return the 200 response body.
        fn call(a: Allocator, i: Io, c: *const config.Config, req: []const u8) ![]const u8 {
            const resp = try handleRpc(a, i, c, req);
            try std.testing.expectEqual(@as(u16, 200), resp.status);
            return resp.body;
        }

        // A failed tool call carries a structuredContent payload with the
        // error name and, for hint-listed names, a readable message.
        fn expectErrorPayload(payload: Value, want_name: []const u8, want_hint: []const u8) !void {
            try std.testing.expectEqualStrings(want_name, payload.object.get("error").?.string);
            try std.testing.expect(payload.object.get("message") != null);
            try std.testing.expectEqualStrings(want_hint, payload.object.get("message").?.string);
            try std.testing.expect(!payload.object.get("ok").?.bool);
        }

        // Error names outside the hint set keep the bare payload shape: no
        // "message" member is added (the hint map is additive-only).
        fn expectNoHint(payload: Value, want_name: []const u8) !void {
            try std.testing.expectEqualStrings(want_name, payload.object.get("error").?.string);
            try std.testing.expect(payload.object.get("message") == null);
            try std.testing.expect(!payload.object.get("ok").?.bool);
        }
    };

    {
        // BadArgv: argv present but not an array.
        const body = try H.call(arena, io, &cfg, "{\"jsonrpc\":\"2.0\",\"id\":\"a\",\"method\":\"tools/call\",\"params\":{\"name\":\"exec\",\"arguments\":{\"argv\":42}}}");
        const parsed = try std.json.parseFromSliceLeaky(Value, arena, body, .{});
        const payload = parsed.object.get("result").?.object.get("structuredContent").?;
        try H.expectErrorPayload(payload, "BadArgv", "argv must be a non-empty array of strings");
        // The unescaped hint text reaches the raw body via structuredContent.
        try std.testing.expect(std.mem.indexOf(u8, body, "\"message\":\"argv must be a non-empty array of strings\"") != null);
        // Tool-domain errors ride a 200 result envelope with isError:false;
        // the ok:false payload is the error channel.
        try std.testing.expect(!parsed.object.get("result").?.object.get("isError").?.bool);
    }
    {
        // BadArgv: an empty argv array.
        const body = try H.call(arena, io, &cfg, "{\"jsonrpc\":\"2.0\",\"id\":\"a\",\"method\":\"tools/call\",\"params\":{\"name\":\"exec\",\"arguments\":{\"argv\":[]}}}");
        const parsed = try std.json.parseFromSliceLeaky(Value, arena, body, .{});
        try H.expectErrorPayload(parsed.object.get("result").?.object.get("structuredContent").?, "BadArgv", "argv must be a non-empty array of strings");
    }
    {
        // BadArgv: non-string argv items.
        const body = try H.call(arena, io, &cfg, "{\"jsonrpc\":\"2.0\",\"id\":\"a\",\"method\":\"tools/call\",\"params\":{\"name\":\"exec\",\"arguments\":{\"argv\":[1]}}}");
        const parsed = try std.json.parseFromSliceLeaky(Value, arena, body, .{});
        try H.expectErrorPayload(parsed.object.get("result").?.object.get("structuredContent").?, "BadArgv", "argv must be a non-empty array of strings");
    }
    {
        // argv entirely absent: actual behavior is MissingArgv, which is not
        // in the hint set - the hint covers argv shapes that fail validation,
        // not the missing member itself.
        const body = try H.call(arena, io, &cfg, "{\"jsonrpc\":\"2.0\",\"id\":\"m\",\"method\":\"tools/call\",\"params\":{\"name\":\"exec\",\"arguments\":{}}}");
        const parsed = try std.json.parseFromSliceLeaky(Value, arena, body, .{});
        try H.expectNoHint(parsed.object.get("result").?.object.get("structuredContent").?, "MissingArgv");
    }
    {
        // write_file with an illegal base64 character: InvalidCharacter
        // plus its matching hint.
        const body = try H.call(arena, io, &cfg, "{\"jsonrpc\":\"2.0\",\"id\":\"b\",\"method\":\"tools/call\",\"params\":{\"name\":\"write_file\",\"arguments\":{\"path\":\"unused-probe\",\"content_b64\":\"!!!!\"}}}");
        const parsed = try std.json.parseFromSliceLeaky(Value, arena, body, .{});
        try H.expectErrorPayload(parsed.object.get("result").?.object.get("structuredContent").?, "InvalidCharacter", "value is not valid standard base64 (illegal character)");
    }
    {
        // write_file with a bad base64 length: InvalidPadding plus its
        // matching hint.
        const body = try H.call(arena, io, &cfg, "{\"jsonrpc\":\"2.0\",\"id\":\"b\",\"method\":\"tools/call\",\"params\":{\"name\":\"write_file\",\"arguments\":{\"path\":\"unused-probe\",\"content_b64\":\"ABCDE\"}}}");
        const parsed = try std.json.parseFromSliceLeaky(Value, arena, body, .{});
        try H.expectErrorPayload(parsed.object.get("result").?.object.get("structuredContent").?, "InvalidPadding", "value is not valid standard base64 (bad length or padding)");
    }
    {
        // FileNotFound is outside the hint set: bare payload shape.
        const body = try H.call(arena, io, &cfg, "{\"jsonrpc\":\"2.0\",\"id\":\"f\",\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\",\"arguments\":{\"path\":\"/nonexistent-mcpnz-hints\"}}}");
        const parsed = try std.json.parseFromSliceLeaky(Value, arena, body, .{});
        try H.expectNoHint(parsed.object.get("result").?.object.get("structuredContent").?, "FileNotFound");
    }
}
