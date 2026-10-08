//! Per-token argument gating: the policy file parser, the in-memory policy
//! set, path canonicalisation, and the per-call checks. Loaded only when
//! MCP_NODE_POLICY_FILE is set; without it the node is exactly v0.3.1.
//!
//! Design contract: docs/arg-gating.md (format, semantics, threat model).
//! Strict parsing: every malformed input is a named config error; unknown
//! keys are errors, never silently ignored.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Value = std.json.Value;
const os = @import("os.zig");
const env_state = @import("env_state.zig");

pub const POLICY_FILE_MAX_BYTES: usize = 256 * 1024;
pub const MAX_TOKENS: usize = 64;
pub const MAX_PREFIXES: usize = 64;
pub const MAX_ARGV0: usize = 64;
pub const MAX_TOOLS: usize = 16;
/// Longest token-file path / prefix / argv0 accepted in the file. Strict
/// caps keep the arena load bounded and the error naming precise.
pub const MAX_ENTRY_STR: usize = 512;

pub const DenyReason = enum {
    tool_not_allowed,
    argv0_not_allowed,
    cwd_not_allowed,
    path_not_allowed,
    denied_path,
    timeout_exceeds_cap,
    write_mode_exceeds_cap,
    session_not_owned,

    pub fn text(self: DenyReason) []const u8 {
        return switch (self) {
            .tool_not_allowed => "tool is not in this token's allowlist",
            .argv0_not_allowed => "program is not in this token's argv[0] allowlist",
            .cwd_not_allowed => "cwd is outside this token's allowed prefixes",
            .path_not_allowed => "path is outside this token's allowed prefixes",
            .denied_path => "path is in this token's deny list",
            .timeout_exceeds_cap => "timeout exceeds this token's cap",
            .write_mode_exceeds_cap => "mode exceeds this token's write mode cap",
            .session_not_owned => "session belongs to another token",
        };
    }
};

/// One argv[0] allowlist entry. `path` entries (containing '/') are
/// canonicalised at load; `bare` entries (no '/') are matched exactly.
const Argv0Entry = struct {
    text: []const u8,
    has_slash: bool,
};

pub const TokenPolicy = struct {
    /// Path of the token file this entry was loaded from (audit/fingerprint
    /// surface; the token VALUE never leaves loadPolicyFile).
    file: []const u8,
    /// sha256 of the trimmed token value; timing-safe compared per request.
    token_hash: [32]u8,
    /// v0.3.1-equivalent: every check passes (admin escape hatch).
    allow_all: bool = false,
    /// Exact tool names or "*"; absent tool = default-deny.
    tools: []const []const u8,
    exec_argv0: []const Argv0Entry,
    /// Empty = caller may not pass cwd at all (inherit stays allowed).
    exec_cwd: []const []const u8,
    cwd_deny: []const []const u8,
    max_timeout_s: ?i64 = null,
    read_paths: []const []const u8,
    write_paths: []const []const u8,
    read_deny: []const []const u8,
    write_deny: []const []const u8,
    write_max_mode: ?u32 = null,

    fn toolAllowed(self: *const TokenPolicy, tool: []const u8) bool {
        for (self.tools) |t| {
            if (std.mem.eql(u8, t, "*")) return true;
            if (std.mem.eql(u8, t, tool)) return true;
        }
        return false;
    }

    fn needsExec(self: *const TokenPolicy) bool {
        return self.toolAllowed("exec") or self.toolAllowed("exec_start") or self.toolAllowed("exec_shell");
    }

    fn needsRead(self: *const TokenPolicy) bool {
        return self.toolAllowed("read_file") or self.toolAllowed("list_dir");
    }

    fn needsWrite(self: *const TokenPolicy) bool {
        return self.toolAllowed("write_file");
    }
};

pub const PolicySet = struct {
    /// Arena backing every slice; freed by deinit.
    arena_state: std.heap.ArenaAllocator,
    entries: []TokenPolicy,
    /// sha256 of the canonical policy file bytes (config fingerprint).
    file_digest: [32]u8,
    file_path: []const u8,

    pub fn deinit(self: *PolicySet) void {
        self.arena_state.deinit();
    }
};

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

pub const LoadError = error{
    InvalidPolicy,
    OutOfMemory,
} || std.Io.Dir.RealPathFileError;

fn policyErr(comptime fmt: []const u8, args: anytype) LoadError {
    std.debug.print("policy: " ++ fmt ++ "\n", args);
    return error.InvalidPolicy;
}

/// Load and strictly parse the policy file. `io` is the process Io; the file
/// must be 0600 like every other secret file the node reads.
pub fn loadPolicyFile(arena: Allocator, io: Io, path: []const u8) LoadError!PolicySet {
    var arena_state = std.heap.ArenaAllocator.init(arena);
    errdefer arena_state.deinit();
    const a = arena_state.allocator();

    os.fd.checkPrivateFileMode(io, path) catch {
        return policyErr("file '{s}' must not grant group/other access (0600)", .{path});
    };
    const raw = os.fd.readFileAlloc(a, io, path, POLICY_FILE_MAX_BYTES) catch |err| {
        return policyErr("cannot read '{s}': {s}", .{ path, @errorName(err) });
    };
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(raw, &digest, .{});

    const parsed = std.json.parseFromSliceLeaky(Value, a, raw, .{}) catch {
        return policyErr("file is not valid JSON", .{});
    };
    if (parsed != .object) return policyErr("top level must be an object", .{});
    const obj = parsed.object;

    const version = obj.get("version") orelse return policyErr("'version' is required", .{});
    if (version != .integer or version.integer != 1)
        return policyErr("'version' must be the integer 1", .{});

    const tokens_v = obj.get("tokens") orelse return policyErr("'tokens' is required", .{});
    if (tokens_v != .array) return policyErr("'tokens' must be an array", .{});
    if (tokens_v.array.items.len == 0) return policyErr("'tokens' must not be empty", .{});
    if (tokens_v.array.items.len > MAX_TOKENS)
        return policyErr("'tokens' has more than {d} entries", .{MAX_TOKENS});

    // Unknown top-level keys are errors (strict parsing).
    var it = obj.iterator();
    while (it.next()) |kv| {
        const k = kv.key_ptr.*;
        if (!std.mem.eql(u8, k, "version") and !std.mem.eql(u8, k, "tokens"))
            return policyErr("unknown top-level key '{s}'", .{k});
    }

    const entries = try a.alloc(TokenPolicy, tokens_v.array.items.len);
    for (tokens_v.array.items, 0..) |tv, i| {
        entries[i] = try parseEntry(a, io, tv, i);
    }
    return .{ .arena_state = arena_state, .entries = entries, .file_digest = digest, .file_path = try a.dupe(u8, path) };
}

fn strDup(a: Allocator, s: []const u8) ![]const u8 {
    if (s.len > MAX_ENTRY_STR) return error.InvalidPolicy;
    return a.dupe(u8, s);
}

fn parseEntry(a: Allocator, io: Io, tv: Value, idx: usize) LoadError!TokenPolicy {
    if (tv != .object) return policyErr("tokens[{d}] must be an object", .{idx});
    const obj = tv.object;

    const file_v = obj.get("file") orelse return policyErr("tokens[{d}]: 'file' is required", .{idx});
    if (file_v != .string) return policyErr("tokens[{d}]: 'file' must be a string", .{idx});
    const file = try strDup(a, file_v.string);
    if (file.len == 0) return policyErr("tokens[{d}]: 'file' must not be empty", .{idx});

    var tools: []const []const u8 = &.{};
    var exec_argv0: []const Argv0Entry = &.{};
    var exec_cwd: []const []const u8 = &.{};
    var cwd_deny: []const []const u8 = &.{};
    var read_paths: []const []const u8 = &.{};
    var write_paths: []const []const u8 = &.{};
    var read_deny: []const []const u8 = &.{};
    var write_deny: []const []const u8 = &.{};
    var max_timeout_s: ?i64 = null;
    var write_max_mode: ?u32 = null;
    var allow_all = false;
    var has_allow_all = false;
    var restricted_keys = false;

    var it = obj.iterator();
    while (it.next()) |kv| {
        const k = kv.key_ptr.*;
        const v = kv.value_ptr.*;
        if (std.mem.eql(u8, k, "file")) continue;
        if (std.mem.eql(u8, k, "allow_all")) {
            if (v != .bool) return policyErr("tokens[{d}]: 'allow_all' must be a boolean", .{idx});
            allow_all = v.bool;
            has_allow_all = true;
            continue;
        }
        restricted_keys = true;
        if (std.mem.eql(u8, k, "tools")) {
            tools = try parseToolList(a, v, idx);
        } else if (std.mem.eql(u8, k, "exec_argv0")) {
            exec_argv0 = try parseArgv0List(a, io, v, idx);
        } else if (std.mem.eql(u8, k, "exec_cwd")) {
            exec_cwd = try parsePrefixList(a, v, idx, "exec_cwd");
        } else if (std.mem.eql(u8, k, "cwd_deny")) {
            cwd_deny = try parsePrefixList(a, v, idx, "cwd_deny");
        } else if (std.mem.eql(u8, k, "max_timeout_s")) {
            if (v != .integer) return policyErr("tokens[{d}]: 'max_timeout_s' must be an integer", .{idx});
            if (v.integer < 1 or v.integer > 1800)
                return policyErr("tokens[{d}]: 'max_timeout_s' must be 1..1800", .{idx});
            max_timeout_s = v.integer;
        } else if (std.mem.eql(u8, k, "read_paths")) {
            read_paths = try parsePrefixList(a, v, idx, "read_paths");
        } else if (std.mem.eql(u8, k, "write_paths")) {
            write_paths = try parsePrefixList(a, v, idx, "write_paths");
        } else if (std.mem.eql(u8, k, "read_deny")) {
            read_deny = try parsePrefixList(a, v, idx, "read_deny");
        } else if (std.mem.eql(u8, k, "write_deny")) {
            write_deny = try parsePrefixList(a, v, idx, "write_deny");
        } else if (std.mem.eql(u8, k, "write_max_mode")) {
            if (v != .string) return policyErr("tokens[{d}]: 'write_max_mode' must be an octal string like \"0644\"", .{idx});
            write_max_mode = std.fmt.parseInt(u32, v.string, 8) catch
                return policyErr("tokens[{d}]: 'write_max_mode' is not a valid octal string", .{idx});
            if (v.string.len < 3 or v.string.len > 4)
                return policyErr("tokens[{d}]: 'write_max_mode' must have 3 or 4 octal digits", .{idx});
            if (write_max_mode.? > 0o7777)
                return policyErr("tokens[{d}]: 'write_max_mode' exceeds 07777", .{idx});
        } else {
            return policyErr("tokens[{d}]: unknown key '{s}'", .{ idx, k });
        }
    }

    if (has_allow_all and restricted_keys)
        return policyErr("tokens[{d}]: 'allow_all' cannot be combined with other keys", .{idx});
    if (allow_all) {
        return .{ .file = file, .token_hash = try loadTokenHash(a, io, file, idx), .allow_all = true, .tools = &.{}, .exec_argv0 = &.{}, .exec_cwd = &.{}, .cwd_deny = &.{}, .read_paths = &.{}, .write_paths = &.{}, .read_deny = &.{}, .write_deny = &.{} };
    }
    if (tools.len == 0) return policyErr("tokens[{d}]: 'tools' is required for a restricted entry", .{idx});

    // Cross-key consistency (fail at startup, not at call time).
    var pol = TokenPolicy{
        .file = file,
        .token_hash = try loadTokenHash(a, io, file, idx),
        .tools = tools,
        .exec_argv0 = exec_argv0,
        .exec_cwd = exec_cwd,
        .cwd_deny = cwd_deny,
        .max_timeout_s = max_timeout_s,
        .read_paths = read_paths,
        .write_paths = write_paths,
        .read_deny = read_deny,
        .write_deny = write_deny,
        .write_max_mode = write_max_mode,
    };
    if (pol.needsExec()) {
        if (exec_argv0.len == 0)
            return policyErr("tokens[{d}]: exec tools are listed but 'exec_argv0' is empty", .{idx});
        // exec_shell with no shell allowlisted would deny every call; that
        // is a config mistake, fail it at load.
        if (pol.toolAllowed("exec_shell")) {
            var any_shell = false;
            for (exec_argv0) |e| {
                if (std.mem.eql(u8, e.text, "bash") or std.mem.eql(u8, e.text, "sh") or
                    std.mem.eql(u8, e.text, "zsh") or std.mem.eql(u8, e.text, "fish") or
                    std.mem.eql(u8, e.text, "cmd") or std.mem.eql(u8, e.text, "powershell") or
                    std.mem.eql(u8, e.text, "/bin/bash") or std.mem.eql(u8, e.text, "/bin/sh"))
                {
                    any_shell = true;
                    break;
                }
            }
            if (!any_shell)
                return policyErr("tokens[{d}]: exec_shell is listed but no shell is in exec_argv0", .{idx});
        }
    }
    if (pol.needsRead() and read_paths.len == 0)
        return policyErr("tokens[{d}]: read tools are listed but 'read_paths' is empty", .{idx});
    if (pol.needsWrite()) {
        if (write_max_mode == null)
            return policyErr("tokens[{d}]: write_file is listed but 'write_max_mode' is missing", .{idx});
        if (read_paths.len == 0 and write_paths.len == 0)
            return policyErr("tokens[{d}]: write_file is listed but neither read_paths nor write_paths is set", .{idx});
    }
    return pol;
}

fn loadTokenHash(a: Allocator, io: Io, file: []const u8, idx: usize) LoadError![32]u8 {
    os.fd.checkPrivateFileMode(io, file) catch {
        return policyErr("tokens[{d}]: token file '{s}' must be 0600", .{ idx, file });
    };
    const raw = os.fd.readFileAlloc(a, io, file, 4096) catch |err| {
        return policyErr("tokens[{d}]: cannot read token file '{s}': {s}", .{ idx, file, @errorName(err) });
    };
    const value = std.mem.trim(u8, raw, " \t\r\n");
    if (value.len == 0) return policyErr("tokens[{d}]: token file '{s}' is empty", .{ idx, file });
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(value, &hash, .{});
    return hash;
}

fn parseToolList(a: Allocator, v: Value, idx: usize) LoadError![]const []const u8 {
    if (v != .array) return policyErr("tokens[{d}]: 'tools' must be an array of strings", .{idx});
    if (v.array.items.len == 0) return policyErr("tokens[{d}]: 'tools' must not be empty", .{idx});
    if (v.array.items.len > MAX_TOOLS)
        return policyErr("tokens[{d}]: 'tools' has more than {d} entries", .{ idx, MAX_TOOLS });
    const out = try a.alloc([]const u8, v.array.items.len);
    for (v.array.items, 0..) |tv, i| {
        if (tv != .string) return policyErr("tokens[{d}]: tools[{d}] must be a string", .{ idx, i });
        const name = tv.string;
        if (!validToolName(name))
            return policyErr("tokens[{d}]: tools[{d}] is not a tool name: '{s}'", .{ idx, i, name });
        out[i] = try strDup(a, name);
    }
    return out;
}

fn validToolName(name: []const u8) bool {
    if (name.len == 0) return false;
    if (std.mem.eql(u8, name, "*")) return true;
    const all = [_][]const u8{
        "exec",       "exec_start", "exec_poll", "exec_write", "exec_kill",
        "exec_close", "exec_wait",  "exec_list", "exec_shell", "sys_info",
        "read_file",  "write_file", "list_dir",
    };
    for (all) |t| {
        if (std.mem.eql(u8, name, t)) return true;
    }
    return false;
}

fn parseArgv0List(a: Allocator, io: Io, v: Value, idx: usize) LoadError![]const Argv0Entry {
    if (v != .array) return policyErr("tokens[{d}]: 'exec_argv0' must be an array of strings", .{idx});
    if (v.array.items.len == 0) return policyErr("tokens[{d}]: 'exec_argv0' must not be empty", .{idx});
    if (v.array.items.len > MAX_ARGV0)
        return policyErr("tokens[{d}]: 'exec_argv0' has more than {d} entries", .{ idx, MAX_ARGV0 });
    const out = try a.alloc(Argv0Entry, v.array.items.len);
    for (v.array.items, 0..) |tv, i| {
        if (tv != .string) return policyErr("tokens[{d}]: exec_argv0[{d}] must be a string", .{ idx, i });
        const s = tv.string;
        if (s.len == 0) return policyErr("tokens[{d}]: exec_argv0[{d}] must not be empty", .{ idx, i });
        if (std.mem.indexOfScalar(u8, s, '/') != null) {
            // A slash entry must be an absolute, canonical path.
            if (!std.fs.path.isAbsolute(s))
                return policyErr("tokens[{d}]: exec_argv0[{d}] contains '/' but is not absolute: '{s}'", .{ idx, i, s });
            const canon = canonicalizePath(a, io, s) catch
                return policyErr("tokens[{d}]: exec_argv0[{d}] cannot be canonicalised: '{s}'", .{ idx, i, s });
            out[i] = .{ .text = canon, .has_slash = true };
        } else {
            out[i] = .{ .text = try strDup(a, s), .has_slash = false };
        }
    }
    return out;
}

fn parsePrefixList(a: Allocator, v: Value, idx: usize, key: []const u8) LoadError![]const []const u8 {
    if (v != .array) return policyErr("tokens[{d}]: '{s}' must be an array of strings", .{ idx, key });
    if (v.array.items.len > MAX_PREFIXES)
        return policyErr("tokens[{d}]: '{s}' has more than {d} entries", .{ idx, key, MAX_PREFIXES });
    const out = try a.alloc([]const u8, v.array.items.len);
    for (v.array.items, 0..) |tv, i| {
        if (tv != .string) return policyErr("tokens[{d}]: {s}[{d}] must be a string", .{ idx, key, i });
        const s = tv.string;
        if (s.len == 0) return policyErr("tokens[{d}]: {s}[{d}] must not be empty", .{ idx, key, i });
        if (s[0] == '~')
            return policyErr("tokens[{d}]: {s}[{d}] must not use '~': write absolute paths", .{ idx, key, i });
        if (!std.fs.path.isAbsolute(s))
            return policyErr("tokens[{d}]: {s}[{d}] must be absolute: '{s}'", .{ idx, key, i, s });
        out[i] = try strDup(a, s);
    }
    return out;
}

// ---------------------------------------------------------------------------
// Canonicalisation and matching
// ---------------------------------------------------------------------------

/// Lexically normalise a path: resolve "." and ".." segments, collapse "//".
/// Pure lexical pass (no fs); makes ".." traversal impossible to hide from
/// the prefix check.
fn normalizeLexical(arena: Allocator, path: []const u8) ![]const u8 {
    var stack: std.ArrayList([]const u8) = .empty;
    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |seg| {
        if (seg.len == 0) continue; // "" (leading /) and "//"
        if (std.mem.eql(u8, seg, ".")) continue;
        if (std.mem.eql(u8, seg, "..")) {
            if (stack.items.len > 0) {
                _ = stack.pop();
            }
            continue;
        }
        try stack.append(arena, seg);
    }
    if (stack.items.len == 0) return arena.dupe(u8, "/");
    var out: std.ArrayList(u8) = .empty;
    for (stack.items) |seg| {
        try out.append(arena, '/');
        try out.appendSlice(arena, seg);
    }
    return out.items;
}

/// Canonicalise a path for policy matching: expand "~", anchor relatives to
/// the daemon cwd, normalise lexically, then realpath the deepest existing
/// ancestor so symlinks are followed wherever they exist (see design §4 for
/// the TOCTOU statement). Returns an absolute, prefix-comparable path.
pub fn canonicalizePath(arena: Allocator, io: Io, path: []const u8) ![]const u8 {
    var p = path;
    // "~"/"~/x" expansion, same semantics as tools.expandPath.
    if (p.len > 0 and p[0] == '~') {
        if (p.len == 1 or p[1] == '/') {
            if (os.homeDir(arena, env_state.process_environ)) |home| {
                if (home.len != 0) p = try std.mem.concat(arena, u8, &.{ home, p[1..] });
            }
        }
    }
    if (!std.fs.path.isAbsolute(p)) {
        const cwd = try std.process.currentPathAlloc(io, arena);
        p = try std.mem.concat(arena, u8, &.{ cwd, "/", p });
    }
    const norm = try normalizeLexical(arena, p);

    // Full path exists -> one realpath resolves everything, symlinks and all.
    if (realPathOf(arena, io, norm)) |rp| {
        return rp;
    } else |_| {}

    // Walk up to the deepest existing ancestor, realpath that, re-append
    // the (lexically normal) tail. A fresh path inside an allowed tree then
    // passes on the strength of its real ancestor — the intended semantics
    // for creating new files. Failure to resolve anything (e.g. every parent
    // missing) leaves the lexical form: the prefix check still applies to
    // it, and an allowlist root that does not exist would be a policy the
    // operator cannot use anyway.
    var dir = std.fs.path.dirname(norm) orelse return norm;
    while (dir.len > 1) {
        if (realPathOf(arena, io, dir)) |rp| {
            const tail = norm[dir.len..]; // keeps its leading '/'
            return try std.mem.concat(arena, u8, &.{ rp, tail });
        } else |_| {}
        dir = std.fs.path.dirname(dir) orelse return norm;
    }
    return norm;
}

fn realPathOf(arena: Allocator, io: Io, absolute: []const u8) ![]const u8 {
    return std.Io.Dir.cwd().realPathFileAlloc(io, absolute, arena);
}

/// Segment-aligned prefix match: `prefix` matches `path` when path equals
/// the prefix or continues it with a '/'. "/a/p" never matches "/a/pwn".
pub fn pathHasPrefix(path: []const u8, prefix: []const u8) bool {
    if (prefix.len == 0) return false;
    if (!std.mem.startsWith(u8, path, prefix)) return false;
    if (path.len == prefix.len) return true;
    // A prefix ending in '/' (the root "/") matches everything under it.
    if (prefix[prefix.len - 1] == '/') return true;
    return path[prefix.len] == '/';
}

fn prefixAllowed(path: []const u8, allow: []const []const u8, deny: []const []const u8) bool {
    for (deny) |d| {
        if (pathHasPrefix(path, d)) return false;
    }
    for (allow) |a| {
        if (pathHasPrefix(path, a)) return true;
    }
    return false;
}

/// Match a requested argv[0] against the allowlist: bare names match bare
/// requests exactly; slash entries (both sides canonicalised) match each
/// other. No cross-boundary matching — allowing "python3" never authorises
/// "/usr/bin/python3" and vice versa (design §5).
pub fn argv0Allowed(policy: *const TokenPolicy, argv0: []const u8, canon: []const u8) bool {
    const req_has_slash = std.mem.indexOfScalar(u8, argv0, '/') != null;
    for (policy.exec_argv0) |e| {
        if (e.has_slash != req_has_slash) continue;
        if (e.has_slash) {
            if (std.mem.eql(u8, e.text, canon)) return true;
        } else {
            if (std.mem.eql(u8, e.text, argv0)) return true;
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// Per-call checks
// ---------------------------------------------------------------------------

pub const PathKind = enum { read, write, cwd };

pub const DenyError = error{PolicyDenied};

pub fn checkTool(policy: *const TokenPolicy, tool: []const u8) DenyError!void {
    if (policy.allow_all) return;
    if (!policy.toolAllowed(tool)) return error.PolicyDenied;
}

pub fn checkTimeout(policy: *const TokenPolicy, timeout_s: i64) DenyError!void {
    if (policy.allow_all) return;
    if (policy.max_timeout_s) |cap| {
        if (timeout_s > cap) return error.PolicyDenied;
    }
}

pub fn checkArgv0(
    arena: Allocator,
    io: Io,
    policy: *const TokenPolicy,
    argv0: []const u8,
) DenyError!void {
    if (policy.allow_all) return;
    if (!policy.needsExec()) return error.PolicyDenied;
    const canon = canonicalizePath(arena, io, argv0) catch argv0;
    if (!argv0Allowed(policy, argv0, canon)) return error.PolicyDenied;
}

pub fn checkCwd(arena: Allocator, io: Io, policy: *const TokenPolicy, cwd: []const u8) DenyError!void {
    if (policy.allow_all) return;
    if (cwd.len == 0) return; // inherit: always allowed (design §5)
    const canon = canonicalizePath(arena, io, cwd) catch cwd;
    if (!prefixAllowed(canon, policy.exec_cwd, policy.cwd_deny)) return error.PolicyDenied;
}

pub fn checkPath(arena: Allocator, io: Io, policy: *const TokenPolicy, path: []const u8, kind: PathKind) DenyError!void {
    if (policy.allow_all) return;
    const canon = canonicalizePath(arena, io, path) catch path;
    const allow: []const []const u8 = switch (kind) {
        .read => policy.read_paths,
        .write => policy.write_paths,
        .cwd => policy.exec_cwd,
    };
    const deny: []const []const u8 = switch (kind) {
        .read => policy.read_deny,
        .write => policy.write_deny,
        .cwd => policy.cwd_deny,
    };
    if (!prefixAllowed(canon, allow, deny)) return error.PolicyDenied;
}

pub fn checkWriteMode(policy: *const TokenPolicy, mode: i64) DenyError!void {
    if (policy.allow_all) return;
    if (policy.write_max_mode) |cap| {
        const m: u64 = @intCast(mode);
        if (m > cap) return error.PolicyDenied;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

/// Write a file with 0600 permissions so loadPolicyFile accepts it.
fn writeSecret(dir: std.Io.Dir, io: Io, name: []const u8, content: []const u8) !void {
    try dir.writeFile(io, .{
        .sub_path = name,
        .data = content,
        .flags = .{ .permissions = std.Io.File.Permissions.fromMode(0o600) },
    });
}

/// Absolute path of `name` inside a testing tmp dir (loadPolicyFile compares
/// and realpaths against the process view, so absolute is the robust shape).
fn tmpAbs(arena: Allocator, tmp: *const testing.TmpDir, io: Io, name: []const u8) ![]const u8 {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = try tmp.dir.realPathFile(io, name, &buf);
    return arena.dupe(u8, buf[0..n]);
}

fn freePolicy(ps: *PolicySet) void {
    ps.deinit();
}

test "policy: valid file parses into entries" {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = Io.Threaded.global_single_threaded.io();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try writeSecret(tmp.dir, io, "tok-a", "aaaa\n");
    try writeSecret(tmp.dir, io, "tok-b", "bbbb\n");
    const tok_a = try tmpAbs(arena, &tmp, io, "tok-a");
    const tok_b = try tmpAbs(arena, &tmp, io, "tok-b");
    var pol_json: std.ArrayList(u8) = .empty;
    try pol_json.print(arena,
        \\{{"version":1,"tokens":[
        \\ {{"file":"{s}","tools":["exec","read_file","list_dir"],
        \\  "exec_argv0":["git","/usr/bin/make"],"exec_cwd":["/srv/build"],
        \\  "max_timeout_s":30,"read_paths":["/srv/build"],
        \\  "write_paths":[],"write_max_mode":"0644"}},
        \\ {{"file":"{s}","allow_all":true}}
        \\]}}
    , .{ tok_a, tok_b });
    try writeSecret(tmp.dir, io, "policy.json", pol_json.items);
    const path = try tmpAbs(arena, &tmp, io, "policy.json");
    var ps = try loadPolicyFile(arena, io, path);
    defer freePolicy(&ps);
    try testing.expectEqual(@as(usize, 2), ps.entries.len);
    try testing.expect(!ps.entries[0].allow_all);
    try testing.expect(ps.entries[1].allow_all);
    try testing.expectEqual(@as(usize, 3), ps.entries[0].tools.len);
    try testing.expectEqual(@as(?i64, 30), ps.entries[0].max_timeout_s);
    try testing.expectEqual(@as(?u32, 0o644), ps.entries[0].write_max_mode);
    try testing.expectEqual(@as(usize, 2), ps.entries[0].exec_argv0.len);
    try testing.expect(!ps.entries[0].exec_argv0[0].has_slash);
    try testing.expect(ps.entries[0].exec_argv0[1].has_slash);
}

test "policy: malformed variants are named errors" {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = Io.Threaded.global_single_threaded.io();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try writeSecret(tmp.dir, io, "tok", "secret\n");
    const tok_abs = try tmpAbs(arena, &tmp, io, "tok");
    var tok_json: std.ArrayList(u8) = .empty;
    try tok_json.print(arena, "{s}", .{tok_abs});

    const cases = [_]struct { name: []const u8, json: []const u8 }{
        .{ .name = "unknown-top", .json = "{\"version\":1,\"tokens\":[{\"file\":\"@TOK@\",\"allow_all\":true}],\"extra\":1}" },
        .{ .name = "bad-version", .json = "{\"version\":2,\"tokens\":[{\"file\":\"@TOK@\",\"allow_all\":true}]}" },
        .{ .name = "no-tokens", .json = "{\"version\":1}" },
        .{ .name = "empty-tokens", .json = "{\"version\":1,\"tokens\":[]}" },
        .{ .name = "not-json", .json = "{oops" },
        .{ .name = "unknown-key", .json = "{\"version\":1,\"tokens\":[{\"file\":\"@TOK@\",\"tools\":[\"exec\"],\"exec_argv0\":[\"git\"],\"read_paths\":[\"/srv\"],\"read_paths2\":[]}]}" },
        .{ .name = "allow-all-mixed", .json = "{\"version\":1,\"tokens\":[{\"file\":\"@TOK@\",\"allow_all\":true,\"tools\":[\"exec\"]}]}" },
        .{ .name = "bad-tool", .json = "{\"version\":1,\"tokens\":[{\"file\":\"@TOK@\",\"tools\":[\"rm_rf\"]}]}" },
        .{ .name = "no-tools", .json = "{\"version\":1,\"tokens\":[{\"file\":\"@TOK@\"}]}" },
        .{ .name = "relative-prefix", .json = "{\"version\":1,\"tokens\":[{\"file\":\"@TOK@\",\"tools\":[\"read_file\"],\"read_paths\":[\"srv/build\"]}]}" },
        .{ .name = "tilde-prefix", .json = "{\"version\":1,\"tokens\":[{\"file\":\"@TOK@\",\"tools\":[\"read_file\"],\"read_paths\":[\"~/build\"]}]}" },
        .{ .name = "exec-no-argv0", .json = "{\"version\":1,\"tokens\":[{\"file\":\"@TOK@\",\"tools\":[\"exec\"]}]}" },
        .{ .name = "read-no-paths", .json = "{\"version\":1,\"tokens\":[{\"file\":\"@TOK@\",\"tools\":[\"read_file\"]}]}" },
        .{ .name = "write-no-mode", .json = "{\"version\":1,\"tokens\":[{\"file\":\"@TOK@\",\"tools\":[\"write_file\"],\"write_paths\":[\"/srv\"]}]}" },
        .{ .name = "write-no-any-paths", .json = "{\"version\":1,\"tokens\":[{\"file\":\"@TOK@\",\"tools\":[\"write_file\"],\"write_max_mode\":\"0644\"}]}" },
        .{ .name = "shell-no-shell-argv0", .json = "{\"version\":1,\"tokens\":[{\"file\":\"@TOK@\",\"tools\":[\"exec_shell\"],\"exec_argv0\":[\"git\"],\"read_paths\":[\"/srv\"]}]}" },
        .{ .name = "bad-octal", .json = "{\"version\":1,\"tokens\":[{\"file\":\"@TOK@\",\"tools\":[\"write_file\"],\"write_paths\":[\"/srv\"],\"write_max_mode\":\"0999\"}]}" },
        .{ .name = "bad-timeout", .json = "{\"version\":1,\"tokens\":[{\"file\":\"@TOK@\",\"tools\":[\"exec\"],\"exec_argv0\":[\"git\"],\"read_paths\":[\"/srv\"],\"max_timeout_s\":9999}]}" },
        .{ .name = "relative-argv0-slash", .json = "{\"version\":1,\"tokens\":[{\"file\":\"@TOK@\",\"tools\":[\"exec\"],\"exec_argv0\":[\"bin/git\"],\"read_paths\":[\"/srv\"]}]}" },
        .{ .name = "missing-file-key", .json = "{\"version\":1,\"tokens\":[{\"tools\":[\"exec\"],\"exec_argv0\":[\"git\"],\"read_paths\":[\"/srv\"]}]}" },
        .{ .name = "empty-argv0", .json = "{\"version\":1,\"tokens\":[{\"file\":\"@TOK@\",\"tools\":[\"exec\"],\"exec_argv0\":[\"\"],\"read_paths\":[\"/srv\"]}]}" },
    };
    for (cases) |c| {
        const json = try std.mem.replaceOwned(u8, arena, c.json, "@TOK@", tok_json.items);
        try writeSecret(tmp.dir, io, c.name, json);
        const path = try tmpAbs(arena, &tmp, io, c.name);
        if (loadPolicyFile(arena, io, path)) |_| {
            std.debug.print("case '{s}' unexpectedly parsed\n", .{c.name});
            return error.TestUnexpectedResult;
        } else |err| {
            try testing.expectEqual(error.InvalidPolicy, err);
        }
    }
}

test "policy: 0644 policy file is rejected" {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = Io.Threaded.global_single_threaded.io();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try writeSecret(tmp.dir, io, "tok", "secret\n");
    const tok_abs = try tmpAbs(arena, &tmp, io, "tok");
    var json: std.ArrayList(u8) = .empty;
    try json.print(arena, "{{\"version\":1,\"tokens\":[{{\"file\":\"{s}\",\"allow_all\":true}}]}}", .{tok_abs});
    try tmp.dir.writeFile(io, .{
        .sub_path = "policy.json",
        .data = json.items,
        .flags = .{ .permissions = std.Io.File.Permissions.fromMode(0o644) },
    });
    const path = try tmpAbs(arena, &tmp, io, "policy.json");
    try testing.expectError(error.InvalidPolicy, loadPolicyFile(arena, io, path));
}

test "policy: token file mode and emptiness are enforced" {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = Io.Threaded.global_single_threaded.io();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    // Empty token file.
    try writeSecret(tmp.dir, io, "empty", "");
    // loadPolicyFile resolves token-file paths against the process cwd;
    // give it an absolute token path via a generated policy.
    const empty_abs = try tmpAbs(arena, &tmp, io, "empty");
    var json1: std.ArrayList(u8) = .empty;
    try json1.print(arena, "{{\"version\":1,\"tokens\":[{{\"file\":\"{s}\",\"allow_all\":true}}]}}", .{empty_abs});
    try writeSecret(tmp.dir, io, "p1", json1.items);
    const p1 = try tmpAbs(arena, &tmp, io, "p1");
    try testing.expectError(error.InvalidPolicy, loadPolicyFile(arena, io, p1));
    // Missing token file.
    try writeSecret(tmp.dir, io, "p3", "{\"version\":1,\"tokens\":[{\"file\":\"/nonexistent/nope\",\"allow_all\":true}]}");
    const p3 = try tmpAbs(arena, &tmp, io, "p3");
    try testing.expectError(error.InvalidPolicy, loadPolicyFile(arena, io, p3));
}

test "policy: loose token file is rejected" {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = Io.Threaded.global_single_threaded.io();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try tmp.dir.writeFile(io, .{
        .sub_path = "loose",
        .data = "secret",
        .flags = .{ .permissions = std.Io.File.Permissions.fromMode(0o644) },
    });
    const loose_abs = try tmpAbs(arena, &tmp, io, "loose");
    var json: std.ArrayList(u8) = .empty;
    try json.print(arena, "{{\"version\":1,\"tokens\":[{{\"file\":\"{s}\",\"allow_all\":true}}]}}", .{loose_abs});
    try writeSecret(tmp.dir, io, "p2", json.items);
    const p2 = try tmpAbs(arena, &tmp, io, "p2");
    try testing.expectError(error.InvalidPolicy, loadPolicyFile(arena, io, p2));
}

test "policy: normalizeLexical resolves traversal and collapses" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try testing.expectEqualStrings("/a/b", try normalizeLexical(arena, "/a/x/../b"));
    try testing.expectEqualStrings("/a/b", try normalizeLexical(arena, "/a/./b//"));
    try testing.expectEqualStrings("/", try normalizeLexical(arena, "/.."));
    try testing.expectEqualStrings("/etc/passwd", try normalizeLexical(arena, "/etc/../etc/passwd"));
    try testing.expectEqualStrings("/a", try normalizeLexical(arena, "/a/b/.."));
}

test "policy: pathHasPrefix is segment aligned" {
    try testing.expect(pathHasPrefix("/a/p/x", "/a/p"));
    try testing.expect(pathHasPrefix("/a/p", "/a/p"));
    try testing.expect(!pathHasPrefix("/a/pwn", "/a/p"));
    try testing.expect(pathHasPrefix("/anything", "/"));
    try testing.expect(!pathHasPrefix("/a", ""));
    try testing.expect(!pathHasPrefix("/ab", "/a"));
}

test "policy: argv0 bare/slash boundary" {
    const pol = TokenPolicy{
        .file = "f",
        .token_hash = [_]u8{0} ** 32,
        .tools = &.{"exec"},
        .exec_argv0 = &.{ .{ .text = "python3", .has_slash = false }, .{ .text = "/usr/bin/git", .has_slash = true } },
        .exec_cwd = &.{},
        .cwd_deny = &.{},
        .read_paths = &.{},
        .write_paths = &.{},
        .read_deny = &.{},
        .write_deny = &.{},
    };
    try testing.expect(argv0Allowed(&pol, "python3", "python3"));
    try testing.expect(argv0Allowed(&pol, "/usr/bin/git", "/usr/bin/git"));
    // Cross-boundary: never.
    try testing.expect(!argv0Allowed(&pol, "/usr/bin/python3", "/usr/bin/python3"));
    try testing.expect(!argv0Allowed(&pol, "git", "git"));
    try testing.expect(!argv0Allowed(&pol, "./python3", "/cwd/python3"));
}

test "policy: checkTimeout / checkWriteMode caps" {
    const pol = TokenPolicy{
        .file = "f",
        .token_hash = [_]u8{0} ** 32,
        .tools = &.{"exec"},
        .exec_argv0 = &.{.{ .text = "git", .has_slash = false }},
        .exec_cwd = &.{},
        .cwd_deny = &.{},
        .max_timeout_s = 30,
        .read_paths = &.{},
        .write_paths = &.{},
        .read_deny = &.{},
        .write_deny = &.{},
        .write_max_mode = 0o644,
    };
    try checkTimeout(&pol, 30);
    try testing.expectError(error.PolicyDenied, checkTimeout(&pol, 31));
    try checkWriteMode(&pol, 0o644);
    try testing.expectError(error.PolicyDenied, checkWriteMode(&pol, 0o755));
    try testing.expectError(error.PolicyDenied, checkWriteMode(&pol, 0o4755));
    const capless = TokenPolicy{
        .file = "f",
        .token_hash = [_]u8{0} ** 32,
        .tools = &.{"exec"},
        .exec_argv0 = &.{.{ .text = "git", .has_slash = false }},
        .exec_cwd = &.{},
        .cwd_deny = &.{},
        .read_paths = &.{},
        .write_paths = &.{},
        .read_deny = &.{},
        .write_deny = &.{},
    };
    try checkTimeout(&capless, 1800);
    try checkWriteMode(&capless, 0o7777);
}

test "policy: allow_all passes every check" {
    const pol = TokenPolicy{
        .file = "f",
        .token_hash = [_]u8{0} ** 32,
        .allow_all = true,
        .tools = &.{},
        .exec_argv0 = &.{},
        .exec_cwd = &.{},
        .cwd_deny = &.{},
        .read_paths = &.{},
        .write_paths = &.{},
        .read_deny = &.{},
        .write_deny = &.{},
    };
    try checkTool(&pol, "exec");
    try checkTimeout(&pol, 99999);
    try checkWriteMode(&pol, 0o7777);
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = Io.Threaded.global_single_threaded.io();
    try checkPath(arena, io, &pol, "/etc/passwd", .read);
    try checkArgv0(arena, io, &pol, "anything");
    try checkCwd(arena, io, &pol, "/any/where");
}

test "policy: tool allowlist is default-deny and '*' opens tools only" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    _ = arena;
    const pol = TokenPolicy{
        .file = "f",
        .token_hash = [_]u8{0} ** 32,
        .tools = &.{"exec"},
        .exec_argv0 = &.{.{ .text = "git", .has_slash = false }},
        .exec_cwd = &.{},
        .cwd_deny = &.{},
        .read_paths = &.{},
        .write_paths = &.{},
        .read_deny = &.{},
        .write_deny = &.{},
    };
    try checkTool(&pol, "exec");
    try testing.expectError(error.PolicyDenied, checkTool(&pol, "read_file"));
    try testing.expectError(error.PolicyDenied, checkTool(&pol, "write_file"));
    try testing.expectError(error.PolicyDenied, checkTool(&pol, "exec_shell"));
    const star = TokenPolicy{
        .file = "f",
        .token_hash = [_]u8{0} ** 32,
        .tools = &.{"*"},
        .max_timeout_s = 30,
        .exec_argv0 = &.{.{ .text = "git", .has_slash = false }},
        .exec_cwd = &.{},
        .cwd_deny = &.{},
        .read_paths = &.{"/"},
        .write_paths = &.{},
        .read_deny = &.{},
        .write_deny = &.{},
        .write_max_mode = 0o600,
    };
    try checkTool(&star, "exec");
    try checkTool(&star, "read_file");
    // '*' does not wave through argument checks:
    try testing.expectError(error.PolicyDenied, checkTimeout(&star, 100));
}

test "policy: canonicalizePath anchors relatives and follows symlinks" {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = Io.Threaded.global_single_threaded.io();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const root = try tmpAbs(arena, &tmp, io, ".");
    try tmp.dir.createDirPath(io, "allow/sub");
    try tmp.dir.createDirPath(io, "outside");
    // symlink: allow/esc -> ../outside
    tmp.dir.symLink(io, "../outside", "allow/esc", .{}) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    const esc_target = try std.mem.concat(arena, u8, &.{ root, "/allow/esc" });
    const canon = try canonicalizePath(arena, io, esc_target);
    // The symlink resolves to the real outside dir: the escape is visible
    // to the prefix check as the true target.
    try testing.expect(std.mem.startsWith(u8, canon, "/"));
    try testing.expect(std.mem.indexOf(u8, canon, "/outside") != null);
    // A plain traversal normalises away.
    const trav = try std.mem.concat(arena, u8, &.{ root, "/allow/sub/../../outside" });
    const canon2 = try canonicalizePath(arena, io, trav);
    try testing.expect(std.mem.endsWith(u8, canon2, "/outside"));
    // A fresh path under an existing ancestor keeps the tail.
    const fresh = try std.mem.concat(arena, u8, &.{ root, "/allow/sub/new/deep.txt" });
    const canon3 = try canonicalizePath(arena, io, fresh);
    try testing.expect(std.mem.endsWith(u8, canon3, "/allow/sub/new/deep.txt"));
    // Relative path anchors to the daemon cwd; the result is absolute.
    const rel = try canonicalizePath(arena, io, "some/rel/path");
    try testing.expect(std.fs.path.isAbsolute(rel));
    // "~" expands via the environ snapshot when HOME is set; without HOME
    // it stays a lexical path (still absolute after anchoring? no: a
    // leading '~' path without HOME expands to nothing, anchors as a
    // relative "~..." path under cwd — acceptable and still prefix-checked).
}

test "policy: prefixAllowed deny wins over allow" {
    const allow = [_][]const u8{"/srv/build"};
    const deny = [_][]const u8{"/srv/build/keys"};
    try testing.expect(prefixAllowed("/srv/build/x", allow[0..], deny[0..]));
    try testing.expect(!prefixAllowed("/srv/build/keys/k", allow[0..], deny[0..]));
    try testing.expect(!prefixAllowed("/etc/passwd", allow[0..], deny[0..]));
}

// ---------------------------------------------------------------------------
// Per-call check driver (rpc-side entry)
// ---------------------------------------------------------------------------

const util = @import("util.zig");
const session_mod = @import("session.zig");

pub const Deny = struct {
    /// Machine-readable DenyReason tag (same string as @tagName).
    reason_tag: []const u8,
    /// JSON field the caller can fix ("argv[0]", "cwd", "path", "mode",
    /// "timeout", "session_id", or "" for tool-level refusals).
    field: []const u8,
};

/// Human-readable text for a DenyReason tag (message field of the denial).
pub fn denyText(tag: []const u8) []const u8 {
    if (std.mem.eql(u8, tag, "tool_not_allowed")) return DenyReason.tool_not_allowed.text();
    if (std.mem.eql(u8, tag, "argv0_not_allowed")) return DenyReason.argv0_not_allowed.text();
    if (std.mem.eql(u8, tag, "cwd_not_allowed")) return DenyReason.cwd_not_allowed.text();
    if (std.mem.eql(u8, tag, "path_not_allowed")) return DenyReason.path_not_allowed.text();
    if (std.mem.eql(u8, tag, "denied_path")) return DenyReason.denied_path.text();
    if (std.mem.eql(u8, tag, "timeout_exceeds_cap")) return DenyReason.timeout_exceeds_cap.text();
    if (std.mem.eql(u8, tag, "write_mode_exceeds_cap")) return DenyReason.write_mode_exceeds_cap.text();
    if (std.mem.eql(u8, tag, "session_not_owned")) return DenyReason.session_not_owned.text();
    return "denied by token policy";
}

fn denyTag(r: DenyReason) []const u8 {
    return switch (r) {
        .tool_not_allowed => "tool_not_allowed",
        .argv0_not_allowed => "argv0_not_allowed",
        .cwd_not_allowed => "cwd_not_allowed",
        .path_not_allowed => "path_not_allowed",
        .denied_path => "denied_path",
        .timeout_exceeds_cap => "timeout_exceeds_cap",
        .write_mode_exceeds_cap => "write_mode_exceeds_cap",
        .session_not_owned => "session_not_owned",
    };
}

/// Evaluate the full argument policy for one tools/call. Returns null when
/// the call may proceed; a Deny describing the FIRST failing rule otherwise.
/// Order matters for error quality: tool membership, then per-tool argument
/// checks in the order the tool reads its arguments.
pub fn checkCall(
    arena: Allocator,
    io: Io,
    cfg: *const @import("config.zig").Config,
    pol: *const TokenPolicy,
    tool: []const u8,
    args: Value,
) ?Deny {
    if (pol.allow_all) return null;
    if (!pol.toolAllowed(tool)) return .{ .reason_tag = denyTag(.tool_not_allowed), .field = "" };

    if (std.mem.eql(u8, tool, "exec") or std.mem.eql(u8, tool, "exec_start") or std.mem.eql(u8, tool, "exec_shell")) {
        return checkExecArgs(arena, io, pol, tool, args);
    }
    if (std.mem.eql(u8, tool, "read_file") or std.mem.eql(u8, tool, "list_dir")) {
        const path = util.objGet(args, "path") orelse return null; // tool's own MissingPath error
        if (path != .string) return null; // tool's own type error
        if (!pathAllowed(arena, io, pol, path.string, .read)) {
            return .{ .reason_tag = if (deniedExplicit(arena, io, pol, path.string, .read)) denyTag(.denied_path) else denyTag(.path_not_allowed), .field = "path" };
        }
        return null;
    }
    if (std.mem.eql(u8, tool, "write_file")) {
        const path = util.objGet(args, "path") orelse return null;
        if (path != .string) return null;
        if (!pathAllowed(arena, io, pol, path.string, .write)) {
            return .{ .reason_tag = if (deniedExplicit(arena, io, pol, path.string, .write)) denyTag(.denied_path) else denyTag(.path_not_allowed), .field = "path" };
        }
        if (util.objGet(args, "mode")) |m| {
            if (m == .integer) {
                checkWriteMode(pol, m.integer) catch {
                    return .{ .reason_tag = denyTag(.write_mode_exceeds_cap), .field = "mode" };
                };
            }
        }
        return null;
    }
    if (std.mem.eql(u8, tool, "exec_wait")) {
        if (util.objGet(args, "timeout")) |t| {
            if (t == .integer) {
                checkTimeout(pol, t.integer) catch {
                    return .{ .reason_tag = denyTag(.timeout_exceeds_cap), .field = "timeout" };
                };
            }
        }
        return null; // session ownership checked inside the tool (owner hash)
    }
    // sys_info and the session-control tools (exec_poll/write/kill/close,
    // exec_list): membership-only above; ownership enforced in tools.zig
    // where the session (and its owner hash) is at hand.
    _ = cfg;
    return null;
}

fn checkExecArgs(arena: Allocator, io: Io, pol: *const TokenPolicy, tool: []const u8, args: Value) ?Deny {
    // exec_shell synthesizes the argv the tool will actually spawn: the
    // explicit shell or the platform default. Gating the synthesized argv
    // is what makes "shell not in exec_argv0" a real, checkable rule.
    var argv0: ?[]const u8 = null;
    if (std.mem.eql(u8, tool, "exec_shell")) {
        const builtin = @import("builtin");
        const default_shell: []const u8 = if (builtin.os.tag == .windows) "cmd" else "bash";
        argv0 = if (util.objGet(args, "shell")) |s| (if (s == .string) s.string else null) else default_shell;
    } else {
        const argv = util.objGet(args, "argv") orelse return null; // tool's own MissingArgv
        if (argv != .array or argv.array.items.len == 0) return null; // tool's own BadArgv
        const first = argv.array.items[0];
        if (first != .string) return null;
        argv0 = first.string;
    }
    checkArgv0(arena, io, pol, argv0.?) catch {
        return .{ .reason_tag = denyTag(.argv0_not_allowed), .field = "argv[0]" };
    };
    if (util.objGet(args, "cwd")) |c| {
        if (c == .string and c.string.len != 0) {
            checkCwd(arena, io, pol, c.string) catch {
                return .{ .reason_tag = if (cwdDeniedExplicit(arena, io, pol, c.string)) denyTag(.denied_path) else denyTag(.cwd_not_allowed), .field = "cwd" };
            };
        }
    }
    if (util.objGet(args, "timeout")) |t| {
        if (t == .integer) {
            checkTimeout(pol, t.integer) catch {
                return .{ .reason_tag = denyTag(.timeout_exceeds_cap), .field = "timeout" };
            };
        }
    } else if (pol.max_timeout_s != null and pol.max_timeout_s.? < 120) {
        // No explicit timeout -> the tool default (120s) would run above the
        // cap: deny rather than silently clamp (design §5).
        return .{ .reason_tag = denyTag(.timeout_exceeds_cap), .field = "timeout" };
    }
    return null;
}

/// Read allow+deny evaluation for read_file/list_dir and write_file paths.
fn pathAllowed(arena: Allocator, io: Io, pol: *const TokenPolicy, path: []const u8, kind: PathKind) bool {
    const canon = canonicalizePath(arena, io, path) catch path;
    const allow: []const []const u8 = if (kind == .read) pol.read_paths else pol.write_paths;
    const deny: []const []const u8 = if (kind == .read) pol.read_deny else pol.write_deny;
    return prefixAllowed(canon, allow, deny);
}

/// True when the path sat under an allow prefix AND a deny prefix: the
/// message then says "deny list", which points at the right knob.
fn deniedExplicit(arena: Allocator, io: Io, pol: *const TokenPolicy, path: []const u8, kind: PathKind) bool {
    const canon = canonicalizePath(arena, io, path) catch path;
    const allow: []const []const u8 = if (kind == .read) pol.read_paths else pol.write_paths;
    const deny: []const []const u8 = if (kind == .read) pol.read_deny else pol.write_deny;
    for (deny) |d| {
        if (pathHasPrefix(canon, d)) {
            for (allow) |a| {
                if (pathHasPrefix(canon, a)) return true;
            }
        }
    }
    return false;
}

fn cwdDeniedExplicit(arena: Allocator, io: Io, pol: *const TokenPolicy, cwd: []const u8) bool {
    const canon = canonicalizePath(arena, io, cwd) catch cwd;
    for (pol.cwd_deny) |d| {
        if (pathHasPrefix(canon, d)) {
            for (pol.exec_cwd) |a| {
                if (pathHasPrefix(canon, a)) return true;
            }
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// Session ownership
// ---------------------------------------------------------------------------

/// The sha256 of the presented client token for the request currently being
/// served on THIS thread (zeroes when no policy is active). Set by the rpc
/// layer around dispatchTool; read by tools.zig when a session is created or
/// addressed. Correct because every request runs synchronously on its own
/// serving thread (HTTP worker, link worker, or the stdio main thread).
pub threadlocal var current_owner: [32]u8 = [_]u8{0} ** 32;

/// True when a policy is active on this thread (current_owner was set from
/// a matched CallCtx policy).
pub threadlocal var policy_active: bool = false;

/// Called by the rpc layer before dispatchTool.
pub fn beginRequest(pol: ?*const TokenPolicy) void {
    if (pol) |p| {
        current_owner = p.token_hash;
        policy_active = true;
    } else {
        current_owner = [_]u8{0} ** 32;
        policy_active = false;
    }
}

/// Called by the rpc layer after dispatchTool returns/errors.
pub fn endRequest() void {
    current_owner = [_]u8{0} ** 32;
    policy_active = false;
}

/// Ownership check for the session-control tools: the session's owner must
/// match the current request's owner when a policy is active. Without a
/// policy both sides are zeroes and every session is accessible — exactly
/// the v0.3.1 behaviour.
pub fn sessionOwned(session_owner: [32]u8) bool {
    if (!policy_active) return true;
    return std.crypto.timing_safe.eql([32]u8, session_owner, current_owner);
}
