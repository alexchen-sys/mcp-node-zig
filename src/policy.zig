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
const builtin = @import("builtin");
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
    bad_argument_type,
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
            .bad_argument_type => "argument has a type this token's policy refuses",
            .session_not_owned => "session belongs to another token",
        };
    }
};

/// One argv[0] allowlist entry. `path` entries (containing '/') are
/// canonicalised at load; `bare` entries (no '/') are matched exactly.
const Argv0Entry = struct {
    /// Matching text: the canonical path for path-form entries, the bare
    /// name verbatim otherwise.
    text: []const u8,
    has_slash: bool,
    /// True when the entry AS WRITTEN names a shell this build can spawn
    /// (basename match, so "/bin/sh" counts). The load-time exec_shell
    /// check reads this: the canonical form of "/bin/sh" is the dash
    /// binary, so testing `text` would miss the documented spelling.
    shell: bool = false,
    /// Original basename, before canonicalization resolves shell symlinks.
    shell_name: ?[]const u8 = null,
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
        return self.toolAllowed("read_file") or self.toolAllowed("list_dir") or self.toolAllowed("copy_path");
    }

    fn needsWrite(self: *const TokenPolicy) bool {
        return self.toolAllowed("write_file") or self.toolAllowed("copy_path");
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
            exec_cwd = try parsePrefixList(a, io, v, idx, "exec_cwd");
        } else if (std.mem.eql(u8, k, "cwd_deny")) {
            cwd_deny = try parsePrefixList(a, io, v, idx, "cwd_deny");
        } else if (std.mem.eql(u8, k, "max_timeout_s")) {
            if (v != .integer) return policyErr("tokens[{d}]: 'max_timeout_s' must be an integer", .{idx});
            if (v.integer < 1 or v.integer > 1800)
                return policyErr("tokens[{d}]: 'max_timeout_s' must be 1..1800", .{idx});
            max_timeout_s = v.integer;
        } else if (std.mem.eql(u8, k, "read_paths")) {
            read_paths = try parsePrefixList(a, io, v, idx, "read_paths");
        } else if (std.mem.eql(u8, k, "write_paths")) {
            write_paths = try parsePrefixList(a, io, v, idx, "write_paths");
        } else if (std.mem.eql(u8, k, "read_deny")) {
            read_deny = try parsePrefixList(a, io, v, idx, "read_deny");
        } else if (std.mem.eql(u8, k, "write_deny")) {
            write_deny = try parsePrefixList(a, io, v, idx, "write_deny");
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
        // is a config mistake, fail it at load. The check is platform-aware:
        // the tool's comptime allowlist decides which shells this build can
        // actually spawn (POSIX: bash/sh/zsh/fish; Windows: cmd/powershell).
        if (pol.toolAllowed("exec_shell")) {
            var any_shell = false;
            for (exec_argv0) |e| {
                if (e.shell) {
                    any_shell = true;
                    break;
                }
            }
            if (!any_shell) return policyErr("tokens[{d}]: {s}", .{ idx, shell_refusal });
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
    if (pol.toolAllowed("copy_path") and write_paths.len == 0)
        return policyErr("tokens[{d}]: copy_path requires nonempty write_paths", .{idx});
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
        "read_file",  "write_file", "list_dir",  "copy_path",
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
        if (argv0HasSeparator(s)) {
            // A path-form entry must be an absolute, canonical path. On
            // Windows the backslash form (`C:\tools\x.exe`) is path-form
            // too: classing it as a bare name broke every spawn — the
            // PATH search joined the whole string under every PATH entry.
            if (!std.fs.path.isAbsolute(s))
                return policyErr("tokens[{d}]: exec_argv0[{d}] contains a path separator but is not absolute: '{s}'", .{ idx, i, s });
            const canon = canonicalizePathOpt(a, io, s, .{ .expand_tilde = false }) catch
                return policyErr("tokens[{d}]: exec_argv0[{d}] cannot be canonicalised: '{s}'", .{ idx, i, s });
            out[i] = .{ .text = canon, .has_slash = true, .shell = namesSpawnableShell(s), .shell_name = try strDup(a, std.fs.path.basename(s)) };
        } else {
            out[i] = .{ .text = try strDup(a, s), .has_slash = false, .shell = namesSpawnableShell(s), .shell_name = try strDup(a, std.fs.path.basename(s)) };
        }
    }
    return out;
}

fn parsePrefixList(a: Allocator, io: Io, v: Value, idx: usize, key: []const u8) LoadError![]const []const u8 {
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
        // Canonicalise at load: the request path is
        // canonicalised before matching, so a prefix stored verbatim
        // silently misses — a trailing slash ("/srv/keys/" never matches
        // the canonical "/srv/keys", so the deny does not fire on the dir
        // itself) and a symlinked segment ("/var" -> "/private/var")
        // diverge from what the request canonicalises to. canonicalizePath
        // resolves existing prefixes through realpath, lexically
        // normalises (and de-slashes) the rest, and refuses a prefix whose
        // own tail is an unresolved symlink — fail at load, not at match.
        const canon = canonicalizePath(a, io, s) catch
            return policyErr("tokens[{d}]: {s}[{d}] cannot be canonicalised: '{s}'", .{ idx, key, i, s });
        out[i] = try strDup(a, canon);
    }
    return out;
}

// ---------------------------------------------------------------------------
// Canonicalisation and matching
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Host path grammar
// ---------------------------------------------------------------------------
// The matchers and the lexical normaliser must speak the HOST filesystem's
// path grammar, not a POSIX-only one. On Windows the canonical form carries
// backslashes ("C:\allow\a.txt" — std's GetFinalPathNameByHandle answers
// the DOS spelling without the \\?\ verifier prefix), NTFS compares names
// ASCII-case-insensitively, and a path has an unpoppable DOS/UNC root. The
// style is an explicit parameter (pure, like hasPathSeparator) so the
// Linux CI pins the Windows contract directly.

pub const PathStyle = struct {
    /// Bytes that separate path segments: '/' on POSIX, '/' and '\' on
    /// Windows, where the kernel accepts both spellings.
    seps: []const u8,
    /// ASCII case-insensitive comparison (NTFS). The fold applies to allow
    /// AND deny equally — see pathHasPrefixSty for why deny needs it too.
    fold: bool,
    /// DOS drive / UNC root grammar (normalizeLexicalSty,
    /// assertTailAbsent). Exactly the Windows style.
    win_roots: bool = false,

    pub const posix: PathStyle = .{ .seps = "/", .fold = false };
    pub const windows: PathStyle = .{ .seps = "/\\", .fold = true, .win_roots = true };
};

/// The grammar of the host this binary runs on: every matcher below
/// defaults to it, so POSIX behaviour is unchanged (the POSIX arms carry
/// the historical bodies).
const host_path_style: PathStyle = if (builtin.os.tag == .windows) .windows else .posix;

fn styleIsSep(style: PathStyle, c: u8) bool {
    return std.mem.indexOfScalar(u8, style.seps, c) != null;
}

/// ASCII case fold for one byte. Non-ASCII bytes compare exactly: NTFS
/// case rules beyond ASCII are not approximated, a mismatch simply does
/// not match (the callers fail closed).
fn foldAscii(c: u8) u8 {
    if (c >= 'A' and c <= 'Z') return c + 32;
    return c;
}

fn styleStartsWith(haystack: []const u8, needle: []const u8, style: PathStyle) bool {
    if (haystack.len < needle.len) return false;
    if (!style.fold) return std.mem.startsWith(u8, haystack, needle);
    for (haystack[0..needle.len], needle) |a, b| {
        if (foldAscii(a) != foldAscii(b)) return false;
    }
    return true;
}

/// First separator of `style` at or after `from`. std.mem has no
/// indexOfAnyPos, so this is the any-of scan the walk needs. Pure.
fn styleSepPos(p: []const u8, from: usize, style: PathStyle) ?usize {
    var i = from;
    while (i < p.len) : (i += 1) {
        if (styleIsSep(style, p[i])) return i;
    }
    return null;
}

fn winIsSepByte(c: u8) bool {
    return c == '/' or c == '\\';
}

fn winIsDriveLetter(c: u8) bool {
    return (c >= 'A' and c <= 'Z') or (c >= 'a' and c <= 'z');
}

fn winEqIgnoreCaseAscii(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (foldAscii(x) != foldAscii(y)) return false;
    }
    return true;
}

/// End index (exclusive) of the path component starting at `i`.
fn winCompEnd(p: []const u8, i: usize) usize {
    var j = i;
    while (j < p.len and !winIsSepByte(p[j])) j += 1;
    return j;
}

/// `i` advanced past at most one separator.
fn winSkipOneSep(p: []const u8, i: usize) usize {
    return if (i < p.len and winIsSepByte(p[i])) i + 1 else i;
}

const WinRootParts = struct {
    /// Canonical '\' spelling of the root, WITHOUT a trailing separator:
    /// "C:", "\\server\share", "\\?\C:", "\\?\UNC\server\share",
    /// "\\?\Volume{...}", or "\" (current-drive root).
    text: []const u8,
    /// The bytes after the root and at most one trailing separator.
    rest: []const u8,
};

/// The root of a Windows-style path, rebuilt with '\' separators, plus the
/// remainder. Verbatim/device namespaces ("\\?\", "\\.") keep their marker
/// (only literal backslashes count — the verbatim namespace is not spelled
/// with '/'); the "UNC" marker behind "\\?\" is matched case-insensitively
/// (NTFS). null = no root (relative). Rebuilding instead of slicing also
/// canonicalises mixed separator spellings ("C:/a" -> "C:\a"): the pin
/// post-check (windowsPathMatchesUtf8) folds case but NOT separators, so
/// only one canonical spelling may leave this normaliser. Pure.
fn winRootParts(arena: Allocator, p: []const u8) Allocator.Error!?WinRootParts {
    if (p.len >= 4 and p[0] == '\\' and p[1] == '\\' and
        (p[2] == '?' or p[2] == '.') and p[3] == '\\')
    {
        const after = p[4..];
        if (after.len >= 4 and winEqIgnoreCaseAscii(after[0..3], "UNC") and winIsSepByte(after[3])) {
            // \\?\UNC\server\share
            const srv_end = winCompEnd(after, 4);
            const share_start = winSkipOneSep(after, srv_end);
            const share_end = winCompEnd(after, share_start);
            return .{ .text = try std.mem.concat(arena, u8, &.{
                "\\\\?\\UNC", "\\", after[4..srv_end], "\\", after[share_start..share_end],
            }), .rest = after[winSkipOneSep(after, share_end)..] };
        }
        // \\?\C: or \\?\Volume{...}: one component is the root.
        const comp_end = winCompEnd(after, 0);
        return .{ .text = try std.mem.concat(arena, u8, &.{
            "\\\\?\\", after[0..comp_end],
        }), .rest = after[winSkipOneSep(after, comp_end)..] };
    }
    // Plain UNC (either separator spelling): two components are the root.
    if (p.len >= 2 and winIsSepByte(p[0]) and winIsSepByte(p[1])) {
        const srv_end = winCompEnd(p, 2);
        const share_start = winSkipOneSep(p, srv_end);
        const share_end = winCompEnd(p, share_start);
        return .{ .text = try std.mem.concat(arena, u8, &.{
            "\\\\", p[2..srv_end], "\\", p[share_start..share_end],
        }), .rest = p[winSkipOneSep(p, share_end)..] };
    }
    // DOS drive: "C:" plus at most one separator.
    if (p.len >= 2 and winIsDriveLetter(p[0]) and p[1] == ':') {
        return .{ .text = p[0..2], .rest = p[winSkipOneSep(p, 2)..] };
    }
    // Current-drive root: a lone leading separator.
    if (p.len >= 1 and winIsSepByte(p[0])) {
        return .{ .text = "\\", .rest = p[1..] };
    }
    return null;
}

/// Byte length of the immutable Windows root prefix of `p`, including AT
/// MOST ONE trailing separator (the normaliser collapses repeats):
/// "C:\" (3), the drive-relative "C:" (2), "\\server\share" (+1),
/// "\\?\C:" (+1), "\\?\UNC\server\share" (+1), or a lone leading
/// separator (1, current-drive root). 0 = no root. The root is not a
/// ".."-poppable component and is never probed by assertTailAbsent.
/// Pure: unit-tested on every CI platform.
fn winRootLen(p: []const u8) usize {
    if (p.len >= 4 and p[0] == '\\' and p[1] == '\\' and
        (p[2] == '?' or p[2] == '.') and p[3] == '\\')
    {
        const after = p[4..];
        if (after.len >= 4 and winEqIgnoreCaseAscii(after[0..3], "UNC") and winIsSepByte(after[3])) {
            const srv_end = winCompEnd(after, 4);
            const share_start = winSkipOneSep(after, srv_end);
            const share_end = winCompEnd(after, share_start);
            return 4 + winSkipOneSep(after, share_end);
        }
        return 4 + winSkipOneSep(after, winCompEnd(after, 0));
    }
    if (p.len >= 2 and winIsSepByte(p[0]) and winIsSepByte(p[1])) {
        const srv_end = winCompEnd(p, 2);
        const share_start = winSkipOneSep(p, srv_end);
        const share_end = winCompEnd(p, share_start);
        return winSkipOneSep(p, share_end);
    }
    if (p.len >= 2 and winIsDriveLetter(p[0]) and p[1] == ':') {
        return winSkipOneSep(p, 2);
    }
    if (p.len >= 1 and winIsSepByte(p[0])) return 1;
    return 0;
}

/// Lexically normalise a path: resolve "." and ".." segments, collapse
/// doubled separators. Pure lexical pass (no fs); makes ".." traversal
/// impossible to hide from the prefix check. Host-grammar wrapper.
fn normalizeLexical(arena: Allocator, path: []const u8) ![]const u8 {
    return normalizeLexicalSty(arena, path, host_path_style);
}

/// Style-parameterised lexical normalisation. The POSIX arm is the
/// historical body, byte-for-byte. The Windows arm splits on BOTH
/// separators, keeps the DOS/UNC root unpoppable and rebuilds the path
/// with '\' separators — splitting only on '/' and re-prefixing every
/// path with it made a new file under a Windows canon come out
/// "/C:\allow\new.txt": unmatchable even against the root prefix, a
/// fail-closed dead policy on Windows. Pure: the Linux CI pins the
/// Windows contract (see the Windows-grammar tests).
pub fn normalizeLexicalSty(arena: Allocator, path: []const u8, style: PathStyle) ![]const u8 {
    if (!style.win_roots) {
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

    // Windows arm: keep the DOS/UNC root, split on both separators, join
    // with '\'. ".." never pops the root (the same rule POSIX applies
    // above "/").
    var out: std.ArrayList(u8) = .empty;
    var rest: []const u8 = path;
    var have_root = false;
    if (try winRootParts(arena, path)) |rp| {
        try out.appendSlice(arena, rp.text);
        rest = rp.rest;
        have_root = true;
    }
    var stack: std.ArrayList([]const u8) = .empty;
    var it = std.mem.splitAny(u8, rest, style.seps);
    while (it.next()) |seg| {
        if (seg.len == 0) continue; // doubled separators, trailing sep
        if (std.mem.eql(u8, seg, ".")) continue;
        if (std.mem.eql(u8, seg, "..")) {
            if (stack.items.len > 0) {
                _ = stack.pop();
            }
            continue;
        }
        try stack.append(arena, seg);
    }
    if (stack.items.len == 0) {
        if (!have_root) return arena.dupe(u8, ".");
        // The bare root, trailing separator preserved (the analog of
        // POSIX "/..": the root is the result). Sliced, not rebuilt: with
        // no components to join there is no separator spelling to fix.
        return arena.dupe(u8, path[0..winRootLen(path)]);
    }
    for (stack.items) |seg| {
        try out.append(arena, '\\');
        try out.appendSlice(arena, seg);
    }
    return out.items;
}

/// Canonicalise a path for policy matching. The order matters and mirrors
/// the kernel: symlink resolution FIRST (realpath on the raw path), lexical
/// ".." collapse SECOND — collapsing first would let "symlink/../x" hide the
/// symlink from realpath while the kernel still resolves it.
/// For a path whose tail does not exist yet we realpath the deepest
/// existing ancestor OF THE RAW FORM, then lexically normalise the joined
/// result, so a symlinked segment can never smuggle ".." past the check.
/// A tail component that EXISTS yet does not resolve is a symlink whose
/// target is gone (or looped): the kernel would still follow the final
/// symlink on an O_CREAT open, silently writing outside every allowed
/// prefix, so canonicalisation fails closed there.
/// The TOCTOU race between this string-level authorisation and the open
/// is closed by the secure-open pipeline: checkCallEx also emits a
/// `FilePin` (matched allow prefix + canonical path + deny list), and
/// the file tools open through os.secure.openPinned, which re-opens the
/// prefix and the target relative to a pinned dirfd and verifies the
/// opened descriptor's kernel path — one kernel-resolved object serves
/// both the decision and the access (see src/os/secure.zig).
pub fn canonicalizePath(arena: Allocator, io: Io, path: []const u8) ![]const u8 {
    return canonicalizePathOpt(arena, io, path, .{});
}

/// Exec semantics: a leading "~" stays a LITERAL relative component and a
/// relative path anchors to `base` (the effective child cwd) — exactly the
/// strings the kernel will see, because the exec tools pass argv[0]/cwd
/// verbatim (tools.zig never calls expandPath there; TOOLS_JSON contract
/// "Passed verbatim"). Expanding "~" here would authorize $HOME/... while
/// the child execs <cwd>/~/... — two different files.
pub fn canonicalizePathExec(arena: Allocator, io: Io, path: []const u8, base: []const u8) ![]const u8 {
    return canonicalizePathOpt(arena, io, path, .{ .base = base, .expand_tilde = false });
}

pub const CanonicalizeOpts = struct {
    /// Base a relative `path` anchors to before the daemon cwd (the
    /// effective child cwd for exec argv[0]; see checkExecArgs).
    base: []const u8 = "",
    /// Expand a leading "~"/"~/" to $HOME. true for FILE tool paths
    /// (read/write/list gate what tools.expandPath actually opens); false
    /// for exec argv[0]/cwd, which the kernel receives verbatim.
    expand_tilde: bool = true,
};

/// Same, parameterised by `opts` (see CanonicalizeOpts).
pub fn canonicalizePathOpt(arena: Allocator, io: Io, path: []const u8, opts: CanonicalizeOpts) ![]const u8 {
    var p = path;
    // "~"/"~/x" expansion — FILE semantics only (same rules as
    // tools.expandPath: "~" and "~/" expand, "~user" stays). Exec paths
    // never take this branch: for the kernel a leading "~" is a plain
    // relative component, and expanding it would gate a path the child
    // never touches.
    if (opts.expand_tilde) {
        if (p.len > 0 and p[0] == '~') {
            if (p.len == 1 or p[1] == '/') {
                if (os.homeDir(arena, env_state.process_environ)) |home| {
                    if (home.len != 0) p = try std.mem.concat(arena, u8, &.{ home, p[1..] });
                }
            }
        }
    }
    if (!std.fs.path.isAbsolute(p)) {
        // Anchor: `base` (the effective child cwd) when given, else the
        // daemon cwd. A relative `base` is where the child chdirs FROM the
        // daemon cwd, so it is anchored first — the composed path must be
        // absolute before the realpath/lexical steps: a relative composed
        // string falls through to normalizeLexical when nothing on the
        // chain exists, and normalizeLexical always re-prefixes with '/',
        // fabricating a root-anchored tree ("/sub/runner" instead of
        // "<daemoncwd>/sub/runner") and breaking the p[tail_start] == '/'
        // invariant of assertTailAbsent.
        var cwd = if (opts.base.len != 0) opts.base else try std.process.currentPathAlloc(io, arena);
        if (!std.fs.path.isAbsolute(cwd)) {
            const dcwd = try std.process.currentPathAlloc(io, arena);
            cwd = try std.mem.concat(arena, u8, &.{ dcwd, "/", cwd });
        }
        p = try std.mem.concat(arena, u8, &.{ cwd, "/", p });
    }

    // Kernel order, step 1: the full raw path exists -> one realpath
    // resolves every symlink exactly like the open will.
    if (realPathOf(arena, io, p)) |rp| {
        return rp;
    } else |_| {}

    // Step 2: the tail is new (write_file creating a file). Realpath the
    // deepest existing ancestor OF THE RAW PATH — symlinked segments stay
    // visible — then re-attach the raw tail and collapse ".." lexically on
    // the REALPATHED prefix, never on the raw form. Before re-attaching,
    // every tail component must be genuinely absent: one that exists but
    // no longer resolves is a dangling/looping symlink the raw open would
    // follow outside the allowed tree.
    var dir = std.fs.path.dirname(p) orelse {
        try assertTailAbsent(io, p, 0);
        return try normalizeLexical(arena, p);
    };
    while (dir.len > 1) {
        if (realPathOf(arena, io, dir)) |rp| {
            const tail = p[dir.len..]; // keeps its leading '/'
            try assertTailAbsent(io, p, dir.len);
            const joined = try std.mem.concat(arena, u8, &.{ rp, tail });
            return try normalizeLexical(arena, joined);
        } else |_| {}
        dir = std.fs.path.dirname(dir) orelse {
            try assertTailAbsent(io, p, 0);
            return try normalizeLexical(arena, p);
        };
    }
    // Nothing exists up the chain ("/" always does, but no component of
    // the tail resolved): lexical form only, after the same dangling-
    // symlink tail check — a first-level "/x" symlink whose target is gone
    // would otherwise pass the prefix check and O_CREAT through it. The
    // prefix check still applies; an allowlist root that does not exist is
    // unusable anyway.
    try assertTailAbsent(io, p, 0);
    return try normalizeLexical(arena, p);
}

/// Walk the non-existent tail (`p[tail_start..]`, starting on a '/')
/// component by component. Every raw prefix ending at a component boundary
/// must either not exist (ENOENT — the tail is legally new) or sit behind a
/// regular-file ancestor (NotDir — the kernel will refuse the raw open on
/// its own, so no escape is possible). A prefix that exists yet does not
/// realpath is a symlink: readLink succeeds on it while full resolution
/// failed, i.e. the target is gone or looped. An O_CREAT open of the raw
/// path would follow that final symlink and create the attacker's file
/// outside every allowed prefix, so this is a hard error (fail closed).
/// Any other readLink failure (exists but unreadable, loop in an ancestor,
/// resources) is likewise fail-closed: unverifiable means denied.
fn assertTailAbsent(io: Io, p: []const u8, tail_start: usize) !void {
    return assertTailAbsentSty(io, p, tail_start, host_path_style);
}

/// The walk uses the parameterised separator set — a Windows tail
/// separates components with '\', and a '/'-only scan never sees them
/// (the whole tail reads as ONE component, so only the final boundary is
/// ever probed). Starting at 0 on a Windows form, the
/// walk begins ON the root's trailing separator: the DOS/UNC root is not
/// a probed component — readLink("C:") is not a probe the kernel makes.
fn assertTailAbsentSty(io: Io, p: []const u8, tail_start: usize, style: PathStyle) !void {
    var i = tail_start; // p[tail_start] is a separator (or a root boundary)
    if (style.win_roots and tail_start == 0) {
        const root_len = winRootLen(p);
        i = if (root_len > 0 and winIsSepByte(p[root_len - 1])) root_len - 1 else root_len;
    }
    while (i < p.len) {
        const next = styleSepPos(p, i + 1, style) orelse p.len;
        // Skip empty components ("//", trailing '/'): the kernel does.
        if (next > i + 1) {
            var buf: [std.fs.max_path_bytes]u8 = undefined;
            if (std.Io.Dir.cwd().readLink(io, p[0..next], &buf)) |_| {
                return error.UnresolvedSymlinkInPath;
            } else |err| switch (err) {
                error.FileNotFound => {}, // component absent: legal new tail
                error.NotDir => {}, // regular-file ancestor: kernel refuses
                else => return err, // exists-but-unresolvable: fail closed
            }
        }
        i = next;
    }
}

fn realPathOf(arena: Allocator, io: Io, absolute: []const u8) ![]const u8 {
    return std.Io.Dir.cwd().realPathFileAlloc(io, absolute, arena);
}

/// Segment-aligned prefix match: `prefix` matches `path` when path equals
/// the prefix or continues it with a separator. "/a/p" never matches
/// "/a/pwn". Host-grammar wrapper (see pathHasPrefixSty).
pub fn pathHasPrefix(path: []const u8, prefix: []const u8) bool {
    return pathHasPrefixSty(path, prefix, host_path_style);
}

/// Style-parameterised segment-aligned prefix match. On the Windows
/// style the boundary separator may be '/' or
/// '\' and the comparison folds ASCII case — for allow AND deny equally:
/// a deny prefix that did not exist at load time keeps the operator's
/// spelling ("C:\data\secret") while the realpath of the requested target
/// answers the on-disk spelling ("C:\data\Secret"); a case-sensitive deny
/// comparison would MISS and the allow match would land — deny-wins
/// semantics demands the fold on both lists. Pure: unit-tested on every
/// CI platform.
pub fn pathHasPrefixSty(path: []const u8, prefix: []const u8, style: PathStyle) bool {
    if (prefix.len == 0) return false;
    if (!styleStartsWith(path, prefix, style)) return false;
    if (path.len == prefix.len) return true;
    // A prefix ending in a separator (the root "/" or "C:\") matches
    // everything under it.
    if (styleIsSep(style, prefix[prefix.len - 1])) return true;
    return styleIsSep(style, path[prefix.len]);
}

fn prefixAllowed(path: []const u8, allow: []const []const u8, deny: []const []const u8) bool {
    return prefixAllowedSty(path, allow, deny, host_path_style);
}

/// Style-parameterised allow/deny evaluation. deny wins, longest-match
/// ordering downstream: the style parameterises the grammar only, the
/// semantics are untouched.
fn prefixAllowedSty(path: []const u8, allow: []const []const u8, deny: []const []const u8, style: PathStyle) bool {
    for (deny) |d| {
        if (pathHasPrefixSty(path, d, style)) return false;
    }
    for (allow) |a| {
        if (pathHasPrefixSty(path, a, style)) return true;
    }
    return false;
}

/// argv[0] path-form separator set: '/' everywhere, plus '\\' on Windows,
/// where `C:\tools\x.exe` is a PATH-FORM request. Classing the Windows
/// form as a bare name made resolvePinnedArgv0Windows join it under every
/// PATH entry — every spawn failed, fail-closed but broken.
const argv0_separators: []const u8 = if (builtin.os.tag == .windows) "/\\" else "/";

/// True when `s` contains any of `seps`. Pure: the separator contract is
/// unit-testable on every CI platform.
pub fn hasPathSeparator(s: []const u8, seps: []const u8) bool {
    return std.mem.indexOfAny(u8, s, seps) != null;
}

fn argv0HasSeparator(s: []const u8) bool {
    return hasPathSeparator(s, argv0_separators);
}

/// Shell names this build can spawn; mirrors the comptime allowlist in
/// tools.toolExecShell. The load-time exec_argv0 check compares by
/// BASENAME, so an operator may write "/bin/sh" instead of "sh" (a
/// whole-string comparison refused the documented absolute spelling).
pub const spawnable_shells: []const []const u8 = if (builtin.os.tag == .windows)
    &.{ "cmd", "powershell" }
else
    &.{ "bash", "sh", "zsh", "fish" };

/// True when `entry` — a bare name or any path form — names one of the
/// shells this build can spawn. Paths are matched by basename only; the
/// entry itself stays verbatim in the policy.
pub fn namesSpawnableShell(entry: []const u8) bool {
    const base = std.fs.path.basename(entry);
    for (spawnable_shells) |shell| {
        if (std.mem.eql(u8, base, shell)) return true;
    }
    return false;
}

/// The tool accepts only supported bare shell names, never caller paths.
pub fn supportedShell(name: []const u8) bool {
    return !argv0HasSeparator(name) and namesSpawnableShell(name);
}

/// Only exec_shell may match the original basename of a path entry.
/// Raw exec/exec_start keep their strict bare/path boundary below.
pub fn shellAllowed(pol: *const TokenPolicy, name: []const u8) bool {
    if (!supportedShell(name)) return false;
    if (pol.allow_all) return true;
    for (pol.exec_argv0) |entry| {
        const candidate = entry.shell_name orelse std.fs.path.basename(entry.text);
        if (std.mem.eql(u8, candidate, name)) return true;
    }
    return false;
}

const shell_names_list: []const u8 = if (builtin.os.tag == .windows) "cmd, powershell" else "sh, bash, zsh, fish";

/// Refusal text for an exec_shell policy whose exec_argv0 lists no
/// spawnable shell. It names the fix, including the accepted spellings.
pub const shell_refusal: []const u8 = std.fmt.comptimePrint(
    "exec_shell is listed but exec_argv0 must list a spawnable shell by bare or absolute name ({s})",
    .{shell_names_list},
);

/// Match a requested argv[0] against the allowlist: bare names match bare
/// requests exactly; slash entries (both sides canonicalised) match each
/// other. No cross-boundary matching — allowing "python3" never authorises
/// "/usr/bin/python3" and vice versa.
pub fn argv0Allowed(policy: *const TokenPolicy, argv0: []const u8, canon: []const u8) bool {
    const req_has_slash = argv0HasSeparator(argv0);
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

/// Alias so rpc.zig (and tests) can name the pin type without importing
/// the os layer: the gate's authorization binding for a file-tool call.
pub const FilePin = os.secure.Pin;

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
    /// Base a RELATIVE argv0 with a separator resolves against: the
    /// canonical effective child cwd (checkExecArgs passes the canon
    /// checkCwd retained — the pinned spawn fchdirs into THAT directory
    /// object, so the child's relative resolution starts from the
    /// canonical directory, never the raw cwd string). Bare names (PATH
    /// search) never use the base.
    base: []const u8,
    /// Retained canonical argv[0]: set only when argv0 contains a
    /// separator, because only then is the canon the exec target (a bare
    /// name is PATH-searched — its anchored "canon" would name a
    /// different object). checkExecArgs builds the ExecPin from THIS
    /// value, so the pin can never be a second, unauthorized
    /// re-canonicalisation.
    out_canon: ?*[]const u8,
) DenyError!void {
    if (out_canon) |oc| oc.* = "";
    if (policy.allow_all) return;
    if (!policy.needsExec()) return error.PolicyDenied;
    // Fail closed: a canonicalisation failure denies the call instead of
    // falling back to the raw string a prefix check would trust. Exec
    // semantics: "~" stays literal, a relative argv0 anchors to `base`.
    // The bare-name
    // case still canonicalises (fail-closed parity with the old path)
    // but never publishes the canon: argv0Allowed matches the raw name.
    const canon = canonicalizePathExec(arena, io, argv0, base) catch return error.PolicyDenied;
    if (out_canon) |oc| {
        // The platform separator set decides: on Windows a
        // `C:\tools\x.exe` argv[0] is path-form and its canon IS the exec
        // target; on POSIX a backslash is an ordinary name character.
        if (argv0HasSeparator(argv0)) oc.* = canon;
    }
    if (!argv0Allowed(policy, argv0, canon)) return error.PolicyDenied;
}

pub fn checkCwd(
    arena: Allocator,
    io: Io,
    policy: *const TokenPolicy,
    cwd: []const u8,
    /// Retained canonical cwd: set as soon as canonicalisation itself
    /// succeeded — even when the prefix check below denies, so the
    /// deny-message tag and the ExecPin talk about the ONE canon the
    /// policy evaluated. "" on canon failure
    /// and for the inherit/allow_all shapes.
    out_canon: ?*[]const u8,
) DenyError!void {
    if (out_canon) |oc| oc.* = "";
    if (policy.allow_all) return;
    if (cwd.len == 0) return; // inherit: always allowed
    // Fail closed on canonicalisation failure. Exec semantics: the child
    // chdirs into the cwd VERBATIM, so "~" is a literal component
    // anchored to the daemon cwd — not $HOME.
    const canon = canonicalizePathExec(arena, io, cwd, "") catch return error.PolicyDenied;
    if (out_canon) |oc| oc.* = canon;
    if (!prefixAllowed(canon, policy.exec_cwd, policy.cwd_deny)) return error.PolicyDenied;
}

pub fn checkPath(arena: Allocator, io: Io, policy: *const TokenPolicy, path: []const u8, kind: PathKind) DenyError!void {
    if (policy.allow_all) return;
    // Fail closed on canonicalisation failure. The
    // `.cwd` kind gates exec cwd semantics (literal "~"); read/write are
    // file semantics (tools.expandPath expands "~" before the open).
    const canon = (if (kind == .cwd)
        canonicalizePathExec(arena, io, path, "")
    else
        canonicalizePath(arena, io, path)) catch return error.PolicyDenied;
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
        // i64 space end to end: a negative mode can never pass the cast
        // (@intCast of a negative would panic in ReleaseSafe).
        if (mode < 0) return error.PolicyDenied;
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

test "policy: exec_argv0 shell check matches by basename" {
    // The load-time shell check compares by basename: comparing the WHOLE
    // exec_argv0 entry refused the documented "/bin/sh" spelling and the
    // node would not start while a bare "sh" entry was required.
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;
    try testing.expect(namesSpawnableShell("sh"));
    try testing.expect(namesSpawnableShell("bash"));
    try testing.expect(namesSpawnableShell("/bin/sh"));
    try testing.expect(namesSpawnableShell("/bin/bash"));
    try testing.expect(namesSpawnableShell("/usr/local/bin/zsh"));
    try testing.expect(namesSpawnableShell("/opt/tools/fish"));
    try testing.expect(!namesSpawnableShell("git"));
    try testing.expect(!namesSpawnableShell("/usr/bin/python3"));
    try testing.expect(!namesSpawnableShell("/opt/shells/bashish"));
    // The refusal names the acceptable spellings instead of only the field.
    try testing.expect(std.mem.indexOf(u8, shell_refusal, "bare or absolute name") != null);
    try testing.expect(std.mem.indexOf(u8, shell_refusal, "sh, bash") != null);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = Io.Threaded.global_single_threaded.io();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try writeSecret(tmp.dir, io, "tok", "secret\n");
    const tok_abs = try tmpAbs(arena, &tmp, io, "tok");

    // "/bin/sh" with exec_shell loads: the absolute spelling is spawnable.
    var ok_json: std.ArrayList(u8) = .empty;
    try ok_json.print(arena, "{{\"version\":1,\"tokens\":[{{\"file\":\"{s}\",\"tools\":[\"exec\",\"exec_shell\"],\"exec_argv0\":[\"/bin/sh\",\"/usr/bin/python3\",\"python3\"],\"read_paths\":[\"/srv\"]}}]}}", .{tok_abs});
    try writeSecret(tmp.dir, io, "shell-abs", ok_json.items);
    const ok_path = try tmpAbs(arena, &tmp, io, "shell-abs");
    var ps = try loadPolicyFile(arena, io, ok_path);
    defer freePolicy(&ps);
    try testing.expectEqual(@as(usize, 3), ps.entries[0].exec_argv0.len);
    try testing.expect(ps.entries[0].exec_argv0[0].has_slash);

    // A nested absolute shell path is accepted too.
    var nested_json: std.ArrayList(u8) = .empty;
    try nested_json.print(arena, "{{\"version\":1,\"tokens\":[{{\"file\":\"{s}\",\"tools\":[\"exec_shell\"],\"exec_argv0\":[\"/usr/local/bin/zsh\"],\"read_paths\":[\"/srv\"]}}]}}", .{tok_abs});
    try writeSecret(tmp.dir, io, "shell-nested", nested_json.items);
    const nested_path = try tmpAbs(arena, &tmp, io, "shell-nested");
    var nested = try loadPolicyFile(arena, io, nested_path);
    freePolicy(&nested);

    // A bogus name is still refused at load, not at call time.
    var bad_json: std.ArrayList(u8) = .empty;
    try bad_json.print(arena, "{{\"version\":1,\"tokens\":[{{\"file\":\"{s}\",\"tools\":[\"exec_shell\"],\"exec_argv0\":[\"/usr/bin/python3\",\"git\"],\"read_paths\":[\"/srv\"]}}]}}", .{tok_abs});
    try writeSecret(tmp.dir, io, "shell-bogus", bad_json.items);
    const bad_path = try tmpAbs(arena, &tmp, io, "shell-bogus");
    try testing.expectError(error.InvalidPolicy, loadPolicyFile(arena, io, bad_path));
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

test "policy: windows prefix grammar matches backslash descendants and folds deny" {
    // Pure logic on the Windows style: the boundary separator may be
    // '\' as well as '/', and the comparison folds ASCII case for allow
    // AND deny — a deny prefix
    // that did not exist at load time keeps the operator's spelling
    // ("C:\data\secret") while realpath answers the on-disk spelling
    // ("C:\data\Secret"): a case-sensitive deny would MISS and the allow
    // match would land.
    const w = PathStyle.windows;
    // Descendant via backslash, and via either separator spelling (each
    // side internally consistent: the normaliser guarantees the '\'
    // canonical spelling on both operands, the matcher does not need to
    // fold one spelling into the other).
    try testing.expect(pathHasPrefixSty("C:\\a\\b", "C:\\a", w));
    try testing.expect(pathHasPrefixSty("C:\\a", "C:\\a", w));
    try testing.expect(pathHasPrefixSty("C:/a/b", "C:/a", w));
    // Sibling-prefix rejection survives the grammar change.
    try testing.expect(!pathHasPrefixSty("C:\\ab", "C:\\a", w));
    try testing.expect(!pathHasPrefixSty("C:\\a", "C:\\ab", w));
    // Case fold (NTFS): either side may carry the other's case.
    try testing.expect(pathHasPrefixSty("c:\\A\\B", "C:\\a", w));
    // A prefix ending in a separator is a root: everything under it.
    try testing.expect(pathHasPrefixSty("C:\\a\\b", "C:\\", w));
    // UNC descendants and sibling shares.
    try testing.expect(pathHasPrefixSty("\\\\srv\\share\\a\\b", "\\\\srv\\share", w));
    try testing.expect(!pathHasPrefixSty("\\\\srv\\share2\\a", "\\\\srv\\share", w));
    // Deny wins over allow, folded both ways.
    try testing.expect(!prefixAllowedSty("C:\\Data\\Secret", &.{"C:\\data"}, &.{"C:\\data\\secret"}, w));
    try testing.expect(prefixAllowedSty("C:\\Data\\pub\\f", &.{"C:\\data"}, &.{"C:\\data\\secret"}, w));
    // Allow folds too (operator spelling vs realpath spelling).
    try testing.expect(prefixAllowedSty("C:\\Data\\Secret", &.{"c:\\data"}, &.{}, w));
    // The POSIX style stays byte-exact: no fold, no '\' boundary.
    try testing.expect(!pathHasPrefixSty("C:\\a\\b", "C:\\a", PathStyle.posix));
    try testing.expect(pathHasPrefixSty("/a/b", "/a", PathStyle.posix));
}

test "policy: windows lexical normalization keeps DOS and UNC roots" {
    // A '/'-only normalize re-prefixes every path with '/', so a new file
    // under a Windows canon comes out "/C:\allow\new.txt" — unmatchable
    // even against the root prefix.
    // The Windows arm keeps the drive/UNC root, splits on both
    // separators, rebuilds with '\' and never fabricates a leading '/'.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const w = PathStyle.windows;
    // New-file canon: root preserved, no leading '/'.
    try testing.expectEqualStrings("C:\\allow\\new.txt", try normalizeLexicalSty(arena, "C:\\allow\\new.txt", w));
    // Traversal and "." collapse inside the tail; the root is unpoppable.
    try testing.expectEqualStrings("C:\\allow\\b", try normalizeLexicalSty(arena, "C:\\allow\\x\\..\\b", w));
    try testing.expectEqualStrings("C:\\allow\\b", try normalizeLexicalSty(arena, "C:\\allow\\.\\b", w));
    try testing.expectEqualStrings("C:\\", try normalizeLexicalSty(arena, "C:\\..\\a\\..\\..", w));
    // Mixed separator spellings collapse to the '\' canonical form (the
    // pin post-check folds case but NOT separators).
    try testing.expectEqualStrings("C:\\a\\b", try normalizeLexicalSty(arena, "C:/a//b", w));
    try testing.expectEqualStrings("C:\\a\\b", try normalizeLexicalSty(arena, "C:\\\\a\\\\b", w));
    // UNC root: two components, never popped by "..".
    try testing.expectEqualStrings("\\\\srv\\share\\a", try normalizeLexicalSty(arena, "\\\\srv\\share\\a", w));
    try testing.expectEqualStrings("\\\\srv\\share\\a", try normalizeLexicalSty(arena, "\\\\srv\\share\\..\\a", w));
    // Verbatim spellings keep their namespace marker.
    try testing.expectEqualStrings("\\\\?\\C:\\allow\\new.txt", try normalizeLexicalSty(arena, "\\\\?\\C:\\allow\\new.txt", w));
    try testing.expectEqualStrings("\\\\?\\UNC\\srv\\share\\a", try normalizeLexicalSty(arena, "\\\\?\\UNC\\srv\\share\\a", w));
    // The POSIX arm is untouched.
    try testing.expectEqualStrings("/a/b", try normalizeLexicalSty(arena, "/a/x/../b", PathStyle.posix));
    try testing.expectEqualStrings("/", try normalizeLexicalSty(arena, "/..", PathStyle.posix));
}

test "policy: windows filePin rel is a real relative path" {
    // rel must be genuinely relative — no leading separator (a single-'/'
    // cut leaves "\sub\a.txt" on a Windows canon, an invalid relative
    // open) and no drive/namespace qualification (the
    // matched prefix covers the canon's root bytes). Longest match wins.
    const w = PathStyle.windows;
    const pin = filePinSty("C:\\Allow\\sub\\a.txt", &.{ "C:\\al", "C:\\allow" }, &.{}, w).?;
    try testing.expectEqualStrings("C:\\allow", pin.prefix);
    try testing.expectEqualStrings("sub\\a.txt", pin.rel);
    try testing.expectEqualStrings("C:\\Allow\\sub\\a.txt", pin.canon);
    // Root prefix: rel is the whole remainder, still clean.
    const pin2 = filePinSty("C:\\a\\b", &.{"C:\\"}, &.{}, w).?;
    try testing.expectEqualStrings("a\\b", pin2.rel);
    // Sibling-prefix rejection is grammar-level: C:\ab is not under C:\a.
    try testing.expect(filePinSty("C:\\ab\\x", &.{"C:\\a"}, &.{}, w) == null);
    // UNC prefix.
    const pin3 = filePinSty("\\\\srv\\share\\sub\\a", &.{"\\\\srv\\share"}, &.{}, w).?;
    try testing.expectEqualStrings("sub\\a", pin3.rel);
    // POSIX arm: the unchanged single-'/' cut.
    const pin4 = filePinSty("/srv/sub/a", &.{"/srv"}, &.{}, PathStyle.posix).?;
    try testing.expectEqualStrings("sub/a", pin4.rel);
}

test "policy: tail absence walk sees backslash components" {
    // The walk splits tail components on '\' too. A symlink
    // named "C:\a" (backslash is a legal POSIX filename byte) sits at a
    // component boundary in the Windows grammar and MUST be probed; in
    // the POSIX grammar the same bytes are ONE absent component and the
    // walk passes. That difference is exactly what this test pins.
    if (builtin.os.tag == .windows) return error.SkipZigTest; // pins the walk logic, not the Windows fs
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = Io.Threaded.global_single_threaded.io();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const root = try tmpAbs(arena, &tmp, io, ".");
    // symlink "C:\a" -> the tmp root itself (any existing target works).
    tmp.dir.symLink(io, ".", "C:\\a", .{}) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    // The walk probes FULL prefixes (p[0..next]) through cwd-relative
    // readLink; on Linux '\' is a filename byte, so the windows-style
    // probe strings only resolve when the cwd holds the fixture. The
    // process cwd is saved and restored around the two probes.
    const saved_cwd = try std.process.currentPathAlloc(io, arena);
    try std.Io.Threaded.chdir(root);
    defer std.Io.Threaded.chdir(saved_cwd) catch {};
    const p = "C:\\a\\b";
    // POSIX grammar: the whole string is ONE absent component -> legal
    // new tail.
    try assertTailAbsentSty(io, p, 0, .posix);
    // Windows grammar: "C:\a" is a probed component, it is a symlink ->
    // fail closed before any file is created through it.
    try testing.expectError(error.UnresolvedSymlinkInPath, assertTailAbsentSty(io, p, 0, .windows));
}

test "policy: exec_start skips the timeout cap" {
    // exec_start has NO `timeout` argument —
    // the session is bounded by exec_wait/exec_poll/exec_kill, not by the
    // spawn. The old unconditional 120s default-cap denied exec_start
    // under every max_timeout_s < 120, while a phantom "timeout" field
    // (never read by toolExecStart) let the identical call through.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = Io.Threaded.global_single_threaded.io();
    const pol = TokenPolicy{
        .file = "f",
        .token_hash = [_]u8{0} ** 32,
        .tools = &.{ "exec", "exec_start" },
        .exec_argv0 = &.{.{ .text = "sh", .has_slash = false }},
        .exec_cwd = &.{},
        .cwd_deny = &.{},
        .max_timeout_s = 10,
        .read_paths = &.{},
        .write_paths = &.{},
        .read_deny = &.{},
        .write_deny = &.{},
    };
    var argv: std.json.Array = .init(arena);
    try argv.append(.{ .string = "sh" });
    var args: std.json.ObjectMap = .empty;
    try args.put(arena, "argv", .{ .array = argv });
    // exec under a cap of 10: the 120s default denies (unchanged rule).
    if (checkCall(arena, io, undefined, &pol, "exec", .{ .object = args })) |d| {
        try testing.expectEqualStrings("timeout_exceeds_cap", d.reason_tag);
    } else return error.TestUnexpectedResult;
    // exec_start: no timeout argument, same cap -> allowed.
    try testing.expect(checkCall(arena, io, undefined, &pol, "exec_start", .{ .object = args }) == null);
    // A phantom "timeout" field is not validated either way: the tool
    // never reads it for exec_start.
    var phantom: std.json.ObjectMap = .empty;
    var argv2: std.json.Array = .init(arena);
    try argv2.append(.{ .string = "sh" });
    try phantom.put(arena, "argv", .{ .array = argv2 });
    try phantom.put(arena, "timeout", .{ .integer = 600 });
    try testing.expect(checkCall(arena, io, undefined, &pol, "exec_start", .{ .object = phantom }) == null);
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

test "policy: argv0 separator detection covers the windows backslash form" {
    // Pure logic: on Windows the separator
    // set is "/\\" — `C:\tools\x.exe` is a path-form request. The old
    // detector probes only '/', so the Windows form is classed BARE and
    // resolvePinnedArgv0Windows joins it under every PATH entry (every
    // spawn refused: fail-closed but functionally broken). The detector's
    // platform delta is comptime, so the Linux CI pins the primitive with
    // explicit sets — the base's single-'/' probe demonstrably cannot see
    // the Windows form (that miss IS the defect).
    const win = "C:\\tools\\x.exe";
    // The base detector's exact probe: no '/' anywhere in the Windows form.
    try testing.expect(std.mem.indexOfScalar(u8, win, '/') == null);
    // The fixed set classifies it as path-form...
    try testing.expect(hasPathSeparator(win, "/\\"));
    // ...while the POSIX set still does not (a backslash in a POSIX name
    // is not a separator; argv0 "foo\\bar" stays bare on POSIX).
    try testing.expect(!hasPathSeparator(win, "/"));
    // Bare names stay bare under either set; the empty string is bare.
    try testing.expect(!hasPathSeparator("mytool", "/\\"));
    try testing.expect(!hasPathSeparator("", "/\\"));
    // POSIX forms match the POSIX set.
    try testing.expect(hasPathSeparator("/usr/bin/env", "/"));
    try testing.expect(hasPathSeparator("./runner", "/"));
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
    try checkArgv0(arena, io, &pol, "anything", "", null);
    try checkCwd(arena, io, &pol, "/any/where", null);
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
    // "The kernel resolves a symlinked segment and '..' in the OPPOSITE
    // order of a lexical pre-collapse": "allow/esc/../outside"
    // must canonicalise OUTSIDE the allow tree, because the kernel would
    // open it there.
    const smuggle = try std.mem.concat(arena, u8, &.{ root, "/allow/esc/../outside" });
    const canon4 = try canonicalizePath(arena, io, smuggle);
    try testing.expect(std.mem.endsWith(u8, canon4, "/outside"));
    try testing.expect(std.mem.indexOf(u8, canon4, "/allow") == null);
    // The same smuggle against a non-existing tail (write_file shape):
    // realpath of the raw existing ancestor resolves esc, the tail is
    // re-attached, then collapsed — still outside.
    const smuggle2 = try std.mem.concat(arena, u8, &.{ root, "/allow/esc/../outside/new.txt" });
    const canon5 = try canonicalizePath(arena, io, smuggle2);
    try testing.expect(std.mem.endsWith(u8, canon5, "/outside/new.txt"));
    try testing.expect(std.mem.indexOf(u8, canon5, "/allow") == null);
}

test "policy: argument-type grammar matches the tool layer" {
    // A present-but-wrong-type or float-typed mode/timeout must
    // be DENIED (or converted exactly like the tool), never skipped.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = Io.Threaded.global_single_threaded.io();

    const pol = TokenPolicy{
        .file = "f",
        .token_hash = [_]u8{0} ** 32,
        .tools = &.{ "write_file", "exec", "exec_wait", "exec_shell" },
        .exec_argv0 = &.{.{ .text = "sh", .has_slash = false }},
        .max_timeout_s = 10,
        .write_max_mode = 0o644,
        .read_paths = &.{},
        .write_paths = &.{"/srv"},
        .read_deny = &.{},
        .write_deny = &.{},
        .cwd_deny = &.{},
        .exec_cwd = &.{},
    };

    // mode as an integral float converts and is checked (420.0 == 0o644 ok;
    // 2533.0 == 0o4755 over the cap -> denied).
    var args_ok: std.json.ObjectMap = .empty;
    try args_ok.put(arena, "path", .{ .string = "/srv/f" });
    try args_ok.put(arena, "content_b64", .{ .string = "aGk=" });
    try args_ok.put(arena, "mode", .{ .float = 420.0 });
    try testing.expect(checkCall(arena, io, undefined, &pol, "write_file", .{ .object = args_ok }) == null);

    var args_setuid: std.json.ObjectMap = .empty;
    try args_setuid.put(arena, "path", .{ .string = "/srv/f" });
    try args_setuid.put(arena, "content_b64", .{ .string = "aGk=" });
    try args_setuid.put(arena, "mode", .{ .float = 2533.0 });
    if (checkCall(arena, io, undefined, &pol, "write_file", .{ .object = args_setuid })) |d| {
        try testing.expectEqualStrings("write_mode_exceeds_cap", d.reason_tag);
    } else return error.TestUnexpectedResult;

    // negative mode: denied, never a @intCast panic.
    var args_neg: std.json.ObjectMap = .empty;
    try args_neg.put(arena, "path", .{ .string = "/srv/f" });
    try args_neg.put(arena, "content_b64", .{ .string = "aGk=" });
    try args_neg.put(arena, "mode", .{ .integer = -1 });
    if (checkCall(arena, io, undefined, &pol, "write_file", .{ .object = args_neg })) |d| {
        try testing.expectEqualStrings("write_mode_exceeds_cap", d.reason_tag);
    } else return error.TestUnexpectedResult;

    // wrong-type mode: bad_argument_type, not a silent skip.
    var args_str: std.json.ObjectMap = .empty;
    try args_str.put(arena, "path", .{ .string = "/srv/f" });
    try args_str.put(arena, "content_b64", .{ .string = "aGk=" });
    try args_str.put(arena, "mode", .{ .string = "0644" });
    if (checkCall(arena, io, undefined, &pol, "write_file", .{ .object = args_str })) |d| {
        try testing.expectEqualStrings("bad_argument_type", d.reason_tag);
    } else return error.TestUnexpectedResult;

    // omitted mode: the tool default 0644 is cap-checked; a 0600 cap
    // refuses an omitted mode, 0644 passes.
    var args_nomode: std.json.ObjectMap = .empty;
    try args_nomode.put(arena, "path", .{ .string = "/srv/f" });
    try args_nomode.put(arena, "content_b64", .{ .string = "aGk=" });
    try testing.expect(checkCall(arena, io, undefined, &pol, "write_file", .{ .object = args_nomode }) == null);
    var pol600 = pol;
    pol600.write_max_mode = 0o600;
    if (checkCall(arena, io, undefined, &pol600, "write_file", .{ .object = args_nomode })) |d| {
        try testing.expectEqualStrings("write_mode_exceeds_cap", d.reason_tag);
    } else return error.TestUnexpectedResult;

    // mode null: the tool applies its 0o644 default (optIntArg maps null
    // -> null -> orelse 0o644), so the gate must check that default
    // against the cap instead of refusing with bad_argument_type: that
    // default is allowed under a 0644 cap, refused under 0600.
    var args_mode_null: std.json.ObjectMap = .empty;
    try args_mode_null.put(arena, "path", .{ .string = "/srv/f" });
    try args_mode_null.put(arena, "content_b64", .{ .string = "aGk=" });
    try args_mode_null.put(arena, "mode", Value.null);
    try testing.expect(checkCall(arena, io, undefined, &pol, "write_file", .{ .object = args_mode_null }) == null);
    if (checkCall(arena, io, undefined, &pol600, "write_file", .{ .object = args_mode_null })) |d| {
        try testing.expectEqualStrings("write_mode_exceeds_cap", d.reason_tag);
    } else return error.TestUnexpectedResult;

    // v0.5.0 write_file content at the gate: presence/exclusivity is the
    // tool's shape rule (MissingContent/ConflictingContent, identical with
    // and without a policy file); the gate only refuses
    // present-but-wrong-typed content fields.
    var args_text: std.json.ObjectMap = .empty;
    try args_text.put(arena, "path", .{ .string = "/srv/f" });
    try args_text.put(arena, "content", .{ .string = "plain" });
    try testing.expect(checkCall(arena, io, undefined, &pol, "write_file", .{ .object = args_text }) == null);

    var args_both: std.json.ObjectMap = .empty;
    try args_both.put(arena, "path", .{ .string = "/srv/f" });
    try args_both.put(arena, "content", .{ .string = "plain" });
    try args_both.put(arena, "content_b64", .{ .string = "aGk=" });
    try testing.expect(checkCall(arena, io, undefined, &pol, "write_file", .{ .object = args_both }) == null);

    var args_neither: std.json.ObjectMap = .empty;
    try args_neither.put(arena, "path", .{ .string = "/srv/f" });
    try testing.expect(checkCall(arena, io, undefined, &pol, "write_file", .{ .object = args_neither }) == null);

    var args_badtype: std.json.ObjectMap = .empty;
    try args_badtype.put(arena, "path", .{ .string = "/srv/f" });
    try args_badtype.put(arena, "content", .{ .integer = 7 });
    if (checkCall(arena, io, undefined, &pol, "write_file", .{ .object = args_badtype })) |d| {
        try testing.expectEqualStrings("bad_argument_type", d.reason_tag);
        try testing.expectEqualStrings("content", d.field);
    } else return error.TestUnexpectedResult;

    // Explicit null content counts as absent: content_b64 alone passes.
    var args_null_text: std.json.ObjectMap = .empty;
    try args_null_text.put(arena, "path", .{ .string = "/srv/f" });
    try args_null_text.put(arena, "content", Value.null);
    try args_null_text.put(arena, "content_b64", .{ .string = "aGk=" });
    try testing.expect(checkCall(arena, io, undefined, &pol, "write_file", .{ .object = args_null_text }) == null);

    // exec timeout as float: 5.0 converts and passes; 600.0 denied.
    var argv_one: std.json.Array = .init(arena);
    try argv_one.append(.{ .string = "sh" });
    var t_ok: std.json.ObjectMap = .empty;
    try t_ok.put(arena, "argv", .{ .array = argv_one });
    try t_ok.put(arena, "timeout", .{ .float = 5.0 });
    try testing.expect(checkCall(arena, io, undefined, &pol, "exec", .{ .object = t_ok }) == null);
    var argv_two: std.json.Array = .init(arena);
    try argv_two.append(.{ .string = "sh" });
    var t_over: std.json.ObjectMap = .empty;
    try t_over.put(arena, "argv", .{ .array = argv_two });
    try t_over.put(arena, "timeout", .{ .float = 600.0 });
    if (checkCall(arena, io, undefined, &pol, "exec", .{ .object = t_over })) |d| {
        try testing.expectEqualStrings("timeout_exceeds_cap", d.reason_tag);
    } else return error.TestUnexpectedResult;

    // timeout null on exec: counts as the 120s default -> over a cap of 10
    // -> denied.
    var argv_three: std.json.Array = .init(arena);
    try argv_three.append(.{ .string = "sh" });
    var t_null: std.json.ObjectMap = .empty;
    try t_null.put(arena, "argv", .{ .array = argv_three });
    try t_null.put(arena, "timeout", Value.null);
    if (checkCall(arena, io, undefined, &pol, "exec", .{ .object = t_null })) |d| {
        try testing.expectEqualStrings("timeout_exceeds_cap", d.reason_tag);
    } else return error.TestUnexpectedResult;

    // exec_wait omitted timeout: the 30s default is cap-checked —
    // denied under a cap of 10, allowed under a cap of 60.
    var w: std.json.ObjectMap = .empty;
    try w.put(arena, "session_id", .{ .integer = 1 });
    if (checkCall(arena, io, undefined, &pol, "exec_wait", .{ .object = w })) |d| {
        try testing.expectEqualStrings("timeout_exceeds_cap", d.reason_tag);
    } else return error.TestUnexpectedResult;
    var pol60 = pol;
    pol60.max_timeout_s = 60;
    try testing.expect(checkCall(arena, io, undefined, &pol60, "exec_wait", .{ .object = w }) == null);

    // exec_shell with a non-string shell: bad_argument_type, never a null
    // unwrap.
    var sh_null: std.json.ObjectMap = .empty;
    try sh_null.put(arena, "script", .{ .string = "x" });
    try sh_null.put(arena, "shell", Value.null);
    if (checkCall(arena, io, undefined, &pol, "exec_shell", .{ .object = sh_null })) |d| {
        try testing.expectEqualStrings("bad_argument_type", d.reason_tag);
    } else return error.TestUnexpectedResult;
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
    if (std.mem.eql(u8, tag, "bad_argument_type")) return DenyReason.bad_argument_type.text();
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
        .bad_argument_type => "bad_argument_type",
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
    var pin: ?os.secure.Pin = null;
    var exec_pin: ?ExecPin = null;
    return checkCallEx(arena, io, cfg, pol, tool, args, &pin, &exec_pin);
}

/// Extended gate: decision-identical to checkCall, and additionally —
/// for the three file tools — emits the authorization binding the
/// secure open consumes (`os.secure.Pin`: matched allow prefix, the
/// canonical target, the same-kind deny list). The tool layer opens
/// through that pin, so the decision and the access operate on ONE
/// kernel-resolved object instead of a re-resolved string. An allow_all
/// decision emits no pin: the admin escape hatch keeps the raw-path
/// v0.3.1 behaviour by design.
pub fn checkCallEx(
    arena: Allocator,
    io: Io,
    cfg: *const @import("config.zig").Config,
    pol: *const TokenPolicy,
    tool: []const u8,
    args: Value,
    out_pin: *?os.secure.Pin,
    out_exec_pin: *?ExecPin,
) ?Deny {
    out_pin.* = null;
    out_exec_pin.* = null;
    if (std.mem.eql(u8, tool, "copy_path")) {
        var pins: ?CopyPins = null;
        return checkCopyArgs(arena, io, pol, args, &pins);
    }
    if (pol.allow_all) return null;
    if (!pol.toolAllowed(tool)) return .{ .reason_tag = denyTag(.tool_not_allowed), .field = "" };

    if (std.mem.eql(u8, tool, "exec") or std.mem.eql(u8, tool, "exec_start") or std.mem.eql(u8, tool, "exec_shell")) {
        return checkExecArgs(arena, io, pol, tool, args, out_exec_pin);
    }
    if (std.mem.eql(u8, tool, "read_file")) {
        // Absent/null path stays the tool's own MissingPath error; a
        // present non-string is the gate's bad_argument_type (the tool's
        // optStrArg would reject it too — same verdict, earlier).
        const path_v = util.objGet(args, "path") orelse return null;
        if (path_v == .null) return null;
        if (path_v != .string)
            return .{ .reason_tag = denyTag(.bad_argument_type), .field = "path" };
        const canon = canonicalizePath(arena, io, path_v.string) catch
            return .{ .reason_tag = denyTag(.path_not_allowed), .field = "path" };
        if (!prefixAllowed(canon, pol.read_paths, pol.read_deny)) {
            return .{ .reason_tag = if (deniedExplicitCanon(canon, pol.read_paths, pol.read_deny)) denyTag(.denied_path) else denyTag(.path_not_allowed), .field = "path" };
        }
        out_pin.* = filePin(canon, pol.read_paths, pol.read_deny);
        return null;
    }
    if (std.mem.eql(u8, tool, "list_dir")) {
        // The tool defaults an absent/null path to "." — a listing of the
        // DAEMON's cwd. The gate must evaluate that same effective path:
        // skipping the check let an allowlisted list_dir enumerate the
        // daemon cwd outside read_paths.
        const path: []const u8 = if (util.objGet(args, "path")) |pv| switch (pv) {
            .string => |s| s,
            .null => ".",
            else => return .{ .reason_tag = denyTag(.bad_argument_type), .field = "path" },
        } else ".";
        const canon = canonicalizePath(arena, io, path) catch
            return .{ .reason_tag = denyTag(.path_not_allowed), .field = "path" };
        if (!prefixAllowed(canon, pol.read_paths, pol.read_deny)) {
            return .{ .reason_tag = if (deniedExplicitCanon(canon, pol.read_paths, pol.read_deny)) denyTag(.denied_path) else denyTag(.path_not_allowed), .field = "path" };
        }
        out_pin.* = filePin(canon, pol.read_paths, pol.read_deny);
        return null;
    }
    if (std.mem.eql(u8, tool, "write_file")) {
        const path_v = util.objGet(args, "path") orelse return null;
        if (path_v == .null) return null; // tool's own MissingPath error
        if (path_v != .string)
            return .{ .reason_tag = denyTag(.bad_argument_type), .field = "path" };
        const canon = canonicalizePath(arena, io, path_v.string) catch
            return .{ .reason_tag = denyTag(.path_not_allowed), .field = "path" };
        if (!prefixAllowed(canon, pol.write_paths, pol.write_deny)) {
            return .{ .reason_tag = if (deniedExplicitCanon(canon, pol.write_paths, pol.write_deny)) denyTag(.denied_path) else denyTag(.path_not_allowed), .field = "path" };
        }
        out_pin.* = filePin(canon, pol.write_paths, pol.write_deny);
        // Argument-shape rule lives in the tool, not the gate: exactly one of
        // content / content_b64 is enforced by the tool as MissingContent /
        // ConflictingContent so the error name is identical with and without
        // a policy file. The gate only checks
        // per-token restrictions; a present-but-wrong-type content stays a
        // bad_argument_type refusal here.
        const content_v = util.objGet(args, "content");
        const b64_v = util.objGet(args, "content_b64");
        if (content_v != null and content_v.? != .null and content_v.? != .string)
            return .{ .reason_tag = denyTag(.bad_argument_type), .field = "content" };
        if (b64_v != null and b64_v.? != .null and b64_v.? != .string)
            return .{ .reason_tag = denyTag(.bad_argument_type), .field = "content_b64" };
        // The gate must validate the SAME grammar the tool accepts: the
        // tool turns an integral float into an integer (util.optIntArg),
        // so the gate does too — otherwise "mode": 2533.0 skips the
        // setuid cap. Present-but-wrong-type is a deny, not a skip. An
        // absent mode means the tool default 0o644; check that against
        // the cap too.
        const mode_v = util.objGet(args, "mode");
        const effective: i64 = if (mode_v) |m| switch (m) {
            .integer => |i| i,
            // null means the same 0o644 default the tool applies
            // (optIntArg maps null -> null -> orelse 0o644), so the cap
            // check sees the real effective mode.
            .null => 0o644,
            .float => |f| blk: {
                const i = util.floatToI64(f) orelse
                    return .{ .reason_tag = denyTag(.bad_argument_type), .field = "mode" };
                if (@as(f64, @floatFromInt(i)) != f)
                    return .{ .reason_tag = denyTag(.bad_argument_type), .field = "mode" };
                break :blk i;
            },
            .number_string => |s| std.fmt.parseInt(i64, s, 10) catch
                return .{ .reason_tag = denyTag(.bad_argument_type), .field = "mode" },
            else => return .{ .reason_tag = denyTag(.bad_argument_type), .field = "mode" },
        } else 0o644;
        if (effective < 0) return .{ .reason_tag = denyTag(.write_mode_exceeds_cap), .field = "mode" };
        checkWriteMode(pol, effective) catch {
            return .{ .reason_tag = denyTag(.write_mode_exceeds_cap), .field = "mode" };
        };
        return null;
    }
    if (std.mem.eql(u8, tool, "exec_wait")) {
        // Same grammar as the tool; absent timeout means the tool default
        // 30s (WAIT_DEFAULT_TIMEOUT_S) — checked against the cap like any
        // explicit value.
        const t_v = util.objGet(args, "timeout");
        const wait_default: i64 = 30;
        const effective: i64 = if (t_v) |t| switch (t) {
            .null => wait_default,
            .integer => |i| i,
            .float => |f| blk: {
                const i = util.floatToI64(f) orelse
                    return .{ .reason_tag = denyTag(.bad_argument_type), .field = "timeout" };
                if (@as(f64, @floatFromInt(i)) != f)
                    return .{ .reason_tag = denyTag(.bad_argument_type), .field = "timeout" };
                break :blk i;
            },
            .number_string => |s| std.fmt.parseInt(i64, s, 10) catch
                return .{ .reason_tag = denyTag(.bad_argument_type), .field = "timeout" },
            else => return .{ .reason_tag = denyTag(.bad_argument_type), .field = "timeout" },
        } else wait_default;
        checkTimeout(pol, effective) catch {
            return .{ .reason_tag = denyTag(.timeout_exceeds_cap), .field = "timeout" };
        };
        return null; // session ownership checked inside the tool (owner hash)
    }
    // sys_info and the session-control tools (exec_poll/write/kill/close,
    // exec_list): membership-only above; ownership enforced in tools.zig
    // where the session (and its owner hash) is at hand.
    _ = cfg;
    return null;
}

fn checkExecArgs(
    arena: Allocator,
    io: Io,
    pol: *const TokenPolicy,
    tool: []const u8,
    args: Value,
    out_exec_pin: *?ExecPin,
) ?Deny {
    // exec_shell synthesizes the argv the tool will actually spawn: the
    // explicit shell or the platform default. Gating the synthesized argv
    // is what makes "shell not in exec_argv0" a real, checkable rule.
    var argv0: []const u8 = undefined;
    if (std.mem.eql(u8, tool, "exec_shell")) {
        const default_shell: []const u8 = if (builtin.os.tag == .windows) "cmd" else "bash";
        // Present-but-wrong-type shell is a deny: the tool
        // would reject it with InvalidParams, and the gate must never
        // unwrap a null built from unvalidated JSON.
        argv0 = if (util.objGet(args, "shell")) |s| switch (s) {
            .string => |ss| ss,
            else => return .{ .reason_tag = denyTag(.bad_argument_type), .field = "shell" },
        } else default_shell;
    } else {
        const argv = util.objGet(args, "argv") orelse return null; // tool's own MissingArgv
        if (argv != .array or argv.array.items.len == 0) return null; // tool's own BadArgv
        const first = argv.array.items[0];
        if (first != .string) return null;
        argv0 = first.string;
    }
    // The cwd the child will actually run in comes FIRST: a relative
    // argv[0] with a separator resolves against THE CHILD's cwd, not the
    // daemon's. Authorizing ./runner against the daemon cwd while the
    // child execs jobcwd/runner would be two different files. A bare
    // argv[0] (PATH search) never uses the
    // base; that semantics stays exactly as it was.
    //
    // Canonicalise ONCE and retain the result.
    // checkCwd/checkArgv0 return the canon they actually evaluated; a
    // relative argv[0] resolves against the RETAINED canonical cwd (the
    // pinned spawn fchdirs into that directory object, so the child's
    // own relative resolution starts from exactly this directory), and
    // the ExecPin below is built from the same strings — never from a
    // second re-canonicalisation of the raw inputs that no authorization
    // ever saw. The file tools' FilePin is built the same way (canon
    // reused from the decision), which is the pattern mirrored here.
    var effective_cwd: []const u8 = ""; // "" -> daemon cwd
    if (util.objGet(args, "cwd")) |c| {
        if (c == .string and c.string.len != 0) {
            checkCwd(arena, io, pol, c.string, &effective_cwd) catch {
                return .{ .reason_tag = if (cwdDeniedCanon(pol, effective_cwd)) denyTag(.denied_path) else denyTag(.cwd_not_allowed), .field = "cwd" };
            };
        }
    }
    var argv0_canon: []const u8 = "";
    if (std.mem.eql(u8, tool, "exec_shell")) {
        if (!shellAllowed(pol, argv0)) return .{ .reason_tag = denyTag(.argv0_not_allowed), .field = "shell" };
    } else {
        checkArgv0(arena, io, pol, argv0, effective_cwd, &argv0_canon) catch {
            return .{ .reason_tag = denyTag(.argv0_not_allowed), .field = "argv[0]" };
        };
    }
    // Timeout grammar identical to the tool: integral
    // floats convert, anything else present-but-wrong-type is a deny, and
    // null counts as absent (the tool's optIntArg maps null -> default).
    //
    // exec_start has NO `timeout` argument —
    // the session it spawns is intentionally long-lived (bounded by
    // exec_wait/exec_poll timeouts and exec_kill/exec_close, not by the
    // spawn). The old unconditional default-cap (120s) made exec_start
    // deny ALWAYS under a max_timeout_s < 120, while a phantom
    // "timeout":1 field — validated by the gate, never read by the tool
    // (toolExecStart parses argv/cwd only) — let the identical call
    // through: validation of an argument the tool does not consume. The
    // cap grammar now skips exec_start entirely; exec and exec_shell
    // (single-shot, timeout is a real tool argument) keep theirs.
    if (!std.mem.eql(u8, tool, "exec_start")) {
        const exec_default_s: i64 = 120;
        if (util.objGet(args, "timeout")) |t| {
            const effective: i64 = switch (t) {
                .null => exec_default_s,
                .integer => |i| i,
                .float => |f| blk: {
                    const i = util.floatToI64(f) orelse
                        return .{ .reason_tag = denyTag(.bad_argument_type), .field = "timeout" };
                    if (@as(f64, @floatFromInt(i)) != f)
                        return .{ .reason_tag = denyTag(.bad_argument_type), .field = "timeout" };
                    break :blk i;
                },
                .number_string => |s| std.fmt.parseInt(i64, s, 10) catch
                    return .{ .reason_tag = denyTag(.bad_argument_type), .field = "timeout" },
                else => return .{ .reason_tag = denyTag(.bad_argument_type), .field = "timeout" },
            };
            checkTimeout(pol, effective) catch {
                return .{ .reason_tag = denyTag(.timeout_exceeds_cap), .field = "timeout" };
            };
        } else if (pol.max_timeout_s != null and pol.max_timeout_s.? < exec_default_s) {
            // No explicit timeout -> the tool default (120s) would run above the
            // cap: deny rather than silently clamp.
            return .{ .reason_tag = denyTag(.timeout_exceeds_cap), .field = "timeout" };
        }
    }
    // Authorized: emit the exec pin — the canonical strings the tool
    // layer pins to kernel objects (os/secure.zig openPinnedDir /
    // openPinnedExe) before the fork. The pin is built ONLY from the
    // canons the checks above authorized and retained: no second
    // canonicalisation happens here, so
    // there is no window in which a namespace change between the
    // authorization and the pin could point the pin at an object the
    // policy never authorized.
    out_exec_pin.* = .{
        .cwd_canon = effective_cwd,
        .argv0 = argv0,
        .argv0_canon = argv0_canon,
    };
    return null;
}

/// Read allow+deny evaluation for read_file/list_dir and write_file paths.
fn pathAllowed(arena: Allocator, io: Io, pol: *const TokenPolicy, path: []const u8, kind: PathKind) bool {
    // Fail closed: a canonicalisation failure is a refusal, never a fall
    // back to the raw string.
    const canon = canonicalizePath(arena, io, path) catch return false;
    const allow: []const []const u8 = if (kind == .read) pol.read_paths else pol.write_paths;
    const deny: []const []const u8 = if (kind == .read) pol.read_deny else pol.write_deny;
    return prefixAllowed(canon, allow, deny);
}

/// Build the secure-open binding for an already-canonicalised,
/// already-allowed path: the LONGEST matched allow prefix (the tightest
/// kernel confinement), the canonical path relative to it, and the
/// same-kind deny list for the open's post-check. Returns null only
/// when nothing matched (the caller refused the call).
fn filePin(canon: []const u8, allow: []const []const u8, deny: []const []const u8) ?os.secure.Pin {
    return filePinSty(canon, allow, deny, host_path_style);
}

/// Style-parameterised pin build. The leading separator is stripped in
/// the HOST grammar — a single-'/' cut leaves rel = "\sub\a.txt" on a
/// Windows canon, an invalid relative open. Stripping EVERY leading
/// separator also keeps rel genuinely
/// relative: the matched prefix always covers the canon's root bytes, so
/// rel starts at a component boundary and carries no drive/namespace
/// qualification.
fn filePinSty(canon: []const u8, allow: []const []const u8, deny: []const []const u8, style: PathStyle) ?os.secure.Pin {
    var best: ?[]const u8 = null;
    for (allow) |a| {
        if (!pathHasPrefixSty(canon, a, style)) continue;
        if (best == null or a.len > best.?.len) best = a;
    }
    const prefix = best orelse return null;
    var rel = canon[prefix.len..];
    while (rel.len > 0 and styleIsSep(style, rel[0])) rel = rel[1..];
    return .{ .prefix = prefix, .rel = rel, .canon = canon, .deny = deny };
}

/// deniedExplicit over an already-canonicalised path (checkCallEx
/// canonicalises once and reuses the result for the pin).
fn deniedExplicitCanon(canon: []const u8, allow: []const []const u8, deny: []const []const u8) bool {
    for (deny) |d| {
        if (pathHasPrefix(canon, d)) {
            for (allow) |a| {
                if (pathHasPrefix(canon, a)) return true;
            }
        }
    }
    return false;
}

/// True when the path sat under an allow prefix AND a deny prefix: the
/// message then says "deny list", which points at the right knob.
fn deniedExplicit(arena: Allocator, io: Io, pol: *const TokenPolicy, path: []const u8, kind: PathKind) bool {
    // Canonicalisation failure: not provably deny-listed; the plain
    // path_not_allowed refusal the caller already decided on stands.
    const canon = canonicalizePath(arena, io, path) catch return false;
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

/// Deny-list message tag over the canon checkCwd already evaluated — no
/// second canonicalisation: the tag and the decision talk about
/// one and the same string. An empty canon means canonicalisation itself
/// failed, which is not provably deny-listed: the plain cwd_not_allowed
/// refusal the caller already decided on stands.
fn cwdDeniedCanon(pol: *const TokenPolicy, canon: []const u8) bool {
    if (canon.len == 0) return false;
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

/// The secure-open authorization binding for the request currently being
/// served on THIS thread: set by the rpc layer from checkCallEx together
/// with the owner, read by the three file tools to open through the pin
/// (os.secure.openPinned). Null when no policy matched, for non-file tools,
/// and for allow_all tokens (raw-path v0.3.1 behaviour). The strings live
/// in the request arena and stay valid until endRequest.
pub threadlocal var current_pin: ?os.secure.Pin = null;

/// Authorization binding for one exec-family call: the canonical
/// strings the gate authorized, which the tool
/// layer pins to kernel objects (os/secure.zig openPinnedDir /
/// openPinnedExe) BEFORE the fork — the spawned child fchdir()s into the
/// pinned cwd descriptor and execveat()s the pinned executable, so a
/// path swap between the gate and the spawn cannot redirect either.
/// All strings live in the request arena and stay valid until endRequest.
pub const ExecPin = struct {
    /// Canonical effective child cwd ("" = inherit the daemon cwd).
    cwd_canon: []const u8,
    /// Raw argv[0] exactly as the child receives it ($0/busybox
    /// semantics — the exec TARGET is the pinned fd, never argv[0]).
    argv0: []const u8,
    /// Canonical absolute argv[0] when it contains a separator; "" for a
    /// bare name (PATH search: authorization is the name match, and the
    /// tool layer pins whichever PATH candidate execvp order selects).
    argv0_canon: []const u8,
};

/// The exec-family tools' accessor for the thread's pin.
pub fn currentExecPin() ?ExecPin {
    return current_exec_pin;
}

pub threadlocal var current_exec_pin: ?ExecPin = null;

/// The file tools' accessor for the thread's pin.
pub fn currentFilePin() ?os.secure.Pin {
    return current_pin;
}

/// Called by the rpc layer before dispatchTool.
pub fn beginRequest(pol: ?*const TokenPolicy, pin: ?os.secure.Pin, exec_pin: ?ExecPin) void {
    if (pol) |p| {
        current_owner = p.token_hash;
        policy_active = true;
    } else {
        current_owner = [_]u8{0} ** 32;
        policy_active = false;
    }
    current_pin = pin;
    current_exec_pin = exec_pin;
}

/// Called by the rpc layer after dispatchTool returns/errors.
pub fn endRequest() void {
    current_owner = [_]u8{0} ** 32;
    policy_active = false;
    current_pin = null;
    current_exec_pin = null;
}

/// Ownership check for the session-control tools: the session's owner must
/// match the current request's owner when a policy is active. Without a
/// policy both sides are zeroes and every session is accessible — exactly
/// the v0.3.1 behaviour.
pub fn sessionOwned(session_owner: [32]u8) bool {
    if (!policy_active) return true;
    return std.crypto.timing_safe.eql([32]u8, session_owner, current_owner);
}

// ---------------------------------------------------------------------------
// Regression tests for the gate/exec boundary
// ---------------------------------------------------------------------------

test "policy: list_dir default path is gated as the daemon cwd" {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = Io.Threaded.global_single_threaded.io();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try tmp.dir.createDirPath(io, "allow");
    const allow = try tmpAbs(arena, &tmp, io, "allow");

    const pol = TokenPolicy{
        .file = "f",
        .token_hash = [_]u8{0} ** 32,
        .tools = &.{ "read_file", "list_dir" },
        .exec_argv0 = &.{},
        .exec_cwd = &.{},
        .cwd_deny = &.{},
        .read_paths = &.{allow},
        .write_paths = &.{},
        .read_deny = &.{},
        .write_deny = &.{},
    };

    // The tool lists "." (the daemon cwd) for an absent or null path: the
    // gate must evaluate THAT path. The daemon cwd sits outside read_paths,
    // so every shape of the default is a refusal.
    try testing.expect(checkCall(arena, io, undefined, &pol, "list_dir", Value.null) != null);
    var null_path: std.json.ObjectMap = .empty;
    try null_path.put(arena, "path", Value.null);
    try testing.expect(checkCall(arena, io, undefined, &pol, "list_dir", .{ .object = null_path }) != null);
    var dot_path: std.json.ObjectMap = .empty;
    try dot_path.put(arena, "path", .{ .string = "." });
    if (checkCall(arena, io, undefined, &pol, "list_dir", .{ .object = dot_path })) |d| {
        try testing.expectEqualStrings("path_not_allowed", d.reason_tag);
    } else return error.TestUnexpectedResult;
    // An explicit allowed path still passes.
    var ok_path: std.json.ObjectMap = .empty;
    try ok_path.put(arena, "path", .{ .string = allow });
    try testing.expect(checkCall(arena, io, undefined, &pol, "list_dir", .{ .object = ok_path }) == null);
    // Present-but-wrong-type path: the gate's bad_argument_type.
    var int_path: std.json.ObjectMap = .empty;
    try int_path.put(arena, "path", .{ .integer = 123 });
    if (checkCall(arena, io, undefined, &pol, "list_dir", .{ .object = int_path })) |d| {
        try testing.expectEqualStrings("bad_argument_type", d.reason_tag);
    } else return error.TestUnexpectedResult;

    // read_file keeps its MissingPath semantics: absent/null stays the
    // tool's own error, only the type check belongs to the gate.
    try testing.expect(checkCall(arena, io, undefined, &pol, "read_file", Value.null) == null);
    try testing.expect(checkCall(arena, io, undefined, &pol, "read_file", .{ .object = null_path }) == null);
    if (checkCall(arena, io, undefined, &pol, "read_file", .{ .object = int_path })) |d| {
        try testing.expectEqualStrings("bad_argument_type", d.reason_tag);
    } else return error.TestUnexpectedResult;
}

test "policy: dangling symlinks in the unresolved tail fail closed" {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = Io.Threaded.global_single_threaded.io();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const root = try tmpAbs(arena, &tmp, io, ".");
    try tmp.dir.createDirPath(io, "allow");
    try tmp.dir.createDirPath(io, "outside");
    const allow = try tmpAbs(arena, &tmp, io, "allow");
    // allow/link -> a missing target: realpath fails, the deepest existing
    // ancestor (allow) realpaths fine, and the raw tail "/link" is a
    // symlink — an O_CREAT open of the raw path would follow it and create
    // the file at the target, outside every allowed prefix.
    tmp.dir.symLink(io, "../outside/new.txt", "allow/link", .{}) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    // Intermediate shape: allow/escdir dangles, the requested path goes
    // deeper through it (the mkdirs:true escape, case B).
    tmp.dir.symLink(io, "../outside/newdir", "allow/escdir", .{}) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    const link = try std.mem.concat(arena, u8, &.{ root, "/allow/link" });
    try testing.expectError(error.UnresolvedSymlinkInPath, canonicalizePath(arena, io, link));
    const deep = try std.mem.concat(arena, u8, &.{ root, "/allow/escdir/new/x.txt" });
    try testing.expectError(error.UnresolvedSymlinkInPath, canonicalizePath(arena, io, deep));
    // Control: a genuinely fresh tail still canonicalises unchanged.
    const fresh = try std.mem.concat(arena, u8, &.{ root, "/allow/fresh.txt" });
    const fresh_canon = try canonicalizePath(arena, io, fresh);
    try testing.expect(std.mem.endsWith(u8, fresh_canon, "/allow/fresh.txt"));

    // Gate level: write_file through the dangling link is denied even
    // though the LEXICAL path sits under the allowed prefix.
    const pol = TokenPolicy{
        .file = "f",
        .token_hash = [_]u8{0} ** 32,
        .tools = &.{"write_file"},
        .exec_argv0 = &.{},
        .exec_cwd = &.{},
        .cwd_deny = &.{},
        .read_paths = &.{},
        .write_paths = &.{allow},
        .read_deny = &.{},
        .write_deny = &.{},
        .write_max_mode = 0o644,
    };
    var w_link: std.json.ObjectMap = .empty;
    try w_link.put(arena, "path", .{ .string = link });
    try w_link.put(arena, "content_b64", .{ .string = "aGk=" });
    if (checkCall(arena, io, undefined, &pol, "write_file", .{ .object = w_link })) |d| {
        try testing.expectEqualStrings("path_not_allowed", d.reason_tag);
    } else return error.TestUnexpectedResult;
    // The mkdirs variant of case B: an intermediate dangling symlink the
    // tool's createDirPath would follow — same refusal.
    var w_mkdirs: std.json.ObjectMap = .empty;
    const esc_sub = try std.mem.concat(arena, u8, &.{ root, "/allow/escdir/new_subdir" });
    try w_mkdirs.put(arena, "path", .{ .string = esc_sub });
    try w_mkdirs.put(arena, "content_b64", .{ .string = "aGk=" });
    try w_mkdirs.put(arena, "mkdirs", .{ .bool = true });
    if (checkCall(arena, io, undefined, &pol, "write_file", .{ .object = w_mkdirs })) |d| {
        try testing.expectEqualStrings("path_not_allowed", d.reason_tag);
    } else return error.TestUnexpectedResult;
}

test "policy: canonicalisation failure denies instead of falling back" {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = Io.Threaded.global_single_threaded.io();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const root = try tmpAbs(arena, &tmp, io, ".");
    try tmp.dir.createDirPath(io, "allow");
    const allow = try tmpAbs(arena, &tmp, io, "allow");
    tmp.dir.symLink(io, "../outside/missing", "allow/dang", .{}) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    const dang = try std.mem.concat(arena, u8, &.{ root, "/allow/dang" });

    const pol = TokenPolicy{
        .file = "f",
        .token_hash = [_]u8{0} ** 32,
        .tools = &.{ "exec", "read_file", "write_file" },
        .exec_argv0 = &.{.{ .text = "sh", .has_slash = false }},
        .exec_cwd = &.{root},
        .cwd_deny = &.{},
        .read_paths = &.{allow},
        .write_paths = &.{allow},
        .read_deny = &.{},
        .write_deny = &.{},
        .write_max_mode = 0o644,
    };
    // Every check surface turns a canonicalisation failure into a refusal
    // — never a fall back to the raw string the prefix check would trust.
    try testing.expectError(error.PolicyDenied, checkPath(arena, io, &pol, dang, .read));
    try testing.expectError(error.PolicyDenied, checkCwd(arena, io, &pol, dang, null));
    try testing.expectError(error.PolicyDenied, checkArgv0(arena, io, &pol, dang, "", null));
    // And the write gate: pathAllowed returns false, not a raw-path pass.
    var w: std.json.ObjectMap = .empty;
    try w.put(arena, "path", .{ .string = dang });
    try w.put(arena, "content_b64", .{ .string = "aGk=" });
    if (checkCall(arena, io, undefined, &pol, "write_file", .{ .object = w })) |d| {
        try testing.expectEqualStrings("path_not_allowed", d.reason_tag);
    } else return error.TestUnexpectedResult;
}

test "policy: prefix lists are canonicalised at load" {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = Io.Threaded.global_single_threaded.io();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const root = try tmpAbs(arena, &tmp, io, ".");
    try tmp.dir.createDirPath(io, "keys");
    try tmp.dir.createDirPath(io, "w");
    try tmp.dir.createDirPath(io, "realdir");
    // alias -> realdir: a symlinked prefix must canonicalise to the real
    // directory, or it never matches the canonicalised request path.
    tmp.dir.symLink(io, "realdir", "alias", .{}) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    try writeSecret(tmp.dir, io, "tok", "secret\n");
    const tok_abs = try tmpAbs(arena, &tmp, io, "tok");

    var json: std.ArrayList(u8) = .empty;
    try json.print(arena,
        \\{{"version":1,"tokens":[{{"file":"{s}","tools":["read_file","write_file"],
        \\  "read_paths":["{s}"],"read_deny":["{s}/keys/"],
        \\  "write_paths":["{s}/w/"],"write_max_mode":"0644"}}]}}
    , .{ tok_abs, root, root, root });
    try writeSecret(tmp.dir, io, "p1", json.items);
    const p1 = try tmpAbs(arena, &tmp, io, "p1");
    var ps = try loadPolicyFile(arena, io, p1);
    defer freePolicy(&ps);
    const pol = &ps.entries[0];

    // The trailing-slash deny matches the directory itself AND its
    // contents.
    const keys = try std.mem.concat(arena, u8, &.{ root, "/keys" });
    const keys_k = try std.mem.concat(arena, u8, &.{ root, "/keys/k" });
    var r_dir: std.json.ObjectMap = .empty;
    try r_dir.put(arena, "path", .{ .string = keys });
    if (checkCall(arena, io, undefined, pol, "read_file", .{ .object = r_dir })) |d| {
        try testing.expectEqualStrings("denied_path", d.reason_tag);
    } else return error.TestUnexpectedResult;
    var r_k: std.json.ObjectMap = .empty;
    try r_k.put(arena, "path", .{ .string = keys_k });
    if (checkCall(arena, io, undefined, pol, "read_file", .{ .object = r_k })) |d| {
        try testing.expectEqualStrings("denied_path", d.reason_tag);
    } else return error.TestUnexpectedResult;
    // A path outside the deny still reads.
    const ok_file = try std.mem.concat(arena, u8, &.{ root, "/ok.txt" });
    var r_ok: std.json.ObjectMap = .empty;
    try r_ok.put(arena, "path", .{ .string = ok_file });
    try testing.expect(checkCall(arena, io, undefined, pol, "read_file", .{ .object = r_ok }) == null);
    // The trailing-slash ALLOW prefix now matches canonical paths too.
    const w_file = try std.mem.concat(arena, u8, &.{ root, "/w/x.txt" });
    var w_ok: std.json.ObjectMap = .empty;
    try w_ok.put(arena, "path", .{ .string = w_file });
    try w_ok.put(arena, "content_b64", .{ .string = "aGk=" });
    try testing.expect(checkCall(arena, io, undefined, pol, "write_file", .{ .object = w_ok }) == null);

    // Second entry: an allowlist prefix given through the symlink alias —
    // it must behave exactly like the real directory it resolves to.
    var json2: std.ArrayList(u8) = .empty;
    try json2.print(arena,
        \\{{"version":1,"tokens":[{{"file":"{s}","tools":["read_file"],
        \\  "read_paths":["{s}/alias"]}}]}}
    , .{ tok_abs, root });
    try writeSecret(tmp.dir, io, "p2", json2.items);
    const p2 = try tmpAbs(arena, &tmp, io, "p2");
    var ps2 = try loadPolicyFile(arena, io, p2);
    defer freePolicy(&ps2);
    const real_file = try std.mem.concat(arena, u8, &.{ root, "/realdir/x" });
    var r_real: std.json.ObjectMap = .empty;
    try r_real.put(arena, "path", .{ .string = real_file });
    try testing.expect(checkCall(arena, io, undefined, &ps2.entries[0], "read_file", .{ .object = r_real }) == null);
}

test "policy: relative argv0 authorizes against the requested cwd" {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = Io.Threaded.global_single_threaded.io();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const root = try tmpAbs(arena, &tmp, io, ".");
    try tmp.dir.createDirPath(io, "job");
    try tmp.dir.createDirPath(io, "other");
    try writeSecret(tmp.dir, io, "job/runner", "#!/bin/sh\n");
    const job = try tmpAbs(arena, &tmp, io, "job");
    const other = try tmpAbs(arena, &tmp, io, "other");
    const runner = try tmpAbs(arena, &tmp, io, "job/runner");

    const pol = TokenPolicy{
        .file = "f",
        .token_hash = [_]u8{0} ** 32,
        .tools = &.{"exec"},
        .exec_argv0 = &.{.{ .text = runner, .has_slash = true }},
        .exec_cwd = &.{root},
        .cwd_deny = &.{},
        .read_paths = &.{},
        .write_paths = &.{},
        .read_deny = &.{},
        .write_deny = &.{},
    };

    const Argv = struct {
        fn one(arena2: Allocator, argv0: []const u8, cwd: ?[]const u8) !std.json.ObjectMap {
            var arr: std.json.Array = .init(arena2);
            try arr.append(.{ .string = argv0 });
            var m: std.json.ObjectMap = .empty;
            try m.put(arena2, "argv", .{ .array = arr });
            if (cwd) |c| try m.put(arena2, "cwd", .{ .string = c });
            return m;
        }
    };

    // "./runner" with cwd=job: the child execs job/runner — the file the
    // entry names — so the call is authorized.
    {
        const m = try Argv.one(arena, "./runner", job);
        try testing.expect(checkCall(arena, io, undefined, &pol, "exec", .{ .object = m }) == null);
    }
    // A different cwd resolves "./runner" to a DIFFERENT file: refused.
    {
        const m = try Argv.one(arena, "./runner", other);
        if (checkCall(arena, io, undefined, &pol, "exec", .{ .object = m })) |d| {
            try testing.expectEqualStrings("argv0_not_allowed", d.reason_tag);
        } else return error.TestUnexpectedResult;
    }
    // No cwd: the child inherits the daemon cwd, where ./runner is not the
    // allowlisted file — refused.
    {
        const m = try Argv.one(arena, "./runner", null);
        if (checkCall(arena, io, undefined, &pol, "exec", .{ .object = m })) |d| {
            try testing.expectEqualStrings("argv0_not_allowed", d.reason_tag);
        } else return error.TestUnexpectedResult;
    }
    // Bare names stay name-matched (PATH search semantics): cwd never
    // changes what a bare argv0 authorizes.
    {
        const m = try Argv.one(arena, "runner", job);
        if (checkCall(arena, io, undefined, &pol, "exec", .{ .object = m })) |d| {
            try testing.expectEqualStrings("argv0_not_allowed", d.reason_tag);
        } else return error.TestUnexpectedResult;
    }
    const bare_pol = TokenPolicy{
        .file = "f",
        .token_hash = [_]u8{0} ** 32,
        .tools = &.{"exec"},
        .exec_argv0 = &.{.{ .text = "runner", .has_slash = false }},
        .exec_cwd = &.{root},
        .cwd_deny = &.{},
        .read_paths = &.{},
        .write_paths = &.{},
        .read_deny = &.{},
        .write_deny = &.{},
    };
    {
        var m: std.json.ObjectMap = .empty;
        try m.put(arena, "argv", .{ .string = "runner" });
        try m.put(arena, "cwd", .{ .string = other });
        try testing.expect(checkCall(arena, io, undefined, &bare_pol, "exec", .{ .object = m }) == null);
    }
}

/// POSIX-only synthetic environ carrying just HOME, for the tilde tests.
/// The caller saves/restores env_state.process_environ around the test —
/// tests share one process (same shape os/env.zig loadEnviron builds).
fn homeEnviron(arena: Allocator, home: []const u8) !std.process.Environ {
    const line = try std.fmt.allocPrint(arena, "HOME={s}", .{home});
    const line_z = try arena.dupeZ(u8, line);
    const slice = try arena.allocSentinel(?[*:0]const u8, 1, null);
    slice[0] = line_z.ptr;
    return .{ .block = .{ .slice = slice } };
}

test "policy: exec tilde argv0 stays literal and anchors to the cwd" {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = Io.Threaded.global_single_threaded.io();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const root = try tmpAbs(arena, &tmp, io, ".");
    try tmp.dir.createDirPath(io, "home/bin");
    // A literal "~" directory the attacker planted under the sandbox —
    // writable via write_file with an explicitly-relative "./~" path.
    try tmp.dir.createDirPath(io, "sandbox/~/bin");
    try writeSecret(tmp.dir, io, "home/bin/runner", "#!/bin/sh\n");
    try writeSecret(tmp.dir, io, "sandbox/~/bin/runner", "#!/bin/sh\n");
    const home = try tmpAbs(arena, &tmp, io, "home");
    const sandbox = try tmpAbs(arena, &tmp, io, "sandbox");
    const home_runner = try tmpAbs(arena, &tmp, io, "home/bin/runner");
    const literal_runner = try tmpAbs(arena, &tmp, io, "sandbox/~/bin/runner");

    const saved_env = env_state.process_environ;
    env_state.process_environ = try homeEnviron(arena, home);
    defer env_state.process_environ = saved_env;

    // The kernel never expands "~": for the child, "~/bin/runner" is a
    // RELATIVE path with a literal "~" component, exec'd as
    // <cwd>/~/bin/runner. A gate that expands "~" to $HOME authorizes
    // $HOME/bin/runner while the child runs <sandbox>/~/bin/runner — two
    // different files. The $HOME entry must NOT
    // match a tilde request.
    const home_pol = TokenPolicy{
        .file = "f",
        .token_hash = [_]u8{0} ** 32,
        .tools = &.{"exec"},
        .exec_argv0 = &.{.{ .text = home_runner, .has_slash = true }},
        .exec_cwd = &.{root},
        .cwd_deny = &.{},
        .read_paths = &.{},
        .write_paths = &.{},
        .read_deny = &.{},
        .write_deny = &.{},
    };
    {
        var arr: std.json.Array = .init(arena);
        try arr.append(.{ .string = "~/bin/runner" });
        var m: std.json.ObjectMap = .empty;
        try m.put(arena, "argv", .{ .array = arr });
        try m.put(arena, "cwd", .{ .string = sandbox });
        if (checkCall(arena, io, undefined, &home_pol, "exec", .{ .object = m })) |d| {
            try testing.expectEqualStrings("argv0_not_allowed", d.reason_tag);
        } else return error.TestUnexpectedResult;
    }
    // Kernel-parity positive: the entry names the file the child actually
    // execs — <sandbox>/~/bin/runner with its literal "~" component.
    const literal_pol = TokenPolicy{
        .file = "f",
        .token_hash = [_]u8{0} ** 32,
        .tools = &.{"exec"},
        .exec_argv0 = &.{.{ .text = literal_runner, .has_slash = true }},
        .exec_cwd = &.{root},
        .cwd_deny = &.{},
        .read_paths = &.{},
        .write_paths = &.{},
        .read_deny = &.{},
        .write_deny = &.{},
    };
    {
        var arr: std.json.Array = .init(arena);
        try arr.append(.{ .string = "~/bin/runner" });
        var m: std.json.ObjectMap = .empty;
        try m.put(arena, "argv", .{ .array = arr });
        try m.put(arena, "cwd", .{ .string = sandbox });
        try testing.expect(checkCall(arena, io, undefined, &literal_pol, "exec", .{ .object = m }) == null);
    }
}

test "policy: exec tilde cwd gates the literal path from the daemon cwd" {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = Io.Threaded.global_single_threaded.io();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try tmp.dir.createDirPath(io, "home/x");
    const home = try tmpAbs(arena, &tmp, io, "home");
    const home_x = try tmpAbs(arena, &tmp, io, "home/x");
    const dcwd = try std.process.currentPathAlloc(io, arena);
    const literal_cwd = try std.mem.concat(arena, u8, &.{ dcwd, "/~/x" });

    const saved_env = env_state.process_environ;
    env_state.process_environ = try homeEnviron(arena, home);
    defer env_state.process_environ = saved_env;

    // cwd "~/x": the child chdirs to <daemon cwd>/~/x (literal "~"),
    // never to $HOME/x. An exec_cwd naming $HOME/x must not authorize it.
    const home_pol = TokenPolicy{
        .file = "f",
        .token_hash = [_]u8{0} ** 32,
        .tools = &.{"exec"},
        .exec_argv0 = &.{.{ .text = "sh", .has_slash = false }},
        .exec_cwd = &.{home_x},
        .cwd_deny = &.{},
        .read_paths = &.{},
        .write_paths = &.{},
        .read_deny = &.{},
        .write_deny = &.{},
    };
    {
        var arr: std.json.Array = .init(arena);
        try arr.append(.{ .string = "sh" });
        var m: std.json.ObjectMap = .empty;
        try m.put(arena, "argv", .{ .array = arr });
        try m.put(arena, "cwd", .{ .string = "~/x" });
        if (checkCall(arena, io, undefined, &home_pol, "exec", .{ .object = m })) |d| {
            try testing.expectEqualStrings("cwd_not_allowed", d.reason_tag);
        } else return error.TestUnexpectedResult;
    }
    // The literal destination — <daemon cwd>/~/x — is what authorizes it.
    const literal_pol = TokenPolicy{
        .file = "f",
        .token_hash = [_]u8{0} ** 32,
        .tools = &.{"exec"},
        .exec_argv0 = &.{.{ .text = "sh", .has_slash = false }},
        .exec_cwd = &.{literal_cwd},
        .cwd_deny = &.{},
        .read_paths = &.{},
        .write_paths = &.{},
        .read_deny = &.{},
        .write_deny = &.{},
    };
    {
        var arr: std.json.Array = .init(arena);
        try arr.append(.{ .string = "sh" });
        var m: std.json.ObjectMap = .empty;
        try m.put(arena, "argv", .{ .array = arr });
        try m.put(arena, "cwd", .{ .string = "~/x" });
        try testing.expect(checkCall(arena, io, undefined, &literal_pol, "exec", .{ .object = m }) == null);
    }
}

test "policy: relative exec base anchors argv0 to the daemon cwd" {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = Io.Threaded.global_single_threaded.io();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const dcwd = try std.process.currentPathAlloc(io, arena);
    const right = try std.mem.concat(arena, u8, &.{ dcwd, "/cir3r2-sub/runner" });
    const root_entry = "/cir3r2-sub/runner";

    // cwd "cir3r2-sub" + argv "./runner": the child execs
    // <daemon cwd>/cir3r2-sub/runner. The old gate joined the relative
    // strings ("cir3r2-sub/./runner"); when nothing on that chain existed,
    // step 2 fell through to normalizeLexical, which fabricates a
    // root-anchored "/cir3r2-sub/runner" — a different tree entirely.
    const pol = TokenPolicy{
        .file = "f",
        .token_hash = [_]u8{0} ** 32,
        .tools = &.{"exec"},
        .exec_argv0 = &.{.{ .text = right, .has_slash = true }},
        .exec_cwd = &.{},
        .cwd_deny = &.{},
        .read_paths = &.{},
        .write_paths = &.{},
        .read_deny = &.{},
        .write_deny = &.{},
    };
    try checkArgv0(arena, io, &pol, "./runner", "cir3r2-sub", null);
    // The fabricated root-anchored form must NOT authorize the call.
    const root_pol = TokenPolicy{
        .file = "f",
        .token_hash = [_]u8{0} ** 32,
        .tools = &.{"exec"},
        .exec_argv0 = &.{.{ .text = root_entry, .has_slash = true }},
        .exec_cwd = &.{},
        .cwd_deny = &.{},
        .read_paths = &.{},
        .write_paths = &.{},
        .read_deny = &.{},
        .write_deny = &.{},
    };
    try testing.expectError(error.PolicyDenied, checkArgv0(arena, io, &root_pol, "./runner", "cir3r2-sub", null));
}

test "policy: exec pin is the authorized canon, canonicalized once" {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = Io.Threaded.global_single_threaded.io();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try tmp.dir.createDirPath(io, "job");
    try writeSecret(tmp.dir, io, "job/runner", "x\n");
    const job = try tmpAbs(arena, &tmp, io, "job");
    const runner = try std.mem.concat(arena, u8, &.{ job, "/runner" });

    const pol = TokenPolicy{
        .file = "f",
        .token_hash = [_]u8{0} ** 32,
        .tools = &.{"exec"},
        .exec_argv0 = &.{.{ .text = runner, .has_slash = true }},
        .exec_cwd = &.{job},
        .cwd_deny = &.{},
        .read_paths = &.{},
        .write_paths = &.{},
        .read_deny = &.{},
        .write_deny = &.{},
    };

    // The gate canonicalises each input
    // exactly ONCE and the emitted pin carries the strings the
    // authorization itself evaluated. The pin's cwd canon equals the
    // canon checkCwd retained, and a relative argv[0] resolves from that
    // retained canonical cwd rather than re-resolving the raw inputs.
    {
        var pin: ?os.secure.Pin = null;
        var epin: ?ExecPin = null;
        var argv_one: std.json.Array = .init(arena);
        try argv_one.append(.{ .string = "./runner" });
        var m: std.json.ObjectMap = .empty;
        try m.put(arena, "argv", .{ .array = argv_one });
        try m.put(arena, "cwd", .{ .string = job });
        try testing.expect(checkCallEx(arena, io, undefined, &pol, "exec", .{ .object = m }, &pin, &epin) == null);
        try testing.expect(epin != null);
        var cwd_canon: []const u8 = "";
        try checkCwd(arena, io, &pol, job, &cwd_canon);
        try testing.expectEqualStrings(cwd_canon, epin.?.cwd_canon);
        try testing.expectEqualStrings(job, epin.?.cwd_canon);
        try testing.expectEqualStrings(runner, epin.?.argv0_canon);
        try testing.expectEqualStrings("./runner", epin.?.argv0); // raw argv[0] preserved
    }

    // Bare argv[0]: the pin keeps the raw name and NO canon (the exec
    // target is PATH-resolved at pin time); the retained canon of a bare
    // name is never published — it would name a different object than
    // the PATH search the authorization matched.
    {
        var pin: ?os.secure.Pin = null;
        var epin: ?ExecPin = null;
        var argv_bare: std.json.Array = .init(arena);
        try argv_bare.append(.{ .string = "runner" });
        var m: std.json.ObjectMap = .empty;
        try m.put(arena, "argv", .{ .array = argv_bare });
        // "runner" is not allowlisted as a bare name here: denied.
        try testing.expect(checkCallEx(arena, io, undefined, &pol, "exec", .{ .object = m }, &pin, &epin) != null);
        try testing.expect(epin == null); // a denial never emits a pin
    }

    // A cwd outside the allowlist denies and leaves no pin — the pin is
    // only ever the authorized pair, never a partially-verified one.
    {
        var pin: ?os.secure.Pin = null;
        var epin: ?ExecPin = null;
        var argv_one: std.json.Array = .init(arena);
        try argv_one.append(.{ .string = "./runner" });
        var m: std.json.ObjectMap = .empty;
        try m.put(arena, "argv", .{ .array = argv_one });
        try m.put(arena, "cwd", .{ .string = "/definitely/not/allowed" });
        if (checkCallEx(arena, io, undefined, &pol, "exec", .{ .object = m }, &pin, &epin)) |d| {
            try testing.expectEqualStrings("cwd_not_allowed", d.reason_tag);
        } else return error.TestUnexpectedResult;
        try testing.expect(epin == null);
    }
}

test "policy: file tool tilde expansion gates the home path" {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = Io.Threaded.global_single_threaded.io();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try tmp.dir.createDirPath(io, "home/x");
    try tmp.dir.createDirPath(io, "home/keys");
    try tmp.dir.createDirPath(io, "home/w");
    try writeSecret(tmp.dir, io, "home/x/x.txt", "data\n");
    try writeSecret(tmp.dir, io, "home/keys/k", "secret\n");
    const home = try tmpAbs(arena, &tmp, io, "home");

    const saved_env = env_state.process_environ;
    env_state.process_environ = try homeEnviron(arena, home);
    defer env_state.process_environ = saved_env;

    // File tools DO expand "~" (tools.expandPath) before touching the fs,
    // so the gate must evaluate the SAME expanded path — no differential
    // (the split is exec-literal vs file-expanded).
    const pol = TokenPolicy{
        .file = "f",
        .token_hash = [_]u8{0} ** 32,
        .tools = &.{ "read_file", "write_file" },
        .exec_argv0 = &.{},
        .exec_cwd = &.{},
        .cwd_deny = &.{},
        .read_paths = &.{home},
        .write_paths = &.{home},
        .read_deny = &.{try tmpAbs(arena, &tmp, io, "home/keys")},
        .write_deny = &.{},
        .write_max_mode = 0o644,
    };
    {
        var m: std.json.ObjectMap = .empty;
        try m.put(arena, "path", .{ .string = "~/x/x.txt" });
        try testing.expect(checkCall(arena, io, undefined, &pol, "read_file", .{ .object = m }) == null);
    }
    {
        var m: std.json.ObjectMap = .empty;
        try m.put(arena, "path", .{ .string = "~/keys/k" });
        if (checkCall(arena, io, undefined, &pol, "read_file", .{ .object = m })) |d| {
            try testing.expectEqualStrings("denied_path", d.reason_tag);
        } else return error.TestUnexpectedResult;
    }
    {
        var m: std.json.ObjectMap = .empty;
        try m.put(arena, "path", .{ .string = "~/w/f.txt" });
        try m.put(arena, "content_b64", .{ .string = "aGk=" });
        try testing.expect(checkCall(arena, io, undefined, &pol, "write_file", .{ .object = m }) == null);
    }
}

test "policy: canonicalizePathExec keeps tilde literal and anchors a relative base" {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = Io.Threaded.global_single_threaded.io();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try tmp.dir.createDirPath(io, "home");
    const home = try tmpAbs(arena, &tmp, io, "home");
    const dcwd = try std.process.currentPathAlloc(io, arena);

    const saved_env = env_state.process_environ;
    env_state.process_environ = try homeEnviron(arena, home);
    defer env_state.process_environ = saved_env;

    // Exec wrapper: "~" stays a literal component; the composed path is
    // always absolute (relative base anchored to the daemon cwd first).
    const e1 = try canonicalizePathExec(arena, io, "~/bin/runner", "sub");
    const want1 = try std.mem.concat(arena, u8, &.{ dcwd, "/sub/~/bin/runner" });
    try testing.expectEqualStrings(want1, e1);
    const e2 = try canonicalizePathExec(arena, io, "./runner", "sub");
    const want2 = try std.mem.concat(arena, u8, &.{ dcwd, "/sub/runner" });
    try testing.expectEqualStrings(want2, e2);
    // No base: the daemon cwd anchors a literal "~".
    const e3 = try canonicalizePathExec(arena, io, "~/x", "");
    const want3 = try std.mem.concat(arena, u8, &.{ dcwd, "/~/x" });
    try testing.expectEqualStrings(want3, e3);
    // "~user" never expands anywhere: exec keeps it, file keeps it.
    const e4 = try canonicalizePathExec(arena, io, "~root/x", "");
    const want4 = try std.mem.concat(arena, u8, &.{ dcwd, "/~root/x" });
    try testing.expectEqualStrings(want4, e4);
    // File wrapper still expands against HOME (parity with expandPath).
    const f1 = try canonicalizePath(arena, io, "~/x");
    const fwant1 = try std.mem.concat(arena, u8, &.{ home, "/x" });
    try testing.expectEqualStrings(fwant1, f1);
    const f2 = try canonicalizePath(arena, io, "~root/x");
    const fwant2 = try std.mem.concat(arena, u8, &.{ dcwd, "/~root/x" });
    try testing.expectEqualStrings(fwant2, f2);
}

/// A copy carries two independent capabilities, never a second file-pin slot.
pub const CopyPins = struct {
    source: os.secure.Pin,
    destination: os.secure.Pin,
};

fn authorizationDeny(err: anyerror, field: []const u8) Deny {
    return .{ .reason_tag = if (err == error.PathDenied) "denied_path" else "path_not_allowed", .field = field };
}

/// Copy-only lexical authorization; symlinks remain visible to the secure open.
pub fn authorizePath(a: Allocator, io: Io, pol: ?*const TokenPolicy, path: []const u8, kind: PathKind) !os.secure.Pin {
    const canon = try copyPath(a, io, path);
    if (pol) |p| {
        if (!p.allow_all) {
            const allow = if (kind == .read) p.read_paths else p.write_paths;
            const deny = if (kind == .read) p.read_deny else p.write_deny;
            if (!prefixAllowed(canon, allow, deny)) {
                if (deniedExplicitCanon(canon, allow, deny)) return error.PathDenied;
                return error.PolicyDenied;
            }
            return filePin(canon, allow, deny) orelse error.PolicyDenied;
        }
    }
    // Unrestricted copies still pin objects and never follow links.
    const prefix = std.fs.path.dirname(canon) orelse canon;
    return .{ .prefix = prefix, .canon = canon, .rel = if (std.mem.eql(u8, prefix, canon)) "" else std.fs.path.basename(canon), .deny = &.{} };
}

pub fn checkCopyArgs(a: Allocator, io: Io, pol: ?*const TokenPolicy, args: Value, out: *?CopyPins) ?Deny {
    out.* = null;
    if (pol) |p| {
        if (!p.allow_all and !p.toolAllowed("copy_path"))
            return .{ .reason_tag = "tool_not_allowed", .field = "" };
    }
    var paths: [2][]const u8 = undefined;
    for ([_][]const u8{ "source", "destination" }, 0..) |field, i| {
        // Absent, null or empty is the tool's shape error (InvalidParams),
        // identical with and without a policy file; the gate refuses only a
        // present-but-wrong-typed value.
        const v = util.objGet(args, field) orelse return null;
        if (v == .null) return null;
        if (v != .string) return .{ .reason_tag = "bad_argument_type", .field = field };
        if (v.string.len == 0) return null;
        paths[i] = v.string;
    }
    const timeout = if (util.objGet(args, "timeout")) |v| blk: {
        if (v != .integer) return .{ .reason_tag = "bad_argument_type", .field = "timeout" };
        break :blk v.integer;
    } else 30;
    if (pol) |p| {
        if (!p.allow_all) if (p.max_timeout_s) |cap| {
            if (timeout > cap) return .{ .reason_tag = "timeout_exceeds_cap", .field = "timeout" };
        };
    }
    const src = authorizePath(a, io, pol, paths[0], .read) catch |err| return authorizationDeny(err, "source");
    const dst = authorizePath(a, io, pol, paths[1], .write) catch |err| return authorizationDeny(err, "destination");
    out.* = .{ .source = src, .destination = dst };
    return null;
}

/// Do not realpath copy arguments: that would erase a forbidden symlink.
/// Reject parent traversal rather than normalize away a component before opening.
pub fn copyPath(a: Allocator, io: Io, path: []const u8) ![]const u8 {
    if (path.len == 0 or std.mem.indexOfScalar(u8, path, 0) != null) return error.BadPathName;
    var p = path;
    if (p[0] == '~' and (p.len == 1 or p[1] == '/')) {
        const home = os.homeDir(a, env_state.process_environ) orelse return error.BadPathName;
        p = try std.mem.concat(a, u8, &.{ home, p[1..] });
    }
    var parts = std.mem.tokenizeScalar(u8, p, '/');
    while (parts.next()) |part| if (std.mem.eql(u8, part, "..")) return error.BadPathName;
    if (!std.fs.path.isAbsolute(p)) p = try std.mem.concat(a, u8, &.{ try std.process.currentPathAlloc(io, a), "/", p });
    return normalizeLexical(a, p);
}
