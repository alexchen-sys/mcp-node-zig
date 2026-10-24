//! Tamper-evident audit log.
//!
//! One append-only JSONL file per process. Every record is one JSON object
//! on one line, fields in a fixed order with no optional whitespace, so the
//! canonical bytes of a record are the line itself:
//!
//!   {"v":1,"seq":42,"ts":"2026-10-06T12:00:00.123Z","host":"node-a",
//!    "role":"node","event":"tool.call",...event fields...,
//!    "prev":"<hex hmac of previous line>","mac":"<hex hmac of this line>"}
//!
//! `mac` is HMAC-SHA256(K, <the line up to and excluding `,"mac"`>) and
//! `prev` is the previous line's `mac`; the first line of a fresh chain
//! carries 64 zeroes. `seq` starts at 0 and is strictly +1, so a gap means
//! deletion. With MCP_NODE_AUDIT_KEY_FILE unset there is no key: records
//! are written without `prev`/`mac` and the start record says
//! "chain":false — plain JSONL with sequence numbers, integrity-free.
//!
//! Writing: callers format an event inner into a stack buffer and enqueue
//! it into a bounded ring (fixed slots, constant memory, no allocation on
//! the hot path). One writer thread composes the canonical line (assigns
//! seq/ts/prev/mac), batches up to 64 records per write+fsync with a short
//! settle beat for trickle bursts, and ends each batch with one fsync.
//! Ring-full policy is block (the tool call waits) or drop (a chained
//! "dropped" record with a count follows when space returns). Past
//! MCP_NODE_AUDIT_MAX_BYTES the file rotates to
//! `<path>.<chain-gen>.<first-seq>` (the generation tags the chain so a
//! restarted chain can never collide with — or overwrite — an old chain's
//! rotated files) and the chain continues in a fresh file opened with a
//! `rotate` record. Rotation and quarantine renames never replace an
//! existing file and flush the parent directory before depending on it.
//!
//! The writer owns its descriptor explicitly (`log: ?AppendLog`). A failed
//! rotation, or a torn tail that cannot be cut back, retires the handle:
//! the retired number may already be recycled by accept(), so writes and
//! the shutdown sync/close only ever run through live ownership. The next
//! batch first reopens and re-verifies the tail BEFORE composing a single
//! line — seq/prev advance only for bytes that reached the file, so no
//! gap can open between the chain state and the bytes on disk. A tail that
//! fails verification (or cannot be cut) is quarantined: the file is
//! renamed aside and the next batch opens a fresh chain with
//! `chain.break`; a recovery that lands on a brand-new empty file while
//! the chain already holds committed records opens it with a `recover`
//! boundary record instead of silently continuing.
//!
//! Startup reads the tail of an existing file, verifies the chain over the
//! tail window and recovers seq/prev, so a restart (incl. kill -9 between
//! batches) continues the same chain. A torn final line is truncated; a
//! tail that fails verification is renamed aside and the new file starts a
//! fresh chain whose first record is chain.break.
//!
//! `mcp-node audit-verify [--anchor] <file>...` re-checks seq continuity,
//! prev links (also across rotated files given in order) and every MAC
//! over the exact line bytes. Exit 0 clean, 1 broken, first bad seq
//! printed. --anchor prints the last line's seq and mac for off-box
//! anchoring.
//!
//! Nothing here logs stdout, file contents, scripts, tokens or secrets:
//! arguments are summarized per tool from a fixed allowlist (argv[0]+argc,
//! path+size, shell+script length, session id), plus a sha256 digest of
//! the canonical arguments.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const os = @import("os.zig");
const config = @import("config.zig");
const util = @import("util.zig");

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const VERSION: []const u8 = @import("build_options").version;

/// Bytes of one ring slot: the largest possible canonical line.
pub const MAX_RECORD: usize = 2048;
/// Largest event inner (everything between the common prefix and prev/mac).
pub const MAX_INNER: usize = 1700;
pub const RING_SLOTS: usize = 1024;
pub const BATCH_MAX: usize = 64;
/// Consecutive failed drains the writer tolerates after `stopping` is set
/// before it reports the outstanding loss and exits anyway. Normal
/// operation retries forever (the daemon lives on); shutdown is bounded.
pub const STOP_RETRY_BUDGET: u8 = 8;
/// Settle beat before draining a partial batch: lets a trickle-burst join
/// one write+fsync. A full ring drains without the beat.
pub const BATCH_SETTLE_MS: u64 = 5;
/// Startup recovery reads at most this many tail bytes.
pub const TAIL_WINDOW: usize = 256 * 1024;
pub const MAC_HEX_LEN: usize = 64;
pub const REQ_ID_MAX: usize = 64;
/// Escaped-byte cap for the args_summary object body.
const SUMMARY_CAP: usize = 960;

const ZERO_PREV = "0000000000000000000000000000000000000000000000000000000000000000";

pub const Transport = enum { http, stdio, link };
// The enums live in config.zig (the env loader owns them); re-exported here
// so the audit API reads naturally.
pub const OnFull = config.AuditOnFull;
pub const ArgsMode = config.AuditArgsMode;

/// What the calling transport knows about the request. All slices are
/// borrowed for the duration of the call; the ring copies bytes.
pub const CallCtx = struct {
    transport: Transport,
    /// HTTP peer address, "stdio", or "hub:<host>:<port>" on a link.
    client: []const u8 = "",
    /// sha256 prefix (16 hex chars) of the Mcp-Session-Id header, or "".
    session: []const u8 = "",
    /// JSON rendering of the JSON-RPC id (already truncated), or "null".
    req_id: []const u8 = "null",
    /// Link REQ stream id (0 off-link); joins hub relay <-> node tool.call.
    link_sid: u32 = 0,
    /// The per-token policy matched for this request (null when no policy
    /// is configured, or on transports without a client token). Borrowed;
    /// the PolicySet outlives every request.
    policy: ?*const @import("policy.zig").TokenPolicy = null,
    /// The matched token's hash prefix (8 bytes as 16 hex chars) — identifies
    /// WHICH policy entry denied, without ever logging the token value.
    /// Zeroes when no policy is active.
    token_fp: [16]u8 = token_fp_default,
};

/// The token_fp value used when no policy is active (all '0' chars).
pub const token_fp_default: [16]u8 = [_]u8{'0'} ** 16;

pub fn fromCfg(cfg: *const config.Config) ?*Writer {
    return @ptrCast(@alignCast(cfg.audit));
}

// ---------------------------------------------------------------------------
// Fixed-capacity byte builder (no allocation; overflow is a hard bug)
// ---------------------------------------------------------------------------

pub const Buf = struct {
    data: [MAX_RECORD]u8 = undefined,
    len: usize = 0,
    overflow: bool = false,

    pub fn reset(self: *Buf) void {
        self.len = 0;
        self.overflow = false;
    }

    pub fn append(self: *Buf, s: []const u8) void {
        if (self.len + s.len > self.data.len) {
            self.overflow = true;
            return;
        }
        @memcpy(self.data[self.len..][0..s.len], s);
        self.len += s.len;
    }

    pub fn print(self: *Buf, comptime fmt: []const u8, args: anytype) void {
        const s = std.fmt.bufPrint(self.data[self.len..], fmt, args) catch {
            self.overflow = true;
            return;
        };
        self.len += s.len;
    }

    /// JSON string literal, same escaping rules as util.appendJsonString
    /// (control bytes as \uXXXX, invalid UTF-8 as U+FFFD). The escaped form
    /// is capped at `cap` bytes; a capped string ends early but stays valid
    /// JSON (the cap is applied on a character boundary, never inside an
    /// escape sequence).
    pub fn jsonStrCap(self: *Buf, s: []const u8, cap: usize) void {
        const mark = self.len;
        self.append("\"");
        var i: usize = 0;
        while (i < s.len) {
            if (self.len - mark + 8 > cap) break; // room for the longest escape + quote
            const c = s[i];
            switch (c) {
                '"' => self.append("\\\""),
                '\\' => self.append("\\\\"),
                '\n' => self.append("\\n"),
                '\r' => self.append("\\r"),
                '\t' => self.append("\\t"),
                0x00...0x08, 0x0b, 0x0c, 0x0e...0x1f => self.print("\\u{x:0>4}", .{c}),
                else => {
                    if (c < 0x80) {
                        self.append(s[i .. i + 1]);
                        i += 1;
                        continue;
                    }
                    const seq_len = util.utf8SeqLen(s[i..]) orelse {
                        self.append("\xef\xbf\xbd");
                        i += 1;
                        continue;
                    };
                    if (i + seq_len > s.len or !util.validUtf8Seq(s[i .. i + seq_len])) {
                        self.append("\xef\xbf\xbd");
                        i += 1;
                        continue;
                    }
                    self.append(s[i .. i + seq_len]);
                    i += seq_len;
                    continue;
                },
            }
            i += 1;
        }
        self.append("\"");
    }

    /// Lowercase hex string literal ("abcd...").
    pub fn hexStr(self: *Buf, bytes: []const u8) void {
        const alphabet = "0123456789abcdef";
        self.append("\"");
        for (bytes) |b| {
            self.append(alphabet[b >> 4 ..][0..1]);
            self.append(alphabet[b & 0x0f ..][0..1]);
        }
        self.append("\"");
    }

    pub fn slice(self: *const Buf) []const u8 {
        return self.data[0..self.len];
    }
};

// ---------------------------------------------------------------------------
// Canonical argument digest and the per-tool summary allowlist
// ---------------------------------------------------------------------------

const Value = std.json.Value;

/// Nesting depth the argument digest examines in full. Past the cutoff the
/// subtree is not silently folded into a value that could collide with a
/// real one: an unencodable marker byte is hashed instead and the digest is
/// flagged partial (ArgsDigest.partial), so a partial fingerprint is never
/// published under the completeness contract.
const DIGEST_DEPTH_MAX: u8 = 32;

pub const ArgsDigest = struct {
    hex: [MAC_HEX_LEN]u8,
    /// True when a subtree past DIGEST_DEPTH_MAX was not examined. The
    /// digest then distinguishes "something unexamined was here" from any
    /// concrete value, but two different over-deep subtrees share it — the
    /// record must carry args_digest_partial so nobody compares such
    /// digests as if they were complete.
    partial: bool,
};

/// sha256 over the canonical argument JSON (compact, object keys in
/// as-received order), streamed so a multi-MiB write_file body costs no
/// memory. The digest identifies the exact arguments without storing them;
/// when ArgsDigest.partial is set, identification holds only down to
/// DIGEST_DEPTH_MAX levels of nesting and the record says so.
pub fn argsDigestHex(args: Value) ArgsDigest {
    var h = Sha256.init(.{});
    var overflowed = false;
    hashJsonCanon(&h, args, 0, &overflowed);
    const digest = h.finalResult();
    var out: [MAC_HEX_LEN]u8 = undefined;
    const alphabet = "0123456789abcdef";
    for (digest, 0..) |b, i| {
        out[i * 2] = alphabet[b >> 4];
        out[i * 2 + 1] = alphabet[b & 0x0f];
    }
    return .{ .hex = out, .partial = overflowed };
}

fn hashJsonCanon(h: *Sha256, v: Value, depth: u8, overflowed: *bool) void {
    if (depth > DIGEST_DEPTH_MAX) {
        // Not "null": a marker byte no encoded value can start with
        // (null/bool/number/string/array/object all open with ASCII, and
        // strings carry their 0x00/0x01 domain byte), so an unexamined
        // subtree can never alias a real value at this position.
        overflowed.* = true;
        h.update("\x02");
        return;
    }
    var num_buf: [1100]u8 = undefined;
    switch (v) {
        .null => h.update("null"),
        .bool => |b| h.update(if (b) "true" else "false"),
        // i64 renders in at most 20 bytes; the buffer always fits.
        .integer => |i| h.update(std.fmt.bufPrint(&num_buf, "{d}", .{i}) catch unreachable),
        // "{d}" renders a float in positional decimal notation: the worst
        // case is the smallest denormal (2^-1074), about 1076 characters.
        // The buffer covers it, but should formatting ever fail, never
        // substitute a value silently — flag the digest partial instead.
        .float => |f| h.update(std.fmt.bufPrint(&num_buf, "{d}", .{f}) catch {
            overflowed.* = true;
            h.update("\x02");
            return;
        }),
        .number_string => |s| {
            // Parser-produced number strings are grammar-valid, but the
            // public digest API accepts hand-built Values: an arbitrary
            // byte string here could swallow collection punctuation just
            // like an unframed raw string. Frame anything unexpected in
            // its own domain (0x03), distinct from the raw-string domain.
            const bare = s.len > 0 and for (s) |c| {
                switch (c) {
                    '0'...'9', 'e', 'E', '+', '-', '.' => {},
                    else => break false,
                }
            } else true;
            if (bare) {
                h.update(s);
            } else {
                h.update("\x03");
                var len_buf: [8]u8 = undefined;
                std.mem.writeInt(u64, &len_buf, s.len, .big);
                h.update(&len_buf);
                h.update(s);
            }
        },
        .string => |s| {
            hashJsonString(h, s);
        },
        .array => |arr| {
            h.update("[");
            for (arr.items, 0..) |item, i| {
                if (i != 0) h.update(",");
                hashJsonCanon(h, item, depth + 1, overflowed);
            }
            h.update("]");
        },
        .object => |obj| {
            h.update("{");
            var it = obj.iterator();
            var first = true;
            while (it.next()) |kv| {
                if (!first) h.update(",");
                first = false;
                hashJsonString(h, kv.key_ptr.*);
                h.update(":");
                hashJsonCanon(h, kv.value_ptr.*, depth + 1, overflowed);
            }
            h.update("}");
        },
    }
}

/// Hash a canonical, injective form of the JSON string `s`.
///
/// The digest exists so an auditor can confirm that two records carried
/// the same arguments; it must therefore be injective: distinct byte
/// strings must never fold to the same digest. The lossy escaped form
/// (invalid UTF-8 replaced by U+FFFD) is NOT injective, so:
///   - a fully valid UTF-8 string hashes as 0x00 | escaped-literal;
///   - anything else hashes as 0x01 | raw bytes.
/// The 0x00/0x01 domain byte cannot appear raw inside a JSON string
/// (control bytes are always escaped), so the two domains cannot meet.
fn hashJsonString(h: *Sha256, s: []const u8) void {
    if (!std.unicode.utf8ValidateSlice(s)) {
        // Raw bytes are framed with an explicit length: without it the
        // string could swallow the enclosing collection's punctuation
        // (a raw ']' or ','), letting two different argument trees hash
        // to the same stream.
        h.update("\x01");
        var len_buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &len_buf, s.len, .big);
        h.update(&len_buf);
        h.update(s);
        return;
    }
    h.update("\x00");
    h.update("\"");
    var esc: [8]u8 = undefined;
    var i: usize = 0;
    while (i < s.len) {
        const c = s[i];
        switch (c) {
            '"' => h.update("\\\""),
            '\\' => h.update("\\\\"),
            '\n' => h.update("\\n"),
            '\r' => h.update("\\r"),
            '\t' => h.update("\\t"),
            0x00...0x08, 0x0b, 0x0c, 0x0e...0x1f => {
                const e = std.fmt.bufPrint(&esc, "\\u{x:0>4}", .{c}) catch unreachable;
                h.update(e);
            },
            else => {
                if (c < 0x80) {
                    h.update(s[i .. i + 1]);
                    i += 1;
                    continue;
                }
                const seq_len = util.utf8SeqLen(s[i..]) orelse {
                    h.update("\xef\xbf\xbd");
                    i += 1;
                    continue;
                };
                if (i + seq_len > s.len or !util.validUtf8Seq(s[i .. i + seq_len])) {
                    h.update("\xef\xbf\xbd");
                    i += 1;
                    continue;
                }
                h.update(s[i .. i + seq_len]);
                i += seq_len;
                continue;
            },
        }
        i += 1;
    }
    h.update("\"");
}

fn objStr(args: Value, key: []const u8) ?[]const u8 {
    if (args != .object) return null;
    const v = args.object.get(key) orelse return null;
    if (v != .string) return null;
    return v.string;
}

/// Integer argument for the args summary. Total on any std.json.Value the
/// wire can hand over (policyDeny args never passed tool validation):
/// non-finite or out-of-range floats and fractional values yield null
/// (the same rejection util.optIntArg applies to an accepted integer
/// argument) instead of trapping in @intFromFloat.
fn objInt(args: Value, key: []const u8) ?i64 {
    if (args != .object) return null;
    const v = args.object.get(key) orelse return null;
    return switch (v) {
        .integer => |i| i,
        .float => |f| blk: {
            const i = util.floatToI64(f) orelse break :blk null;
            // Reject fractional floats a bare cast would silently truncate.
            if (@as(f64, @floatFromInt(i)) != f) break :blk null;
            break :blk i;
        },
        .number_string => |s| blk: {
            break :blk std.fmt.parseInt(i64, s, 10) catch break :blk null;
        },
        else => null,
    };
}

/// Per-tool argument summary, appended as a JSON object. The allowlist is
/// the design's: argv[0]+argc for exec/exec_start (full argv in `full`
/// mode), shell+script length for exec_shell, path(+size) for
/// read_file/write_file/list_dir, source/destination(+caps) for copy_path,
/// session_id for the session tools.
/// Scripts, file contents and stdout are never logged in any mode.
pub fn appendArgsSummary(buf: *Buf, tool: []const u8, args: Value, mode: ArgsMode) void {
    const start_len = buf.len;
    if (std.mem.eql(u8, tool, "copy_path")) {
        buf.append("{");
        for ([_][]const u8{ "source", "destination" }, 0..) |field, i| {
            if (i != 0) buf.append(",");
            buf.jsonStrCap(field, 32);
            buf.append(":");
            if (objStr(args, field)) |p| buf.jsonStrCap(p, 160) else buf.append("null");
        }
        for ([_][]const u8{ "max_bytes", "max_entries", "timeout" }) |field| {
            buf.append(",");
            buf.jsonStrCap(field, 32);
            buf.append(":");
            if (objInt(args, field)) |n| buf.print("{d}", .{n}) else buf.append("null");
        }
        buf.append("}");
        return;
    }
    if (std.mem.eql(u8, tool, "exec") or std.mem.eql(u8, tool, "exec_start")) {
        const argv: ?[]Value = blk: {
            if (args != .object) break :blk null;
            const v = args.object.get("argv") orelse break :blk null;
            if (v != .array) break :blk null;
            break :blk v.array.items;
        };
        const argc: usize = if (argv) |a| a.len else 0;
        if (mode == .full and argv != null) {
            buf.append("{\"argv\":[");
            var first = true;
            var truncated = false;
            for (argv.?) |item| {
                if (item != .string) continue;
                // Budget check AFTER the append: the escaped form, not the
                // raw string length, is what spends SUMMARY_CAP. An item
                // that overflows the budget is rolled back whole, so the
                // summary never exceeds the cap and `truncated` is honest.
                const before = buf.len;
                if (!first) buf.append(",");
                buf.jsonStrCap(item.string, 256);
                if (buf.len - start_len > SUMMARY_CAP) {
                    buf.len = before;
                    truncated = true;
                    break;
                }
                first = false;
            }
            buf.append("],\"argc\":");
            buf.print("{d}", .{argc});
            if (truncated) buf.append(",\"truncated\":true");
            buf.append("}");
            return;
        }
        buf.append("{\"argv0\":");
        if (argv) |a| {
            if (a.len > 0 and a[0] == .string) {
                buf.jsonStrCap(a[0].string, 256);
            } else {
                buf.append("null");
            }
        } else {
            buf.append("null");
        }
        buf.append(",\"argc\":");
        buf.print("{d}", .{argc});
        buf.append("}");
        return;
    }
    if (std.mem.eql(u8, tool, "exec_shell")) {
        buf.append("{\"shell\":");
        if (objStr(args, "shell")) |sh| buf.jsonStrCap(sh, 64) else buf.append("null");
        const script_len = if (objStr(args, "script")) |sc| sc.len else 0;
        buf.append(",\"script_len\":");
        buf.print("{d}", .{script_len});
        buf.append("}");
        return;
    }
    if (std.mem.eql(u8, tool, "read_file") or std.mem.eql(u8, tool, "list_dir")) {
        buf.append("{\"path\":");
        if (objStr(args, "path")) |p| buf.jsonStrCap(p, 768) else buf.append("null");
        buf.append("}");
        return;
    }
    if (std.mem.eql(u8, tool, "write_file")) {
        buf.append("{\"path\":");
        if (objStr(args, "path")) |p| buf.jsonStrCap(p, 768) else buf.append("null");
        if (objStr(args, "content_b64")) |b64| {
            const size = std.base64.standard.Decoder.calcSizeForSlice(b64) catch 0;
            buf.append(",\"size\":");
            buf.print("{d}", .{size});
        }
        buf.append("}");
        return;
    }
    if (std.mem.startsWith(u8, tool, "exec_")) {
        // exec_poll, exec_write, exec_kill, exec_close, exec_wait.
        if (objInt(args, "session_id")) |sid| {
            buf.append("{\"session_id\":");
            buf.print("{d}", .{sid});
            buf.append("}");
            return;
        }
    }
    buf.append("{}");
}

/// Render a JSON-RPC id for the log: canonical bytes, strings truncated to
/// REQ_ID_MAX bytes of JSON (escape-safe and UTF-8 character-boundary safe,
/// closing quote preserved).
pub fn renderReqId(buf: *Buf, id: Value) void {
    const id_start = buf.len;
    appendJsonValueCanon(buf, id);
    const rendered = buf.data[id_start..buf.len];
    if (rendered.len <= REQ_ID_MAX) return;
    // Truncate: strings keep a valid closing quote; anything else is cut
    // on a plain boundary (numbers stay valid literals).
    if (rendered.len > 0 and rendered[0] == '"') {
        // Forward scan from the opening quote: track the offset just past
        // each complete unit (escape pair, \uXXXX sextet, or whole UTF-8
        // sequence) and cut at the last unit boundary that still leaves
        // room for the `~` marker and the closing quote. Backward
        // heuristics misread an escaped backslash as the start of a
        // \uXXXX (a raw `\u00e9` in the id renders as `\\u00e9`, and
        // walking back to "the backslash before u" leaves a dangling
        // escape); a forward pass cannot split a unit by construction.
        var cut: usize = 1;
        var i: usize = 1;
        while (i < rendered.len) {
            const unit: usize = if (rendered[i] != '\\')
                util.utf8SeqLen(rendered[i..]) orelse 1
            else if (i + 1 < rendered.len and rendered[i + 1] == 'u')
                6
            else
                2;
            if (i + unit > REQ_ID_MAX - 2) break;
            i += unit;
            cut = i;
        }
        buf.len = id_start + cut;
        buf.append("~\"");
    } else {
        // A number cut on a plain byte boundary can end mid-exponent and
        // stop being a valid literal; render a truncated non-string as null.
        if (id == .integer or id == .bool or id == .null) {
            buf.len = id_start + REQ_ID_MAX;
        } else {
            buf.len = id_start;
            buf.append("null");
        }
    }
}

fn appendJsonValueCanon(buf: *Buf, v: Value) void {
    switch (v) {
        .null => buf.append("null"),
        .bool => |b| buf.append(if (b) "true" else "false"),
        .integer => |i| buf.print("{d}", .{i}),
        .float => |f| buf.print("{d}", .{f}),
        .number_string => |s| buf.append(s),
        .string => |s| buf.jsonStrCap(s, 4096),
        else => buf.append("null"),
    }
}

// ---------------------------------------------------------------------------
// The writer
// ---------------------------------------------------------------------------

pub const Options = struct {
    path: []const u8,
    key: ?[]const u8 = null,
    host: []const u8 = "mcp-node",
    role: []const u8 = "node",
    mode: []const u8 = "listen",
    config_fingerprint: [MAC_HEX_LEN]u8 = ZERO_PREV.*,
    args_mode: ArgsMode = .summary,
    on_full: OnFull = .block,
    max_bytes: u64 = 64 * 1024 * 1024,
    spawn_thread: bool = true,
    /// Test hook: shrink the ring without touching RING_SLOTS semantics.
    ring_cap: usize = RING_SLOTS,
    /// Test hook: pin the wall clock (epoch ms) for canonical-byte tests.
    now_ms_override: ?i64 = null,
    /// Test hook: do not enqueue the start record (exact-byte tests).
    skip_start_record: bool = false,
};

/// Which rename the directory-sync gate is holding: a rotation (the fresh
/// file and its rotate record are deferred) or a quarantine (the fresh
/// chain file's open is deferred; chain reset and pending_break are
/// already staged in memory).
const DirSyncGate = enum { none, rotate, quarantine };

pub const Writer = struct {
    gpa: Allocator,
    io: Io,
    /// The live log handle, or null once it has been retired (a rotate
    /// cascade, a torn tail that could not be cut back). A retired number
    /// may already be recycled by accept(), so writes, the shutdown sync
    /// and the close only ever run through live ownership.
    log: ?os.fd.AppendLog,
    path: []const u8,
    key: ?[]const u8,
    host: []const u8,
    role: []const u8,
    on_full: OnFull,
    args_mode: ArgsMode,
    max_bytes: u64,
    now_ms_override: ?i64,

    mutex: Io.Mutex = .init,
    not_empty: Io.Condition = .init,
    not_full: Io.Condition = .init,
    slots: [RING_SLOTS][MAX_INNER]u8 = undefined,
    lens: [RING_SLOTS]u16 = @splat(0),
    head: usize = 0, // next slot to write
    tail: usize = 0, // next slot to drain
    count: usize = 0,
    ring_cap: usize,
    dropped: u64 = 0,
    stopping: bool = false,
    io_failed: bool = false,
    /// Mid-run recovery quarantined a corrupt file: the next batch opens
    /// with a chain.break record naming it (break_name below).
    pending_break: bool = false,
    /// Mid-run recovery landed on a brand-new empty file while the chain
    /// already holds committed records: the next batch opens with an
    /// explicit `recover` boundary record instead of silently continuing.
    pending_recover: bool = false,
    break_name: [512]u8 = undefined,
    break_name_len: usize = 0,
    /// Rename-durability gate: a rotation or quarantine rename whose
    /// parent-directory flush failed. While the gate is set, drainOnce
    /// refuses to write any record — the chain continues only after the
    /// rename is proven durable (and, for a rotation, the deferred rotate
    /// record has landed in the fresh file).
    dir_sync_gate: DirSyncGate = .none,
    /// The winning rotation name, kept for the deferred rotate record
    /// while the dir_sync_gate holds a rotation.
    rotated_name: [512]u8 = undefined,
    rotated_name_len: u16 = 0,
    /// Chain generation tag (epoch ms at chain genesis): keeps rotation
    /// names unique across chain restarts so a post-quarantine rotation
    /// can never collide with — let alone overwrite — an old chain's file.
    chain_gen: u64 = 0,
    /// Test hooks (same-file tests only): force the next drain-side
    /// write/truncation to fail so the transactional rollback paths run
    /// against a real file. Never set in production.
    fail_next_write: bool = false,
    fail_next_trunc: bool = false,
    fail_next_sync: bool = false,
    fail_rotate_sync: bool = false,
    fail_dir_sync: bool = false,
    /// Test hooks: fail EVERY write / directory sync (persistent outage),
    /// for the bounded-shutdown regression tests. Never set in production.
    fail_all_writes: bool = false,
    fail_all_dir_sync: bool = false,
    /// Consecutive failed drains since `stopping` was set: the shutdown
    /// retry budget. A transient failure still heals (the counter resets
    /// on any committed batch); a persistent outage must not hold process
    /// exit hostage.
    stop_failures: u8 = 0,
    /// Terminal shutdown: the retry budget is exhausted, the outstanding
    /// loss was reported, and remaining records are drained and discarded
    /// so the thread can exit. Drain-side only.
    stop_gave_up: bool = false,
    /// A rename (rotation or quarantine) vacated the pathname and the
    /// fresh exclusive create has not landed yet: until it does, every
    /// (re)open of self.path must be exclusive — a plain appendOpen would
    /// commit chain bytes into a foreign occupant's file.
    need_exclusive_create: bool = false,

    seq: u64 = 0,
    prev: [MAC_HEX_LEN]u8 = ZERO_PREV.*,
    /// First seq of the currently open file (rotation names the old file
    /// with it); recovered from the head line at open.
    file_first_seq: u64 = 0,
    thread: ?std.Thread = null,

    fn nowMs(self: *const Writer) i64 {
        return self.now_ms_override orelse Io.Clock.real.now(self.io).toMilliseconds();
    }

    /// Enqueue a preformatted event inner. Hot path: one mutex, one memcpy,
    /// no allocation. Null writer = audit off (single branch at call site).
    pub fn enqueueInner(self: *Writer, inner: []const u8) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (inner.len == 0 or inner.len > MAX_INNER) {
            // Oversize inners must not vanish silently: count them so the
            // drain side emits the chained `dropped` marker — and wake the
            // drainer, the ring may be empty otherwise.
            self.dropped += 1;
            self.not_empty.signal(self.io);
            return;
        }
        if (self.stopping) return;
        if (self.count >= self.ring_cap) {
            switch (self.on_full) {
                .block => {
                    while (self.count >= self.ring_cap and !self.stopping)
                        self.not_full.waitUncancelable(self.io, &self.mutex);
                    if (self.stopping) return;
                },
                .drop => {
                    self.dropped += 1;
                    return;
                },
            }
        }
        @memcpy(self.slots[self.head][0..inner.len], inner);
        self.lens[self.head] = @intCast(inner.len);
        self.head = (self.head + 1) % self.ring_cap;
        self.count += 1;
        self.not_empty.signal(self.io);
    }

    /// One drain cycle without the thread: collect up to BATCH_MAX inners,
    /// compose canonical lines, append the dropped record when due, write
    /// and fsync. Exported for tests; the writer thread calls it in a loop.
    pub fn drainOnce(self: *Writer) void {
        var inners: [BATCH_MAX][MAX_INNER]u8 = undefined;
        var ilens: [BATCH_MAX]u16 = undefined;
        var n: usize = 0;
        var dropped_here: u64 = 0;
        {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            while (n < BATCH_MAX and self.count > 0) : (n += 1) {
                const l = self.lens[self.tail];
                @memcpy(inners[n][0..l], self.slots[self.tail][0..l]);
                ilens[n] = l;
                self.tail = (self.tail + 1) % self.ring_cap;
                self.count -= 1;
            }
            if (self.dropped > 0) {
                dropped_here = self.dropped;
                self.dropped = 0;
            }
            self.not_full.broadcast(self.io);
        }
        if (n == 0 and dropped_here == 0) return;
        // Terminal shutdown: the give-up already reported the outstanding
        // loss; drain and discard whatever is still arriving so the thread
        // reaches its exit condition.
        if (self.stop_gave_up) return;
        // Rename-durability gate: a rotation or quarantine rename whose
        // parent-directory flush has not succeeded must not be built on.
        // Retry the flush (and the deferred reopen / rotate record) before
        // any record is written against the rename; while the gate holds,
        // records are counted as dropped rather than committed onto ground
        // a crash may still pull away.
        if (self.dir_sync_gate != .none) {
            var gate_err: ?anyerror = self.syncDir();
            if (gate_err == null) gate_err = self.completeDirSyncGate();
            if (gate_err) |err| {
                self.io_failed = true;
                self.mutex.lockUncancelable(self.io);
                self.dropped += n + dropped_here;
                self.mutex.unlock(self.io);
                std.debug.print("audit: directory sync gate holds: {s}\n", .{@errorName(err)});
                self.noteDrainFailure();
                return;
            }
            self.dir_sync_gate = .none;
        }
        // Reopen and re-verify the file BEFORE composing a single line:
        // composeLine assigns seq/prev, and those may only advance for
        // bytes that reach the file. A failed recovery counts the losses
        // and leaves the committed chain state untouched, so a later
        // successful reopen can never resume from a chain state that
        // phantom records already advanced.
        if (!self.recoverHandle()) {
            self.mutex.lockUncancelable(self.io);
            self.dropped += n + dropped_here;
            self.mutex.unlock(self.io);
            self.noteDrainFailure();
            return;
        }
        // Snapshot the chain state: a failed write rolls seq/prev/pos back
        // so the on-disk chain keeps exact continuity, and the lost records
        // surface as a chained `dropped` record on the next good batch. The
        // pending boundary markers ride along: a failed batch must not
        // consume the chain.break/recover record it was supposed to write.
        const seq0 = self.seq;
        const prev0 = self.prev;
        const pos0 = self.log.?.pos;
        const pending_break0 = self.pending_break;
        const pending_recover0 = self.pending_recover;
        // +2: an optional boundary record (chain.break/recover) plus the
        // dropped marker can lead the batch.
        var batch: [BATCH_MAX * MAX_RECORD + 2 * MAX_RECORD]u8 = undefined;
        var blen: usize = 0;
        var line: Buf = undefined;
        if (self.pending_break) {
            self.pending_break = false;
            var inner: Buf = undefined;
            inner.reset();
            inner.append("\"event\":\"chain.break\",\"reason\":\"tail_verify_failed\",\"lost_file\":");
            inner.jsonStrCap(self.break_name[0..self.break_name_len], 128);
            self.composeLine(inner.slice(), &line);
            @memcpy(batch[blen..][0..line.len], line.slice());
            blen += line.len;
        } else if (self.pending_recover) {
            self.pending_recover = false;
            var inner: Buf = undefined;
            inner.reset();
            inner.append("\"event\":\"recover\",\"reason\":\"reopened_new_file\"");
            self.composeLine(inner.slice(), &line);
            @memcpy(batch[blen..][0..line.len], line.slice());
            blen += line.len;
        }
        for (inners[0..n], ilens[0..n]) |*inner, l| {
            self.composeLine(inner[0..l], &line);
            @memcpy(batch[blen..][0..line.len], line.slice());
            blen += line.len;
        }
        if (dropped_here > 0) {
            var inner_buf: Buf = undefined;
            inner_buf.reset();
            inner_buf.append("\"event\":\"dropped\",\"count\":");
            inner_buf.print("{d}", .{dropped_here});
            self.composeLine(inner_buf.slice(), &line);
            @memcpy(batch[blen..][0..line.len], line.slice());
            blen += line.len;
        }
        // The batch is committed only when its bytes are durable: a write
        // failure and an fsync failure share one transactional rollback.
        var commit_err: ?anyerror = self.writeBatch(batch[0..blen]);
        if (commit_err == null) commit_err = self.syncNow();
        if (commit_err) |err| {
            self.io_failed = true;
            self.seq = seq0;
            self.prev = prev0;
            self.pending_break = pending_break0;
            self.pending_recover = pending_recover0;
            // A partial write (or an unsynced tail) leaves garbage past the
            // last good offset; cutting back to it is a PRECONDITION for
            // taking more records, not a best-effort cleanup. When the cut
            // itself fails, the offset is unconfirmed: retire the handle,
            // keep log.pos away from the unverified value, and let the next
            // batch resume only after a verified recovery (or quarantine)
            // re-derives the state from the live file.
            if (self.truncTo(pos0) != null) {
                self.retireHandle();
            } else {
                self.log.?.pos = pos0;
            }
            self.mutex.lockUncancelable(self.io);
            self.dropped += n + dropped_here;
            self.mutex.unlock(self.io);
            std.debug.print("audit: batch commit failed: {s}\n", .{@errorName(err)});
            self.noteDrainFailure();
            return;
        }
        self.io_failed = false;
        self.stop_failures = 0;
        if (self.log.?.pos >= self.max_bytes) self.rotate();
    }

    /// Shutdown accounting for a failed drain. Normal operation retries
    /// forever — the daemon lives on and a transient outage heals. Once
    /// `stopping` is set, a persistent outage must not hold process exit
    /// hostage: after STOP_RETRY_BUDGET consecutive failures the writer
    /// reports the outstanding loss, retires the handle, and drains the
    /// ring to nowhere so the thread reaches its exit condition. The
    /// give-up is terminal for this writer; it never happens mid-run.
    fn noteDrainFailure(self: *Writer) void {
        self.mutex.lockUncancelable(self.io);
        if (!self.stopping) {
            self.mutex.unlock(self.io);
            return;
        }
        self.stop_failures +|= 1;
        if (self.stop_failures < STOP_RETRY_BUDGET) {
            self.mutex.unlock(self.io);
            return;
        }
        const outstanding = self.dropped + self.count;
        self.dropped = 0;
        self.mutex.unlock(self.io);
        self.retireHandle();
        self.stop_gave_up = true;
        std.debug.print(
            "audit: shutdown gives up after {d} failed retries; {d} records could not be persisted\n",
            .{ self.stop_failures, outstanding },
        );
    }

    /// Size rotation, called by the draining side only, between batches so
    /// the cut lands on a record boundary. The old file is renamed to
    /// `<path>.<first-seq>` and the chain continues in a fresh file whose
    /// first record is `rotate` (its `prev` links the two files). The old
    /// fd is closed before the rename because Windows forbids renaming an
    /// open file; ownership is dropped with it — a failed reopen leaves no
    /// dead descriptor number behind, the next batch reopens and
    /// re-verifies, and the log grows past the limit instead of losing
    /// records.
    fn rotate(self: *Writer) void {
        // Rotation names carry the chain generation so a chain restarted
        // after a quarantine can never collide with (and silently replace)
        // an old chain's rotated files; renamePathNoReplace fails closed on
        // any residual collision and the disambiguator suffix resolves it.
        var name_buf: [512]u8 = undefined;
        var rotated: []const u8 = std.fmt.bufPrint(&name_buf, "{s}.{d}.{d}", .{ self.path, self.chain_gen, self.file_first_seq }) catch return;
        const old_fd = self.log.?.fd;
        // The old file must be durable before it is renamed away: the fresh
        // file's rotate record links prev to bytes that may otherwise vanish
        // on a crash. Fails closed: the handle stays live, the log grows
        // past the limit, and the next batch retries the rotation.
        if (self.syncBeforeRotate() != null) {
            self.io_failed = true;
            return;
        }
        os.closeFd(old_fd);
        self.log = null;
        var renamed = false;
        var attempt: u8 = 0;
        while (attempt < 16) : (attempt += 1) {
            if (attempt > 0) {
                rotated = std.fmt.bufPrint(&name_buf, "{s}.{d}.{d}-{d}", .{ self.path, self.chain_gen, self.file_first_seq, attempt }) catch return;
            }
            os.fd.renamePathNoReplace(self.io, self.path, rotated) catch |err| switch (err) {
                error.TargetExists => continue, // name taken: disambiguate
                else => {
                    // Rename failed with the fd already closed: reopen the
                    // live file so the next batch still has somewhere to
                    // write.
                    if (!self.reopenLive()) self.io_failed = true;
                    return;
                },
            };
            renamed = true;
            // The pathname is vacated: until the fresh exclusive create
            // lands, no plain appendOpen may touch it.
            self.need_exclusive_create = true;
            break;
        }
        if (!renamed) {
            // Every candidate name was taken: keep the log growing past the
            // limit and retry the rotation with the next batch.
            if (!self.reopenLive()) self.io_failed = true;
            return;
        }
        // The rename is directory metadata: flush the parent so the rotated
        // name survives a crash before the fresh file's records depend on
        // it. Fails closed: while the flush is unconfirmed, the fresh file
        // and its rotate record stay deferred behind the directory-sync
        // gate — committing them would tie the chain to a rename a crash
        // may still undo.
        if (self.syncDir() != null) {
            @memcpy(self.rotated_name[0..rotated.len], rotated);
            self.rotated_name_len = @intCast(rotated.len);
            self.dir_sync_gate = .rotate;
            self.io_failed = true;
            return;
        }
        if (self.commitRotateRecord(rotated)) |err| {
            if (err == error.PathAlreadyExists) {
                // A foreign file occupies the just-vacated pathname:
                // quarantine it and restart the chain with chain.break —
                // never append a rotate boundary to foreign bytes.
                if (self.absorbForeignFile() != null) self.io_failed = true;
                return;
            }
            self.io_failed = true;
            std.debug.print("audit: rotate record failed: {s}\n", .{@errorName(err)});
        }
    }

    /// Open the fresh post-rename file with exclusive create: the pathname
    /// was deliberately removed by the rename, so anything found there is
    /// another writer's file — never append to it. Null = created; the
    /// error propagates (PathAlreadyExists on a foreign occupant).
    fn createFresh(self: *Writer) ?anyerror {
        self.log = os.fd.createOpenExcl(self.io, self.path) catch |err| return err;
        self.need_exclusive_create = false;
        return null;
    }

    /// The pathname a rename just vacated is occupied again: the occupant
    /// is definitionally not ours. Quarantine it like any damaged file and
    /// restart the chain with an explicit chain.break — never append a
    /// rotate/recover boundary to foreign bytes. Null = the chain restarts
    /// in a fresh exclusive file; an error keeps the caller's gate/flags
    /// so the next batch retries (DirSyncPending arms the quarantine gate).
    fn absorbForeignFile(self: *Writer) ?anyerror {
        if (!self.quarantineDamagedFile()) return error.QuarantineFailed;
        self.seq = 0;
        self.prev = ZERO_PREV.*;
        self.file_first_seq = 0;
        self.chain_gen = @intCast(@max(self.nowMs(), 0));
        self.pending_break = true;
        if (self.dir_sync_gate == .quarantine) {
            // The quarantine rename is not proven durable: keep a gate
            // armed so the fresh file opens only after the flush.
            return error.DirSyncPending;
        }
        self.log = os.fd.createOpenExcl(self.io, self.path) catch return error.ReopenFailed;
        self.need_exclusive_create = false;
        return null;
    }

    /// Open the fresh file after a rotation and commit the rotate record
    /// transactionally (same write+sync rollback as drainOnce). Null = the
    /// chain continues in the fresh file.
    fn commitRotateRecord(self: *Writer, rotated: []const u8) ?anyerror {
        // The fresh file must be one we created exclusively: the pathname
        // was vacated by the rename, so PathAlreadyExists means a foreign
        // occupant (the caller quarantines it and restarts the chain).
        if (self.log == null) if (self.createFresh()) |err| return err;
        self.file_first_seq = self.seq;
        const seq0 = self.seq;
        const prev0 = self.prev;
        var inner: Buf = undefined;
        inner.reset();
        inner.append("\"event\":\"rotate\",\"rotated\":");
        inner.jsonStrCap(rotated, 384);
        var line: Buf = undefined;
        self.composeLine(inner.slice(), &line);
        // Same transactional commit as drainOnce: the rotate record counts
        // as written only once it is durable.
        var rot_err: ?anyerror = self.writeBatch(line.slice());
        if (rot_err == null) rot_err = self.syncNow();
        if (rot_err) |err| {
            self.seq = seq0;
            self.prev = prev0;
            // A partial/unsynced rotate record leaves a torn tail in the
            // fresh file. Cutting it back is a precondition for the next
            // batch; when the cut fails the fresh file is unusable at this
            // offset: retire the handle and recover with verification.
            if (self.truncTo(0) != null) {
                self.retireHandle();
            } else {
                self.log.?.pos = 0;
                // The fresh file lost its boundary record: the next batch
                // must open it with an explicit recover marker rather than
                // silently continuing the chain in a boundary-less file.
                self.pending_recover = true;
            }
            return err;
        }
        return null;
    }

    /// Finish the work deferred behind the directory-sync gate once the
    /// parent-directory flush has succeeded. Null = the gate may open.
    fn completeDirSyncGate(self: *Writer) ?anyerror {
        switch (self.dir_sync_gate) {
            .none => return null,
            .quarantine => {
                // The quarantine rename is durable: open the fresh chain
                // file with exclusive create — anything already at the
                // pathname is another writer's file, quarantined and
                // absorbed exactly like on the rotate path. The chain
                // reset and pending_break are already staged, so the next
                // batch leads with chain.break.
                self.log = os.fd.createOpenExcl(self.io, self.path) catch |err| switch (err) {
                    error.PathAlreadyExists => return self.absorbForeignFile(),
                    else => return err,
                };
                self.need_exclusive_create = false;
                return null;
            },
            .rotate => {
                const rot_err = self.commitRotateRecord(self.rotated_name[0..self.rotated_name_len]);
                if (rot_err) |err| switch (err) {
                    // A foreign file occupies the just-vacated pathname:
                    // quarantine it and restart the chain with chain.break
                    // instead of linking a rotate record into foreign
                    // bytes.
                    error.PathAlreadyExists => return self.absorbForeignFile(),
                    else => {
                        if (self.log == null) {
                            // The fresh file is torn beyond an in-place
                            // cut: the rename itself is durable at this
                            // point, so the ordinary verified-recovery path
                            // takes over.
                            return null;
                        }
                        return err;
                    },
                };
                return null;
            },
        }
    }

    /// Rotate-side old-file sync with the test injection point. Null =
    /// durable. Distinct from syncNow so tests can fail the rotation
    /// boundary sync without touching the batch commit sync.
    fn syncBeforeRotate(self: *Writer) ?anyerror {
        if (self.fail_rotate_sync) {
            self.fail_rotate_sync = false;
            return error.InjectedSyncFailure;
        }
        os.fd.syncFile(self.log.?.fd) catch |err| return err;
        return null;
    }

    /// Quarantine the damaged live file: rename it aside under
    /// `<path>.corrupt-<ms>` (never replacing an existing quarantine — two
    /// quarantines in the same millisecond get a disambiguator suffix),
    /// flush the parent directory so the rename survives a crash, and
    /// remember the aside name for the chain.break record. The caller owns
    /// closing the old handle first. False = nothing was renamed.
    fn quarantineDamagedFile(self: *Writer) bool {
        var attempt: u8 = 0;
        while (attempt < 16) : (attempt += 1) {
            const ms = Io.Clock.real.now(self.io).toMilliseconds();
            const aside = if (attempt == 0)
                std.fmt.bufPrint(&self.break_name, "{s}.corrupt-{d}", .{ self.path, ms }) catch return false
            else
                std.fmt.bufPrint(&self.break_name, "{s}.corrupt-{d}-{d}", .{ self.path, ms, attempt }) catch return false;
            os.fd.renamePathNoReplace(self.io, self.path, aside) catch |err| switch (err) {
                error.TargetExists => continue,
                else => return false,
            };
            self.break_name_len = aside.len;
            // The pathname is vacated: until the fresh exclusive create
            // lands, no plain appendOpen may touch it.
            self.need_exclusive_create = true;
            if (self.syncDir() != null) {
                // Renamed but not proven durable: the fresh chain file must
                // not be opened (and no chain.break committed) until the
                // parent-directory flush confirms the rename survives a
                // crash. The caller defers that work behind the gate.
                self.dir_sync_gate = .quarantine;
            }
            return true;
        }
        return false;
    }

    /// Plain reopen without verification, for rotate's failure paths where
    /// the file content is known-good (the previous batch was written and
    /// synced before the rotation started).
    fn reopenLive(self: *Writer) bool {
        self.log = os.fd.appendOpen(self.io, self.path) catch return false;
        return true;
    }

    /// Reopen the log after the handle was retired and re-derive the
    /// committed chain state from the live file BEFORE any batch
    /// composition: a torn final line is cut, the tail window is verified,
    /// and seq/prev/pos roll back to what the file actually holds. A tail
    /// that cannot be cut or fails verification is quarantined (renamed
    /// aside for forensics) and the next batch opens a fresh chain with
    /// chain.break. Returns true when a live, verified handle exists.
    fn recoverHandle(self: *Writer) bool {
        if (self.log != null) return true;
        if (self.need_exclusive_create) {
            // A rename vacated the pathname and the fresh exclusive create
            // has not landed: re-opening here must stay exclusive — a plain
            // appendOpen would commit chain.break and the fresh chain into
            // a foreign occupant's file.
            if (self.createFresh()) |err| {
                switch (err) {
                    error.PathAlreadyExists => return self.absorbForeignFile() == null,
                    else => return false,
                }
            }
            // Fresh empty file by construction; the staged chain.break or
            // recover boundary leads the next batch.
            return true;
        }
        self.log = os.fd.appendOpen(self.io, self.path) catch return false;
        var rec_err: ?anyerror = null;
        if (self.log) |*l| {
            recoverTail(self.gpa, self.io, self, l) catch |err| {
                rec_err = err;
            };
        }
        if (rec_err) |err| switch (err) {
            error.CorruptTail, error.UnusableTail => {
                // Quarantine: move the damaged file aside and start a fresh
                // chain; the pending batch is not lost — it follows the
                // chain.break record in the new file.
                self.retireHandle();
                if (!self.quarantineDamagedFile()) return false;
                // The chain reset lands BEFORE the reopen: when the open
                // fails, the retried recovery still knows the chain was
                // restarted and leads with chain.break (not recover).
                self.seq = 0;
                self.prev = ZERO_PREV.*;
                self.file_first_seq = 0;
                self.chain_gen = @intCast(@max(self.nowMs(), 0));
                self.pending_break = true;
                if (self.dir_sync_gate == .quarantine) {
                    // The quarantine rename is not proven durable: defer
                    // the fresh file open behind the directory-sync gate.
                    // The chain reset above is in-memory only — harmless
                    // until the gate confirms the rename and opens the file.
                    self.io_failed = true;
                    return false;
                }
                // Exclusive create: the pathname was just renamed away, so
                // a file found there belongs to another writer — absorb it
                // (quarantine + chain.break) instead of failing forever.
                self.log = os.fd.createOpenExcl(self.io, self.path) catch |oc_err| switch (oc_err) {
                    error.PathAlreadyExists => return self.absorbForeignFile() == null,
                    else => return false,
                };
                self.need_exclusive_create = false;
            },
            else => {
                // Transient verification I/O error: stay handle-less and
                // retry with the next batch.
                self.retireHandle();
                return false;
            },
        };
        if (self.log) |*l| {
            if (l.pos == 0 and self.seq > 0) {
                // Recovery landed on a brand-new empty file while the chain
                // already holds committed records (the old file was rotated
                // away or vanished): make the file boundary explicit
                // instead of silently continuing into a fresh file.
                self.file_first_seq = self.seq;
                self.pending_recover = true;
            }
        }
        return self.log != null;
    }

    /// Drain-side write with the test injection point. Null = written.
    fn writeBatch(self: *Writer, bytes: []const u8) ?anyerror {
        if (self.fail_all_writes) return error.InjectedWriteFailure;
        if (self.fail_next_write) {
            self.fail_next_write = false;
            return error.InjectedWriteFailure;
        }
        os.fd.appendWrite(self.io, &self.log.?, bytes) catch |err| return err;
        return null;
    }

    /// Drain-side truncation with the test injection point. Null = cut done.
    fn truncTo(self: *Writer, off: u64) ?anyerror {
        if (self.fail_next_trunc) {
            self.fail_next_trunc = false;
            return error.InjectedTruncFailure;
        }
        os.fd.truncFile(self.log.?.fd, off) catch |err| return err;
        return null;
    }

    /// Drain-side fsync with the test injection point. Null = durable.
    /// A sync failure is a batch commit failure: the caller rolls the chain
    /// state back and cuts the unsynced tail before taking more records.
    fn syncNow(self: *Writer) ?anyerror {
        if (self.fail_next_sync) {
            self.fail_next_sync = false;
            return error.InjectedSyncFailure;
        }
        os.fd.syncFile(self.log.?.fd) catch |err| return err;
        return null;
    }

    /// Parent-directory flush after a rename, with the test injection
    /// point. Null = the rename is durable. A failure arms the
    /// directory-sync gate: the rename happened but a crash may still undo
    /// it, so nothing may be committed against the new layout yet.
    fn syncDir(self: *Writer) ?anyerror {
        if (self.fail_all_dir_sync) return error.InjectedSyncFailure;
        if (self.fail_dir_sync) {
            self.fail_dir_sync = false;
            return error.InjectedSyncFailure;
        }
        os.fd.syncParentDir(self.io, self.path) catch |err| return err;
        return null;
    }

    /// Give up the handle: the fd is closed and its number is dead to this
    /// writer — the OS may hand it to accept() at any moment.
    fn retireHandle(self: *Writer) void {
        if (self.log) |*l| os.closeFd(l.fd);
        self.log = null;
    }

    /// Compose the canonical line for `inner`, assigning seq/ts/prev/mac.
    /// Only ever called by the draining side (single thread), which is what
    /// makes seq a total order.
    fn composeLine(self: *Writer, inner: []const u8, out: *Buf) void {
        out.reset();
        out.append("{\"v\":1,\"seq\":");
        out.print("{d}", .{self.seq});
        out.append(",\"ts\":\"");
        appendTs(out, self.nowMs());
        out.append("\",\"host\":");
        out.jsonStrCap(self.host, 96);
        out.append(",\"role\":\"");
        out.append(self.role);
        out.append("\",");
        out.append(inner);
        if (self.key) |k| {
            out.append(",\"prev\":\"");
            out.append(&self.prev);
            out.append("\"");
            var mac: [32]u8 = undefined;
            HmacSha256.create(&mac, out.data[0..out.len], k);
            out.append(",\"mac\":\"");
            const mac_at = out.len;
            const alphabet = "0123456789abcdef";
            for (mac) |b| {
                out.append(alphabet[b >> 4 ..][0..1]);
                out.append(alphabet[b & 0x0f ..][0..1]);
            }
            out.append("\"");
            @memcpy(&self.prev, out.data[mac_at .. mac_at + 64]);
        }
        out.append("}\n");
        self.seq += 1;
        // A truncated line would fail verification and look like tampering;
        // the budget is sized so this never fires — assert it loudly.
        std.debug.assert(!out.overflow);
    }
};

fn threadMain(w: *Writer) void {
    while (true) {
        var partial = false;
        {
            w.mutex.lockUncancelable(w.io);
            defer w.mutex.unlock(w.io);
            while (w.count == 0 and w.dropped == 0 and !w.stopping)
                w.not_empty.waitUncancelable(w.io, &w.mutex);
            // A pending dropped marker must be drained even at shutdown:
            // it is the only durable trace of the loss.
            if (w.count == 0 and w.dropped == 0 and w.stopping) break;
            partial = w.count < BATCH_MAX;
        }
        // Batch settle: a short beat lets a trickle-burst accumulate into
        // one write+fsync; a full ring skips it (throughput over latency).
        if (partial) os.sleepMs(BATCH_SETTLE_MS);
        w.drainOnce();
        w.mutex.lockUncancelable(w.io);
        const done = w.stopping and w.count == 0 and w.dropped == 0;
        w.mutex.unlock(w.io);
        if (done) break;
    }
    // Final fsync so a clean stop leaves nothing in the kernel page cache —
    // only through live ownership: a retired handle's number may belong to
    // an unrelated live resource by now.
    syncLiveHandle(w);
}

/// fsync through live ownership only (see Writer.log).
fn syncLiveHandle(w: *Writer) void {
    if (w.log) |*l| os.fd.syncFile(l.fd) catch {};
}

/// Close through live ownership only: a retired handle's number may have
/// been recycled by accept() and must never be closed a second time.
fn closeLiveHandle(w: *Writer) void {
    if (w.log) |*l| os.closeFd(l.fd);
}

/// Open the log, recover the tail chain, start the writer thread and record
/// the start event. On a corrupt tail the old file is renamed to
/// `<path>.corrupt-<epoch ms>` and the new file opens with chain.break.
pub fn start(gpa: Allocator, io: Io, opts: Options) !*Writer {
    // Quarantine and rotation names extend the path by up to ~60 bytes;
    // fail at startup rather than discovering the overflow mid-run with a
    // permanently dead audit writer.
    if (opts.path.len + 64 > 512) return error.NameTooLong;
    const w = try gpa.create(Writer);
    errdefer gpa.destroy(w);
    var log = try os.fd.appendOpen(io, opts.path);
    // The corrupt-tail path closes and reopens the fd by hand; the flag
    // keeps the errdefer from double-closing a dead descriptor.
    var log_open = true;
    errdefer if (log_open) os.closeFd(log.fd);
    w.* = .{
        .gpa = gpa,
        .io = io,
        .log = log,
        .path = opts.path,
        .key = opts.key,
        .host = opts.host,
        .role = opts.role,
        .on_full = opts.on_full,
        .args_mode = opts.args_mode,
        .max_bytes = opts.max_bytes,
        .now_ms_override = opts.now_ms_override,
        .ring_cap = opts.ring_cap,
    };
    var broke = false;
    if (w.log) |*l| {
        recoverTail(gpa, io, w, l) catch |err| switch (err) {
            // A tail that fails verification, or a torn tail that cannot be
            // cut back: quarantine the file and start a new chain.
            error.CorruptTail, error.UnusableTail => broke = true,
            else => return err,
        };
    }
    if (broke) {
        // Move the damaged file aside for forensics and start a new chain.
        os.closeFd(w.log.?.fd);
        log_open = false;
        if (!w.quarantineDamagedFile()) return error.RenameFailed;
        // A quarantine rename that cannot be proven durable fails startup
        // closed: no chain.break may be committed against a rename a crash
        // may still undo.
        if (w.dir_sync_gate != .none) return error.DirSyncFailed;
        // Exclusive create: the quarantine rename just removed the
        // pathname, so a file found there belongs to another writer.
        log = os.fd.createOpenExcl(io, opts.path) catch return error.PathReappeared;
        log_open = true;
        w.log = log;
        w.need_exclusive_create = false;
        w.seq = 0;
        w.prev = ZERO_PREV.*;
        var inner: Buf = undefined;
        inner.reset();
        inner.append("\"event\":\"chain.break\",\"reason\":\"tail_verify_failed\",\"lost_file\":");
        inner.jsonStrCap(w.break_name[0..w.break_name_len], 128);
        w.enqueueInner(inner.slice());
    }
    // The generation tags rotation names so a chain restarted after a
    // quarantine never collides with an old chain's rotated files.
    w.chain_gen = @intCast(@max(w.nowMs(), 0));
    // The start record is the first line of a fresh file and the first
    // record after a recovery alike.
    if (!opts.skip_start_record) {
        var inner: Buf = undefined;
        inner.reset();
        inner.append("\"event\":\"start\",\"chain\":");
        inner.append(if (opts.key != null) "true" else "false");
        inner.append(",\"version\":");
        inner.jsonStrCap(VERSION, 32);
        inner.append(",\"mode\":");
        inner.jsonStrCap(opts.mode, 16);
        inner.append(",\"config\":\"");
        inner.append(&opts.config_fingerprint);
        inner.append("\"");
        w.enqueueInner(inner.slice());
    }
    if (opts.spawn_thread) {
        w.thread = try std.Thread.spawn(.{}, threadMain, .{w});
    }
    return w;
}

/// Record the stop event, drain, fsync and close. Producers must be gone.
pub fn stop(w: *Writer) void {
    var inner: Buf = undefined;
    inner.reset();
    inner.append("\"event\":\"stop\",\"reason\":\"shutdown\"");
    w.enqueueInner(inner.slice());
    w.mutex.lockUncancelable(w.io);
    w.stopping = true;
    w.mutex.unlock(w.io);
    w.not_empty.signal(w.io);
    w.not_full.broadcast(w.io);
    if (w.thread) |t| t.join();
    // Close only what the writer still owns: a retired handle's number may
    // have been recycled into an unrelated live resource.
    closeLiveHandle(w);
    w.gpa.destroy(w);
}

// ---------------------------------------------------------------------------
// Startup tail recovery
// ---------------------------------------------------------------------------

const Recovery = struct { seq: u64, prev: [MAC_HEX_LEN]u8 };

fn recoverTail(gpa: Allocator, io: Io, w: *Writer, l: *os.fd.AppendLog) !void {
    const size = try os.fd.fileLength(io, l.fd);
    if (size == 0) return; // fresh file: seq 0, zero prev
    const window: usize = @intCast(@min(size, TAIL_WINDOW));
    const buf = try gpa.alloc(u8, window);
    defer gpa.free(buf);
    const got = try os.fd.preadAt(io, l.fd, buf, size - window);
    const data = buf[0..got];

    // A torn final line (killed mid-write) is cut back to the last newline.
    // The cut is a precondition for appending: when it fails the tail is
    // unusable (the caller quarantines the file), not merely unread.
    var end = got;
    if (got > 0 and data[got - 1] != '\n') {
        const last_nl = std.mem.lastIndexOfScalar(u8, data, '\n') orelse {
            if (size > window) return error.CorruptTail; // no boundary in window
            os.fd.truncFile(l.fd, 0) catch return error.UnusableTail;
            l.pos = 0;
            return; // single partial line in a fresh file: truncate, start over
        };
        const keep: u64 = size - got + last_nl + 1;
        os.fd.truncFile(l.fd, keep) catch return error.UnusableTail;
        l.pos = keep;
        end = last_nl + 1;
    }
    if (end == 0) return;

    const tail = data[0..end];
    // First line of the window may be partial when the file is longer than
    // the window; skip to after the first newline then.
    var lines = tail;
    if (size > window) {
        const first_nl = std.mem.indexOfScalar(u8, tail, '\n') orelse return error.CorruptTail;
        lines = tail[first_nl + 1 ..];
        if (lines.len == 0) return error.CorruptTail;
    }

    var rec: ?Recovery = null;
    var it = std.mem.splitScalar(u8, lines, '\n');
    while (it.next()) |line| {
        if (line.len == 0) continue;
        const meta = parseLineMeta(line) orelse return error.CorruptTail;
        // seq+1 below must not wrap: a maxInt seq is a broken tail.
        if (meta.seq == std.math.maxInt(u64)) return error.CorruptTail;
        if (w.key) |k| {
            const mac = meta.mac orelse return error.CorruptTail;
            const prev = meta.prev orelse return error.CorruptTail;
            if (rec) |r| {
                if (meta.seq != r.seq) return error.CorruptTail;
                if (!std.mem.eql(u8, prev, &r.prev)) return error.CorruptTail;
            }
            if (!verifyLineMac(line, mac, k)) return error.CorruptTail;
            rec = .{ .seq = meta.seq + 1, .prev = undefined };
            @memcpy(&rec.?.prev, mac);
        } else {
            // Keyless now but the tail is mac'd: the key was removed between
            // runs. Mixing chained and unchained lines in one file would
            // fail every later verify, so refuse the tail and start a fresh
            // chain (the caller renames the old file aside with chain.break).
            if (meta.mac != null) return error.CorruptTail;
            if (rec) |r| {
                if (meta.seq != r.seq) return error.CorruptTail;
            }
            rec = .{ .seq = meta.seq + 1, .prev = ZERO_PREV.* };
        }
    }
    const r = rec orelse return error.CorruptTail;
    w.seq = r.seq;
    w.prev = r.prev;

    // Head read: rotation names the old file with its first seq. One line
    // is at most MAX_RECORD, so a 4 KiB peek always holds it.
    var head_buf: [4096]u8 = undefined;
    const head_got = try os.fd.preadAt(io, l.fd, &head_buf, 0);
    if (head_got > 0) {
        const first = head_buf[0..head_got];
        const nl = std.mem.indexOfScalar(u8, first, '\n') orelse first.len;
        if (parseLineMeta(first[0..nl])) |m| w.file_first_seq = m.seq;
    }
}

// ---------------------------------------------------------------------------
// Line parsing + verification (shared by recovery and audit-verify)
// ---------------------------------------------------------------------------

const LineMeta = struct {
    seq: u64,
    event: []const u8,
    /// 64 hex chars when the line is MAC-chained.
    prev: ?[]const u8,
    mac: ?[]const u8,
};

/// Strict structural parse of a canonical line. The fixed field order makes
/// the anchors unambiguous: string values are escaped on write, so a raw
/// `,"event":"` / `,"prev":"` / `,"mac":"` byte run can only be the field.
fn parseLineMeta(line: []const u8) ?LineMeta {
    const prefix = "{\"v\":1,\"seq\":";
    if (!std.mem.startsWith(u8, line, prefix)) return null;
    const digits_start = prefix.len;
    var digits_end = digits_start;
    while (digits_end < line.len and line[digits_end] >= '0' and line[digits_end] <= '9')
        digits_end += 1;
    if (digits_end == digits_start or digits_end - digits_start > 20) return null;
    const seq = std.fmt.parseInt(u64, line[digits_start..digits_end], 10) catch return null;

    const ev_at = std.mem.indexOfPos(u8, line, digits_end, ",\"event\":\"") orelse return null;
    const ev_start = ev_at + ",\"event\":\"".len;
    const ev_end = std.mem.indexOfScalarPos(u8, line, ev_start, '"') orelse return null;
    const event = line[ev_start..ev_end];
    if (event.len == 0) return null;

    // MAC-chained line: ...,"prev":"<64>","mac":"<64>"}\n (line is \n-free).
    // The anchor `,"mac":"` is 8 bytes; the mac hex ends 2 before the line end.
    if (line.len >= 74 + 10 and line[line.len - 1] == '}') {
        const mac_start = line.len - 2 - 64;
        if (mac_start >= 8 and std.mem.eql(u8, line[mac_start - 8 .. mac_start], ",\"mac\":\"")) {
            const mac = line[mac_start .. mac_start + 64];
            if (!isHex(mac)) return null;
            // `,"prev":"` is 9 bytes; its hex ends exactly one quote before the
            // mac anchor: strict structure, no slack.
            const prev_anchor = std.mem.lastIndexOf(u8, line[0 .. mac_start - 8], ",\"prev\":\"") orelse return null;
            const prev_start = prev_anchor + ",\"prev\":\"".len;
            if (prev_start + 64 != mac_start - 9) return null;
            const prev = line[prev_start .. prev_start + 64];
            if (!isHex(prev)) return null;
            return .{ .seq = seq, .event = event, .prev = prev, .mac = mac };
        }
    }
    if (!std.mem.endsWith(u8, line, "}")) return null;
    return .{ .seq = seq, .event = event, .prev = null, .mac = null };
}

fn isHex(s: []const u8) bool {
    for (s) |c| {
        if (!std.ascii.isHex(c)) return false;
    }
    return s.len > 0;
}

/// Recompute the HMAC over the exact line bytes minus the trailing
/// `,"mac":"..."}` and compare in constant time. No JSON re-serialization
/// anywhere.
fn verifyLineMac(line: []const u8, mac_hex: []const u8, key: []const u8) bool {
    if (line.len < 74) return false;
    const covered = line[0 .. line.len - 74];
    var mac: [32]u8 = undefined;
    HmacSha256.create(&mac, covered, key);
    var given: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&given, mac_hex) catch return false;
    return std.crypto.timing_safe.eql([32]u8, mac, given);
}

// ---------------------------------------------------------------------------
// audit-verify
// ---------------------------------------------------------------------------

pub const Verdict = union(enum) {
    ok: struct {
        records: u64,
        last_seq: u64,
        last_mac: ?[MAC_HEX_LEN]u8,
        /// File boundaries where the chain continued (prev == last mac).
        chained_files: u32,
    },
    broken: struct {
        file_index: usize,
        seq: ?u64,
        reason: Reason,
    },
};

pub const Reason = enum {
    bad_structure,
    seq_gap,
    prev_mismatch,
    /// The first supplied chained file has a nonzero prev: the caller handed
    /// over a rotated suffix (earlier files omitted, hidden or deleted), so
    /// the verified history is provably incomplete.
    missing_predecessor,
    mac_mismatch,
    mixed_chain_mode,
    key_required,
    chain_required,
    oversize_record,
};

/// Verify files in the given order: seq continuity, prev links across file
/// boundaries (a rotated file's first prev must be the previous file's last
/// mac), and every MAC over the exact line bytes. The first supplied chained
/// file must open a fresh chain (prev == zeros) — a nonzero first prev means
/// the history was truncated upstream and the verdict fails closed. Mid-list
/// a fresh chain is legitimate only at an explicit chain.break boundary
/// (quarantine); any other zero-prev splice is rejected.
pub fn verifyFiles(gpa: Allocator, io: Io, files: []const []const u8, key: ?[]const u8) !Verdict {
    var total: u64 = 0;
    var expect_seq: ?u64 = null;
    var last_mac: ?[MAC_HEX_LEN]u8 = null;
    var chained_files: u32 = 0;
    var last_seq: u64 = 0;

    for (files, 0..) |path, file_index| {
        var file = try std.Io.Dir.cwd().openFile(io, path, .{});
        defer file.close(io);
        var rbuf: [64 * 1024]u8 = undefined;
        var line_buf = try gpa.alloc(u8, MAX_RECORD + 2);
        defer gpa.free(line_buf);
        var line_len: usize = 0;
        var file_mode: ?bool = null; // true = mac'd
        var first_in_file = true;

        while (true) {
            const n = file.readStreaming(io, &.{rbuf[0..]}) catch |err| switch (err) {
                error.EndOfStream => break,
                else => |e| return e,
            };
            if (n == 0) break; // defensive: a zero progress read must not spin
            for (rbuf[0..n]) |c| {
                if (c != '\n') {
                    if (line_len >= MAX_RECORD + 1)
                        return .{ .broken = .{ .file_index = file_index, .seq = expect_seq, .reason = .oversize_record } };
                    line_buf[line_len] = c;
                    line_len += 1;
                    continue;
                }
                const line = line_buf[0..line_len];
                line_len = 0;
                if (line.len == 0) continue;
                const meta = parseLineMeta(line) orelse
                    return .{ .broken = .{ .file_index = file_index, .seq = expect_seq, .reason = .bad_structure } };
                const macd = meta.mac != null;
                if (file_mode == null) file_mode = macd;
                if (file_mode.? != macd)
                    return .{ .broken = .{ .file_index = file_index, .seq = meta.seq, .reason = .mixed_chain_mode } };
                if (macd and key == null)
                    return .{ .broken = .{ .file_index = file_index, .seq = meta.seq, .reason = .key_required } };
                // Fail closed in the other direction too: with a key, a
                // keyless file is a downgrade (an attacker without the key
                // could strip prev/mac tails and pass), not a valid chain.
                if (!macd and key != null)
                    return .{ .broken = .{ .file_index = file_index, .seq = meta.seq, .reason = .chain_required } };

                const at_boundary = first_in_file;
                if (first_in_file) {
                    first_in_file = false;
                    if (macd) {
                        const prev = meta.prev.?;
                        if (last_mac) |lm| {
                            if (std.mem.eql(u8, prev, &lm)) {
                                chained_files += 1;
                                // expect_seq already holds last_seq + 1.
                            } else if (std.mem.eql(u8, prev, ZERO_PREV) and
                                std.mem.eql(u8, meta.event, "chain.break") and
                                meta.seq == 0)
                            {
                                // A fresh chain mid-list is legitimate only
                                // at an explicit quarantine boundary; any
                                // other zero-prev record is a spliced-in
                                // independent chain. A fresh chain always
                                // starts at seq 0, so a nonzero seq here is
                                // a splice wearing a chain.break costume.
                                expect_seq = meta.seq;
                            } else {
                                return .{ .broken = .{ .file_index = file_index, .seq = meta.seq, .reason = .prev_mismatch } };
                            }
                        } else {
                            // The first supplied chained file must open a
                            // fresh chain: a nonzero prev without a supplied
                            // predecessor means earlier history was omitted.
                            // A fresh chain always starts at seq 0, so a
                            // zero-prev record with a nonzero seq means the
                            // genesis records were omitted from the input.
                            if (!std.mem.eql(u8, prev, ZERO_PREV) or meta.seq != 0)
                                return .{ .broken = .{ .file_index = file_index, .seq = meta.seq, .reason = .missing_predecessor } };
                            expect_seq = meta.seq;
                        }
                    } else {
                        // Keyless mode has no MACs; seq continuity across
                        // files is its only tamper signal, so only the very
                        // first file anchors the expectation — later files
                        // must continue it (a gap is reported as seq_gap).
                        if (expect_seq == null) expect_seq = meta.seq;
                    }
                }
                if (expect_seq) |e| {
                    if (meta.seq != e)
                        return .{ .broken = .{ .file_index = file_index, .seq = e, .reason = .seq_gap } };
                } else {
                    expect_seq = meta.seq;
                }
                if (meta.seq == std.math.maxInt(u64))
                    return .{ .broken = .{ .file_index = file_index, .seq = meta.seq, .reason = .seq_gap } };
                if (macd) {
                    // Past the file boundary the only legal prev is the
                    // previous line's mac; zeros mid-file break the chain.
                    if (!at_boundary) {
                        if (last_mac) |lm| {
                            if (!std.mem.eql(u8, meta.prev.?, &lm))
                                return .{ .broken = .{ .file_index = file_index, .seq = meta.seq, .reason = .prev_mismatch } };
                        }
                    }
                    if (!verifyLineMac(line, meta.mac.?, key.?))
                        return .{ .broken = .{ .file_index = file_index, .seq = meta.seq, .reason = .mac_mismatch } };
                    var lm: [64]u8 = undefined;
                    @memcpy(&lm, meta.mac.?);
                    last_mac = lm;
                }
                expect_seq = meta.seq + 1;
                last_seq = meta.seq;
                total += 1;
            }
        }
        if (line_len != 0)
            return .{ .broken = .{ .file_index = file_index, .seq = expect_seq, .reason = .bad_structure } };
    }
    return .{ .ok = .{
        .records = total,
        .last_seq = last_seq,
        .last_mac = last_mac,
        .chained_files = chained_files,
    } };
}

/// The `audit-verify` subcommand. Reads the key from
/// MCP_NODE_AUDIT_KEY_FILE (same variable the daemon uses), verifies the
/// files, prints the outcome and the process exit code semantics: 0 clean,
/// 1 broken (first bad seq on stderr).
pub fn verifyCli(arena: Allocator, io: Io, anchor: bool, files: []const []const u8) !u8 {
    var key: ?[]const u8 = null;
    if (os.environGet(arena, @import("env_state.zig").process_environ, "MCP_NODE_AUDIT_KEY_FILE")) |kf| {
        if (kf.len > 0) {
            os.fd.checkPrivateFileMode(io, kf) catch {
                std.debug.print("audit-verify: {s} must not grant group/other access (0600)\n", .{kf});
                return 2;
            };
            const raw = os.fd.readFileAlloc(arena, io, kf, 64 * 1024) catch |err| {
                std.debug.print("audit-verify: cannot read key file: {s}\n", .{@errorName(err)});
                return 2;
            };
            const trimmed = std.mem.trim(u8, raw, " \t\r\n");
            if (trimmed.len == 0) {
                std.debug.print("audit-verify: key file is empty\n", .{});
                return 2;
            }
            key = trimmed;
        }
    }
    const verdict = try verifyFiles(arena, io, files, key);
    switch (verdict) {
        .ok => |ok| {
            var out: Buf = undefined;
            out.reset();
            out.print("audit-verify: OK ({d} records", .{ok.records});
            if (ok.chained_files > 0) out.print(", {d} chained files", .{ok.chained_files});
            out.append(")\n");
            os.writeAllFd(os.stdoutFd(), out.slice()) catch {};
            if (anchor) {
                out.reset();
                out.print("{d} ", .{ok.last_seq});
                if (ok.last_mac) |m| out.append(&m) else out.append("-");
                out.append("\n");
                os.writeAllFd(os.stdoutFd(), out.slice()) catch {};
            }
            return 0;
        },
        .broken => |b| {
            var out: Buf = undefined;
            out.reset();
            out.append("audit-verify: broken");
            if (b.seq) |s| out.print(" at seq {d}", .{s});
            out.print(": {s} (file {d})\n", .{ @tagName(b.reason), b.file_index });
            os.writeAllFd(os.stderrFd(), out.slice()) catch {};
            return 1;
        },
    }
}

// ---------------------------------------------------------------------------
// Event producers (null writer = audit off)
// ---------------------------------------------------------------------------

fn appendCallFields(buf: *Buf, w: *Writer, ctx: CallCtx, tool: []const u8, args: Value) void {
    buf.append("\"tool\":");
    buf.jsonStrCap(tool, 48);
    buf.append(",\"transport\":\"");
    buf.append(@tagName(ctx.transport));
    buf.append("\",\"client\":");
    buf.jsonStrCap(ctx.client, 96);
    if (ctx.session.len > 0) {
        buf.append(",\"session\":\"");
        buf.append(ctx.session);
        buf.append("\"");
    }
    buf.append(",\"req_id\":");
    buf.append(ctx.req_id);
    if (ctx.link_sid != 0) {
        buf.append(",\"link_sid\":");
        buf.print("{d}", .{ctx.link_sid});
    }
    buf.append(",\"args_digest\":\"");
    const digest = argsDigestHex(args);
    buf.append(&digest.hex);
    buf.append("\"");
    // A partial digest is never presented as a complete fingerprint.
    if (digest.partial) buf.append(",\"args_digest_partial\":true");
    buf.append(",\"args_summary\":");
    appendArgsSummary(buf, tool, args, w.args_mode);
}

/// A long tool call (exec, exec_shell, exec_start) leaves a trace even
/// when the process dies mid-call.
pub fn toolStart(w: ?*Writer, ctx: CallCtx, tool: []const u8, args: Value) void {
    const wr = w orelse return;
    var buf: Buf = undefined;
    buf.reset();
    buf.append("\"event\":\"tool.start\",");
    appendCallFields(&buf, wr, ctx, tool, args);
    if (!buf.overflow) wr.enqueueInner(buf.slice());
}

pub fn toolCall(
    w: ?*Writer,
    ctx: CallCtx,
    tool: []const u8,
    args: Value,
    ok: bool,
    exit_code: ?i32,
    error_name: ?[]const u8,
    duration_ms: u64,
    out_bytes: usize,
) void {
    const wr = w orelse return;
    var buf: Buf = undefined;
    buf.reset();
    buf.append("\"event\":\"tool.call\",");
    appendCallFields(&buf, wr, ctx, tool, args);
    buf.append(",\"ok\":");
    buf.append(if (ok) "true" else "false");
    if (exit_code) |ec| buf.print(",\"exit_code\":{d}", .{ec});
    if (error_name) |e| {
        buf.append(",\"error\":");
        buf.jsonStrCap(e, 64);
    }
    buf.append(",\"duration_ms\":");
    buf.print("{d}", .{duration_ms});
    buf.append(",\"out_bytes\":");
    buf.print("{d}", .{out_bytes});
    if (!buf.overflow) wr.enqueueInner(buf.slice());
}

/// A policy refusal. Same call fields as tool.call (client, session hash,
/// req_id, args digest + summary) plus the deny reason and the token
/// fingerprint — the operator sees what was attempted and why. Never the
/// token value.
pub fn policyDeny(
    w: ?*Writer,
    ctx: CallCtx,
    tool: []const u8,
    args: Value,
    reason: []const u8,
) void {
    const wr = w orelse return;
    var buf: Buf = undefined;
    buf.reset();
    buf.append("\"event\":\"policy.deny\",");
    appendCallFields(&buf, wr, ctx, tool, args);
    buf.append(",\"reason\":");
    buf.jsonStrCap(reason, 64);
    buf.append(",\"token\":\"");
    buf.append(&ctx.token_fp);
    buf.append("\"");
    if (!buf.overflow) wr.enqueueInner(buf.slice());
}

pub fn linkUp(w: ?*Writer, name: []const u8, source: []const u8) void {
    const wr = w orelse return;
    var buf: Buf = undefined;
    buf.reset();
    buf.append("\"event\":\"link.up\",\"name\":");
    buf.jsonStrCap(name, 64);
    buf.append(",\"source\":");
    buf.jsonStrCap(source, 96);
    if (!buf.overflow) wr.enqueueInner(buf.slice());
}

pub fn linkFail(w: ?*Writer, source: []const u8, error_name: []const u8) void {
    const wr = w orelse return;
    var buf: Buf = undefined;
    buf.reset();
    buf.append("\"event\":\"link.fail\",\"source\":");
    buf.jsonStrCap(source, 96);
    buf.append(",\"error\":");
    buf.jsonStrCap(error_name, 64);
    if (!buf.overflow) wr.enqueueInner(buf.slice());
}

pub fn linkBan(w: ?*Writer, source_key: [16]u8, seconds: u32) void {
    const wr = w orelse return;
    var buf: Buf = undefined;
    buf.reset();
    buf.append("\"event\":\"link.ban\",\"source\":\"");
    const alphabet = "0123456789abcdef";
    for (source_key) |b| {
        buf.append(alphabet[b >> 4 ..][0..1]);
        buf.append(alphabet[b & 0x0f ..][0..1]);
    }
    buf.append("\",\"seconds\":");
    buf.print("{d}", .{seconds});
    if (!buf.overflow) wr.enqueueInner(buf.slice());
}

pub fn linkDown(w: ?*Writer, name: []const u8, reason: []const u8) void {
    const wr = w orelse return;
    var buf: Buf = undefined;
    buf.reset();
    buf.append("\"event\":\"link.down\",\"name\":");
    buf.jsonStrCap(name, 64);
    buf.append(",\"reason\":");
    buf.jsonStrCap(reason, 64);
    if (!buf.overflow) wr.enqueueInner(buf.slice());
}

pub fn relay(
    w: ?*Writer,
    client: []const u8,
    node: []const u8,
    method: ?[]const u8,
    tool: ?[]const u8,
    req_id: []const u8,
    link_sid: u32,
    ok: bool,
    error_name: ?[]const u8,
    duration_ms: u64,
    bytes_in: usize,
    bytes_out: usize,
) void {
    const wr = w orelse return;
    var buf: Buf = undefined;
    buf.reset();
    buf.append("\"event\":\"relay\",\"client\":");
    buf.jsonStrCap(client, 96);
    buf.append(",\"node\":");
    buf.jsonStrCap(node, 64);
    if (method) |m| {
        buf.append(",\"method\":");
        buf.jsonStrCap(m, 48);
    }
    if (tool) |t| {
        buf.append(",\"tool\":");
        buf.jsonStrCap(t, 48);
    }
    buf.append(",\"req_id\":");
    buf.append(req_id);
    if (link_sid != 0) buf.print(",\"link_sid\":{d}", .{link_sid});
    buf.append(",\"ok\":");
    buf.append(if (ok) "true" else "false");
    if (error_name) |e| {
        buf.append(",\"error\":");
        buf.jsonStrCap(e, 64);
    }
    buf.append(",\"duration_ms\":");
    buf.print("{d}", .{duration_ms});
    buf.append(",\"bytes_in\":");
    buf.print("{d}", .{bytes_in});
    buf.append(",\"bytes_out\":");
    buf.print("{d}", .{bytes_out});
    if (!buf.overflow) wr.enqueueInner(buf.slice());
}

/// Peek at a client request body for the relay record. Best effort: a body
/// the node would reject as non-JSON still gets relayed (and refused)
/// there, so parse failure just omits the fields.
pub const RelayPeek = struct {
    method: ?[]const u8 = null,
    tool: ?[]const u8 = null,
    req_id_rendered: []const u8 = "null",
};

pub fn relayPeek(arena: Allocator, body: []const u8) RelayPeek {
    var peek: RelayPeek = .{};
    const req = std.json.parseFromSliceLeaky(Value, arena, body, .{}) catch return peek;
    if (req != .object) return peek;
    if (req.object.get("method")) |m| {
        if (m == .string) peek.method = m.string;
    }
    if (req.object.get("id")) |id_v| {
        switch (id_v) {
            .string, .integer, .number_string, .null => {
                var buf: Buf = undefined;
                buf.reset();
                renderReqId(&buf, id_v);
                if (!buf.overflow) {
                    const owned = arena.dupe(u8, buf.slice()) catch return peek;
                    peek.req_id_rendered = owned;
                }
            },
            else => {},
        }
    }
    if (peek.method) |m| {
        if (std.mem.eql(u8, m, "tools/call")) {
            if (req.object.get("params")) |p| {
                if (p == .object) {
                    if (p.object.get("name")) |n| {
                        if (n == .string) peek.tool = n.string;
                    }
                }
            }
        }
    }
    return peek;
}

/// sha256 of the effective config with secrets replaced by their file
/// paths (hex). A changed allowlist, mode or limit shows up in the start
/// record of the next run.
pub fn configFingerprint(cfg: *const config.Config) [MAC_HEX_LEN]u8 {
    var h = Sha256.init(.{});
    var nb: [24]u8 = undefined;
    h.update("copy_max_bytes\x00");
    h.update(std.fmt.bufPrint(&nb, "{d}", .{cfg.copy_max_bytes}) catch "");
    h.update("\x00copy_max_entries\x00");
    h.update(std.fmt.bufPrint(&nb, "{d}", .{cfg.copy_max_entries}) catch "");
    h.update(if (cfg.state_dir != null) "durable:1" else "durable:0");
    h.update("\x00");
    h.update(std.fmt.bufPrint(&nb, "{d}", .{cfg.state_max_bytes}) catch "");
    h.update("\x00");
    h.update(cfg.name);
    h.update("\x00");
    h.update(@tagName(cfg.mode));
    h.update("\x00");
    h.update(cfg.host);
    h.update("\x00");
    h.update(std.fmt.bufPrint(&nb, "{d}", .{cfg.port}) catch "");
    h.update("\x00");
    h.update(std.fmt.bufPrint(&nb, "{d}", .{cfg.max_out}) catch "");
    h.update("\x00");
    h.update(std.fmt.bufPrint(&nb, "{d}", .{cfg.socket_timeout_s}) catch "");
    h.update("\x00");
    h.update(std.fmt.bufPrint(&nb, "{d}", .{cfg.max_conn}) catch "");
    h.update("\x00");
    h.update(std.fmt.bufPrint(&nb, "{d}", .{cfg.max_sessions}) catch "");
    h.update("\x00");
    h.update(std.fmt.bufPrint(&nb, "{d}", .{cfg.session_ttl_s}) catch "");
    h.update("\x00");
    h.update(std.fmt.bufPrint(&nb, "{d}", .{cfg.max_inflight_bytes}) catch "");
    h.update("\x00");
    h.update(if (cfg.text_mirror) "1" else "0");
    h.update("\x00");
    for (cfg.allowed_hosts) |ho| {
        h.update(ho);
        h.update("\x00");
        h.update(",");
        h.update("\x00");
    }
    for (cfg.allowed_origins) |o| {
        h.update(o);
        h.update("\x00");
        h.update(",");
        h.update("\x00");
    }
    h.update(cfg.token_file);
    h.update("\x00");
    // Secret material never enters the fingerprint; the file PATHS do, so a
    // rotated link secret or token file shows up in the next start record.
    h.update(cfg.connect_secret_file);
    h.update("\x00");
    h.update(cfg.hub_secret_file);
    h.update("\x00");
    if (cfg.connect) |ep| {
        h.update(ep.host);
        h.update("\x00");
        h.update(std.fmt.bufPrint(&nb, "{d}", .{ep.port}) catch "");
        h.update("\x00");
    }
    if (cfg.hub_listen) |ep| {
        h.update(ep.host);
        h.update("\x00");
        h.update(std.fmt.bufPrint(&nb, "{d}", .{ep.port}) catch "");
        h.update("\x00");
    }
    if (cfg.hub_tls_cert_file) |f| h.update(f);
    h.update("\x00");
    if (cfg.audit_file) |f| h.update(f);
    h.update("\x00");
    h.update(@tagName(cfg.audit_args));
    h.update("\x00");
    h.update(@tagName(cfg.audit_on_full));
    h.update("\x00");
    h.update(std.fmt.bufPrint(&nb, "{d}", .{cfg.audit_max_bytes}) catch "");
    h.update("\x00");
    // Argument-gating: the policy file path plus a sha256 of its bytes, so
    // any policy edit shows up in the next start record. Token values stay
    // out (they live in separate files; their paths are in the policy).
    if (cfg.policy) |p| {
        const ps: *const @import("policy.zig").PolicySet = @ptrCast(@alignCast(p));
        h.update(ps.file_path);
        h.update("\x00");
        for (ps.file_digest) |b| h.update(&[1]u8{b});
    }
    h.update("\x00");
    const digest = h.finalResult();
    var out: [MAC_HEX_LEN]u8 = undefined;
    const alphabet = "0123456789abcdef";
    for (digest, 0..) |b, i| {
        out[i * 2] = alphabet[b >> 4];
        out[i * 2 + 1] = alphabet[b & 0x0f];
    }
    return out;
}

/// sha256 prefix (16 lowercase hex chars) of an Mcp-Session-Id header value
/// for the audit record's session field: correlatable within one log, never
/// the id itself.
pub fn sessionHashHex(id: ?[]const u8, out: *[16]u8) []const u8 {
    const v = id orelse return "";
    if (v.len == 0) return "";
    var digest: [32]u8 = undefined;
    Sha256.hash(v, &digest, .{});
    const alphabet = "0123456789abcdef";
    for (digest[0..8], 0..) |b, i| {
        out[i * 2] = alphabet[b >> 4];
        out[i * 2 + 1] = alphabet[b & 0x0f];
    }
    return out[0..16];
}

fn appendTs(buf: *Buf, ms_raw: i64) void {
    // A clock before the epoch (broken RTC, tampered clock) must not panic
    // the writer thread on the u64 cast: clamp to the epoch.
    const ms = @max(ms_raw, 0);
    const ms_part: u64 = @intCast(@mod(ms, 1000));
    const secs: u64 = @intCast(@divFloor(ms, 1000));
    const es: std.time.epoch.EpochSeconds = .{ .secs = secs };
    const ed = es.getEpochDay();
    const yd = ed.calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    buf.print("{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>3}Z", .{
        yd.year,
        md.month.numeric(),
        md.day_index + 1,
        ds.getHoursIntoDay(),
        ds.getMinutesIntoHour(),
        ds.getSecondsIntoMinute(),
        ms_part,
    });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn tmpPath(arena: Allocator, tmp: *const testing.TmpDir, name: []const u8) ![]const u8 {
    return std.fmt.allocPrint(arena, ".zig-cache/tmp/{s}/{s}", .{ tmp.sub_path, name });
}

fn testIo() Io {
    return Io.Threaded.global_single_threaded.io();
}

fn readAll(arena: Allocator, path: []const u8) ![]u8 {
    return os.fd.readFileAlloc(arena, testIo(), path, 16 * 1024 * 1024);
}

/// Split a file body into lines without the trailing \n.
fn linesOf(arena: Allocator, data: []const u8) ![][]const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var it = std.mem.splitScalar(u8, data, '\n');
    while (it.next()) |l| {
        if (l.len > 0) try out.append(arena, l);
    }
    return out.items;
}

test "audit canonical line bytes are fixed order and whitespace free" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmpPath(arena, &tmp, "a.log");

    const w = try start(arena, testIo(), .{
        .path = path,
        .key = "k",
        .host = "t",
        .role = "node",
        .mode = "listen",
        .spawn_thread = false,
        .skip_start_record = true,
        .now_ms_override = 1759742400123,
    });
    w.enqueueInner("\"event\":\"dropped\",\"count\":2");
    w.drainOnce();

    const data = try readAll(arena, path);
    const line = std.mem.trimEnd(u8, data, "\n");
    var ts_buf: Buf = undefined;
    ts_buf.reset();
    appendTs(&ts_buf, 1759742400123);
    const expected_prefix = try std.fmt.allocPrint(arena, "{{\"v\":1,\"seq\":0,\"ts\":\"{s}\",\"host\":\"t\",\"role\":\"node\",\"event\":\"dropped\",\"count\":2,\"prev\":\"{s}\",\"mac\":\"", .{ ts_buf.slice(), ZERO_PREV });
    try testing.expect(std.mem.startsWith(u8, line, expected_prefix));
    try testing.expect(std.mem.endsWith(u8, line, "\"}"));
    const mac_hex = line[expected_prefix.len .. line.len - 2];
    try testing.expectEqual(@as(usize, 64), mac_hex.len);
    // Independently recompute the MAC over the exact covered bytes.
    var mac: [32]u8 = undefined;
    HmacSha256.create(&mac, line[0 .. line.len - 74], "k");
    var expect: [64]u8 = undefined;
    const alphabet = "0123456789abcdef";
    for (mac, 0..) |b, i| {
        expect[i * 2] = alphabet[b >> 4];
        expect[i * 2 + 1] = alphabet[b & 0x0f];
    }
    try testing.expectEqualSlices(u8, &expect, mac_hex);
    // No optional whitespace anywhere outside the string values.
    try testing.expect(std.mem.indexOf(u8, line, ": ") == null);
    w.mutex.lockUncancelable(w.io);
    w.stopping = true;
    w.mutex.unlock(w.io);
    os.closeFd(w.log.?.fd);
    // w lives on the arena; no thread was spawned, so nothing else to stop.
}

/// Start a writer, enqueue `n` tool.call records, drain, read back lines.
fn writeToolCalls(arena: Allocator, path: []const u8, key: ?[]const u8, n: usize) ![][]const u8 {
    const w = try start(arena, testIo(), .{
        .path = path,
        .key = key,
        .host = "t",
        .role = "node",
        .spawn_thread = false,
        .skip_start_record = true,
        .now_ms_override = 1759742400123,
    });
    const ctx: CallCtx = .{ .transport = .http, .client = "127.0.0.1:5555", .req_id = "1" };
    for (0..n) |i| {
        const args_json = try std.fmt.allocPrint(arena, "{{\"argv\":[\"echo\",\"hi{d}\"]}}", .{i});
        const args = try std.json.parseFromSliceLeaky(Value, arena, args_json, .{});
        toolCall(w, ctx, "exec", args, true, 0, null, 3, 20);
    }
    w.drainOnce();
    const data = try readAll(arena, path);
    const lines = try linesOf(arena, data);
    w.mutex.lockUncancelable(w.io);
    w.stopping = true;
    w.mutex.unlock(w.io);
    os.closeFd(w.log.?.fd);
    return lines;
}

test "audit mac chain over three records verifies" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmpPath(arena, &tmp, "b.log");

    const lines = try writeToolCalls(arena, path, "chain-key", 3);
    try testing.expectEqual(@as(usize, 3), lines.len);
    // prev of line i+1 is the mac of line i.
    var prev_mac: []const u8 = ZERO_PREV;
    for (lines, 0..) |line, i| {
        const meta = parseLineMeta(line).?;
        try testing.expectEqual(@as(u64, i), meta.seq);
        try testing.expectEqualStrings("tool.call", meta.event);
        try testing.expectEqualStrings(prev_mac, meta.prev.?);
        try testing.expect(verifyLineMac(line, meta.mac.?, "chain-key"));
        prev_mac = meta.mac.?;
    }
    // ...and the whole file passes the verifier.
    const verdict = try verifyFiles(arena, testIo(), &.{path}, "chain-key");
    switch (verdict) {
        .ok => |ok| {
            try testing.expectEqual(@as(u64, 3), ok.records);
            try testing.expectEqual(@as(u64, 2), ok.last_seq);
        },
        .broken => return error.TestUnexpectedResult,
    }
}

/// Rewrite `path` with `f` applied to its lines.
fn rewriteLines(arena: Allocator, path: []const u8, comptime f: fn (Allocator, [][]const u8) [][]const u8) !void {
    const data = try readAll(arena, path);
    const lines = try linesOf(arena, data);
    const mutated = f(arena, lines);
    var out: std.ArrayList(u8) = .empty;
    for (mutated) |l| {
        try out.appendSlice(arena, l);
        try out.append(arena, '\n');
    }
    try os.fd.writeFile(testIo(), path, out.items, 0o600);
}

fn mutateEdit(arena: Allocator, lines: [][]const u8) [][]const u8 {
    // Flip one hex digit inside line 1's args_digest.
    const l = lines[1];
    const at = std.mem.indexOf(u8, l, "\"args_digest\":\"").? + 15;
    const owned = arena.dupe(u8, l) catch @panic("oom");
    var mut = @constCast(owned);
    mut[at] = if (l[at] == '0') '1' else '0';
    lines[1] = mut;
    return lines;
}

test "audit verifier detects edit" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmpPath(arena, &tmp, "c.log");
    _ = try writeToolCalls(arena, path, "k", 3);
    try rewriteLines(arena, path, mutateEdit);
    const verdict = try verifyFiles(arena, testIo(), &.{path}, "k");
    switch (verdict) {
        .ok => return error.TestUnexpectedResult,
        .broken => |b| {
            try testing.expectEqual(@as(?u64, 1), b.seq);
            try testing.expectEqual(Reason.mac_mismatch, b.reason);
        },
    }
}

fn mutateDelete(arena: Allocator, lines: [][]const u8) [][]const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    out.appendSlice(arena, lines[0..1]) catch @panic("oom");
    out.appendSlice(arena, lines[2..]) catch @panic("oom");
    return out.items;
}

test "audit verifier detects deletion" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmpPath(arena, &tmp, "d.log");
    _ = try writeToolCalls(arena, path, "k", 3);
    try rewriteLines(arena, path, mutateDelete);
    const verdict = try verifyFiles(arena, testIo(), &.{path}, "k");
    switch (verdict) {
        .ok => return error.TestUnexpectedResult,
        .broken => |b| {
            try testing.expectEqual(@as(?u64, 1), b.seq);
            try testing.expectEqual(Reason.seq_gap, b.reason);
        },
    }
}

fn mutateReorder(arena: Allocator, lines: [][]const u8) [][]const u8 {
    _ = arena;
    const t = lines[1];
    lines[1] = lines[2];
    lines[2] = t;
    return lines;
}

test "audit verifier detects reorder" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmpPath(arena, &tmp, "e.log");
    _ = try writeToolCalls(arena, path, "k", 3);
    try rewriteLines(arena, path, mutateReorder);
    const verdict = try verifyFiles(arena, testIo(), &.{path}, "k");
    switch (verdict) {
        .ok => return error.TestUnexpectedResult,
        .broken => |b| try testing.expect(b.reason == .seq_gap or b.reason == .prev_mismatch or b.reason == .mac_mismatch),
    }
}

test "audit tail recovery continues the chain after reopen" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmpPath(arena, &tmp, "f.log");
    const lines1 = try writeToolCalls(arena, path, "k", 3);
    const last_mac = parseLineMeta(lines1[2]).?.mac.?;

    // Reopen: what a fresh process does on the same file.
    const w2 = try start(arena, testIo(), .{
        .path = path,
        .key = "k",
        .spawn_thread = false,
        .skip_start_record = true,
        .now_ms_override = 1759742400999,
    });
    try testing.expectEqual(@as(u64, 3), w2.seq);
    try testing.expectEqualStrings(last_mac, &w2.prev);
    const ctx: CallCtx = .{ .transport = .stdio, .client = "stdio", .req_id = "9" };
    toolCall(w2, ctx, "sys_info", Value.null, true, null, null, 1, 10);
    w2.drainOnce();
    w2.mutex.lockUncancelable(w2.io);
    w2.stopping = true;
    w2.mutex.unlock(w2.io);
    os.closeFd(w2.log.?.fd);

    const verdict = try verifyFiles(arena, testIo(), &.{path}, "k");
    switch (verdict) {
        .ok => |ok| try testing.expectEqual(@as(u64, 4), ok.records),
        .broken => return error.TestUnexpectedResult,
    }
}

test "audit corrupt tail starts a new file with chain.break" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const path = try tmpPath(arena, &tmp, "g.log");
    _ = try writeToolCalls(arena, path, "k", 3);
    try rewriteLines(arena, path, mutateEdit);

    const w2 = try start(arena, testIo(), .{
        .path = path,
        .key = "k",
        .spawn_thread = false,
        .now_ms_override = 1759742401000,
    });
    // Fresh chain from seq 0: chain.break first, then the start record.
    w2.drainOnce();
    w2.mutex.lockUncancelable(w2.io);
    w2.stopping = true;
    w2.mutex.unlock(w2.io);
    os.closeFd(w2.log.?.fd);

    const data = try readAll(arena, path);
    const lines = try linesOf(arena, data);
    try testing.expectEqual(@as(usize, 2), lines.len);
    const m0 = parseLineMeta(lines[0]).?;
    try testing.expectEqual(@as(u64, 0), m0.seq);
    try testing.expectEqualStrings("chain.break", m0.event);
    try testing.expectEqualStrings(ZERO_PREV, m0.prev.?);
    const m1 = parseLineMeta(lines[1]).?;
    try testing.expectEqualStrings("start", m1.event);
    // The damaged file was moved aside, not deleted.
    var found_corrupt_aside = false;
    var it = tmp.dir.iterate();
    while (try it.next(testIo())) |ent| {
        if (std.mem.startsWith(u8, ent.name, "g.log.corrupt-")) found_corrupt_aside = true;
    }
    try testing.expect(found_corrupt_aside);
    const verdict = try verifyFiles(arena, testIo(), &.{path}, "k");
    switch (verdict) {
        .ok => {},
        .broken => return error.TestUnexpectedResult,
    }
}

test "audit ring block policy waits for space then drains" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmpPath(arena, &tmp, "h.log");
    const w = try start(arena, testIo(), .{
        .path = path,
        .key = "k",
        .spawn_thread = false,
        .skip_start_record = true,
        .ring_cap = 2,
        .now_ms_override = 1759742400123,
    });
    w.enqueueInner("\"event\":\"dropped\",\"count\":0");
    w.enqueueInner("\"event\":\"dropped\",\"count\":0");
    // The third producer must block until a drain frees a slot.
    var done = std.atomic.Value(bool).init(false);
    const P = struct {
        fn run(wr: *Writer, flag: *std.atomic.Value(bool)) void {
            wr.enqueueInner("\"event\":\"dropped\",\"count\":0");
            flag.store(true, .release);
        }
    };
    const t = try std.Thread.spawn(.{}, P.run, .{ w, &done });
    var spins: u32 = 0;
    while (spins < 100) : (spins += 1) {
        if (done.load(.acquire)) return error.TestUnexpectedResult; // must still block
        os.sleepMs(1);
    }
    w.drainOnce();
    t.join();
    try testing.expect(done.load(.acquire));
    w.drainOnce();
    const data = try readAll(arena, path);
    try testing.expectEqual(@as(usize, 3), (try linesOf(arena, data)).len);
    w.mutex.lockUncancelable(w.io);
    w.stopping = true;
    w.mutex.unlock(w.io);
    os.closeFd(w.log.?.fd);
    // w lives on the arena; no thread was spawned, so nothing else to stop.
}

test "audit ring drop policy counts drops and logs a dropped record" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmpPath(arena, &tmp, "i.log");
    const w = try start(arena, testIo(), .{
        .path = path,
        .key = "k",
        .spawn_thread = false,
        .skip_start_record = true,
        .ring_cap = 2,
        .on_full = .drop,
        .now_ms_override = 1759742400123,
    });
    for (0..4) |_| w.enqueueInner("\"event\":\"dropped\",\"count\":0");
    w.drainOnce();
    const data = try readAll(arena, path);
    const lines = try linesOf(arena, data);
    // 2 user records + 1 dropped record carrying the count of the 2 losses.
    try testing.expectEqual(@as(usize, 3), lines.len);
    const meta = parseLineMeta(lines[2]).?;
    try testing.expectEqualStrings("dropped", meta.event);
    try testing.expect(std.mem.indexOf(u8, lines[2], "\"count\":2") != null);
    const verdict = try verifyFiles(arena, testIo(), &.{path}, "k");
    switch (verdict) {
        .ok => {},
        .broken => return error.TestUnexpectedResult,
    }
    w.mutex.lockUncancelable(w.io);
    w.stopping = true;
    w.mutex.unlock(w.io);
    os.closeFd(w.log.?.fd);
    // w lives on the arena; no thread was spawned, so nothing else to stop.
}

test "audit args summary never contains script or content" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmpPath(arena, &tmp, "j.log");
    const w = try start(arena, testIo(), .{
        .path = path,
        .key = "k",
        .spawn_thread = false,
        .skip_start_record = true,
        .args_mode = .full, // even full mode never logs script or content
    });
    const ctx: CallCtx = .{ .transport = .http, .client = "c", .req_id = "1" };
    const shell_args = try std.json.parseFromSliceLeaky(Value, arena, "{\"shell\":\"sh\",\"script\":\"echo SECRET_SCRIPT_TEXT\"}", .{});
    toolCall(w, ctx, "exec_shell", shell_args, true, 0, null, 1, 1);
    const write_args = try std.json.parseFromSliceLeaky(Value, arena, "{\"path\":\"/tmp/x\",\"content_b64\":\"U0VDUkVUX0ZJTEVfQ09OVEVOVA==\"}", .{});
    toolCall(w, ctx, "write_file", write_args, true, null, null, 1, 1);
    const exec_args = try std.json.parseFromSliceLeaky(Value, arena, "{\"argv\":[\"sh\",\"-c\",\"echo SECRET_ARGV_TAIL\"]}", .{});
    toolCall(w, ctx, "exec", exec_args, true, 0, null, 1, 1);
    w.drainOnce();
    const data = try readAll(arena, path);
    try testing.expect(std.mem.indexOf(u8, data, "SECRET_SCRIPT_TEXT") == null);
    try testing.expect(std.mem.indexOf(u8, data, "SECRET_FILE_CONTENT") == null);
    try testing.expect(std.mem.indexOf(u8, data, "U0VDUkVUX0ZJTEVfQ09OVEVOVA==") == null);
    // Full mode logs argv whole; summary mode logs argv0 only (next test).
    try testing.expect(std.mem.indexOf(u8, data, "SECRET_ARGV_TAIL") != null);
    // "echo SECRET_SCRIPT_TEXT" is 23 bytes; the b64 payload decodes to 19.
    try testing.expect(std.mem.indexOf(u8, data, "\"script_len\":23") != null);
    try testing.expect(std.mem.indexOf(u8, data, "\"size\":19") != null);
    w.mutex.lockUncancelable(w.io);
    w.stopping = true;
    w.mutex.unlock(w.io);
    os.closeFd(w.log.?.fd);
    // w lives on the arena; no thread was spawned, so nothing else to stop.
}

test "audit summary mode logs argv0 and argc only" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmpPath(arena, &tmp, "j2.log");
    const w = try start(arena, testIo(), .{
        .path = path,
        .key = "k",
        .spawn_thread = false,
        .skip_start_record = true,
    });
    const ctx: CallCtx = .{ .transport = .http, .client = "c", .req_id = "1" };
    const exec_args = try std.json.parseFromSliceLeaky(Value, arena, "{\"argv\":[\"echo\",\"TAIL_SECRET\"]}", .{});
    toolCall(w, ctx, "exec", exec_args, true, 0, null, 1, 1);
    w.drainOnce();
    const data = try readAll(arena, path);
    try testing.expect(std.mem.indexOf(u8, data, "\"argv0\":\"echo\"") != null);
    try testing.expect(std.mem.indexOf(u8, data, "\"argc\":2") != null);
    try testing.expect(std.mem.indexOf(u8, data, "TAIL_SECRET") == null);
    w.mutex.lockUncancelable(w.io);
    w.stopping = true;
    w.mutex.unlock(w.io);
    os.closeFd(w.log.?.fd);
    // w lives on the arena; no thread was spawned, so nothing else to stop.
}

test "audit keyless mode writes chain:false without mac and verifies seq only" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmpPath(arena, &tmp, "k.log");
    const w = try start(arena, testIo(), .{
        .path = path,
        .key = null,
        .spawn_thread = false,
        .now_ms_override = 1759742400123,
    });
    const ctx: CallCtx = .{ .transport = .stdio, .client = "stdio", .req_id = "2" };
    toolCall(w, ctx, "sys_info", Value.null, true, null, null, 1, 5);
    w.drainOnce();
    w.mutex.lockUncancelable(w.io);
    w.stopping = true;
    w.mutex.unlock(w.io);
    os.closeFd(w.log.?.fd);

    const data = try readAll(arena, path);
    try testing.expect(std.mem.indexOf(u8, data, "\"chain\":false") != null);
    try testing.expect(std.mem.indexOf(u8, data, "\"mac\"") == null);
    try testing.expect(std.mem.indexOf(u8, data, "\"prev\"") == null);
    const verdict = try verifyFiles(arena, testIo(), &.{path}, null);
    switch (verdict) {
        .ok => |ok| try testing.expect(ok.last_mac == null),
        .broken => return error.TestUnexpectedResult,
    }
    // Reopen keyless: seq continues from the tail.
    const w2 = try start(arena, testIo(), .{ .path = path, .key = null, .spawn_thread = false, .skip_start_record = true });
    try testing.expectEqual(@as(u64, 2), w2.seq);
    w2.mutex.lockUncancelable(w2.io);
    w2.stopping = true;
    w2.mutex.unlock(w2.io);
    os.closeFd(w2.log.?.fd);
}

test "audit verify of a chained file without the key fails closed" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmpPath(arena, &tmp, "l.log");
    _ = try writeToolCalls(arena, path, "k", 2);
    const verdict = try verifyFiles(arena, testIo(), &.{path}, null);
    switch (verdict) {
        .ok => return error.TestUnexpectedResult,
        .broken => |b| try testing.expectEqual(Reason.key_required, b.reason),
    }
}

test "audit start and stop records frame a run" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmpPath(arena, &tmp, "m.log");
    const w = try start(arena, testIo(), .{
        .path = path,
        .key = "k",
        .spawn_thread = false,
        .mode = "hub",
        .now_ms_override = 1759742400123,
    });
    w.enqueueInner("\"event\":\"stop\",\"reason\":\"shutdown\"");
    w.drainOnce();
    const data = try readAll(arena, path);
    const lines = try linesOf(arena, data);
    try testing.expectEqual(@as(usize, 2), lines.len);
    const m0 = parseLineMeta(lines[0]).?;
    try testing.expectEqualStrings("start", m0.event);
    try testing.expect(std.mem.indexOf(u8, lines[0], "\"chain\":true") != null);
    try testing.expect(std.mem.indexOf(u8, lines[0], "\"mode\":\"hub\"") != null);
    try testing.expect(std.mem.indexOf(u8, lines[0], "\"config\":\"") != null);
    try testing.expectEqualStrings("stop", parseLineMeta(lines[1]).?.event);
    w.mutex.lockUncancelable(w.io);
    w.stopping = true;
    w.mutex.unlock(w.io);
    os.closeFd(w.log.?.fd);
    // w lives on the arena; no thread was spawned, so nothing else to stop.
}

test "audit req_id truncation keeps valid json" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const long_id = "req-" ++ ("x" ** 200);
    const id_json = try std.fmt.allocPrint(arena, "\"{s}\"", .{long_id});
    const id = try std.json.parseFromSliceLeaky(Value, arena, id_json, .{});
    var buf: Buf = undefined;
    buf.reset();
    renderReqId(&buf, id);
    try testing.expect(!buf.overflow);
    try testing.expect(buf.slice().len <= REQ_ID_MAX);
    // Still a valid JSON string literal.
    const parsed = try std.json.parseFromSliceLeaky(Value, arena, buf.slice(), .{});
    try testing.expect(parsed == .string);
}

test "audit relay and link event shapes stay inside the record budget" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmpPath(arena, &tmp, "n.log");
    const w = try start(arena, testIo(), .{
        .path = path,
        .key = "k",
        .spawn_thread = false,
        .skip_start_record = true,
        .now_ms_override = 1759742400123,
    });
    relay(w, "192.0.2.1:9999", "node-a", "tools/call", "exec", "\"r1\"", 7, true, null, 12, 340, 512);
    linkUp(w, "node-a", "192.0.2.9:4444");
    linkFail(w, "192.0.2.9:4444", "AuthFailed");
    linkBan(w, [_]u8{0} ** 10 ++ [_]u8{ 0xff, 0xff, 192, 0, 2, 9 }, 60);
    linkDown(w, "node-a", "closed");
    w.drainOnce();
    const data = try readAll(arena, path);
    const lines = try linesOf(arena, data);
    try testing.expectEqual(@as(usize, 5), lines.len);
    const expect_events = [_][]const u8{ "relay", "link.up", "link.fail", "link.ban", "link.down" };
    for (lines, expect_events) |line, ev| {
        try testing.expect(line.len <= MAX_RECORD);
        try testing.expectEqualStrings(ev, parseLineMeta(line).?.event);
    }
    try testing.expect(std.mem.indexOf(u8, lines[0], "\"link_sid\":7") != null);
    try testing.expect(std.mem.indexOf(u8, lines[0], "\"bytes_out\":512") != null);
    try testing.expect(std.mem.indexOf(u8, lines[3], "\"seconds\":60") != null);
    const verdict = try verifyFiles(arena, testIo(), &.{path}, "k");
    switch (verdict) {
        .ok => {},
        .broken => return error.TestUnexpectedResult,
    }
    w.mutex.lockUncancelable(w.io);
    w.stopping = true;
    w.mutex.unlock(w.io);
    os.closeFd(w.log.?.fd);
    // w lives on the arena; no thread was spawned, so nothing else to stop.
}

test "audit rotation chains files by prev across the rename" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const path = try tmpPath(arena, &tmp, "rot.log");

    const w = try start(arena, testIo(), .{
        .path = path,
        .key = "k",
        .host = "t",
        .role = "node",
        .spawn_thread = false,
        .skip_start_record = true,
        .now_ms_override = 1759742400123,
        .max_bytes = 4096,
    });
    const ctx: CallCtx = .{ .transport = .http, .client = "127.0.0.1:5555", .req_id = "1" };
    const args = try std.json.parseFromSliceLeaky(Value, arena, "{\"argv\":[\"echo\",\"hi\"]}", .{});
    // ~450 bytes per record: 40 records cross the 4 KiB limit several times.
    for (0..40) |_| {
        toolCall(w, ctx, "exec", args, true, 0, null, 3, 20);
        w.drainOnce();
    }
    w.mutex.lockUncancelable(w.io);
    w.stopping = true;
    w.mutex.unlock(w.io);
    os.closeFd(w.log.?.fd);
    // w lives on the arena; no thread was spawned, so nothing else to stop.

    // Rotated siblings are named rot.log.<first-seq>; the live path is last.
    var names: std.ArrayList([]const u8) = .empty;
    var it = tmp.dir.iterate();
    while (try it.next(testIo())) |ent| {
        if (std.mem.startsWith(u8, ent.name, "rot.log"))
            try names.append(arena, try arena.dupe(u8, ent.name));
    }
    try testing.expect(names.items.len >= 2);
    std.mem.sort([]const u8, names.items, {}, struct {
        fn suffix(name: []const u8) u64 {
            const d = std.mem.lastIndexOfScalar(u8, name, '.') orelse return 0;
            return std.fmt.parseInt(u64, name[d + 1 ..], 10) catch std.math.maxInt(u64);
        }
        fn lessThan(_: void, a: []const u8, b: []const u8) bool {
            return suffix(a) < suffix(b);
        }
    }.lessThan);
    var files: std.ArrayList([]const u8) = .empty;
    for (names.items) |n| try files.append(arena, try tmpPath(arena, &tmp, n));

    const verdict = try verifyFiles(arena, testIo(), files.items, "k");
    const ok = switch (verdict) {
        .ok => |o| o,
        .broken => |b| {
            std.debug.print("rotation verify broken at seq {?d}: {s}\n", .{ b.seq, @tagName(b.reason) });
            return error.TestUnexpectedResult;
        },
    };
    try testing.expectEqual(names.items.len - 1, ok.chained_files);
    try testing.expect(ok.records > 41); // 40 calls + at least one rotate
}

test "audit renderReqId survives a backslash-heavy id" {
    // A crafted id whose escaped form is mostly backslashes once panicked the
    // truncation walk-back (usize underflow). Regression test for it.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var id_bytes: std.ArrayList(u8) = .empty;
    // JSON source: "ab" + 60 backslashes + "cd" -> id is ab + 30 real
    // backslashes + cd; the escaped rendering is ~66 bytes of nearly pure
    // backslash run, so truncation walks back to cut < 6.
    try id_bytes.appendSlice(arena, "\"ab");
    for (0..60) |_| try id_bytes.append(arena, '\\');
    try id_bytes.appendSlice(arena, "cd\"");
    const parsed = try std.json.parseFromSliceLeaky(Value, arena, id_bytes.items, .{});
    var buf: Buf = undefined;
    buf.reset();
    renderReqId(&buf, parsed);
    const out = buf.slice();
    // Valid JSON string literal, within the byte cap, escape-safe.
    try testing.expect(out.len <= REQ_ID_MAX + 1);
    try testing.expect(out[0] == '"' and out[out.len - 1] == '"');
    try testing.expect(std.mem.indexOfScalar(u8, out, '\n') == null);
    // A huge float-ish id degrades to null rather than a broken literal.
    var buf2: Buf = undefined;
    buf2.reset();
    renderReqId(&buf2, .{ .number_string = "1.5e123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890" });
    try testing.expectEqualStrings("null", buf2.slice());
}

test "audit tail recovery truncates a torn final line" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmpPath(arena, &tmp, "torn.log");

    const w = try start(arena, testIo(), .{
        .path = path,
        .key = "k",
        .host = "t",
        .role = "node",
        .spawn_thread = false,
        .skip_start_record = true,
        .now_ms_override = 1759742400123,
    });
    w.enqueueInner("\"event\":\"a\"");
    w.enqueueInner("\"event\":\"b\"");
    w.drainOnce();
    const clean_seq = w.seq;
    w.mutex.lockUncancelable(w.io);
    w.stopping = true;
    w.mutex.unlock(w.io);
    os.closeFd(w.log.?.fd);

    // Simulate a kill mid-write: half a record glued onto the file end.
    var al = try os.fd.appendOpen(testIo(), path);
    try os.fd.appendWrite(testIo(), &al, "{\"v\":1,\"seq\":2,\"torn");
    os.closeFd(al.fd);

    const w2 = try start(arena, testIo(), .{
        .path = path,
        .key = "k",
        .host = "t",
        .role = "node",
        .spawn_thread = false,
        .skip_start_record = true,
        .now_ms_override = 1759742400456,
    });
    // The torn tail is gone and the chain continues where the good lines left.
    try testing.expectEqual(clean_seq, w2.seq);
    w2.enqueueInner("\"event\":\"c\"");
    w2.drainOnce();
    w2.mutex.lockUncancelable(w2.io);
    w2.stopping = true;
    w2.mutex.unlock(w2.io);
    os.closeFd(w2.log.?.fd);

    const verdict = try verifyFiles(arena, testIo(), &.{path}, "k");
    switch (verdict) {
        .ok => |ok| try testing.expectEqual(@as(u64, 3), ok.records),
        .broken => |b| return std.debug.panic("torn tail verify broken at seq {?d}: {s}", .{ b.seq, @tagName(b.reason) }),
    }
    // No torn fragment survives in the file.
    const data = try readAll(arena, path);
    try testing.expect(std.mem.indexOf(u8, data, "torn") == null);
}

test "audit verify with a key refuses a keyless file" {
    // Fail closed against a downgrade: an attacker without the key could
    // strip prev/mac from every line and otherwise pass verification.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmpPath(arena, &tmp, "kl.log");

    const w = try start(arena, testIo(), .{
        .path = path,
        .key = null,
        .host = "t",
        .role = "node",
        .spawn_thread = false,
        .skip_start_record = true,
        .now_ms_override = 1759742400123,
    });
    w.enqueueInner("\"event\":\"a\"");
    w.drainOnce();
    w.mutex.lockUncancelable(w.io);
    w.stopping = true;
    w.mutex.unlock(w.io);
    os.closeFd(w.log.?.fd);

    // Keyless verify passes; keyed verify of the same file must fail.
    const plain = try verifyFiles(arena, testIo(), &.{path}, null);
    try testing.expect(plain == .ok);
    const keyed = try verifyFiles(arena, testIo(), &.{path}, "k");
    try testing.expect(keyed == .broken);
    try testing.expectEqual(Reason.chain_required, keyed.broken.reason);
}

test "audit removing the key between runs starts a new chain" {
    // Keyless writer + mac'd tail: recovery refuses the mixed file, the old
    // file moves aside and the new file opens with a chain.break record.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const path = try tmpPath(arena, &tmp, "mix.log");

    const w = try start(arena, testIo(), .{
        .path = path,
        .key = "k",
        .host = "t",
        .role = "node",
        .spawn_thread = false,
        .skip_start_record = true,
        .now_ms_override = 1759742400123,
    });
    w.enqueueInner("\"event\":\"a\"");
    w.drainOnce();
    w.mutex.lockUncancelable(w.io);
    w.stopping = true;
    w.mutex.unlock(w.io);
    os.closeFd(w.log.?.fd);

    const w2 = try start(arena, testIo(), .{
        .path = path,
        .key = null,
        .host = "t",
        .role = "node",
        .spawn_thread = false,
        .skip_start_record = true,
        .now_ms_override = 1759742400999,
    });
    w2.drainOnce();
    w2.mutex.lockUncancelable(w2.io);
    w2.stopping = true;
    w2.mutex.unlock(w2.io);
    os.closeFd(w2.log.?.fd);

    // The old file is renamed aside; the new file's first record is chain.break.
    var it = tmp.dir.iterate();
    var aside: usize = 0;
    while (try it.next(testIo())) |ent| {
        if (std.mem.startsWith(u8, ent.name, "mix.log.corrupt-")) aside += 1;
    }
    try testing.expectEqual(@as(usize, 1), aside);
    const lines = try linesOf(arena, try readAll(arena, path));
    try testing.expect(lines.len == 1);
    try testing.expect(std.mem.indexOf(u8, lines[0], "\"event\":\"chain.break\"") != null);
    // Keyless lines carry no chain fields.
    try testing.expect(std.mem.indexOf(u8, lines[0], "\"prev\":") == null);
}

test "audit session hash is a stable 16 hex prefix" {
    var out: [16]u8 = undefined;
    _ = sessionHashHex("sess-abc-123", &out);
    for (out) |c| try testing.expect(std.ascii.isHex(c));
    var again: [16]u8 = undefined;
    _ = sessionHashHex("sess-abc-123", &again);
    try testing.expectEqualSlices(u8, &out, &again);
    var other: [16]u8 = undefined;
    _ = sessionHashHex("sess-abc-124", &other);
    try testing.expect(!std.mem.eql(u8, &out, &other));
}

test "audit wall clock ts is a plausible UTC epoch" {
    // Pins the clock choice: a monotonic source would render a 1970 date.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmpPath(arena, &tmp, "clock.log");
    const w = try start(arena, testIo(), .{
        .path = path,
        .key = "k",
        .host = "t",
        .role = "node",
        .spawn_thread = false,
        .skip_start_record = true,
    });
    w.enqueueInner("\"event\":\"a\"");
    w.drainOnce();
    w.mutex.lockUncancelable(w.io);
    w.stopping = true;
    w.mutex.unlock(w.io);
    os.closeFd(w.log.?.fd);
    const data = try readAll(arena, path);
    // 2026-01-01T00:00:00Z in epoch ms: any CI runner is newer than that.
    const cutoff: i64 = 1767225600000;
    try testing.expect(w.nowMs() > cutoff);
    try testing.expect(std.mem.indexOf(u8, data, "\"ts\":\"202") != null);
}

fn startTestWriter(arena: Allocator, path: []const u8) !*Writer {
    return start(arena, testIo(), .{
        .path = path,
        .key = "k",
        .host = "t",
        .role = "node",
        .spawn_thread = false,
        .skip_start_record = true,
        .now_ms_override = 1759742400123,
    });
}

fn stopTestWriter(w: *Writer) void {
    w.mutex.lockUncancelable(w.io);
    w.stopping = true;
    w.mutex.unlock(w.io);
    closeLiveHandle(w);
}

fn expectVerifies(arena: Allocator, files: []const []const u8, records: u64, last_seq: u64) !void {
    const verdict = try verifyFiles(arena, testIo(), files, "k");
    switch (verdict) {
        .ok => |ok| {
            try testing.expectEqual(records, ok.records);
            try testing.expectEqual(last_seq, ok.last_seq);
        },
        .broken => |b| {
            std.debug.print("verify broken at seq {?d}: {s}\n", .{ b.seq, @tagName(b.reason) });
            return error.TestUnexpectedResult;
        },
    }
}

test "audit write failure rolls back and the next batch heals the chain" {
    // A failed write must roll seq/prev/pos back to the last committed
    // record; the loss surfaces as a chained `dropped` marker and the
    // chain still verifies end to end.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmpPath(arena, &tmp, "wf.log");

    const w = try startTestWriter(arena, path);
    w.enqueueInner("\"event\":\"a\"");
    w.enqueueInner("\"event\":\"b\"");
    w.drainOnce(); // seq 0,1 committed

    // Injected write failure: nothing reaches the file, the batch is lost.
    w.fail_next_write = true;
    w.enqueueInner("\"event\":\"lost\"");
    w.drainOnce();
    try testing.expect(w.io_failed);
    try testing.expectEqual(@as(u64, 1), w.dropped);
    try testing.expectEqual(@as(u64, 2), w.seq); // chain state untouched
    {
        const data = try readAll(arena, path);
        const lines = try linesOf(arena, data);
        try testing.expectEqual(@as(usize, 2), lines.len); // rolled back
    }

    // The next batch heals: the new record plus the chained dropped marker.
    w.enqueueInner("\"event\":\"c\"");
    w.drainOnce();
    try testing.expect(!w.io_failed);
    const data = try readAll(arena, path);
    const lines = try linesOf(arena, data);
    try testing.expectEqual(@as(usize, 4), lines.len);
    try testing.expectEqual(@as(u64, 2), parseLineMeta(lines[2]).?.seq);
    try testing.expect(std.mem.indexOf(u8, lines[3], "\"event\":\"dropped\",\"count\":1") != null);
    try expectVerifies(arena, &.{path}, 4, 3);
    stopTestWriter(w);
}

test "audit failed rollback retires the handle and recovery re-verifies before writing" {
    // When the compensating truncation itself fails, the handle is retired
    // (its number may be recycled by accept()); the next batch must reopen,
    // re-verify the tail and re-derive seq/prev from the file BEFORE
    // composing anything, so the on-disk chain keeps exact continuity.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmpPath(arena, &tmp, "retire.log");

    const w = try startTestWriter(arena, path);
    w.enqueueInner("\"event\":\"a\"");
    w.enqueueInner("\"event\":\"b\"");
    w.drainOnce(); // seq 0,1 committed

    w.fail_next_write = true;
    w.fail_next_trunc = true;
    w.enqueueInner("\"event\":\"lost\"");
    w.drainOnce();
    try testing.expect(w.log == null); // handle retired, offset unconfirmed
    try testing.expectEqual(@as(u64, 1), w.dropped);

    w.enqueueInner("\"event\":\"c\"");
    w.drainOnce(); // recoverHandle: reopen + verify, then compose
    try testing.expect(w.log != null);
    const data = try readAll(arena, path);
    const lines = try linesOf(arena, data);
    try testing.expectEqual(@as(usize, 4), lines.len);
    // seq continuity proves the failed batch never advanced the chain.
    try testing.expectEqual(@as(u64, 2), parseLineMeta(lines[2]).?.seq);
    try expectVerifies(arena, &.{path}, 4, 3);
    stopTestWriter(w);
}

test "audit mid-run tail corruption quarantines and reopens with chain.break" {
    // A retired handle recovers through full tail verification; a tail
    // that fails verification is renamed aside for forensics and the chain
    // restarts with an explicit chain.break record naming the lost file.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const path = try tmpPath(arena, &tmp, "q.log");

    const w = try startTestWriter(arena, path);
    w.enqueueInner("\"event\":\"a\"");
    w.enqueueInner("\"event\":\"b\"");
    w.drainOnce(); // seq 0,1 committed

    // Retire the handle through the injected write+trunc failure pair.
    w.fail_next_write = true;
    w.fail_next_trunc = true;
    w.enqueueInner("\"event\":\"lost\"");
    w.drainOnce();
    try testing.expect(w.log == null);

    // Corruption lands while the handle is down: a garbage tail line.
    var al = try os.fd.appendOpen(testIo(), path);
    try os.fd.appendWrite(testIo(), &al, "not-a-record\n");
    os.closeFd(al.fd);

    w.enqueueInner("\"event\":\"c\"");
    w.drainOnce(); // recovery fails verification -> quarantine -> fresh chain
    try testing.expect(w.log != null);

    // The damaged file was moved aside under <path>.corrupt-<ms>.
    var aside: ?[]const u8 = null;
    var it = tmp.dir.iterate();
    while (try it.next(testIo())) |ent| {
        if (std.mem.startsWith(u8, ent.name, "q.log.corrupt-"))
            aside = try arena.dupe(u8, ent.name);
    }
    try testing.expect(aside != null);

    const data = try readAll(arena, path);
    const lines = try linesOf(arena, data);
    try testing.expectEqual(@as(usize, 3), lines.len); // break + c + dropped
    const m0 = parseLineMeta(lines[0]).?;
    try testing.expectEqualStrings("chain.break", m0.event);
    try testing.expectEqual(@as(u64, 0), m0.seq);
    try testing.expectEqualStrings(ZERO_PREV, m0.prev.?);
    try testing.expect(std.mem.indexOf(u8, lines[0], aside.?) != null);
    // The fresh chain verifies on its own...
    try expectVerifies(arena, &.{path}, 3, 2);
    // ...and the quarantined file stays broken for forensics.
    const aside_path = try tmpPath(arena, &tmp, aside.?);
    const old = try verifyFiles(arena, testIo(), &.{aside_path}, "k");
    switch (old) {
        .ok => return error.TestUnexpectedResult,
        .broken => {},
    }
    stopTestWriter(w);
}

test "audit recovery onto a vanished file opens with a recover boundary" {
    // Recovery that lands on a brand-new empty file while the chain holds
    // committed records opens the file with an explicit `recover` boundary
    // record instead of silently continuing; the verifier chains the two
    // files by prev like a rotation.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmpPath(arena, &tmp, "gone.log");

    const w = try startTestWriter(arena, path);
    w.enqueueInner("\"event\":\"a\"");
    w.enqueueInner("\"event\":\"b\"");
    w.drainOnce(); // seq 0,1 committed
    const committed_mac = try arena.dupe(u8, blk: {
        const data = try readAll(arena, path);
        const lines = try linesOf(arena, data);
        break :blk parseLineMeta(lines[1]).?.mac.?;
    });

    // Retire the handle (injected write+trunc failure), then the file
    // vanishes (rotated away by an external actor).
    w.fail_next_write = true;
    w.fail_next_trunc = true;
    w.enqueueInner("\"event\":\"lost\"");
    w.drainOnce();
    try testing.expect(w.log == null);
    const aside = try tmpPath(arena, &tmp, "gone.log.0");
    try os.fd.renamePath(testIo(), path, aside);

    w.enqueueInner("\"event\":\"c\"");
    w.drainOnce(); // fresh empty file + live chain state -> recover record
    try testing.expect(w.log != null);
    const data = try readAll(arena, path);
    const lines = try linesOf(arena, data);
    try testing.expectEqual(@as(usize, 3), lines.len); // recover + c + dropped
    const m0 = parseLineMeta(lines[0]).?;
    try testing.expectEqualStrings("recover", m0.event);
    try testing.expect(std.mem.indexOf(u8, lines[0], "reopened_new_file") != null);
    try testing.expectEqual(@as(u64, 2), m0.seq); // chain continues
    try testing.expectEqualStrings(committed_mac, m0.prev.?);

    // The pair verifies like a rotation: prev links across the boundary.
    const verdict = try verifyFiles(arena, testIo(), &.{ aside, path }, "k");
    switch (verdict) {
        .ok => |ok| {
            try testing.expectEqual(@as(u32, 1), ok.chained_files);
            try testing.expectEqual(@as(u64, 5), ok.records);
            try testing.expectEqual(@as(u64, 4), ok.last_seq);
        },
        .broken => |b| {
            std.debug.print("verify broken at seq {?d}: {s}\n", .{ b.seq, @tagName(b.reason) });
            return error.TestUnexpectedResult;
        },
    }
    stopTestWriter(w);
}

test "audit verify refuses a rotated suffix as the first file" {
    // A continuation file whose first prev is nonzero is proof that earlier
    // history exists; supplied alone it must fail closed, not verify as a
    // complete history.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmpPath(arena, &tmp, "sfx.log");

    const w = try startTestWriter(arena, path);
    w.enqueueInner("\"event\":\"a\"");
    w.enqueueInner("\"event\":\"b\"");
    w.drainOnce(); // seq 0,1 committed

    // Produce a genuine continuation file: retire the handle, move the
    // committed file away, let recovery open the fresh file with a recover
    // boundary whose prev links back to the predecessor.
    w.fail_next_write = true;
    w.fail_next_trunc = true;
    w.enqueueInner("\"event\":\"lost\"");
    w.drainOnce();
    try testing.expect(w.log == null);
    const aside = try tmpPath(arena, &tmp, "sfx.log.0");
    try os.fd.renamePath(testIo(), path, aside);
    w.enqueueInner("\"event\":\"c\"");
    w.drainOnce();
    stopTestWriter(w);

    // The suffix alone is an incomplete history: fail closed.
    const lone = try verifyFiles(arena, testIo(), &.{path}, "k");
    switch (lone) {
        .ok => return error.TestUnexpectedResult,
        .broken => |b| try testing.expectEqual(Reason.missing_predecessor, b.reason),
    }
    // The full pair still verifies.
    try expectVerifies(arena, &.{ aside, path }, 5, 4);
}

test "audit verify refuses a spliced independent chain at a file boundary" {
    // A zero-prev record mid-list that is not an explicit chain.break
    // boundary is a spliced-in independent chain: reject it.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path_a = try tmpPath(arena, &tmp, "sp-a.log");
    const path_b = try tmpPath(arena, &tmp, "sp-b.log");

    const wa = try startTestWriter(arena, path_a);
    wa.enqueueInner("\"event\":\"a1\"");
    wa.enqueueInner("\"event\":\"a2\"");
    wa.drainOnce();
    stopTestWriter(wa);

    // An independently valid chain with the same key, starting fresh.
    const wb = try startTestWriter(arena, path_b);
    wb.enqueueInner("\"event\":\"b1\"");
    wb.enqueueInner("\"event\":\"b2\"");
    wb.drainOnce();
    stopTestWriter(wb);

    const splice = try verifyFiles(arena, testIo(), &.{ path_a, path_b }, "k");
    switch (splice) {
        .ok => return error.TestUnexpectedResult,
        .broken => |b| {
            try testing.expectEqual(@as(usize, 1), b.file_index);
            try testing.expectEqual(Reason.prev_mismatch, b.reason);
        },
    }
    // Each file alone is a complete fresh chain.
    try expectVerifies(arena, &.{path_a}, 2, 1);
    try expectVerifies(arena, &.{path_b}, 2, 1);
}

test "audit verify accepts an explicit chain.break boundary between files" {
    // The legitimate mid-list fresh chain: quarantine wrote chain.break.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path_a = try tmpPath(arena, &tmp, "cb-a.log");
    const path_b = try tmpPath(arena, &tmp, "cb-b.log");

    const wa = try startTestWriter(arena, path_a);
    wa.enqueueInner("\"event\":\"a1\"");
    wa.enqueueInner("\"event\":\"a2\"");
    wa.drainOnce();
    stopTestWriter(wa);

    // Pre-seed a corrupt tail so start() quarantines and opens path_b with
    // an explicit chain.break boundary.
    {
        var al = try os.fd.appendOpen(testIo(), path_b);
        try os.fd.appendWrite(testIo(), &al, "corrupt\n");
        os.closeFd(al.fd);
    }
    const wb = try startTestWriter(arena, path_b);
    wb.enqueueInner("\"event\":\"b1\"");
    wb.drainOnce(); // chain.break (seq 0) + b1 (seq 1)
    stopTestWriter(wb);

    const verdict = try verifyFiles(arena, testIo(), &.{ path_a, path_b }, "k");
    switch (verdict) {
        .ok => |ok| {
            try testing.expectEqual(@as(u64, 4), ok.records);
            try testing.expectEqual(@as(u64, 1), ok.last_seq);
            try testing.expectEqual(@as(u32, 0), ok.chained_files);
        },
        .broken => |b| {
            std.debug.print("verify broken at seq {?d}: {s}\n", .{ b.seq, @tagName(b.reason) });
            return error.TestUnexpectedResult;
        },
    }
}

test "audit verify and recovery refuse seq overflow instead of panicking" {
    // seq == maxInt(u64) must be a broken verdict / corrupt tail, never a
    // checked-overflow panic on the seq+1 step.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmpPath(arena, &tmp, "ovf.log");

    {
        var al = try os.fd.appendOpen(testIo(), path);
        try os.fd.appendWrite(testIo(), &al, "{\"v\":1,\"seq\":18446744073709551615,\"event\":\"x\"}\n");
        os.closeFd(al.fd);
    }
    // Verifier: broken, not a panic (keyless line needs no MAC to reach it).
    const verdict = try verifyFiles(arena, testIo(), &.{path}, null);
    switch (verdict) {
        .ok => return error.TestUnexpectedResult,
        .broken => |b| try testing.expectEqual(Reason.seq_gap, b.reason),
    }
    // Recovery: the same line quarantines the file and opens a fresh chain.
    const w = try start(arena, testIo(), .{
        .path = path,
        .key = null,
        .host = "t",
        .role = "node",
        .spawn_thread = false,
        .skip_start_record = true,
        .now_ms_override = 1759742400123,
    });
    w.drainOnce();
    const data = try readAll(arena, path);
    const lines = try linesOf(arena, data);
    try testing.expectEqual(@as(usize, 1), lines.len);
    try testing.expectEqualStrings("chain.break", parseLineMeta(lines[0]).?.event);
    stopTestWriter(w);
}

test "audit failed batch preserves the pending chain.break boundary" {
    // A write failure on the very batch that carries the quarantine
    // boundary must not consume it: the next batch still leads with
    // chain.break naming the lost file.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmpPath(arena, &tmp, "pb.log");

    const w = try startTestWriter(arena, path);
    w.enqueueInner("\"event\":\"a\"");
    w.enqueueInner("\"event\":\"b\"");
    w.drainOnce(); // seq 0,1 committed

    w.fail_next_write = true;
    w.fail_next_trunc = true;
    w.enqueueInner("\"event\":\"lost\"");
    w.drainOnce();
    try testing.expect(w.log == null);

    // Corruption lands while the handle is down; the next drain quarantines
    // and its boundary-carrying batch fails the write.
    var al = try os.fd.appendOpen(testIo(), path);
    try os.fd.appendWrite(testIo(), &al, "corrupt\n");
    os.closeFd(al.fd);
    w.fail_next_write = true;
    w.enqueueInner("\"event\":\"c\"");
    w.drainOnce();
    try testing.expect(w.pending_break); // boundary survived the rollback

    w.enqueueInner("\"event\":\"d\"");
    w.drainOnce();
    const data = try readAll(arena, path);
    const lines = try linesOf(arena, data);
    try testing.expectEqual(@as(usize, 3), lines.len); // break + d + dropped
    const m0 = parseLineMeta(lines[0]).?;
    try testing.expectEqualStrings("chain.break", m0.event);
    try testing.expectEqual(@as(u64, 0), m0.seq);
    try testing.expect(std.mem.indexOf(u8, lines[0], ".corrupt-") != null);
    try testing.expect(std.mem.indexOf(u8, lines[2], "\"event\":\"dropped\",\"count\":2") != null);
    try expectVerifies(arena, &.{path}, 3, 2);
    stopTestWriter(w);
}

test "audit failed batch preserves the pending recover boundary" {
    // Same transactional guard for the recover boundary: a failed batch
    // must not consume it.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmpPath(arena, &tmp, "pr.log");

    const w = try startTestWriter(arena, path);
    w.enqueueInner("\"event\":\"a\"");
    w.enqueueInner("\"event\":\"b\"");
    w.drainOnce(); // seq 0,1 committed

    w.fail_next_write = true;
    w.fail_next_trunc = true;
    w.enqueueInner("\"event\":\"lost\"");
    w.drainOnce();
    try testing.expect(w.log == null);
    const aside = try tmpPath(arena, &tmp, "pr.log.0");
    try os.fd.renamePath(testIo(), path, aside);

    // Recovery lands on a fresh empty file; the boundary batch fails.
    w.fail_next_write = true;
    w.enqueueInner("\"event\":\"c\"");
    w.drainOnce();
    try testing.expect(w.pending_recover); // boundary survived the rollback

    w.enqueueInner("\"event\":\"d\"");
    w.drainOnce();
    const data = try readAll(arena, path);
    const lines = try linesOf(arena, data);
    try testing.expectEqual(@as(usize, 3), lines.len); // recover + d + dropped
    try testing.expectEqualStrings("recover", parseLineMeta(lines[0]).?.event);
    try testing.expectEqual(@as(u64, 2), parseLineMeta(lines[0]).?.seq);
    try expectVerifies(arena, &.{ aside, path }, 5, 4);
    stopTestWriter(w);
}

test "audit failed sync rolls the batch back and the retry heals the chain" {
    // An fsync failure is a commit failure: the batch is cut back, the loss
    // surfaces as a chained dropped marker, and the chain still verifies.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmpPath(arena, &tmp, "sy.log");

    const w = try startTestWriter(arena, path);
    w.enqueueInner("\"event\":\"a\"");
    w.enqueueInner("\"event\":\"b\"");
    w.drainOnce(); // seq 0,1 committed

    w.fail_next_sync = true;
    w.enqueueInner("\"event\":\"lost\"");
    w.drainOnce();
    try testing.expect(w.io_failed);
    try testing.expectEqual(@as(u64, 1), w.dropped);
    {
        // The unsynced batch was cut back to the last durable offset.
        const data = try readAll(arena, path);
        const lines = try linesOf(arena, data);
        try testing.expectEqual(@as(usize, 2), lines.len);
    }
    w.enqueueInner("\"event\":\"c\"");
    w.drainOnce();
    try testing.expect(!w.io_failed);
    const data = try readAll(arena, path);
    const lines = try linesOf(arena, data);
    try testing.expectEqual(@as(usize, 4), lines.len);
    try testing.expect(std.mem.indexOf(u8, lines[3], "\"event\":\"dropped\",\"count\":1") != null);
    try expectVerifies(arena, &.{path}, 4, 3);
    stopTestWriter(w);
}

test "audit rotation refuses to rename away an unsynced file" {
    // A failed pre-rename fsync must stop the rotation: the old file stays
    // under its live name (handle retained), and the next batch retries.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const path = try tmpPath(arena, &tmp, "rs.log");

    const w = try start(arena, testIo(), .{
        .path = path,
        .key = "k",
        .host = "t",
        .role = "node",
        .spawn_thread = false,
        .skip_start_record = true,
        .now_ms_override = 1759742400123,
        .max_bytes = 4096,
    });
    // Fill to just under the limit, one record per batch.
    var guard: usize = 0;
    while (w.log.?.pos < 4096 - 300 and guard < 100) : (guard += 1) {
        w.enqueueInner("\"event\":\"a\"");
        w.drainOnce();
    }
    try testing.expect(w.log.?.pos < 4096);
    try testing.expect(guard < 100);
    try testing.expect(guard > 0);

    // The crossing batch commits; the rotation boundary sync fails.
    w.fail_rotate_sync = true;
    w.enqueueInner("\"event\":\"b\"");
    w.drainOnce();
    try testing.expect(w.io_failed);
    try testing.expect(w.log != null); // handle retained, no rename happened
    var it = tmp.dir.iterate();
    while (try it.next(testIo())) |ent| {
        try testing.expect(!std.mem.startsWith(u8, ent.name, "rs.log."));
    }

    // Retry: rotation completes and the chain spans both files.
    w.enqueueInner("\"event\":\"c\"");
    w.drainOnce();
    try testing.expect(!w.io_failed);
    var names: std.ArrayList([]const u8) = .empty;
    var it2 = tmp.dir.iterate();
    while (try it2.next(testIo())) |ent| {
        if (std.mem.startsWith(u8, ent.name, "rs.log"))
            try names.append(arena, try arena.dupe(u8, ent.name));
    }
    try testing.expectEqual(@as(usize, 2), names.items.len);
    std.mem.sort([]const u8, names.items, {}, struct {
        fn suffix(name: []const u8) u64 {
            const d = std.mem.lastIndexOfScalar(u8, name, '.') orelse return 0;
            return std.fmt.parseInt(u64, name[d + 1 ..], 10) catch std.math.maxInt(u64);
        }
        fn lessThan(_: void, a: []const u8, b: []const u8) bool {
            return suffix(a) < suffix(b);
        }
    }.lessThan);
    var files: std.ArrayList([]const u8) = .empty;
    for (names.items) |n| try files.append(arena, try tmpPath(arena, &tmp, n));
    const verdict = try verifyFiles(arena, testIo(), files.items, "k");
    switch (verdict) {
        .ok => |ok| {
            try testing.expectEqual(@as(u32, 1), ok.chained_files);
            try testing.expectEqual(@as(u64, guard + 3), ok.records);
        },
        .broken => |b| {
            std.debug.print("verify broken at seq {?d}: {s}\n", .{ b.seq, @tagName(b.reason) });
            return error.TestUnexpectedResult;
        },
    }
    stopTestWriter(w);
}

test "audit rotation after a chain restart never overwrites old history" {
    // Two chains share the chain-gen tag (fixed test clock): the second
    // chain's first rotation collides with the first chain's genesis
    // segment. The rename must fail closed and disambiguate instead of
    // silently replacing committed, MAC'd history.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const path = try tmpPath(arena, &tmp, "kc.log");
    const gen0_name = "kc.log.1759742400123.0";

    const hasFile = struct {
        fn f(t: *testing.TmpDir, name: []const u8) bool {
            var it = t.dir.iterate();
            while (it.next(testIo()) catch return false) |ent| {
                if (std.mem.eql(u8, ent.name, name)) return true;
            }
            return false;
        }
    }.f;

    // Chain 1 (key k1): fill until the first rotation lands.
    const w1 = try start(arena, testIo(), .{
        .path = path,
        .key = "k1",
        .host = "t",
        .role = "node",
        .spawn_thread = false,
        .skip_start_record = true,
        .now_ms_override = 1759742400123,
        .max_bytes = 4096,
    });
    var guard: usize = 0;
    while (!hasFile(&tmp, gen0_name) and guard < 60) : (guard += 1) {
        w1.enqueueInner("\"event\":\"r1\"");
        w1.drainOnce();
    }
    try testing.expect(hasFile(&tmp, gen0_name));
    const orig_bytes = try readAll(arena, try tmpPath(arena, &tmp, gen0_name));
    stopTestWriter(w1);

    // Chain 2 (key k2 — a key change quarantines chain 1's live file):
    // fill until the colliding rotation is disambiguated.
    const w2 = try start(arena, testIo(), .{
        .path = path,
        .key = "k2",
        .host = "t",
        .role = "node",
        .spawn_thread = false,
        .skip_start_record = true,
        .now_ms_override = 1759742400123,
        .max_bytes = 4096,
    });
    guard = 0;
    const disambiguated = "kc.log.1759742400123.0-1";
    while (!hasFile(&tmp, disambiguated) and guard < 60) : (guard += 1) {
        w2.enqueueInner("\"event\":\"r2\"");
        w2.drainOnce();
    }
    stopTestWriter(w2);

    // The old genesis segment is byte-identical: never replaced.
    const after = try readAll(arena, try tmpPath(arena, &tmp, gen0_name));
    try testing.expectEqualSlices(u8, orig_bytes, after);
    // The colliding rotation went to the disambiguated name.
    try testing.expect(hasFile(&tmp, disambiguated));

    // Chain 1 still verifies under k1 (rotated genesis + quarantined tail).
    var aside: ?[]const u8 = null;
    var it = tmp.dir.iterate();
    while (try it.next(testIo())) |ent| {
        if (std.mem.startsWith(u8, ent.name, "kc.log.corrupt-"))
            aside = try arena.dupe(u8, ent.name);
    }
    try testing.expect(aside != null);
    const chain1 = try verifyFiles(arena, testIo(), &.{
        try tmpPath(arena, &tmp, gen0_name),
        try tmpPath(arena, &tmp, aside.?),
    }, "k1");
    switch (chain1) {
        .ok => {},
        .broken => |b| {
            std.debug.print("chain1 verify broken at seq {?d}: {s}\n", .{ b.seq, @tagName(b.reason) });
            return error.TestUnexpectedResult;
        },
    }
    // Chain 2 verifies under k2 (disambiguated segment + live file).
    const chain2 = try verifyFiles(arena, testIo(), &.{
        try tmpPath(arena, &tmp, disambiguated),
        path,
    }, "k2");
    switch (chain2) {
        .ok => |ok| try testing.expectEqual(@as(u32, 1), ok.chained_files),
        .broken => |b| {
            std.debug.print("chain2 verify broken at seq {?d}: {s}\n", .{ b.seq, @tagName(b.reason) });
            return error.TestUnexpectedResult;
        },
    }
}

fn tmpHasFile(tmp: *const testing.TmpDir, name: []const u8) bool {
    var it = tmp.dir.iterate();
    while (it.next(testIo()) catch return false) |ent| {
        if (std.mem.eql(u8, ent.name, name)) return true;
    }
    return false;
}

test "audit rotation behind the dir-sync gate commits nothing until the rename is durable" {
    // The post-rename parent-directory flush fails: the rename happened but
    // is not proven durable, so the fresh file and its rotate record must
    // stay deferred behind the gate — never committed against a layout a
    // crash may still undo.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const path = try tmpPath(arena, &tmp, "dg.log");
    const rotated_name = "dg.log.1759742400123.0";

    const w = try start(arena, testIo(), .{
        .path = path,
        .key = "k",
        .host = "t",
        .role = "node",
        .spawn_thread = false,
        .skip_start_record = true,
        .now_ms_override = 1759742400123,
        .max_bytes = 4096,
    });
    var guard: usize = 0;
    while (w.log.?.pos < 4096 - 300 and guard < 100) : (guard += 1) {
        w.enqueueInner("\"event\":\"a\"");
        w.drainOnce();
    }
    try testing.expect(guard > 0 and guard < 100);

    // The crossing batch commits; the rename lands but the directory flush
    // fails. No fresh file, no rotate record: the gate holds.
    w.fail_dir_sync = true;
    w.enqueueInner("\"event\":\"b\"");
    w.drainOnce();
    try testing.expect(w.dir_sync_gate == .rotate);
    try testing.expect(w.io_failed);
    try testing.expect(w.log == null);
    try testing.expect(!tmpHasFile(&tmp, "dg.log"));
    try testing.expect(tmpHasFile(&tmp, rotated_name));

    // While the gate holds, batches are counted as dropped — not written.
    w.fail_dir_sync = true;
    w.enqueueInner("\"event\":\"c\"");
    w.drainOnce();
    try testing.expect(w.dir_sync_gate == .rotate);
    try testing.expect(!tmpHasFile(&tmp, "dg.log"));

    // The flush finally succeeds: the gate completes the rotation and the
    // batch lands in the fresh file behind its rotate record.
    w.enqueueInner("\"event\":\"d\"");
    w.drainOnce();
    try testing.expect(w.dir_sync_gate == .none);
    try testing.expect(!w.io_failed);
    try testing.expect(tmpHasFile(&tmp, "dg.log"));
    const data = try readAll(arena, path);
    const lines = try linesOf(arena, data);
    try testing.expectEqual(@as(usize, 3), lines.len); // rotate + d + dropped
    try testing.expectEqualStrings("rotate", parseLineMeta(lines[0]).?.event);
    try testing.expect(std.mem.indexOf(u8, lines[0], rotated_name) != null);
    try testing.expectEqualStrings("d", parseLineMeta(lines[1]).?.event);
    try testing.expect(std.mem.indexOf(u8, lines[2], "\"event\":\"dropped\",\"count\":1") != null);

    try expectVerifies(arena, &.{
        try tmpPath(arena, &tmp, rotated_name),
        path,
    }, @intCast(guard + 4), @intCast(guard + 3));
    stopTestWriter(w);
}

test "audit quarantine behind the dir-sync gate opens no fresh file until the rename is durable" {
    // Same fail-closed gate on the quarantine path: the damaged file was
    // renamed aside, but until the parent directory is flushed no fresh
    // chain file is opened and no chain.break is committed.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const path = try tmpPath(arena, &tmp, "qg.log");

    const w = try startTestWriter(arena, path);
    w.enqueueInner("\"event\":\"a\"");
    w.enqueueInner("\"event\":\"b\"");
    w.drainOnce(); // seq 0,1 committed

    // Retire the handle, then corrupt the tail while it is down.
    w.fail_next_write = true;
    w.fail_next_trunc = true;
    w.enqueueInner("\"event\":\"lost\"");
    w.drainOnce();
    try testing.expect(w.log == null);
    {
        var al = try os.fd.appendOpen(testIo(), path);
        try os.fd.appendWrite(testIo(), &al, "corrupt\n");
        os.closeFd(al.fd);
    }

    // Recovery quarantines the damaged file, but the directory flush
    // fails: the gate holds, no fresh file is created.
    w.fail_dir_sync = true;
    w.enqueueInner("\"event\":\"c\"");
    w.drainOnce();
    try testing.expect(w.dir_sync_gate == .quarantine);
    try testing.expect(w.io_failed);
    try testing.expect(w.log == null);
    try testing.expect(!tmpHasFile(&tmp, "qg.log"));

    // While the gate holds the batch is dropped, not written.
    w.fail_dir_sync = true;
    w.enqueueInner("\"event\":\"d\"");
    w.drainOnce();
    try testing.expect(w.dir_sync_gate == .quarantine);
    try testing.expect(!tmpHasFile(&tmp, "qg.log"));

    // The flush succeeds: the fresh file opens and the chain restarts
    // behind an explicit chain.break naming the quarantined file.
    w.enqueueInner("\"event\":\"e\"");
    w.drainOnce();
    try testing.expect(w.dir_sync_gate == .none);
    try testing.expect(!w.io_failed);
    const data = try readAll(arena, path);
    const lines = try linesOf(arena, data);
    try testing.expectEqual(@as(usize, 3), lines.len); // break + e + dropped
    const m0 = parseLineMeta(lines[0]).?;
    try testing.expectEqualStrings("chain.break", m0.event);
    try testing.expectEqual(@as(u64, 0), m0.seq);
    try testing.expect(std.mem.indexOf(u8, lines[0], ".corrupt-") != null);
    // lost + c + d were dropped across the failed commit and the gate.
    try testing.expect(std.mem.indexOf(u8, lines[2], "\"event\":\"dropped\",\"count\":3") != null);
    try expectVerifies(arena, &.{path}, 3, 2);
    stopTestWriter(w);
}

test "audit truncated request id is always valid UTF-8 and valid JSON" {
    // The escape-aware truncation heuristics must never emit a partial
    // multibyte sequence: whatever lands near the cap, the rendered id
    // stays a valid JSON string literal of valid UTF-8.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const cases = [_][]const u8{
        // Multibyte chars straddling the cap in every phase (87 bytes).
        ("……" ** 12) ++ "………",
        // A backslash run across the cap (66 bytes).
        ("a" ** 50) ++ ("\\" ** 16),
        // An escape-looking sequence right at the cap (66 bytes).
        "0123456789abcdef0123456789abcdef0123456789abcdef01234567" ++ "\\u00e9" ++ "ZZZZ",
        // Backslashes immediately followed by multibyte chars (67 bytes).
        ("b" ** 56) ++ "\\\\" ++ "………",
    };
    for (cases) |id| {
        var buf: Buf = undefined;
        buf.reset();
        renderReqId(&buf, .{ .string = id });
        const out = buf.slice();
        try testing.expect(out.len <= REQ_ID_MAX);
        try testing.expect(std.unicode.utf8ValidateSlice(out));
        // The rendered literal must parse back as a JSON string.
        const parsed = try std.json.parseFromSlice(Value, arena, out, .{});
        try testing.expect(parsed.value == .string);
    }
}

test "audit args digest distinguishes invalid UTF-8 byte strings" {
    // The lossy escaped form maps both raw strings to "a<U+FFFD>"; the
    // digest must still tell them apart, or forensic comparisons of
    // policy-denied calls collide on exactly the payloads that matter.
    const raw_a = [_]u8{ 'a', 0xff };
    const raw_b = [_]u8{ 'a', 0xfe };
    const da = argsDigestHex(.{ .string = &raw_a });
    const db = argsDigestHex(.{ .string = &raw_b });
    try testing.expect(!da.partial and !db.partial);
    try testing.expect(!std.mem.eql(u8, &da.hex, &db.hex));
    // A valid string keeps a stable, distinct digest as well.
    const dc = argsDigestHex(.{ .string = "a" });
    try testing.expect(!std.mem.eql(u8, &da.hex, &dc.hex));
    const dc2 = argsDigestHex(.{ .string = "a" });
    try testing.expectEqualSlices(u8, &dc.hex, &dc2.hex);
}

test "audit args digest flags deep argument trees as partial" {
    // Past DIGEST_DEPTH_MAX the digest must not silently fold the subtree
    // into a value that could collide with a real one: the digest is
    // flagged partial, and the fold marker cannot alias any encodable
    // value at that position.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // depth-nested single-element arrays: [[...[leaf]...]]
    const deep = try arena.create(Value);
    deep.* = .{ .string = "leaf-a" };
    var v = deep;
    for (0..DIGEST_DEPTH_MAX + 4) |_| {
        var arr: std.json.Array = .init(arena);
        try arr.append(v.*);
        const box = try arena.create(Value);
        box.* = .{ .array = arr };
        v = box;
    }
    const d_deep = argsDigestHex(v.*);
    try testing.expect(d_deep.partial);

    // A shallow tree over the same leaf is complete.
    var shallow_arr: std.json.Array = .init(arena);
    try shallow_arr.append(.{ .string = "leaf-a" });
    const d_shallow = argsDigestHex(.{ .array = shallow_arr });
    try testing.expect(!d_shallow.partial);

    // The marker cannot alias a real value at the fold position: a tree
    // whose depth-33 slot holds a literal null still differs from the
    // folded marker... and crucially the deep digest is marked partial.
    // Object nesting takes the same path.
    const deep_obj = try arena.create(Value);
    deep_obj.* = .{ .integer = 1 };
    var vo = deep_obj;
    for (0..DIGEST_DEPTH_MAX + 4) |_| {
        var obj: std.json.ObjectMap = .empty;
        try obj.put(arena, "k", vo.*);
        const box = try arena.create(Value);
        box.* = .{ .object = obj };
        vo = box;
    }
    try testing.expect(argsDigestHex(vo.*).partial);
}

test "audit args summary caps the escaped form and flags truncation honestly" {
    // The budget counts escaped bytes. Each item is individually capped by
    // jsonStrCap (~256 bytes), so overflowing SUMMARY_CAP takes several
    // control-byte-heavy items: 5 items x 60 control bytes escape to ~360
    // each (capped to ~256); the item that would push the summary past the
    // cap is rolled back whole and the record is marked truncated.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var evil: [60]u8 = undefined;
    @memset(&evil, 0x01);
    var argv: std.json.Array = .init(arena);
    try argv.append(.{ .string = "ok" });
    for (0..5) |_| try argv.append(.{ .string = &evil });
    try argv.append(.{ .string = "never-reached" });
    var obj: std.json.ObjectMap = .empty;
    try obj.put(arena, "argv", .{ .array = argv });

    var buf: Buf = undefined;
    buf.reset();
    appendArgsSummary(&buf, "exec", .{ .object = obj }, .full);
    const out = buf.slice();
    try testing.expect(out.len <= SUMMARY_CAP);
    try testing.expect(std.mem.indexOf(u8, out, "\"truncated\":true") != null);
    // The first item survived; everything past the budget was left out.
    try testing.expect(std.mem.indexOf(u8, out, "\"ok\"") != null);
    try testing.expect(std.mem.indexOf(u8, out, "never-reached") == null);
    // The summary is still a complete JSON object literal.
    const wrapped = try std.fmt.allocPrint(arena, "{{\"args\":{s}}}", .{out});
    _ = try std.json.parseFromSlice(Value, arena, wrapped, .{});
}

test "audit verify refuses a fresh chain that does not start at seq 0" {
    // A zero-prev first record with a nonzero seq means the genesis records
    // were omitted from the input — fail closed, do not anchor on a chain
    // whose start nobody showed us.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmpPath(arena, &tmp, "s42.log");

    var line: std.ArrayList(u8) = .empty;
    try line.appendSlice(arena, "{\"v\":1,\"seq\":42,\"ts\":\"2025-10-06T00:00:00.000Z\",\"host\":\"t\",\"role\":\"node\",\"event\":\"x\",\"prev\":\"" ++ ZERO_PREV ++ "\"");
    var mac: [32]u8 = undefined;
    HmacSha256.create(&mac, line.items, "k");
    try line.appendSlice(arena, ",\"mac\":\"");
    const alphabet = "0123456789abcdef";
    for (mac) |b| {
        try line.append(arena, alphabet[b >> 4]);
        try line.append(arena, alphabet[b & 0x0f]);
    }
    try line.appendSlice(arena, "\"}\n");
    {
        var al = try os.fd.appendOpen(testIo(), path);
        try os.fd.appendWrite(testIo(), &al, line.items);
        os.closeFd(al.fd);
    }

    const verdict = try verifyFiles(arena, testIo(), &.{path}, "k");
    switch (verdict) {
        .ok => return error.TestUnexpectedResult,
        .broken => |b| try testing.expectEqual(Reason.missing_predecessor, b.reason),
    }

    // The mid-list variant: a chain.break wearing a nonzero seq is a
    // splice, not a boundary.
    const path_a = try tmpPath(arena, &tmp, "s42-a.log");
    const wa = try startTestWriter(arena, path_a);
    wa.enqueueInner("\"event\":\"a1\"");
    wa.drainOnce();
    stopTestWriter(wa);

    const path_b = try tmpPath(arena, &tmp, "s42-b.log");
    var line_b: std.ArrayList(u8) = .empty;
    try line_b.appendSlice(arena, "{\"v\":1,\"seq\":7,\"ts\":\"2025-10-06T00:00:00.000Z\",\"host\":\"t\",\"role\":\"node\",\"event\":\"chain.break\",\"reason\":\"tail_verify_failed\",\"lost_file\":\"x\",\"prev\":\"" ++ ZERO_PREV ++ "\"");
    HmacSha256.create(&mac, line_b.items, "k");
    try line_b.appendSlice(arena, ",\"mac\":\"");
    for (mac) |b| {
        try line_b.append(arena, alphabet[b >> 4]);
        try line_b.append(arena, alphabet[b & 0x0f]);
    }
    try line_b.appendSlice(arena, "\"}\n");
    {
        var al = try os.fd.appendOpen(testIo(), path_b);
        try os.fd.appendWrite(testIo(), &al, line_b.items);
        os.closeFd(al.fd);
    }
    const verdict2 = try verifyFiles(arena, testIo(), &.{ path_a, path_b }, "k");
    switch (verdict2) {
        .ok => return error.TestUnexpectedResult,
        .broken => |b| try testing.expectEqual(Reason.prev_mismatch, b.reason),
    }
}

test "audit stop terminates under a persistent write failure" {
    // Persistent storage failure must not livelock shutdown: the shutdown
    // retry budget reports the loss and lets the writer thread exit.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmpPath(arena, &tmp, "pf.log");

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const w = try start(arena, io, .{
        .path = path,
        .key = "k",
        .host = "t",
        .role = "node",
        .now_ms_override = 1759742400123,
    });
    w.enqueueInner("\"event\":\"a\"");
    w.fail_all_writes = true;
    // stop() joins the writer thread; without the budget this never
    // returned while storage stayed broken.
    stop(w);
}

test "audit stop terminates with a held directory-sync gate" {
    // Same livelock class through a different failure path: the post-
    // rename directory flush fails persistently, so the gate holds every
    // drain; the budget still bounds the shutdown.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const path = try tmpPath(arena, &tmp, "pg.log");

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const w = try start(arena, io, .{
        .path = path,
        .key = "k",
        .host = "t",
        .role = "node",
        .now_ms_override = 1759742400123,
        .max_bytes = 4096,
    });
    w.fail_all_dir_sync = true;
    // Enough records to cross the rotation threshold: the rename lands,
    // the directory flush never does, the gate holds.
    for (0..40) |_| w.enqueueInner("\"event\":\"x\"");
    stop(w);
}

test "audit args digest never substitutes on numeric formatting" {
    // Large-magnitude and subnormal f64 values expand far past 40 bytes in
    // positional decimal notation; scientific formatting keeps adjacent
    // subnormals distinct with complete digests.
    const tiny1 = std.math.floatTrueMin(f64);
    const tiny2 = tiny1 * 2;
    const huge = std.math.floatMax(f64);
    const d1 = argsDigestHex(.{ .float = tiny1 });
    const d2 = argsDigestHex(.{ .float = tiny2 });
    const d3 = argsDigestHex(.{ .float = huge });
    const d4 = argsDigestHex(.{ .float = -huge });
    try testing.expect(!d1.partial and !d2.partial and !d3.partial and !d4.partial);
    try testing.expect(!std.mem.eql(u8, &d1.hex, &d2.hex));
    try testing.expect(!std.mem.eql(u8, &d1.hex, &d3.hex));
    try testing.expect(!std.mem.eql(u8, &d3.hex, &d4.hex));
    // Zero and a nonzero value must never collide either.
    const dz = argsDigestHex(.{ .float = 0.0 });
    try testing.expect(!std.mem.eql(u8, &dz.hex, &d1.hex));
}

test "audit args digest frames raw invalid strings against boundary collisions" {
    // Unframed raw bytes could swallow the enclosing collection's
    // punctuation: ["\xff", "x]"] and ["\xff,\x00\"x]\""] produced the
    // identical hash stream. Length framing keeps the tree boundary.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const s1 = [_]u8{0xff};
    const s2 = [_]u8{ 0xff, ',', 0x00, '"', 'x', ']', '"' };
    var arr1: std.json.Array = .init(arena);
    try arr1.append(.{ .string = &s1 });
    try arr1.append(.{ .string = "x]" });
    var arr2: std.json.Array = .init(arena);
    try arr2.append(.{ .string = &s2 });
    const d1 = argsDigestHex(.{ .array = arr1 });
    const d2 = argsDigestHex(.{ .array = arr2 });
    try testing.expect(!d1.partial and !d2.partial);
    try testing.expect(!std.mem.eql(u8, &d1.hex, &d2.hex));

    // A raw number_string lives in its own domain: same bytes as a string
    // must not alias across types.
    const dn = argsDigestHex(.{ .number_string = &s2 });
    const ds = argsDigestHex(.{ .string = &s2 });
    try testing.expect(!std.mem.eql(u8, &dn.hex, &ds.hex));
}

test "audit rotation never appends to a foreign file at the freed pathname" {
    // The rename/open race: between the rotation rename and the fresh
    // file's creation another writer drops a file at the freed pathname.
    // The writer must not append a rotate boundary to it (that would make
    // a truncated history verify); the foreign file is quarantined and the
    // chain restarts with an honest chain.break.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const path = try tmpPath(arena, &tmp, "rc.log");
    const rotated_name = "rc.log.1759742400123.0";

    const w = try start(arena, testIo(), .{
        .path = path,
        .key = "k",
        .host = "t",
        .role = "node",
        .spawn_thread = false,
        .skip_start_record = true,
        .now_ms_override = 1759742400123,
        .max_bytes = 4096,
    });
    var guard: usize = 0;
    while (w.log.?.pos < 4096 - 300 and guard < 100) : (guard += 1) {
        w.enqueueInner("\"event\":\"a\"");
        w.drainOnce();
    }
    try testing.expect(guard > 0 and guard < 100);

    // The directory-sync hook pauses the rotation between the rename and
    // the fresh file's creation.
    w.fail_dir_sync = true;
    w.enqueueInner("\"event\":\"b\"");
    w.drainOnce();
    try testing.expect(w.dir_sync_gate == .rotate);
    try testing.expect(!tmpHasFile(&tmp, "rc.log"));
    try testing.expect(tmpHasFile(&tmp, rotated_name));

    // A foreign empty file appears at the freed pathname.
    {
        const al = try os.fd.appendOpen(testIo(), path);
        os.closeFd(al.fd);
    }
    try testing.expect(tmpHasFile(&tmp, "rc.log"));

    // The gate completes: the fresh open must refuse the foreign file
    // (exclusive create), recovery quarantines it, and the chain restarts
    // with chain.break instead of a rotate record linking into it.
    w.enqueueInner("\"event\":\"c\"");
    w.drainOnce();
    try testing.expect(w.dir_sync_gate == .none);
    try testing.expect(!w.io_failed);

    // The foreign file was preserved under a quarantine name, still empty.
    var aside_len: ?usize = null;
    {
        var it = tmp.dir.iterate();
        while (try it.next(testIo())) |ent| {
            if (std.mem.startsWith(u8, ent.name, "rc.log.corrupt-")) {
                const q = try readAll(arena, try tmpPath(arena, &tmp, ent.name));
                aside_len = q.len;
            }
        }
    }
    try testing.expectEqual(@as(?usize, 0), aside_len);

    // The live file opens with chain.break (seq 0), not a rotate record.
    const data = try readAll(arena, path);
    const lines = try linesOf(arena, data);
    try testing.expectEqual(@as(usize, 2), lines.len);
    const m0 = parseLineMeta(lines[0]).?;
    try testing.expectEqualStrings("chain.break", m0.event);
    try testing.expectEqual(@as(u64, 0), m0.seq);

    // The two generations verify honestly across the explicit boundary.
    try expectVerifies(arena, &.{
        try tmpPath(arena, &tmp, rotated_name),
        path,
    }, @intCast(guard + 3), 1);
    stopTestWriter(w);
}

test "audit quarantine gate absorbs a foreign occupant at the freed pathname" {
    // The quarantine twin of the rotation race: the gate is armed between
    // the quarantine rename and the fresh create, a foreign file lands at
    // the freed pathname, and the gate completion must absorb it
    // (quarantine untouched, chain.break) rather than livelock or append
    // chain bytes into it.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const path = try tmpPath(arena, &tmp, "qa.log");

    const w = try startTestWriter(arena, path);
    w.enqueueInner("\"event\":\"a\"");
    w.enqueueInner("\"event\":\"b\"");
    w.drainOnce(); // seq 0,1 committed

    // Retire the handle, then corrupt the tail while it is down.
    w.fail_next_write = true;
    w.fail_next_trunc = true;
    w.enqueueInner("\"event\":\"lost\"");
    w.drainOnce();
    try testing.expect(w.log == null);
    {
        var al = try os.fd.appendOpen(testIo(), path);
        try os.fd.appendWrite(testIo(), &al, "corrupt\n");
        os.closeFd(al.fd);
    }

    // Arm the gate: quarantine renames the damaged file, the directory
    // flush fails, the fresh open is deferred.
    w.fail_dir_sync = true;
    w.enqueueInner("\"event\":\"c\"");
    w.drainOnce();
    try testing.expect(w.dir_sync_gate == .quarantine);
    try testing.expect(!tmpHasFile(&tmp, "qa.log"));

    // A foreign empty file lands at the freed pathname.
    {
        const al = try os.fd.appendOpen(testIo(), path);
        os.closeFd(al.fd);
    }

    // Gate completion: the occupant is quarantined untouched and the fresh
    // chain opens exclusively behind chain.break. The absorb needs one
    // extra drain while the occupant's own quarantine rename is flushed.
    w.enqueueInner("\"event\":\"d\"");
    w.drainOnce();
    w.enqueueInner("\"event\":\"e\"");
    w.drainOnce();
    try testing.expect(w.dir_sync_gate == .none);
    try testing.expect(!w.io_failed);

    // Two quarantine asides: the damaged original (non-empty) and the
    // foreign occupant (untouched, still empty).
    var asides: usize = 0;
    var empty_asides: usize = 0;
    var it = tmp.dir.iterate();
    while (try it.next(testIo())) |ent| {
        if (std.mem.startsWith(u8, ent.name, "qa.log.corrupt-")) {
            asides += 1;
            const q = try readAll(arena, try tmpPath(arena, &tmp, ent.name));
            if (q.len == 0) empty_asides += 1;
        }
    }
    try testing.expectEqual(@as(usize, 2), asides);
    try testing.expectEqual(@as(usize, 1), empty_asides);

    // The live chain restarts behind chain.break (seq 0), then e and the
    // dropped marker (lost + c + d).
    const data = try readAll(arena, path);
    const lines = try linesOf(arena, data);
    try testing.expectEqual(@as(usize, 3), lines.len);
    const m0 = parseLineMeta(lines[0]).?;
    try testing.expectEqualStrings("chain.break", m0.event);
    try testing.expectEqual(@as(u64, 0), m0.seq);
    try testing.expectEqualStrings("e", parseLineMeta(lines[1]).?.event);
    try testing.expect(std.mem.indexOf(u8, lines[2], "\"event\":\"dropped\",\"count\":3") != null);
    try expectVerifies(arena, &.{path}, 3, 2);
    stopTestWriter(w);
}

test "audit keyless verify catches a cross-file seq gap" {
    // Keyless files carry no MACs; seq continuity across files is the only
    // tamper signal, so a gap at a file boundary must be reported.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path_a = try tmpPath(arena, &tmp, "kl-a.log");
    const path_b = try tmpPath(arena, &tmp, "kl-b.log");
    const path_c = try tmpPath(arena, &tmp, "kl-c.log");

    {
        var al = try os.fd.appendOpen(testIo(), path_a);
        try os.fd.appendWrite(testIo(), &al, "{\"v\":1,\"seq\":0,\"event\":\"a\"}\n");
        os.closeFd(al.fd);
    }
    {
        var al = try os.fd.appendOpen(testIo(), path_b);
        try os.fd.appendWrite(testIo(), &al, "{\"v\":1,\"seq\":5,\"event\":\"b\"}\n");
        os.closeFd(al.fd);
    }
    const verdict = try verifyFiles(arena, testIo(), &.{ path_a, path_b }, null);
    switch (verdict) {
        .ok => return error.TestUnexpectedResult,
        .broken => |b| try testing.expectEqual(Reason.seq_gap, b.reason),
    }
    // Continuity across the boundary verifies fine.
    {
        var al = try os.fd.appendOpen(testIo(), path_c);
        try os.fd.appendWrite(testIo(), &al, "{\"v\":1,\"seq\":1,\"event\":\"c\"}\n");
        os.closeFd(al.fd);
    }
    const ok = try verifyFiles(arena, testIo(), &.{ path_a, path_c }, null);
    switch (ok) {
        .ok => |o| {
            try testing.expectEqual(@as(u64, 2), o.records);
            try testing.expectEqual(@as(u64, 1), o.last_seq);
        },
        .broken => return error.TestUnexpectedResult,
    }
}
