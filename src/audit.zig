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
//! MCP_NODE_AUDIT_MAX_BYTES the file rotates to `<path>.<first-seq>` and
//! the chain continues in a fresh file opened with a `rotate` record.
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

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const VERSION: []const u8 = @import("build_options").version;

/// Bytes of one ring slot: the largest possible canonical line.
pub const MAX_RECORD: usize = 2048;
/// Largest event inner (everything between the common prefix and prev/mac).
pub const MAX_INNER: usize = 1700;
pub const RING_SLOTS: usize = 1024;
pub const BATCH_MAX: usize = 64;
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
};

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
                    const seq_len = utf8SeqLen(s[i..]) orelse {
                        self.append("\xef\xbf\xbd");
                        i += 1;
                        continue;
                    };
                    if (i + seq_len > s.len or !validUtf8Seq(s[i .. i + seq_len])) {
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

// ---------------------------------------------------------------------------
// Canonical argument digest and the per-tool summary allowlist
// ---------------------------------------------------------------------------

const Value = std.json.Value;

/// sha256 over the canonical argument JSON (compact, object keys in
/// as-received order), streamed so a multi-MiB write_file body costs no
/// memory. The digest identifies the exact arguments without storing them.
pub fn argsDigestHex(args: Value) [MAC_HEX_LEN]u8 {
    var h = Sha256.init(.{});
    hashJsonCanon(&h, args, 0);
    const digest = h.finalResult();
    var out: [MAC_HEX_LEN]u8 = undefined;
    const alphabet = "0123456789abcdef";
    for (digest, 0..) |b, i| {
        out[i * 2] = alphabet[b >> 4];
        out[i * 2 + 1] = alphabet[b & 0x0f];
    }
    return out;
}

fn hashJsonCanon(h: *Sha256, v: Value, depth: u8) void {
    if (depth > 32) {
        h.update("null");
        return;
    }
    var num_buf: [40]u8 = undefined;
    switch (v) {
        .null => h.update("null"),
        .bool => |b| h.update(if (b) "true" else "false"),
        .integer => |i| h.update(std.fmt.bufPrint(&num_buf, "{d}", .{i}) catch "0"),
        .float => |f| h.update(std.fmt.bufPrint(&num_buf, "{d}", .{f}) catch "0"),
        .number_string => |s| h.update(s),
        .string => |s| {
            hashJsonString(h, s);
        },
        .array => |arr| {
            h.update("[");
            for (arr.items, 0..) |item, i| {
                if (i != 0) h.update(",");
                hashJsonCanon(h, item, depth + 1);
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
                hashJsonCanon(h, kv.value_ptr.*, depth + 1);
            }
            h.update("}");
        },
    }
}

/// Hash the JSON string literal form of `s` with Buf's escaping rules.
fn hashJsonString(h: *Sha256, s: []const u8) void {
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
                const seq_len = utf8SeqLen(s[i..]) orelse {
                    h.update("\xef\xbf\xbd");
                    i += 1;
                    continue;
                };
                if (i + seq_len > s.len or !validUtf8Seq(s[i .. i + seq_len])) {
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

fn objInt(args: Value, key: []const u8) ?i64 {
    if (args != .object) return null;
    const v = args.object.get(key) orelse return null;
    return switch (v) {
        .integer => |i| i,
        .float => |f| blk: {
            const i: i64 = @intFromFloat(f);
            break :blk i;
        },
        else => null,
    };
}

/// Per-tool argument summary, appended as a JSON object. The allowlist is
/// the design's: argv[0]+argc for exec/exec_start (full argv in `full`
/// mode), shell+script length for exec_shell, path(+size) for
/// read_file/write_file/list_dir, session_id for the session tools.
/// Scripts, file contents and stdout are never logged in any mode.
pub fn appendArgsSummary(buf: *Buf, tool: []const u8, args: Value, mode: ArgsMode) void {
    const start_len = buf.len;
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
                // Stop before the summary exceeds its byte budget.
                if (buf.len - start_len + item.string.len + 16 > SUMMARY_CAP) {
                    truncated = true;
                    break;
                }
                if (!first) buf.append(",");
                first = false;
                buf.jsonStrCap(item.string, 256);
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
/// REQ_ID_MAX bytes of JSON (escape-safe, closing quote preserved).
pub fn renderReqId(buf: *Buf, id: Value) void {
    const id_start = buf.len;
    appendJsonValueCanon(buf, id);
    const rendered = buf.data[id_start..buf.len];
    if (rendered.len <= REQ_ID_MAX) return;
    // Truncate: strings keep a valid closing quote; anything else is cut
    // on a plain boundary (numbers stay valid literals).
    if (rendered.len > 0 and rendered[0] == '"') {
        var cut: usize = REQ_ID_MAX - 2;
        // Never cut right after a backslash or inside a \uXXXX escape.
        while (cut > 0 and rendered[cut - 1] == '\\') cut -= 1;
        if (cut >= 2) {
            // inside \uXXXX? walk back over hex digits preceded by \u
            var k = cut;
            while (k >= 2 and k > cut -| 6 and std.ascii.isHex(rendered[k - 1])) k -= 1;
            if (k >= 2 and rendered[k - 1] == 'u' and rendered[k - 2] == '\\') cut = k - 2;
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

pub const Writer = struct {
    gpa: Allocator,
    io: Io,
    log: os.fd.AppendLog,
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
            // drain side emits the chained `dropped` marker.
            self.dropped += 1;
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
        // Snapshot the chain state: a failed write rolls seq/prev/pos back
        // so the on-disk chain keeps exact continuity, and the lost records
        // surface as a chained `dropped` record on the next good batch.
        const seq0 = self.seq;
        const prev0 = self.prev;
        const pos0 = self.log.pos;
        var batch: [BATCH_MAX * MAX_RECORD + MAX_RECORD]u8 = undefined;
        var blen: usize = 0;
        var line: Buf = undefined;
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
        os.fd.appendWrite(self.io, &self.log, batch[0..blen]) catch |err| {
            self.io_failed = true;
            self.seq = seq0;
            self.prev = prev0;
            self.dropped += n + dropped_here;
            // A partial write leaves a torn tail; cut back to the last good
            // offset so the next batch never glues onto garbage.
            os.fd.truncFile(self.log.fd, pos0) catch {};
            self.log.pos = pos0;
            std.debug.print("audit: write failed: {s}\n", .{@errorName(err)});
            return;
        };
        os.fd.syncFile(self.log.fd) catch |err| {
            self.io_failed = true;
            std.debug.print("audit: fsync failed: {s}\n", .{@errorName(err)});
        };
        if (self.log.pos >= self.max_bytes) self.rotate();
    }

    /// Size rotation, called by the draining side only, between batches so
    /// the cut lands on a record boundary. The old file is renamed to
    /// `<path>.<first-seq>` and the chain continues in a fresh file whose
    /// first record is `rotate` (its `prev` links the two files). The old fd
    /// is closed before the rename because Windows forbids renaming an open
    /// file; a failed reopen renames back and reopens, so failures keep the
    /// current fd: the log grows past the limit instead of losing records,
    /// and the next batch retries.
    fn rotate(self: *Writer) void {
        var name_buf: [512]u8 = undefined;
        const rotated = std.fmt.bufPrint(&name_buf, "{s}.{d}", .{ self.path, self.file_first_seq }) catch return;
        os.fd.syncFile(self.log.fd) catch {};
        const old_fd = self.log.fd;
        os.closeFd(old_fd);
        os.fd.renamePath(self.io, self.path, rotated) catch {
            // Rename failed with the fd already closed: reopen the live file
            // so the next batch still has somewhere to write.
            self.log = os.fd.appendOpen(self.io, self.path) catch {
                self.io_failed = true;
                return;
            };
            return;
        };
        const new_log = os.fd.appendOpen(self.io, self.path) catch {
            // Reopen failed: put the old name back and reopen it; records
            // keep flowing to the same file either way.
            os.fd.renamePath(self.io, rotated, self.path) catch {};
            self.log = os.fd.appendOpen(self.io, self.path) catch {
                self.io_failed = true;
                return;
            };
            return;
        };
        self.log = new_log;
        self.file_first_seq = self.seq;
        const seq0 = self.seq;
        const prev0 = self.prev;
        var inner: Buf = undefined;
        inner.reset();
        inner.append("\"event\":\"rotate\",\"rotated\":");
        inner.jsonStrCap(rotated, 384);
        var line: Buf = undefined;
        self.composeLine(inner.slice(), &line);
        os.fd.appendWrite(self.io, &self.log, line.slice()) catch {
            self.seq = seq0;
            self.prev = prev0;
            self.io_failed = true;
            return;
        };
        os.fd.syncFile(self.log.fd) catch {};
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
            while (w.count == 0 and !w.stopping)
                w.not_empty.waitUncancelable(w.io, &w.mutex);
            if (w.count == 0 and w.stopping) break;
            partial = w.count < BATCH_MAX;
        }
        // Batch settle: a short beat lets a trickle-burst accumulate into
        // one write+fsync; a full ring skips it (throughput over latency).
        if (partial) os.sleepMs(BATCH_SETTLE_MS);
        w.drainOnce();
        w.mutex.lockUncancelable(w.io);
        const done = w.stopping and w.count == 0;
        w.mutex.unlock(w.io);
        if (done) break;
    }
    // Final fsync so a clean stop leaves nothing in the kernel page cache.
    os.fd.syncFile(w.log.fd) catch {};
}

/// Open the log, recover the tail chain, start the writer thread and record
/// the start event. On a corrupt tail the old file is renamed to
/// `<path>.corrupt-<epoch ms>` and the new file opens with chain.break.
pub fn start(gpa: Allocator, io: Io, opts: Options) !*Writer {
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
    recoverTail(gpa, io, w) catch |err| switch (err) {
        error.CorruptTail => broke = true,
        else => return err,
    };
    if (broke) {
        // Move the damaged file aside for forensics and start a new chain.
        os.closeFd(w.log.fd);
        log_open = false;
        var name_buf: [512]u8 = undefined;
        const aside = std.fmt.bufPrint(&name_buf, "{s}.corrupt-{d}", .{ opts.path, Io.Clock.real.now(io).toMilliseconds() }) catch return error.NameTooLong;
        try os.fd.renamePath(io, opts.path, aside);
        log = try os.fd.appendOpen(io, opts.path);
        log_open = true;
        w.log = log;
        w.seq = 0;
        w.prev = ZERO_PREV.*;
        var inner: Buf = undefined;
        inner.reset();
        inner.append("\"event\":\"chain.break\",\"reason\":\"tail_verify_failed\",\"lost_file\":");
        inner.jsonStrCap(aside, 128);
        w.enqueueInner(inner.slice());
    }
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
    os.closeFd(w.log.fd);
    w.gpa.destroy(w);
}

// ---------------------------------------------------------------------------
// Startup tail recovery
// ---------------------------------------------------------------------------

const Recovery = struct { seq: u64, prev: [MAC_HEX_LEN]u8 };

fn recoverTail(gpa: Allocator, io: Io, w: *Writer) !void {
    const size = try os.fd.fileLength(io, w.log.fd);
    if (size == 0) return; // fresh file: seq 0, zero prev
    const window: usize = @intCast(@min(size, TAIL_WINDOW));
    const buf = try gpa.alloc(u8, window);
    defer gpa.free(buf);
    const got = try os.fd.preadAt(io, w.log.fd, buf, size - window);
    const data = buf[0..got];

    // A torn final line (killed mid-write) is cut back to the last newline.
    var end = got;
    if (got > 0 and data[got - 1] != '\n') {
        const last_nl = std.mem.lastIndexOfScalar(u8, data, '\n') orelse {
            if (size > window) return error.CorruptTail; // no boundary in window
            try os.fd.truncFile(w.log.fd, 0);
            w.log.pos = 0;
            return; // single partial line in a fresh file: truncate, start over
        };
        const keep: u64 = size - got + last_nl + 1;
        try os.fd.truncFile(w.log.fd, keep);
        w.log.pos = keep;
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
    const head_got = try os.fd.preadAt(io, w.log.fd, &head_buf, 0);
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
/// `,"mac":"..."}` and compare. No JSON re-serialization anywhere.
fn verifyLineMac(line: []const u8, mac_hex: []const u8, key: []const u8) bool {
    if (line.len < 74) return false;
    const covered = line[0 .. line.len - 74];
    var mac: [32]u8 = undefined;
    HmacSha256.create(&mac, covered, key);
    var expect: [64]u8 = undefined;
    const alphabet = "0123456789abcdef";
    for (mac, 0..) |b, i| {
        expect[i * 2] = alphabet[b >> 4];
        expect[i * 2 + 1] = alphabet[b & 0x0f];
    }
    return std.mem.eql(u8, mac_hex, &expect);
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
    mac_mismatch,
    mixed_chain_mode,
    key_required,
    chain_required,
    oversize_record,
};

/// Verify files in the given order: seq continuity, prev links across file
/// boundaries (a rotated file's first prev must be the previous file's last
/// mac), and every MAC over the exact line bytes. A file that starts with
/// 64 zero prev begins a fresh chain (first run, or after chain.break).
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
                            } else if (std.mem.eql(u8, prev, ZERO_PREV)) {
                                expect_seq = meta.seq; // fresh chain (start or chain.break)
                            } else {
                                return .{ .broken = .{ .file_index = file_index, .seq = meta.seq, .reason = .prev_mismatch } };
                            }
                        } else {
                            expect_seq = meta.seq;
                        }
                    } else {
                        expect_seq = meta.seq;
                    }
                }
                if (expect_seq) |e| {
                    if (meta.seq != e)
                        return .{ .broken = .{ .file_index = file_index, .seq = e, .reason = .seq_gap } };
                } else {
                    expect_seq = meta.seq;
                }
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
                return 1;
            };
            const raw = os.fd.readFileAlloc(arena, io, kf, 64 * 1024) catch |err| {
                std.debug.print("audit-verify: cannot read key file: {s}\n", .{@errorName(err)});
                return 1;
            };
            const trimmed = std.mem.trim(u8, raw, " \t\r\n");
            if (trimmed.len == 0) {
                std.debug.print("audit-verify: key file is empty\n", .{});
                return 1;
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
    buf.append(&digest);
    buf.append("\",\"args_summary\":");
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
    h.update(cfg.name);
    h.update(@tagName(cfg.mode));
    h.update(cfg.host);
    h.update(std.fmt.bufPrint(&nb, "{d}", .{cfg.port}) catch "");
    h.update(std.fmt.bufPrint(&nb, "{d}", .{cfg.max_out}) catch "");
    h.update(std.fmt.bufPrint(&nb, "{d}", .{cfg.socket_timeout_s}) catch "");
    h.update(std.fmt.bufPrint(&nb, "{d}", .{cfg.max_conn}) catch "");
    h.update(std.fmt.bufPrint(&nb, "{d}", .{cfg.max_sessions}) catch "");
    h.update(std.fmt.bufPrint(&nb, "{d}", .{cfg.session_ttl_s}) catch "");
    h.update(std.fmt.bufPrint(&nb, "{d}", .{cfg.max_inflight_bytes}) catch "");
    h.update(if (cfg.text_mirror) "1" else "0");
    for (cfg.allowed_hosts) |ho| {
        h.update(ho);
        h.update(",");
    }
    for (cfg.allowed_origins) |o| {
        h.update(o);
        h.update(",");
    }
    h.update(cfg.token_file);
    // Secret material never enters the fingerprint; the file PATHS do, so a
    // rotated link secret or token file shows up in the next start record.
    h.update(cfg.connect_secret_file);
    h.update(cfg.hub_secret_file);
    if (cfg.connect) |ep| {
        h.update(ep.host);
        h.update(std.fmt.bufPrint(&nb, "{d}", .{ep.port}) catch "");
    }
    if (cfg.hub_listen) |ep| {
        h.update(ep.host);
        h.update(std.fmt.bufPrint(&nb, "{d}", .{ep.port}) catch "");
    }
    if (cfg.hub_tls_cert_file) |f| h.update(f);
    if (cfg.audit_file) |f| h.update(f);
    h.update(@tagName(cfg.audit_args));
    h.update(@tagName(cfg.audit_on_full));
    h.update(std.fmt.bufPrint(&nb, "{d}", .{cfg.audit_max_bytes}) catch "");
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

fn appendTs(buf: *Buf, ms: i64) void {
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
    os.closeFd(w.log.fd);
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
    os.closeFd(w.log.fd);
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
    os.closeFd(w2.log.fd);

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
    os.closeFd(w2.log.fd);

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
    os.closeFd(w.log.fd);
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
    os.closeFd(w.log.fd);
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
    os.closeFd(w.log.fd);
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
    os.closeFd(w.log.fd);
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
    os.closeFd(w.log.fd);

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
    os.closeFd(w2.log.fd);
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
    os.closeFd(w.log.fd);
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
    os.closeFd(w.log.fd);
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
    os.closeFd(w.log.fd);
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
    os.closeFd(w.log.fd);

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
    os.closeFd(w2.log.fd);

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
    os.closeFd(w.log.fd);

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
    os.closeFd(w.log.fd);

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
    os.closeFd(w2.log.fd);

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
    os.closeFd(w.log.fd);
    const data = try readAll(arena, path);
    // 2026-01-01T00:00:00Z in epoch ms: any CI runner is newer than that.
    const cutoff: i64 = 1767225600000;
    try testing.expect(w.nowMs() > cutoff);
    try testing.expect(std.mem.indexOf(u8, data, "\"ts\":\"202") != null);
}
