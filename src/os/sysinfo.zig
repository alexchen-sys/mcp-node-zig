//! Per-OS sysinfo fetchers.
//!
//! Best-effort contract: every field degrades independently to "" / 0 on
//! failure and `fetch` itself never fails. All OSes emit the same JSON
//! fields, filled from their native sources (loadavg_raw/uptime_raw stay
//! empty where the OS has no analog).

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const Io = std.Io;

const fd = @import("fd.zig");

/// OS name reported in the sys_info payload, fixed at comptime per target.
pub const os_name: []const u8 = switch (builtin.os.tag) {
    .linux => "Linux",
    .macos => "macOS",
    .windows => "Windows",
    else => @tagName(builtin.os.tag),
};
pub const machine: []const u8 = @tagName(builtin.cpu.arch);

pub const SysInfo = struct {
    hostname: []const u8 = "",
    loadavg_raw: []const u8 = "",
    uptime_raw: []const u8 = "",
    /// Total physical memory in bytes; 0 when unknown.
    mem_total: u64 = 0,
    /// Available physical memory in bytes; 0 when unknown.
    mem_available: u64 = 0,
};

pub fn fetch(arena: Allocator, io: Io) SysInfo {
    return switch (builtin.os.tag) {
        .linux => fetchLinux(arena, io),
        .macos => fetchDarwin(arena, io),
        .windows => fetchWindows(arena),
        // os.zig compile-errors on other targets; this prong is never
        // analyzed on the three supported ones.
        else => .{},
    };
}

// ---------------------------------------------------------------------------
// Linux: everything comes from /proc.
// ---------------------------------------------------------------------------

fn fetchLinux(arena: Allocator, io: Io) SysInfo {
    var info: SysInfo = .{};
    info.hostname = std.mem.trim(u8, fd.readFileAlloc(arena, io, "/proc/sys/kernel/hostname", 256) catch "", "\r\n ");
    info.loadavg_raw = std.mem.trim(u8, fd.readFileAlloc(arena, io, "/proc/loadavg", 256) catch "", "\r\n ");
    info.uptime_raw = std.mem.trim(u8, fd.readFileAlloc(arena, io, "/proc/uptime", 256) catch "", "\r\n ");
    const meminfo = fd.readFileAlloc(arena, io, "/proc/meminfo", 16384) catch "";
    var it = std.mem.splitScalar(u8, meminfo, '\n');
    while (it.next()) |line| {
        if (std.mem.startsWith(u8, line, "MemTotal:")) info.mem_total = parseKbLine(line) * 1024;
        if (std.mem.startsWith(u8, line, "MemAvailable:")) info.mem_available = parseKbLine(line) * 1024;
    }
    return info;
}

/// Parse a "/proc/meminfo"-style line ("MemTotal:       16384 kB") into the
/// kB value (only sysinfo uses it).
fn parseKbLine(line: []const u8) u64 {
    var it = std.mem.tokenizeScalar(u8, line, ' ');
    _ = it.next();
    const num = it.next() orelse return 0;
    return std.fmt.parseInt(u64, num, 10) catch 0;
}

// ---------------------------------------------------------------------------
// macOS: gethostname + sysctlbyname + host_statistics64. Darwin always links
// libSystem, so std.c externs and the mach IPC flavor of host statistics
// resolve on every Apple target.
// ---------------------------------------------------------------------------

/// XNU `struct loadavg` (bsd/sys/loadavg.h): fixed-point averages + scale.
const DarwinLoadavg = extern struct {
    ldavg: [3]u32, // fixpt_t = u_int32_t
    fscale: c_long,
};

/// XNU `struct timeval` as returned by the kern.boottime sysctl.
const DarwinTimeval = extern struct {
    sec: c_long, // time_t
    usec: c_int, // suseconds_t
};

/// XNU `struct vm_statistics64` (mach/vm_statistics.h), natural_t = u32.
const VmStatistics64 = extern struct {
    free_count: c_uint,
    active_count: c_uint,
    inactive_count: c_uint,
    wire_count: c_uint,
    zero_fill_count: u64,
    reactivations: u64,
    pageins: u64,
    pageouts: u64,
    faults: u64,
    copy_on_write: u64,
    object_lookups: u64,
    object_hits: u64,
    purgeable_count: u64,
    purges: u64,
    speculative_count: u64,
    decompressions: u64,
    compressions: u64,
    swapins: u64,
    swapouts: u64,
    compressor_page_count: c_uint,
    throttled_count: c_uint,
    external_page_count: c_uint,
    internal_page_count: c_uint,
    total_uncompressed_pages_in_compressor: u64,
};

const HOST_VM_INFO64: c_int = 4;
const HOST_VM_INFO64_COUNT: c_uint = @sizeOf(VmStatistics64) / @sizeOf(c_uint);

// Not wrapped by std 0.16; kern_return_t = c_int.
extern "c" fn host_statistics64(host: c_uint, flavor: c_int, info: *VmStatistics64, count: *c_uint) c_int; // host: mach_port_t

fn fetchDarwin(arena: Allocator, io: Io) SysInfo {
    var info: SysInfo = .{};
    info.hostname = darwinHostname(arena);
    info.loadavg_raw = darwinLoadavg(arena);
    info.uptime_raw = darwinUptime(arena, io);
    darwinMeminfo(&info);
    return info;
}

fn darwinHostname(arena: Allocator) []const u8 {
    var buf: [256]u8 = undefined; // CTL_HOSTNAME max is 255 + NUL
    if (std.c.gethostname(&buf, buf.len) != 0) return "";
    // gethostname(3) may skip the NUL on truncation; bound the scan.
    const len = std.mem.indexOfScalar(u8, &buf, 0) orelse buf.len;
    return arena.dupe(u8, buf[0..len]) catch "";
}

fn darwinLoadavg(arena: Allocator) []const u8 {
    var la: DarwinLoadavg = undefined;
    var size: usize = @sizeOf(DarwinLoadavg);
    if (std.c.sysctlbyname("vm.loadavg", &la, &size, null, 0) != 0) return "";
    if (size < @sizeOf(DarwinLoadavg)) return "";
    const scale: f64 = @floatFromInt(la.fscale);
    if (scale == 0) return "";
    return std.fmt.allocPrint(arena, "{d:.2} {d:.2} {d:.2}", .{
        @as(f64, @floatFromInt(la.ldavg[0])) / scale,
        @as(f64, @floatFromInt(la.ldavg[1])) / scale,
        @as(f64, @floatFromInt(la.ldavg[2])) / scale,
    }) catch "";
}

fn darwinUptime(arena: Allocator, io: Io) []const u8 {
    var boot: DarwinTimeval = undefined;
    var size: usize = @sizeOf(DarwinTimeval);
    if (std.c.sysctlbyname("kern.boottime", &boot, &size, null, 0) != 0) return "";
    if (size < @sizeOf(DarwinTimeval)) return "";
    const now_us = @divTrunc(std.Io.Clock.real.now(io).nanoseconds, std.time.ns_per_us);
    const boot_us = @as(i96, boot.sec) * std.time.us_per_s + boot.usec;
    const up_us = now_us - boot_us;
    if (up_us < 0) return ""; // clock moved backwards across boot time
    return std.fmt.allocPrint(arena, "{d}.{d:0>2}", .{
        @divTrunc(up_us, std.time.us_per_s),
        @divTrunc(@mod(up_us, std.time.us_per_s), 10_000), // hundredths of a second
    }) catch "";
}

fn darwinMeminfo(info: *SysInfo) void {
    var memsize: u64 = 0;
    var size: usize = @sizeOf(u64);
    if (std.c.sysctlbyname("hw.memsize", &memsize, &size, null, 0) == 0) {
        info.mem_total = memsize;
    }
    var pagesize: u64 = 0;
    size = @sizeOf(u64);
    if (std.c.sysctlbyname("hw.pagesize", &pagesize, &size, null, 0) != 0 or pagesize == 0) return;
    var stats: VmStatistics64 = undefined;
    var count: c_uint = HOST_VM_INFO64_COUNT;
    if (host_statistics64(std.c.mach_host_self(), HOST_VM_INFO64, &stats, &count) != 0) return;
    // No official "available" counter on Darwin; free + inactive is the
    // standard approximation (inactive pages are reclaimable on pressure).
    info.mem_available = (@as(u64, stats.free_count) + stats.inactive_count) * pagesize;
}

// ---------------------------------------------------------------------------
// Windows: kernel32 externs (std 0.16 does not wrap these three).
// ---------------------------------------------------------------------------

extern "kernel32" fn GetTickCount64() u64;
extern "kernel32" fn GetComputerNameW(buffer: [*]u16, size: *u32) i32;
extern "kernel32" fn GlobalMemoryStatusEx(status: *MemoryStatusEx) i32;

/// Win32 MEMORYSTATUSEX.
const MemoryStatusEx = extern struct {
    length: u32,
    memory_load: u32,
    total_phys: u64,
    avail_phys: u64,
    total_page_file: u64,
    avail_page_file: u64,
    total_virtual: u64,
    avail_virtual: u64,
    avail_extended_virtual: u64,
};

fn fetchWindows(arena: Allocator) SysInfo {
    var info: SysInfo = .{};
    info.hostname = windowsHostname(arena);
    // No native load-average analog on Windows: loadavg_raw stays "".
    info.uptime_raw = windowsUptime(arena);
    var status: MemoryStatusEx = .{
        .length = @sizeOf(MemoryStatusEx),
        .memory_load = 0,
        .total_phys = 0,
        .avail_phys = 0,
        .total_page_file = 0,
        .avail_page_file = 0,
        .total_virtual = 0,
        .avail_virtual = 0,
        .avail_extended_virtual = 0,
    };
    if (GlobalMemoryStatusEx(&status) != 0) {
        info.mem_total = status.total_phys;
        info.mem_available = status.avail_phys;
    }
    return info;
}

fn windowsHostname(arena: Allocator) []const u8 {
    var buf: [256]u16 = undefined; // MAX_COMPUTERNAME_LENGTH is 15; ample
    var len: u32 = buf.len; // in: buffer size in chars; out: chars w/o NUL
    if (GetComputerNameW(&buf, &len) == 0) return "";
    if (len > buf.len) return ""; // defensive: never trust an out-param
    return std.unicode.wtf16LeToWtf8Alloc(arena, buf[0..len]) catch "";
}

fn windowsUptime(arena: Allocator) []const u8 {
    const ms = GetTickCount64();
    return std.fmt.allocPrint(arena, "{d}.{d:0>2}", .{ ms / std.time.ms_per_s, (ms % std.time.ms_per_s) / 10 }) catch "";
}
