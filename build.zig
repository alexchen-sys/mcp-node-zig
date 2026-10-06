const std = @import("std");
const zon = @import("build.zig.zon");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    // Opt-in: serve TLS on the hub's node-link listener via mbedTLS.
    // Off by default: the dependency is lazy, so the default build does not
    // even fetch it and stays free of any C code.
    const tls_server = b.option(bool, "tls-server", "Serve TLS on the hub node-link listener (fetches and builds mbedTLS)") orelse false;

    const root = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    if (tls_server) addMbedTls(b, root);

    // Single source of truth for the version string is build.zig.zon;
    // inject it so main.zig never carries a second copy.
    const options = b.addOptions();
    options.addOption([]const u8, "version", zon.version);
    options.addOption(bool, "tls_server", tls_server);
    root.addOptions("build_options", options);

    const exe = b.addExecutable(.{
        .name = "mcp-node",
        .root_module = root,
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Run mcp-node");
    run_step.dependOn(&run_cmd.step);

    const tests = b.addTest(.{ .root_module = root });
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&b.addRunArtifact(tests).step);
}

/// Compile mbedTLS into the module and put its headers plus our TLS config
/// header on the include path. Every library/*.c file is listed: each one
/// is internally guarded by its MBEDTLS_*_C symbol, so disabled features
/// compile to empty objects and the set stays in step with upstream.
fn addMbedTls(b: *std.Build, root: *std.Build.Module) void {
    const mbedtls = b.lazyDependency("mbedtls", .{}) orelse return;
    root.link_libc = true;
    root.addIncludePath(b.path("tls"));
    root.addIncludePath(mbedtls.path("include"));

    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const lib_path = mbedtls.path("library").getPath(b);
    const io = b.graph.io;
    var dir = std.Io.Dir.openDirAbsolute(io, lib_path, .{ .iterate = true }) catch |err|
        std.debug.panic("mbedtls library dir: {s}", .{@errorName(err)});
    defer dir.close(io);
    var files: std.ArrayList([]const u8) = .empty;
    var it = dir.iterate();
    while (it.next(io) catch |err| std.debug.panic("mbedtls library dir: {s}", .{@errorName(err)})) |ent| {
        if (ent.kind == .file and std.mem.endsWith(u8, ent.name, ".c"))
            files.append(arena, arena.dupe(u8, ent.name) catch @panic("oom")) catch @panic("oom");
    }
    std.mem.sort([]const u8, files.items, {}, struct {
        fn lt(_: void, a: []const u8, bb: []const u8) bool {
            return std.mem.lessThan(u8, a, bb);
        }
    }.lt);

    root.addCSourceFiles(.{
        .root = mbedtls.path("library"),
        .files = files.items,
        .flags = &.{
            "-DMBEDTLS_CONFIG_FILE=<mcp_hub_mbedtls_config.h>",
            "-std=c99",
            // The C code is upstream mbedTLS; only upstream warnings matter.
            "-Wno-everything",
        },
    });
    // Our one C file: OS mutex bindings for MBEDTLS_THREADING_ALT. Compiled
    // with warnings on; it is small enough to keep warning-clean.
    root.addCSourceFile(.{
        .file = b.path("tls/mcp_hub_threading.c"),
        .flags = &.{ "-DMBEDTLS_CONFIG_FILE=<mcp_hub_mbedtls_config.h>", "-std=c99" },
    });
    // Windows entropy uses BCryptGenRandom (see mbedtls entropy_poll.c).
    if (root.resolved_target.?.result.os.tag == .windows)
        root.linkSystemLibrary("bcrypt", .{});
}
