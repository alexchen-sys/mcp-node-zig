//! Platform OS layer.
//!
//! Dispatcher selected at comptime by `builtin.os.tag`. All platform
//! knowledge must live behind this module; `main.zig` and the platform modules
//! (env, process, fd+sysinfo, net) call only the narrow API re-exported
//! here.
//!
//! API surface (intentionally minimal):
//!   * `closeFd(fd)`          — close a descriptor/handle, result discarded
//!   * `sleepMs(ms)`          — monotonic-ish sleep on the calling thread
//!   * `writeAllFd(fd, buf)`  — full-buffer write with short-write loop
//!
//! The process-environment surface — see
//! `os/env.zig` for the platform source details:
//!   * `loadEnviron(gpa)`            — one startup snapshot of the environ
//!   * `environGet(arena, env, key)` — unified lookup over the snapshot
//!   * `homeDir(arena, env)`         — "~" expansion source
//!
//! Cross-compile gates registered here:
//! none at this level — the dispatch itself is the only comptime switch.
//! Call-site gates in `main.zig` for not-yet-ported Linux-only code
//! (file I/O, process control, socket options) are annotated
//! inline where they live.

const builtin = @import("builtin");

pub const posix = @import("os/posix.zig");
pub const darwin = @import("os/darwin.zig");
pub const windows = @import("os/windows.zig");

const impl = switch (builtin.os.tag) {
    .windows => windows,
    .macos => darwin,
    // Linux and every other POSIX-like target share the POSIX path.
    else => posix,
};

pub const fd_t = impl.fd_t;
pub const closeFd = impl.closeFd;
pub const sleepMs = impl.sleepMs;
pub const writeAllFd = impl.writeAllFd;
pub const WriteAllError = impl.WriteAllError;
pub const stderrFd = impl.stderrFd;

// Cross-platform process environment. The module does
// its own comptime platform selection (its data source is per-OS, not
// per-POSIX-family), so it is re-exported directly rather than via `impl`.
pub const env = @import("os/env.zig");
pub const loadEnviron = env.loadEnviron;
pub const environGet = env.environGet;
pub const homeDir = env.homeDir;

pub const gate_posix_file_io = builtin.os.tag == .windows;
pub const stub_process_control = builtin.os.tag == .windows;
pub const stub_pipe_poll = builtin.os.tag == .windows;
pub const stub_socket_read = builtin.os.tag == .windows;
pub const stub_socket_options = builtin.os.tag == .windows;

comptime {
    // Fail loudly on targets nobody has thought about instead of silently
    // producing a broken binary: supported targets: linux, macos, windows.
    switch (builtin.os.tag) {
        .linux, .macos, .windows => {},
        else => @compileError("os layer: unsupported target OS (supported: linux, macos, windows)"),
    }
}
