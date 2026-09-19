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
//! Connected-socket I/O, per-operation timeouts and
//! socket options live in `os/net.zig`, re-exported below as `os.net`.
//!
//! Cross-compile gates registered here:
//! none at this level — the dispatch itself is the only comptime switch.
//! Call-site gates in `main.zig` for not-yet-ported Linux-only code
//! (environ, file I/O, process control) are annotated inline where they
//! live.

const builtin = @import("builtin");

pub const posix = @import("os/posix.zig");
pub const darwin = @import("os/darwin.zig");
pub const windows = @import("os/windows.zig");

/// Connected-socket I/O, timeouts and socket options.
pub const net = @import("os/net.zig");

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

pub const gate_posix_file_io = builtin.os.tag == .windows;
pub const stub_process_control = builtin.os.tag == .windows;
pub const stub_pipe_poll = builtin.os.tag == .windows;

comptime {
    // Fail loudly on targets nobody has thought about instead of silently
    // producing a broken binary: supported targets: linux, macos, windows.
    switch (builtin.os.tag) {
        .linux, .macos, .windows => {},
        else => @compileError("os layer: unsupported target OS (supported: linux, macos, windows)"),
    }
}
