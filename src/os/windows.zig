//! Windows platform path.
//!
//! Only `closeFd` is a real implementation (std exposes
//! `std.os.windows.CloseHandle`, and on Windows `std.posix.fd_t` is a
//! `HANDLE`). The other two entry points are documented stubs so the file
//! compiles for `x86_64-windows-gnu`; real implementations land with their
//! respective follow-ups.

const std = @import("std");

pub const fd_t = std.posix.fd_t; // HANDLE on Windows

extern "kernel32" fn Sleep(dwMilliseconds: u32) void;
extern "kernel32" fn GetStdHandle(nStdHandle: u32) ?std.os.windows.HANDLE;

/// Win32 STD_ERROR_HANDLE constant: (DWORD)-12.
const STD_ERROR_HANDLE: u32 = 0xffff_fff4;

/// Handle of the process standard error stream. Real implementation
/// (kernel32 GetStdHandle); std 0.16 does not wrap it.
pub fn stderrFd() fd_t {
    return GetStdHandle(STD_ERROR_HANDLE) orelse std.os.windows.INVALID_HANDLE_VALUE;
}

/// Close a handle. Real implementation: CloseHandle is the Windows
/// equivalent of close(2) for both files and pipes.
pub fn closeFd(fd: fd_t) void {
    std.os.windows.CloseHandle(fd);
}

/// TODO: works, but should be re-evaluated together with the
/// timer/Io side (std.Io.sleep or a waitable timer) instead of a bare
/// kernel32 Sleep.
pub fn sleepMs(ms: u64) void {
    Sleep(@intCast(ms));
}

pub const WriteAllError = error{WriteFailed};

/// TODO: real implementation is a WriteFile loop over
/// `std.os.windows.WriteFile`. Returns an error instead
/// of silently succeeding so no caller can mistake the stub for a working
/// write.
pub fn writeAllFd(fd: fd_t, bytes: []const u8) WriteAllError!void {
    _ = fd;
    _ = bytes;
    return error.WriteFailed;
}
