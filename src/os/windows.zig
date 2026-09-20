//! Windows platform path.
//!
//! `std.posix.fd_t` is a `HANDLE` here, so `closeFd` maps to
//! `std.os.windows.CloseHandle`; writes go through `WriteFile`.

const std = @import("std");

pub const fd_t = std.posix.fd_t; // HANDLE on Windows

extern "kernel32" fn Sleep(dwMilliseconds: u32) void;
extern "kernel32" fn GetStdHandle(nStdHandle: u32) ?std.os.windows.HANDLE;
extern "kernel32" fn WriteFile(
    hFile: std.os.windows.HANDLE,
    lpBuffer: [*]const u8,
    nNumberOfBytesToWrite: u32,
    lpNumberOfBytesWritten: ?*u32,
    lpOverlapped: ?*anyopaque,
) callconv(.winapi) i32;

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

/// TODO: works, but should be re-evaluated against
/// std.Io.sleep or a waitable timer instead of a bare
/// kernel32 Sleep.
pub fn sleepMs(ms: u64) void {
    Sleep(@intCast(ms));
}

pub const WriteAllError = error{WriteFailed};

/// Write the whole buffer to a synchronous handle (stderr, files, pipe
/// write ends opened without FILE_FLAG_OVERLAPPED). Loops on short writes.
pub fn writeAllFd(fd: fd_t, bytes: []const u8) WriteAllError!void {
    var off: usize = 0;
    while (off < bytes.len) {
        const chunk: u32 = @intCast(@min(bytes.len - off, 1 << 30));
        var written: u32 = 0;
        if (WriteFile(fd, bytes.ptr + off, chunk, &written, null) == 0)
            return error.WriteFailed;
        if (written == 0) return error.WriteFailed;
        off += written;
    }
}
