#!/usr/bin/env python3
"""Machine/stand passport for the bench run (methodology: before the numbers).

Collects CPU, RAM, kernel, governor, load, swap, python/node/uvx/npx/zig
versions, binary identity. CPU governor is REPORTED, never changed — a bench
that silently reconfigures the reader's machine is not a bench.
"""
import json
import os
import platform
import subprocess
import sys
import time


def sh(cmd):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        if r.returncode == 0:
            return r.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        pass
    return None


def lscpu():
    out = {}
    for line in (sh(["lscpu"]) or "").splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            out.setdefault(k.strip(), v.strip())
    return out


def gov():
    try:
        with open("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor") as f:
            return f.read().strip()
    except OSError:
        return None


def meminfo():
    out = {}
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                k, _, v = line.partition(":")
                out[k.strip()] = v.strip()
    except OSError:
        pass
    return out


def main():
    bin_path = os.environ.get("MCPNZ_BIN")
    bin_stat = None
    if bin_path and os.path.exists(bin_path):
        st = os.stat(bin_path)
        sha = sh(["sha256sum", bin_path])
        bin_stat = {"path": bin_path, "size_bytes": st.st_size,
                    "sha256": sha.split()[0] if sha else None,
                    "ldd": sh(["ldd", bin_path]) or "(static or no ldd)"}
    out = {
        "date_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "hostname": sh(["hostname"]),
        "os": {
            "kernel": platform.release(),
            "distribution": sh(["bash", "-lc", ". /etc/os-release 2>/dev/null; echo $PRETTY_NAME"]),
        },
        "cpu": {
            "model": lscpu().get("Model name"),
            "cores": lscpu().get("^CPU(s)".lstrip("^")) or lscpu().get("CPU(s)"),
            "max_mhz": lscpu().get("CPU max MHz"),
            "governor": gov(),
        },
        "memory": {
            "MemTotal": meminfo().get("MemTotal"),
            "MemAvailable": meminfo().get("MemAvailable"),
            "SwapTotal": meminfo().get("SwapTotal"),
            "SwapFree": meminfo().get("SwapFree"),
        },
        "load": {
            "uptime": sh(["uptime"]),
            "loadavg": open("/proc/loadavg").read().strip() if os.path.exists("/proc/loadavg") else None,
            "vmstat_1s_x3": sh(["vmstat", "1", "3"]),
        },
        "tools": {
            "python": sys.version.split()[0],
            "node": sh(["node", "--version"]),
            "uvx": sh(["uvx", "--version"]),
            "npx": sh(["npx", "--version"]),
            "zig": sh([os.environ.get("ZIG_BIN", "zig"), "version"]),
        },
        "binary": bin_stat,
        "build_mode": os.environ.get("MCPNZ_BUILD_MODE", "ReleaseSafe"),
    }
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
