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


def cpufreq():
    """Per-CPU current frequency and per-policy governor from /sys cpufreq.

    Returns (freq_mhz_list, governor_per_policy, note). In containers
    /sys/devices/system/cpu/cpufreq is often absent — that is reported as
    an explicit note, never as a silent blank.
    """
    base = "/sys/devices/system/cpu"
    cpus = []
    try:
        cpus = sorted((c for c in os.listdir(base)
                       if c.startswith("cpu") and c[3:].isdigit()),
                      key=lambda c: int(c[3:]))
    except OSError:
        pass
    freqs = []
    for c in cpus:
        try:
            with open(f"{base}/{c}/cpufreq/scaling_cur_freq") as f:
                freqs.append(round(int(f.read().strip()) / 1000.0, 1))  # kHz -> MHz
        except (OSError, ValueError):
            pass
    governors = {}
    policies = []
    try:
        policies = sorted(p for p in os.listdir(f"{base}/cpufreq")
                          if p.startswith("policy"))
    except OSError:
        pass
    for pol in policies:
        try:
            with open(f"{base}/cpufreq/{pol}/scaling_governor") as f:
                governors[pol] = f.read().strip()
        except OSError:
            pass
    note = None
    if not freqs and not governors:
        note = "containerized or cpufreq not exposed: /sys cpufreq absent"
    return freqs, governors, note


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


def loadavg():
    """1/5/15 load averages only — the running/total and last-PID fields
    of /proc/loadavg are host state, not bench evidence."""
    try:
        with open("/proc/loadavg") as f:
            parts = f.read().split()
    except OSError:
        return None
    return " ".join(parts[:3]) or None


def main():
    bin_path = os.environ.get("MCPNZ_BIN")
    bin_stat = None
    if bin_path and os.path.exists(bin_path):
        st = os.stat(bin_path)
        sha = sh(["sha256sum", bin_path])
        bin_stat = {"path": os.path.basename(bin_path), "size_bytes": st.st_size,
                    "sha256": sha.split()[0] if sha else None,
                    "ldd": sh(["ldd", bin_path]) or "(static or no ldd)"}
    freqs, governors, cpufreq_note = cpufreq()
    out = {
        "date_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "os": {
            "kernel": platform.release(),
            "distribution": sh(["bash", "-lc", ". /etc/os-release 2>/dev/null; echo $PRETTY_NAME"]),
        },
        "cpu": {
            "model": lscpu().get("Model name"),
            "cores": lscpu().get("^CPU(s)".lstrip("^")) or lscpu().get("CPU(s)"),
            "max_mhz": lscpu().get("CPU max MHz"),
            "governor": gov(),
            "governor_per_policy": governors or None,
            "cpu_freq_mhz_observed": freqs or None,
            "cpufreq_note": cpufreq_note,
        },
        "memory": {
            "MemTotal": meminfo().get("MemTotal"),
            "MemAvailable": meminfo().get("MemAvailable"),
            "SwapTotal": meminfo().get("SwapTotal"),
            "SwapFree": meminfo().get("SwapFree"),
        },
        "load": {
            "loadavg": loadavg(),
            "vmstat_1s_x3": sh(["vmstat", "1", "3"]),
        },
        "tools": {
            "python": sys.version.split()[0],
            "node": sh(["node", "--version"]),
            "uvx": sh([os.environ.get("UVX_BIN", "uvx"), "--version"]),
            "npx": sh([os.environ.get("NPX_BIN", "npx"), "--version"]),
            "zig": sh([os.environ.get("ZIG_BIN", "zig"), "version"]),
        },
        "binary": bin_stat,
        "build_mode": os.environ.get("MCPNZ_BUILD_MODE", "ReleaseSafe"),
    }
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
