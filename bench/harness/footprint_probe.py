#!/usr/bin/env python3
"""Delivery footprint probe (methodology b08).

mcp-node-zig: the shipped artifact is one static binary; we stat it.

Rivals: a "standard install" via their documented channels (uvx / npx) puts
a package environment on the machine plus a language runtime to interpret
it. We resolve the real paths from a live process (/proc/<pid>/environ,
exe, cmdline) and du -sb them, so the numbers trace to what the installer
actually laid down on this box.
"""
import argparse
import json
import os
import subprocess
import sys

sys.path.insert(0, __file__.rsplit("/", 1)[0])
import probe_lib as pl  # noqa: E402


def du_bytes(path):
    if not path or not os.path.exists(path):
        return None
    r = subprocess.run(["du", "-sb", path], capture_output=True, text=True)
    if r.returncode != 0:
        return None
    return int(r.stdout.split()[0])


def read_cmdline(pid):
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            return [c.decode() for c in f.read().split(b"\0") if c]
    except OSError:
        return []


def exe_of(pid):
    try:
        return os.path.realpath(f"/proc/{pid}/exe")
    except OSError:
        return None


def mib(b):
    return round(b / (1024 * 1024), 1) if b else None


def probe_ours(bin_path, build_mode):
    st = os.stat(bin_path)
    return {
        "participant": "mcp-node-zig",
        "artifact": bin_path,
        "build_mode": build_mode,
        "binary_bytes": st.st_size,
        "binary_mib": mib(st.st_size),
        "runtime_bytes": 0,
        "runtime_mib": 0.0,
        "notes": "static binary, no runtime to install (Linux: no libc dependency)",
    }


def probe_tumf():
    argv = ["uvx", "mcp-shell-server"]
    cli = pl.StdioMcpClient(argv, env_extra={"ALLOW_COMMANDS": "uname"})
    resp, _ = cli.request("initialize", pl.initialize_params())
    if resp is None:
        cli.close()
        return {"participant": "tumf/mcp-shell-server", "error": "initialize failed"}
    version = resp.get("result", {}).get("serverInfo", {}).get("version")
    tree = pl.tree_pids(cli.p.pid)
    venv, interp, interp_install = None, None, None
    for pid in tree:
        cmd = read_cmdline(pid)
        exe = exe_of(pid)
        if exe:
            interp = exe
        # uvx runs the server from a cached venv: <uv-cache>/archive-v0/<hash>/bin/python
        for part in cmd:
            if "/archive-v0/" in part:
                idx = part.find("/archive-v0/") + len("/archive-v0/")
                rest = part[idx:].split("/", 1)[0]
                if rest:
                    venv = part[:part.find("/archive-v0/") + len("/archive-v0/") + len(rest)]
                    break
        if venv:
            break
    cli.close()

    # the interpreter uvx actually resolved may be its own managed CPython
    if interp and "/.local/share/uv/python/" in interp:
        idx = interp.find("/.local/share/uv/python/") + len("/.local/share/uv/python/")
        rest = interp[idx:].split("/", 1)[0]
        interp_install = interp[:interp.find("/.local/share/uv/python/") + len("/.local/share/uv/python/") + len(rest)]

    uv_cache = None
    r = subprocess.run(["uv", "cache", "dir"], capture_output=True, text=True)
    if r.returncode == 0:
        uv_cache = r.stdout.strip()
    return {
        "participant": "tumf/mcp-shell-server",
        "version": version,
        "channel": "uvx",
        "venv": venv,
        "venv_bytes": du_bytes(venv),
        "venv_mib": mib(du_bytes(venv)),
        "uv_cache": uv_cache,
        "uv_cache_bytes": du_bytes(uv_cache),
        "uv_cache_mib": mib(du_bytes(uv_cache)),
        "interpreter": interp,
        "interpreter_install": interp_install,
        "runtime_bytes": du_bytes(interp_install) if interp_install else (du_bytes(interp) if interp else None),
        "runtime_mib": mib(du_bytes(interp_install)) if interp_install else (mib(du_bytes(interp)) if interp else None),
        "runtime_kind": "Python interpreter uvx resolved for the venv",
        "notes": "venv is the per-package environment uvx materializes under its cache; uv cache holds the wheels; the interpreter is uv-managed CPython when no system one matches",
    }


def probe_g0t4():
    argv = ["npx", "-y", "mcp-server-commands"]
    cli = pl.StdioMcpClient(argv)
    resp, _ = cli.request("initialize", pl.initialize_params())
    if resp is None:
        cli.close()
        return {"participant": "g0t4/mcp-server-commands", "error": "initialize failed"}
    version = resp.get("result", {}).get("serverInfo", {}).get("version")
    tree = pl.tree_pids(cli.p.pid)
    package_dir, node_exe = None, None
    for pid in tree:
        cmd = read_cmdline(pid)
        node_exe = exe_of(pid) or node_exe
        for part in cmd:
            if "node_modules" in part:
                idx = part.find("node_modules")
                root = part[:idx + len("node_modules")]
                if os.path.isdir(root):
                    package_dir = root
                    break
        if package_dir:
            break
    cli.close()

    node_lib = "/usr/lib/node_modules"
    return {
        "participant": "g0t4/mcp-server-commands",
        "version": version,
        "channel": "npx",
        "package_env": package_dir,
        "package_env_bytes": du_bytes(package_dir),
        "package_env_mib": mib(du_bytes(package_dir)),
        "node_exe": node_exe,
        "node_exe_bytes": du_bytes(node_exe),
        "node_stdlib_bytes": du_bytes(node_lib),
        "runtime_bytes": (du_bytes(node_exe) or 0) + (du_bytes(node_lib) or 0),
        "runtime_mib": mib((du_bytes(node_exe) or 0) + (du_bytes(node_lib) or 0)),
        "runtime_kind": "Node.js (system package: node binary + bundled npm modules)",
        "notes": "package env is the npx cache dir for this package; runtime is the system Node.js install",
    }


def main():
    ap = argparse.ArgumentParser(description="delivery footprint probe")
    ap.add_argument("--ours-bin", required=True)
    ap.add_argument("--build-mode", default="ReleaseSafe")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    out = {
        "phase": "footprint",
        "ours": probe_ours(args.ours_bin, args.build_mode),
        "tumf": probe_tumf(),
        "g0t4": probe_g0t4(),
    }
    payload = json.dumps(out, indent=1)
    if args.out:
        with open(args.out, "w") as f:
            f.write(payload + "\n")
        print(f"wrote {args.out}", file=sys.stderr)
    else:
        print(payload)
    return 0


if __name__ == "__main__":
    sys.exit(main())
