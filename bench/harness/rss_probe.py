#!/usr/bin/env python3
"""Idle-RSS probe: bring a participant up, settle, sample tree memory.

Protocol (methodology b03): spawn -> initialize -> settle -> N samples of
VmRSS and Pss summed over the whole process tree every --interval seconds ->
shutdown. Reports median and max.

Two runs when --time-v-out is given for http participants:
1. the CLEAN server tree (no wrapper process in the measurement);
2. a separate /usr/bin/time -v run, terminated with SIGTERM so the wrapper
   can write its report (Max RSS over the full lifecycle) — an orthogonal
   cross-check, never mixed into the tree numbers.

The /proc-based sampler replaces psutil (which reads the same /proc files);
PSS is additionally reported because rival launchers spawn a process tree
(uvx -> python, npx -> node) and RSS would double-count shared library pages.
"""
import argparse
import json
import os
import signal
import subprocess
import sys
import time

sys.path.insert(0, __file__.rsplit("/", 1)[0])
import probe_lib as pl  # noqa: E402


def proc_name(pid):
    try:
        with open(f"/proc/{pid}/stat") as f:
            return f.read().split("(", 1)[1].rsplit(")", 1)[0]
    except (OSError, IndexError):
        return "?"


def tree_snapshot(root_pid):
    m = pl.tree_memory_kib(root_pid)
    m["breakdown"] = pl.tree_memory_breakdown(root_pid)
    m["names"] = [proc_name(p) for p in m["pids"]]
    return m


def run_clean(args, env, token):
    """Measurement run: nothing but the server in the tree."""
    if args.transport == "http":
        p = pl.spawn(args.argv, env_extra=env)
        _, ok = pl.wait_port(args.port)
        if not ok:
            pl.kill_tree(p)
            return None, "port never became reachable"
        cli = pl.HttpMcpClient(args.port, token=token)
        resp, _, err = cli.request("initialize", pl.initialize_params())
        server_info = (resp or {}).get("result", {}).get("serverInfo", {})
        if resp is None:
            cli.close()
            pl.kill_tree(p)
            return None, f"initialize failed: {err}"
        root_pid = p.pid
        cli.close()  # drop the measuring connection; server stays idle
    else:
        cli = pl.StdioMcpClient(args.argv, env_extra=env)
        resp, _ = cli.request("initialize", pl.initialize_params())
        server_info = (resp or {}).get("result", {}).get("serverInfo", {})
        if resp is None:
            cli.close()
            return None, "initialize failed"
        root_pid = cli.p.pid
        globals()["_keep_cli"] = cli  # keep pipes open while sampling

    time.sleep(args.settle)
    snap = tree_snapshot(root_pid)
    mem = pl.sample_tree_memory(root_pid, samples=args.samples, interval_s=args.interval)
    end = tree_snapshot(root_pid)

    if args.transport == "http":
        pl.kill_tree(p)
    else:
        cli.close()
    return {
        "server_info": server_info,
        "process_tree_start": snap,
        "process_tree_end": end,
        "memory": mem,
    }, None


def run_time_v(args, env, token):
    """Orthogonal /usr/bin/time -v run for single-process http servers."""
    launch = ["/usr/bin/time", "-v", "-o", args.time_v_out, "--"] + list(args.argv)
    env2 = dict(env)
    p = pl.spawn(launch, env_extra=env2)
    _, ok = pl.wait_port(args.port)
    if not ok:
        pl.kill_tree(p, term_first=True)
        return None, "port never became reachable"
    cli = pl.HttpMcpClient(args.port, token=token)
    resp, _, err = cli.request("initialize", pl.initialize_params())
    if resp is None:
        cli.close()
        pl.kill_tree(p, term_first=True)
        return None, f"initialize failed: {err}"
    time.sleep(args.settle)
    cli.close()
    # SIGTERM the SERVER (child of /usr/bin/time) only: when the child exits,
    # time writes its report and exits on its own; killing the whole group
    # would take time down before it can report.
    kids = [pid for pid in pl.tree_pids(p.pid) if pid != p.pid]
    for kid in kids:
        try:
            os.kill(kid, signal.SIGTERM)
        except OSError:
            pass
    try:
        p.wait(timeout=15)
    except subprocess.TimeoutExpired:
        pass
    pl.kill_tree(p)  # sweep anything left
    if not os.path.exists(args.time_v_out) or os.path.getsize(args.time_v_out) == 0:
        return None, "time -v produced no report"
    time_v = {}
    with open(args.time_v_out) as f:
        for line in f:
            if ":" in line:
                k, v = line.split(":", 1)
                time_v[k.strip()] = v.strip()
    return {"time_v": time_v}, None


def main():
    ap = argparse.ArgumentParser(description="idle RSS probe")
    ap.add_argument("--transport", choices=["stdio", "http"], default="stdio")
    ap.add_argument("--port", type=int, default=18341)
    ap.add_argument("--token-file", default=None)
    ap.add_argument("--settle", type=float, default=2.0, help="seconds to settle before sampling")
    ap.add_argument("--samples", type=int, default=20)
    ap.add_argument("--interval", type=float, default=0.5)
    ap.add_argument("--time-v-out", default=None,
                    help="also run /usr/bin/time -v into this file (http, single-process)")
    ap.add_argument("-E", "--env", action="append")
    ap.add_argument("--out", default=None)
    ap.add_argument("argv", nargs="*")
    args = ap.parse_args()
    if not args.argv:
        ap.error("server command is required")

    env = {}
    for it in args.env or []:
        k, _, v = it.partition("=")
        env[k] = v

    token = None
    if args.token_file:
        with open(args.token_file) as f:
            token = f.read().strip()
    if args.transport == "http":
        env.setdefault("MCP_NODE_PORT", str(args.port))
        env.setdefault("MCP_NODE_HOST", "127.0.0.1")
        if args.token_file:
            env.setdefault("MCP_NODE_TOKEN_FILE", args.token_file)

    clean, err = run_clean(args, env, token)
    if err or clean is None:
        print(json.dumps({"phase": "rss_idle", "error": err or "no result"}))
        return 1
    mem = clean["memory"]

    out = {
        "phase": "rss_idle",
        "transport": args.transport,
        "argv": args.argv,
        "settle_s": args.settle,
        "samples": args.samples,
        "interval_s": args.interval,
        "server_info": clean["server_info"],
        "process_tree_start": clean["process_tree_start"],
        "process_tree_end": clean["process_tree_end"],
        "memory": clean["memory"],
        "summary": {
            "rss_mib_median": round(mem["rss_kib"]["median"] / 1024.0, 2) if mem["rss_kib"]["median"] else None,
            "rss_mib_max": round(mem["rss_kib"]["max"] / 1024.0, 2) if mem["rss_kib"]["max"] else None,
            "pss_mib_median": round(mem["pss_kib"]["median"] / 1024.0, 2) if mem["pss_kib"]["median"] else None,
            "pss_mib_max": round(mem["pss_kib"]["max"] / 1024.0, 2) if mem["pss_kib"]["max"] else None,
        },
    }

    if args.time_v_out and args.transport == "http":
        tv, err = run_time_v(args, env, token)
        if err:
            out["time_v_error"] = err
        else:
            out["time_v"] = tv["time_v"]

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
