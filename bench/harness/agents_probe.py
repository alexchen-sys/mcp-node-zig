#!/usr/bin/env python3
"""Per-connection memory probe ("cost of the second agent", methodology b07).

http transport (mcp-node-zig): one server process; we open N keep-alive
connections step by step (5 at a time), sampling tree RSS after each step.
The delta per connection is the marginal cost of one more attached agent
inside the same process.

stdio transport (rivals): each agent runs its own server process, so the
"cost of the second agent" is a full second instance; we spawn two instances
side by side and report each tree's RSS.
"""
import argparse
import json
import sys
import time

sys.path.insert(0, __file__.rsplit("/", 1)[0])
import probe_lib as pl  # noqa: E402


def median(xs):
    s = sorted(xs)
    return s[len(s) // 2] if s else None


def rss_now_kib(root_pid, n=5, interval=0.2):
    vals = []
    for _ in range(n):
        m = pl.tree_memory_kib(root_pid)
        if m["pids"]:
            vals.append(m["rss_kib"])
        time.sleep(interval)
    return median(vals)


def http_probe(args, env, token):
    p = pl.spawn(args.argv, env_extra=env)
    _, ok = pl.wait_port(args.port)
    if not ok:
        pl.kill_tree(p)
        return {"error": "port never became reachable"}
    cli0 = pl.HttpMcpClient(args.port, token=token)
    resp, _, err = cli0.request("initialize", pl.initialize_params())
    if resp is None:
        cli0.close()
        pl.kill_tree(p)
        return {"error": f"initialize failed: {err}"}
    server_info = resp.get("result", {}).get("serverInfo", {})
    time.sleep(1.0)
    base = rss_now_kib(p.pid)

    conns = [cli0]
    steps = []
    for step in range(1, (args.connections // args.step) + 1):
        for _ in range(args.step):
            c = pl.HttpMcpClient(args.port, token=token)
            resp, _, err = c.request("initialize", pl.initialize_params())
            if resp is None:
                c.close()
            else:
                conns.append(c)
        time.sleep(0.5)
        rss = rss_now_kib(p.pid)
        steps.append({"connections": len(conns), "rss_kib": rss})

    for c in conns:
        c.close()
    time.sleep(1.0)
    recovered = rss_now_kib(p.pid)
    pl.kill_tree(p)

    final = steps[-1]["rss_kib"] if steps else base
    delta_total = (final - base) if (final is not None and base is not None) else None
    recovered_delta = (recovered - base) if (recovered is not None and base is not None) else None
    return {
        "mode": "one process, N keep-alive connections",
        "transport": "http",
        "argv": args.argv,
        "server_info": server_info,
        "base_rss_kib": base,
        "steps": steps,
        "connections_total": args.connections,
        "delta_rss_kib_total": delta_total,
        "delta_rss_kib_per_connection": round(delta_total / args.connections, 1) if delta_total is not None else None,
        "rss_kib_after_close": recovered,
        "recovered_delta_kib": recovered_delta,
        "recovered": (recovered is not None and recovered_delta is not None and recovered_delta <= 512),
    }


def stdio_probe(args, env):
    a = pl.StdioMcpClient(args.argv, env_extra=env)
    resp_a, _ = a.request("initialize", pl.initialize_params())
    if resp_a is None:
        a.close()
        return {"error": "instance A initialize failed"}
    server_info = resp_a.get("result", {}).get("serverInfo", {})
    time.sleep(1.0)
    rss_a = rss_now_kib(a.p.pid)

    b = pl.StdioMcpClient(args.argv, env_extra=env)
    resp_b, _ = b.request("initialize", pl.initialize_params())
    if resp_b is None:
        b.close()
        return {"error": "instance B initialize failed"}
    time.sleep(1.0)
    rss_b = rss_now_kib(b.p.pid)
    rss_b_alone = rss_now_kib(b.p.pid)

    b.close()
    a.close()
    return {
        "mode": "one process per agent (two instances side by side)",
        "transport": "stdio",
        "argv": args.argv,
        "server_info": server_info,
        "instance_a_rss_kib": rss_a,
        "instance_b_rss_kib": rss_b_alone,
        "second_agent_cost_kib": rss_b_alone,
        "two_agents_total_kib": (rss_a + rss_b_alone) if (rss_a is not None and rss_b_alone is not None) else None,
    }


def main():
    ap = argparse.ArgumentParser(description="per-connection / per-agent memory probe")
    ap.add_argument("--transport", choices=["stdio", "http"], default="http")
    ap.add_argument("--port", type=int, default=18341)
    ap.add_argument("--token-file", default=None)
    ap.add_argument("--connections", type=int, default=20)
    ap.add_argument("--step", type=int, default=5)
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
        out = http_probe(args, env, token)
    else:
        out = stdio_probe(args, env)

    out["phase"] = "per_connection"
    payload = json.dumps(out, indent=1)
    if args.out:
        with open(args.out, "w") as f:
            f.write(payload + "\n")
        print(f"wrote {args.out}", file=sys.stderr)
    else:
        print(payload)
    return 0 if "error" not in out else 1


if __name__ == "__main__":
    sys.exit(main())
