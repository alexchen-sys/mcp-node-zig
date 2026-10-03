#!/usr/bin/env python3
"""Unified MCP client harness: the single measuring arm for all participants.

Phases
- bootstrap: full cold cycle (spawn -> initialize -> tools/list -> one exec ->
  shutdown), repeated --runs times. Reports time from spawn to the first MCP
  response (cold start) and to the first completed tool call (ready to serve).
- latency: one warm server, --warmup exec calls, then --runs exec round-trips
  on the same channel (keep-alive HTTP or stdio pipes) with p50/p95/p99.
- warmup: single initialize against a freshly spawned server; used to
  pre-populate uvx/npx package caches BEFORE cold series.

Transports
- stdio: newline-delimited JSON-RPC over pipes (rivals' native transport).
- http: POST /mcp with token auth (mcp-node-zig transport).

Usage examples are in bench/README.md. Output: one JSON document on stdout
(per-run samples + summary); progress goes to stderr.
"""
import argparse
import json
import sys
import time

sys.path.insert(0, __file__.rsplit("/", 2)[0] + "/lib")
import stats  # noqa: E402

sys.path.insert(0, __file__.rsplit("/", 1)[0])
import probe_lib as pl  # noqa: E402


def parse_env(items):
    out = {}
    for it in items or []:
        k, _, v = it.partition("=")
        out[k] = v
    return out


class Participant:
    """Binds one server (argv + env) to its exec tool schema."""

    def __init__(self, args):
        self.transport = args.transport
        self.argv = args.argv
        self.env = parse_env(args.env)
        self.tool = args.tool
        self.tool_key = args.tool_key
        self.tool_argv = args.tool_argv
        self.port = args.port
        self.token = None
        self.token_file = args.token_file
        if args.token_file:
            with open(args.token_file) as f:
                self.token = f.read().strip()

    def exec_params(self):
        return {"name": self.tool, "arguments": {self.tool_key: self.tool_argv}}

    def spawn_stdin_server(self):
        return pl.StdioMcpClient(self.argv, env_extra=self.env)

    def spawn_http_server(self):
        env = dict(self.env)
        env.setdefault("MCP_NODE_PORT", str(self.port))
        env.setdefault("MCP_NODE_HOST", "127.0.0.1")
        if self.token_file:
            env.setdefault("MCP_NODE_TOKEN_FILE", self.token_file)
        p = pl.spawn(self.argv, env_extra=env)
        return p


def handshake_http(part, p):
    """Returns phase dict; p is the server Popen."""
    t_spawn = time.perf_counter_ns()
    attempts, ok = pl.wait_port(part.port)
    if not ok:
        return {"ok": False, "error": "port never became reachable"}
    cli = pl.HttpMcpClient(part.port, token=part.token)
    resp, rtt, err = cli.request("initialize", pl.initialize_params())
    if resp is None:
        cli.close()
        return {"ok": False, "error": f"initialize failed: {err}"}
    t_first = time.perf_counter_ns()
    server_info = resp.get("result", {}).get("serverInfo", {})
    resp2, rtt_list, _ = cli.request("tools/list")
    n_tools = len(resp2.get("result", {}).get("tools", [])) if resp2 else 0
    resp3, rtt_exec, err3 = cli.request("tools/call", part.exec_params())
    t_exec_done = time.perf_counter_ns()
    ok_exec = resp3 is not None and not resp3.get("result", {}).get("isError", False)
    cli.close()
    return {
        "ok": True,
        "cold_first_response_ms": (t_first - t_spawn) / 1e6,
        "ready_to_serve_ms": (t_exec_done - t_spawn) / 1e6,
        "rtt_initialize_ms": rtt,
        "rtt_tools_list_ms": rtt_list,
        "rtt_exec_ms": rtt_exec,
        "tools_listed": n_tools,
        "exec_ok": ok_exec,
        "server_info": server_info,
        "port_wait_attempts": attempts,
    }


def handshake_stdio(part):
    cli = part.spawn_stdin_server()
    t_spawn = cli.spawn_t
    resp, rtt = cli.request("initialize", pl.initialize_params())
    if resp is None:
        cli.close()
        return {"ok": False, "error": "initialize failed"}
    t_first = time.perf_counter_ns()
    server_info = resp.get("result", {}).get("serverInfo", {})
    cli.notify("notifications/initialized")
    resp2, rtt_list = cli.request("tools/list")
    n_tools = len(resp2.get("result", {}).get("tools", [])) if resp2 else 0
    resp3, rtt_exec = cli.request("tools/call", part.exec_params())
    t_exec_done = time.perf_counter_ns()
    ok_exec = resp3 is not None and not resp3.get("result", {}).get("isError", False)
    cli.close()
    return {
        "ok": True,
        "cold_first_response_ms": (t_first - t_spawn) / 1e6,
        "ready_to_serve_ms": (t_exec_done - t_spawn) / 1e6,
        "rtt_initialize_ms": rtt,
        "rtt_tools_list_ms": rtt_list,
        "rtt_exec_ms": rtt_exec,
        "tools_listed": n_tools,
        "exec_ok": ok_exec,
        "server_info": server_info,
    }


def do_bootstrap(part, runs, pause_s):
    samples, failures = [], []
    for i in range(runs):
        if part.transport == "http":
            p = part.spawn_http_server()
            try:
                rec = handshake_http(part, p)
            finally:
                pl.kill_tree(p)
        else:
            rec = handshake_stdio(part)
        if rec.pop("ok", True):
            samples.append(rec)
        else:
            failures.append({"run": i, **rec})
        if (i + 1) % 10 == 0:
            print(f"[bootstrap] {i + 1}/{runs} done", file=sys.stderr)
        time.sleep(pause_s)
    out = {
        "phase": "bootstrap",
        "transport": part.transport,
        "argv": part.argv,
        "runs": runs,
        "pause_between_runs_s": pause_s,
        "failures": failures,
        "samples": samples,
    }
    if samples:
        out["summary"] = {
            "cold_first_response_ms": stats.summarize_samples(
                [s["cold_first_response_ms"] for s in samples]),
            "ready_to_serve_ms": stats.summarize_samples(
                [s["ready_to_serve_ms"] for s in samples]),
            "rtt_exec_ms": stats.summarize_samples(
                [s["rtt_exec_ms"] for s in samples]),
        }
        out["server_info"] = samples[0].get("server_info", {})
        out["exec_ok_count"] = sum(1 for s in samples if s.get("exec_ok"))
    return out


def do_latency(part, runs, warmup):
    # bring the server up warm
    if part.transport == "http":
        p = part.spawn_http_server()
        _, ok = pl.wait_port(part.port)
        if not ok:
            pl.kill_tree(p)
            return {"phase": "latency", "error": "port never became reachable"}
        cli = pl.HttpMcpClient(part.port, token=part.token)
        resp, _, err = cli.request("initialize", pl.initialize_params())
        if resp is None:
            cli.close()
            pl.kill_tree(p)
            return {"phase": "latency", "error": f"initialize failed: {err}"}
    else:
        p = None
        cli = part.spawn_stdin_server()
        resp, _ = cli.request("initialize", pl.initialize_params())
        if resp is None:
            cli.close()
            return {"phase": "latency", "error": "initialize failed"}
    server_info = resp.get("result", {}).get("serverInfo", {})
    if part.transport == "stdio":
        cli.notify("notifications/initialized")

    for _ in range(warmup):
        cli.request("tools/call", part.exec_params())

    samples, failures = [], 0
    for i in range(runs):
        if part.transport == "http":
            resp, rtt, err = cli.request("tools/call", part.exec_params())
            if resp is None:
                failures += 1
                continue
        else:
            resp, rtt = cli.request("tools/call", part.exec_params())
            if resp is None:
                failures += 1
                continue
        if resp.get("result", {}).get("isError", False):
            failures += 1
            continue
        samples.append(rtt)
        if (i + 1) % 50 == 0:
            print(f"[latency] {i + 1}/{runs}", file=sys.stderr)

    cli.close()
    if p is not None:
        pl.kill_tree(p)
    return {
        "phase": "latency",
        "transport": part.transport,
        "argv": part.argv,
        "runs": runs,
        "warmup": warmup,
        "failures": failures,
        "server_info": server_info,
        "samples_ms": [round(x, 3) for x in samples],
        "summary": stats.latency_summary(samples) if samples else None,
    }


def do_warmup(part):
    if part.transport == "http":
        p = part.spawn_http_server()
        try:
            rec = handshake_http(part, p)
        finally:
            pl.kill_tree(p)
    else:
        rec = handshake_stdio(part)
    rec.pop("samples", None)
    return {"phase": "warmup", "transport": part.transport, "argv": part.argv, **rec}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("phase", choices=["bootstrap", "latency", "warmup"])
    ap.add_argument("--transport", choices=["stdio", "http"], default="stdio")
    ap.add_argument("--runs", type=int, default=20)
    ap.add_argument("--warmup", type=int, default=10)
    ap.add_argument("--pause", type=float, default=0.05, help="pause between bootstrap runs, s")
    ap.add_argument("--port", type=int, default=18341)
    ap.add_argument("--token-file", default=None)
    ap.add_argument("--tool", default="exec", help="tool name for the exec probe")
    ap.add_argument("--tool-key", default="argv", help="argument key holding the argv array")
    ap.add_argument("--tool-argv", nargs="+", default=["uname", "-a"])
    ap.add_argument("-E", "--env", action="append", help="env K=V for the spawned server")
    ap.add_argument("--out", default=None, help="write JSON here instead of stdout")
    ap.add_argument("argv", nargs="*", help="server command (after --)")
    args = ap.parse_args()

    if not args.argv:
        ap.error("server command is required (put it after --)")

    part = Participant(args)
    if args.phase == "bootstrap":
        out = do_bootstrap(part, args.runs, args.pause)
    elif args.phase == "latency":
        out = do_latency(part, args.runs, args.warmup)
    else:
        out = do_warmup(part)
    out["harness"] = {"python": sys.version.split()[0], "phase": args.phase,
                      "tool": args.tool, "tool_key": args.tool_key,
                      "tool_argv": args.tool_argv}
    payload = json.dumps(out, indent=1)
    if args.out:
        with open(args.out, "w") as f:
            f.write(payload + "\n")
        print(f"wrote {args.out}", file=sys.stderr)
    else:
        print(payload)


if __name__ == "__main__":
    main()
