#!/usr/bin/env python3
"""Shared harness primitives: server spawn/control, MCP clients, /proc RSS.

Design goals (methodology bench/README.md, section "Measuring arm"):
- ONE measuring arm for all participants; the harness itself stays out of the
  measured numbers: the outer python startup never happens inside a sample,
  spawn-to-first-response is measured with perf_counter_ns around the child
  lifecycle only.
- stdio and http transports share the same phase structure so rivals are not
  penalized for their transport, and neither are we.
- No third-party dependencies (psutil is replaced by direct /proc reads,
  which is what psutil itself does on Linux).
"""
import http.client
import json
import os
import queue
import signal
import socket
import subprocess
import sys
import threading
import time

PROC_VERSION = "2024-11-05"


# ---------------------------------------------------------------- spawn/kill

def spawn(argv, env_extra=None, cwd=None, stderr=None):
    """Spawn a server as its own process group so the whole tree can be killed."""
    env = dict(os.environ)
    if env_extra:
        for k, v in env_extra.items():
            if v is None:
                env.pop(k, None)
            else:
                env[k] = v
    return subprocess.Popen(
        argv, cwd=cwd, env=env,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr or subprocess.DEVNULL,
        start_new_session=True,
    )


def kill_tree(p, term_first=False):
    """Kill the process group, then reap. Idempotent.

    term_first lets wrapper processes (/usr/bin/time) write their report
    before the group goes away; falls back to SIGKILL after a timeout.
    """
    if term_first:
        try:
            os.killpg(os.getpgid(p.pid), signal.SIGTERM)
            p.wait(timeout=10)
            return
        except (subprocess.TimeoutExpired, ProcessLookupError, PermissionError, OSError):
            pass
    try:
        os.killpg(os.getpgid(p.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            p.kill()
        except OSError:
            pass
    try:
        p.wait(timeout=10)
    except subprocess.TimeoutExpired:
        pass


# ---------------------------------------------------------------- stdio arm

class LineReader:
    """Background reader so a hung server can never hang the harness."""

    def __init__(self, fobj):
        self.q = queue.Queue()
        self.f = fobj

        def loop():
            try:
                for line in self.f:
                    self.q.put(line)
                    if self.f.closed:
                        break
            except (ValueError, OSError):
                pass
            finally:
                self.q.put(None)  # EOF sentinel

        self.t = threading.Thread(target=loop, daemon=True)
        self.t.start()

    def get(self, timeout):
        """Next non-empty line, or None on EOF/timeout."""
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            try:
                item = self.q.get(timeout=remaining)
            except queue.Empty:
                return None
            if item is None:
                return None
            if item.strip():
                return item


class StdioMcpClient:
    """JSON-RPC over newline-delimited stdio (the MCP stdio transport)."""

    def __init__(self, argv, env_extra=None, cwd=None, stderr=None):
        self.p = spawn(argv, env_extra, cwd, stderr)
        assert self.p.stdin is not None and self.p.stdout is not None
        self.rdr = LineReader(self.p.stdout)
        self._id = 0
        self.spawn_t = time.perf_counter_ns()

    def request(self, method, params=None, timeout=60.0):
        self._id += 1
        msg = {"jsonrpc": "2.0", "id": self._id, "method": method}
        if params is not None:
            msg["params"] = params
        t0 = time.perf_counter_ns()
        try:
            self.p.stdin.write((json.dumps(msg) + "\n").encode())
            self.p.stdin.flush()
        except (BrokenPipeError, ValueError):
            return None, None
        line = self.rdr.get(timeout)
        t1 = time.perf_counter_ns()
        if line is None:
            return None, None
        try:
            resp = json.loads(line)
        except json.JSONDecodeError:
            return None, None
        return resp, (t1 - t0) / 1e6

    def notify(self, method, params=None):
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        try:
            self.p.stdin.write((json.dumps(msg) + "\n").encode())
            self.p.stdin.flush()
        except (BrokenPipeError, ValueError):
            pass

    def close(self):
        kill_tree(self.p)


# ---------------------------------------------------------------- http arm

def wait_port(port, host="127.0.0.1", deadline_s=30.0, poll_ms=1.0):
    """Busy-ish connect loop: returns (t_last_attempt_ms, True) once reachable."""
    deadline = time.monotonic() + deadline_s
    attempts = 0
    while time.monotonic() < deadline:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.25)
        try:
            s.connect((host, port))
            s.close()
            return attempts, True
        except OSError:
            attempts += 1
            time.sleep(poll_ms / 1000.0)
        finally:
            try:
                s.close()
            except OSError:
                pass
    return attempts, False


class HttpMcpClient:
    """JSON-RPC over POST /mcp with a persistent (keep-alive) connection."""

    def __init__(self, port, token=None, host="127.0.0.1", timeout=30.0):
        self.port = port
        self.host = host
        self.timeout = timeout
        self.headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if token:
            self.headers["X-Node-Token"] = token
        self.conn = None
        self._id = 0

    def _connect(self):
        self.conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)

    def request(self, method, params=None, timeout=60.0):
        self._id += 1
        msg = {"jsonrpc": "2.0", "id": self._id, "method": method}
        if params is not None:
            msg["params"] = params
        body = json.dumps(msg)
        t0 = time.perf_counter_ns()
        resp, data = None, None
        for attempt in (0, 1):  # one retry after a stale keep-alive
            if self.conn is None:
                self._connect()
            assert self.conn is not None
            try:
                self.conn.request("POST", "/mcp", body=body, headers=self.headers)
                resp = self.conn.getresponse()
                data = resp.read()
                break
            except (http.client.HTTPException, OSError) as e:
                self.conn = None
                if attempt == 1:
                    return None, None, str(e)
        t1 = time.perf_counter_ns()
        if resp is None or data is None:
            return None, None, "no response"
        if resp.status != 200:
            return None, None, f"http {resp.status}"
        try:
            out = json.loads(data)
        except json.JSONDecodeError:
            return None, None, "bad json"
        return out, (t1 - t0) / 1e6, None

    def close(self):
        if self.conn:
            try:
                self.conn.close()
            except OSError:
                pass
            self.conn = None


def initialize_params(client_name="bench-harness", client_version="0.1"):
    return {"protocolVersion": PROC_VERSION, "capabilities": {},
            "clientInfo": {"name": client_name, "version": client_version}}


# ---------------------------------------------------------------- /proc RSS

def _read_status(pid):
    out = {}
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if ":" in line:
                    k, v = line.split(":", 1)
                    out[k.strip()] = v.strip()
    except OSError:
        pass
    return out


def _read_rollup(pid):
    out = {}
    try:
        with open(f"/proc/{pid}/smaps_rollup") as f:
            for line in f:
                if ":" in line:
                    k, v = line.split(":", 1)
                    out[k.strip()] = v.strip()
    except OSError:
        pass
    return out


def process_rss_kib(pid):
    st = _read_status(pid)
    v = st.get("VmRSS", "")
    return int(v.split()[0]) if v else None


def tree_pids(root_pid):
    """All live descendants of root_pid (BFS over /proc/*/stat ppid)."""
    children = {}
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/stat") as f:
                parts = f.read().rsplit(")", 1)
                ppid = int(parts[1].split()[1])
            children.setdefault(ppid, []).append(int(entry))
        except (OSError, IndexError, ValueError):
            continue
    seen, frontier = {root_pid}, [root_pid]
    while frontier:
        nxt = []
        for pid in frontier:
            for c in children.get(pid, []):
                if c not in seen:
                    seen.add(c)
                    nxt.append(c)
        frontier = nxt
    return sorted(seen)


def tree_memory_kib(root_pid):
    """Sum of VmRSS and (proportional) PSS over the process tree, in KiB."""
    rss, pss, pids = 0, 0, []
    for pid in tree_pids(root_pid):
        r = process_rss_kib(pid)
        if r is None:
            continue
        rss += r
        pids.append(pid)
        roll = _read_rollup(pid)
        v = roll.get("Pss", "")
        if v:
            pss += int(v.split()[0])
    return {"rss_kib": rss, "pss_kib": pss, "pids": pids}


def sample_tree_memory(root_pid, samples=20, interval_s=0.5):
    """Timed samples of tree RSS/PSS -> median + max (psutil-style protocol)."""
    out = []
    for _ in range(samples):
        m = tree_memory_kib(root_pid)
        if m["pids"]:
            out.append(m)
        time.sleep(interval_s)
    rss = [m["rss_kib"] for m in out]
    pss = [m["pss_kib"] for m in out]
    return {
        "samples_taken": len(out),
        "rss_kib": {"median": sorted(rss)[len(rss) // 2] if rss else None,
                    "max": max(rss) if rss else None,
                    "series": rss},
        "pss_kib": {"median": sorted(pss)[len(pss) // 2] if pss else None,
                    "max": max(pss) if pss else None,
                    "series": pss},
    }


def tree_memory_breakdown(root_pid):
    """Per-pid {name, rss_kib} snapshot so reports show the tree composition."""
    out = {}
    for pid in tree_pids(root_pid):
        r = process_rss_kib(pid)
        if r is None:
            continue
        try:
            with open(f"/proc/{pid}/stat") as f:
                name = f.read().split("(", 1)[1].rsplit(")", 1)[0]
        except (OSError, IndexError):
            name = "?"
        out[str(pid)] = {"name": name, "rss_kib": r}
    return out
