#!/usr/bin/env python3
"""TLS node-link handshake probe (bench series b02).

Measures the hub's built-in TLS node-link listener (requires the -Dtls-server
build):
- client side: N fresh TLS 1.3 handshakes against the link port, each split
  into tcp_connect_ms and tls_handshake_ms, verifying the server certificate
  against a throwaway EC CA generated for this run (openssl CLI; the recipe
  mirrors the e2e suite but stays self-contained in bench/).
- node side: M cycles of spawning a node with MCP_NODE_CONNECT_TLS=1 and
  polling the hub's POST /n at ~1 ms until the node registers; the cycle
  time is link_established_ms = spawn + TCP + TLS handshake + registration.

The MCP client surface (POST /mcp) has no TLS by design (loopback + token);
this series covers the node-link path only, and BENCHMARKS.md says exactly
that.

Skips cleanly (exit 0, `skipped` set in the output document) when the binary
was built without -Dtls-server or the openssl CLI is unavailable.

Output: one JSON document (--out or stdout); progress to stderr; raw
samples stream to --jsonl-client / --jsonl-node as they complete.
"""
import argparse
import http.client
import json
import os
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, __file__.rsplit("/", 1)[0])
import probe_lib as pl  # noqa: E402

sys.path.insert(0, __file__.rsplit("/", 2)[0] + "/lib")
import stats  # noqa: E402

HUB_START_NOTE = "serving TLS 1.3 node links"
NO_TLS_SERVER_NOTE = "need a build with -Dtls-server"


def base_env():
    """Copy of os.environ without MCP_NODE_* knobs (probes configure these)."""
    return {k: v for k, v in os.environ.items() if not k.startswith("MCP_NODE_")}


def spawn_logged(argv, env, logpath):
    """Popen whose stdout+stderr append to logpath, own process group.

    The parent closes its copy of the log fd right after spawn; the child
    keeps its dup, so thousands of short-lived nodes do not leak fds.
    """
    log = open(logpath, "ab")
    try:
        return subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL,
                                stdout=log, stderr=log, start_new_session=True)
    finally:
        log.close()


def read_log(logpath):
    try:
        with open(logpath, "r", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


# ------------------------------------------------------- throwaway PKI (EC)

def _openssl(*args, cwd):
    r = subprocess.run(["openssl", *args], cwd=cwd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"openssl {' '.join(args[:2])} failed: "
                           f"{(r.stderr or '').strip()[:200]}")


def make_ca(workdir):
    """Throwaway EC P-256 CA, valid two days (same recipe as the e2e suite)."""
    _openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
             "-nodes", "-days", "2", "-subj", "/CN=throwaway bench ca",
             "-addext", "basicConstraints=critical,CA:TRUE",
             "-addext", "keyUsage=critical,keyCertSign,cRLSign",
             "-keyout", "ca.key", "-out", "ca.pem", cwd=workdir)


def make_server_cert(workdir):
    with open(os.path.join(workdir, "ext.cnf"), "w") as f:
        f.write("basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                "extendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n")
    _openssl("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
             "-subj", "/CN=localhost", "-keyout", "server.key", "-out", "server.csr",
             cwd=workdir)
    _openssl("x509", "-req", "-in", "server.csr", "-CA", "ca.pem",
             "-CAkey", "ca.key", "-CAcreateserial", "-days", "2",
             "-extfile", "ext.cnf", "-out", "server.pem", cwd=workdir)


# ------------------------------------------------------------------ hub

def wait_hub_api(p, port, deadline_s=15.0):
    """Port-open OR process death, whichever comes first."""
    deadline = time.monotonic() + deadline_s
    while time.monotonic() < deadline:
        if p.poll() is not None:
            return False
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.25)
        try:
            s.connect(("127.0.0.1", port))
            return True
        except OSError:
            pass
        finally:
            try:
                s.close()
            except OSError:
                pass
        time.sleep(0.001)
    return False


def start_hub(args, workdir, token_file, secret_file):
    """Start the TLS hub; returns (proc, None) or (None, 'skip: ...'/'error: ...')."""
    logpath = os.path.join(workdir, "hub.log")
    env = base_env()
    env.update({
        "MCP_NODE_HOST": "127.0.0.1",
        "MCP_NODE_PORT": str(args.api_port),
        "MCP_NODE_NAME": "hub-bench",
        "MCP_NODE_SOCKET_TIMEOUT_S": "5",
        "MCP_NODE_HUB_LISTEN": f"127.0.0.1:{args.link_port}",
        "MCP_NODE_HUB_SECRET_FILE": str(secret_file),
        "MCP_NODE_HUB_TLS_CERT_FILE": os.path.join(workdir, "server.pem"),
        "MCP_NODE_HUB_TLS_KEY_FILE": os.path.join(workdir, "server.key"),
        "MCP_NODE_TOKEN_FILE": str(token_file),
    })
    p = spawn_logged([args.binary], env, logpath)
    if not wait_hub_api(p, args.api_port):
        pl.kill_tree(p)
        tail = read_log(logpath)
        if NO_TLS_SERVER_NOTE in tail:
            return None, f"skip:{NO_TLS_SERVER_NOTE}"
        return None, f"error:hub did not start: {tail[-400:]}"
    # wait for the TLS announcement so handshakes hit a ready listener
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        tail = read_log(logpath)
        if HUB_START_NOTE in tail:
            return p, None
        if p.poll() is not None:
            break
        time.sleep(0.05)
    pl.kill_tree(p)
    tail = read_log(logpath)
    if NO_TLS_SERVER_NOTE in tail:
        return None, f"skip:{NO_TLS_SERVER_NOTE}"
    return None, f"error:hub did not announce TLS: {tail[-400:]}"


# ------------------------------------------------------- client-side series

def client_handshakes(args, ca_path, js):
    """N TLS 1.3 handshakes: tcp_connect / tls_handshake / total per sample."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_verify_locations(ca_path)  # trust ONLY the throwaway CA
    recs, failures = [], 0
    for i in range(args.handshakes):
        rec = {"run": i, "ok": True}
        t0 = time.perf_counter_ns()
        try:
            raw = socket.create_connection(("127.0.0.1", args.link_port), timeout=10)
        except OSError as e:
            failures += 1
            if js:
                js.emit(run=i, ok=False, error=f"connect: {e}")
            continue
        t1 = time.perf_counter_ns()
        try:
            tls = ctx.wrap_socket(raw, server_hostname="localhost")
        except (OSError, ssl.SSLError) as e:
            failures += 1
            raw.close()
            if js:
                js.emit(run=i, ok=False, error=f"tls: {e}")
            continue
        t2 = time.perf_counter_ns()
        rec["tcp_connect_ms"] = round((t1 - t0) / 1e6, 6)
        rec["tls_handshake_ms"] = round((t2 - t1) / 1e6, 6)
        rec["total_ms"] = round((t2 - t0) / 1e6, 6)
        rec["tls_version"] = tls.version()
        cipher = tls.cipher()
        rec["cipher"] = cipher[0] if cipher else None
        tls.close()
        recs.append(rec)
        if js:
            js.emit(**rec)
        if (i + 1) % 500 == 0:
            print(f"[b02 client] {i + 1}/{args.handshakes}", file=sys.stderr)
    return recs, failures


# --------------------------------------------------------- node-side series

class HubPoller:
    """POST /n poller with token auth on one keep-alive connection."""

    def __init__(self, api_port, token):
        self.api_port = api_port
        self.token = token
        self.conn = http.client.HTTPConnection("127.0.0.1", api_port, timeout=5)

    def has_node(self, name):
        try:
            self.conn.request("POST", "/n", body=b"{}",
                              headers={"Content-Type": "application/json",
                                       "X-Node-Token": self.token})
            resp = self.conn.getresponse()
            data = resp.read()
        except (http.client.HTTPException, OSError):
            self._reconnect()
            return False
        if resp.status != 200:
            return False
        try:
            nodes = json.loads(data).get("nodes", [])
        except (json.JSONDecodeError, AttributeError):
            return False
        return any(n.get("name") == name for n in nodes)

    def _reconnect(self):
        try:
            self.conn.close()
        except OSError:
            pass
        self.conn = http.client.HTTPConnection("127.0.0.1", self.api_port, timeout=5)

    def close(self):
        try:
            self.conn.close()
        except OSError:
            pass


def node_runs(args, workdir, secret_file, ca_path, token, js):
    """M spawn->registered cycles: link_established_ms per cycle."""
    poller = HubPoller(args.api_port, token)
    node_log = os.path.join(workdir, "nodes.log")
    recs, failures = [], 0
    try:
        for i in range(args.node_runs):
            name = f"b02-node-{i}"
            env = base_env()
            env.update({
                "MCP_NODE_NAME": name,
                "MCP_NODE_SOCKET_TIMEOUT_S": "5",
                # 'localhost', not 127.0.0.1: the node verifies the hub
                # certificate hostname (SAN DNS:localhost), same as the e2e
                # suite's targets. Dialing the bare IP fails verification.
                "MCP_NODE_CONNECT": f"localhost:{args.link_port}",
                "MCP_NODE_CONNECT_TLS": "1",
                "MCP_NODE_CONNECT_CA_FILE": str(ca_path),
                "MCP_NODE_CONNECT_SECRET_FILE": str(secret_file),
            })
            t0 = time.perf_counter_ns()
            p = spawn_logged([args.binary], env, node_log)
            established = None
            deadline = time.monotonic() + 10.0
            while time.monotonic() < deadline:
                if poller.has_node(name):
                    established = time.perf_counter_ns()
                    break
                if p.poll() is not None:
                    break
                time.sleep(0.001)
            if established is None:
                failures += 1
                reason = ("node exited before registering" if p.poll() is not None
                          else "timeout waiting for registration")
                if js:
                    js.emit(run=i, ok=False, error=reason)
            else:
                rec = {"run": i, "ok": True,
                       "link_established_ms": round((established - t0) / 1e6, 6)}
                recs.append(rec)
                if js:
                    js.emit(**rec)
            pl.kill_tree(p)
            if (i + 1) % 100 == 0:
                print(f"[b02 node] {i + 1}/{args.node_runs}", file=sys.stderr)
    finally:
        poller.close()
    return recs, failures


# ------------------------------------------------------------------ output

def _counts(recs, field):
    out = {}
    for r in recs:
        v = r.get(field)
        if v is not None:
            out[v] = out.get(v, 0) + 1
    return out


def write_out(doc, path):
    payload = json.dumps(doc, indent=1)
    if path:
        with open(path, "w") as f:
            f.write(payload + "\n")
        print(f"wrote {path}", file=sys.stderr)
    else:
        print(payload)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--binary", required=True, help="mcp-node binary (-Dtls-server build)")
    ap.add_argument("--handshakes", type=int, default=10000,
                    help="client-side TLS handshakes")
    ap.add_argument("--node-runs", type=int, default=1000,
                    help="node-side spawn->registered cycles")
    ap.add_argument("--api-port", type=int, default=18351,
                    help="hub MCP API port (client token auth)")
    ap.add_argument("--link-port", type=int, default=18352,
                    help="hub TLS node-link listener port")
    ap.add_argument("--participant", default="ours")
    ap.add_argument("--jsonl-client", default=None,
                    help="append one JSON object per client handshake as it lands")
    ap.add_argument("--jsonl-node", default=None,
                    help="append one JSON object per node cycle as it lands")
    ap.add_argument("--out", default=None, help="write the aggregate JSON here")
    args = ap.parse_args()

    doc = {
        "metric": "b02_tls_handshake",
        "label": "TLS 1.3 node-link handshakes (client side) and node "
                 "spawn->registered cycles (hub -Dtls-server)",
        "participant": args.participant,
        "binary": args.binary,
        "api_port": args.api_port,
        "link_port": args.link_port,
        "handshakes": args.handshakes,
        "node_runs": args.node_runs,
        "skipped": None,
    }

    if shutil.which("openssl") is None:
        doc["skipped"] = "openssl CLI not found"
        write_out(doc, args.out)
        return 0

    workdir = tempfile.mkdtemp(prefix="mcpnz-b02.")
    hub, js_client, js_node = None, None, None
    try:
        make_ca(workdir)
        make_server_cert(workdir)
        ca_path = os.path.join(workdir, "ca.pem")
        token_file = os.path.join(workdir, "client-token")
        secret = secrets.token_hex(24)
        with open(token_file, "w") as f:
            f.write(secret)
        # the hub reads its secret file with the trailing newline it writes;
        # nodes read the bare secret (mirrors the e2e suite's files)
        hub_secret = os.path.join(workdir, "hub-secret")
        with open(hub_secret, "w") as f:
            f.write(secret + "\n")
        node_secret = os.path.join(workdir, "node-secret")
        with open(node_secret, "w") as f:
            f.write(secret)

        hub, err = start_hub(args, workdir, token_file, hub_secret)
        if err is not None:
            if err.startswith("skip:"):
                doc["skipped"] = err[len("skip:"):]
                write_out(doc, args.out)
                return 0
            doc["error"] = err
            write_out(doc, args.out)
            return 1

        if args.jsonl_client:
            js_client = pl.JsonlWriter(args.jsonl_client, "b02_client", args.participant)
        if args.jsonl_node:
            js_node = pl.JsonlWriter(args.jsonl_node, "b02_node", args.participant)

        with open(token_file) as f:
            token = f.read().strip()
        crecs, cfail = client_handshakes(args, ca_path, js_client)
        nrecs, nfail = node_runs(args, workdir, node_secret, ca_path, token, js_node)

        def lat(recs, field):
            return stats.latency_summary([r[field] for r in recs]) if recs else None

        doc["client"] = {
            "runs": args.handshakes,
            "failures": cfail,
            "summary": {
                "tcp_connect_ms": lat(crecs, "tcp_connect_ms"),
                "tls_handshake_ms": lat(crecs, "tls_handshake_ms"),
                "total_ms": lat(crecs, "total_ms"),
            },
            "tls_versions": _counts(crecs, "tls_version"),
            "ciphers": _counts(crecs, "cipher"),
        }
        doc["node"] = {
            "runs": args.node_runs,
            "failures": nfail,
            "summary": {
                "link_established_ms": lat(nrecs, "link_established_ms"),
            },
        }
        write_out(doc, args.out)
        return 0
    finally:
        if js_client:
            js_client.close()
        if js_node:
            js_node.close()
        if hub is not None:
            pl.kill_tree(hub)
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
