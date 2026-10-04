#!/usr/bin/env python3
"""End-to-end suite for reverse connect (hub + outbound nodes).

Black-box over real processes: one hub (MCP_NODE_HUB_LISTEN) and one or
more nodes (MCP_NODE_CONNECT) on loopback, driven through the hub's client
listener (POST /n and POST /n/<name>/mcp). Covers listing, the MCP
surface through the relay, auth and routing errors, concurrency, hub
restart with exec session survival, an in-flight request at hub death,
node replacement, and that the default listener mode is unaffected.

Run: python3 ci/test_reverse.py [path/to/mcp-node]
Prints one PASS/FAIL line per case; exits nonzero on any failure.
"""
import http.client
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import traceback

ROOT = Path(__file__).resolve().parent.parent
BINARY = Path(sys.argv[1] if len(sys.argv) > 1
              else ROOT / 'zig-out' / 'bin' / ('mcp-node.exe' if os.name == 'nt' else 'mcp-node')).resolve()

PORT_RANGE = range(18400, 18500)
_used_ports = set()


def pick_port():
    """A free loopback port from the suite's fixed range, never reused."""
    for port in PORT_RANGE:
        if port in _used_ports:
            continue
        with socket.socket() as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                probe.bind(('127.0.0.1', port))
            except OSError:
                continue
        _used_ports.add(port)
        return port
    raise RuntimeError('no free port in %d-%d' % (PORT_RANGE.start, PORT_RANGE.stop - 1))


def base_env():
    return {k: v for k, v in os.environ.items() if not k.startswith('MCP_NODE_')}


def wait_until(pred, timeout_s, step_s=0.05):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        value = pred()
        if value:
            return value
        time.sleep(step_s)
    return pred()


class Proc:
    """One daemon process with its log file."""

    def __init__(self, workdir, tag, env, args=()):
        self.log_path = Path(workdir) / ('%s.log' % tag)
        self.log = self.log_path.open('ab')
        self.process = subprocess.Popen([str(BINARY), *args], cwd=workdir, env=env,
                                        stdout=self.log, stderr=self.log)

    @property
    def pid(self):
        return self.process.pid

    def alive(self):
        return self.process.poll() is None

    def logs(self):
        self.log.flush()
        return self.log_path.read_text(errors='replace')

    def kill9(self):
        if self.alive():
            self.process.send_signal(signal.SIGKILL)
        self.process.wait(timeout=10)

    def stop(self):
        if self.alive():
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.log.close()


class Env:
    """Temp dir with client token and link secret files; owns all processes."""

    def __init__(self):
        self.temp = tempfile.TemporaryDirectory(prefix='mcp-reverse-')
        self.dir = Path(self.temp.name)
        self.token = secrets.token_hex(24)
        self.secret = secrets.token_hex(24)
        (self.dir / 'client-token').write_text(self.token)
        (self.dir / 'hub-secrets').write_text(self.secret + '\n')
        (self.dir / 'node-secret').write_text(self.secret)
        (self.dir / 'wrong-secret').write_text(secrets.token_hex(24))
        self.procs = []
        self.hub_port = None
        self.link_port = None

    def spawn(self, tag, env, args=()):
        proc = Proc(self.dir, tag, env, args)
        self.procs.append(proc)
        return proc

    def start_hub(self, extra=None):
        if self.hub_port is None:
            self.hub_port = pick_port()
            self.link_port = pick_port()
        env = base_env()
        env.update(MCP_NODE_HOST='127.0.0.1', MCP_NODE_PORT=str(self.hub_port),
                   MCP_NODE_NAME='hub', MCP_NODE_SOCKET_TIMEOUT_S='5',
                   MCP_NODE_HUB_LISTEN='127.0.0.1:%d' % self.link_port,
                   MCP_NODE_HUB_SECRET_FILE=str(self.dir / 'hub-secrets'))
        env['MCP_NODE_TOKEN_' + 'FILE'] = str(self.dir / 'client-token')
        env.update(extra or {})
        hub = self.spawn('hub', env)
        if not wait_until(lambda: port_open(self.hub_port) or not hub.alive(), 10) or not hub.alive():
            raise RuntimeError('hub did not start: ' + hub.logs()[-2000:])
        return hub

    def start_node(self, name, secret_file='node-secret', target=None, extra=None, tag=None):
        env = base_env()
        env.update(MCP_NODE_NAME=name, MCP_NODE_SOCKET_TIMEOUT_S='5',
                   MCP_NODE_CONNECT=target or '127.0.0.1:%d' % self.link_port,
                   MCP_NODE_CONNECT_SECRET_FILE=str(self.dir / secret_file))
        env.update(extra or {})
        return self.spawn(tag or ('node-' + name), env)

    def close(self):
        for proc in self.procs:
            try:
                proc.stop()
            except Exception:
                pass
        self.temp.cleanup()

    # ---- client side -------------------------------------------------------

    def post(self, path, payload, token=True, timeout=15, port=None):
        """POST JSON to the hub; returns (status, decoded body or None)."""
        body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        conn = http.client.HTTPConnection('127.0.0.1', port or self.hub_port, timeout=timeout)
        try:
            headers = {'Content-Type': 'application/json', 'Connection': 'close'}
            if token:
                headers['X-Node-Token'] = self.token if token is True else token
            conn.request('POST', path, body=body, headers=headers)
            resp = conn.getresponse()
            data = resp.read()
            return resp.status, (json.loads(data) if data else None)
        finally:
            conn.close()

    def nodes(self):
        status, reply = self.post('/n', b'{}')
        if status != 200:
            raise AssertionError(('list', status, reply))
        return {n['name']: n for n in reply['nodes']}

    def wait_node(self, name, timeout_s=10):
        def present():
            try:
                return name in self.nodes()
            except OSError:
                return False
        return wait_until(present, timeout_s, 0.1)

    def rpc(self, name, method, params=None, rid=1, timeout=15):
        payload = {'jsonrpc': '2.0', 'id': rid, 'method': method}
        if params is not None:
            payload['params'] = params
        return self.post('/n/%s/mcp' % name, payload, timeout=timeout)

    def tool(self, name, tool, arguments=None, timeout=15):
        status, reply = self.rpc(name, 'tools/call', {'name': tool, 'arguments': arguments or {}},
                                 timeout=timeout)
        if status != 200 or not isinstance(reply, dict) or 'result' not in reply:
            raise AssertionError(('tool', tool, status, reply))
        result = reply['result']
        return result.get('structuredContent') or json.loads(result['content'][0]['text'])


def port_open(port):
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=0.2):
            return True
    except OSError:
        return False


def check(cond, what):
    if not cond:
        raise AssertionError(what)


PY = sys.executable

# ---------------------------------------------------------------------------
# Cases. Each gets a fresh Env and must leave no process behind.
# ---------------------------------------------------------------------------


def case_connect_and_list(env):
    env.start_hub()
    env.start_node('alpha')
    check(env.wait_node('alpha'), 'node alpha never appeared in /n: %r' % env.nodes())
    entry = env.nodes()['alpha']
    check(entry.get('inflight') == 0 and isinstance(entry.get('connected_s'), int), entry)


def case_mcp_surface_via_hub(env):
    env.start_hub()
    env.start_node('alpha')
    check(env.wait_node('alpha'), 'node never connected')
    status, reply = env.rpc('alpha', 'initialize', {
        'protocolVersion': '2025-06-18', 'capabilities': {},
        'clientInfo': {'name': 'reverse-suite', 'version': '1'}})
    check(status == 200 and 'serverInfo' in reply.get('result', {}), (status, reply))
    status, reply = env.rpc('alpha', 'tools/list', {})
    names = {t['name'] for t in reply.get('result', {}).get('tools', [])}
    check(status == 200 and {'exec', 'sys_info', 'exec_start'} <= names, (status, sorted(names)))
    info = env.tool('alpha', 'sys_info')
    check(info.get('hostname') == socket.gethostname() or info.get('hostname'), info)
    out = env.tool('alpha', 'exec', {'argv': ['echo', 'through-the-hub'], 'timeout': 10})
    check(out.get('ok') and out.get('stdout') == 'through-the-hub\n', out)


def case_401_without_token(env):
    env.start_hub()
    status, reply = env.post('/n', b'{}', token=False)
    check(status == 401, (status, reply))
    status, reply = env.post('/n/alpha/mcp', {'jsonrpc': '2.0', 'id': 1, 'method': 'ping'}, token='nope')
    check(status == 401, (status, reply))


def case_unknown_node_404(env):
    env.start_hub()
    status, reply = env.rpc('ghost', 'ping')
    check(status == 404 and reply.get('error') == 'unknown_node', (status, reply))


def case_wrong_secret_refused(env):
    hub = env.start_hub()
    node = env.start_node('mallory', secret_file='wrong-secret')
    refused = wait_until(lambda: 'hub refused' in node.logs(), 10, 0.1)
    check(refused, 'node log has no refusal: ' + node.logs()[-1000:])
    check('mallory' not in env.nodes(), env.nodes())
    check('AuthFailed' in hub.logs(), 'hub log has no AuthFailed: ' + hub.logs()[-1000:])
    time.sleep(1.5)  # a retry or two later it still must not appear
    check('mallory' not in env.nodes(), env.nodes())


def case_concurrent_exec(env):
    env.start_hub()
    env.start_node('alpha')
    check(env.wait_node('alpha'), 'node never connected')
    count = 24
    results = [None] * count
    errors = []

    def one(i):
        try:
            marker = 'req-%02d-%s' % (i, secrets.token_hex(4))
            code = 'import time,sys; time.sleep(0.3); sys.stdout.write(sys.argv[1])'
            out = env.tool('alpha', 'exec', {'argv': [PY, '-c', code, marker], 'timeout': 20}, timeout=30)
            results[i] = (marker, out.get('stdout'))
        except Exception as err:  # collected, reported below
            errors.append((i, repr(err)))

    threads = [threading.Thread(target=one, args=(i,)) for i in range(count)]
    started = time.monotonic()
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    elapsed = time.monotonic() - started
    check(not errors, errors[:3])
    mismatched = [r for r in results if r is None or r[0] != r[1]]
    check(not mismatched, mismatched[:3])
    # 24 x 0.3 s serially would be >= 7.2 s; relayed in parallel it is far less.
    check(elapsed < 6.0, 'requests were not concurrent: %.2fs' % elapsed)


def case_hub_restart_keeps_sessions(env):
    hub = env.start_hub()
    env.start_node('alpha')
    check(env.wait_node('alpha'), 'node never connected')
    code = 'import time\nfor i in range(60):\n    print("tick", i, flush=True)\n    time.sleep(0.25)\n'
    started = env.tool('alpha', 'exec_start', {'argv': [PY, '-c', code]})
    check(started.get('ok'), started)
    sid = started['session_id']

    # A request in flight while the hub dies must fail fast, not hang.
    inflight = {}

    def long_call():
        t0 = time.monotonic()
        try:
            inflight['reply'] = env.tool('alpha', 'exec', {'argv': ['sleep', '20'], 'timeout': 30}, timeout=40)
        except (ConnectionError, http.client.HTTPException, OSError) as err:
            inflight['error'] = repr(err)
        inflight['elapsed'] = time.monotonic() - t0

    t = threading.Thread(target=long_call)
    t.start()
    wait_until(lambda: env.nodes().get('alpha', {}).get('inflight', 0) >= 1, 5, 0.05)
    hub.kill9()
    t.join(15)
    check(not t.is_alive(), 'in-flight request hung after hub death')
    check('error' in inflight and inflight['elapsed'] < 10, inflight)

    env.start_hub()
    reconnected = env.wait_node('alpha', 40)
    check(reconnected, 'node did not reconnect within 40 s')
    polled = env.tool('alpha', 'exec_poll', {'session_id': sid})
    check('tick 0' in polled.get('stdout', ''), polled)
    waited = env.tool('alpha', 'exec_wait', {'session_id': sid, 'timeout': 30}, timeout=40)
    check(waited.get('done') and waited.get('exit_code') == 0, waited)
    closed = env.tool('alpha', 'exec_close', {'session_id': sid})
    check(closed.get('ok'), closed)


def case_node_restart_replaces_link(env):
    env.start_hub()
    first = env.start_node('alpha', tag='node-alpha-1')
    check(env.wait_node('alpha'), 'node never connected')
    ppid_code = 'import os; print(os.getppid())'
    out = env.tool('alpha', 'exec', {'argv': [PY, '-c', ppid_code]})
    check(out.get('stdout', '').strip() == str(first.pid), (out, first.pid))
    first.kill9()
    second = env.start_node('alpha', tag='node-alpha-2')

    def served_by_second():
        try:
            reply = env.tool('alpha', 'exec', {'argv': [PY, '-c', ppid_code]})
            return reply.get('stdout', '').strip() == str(second.pid)
        except AssertionError:
            return False
    check(wait_until(served_by_second, 15, 0.2), 'requests never reached the new node')
    check(list(env.nodes()) == ['alpha'], env.nodes())


def case_live_replacement(env):
    """A second node with the same name replaces a live link; the old one
    gets GOAWAY. (It then retries and may take the name back, which is the
    documented behaviour for two holders of one secret.)"""
    env.start_hub()
    first = env.start_node('alpha', tag='node-alpha-1')
    check(env.wait_node('alpha'), 'node never connected')
    env.start_node('alpha', tag='node-alpha-2')
    check(wait_until(lambda: 'replaced by a new link' in first.logs(), 10, 0.1),
          'old link got no GOAWAY: ' + first.logs()[-1000:])
    first.kill9()
    out = wait_until(lambda: _try_exec(env, 'alpha'), 15, 0.2)
    check(out, 'no answer after replacement')


def _try_exec(env, name):
    try:
        out = env.tool(name, 'exec', {'argv': ['echo', 'ok']})
        return out.get('stdout') == 'ok\n'
    except (AssertionError, OSError):
        return False


def case_listen_mode_unaffected(env):
    port = pick_port()
    e = base_env()
    e.update(MCP_NODE_HOST='127.0.0.1', MCP_NODE_PORT=str(port), MCP_NODE_NAME='plain')
    e['MCP_NODE_TOKEN_' + 'FILE'] = str(env.dir / 'client-token')
    proc = env.spawn('plain', e)
    check(wait_until(lambda: port_open(port) or not proc.alive(), 10) and proc.alive(),
          'plain node did not start: ' + proc.logs()[-1000:])
    status, reply = env.post('/mcp', {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {
        'protocolVersion': '2025-06-18', 'capabilities': {},
        'clientInfo': {'name': 'reverse-suite', 'version': '1'}}}, port=port)
    check(status == 200 and 'serverInfo' in reply.get('result', {}), (status, reply))
    status, _ = env.post('/n', b'{}', port=port)
    check(status == 404, 'listen mode must not expose /n: %d' % status)


CASES = [
    ('hub + node connect, node listed in /n', case_connect_and_list),
    ('initialize, tools/list, sys_info, exec via /n/<name>/mcp', case_mcp_surface_via_hub),
    ('401 without or with a wrong client token', case_401_without_token),
    ('unknown node -> 404 unknown_node', case_unknown_node_404),
    ('wrong link secret is refused and never listed', case_wrong_secret_refused),
    ('24 concurrent exec through the hub, answers match requests', case_concurrent_exec),
    ('hub kill -9 + restart: in-flight request fails, exec session survives', case_hub_restart_keeps_sessions),
    ('node restart under the same name takes over', case_node_restart_replaces_link),
    ('same name on a live link replaces it with GOAWAY', case_live_replacement),
    ('default listener mode unaffected', case_listen_mode_unaffected),
]


def main():
    if os.name == 'nt':
        print('SKIP reverse connect suite: needs POSIX signals and echo/sleep')
        return 0
    if not BINARY.exists():
        print('binary not found: %s' % BINARY)
        return 2
    selected = sys.argv[2:]
    failed = 0
    for title, fn in CASES:
        if selected and fn.__name__ not in selected:
            continue
        env = Env()
        t0 = time.monotonic()
        try:
            fn(env)
            print('PASS %s (%.1fs)' % (title, time.monotonic() - t0), flush=True)
        except Exception:
            failed += 1
            print('FAIL %s' % title, flush=True)
            traceback.print_exc()
            for proc in env.procs:
                print('--- %s log tail ---' % proc.log_path.name)
                print(proc.logs()[-1500:])
        finally:
            env.close()
    print('%d case(s) failed' % failed if failed else 'all cases passed')
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
