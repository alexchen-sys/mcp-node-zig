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
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import struct
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


FRAME_CHALLENGE, FRAME_HELLO, FRAME_WELCOME, FRAME_REQ, FRAME_RESP = 2, 1, 3, 4, 5
AUTH_DOMAIN = b'mcp-node-reverse-v1'


def _send_frame(sock, kind, stream_id, payload):
    sock.sendall(struct.pack('>IBI', len(payload), kind, stream_id) + payload)


def _recv_exact(sock, n):
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError('peer closed')
        buf += chunk
    return buf


def _recv_frame(sock):
    length, kind, stream_id = struct.unpack('>IBI', _recv_exact(sock, 9))
    return kind, stream_id, _recv_exact(sock, length)


def _fake_hub_session(env, name, welcome_auth_secret, marker):
    """Play the hub side of one link by hand on a raw socket.

    Sends CHALLENGE, reads HELLO, answers WELCOME with a MAC made from
    `welcome_auth_secret` (None = bogus bytes), then sends a REQ that would
    create `marker` via exec. Returns (frames received after WELCOME, whether
    the node closed the connection).
    """
    port = pick_port()
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('127.0.0.1', port))
    srv.listen(4)
    srv.settimeout(10)
    node = env.start_node(name, target='127.0.0.1:%d' % port)
    try:
        conn, _ = srv.accept()
        conn.settimeout(5)
        with conn:
            hub_nonce = os.urandom(32)
            _send_frame(conn, FRAME_CHALLENGE, 0, hub_nonce)
            kind, _, payload = _recv_frame(conn)
            check(kind == FRAME_HELLO, ('expected HELLO', kind))
            hello = json.loads(payload)
            node_nonce = bytes.fromhex(hello['nonce'])
            check(len(node_nonce) == 32, hello)
            if welcome_auth_secret is None:
                auth = secrets.token_hex(32)
            else:
                msg = AUTH_DOMAIN + b' hub' + hub_nonce + node_nonce + hello['name'].encode()
                auth = hmac.new(welcome_auth_secret.encode(), msg, hashlib.sha256).hexdigest()
            req = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                   'params': {'name': 'exec', 'arguments': {'argv': ['touch', str(marker)], 'timeout': 10}}}
            try:
                _send_frame(conn, FRAME_WELCOME, 0, json.dumps({'v': 1, 'auth': auth}).encode())
                _send_frame(conn, FRAME_REQ, 1, json.dumps(req).encode())
            except OSError:
                pass  # the node may already have closed
            got = []
            closed = False
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                try:
                    got.append(_recv_frame(conn)[0])
                    if FRAME_RESP in got:
                        break
                except socket.timeout:
                    continue
                except (EOFError, OSError):
                    closed = True
                    break
            return got, closed, node
    finally:
        srv.close()


def case_fake_hub_without_secret_refused(env):
    # Control: a hand-written hub that does know the secret is served, so
    # the frames below are well formed and the REQ really runs exec.
    control = env.dir / 'control'
    got, _, node = _fake_hub_session(env, 'ctl', env.secret, control)
    check(FRAME_RESP in got, ('control REQ got no RESP', got, node.logs()[-1000:]))
    check(wait_until(control.exists, 3, 0.1), 'control exec did not run')
    node.stop()

    marker = env.dir / 'pwned'
    got, closed, node = _fake_hub_session(env, 'victim', None, marker)
    check(closed, ('node kept the link to a hub without the secret', got))
    check(not got, ('node answered a hub without the secret', got))
    time.sleep(3)
    check(not marker.exists(), 'REQ from an unauthenticated hub ran exec')
    check('hub authentication failed' in node.logs(), node.logs()[-1000:])
    check(node.alive(), 'node must keep retrying, not exit')


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


def case_live_name_is_kept(env):
    """A second node under a name held by a live link is refused; the live
    link keeps the name and is never evicted. Once the holder dies, the
    second node takes the name at its next retry."""
    hub = env.start_hub()
    first = env.start_node('alpha', tag='node-alpha-1')
    check(env.wait_node('alpha'), 'node never connected')
    ppid_code = 'import os; print(os.getppid())'
    second = env.start_node('alpha', tag='node-alpha-2')
    check(wait_until(lambda: 'name in use by a live link' in second.logs(), 15, 0.1),
          'second node was not refused: ' + second.logs()[-1000:])
    check('name in use by a live link' in hub.logs(), 'hub did not log the refusal')
    # Several retry rounds: the holder must not lose the name even once.
    time.sleep(6)
    check('replaced by a new link' not in first.logs(), first.logs()[-1000:])
    out = env.tool('alpha', 'exec', {'argv': [PY, '-c', ppid_code]})
    check(out.get('stdout', '').strip() == str(first.pid), (out, first.pid))
    first.kill9()

    def served_by_second():
        try:
            reply = env.tool('alpha', 'exec', {'argv': [PY, '-c', ppid_code]})
            return reply.get('stdout', '').strip() == str(second.pid)
        except AssertionError:
            return False
    check(wait_until(served_by_second, 60, 0.3), 'second node never took over the name')


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


def case_second_listener_refused(env):
    """A second process on a taken client or link port must fail with
    AddressInUse instead of co-binding it and taking half of the traffic."""
    hub = env.start_hub()
    for port, tag in ((env.hub_port, 'dup-client'), (env.link_port, 'dup-link')):
        e = base_env()
        e.update(MCP_NODE_HOST='127.0.0.1', MCP_NODE_PORT=str(port if tag == 'dup-client' else pick_port()),
                 MCP_NODE_NAME=tag, MCP_NODE_HUB_LISTEN='127.0.0.1:%d' % (
                     env.link_port if tag == 'dup-link' else pick_port()),
                 MCP_NODE_HUB_SECRET_FILE=str(env.dir / 'hub-secrets'))
        e['MCP_NODE_TOKEN_' + 'FILE'] = str(env.dir / 'client-token')
        dup = env.spawn(tag, e)
        check(wait_until(lambda: not dup.alive(), 10), tag + ' co-bound a taken port: ' + dup.logs()[-800:])
        check(dup.process.returncode != 0, (tag, dup.process.returncode))
        check('AddressInUse' in dup.logs(), dup.logs()[-800:])
    check(hub.alive(), 'first hub died')
    env.start_node('alpha')
    check(env.wait_node('alpha'), 'first hub stopped serving links')


class SkipCase(Exception):
    pass


def _openssl(*args, cwd):
    subprocess.run(['openssl', *args], cwd=cwd, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _make_ca(d, tag):
    _openssl('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
             '-nodes', '-days', '2', '-subj', '/CN=throwaway %s ca' % tag,
             '-addext', 'basicConstraints=critical,CA:TRUE',
             '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
             '-keyout', '%s-ca.key' % tag, '-out', '%s-ca.pem' % tag, cwd=d)


def _make_server_cert(d, ca_tag):
    (Path(d) / 'ext.cnf').write_text(
        'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\n'
        'extendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n')
    _openssl('req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
             '-subj', '/CN=localhost', '-keyout', 'server.key', '-out', 'server.csr', cwd=d)
    _openssl('x509', '-req', '-in', 'server.csr', '-CA', '%s-ca.pem' % ca_tag,
             '-CAkey', '%s-ca.key' % ca_tag, '-CAcreateserial', '-days', '2',
             '-extfile', 'ext.cnf', '-out', 'server.pem', cwd=d)


class TlsTerminator:
    """TLS server on loopback that pipes each connection to a plain port."""

    def __init__(self, cert, key, upstream_port):
        import ssl
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(cert, key)
        self.upstream_port = upstream_port
        self.port = pick_port()
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('127.0.0.1', self.port))
        self.sock.listen(8)
        self.closed = False
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while not self.closed:
            try:
                raw, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(raw,), daemon=True).start()

    def _serve(self, raw):
        try:
            tls = self.ctx.wrap_socket(raw, server_side=True)
        except OSError:
            raw.close()
            return
        try:
            up = socket.create_connection(('127.0.0.1', self.upstream_port), timeout=5)
        except OSError:
            tls.close()
            return
        up.settimeout(None)
        tls.settimeout(None)

        def pump(src, dst):
            try:
                while True:
                    data = src.recv(65536)
                    if not data:
                        break
                    dst.sendall(data)
            except OSError:
                pass
            for s in (src, dst):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

        threading.Thread(target=pump, args=(up, tls), daemon=True).start()
        pump(tls, up)

    def close(self):
        self.closed = True
        self.sock.close()


def case_tls_link(env):
    import shutil
    if shutil.which('openssl') is None:
        raise SkipCase('openssl CLI not found')
    d = str(env.dir)
    _make_ca(d, 'good')
    _make_ca(d, 'other')
    _make_server_cert(d, 'good')
    env.start_hub()
    term = TlsTerminator(str(env.dir / 'server.pem'), str(env.dir / 'server.key'), env.link_port)
    try:
        target = 'localhost:%d' % term.port
        env.start_node('tlsnode', target=target, extra={
            'MCP_NODE_CONNECT_TLS': '1', 'MCP_NODE_CONNECT_CA_FILE': str(env.dir / 'good-ca.pem')})
        check(env.wait_node('tlsnode', 15), 'TLS node never appeared in /n')
        out = env.tool('tlsnode', 'exec', {'argv': ['echo', 'over-tls'], 'timeout': 10})
        check(out.get('ok') and out.get('stdout') == 'over-tls\n', out)

        # 16 concurrent exec over one TLS link: RESP writes from many
        # workers interleave with the reader decrypting REQ records.
        results = {}

        def one(i):
            try:
                r = env.tool('tlsnode', 'exec', {'argv': ['echo', 'tls-%d' % i], 'timeout': 20}, timeout=40)
                results[i] = r.get('stdout')
            except Exception as e:  # recorded, checked below
                results[i] = repr(e)
        threads = [threading.Thread(target=one, args=(i,)) for i in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(60)
        bad_answers = {i: v for i, v in results.items() if v != 'tls-%d\n' % i}
        check(len(results) == 16 and not bad_answers, bad_answers or results)
        check('tlsnode' in env.nodes(), 'TLS link dropped under concurrency')

        bad = env.start_node('tlsbad', target=target, extra={
            'MCP_NODE_CONNECT_TLS': '1', 'MCP_NODE_CONNECT_CA_FILE': str(env.dir / 'other-ca.pem')})
        failed = wait_until(lambda: 'TLS handshake failed' in bad.logs(), 10, 0.1)
        check(failed, 'untrusted CA was not rejected: ' + bad.logs()[-1000:])
        time.sleep(1.5)
        check('tlsbad' not in env.nodes(), env.nodes())
        check(bad.alive(), 'node must keep retrying, not exit')
    finally:
        term.close()


CASES = [
    ('hub + node connect, node listed in /n', case_connect_and_list),
    ('initialize, tools/list, sys_info, exec via /n/<name>/mcp', case_mcp_surface_via_hub),
    ('401 without or with a wrong client token', case_401_without_token),
    ('unknown node -> 404 unknown_node', case_unknown_node_404),
    ('wrong link secret is refused and never listed', case_wrong_secret_refused),
    ('fake hub without secret is refused', case_fake_hub_without_secret_refused),
    ('24 concurrent exec through the hub, answers match requests', case_concurrent_exec),
    ('hub kill -9 + restart: in-flight request fails, exec session survives', case_hub_restart_keeps_sessions),
    ('node restart under the same name takes over', case_node_restart_replaces_link),
    ('a live name is kept, a second node is refused', case_live_name_is_kept),
    ('default listener mode unaffected', case_listen_mode_unaffected),
    ('a second listener on a taken port fails with AddressInUse', case_second_listener_refused),
    ('TLS link: trusted CA connects and serves exec, other CA never appears', case_tls_link),
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
        except SkipCase as why:
            print('SKIP %s: %s' % (title, why), flush=True)
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
