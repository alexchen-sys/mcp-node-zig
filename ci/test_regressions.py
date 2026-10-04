#!/usr/bin/env python3
"""Regression harness for the mcp-node HTTP/JSON-RPC/exec contract.

Covers, black-box over raw sockets and JSON-RPC:
  * POSIX process-tree lifecycle (leader exit must kill the group; done
    implies drained output; start/close race stability)
  * strict HTTP/1.1 framing (request line, header grammar, Transfer-Encoding
    refusal, duplicate/conflicting headers, strict Content-Type)
  * gates before body read (auth/method/path/413/503 answered from headers
    alone, never after a forced 32 MiB read)
  * global in-flight body budget (MCP_NODE_MAX_INFLIGHT_BYTES)
  * strict JSON-RPC envelope (jsonrpc=="2.0", id typing, notification rules,
    params/arguments typing)
  * failed-spawn hygiene (missing/invalid argv[0] never leaks zombies)
  * list_dir truncation contract (truncated + has_more + count)

Run: python3 ci/test_regressions.py [path/to/mcp-node]
Default binary: zig-out/bin/mcp-node (.exe on Windows), resolved against the
repo root (parent of this file's directory).

Cross-platform: process-tree tests are POSIX-flavored; on Windows the
descendant-liveness check uses OpenProcess (Job Object semantics cover the
tree there). No fixed ports, no sleeps for state: every wait is a bounded
poll on an observable condition.
"""
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parent.parent
BINARY = Path(sys.argv.pop(1) if len(sys.argv) > 1 and not sys.argv[1].startswith('-')
              else ROOT / 'zig-out' / 'bin' / ('mcp-node.exe' if os.name == 'nt' else 'mcp-node')).resolve()

BODY_CAP = 32 * 1024 * 1024
HEADER_CAP = 64 * 1024


def free_port():
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        return probe.getsockname()[1]


# Bytes read past one response that belong to the next response on the same
# connection (coalesced pipelined delivery), keyed by the socket object.
# socket.socket forbids attribute assignment (no __dict__), so a side table
# with pop-on-read semantics holds them; entries only persist while bytes
# are actually pending.
_response_overread = {}


def read_http_response(sock, deadline_s=8.0):
    """Read one HTTP/1.1 response; returns (status, reason, headers, body).

    Bytes over-read past this response (a pipelined next response delivered
    in the same recv) are kept for the next call on the same socket, so
    coalesced delivery never loses a response."""
    sock.settimeout(deadline_s)
    data = _response_overread.pop(id(sock), b'')
    while b'\r\n\r\n' not in data:
        chunk = sock.recv(65536)
        if not chunk:
            raise AssertionError('connection closed before response head: %r' % data[:200])
        data += chunk
    head, rest = data.split(b'\r\n\r\n', 1)
    lines = head.split(b'\r\n')
    parts = lines[0].split(b' ', 2)
    if len(parts) < 2 or not parts[1].isdigit():
        raise AssertionError('bad status line: %r' % lines[0])
    status = int(parts[1])
    reason = parts[2].decode('latin1') if len(parts) > 2 else ''
    headers = {}
    for line in lines[1:]:
        name, _, value = line.partition(b':')
        headers[name.strip().lower().decode('latin1')] = value.strip().decode('latin1')
    length = int(headers.get('content-length', '0'))
    body = rest
    while len(body) < length:
        chunk = sock.recv(65536)
        if not chunk:
            raise AssertionError('connection closed mid-body: %d/%d bytes' % (len(body), length))
        body += chunk
    leftover = body[length:]
    if leftover:
        _response_overread[id(sock)] = leftover
    return status, reason, headers, body[:length]


def err_code(reply):
    """JSON-RPC error code or None (keeps RED failures as assertions, not KeyErrors)."""
    if not isinstance(reply, dict):
        return None
    err = reply.get('error')
    return err.get('code') if isinstance(err, dict) else None


class Node:
    """One isolated daemon: dynamic loopback port, random token, temp root."""

    def __init__(self, **config):
        self.temp = tempfile.TemporaryDirectory(prefix='mcp-regress-')
        self.root = Path(self.temp.name)
        self.secret = secrets.token_hex(24)
        auth = self.root / 'auth-fixture'
        auth.write_text(self.secret)
        self.port = free_port()
        env = {key: value for key, value in os.environ.items() if not key.startswith('MCP_NODE_')}
        env.update(MCP_NODE_HOST='127.0.0.1', MCP_NODE_PORT=str(self.port),
                   MCP_NODE_NAME='regression-node', MCP_NODE_SOCKET_TIMEOUT_S='3')
        env['MCP_NODE_TOKEN_' + 'FILE'] = str(auth)
        env.update({key: str(value) for key, value in config.items()})
        self.log = (self.root / 'daemon.log').open('w+b')
        self.process = subprocess.Popen([str(BINARY)], cwd=self.root, env=env,
                                        stdout=self.log, stderr=self.log)
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if self.process.poll() is not None:
                    raise RuntimeError('daemon exited before readiness: ' + self.logs())
                try:
                    with socket.create_connection(('127.0.0.1', self.port), timeout=.2):
                        break
                except OSError:
                    time.sleep(.025)
            else:
                raise RuntimeError('daemon readiness timeout: ' + self.logs())
        except BaseException:
            self.close()
            raise

    def logs(self):
        self.log.flush()
        return (self.root / 'daemon.log').read_text(errors='replace')[-4000:]

    # ---- transport helpers -------------------------------------------------

    def connect(self):
        return socket.create_connection(('127.0.0.1', self.port), timeout=10)

    def raw_request(self, head, body=b'', sock=None):
        """Send a literal request head (+ optional body), read one response."""
        own = sock is None
        sock = sock or self.connect()
        try:
            sock.sendall(head + body)
            return read_http_response(sock)
        finally:
            if own:
                sock.close()

    def head_for(self, body_len, extra_headers=(), token=None, method=b'POST', path=b'/mcp',
                 version=b'HTTP/1.1', content_type=b'application/json'):
        """Build a literal request head. token=False omits X-Node-Token."""
        lines = [method + b' ' + path + b' ' + version,
                 b'Host: 127.0.0.1:' + str(self.port).encode(),
                 b'Content-Length: ' + str(body_len).encode()]
        if content_type is not None:
            lines.append(b'Content-Type: ' + content_type)
        if token is not False:
            tok = self.secret if token is None else token
            lines.append(b'X-Node-Token: ' + tok.encode())
        lines.extend(extra_headers)
        return b'\r\n'.join(lines) + b'\r\n\r\n'

    def rpc(self, payload, **overrides):
        body = json.dumps(payload).encode()
        status, _, _, data = self.raw_request(self.head_for(len(body), **overrides), body)
        return status, json.loads(data) if data else None

    def tool(self, name, arguments=None, expect=200):
        status, reply = self.rpc({'jsonrpc': '2.0', 'id': 7, 'method': 'tools/call',
                                  'params': {'name': name, 'arguments': arguments or {}}})
        if status != expect:
            raise AssertionError((status, reply))
        if expect != 200:
            return reply
        if 'result' not in reply:
            raise AssertionError(reply)
        result = reply['result']
        return result.get('structuredContent', json.loads(result['content'][0]['text']))

    # ---- lifecycle ---------------------------------------------------------

    def close(self):
        if self.process.poll() is None:
            try:
                for session in self.tool('exec_list').get('sessions', []):
                    self.tool('exec_close', {'session_id': session['session_id']})
            except Exception:
                pass
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.log.close()
        self.temp.cleanup()


def kill_pid(pid):
    try:
        os.kill(pid, 9)
    except (ProcessLookupError, PermissionError, OSError):
        pass


def zombie_direct_children(pid):
    """Direct children of `pid` that are zombies, via /proc (Linux only)."""
    zombies = []
    proc = Path('/proc')
    if not proc.is_dir():
        return None
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            data = (entry / 'stat').read_bytes()
        except OSError:
            continue
        # The comm field may contain spaces and parens; state and ppid sit
        # after the final ')'.
        rest = data.rsplit(b')', 1)[1].split()
        if len(rest) < 2:
            continue
        if int(rest[1]) == pid and rest[0] in (b'Z', b'X'):
            zombies.append((int(entry.name), rest[0].decode()))
    return zombies


class ExecSpawnHygieneTests(unittest.TestCase):
    """Failed spawns must never leak zombie children.

    std's POSIX spawn returns execve failures without reaping the forked
    child; the node pre-flights argv[0]/cwd so the common failures never
    fork, and sweeps strays for residual execve errors (ENOEXEC etc.)."""

    def setUp(self):
        self.node = Node()
        self.addCleanup(self.node.close)

    def test_failed_spawns_leave_no_zombies(self):
        if zombie_direct_children(1) is None:
            self.skipTest('/proc not available (Linux-only contract)')
        missing = '/nonexistent/mcpnz-zombie-probe'
        for ident in range(5):
            reply = self.node.tool('exec', {'argv': [missing], 'timeout': 5})
            self.assertFalse(reply.get('ok'), reply)
            self.assertEqual(reply.get('error'), 'FileNotFound', reply)
        for ident in range(3):
            reply = self.node.tool('exec_start', {'argv': [missing]})
            self.assertFalse(reply.get('ok'), reply)
            self.assertEqual(reply.get('error'), 'FileNotFound', reply)
        # ENOEXEC: an executable file with an invalid format passes the
        # pre-flight, fails the real execve, and must be reaped by the sweep.
        garbage = self.node.root / 'garbage-probe'
        garbage.write_text('not a program\n')
        garbage.chmod(0o755)
        for ident in range(3):
            reply = self.node.tool('exec', {'argv': [str(garbage)], 'timeout': 5})
            self.assertFalse(reply.get('ok'), reply)
            self.assertEqual(reply.get('error'), 'InvalidExe', reply)
        reply = self.node.tool('exec_start', {'argv': [str(garbage)]})
        self.assertFalse(reply.get('ok'), reply)
        self.assertEqual(reply.get('error'), 'InvalidExe', reply)
        # A missing cwd is pre-flighted the same way (child-side chdir would
        # otherwise fail post-fork).
        reply = self.node.tool('exec', {'argv': [sys.executable, '-c', 'pass'],
                                        'cwd': '/nonexistent/mcpnz-dir'})
        self.assertFalse(reply.get('ok'), reply)
        self.assertEqual(reply.get('error'), 'FileNotFound', reply)
        # Sanity: successful execs still work on the same daemon.
        ok = self.node.tool('exec', {'argv': [sys.executable, '-c', 'print("z")']})
        self.assertTrue(ok.get('ok'), ok)
        self.assertEqual(ok.get('exit_code'), 0, ok)
        # Bounded drain: sweeps run on exec-family call exit, so any stray
        # still dying at check time is gone after one more call.
        deadline = time.monotonic() + 5
        while True:
            zombies = zombie_direct_children(self.node.process.pid)
            if not zombies:
                break
            if time.monotonic() >= deadline:
                self.fail('failed spawns leaked zombie children: %r' % zombies)
            self.node.tool('exec', {'argv': [sys.executable, '-c', 'pass']})
            time.sleep(0.05)


def pid_alive_posix(pid):
    """Linux: /proc state (zombie counts as dead). Other POSIX: kill(pid, 0)."""
    if Path('/proc').is_dir():
        try:
            data = Path('/proc/%d/stat' % pid).read_bytes()
            state = data.rsplit(b')', 1)[1].split()[0]
            return state not in (b'Z', b'X')
        except FileNotFoundError:
            return False
        except OSError:
            pass
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def pid_alive_windows(pid):
    import ctypes
    handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)  # QUERY_LIMITED_INFORMATION
    if not handle:
        return False
    try:
        code = ctypes.c_ulong(0)
        if not ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
            return False
        return code.value == 259  # STILL_ACTIVE
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)


def pid_alive(pid):
    if sys.platform == 'win32':
        return pid_alive_windows(pid)
    return pid_alive_posix(pid)


def wait_pid_dead(pid, timeout_s=6.0):
    """Bounded poll on an observable condition (no blind sleeps)."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if not pid_alive(pid):
            return True
        time.sleep(0.05)
    return not pid_alive(pid)


class TreeTests(unittest.TestCase):
    """Process-tree lifecycle. POSIX exercises the group-kill contract; the
    Windows run covers the same descendant-liveness assertions through the
    Job Object path (same test, platform-specific liveness probe)."""

    def setUp(self):
        self.node = Node()
        self.addCleanup(self.node.close)
        self.descendants = []
        self.addCleanup(self._reap_descendants)

    def _reap_descendants(self):
        for pid in self.descendants:
            kill_pid(pid)

    def _spawn_with_descendant(self, marker):
        pid_file = self.node.root / ('descendant-%s.pid' % marker)
        if sys.platform == 'win32':
            code = ('import subprocess,pathlib,sys;'
                    'p=subprocess.Popen([sys.executable,"-c","import time;time.sleep(90)"],'
                    'stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);'
                    'pathlib.Path(sys.argv[1]).write_text(str(p.pid))')
        else:
            # Same process group as the leader (default POSIX spawn), stdout
            # detached: the leader-exit-leaks-the-group case.
            code = ('import subprocess,pathlib,sys;'
                    'p=subprocess.Popen([sys.executable,"-c","import time;time.sleep(90)"],'
                    'stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);'
                    'pathlib.Path(sys.argv[1]).write_text(str(p.pid))')
        started = self.node.tool('exec_start', {'argv': [sys.executable, '-c', code, str(pid_file)]})
        self.assertTrue(started.get('ok'), started)
        sid = started['session_id']
        waited = self.node.tool('exec_wait', {'session_id': sid, 'timeout': 10})
        self.assertTrue(waited.get('done'), waited)
        self.assertEqual(waited.get('exit_code'), 0, waited)
        deadline = time.monotonic() + 3
        while not pid_file.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(pid_file.exists(), 'descendant pid file never appeared')
        pid = int(pid_file.read_text())
        self.descendants.append(pid)
        return sid, pid

    def test_descendant_dead_after_leader_exit_and_close(self):
        """Leader spawns a child in the same process group and
        exits; exec_wait reports done; the tree must not survive the session."""
        sid, pid = self._spawn_with_descendant('close')
        self.assertTrue(wait_pid_dead(pid),
                        'descendant %d still alive after leader exit (tree not killed)' % pid)
        closed = self.node.tool('exec_close', {'session_id': sid})
        self.assertTrue(closed.get('ok'), closed)
        self.assertFalse(pid_alive(pid), 'descendant %d alive after exec_close' % pid)

    def test_done_means_output_drained(self):
        payload = 65536
        started = self.node.tool('exec_start', {'argv': [sys.executable, '-c',
            'import os,sys; os.write(1, b"x"*%d); os.write(2, b"y"*1024)' % payload]})
        self.assertTrue(started.get('ok'), started)
        state = self.node.tool('exec_wait', {'session_id': started['session_id'], 'timeout': 10})
        self.assertTrue(state.get('done'), state)
        self.assertEqual(len(state.get('stdout', '')), payload,
                         'done=true but stdout not fully drained')
        self.assertEqual(len(state.get('stderr', '')), 1024)
        self.node.tool('exec_close', {'session_id': started['session_id']})

    def test_start_close_race_is_stable(self):
        """exec_close racing the tail of exec_start must never crash or hang
        the daemon (the publisher must hold its own session reference)."""
        for round_no in range(30):
            marker = 'race-%d-%s' % (round_no, secrets.token_hex(4))
            outcome = {}

            def starter():
                try:
                    outcome['start'] = self.node.tool('exec_start', {'argv': [
                        sys.executable, '-c', 'import time,sys; time.sleep(30)', marker]})
                except Exception as exc:  # close may legitimately win mid-flight
                    outcome['start_error'] = exc

            thread = threading.Thread(target=starter)
            thread.start()
            deadline = time.monotonic() + 3
            closed = None
            while time.monotonic() < deadline:
                sessions = self.node.tool('exec_list').get('sessions', [])
                match = [s for s in sessions if marker in s.get('argv', [])]
                if match:
                    closed = self.node.tool('exec_close', {'session_id': match[0]['session_id']})
                    break
                if not thread.is_alive():
                    break
                time.sleep(0.002)
            thread.join(timeout=10)
            self.assertFalse(thread.is_alive(), 'exec_start hung in round %d' % round_no)
            if closed is not None:
                self.assertTrue(closed.get('ok'), closed)
            elif outcome.get('start', {}).get('ok'):
                self.node.tool('exec_close', {'session_id': outcome['start']['session_id']})
        status, reply = self.node.rpc({'jsonrpc': '2.0', 'id': 9, 'method': 'ping'})
        self.assertEqual(status, 200, 'daemon unhealthy after start/close race hammer')
        self.assertEqual(reply.get('result'), {})


class FramingTests(unittest.TestCase):
    def setUp(self):
        self.node = Node()
        self.addCleanup(self.node.close)

    def status_only(self, head, body=b'', deadline_s=8.0):
        sock = self.node.connect()
        try:
            sock.sendall(head + body)
            status, _, _, _ = read_http_response(sock, deadline_s)
            return status
        finally:
            sock.close()

    def test_request_line_version_enforced(self):
        body = b'{"jsonrpc":"2.0","id":1,"method":"ping"}'
        for version in (b'HTTP/1.0', b'HTTP/2', b'HTTP/1.1-extra'):
            with self.subTest(version=version):
                head = self.node.head_for(len(body), version=version)
                self.assertEqual(self.status_only(head, body), 400)
        good = self.node.head_for(len(body))
        self.assertEqual(self.status_only(good, body), 200)

    def test_request_line_shape_enforced(self):
        body = b'{"jsonrpc":"2.0","id":1,"method":"ping"}'
        tail = self.node.head_for(len(body)).split(b'\r\n', 1)[1]
        extra = b'POST /mcp HTTP/1.1 junk\r\n' + tail
        self.assertEqual(self.status_only(extra, body), 400)
        double_space = b'POST  /mcp HTTP/1.1\r\n' + tail
        self.assertEqual(self.status_only(double_space, body), 400)

    def test_transfer_encoding_rejected(self):
        body = b'{"jsonrpc":"2.0","id":1,"method":"ping"}'
        head = self.node.head_for(len(body), extra_headers=[b'Transfer-Encoding: chunked'])
        self.assertEqual(self.status_only(head, body), 400)

    def test_content_type_strict(self):
        body = b'{"jsonrpc":"2.0","id":1,"method":"ping"}'
        for ct in (b'application/json-not-real', b'application/jsonx', b'text/json',
                   b'application/json2', b'application/JSONP'):
            with self.subTest(ct=ct):
                self.assertEqual(self.status_only(self.node.head_for(len(body), content_type=ct), body), 415)
        for ct in (b'application/json', b'application/json; charset=utf-8',
                   b'application/json;charset=UTF-8', b'Application/JSON'):
            with self.subTest(ct=ct):
                self.assertEqual(self.status_only(self.node.head_for(len(body), content_type=ct), body), 200)

    def test_duplicate_security_headers_rejected(self):
        body = b'{"jsonrpc":"2.0","id":1,"method":"ping"}'
        host = b'Host: 127.0.0.1:' + str(self.node.port).encode()
        dup_host = self.node.head_for(len(body), extra_headers=[host])
        self.assertEqual(self.status_only(dup_host, body), 400)
        token_line = b'X-Node-Token: ' + self.node.secret.encode()
        dup_token = self.node.head_for(len(body), extra_headers=[token_line])
        self.assertEqual(self.status_only(dup_token, body), 400)
        dup_ct = self.node.head_for(len(body), extra_headers=[b'Content-Type: application/json'])
        self.assertEqual(self.status_only(dup_ct, body), 400)

    def test_conflicting_content_length_rejected(self):
        body = b'{"jsonrpc":"2.0","id":1,"method":"ping"}'
        head = self.node.head_for(len(body), extra_headers=[b'Content-Length: 1'])
        self.assertEqual(self.status_only(head, body), 400)

    def test_header_grammar_rejected(self):
        body = b'{"jsonrpc":"2.0","id":1,"method":"ping"}'
        port = str(self.node.port).encode()
        cl = b'Content-Length: ' + str(len(body)).encode()
        token = b'X-Node-Token: ' + self.node.secret.encode()
        obs_fold = (b'POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:' + port +
                    b'\r\nContent-Type: application/json\r\n ' + token +
                    b'\r\n' + cl + b'\r\n\r\n')
        self.assertEqual(self.status_only(obs_fold, body), 400)
        spaced = (b'POST /mcp HTTP/1.1\r\nHost : 127.0.0.1:' + port +
                  b'\r\nContent-Type: application/json\r\n' + token +
                  b'\r\n' + cl + b'\r\n\r\n')
        self.assertEqual(self.status_only(spaced, body), 400)
        ctrl = (b'POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:' + port +
                b'\r\nContent-Type: application/json\r\n' + token +
                b'\r\nX-Bad: a\x07b\r\n' + cl + b'\r\n\r\n')
        self.assertEqual(self.status_only(ctrl, body), 400)

    def test_gates_answer_before_body_read(self):
        """A rejected request must be answered from headers alone: no client
        may force a 32 MiB read before a 401/404/405/415."""
        huge = BODY_CAP
        cases = [
            ('unauthorized', dict(token='wrong-token'), 401),
            ('bad method', dict(method=b'GET'), 405),
            ('bad path', dict(path=b'/nope'), 404),
            ('bad content type', dict(content_type=b'text/plain'), 415),
        ]
        for name, kw, cases_expected in cases:
            with self.subTest(name=name):
                head = self.node.head_for(huge, **kw)
                sock = self.node.connect()
                try:
                    started = time.monotonic()
                    sock.sendall(head)
                    status, _, _, _ = read_http_response(sock, deadline_s=8)
                    elapsed = time.monotonic() - started
                finally:
                    sock.close()
                self.assertEqual(status, cases_expected)
                self.assertLess(elapsed, 1.5,
                                'gate answered only after %.2fs (body read before gate?)' % elapsed)

    def test_expect_continue_never_precedes_gate_rejection(self):
        """Expect: 100-continue must not let a rejected request skip the
        gates: the first status line is the rejection, never 100."""
        cases = [
            ('unauthorized', dict(token='wrong-token'), 401),
            ('bad path', dict(path=b'/nope'), 404),
            ('bad content type', dict(content_type=b'text/plain'), 415),
        ]
        for name, kw, expected in cases:
            with self.subTest(name=name):
                head = self.node.head_for(1024, extra_headers=[b'Expect: 100-continue'], **kw)
                sock = self.node.connect()
                try:
                    sock.sendall(head)
                    status, _, _, _ = read_http_response(sock, deadline_s=8)
                finally:
                    sock.close()
                self.assertEqual(status, expected,
                                 '%s: got %d before the gate answer' % (name, status))

    def test_expect_continue_sent_before_body_when_accepted(self):
        body = json.dumps({'jsonrpc': '2.0', 'id': 9, 'method': 'ping'}).encode()
        head = self.node.head_for(len(body), extra_headers=[b'Expect: 100-continue'])
        sock = self.node.connect()
        try:
            sock.sendall(head)
            status, _, _, _ = read_http_response(sock, deadline_s=8)
            self.assertEqual(status, 100, 'accepted request with Expect got %d instead of 100' % status)
            sock.sendall(body)
            status, _, _, data = read_http_response(sock, deadline_s=8)
        finally:
            sock.close()
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data).get('id'), 9)

    def test_rejection_survives_unread_body(self):
        """A rejection answered before the body is read must reach a client
        that already streamed (part of) that body, and the connection must
        end with FIN, not RST: closing a socket with unread input sends RST,
        and many TCP stacks (Windows, macOS) drop not-yet-read response bytes
        when it arrives. Linux keeps them, so the RST itself is what this
        test observes: after the response, the next read must be a clean
        EOF. The client deliberately reads late."""
        payload = b'x' * (128 * 1024)
        cases = [
            ('unauthorized', dict(token='wrong-token'), len(payload), 401),
            ('bad path', dict(path=b'/nope'), len(payload), 404),
            ('oversize', dict(), BODY_CAP + 1, 413),
        ]
        for name, kw, declared, expected in cases:
            for round_no in range(5):
                with self.subTest(name=name, round=round_no):
                    sock = self.node.connect()
                    head = self.node.head_for(declared, **kw)

                    def stream():
                        try:
                            sock.sendall(head + payload)
                        except OSError:
                            pass  # the server may legitimately stop reading

                    sender = threading.Thread(target=stream)
                    try:
                        sender.start()
                        sender.join(timeout=5)
                        time.sleep(0.4)  # let the server answer and close first
                        try:
                            status, _, _, _ = read_http_response(sock, deadline_s=8)
                        except ConnectionResetError as exc:
                            self.fail('%s: response destroyed by RST: %r' % (name, exc))
                        try:
                            tail = sock.recv(1)
                        except ConnectionResetError as exc:
                            self.fail('%s: connection reset after response: %r' % (name, exc))
                        self.assertEqual(tail, b'', '%s: expected clean EOF after response' % name)
                    finally:
                        sock.close()
                    self.assertEqual(status, expected)

    def test_oversize_body_413_before_read(self):
        head = self.node.head_for(BODY_CAP + 1)
        sock = self.node.connect()
        try:
            started = time.monotonic()
            sock.sendall(head)
            status, _, _, _ = read_http_response(sock, deadline_s=8)
            elapsed = time.monotonic() - started
        finally:
            sock.close()
        self.assertEqual(status, 413)
        self.assertLess(elapsed, 1.5)

    def test_max_size_body_accepted(self):
        pad = BODY_CAP - 90
        payload = {'jsonrpc': '2.0', 'id': 1, 'method': 'ping',
                   'params': {'pad': 'x' * pad}}
        body = json.dumps(payload).encode()
        self.assertLessEqual(len(body), BODY_CAP)
        status, reply = self.node.rpc(payload)
        self.assertEqual(status, 200)
        self.assertEqual(reply.get('result'), {})

    def test_headers_over_cap_431(self):
        filler = b'X-Fill: ' + b'a' * (HEADER_CAP + 1024)
        head = (b'POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:' + str(self.node.port).encode() +
                b'\r\n' + filler + b'\r\nContent-Length: 0\r\n\r\n')
        self.assertEqual(self.status_only(head), 431)

    def test_absolute_request_deadline(self):
        """A dribbled body must hit the absolute request deadline, not a fresh
        per-read timeout: with a 3s budget and a 1.3s dribble the server must
        give up near 3.0s, not ~3.9s (one full extra read timeout)."""
        head = self.node.head_for(5)
        sock = self.node.connect()
        try:
            sock.settimeout(15)
            sock.sendall(head)
            started = time.monotonic()
            for _ in range(2):
                time.sleep(1.3)
                sock.sendall(b'{')
            try:
                status, _, _, _ = read_http_response(sock, deadline_s=15)
            except (socket.timeout, ConnectionError, AssertionError):
                status = None
            elapsed = time.monotonic() - started
        finally:
            sock.close()
        self.assertGreater(elapsed, 2.5, 'server gave up before any real wait: %r' % status)
        self.assertLess(elapsed, 3.45,
                        'deadline not absolute: %.2fs elapsed (fresh per-read timeout)' % elapsed)

    def test_pipelined_requests_do_not_desync(self):
        """Two full requests written in one shot: either two answers in order
        (carried bytes) or one answer + connection close. Never a silent drop
        on an open connection."""
        first = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'ping'}).encode()
        second = json.dumps({'jsonrpc': '2.0', 'id': 2, 'method': 'ping'}).encode()
        sock = self.node.connect()
        try:
            sock.sendall(self.node.head_for(len(first)) + first +
                         self.node.head_for(len(second)) + second)
            s1, _, h1, b1 = read_http_response(sock)
            self.assertEqual(s1, 200)
            self.assertEqual(json.loads(b1).get('id'), 1)
            if h1.get('connection', '').lower() == 'close':
                return  # explicit safe refusal: no bytes misinterpreted
            s2, _, _, b2 = read_http_response(sock)
            self.assertEqual(s2, 200)
            self.assertEqual(json.loads(b2).get('id'), 2)
        finally:
            sock.close()

    def test_keep_alive_sequential(self):
        sock = self.node.connect()
        try:
            for ident in (1, 2, 3):
                body = json.dumps({'jsonrpc': '2.0', 'id': ident, 'method': 'ping'}).encode()
                status, _, _, data = self.node.raw_request(self.node.head_for(len(body)), body, sock)
                self.assertEqual(status, 200)
                self.assertEqual(json.loads(data).get('id'), ident)
        finally:
            sock.close()


class BudgetTests(unittest.TestCase):
    def test_budget_config_rejected_when_invalid(self):
        for bad in ('abc', '1024'):
            with self.subTest(value=bad):
                root = Path(tempfile.mkdtemp(prefix='mcp-budget-cfg-'))
                self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
                auth = root / 'auth'
                auth.write_text('x')
                env = {k: v for k, v in os.environ.items() if not k.startswith('MCP_NODE_')}
                env.update(MCP_NODE_HOST='127.0.0.1', MCP_NODE_PORT=str(free_port()),
                           MCP_NODE_MAX_INFLIGHT_BYTES=bad)
                env['MCP_NODE_TOKEN_' + 'FILE'] = str(auth)
                proc = subprocess.Popen([str(BINARY)], cwd=root, env=env,
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                try:
                    try:
                        code = proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=5)
                        self.fail('daemon accepted MCP_NODE_MAX_INFLIGHT_BYTES=%r and started' % bad)
                    self.assertNotEqual(code, 0, 'invalid budget config must fail startup')
                finally:
                    if proc.poll() is None:
                        proc.kill()
                        proc.wait(timeout=5)

    def test_budget_exceeded_503_without_body_read(self):
        node = Node(MCP_NODE_MAX_INFLIGHT_BYTES=str(1024 * 1024))
        self.addCleanup(node.close)
        head = node.head_for(2 * 1024 * 1024)
        sock = node.connect()
        try:
            started = time.monotonic()
            sock.sendall(head)
            status, _, _, _ = read_http_response(sock, deadline_s=8)
            elapsed = time.monotonic() - started
        finally:
            sock.close()
        self.assertEqual(status, 503)
        self.assertLess(elapsed, 1.5)

    def test_budget_released_between_requests(self):
        node = Node(MCP_NODE_MAX_INFLIGHT_BYTES=str(1024 * 1024))
        self.addCleanup(node.close)
        pad = 600 * 1024
        for round_no in range(2):
            with self.subTest(round=round_no):
                status, reply = node.rpc({'jsonrpc': '2.0', 'id': round_no, 'method': 'ping',
                                          'params': {'pad': 'x' * pad}})
                self.assertEqual(status, 200)
                self.assertEqual(reply.get('result'), {})

    def test_budget_concurrent_hold(self):
        """A reservation is held while the body is in flight: a second big
        request must see 503 until the first completes."""
        node = Node(MCP_NODE_MAX_INFLIGHT_BYTES=str(1024 * 1024))
        self.addCleanup(node.close)
        big = 700 * 1024
        holder_body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'ping',
                                  'params': {'pad': 'x' * (big - 90)}}).encode()
        holder = node.connect()
        try:
            holder.sendall(node.head_for(len(holder_body)))  # headers only: body held back
            probe_statuses = set()
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                probe_body = json.dumps({'jsonrpc': '2.0', 'id': 2, 'method': 'ping',
                                         'params': {'pad': 'y' * (big - 90)}}).encode()
                probe = node.connect()
                try:
                    probe.settimeout(4)
                    probe.sendall(node.head_for(len(probe_body)))
                    try:
                        status, _, _, _ = read_http_response(probe, deadline_s=4)
                    except socket.timeout:
                        probe.sendall(probe_body)
                        status, _, _, _ = read_http_response(probe, deadline_s=8)
                    probe_statuses.add(status)
                    if status == 503:
                        break
                finally:
                    probe.close()
                time.sleep(0.05)
            self.assertIn(503, probe_statuses,
                          'concurrent big request never hit the in-flight budget: %r' % probe_statuses)
            holder.sendall(holder_body)
            status, _, _, data = read_http_response(holder)
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(data).get('id'), 1)
        finally:
            holder.close()


class JsonRpcTests(unittest.TestCase):
    def setUp(self):
        self.node = Node()
        self.addCleanup(self.node.close)

    def test_jsonrpc_version_required(self):
        for payload in ({'jsonrpc': 'wrong', 'id': 1, 'method': 'ping'},
                        {'id': 1, 'method': 'ping'},
                        {'jsonrpc': '2.1', 'id': 1, 'method': 'ping'},
                        {'jsonrpc': 2.0, 'id': 1, 'method': 'ping'}):
            with self.subTest(payload=payload):
                status, reply = self.node.rpc(payload)
                self.assertEqual(status, 400)
                self.assertEqual(err_code(reply), -32600)

    def test_id_type_restricted(self):
        for bad_id in ([1], {'a': 1}, 1.5, True):
            with self.subTest(bad_id=bad_id):
                status, reply = self.node.rpc({'jsonrpc': '2.0', 'id': bad_id, 'method': 'ping'})
                self.assertEqual(status, 400)
                self.assertEqual(err_code(reply), -32600)
        for good_id in ('abc', 7, None):
            with self.subTest(good_id=good_id):
                status, reply = self.node.rpc({'jsonrpc': '2.0', 'id': good_id, 'method': 'ping'})
                self.assertEqual(status, 200)
                self.assertEqual(reply.get('id'), good_id)
                self.assertEqual(reply.get('result'), {})

    def test_method_must_be_string(self):
        status, reply = self.node.rpc({'jsonrpc': '2.0', 'id': 1, 'method': 123})
        self.assertEqual(status, 400)
        self.assertEqual(err_code(reply), -32600)

    def test_params_must_be_structured(self):
        for params in (5, 'x', True):
            with self.subTest(params=params):
                status, reply = self.node.rpc({'jsonrpc': '2.0', 'id': 1, 'method': 'ping',
                                               'params': params})
                self.assertEqual(status, 400)
                self.assertEqual(err_code(reply), -32600)

    def test_notification_without_id_accepted(self):
        status, reply = self.node.rpc({'jsonrpc': '2.0', 'method': 'notifications/initialized'})
        self.assertEqual(status, 202)
        self.assertIsNone(reply)

    def test_malformed_notification_rejected(self):
        status, reply = self.node.rpc({'jsonrpc': '2.0', 'method': 'notifications/progress',
                                       'params': 5})
        self.assertEqual(status, 400)
        self.assertEqual(err_code(reply), -32600)
        status, reply = self.node.rpc({'jsonrpc': 'nope', 'method': 'notifications/progress'})
        self.assertEqual(status, 400)

    def test_notification_method_with_id_not_dropped_silently(self):
        status, reply = self.node.rpc({'jsonrpc': '2.0', 'id': 1, 'method': 'notifications/initialized'})
        self.assertNotEqual(status, 202, 'request with id must never get a silent 202')
        self.assertEqual(status, 400)
        self.assertEqual(err_code(reply), -32600)

    def test_arguments_must_be_object(self):
        status, reply = self.node.rpc({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                                       'params': {'name': 'sys_info', 'arguments': [1, 2]}})
        self.assertEqual(status, 200)
        self.assertEqual(err_code(reply), -32602)

    def test_tool_arg_wrong_type_is_strict_error(self):
        cases = [
            (1, {'name': 'exec', 'arguments': {'argv': ['/bin/true'], 'timeout': 'abc'}}),
            (2, {'name': 'exec', 'arguments': {'argv': ['/bin/true'], 'cwd': 5}}),
            (3, {'name': 'exec_wait', 'arguments': {'session_id': '1'}}),
            (4, {'name': 'exec_write', 'arguments': {'session_id': 1, 'data_b64': 5}}),
        ]
        for ident, params in cases:
            with self.subTest(id=ident):
                status, reply = self.node.rpc({'jsonrpc': '2.0', 'id': ident,
                                               'method': 'tools/call', 'params': params})
                self.assertEqual(status, 200)
                self.assertEqual(err_code(reply), -32602)

    def test_tool_arg_correct_types_still_work(self):
        # /bin/true is Linux-only (macOS keeps `true` in /usr/bin, Windows has
        # neither): use the interpreter running this harness plus a
        # platform-valid root cwd — the types under test are unchanged.
        if os.name == 'nt':
            cwd = str(Path(sys.executable).anchor)
        else:
            cwd = '/'
        reply = self.node.tool('exec', {'argv': [sys.executable, '-c', 'pass'], 'timeout': 5, 'cwd': cwd})
        self.assertTrue(reply.get('ok'), reply)
        self.assertEqual(reply.get('exit_code'), 0)


class ListDirTests(unittest.TestCase):
    def setUp(self):
        self.node = Node()
        self.addCleanup(self.node.close)

    def _make_dir(self, count):
        target = self.node.root / ('dir-%d' % count)
        target.mkdir()
        for i in range(count):
            (target / ('entry-%05d' % i)).touch()
        return target

    def test_truncation_contract_over_cap(self):
        target = self._make_dir(2001)
        reply = self.node.tool('list_dir', {'path': str(target)})
        self.assertTrue(reply.get('ok'), reply)
        self.assertEqual(reply.get('count'), 2000)
        self.assertEqual(len(reply.get('items', [])), 2000)
        self.assertIs(reply.get('truncated'), True)
        self.assertIs(reply.get('has_more'), True)
        names = [item['name'] for item in reply['items']]
        self.assertEqual(names, sorted(names), 'returned set must be stably sorted')

    def test_exact_cap_is_not_truncated(self):
        target = self._make_dir(2000)
        reply = self.node.tool('list_dir', {'path': str(target)})
        self.assertTrue(reply.get('ok'), reply)
        self.assertEqual(reply.get('count'), 2000)
        self.assertIs(reply.get('truncated'), False)
        self.assertIs(reply.get('has_more'), False)

    def test_small_dir_not_truncated(self):
        target = self._make_dir(3)
        reply = self.node.tool('list_dir', {'path': str(target)})
        self.assertTrue(reply.get('ok'), reply)
        self.assertEqual(reply.get('count'), 3)
        self.assertIs(reply.get('truncated'), False)
        self.assertIs(reply.get('has_more'), False)


class SanityTests(unittest.TestCase):
    def test_sys_info_baseline(self):
        node = Node()
        self.addCleanup(node.close)
        info = node.tool('sys_info')
        self.assertIn('hostname', info)
        self.assertTrue(info['hostname'])

    def test_exec_output_replaces_invalid_utf8(self):
        """exec decodes stdout/stderr lossily (U+FFFD), matching read_file
        and the session tools, instead of dropping invalid bytes."""
        node = Node()
        self.addCleanup(node.close)
        code = 'import os; os.write(1, b"\\xff\\xfeabc"); os.write(2, b"\\x80xy")'
        reply = node.tool('exec', {'argv': [sys.executable, '-c', code], 'timeout': 10})
        self.assertTrue(reply.get('ok'), reply)
        self.assertEqual(reply.get('exit_code'), 0, reply)
        self.assertEqual(reply.get('stdout'), '\ufffd\ufffdabc', reply)
        self.assertEqual(reply.get('stderr'), '\ufffdxy', reply)

    def test_exec_payload_has_no_dead_truncated_flag(self):
        """exec never truncates output (StreamTooLong fails as OutputTooLong),
        so the always-false `truncated` flag was dead weight and is gone."""
        node = Node()
        self.addCleanup(node.close)
        reply = node.tool('exec', {'argv': [sys.executable, '-c', 'pass']})
        self.assertTrue(reply.get('ok'), reply)
        self.assertNotIn('truncated', reply,
                         'exec carries a dead truncated flag that is always false')

    def test_cryptic_error_names_carry_a_message(self):
        """BadArgv and the base64 decode errors are cryptic as bare Zig names;
        they carry a human-readable `message` next to `error`. Other error
        payloads keep their historical two-key shape (additive, scoped)."""
        node = Node()
        self.addCleanup(node.close)
        reply = node.tool('exec', {'argv': 'not-an-array'})
        self.assertFalse(reply.get('ok'), reply)
        self.assertEqual(reply.get('error'), 'BadArgv', reply)
        self.assertEqual(reply.get('message'),
                         'argv must be a non-empty array of strings', reply)
        reply = node.tool('write_file', {'path': '/tmp/mcpnz-b64probe',
                                         'content_b64': '!!!'})
        self.assertFalse(reply.get('ok'), reply)
        self.assertIn(reply.get('error'),
                      ('InvalidPadding', 'InvalidCharacter', 'InvalidLength'), reply)
        self.assertTrue(reply.get('message'), reply)
        # Scope boundary: self-explanatory names stay message-less.
        reply = node.tool('exec', {})
        self.assertFalse(reply.get('ok'), reply)
        self.assertEqual(reply.get('error'), 'MissingArgv', reply)
        self.assertNotIn('message', reply)


if __name__ == '__main__':
    unittest.main(verbosity=2)
