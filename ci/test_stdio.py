#!/usr/bin/env python3
"""End-to-end suite for the stdio transport (--stdio / MCP_NODE_STDIO=1).

Black-box over a real process with pipes: newline-delimited JSON-RPC in on
stdin, one JSON line per response out on stdout, logs on stderr. Covers the
MCP handshake, tools/list, a real tools/call, a silent notification, a
broken line answered with -32700 while the server keeps going, stdout
purity (nothing but JSON lines), clean exit on EOF, the env switch, the
no-token contract and the flag conflicts with link modes.

Run: python3 ci/test_stdio.py [path/to/mcp-node]
Prints one PASS/FAIL line per case; exits nonzero on any failure.
"""
import json
import os
from pathlib import Path
import platform
import queue
import subprocess
import sys
import tempfile
import threading
import traceback

ROOT = Path(__file__).resolve().parent.parent
BINARY = Path(sys.argv[1] if len(sys.argv) > 1
              else ROOT / 'zig-out' / 'bin' / ('mcp-node.exe' if os.name == 'nt' else 'mcp-node')).resolve()

TIMEOUT_S = 20
EXPECTED_TOOLS = 13


def base_env():
    return {k: v for k, v in os.environ.items() if not k.startswith('MCP_NODE_')}


class StdioNode:
    """mcp-node in stdio mode, started in an empty directory so that no
    token file exists: stdio must not need one."""

    def __init__(self, args=('--stdio',), env_extra=None):
        self.dir = tempfile.TemporaryDirectory(prefix='mcpnz-stdio-')
        env = base_env()
        env.update(env_extra or {})
        self.proc = subprocess.Popen([str(BINARY), *args], cwd=self.dir.name, env=env,
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE)
        self.lines = queue.Queue()
        self.raw_out = bytearray()
        self.raw_err = bytearray()
        self._t_out = threading.Thread(target=self._pump_out, daemon=True)
        self._t_err = threading.Thread(target=self._pump_err, daemon=True)
        self._t_out.start()
        self._t_err.start()

    def _pump_out(self):
        for line in self.proc.stdout:
            self.raw_out.extend(line)
            self.lines.put(line)
        self.lines.put(None)

    def _pump_err(self):
        for chunk in iter(lambda: self.proc.stderr.read(4096), b''):
            self.raw_err.extend(chunk)

    def send_raw(self, data):
        self.proc.stdin.write(data)
        self.proc.stdin.flush()

    def send(self, obj):
        self.send_raw(json.dumps(obj).encode() + b'\n')

    def recv(self, timeout=TIMEOUT_S):
        line = self.lines.get(timeout=timeout)
        if line is None:
            raise AssertionError('stdout closed; stderr=%r' % bytes(self.raw_err))
        assert line.endswith(b'\n'), line
        return json.loads(line)

    def no_line(self, wait_s=0.5):
        try:
            line = self.lines.get(timeout=wait_s)
        except queue.Empty:
            return
        raise AssertionError('unexpected stdout line: %r' % line)

    def call(self, obj):
        self.send(obj)
        return self.recv()

    def close_stdin_and_wait(self):
        self.proc.stdin.close()
        rc = self.proc.wait(timeout=TIMEOUT_S)
        self._t_out.join(TIMEOUT_S)
        self._t_err.join(TIMEOUT_S)
        return rc

    def kill(self):
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait(timeout=TIMEOUT_S)
        self.dir.cleanup()


def initialize(node, rid=1):
    resp = node.call({'jsonrpc': '2.0', 'id': rid, 'method': 'initialize',
                      'params': {'protocolVersion': '2025-06-18', 'capabilities': {},
                                 'clientInfo': {'name': 'test-stdio', 'version': '0'}}})
    assert resp['id'] == rid, resp
    assert resp['result']['protocolVersion'] == '2025-06-18', resp
    assert resp['result']['capabilities'] == {'tools': {}}, resp
    assert resp['result']['serverInfo']['name'] == 'mcp-node', resp
    return resp


def assert_stdout_pure(node):
    """Every byte on stdout belongs to a newline-terminated JSON-RPC object."""
    raw = bytes(node.raw_out)
    assert raw == b'' or raw.endswith(b'\n'), raw[-80:]
    for line in raw.split(b'\n')[:-1]:
        obj = json.loads(line)
        assert isinstance(obj, dict) and obj.get('jsonrpc') == '2.0', line


def case_full_session():
    node = StdioNode()
    try:
        initialize(node)
        node.send({'jsonrpc': '2.0', 'method': 'notifications/initialized'})
        node.no_line()

        tl = node.call({'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list'})
        names = [t['name'] for t in tl['result']['tools']]
        assert len(names) == EXPECTED_TOOLS, names
        assert 'exec' in names and 'sys_info' in names, names

        if os.name == 'nt':
            argv = ['cmd', '/c', 'echo', 'stdio-ok']
        else:
            argv = ['uname', '-sm']
        r = node.call({'jsonrpc': '2.0', 'id': 3, 'method': 'tools/call',
                       'params': {'name': 'exec', 'arguments': {'argv': argv}}})
        assert r['id'] == 3, r
        sc = r['result']['structuredContent']
        assert r['result']['isError'] is False, r
        assert sc['ok'] is True and sc['exit_code'] == 0, sc
        if os.name == 'nt':
            assert 'stdio-ok' in sc['stdout'], sc
        else:
            assert sc['stdout'].strip() == '%s %s' % (platform.system(), platform.machine()), sc

        # A broken line is answered with a parse error; the server lives on.
        node.send_raw(b'{"jsonrpc":"2.0","id":4,"method":\n')
        bad = node.recv()
        assert bad == {'jsonrpc': '2.0', 'id': None,
                       'error': {'code': -32700, 'message': 'Parse error'}}, bad
        ping = node.call({'jsonrpc': '2.0', 'id': 5, 'method': 'ping'})
        assert ping == {'jsonrpc': '2.0', 'id': 5, 'result': {}}, ping

        rc = node.close_stdin_and_wait()
        assert rc == 0, (rc, bytes(node.raw_err))
        assert_stdout_pure(node)
        assert b'stdio' in bytes(node.raw_err), bytes(node.raw_err)
    finally:
        node.kill()


def case_pipelined_burst_in_order():
    """Several messages in one write come back one line each, in order;
    blank lines and CRLF endings are tolerated."""
    node = StdioNode()
    try:
        burst = b''.join([
            b'{"jsonrpc":"2.0","id":10,"method":"ping"}\r\n',
            b'\n',
            b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n',
            b'{"jsonrpc":"2.0","id":"s","method":"no/such/method"}\n',
            b'[1,2]\n',
            b'{"jsonrpc":"2.0","id":11,"method":"ping"}',  # no trailing newline
        ])
        node.send_raw(burst)
        assert node.recv() == {'jsonrpc': '2.0', 'id': 10, 'result': {}}
        e = node.recv()
        assert e['id'] == 's' and e['error']['code'] == -32601, e
        e = node.recv()
        assert e['id'] is None and e['error']['code'] == -32600, e
        # The unterminated final message is answered once stdin closes.
        rc = node.close_stdin_and_wait()
        assert rc == 0, rc
        assert node.lines.get(timeout=1) == b'{"jsonrpc":"2.0","id":11,"result":{}}\n'
        assert_stdout_pure(node)
    finally:
        node.kill()


def case_env_switch_and_immediate_eof():
    node = StdioNode(args=(), env_extra={'MCP_NODE_STDIO': '1'})
    try:
        initialize(node, rid='e')
        rc = node.close_stdin_and_wait()
        assert rc == 0, rc
        assert_stdout_pure(node)
    finally:
        node.kill()
    node = StdioNode()
    try:
        rc = node.close_stdin_and_wait()
        assert rc == 0, rc
        assert bytes(node.raw_out) == b'', bytes(node.raw_out)
    finally:
        node.kill()


def case_exec_session_killed_on_eof():
    """A long-running exec session dies with the server on EOF instead of
    leaking as an orphan."""
    if os.name == 'nt':
        return
    node = StdioNode()
    try:
        initialize(node)
        r = node.call({'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call',
                       'params': {'name': 'exec_start', 'arguments': {'argv': ['sleep', '300']}}})
        sc = r['result']['structuredContent']
        assert sc['ok'] is True, sc
        pid = sc['pid']
        rc = node.close_stdin_and_wait()
        assert rc == 0, rc
        # The child is gone (or a zombie reaped by init very soon).
        import time
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
            stat = Path('/proc/%d/stat' % pid)
            if stat.exists() and stat.read_text().split(')')[-1].split()[0] == 'Z':
                break
            time.sleep(0.05)
        else:
            raise AssertionError('session child %d outlived the server' % pid)
    finally:
        node.kill()


def case_bad_config():
    for args, env in ((('--stdio', '--connect', '127.0.0.1:9'), {}),
                      (('--stdio',), {'MCP_NODE_HUB_LISTEN': '127.0.0.1:9'}),
                      ((), {'MCP_NODE_STDIO': 'yes'})):
        node = StdioNode(args=args, env_extra=env)
        try:
            rc = node.close_stdin_and_wait()
            assert rc != 0, (args, env)
            assert bytes(node.raw_out) == b'', (args, env, bytes(node.raw_out))
        finally:
            node.kill()


def case_default_mode_unchanged():
    """Without --stdio the binary still wants a token file (HTTP mode)."""
    node = StdioNode(args=())
    try:
        rc = node.close_stdin_and_wait()
        assert rc != 0, rc
        assert b'TokenFileMissing' in bytes(node.raw_err), bytes(node.raw_err)
    finally:
        node.kill()


CASES = [
    case_full_session,
    case_pipelined_burst_in_order,
    case_env_switch_and_immediate_eof,
    case_exec_session_killed_on_eof,
    case_bad_config,
    case_default_mode_unchanged,
]


def main():
    if not BINARY.exists():
        print('binary not found: %s' % BINARY)
        return 2
    failed = 0
    for case in CASES:
        try:
            case()
            print('PASS %s' % case.__name__)
        except Exception:
            failed += 1
            print('FAIL %s' % case.__name__)
            traceback.print_exc()
    print('%d/%d passed' % (len(CASES) - failed, len(CASES)))
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
