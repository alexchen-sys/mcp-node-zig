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
EXPECTED_TOOLS = 14


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


def tool_call(node, name, arguments):
    response = node.call({'jsonrpc': '2.0', 'id': 42, 'method': 'tools/call',
                          'params': {'name': name, 'arguments': arguments}})
    if 'error' in response:
        assert response['error']['code'] == -32602, response
        return {'ok': False, 'error': 'InvalidParams'}
    return response['result']['structuredContent']


def case_shaped_exec_and_shell():
    node = StdioNode(env_extra={'MCP_NODE_MAX_OUT': '64'})
    try:
        script = "import os; os.write(1,b'a\\r\\nb\\r\\nc'); os.write(2,b'err')"
        shaped = tool_call(node, 'exec', {'argv': [sys.executable, '-c', script],
                                         'tail_lines': 2, 'max_bytes': 4})
        assert shaped['stdout'] == 'b\r\nc', shaped
        assert shaped['stderr'] == 'err', shaped
        assert shaped['total_stdout_bytes'] == 7, shaped
        assert shaped['returned_stdout_bytes'] == 4, shaped
        assert shaped['omitted_stdout_bytes'] == 3, shaped
        assert shaped['truncated'] and shaped['truncated_stdout'], shaped
        assert not shaped['truncated_stderr'], shaped
        assert shaped['output_complete'] and shaped['exit_code'] == 0, shaped
        if os.name != 'nt':
            shaped = tool_call(node, 'exec_shell', {'shell': 'sh',
                'script': "printf 'one\\ntwo\\nthree'; printf err >&2",
                'head_lines': 1})
            assert shaped['stdout'] == 'one\n' and shaped['stderr'] == 'err', shaped
            assert shaped['total_stdout_bytes'] == 13, shaped
            assert shaped['omitted_stdout_bytes'] == 9, shaped
        argv = [sys.executable, '-c', "import os; os.write(1,b'x'*100000); os.write(2,b'y'*100000)"]
        shaped = tool_call(node, 'exec', {'argv': argv, 'max_bytes': 0})
        assert shaped['stdout'] == shaped['stderr'] == '', shaped
        for stream in ('stdout', 'stderr'):
            assert shaped['total_' + stream + '_bytes'] == 100000, shaped
            assert shaped['omitted_' + stream + '_bytes'] == 100000, shaped
        legacy = tool_call(node, 'exec', {'argv': argv})
        assert legacy['error'] == 'OutputTooLong', legacy
        assert 'output_complete' not in legacy, legacy
        legacy = tool_call(node, 'exec', {'argv': [sys.executable, '-c', "print('ok')"]})
        assert legacy['stdout'] == 'ok\n', legacy
        assert 'total_stdout_bytes' not in legacy, legacy
    finally:
        node.kill()


def case_shaped_validation_and_timeout():
    node = StdioNode(env_extra={'MCP_NODE_MAX_OUT': '64'})
    try:
        for extra, error in [({'head_lines': 0, 'tail_lines': 0}, 'ConflictingOutputSelection'),
                             ({'max_bytes': -1}, 'InvalidParams'),
                             ({'max_bytes': True}, 'InvalidParams'),
                             ({'head_lines': 1.5}, 'InvalidParams'),
                             ({'max_bytes': 65}, 'BadOutputLimit')]:
            # Invalid selectors must win over preflight/spawn errors.
            got = tool_call(node, 'exec', {'argv': ['/missing-output-shape-test'], **extra})
            assert got['error'] == error, got
        got = tool_call(node, 'exec', {'argv': [sys.executable, '-c',
            "import os,time; os.write(1,b'abcdef'); os.write(2,b'err'); time.sleep(30)"],
            'timeout': 1, 'max_bytes': 4})
        assert not got['ok'] and got['timeout'] and got['exit_code'] is None, got
        assert not got['output_complete'], got
        assert got['stdout'] == 'abcd' and got['stderr'] == 'err', got
        assert got['total_stdout_bytes'] == 6 and got['omitted_stdout_bytes'] == 2, got
        assert got['returned_stderr_bytes'] == 3 and got['omitted_stderr_bytes'] == 0, got
    finally:
        node.kill()


def case_output_page_progression():
    node = StdioNode(env_extra={'MCP_NODE_MAX_OUT': '64'})
    sid = None
    try:
        expected = 'a💩é中z'
        script = "import os; os.write(1,bytes.fromhex('%s')); os.write(2,b'123456')" % expected.encode().hex()
        sid = tool_call(node, 'exec_start', {'argv': [sys.executable, '-c', script]})['session_id']
        args = {'session_id': sid, 'max_bytes': 4}
        pieces = []
        err_pieces = []
        for index in range(10):
            page = tool_call(node, 'exec_wait' if index == 0 else 'exec_poll', args)
            assert page['done'] and page['exit_code'] == 0, page
            assert page['total_stdout_bytes'] == len(expected.encode()), page
            assert not page['truncated_stdout'] and not page['truncated_stderr'], page
            assert page['lost_stdout_bytes'] == page['lost_stderr_bytes'] == 0, page
            pieces.append(page['stdout'])
            err_pieces.append(page['stderr'])
            if not page['has_more']:
                assert not page['page_limited'], page
                break
            assert page['stdout_offset'] > args.get('stdout_offset', 0), page
            args.update(stdout_offset=page['stdout_offset'], stderr_offset=page['stderr_offset'])
        else:
            raise AssertionError('pagination made no progress')
        assert ''.join(pieces) == expected, pieces
        assert ''.join(err_pieces) == '123456', err_pieces
        assert page['stdout_offset'] == len(expected.encode()), page
        assert page['stderr_offset'] == 6, page
        legacy = tool_call(node, 'exec_poll', {'session_id': sid})
        assert legacy['stdout'] == expected and 'has_more' not in legacy, legacy
        for tool in ('exec_poll', 'exec_wait'):
            assert tool_call(node, tool, {'session_id': sid, 'max_bytes': 3})['error'] == 'BadOutputLimit'
            assert tool_call(node, tool, {'session_id': sid, 'tail_lines': 1})['error'] == 'InvalidParams'
    finally:
        if sid is not None:
            tool_call(node, 'exec_close', {'session_id': sid})
        node.kill()


CASES = [
    case_shaped_exec_and_shell,
    case_shaped_validation_and_timeout,
    case_output_page_progression,
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
