#!/usr/bin/env python3
"""Regeneration/evidence probe for the v0 compat golden fixtures.

Boots one mcp-node daemon (dynamic loopback port, random token, temp cwd)
and replays the full request plan the fixtures are built from, dumping one
JSON record per request to stdout:

    {"label": ..., "request": ..., "status": ..., "response": ...}

The output is raw evidence: whatever the binary really answered, including
transport failures ({"error": ...}). It asserts nothing. Point the fixture
authors at this dump (captured in the sandbox run logs) whenever the
contract needs re-baselining.

Run: python3 ci/fixtures/compat/probe.py [path/to/mcp-node]
Default binary: zig-out/bin/mcp-node resolved against the repo root
(parent of ci/).
"""
import base64
import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BINARY = Path(sys.argv.pop(1) if len(sys.argv) > 1 and not sys.argv[1].startswith('-')
              else ROOT / 'zig-out' / 'bin' / ('mcp-node.exe' if os.name == 'nt' else 'mcp-node')).resolve()

HELLO_COMPAT = base64.b64encode(b'hello compat\n').decode()      # 13 bytes
PING_NL = base64.b64encode(b'ping\n').decode()                   # 5 bytes
NESTED_OK = base64.b64encode(b'nested ok\n').decode()
ONE_BYTE = base64.b64encode(b'x').decode()


def free_port():
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        return probe.getsockname()[1]


def read_http_response(sock, deadline_s=15.0):
    sock.settimeout(deadline_s)
    data = b''
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
    return status, body[:length]


def tool_call(ident, name, arguments=None):
    return {'jsonrpc': '2.0', 'id': ident, 'method': 'tools/call',
            'params': {'name': name, 'arguments': arguments if arguments is not None else {}}}


class Daemon:
    def __init__(self):
        self.temp = tempfile.TemporaryDirectory(prefix='mcp-probe-')
        self.root = Path(self.temp.name)
        self.secret = secrets.token_hex(24)
        auth = self.root / 'auth-fixture'
        auth.write_text(self.secret)
        self.port = free_port()
        env = {key: value for key, value in os.environ.items() if not key.startswith('MCP_NODE_')}
        env.update(MCP_NODE_HOST='127.0.0.1', MCP_NODE_PORT=str(self.port),
                   MCP_NODE_NAME='compat-node', MCP_NODE_SOCKET_TIMEOUT_S='10')
        env['MCP_NODE_TOKEN_' + 'FILE'] = str(auth)
        self.log = (self.root / 'daemon.log').open('w+b')
        self.process = subprocess.Popen([str(BINARY)], cwd=self.root, env=env,
                                        stdout=self.log, stderr=self.log)
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

    def logs(self):
        self.log.flush()
        return (self.root / 'daemon.log').read_text(errors='replace')[-4000:]

    def rpc(self, payload):
        body = json.dumps(payload).encode()
        head = ('\r\n'.join(['POST /mcp HTTP/1.1',
                             'Host: 127.0.0.1:' + str(self.port),
                             'Content-Length: ' + str(len(body)),
                             'Content-Type: application/json',
                             'X-Node-Token: ' + self.secret]) + '\r\n\r\n').encode()
        sock = socket.create_connection(('127.0.0.1', self.port), timeout=20)
        try:
            sock.sendall(head + body)
            status, data = read_http_response(sock)
        finally:
            sock.close()
        return status, json.loads(data) if data else None

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.log.close()
        self.temp.cleanup()


def substitute(value, ctx):
    """Replace strings that are exactly '$key' with captured values (type kept)."""
    if isinstance(value, str) and value.startswith('$') and value[1:] in ctx:
        return ctx[value[1:]]
    if isinstance(value, dict):
        return {k: substitute(v, ctx) for k, v in value.items()}
    if isinstance(value, list):
        return [substitute(v, ctx) for v in value]
    return value


def dig(obj, dotted):
    node = obj
    for segment in dotted.split('.'):
        if isinstance(node, list):
            node = node[int(segment)]
        else:
            node = node[segment]
    return node


# label, request, optional capture: (ctx key, dotted path into the parsed response)
PLAN = [
    ('init_supported', {'jsonrpc': '2.0', 'id': 101, 'method': 'initialize',
                        'params': {'protocolVersion': '2025-06-18', 'capabilities': {},
                                   'clientInfo': {'name': 'probe', 'version': '0'}}}, None),
    ('init_unsupported', {'jsonrpc': '2.0', 'id': 102, 'method': 'initialize',
                          'params': {'protocolVersion': '1999-01-01'}}, None),
    ('init_no_params', {'jsonrpc': '2.0', 'id': 'init-str', 'method': 'initialize'}, None),
    ('ping_int', {'jsonrpc': '2.0', 'id': 7, 'method': 'ping'}, None),
    ('ping_str', {'jsonrpc': '2.0', 'id': 'probe-ping', 'method': 'ping'}, None),
    ('ping_notification', {'jsonrpc': '2.0', 'method': 'notifications/initialized'}, None),
    ('ping_bad_params', {'jsonrpc': '2.0', 'id': 8, 'method': 'ping', 'params': 5}, None),
    ('tools_list', {'jsonrpc': '2.0', 'id': 42, 'method': 'tools/list'}, None),

    ('call_missing_name', {'jsonrpc': '2.0', 'id': 50, 'method': 'tools/call', 'params': {}}, None),
    ('call_unknown_tool', tool_call(51, 'no_such_tool_v0'), None),

    ('sys_info', tool_call(43, 'sys_info'), None),
    ('sys_info_junk_args', tool_call(44, 'sys_info', {'bogus': [1, 2]}), None),

    ('exec_echo', tool_call(45, 'exec', {'argv': ['/bin/echo', 'hello']}), None),
    ('exec_false', tool_call(46, 'exec', {'argv': ['/usr/bin/false']}), None),
    ('exec_nonexistent', tool_call(47, 'exec', {'argv': ['/nonexistent/mcpnz-probe']}), None),
    ('exec_missing_argv', tool_call(48, 'exec'), None),
    ('exec_argv_string', tool_call(49, 'exec', {'argv': '/bin/echo'}), None),
    ('exec_timeout_string', tool_call(52, 'exec', {'argv': ['/usr/bin/true'], 'timeout': 'abc'}), None),

    ('exec_shell_ok', tool_call(53, 'exec_shell', {'script': 'echo shell-ok'}), None),
    ('exec_shell_missing_script', tool_call(54, 'exec_shell'), None),
    ('exec_shell_unsupported', tool_call(55, 'exec_shell', {'script': 'echo hi', 'shell': 'csh'}), None),
    ('exec_shell_script_int', tool_call(56, 'exec_shell', {'script': 5}), None),

    ('start_echo', tool_call(57, 'exec_start', {'argv': ['/bin/echo', 'compat-poll']}),
     ('sid', 'result.structuredContent.session_id')),
    ('wait_sid', tool_call(58, 'exec_wait', {'session_id': '$sid', 'timeout': 10}), None),
    ('poll_full', tool_call(59, 'exec_poll', {'session_id': '$sid'}), None),
    ('poll_offset7', tool_call(60, 'exec_poll', {'session_id': '$sid', 'stdout_offset': 7}), None),
    ('poll_offset12', tool_call(61, 'exec_poll', {'session_id': '$sid', 'stdout_offset': 12}), None),
    ('poll_missing_sid', tool_call(62, 'exec_poll'), None),
    ('poll_unknown_sid', tool_call(63, 'exec_poll', {'session_id': 999999}), None),
    ('poll_sid_string', tool_call(64, 'exec_poll', {'session_id': '1'}), None),
    ('close_sid', tool_call(65, 'exec_close', {'session_id': '$sid'}), None),
    ('close_sid_again', tool_call(66, 'exec_close', {'session_id': '$sid'}), None),
    ('close_unknown', tool_call(67, 'exec_close', {'session_id': 999999}), None),
    ('poll_after_close', tool_call(68, 'exec_poll', {'session_id': '$sid'}), None),

    ('start_cat', tool_call(69, 'exec_start', {'argv': ['/bin/cat']}),
     ('sid2', 'result.structuredContent.session_id')),
    ('write_ping', tool_call(70, 'exec_write', {'session_id': '$sid2', 'data_b64': PING_NL}), None),
    ('write_eof', tool_call(71, 'exec_write', {'session_id': '$sid2', 'data_b64': '', 'eof': True}), None),
    ('wait_cat', tool_call(72, 'exec_wait', {'session_id': '$sid2', 'timeout': 10}), None),
    ('close_cat', tool_call(73, 'exec_close', {'session_id': '$sid2'}), None),
    ('write_missing_data', tool_call(74, 'exec_write', {'session_id': 999999}), None),
    ('write_data_int', tool_call(75, 'exec_write', {'session_id': 999999, 'data_b64': 5}), None),
    ('write_unknown_session', tool_call(76, 'exec_write', {'session_id': 999999, 'data_b64': ''}), None),

    ('start_sleep', tool_call(77, 'exec_start', {'argv': ['/bin/sleep', '30']}),
     ('sid3', 'result.structuredContent.session_id')),
    ('kill_sid', tool_call(78, 'exec_kill', {'session_id': '$sid3'}), None),
    ('wait_killed', tool_call(79, 'exec_wait', {'session_id': '$sid3', 'timeout': 5}), None),
    ('close_sleep', tool_call(80, 'exec_close', {'session_id': '$sid3'}), None),
    ('kill_missing_sid', tool_call(81, 'exec_kill'), None),
    ('close_missing_sid', tool_call(82, 'exec_close'), None),
    ('wait_missing_sid', tool_call(83, 'exec_wait'), None),
    ('wait_timeout_string', tool_call(84, 'exec_wait', {'session_id': 999999, 'timeout': 'abc'}), None),

    ('start_missing_argv', tool_call(85, 'exec_start'), None),
    ('start_argv_empty', tool_call(86, 'exec_start', {'argv': []}), None),
    ('start_argv_int_elem', tool_call(87, 'exec_start', {'argv': [5]}), None),
    ('start_argv_string', tool_call(88, 'exec_start', {'argv': '/bin/echo'}), None),
    ('start_cwd_int', tool_call(89, 'exec_start', {'argv': ['/usr/bin/true'], 'cwd': 5}), None),

    ('list_initial_empty', tool_call(90, 'exec_list'), None),
    ('start_sleep2', tool_call(91, 'exec_start', {'argv': ['/bin/sleep', '30']}),
     ('sid4', 'result.structuredContent.session_id')),
    ('list_running', tool_call(92, 'exec_list'), None),
    ('close_sleep2', tool_call(93, 'exec_close', {'session_id': '$sid4'}), None),
    ('list_after_close', tool_call(94, 'exec_list'), None),
    ('start_echo2', tool_call(95, 'exec_start', {'argv': ['/bin/echo', 'compat-list']}),
     ('sid5', 'result.structuredContent.session_id')),
    ('wait_echo2', tool_call(96, 'exec_wait', {'session_id': '$sid5', 'timeout': 10}), None),
    ('list_done', tool_call(97, 'exec_list'), None),
    ('close_echo2', tool_call(98, 'exec_close', {'session_id': '$sid5'}), None),

    ('write_file_ok', tool_call(99, 'write_file', {'path': 'probe-file.txt', 'content_b64': HELLO_COMPAT}), None),
    ('read_file_full', tool_call(100, 'read_file', {'path': 'probe-file.txt'}), None),
    ('read_file_limit', tool_call(101, 'read_file', {'path': 'probe-file.txt', 'limit': 5}), None),
    ('read_file_offset', tool_call(102, 'read_file', {'path': 'probe-file.txt', 'offset': 6}), None),
    ('read_file_missing_path', tool_call(103, 'read_file'), None),
    ('read_file_path_int', tool_call(104, 'read_file', {'path': 5}), None),
    ('read_file_not_found', tool_call(105, 'read_file', {'path': 'no-such-probe-file.txt'}), None),
    ('write_file_missing_content', tool_call(106, 'write_file', {'path': 'x.txt'}), None),
    ('write_file_content_int', tool_call(107, 'write_file', {'path': 'x.txt', 'content_b64': 5}), None),
    ('write_file_nested', tool_call(108, 'write_file', {'path': 'nested-probe/dir/probe.txt', 'content_b64': NESTED_OK}), None),
    ('read_file_nested', tool_call(109, 'read_file', {'path': 'nested-probe/dir/probe.txt'}), None),
    ('read_file_is_dir', tool_call(110, 'read_file', {'path': 'nested-probe'}), None),
    ('write_file_nomkdirs', tool_call(111, 'write_file', {'path': 'nomkdir/deep.txt', 'content_b64': ONE_BYTE, 'mkdirs': False}), None),
    ('write_file_bad_mode', tool_call(112, 'write_file', {'path': 'bad-mode.txt', 'content_b64': ONE_BYTE, 'mode': 4096}), None),

    ('list_dir_nested', tool_call(113, 'list_dir', {'path': 'nested-probe/dir'}), None),
    ('list_dir_default', tool_call(114, 'list_dir'), None),
    ('list_dir_missing', tool_call(115, 'list_dir', {'path': 'no-such-dir-probe'}), None),
    ('list_dir_on_file', tool_call(116, 'list_dir', {'path': 'probe-file.txt'}), None),
    ('list_dir_path_int', tool_call(117, 'list_dir', {'path': 5}), None),
]


def main():
    daemon = Daemon()
    ctx = {}
    failures = 0
    try:
        for label, request, capture in PLAN:
            payload = substitute(request, ctx)
            try:
                status, response = daemon.rpc(payload)
                record = {'label': label, 'request': payload, 'status': status, 'response': response}
                if capture and isinstance(response, dict):
                    key, capture_path = capture
                    try:
                        ctx[key] = dig(response, capture_path)
                    except (KeyError, IndexError, TypeError, ValueError):
                        record['capture_error'] = capture_path
            except Exception as exc:
                failures += 1
                record = {'label': label, 'request': payload, 'error': '%s: %s' % (type(exc).__name__, exc)}
            print(json.dumps(record, sort_keys=True), flush=True)
        health = daemon.rpc({'jsonrpc': '2.0', 'id': 999, 'method': 'ping'})
        print(json.dumps({'label': 'final_ping', 'status': health[0], 'response': health[1]}, sort_keys=True), flush=True)
    finally:
        daemon.close()
    print('PROBE_DONE transport_failures=%d' % failures, flush=True)
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
