#!/usr/bin/env python3
"""Black-box contracts for a built node; Python is test tooling, not a runtime dependency.

Run: python3 ci/test_contract.py [path/to/mcp-node]
Each test owns an isolated loopback server, temporary files and child processes.
"""
import base64
import concurrent.futures
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import unittest

BINARY = Path(sys.argv.pop(1) if len(sys.argv) > 1 and not sys.argv[1].startswith('-')
              else 'zig-out/bin/mcp-node' + ('.exe' if os.name == 'nt' else '')).resolve()


class Node:
    def __init__(self, **config):
        self.temp = tempfile.TemporaryDirectory(prefix='mcp-contract-')
        self.root = Path(self.temp.name)
        self.secret = secrets.token_hex(24)
        auth = self.root / 'auth-fixture'
        auth.write_text(self.secret)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            self.port = sock.getsockname()[1]
        env = {key: value for key, value in os.environ.items() if not key.startswith('MCP_NODE_')}
        env.update(MCP_NODE_HOST='127.0.0.1', MCP_NODE_PORT=str(self.port),
                   MCP_NODE_NAME='contract-node', MCP_NODE_TOKEN_FILE=str(auth),
                   MCP_NODE_SOCKET_TIMEOUT_S='3')
        env.update({key: str(value) for key, value in config.items()})
        self.log = (self.root / 'daemon.log').open('w+b')
        self.process = None
        try:
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
        except BaseException:
            self.close()
            raise

    def logs(self):
        self.log.flush()
        return (self.root / 'daemon.log').read_text(errors='replace')[-4000:]

    def request(self, body, headers=None, connection=None):
        hdr = {'Content-Type': 'application/json', 'X-Node-Token': self.secret}
        hdr.update(headers or {})
        own = connection is None
        conn = connection or http.client.HTTPConnection('127.0.0.1', self.port, timeout=10)
        try:
            conn.request('POST', '/mcp', json.dumps(body), hdr)
            reply = conn.getresponse()
            data = reply.read()
            return reply.status, json.loads(data) if data else None
        finally:
            if own:
                conn.close()

    def rpc(self, method, params=None):
        body = {'jsonrpc': '2.0', 'id': 'test', 'method': method}
        if params is not None:
            body['params'] = params
        status, reply = self.request(body)
        if status != 200 or not isinstance(reply, dict) or 'result' not in reply:
            raise AssertionError((status, reply))
        return reply['result']

    def tool(self, name, **arguments):
        result = self.rpc('tools/call', {'name': name, 'arguments': arguments})
        # structuredContent first: it is present in both text-mirror modes
        # (MCP_NODE_TEXT_MIRROR=0 drops the content mirror); the text
        # fallback covers isError envelopes, which never carry it.
        if 'structuredContent' in result:
            return result['structuredContent']
        return json.loads(result['content'][0]['text'])

    def close(self):
        if self.process is not None and self.process.poll() is None:
            # Close all published sessions before stopping the test daemon.
            try:
                for session in self.tool('exec_list').get('sessions', []):
                    self.tool('exec_close', session_id=session['session_id'])
            except (OSError, ValueError, AssertionError, http.client.HTTPException):
                pass
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.log.close()
        self.temp.cleanup()


class Contracts(unittest.TestCase):
    def setUp(self):
        self.node = Node()
        self.addCleanup(self.node.close)

    def start(self, code):
        result = self.node.tool('exec_start', argv=[sys.executable, '-c', code])
        self.assertTrue(result['ok'], result)
        return result['session_id']

    def test_initialize_and_tool_inventory(self):
        init = self.node.rpc('initialize', {'protocolVersion': '2025-11-25',
            'capabilities': {}, 'clientInfo': {'name': 'contract-tests', 'version': '1'}})
        self.assertEqual(init['protocolVersion'], '2025-11-25')
        self.assertEqual(init['serverInfo']['name'], 'contract-node')
        self.assertEqual({t['name'] for t in self.node.rpc('tools/list')['tools']},
            {'sys_info', 'exec', 'exec_shell', 'exec_start', 'exec_poll', 'exec_wait',
             'exec_write', 'exec_kill', 'exec_close', 'exec_list', 'read_file',
             'write_file', 'list_dir'})

    def test_sys_info_and_ping(self):
        info = self.node.tool('sys_info')
        self.assertTrue(info['hostname'])
        self.assertIn(info['os'], ('Linux', 'Darwin', 'macOS', 'Windows'))
        self.assertIn('MemTotal', info['mem'])
        self.assertEqual(self.node.rpc('ping'), {})

    def test_auth_host_and_origin_gates(self):
        body = {'jsonrpc': '2.0', 'id': 1, 'method': 'ping'}
        for headers, expected in [({'X-Node-Token': ''}, 401),
                                  ({'X-Node-Token': 'not-the-fixture'}, 401),
                                  ({'Host': 'invalid.example'}, 421),
                                  ({'Origin': 'https://invalid.example'}, 403)]:
            with self.subTest(expected=expected):
                self.assertEqual(self.node.request(body, headers)[0], expected)

    def test_keep_alive_sequential_requests(self):
        conn = http.client.HTTPConnection('127.0.0.1', self.node.port, timeout=5)
        self.addCleanup(conn.close)
        for ident in [1, 2, 3]:
            status, body = self.node.request({'jsonrpc': '2.0', 'id': ident, 'method': 'ping'}, connection=conn)
            self.assertEqual(status, 200)
            if not isinstance(body, dict):
                self.fail('expected JSON-RPC object')
            self.assertEqual(body['id'], ident)
            self.assertEqual(body['result'], {})

    def test_exec_preserves_literal_argv_and_unicode(self):
        literal = "single ' double \" dollar $HOME backtick `tick` ; | & \\ Юникод 雪"
        reply = self.node.tool('exec', argv=[sys.executable, '-c',
            'import sys; sys.stdout.buffer.write(sys.argv[1].encode("utf-8"))', literal])
        self.assertTrue(reply['ok'], reply)
        self.assertEqual(reply['stdout'], literal)
        self.assertEqual(reply['exit_code'], 0)

    def test_exec_nonzero_exit(self):
        reply = self.node.tool('exec', argv=[sys.executable, '-c', 'raise SystemExit(37)'])
        self.assertFalse(reply['ok'])
        self.assertEqual(reply['exit_code'], 37)

    def test_exec_timeout(self):
        reply = self.node.tool('exec', argv=[sys.executable, '-c', 'import time; time.sleep(30)'], timeout=1)
        self.assertFalse(reply['ok'])
        self.assertTrue(reply['timeout'])

    def test_exec_shell(self):
        reply = self.node.tool('exec_shell', script='echo shell-contract')
        self.assertTrue(reply['ok'], reply)
        self.assertEqual(reply['stdout'].strip(), 'shell-contract')

    def test_file_roundtrip_hash_and_unicode_offsets(self):
        text = 'abcЮ雪😀xyz'
        data = text.encode('utf-8')
        file = self.node.root / 'nested' / 'file.txt'
        write = self.node.tool('write_file', path=str(file), content_b64=base64.b64encode(data).decode())
        self.assertTrue(write['ok'], write)
        self.assertEqual(write['sha256'], hashlib.sha256(data).hexdigest())
        self.assertEqual(file.read_bytes(), data)
        read = self.node.tool('read_file', path=str(file), offset=3, limit=3)
        self.assertEqual(read['content'], 'Ю雪😀')
        self.assertTrue(read['has_more'])
        last = self.node.tool('read_file', path=str(file), offset=6, limit=100)
        self.assertEqual(last['content'], 'xyz')
        self.assertFalse(last['has_more'])
        listing = self.node.tool('list_dir', path=str(file.parent))
        self.assertEqual([x['name'] for x in listing['items']], ['file.txt'])

    def test_invalid_utf8_file_replacement(self):
        file = self.node.root / 'invalid.txt'
        file.write_bytes(b'a\xffb')
        reply = self.node.tool('read_file', path=str(file))
        self.assertEqual(reply['content'], 'a\ufffdb')

    def test_session_stdin_eof_and_final_output(self):
        sid = self.start('import sys; d=sys.stdin.buffer.read(); sys.stdout.buffer.write(d); sys.stderr.write("err")')
        self.assertIn(sid, [s['session_id'] for s in self.node.tool('exec_list')['sessions']])
        data = 'stdin-Ю雪😀'.encode()
        written = self.node.tool('exec_write', session_id=sid,
            data_b64=base64.b64encode(data).decode(), eof=True)
        self.assertTrue(written['ok'], written)
        state = self.node.tool('exec_wait', session_id=sid, timeout=5)
        self.assertTrue(state['done'], state)
        self.assertEqual(state['stdout'], data.decode())
        self.assertEqual(state['stderr'], 'err')
        empty = self.node.tool('exec_poll', session_id=sid,
            stdout_offset=state['stdout_offset'], stderr_offset=state['stderr_offset'])
        self.assertEqual(empty['stdout'], '')
        self.assertEqual(empty['stderr'], '')

    def test_session_kill_and_idempotent_close(self):
        sid = self.start('import time; time.sleep(90)')
        self.assertTrue(self.node.tool('exec_kill', session_id=sid)['ok'])
        state = self.node.tool('exec_wait', session_id=sid, timeout=5)
        self.assertTrue(state['done'], state)
        self.assertNotEqual(state['exit_code'], 0)
        self.assertTrue(self.node.tool('exec_close', session_id=sid)['ok'])
        second = self.node.tool('exec_close', session_id=sid)
        self.assertTrue(second['ok'])
        self.assertTrue(second['already_closed'])

    def test_concurrent_close_is_safe(self):
        sid = self.start('import time; time.sleep(90)')
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: self.node.tool('exec_close', session_id=sid), range(8)))
        self.assertTrue(all(result['ok'] for result in results), results)
        self.assertEqual(self.node.rpc('ping'), {})

    def test_capped_session_output(self):
        node = Node(MCP_NODE_MAX_OUT=1024)
        self.addCleanup(node.close)
        start = node.tool('exec_start', argv=[sys.executable, '-c',
            'import os; os.write(1,b"x"*8192); os.write(2,b"y"*8192)'])
        self.assertTrue(start['ok'], start)
        state = node.tool('exec_wait', session_id=start['session_id'], timeout=5)
        self.assertTrue(state['done'], state)
        self.assertEqual(len(state['stdout']), 1024)
        self.assertEqual(len(state['stderr']), 1024)
        self.assertTrue(state['truncated_stdout'])
        self.assertTrue(state['truncated_stderr'])

    def test_text_mirror_flag_structured_only_mode(self):
        # MCP_NODE_TEXT_MIRROR=0: successful tool results drop the redundant
        # content[0].text mirror and ship structuredContent only; isError
        # results keep the text channel for every client.
        node = Node(MCP_NODE_TEXT_MIRROR='0')
        self.addCleanup(node.close)
        result = node.rpc('tools/call', {'name': 'exec',
            'arguments': {'argv': [sys.executable, '-c', 'print("mirror-off")']}})
        self.assertNotIn('content', result)
        self.assertIn('structuredContent', result)
        self.assertIs(result['isError'], False)
        self.assertEqual(result['structuredContent']['stdout'], 'mirror-off\n')
        # Domain error (isError stays false in the v0 quirk): structured-only.
        result = node.rpc('tools/call', {'name': 'read_file',
            'arguments': {'path': '/nonexistent-mcpnz-contract'}})
        self.assertNotIn('content', result)
        self.assertEqual(result['structuredContent']['error'], 'FileNotFound')
        # isError result: text mirror survives the flag.
        result = node.rpc('tools/call', {'name': 'no_such_tool', 'arguments': {}})
        self.assertIn('content', result)
        self.assertTrue(result['content'][0]['text'])
        self.assertIs(result['isError'], True)
        self.assertNotIn('structuredContent', result)
        # Default (mirror on): both channels, as before.
        default = Node()
        self.addCleanup(default.close)
        result = default.rpc('tools/call', {'name': 'exec',
            'arguments': {'argv': [sys.executable, '-c', 'print("mirror-on")']}})
        self.assertIn('content', result)
        self.assertIn('structuredContent', result)
        self.assertEqual(json.loads(result['content'][0]['text'])['stdout'], 'mirror-on\n')


if __name__ == '__main__':
    unittest.main(verbosity=2)
