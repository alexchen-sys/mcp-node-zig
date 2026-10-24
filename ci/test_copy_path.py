#!/usr/bin/env python3
"""Local copy contracts using the shared real-node HTTP harness."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import struct
import tempfile
import time
import unittest

from test_regressions import Node


class CopyPath(unittest.TestCase):
    def setUp(self):
        self.node = Node()
        self.addCleanup(self.node.close)
        self.root = self.node.root

    def call(self, **args):
        return self.node.tool('copy_path', dict(source=str(self.root / 'src'),
                                              destination=str(self.root / 'dst'), **args))

    def clean_stage(self):
        self.assertFalse(list(self.root.glob('.mcpnz-copy-*')))

    def test_file_binary_and_private_mode(self):
        data = bytes(range(256)) * 1024
        (self.root / 'src').write_bytes(data)
        result = self.call()
        self.assertTrue(result['ok'], result)
        self.assertEqual((self.root / 'dst').read_bytes(), data)
        self.assertEqual(result['sha256'], hashlib.sha256(data).hexdigest())
        self.assertEqual(result['bytes'], len(data))
        self.assertEqual(result['checksum_format'], 'content-sha256')
        self.assertTrue(result['atomic_publish'])
        self.assertFalse(result['crash_durable'])
        self.assertEqual((self.root / 'dst').stat().st_mode & 0o7777, 0o600)
        self.clean_stage()

    def test_tree_digest_and_counts(self):
        src = self.root / 'src'
        (src / 'z').mkdir(parents=True)
        (src / 'b').write_bytes(b'B')
        (src / 'a').write_bytes(b'abc')
        result = self.call(recursive=True)
        self.assertTrue(result['ok'], result)
        h = hashlib.sha256(b'MCPNZ-TREE-v1\0')
        for kind, path, data in [(2, b'', b''), (1, b'a', b'abc'),
                                 (1, b'b', b'B'), (2, b'z', b'')]:
            h.update(bytes([kind]) + struct.pack('<I', len(path)) + path)
            h.update(struct.pack('<Q', len(data)))
            h.update(hashlib.sha256(data).digest() if kind == 1 else bytes(32))
        self.assertEqual(result['sha256'], h.hexdigest())
        self.assertEqual((result['files'], result['directories'], result['bytes']), (2, 2, 4))
        self.assertEqual(result['checksum_format'], 'mcp-tree-v1')
        self.clean_stage()

    def test_no_overwrite_or_implicit_parents(self):
        (self.root / 'src').write_text('new')
        (self.root / 'dst').write_text('old')
        self.assertEqual(self.call()['error'], 'DestinationExists')
        self.assertEqual((self.root / 'dst').read_text(), 'old')
        result = self.node.tool('copy_path', {'source': str(self.root / 'src'),
            'destination': str(self.root / 'missing' / 'dst')})
        self.assertEqual(result['error'], 'FileNotFound')
        self.assertFalse((self.root / 'missing').exists())
        self.clean_stage()

    def test_limits_and_recursive(self):
        (self.root / 'src').mkdir()
        (self.root / 'src' / 'a').write_text('abc')
        for args, error in [({}, 'DirectoryRequiresRecursive'),
                            ({'recursive': True, 'max_entries': 1}, 'CopyLimitExceeded'),
                            ({'recursive': True, 'max_bytes': 2}, 'CopyLimitExceeded')]:
            self.assertEqual(self.call(**args)['error'], error)
            self.assertFalse((self.root / 'dst').exists())
            self.clean_stage()
        self.assertTrue(self.call(recursive=True)['ok'])

    def test_symlinks_preserved_for_refusal(self):
        (self.root / 'real').write_text('private')
        (self.root / 'src').symlink_to('real')
        self.assertEqual(self.call()['error'], 'SymlinkNotAllowed')
        (self.root / 'src').unlink()
        (self.root / 'src').write_text('abc')
        (self.root / 'dst').symlink_to('missing')
        self.assertEqual(self.call()['error'], 'SymlinkNotAllowed')
        self.assertFalse((self.root / 'missing').exists())
        self.clean_stage()

    def test_descendant_symlink_and_hardlink(self):
        src = self.root / 'src'
        src.mkdir()
        (src / 'a').write_text('abc')
        (src / 'z').symlink_to('a')
        self.assertEqual(self.call(recursive=True)['error'], 'SymlinkNotAllowed')
        (src / 'z').unlink()
        os.link(src / 'a', src / 'z')
        self.assertEqual(self.call(recursive=True)['error'], 'UnsupportedFileType')
        self.clean_stage()

    def test_argument_types_and_ceiling(self):
        (self.root / 'src').write_text('abc')
        for extra in [{'recursive': None}, {'recursive': 1}, {'max_bytes': -1},
                      {'max_bytes': 1.5}, {'max_bytes': 67108865}, {'max_entries': 0},
                      {'timeout': 0}, {'timeout': 301}, {'overwrite': True}]:
            args = {'source': str(self.root / 'src'), 'destination': str(self.root / 'dst'), **extra}
            _, reply = self.node.rpc({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                                     'params': {'name': 'copy_path', 'arguments': args}})
            self.assertEqual(reply.get('error', {}).get('code'), -32602, reply)
        self.assertFalse((self.root / 'dst').exists())
        self.clean_stage()

    def test_features_and_manifest(self):
        info = self.node.tool('sys_info')
        self.assertTrue(info['features']['copy_path'])
        self.assertEqual(info['features']['copy_max_bytes'], 67108864)
        _, result = self.node.rpc({'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list'})
        tool = result['result']['tools'][-1]
        self.assertEqual(tool['name'], 'copy_path')
        self.assertEqual(tool['inputSchema']['required'], ['source', 'destination'])


class CopyPolicyAudit(unittest.TestCase):
    def test_dual_roots_descendant_denies_and_audit(self):
        with tempfile.TemporaryDirectory(prefix='mcp-copy-policy-') as temp:
            root = Path(temp)
            src, dst = root / 'read', root / 'write'
            src.mkdir(); dst.mkdir()
            (src / 'a').write_text('never log this content')
            token = root / 'token'
            token.write_text(secrets.token_hex(24)); token.chmod(0o600)
            policy = root / 'policy.json'
            policy.write_text(json.dumps({'version': 1, 'tokens': [{
                'file': str(token), 'tools': ['copy_path'],
                'read_paths': [str(src)], 'write_paths': [str(dst)],
                'read_deny': [str(src / 'blocked')],
                'write_deny': [str(dst / 'tree' / 'blocked')],
                'write_max_mode': '0700', 'max_timeout_s': 30,
            }]})); policy.chmod(0o600)
            audit = root / 'audit.jsonl'
            node = Node(MCP_NODE_POLICY_FILE=policy, MCP_NODE_AUDIT_FILE=audit,
                        **{'MCP_NODE_TOKEN_' + 'FILE': token})
            node.secret = token.read_text()
            try:
                ok = node.tool('copy_path', {'source': str(src / 'a'), 'destination': str(dst / 'a')})
                self.assertTrue(ok['ok'], ok)
                denied = node.tool('copy_path', {'source': str(dst / 'a'), 'destination': str(dst / 'b')})
                self.assertEqual(denied['error'], 'PolicyDenied')
                denied = node.tool('copy_path', {'source': str(src / 'a'), 'destination': str(src / 'b')})
                self.assertEqual(denied['error'], 'PolicyDenied')
                (src / 'blocked').write_text('private')
                denied = node.tool('copy_path', {'source': str(src), 'destination': str(dst / 'tree'), 'recursive': True})
                self.assertEqual(denied['error'], 'PathDenied')
                (src / 'blocked').unlink()
                (src / 'sub').mkdir(); (src / 'sub' / 'blocked').write_text('private')
                denied = node.tool('copy_path', {'source': str(src / 'sub'), 'destination': str(dst / 'tree'), 'recursive': True})
                self.assertEqual(denied['error'], 'PathDenied')
                self.assertFalse((dst / 'tree').exists())
                self.assertFalse(list(dst.glob('.mcpnz-copy-*')))
                # The shared harness terminates the daemon, so wait for the
                # asynchronous audit batch before asking it to shut down.
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    if audit.exists() and audit.read_text().count('"event":"tool.call"') >= 3:
                        break
                    time.sleep(.01)
                else:
                    self.fail('copy audit batch did not reach disk')
            finally:
                node.close()
            text = audit.read_text()
            self.assertNotIn('never log this content', text)
            records = [json.loads(line) for line in text.splitlines()]
            self.assertTrue(any(r.get('event') == 'tool.start' and r.get('tool') == 'copy_path' for r in records), records)
            self.assertIn(str(src / 'a'), text)
            self.assertIn(str(dst / 'a'), text)


if __name__ == '__main__':
    unittest.main()
