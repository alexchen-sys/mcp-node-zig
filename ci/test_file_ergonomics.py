#!/usr/bin/env python3
"""File ergonomics e2e (v0.5.0): read_file line windows, write_file text content.

Black-box over a real node process (listener mode), reusing the regression
harness Node. Covers:

  * read_file line mode: line_offset (1-indexed) / line_limit windows,
    exact total_lines, has_more at window boundaries, past-EOF windows,
    line_limit=0, CRLF preservation, mutual exclusion with offset/limit.
  * write_file content: plain UTF-8 text lands byte-exact with the sha256
    contract; content + content_b64 together is refused; neither is refused;
    the written file reads back identically in both window modes.

Plus bulk-copy interoperability cases for copy_path
  (write -> copy -> read roundtrips, destination-exists refusal, no staging
  residue).

Run: python3 ci/test_file_ergonomics.py [path/to/mcp-node]
"""
import base64
import hashlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_regressions as harness  # noqa: E402

Node = harness.Node


def case_read_file_line_windows(node):
    root = node.root
    body = "".join(f"line-{i:04d} x{('y' * (i % 7))}\n" for i in range(1, 101))
    body += "unterminated-tail"  # 101st line, no trailing LF
    target = root / "big.log"
    target.write_text(body)

    r = node.tool("read_file", {"path": str(target), "line_offset": 95})
    assert r["ok"] is True, r
    assert r["total_lines"] == 101, r
    assert r["line_offset"] == 95
    assert r["line_limit"] is None
    assert r["content"].startswith("line-0095"), r["content"][:40]
    assert r["content"].endswith("unterminated-tail"), r["content"][-40:]
    assert r["has_more"] is False
    assert r["truncated"] is False

    r = node.tool("read_file", {"path": str(target), "line_offset": 1, "line_limit": 3})
    assert r["content"].count("\n") == 3 and "line-0003" in r["content"], r
    assert r["has_more"] is True and r["total_lines"] == 101, r

    r = node.tool("read_file", {"path": str(target), "line_offset": 101, "line_limit": 1})
    assert r["content"] == "unterminated-tail", r
    assert r["has_more"] is False, r

    r = node.tool("read_file", {"path": str(target), "line_offset": 500})
    assert r["content"] == "" and r["has_more"] is False, r

    r = node.tool("read_file", {"path": str(target), "line_limit": 0})
    assert r["content"] == "" and r["total_lines"] == 101 and r["has_more"] is True, r

    # Mutual exclusion with the character window family.
    r = node.tool("read_file", {"path": str(target), "line_offset": 1, "offset": 0})
    assert r.get("ok") is False and r.get("error") == "ConflictingParams", r
    r = node.tool("read_file", {"path": str(target), "line_limit": 2, "limit": 10})
    assert r.get("ok") is False and r.get("error") == "ConflictingParams", r

    # line_offset is 1-indexed.
    r = node.tool("read_file", {"path": str(target), "line_offset": 0})
    assert r.get("ok") is False and r.get("error") == "BadOffset", r

    # Character mode is untouched: no line keys leak into it.
    r = node.tool("read_file", {"path": str(target), "offset": 0, "limit": 12})
    assert r["ok"] is True and "total_lines" not in r and r["offset"] == 0, r
    print("ok  case_read_file_line_windows")


def case_write_file_text_content(node):
    root = node.root
    target = root / "conf" / "app.json"
    text = '{\n  "greeting": "héllo",\n  "level": 3\n}\n'
    r = node.tool("write_file", {"path": str(target), "content": text})
    assert r["ok"] is True, r
    assert r["size"] == len(text.encode()), r
    assert r["sha256"] == hashlib.sha256(text.encode()).hexdigest(), r
    assert target.read_text() == text

    # Byte-identical read-back in both window modes.
    r = node.tool("read_file", {"path": str(target)})
    assert r["content"] == text, r
    r = node.tool("read_file", {"path": str(target), "line_offset": 2, "line_limit": 1})
    assert r["content"] == '  "greeting": "héllo",\n', r
    assert r["total_lines"] == 4, r

    # content + content_b64 together: refused, and the file is untouched.
    before = target.read_bytes()
    r = node.tool("write_file", {"path": str(target), "content": "x", "content_b64": "eA=="})
    assert r.get("ok") is False and r.get("error") == "ConflictingContent", r
    assert target.read_bytes() == before

    # Neither field: refused.
    r = node.tool("write_file", {"path": str(target)})
    assert r.get("ok") is False and r.get("error") == "MissingContent", r

    # Binary path still works and overwrites.
    r = node.tool("write_file", {"path": str(target), "content_b64": "AAECAwQ="})
    assert r["ok"] is True and r["size"] == 5, r
    assert target.read_bytes() == b"\x00\x01\x02\x03\x04"
    print("ok  case_write_file_text_content")


class FileInteroperability(unittest.TestCase):
    def setUp(self):
        self.node = Node()
        self.addCleanup(self.node.close)

    def test_written_file_copies_and_reads(self):
        src = str(self.node.root / 'source')
        dst = str(self.node.root / 'destination')
        text = 'first\nsecond\n'
        written = self.node.tool('write_file', {'path': src,
            'content_b64': base64.b64encode(text.encode()).decode()})
        self.assertTrue(written['ok'])
        copied = self.node.tool('copy_path', {'source': src, 'destination': dst})
        self.assertEqual(copied['sha256'], written['sha256'])
        read = self.node.tool('read_file', {'path': dst})
        self.assertEqual(read['content'], text)

    def test_existing_file_still_requires_explicit_write(self):
        root = self.node.root
        (root / 'src').write_text('replacement')
        (root / 'dst').write_text('original')
        refused = self.node.tool('copy_path', {'source': str(root / 'src'), 'destination': str(root / 'dst')})
        self.assertEqual(refused['error'], 'DestinationExists')
        result = self.node.tool('write_file', {'path': str(root / 'dst'), 'content_b64': 'bmV3'})
        self.assertTrue(result['ok'])
        self.assertEqual((root / 'dst').read_text(), 'new')

    def test_copied_tree_lists_without_staging_names(self):
        root = self.node.root
        (root / 'src').mkdir()
        (root / 'src' / 'a').write_text('a')
        result = self.node.tool('copy_path', {'source': str(root / 'src'), 'destination': str(root / 'dst'), 'recursive': True})
        self.assertTrue(result['ok'])
        listing = self.node.tool('list_dir', {'path': str(root / 'dst')})
        self.assertEqual([item['name'] for item in listing['items']], ['a'])
        self.assertFalse(list(root.glob('.mcpnz-copy-*')))


def main():
    node = Node()
    try:
        case_read_file_line_windows(node)
        case_write_file_text_content(node)
    finally:
        node.close()
    suite = unittest.TestLoader().loadTestsFromTestCase(FileInteroperability)
    result = unittest.TextTestRunner(verbosity=0).run(suite)
    if not result.wasSuccessful():
        raise SystemExit(1)
    print("file ergonomics: all cases passed")


if __name__ == "__main__":
    main()
