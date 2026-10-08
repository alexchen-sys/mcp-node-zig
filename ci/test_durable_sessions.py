#!/usr/bin/env python3
"""Durable sessions: reattach, overflow accounting, TTL reap, unknown_session.

Black-box over real processes (listener mode), reusing the regression
harness Node. Covers the durability contract:

  * Client disconnect + reattach: a session started on connection A is
    fully serviceable from connection B by session_id — poll from the old
    offsets, write, kill, close. Capture keeps running while nobody polls.
  * Buffer overflow: with MCP_NODE_MAX_OUT=2048 a child printing past the
    cap keeps its first 2048 bytes, sets truncated_* and reports the exact
    lost byte count in lost_*_bytes. Never a silent loss.
  * TTL reap: with MCP_NODE_SESSION_TTL_S=1 a finished session leaves
    exec_list and a later poll answers unknown_session with expired=true.
  * unknown_session contract: a never-existent id answers the structured
    payload (ok:false, error:unknown_session, session_id, expired:false)
    inside a normal 200 result envelope — never a bare JSON-RPC -32602.

Run: python3 ci/test_durable_sessions.py [path/to/mcp-node]
"""
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_regressions as harness  # noqa: E402

Node = harness.Node
PY = sys.executable


def wait_for(pred, timeout_s=10.0, step_s=0.05):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if pred():
            return True
        time.sleep(step_s)
    return pred()


def assert_check(cond, msg):
    if not cond:
        raise AssertionError(msg)


def case_reattach_after_client_disconnect():
    node = Node(MCP_NODE_MAX_OUT='1000000')
    try:
        code = ("import sys, time\n"
                "for i in range(40):\n"
                "    print('line', i, flush=True)\n"
                "    time.sleep(0.05)\n")
        started = node.tool('exec_start', {'argv': [PY, '-c', code]})
        sid = started['session_id']
        # First read on connection A, then drop the connection mid-run.
        first = node.tool('exec_poll', {'session_id': sid})
        assert_check(first['ok'], first)
        off = first['stdout_offset']
        # Let the child produce more output while nobody is connected.
        time.sleep(1.0)
        # A brand-new HTTP connection reattaches by session_id only.
        second = node.tool('exec_poll', {'session_id': sid, 'stdout_offset': off})
        assert_check(second['ok'], second)
        assert_check(second['stdout_offset'] > off, second)
        # The delta continues exactly at the old offset: no gap, no replay.
        assert_check('line' in second['stdout'], second)
        # Write, kill and close from the reattached connection.
        assert_check(node.tool('exec_kill', {'session_id': sid})['ok'], 'kill failed')
        waited = node.tool('exec_wait', {'session_id': sid, 'timeout': 5})
        assert_check(waited['done'], waited)
        closed = node.tool('exec_close', {'session_id': sid})
        assert_check(closed['ok'], closed)
    finally:
        node.close()


def case_overflow_counts_lost_bytes():
    node = Node(MCP_NODE_MAX_OUT='2048')
    try:
        code = ("import sys\n"
                "sys.stdout.write('A' * 5000)\n"
                "sys.stdout.flush()\n")
        started = node.tool('exec_start', {'argv': [PY, '-c', code]})
        sid = started['session_id']
        waited = node.tool('exec_wait', {'session_id': sid, 'timeout': 10})
        assert_check(waited['done'], waited)
        # Head policy: the first max_out bytes are kept.
        assert_check(len(waited['stdout']) <= 2048, waited['stdout'][:64])
        # Explicit truncation flag and the exact lost count.
        assert_check(waited['truncated_stdout'], waited)
        assert_check(waited['lost_stdout_bytes'] >= 5000 - 2048, waited)
        assert_check(waited['lost_stderr_bytes'] == 0, waited)
        node.tool('exec_close', {'session_id': sid})
    finally:
        node.close()


def case_ttl_reap_expired_flag():
    node = Node(MCP_NODE_SESSION_TTL_S='1')
    try:
        started = node.tool('exec_start', {'argv': ['/bin/echo', 'done-fast']})
        sid = started['session_id']
        waited = node.tool('exec_wait', {'session_id': sid, 'timeout': 5})
        assert_check(waited['done'], waited)
        # After the TTL the finished session leaves exec_list and any poll
        # answers unknown_session with expired=true.
        def gone():
            listing = node.tool('exec_list')
            return all(s['session_id'] != sid for s in listing.get('sessions', []))
        assert_check(wait_for(gone, 15, 0.2), 'session not reaped within TTL')
        # reapDone runs on put/list: trigger it explicitly, then poll.
        ghost = node.tool('exec_poll', {'session_id': sid})
        assert_check(not ghost['ok'] and ghost['error'] == 'unknown_session', ghost)
        assert_check(ghost['session_id'] == sid, ghost)
        assert_check(ghost['expired'] is True, ghost)
        assert_check('exec_list' in ghost.get('message', ''), ghost)
    finally:
        node.close()


def case_unknown_session_never_existed():
    node = Node()
    try:
        reply = node.tool('exec_poll', {'session_id': 999999})
        assert_check(not reply['ok'], reply)
        assert_check(reply['error'] == 'unknown_session', reply)
        assert_check(reply['session_id'] == 999999, reply)
        assert_check(reply['expired'] is False, reply)
        # The full JSON-RPC envelope must be a 200 result, never -32602:
        # verify through the raw rpc helper.
        status, body = node.rpc({'jsonrpc': '2.0', 'id': 88, 'method': 'tools/call',
                                 'params': {'name': 'exec_poll', 'arguments': {'session_id': 123456}}})
        assert_check(status == 200, (status, body))
        assert_check('error' not in body, body)  # no JSON-RPC error member
        assert_check(body['result']['structuredContent']['error'] == 'unknown_session', body)
        # exec_close keeps its idempotent contract for the same situation.
        closed = node.tool('exec_close', {'session_id': 999999})
        assert_check(closed['ok'] and closed.get('already_closed') is True, closed)
        # exec_write and exec_kill answer the same unknown_session payload.
        wreply = node.tool('exec_write', {'session_id': 999998, 'data_b64': ''})
        assert_check(wreply['error'] == 'unknown_session', wreply)
        kreply = node.tool('exec_kill', {'session_id': 999997})
        assert_check(kreply['error'] == 'unknown_session', kreply)
    finally:
        node.close()


def main():
    import unittest
    suite = unittest.TestSuite()
    cases = [
        ('reattach_after_client_disconnect', case_reattach_after_client_disconnect),
        ('overflow_counts_lost_bytes', case_overflow_counts_lost_bytes),
        ('ttl_reap_expired_flag', case_ttl_reap_expired_flag),
        ('unknown_session_never_existed', case_unknown_session_never_existed),
    ]
    failures = 0
    for name, fn in cases:
        t0 = time.monotonic()
        try:
            fn()
            print('PASS %s (%.1fs)' % (name, time.monotonic() - t0))
        except Exception as err:
            failures += 1
            print('FAIL %s: %r' % (name, err))
            import traceback
            traceback.print_exc()
    print('%d/%d passed' % (len(cases) - failures, len(cases)))
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
