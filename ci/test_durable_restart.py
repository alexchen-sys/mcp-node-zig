#!/usr/bin/env python3
"""Durable session e2e: real node death, file-backed output, recovery, control.

Black-box over real processes started through the stdio transport:

  * exec_start durable:true without a state dir answers DurabilityDisabled.
  * A live slow writer keeps writing to <state_dir>/sessions/<id>/stdout.log
    while the node process is SIGKILLed; after a restart with the same
    --state-dir the same session_id answers recovered:true and
    stdin_available:false, and the poll deltas are byte-exact against the
    log file (including the bytes written while the node was down).
  * exec_write on the recovered session answers StdinUnavailable.
  * exec_kill verifies the recorded identity and kills the tree (the child
    pid is gone or a reaped zombie, tree_state answers killed).
  * A recovered session whose child exited while the node was down reports
    exit_code:null with completion_reason orphaned_exit and
    output_complete:true, because init reaped the exit status.
  * exec_close retires the session: the state dir entry disappears and the
    id answers unknown_session with expired:true, still after another
    restart (the tombstone ring is on disk). The next durable start takes a
    higher id than the retired one.

Run: python3 ci/test_durable_restart.py [path/to/mcp-node]
"""
import base64
import os
from pathlib import Path
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_stdio import StdioNode

STATE_MAX_BYTES = 8192
META_HEADER = 160
META_TRAILER = 32


def tool(node, name, args):
    reply = node.call({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                       'params': {'name': name, 'arguments': args}})
    assert 'result' in reply, reply
    return reply['result']['structuredContent']


def wait_dead(pid, timeout=10.0):
    """True once pid is gone or a zombie (its status was reaped by init)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            stat = Path('/proc/%d/stat' % pid).read_bytes()
        except FileNotFoundError:
            return True
        end = stat.rindex(b')')
        state = stat[end + 2:end + 3]
        if state in (b'Z', b'X'):
            return True
        time.sleep(0.02)
    return False


def case_disabled():
    node = StdioNode()
    try:
        result = tool(node, 'exec_start', {'argv': [sys.executable, '-c', 'pass'], 'durable': True})
        assert result['ok'] is False, result
        assert result['error'] == 'DurabilityDisabled', result
    finally:
        node.kill()


def case_restart_live_writer():
    with tempfile.TemporaryDirectory(prefix='mcpnz-durable-') as state:
        node = StdioNode(args=('--stdio', '--state-dir', state))
        replacement = None
        pid = None
        try:
            code = ("import sys,time\n"
                    "for i in range(600):\n"
                    "    sys.stdout.write('%04d\\n' % i)\n"
                    "    sys.stdout.flush()\n"
                    "    time.sleep(0.03)\n")
            started = tool(node, 'exec_start',
                           {'argv': [sys.executable, '-c', code], 'durable': True})
            assert started['ok'] is True, started
            assert started['recovered'] is False and started['stdin_available'] is True, started
            sid, pid = started['session_id'], started['pid']

            session_dir = Path(state) / 'sessions' / str(sid)
            log = session_dir / 'stdout.log'
            assert (Path(state) / 'index.bin').stat().st_size == STATE_MAX_BYTES
            assert (session_dir / 'meta.bin').stat().st_size > META_HEADER + META_TRAILER

            time.sleep(0.2)
            assert log.stat().st_size > 0, 'the child never wrote to its log'
            first = tool(node, 'exec_poll', {'session_id': sid})
            assert first['ok'] is True and first['done'] is False, first
            assert first['stdout'], first
            assert first['recovered'] is False and first['stdin_available'] is True, first

            # Real node death: SIGKILL, no clean stop path, no flush.
            node.proc.kill()
            assert node.proc.wait(timeout=20) == -9
            before = log.stat().st_size
            time.sleep(0.3)
            assert log.stat().st_size > before, 'the detached child stopped writing'

            replacement = StdioNode(args=('--stdio', '--state-dir', state))
            second = tool(replacement, 'exec_poll',
                          {'session_id': sid, 'stdout_offset': first['stdout_offset']})
            assert second['ok'] is True and second['done'] is False, second
            assert second['recovered'] is True and second['stdin_available'] is False, second
            assert second['stdout'], second
            assert second['stdout_offset'] > first['stdout_offset'], second
            # Byte-exact deltas against the append-only log, node death in the middle.
            raw = log.read_bytes()
            assert raw[:first['stdout_offset']].decode() == first['stdout'], first
            assert raw[first['stdout_offset']:second['stdout_offset']].decode() == second['stdout'], second

            written = tool(replacement, 'exec_write',
                           {'session_id': sid, 'data_b64': base64.b64encode(b'x').decode()})
            assert written['ok'] is False and written['error'] == 'StdinUnavailable', written

            killed = tool(replacement, 'exec_kill', {'session_id': sid})
            assert killed['ok'] is True, killed
            assert wait_dead(pid), 'the verified tree survived exec_kill'
            after = tool(replacement, 'exec_poll',
                         {'session_id': sid, 'stdout_offset': second['stdout_offset']})
            assert after['tree_state'] == 'killed', after
            done = tool(replacement, 'exec_wait', {'session_id': sid, 'timeout': 10})
            assert done['done'] is True and done['recovered'] is True, done
            assert done['exit_code'] is None, done
            assert done['completion_reason'] == 'orphaned_exit', done
            assert done['output_complete'] is True, done

            closed = tool(replacement, 'exec_close', {'session_id': sid})
            assert closed['ok'] is True, closed
            assert not session_dir.exists(), 'exec_close left the session dir behind'
            gone = tool(replacement, 'exec_poll', {'session_id': sid})
            assert gone['ok'] is False and gone['error'] == 'unknown_session', gone
            assert gone['expired'] is True, gone

            replacement.close_stdin_and_wait()
            replacement = StdioNode(args=('--stdio', '--state-dir', state))
            expired = tool(replacement, 'exec_poll', {'session_id': sid})
            assert expired['error'] == 'unknown_session' and expired['expired'] is True, expired
            new = tool(replacement, 'exec_start',
                       {'argv': [sys.executable, '-c', 'pass'], 'durable': True})
            assert new['ok'] is True and new['session_id'] > sid, new
            assert tool(replacement, 'exec_close', {'session_id': new['session_id']})['ok']
        finally:
            if pid:
                try:
                    os.killpg(pid, 9)
                except (ProcessLookupError, PermissionError):
                    pass
            node.kill()
            if replacement:
                replacement.kill()


def case_finished_while_down():
    with tempfile.TemporaryDirectory(prefix='mcpnz-durable-') as state:
        node = StdioNode(args=('--stdio', '--state-dir', state))
        replacement = None
        try:
            code = ("import sys,time\n"
                    "sys.stdout.write('one\\n')\n"
                    "sys.stdout.flush()\n"
                    "time.sleep(0.4)\n"
                    "sys.stdout.write('two\\n')\n"
                    "sys.stdout.flush()\n"
                    "sys.exit(7)\n")
            started = tool(node, 'exec_start',
                           {'argv': [sys.executable, '-c', code], 'durable': True})
            assert started['ok'] is True, started
            sid = started['session_id']
            node.proc.kill()
            assert node.proc.wait(timeout=20) == -9

            replacement = StdioNode(args=('--stdio', '--state-dir', state))
            deadline = time.time() + 20
            while True:
                polled = tool(replacement, 'exec_poll', {'session_id': sid})
                if polled['done'] or time.time() > deadline:
                    break
                time.sleep(0.05)
            assert polled['done'] is True, polled
            assert polled['recovered'] is True and polled['stdin_available'] is False, polled
            assert polled['stdout'].replace('\r\n', '\n') == 'one\ntwo\n', polled
            # init reaped the orphan: the POSIX exit code is unknowable.
            assert polled['exit_code'] is None, polled
            assert polled['completion_reason'] == 'orphaned_exit', polled
            assert polled['output_complete'] is True, polled
            assert tool(replacement, 'exec_close', {'session_id': sid})['ok']
        finally:
            node.kill()
            if replacement:
                replacement.kill()


def case_ephemeral_expiry_with_state():
    # With a state dir configured, closing an EPHEMERAL session must keep
    # the pre-durable contract: a follow-up poll answers unknown_session
    # with expired:true from the in-memory ring (the disk ring serves
    # durable records only).
    with tempfile.TemporaryDirectory(prefix='mcpnz-durable-') as state:
        node = StdioNode(args=('--stdio', '--state-dir', state))
        try:
            started = tool(node, 'exec_start',
                           {'argv': [sys.executable, '-c', 'pass']})
            assert started['ok'] is True, started
            sid = started['session_id']
            closed = tool(node, 'exec_close', {'session_id': sid})
            assert closed['ok'] is True, closed
            polled = tool(node, 'exec_poll', {'session_id': sid})
            assert polled['ok'] is False and polled['error'] == 'unknown_session', polled
            assert polled['expired'] is True, polled
        finally:
            node.kill()


if __name__ == '__main__':
    cases = (case_disabled, case_restart_live_writer, case_finished_while_down,
             case_ephemeral_expiry_with_state)
    for case in cases:
        case()
        print('PASS', case.__name__)
    print('%d passed' % len(cases))
