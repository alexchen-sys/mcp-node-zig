#!/usr/bin/env python3
"""Process-lifecycle edge cases.

Kept apart from ci/test_regressions.py so the general contract suite stays
small. Covers, black-box over JSON-RPC (plus one source-contract guard):

  * Escaped pipe holder (POSIX): a session whose setsid grandchild keeps
    stdout/stderr open must still finalize — bounded drain, all available
    output preserved, done=true. Before the bounded drain done never became
    true.
  * Multisession isolation: one session's exit must never disturb another
    session's tree. On Linux the waitid call is typed and this passes by
    construction; flipping the Linux idtype .PID -> .ALL makes it fail, and
    on macOS it guards the libSystem waitid branch (P_ALL=0 vs P_PID=1).
  * check/kill/reap serialization guard: exec_kill / exec_wait / exec_close
    hammer against fast-exiting sessions — no crash, no hang, well-formed
    replies, daemon healthy afterwards.
  * Source contract for the Darwin waitid branch Linux cannot execute:
    typed idtype (P_PID = 1 on XNU), no bare literal-0 idtype, and a
    child-identity check on the waitid result.

Run: python3 ci/test_lifecycle_edge.py [path/to/mcp-node]
"""
import os
from pathlib import Path
import re
import sys
import threading
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
# Reuse the battle-tested harness (Node, pid_alive, wait_pid_dead). Importing
# test_regressions pops argv[1] as the binary override when present; its
# __main__ block does not fire on import.
import test_regressions as harness

Node = harness.Node
pid_alive = harness.pid_alive
wait_pid_dead = harness.wait_pid_dead
kill_pid = harness.kill_pid

ROOT = harness.ROOT
PROC_ZIG = ROOT / 'src' / 'os' / 'proc.zig'

TAIL_STDOUT = 65536
TAIL_STDERR = 1024


class KillFinalizeTests(unittest.TestCase):
    """A session whose escaped (setsid) grandchild pins the output
    pipes open must still finalize — bounded drain, all available output
    preserved, done=true. Not a blind close: the already-written tail must
    survive finalization."""

    def setUp(self):
        self.node = Node()
        self.addCleanup(self.node.close)
        self.escapees = []
        self.addCleanup(self._reap_escapees)

    def _reap_escapees(self):
        for pid in self.escapees:
            kill_pid(pid)

    def _spawn_leader_with_escapee(self, marker, then_sleep_s=0):
        """Leader: spawn a setsid escapee holding stdout/stderr, write the
        full tail, optionally sleep, then exit (or be killed while asleep).
        Returns (session_id, escapee_pid)."""
        pid_file = self.node.root / ('escapee-%s.pid' % marker)
        if sys.platform == 'win32':
            escapee_code = ('import subprocess,pathlib,sys;'
                            'p=subprocess.Popen([sys.executable,"-c","import time;time.sleep(90)"],'
                            'creationflags=0x200);'  # CREATE_NEW_PROCESS_GROUP
                            'pathlib.Path(sys.argv[1]).write_text(str(p.pid))')
        else:
            escapee_code = ('import subprocess,pathlib,sys;'
                            'p=subprocess.Popen([sys.executable,"-c","import time;time.sleep(90)"],'
                            'start_new_session=True);'
                            'pathlib.Path(sys.argv[1]).write_text(str(p.pid))')
        sleep_line = 'import time; time.sleep(%d);' % then_sleep_s if then_sleep_s else ''
        leader_code = ('import os,sys;'
                       + 'exec(%r, {"sys": sys});' % escapee_code
                       + 'os.write(1, b"T"*%d);'
                         'os.write(2, b"E"*%d);' % (TAIL_STDOUT, TAIL_STDERR)
                       + sleep_line)
        started = self.node.tool('exec_start', {'argv': [sys.executable, '-c', leader_code, str(pid_file)]})
        self.assertTrue(started.get('ok'), started)
        sid = started['session_id']
        deadline = time.monotonic() + 5
        while not pid_file.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(pid_file.exists(), 'escapee pid file never appeared')
        escapee = int(pid_file.read_text())
        self.escapees.append(escapee)
        return sid, escapee

    def _assert_finalized_with_tail(self, sid, expected_exit):
        # exec_wait timeout stays below the harness client socket deadline
        # (read_http_response sets 8s) so a non-finalizing session yields a
        # clean done=false assertion failure, not a transport TimeoutError.
        state = self.node.tool('exec_wait', {'session_id': sid, 'timeout': 5})
        self.assertTrue(state.get('done'),
                        'session never finalized with an escaped grandchild '
                        'holding the pipes (waiter stuck in the drain loop): %r' % (state,))
        self.assertEqual(state.get('exit_code'), expected_exit, state)
        self.assertEqual(state.get('stdout', ''), 'T' * TAIL_STDOUT,
                         'finalization lost available output tail: got %d/%d bytes'
                         % (len(state.get('stdout', '')), TAIL_STDOUT))
        self.assertEqual(state.get('stderr', ''), 'E' * TAIL_STDERR)

    def _assert_escapee_lifecycle(self, sid, escapee):
        if sys.platform == 'win32':
            # The Job Object terminates every process that ever belonged to
            # the tree; the escapee cannot outlive the leader there.
            self.assertTrue(wait_pid_dead(escapee),
                            'escapee %d alive despite Job Object termination' % escapee)
        else:
            # POSIX: the escapee left the process group; finalization must
            # NOT reach outside the session's own group (no overkill), so it
            # legitimately survives — the test cleans it up itself.
            self.assertTrue(pid_alive(escapee),
                            'escapee %d unexpectedly dead; kill reached outside '
                            'the session process group' % escapee)
        closed = self.node.tool('exec_close', {'session_id': sid})
        self.assertTrue(closed.get('ok'), closed)
        if sys.platform != 'win32':
            self.assertTrue(pid_alive(escapee),
                            'escapee %d killed by exec_close: kill escaped the '
                            'session process group' % escapee)
            kill_pid(escapee)
            self.assertTrue(wait_pid_dead(escapee), 'escapee cleanup failed')
        status, reply = self.node.rpc({'jsonrpc': '2.0', 'id': 1, 'method': 'ping'})
        self.assertEqual(status, 200)
        self.assertEqual(reply.get('result'), {})

    def test_kill_finalizes_after_leader_exit_with_escaped_pipe_holder(self):
        """Core scenario: the leader has ALREADY exited, the
        setsid escapee holds the pipes; the session must still finalize on
        its own (bounded drain); without it done never becomes true."""
        sid, escapee = self._spawn_leader_with_escapee('exit')
        # Leader exits 0 right after writing the tail. No kill needed to
        # expose the defect: without the bounded drain exec_wait alone hangs.
        self._assert_finalized_with_tail(sid, 0)
        # exec_kill on an already-finalized session must be a safe no-op.
        killed = self.node.tool('exec_kill', {'session_id': sid})
        self.assertTrue(killed.get('ok'), killed)
        self._assert_escapee_lifecycle(sid, escapee)

    def test_kill_finalizes_live_session_with_escaped_pipe_holder(self):
        """exec_kill as the terminal intent: leader alive (asleep) with the
        escapee holding the pipes; kill must lead to bounded finalization
        with the available tail preserved."""
        sid, escapee = self._spawn_leader_with_escapee('live', then_sleep_s=30)
        killed = self.node.tool('exec_kill', {'session_id': sid})
        self.assertTrue(killed.get('ok'), killed)
        # SIGKILLed leader: 128 + SIGKILL. Windows job kill reports 1.
        self._assert_finalized_with_tail(sid, 1 if sys.platform == 'win32' else 137)
        self._assert_escapee_lifecycle(sid, escapee)


class MultisessionTests(unittest.TestCase):
    """Concurrent sessions are isolated. One session's exit
    must never wake another session's waiter into killing its own live tree
    (the waitid(P_ALL) class of bug). The Linux .PID->.ALL flip fails it;
    on macOS it exercises the libSystem waitid branch."""

    def setUp(self):
        self.node = Node()
        self.addCleanup(self.node.close)

    def test_multisession_exit_isolation(self):
        marker = 'B-SURVIVED-MARKER'
        # Session B: stays alive well past A's exit, then completes cleanly.
        started_b = self.node.tool('exec_start', {'argv': [sys.executable, '-c',
            'import time,os; time.sleep(1.5); os.write(1, b"%s")' % marker]})
        self.assertTrue(started_b.get('ok'), started_b)
        sid_b = started_b['session_id']
        # Session A: exits immediately while B's waiter is blocked in waitid.
        started_a = self.node.tool('exec_start', {'argv': [sys.executable, '-c',
            'import os; os.write(1, b"A")']})
        self.assertTrue(started_a.get('ok'), started_a)
        sid_a = started_a['session_id']

        state_a = self.node.tool('exec_wait', {'session_id': sid_a, 'timeout': 10})
        self.assertTrue(state_a.get('done'), state_a)
        self.assertEqual(state_a.get('exit_code'), 0, state_a)

        state_b = self.node.tool('exec_wait', {'session_id': sid_b, 'timeout': 15})
        self.assertTrue(state_b.get('done'), state_b)
        self.assertEqual(state_b.get('exit_code'), 0,
                         'session B was disturbed by session A exiting '
                         '(cross-session kill — waitid matched the wrong child): %r' % (state_b,))
        self.assertEqual(state_b.get('stdout', ''), marker,
                         'session B output cut short after A exited: %r' % (state_b.get('stdout'),))

        for sid in (sid_a, sid_b):
            closed = self.node.tool('exec_close', {'session_id': sid})
            self.assertTrue(closed.get('ok'), closed)
        status, reply = self.node.rpc({'jsonrpc': '2.0', 'id': 2, 'method': 'ping'})
        self.assertEqual(status, 200)
        self.assertEqual(reply.get('result'), {})


class KillSerializationTests(unittest.TestCase):
    """Guard for the check/kill/reap serialization (tree_killed alone is a
    data race: load(false) -> context switch -> waiter kill+reap -> late kill
    at a recycled pgid). Hammer concurrent kill/wait/close on fast-exiting
    sessions: every reply well-formed, no hang, daemon stays healthy."""

    def setUp(self):
        self.node = Node()
        self.addCleanup(self.node.close)

    def test_kill_wait_close_hammer_no_hang(self):
        rounds = 20
        for round_no in range(rounds):
            started = self.node.tool('exec_start', {'argv': [sys.executable, '-c',
                'import os; os.write(1, b"x"*64)']})
            self.assertTrue(started.get('ok'), started)
            sid = started['session_id']
            outcomes = {}

            def call(name, tool, args):
                try:
                    status, reply = self.node.rpc({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                                                   'params': {'name': tool, 'arguments': args}})
                    outcomes[name] = (status, 'result' in reply or 'error' in reply)
                except Exception as exc:
                    outcomes[name] = ('exception', repr(exc))

            threads = [
                threading.Thread(target=call, args=('kill', 'exec_kill', {'session_id': sid})),
                threading.Thread(target=call, args=('wait', 'exec_wait', {'session_id': sid, 'timeout': 10})),
                threading.Thread(target=call, args=('close', 'exec_close', {'session_id': sid})),
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=20)
            for t in threads:
                self.assertFalse(t.is_alive(), 'round %d: %s hung' % (round_no, outcomes))
            for name, outcome in outcomes.items():
                self.assertEqual(outcome[0], 200, 'round %d %s: %r' % (round_no, name, outcome))
                self.assertTrue(outcome[1], 'round %d %s malformed reply: %r' % (round_no, name, outcome))
            # Deterministic final state: nobody holds the session anymore.
            self.node.tool('exec_close', {'session_id': sid})

        status, reply = self.node.rpc({'jsonrpc': '2.0', 'id': 3, 'method': 'ping'})
        self.assertEqual(status, 200, 'daemon unhealthy after kill/wait/close hammer')
        self.assertEqual(reply.get('result'), {})
        sessions = self.node.tool('exec_list').get('sessions', [])
        self.assertEqual(sessions, [], 'sessions leaked after hammer: %r' % (sessions,))


class DarwinWaitidContractTests(unittest.TestCase):
    """Source contract for the Darwin branch of waitChildExitNoReap, which
    Linux runs cannot execute. XNU bsd/sys/wait.h: enum idtype { P_ALL, P_PID,
    P_PGID } — P_ALL=0, P_PID=1, P_PGID=2. A literal 0 (P_ALL) matches ANY
    exited child of the daemon and kills parallel sessions' trees."""

    def test_darwin_waitid_p_pid_identity_contract(self):
        self.assertTrue(PROC_ZIG.is_file(), 'proc.zig not found at %s' % PROC_ZIG)
        src = PROC_ZIG.read_text()
        # Anti-vacuity anchors: the function, its Darwin branch and the extern
        # waitid declaration must actually be present, otherwise the asserts
        # below prove nothing.
        self.assertIn('fn waitChildExitNoReap', src)
        self.assertIn('extern "c" fn waitid', src)
        self.assertIn('.linux', src, 'Linux waitid branch anchor missing')

        # 1. No bare literal-0 idtype may reach waitid anywhere (0 == P_ALL).
        self.assertIsNone(re.search(r'waitid\(\s*0\s*,', src),
                          'waitid called with literal idtype 0 (P_ALL on XNU): '
                          'matches any exited child, kills parallel sessions')
        # 2. The Darwin call must use a typed idtype whose pid value is 1.
        self.assertIsNotNone(re.search(r'enum\s*\(\s*c_uint\s*\)', src),
                             'typed XNU idtype enum missing')
        self.assertIsNotNone(re.search(r'\ball\s*=\s*0\b', src), 'P_ALL = 0 constant missing')
        self.assertIsNotNone(re.search(r'\bpid\s*=\s*1\b', src), 'P_PID = 1 constant missing')
        self.assertIsNotNone(re.search(r'\bpgid\s*=\s*2\b', src), 'P_PGID = 2 constant missing')
        self.assertIsNotNone(re.search(r'waitid\([^,]*\.pid\s*\)', src),
                             'Darwin waitid must pass the typed .pid idtype')
        # 3. Defensive identity check: a returned child that is not ours must
        # degrade to the fallback path, never to killing our own live tree.
        self.assertIsNotNone(re.search(r'info\.pid\s*!=\s*pid', src),
                             'waitid result identity check (info.pid != pid) missing')


if __name__ == '__main__':
    unittest.main(verbosity=2)
