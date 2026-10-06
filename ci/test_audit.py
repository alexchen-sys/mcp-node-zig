#!/usr/bin/env python3
"""End-to-end suite for the tamper-evident audit log.

Black-box over real processes: a hub and a node with audit enabled, driven
through the hub's client listener. Covers the audit-off default, tool.call
records on the node, relay records on the hub joined by req_id, link
lifecycle events, kill -9 + restart chain continuation, tamper detection
via audit-verify, and that neither the client token nor the link secret
ever lands in a log file.

Run: python3 ci/test_audit.py [path/to/mcp-node]
Prints one PASS/FAIL line per case; exits nonzero on any failure.
"""
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'ci'))
import test_reverse as rev  # noqa: E402  reuse Proc/Env/pick_port/wait_until

BINARY = rev.BINARY
pick_port = rev.pick_port
base_env = rev.base_env
wait_until = rev.wait_until
check = rev.check


class AuditEnv(rev.Env):
    """Env with audit key files and per-daemon audit file paths."""

    def __init__(self):
        super().__init__()
        self.key = secrets.token_hex(24)
        (self.dir / 'audit-key').write_text(self.key)
        os.chmod(self.dir / 'audit-key', 0o600)

    def audit_extra(self, tag):
        path = self.dir / ('audit-%s.jsonl' % tag)
        return {'MCP_NODE_AUDIT_FILE': str(path),
                'MCP_NODE_AUDIT_KEY_FILE': str(self.dir / 'audit-key')}, path

    def start_hub_audited(self):
        extra, path = self.audit_extra('hub')
        hub = self.start_hub(extra=extra)
        return hub, path

    def start_node_audited(self, name, tag=None):
        extra, path = self.audit_extra(tag or ('node-%s' % name))
        node = self.start_node(name, extra=extra, tag=tag)
        return node, path


def verify(path, expect_rc=0, anchor=False, key_path=None):
    """Run the binary's own audit-verify on one file."""
    env = base_env()
    if key_path:
        env['MCP_NODE_AUDIT_KEY_FILE'] = str(key_path)
    args = [str(BINARY), 'audit-verify']
    if anchor:
        args.append('--anchor')
    args.append(str(path))
    out = subprocess.run(args, env=env, capture_output=True, text=True, timeout=30)
    check(out.returncode == expect_rc,
          'audit-verify %s rc=%d want %d: %s %s' % (path, out.returncode, expect_rc, out.stdout, out.stderr))
    return out


def read_records(path):
    lines = Path(path).read_text().splitlines()
    return [json.loads(line) for line in lines if line.strip()]


def wait_records(path, pred, timeout_s=10):
    """Wait until the audit file holds records matching pred."""
    def ready():
        try:
            recs = read_records(path)
        except (OSError, json.JSONDecodeError):
            return None
        return recs if pred(recs) else None
    return wait_until(ready, timeout_s, 0.1)


def case_audit_off_default(env):
    """Without MCP_NODE_AUDIT_FILE nothing is written, everything works."""
    env.start_hub()
    env.start_node('alpha')
    check(env.wait_node('alpha'), 'node never connected')
    out = env.tool('alpha', 'exec', {'argv': ['echo', 'plain'], 'timeout': 10})
    check(out.get('ok') and out.get('stdout') == 'plain\n', out)
    stray = list(env.dir.glob('audit-*.jsonl'))
    check(not stray, 'audit-off run created files: %s' % stray)


def case_tool_call_and_relay_join(env):
    """exec via the hub: node logs tool.call (+tool.start), hub logs relay,
    both chained by the same req_id; both files verify."""
    hub, hub_log = env.start_hub_audited()
    node, node_log = env.start_node_audited('alpha')
    check(env.wait_node('alpha'), 'node never connected')
    marker = secrets.token_hex(8)
    status, reply = env.rpc('alpha', 'tools/call',
                            {'name': 'exec', 'arguments': {'argv': ['echo', marker], 'timeout': 10}},
                            rid=4242)
    check(status == 200 and isinstance(reply, dict) and 'result' in reply, (status, reply))
    result = reply['result']
    out = result.get('structuredContent') or json.loads(result['content'][0]['text'])
    check(out.get('ok') and marker in out.get('stdout', ''), out)

    node_recs = wait_records(node_log, lambda r: any(x.get('event') == 'tool.call' for x in r))
    check(node_recs, 'node audit log has no tool.call: %s' % node_log)
    hub_recs = wait_records(hub_log, lambda r: any(x.get('event') == 'relay' for x in r))
    check(hub_recs, 'hub audit log has no relay record')

    calls = [r for r in node_recs if r.get('event') == 'tool.call' and r.get('tool') == 'exec']
    check(calls, 'no exec tool.call in node log')
    call = calls[-1]
    check(call.get('ok') is True and call.get('exit_code') == 0, call)
    check(call.get('transport') == 'link', call)
    check(call.get('req_id') == 4242, call)
    check(isinstance(call.get('duration_ms'), int), call)
    starts = [r for r in node_recs if r.get('event') == 'tool.start' and r.get('tool') == 'exec']
    check(starts, 'exec left no tool.start trace')
    # The marker (argv[1], also stdout content) must not appear anywhere in
    # the log; summary mode keeps only argv0 + argc.
    raw = Path(node_log).read_text()
    check(marker not in raw, 'tool argument/output leaked into the node audit log')
    summary = call.get('args_summary')
    check(isinstance(summary, dict) and summary.get('argv0') == 'echo'
          and summary.get('argc') == 2 and 'argv' not in summary, summary)

    relays = [r for r in hub_recs if r.get('event') == 'relay']
    joined = [r for r in relays if r.get('req_id') == 4242 and r.get('node') == 'alpha']
    check(joined, 'no hub relay record with the node req_id: %s' % relays)
    check(joined[-1].get('ok') is True, joined[-1])
    check(joined[-1].get('tool') == 'exec', joined[-1])

    ups = [r for r in hub_recs if r.get('event') == 'link.up' and r.get('name') == 'alpha']
    check(ups, 'hub log has no link.up for alpha')

    # Sequence and chain shape: seq starts at 0 and is dense, first event is start.
    for recs, path in ((node_recs, node_log), (read_records(hub_log), hub_log)):
        seqs = [r['seq'] for r in recs]
        check(seqs == list(range(len(seqs))), ('seq gap', path, seqs[:20]))
        check(recs[0].get('event') == 'start', recs[0])

    # Stop the daemons (SIGTERM is a hard stop by design: no stop record),
    # then verify both keyed chains.
    node.stop()
    hub.stop()
    verify(node_log, key_path=env.dir / 'audit-key')
    verify(hub_log, key_path=env.dir / 'audit-key')


def case_wrong_secret_link_fail_logged(env):
    """A node with a wrong link secret is refused; the hub audit log carries
    link.fail and the node appears in no link.up."""
    hub, hub_log = env.start_hub_audited()
    extra, _ = env.audit_extra('node-mallory')
    node = env.start_node('mallory', secret_file='wrong-secret', extra=extra)
    check(wait_until(lambda: 'hub refused' in node.logs(), 10, 0.1),
          'node log has no refusal: ' + node.logs()[-1000:])
    recs = wait_records(hub_log, lambda r: any(x.get('event') == 'link.fail' for x in r))
    check(recs, 'hub audit log has no link.fail: %s' % hub_log)
    node.stop()
    hub.stop()
    verify(hub_log, key_path=env.dir / 'audit-key')


def case_kill9_restart_continues_chain(env):
    """kill -9 the node mid-run; on restart the same file continues the
    chain (no fresh seq 0, no chain.break) and verifies."""
    env.start_hub()
    node, node_log = env.start_node_audited('alpha')
    check(env.wait_node('alpha'), 'node never connected')
    for i in range(5):
        out = env.tool('alpha', 'exec', {'argv': ['echo', 'pre-%d' % i], 'timeout': 10})
        check(out.get('ok'), out)
    first = wait_records(node_log, lambda r: len(r) >= 6)
    check(first, 'node audit log did not fill up')
    max_seq = max(r['seq'] for r in first)
    node.kill9()

    # The restarted node must continue the SAME audit file (fresh tag only
    # for its own process log).
    node2 = env.start_node('alpha',
                           extra={'MCP_NODE_AUDIT_FILE': str(node_log),
                                  'MCP_NODE_AUDIT_KEY_FILE': str(env.dir / 'audit-key')},
                           tag='node-alpha-2')
    check(env.wait_node('alpha'), 'node did not reconnect')
    out = env.tool('alpha', 'exec', {'argv': ['echo', 'post'], 'timeout': 10})
    check(out.get('ok'), out)
    recs = wait_records(node_log, lambda r: any(
        x.get('event') == 'tool.call' and x.get('seq', 0) > max_seq for x in r), 5)
    check(recs, 'no post-restart tool.call in the continued chain')
    node2.stop()
    breaks = [r for r in recs if r.get('event') == 'chain.break']
    check(not breaks, 'chain broke across kill -9 restart: %s' % breaks)
    starts = [r for r in recs if r.get('event') == 'start']
    check(len(starts) == 2, 'expected exactly 2 start records: %s' % starts)
    check(starts[1]['seq'] > max_seq, ('second start did not continue seq', max_seq, starts[1]))
    verify(node_log, key_path=env.dir / 'audit-key')


def case_tamper_is_detected(env):
    """Flip one byte in a middle record; audit-verify exits 1 and names
    the seq of the first broken record."""
    env.start_hub()
    node, node_log = env.start_node_audited('alpha')
    check(env.wait_node('alpha'), 'node never connected')
    out = env.tool('alpha', 'exec', {'argv': ['echo', 'tamper'], 'timeout': 10})
    check(out.get('ok'), out)
    recs = wait_records(node_log, lambda r: any(
        x.get('event') == 'tool.call' and x.get('tool') == 'exec' for x in r), 5)
    check(recs and len(recs) >= 3, 'log too short for the tamper case')
    node.stop()
    verify(node_log, key_path=env.dir / 'audit-key')  # sanity: clean before the flip

    lines = Path(node_log).read_bytes().splitlines(keepends=True)
    victim = 1  # flip a payload byte of the second record
    row = bytearray(lines[victim])
    pos = len(row) // 2
    row[pos] = ord('0') if row[pos] != ord('0') else ord('1')
    lines[victim] = bytes(row)
    Path(node_log).write_bytes(b''.join(lines))

    out = verify(node_log, expect_rc=1, key_path=env.dir / 'audit-key')
    target_seq = recs[victim]['seq']
    check(str(target_seq) in out.stderr or str(target_seq) in out.stdout,
          'verify did not name seq %d: %s %s' % (target_seq, out.stdout, out.stderr))

def case_no_secrets_in_logs(env):
    """Token, link secret and audit key are not byte-present in the logs;
    a rejected client token is not echoed either; tool output never
    appears in any audit file."""
    hub, hub_log = env.start_hub_audited()
    node, node_log = env.start_node_audited('alpha')
    check(env.wait_node('alpha'), 'node never connected')
    out = env.tool('alpha', 'exec', {'argv': ['echo', 'secret-scan'], 'timeout': 10})
    check(out.get('ok'), out)
    status, _ = env.post('/n', b'{}', token='attacker-controlled-token-value')
    check(status == 401, status)
    check(wait_records(node_log, lambda r: any(
        x.get('event') == 'tool.call' and x.get('tool') == 'exec' for x in r), 5),
        'no tool.call on the node')
    node.stop()
    hub.stop()
    for path in (node_log, hub_log):
        raw = Path(path).read_text()
        check(env.token not in raw, 'client token leaked into %s' % path)
        check(env.secret not in raw, 'link secret leaked into %s' % path)
        check(env.key not in raw, 'audit key leaked into %s' % path)
        check('attacker-controlled-token-value' not in raw, 'bad token leaked into %s' % path)


def case_anchor_output(env):
    """--anchor prints the last seq and mac so an off-box anchor can pin it.
    Uses a stdio node: closing stdin is the clean exit that writes `stop`
    (SIGTERM to a listener node is an uncaught hard stop, by design)."""
    log = str(Path(env.dir) / 'stdio-audit.jsonl')
    e = {**os.environ, 'MCP_NODE_AUDIT_FILE': log, 'MCP_NODE_AUDIT_KEY_FILE': str(env.dir / 'audit-key')}
    request_lines = b'\n'.join([
        json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
                    'params': {'protocolVersion': '2025-06-18', 'capabilities': {},
                               'clientInfo': {'name': 'audit-anchor', 'version': '0'}}}).encode(),
        json.dumps({'jsonrpc': '2.0', 'method': 'notifications/initialized'}).encode(),
        json.dumps({'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call',
                    'params': {'name': 'exec', 'arguments': {'argv': ['echo', 'anchor'], 'timeout': 10}}}).encode(),
    ]) + b'\n'
    proc = subprocess.run([str(BINARY), '--stdio'], input=request_lines,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=e, timeout=20)
    check(proc.returncode == 0, ('stdio node exit', proc.returncode, proc.stderr[-400:]))
    recs = read_records(log)
    check(recs and recs[-1].get('event') == 'stop', ('last record is not stop', recs[-1] if recs else None))
    out = verify(log, anchor=True, key_path=env.dir / 'audit-key')
    last = recs[-1]
    tail = out.stdout.strip().splitlines()[-1].split()
    check(len(tail) == 2 and tail[0] == str(last['seq']) and tail[1] == last.get('mac'),
          ('anchor line mismatch', tail, last.get('seq'), last.get('mac')))


CASES = [
    ('audit off by default: no files, relay still works', case_audit_off_default),
    ('tool.call on the node joins relay on the hub by req_id', case_tool_call_and_relay_join),
    ('wrong link secret leaves link.fail in the hub log', case_wrong_secret_link_fail_logged),
    ('kill -9 + restart continues the same chain', case_kill9_restart_continues_chain),
    ('one flipped byte fails verify with the broken seq', case_tamper_is_detected),
    ('token, link secret and audit key never reach the logs', case_no_secrets_in_logs),
    ('--anchor prints the last seq and mac', case_anchor_output),
]


def main():
    if os.name == 'nt':
        print('SKIP audit suite: needs POSIX signals and echo')
        return 0
    if not BINARY.exists():
        print('binary not found: %s' % BINARY)
        return 2
    selected = sys.argv[2:]
    failed = 0
    for title, fn in CASES:
        if selected and fn.__name__ not in selected:
            continue
        env = AuditEnv()
        t0 = time.monotonic()
        try:
            fn(env)
            print('PASS %s (%.1fs)' % (title, time.monotonic() - t0), flush=True)
        except rev.SkipCase as why:
            print('SKIP %s: %s' % (title, why), flush=True)
        except Exception:
            failed += 1
            print('FAIL %s' % title, flush=True)
            traceback.print_exc()
        finally:
            env.close()
    if failed:
        print('%d case(s) failed' % failed)
        return 1
    print('audit e2e: all cases passed')
    return 0


if __name__ == '__main__':
    sys.exit(main())
