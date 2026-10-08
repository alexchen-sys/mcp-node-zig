#!/usr/bin/env python3
"""End-to-end suite for per-token argument gating.

Black-box over a real listen-mode binary: one node with
MCP_NODE_POLICY_FILE configured, two client tokens (read-only and build),
plus the classic token file mapped to an admin entry. Proves that a denied
call NEVER executes (no side-effect file), that path/traversal/symlink/
argv0/timeout/mode rules hold, that sessions are token-owned, that
denials land in the audit log with reasons, and that startup fails on
policy misuse. Also proves the no-policy default is v0.3.1 behaviour.

Run: python3 ci/test_arggating.py [path/to/mcp-node]
Prints one PASS/FAIL line per case; exits nonzero on any failure.
"""
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time
import traceback

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'ci'))
import test_reverse as rev  # noqa: E402  reuse Proc/Env/pick_port helpers

BINARY = rev.BINARY
pick_port = rev.pick_port
base_env = rev.base_env
wait_until = rev.wait_until
check = rev.check


def start_node(tmp, token_file, policy_file, port, extra=None, env=None):
    e = base_env()
    e.update({
        'MCP_NODE_HOST': '127.0.0.1',
        'MCP_NODE_PORT': str(port),
        'MCP_NODE_SOCKET_TIMEOUT_S': '5',
        'MCP_NODE_TOKEN_FILE': str(token_file),
        'MCP_NODE_POLICY_FILE': str(policy_file),
    })
    e.update(extra or {})
    return rev.Proc(tmp, 'node', e)


def post(port, path, payload, token=None, timeout=15):
    import http.client
    body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=timeout)
    try:
        headers = {'Content-Type': 'application/json', 'Connection': 'close'}
        if token is not None:
            headers['X-Node-Token'] = token
        conn.request('POST', path, body=body, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        return resp.status, (json.loads(data) if data else None)
    finally:
        conn.close()


def tool(port, token, name, arguments=None, timeout=20):
    payload = {'jsonrpc': '2.0', 'id': 7, 'method': 'tools/call',
               'params': {'name': name, 'arguments': arguments or {}}}
    status, reply = post(port, '/mcp', payload, token, timeout=timeout)
    if status != 200 or not isinstance(reply, dict) or 'result' not in reply:
        raise AssertionError(('tool', name, status, reply))
    result = reply['result']
    return result.get('structuredContent') or json.loads(result['content'][0]['text'])


def write0600(path, content):
    p = Path(path)
    p.write_text(content)
    os.chmod(p, 0o600)


class Case:
    def __init__(self):
        self.temp = tempfile.TemporaryDirectory(prefix='arggating-')
        self.dir = Path(self.temp.name)
        self.port = pick_port()
        self.token_admin = secrets.token_hex(24)
        self.token_reader = secrets.token_hex(24)
        self.token_build = secrets.token_hex(24)
        write0600(self.dir / 'admin-token', self.token_admin + '\n')
        write0600(self.dir / 'reader-token', self.token_reader + '\n')
        write0600(self.dir / 'build-token', self.token_build + '\n')
        # Workspaces for the path rules.
        (self.dir / 'ws').mkdir()
        (self.dir / 'ws' / 'allow').mkdir()
        (self.dir / 'ws' / 'outside').mkdir()
        write0600(self.dir / 'ws' / 'allow' / 'readable.txt', 'inside\n')
        write0600(self.dir / 'ws' / 'outside' / 'secret.txt', 'secret\n')
        # Symlink escape: allow/esc -> ../outside
        os.symlink('..\\outside' if os.name == 'nt' else '../outside',
                   self.dir / 'ws' / 'allow' / 'esc')
        policy = {
            'version': 1,
            'tokens': [
                {
                    'file': str(self.dir / 'admin-token'),
                    'allow_all': True,
                },
                {
                    'file': str(self.dir / 'reader-token'),
                    'tools': ['sys_info', 'read_file', 'list_dir'],
                    'read_paths': [str(self.dir / 'ws' / 'allow')],
                    'read_deny': [str(self.dir / 'ws' / 'allow' / 'denybox')],
                },
                {
                    'file': str(self.dir / 'build-token'),
                    'tools': ['sys_info', 'exec', 'exec_start', 'exec_shell',
                              'exec_poll', 'exec_write', 'exec_kill',
                              'exec_close', 'exec_wait', 'exec_list',
                              'read_file', 'write_file', 'list_dir'],
                    'exec_argv0': ['sh', '/bin/sh', 'cat', 'touch'],
                    'exec_cwd': [str(self.dir / 'ws')],
                    'max_timeout_s': 10,
                    'read_paths': [str(self.dir / 'ws')],
                    'write_paths': [str(self.dir / 'ws' / 'allow')],
                    'write_max_mode': '0644',
                },
            ],
        }
        write0600(self.dir / 'policy.json', json.dumps(policy, indent=1))
        self.policy_file = self.dir / 'policy.json'
        self.audit_file = self.dir / 'audit.jsonl'
        self.key_file = self.dir / 'audit-key'
        write0600(self.key_file, secrets.token_hex(24))

    def start(self, extra=None):
        extra = dict(extra or {})
        extra.setdefault('MCP_NODE_AUDIT_FILE', str(self.audit_file))
        extra.setdefault('MCP_NODE_AUDIT_KEY_FILE', str(self.key_file))
        self.proc = start_node(self.dir, self.dir / 'admin-token',
                               self.policy_file, self.port, extra=extra)
        check(rev.wait_until(lambda: rev.port_open(self.port) or not self.proc.alive(), 10)
              and self.proc.alive(), 'node did not start: ' + self.proc.logs()[-2000:])
        return self.proc

    def close(self):
        try:
            self.proc.stop()
        except Exception:
            pass
        self.temp.cleanup()

    def audit_records(self):
        lines = self.audit_file.read_text().splitlines()
        return [json.loads(x) for x in lines if x.strip()]

    def wait_denies(self, timeout_s=10):
        """The audit ring flushes asynchronously; wait for the file."""
        deadline = time.monotonic() + timeout_s
        recs = []
        while time.monotonic() < deadline:
            try:
                recs = self.audit_records()
            except (OSError, json.JSONDecodeError):
                recs = []
            if any(r.get('event') == 'policy.deny' for r in recs):
                return recs
            time.sleep(0.1)
        return recs


def expect_deny(out, reason):
    check(out.get('error') == 'PolicyDenied',
          'expected PolicyDenied, got %r' % (out,))
    check(out.get('reason') == reason,
          'expected reason %r, got %r (out=%r)' % (reason, out.get('reason'), out))


def case_no_policy_default(tmp):
    """Without MCP_NODE_POLICY_FILE the node behaves exactly as before."""
    port = pick_port()
    token_file = tmp / 'plain-token'
    write0600(token_file, secrets.token_hex(16) + '\n')
    e = base_env()
    e.update({'MCP_NODE_HOST': '127.0.0.1', 'MCP_NODE_PORT': str(port),
              'MCP_NODE_SOCKET_TIMEOUT_S': '5',
              'MCP_NODE_TOKEN_FILE': str(token_file)})
    proc = rev.Proc(tmp, 'plain', e)
    try:
        check(rev.wait_until(lambda: rev.port_open(port) or not proc.alive(), 10)
              and proc.alive(), 'plain node did not start')
        out = tool(port, token_file.read_text().strip(), 'exec',
                   {'argv': ['echo', 'hi'], 'timeout': 5})
        check(out.get('ok') and out['stdout'] == 'hi\n', out)
    finally:
        proc.stop()


def case_reader_token(env):
    """Reader token: reads inside, denied outside, traversal, symlink,
    write denied, exec denied-without-execution."""
    port = env.port
    allow = env.dir / 'ws' / 'allow'
    outside = env.dir / 'ws' / 'outside'
    # read inside: ok
    out = tool(port, env.token_reader, 'read_file', {'path': str(allow / 'readable.txt')})
    check(out.get('ok') and out['content'] == 'inside\n', out)
    # list_dir inside: ok
    out = tool(port, env.token_reader, 'list_dir', {'path': str(allow)})
    check(out.get('ok'), out)
    names = [e['name'] for e in out['items']]
    check('readable.txt' in names, names)
    # read outside: denied
    out = tool(port, env.token_reader, 'read_file', {'path': str(outside / 'secret.txt')})
    expect_deny(out, 'path_not_allowed')
    # traversal from inside: denied
    out = tool(port, env.token_reader, 'read_file',
               {'path': str(allow / '..' / 'outside' / 'secret.txt')})
    expect_deny(out, 'path_not_allowed')
    # symlink escape: denied (the gate sees the realpath target)
    out = tool(port, env.token_reader, 'read_file', {'path': str(allow / 'esc' / 'secret.txt')})
    expect_deny(out, 'path_not_allowed')
    # adversarial: symlink + '..' smuggling — the kernel would open the
    # target OUTSIDE the tree; the canonicaliser resolves in kernel order
    # (realpath first, '..' collapse second) so this denies too
    out = tool(port, env.token_reader, 'read_file',
               {'path': str(allow / 'esc' / '..' / 'outside' / 'secret.txt')})
    expect_deny(out, 'path_not_allowed')
    out = tool(port, env.token_reader, 'read_file',
               {'path': str(allow / 'esc' / '..' / 'secret.txt')})
    expect_deny(out, 'path_not_allowed')
    # write: denied at tool level
    out = tool(port, env.token_reader, 'write_file',
               {'path': str(allow / 'nope.txt'), 'content_b64': 'aGk='})
    expect_deny(out, 'tool_not_allowed')
    check(not (allow / 'nope.txt').exists(), 'denied write_file created the file')
    # exec: denied at tool level, and NEVER executes
    marker = env.dir / 'ws' / 'allow' / 'marker-should-not-exist.txt'
    out = tool(port, env.token_reader, 'exec',
               {'argv': ['touch', str(marker)], 'timeout': 5})
    expect_deny(out, 'tool_not_allowed')
    check(not marker.exists(), 'denied exec ran anyway (marker created)')
    # sys_info: allowed (read-only connectivity check; no 'ok' field in
    # its response shape)
    out = tool(port, env.token_reader, 'sys_info')
    check('node' in out and 'mem' in out, out)


def case_build_token(env):
    """Build token: allowed argv0 runs, disallowed denied without execution,
    cwd rule, timeout cap, write path/mode rules."""
    port = env.port
    allow = env.dir / 'ws' / 'allow'
    ws = env.dir / 'ws'
    # allowed bare argv0: runs
    out = tool(port, env.token_build, 'exec',
               {'argv': ['sh', '-c', 'echo build-ok'], 'timeout': 5})
    check(out.get('ok') and out['stdout'] == 'build-ok\n', out)
    # disallowed argv0: denied, never executes
    marker = allow / 'denied-should-not-exist.txt'
    out = tool(port, env.token_build, 'exec',
               {'argv': ['rm', str(marker)]})
    expect_deny(out, 'argv0_not_allowed')
    # absolute disallowed: denied
    out = tool(port, env.token_build, 'exec',
               {'argv': ['/bin/rm', '-f', str(marker)]})
    expect_deny(out, 'argv0_not_allowed')
    # cross-boundary: bare 'sh' allowed but '/bin/sh' via argv[0] mismatch...
    # '/bin/sh' IS in the allowlist; 'sh' and '/bin/sh' are both listed.
    # A bare name that is NOT allowed: 'echo' -> denied.
    out = tool(port, env.token_build, 'exec', {'argv': ['echo', 'x']})
    expect_deny(out, 'argv0_not_allowed')
    # cwd outside: denied
    out = tool(port, env.token_build, 'exec',
               {'argv': ['sh', '-c', 'true'], 'cwd': '/etc', 'timeout': 5})
    expect_deny(out, 'cwd_not_allowed')
    # timeout over cap: denied
    out = tool(port, env.token_build, 'exec',
               {'argv': ['sh', '-c', 'true'], 'timeout': 600})
    expect_deny(out, 'timeout_exceeds_cap')
    # cwd inside: allowed
    out = tool(port, env.token_build, 'exec',
               {'argv': ['sh', '-c', 'pwd'], 'cwd': str(ws), 'timeout': 5})
    check(out.get('ok'), out)
    # write inside allow tree: ok at mode 0644
    target = allow / 'written.txt'
    out = tool(port, env.token_build, 'write_file',
               {'path': str(target), 'content_b64': 'd3JpdHRlbg==', 'mode': 420})
    check(out.get('ok') and target.exists(), out)
    # write outside allow (but inside read tree): denied
    out = tool(port, env.token_build, 'write_file',
               {'path': str(ws / 'no.txt'), 'content_b64': 'aGk='})
    expect_deny(out, 'path_not_allowed')
    # mode over cap: denied (setuid-ish 4755 > 0644)
    out = tool(port, env.token_build, 'write_file',
               {'path': str(allow / 'setuid.txt'), 'content_b64': 'aGk=',
                'mode': 2533})
    expect_deny(out, 'write_mode_exceeds_cap')
    check(not (allow / 'setuid.txt').exists(), 'denied write created the file')
    # exec_shell: explicit sh is in the allowlist -> allowed and runs.
    # (The platform default is bash; the policy gates the shell actually
    # spawned, so an unspecified shell would be argv0-denied here.)
    out = tool(port, env.token_build, 'exec_shell',
               {'script': 'echo shell-ok', 'shell': 'sh', 'timeout': 5})
    check(out.get('ok') and out['stdout'] == 'shell-ok\n', out)
    # exec_shell with disallowed shell: denied
    out = tool(port, env.token_build, 'exec_shell', {'script': 'x', 'shell': 'zsh'})
    expect_deny(out, 'argv0_not_allowed')
    # adversarial: integral-float mode (setuid value) is checked, not skipped
    out = tool(port, env.token_build, 'write_file',
               {'path': str(allow / 'floatsetuid.txt'), 'content_b64': 'aGk=',
                'mode': 2533.0})
    expect_deny(out, 'write_mode_exceeds_cap')
    check(not (allow / 'floatsetuid.txt').exists(), 'float-mode denial created the file')
    # adversarial: negative mode must not crash the node (it survived the
    # call above if we are here) and is denied
    out = tool(port, env.token_build, 'write_file',
               {'path': str(allow / 'neg.txt'), 'content_b64': 'aGk=', 'mode': -1})
    expect_deny(out, 'write_mode_exceeds_cap')
    check(not (allow / 'neg.txt').exists(), 'negative-mode denial created the file')
    # adversarial: wrong-type mode (string) denied
    out = tool(port, env.token_build, 'write_file',
               {'path': str(allow / 'strmode.txt'), 'content_b64': 'aGk=',
                'mode': '0644'})
    expect_deny(out, 'bad_argument_type')
    # adversarial: null timeout counts as the 120s default -> over cap
    out = tool(port, env.token_build, 'exec',
               {'argv': ['sh', '-c', 'true'], 'timeout': None})
    expect_deny(out, 'timeout_exceeds_cap')
    # adversarial: non-string shell never crashes and is denied
    out = tool(port, env.token_build, 'exec_shell', {'script': 'x', 'shell': 123})
    expect_deny(out, 'bad_argument_type')
    # node still alive after all adversarial shapes
    out = tool(port, env.token_reader, 'sys_info')
    check('node' in out, out)


def case_session_ownership(env):
    """Sessions are token-owned: build starts, reader cannot drive it."""
    port = env.port
    # An explicit timeout at/below the cap: without one the tool default
    # (120s) exceeds this token's cap and the call is refused.
    out = tool(port, env.token_build, 'exec_start',
               {'argv': ['sh', '-c', 'sleep 30'], 'timeout': 10})
    check(out.get('ok') and out.get('session_id'), out)
    sid = out['session_id']
    # owner can poll and close
    out = tool(port, env.token_build, 'exec_poll', {'session_id': sid})
    check(out.get('ok'), out)
    # reader token: session tools not in its allowlist -> tool_not_allowed
    out = tool(port, env.token_reader, 'exec_poll', {'session_id': sid})
    expect_deny(out, 'tool_not_allowed')
    # admin token: sessions owned by build token -> SessionNotOwned error
    # (admin is allow_all, so the OWNER check still applies to sessions
    #  started by other tokens while a policy is active)
    out = tool(port, env.token_admin, 'exec_poll', {'session_id': sid})
    check(out.get('ok') is False and out.get('error') == 'SessionNotOwned', out)
    # build lists only its own; admin list shows none of build's sessions
    out = tool(port, env.token_build, 'exec_list')
    check(any(s['session_id'] == sid for s in out.get('sessions', [])), out)
    out = tool(port, env.token_admin, 'exec_list')
    check(not any(s['session_id'] == sid for s in out.get('sessions', [])), out)
    # close by owner
    out = tool(port, env.token_build, 'exec_close', {'session_id': sid})
    check(out.get('ok'), out)


def case_audit_records(env):
    """policy.deny lines exist with reasons and no token values."""
    recs = env.wait_denies()
    denies = [r for r in recs if r.get('event') == 'policy.deny']
    check(denies, 'no policy.deny records in the audit log')
    reasons = {r.get('reason') for r in denies}
    for want in ('tool_not_allowed', 'argv0_not_allowed', 'path_not_allowed',
                 'cwd_not_allowed', 'timeout_exceeds_cap',
                 'write_mode_exceeds_cap'):
        check(want in reasons, 'missing policy.deny reason %r in %r' % (want, reasons))
    blob = env.audit_file.read_text()
    check(env.token_reader not in blob, 'reader token value leaked into audit log')
    check(env.token_build not in blob, 'build token value leaked into audit log')
    check(env.token_admin not in blob, 'admin token value leaked into audit log')
    # every deny carries a token fingerprint (16 hex) and a tool
    for r in denies:
        check(len(r.get('token', '')) == 16, r)
        check(r.get('tool'), r)


def case_wrong_token(env):
    """An unknown token gets the classic 401 body, no oracle."""
    status, reply = post(env.port, '/mcp',
                         {'jsonrpc': '2.0', 'id': 1, 'method': 'ping'})
    check(status == 401 and reply and reply.get('error') == 'unauthorized',
          (status, reply))
    status2, _ = post(env.port, '/mcp',
                      {'jsonrpc': '2.0', 'id': 1, 'method': 'ping'},
                      token='not-a-real-token')
    check(status2 == 401 and status == status2, (status, status2))


def case_startup_failures(tmp):
    """Policy misuse fails startup with a named error."""
    def try_start(policy_obj, token_file, extra=None, tag='x'):
        port = pick_port()
        pf = tmp / ('policy-%s.json' % tag)
        write0600(pf, json.dumps(policy_obj))
        e = base_env()
        e.update({'MCP_NODE_HOST': '127.0.0.1', 'MCP_NODE_PORT': str(port),
                  'MCP_NODE_SOCKET_TIMEOUT_S': '5',
                  'MCP_NODE_TOKEN_FILE': str(token_file),
                  'MCP_NODE_POLICY_FILE': str(pf)})
        e.update(extra or {})
        proc = rev.Proc(tmp, tag, e)
        ok = rev.wait_until(lambda: (not proc.alive()) or rev.port_open(port), 8)
        alive = proc.alive()
        logs = proc.logs()
        proc.stop()
        return alive, logs, ok

    tok = tmp / 'st-token'
    write0600(tok, secrets.token_hex(16) + '\n')
    # 1. classic token not covered by any entry -> startup error
    other = tmp / 'st-other'
    write0600(other, secrets.token_hex(16) + '\n')
    alive, logs, _ = try_start(
        {'version': 1, 'tokens': [{'file': str(other), 'allow_all': True}]},
        tok, tag='uncovered')
    check(not alive, 'node started with uncovered classic token')
    check('matches no policy entry' in logs, logs[-800:])
    # 2. node mode + policy -> startup error
    secret = tmp / 'st-secret'
    write0600(secret, secrets.token_hex(16))
    port = pick_port()
    pf = tmp / 'policy-nodemode.json'
    write0600(pf, json.dumps({'version': 1, 'tokens': [{'file': str(tok), 'allow_all': True}]}))
    e = base_env()
    e.update({'MCP_NODE_NAME': 'n', 'MCP_NODE_CONNECT': '127.0.0.1:1',
              'MCP_NODE_CONNECT_SECRET_FILE': str(secret),
              'MCP_NODE_TOKEN_FILE': str(tok),
              'MCP_NODE_POLICY_FILE': str(pf)})
    proc = rev.Proc(tmp, 'nodemode', e)
    rev.wait_until(lambda: not proc.alive(), 8)
    check(not proc.alive(), 'node mode started with a policy file')
    check('cannot be combined with node/stdio mode' in proc.logs(), proc.logs()[-800:])
    proc.stop()
    # 3. insecure + policy -> startup error
    alive, logs, _ = try_start(
        {'version': 1, 'tokens': [{'file': str(tok), 'allow_all': True}]},
        tok, extra={'MCP_NODE_INSECURE': '1'}, tag='insecure')
    # INSECURE is refused outright next to a policy file, even when the
    # classic token is valid and the flag would be inert: the strictness is
    # the point (docs/arg-gating.md).
    check(not alive, 'insecure+policy started despite the strict rule')
    check('MCP_NODE_INSECURE' in logs, logs[-800:])
    tok_empty = tmp / 'st-empty'
    write0600(tok_empty, '\n')
    alive2, logs2, _ = try_start(
        {'version': 1, 'tokens': [{'file': str(tok), 'allow_all': True}]},
        tok_empty, extra={'MCP_NODE_INSECURE': '1'}, tag='insecure-empty')
    check(not alive2, 'insecure+policy started')
    check('MCP_NODE_INSECURE' in logs2, logs2[-800:])
    # 4. 0644 policy file -> startup error
    port = pick_port()
    pf = tmp / 'policy-loose.json'
    pf.write_text(json.dumps({'version': 1, 'tokens': [{'file': str(tok), 'allow_all': True}]}))
    os.chmod(pf, 0o644)
    e = base_env()
    e.update({'MCP_NODE_HOST': '127.0.0.1', 'MCP_NODE_PORT': str(port),
              'MCP_NODE_SOCKET_TIMEOUT_S': '5',
              'MCP_NODE_TOKEN_FILE': str(tok),
              'MCP_NODE_POLICY_FILE': str(pf)})
    proc = rev.Proc(tmp, 'loose', e)
    rev.wait_until(lambda: not proc.alive(), 8)
    check(not proc.alive(), 'node started with a 0644 policy file')
    check('0600' in proc.logs(), proc.logs()[-800:])
    proc.stop()
    # 5. unknown key -> startup error
    alive, logs, _ = try_start(
        {'version': 1, 'tokens': [{'file': str(tok), 'allow_all': True}],
         'oops': 1}, tok, tag='unknownkey')
    check(not alive, 'node started with an unknown policy key')
    check('unknown top-level key' in logs, logs[-800:])
    # 6. hub mode + policy -> startup error (relay route runs on nodes
    #    with no policy; a hub-side policy would be a false sense of
    #    security)
    pf = tmp / 'policy-hubmode.json'
    write0600(pf, json.dumps({'version': 1, 'tokens': [{'file': str(tok), 'allow_all': True}]}))
    e = base_env()
    e.update({'MCP_NODE_HUB_LISTEN': '127.0.0.1:1',
              'MCP_NODE_HUB_SECRET_FILE': str(tmp / 'hub-secret'),
              'MCP_NODE_TOKEN_FILE': str(tok),
              'MCP_NODE_POLICY_FILE': str(pf)})
    write0600(tmp / 'hub-secret', secrets.token_hex(16))
    proc = rev.Proc(tmp, 'hubmode', e)
    rev.wait_until(lambda: not proc.alive(), 8)
    check(not proc.alive(), 'hub started with a policy file')
    check('hub mode' in proc.logs(), proc.logs()[-800:])
    proc.stop()


def main():
    print('arg-gating e2e: binary %s' % BINARY)
    failures = []
    tmpdir = tempfile.TemporaryDirectory(prefix='arggating-root-')
    tmp = Path(tmpdir.name)
    try:
        def run(name, fn, *args):
            try:
                fn(*args)
                print('PASS %s' % name)
            except Exception as exc:  # noqa: BLE001
                failures.append(name)
                print('FAIL %s: %s' % (name, exc))
                traceback.print_exc()
        run('no-policy default', case_no_policy_default, tmp)
        env = Case()
        try:
            env.start()
            run('reader token', case_reader_token, env)
            run('build token', case_build_token, env)
            run('session ownership', case_session_ownership, env)
            run('audit records', case_audit_records, env)
            run('wrong token', case_wrong_token, env)
        finally:
            env.close()
        run('startup failures', case_startup_failures, tmp)
    finally:
        tmpdir.cleanup()
    if failures:
        print('FAILURES: %d (%s)' % (len(failures), ', '.join(failures)))
        return 1
    print('ALL PASS')
    return 0


if __name__ == '__main__':
    sys.exit(main())
