#!/usr/bin/env python3
"""Cross-platform end-to-end check of the built-in TLS hub.

Needs a binary built with -Dtls-server and the openssl CLI. Runs on Linux,
macOS and Windows: one hub serving TLS 1.3 on the node-link port, one node
dialing it with certificate verification, then the MCP surface through the
relay. Also checks that a plaintext node and a node trusting another CA are
refused while the hub keeps serving.

Run: python3 ci/smoke_tls.py [path/to/mcp-node]
Set MCP_SMOKE_TLS_REQUIRE=1 to turn a missing openssl or a flagless binary
into a failure instead of a skip (CI does this).
"""
import os
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_reverse as tr  # noqa: E402  (shares Env, cert helpers, TLS hub start)


def fail_or_skip(why):
    if os.environ.get('MCP_SMOKE_TLS_REQUIRE') == '1':
        print('FAIL built-in TLS smoke: %s' % why)
        return 1
    print('SKIP built-in TLS smoke: %s' % why)
    return 0


def run(env):
    d = str(env.dir)
    tr._make_ca(d, 'good')
    tr._make_ca(d, 'other')
    tr._make_server_cert(d, 'good')
    hub = tr._start_tls_hub(env)
    target = 'localhost:%d' % env.link_port

    env.start_node('tlsnode', target=target, extra={
        'MCP_NODE_CONNECT_TLS': '1', 'MCP_NODE_CONNECT_CA_FILE': str(env.dir / 'good-ca.pem')})
    tr.check(env.wait_node('tlsnode', 20), 'TLS node never appeared: ' + hub.logs()[-800:])

    status, reply = env.rpc('tlsnode', 'tools/list', {})
    tools = reply.get('result', {}).get('tools', []) if isinstance(reply, dict) else []
    tr.check(status == 200 and len(tools) == 13, (status, len(tools)))

    # The interpreter running this script exists on every platform; echo does not.
    out = env.tool('tlsnode', 'exec', {
        'argv': [sys.executable, '-c', 'print("over-builtin-tls")'], 'timeout': 20}, timeout=40)
    tr.check(out.get('ok') and out.get('stdout', '').strip() == 'over-builtin-tls', out)

    env.start_node('plain', target=target)
    tr.check(not env.wait_node('plain', 3), 'plaintext node got in: %r' % env.nodes())

    bad = env.start_node('badca', target=target, extra={
        'MCP_NODE_CONNECT_TLS': '1', 'MCP_NODE_CONNECT_CA_FILE': str(env.dir / 'other-ca.pem')})
    tr.check(tr.wait_until(lambda: 'TLS handshake failed' in bad.logs(), 15, 0.1),
             'untrusted CA was not rejected: ' + bad.logs()[-800:])
    tr.check('badca' not in env.nodes(), env.nodes())

    tr.check(hub.alive(), 'hub died: ' + hub.logs()[-800:])
    tr.check('tlsnode' in env.nodes(), 'good node dropped after refused peers')


def main():
    if not tr.BINARY.exists():
        print('binary not found: %s' % tr.BINARY)
        return 2
    if shutil.which('openssl') is None:
        return fail_or_skip('openssl CLI not found')
    env = tr.Env()
    try:
        run(env)
    except tr.SkipCase as why:
        return fail_or_skip(str(why))
    except Exception:
        import traceback
        traceback.print_exc()
        for proc in env.procs:
            print('--- %s log tail ---' % proc.log_path.name)
            print(proc.logs()[-1500:])
        print('FAIL built-in TLS smoke')
        return 1
    finally:
        env.close()
    print('PASS built-in TLS smoke (%s)' % sys.platform)
    return 0


if __name__ == '__main__':
    sys.exit(main())
