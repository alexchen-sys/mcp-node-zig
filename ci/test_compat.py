#!/usr/bin/env python3
"""v0 compatibility golden-fixture harness for mcp-node.

Replays every case from ci/fixtures/compat/*.json against a real daemon,
black-box over raw sockets, and deep-matches each JSON-RPC response against
the fixture's matcher. One fresh daemon per fixture file (isolated session
and cwd state); cases inside a file run in order and may capture response
values into variables ($name) for later requests.

Fixture format and the matcher language (typed wildcards {"*int"},
{"*str"}, {"*any"}, subset matching, captures) are documented in
ci/fixtures/compat/README.md.

Run: python3 ci/test_compat.py [path/to/mcp-node] [--fixtures-dir DIR]
Default binary: zig-out/bin/mcp-node (.exe on Windows), resolved against the
repo root (parent of this file's directory). Default fixtures dir:
ci/fixtures/compat. Exits nonzero if any case fails or any fixture file is
malformed. No fixed ports, no blind sleeps for state: daemon readiness is a
bounded poll on a connectable socket.
"""
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent

WILDCARDS = ('*int', '*str', '*any')


def parse_argv(argv):
    """Binary path: first bare argument. --fixtures-dir VALUE / =VALUE form."""
    binary = None
    fixtures_dir = ROOT / 'ci' / 'fixtures' / 'compat'
    index = 1
    while index < len(argv):
        arg = argv[index]
        if arg == '--fixtures-dir':
            if index + 1 >= len(argv):
                raise SystemExit('--fixtures-dir requires a value')
            fixtures_dir = Path(argv[index + 1])
            index += 2
            continue
        if arg.startswith('--fixtures-dir='):
            fixtures_dir = Path(arg.split('=', 1)[1])
            index += 1
            continue
        if arg.startswith('-'):
            raise SystemExit('unknown option: %r' % arg)
        if binary is None:
            binary = arg
            index += 1
            continue
        raise SystemExit('unexpected extra argument: %r' % arg)
    binary = Path(binary) if binary else (ROOT / 'zig-out' / 'bin' /
                                          ('mcp-node.exe' if os.name == 'nt' else 'mcp-node'))
    return binary.resolve(), fixtures_dir


def free_port():
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        return probe.getsockname()[1]


def read_http_response(sock, deadline_s=15.0):
    """Read one HTTP/1.1 response; returns (status, body)."""
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


class Node:
    """One isolated daemon per fixture file: dynamic port, random token, temp cwd."""

    def __init__(self):
        self.temp = tempfile.TemporaryDirectory(prefix='mcp-compat-')
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
        try:
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

    def rpc(self, payload):
        """Send one JSON-RPC request over a fresh connection; (status, parsed reply)."""
        body = json.dumps(payload).encode()
        head = ('\r\n'.join(['POST /mcp HTTP/1.1',
                             'Host: 127.0.0.1:' + str(self.port),
                             'Content-Length: ' + str(len(body)),
                             'Content-Type: application/json',
                             'X-Node-Token: ' + self.secret]) + '\r\n\r\n').encode()
        sock = socket.create_connection(('127.0.0.1', self.port), timeout=30)
        try:
            sock.sendall(head + body)
            status, data = read_http_response(sock)
        finally:
            sock.close()
        return status, json.loads(data) if data else None

    def call_tool(self, name, arguments):
        """Fire-and-forget tool call used only for teardown."""
        try:
            self.rpc({'jsonrpc': '2.0', 'id': 0, 'method': 'tools/call',
                      'params': {'name': name, 'arguments': arguments or {}}})
        except Exception:
            pass

    def close(self):
        if self.process.poll() is None:
            try:
                status, reply = self.rpc({'jsonrpc': '2.0', 'id': 0, 'method': 'tools/call',
                                          'params': {'name': 'exec_list', 'arguments': {}}})
                for session in ((reply or {}).get('result', {})
                                .get('structuredContent', {}).get('sessions', [])):
                    self.call_tool('exec_close', {'session_id': session['session_id']})
            except Exception:
                pass
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.log.close()
        self.temp.cleanup()


# ---- matcher ---------------------------------------------------------------

class Mismatch(Exception):
    pass


def _fail(path, message, expect, actual):
    raise Mismatch('%s: %s\n    expect: %s\n    actual: %s'
                   % (path, message, _show(expect), _show(actual)))


def _show(value):
    text = json.dumps(value, sort_keys=True, ensure_ascii=False)
    return text if len(text) <= 300 else text[:297] + '...'


def matches(actual, expect, path, subset):
    """Deep match with typed wildcards. Exact mode: key sets must be equal;
    subset mode: expect keys must be present, extra actual keys are allowed."""
    if isinstance(expect, dict) and len(expect) == 1 and next(iter(expect)) in WILDCARDS:
        kind = next(iter(expect))
        if kind == '*int':
            if not isinstance(actual, int) or isinstance(actual, bool):
                _fail(path, 'wildcard *int wants an integer, got %s' % type(actual).__name__,
                      expect, actual)
        elif kind == '*str':
            if not isinstance(actual, str):
                _fail(path, 'wildcard *str wants a string, got %s' % type(actual).__name__,
                      expect, actual)
        return
    if isinstance(expect, dict):
        if not isinstance(actual, dict):
            _fail(path, 'want object, got %s' % type(actual).__name__, expect, actual)
        for key, sub in expect.items():
            if key not in actual:
                _fail(path, 'missing key %r' % key, expect, actual)
            matches(actual[key], sub, path + '.' + key, subset)
        if not subset:
            extra = sorted(set(actual) - set(expect))
            if extra:
                _fail(path, 'unexpected extra keys %r (exact match mode)' % extra, expect, actual)
        return
    if isinstance(expect, list):
        if not isinstance(actual, list):
            _fail(path, 'want array, got %s' % type(actual).__name__, expect, actual)
        if len(actual) != len(expect):
            _fail(path, 'array length %d != expected %d' % (len(actual), len(expect)), expect, actual)
        for i, sub in enumerate(expect):
            matches(actual[i], sub, '%s[%d]' % (path, i), subset)
        return
    if isinstance(expect, bool) or isinstance(actual, bool):
        if not (isinstance(expect, bool) and isinstance(actual, bool)) or actual != expect:
            _fail(path, 'bool mismatch', expect, actual)
        return
    if isinstance(expect, (int, float)) or isinstance(actual, (int, float)):
        if type(actual) is not type(expect) or actual != expect:
            _fail(path, 'number mismatch', expect, actual)
        return
    if actual != expect:
        _fail(path, 'value mismatch', expect, actual)


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


# ---- fixture runner ---------------------------------------------------------

def run_case(node, case, ctx):
    """Returns None on pass, failure string on mismatch/transport error."""
    name = case['name']
    request = substitute(case['request'], ctx)
    try:
        status, response = node.rpc(request)
    except Exception as exc:
        return '%s: transport error: %s: %s' % (name, type(exc).__name__, exc)
    expect = case.get('expect') or {}
    if 'status' not in expect:
        return '%s: fixture error: expect.status is required' % name
    if status != expect['status']:
        return ('%s: status %d != expected %d; reply: %s'
                % (name, status, expect['status'], _show(response)))
    if 'response' in expect:
        want = substitute(expect['response'], ctx)
        subset = expect.get('match') == 'subset'
        try:
            matches(response, want, 'response', subset)
        except Mismatch as exc:
            return '%s: mismatch: %s' % (name, exc)
    for key, dotted in (expect.get('capture') or {}).items():
        try:
            ctx[key] = dig(response, dotted)
        except (KeyError, IndexError, TypeError, ValueError):
            return '%s: fixture error: capture %r cannot resolve %r in response' % (name, key, dotted)
    return None


def load_fixture(path):
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
    except ValueError as exc:
        raise ValueError('invalid JSON: %s' % exc)
    if not isinstance(data, dict) or not isinstance(data.get('cases'), list) or not data['cases']:
        raise ValueError('fixture must be an object with a non-empty "cases" array')
    for case in data['cases']:
        if not isinstance(case, dict):
            raise ValueError('each case must be an object')
        for field in ('name', 'request', 'expect'):
            if field not in case:
                raise ValueError('case is missing %r' % field)
        if not isinstance(case['request'], dict) or not isinstance(case['expect'], dict):
            raise ValueError('"request" and "expect" must be objects')
    return data


KNOWN_PLATFORMS = ('linux', 'macos', 'windows', 'posix')


def platform_tokens():
    """Tokens for the running platform: posix covers linux+macos."""
    if sys.platform == 'darwin':
        return {'macos', 'posix'}
    if sys.platform == 'win32':
        return {'windows'}
    if sys.platform.startswith('linux'):
        return {'linux', 'posix'}
    return {sys.platform}


def platform_skip(fixture):
    """Skip reason string if the fixture is out of scope on this platform,
    else None. Malformed scope metadata raises ValueError (hard fixture
    error) so a platform skip can never happen silently."""
    if 'platforms' not in fixture:
        return None
    scopes = fixture['platforms']
    if (not isinstance(scopes, list) or not scopes
            or any(not isinstance(s, str) for s in scopes)):
        raise ValueError('"platforms" must be a non-empty array of strings')
    unknown = sorted(set(scopes) - set(KNOWN_PLATFORMS))
    if unknown:
        raise ValueError('"platforms" has unknown tokens %r (known: %s)'
                         % (unknown, ', '.join(KNOWN_PLATFORMS)))
    if platform_tokens() & set(scopes):
        return None
    reason = fixture.get('platforms_reason')
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError('platform-scoped fixture requires a non-empty "platforms_reason"')
    return reason


def main():
    global BINARY
    BINARY, fixtures_dir = parse_argv(sys.argv)
    if not BINARY.exists():
        print('FATAL: binary not found: %s' % BINARY, file=sys.stderr)
        return 2
    paths = sorted(fixtures_dir.glob('*.json'))
    if not paths:
        print('FATAL: no fixture files in %s' % fixtures_dir, file=sys.stderr)
        return 2
    total = passed = failed = 0
    file_failures = []
    skipped_files = []
    for path in paths:
        try:
            fixture = load_fixture(path)
        except ValueError as exc:
            print('FAIL %s: fixture error: %s' % (path.name, exc))
            file_failures.append(path.name)
            failed += 1
            continue
        try:
            skip_reason = platform_skip(fixture)
        except ValueError as exc:
            print('FAIL %s: fixture error: %s' % (path.name, exc))
            file_failures.append(path.name)
            failed += 1
            continue
        if skip_reason is not None:
            skipped_files.append((path.name, skip_reason))
            print('SKIP %s: %s' % (path.name, skip_reason))
            continue
        node = Node()
        ctx = {}  # captures flow between the cases of one file
        try:
            for case in fixture['cases']:
                total += 1
                outcome = run_case(node, case, ctx)
                if outcome is None:
                    passed += 1
                    print('PASS %s/%s (status %s)' % (path.name, case['name'],
                                                      case['expect']['status']))
                else:
                    failed += 1
                    print('FAIL ' + outcome)
                    file_failures.append(path.name)
        finally:
            node.close()
    print('COMPAT SUMMARY files=%d cases=%d passed=%d failed=%d skipped_files=%d'
          % (len(paths), total, passed, failed, len(skipped_files)))
    for name, reason in skipped_files:
        print('SKIPPED FILE: %s (%s)' % (name, reason))
    if file_failures:
        print('FAILED FILES: %s' % ', '.join(sorted(set(file_failures))))
    return 0 if failed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
