#!/usr/bin/env python3
"""Deterministic seeded HTTP/1.1 parser fuzzer for mcp-node.

Corpus classes: request smuggling (duplicate / conflicting Content-Length,
Content-Length + Transfer-Encoding), framing (bare LF / bare CR line
terminators), truncation (body short of Content-Length, oversized
Content-Length with client close or hold), and pipelining (two valid
requests, valid + malformed). Plus seeded PRNG mutations (byte flips and
truncations) of the canonical valid request head.

Conventions copied from ci/test_regressions.py: self-contained runner,
raw sockets, dynamic port, daemon spawned via MCP_NODE_TOKEN_FILE env,
bounded polls for every wait, argv[1] (without a leading '-') is the path
to the mcp-node binary (default zig-out/bin/mcp-node resolved against the
repo root).

Determinism: the canonical corpus stores literal bytes. Mutation cases
are produced by an LCG seeded from --seed (default 20261002) applied to
the canonical request head; with the default seed the generated stream is
verified byte-for-byte against the frozen ops in mutations.json. Same
seed => identical case stream (prove with two --list runs and cmp).
A non-default seed runs exploration mode: expectations relax to
"well-formed resolution within the allowed status set or clean close,
bounded time, daemon healthy afterwards".

Usage:
  python3 ci/fuzz_http.py [path/to/mcp-node] [--seed N] [--case ID]
      [--corpus-dir DIR] [--list] [--probe]
"""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
BINARY = Path(sys.argv.pop(1) if len(sys.argv) > 1 and not sys.argv[1].startswith('-')
              else ROOT / 'zig-out' / 'bin' / ('mcp-node.exe' if os.name == 'nt' else 'mcp-node')).resolve()

DEFAULT_SEED = 20261002
DEFAULT_CORPUS = ROOT / 'ci' / 'fixtures' / 'fuzz'
N_FLIPS = 48
N_TRUNCATIONS = 16
FUZZ_TOKEN = 'fuzzcafe20261002c70c323'
HOST_LINE = '127.0.0.1:65535'  # fake port; matches default allowed-hosts wildcard
ALLOWED_MUTATION_STATUS = {200, 202, 400, 401, 403, 404, 405, 408, 413, 415, 417, 421, 431}
PEEK_S = 0.5


class CorpusError(RuntimeError):
    pass


class Lcg:
    """Deterministic 64-bit LCG, PCG-style high-half output. Own arithmetic
    instead of random.Random so the case stream cannot drift with the
    Python version (randrange has no cross-version stability guarantee)."""
    MUL = 6364136223846793005
    ADD = 1442695040888963407

    def __init__(self, seed):
        self.state = (seed ^ 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
        if self.state == 0:
            self.state = 0x853C49E6748FEA9B

    def next_u32(self):
        self.state = (self.state * Lcg.MUL + Lcg.ADD) & 0xFFFFFFFFFFFFFFFF
        return self.state >> 32

    def below(self, n):
        return self.next_u32() % n


def generate_mutation_ops(seed, head_len):
    """Seeded mutation stream over the canonical head: N_FLIPS xor-flips
    (mask 1..255, byte always changes) then N_TRUNCATIONS cut points."""
    rng = Lcg(seed)
    ops = []
    for i in range(N_FLIPS):
        ops.append({'id': 'mut-flip-%03d' % (i + 1), 'op': 'flip',
                    'pos': rng.below(head_len), 'mask': 1 + rng.below(255)})
    for i in range(N_TRUNCATIONS):
        ops.append({'id': 'mut-trunc-%03d' % (i + 1), 'op': 'truncate',
                    'pos': rng.below(head_len)})
    return ops


def apply_op(head, op):
    if op['op'] == 'flip':
        b = bytearray(head)
        b[op['pos']] ^= op['mask']
        return bytes(b)
    if op['op'] == 'truncate':
        return head[:op['pos']]
    raise CorpusError('unknown op %r' % op['op'])


def load_corpus(corpus_dir, seed):
    """Resolve the full ordered case list: canonical cases from
    canonical.json, then mutation cases derived from the base case head."""
    corpus_dir = Path(corpus_dir)
    cases = {}
    order = []
    canon = json.loads((corpus_dir / 'canonical.json').read_text(encoding='utf-8'))
    for entry in canon['cases']:
        c = dict(entry)
        c['bytes'] = c['send'].encode('latin-1')
        cases[c['id']] = c
        order.append(c['id'])
    mut = json.loads((corpus_dir / 'mutations.json').read_text(encoding='utf-8'))
    base = cases.get(mut['base_case'])
    if base is None:
        raise CorpusError('mutations.json base_case %r not in canonical.json' % mut['base_case'])
    stream = base['bytes']
    head_end = stream.find(b'\r\n\r\n')
    if head_end < 0:
        raise CorpusError('base case %r has no head terminator' % mut['base_case'])
    head_end += 4
    head, body = stream[:head_end], stream[head_end:]
    ops = generate_mutation_ops(seed, len(head))
    frozen = mut['ops']
    if seed == mut['seed']:
        # Integrity: the frozen corpus must be exactly what the LCG emits.
        if len(ops) != len(frozen):
            raise CorpusError('mutation stream length mismatch: %d generated vs %d frozen'
                              % (len(ops), len(frozen)))
        for gen, frz in zip(ops, frozen):
            if (gen['id'] != frz['id'] or gen['op'] != frz['op']
                    or gen['pos'] != frz['pos'] or gen.get('mask') != frz.get('mask')):
                raise CorpusError('mutation stream diverges from frozen corpus at %s'
                                  ' (generated %r vs frozen %r)' % (gen['id'], gen, frz))
        expected_source = frozen
    else:
        expected_source = [None] * len(ops)
    for op, frz in zip(ops, expected_source):
        expect = None
        if frz is not None and frz.get('expected'):
            expect = frz['expected']
        if expect is None:
            expect = {'exploration': True}
        desc = ('seeded %s at byte %d%s of the canonical head (head_len=%d)'
                % (op['op'], op['pos'],
                   (' mask=0x%02x' % op['mask']) if op['op'] == 'flip' else '',
                   len(head)))
        c = {'id': op['id'], 'class': 'mutated-head', 'description': desc,
             'bytes': apply_op(head, op) + body, 'after_send': 'shutdown',
             'expect': expect, 'known_bug': False}
        cases[op['id']] = c
        order.append(op['id'])
    return cases, order


def free_port():
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        return probe.getsockname()[1]


def _read_response(sock, deadline_s, pending=b''):
    """Read one HTTP/1.1 response, seeded with any over-read bytes from a
    previous response on the same connection (TCP can coalesce pipelined
    answers into one segment). Returns (result, extra): result is
    (status, reason, headers, body), or 'closed' (EOF before any response
    byte), 'closed-mid-head' / 'closed-mid-body' (truncated response), or
    'timeout'; extra carries bytes read past this response's body, which
    the caller must feed back as the next pending."""
    sock.settimeout(deadline_s)
    data = bytearray(pending)
    try:
        while b'\r\n\r\n' not in data:
            chunk = sock.recv(65536)
            if not chunk:
                return ('closed' if not data else 'closed-mid-head'), b''
            data += chunk
    except socket.timeout:
        return 'timeout', bytes(data)
    except (ConnectionError, OSError):
        return 'closed', bytes(data)
    head, rest = data.split(b'\r\n\r\n', 1)
    lines = head.split(b'\r\n')
    parts = lines[0].split(b' ', 2)
    if len(parts) < 2 or not parts[1].isdigit():
        return 'closed', b''
    status = int(parts[1])
    headers = {}
    for line in lines[1:]:
        name, _, value = line.partition(b':')
        headers[name.strip().lower().decode('latin1')] = value.strip().decode('latin1')
    try:
        length = int(headers.get('content-length', '0'))
    except ValueError:
        length = 0
    body = rest
    try:
        while len(body) < length:
            chunk = sock.recv(65536)
            if not chunk:
                return 'closed-mid-body', b''
            body += chunk
    except socket.timeout:
        return 'timeout', bytes(body)
    except (ConnectionError, OSError):
        return 'closed-mid-body', b''
    reason = parts[2].decode('latin1') if len(parts) > 2 else ''
    return (status, reason, headers, bytes(body[:length])), bytes(body[length:])


def _peek(sock, wait_s):
    """Short look at the socket: (closed, consumed). closed=True on EOF or
    error; consumed is a byte read from a not-yet-closed peer (a pipelined
    answer's first byte) that the caller must push back into its pending
    buffer — never swallowed."""
    sock.settimeout(wait_s)
    try:
        chunk = sock.recv(1)
    except socket.timeout:
        return False, b''
    except (ConnectionError, OSError):
        return True, b''
    if not chunk:
        return True, b''
    return False, chunk


class Node:
    """One isolated daemon: dynamic loopback port, corpus token file, temp
    root. Spawn/readiness/close conventions from ci/test_regressions.py."""

    def __init__(self):
        self.temp = tempfile.TemporaryDirectory(prefix='mcp-fuzz-')
        self.root = Path(self.temp.name)
        auth = self.root / 'auth-fixture'
        auth.write_text(FUZZ_TOKEN)
        self.port = free_port()
        env = {k: v for k, v in os.environ.items() if not k.startswith('MCP_NODE_')}
        env.update(MCP_NODE_HOST='127.0.0.1', MCP_NODE_PORT=str(self.port),
                   MCP_NODE_NAME='fuzz-node', MCP_NODE_SOCKET_TIMEOUT_S='3',
                   MCP_NODE_TOKEN_FILE=str(auth))
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

    def connect(self):
        return socket.create_connection(('127.0.0.1', self.port), timeout=10)

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.log.close()
        self.temp.cleanup()


def health_ping(node):
    """Global invariant: fresh connection, valid ping => 200. Catches a
    daemon that crashed, hung, or leaked its accept loop on any case."""
    body = b'{"jsonrpc":"2.0","id":987,"method":"ping"}'
    head = (b'POST /mcp HTTP/1.1\r\nHost: ' + HOST_LINE.encode() +
            b'\r\nContent-Type: application/json\r\nX-Node-Token: ' + FUZZ_TOKEN.encode() +
            b'\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n')
    sock = node.connect()
    try:
        sock.sendall(head + body)
        res, _extra = _read_response(sock, 8)
        return isinstance(res, tuple) and res[0] == 200
    except (socket.timeout, ConnectionError, OSError):
        return False
    finally:
        sock.close()


def run_case(node, case, probe=False):
    """Send the case bytes, collect the outcome. In check mode reads exactly
    len(expect.responses) answers; in probe mode reads answers while more
    bytes are already in hand (pipelined answer) or a short peek shows data,
    stopping on close or an idle open connection. Over-read bytes are pushed
    back through a pending buffer, so TCP coalescing of pipelined answers
    cannot make a second response disappear."""
    deadline = float(case.get('deadline_s', 8.0))
    exp = case.get('expect') or {}
    n_hint = None if probe else len(exp.get('responses', []))
    out = {'responses': [], 'bodies': [], 'closed_after': None,
           'elapsed': 0.0, 'error': None}
    sock = node.connect()
    pending = b''
    t0 = time.monotonic()
    try:
        sock.settimeout(deadline)
        sock.sendall(case['bytes'])
        if case.get('after_send', 'shutdown') != 'hold':
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass
        while True:
            if n_hint is None and out['responses'] and not pending:
                closed, consumed = _peek(sock, 0.3)
                if consumed:
                    pending = consumed + pending
                if closed:
                    out['closed_after'] = True
                    break
                if not pending:
                    break  # idle keep-alive: no further answer in flight
            res, extra = _read_response(sock, deadline, pending)
            pending = extra
            if res in ('closed', 'closed-mid-head', 'closed-mid-body'):
                if res != 'closed':
                    out['error'] = res
                out['closed_after'] = True
                break
            if res == 'timeout':
                if n_hint is None and not out['responses']:
                    out['error'] = 'timeout'
                    break
                if n_hint is None:
                    break  # probe: keep-alive open, no further answer
                out['error'] = 'timeout waiting for response %d' % (len(out['responses']) + 1)
                break
            status, _reason, _headers, body = res
            out['responses'].append(status)
            out['bodies'].append(body)
            if n_hint is not None and len(out['responses']) >= n_hint:
                break
            if n_hint is None and len(out['responses']) >= 4:
                break
        if out['closed_after'] is None and out['responses']:
            ca = exp.get('close_after', 'any')
            if ca == 'any' and not probe:
                out['closed_after'] = False  # unchecked
            else:
                closed, consumed = _peek(sock, PEEK_S)
                if consumed:
                    pending = consumed + pending
                out['closed_after'] = closed
        if out['closed_after'] is None:
            out['closed_after'] = False
    except (socket.timeout, ConnectionError, OSError) as exc:
        out['error'] = '%s: %s' % (type(exc).__name__, exc)
        out['closed_after'] = True
    finally:
        out['elapsed'] = round(time.monotonic() - t0, 3)
        try:
            sock.close()
        except OSError:
            pass
    return out


def check_case(case, outcome):
    """Expected-vs-observed. Returns a list of failure strings (empty=ok)."""
    exp = case.get('expect') or {}
    errs = []
    if exp.get('exploration'):
        if outcome['error']:
            errs.append('transport error: %s' % outcome['error'])
        for status in outcome['responses']:
            if status not in ALLOWED_MUTATION_STATUS:
                errs.append('status %d outside the allowed set' % status)
        if not outcome['responses'] and not outcome['closed_after']:
            errs.append('neither an answer nor a close (hung connection)')
        if outcome['elapsed'] > float(case.get('deadline_s', 8.0)) + 1.0:
            errs.append('unbounded case: %.2fs' % outcome['elapsed'])
        return errs
    want = exp.get('responses', [])
    if want != outcome['responses']:
        errs.append('responses %r != expected %r' % (outcome['responses'], want))
    if outcome['error']:
        errs.append('transport error: %s' % outcome['error'])
    ca = exp.get('close_after', 'any')
    if ca == 'yes' and outcome['closed_after'] is not True:
        errs.append('expected close after response, observed %r' % outcome['closed_after'])
    if ca == 'no' and outcome['closed_after'] is not False:
        errs.append('expected keep-alive after response, observed %r' % outcome['closed_after'])
    for needle, got in zip(exp.get('body_contains', []), outcome['bodies']):
        if needle.encode() not in got:
            errs.append('body %r missing %r' % (got[:80], needle))
    max_elapsed = exp.get('max_elapsed_s')
    if max_elapsed is not None and outcome['elapsed'] > float(max_elapsed):
        errs.append('elapsed %.2fs > max %.2fs' % (outcome['elapsed'], max_elapsed))
    return errs


def _escaped(b, limit=160):
    s = ''.join('\\x%02x' % c if c < 0x20 or c >= 0x7f else chr(c) for c in b[:limit])
    return s + ('+%d more' % (len(b) - limit) if len(b) > limit else '')


def _fmt_expect(case):
    exp = case.get('expect') or {}
    return json.dumps(exp, sort_keys=True)


def main():
    ap = argparse.ArgumentParser(description='deterministic seeded HTTP/1.1 parser fuzzer')
    ap.add_argument('--seed', type=int, default=DEFAULT_SEED)
    ap.add_argument('--list', action='store_true', help='dump the resolved case list and exit')
    ap.add_argument('--case', help='run a single case id')
    ap.add_argument('--corpus-dir', default=str(DEFAULT_CORPUS))
    ap.add_argument('--probe', action='store_true',
                    help='run all cases, print observed outcomes, do not check expectations')
    args = ap.parse_args()
    corpus_dir = Path(args.corpus_dir).resolve()
    cases, order = load_corpus(corpus_dir, args.seed)
    if args.case:
        if args.case not in cases:
            print('unknown case id: %s (see --list)' % args.case)
            return 2
        order = [args.case]
    if args.list:
        for cid in order:
            c = cases[cid]
            print('%-14s %-24s len=%-4d expect=%s' % (cid, c['class'], len(c['bytes']), _fmt_expect(c)))
            print('    bytes: %s' % _escaped(c['bytes']))
        print('# %d cases resolved (seed %d, corpus %s)' % (len(order), args.seed, corpus_dir))
        return 0
    node = Node()
    failures = []
    try:
        for i, cid in enumerate(order):
            case = cases[cid]
            out = run_case(node, case, probe=args.probe)
            if args.probe:
                print('PROBE %-14s -> %s' % (cid, json.dumps(
                    {k: out[k] for k in ('responses', 'closed_after', 'elapsed', 'error')})))
            else:
                errs = check_case(case, out)
                if errs:
                    failures.append((cid, errs))
                    print('FAIL  %s: %s' % (cid, '; '.join(errs)))
                    print('      bytes: %s' % _escaped(case['bytes']))
                else:
                    print('ok    %-14s -> responses=%r closed=%s elapsed=%.2fs'
                          % (cid, out['responses'], out['closed_after'], out['elapsed']))
            if not health_ping(node):
                failures.append((cid, ['daemon unhealthy after case']))
                print('FAIL  %s: daemon unhealthy after case (crash or accept-loop stall)' % cid)
                print('      daemon logs: %s' % node.logs()[-1500:])
                break
    finally:
        node.close()
    if args.probe:
        print('# probe complete: %d cases, %d failures' % (len(order), len(failures)))
        return 1 if failures else 0
    if failures:
        print('FAILED %d/%d cases' % (len(failures), len(order)))
        for cid, errs in failures:
            print('  %s: %s' % (cid, '; '.join(errs)))
        return 1
    print('GREEN: %d/%d cases passed (seed %d, corpus %s)'
          % (len(order), len(order), args.seed, corpus_dir))
    return 0


if __name__ == '__main__':
    sys.exit(main())
