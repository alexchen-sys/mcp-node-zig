# ci/fixtures/fuzz — deterministic HTTP/1.1 parser fuzzer corpus

Corpus for `ci/fuzz_http.py`: request smuggling (duplicate / conflicting
Content-Length, CL+TE), framing (bare LF / bare CR), truncation (short
body, oversized Content-Length), pipelining (valid+valid, valid+malformed),
and seeded PRNG mutations of the canonical request head.

Base binary: mcp-node at commit c70c323.
Expectations are the frozen observed behavior of that binary, cross-checked
against RFC 9112 smuggling-resistant semantics. The corpus is byte-literal:
nothing depends on the daemon's real port (Host uses the fake port 65535,
which the default allowed-hosts wildcard `127.0.0.1:*` accepts), and the
auth token is the fixed corpus fixture `fuzzcafe20261002c70c323`, delivered
through `MCP_NODE_TOKEN_FILE` exactly like ci/test_regressions.py does.

## Running

```
zig build -Doptimize=ReleaseSafe
python3 ci/fuzz_http.py                 # all 82 cases, exit 0 on green
python3 ci/fuzz_http.py --case canon-014
python3 ci/fuzz_http.py --list          # resolved case stream (bytes included)
python3 ci/fuzz_http.py --probe         # print observed outcomes, no checks
python3 ci/fuzz_http.py --seed 777      # exploration: LCG stream + invariant contract
```

Files:
- `canonical.json` — 18 handwritten cases (bytes escaped as JSON strings,
  exact and literal).
- `mutations.json` — the frozen LCG mutation stream for seed 20261002
  (48 flips + 16 truncations of the canonical head) with expected outcomes.
  The runner regenerates the stream from the seed and refuses to run if the
  file does not match byte-for-byte (corpus integrity check).
- `README.md` — this document.

Determinism: mutation positions/masks come from a 64-bit LCG
(`x = x*6364136223846793005 + 1442695040888963407`, high 32 bits), not from
`random.Random`, so the stream cannot drift with the Python version.
Same seed => identical case stream: verified by `--list > a; --list > b; cmp a b`
(both for the default seed and a non-default seed) in the green run.
With a non-default seed the runner switches to exploration mode: every case
must still resolve as a status from the allowed set (200/202/4xx listed) or a
clean close, within the bounded deadline, and the daemon must stay healthy.

Global invariant (checked after EVERY case, any mode): fresh connection,
valid `ping` -> HTTP 200. This catches a crashed, hung, or accept-loop-stalled
daemon, not just wrong status codes.

Outcome classes: `status==N` (list of expected response statuses, in order,
for pipelined cases), `closed-after-response` (close_after: yes/no), and
`closed-without-response` (responses: [] + close_after: yes).

## Canonical cases (18)

Legend for "bytes": escaped, `CR`=`\r`=`0x0d`, `LF`=`\n`=`0x0a`. The body of
the canonical ping is `{"jsonrpc":"2.0","id":1,"method":"ping"}` (40 bytes).

| id | class | bytes (shape) | why | expected | observed (probe) |
|----|-------|---------------|-----|----------|------------------|
| canon-000 | baseline | canonical valid POST /mcp ping | proof the harness and gates work; base for mutations | [200], body id:1 | [200] |
| canon-001 | cl-duplicate-identical (a) | `Content-Length: 40` twice, same value | RFC 9112 6.3 permits collapsing identical duplicates; smugglers probe the opposite | [200], body id:1 | [200] |
| canon-002 | cl-duplicate-conflict (b) | `Content-Length: 40` + `Content-Length: 39` | classic CL.CL split: must be an error, never last-wins | [400], close | [400] |
| canon-003 | cl-plus-te-chunked (c) | `Content-Length: 40` + `Transfer-Encoding: chunked` | canonical CL.TE smuggling vector | [400], close | [400] |
| canon-004 | cl-plus-te-identity (d) | `Content-Length: 40` + `Transfer-Encoding: identity` | legacy coding variant of CL.TE desync; RFC 9112 6.1: chunked not final => MUST 400 | [400], close | [400] |
| canon-005 | te-alone | `Transfer-Encoding: chunked`, no CL | framing would fall to chunked parsing; server refuses all TE | [400], close | [400] |
| canon-006 | bare-lf-terminator-close (e) | LF-only head, then half-close | no CRLFCRLF ever: strict CRLF-only framing must answer 400 on EOF mid-head, not hang | [400], close | [400] |
| canon-007 | bare-lf-terminator-hold (e) | LF-only head, connection held open | unterminated head + silent client: absolute deadline must fire | [408] at ~3s (max 5.5s), close | [408] at 3.03s |
| canon-008 | bare-cr-terminator-close (f) | CR-only head, then half-close | no LF at all; head never terminates; EOF => 400 | [400], close | [400] |
| canon-009 | bare-cr-in-value (f) | valid head + `X-Junk: a<CR>b` | 0x0d is not field-content; header grammar must reject | [400], close | [400] |
| canon-010 | body-truncated-close (g) | head CL=40, 30 body bytes, half-close | short body must be 400 ShortBody, never a silent drop | [400], close | [400] |
| canon-011 | cl-oversize-close (h) | head CL=1024, 10 body bytes, half-close | 1014 missing bytes; EOF must end the wait immediately | [400], close | [400] |
| canon-012 | cl-oversize-hold (h) | head CL=1024, 10 bytes, hold open | dribbled body hits the absolute deadline, not a stacked fresh timeout | [408] at ~3s (max 5.5s), close | [408] at 3.00s |
| canon-013 | pipelining-two-valid (i) | two full pings in one write | answers in order (id 1 then 2): no desync | [200, 200], bodies id:1, id:2 | [200, 200] |
| canon-014 | pipelining-valid-plus-malformed (j) | ping + second request with conflicting CL | first answered, smuggled second rejected, connection closed | [200, 400], close | [200, 400] |
| canon-015 | pipelining-valid-plus-short-body | ping + second request CL=10 with 3 bytes | truncation arriving through the carry path | [200, 400], close | [200, 400] |
| canon-016 | silent-close | connect, send 0 bytes, half-close | clean EOF before any byte is the keep-alive shutdown: close silently, no zombie 400 | [] (closed-without-response) | [] |
| canon-017 | pipelining-valid-plus-bare-lf | ping + second request with LF-only framing | carry-fed unterminated head + EOF => BadHeaders | [200, 400], close | [200, 400] |

Probe detail worth knowing: with a half-closed client the server answers,
then sees clean EOF in its keep-alive loop and closes — so even 200-success
cases end with close_after=yes in this harness. The answers themselves (on
the same connection, in order) are what prove keep-alive works.

## Mutations (64, class "mutated-head", seed 20261002)

Canonical head layout (136 bytes):

```
  0.. 17  POST /mcp HTTP/1.1
 20.. 40  Host: 127.0.0.1:65535
 43.. 72  Content-Type: application/json
 75..111  X-Node-Token: fuzzcafe20261002c70c323
114..131  Content-Length: 40
134..135  (final CRLFCRLF terminator)
```

Each mutation sends `mutated_head + canonical_body` (40 bytes), then
half-closes. Expected outcomes are frozen observations from the probe run
(captured in the sandbox run logs). Distribution: 44x[400], 7x[415], 7x[401],
3x[400,400], 1x[421], 1x[405], 1x[200].

Notable outcomes and what they prove:
- `mut-flip-005` (byte 0, `P`->`9`): method stays a valid token but is not
  POST => 405 (gate, not a parser crash).
- `mut-flip-001` (byte 25, space->`s`): Host value becomes
  `s127.0.0.1:65535` => 421 (host gate).
- `mut-flip-021` (byte 39, `3`->`E`): Host port digits become `655E5`;
  the `127.0.0.1:*` wildcard still matches => 200. Proves the corpus really
  pins behavior byte-by-byte, including the wildcard semantics.
- `mut-flip-023/033/035` (bytes in the `Content-Length` field name):
  the name turns into an unknown-but-grammatical header => CL=0, the 40-byte
  body becomes leftover carried into the next iteration => first answer 400
  (JSON parse error on an empty body) + second answer 400 (BadHeaders on the
  unterminated carry + EOF). This is the pipelining-desync pattern caught by
  the fuzzer, deterministically.
- `mut-flip-006/020/024` (bytes in/next to the final CRLFCRLF): terminator
  broken => head never completes => 400 BadHeaders on EOF.
- `mut-flip-002` (byte 83, `o`->0xad in `X-Node-Token`): non-token byte in a
  field name => 400 BadHeader; `mut-flip-037` (`o`->`v`): grammatical but
  unknown header => 401. The grammar gate and the auth gate are distinct.

| id | mutation | expected responses | close |
|----|----------|--------------------|-------|
| mut-flip-001 | flip byte 25: 0x20 -> 0x73 | [421] | yes |
| mut-flip-002 | flip byte 83: 0x6f -> 0xad | [400] | yes |
| mut-flip-003 | flip byte 72: 0x6e -> 0x3b | [415] | yes |
| mut-flip-004 | flip byte 119: 0x6e -> 0xf5 | [400] | yes |
| mut-flip-005 | flip byte 0: 0x50 -> 0x39 | [405] | yes |
| mut-flip-006 | flip byte 133: 0x0a -> 0x04 | [400] | yes |
| mut-flip-007 | flip byte 70: 0x73 -> 0xd7 | [415] | yes |
| mut-flip-008 | flip byte 47: 0x65 -> 0x17 | [400] | yes |
| mut-flip-009 | flip byte 90: 0x75 -> 0xa7 | [401] | yes |
| mut-flip-010 | flip byte 63: 0x61 -> 0xc2 | [415] | yes |
| mut-flip-011 | flip byte 133: 0x0a -> 0xe5 | [400] | yes |
| mut-flip-012 | flip byte 46: 0x74 -> 0x95 | [400] | yes |
| mut-flip-013 | flip byte 125: 0x67 -> 0x29 | [400] | yes |
| mut-flip-014 | flip byte 47: 0x65 -> 0x93 | [400] | yes |
| mut-flip-015 | flip byte 109: 0x33 -> 0xed | [401] | yes |
| mut-flip-016 | flip byte 79: 0x64 -> 0x20 | [400] | yes |
| mut-flip-017 | flip byte 116: 0x6e -> 0xd1 | [400] | yes |
| mut-flip-018 | flip byte 59: 0x70 -> 0x0c | [400] | yes |
| mut-flip-019 | flip byte 116: 0x6e -> 0x8b | [400] | yes |
| mut-flip-020 | flip byte 134: 0x0d -> 0xc9 | [400] | yes |
| mut-flip-021 | flip byte 39: 0x33 -> 0x45 | [200] | yes |
| mut-flip-022 | flip byte 18: 0x0d -> 0xea | [400] | yes |
| mut-flip-023 | flip byte 117: 0x74 -> 0x60 | [400, 400] | yes |
| mut-flip-024 | flip byte 134: 0x0d -> 0x29 | [400] | yes |
| mut-flip-025 | flip byte 88: 0x20 -> 0xb4 | [401] | yes |
| mut-flip-026 | flip byte 69: 0x6a -> 0x0c | [400] | yes |
| mut-flip-027 | flip byte 128: 0x3a -> 0xcd | [400] | yes |
| mut-flip-028 | flip byte 110: 0x32 -> 0xf5 | [401] | yes |
| mut-flip-029 | flip byte 103: 0x30 -> 0xec | [401] | yes |
| mut-flip-030 | flip byte 48: 0x6e -> 0xbb | [400] | yes |
| mut-flip-031 | flip byte 60: 0x6c -> 0x7f | [400] | yes |
| mut-flip-032 | flip byte 72: 0x6e -> 0x85 | [415] | yes |
| mut-flip-033 | flip byte 124: 0x6e -> 0x61 | [400, 400] | yes |
| mut-flip-034 | flip byte 129: 0x20 -> 0xac | [400] | yes |
| mut-flip-035 | flip byte 120: 0x74 -> 0x7c | [400, 400] | yes |
| mut-flip-036 | flip byte 95: 0x66 -> 0x07 | [400] | yes |
| mut-flip-037 | flip byte 83: 0x6f -> 0x76 | [401] | yes |
| mut-flip-038 | flip byte 71: 0x6f -> 0xf4 | [415] | yes |
| mut-flip-039 | flip byte 125: 0x67 -> 0x94 | [400] | yes |
| mut-flip-040 | flip byte 61: 0x69 -> 0x45 | [415] | yes |
| mut-flip-041 | flip byte 10: 0x48 -> 0xd0 | [400] | yes |
| mut-flip-042 | flip byte 124: 0x6e -> 0xab | [400] | yes |
| mut-flip-043 | flip byte 23: 0x74 -> 0xd5 | [400] | yes |
| mut-flip-044 | flip byte 14: 0x2f -> 0x14 | [400] | yes |
| mut-flip-045 | flip byte 109: 0x33 -> 0x5c | [401] | yes |
| mut-flip-046 | flip byte 57: 0x61 -> 0xb7 | [415] | yes |
| mut-flip-047 | flip byte 77: 0x4e -> 0x91 | [400] | yes |
| mut-flip-048 | flip byte 24: 0x3a -> 0xed | [400] | yes |
| mut-trunc-001 | truncate head to 86 of 136 bytes | [400] | yes |
| mut-trunc-002 | truncate head to 116 of 136 bytes | [400] | yes |
| mut-trunc-003 | truncate head to 32 of 136 bytes | [400] | yes |
| mut-trunc-004 | truncate head to 22 of 136 bytes | [400] | yes |
| mut-trunc-005 | truncate head to 51 of 136 bytes | [400] | yes |
| mut-trunc-006 | truncate head to 40 of 136 bytes | [400] | yes |
| mut-trunc-007 | truncate head to 30 of 136 bytes | [400] | yes |
| mut-trunc-008 | truncate head to 87 of 136 bytes | [400] | yes |
| mut-trunc-009 | truncate head to 111 of 136 bytes | [400] | yes |
| mut-trunc-010 | truncate head to 54 of 136 bytes | [400] | yes |
| mut-trunc-011 | truncate head to 27 of 136 bytes | [400] | yes |
| mut-trunc-012 | truncate head to 91 of 136 bytes | [400] | yes |
| mut-trunc-013 | truncate head to 90 of 136 bytes | [400] | yes |
| mut-trunc-014 | truncate head to 127 of 136 bytes | [400] | yes |
| mut-trunc-015 | truncate head to 10 of 136 bytes | [400] | yes |
| mut-trunc-016 | truncate head to 27 of 136 bytes | [400] | yes |

Truncations always lose the final CRLFCRLF terminator, so the head never
completes; EOF after the client's half-close yields 400 BadHeaders. The body
(40 JSON bytes) rides along as head-continuation noise — exactly the
truncation fuzz shape the parser must survive.

## Known bugs / RFC deviations

None found at c70c323. Every observed outcome is contract-correct:

- conflicting duplicate CL, CL+TE (chunked or identity), TE with chunked not
  final: 400 — matches RFC 9112 6.1/6.3 and the smuggling-resistant stance;
- identical duplicate CL accepted: permitted by RFC 9112 6.3;
- bare LF / bare CR rejected (strict CRLF): RFC 9112 2.2 makes LF
  recognition a MAY — refusing is the desync-resistant choice, not a bug;
- TE refused outright (including chunked-alone where a 501 would also be
  defensible): documented hardening ("this server speaks Content-Length
  only"), stricter than the RFC requires — flagged here as a deliberate
  design decision, not a defect;
- short body / oversized CL: 400 + close; silent dribble: 408 at the
  absolute deadline (~3.0s observed with MCP_NODE_SOCKET_TIMEOUT_S=3);
- pipelining: answers in order, malformed second request rejected with 400
  and connection closed — no desync window observed.

## Verification trail (ephemeral CI sandboxes, Zig 0.16.0)

- probe run — `zig build -Doptimize=ReleaseSafe && python3 ci/fuzz_http.py --probe`:
  82 cases, 0 failures; the per-case observed outcomes are in the sandbox
  run logs.
- green run — `zig build -Doptimize=ReleaseSafe && python3 ci/fuzz_http.py`
  + double `--list` cmp (default seed and seed 777): GREEN 82/82,
  DETERMINISM_OK; exit 0.
- red run — corpus copied to a sandbox temp dir, canon-002 expectation flipped
  to [499]: runner FAILS (`canon-002: responses [400] != expected [499]`),
  wrapped so the overall command exits 0 with MUTATION_RED_OK in the run log.
