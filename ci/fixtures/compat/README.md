# mcp-node v0 compatibility golden fixtures

This directory freezes the v0 wire contract of all 13 MCP tools plus the
`initialize` / `ping` / `tools/list` protocol methods. `ci/test_compat.py`
replays every case against a real daemon (raw HTTP, JSON-RPC 2.0, one fresh
daemon per fixture file) and deep-matches each response.

## Layout

- `initialize.json`, `ping.json`, `tools_list.json` — protocol surface.
- `<tool>.json` for each of the 13 tools: `sys_info`, `exec`, `exec_start`,
  `exec_poll`, `exec_write`, `exec_kill`, `exec_close`, `exec_wait`,
  `exec_list`, `exec_shell`, `read_file`, `write_file`, `list_dir`.
- `probe.py` — evidence/regeneration tool: boots the binary, replays the
  planned requests, dumps real responses as JSON lines to stdout. Use it to
  re-baseline when a contract change is intentional (read the dump, update
  fixtures deliberately — never bulk-regenerate).

## Fixture format

Each file is a JSON object:

```json
{
  "description": "what this file freezes and why",
  "cases": [
    {
      "name": "case_name",
      "request": { "jsonrpc": "2.0", "id": 7, "method": "tools/call",
                   "params": { "name": "exec", "arguments": { } } },
      "expect": {
        "status": 200,
        "response": { "...matcher..." },
        "match": "subset",
        "capture": { "sid": "result.structuredContent.session_id" }
      }
    }
  ]
}
```

- `request` — the full JSON-RPC request object, sent verbatim (POST /mcp,
  `X-Node-Token`, `Content-Type: application/json`).
- `expect.status` — required; the HTTP status code.
- `expect.response` — matcher applied to the parsed response body. `null`
  matches the empty body of a 202 notification.
- `expect.match` — `"subset"` switches the whole response matcher to subset
  mode (see below). Default (absent) is exact mode.
- `expect.capture` — after the response arrives, resolve each dotted path
  against the response object and store it as a named variable. Dotted path
  segments are object keys or integer array indices
  (`result.structuredContent.session_id`, `result.tools.3.name`).
- Variable substitution: any JSON string whose entire value is `"$name"`
  (in `request` or in `expect.response`) is replaced by the captured value
  with its original JSON type. This is how multi-step flows chain
  `exec_start` → `exec_poll`/`exec_wait`/`exec_write` → `exec_close`.

## Matcher language

The matcher is a structural deep-match, deliberately minimal:

- Exact scalars compare with strict typing: `true` never equals `1`, `1`
  never equals `"1"`, `1` never equals `1.0`.
- Objects (default exact mode): the actual and expected key sets must be
  equal — a new response field or a removed one fails the case.
- Objects (`"match": "subset"`): every expected key must be present and
  match; extra keys in the actual response are allowed. Subset mode
  propagates into nested objects and array elements. Used for
  `tools/list`, where schema details beyond `name` + `required` are not
  byte-pinned.
- Arrays: same length, element-wise match, in order (the tools array order
  is part of the contract).
- Typed wildcards — a single-key object whose key is one of:
  - `{"*int": null}` — any integer (booleans do not match).
  - `{"*str": null}` — any string.
  - `{"*any": null}` — anything, including null.
  The value in the wildcard object is ignored. Wildcards exist for volatile
  fields only: `session_id`, `pid`, `duration_ms`, `started_ms`,
  `ended_ms`, `mtime`, `MemTotal`/`MemAvailable`, `hostname`, `node`,
  `loadavg_raw`, `uptime_raw`, directory sizes, `auth-fixture`/`daemon.log`
  sizes. Deterministic values (`exit_code`, `stdout`, `sha256`, file sizes,
  offsets) are pinned exactly so accidental contract drift cannot hide
  behind a wildcard.
- The envelope `text` mirror follows the same rule: the daemon serializes
  its payload once and emits it both as `structuredContent` and (JSON
  string-escaped) as `content[0].text`, so the mirror is the compact JSON
  of the payload in the daemon's field order. Wherever that payload is
  fully deterministic — `read_file` / `write_file` results, `exec_write`
  `bytes`/`eof`, `exec_close`, `exec_kill`, and the `{"ok":false,
  "error":...}` domain errors — the mirror is pinned as an exact string;
  where volatile fields are embedded (`session_id`, `pid`,
  `duration_ms`, ...) it stays a `{"*str": null}` wildcard. Fixture
  files tightened so far: `read_file`, `write_file`, `exec_write`,
  `exec_close`, `exec_kill` (other files may still carry wildcarded
  deterministic mirrors until they are re-baselined).

## Error contract (as frozen in v0)

- A present tool argument with the wrong JSON type is a protocol error:
  HTTP 200 with JSON-RPC `error.code == -32602` (`Invalid params`).
- A missing required argument is a tool-domain error: HTTP 200, tool
  envelope, `result.structuredContent == {"ok": false, "error":
  "<ErrorName>"}` (e.g. `MissingArgv`, `MissingSession`, `MissingData`,
  `MissingScript`, `MissingPath`, `MissingContent`), and — v0 quirk —
  `isError` stays `false` on the envelope for these; only an unknown tool
  name sets `isError: true` (that envelope has no `structuredContent`).
- Domain failures (`FileNotFound`, `NotDirectory`, `BadArgv`,
  `UnsupportedShell`, `UnknownSession`) use the same `{"ok": false,
  "error": "..."}` payload shape.
- Validation order is part of the frozen contract: `exec_write` validates
  argument types before session resolution (a bad `data_b64` is -32602
  even when the session is unknown), while `exec_poll`/`exec_wait`
  resolve the session first (an unknown session answers `UnknownSession`
  even when `stdout_offset`/`timeout` also has the wrong type). Both
  orders are pinned by discriminating cases.

## Environment assumptions

- POSIX sandbox with `/bin/echo`, `/bin/true`, `/bin/false`, `/bin/cat`,
  `/bin/sleep` and `bash` (the default `exec_shell` shell). SIGKILL is
  signal 9, so a killed session reports `exit_code` 137 (128+9).
- `sys_info` pins `os: "Linux"` and `machine: "x86_64"` (compile-time
  constants of the build platform); the hostname and memory numbers are
  wildcards.
- File tools run inside the daemon's temp cwd. The default-path `list_dir`
  case expects exactly `auth-fixture`, `compat-dir`, `daemon.log` — the
  harness creates the first and last, the fixture file itself creates
  `compat-dir` before that case runs.
- The daemon name is `compat-node` (set by the harness) and the version
  `0.1.0` comes from build.zig.zon via build options.

## Platform scope

A fixture file may declare `"platforms"` (a non-empty subset of `"linux"`,
`"macos"`, `"windows"`, `"posix"` — `posix` covers linux+macos) together
with a non-empty `"platforms_reason"` string. On a platform outside the
scope the harness reports the file as `SKIP` with the reason and does not
count it as a failure. Malformed scope metadata is a hard fixture error,
so a skip can never be introduced silently. Fixtures without `platforms`
run everywhere.

