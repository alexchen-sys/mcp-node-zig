# Per-token argument gating

`MCP_NODE_POLICY_FILE` turns the single shared client token into a set of
per-token policies that constrain **what arguments** each token may use, not
just which tools it may call. When the variable is unset the node is exactly
the previous version: one token file, everything allowed.

This is the honest answer to the question "what stops a scoped exec from
reading `~/.aws`?": a policy is checked per call, on the node, before
anything runs — and it checks arguments.

## Quick start

```
# /etc/mcp-node/policy.json (0600)
{
  "version": 1,
  "tokens": [
    {
      "file": "/etc/mcp-node/tokens/build",
      "tools": ["sys_info", "exec", "read_file", "list_dir"],
      "exec_argv0": ["/usr/bin/git", "/usr/bin/make", "tar"],
      "exec_cwd": ["/srv/build"],
      "max_timeout_s": 120,
      "read_paths": ["/srv/build", "/var/log/build"],
      "write_paths": [],
      "write_max_mode": "0644",
      "read_deny": ["/srv/build/keys"]
    },
    {
      "file": "/etc/mcp-node/tokens/admin",
      "allow_all": true
    }
  ]
}

MCP_NODE_POLICY_FILE=/etc/mcp-node/policy.json mcp-node
```

Each entry's `file` is a 0600 file holding the raw token (same format as the
classic token file). The token **values** never enter the policy file, the
audit log, or the config fingerprint — the node keeps only
`sha256(value)` per entry and compares it timing-safe.

The classic `MCP_NODE_TOKEN_FILE` must name a token that one of the entries
also names (matched by value). If it does not, startup fails: opting into
policies must not leave an ungated backdoor token by accident. Node and
stdio modes refuse a policy file outright (there is no client token there),
and `MCP_NODE_INSECURE=1` combined with a policy file is a startup error.

## What a policy can constrain

| Rule | Applies to | Meaning |
|---|---|---|
| `tools` | all 13 tools | Exact names, or `"*"`. Default-deny. |
| `exec_argv0` | exec, exec_start, exec_shell | Allowed argv[0]. Bare names match bare requests exactly; slash entries must be absolute and match slash requests (both sides canonicalised). **No cross-boundary matching**: allowing `python3` does not authorise `/usr/bin/python3` and vice versa. |
| `exec_cwd` | exec-family `cwd` | Absolute prefixes. Absent → the caller may not set `cwd` at all; inheriting the daemon cwd stays allowed. |
| `max_timeout_s` | exec-family, exec_wait | A `timeout` above the cap is **refused**, not clamped. If the cap is below the 120s default, calls without an explicit `timeout` are refused too. |
| `read_paths` | read_file, list_dir | Absolute prefixes. Required when either tool is callable. |
| `write_paths` | write_file | Absolute prefixes. Empty array is legal and denies every path. |
| `write_max_mode` | write_file | Octal string cap (e.g. `"0644"`). A requested `mode` above the cap is refused — this is what keeps a token from creating setuid/sticky files. Required when write_file is callable. |
| `read_deny` / `write_deny` / `cwd_deny` | corresponding paths | Subtractive prefixes evaluated after the allowlist: allow+deny → deny. |

Parsing is **strict**: unknown keys, bad versions, relative or `~` prefixes,
cross-key contradictions (exec listed with empty `exec_argv0`, write_file
without `write_max_mode`, exec_shell with no shell reachable) all fail
startup with the offending key named in the error.

## exec_shell, stated plainly

`exec_shell` runs a script under an interpreter. A script cannot be
argument-gated in any meaningful sense — the script text *is* the program.
The gate evaluates the shell the tool will actually spawn (explicit `shell`
argument or the platform default) against `exec_argv0`, and the strict
parser refuses an `exec_shell` policy that lists no shell at all, because
every call would be denied anyway. Allowing any shell is equivalent to
allowing arbitrary code as far as the policy is concerned. If you do not
mean to allow that, omit `exec_shell` from `tools` — that is the supported
way to disable it.

## Path matching and its limits

Paths are canonicalised before matching: `~` is expanded, relative paths are
anchored to the daemon working directory, `.`/`..` are resolved lexically,
`//` collapses, and symlinks are followed (via realpath) wherever they
exist. Prefix matches are segment-aligned — `/srv/build` matches
`/srv/build/x`, never `/srv/buildkeys`.

Honest limits:

- **TOCTOU**: the gate canonicalises, then the tool opens. A local racing
  process that swaps a component for a symlink in that window can redirect
  the open. This is inherent to allowlist-then-open; it requires an attacker
  with local code execution, which a token holder does not have — unless you
  also hand them an exec token (see below).
- **Case-insensitive filesystems** (macOS, Windows) are matched byte-exactly.
  Write prefixes in the canonical case the host reports; a mismatch denies.
- A path under an allow prefix but not yet existing passes on the strength of
  its real (existing) ancestor — that is the intended semantics for creating
  new files in an allowed tree.

## Sessions are token-owned

`exec_start` sessions record the sha256 of the starting token. While a
policy is active, `exec_poll`, `exec_write`, `exec_kill`, `exec_close`,
`exec_wait` refuse sessions started by a different token, and `exec_list`
shows only your own. This closes the obvious bypass: a token denied exec
guessing another token's session id and driving it via `exec_write`.

## Denials

A denied call returns the normal tool-error envelope with `isError: true`:

```json
{"ok": false, "error": "PolicyDenied", "message": "timeout exceeds this token's cap", "field": "timeout"}
```

The denial happens **before dispatch**: a denied exec never spawns, a denied
write never opens the file. Every denial is recorded in the audit log (when
enabled) as a `policy.deny` event with the tool, the same args
digest/summary as `tool.call`, the reason, and a 16-hex fingerprint of the
token — never the token value. The `start` record's config fingerprint
includes the policy file path and a sha256 of its bytes, so policy edits
show up in the next start record.

## Threat model, stated plainly

- **An allowed interpreter re-opens everything.** `exec_argv0: ["python3"]`
  means arbitrary Python; `bash` means arbitrary shell. The gate constrains
  the *capability reach* of a token, not what the allowed binaries can do
  when combined creatively. Treat every exec allowance as code execution
  with the node user's ambient rights.
- **argv[1..] is not filtered.** Allowing `git` allows every git subcommand.
- **The policy constrains the token holder, not the OS user.** A local
  compromise of the node's user is unaffected by this feature.
- Node↔hub **links are trusted** and unaffected: policies apply to client
  tokens (listen mode, and the hub's own client listener), never to link
  traffic.
- `allow_all: true` entries are a deliberate escape hatch (an admin token)
  — the point of the feature is that not every token needs to be god.
