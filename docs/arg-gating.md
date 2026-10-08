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
policies must not leave an ungated backdoor token by accident. Node, hub and
stdio modes refuse a policy file outright — node/stdio have no client token,
and on a hub the relay route (`/n/<name>/mcp`) forwards raw bodies to nodes
where no policy exists, so a hub-side policy would be a false sense of
security. Run the policy on each node's own listen listener instead.
`MCP_NODE_INSECURE=1` combined with a policy file is also a startup error.

## What a policy can constrain

| Rule | Applies to | Meaning |
|---|---|---|
| `tools` | all 13 tools | Exact names, or `"*"`. Default-deny. |
| `exec_argv0` | exec, exec_start, exec_shell | Allowed argv[0]. Bare names match bare requests exactly; slash entries must be absolute and match slash requests (both sides canonicalised). **No cross-boundary matching**: allowing `python3` does not authorise `/usr/bin/python3` and vice versa. |
| `exec_cwd` | exec-family `cwd` | Absolute prefixes. Absent → the caller may not set `cwd` at all; inheriting the daemon cwd stays allowed. |
| `max_timeout_s` | exec-family, exec_wait | A `timeout` above the cap is **refused**, not clamped. Values with the wrong JSON type (e.g. `"timeout": "10"` or `123.5`) are refused too — the gate validates the exact grammar the tool accepts, so nothing can slip past on a type technicality. `exec`/`exec_start`/`exec_shell` default to 120s and `exec_wait` to 30s when `timeout` is absent or null: a cap below the default refuses the call outright. |
| `read_paths` | read_file, list_dir | Absolute prefixes. Required when either tool is callable. |
| `write_paths` | write_file | Absolute prefixes. Empty array is legal and denies every path. |
| `write_max_mode` | write_file | Octal string cap (e.g. `"0644"`). A requested `mode` above the cap is refused — this is what keeps a token from creating setuid/sticky files. Required when write_file is callable. The cap applies to the effective mode: an omitted `mode` means the tool default 0644, and a mode with the wrong JSON type is refused (the tool accepts integral floats like `420.0`; the gate converts them the same way, so they are checked, not skipped). |
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

Paths are canonicalised before matching, in the order the kernel resolves
them: symlink resolution first (realpath on the raw path), lexical `..`
collapse second, then only for a not-yet-existing tail, realpath of the
deepest existing raw ancestor with the tail re-attached before collapsing.
`~` is expanded, relatives anchor to the daemon working directory, `//`
collapses. Prefix matches are segment-aligned — `/srv/build` matches
`/srv/build/x`, never `/srv/buildkeys`.

Honest limits:

- **TOCTOU**: the gate canonicalises, then the tool opens the raw argument.
  A local racing process that swaps a component for a symlink in that window
  can redirect the open. This requires an attacker with local code
  execution — which a token holder does not have unless you also hand them
  an exec token (see below).
- **Hardlinks defeat path rules**: realpath does not see hardlinks, so a
  file hardlinked into an allowed tree from outside it reads as allowed.
  No tool creates hardlinks, but a co-tenant with shell access can.
- **Bare argv[0] trusts the daemon's PATH**: an allowlisted bare name is
  resolved by the daemon's PATH at exec time; a writable directory early in
  PATH redefines it. Prefer absolute entries where it matters.
- **Case-insensitive filesystems** (macOS, Windows) are matched byte-exactly.
  Write prefixes in the canonical case the host reports; a mismatch denies.
- A path under an allow prefix but not yet existing passes on the strength of
  its real (existing) ancestor — that is the intended semantics for creating
  new files in an allowed tree.
- **Session ids are enumerable**: `exec_poll` on another token's session
  returns `SessionNotOwned` versus `UnknownSession` for a missing one, which
  distinguishes the two states. With a policy active the ids a token can
  act on are only its own, so the oracle reveals existence, not control.

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
- **Hub relay is out of scope, by refusal.** A hub refuses to start with
  `MCP_NODE_POLICY_FILE` set: the `/n/<name>/mcp` route forwards raw bodies
  to nodes that have no policy, so gating only the hub's own client
  listener would be a false sense of security. Configure the policy on each
  node's listen listener; hub-side client tokens keep their v0.3.1 meaning.
  Node↔hub links are trusted and unaffected either way.
- `allow_all: true` entries are a deliberate escape hatch (an admin token)
  — the point of the feature is that not every token needs to be god.
