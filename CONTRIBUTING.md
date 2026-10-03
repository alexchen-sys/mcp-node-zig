# Contributing

Small, focused pull requests are welcome. By submitting a PR you agree to
license your contribution under the project's MIT license.

## Toolchain

- **Zig 0.16.x** (see `minimum_zig_version` in `build.zig.zon`) — other
  versions may fail to build
- Linux, macOS, and Windows: platform specifics live behind the `src/os/` layer (POSIX process groups, Windows Job Objects) — put new platform code there, not in `main.zig`

## Checks

Run all three before opening a PR — CI runs exactly these plus a live
auth-gate smoke test, and red CI is not reviewed:

```sh
zig fmt --check .
zig build test
zig build -Doptimize=ReleaseSafe
```

## Conventions

- Commit messages: conventional style, lowercase, scoped —
  `feat(exec): ...`, `fix(http): ...`, `perf(transport): ...`
- One concern per PR; small diffs over sweeping refactors
- **No new dependencies.** A single static, no-libc binary is a core design
  goal — proposals that need a library/framework need a strong justification
  first (open an issue before writing code)
- Preserve the security invariants documented in README → "Security notes":
  token check before any work, `Host` validation before JSON parsing, all
  resource caps enforced
- If you change observable behavior (new tool, new env var, new error shape),
  update README in the same PR

## Bugs and features

- Regular bugs / feature ideas: open an issue (templates provided)
- Security issues: see [SECURITY.md](SECURITY.md) — private reports only
