# Contributing

Small, focused PRs are welcome. Contributions are licensed under MIT.

## Setup

- Zig 0.16.x
- Platform-specific code goes in `src/os/`

## Before you open a PR

```sh
zig fmt --check .
zig build test
zig build -Doptimize=ReleaseSafe
```

CI runs these plus smoke and regression tests on Linux, macOS, and Windows.

## Guidelines

- Conventional commits: `fix(http): ...`, `feat(exec): ...`
- One change per PR
- No new dependencies. The single static binary is the point. Open an issue first if you think you need one.
- Keep the security checks in order: token first, then `Host`, then parsing. All resource caps stay enforced.
- New tool, env var, or error shape? Update the README in the same PR.

## Issues

- Bugs and ideas: [open an issue](https://github.com/alexchen-sys/mcp-node-zig/issues/new/choose)
- Security: see [SECURITY.md](SECURITY.md)
