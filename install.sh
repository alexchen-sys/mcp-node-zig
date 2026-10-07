#!/bin/sh
# mcp-node-zig installer. Usage:
#   curl -fsSL https://raw.githubusercontent.com/alexchen-sys/mcp-node-zig/main/install.sh | sh
#   MCP_NODE_VERSION=0.3.0 ... | sh   # pin a version instead of latest
#   MCP_NODE_FLAVOR=tls ... | sh      # hub build with the built-in TLS server
#   PREFIX=/opt/bin ... | sh          # install somewhere else
#   MCP_NODE_VERIFY=require ... | sh  # fail unless cosign verifies the signature
set -eu

REPO="alexchen-sys/mcp-node-zig"
VERSION="${MCP_NODE_VERSION:-latest}"
FLAVOR="${MCP_NODE_FLAVOR:-}"
case "$FLAVOR" in
    "")  suffix="" ;;
    tls) suffix="-tls" ;;
    *)   echo "install: unknown MCP_NODE_FLAVOR: $FLAVOR (use tls or leave it unset)" >&2; exit 1 ;;
esac

die() { echo "install: $*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "missing required tool: $1"; }
need curl
need tar

# --- resolve version ---
if [ "$VERSION" = latest ]; then
    VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
        | sed -n 's/.*"tag_name": *"v\([^"]*\)".*/\1/p' | head -n1)
    [ -n "$VERSION" ] || die "could not resolve latest release tag"
fi
echo "install: mcp-node v$VERSION"

# --- detect platform ---
OS=$(uname -s)
ARCH=$(uname -m)
case "$OS" in
    Linux)  os=linux ;;
    Darwin) os=macos ;;
    *)      die "unsupported OS: $OS (on Windows, grab mcp-node-v$VERSION-x86_64-windows.zip from the release page)" ;;
esac
case "$ARCH" in
    x86_64|amd64)   arch=x86_64 ;;
    aarch64|arm64)  arch=aarch64 ;;
    *)              die "unsupported architecture: $ARCH" ;;
esac
target="$arch-$os"
[ "$target" = "x86_64-macos" ] && die "no x86_64 macOS build; use aarch64-macos (Apple Silicon) or build from source"
[ -n "$suffix" ] && [ "$os" != linux ] && [ "$os" != macos ] && die "the tls flavor ships for Linux and macOS; on Windows grab the -tls zip from the release page"
pkg="mcp-node-v$VERSION-$target$suffix"
base="https://github.com/$REPO/releases/download/v$VERSION"

# --- download + verify ---
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
echo "install: downloading $base/$pkg.tar.gz"
curl -fsSL "$base/$pkg.tar.gz" -o "$tmp/$pkg.tar.gz" || die "download failed (does v$VERSION have a $target asset?)"
curl -fsSL "$base/SHA256SUMS.txt" -o "$tmp/SHA256SUMS.txt" || die "download of SHA256SUMS.txt failed"
cd "$tmp"
# Signed releases ship a Sigstore bundle for SHA256SUMS.txt. With cosign on
# PATH the manifest is verified against this repo's release workflow before
# any checksum is trusted; MCP_NODE_VERIFY=require makes that mandatory.
if curl -fsSL "$base/SHA256SUMS.txt.sigstore.json" -o "$tmp/SHA256SUMS.txt.sigstore.json" 2>/dev/null; then
    if command -v cosign >/dev/null 2>&1; then
        cosign verify-blob SHA256SUMS.txt \
            --bundle SHA256SUMS.txt.sigstore.json \
            --certificate-identity "https://github.com/$REPO/.github/workflows/release.yml@refs/tags/v$VERSION" \
            --certificate-oidc-issuer https://token.actions.githubusercontent.com >/dev/null 2>&1 \
            || die "signature check of SHA256SUMS.txt failed"
        echo "install: signature OK (Sigstore, release workflow of $REPO)"
    elif [ "${MCP_NODE_VERIFY:-}" = require ]; then
        die "MCP_NODE_VERIFY=require but cosign is not installed"
    else
        echo "install: note: install cosign to verify the release signature"
    fi
elif [ "${MCP_NODE_VERIFY:-}" = require ]; then
    die "v$VERSION has no signature bundle"
fi
if command -v sha256sum >/dev/null 2>&1; then
    grep "  $pkg.tar.gz\$" SHA256SUMS.txt | sha256sum -c - >/dev/null || die "checksum mismatch"
elif command -v shasum >/dev/null 2>&1; then
    grep "  $pkg.tar.gz\$" SHA256SUMS.txt | shasum -a 256 -c - >/dev/null || die "checksum mismatch"
else
    die "neither sha256sum nor shasum found"
fi
echo "install: checksum OK"
tar xzf "$pkg.tar.gz"

# --- install ---
if [ -n "${PREFIX:-}" ]; then
    dest="$PREFIX"
elif [ -w /usr/local/bin ]; then
    dest=/usr/local/bin
else
    dest="$HOME/.local/bin"
fi
mkdir -p "$dest"
cp "$tmp/$pkg/mcp-node" "$dest/mcp-node"
chmod 755 "$dest/mcp-node"
echo "install: $dest/mcp-node"
"$dest/mcp-node" --version || die "installed binary failed to run (wrong libc/arch?)"
case ":$PATH:" in
    *":$dest:"*) ;;
    *) echo "install: note: $dest is not on your PATH" ;;
esac
echo "install: done. Run it under your MCP client or: mcp-node --help"
