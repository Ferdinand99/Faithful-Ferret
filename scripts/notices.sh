#!/usr/bin/env bash
# Makes THIRD-PARTY-NOTICES from the dependencies of the program, or with --check
# only tests that the file in the repository is up to date. Fails when a dependency has a
# licence that is not on the allowlist in about.toml.
#
# Two Rust graphs are covered: the server (crates/ferret-server, a workspace of its own: the
# binary in the Docker image) and the WebAssembly binding (bindings/wasm, wasm32-unknown-unknown:
# the release archives, and the module that the web vault in the image embeds).
#
# Needs: cargo-about 0.9.3 (CI installs it with a pinned checksum) and Node.js. The build
# environments are the LANBox (cargo and Node are not run on the development PC).
# Run from anywhere: scripts/notices.sh [--check]
set -euo pipefail

want_version="0.9.3"
cd "$(dirname "$0")/.."

have_version="$(cargo about --version 2>/dev/null | awk '{print $2}' || true)"
if [ "$have_version" != "$want_version" ]; then
  echo "ERROR: cargo-about $want_version is needed, found '${have_version:-none}'." >&2
  echo "Install it: cargo install --locked cargo-about --version $want_version" >&2
  exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# --fail stops on a crate whose licence cannot be read; without it the crate is left out and the
# command still succeeds (scripts/test-notices-fail.sh proves that).
cargo about generate --config about.toml --locked --fail --format json \
  --manifest-path crates/ferret-server/Cargo.toml --output-file "$tmp/server.json"
cargo about generate --config about.toml --locked --fail --format json \
  --target wasm32-unknown-unknown \
  --manifest-path bindings/wasm/Cargo.toml --output-file "$tmp/wasm.json"

if [ "${1:-}" = "--check" ]; then
  node scripts/third-party-notices.mjs --rust "$tmp/server.json" --rust "$tmp/wasm.json" --check
else
  node scripts/third-party-notices.mjs --rust "$tmp/server.json" --rust "$tmp/wasm.json" --out THIRD-PARTY-NOTICES
fi
