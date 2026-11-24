#!/usr/bin/env bash
# Builds the WebAssembly package from this tree, for test builds of the web vault and the
# extension. Run it inside the builder image (scripts/lanbox-wasm.sh --tree does that) or in
# CI, where wasm-pack, wasm-opt and the wasm32 target are installed. Never on a developer PC.
#
#   scripts/wasm-tree.sh [<outdir>]            default outdir: wasm-package
#   scripts/wasm-tree.sh --record [<outdir>]   no build: writes wasm-tree.json for the packages already in
#                                              <outdir>. CI uses it when it has the packages of the same
#                                              inputs from an earlier run (its cache key is the hash of
#                                              everything the build reads), so the record names the commit
#                                              under test and the digest of those bytes.
#
# It runs the recipe of the release (scripts/build-wasm.sh: no test-support, wasm-opt -Oz) and
# the packaging of the release (scripts/package-release.sh: the same archives, the same
# reproducible tar), so a tree package differs from a published one only in the commit it was
# built from. It writes to <outdir>:
#
#   ferret-core-wasm-web-<version>.tar.gz    what web/scripts/build.mjs and
#   ferret-core-wasm-node-<version>.tar.gz   extension/scripts/build.mjs take as --wasm-tar
#   SHA256SUMS
#   wasm-tree.json                           {"source":"tree","commit":"<40 hex>[-dirty]","sha256":"<web archive>"}
#
# The commit is FERRET_TREE_COMMIT (the caller says it when the tree has no .git, as in the
# build host's container) or `git rev-parse HEAD`, with -dirty after it when the tree has
# changes that are not committed.
#
# This is the only way a package that no release signed reaches a build. The builds that take
# it (--wasm tree) are test builds: the release variant of the extension and the release image
# of the server refuse it, and a stack with real data refuses an image that carries one.
set -euo pipefail
cd "$(dirname "$0")/.."

record=0
if [ "${1:-}" = "--record" ]; then record=1; shift; fi
out="${1:-wasm-package}"
case "$out" in
  /* | *..* | "") echo "wasm-tree: the output folder is a relative path inside the repository" >&2; exit 2 ;;
esac

version="$(sed -n '/^\[workspace.package\]/,/^\[/{s/^version = "\(.*\)"$/\1/p}' Cargo.toml)"
[ -n "$version" ] || { echo "wasm-tree: no workspace version in Cargo.toml" >&2; exit 1; }

commit="${FERRET_TREE_COMMIT:-}"
if [ -z "$commit" ]; then
  commit="$(git rev-parse HEAD 2> /dev/null)" || { echo "wasm-tree: no git history here; set FERRET_TREE_COMMIT to the commit the tree is" >&2; exit 1; }
  if [ -n "$(git status --porcelain 2> /dev/null)" ]; then commit="$commit-dirty"; fi
fi
printf '%s' "$commit" | grep -Eq '^[0-9a-f]{40}(-dirty)?$' || { echo "wasm-tree: '$commit' is not a 40-digit commit (with -dirty when the tree has changes)" >&2; exit 2; }

if [ "$record" = 0 ]; then
  rm -rf "$out"
  scripts/build-wasm.sh
  # The package has no test-support, whatever the caller did before (the same check the release runs).
  scripts/check-no-test-support.sh
  scripts/package-release.sh package "$version" "$out"
fi

web="$out/ferret-core-wasm-web-$version.tar.gz"
[ -f "$web" ] || { echo "wasm-tree: $web is missing" >&2; exit 1; }
sha="$(sha256sum "$web" | cut -d' ' -f1)"
printf '{"source":"tree","commit":"%s","sha256":"%s"}\n' "$commit" "$sha" > "$out/wasm-tree.json"
echo "wasm-tree: $web ($sha) built from $commit" >&2
