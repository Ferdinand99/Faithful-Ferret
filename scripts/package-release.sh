#!/usr/bin/env bash
# Packages the release build of the WebAssembly binding.
#
#   scripts/package-release.sh package <version> <outdir>
#       writes ferret-core-wasm-web-<version>.tar.gz and
#       ferret-core-wasm-node-<version>.tar.gz to <outdir>, and SHA256SUMS
#   scripts/package-release.sh checksums <outdir>
#       rewrites <outdir>/SHA256SUMS for every ferret-core-wasm-* file there
#       (run it again after the SBOM has been added)
#
# It packages what scripts/build-wasm.sh left in bindings/wasm/pkg-web and
# bindings/wasm/pkg-node (the build without `test-support`). The web package
# also holds js/, the worker client that loads it. The archives are
# reproducible: sorted names, a fixed time stamp, root ownership, fixed modes
# and a gzip header without a name or a time. It needs GNU tar.
set -euo pipefail
cd "$(dirname "$0")/.."

usage() {
  echo "usage: scripts/package-release.sh package <version> <outdir> | checksums <outdir>" >&2
  exit 2
}

checksums() {
  local dir="$1"
  (
    cd "$dir"
    # shellcheck disable=SC2012
    LC_ALL=C sha256sum $(LC_ALL=C ls -1 ferret-core-wasm-* | LC_ALL=C sort) > SHA256SUMS
  )
}

mode="${1:-}"
case "$mode" in
  checksums)
    [ "$#" -eq 2 ] || usage
    checksums "$2"
    cat "$2/SHA256SUMS"
    exit 0
    ;;
  package) [ "$#" -eq 3 ] || usage ;;
  *) usage ;;
esac

version="$2"
out="$3"
if ! printf '%s' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$'; then
  echo "package-release: '$version' is not a version number" >&2
  exit 2
fi
for flavor in web node; do
  wasm="bindings/wasm/pkg-$flavor/ferret_core_wasm_bg.wasm"
  [ -f "$wasm" ] || { echo "package-release: $wasm is missing; run scripts/build-wasm.sh first" >&2; exit 1; }
done

mkdir -p "$out"
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT

pack() {
  local flavor="$1" name="ferret-core-wasm-$1-$version"
  local root="$stage/$name"
  mkdir -p "$root"
  cp -R "bindings/wasm/pkg-$flavor" "$root/pkg-$flavor"
  rm -f "$root/pkg-$flavor/.gitignore"
  if [ "$flavor" = web ]; then
    cp -R bindings/wasm/js "$root/js"
  fi
  cp LICENSE "$root/LICENSE"
  find "$root" -type d -exec chmod 0755 {} +
  find "$root" -type f -exec chmod 0644 {} +
  tar --sort=name --mtime='1970-01-01 00:00:00 UTC' --owner=0 --group=0 --numeric-owner \
      -C "$stage" -cf - "$name" | gzip -n -9 > "$out/$name.tar.gz"
}

pack web
pack node
checksums "$out"
cat "$out/SHA256SUMS"
