#!/usr/bin/env bash
# Refreshes the embedded Public Suffix List snapshot
# (crates/ferret-core/src/passkey/public_suffix_list.dat).
#
# The snapshot is the upstream list with the comments dropped, except the MPL
# notice and the VERSION and COMMIT lines, which carry the date that the
# snapshot age test reads. Private domains are kept (github.io, vercel.app).
# Run this before every release; the test `psl_snapshot_is_not_older_than_90_days`
# fails otherwise.
set -euo pipefail
cd "$(dirname "$0")/.."

out=crates/ferret-core/src/passkey/public_suffix_list.dat
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
curl -fsSL https://publicsuffix.org/list/public_suffix_list.dat -o "$tmp"
sum="$(sha256sum "$tmp" | cut -d' ' -f1)"

{
  sed -n '1,3p' "$tmp"
  echo "// Source: https://publicsuffix.org/list/public_suffix_list.dat"
  echo "// Upstream-SHA256: $sum"
  echo "// Reduced: comments and blank lines removed, rules unchanged."
  grep -E '^// (VERSION|COMMIT): ' "$tmp"
  grep -v '^//' "$tmp" | grep -v '^[[:space:]]*$' | tr -d '\r'
} > "$out"
echo "wrote $out ($(wc -c < "$out") bytes)"
