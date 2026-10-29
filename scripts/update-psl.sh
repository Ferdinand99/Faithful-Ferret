#!/usr/bin/env bash
# Refreshes the embedded Public Suffix List snapshot
# (crates/ferret-core/src/passkey/public_suffix_list.dat).
#
# The snapshot is the upstream list with the comments dropped, except the MPL
# notice and the VERSION and COMMIT lines, which carry the date that the
# snapshot age test reads. Private domains are kept (github.io, vercel.app).
# Run this before every release; `scripts/check-psl-age.sh` (weekly and on
# release pull requests) fails when the snapshot is more than 90 days old.
# It also fetches the upstream test file of the same commit into
# vectors/external/; update its commit and hash in vectors/external/SOURCE.md
# and review the diff (rule count, no removed ICANN top-level domains).
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
commit="$(grep -E '^// COMMIT: ' "$out" | cut -d' ' -f3)"
curl -fsSL "https://raw.githubusercontent.com/publicsuffix/list/$commit/tests/test_psl.txt"   -o vectors/external/publicsuffix-test_psl.txt
echo "test file: commit $commit, sha256 $(sha256sum vectors/external/publicsuffix-test_psl.txt | cut -d' ' -f1)"
echo "wrote $out ($(wc -c < "$out") bytes)"
