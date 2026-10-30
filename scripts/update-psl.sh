#!/usr/bin/env bash
# Refreshes the embedded Public Suffix List snapshot
# (crates/ferret-core/src/passkey/public_suffix_list.dat) and the upstream test
# file of the same commit (vectors/external/publicsuffix-test_psl.txt).
#
# The snapshot is the upstream list with the comments dropped, except the MPL
# notice and the VERSION and COMMIT lines, which carry the date that the
# snapshot age test reads. Private domains are kept (github.io, vercel.app).
# Run this before every release; `scripts/check-psl-age.sh` (weekly and on
# release pull requests) warns after 75 days and fails after 90.
#
# Both files are downloaded and built first, next to the files they replace
# (so on the same file system), and renamed into place one right after the
# other at the end. A failed download or check never leaves a new snapshot next
# to an old test file, and a rename never copies.
#
# After it runs, by hand:
#  1. In vectors/external/SOURCE.md, set the new commit and the SHA-256 of the
#     test file (the script prints both).
#  2. The test `psl_upstream_test_file` in crates/ferret-core/tests/origin.rs
#     asserts the number of `checkPublicSuffix` cases in the test file (78 at
#     the time of writing). The script prints the number; if upstream added or
#     removed cases, change the number in the test and in SOURCE.md.
#  3. Review the diff of the snapshot (rule count, no removed ICANN top-level
#     domains), run the test suite, and run `cargo run -p ferret-vectorgen --bin
#     vectorgen -- generate` if vectors/MANIFEST.json lists the test file.
set -euo pipefail
cd "$(dirname "$0")/.."

out=crates/ferret-core/src/passkey/public_suffix_list.dat
test_out=vectors/external/publicsuffix-test_psl.txt

work="$(mktemp -d)"
new_out="$out.new"
new_test="$test_out.new"
trap 'rm -rf "$work" "$new_out" "$new_test"' EXIT

curl -fsSL https://publicsuffix.org/list/public_suffix_list.dat -o "$work/list.dat"
sum="$(sha256sum "$work/list.dat" | cut -d' ' -f1)"

{
  sed -n '1,3p' "$work/list.dat"
  echo "// Source: https://publicsuffix.org/list/public_suffix_list.dat"
  echo "// Upstream-SHA256: $sum"
  echo "// Reduced: comments and blank lines removed, rules unchanged."
  grep -E '^// (VERSION|COMMIT): ' "$work/list.dat"
  grep -v '^//' "$work/list.dat" | grep -v '^[[:space:]]*$' | tr -d '\r'
} > "$work/snapshot.dat"

commit="$(grep -E '^// COMMIT: ' "$work/snapshot.dat" | cut -d' ' -f3)"
if ! printf '%s' "$commit" | grep -Eq '^[0-9a-f]{40}$'; then
  echo "update-psl: no commit id in the list header" >&2
  exit 1
fi
curl -fsSL "https://raw.githubusercontent.com/publicsuffix/list/$commit/tests/test_psl.txt" -o "$work/test_psl.txt"

# Both downloads worked; sanity-check them before anything is replaced.
rules="$(grep -vc '^//' "$work/snapshot.dat")"
cases="$(grep -c '^checkPublicSuffix(' "$work/test_psl.txt")"
if [ "$rules" -lt 5000 ] || [ "$cases" -lt 1 ]; then
  echo "update-psl: the download looks wrong ($rules rules, $cases test cases); nothing was replaced" >&2
  exit 1
fi

# Stage both next to their targets, then rename (atomic on one file system).
cp "$work/snapshot.dat" "$new_out"
cp "$work/test_psl.txt" "$new_test"
mv -f "$new_out" "$out"
mv -f "$new_test" "$test_out"

echo "snapshot:  $out ($(wc -c < "$out") bytes, $rules rules), commit $commit"
echo "test file: $test_out, sha256 $(sha256sum "$test_out" | cut -d' ' -f1), $cases cases (the test expects the number in tests/origin.rs)"
