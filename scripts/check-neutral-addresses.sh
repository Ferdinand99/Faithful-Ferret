#!/usr/bin/env bash
# The repository is public, so no tracked file may name the private test
# addresses of the people who work on it: a private LAN range or a private
# domain. The check fails when one of them appears again in a tracked file
# (lock files excluded).
#
# The values are not written out here, so that this file does not hold them
# itself: the pattern is put together from parts. FERRET_PRIVATE_PATTERN (an
# extended regular expression, matched without regard to case) replaces the
# built-in pattern, for a value that should be caught on one machine only.
# Anything in the private test stack that needs such a value reads it from the
# environment or from the untracked docker/.env instead.
#
#   scripts/check-neutral-addresses.sh               check the tracked files
#   scripts/check-neutral-addresses.sh --self-test   check the check on a throwaway repository
set -euo pipefail

range_a='10\.0'
sample_a='10.0'
range_b='\.3\.'
domain_a='op'
domain_b='land'
pattern="${FERRET_PRIVATE_PATTERN:-${range_a}${range_b}|${domain_a}${domain_b}}"

# Prints the offending lines of the tracked files of the repository in the
# current directory; exit status 0 when there is none.
scan() {
  local hits
  hits="$(git grep -n -I -i -E "$pattern" -- . ':!*.lock' ':!package-lock.json' || true)"
  if [ -n "$hits" ]; then
    printf '%s\n' "$hits" >&2
    return 1
  fi
}

if [ "${1:-}" = "--self-test" ]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  cd "$tmp"
  git init -q .
  git config user.email check@example.test
  git config user.name check
  printf '%s\n' 'host 192.0.2.10 and vault.example.test' > clean.txt
  git add clean.txt
  scan || { echo "check-neutral-addresses: self-test: a clean file was reported" >&2; exit 1; }
  printf '%s\n' "host ${sample_a}.3.7" > address.txt
  git add address.txt
  if scan 2>/dev/null; then echo "check-neutral-addresses: self-test: a private address was not found" >&2; exit 1; fi
  git rm -q -f address.txt
  printf '%s\n' "https://vault.${domain_a}${domain_b}.example" > domain.txt
  git add domain.txt
  if scan 2>/dev/null; then echo "check-neutral-addresses: self-test: a private domain was not found" >&2; exit 1; fi
  git rm -q -f domain.txt
  printf '%s\n' "host ${sample_a}.3.7" > Cargo.lock
  git add Cargo.lock
  scan || { echo "check-neutral-addresses: self-test: a lock file was reported" >&2; exit 1; }
  echo "check-neutral-addresses: self-test ok"
  exit 0
fi

cd "$(dirname "$0")/.."
if ! scan; then
  echo "check-neutral-addresses: the lines above name private test addresses; use a documentation address (192.0.2.0/24, 2001:db8::/32) or example.com / *.example.test, or read the value from the environment" >&2
  exit 1
fi
echo "check-neutral-addresses: ok"
