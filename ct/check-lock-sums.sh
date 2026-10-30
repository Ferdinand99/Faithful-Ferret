#!/usr/bin/env bash
# Every crate that both lock files have at the same name and version must have
# the same checksum in both (a different source or a re-published crate would
# have another).
#
#   ct/check-lock-sums.sh Cargo.lock ct/dudect/Cargo.lock
set -euo pipefail

sums() { awk '/^name = /{n=$3} /^version = /{v=$3} /^checksum = /{print n, v, $3}' "$1" | tr -d '"' | sort -u; }

changed="$(awk 'NR==FNR{ck[$1" "$2]=$3; next} ($1" "$2) in ck && ck[$1" "$2]!=$3 {print $1, $2}' \
  <(sums "$1") <(sums "$2"))"
if [ -n "$changed" ]; then
  echo "FAIL: these crates have another checksum in $2 than in $1:" >&2
  echo "$changed" >&2
  exit 1
fi
