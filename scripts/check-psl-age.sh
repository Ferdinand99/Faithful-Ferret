#!/usr/bin/env bash
# Fails when the embedded Public Suffix List snapshot is more than 90 days old
# (Fase 1 section 9.2). Run weekly and on release pull requests by
# .github/workflows/psl-age.yml; refresh with scripts/update-psl.sh.
set -euo pipefail
cd "$(dirname "$0")/.."

file=crates/ferret-core/src/passkey/public_suffix_list.dat
max_days=90

version="$(grep -E '^// VERSION: ' "$file" | head -n1 | cut -d' ' -f3)"
date_part="${version%%_*}"
if ! printf '%s' "$date_part" | grep -Eq '^[0-9]{4}-[0-9]{2}-[0-9]{2}$'; then
  echo "FAIL: no VERSION date in $file" >&2
  exit 1
fi

snapshot_s="$(date -u -d "$date_part" +%s)"
now_s="$(date -u +%s)"
age_days=$(( (now_s - snapshot_s) / 86400 ))
echo "Public Suffix List snapshot $date_part is $age_days days old (limit $max_days)"
if [ "$age_days" -gt "$max_days" ]; then
  echo "FAIL: run scripts/update-psl.sh and commit the new snapshot" >&2
  exit 1
fi
if [ "$age_days" -lt -1 ]; then
  echo "FAIL: the snapshot is dated in the future" >&2
  exit 1
fi
