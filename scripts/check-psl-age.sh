#!/usr/bin/env bash
# Checks the age of the embedded Public Suffix List snapshot (Fase 1 section
# 9.2). Run weekly and on release pull requests by .github/workflows/psl-age.yml
# and by the release workflow; refresh with scripts/update-psl.sh.
#
#   up to 75 days   fine
#   76 to 90 days   a warning (an annotation on GitHub); the exit code is 0
#   over 90 days    fails
set -euo pipefail
cd "$(dirname "$0")/.."

file=crates/ferret-core/src/passkey/public_suffix_list.dat
warn_days=75
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
echo "Public Suffix List snapshot $date_part is $age_days days old (warning at $warn_days, limit $max_days)"
if [ "$age_days" -gt "$max_days" ]; then
  echo "FAIL: run scripts/update-psl.sh and commit the new snapshot" >&2
  exit 1
fi
if [ "$age_days" -lt -1 ]; then
  echo "FAIL: the snapshot is dated in the future" >&2
  exit 1
fi
if [ "$age_days" -gt "$warn_days" ]; then
  echo "::warning title=Public Suffix List snapshot is getting old::The snapshot is $age_days days old and the limit is $max_days. Run scripts/update-psl.sh before the next release."
fi
