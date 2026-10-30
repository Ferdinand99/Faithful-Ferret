#!/usr/bin/env bash
# Fetches the pinned ct_analyzer into <dir>/ct_analyzer (ct/analyzer.pin) and
# prints the path of analyzer.py. The builder image has it already in
# /opt/ct-analyzer; this is for CI.
#
#   CT_ANALYZER="$(ct/fetch-analyzer.sh "$RUNNER_TEMP/ct-analyzer")"
set -euo pipefail
cd "$(dirname "$0")/.."
dest="${1:?usage: fetch-analyzer.sh <dir>}"
repo="$(sed -n 's/^repository=//p' ct/analyzer.pin)"
commit="$(sed -n 's/^commit=//p' ct/analyzer.pin)"
path="$(sed -n 's/^path=//p' ct/analyzer.pin)"
mkdir -p "$dest/ct_analyzer"
sed -n 's/^sha256 \([^=]*\)=\(.*\)$/\1 \2/p' ct/analyzer.pin | while read -r file sum; do
  curl -fsSL -o "$dest/ct_analyzer/$file" "https://raw.githubusercontent.com/$repo/$commit/$path/$file"
  echo "$sum  $dest/ct_analyzer/$file" | sha256sum -c - >&2
done
echo "$dest/ct_analyzer/analyzer.py"
