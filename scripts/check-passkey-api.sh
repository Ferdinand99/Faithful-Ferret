#!/usr/bin/env bash
# No public item of the passkey module may return the PKCS#8 private key or a
# PRF seed as bytes (Fase 1 section 9.1: the key is used only in the core and
# leaves it only inside a sealed envelope, see `seal_passkey_item`).
#
# A simple grep over the public API of crates/ferret-core/src/passkey/:
#  1. a `pub fn` (not `pub(crate)`) whose name mentions the key or a seed, or is
#     `to_item`, `der` or `from_pkcs8_der`, fails;
#  2. a `pub fn` that returns `Vec<u8>`, `[u8; 32]` or `&[u8]` and sits in
#     cose.rs or prf.rs, apart from the reviewed list below, fails;
#  3. the crate root must not re-export `to_item` or `from_pkcs8_der`.
#
# The reviewed list: `prf_salt` (a public hash), `PrfResults::reveal_first` and
# `reveal_second` (the PRF outputs that go to the page, by design).
set -euo pipefail
cd "$(dirname "$0")/.."

dir=crates/ferret-core/src/passkey
fail=0

# Public function signatures, joined to one line each (up to the opening brace).
sigs="$(awk '
  /^[[:space:]]*pub fn / { sig = $0; while (sig !~ /[{;][[:space:]]*$/ && (getline line) > 0) sig = sig " " line; print FILENAME ": " sig }
' "$dir"/*.rs)"

if printf '%s\n' "$sigs" | grep -Ei 'pub fn [a-z_0-9]*(pkcs8|priv|seed|to_item|secret)[a-z_0-9]*|pub fn der\b'; then
  echo "FAIL: a public passkey function handles the private key or a seed (above)" >&2
  fail=1
fi

allowed='prf_salt|reveal_first|reveal_second'
if printf '%s\n' "$sigs" | grep -E '/(cose|prf)\.rs: .*->.*(Vec<u8>|\[u8; ?32\]|&\[u8\])' \
   | grep -Ev "pub fn ($allowed)\b"; then
  echo "FAIL: a public function in cose.rs or prf.rs returns bytes (above); review it and, if it is safe, add it to the list in this script" >&2
  fail=1
fi

if grep -nE 'to_item|from_pkcs8_der' crates/ferret-core/src/lib.rs; then
  echo "FAIL: lib.rs re-exports key material accessors" >&2
  fail=1
fi

# The accessors themselves must stay crate-private.
for f in to_item from_pkcs8_der; do
  if grep -nE "^[[:space:]]*pub fn $f\b" "$dir"/*.rs; then
    echo "FAIL: $f is public" >&2
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  exit 1
fi
echo "ok: the public passkey API returns no PKCS#8 or PRF seed bytes"
