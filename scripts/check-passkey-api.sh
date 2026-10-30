#!/usr/bin/env bash
# No public item of the passkey module may return the PKCS#8 private key or a
# PRF seed as bytes (Fase 1 section 9.1: the key is used only in the core and
# leaves it only inside a sealed envelope, see `seal_passkey_item`).
#
# A grep over every .rs file of crates/ferret-core/src/passkey/ (mod.rs
# included). "Public" means a `pub fn`, with or without `const`, `unsafe`,
# `async` or `extern "C"` in front, and also every `fn` inside an
# `impl Trait for Type` block, because a trait method is as public as the
# trait. `pub(crate)` and private functions are not part of the surface.
#
#  1. a public function whose name mentions the key or a seed, or is `to_item`,
#     `der` or `from_pkcs8_der`, fails;
#  2. a public function that returns `Vec<u8>`, `[u8; N]` or `&[u8]` (also
#     inside `Option`, `Result` or `Zeroizing`) fails, apart from the reviewed
#     list below;
#  3. a public field of such a byte type whose name mentions the key or a
#     seed fails;
#  4. the crate root must not re-export `to_item` or `from_pkcs8_der`, and the
#     two accessors must stay crate-private.
#
# The reviewed list: `prf_salt` (a public hash), `hash` (the SHA-256 of a
# canonical origin, public), `PrfResults::reveal_first` and `reveal_second`
# (the PRF outputs that go to the page, by design).
#
# `scripts/check-passkey-api.sh --self-test` runs the checks on small samples
# that must fail, so a change to the patterns that makes them blind is noticed.
set -euo pipefail
cd "$(dirname "$0")/.."

allowed='prf_salt|hash|reveal_first|reveal_second'
bytes_ty='Vec<u8>|\[u8; ?[0-9A-Za-z_]+\]|&(.*)?\[u8\]'
name_re='[a-z_0-9]*(pkcs8|priv|seed|to_item|secret)[a-z_0-9]*|der'

# Public function signatures of the given files, one line each:
# "file: pub fn name(...) -> ret". A function of a trait impl is printed as if
# it were `pub fn`.
signatures() {
  awk '
    function brace_delta(s,   t, o, c) {
      t = s; o = gsub(/\{/, "", t); t = s; c = gsub(/\}/, "", t); return o - c
    }
    FNR == 1 { in_impl = 0; depth = 0 }
    {
      line = $0
      if (!in_impl && line ~ /^[[:space:]]*(unsafe[[:space:]]+)?impl[^{;]*[[:space:]]for[[:space:]]/) {
        in_impl = 1; depth = 0
        depth += brace_delta(line)
        next
      }
      if (in_impl) {
        is_fn = (line ~ /^[[:space:]]*((const|unsafe|async|extern[[:space:]]+"[^"]*")[[:space:]]+)*fn[[:space:]]/)
        if (is_fn) {
          sig = line
          sub(/^[[:space:]]*/, "", sig)
          while (sig !~ /[{;][[:space:]]*$/ && (getline more) > 0) sig = sig " " more
          print FILENAME ": pub " sig
          depth += brace_delta(sig)
          if (depth <= 0) in_impl = 0
          next
        }
        depth += brace_delta(line)
        if (depth <= 0) in_impl = 0
        next
      }
      if (line ~ /^[[:space:]]*pub[[:space:]]+((const|unsafe|async|extern[[:space:]]+"[^"]*")[[:space:]]+)*fn[[:space:]]/) {
        sig = line
        sub(/^[[:space:]]*/, "", sig)
        while (sig !~ /[{;][[:space:]]*$/ && (getline more) > 0) sig = sig " " more
        print FILENAME ": " sig
      }
    }
  ' "$@"
}

# Prints the offending lines of a check and returns 1 if there are any.
check_files() {
  local status=0 sigs
  sigs="$(signatures "$@")"

  if printf '%s\n' "$sigs" | grep -Ei "pub (const |unsafe |async |extern \"[^\"]*\" )*fn ($name_re)\b"; then
    echo "FAIL: a public passkey function handles the private key or a seed (above)" >&2
    status=1
  fi

  if printf '%s\n' "$sigs" | grep -E -- "->.*($bytes_ty)" \
     | grep -Ev "fn ($allowed)\b"; then
    echo "FAIL: a public passkey function returns bytes (above); review it and, if it is safe, add it to the list in this script" >&2
    status=1
  fi

  if grep -nE "^[[:space:]]*pub[[:space:]]+[a-z_0-9]*(pkcs8|priv|seed|secret)[a-z_0-9]*:[^,]*($bytes_ty)" "$@" \
     | grep -Ev ': *bool'; then
    echo "FAIL: a public field holds key or seed bytes (above)" >&2
    status=1
  fi
  return "$status"
}

if [ "${1:-}" = --self-test ]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  n=0
  expect_fail() {
    n=$((n + 1))
    printf '%s\n' "$2" > "$tmp/case$n.rs"
    if check_files "$tmp/case$n.rs" >/dev/null 2>&1; then
      echo "self-test FAILED: '$1' was not caught" >&2
      exit 1
    fi
  }
  expect_fail "plain pub fn returning a key" 'pub fn private_key(&self) -> Vec<u8> { todo!() }'
  expect_fail "pub const fn returning bytes" 'pub const fn raw(&self) -> [u8; 32] { [0; 32] }'
  expect_fail "pub unsafe fn returning bytes" 'pub unsafe fn raw(&self) -> &[u8] { &[] }'
  expect_fail "a multi-line signature" $'pub fn bytes(\n    &self,\n) -> Result<Vec<u8>, Error> {\n}'
  expect_fail "a trait method returning bytes" $'impl AsRef<[u8]> for Thing {\n    fn as_ref(&self) -> &[u8] {\n        &self.0\n    }\n}'
  expect_fail "a trait method named after the seed" $'impl Thing for Other {\n    fn seed(&self) -> u8 { 0 }\n}'
  expect_fail "a public field with the key" $'pub struct S {\n    pub priv_pkcs8: Vec<u8>,\n}'
  # These must pass.
  printf '%s\n' $'pub(crate) fn private_key(&self) -> Vec<u8> { todo!() }\nfn seed() -> Vec<u8> { todo!() }\nimpl Display for X {\n    fn fmt(&self, f: &mut F) -> Result { Ok(()) }\n}\npub fn prf_salt(i: &[u8]) -> [u8; 32] { [0; 32] }' > "$tmp/ok.rs"
  check_files "$tmp/ok.rs" >/dev/null 2>&1 || { echo "self-test FAILED: a clean sample was refused" >&2; exit 1; }
  echo "ok: the passkey API check catches $n samples and passes a clean one"
  exit 0
fi

dir=crates/ferret-core/src/passkey
fail=0

check_files "$dir"/*.rs || fail=1

if grep -nE 'to_item|from_pkcs8_der' crates/ferret-core/src/lib.rs; then
  echo "FAIL: lib.rs re-exports key material accessors" >&2
  fail=1
fi

# The accessors themselves must stay crate-private.
for f in to_item from_pkcs8_der; do
  if grep -nE "^[[:space:]]*pub[[:space:]]+((const|unsafe|async)[[:space:]]+)*fn $f\b" "$dir"/*.rs; then
    echo "FAIL: $f is public" >&2
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  exit 1
fi
echo "ok: the public passkey API returns no PKCS#8 or PRF seed bytes"
