# Constant-time triage

Plan section 10 point 3. `ct/run.sh analyze` runs the Trail of Bits
`ct_analyzer` (`--warnings`) on every file in `ct/harness/`, for `x86_64` and
`arm64` at `O0`, `O2`, `O3` and `Os`: 5 files, 2 architectures, 4 levels, 40
reports. The analyzer has no data flow analysis. It reports every variable-time
instruction (division, and with `--warnings` every conditional branch) whether
or not a secret reaches it, so the reports are a worklist. This file is the
result of working through it: for each finding, whether an operand can depend
on a secret, and why.

`ct/check-triage.mjs` (the test `ct_analyzer_clean_or_triaged`) fails if a
finding in any of the 40 reports has no row in the `triage` block below, if a
row has no section here, or if a report has fewer functions than the file has
public functions (a clean report of nothing, see F-2).

Tool versions: analyzer from `trailofbits/skills` at the commit in
`ct/analyzer.pin` (checked against SHA-256), `rustc 1.99.1`, targets
`x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu`, run in the
builder image on the LANBox (`scripts/lanbox-ct.sh analyze`).

## What was found and fixed

### F-1. `ct_select_bytes` read only one of its two sources

At `O2` on x86_64 LLVM saw that the mask `0u8.wrapping_sub(flag & 1)` is
either all ones or all zeros, and turned `(a & mask) | (b & !mask)` into a
`cmov` that chooses the source *pointer* (`test dil, 1; cmove r8, rcx`) and
copies from it. The result is right, but only one of `a` and `b` is read, so
the flag shows in which memory is touched. The analyzer does not report a
`cmov` (it is not a branch), so this was found by reading the assembly of every
function that selects. Fixed: the mask goes through `core::hint::black_box`,
the same barrier `subtle` uses; the new `O2` output ands and ors both sources
in vector registers. `ct_select` is reserved for callers that need a masked
choice (nothing in the core calls it yet).

### F-2. The first run of the analyzer looked at nothing

`unpad.rs` reported `0 functions, 0 findings` at `O2` and `O3`. Since Rust 1.75
rustc leaves a small function out of the compiled library when nothing in the
file calls it (it is "cross-crate inlinable"), so there was nothing to analyze,
and `Result: PASSED` meant nothing. Fixed: every public function in the harness
files is `#[inline(never)]`, so each one is a function of its own in the
analyzer's input and in the core. As a side effect the analyzed body is the
body that is shipped, not a body that the optimizer may have merged into a
caller. `check-triage.mjs` now fails on a report with too few functions.

### F-3. Base32 was not in the analyzed code

`totp.rs` had its own copy of the table-free base32 reading (written for Task
11), outside `ct/harness/`. It is now `ct/harness/base32.rs`, included by
`totp.rs`, analyzed with the rest and timed (`base32_decode`).

### F-4. `commit_eq` and `mac_eq`

The core compared the key commitment and the row tag with the general `ct_eq`.
They now call `commit_eq` and `mac_eq` (32 bytes each, the same body), in
`ct/harness/ct_eq.rs` with `ct_eq`. `ct_eq.rs` needs `subtle`, so the analyzer
gets it with `--extern` (built with the release settings, so no
`debug_assert` of `subtle` is in the output).

## Triage

```triage
# id @ file @ function (regex on the demangled path) @ mnemonic @ severity
T1 @ crockford @ ^crockford::(decode_symbols|encode_symbols)$ @ .* @ warning
T2 @ base32 @ ^base32::decode_letters$ @ .* @ warning
T3 @ unpad @ ^unpad::unpad_scan$ @ .* @ warning
T4 @ ct_eq @ ^ct_eq::(ct_eq|mac_eq|commit_eq)$ @ .* @ warning
T5 @ ct_select @ ^ct_select::ct_select_bytes$ @ .* @ warning
T6 @ .* @ (Iterator|DoubleEndedIterator)::(next|next_back|size_hint)|zip::.*::next @ .* @ warning|error
T7 @ .* @ precondition_check @ .* @ warning
T8 @ .* @ ^core::(option::|cmp::Ord::min|ptr::const_ptr::is_aligned_to) @ .* @ warning
```

```coverage
# file @ at least this many functions in every report (the public functions)
base32 @ 2
crockford @ 5
ct_eq @ 3
ct_select @ 4
unpad @ 1
```

How the table was made. For `decode_symbols`, `unpad_scan`, `decode_letters`,
`ct_eq`, `mac_eq` and `ct_select_bytes` the whole `x86_64` `O2` output was
read, and the conditional branches of `decode_symbols` were listed with the two
instructions before each on `arm64` `O2` and `x86_64` `O0`. The other
configurations were checked for the same shape: every branch target is a loop
head or exit, a slice-length test or the test of a counter that is derived from
a length. That is a reading, not a proof; the timing runs (`dudect`, report)
are the independent evidence. Findings that are the same in all configurations
share a row.

### T1. `crockford::decode_symbols`, `encode_symbols`: conditional branches

Operand: public. The branches are the loop over the symbols (the length is
public), the test `symbols.len() == 0`, `bits >= 8` (a counter that moves by
5 per symbol, so it is a function of the position), and `slots.next()` (is
there still an output byte: a function of the position). The values of the
symbols only meet `normalize_byte`, `decode_symbol` and `encode_symbol`, which
have no conditional branch in any configuration (they are not in the
reports): their comparisons are `wrapping_sub` and a shift of the sign bit,
combined with `&` and `*`. `all_valid` is accumulated with `&` and returned,
and the caller tests it after the loop, which is the same for every input of
the same length. The analyzer reports no division.

### T2. `base32::decode_letters`: conditional branches

Operand: public, for the same reason as T1: the loop, the counter `bits >= 8`
and the output slot. `symbol` has no branch in any configuration.

### T3. `unpad::unpad_scan`: conditional branches

Operand: public. The loop runs `padded.len()` times from the back (the one
`jb`/`b.ne` of the back edge, the one `je`/`cbz` for an empty buffer). The
update of `at` is `(index & mask) | (at & !mask)` with a mask made from `hit`;
on x86_64 LLVM turns it into `cmovne` (a data-independent select, not a
branch; see R5). The marker position and the contents of the buffer reach only
masks, `or` and `and`.

### T4. `ct_eq::ct_eq`, `mac_eq`, `commit_eq`: conditional branches

Operand: public. `ct_eq` tests the two lengths first (public) and loops over
the bytes; `mac_eq` and `commit_eq` have the length 32 fixed and loop over it.
The bytes are only xor-ed and combined with `&`, through `subtle`'s
`black_box`. The same loop and length test are in `subtle`'s own generic code
when it is not inlined (`O0`, `Os`). `ct_eq.rs` is analyzed against the
release build of `subtle`, which has no `debug_assert` on `Choice::from`; an
earlier run against a debug build showed `cmp al, 2; jae panic`, a branch on
the result of the comparison that is never taken and does not exist in the
shipped code.

### T5. `ct_select::ct_select_bytes`: conditional branches

Operand: public. After F-1 the branches are the length tests of the unrolled
and vectorized loops (`cmp rax, 8`, `cmp rax, 32`, the remainder loop), all on
`min(a.len(), b.len(), out.len())`. The flag only enters as the mask.

### T6. Slice iterators in `core` (`Iterator::next`, `next_back`, `size_hint`, `Zip`)

Operand: public: pointers and lengths of slices. At `O0` and sometimes at `Os`
the iterator helpers of `core` are separate functions, with a branch on the
end of the iteration. The one `error` finding in the 40 reports is a `UDIV` in
`size_hint`, which divides a pointer difference by the element size (1 for
`u8`, but not folded at `O0`); both operands are lengths. It is `arm64` `O0`
for `ct_eq` and `ct_select`, and the other configurations do not contain it.

### T7. `precondition_check` of `core` (`unchecked_shl`, `unchecked_shr`, `unchecked_neg`, `read_volatile`, `offset_from_unsigned`)

Operand: public. These are the debug-time checks that the standard library
inlines at `O0`: the shift count (`bits`, a function of the position), the
alignment and non-overlap of the pointers of a slice. They do not exist at
`O2` and above.

### T8. `core::option::{copied, unwrap_or}`, `cmp::Ord::min`, `ptr::is_aligned_to`

Operand: public: the `Option` of a slice iterator (is there another element),
`min` of two slice lengths, and the alignment test of a pointer.

## Residual risks that this analysis does not remove

These are not findings of the analyzer on the harness. They are the things the
WebAssembly scan (`ct/wasm-allow.toml`) and the reading of the code showed to
be variable time on a secret, or that no tool here can see. Each is accepted
with its reason, and each is repeated in the report.

- **R1. Unicode normalization of the master password.** `normalize_password`
  uses the tables of `unicode-normalization` and `unicode-general-category`.
  Lookups and branches are keyed by the characters of the password; the
  characters are the secret, the length is not. There is no table-free NFKD,
  and the result must equal other implementations byte for byte. It runs once
  per unlock in the user's own worker, so the observer would have to share the
  device. Accepted.
- **R2. TOTP code.** `totp_code` takes the dynamic truncation of the HMAC
  output modulo 10^digits. The dividend is the HMAC output of this one code,
  not the TOTP secret, and the code is shown to the user and sent to a server.
  RFC 4226 section 5.3. Accepted.
- **R3. Text handling of an otpauth URI.** The URI holds the TOTP secret. The
  glue (`normalize_otpauth`) and the parser (`parse_otpauth`, percent-decoding)
  read it as text with ordinary string functions. The secret is a JavaScript
  string before it reaches the core, and a JavaScript string can neither be
  wiped nor read in constant time (Task 12 review). The letters themselves go
  through `base32.rs`. Accepted.
- **R4. The decrypted item body.** CBOR decoding, the views, the plaintext
  export and the UTF-8 check of `core::str` branch on the structure and on the
  bytes of what the AEAD has already accepted, in the user's own worker. The
  bytes of a password or a note are copied, not used as an address. Accepted.
- **R5. `cmov`.** LLVM may compile the masked selects to `cmov` (`unpad_scan`
  on x86_64 does) or `csel` (arm64). Both are constant time on current x86_64
  and arm64 cores, apart from the data-independent-timing caveats of the
  vendors (Intel DOIT, Arm DIT), which a WebAssembly module cannot set.
  Accepted.
- **R6. Third-party code.** `argon2` and the RustCrypto crates are not
  re-verified (plan section 10 point 6). Argon2id has memory access that
  depends on the data in the second half of each pass, by design. The WASM scan
  counts what is in the other crates and does not gate it.
- **R7. What `dudect` can and cannot say.** It is statistical evidence for the
  inputs it uses, on one CPU, with the timer of the platform. It does not prove
  the absence of a leak, and it cannot see a leak much smaller than the noise.
  `kek_pw_commit_path` compares a commitment that is wrong in the first byte
  with one that is wrong in the last; a wrong commitment against a right one
  differs by the AEAD that is skipped, by design (Fase 1 section 4.3,
  `info_unwrap_valid_vs_bad_commit`).
