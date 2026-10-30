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
row has no section here, or if the numbers in the `counts` block change. That
block pins, for every file, architecture and level, how many functions the
analyzer looked at and how many findings each row covers. A new branch in a
function that is already triaged is a new finding even though its row would
cover it; a report with fewer functions than the file has public functions is
a clean report of nothing (F-2). After a change has been looked at, the block
is regenerated with `node ct/check-triage.mjs ct/results/analyzer ct/TRIAGE.md
--write-counts`.

Tool versions: analyzer from `trailofbits/skills` at the commit in
`ct/analyzer.pin` (checked against SHA-256), `rustc 1.99.1` (the image build
stops if the toolchain is another), targets `x86_64-unknown-linux-gnu` and
`aarch64-unknown-linux-gnu`, `-C overflow-checks=on` as in the release profile
that is shipped (its `subtle` is built the same way), run in the builder image
on the LANBox (`scripts/lanbox-ct.sh analyze`).

## What was found and fixed

### F-1. `ct_select_bytes` read only one of its two sources

At `O2` on x86_64 LLVM saw that the mask `0u8.wrapping_sub(flag & 1)` is
either all ones or all zeros, and turned `(a & mask) | (b & !mask)` into a
`cmov` that chooses the source *pointer* (`test dil, 1; cmove r8, rcx`) and
copies from it. The result is right, but only one of `a` and `b` is read, so
the flag shows in which memory is touched. The analyzer does not report a
`cmov` (it is not a branch), so this was found by reading the assembly of every
function that selects.

First fix: the mask went through `core::hint::black_box`. That worked on the
compiler at hand, but `black_box` is best effort (its documentation says it
gives no guarantee for cryptographic purposes), and the first text called it
"the same barrier `subtle` uses", which it is not. Fix of the review round: the
select is now `subtle::ConditionallySelectable` on a `subtle::Choice`. The
barrier of `subtle` (which the rest of the core already relies on for every
comparison) is a `#[inline(never)]` function that stores the value on the stack
and reads it back with a volatile read; the optimizer cannot see through it.
That is still a property of today's compiler and not of the language, so
`ct/run.sh select-asm` compiles `ct_select_bytes` at O2, O3 and Os for x86_64
and arm64 and fails if the function has an instruction that tests bit 0 of the
flag, or more than the two conditional moves that the `min`s of the slice
lengths need (the pointer-selecting version had 6 at O2 and 3 at Os on x86_64;
the check was tried on it and fails). `ct_select` is reserved for callers that
need a masked choice (nothing in the core calls it yet).

### F-2. The first run of the analyzer looked at nothing

`unpad.rs` reported `0 functions, 0 findings` at `O2` and `O3`. Since Rust 1.75
rustc leaves a small function out of the compiled library when nothing in the
file calls it (it is "cross-crate inlinable"), so there was nothing to analyze,
and `Result: PASSED` meant nothing. Fixed: every public function in the harness
files is `#[inline(never)]`, so each one is a function of its own in the
analyzer's input and in the core. As a side effect the analyzed body is the
body that is shipped, not a body that the optimizer may have merged into a
caller. The pinned `functions=` numbers of the `counts` block fail on a report
with fewer or more functions.

### F-3. Base32 was not in the analyzed code

`totp.rs` had its own copy of the table-free base32 reading (written for Task
11), outside `ct/harness/`. It is now `ct/harness/base32.rs`, included by
`totp.rs`, analyzed with the rest and timed (`base32_decode`).

### F-4. `commit_eq` and `mac_eq`

The core compared the key commitment and the row tag with the general `ct_eq`.
They now call `commit_eq` and `mac_eq` (32 bytes each, the same body), in
`ct/harness/ct_eq.rs` with `ct_eq`. `ct_eq.rs` needs `subtle`, so the analyzer
gets it with `--extern` (built with the release settings, so no
`debug_assert` of `subtle` is in the output). The checkpoint MAC and digest
use `mac_eq` too; the secret key confirmation in `account.rs` still calls
`subtle` directly (same body, same `subtle`, so the results carry over).

## Triage

```triage
# id @ file @ function (regex on the demangled path) @ mnemonic @ severity
T1 @ crockford @ ^crockford::decode_symbols$ @ .* @ warning
T2 @ crockford @ ^crockford::encode_symbols$ @ .* @ warning
T3 @ base32 @ ^base32::decode_letters$ @ .* @ warning
T4 @ unpad @ ^unpad::unpad_scan$ @ .* @ warning
T5 @ ct_eq @ ^ct_eq::ct_eq$ @ .* @ warning
T6 @ ct_eq @ ^ct_eq::(mac_eq|commit_eq)$ @ .* @ warning
T7 @ ct_select @ ^ct_select::ct_select_bytes$ @ .* @ warning
T8 @ .* @ (Iterator|DoubleEndedIterator)::(next|next_back|size_hint)|zip::.*::next @ .* @ warning|error
T9 @ .* @ precondition_check @ .* @ warning
T10 @ .* @ ^core::(option::|cmp::Ord::min|ptr::const_ptr::is_aligned_to) @ .* @ warning
T11 @ ct_select @ ^(ct_select::ct_select_u8|subtle::.*conditional_select.*)$ @ .* @ warning
```

```counts
# file @ arch @ opt @ functions analysed, findings per row
base32__arm64__O0.json       functions  18  errors 0  warnings 4
base32__arm64__O2.json       functions   4  errors 0  warnings 4
base32__arm64__O3.json       functions   4  errors 0  warnings 4
base32__arm64__Os.json       functions   4  errors 0  warnings 4
base32__x86_64__O0.json      functions  18  errors 0  warnings 7
base32__x86_64__O2.json      functions   4  errors 0  warnings 4
base32__x86_64__O3.json      functions   4  errors 0  warnings 4
base32__x86_64__Os.json      functions   4  errors 0  warnings 4
crockford__arm64__O0.json    functions  34  errors 0  warnings 7
crockford__arm64__O2.json    functions  10  errors 0  warnings 8
crockford__arm64__O3.json    functions  10  errors 0  warnings 9
crockford__arm64__Os.json    functions  10  errors 0  warnings 8
crockford__x86_64__O0.json   functions  34  errors 0  warnings 11
crockford__x86_64__O2.json   functions  10  errors 0  warnings 8
crockford__x86_64__O3.json   functions  10  errors 0  warnings 8
crockford__x86_64__Os.json   functions  10  errors 0  warnings 8
ct_eq__arm64__O0.json        functions  55  errors 1  warnings 4
ct_eq__arm64__O2.json        functions   7  errors 0  warnings 4
ct_eq__arm64__O3.json        functions   7  errors 0  warnings 4
ct_eq__arm64__Os.json        functions  11  errors 0  warnings 4
ct_eq__x86_64__O0.json       functions  55  errors 0  warnings 7
ct_eq__x86_64__O2.json       functions   7  errors 0  warnings 4
ct_eq__x86_64__O3.json       functions   7  errors 0  warnings 4
ct_eq__x86_64__Os.json       functions  11  errors 0  warnings 4
ct_select__arm64__O0.json    functions  87  errors 2  warnings 6
ct_select__arm64__O2.json    functions  10  errors 0  warnings 9
ct_select__arm64__O3.json    functions  10  errors 0  warnings 9
ct_select__arm64__Os.json    functions  19  errors 0  warnings 4
ct_select__x86_64__O0.json   functions  87  errors 0  warnings 9
ct_select__x86_64__O2.json   functions  10  errors 0  warnings 10
ct_select__x86_64__O3.json   functions  10  errors 0  warnings 10
ct_select__x86_64__Os.json   functions  19  errors 0  warnings 4
unpad__arm64__O0.json        functions  20  errors 0  warnings 3
unpad__arm64__O2.json        functions   2  errors 0  warnings 2
unpad__arm64__O3.json        functions   2  errors 0  warnings 2
unpad__arm64__Os.json        functions   2  errors 0  warnings 2
unpad__x86_64__O0.json       functions  20  errors 0  warnings 4
unpad__x86_64__O2.json       functions   2  errors 0  warnings 2
unpad__x86_64__O3.json       functions   2  errors 0  warnings 2
unpad__x86_64__Os.json       functions   2  errors 0  warnings 2
base32 @ arm64 @ O0 @ T3=2 T8=2 functions=18
base32 @ arm64 @ O2 @ T3=4 functions=4
base32 @ arm64 @ O3 @ T3=4 functions=4
base32 @ arm64 @ Os @ T3=4 functions=4
base32 @ x86_64 @ O0 @ T3=3 T8=2 T9=2 functions=18
base32 @ x86_64 @ O2 @ T3=4 functions=4
base32 @ x86_64 @ O3 @ T3=4 functions=4
base32 @ x86_64 @ Os @ T3=4 functions=4
crockford @ arm64 @ O0 @ T10=2 T1=2 T2=1 T8=2 functions=34
crockford @ arm64 @ O2 @ T1=4 T2=4 functions=10
crockford @ arm64 @ O3 @ T1=5 T2=4 functions=10
crockford @ arm64 @ Os @ T1=4 T2=4 functions=10
crockford @ x86_64 @ O0 @ T10=2 T1=3 T2=2 T8=2 T9=2 functions=34
crockford @ x86_64 @ O2 @ T1=4 T2=4 functions=10
crockford @ x86_64 @ O3 @ T1=4 T2=4 functions=10
crockford @ x86_64 @ Os @ T1=4 T2=4 functions=10
ct_eq @ arm64 @ O0 @ T10=1 T5=2 T8=1 T9=1 functions=55
ct_eq @ arm64 @ O2 @ T5=3 T6=1 functions=7
ct_eq @ arm64 @ O3 @ T5=3 T6=1 functions=7
ct_eq @ arm64 @ Os @ T5=3 T6=1 functions=11
ct_eq @ x86_64 @ O0 @ T10=2 T5=2 T8=1 T9=2 functions=55
ct_eq @ x86_64 @ O2 @ T5=3 T6=1 functions=7
ct_eq @ x86_64 @ O3 @ T5=3 T6=1 functions=7
ct_eq @ x86_64 @ Os @ T5=3 T6=1 functions=11
ct_select @ arm64 @ O0 @ T10=1 T11=3 T7=1 T8=2 T9=1 functions=87
ct_select @ arm64 @ O2 @ T11=1 T7=8 functions=10
ct_select @ arm64 @ O3 @ T11=1 T7=8 functions=10
ct_select @ arm64 @ Os @ T11=1 T7=3 functions=19
ct_select @ x86_64 @ O0 @ T10=2 T11=3 T7=1 T8=1 T9=2 functions=87
ct_select @ x86_64 @ O2 @ T11=1 T7=9 functions=10
ct_select @ x86_64 @ O3 @ T11=1 T7=9 functions=10
ct_select @ x86_64 @ Os @ T11=1 T7=3 functions=19
unpad @ arm64 @ O0 @ T4=1 T8=1 T9=1 functions=20
unpad @ arm64 @ O2 @ T4=2 functions=2
unpad @ arm64 @ O3 @ T4=2 functions=2
unpad @ arm64 @ Os @ T4=2 functions=2
unpad @ x86_64 @ O0 @ T4=1 T8=1 T9=2 functions=20
unpad @ x86_64 @ O2 @ T4=2 functions=2
unpad @ x86_64 @ O3 @ T4=2 functions=2
unpad @ x86_64 @ Os @ T4=2 functions=2
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

### T1. `crockford::decode_symbols`: conditional branches

Operand: public. The branches are the loop over the symbols (the length is
public), the test `symbols.len() == 0`, `bits >= 8` (a counter that moves by
5 per symbol, so it is a function of the position), and `slots.next()` (is
there still an output byte: a function of the position). The values of the
symbols only meet `normalize_byte` and `decode_symbol`, which have no
conditional branch in any configuration (they are not in the reports): their
comparisons are `wrapping_sub` and a shift of the sign bit, combined with `&`
and `*`. `all_valid` is accumulated with `&` and returned, and the caller
tests it after the loop, which is the same for every input of the same length.
The analyzer reports no division.

### T2. `crockford::encode_symbols`: conditional branches

Operand: public, as T1: the loop over the output symbols, the byte counter and
the refill of the accumulator, which depend on the position only. The bits of
the data meet `encode_symbol` (no branch in any configuration).

### T3. `base32::decode_letters`: conditional branches

Operand: public, for the same reason as T1: the loop, the counter `bits >= 8`
and the output slot. `symbol` has no branch in any configuration.

### T4. `unpad::unpad_scan`: conditional branches

Operand: public. The loop runs `padded.len()` times from the back (the one
`jb`/`b.ne` of the back edge, the one `je`/`cbz` for an empty buffer). The
update of `at` is `(index & mask) | (at & !mask)` with a mask made from `hit`;
on x86_64 LLVM turns it into `cmovne` (a data-independent select, not a
branch; see R5). The marker position and the contents of the buffer reach only
masks, `or` and `and`. The pinned counts are what would show a `cmov` that
turned into a branch: it would be one more finding in this function.

### T5. `ct_eq::ct_eq`: conditional branches

Operand: public. It tests the two lengths first (public) and loops over the
bytes, which are only xor-ed and combined with `&` through `subtle`'s barrier.
The same loop and length test are in `subtle`'s own generic code when it is not
inlined (`O0`, `Os`). `ct_eq.rs` is analyzed against the release build of
`subtle`, which has no `debug_assert` on `Choice::from`; an earlier run against
a debug build showed `cmp al, 2; jae panic`, a branch on the result of the
comparison that is never taken and does not exist in the shipped code.

### T6. `ct_eq::mac_eq` (`commit_eq` is the same body): conditional branches

Operand: public: the length is the constant 32, so only the loop's back edge
is left. The bytes are combined as in T5.

### T7. `ct_select::ct_select_bytes`: conditional branches

Operand: public. The branches are the length tests of the unrolled and
vectorized loops (`cmp rax, 8`, `cmp rax, 32`, the remainder loop), all on
`min(a.len(), b.len(), out.len())`. The flag only enters as `Choice`, behind
the barrier of `subtle` (F-1, and `ct/run.sh select-asm`).

### T8. Slice iterators in `core` (`Iterator::next`, `next_back`, `size_hint`, `Zip`)

Operand: public: pointers and lengths of slices. At `O0` and sometimes at `Os`
the iterator helpers of `core` are separate functions, with a branch on the
end of the iteration. The three `error` findings in the 40 reports are a
`UDIV` in `size_hint`, which divides a pointer difference by the element size
(1 for `u8`, but not folded at `O0`); both operands are lengths. They are
`arm64` `O0` for `ct_eq` and `ct_select`.

### T9. `precondition_check` of `core` (`unchecked_shl`, `unchecked_shr`, `unchecked_neg`, `read_volatile`, `offset_from_unsigned`)

Operand: public. These are the debug-time checks that the standard library
inlines at `O0`: the shift count (`bits`, a function of the position), the
alignment and non-overlap of the pointers of a slice, the alignment of the
stack slot of `subtle`'s barrier. They do not exist at `O2` and above.

### T10. `core::option::{copied, unwrap_or}`, `cmp::Ord::min`, `ptr::is_aligned_to`

Operand: public: the `Option` of a slice iterator (is there another element),
`min` of two slice lengths, and the alignment test of a pointer.

### T11. The overflow check on the mask of `subtle::ConditionallySelectable` for `u8`

Operand: a `Choice`, which is 0 or 1. `u8::conditional_select` negates the
choice as an `i8` (`-(choice as i8)`), and with overflow checks on (as in the
shipped release profile) that is a compare of the byte with `0x80` and a branch
to the panic. The value is never `0x80`, so the branch goes the same way for
every flag and every pair of values. It is in `subtle::...::conditional_select`
at `O0` and inlined into `ct_select_u8` at `O2` and above; the `u32` and `u64`
versions widen the byte first and have no such check.

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
- **R5. `cmov`.** LLVM compiles several of the masked computations to `cmov`
  (x86_64) or `csel` (arm64), and the analyzer does not report them because
  they are not branches. On the secret itself: `setcc` followed by `cmov` on
  the letter in `base32::symbol` (4 `cmov`), `crockford::decode_symbol` (6) and
  `normalize_byte` (3); `cmovne` on the marker flag in `unpad_scan`; the
  `min`s of the slice lengths (public) in `ct_select_bytes`. All are constant
  time on current x86_64 (`cmov` is on Intel's list of instructions with
  data-operand-independent timing) and arm64 (`csel`), apart from the
  caveats of the vendors (Intel DOIT, Arm DIT), which a WebAssembly module
  cannot set. In WebAssembly the engine decides what a `select` becomes.
  Accepted.
- **R6. Third-party code.** `argon2` and the RustCrypto crates are not
  re-verified (plan section 10 point 6). Argon2id has data-dependent memory
  addressing by design: RFC 9106 makes only the first half of the first pass
  data-independent (the first two of four slices); every later slice of every
  later pass, so most of the work at t = 3, is addressed by the data. The WASM scan
  counts what is in the other crates and does not gate it.
- **R7. What `dudect` can and cannot say.** It is statistical evidence for the
  inputs it uses, on one CPU, with the timer of the platform. It does not prove
  the absence of a leak, and it cannot see a leak much smaller than the noise.
  `kek_pw_commit_path` compares a commitment that is wrong in the first byte
  with one that is wrong in the last; a wrong commitment against a right one
  differs by the AEAD that is skipped, by design (Fase 1 section 4.3,
  `info_unwrap_valid_vs_bad_commit`). The rule: a gated bench with |t| >= 4.5 is
  measured again with ten times as many measurements and fails if that is still
  >= 4.5. Under the null hypothesis t does not shrink with more measurements, so
  the rerun is a fresh draw and not a stronger test of the first; a real
  difference grows with the square root of n. The setup is shown to see a leak
  by `control_leaky` (a 32-byte comparison) and `control_unpad_leaky` (a
  1024-byte scan); the sensitivity of the other targets, `kek_pw_commit_path`
  in particular, is not shown by a control of its own. In WebAssembly, targets
  of a few hundred nanoseconds are repeated eight times inside one measurement:
  with one repetition `base32_decode` gave |t| of 5 to 14 in some runs, with
  alternating sign, and even two fixed strings (`info_base32_a_vs_z`) gave 5 to
  7; with eight repetitions 24 runs of the bench and its three variants stayed
  below 4. In native, `unpad_ct` failed the gate (|t| of 7 to 22 at 10^6 and 26
  to 66 at 10^7, growing with n, so not noise) while the inputs of the zero
  class were `vec![0; n]`: `calloc` gives the shared zero page, so the source
  of the copy into the working cell was a different memory for that class. It is
  a flaw of the harness and not of `unpad_scan`: with pages of their own for the
  zero inputs the same bench, its content variant, a random-pair null and a
  same-input null all sit at 1 to 4. The lesson is the one the null controls
  teach; the controls of `unpad_scan` are `info_unpad_random_pair` and
  `info_unpad_same`.
- **R8. The accumulators are not wiped.** The harness is `core` only and has
  no `zeroize`, so the local `acc` of `base32::decode_letters` (up to 13 bits of
  the TOTP secret, which the old loop in `totp.rs` wiped with `acc.zeroize()`),
  of `crockford::decode_symbols` and `encode_symbols`, and the temporaries of
  `symbol` and `decode_symbol` stay in registers and in dead stack slots until
  they are overwritten. The wiped buffers (`Zeroizing`) are the callers'. Low;
  accepted.
- **R9. What the WebAssembly scan measures.** The scan reads the module at the
  optimisation level that is shipped (`wasm-bindgen`, then `wasm-opt -Oz` with
  the flags of `scripts/build-wasm.sh`, names kept with `-g`), and
  `ct/run.sh wasm-shipped` checks that it is the shipped module: the same bytes
  once the name section is removed from both. The timing module of `ct/dudect`
  is optimised the same way, but it is another module (the harness code, not
  the binding); its code for the harness functions is not byte-identical to the
  one in the binding, because `wasm-opt` inlines across `#[inline(never)]`.
