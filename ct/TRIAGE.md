# Constant-time triage

`ct/run.sh analyze` runs the Trail of Bits
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
"the same barrier `subtle` uses", which it is not. The
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

`totp.rs` had its own copy of the table-free base32 reading (written separately),
outside `ct/harness/`. It is now `ct/harness/base32.rs`, included by
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

## Server library (`ferret-server-auth`)

The OPAQUE server library compares and selects with the same code as the core
and nothing else. `src/ct.rs` includes `ct/harness/ct_eq.rs` and
`ct/harness/ct_select.rs` by path, the files the analyzer reads
(`ct_include_is_the_analyzer_source` checks the include, in this crate and in
the core), so the 40 reports above, T5 to T7, T11 and the assembly check of
`ct_select_bytes` (`ct/run.sh select-asm`) are the analysis of the server's
`ct_eq` and `ct_select_*` too. There is no harness file of its own: the
selection of bytes was added to `ct_select.rs` with the core. What this part
adds is the review of every place the library compares or chooses, a timing
test of the library through its public functions, and tests that keep the
list of places from growing unnoticed.

- **WebAssembly.** The library is not in the binding. The scan
  (`ct/wasm-allow.toml`) and the WebAssembly timing module have nothing of it
  to read, and `the_server_library_is_not_in_the_webassembly_build` fails if
  the binding starts to depend on it. The server benches of `ct/dudect` are
  behind the feature `server` and are native only.
- **Places that compare or choose.** `no_secret_comparison_uses_eq` lists every
  line of the shipped code that compares with `==`, `!=`, `.eq(`, `.ne(`, an
  assertion macro, `matches!` or a slice pattern, with the reason it cannot leak
  (lengths, times, closed sets, public data); a listed text has to account for
  everything compared on its line, so a second compare appended to a listed
  line fails, and only the body of a test module is left out of the scan.
  `types_with_bytes_derive_partial_eq_only_when_listed` does the same for
  derived `PartialEq` over bytes, text and the usual wrappers of them, and
  `the_constant_time_call_sites_are_the_ones_that_were_checked` pins how many
  times each file calls `ct_eq` and `ct_select_*`. A new place fails one of them
  until it has been read and listed here. These are tripwires, not a proof.
  They do not see ordering (`<`, `cmp`, `sort`, `binary_search`), a map keyed
  by a raw secret (review point 4 holds only while the key types stay
  digests), `starts_with` and `contains` on byte slices, a call of `ct_eq`
  under another name (`use ... as`), a direct use of `subtle`, or a derived
  `PartialEq` over a byte type of another crate that the needles do not name.
- **Where the library does not run division, search or index by a secret.** In
  `login.rs`, `state.rs` and `replace.rs` the shipped code has no `/`, `%`,
  `checked_div`, `checked_rem`, `min`, `max`, `position`, `find`, `contains`,
  `binary_search` or `windows`. What is left in the crate is in
  `prelogin::fake_prelogin`: the remainder `permille` (an HMAC output modulo
  1000, a constant divisor), the early exit of the `find_map` over the profiles
  of the policy on that draw, and the compare of the hint draw with the share of
  the policy. All three work on a value derived from the pre-login secret, not
  chosen by the client, and their result is the answer that is given anyway.
  Accepted.

### Review points

| # | Compare or choice | Secret? | How it is done | Checked by |
|---|---|---|---|---|
| 1 | KE3 against the expected MAC | yes | `opaque-ke` (`subtle::ConstantTimeEq`) inside `ServerLogin::finish` | a KE3 with one byte changed, at every position, is refused (`tests/rfc9807_server.rs`) |
| 2 | Real or made-up record, id, profile and hint | no for the world, but the choice must not show in time | both sides are always computed; `ct_select_bytes` (`login.rs`, 2 calls, `prelogin.rs`, 1) and `ct_select_u8` (`login.rs`, 2) choose | T7, T11, `select-asm`; `known_and_unknown_run_the_same_steps_in_the_same_order` (trace of steps); `server_login_start_known_vs_unknown` and its replicate `server_login_start_known_vs_disabled` (the same library path), with the null control `control_server_login_start_null` and the isolating benches `info_server_login_start_lookup_only` and `info_server_login_start_real_vs_made_up`; `server_prelogin_known_vs_unknown` times the pattern an endpoint has to follow (no library code in it depends on the class) |
| 3 | Purpose, session and account of a re-authentication | yes | `ct_eq` on the 48 binding bytes (`LoginPurpose::same_as`), the purpose byte next to it with `&` | T5 and the call-site test; `server_state_binding` is a smoke test (it cannot tell `ct_eq` from `==` on 48 bytes behind an AEAD open) |
| 3b | Account of the session against the credential of the state | yes | `ct_eq` in `login_finish`, before the limiter is asked | T5 and the call-site test; `server_finish_credential_vs_account` is a smoke test (16 bytes behind an AEAD open); `a_finish_refused_before_the_account_is_known_charges_the_address_alone` |
| 4 | Nonce and login id in the stores | yes (bearer values) | the stores are keyed by `SHA-256(label, value)` (`StateKey`, `ChallengeKey`); no `==` on a raw value | `types_with_bytes_derive_partial_eq_only_when_listed`; `no_secret_comparison_uses_eq` |
| 5 | SHA-256 checksum of a secret file | the content is secret | `ct_eq` (`secret_file.rs`) | `the_constant_time_call_sites_are_the_ones_that_were_checked` |
| 6 | Fingerprint of the set-up at start-up | no (a hash, no remote caller) | `PartialEq` of `SetupFingerprint` is `ct_eq` anyway | `no_secret_comparison_uses_eq` |
| 7 | Profile numbers, lengths, times | no | plain | `no_secret_comparison_uses_eq` |
| 8 | AEAD tag of a sealed state | yes | inside `chacha20poly1305` (`subtle`) | not re-verified here (R6) |
| 9 | Ed25519 proof | no (public data) | `ferret-core` | not re-verified here |
| 10 | Hex reading of the login id | the value is a bearer | rejects on length and character class; the answer depends on the given bytes alone, and nothing is compared with a stored value | `LoginId::parse` tests; the lookup is by the SHA-256 key |

### S-1. A plain `==` on the binding bytes of a login state

Found by `no_secret_comparison_uses_eq`: the parser of a sealed state
compared the binding with zeros (`binding == [0u8; BINDING_LEN]`) to accept a
plain login. The bytes are those of a plaintext the AEAD has already
accepted, so no caller can steer the compare, and the same bytes hold the
session of a re-authentication in the other case. Fixed: it is `ct_eq` now.

### S-2. The library branches once on whether an account was found

That bit is secret from the network: whether a name has an account is what
§ 4.2 keeps from a caller. The library branches on it in two places:
`login_start` matches on `AccountLookup`, and `resolve_credential(secret, name,
Option<&AccountId>)` read the account id through a reference that may be
absent, which is a branch (a load through a pointer that may be null cannot be
made without one). `resolve_credential` now chooses the pointer first (the
account's own, or a fixed all-zero id: a select of two valid addresses) and
loads once, so the source has no branch there; that a compiler turns it into a
`cmov` is not guaranteed, and `info_server_prelogin_resolve_credential`
measures it (before the change |t| of 5.6 and 4.6 at 10^6, tau 0.016 and
0.005, eight calls per measurement). The match in `login_start` stays: it needs
an always-present record reference, which is an API change
(`StoredRecord::placeholder()` for unknown and disabled, and the match as a
`ct_select`), to be decided with the result of
`info_server_login_start_lookup_only`. The branch is accepted as long as the
caller's own lookup on the same bit, which differs by a database round trip,
dominates it; the endpoint test (§ 4.2: response bytes and delays) has to cover
that, see R10. The choices after the match are branch-free.
`server_prelogin_known_vs_unknown` times the rest of the pre-login answer (the
made-up answer is always computed, the real or made-up profile and hint are
chosen by a flag with `ct_select_u8`) and is gated.

### S-3. Two pools of inputs gave the classes a different mean

The first runs of the server benches failed, and the cause was the bench, not
the library. With a pool of names for each class, `server_prelogin_known_vs_unknown`
gave |t| of 10.9, 34.6 and 16.7 (negative every time, growing with n), and
with a pool of expected values for each class `server_state_binding` and
`server_finish_credential_vs_account` gave |t| of 7 to 11 with a different
sign from one process to the next. 256 names (or 256 sealed states) per class
are 256 samples of whatever depends on the input or on where it sits in
memory (layout, or data: not isolated; HMAC and a constant-divisor remainder
have no data-dependent time on this CPU in theory): the means of the two pools
differ by chance, and dudect, which asks whether the means differ, sees that
once n is large enough. The same
lesson as `unpad_ct` (R7), met again. The benches now give both classes the same
pool (the same names, the same masks; one allocation holds both classes of the
sealed states, input `i` of class `c` at `2i + c`), and the classes differ in
the flag alone, or in the index of the byte that is wrong. A bench of
`login_start` with the working cell filled differently per class (a clone of the
record only for the class with an account) gave |t| = 20 for the same reason:
the allocator and the caches were in another state before the timer started.
Both classes now run the same copies.

### Timing of the server library

**The table below is indicative, not decisive.** It is
`ct/results/dudect-lanbox-server.md` as it was first written
(`CT_ONLY=server CT_REPEAT=2`, 10^6 measurements per bench, a bench over 4.5
measured again with 10^7), on commit 9aaa566, taken while other builds ran on
the LANBox (load average 21 at the start, the dudect process pinned to the least
busy core, no controls in the run). Only docs, comments, imports and a rebinding
changed in `src/` after that commit. The decisive run is the one that replaces
it: 10^7 measurements per bench from the start, the controls in the same run,
the load average at the start and at the end in the file, on a quiet LANBox (the
file says NOT DECISIVE when the 1-minute load average was above 2). The gated
benches fail at 10^7 without a rerun.

| bench | t at 10^6 (two runs) | result |
|---|---|---|
| `server_login_start_known_vs_unknown` | -3.88, -2.92 | below 4.5 |
| `server_login_start_known_vs_disabled` (replicate) | +2.29, -3.10 | below 4.5 |
| `server_prelogin_known_vs_unknown` | +2.31, +1.90 | below 4.5 |
| `server_state_binding` (smoke test) | -1.72, -1.69 | below 4.5 |
| `server_finish_credential_vs_account` (smoke test) | +4.17, +4.65 (10^7: +2.14) | below 4.5 at 10^7 |
| `info_server_prelogin_resolve_credential` (not gated) | +5.61, +4.57 | before the pointer select, see S-2 |
| `info_server_finish_state_vs_missing` (not gated) | +19668, +20326 | the setup sees a missing state: an end-to-end timing of `login_finish` sees the difference of one AEAD open |

One run of `server_login_start_known_vs_unknown` with 10^7 measurements from the
start gave t = +7.06 (tau +0.0087), on a LANBox with a load average of 15. It is
probably not noise. The tool reports the largest |t| of the whole sample, about
a hundred percentile crops and a second-order test, and `n` is the size of that
test: 0.67M of 10^7 means the fastest 6.7 % of the runs, which are the ones
nobody disturbed and the most sensitive place for a small constant offset. The
two runs at 10^6 (-3.88 at n = 0.979M, -2.92 at n = 0.999M) are near-uncropped
tests, so their sign says nothing about the cropped one. The sign (Left, the
known side, slower) is that of `info_server_prelogin_resolve_credential`, which
times the branch of S-2 on the same bit. tau = 0.0087 of a crop spread of a few
hundred nanoseconds is a few nanoseconds, a handful of cycles. The suspects, in
order: the match on the lookup and the loads of the known side, the bench's own
class branch (it was in the timed closure then; it is in `prepare` now), and the
data (the dummy public key of the unknown side is one value, the known side has
256). The rerun is therefore a diagnosis: `control_server_login_start_null` gives
the noise floor of a target this size, `info_server_login_start_lookup_only` has
every byte OPAQUE sees the same and only the variant of the lookup differs, and
`info_server_login_start_real_vs_made_up` has only the data differ. Read: if the
gated bench passes at 10^7, the point is closed; if it fails and `lookup_only`
has the same sign, the cause is the variant, and it is either accepted as part
of S-2 by a written ruling or removed by the API change in S-2; if the data
bench shows it, look further down the stack before release. In every case the
size is a few cycles against a database lookup and a network that differ by
orders of magnitude, and the exposure is decided by the endpoint test.

This times the library, not the database: the lookup that decides `Active`,
`Unknown` or `Disabled` is the caller's, and the comparison of the bytes and
delays of the answers is a test of the endpoint.

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
  wiped nor read in constant time. The letters themselves go
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
  re-verified. Argon2id has data-dependent memory
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
  below 4; at 10^7, five runs on the LANBox were all below 2.7
  (`ct/results/base32-wasm-1e7.md`). In native, `unpad_ct` failed the gate (|t| of 7 to 22 at 10^6 and 26
  to 66 at 10^7, growing with n, so not noise) while the inputs of the zero
  class were `vec![0; n]`: `calloc` gives the shared zero page, so the source
  of the copy into the working cell was a different memory for that class. It is
  a flaw of the harness and not of `unpad_scan`: with pages of their own for the
  zero inputs the same bench, its content variant, a random-pair null and a
  same-input null all sit at 1 to 4. The lesson is the one the null controls
  teach; the controls of `unpad_scan` are `info_unpad_random_pair` and
  `info_unpad_same`. On hosted runners `unpad_ct` stayed positive and grew with
  n, and its own null `info_unpad_random_pair` was at the threshold on some
  machines (-4.77 on the LANBox once, +4.99 hosted), so a smaller bias remained:
  the two buffers of a pair were always allocated left then right, which fixes
  their offsets in a cache line by class. They are now allocated in a random
  order per pair. After that, on the LANBox, `unpad_ct` at 10^6 (five runs) is
  within +-2.4 and the random-pair and same-input nulls at 10^7 (five runs
  each) within +-3.3 (`ct/results/base32-wasm-1e7.md`); the hosted values are in
  the CI log of the pull request.
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
  **What the scan cannot see:** a table lookup whose address was built with an
  add, put in a local (`local.set`, `local.tee`) and loaded from there, and a
  store at a computed address. The pins of `ct/wasm-allow.toml` count only the
  hits that were flagged, so such a lookup is not counted in any function, with
  pins or without. A flow that flags it was tried and gave 6341 hits against
  168, because `wasm-opt` keeps every running pointer of a loop in such a local.
  It would take a data-flow pass over the output of `wasm-opt` to close the gap,
  or a dudect run on an input that selects the table index of a secret-dependent
  lookup; no such lookup is known in our code. Parked for 14c.
- **R10. What the server timing tests do not see.** They time the library
  through its public functions with a limiter that admits everything, a store
  that keeps nothing and one replayed random tape. They say nothing about the
  database lookup that builds `AccountLookup` (a row found or not takes
  another path through the database), the HTTP layer, TLS or the network; the
  comparison of the bytes and delays of the answers of a running server is a
  test of the endpoint (§ 4.2), and it has to name this part as an input. The
  branch on the lookup in `login_start` is the secret bit, branched on once;
  the caller's own lookup on the same bit dominates it (S-2). The endpoint
  has a larger difference of the same kind: the M1 `finish_lookup` parses the
  record only for a known account (a finding of the review of the endpoint code), and the endpoint
  test owner must see both. The compare of the credential in `login_finish`
  is shown by the timing only to within the noise of the whole `login_finish`
  call (|t| up to 4.65 at 10^6 and 2.14 at 10^7); that it is `ct_eq` is shown by the call-site test and the
  analysis of the harness (T5), not by the timing alone. Accepted.
