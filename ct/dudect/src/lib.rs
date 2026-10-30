//! Timing tests of the constant-time code of the Ferret core.
//!
//! A [`Target`] has two pools of inputs, one for each dudect class, and one
//! working cell. For every measurement the caller first calls
//! [`Target::prepare`] (not timed), which copies input `i` of a class into the
//! cell, and then times [`Target::run`], which runs the operation on the
//! cell. The cell sits at the same address for both classes, so the two
//! classes differ in the *contents* of the input and in nothing else: not in
//! where it is in memory, not in which branch the timed code takes to find it.
//! (Pools in two places differ by a nanosecond or so on average, and with a
//! million measurements dudect sees that as a leak: the null control of this
//! crate showed t-values of 50 before it was built this way.)
//!
//! The native bench (`src/bin/dudect.rs`, `dudect-bencher`) and the
//! WebAssembly module that `ct/dudect-wasm/run.mjs` times in Node use the same
//! targets.
//!
//! The code under test is the code of the core: the harness files in
//! `ct/harness/` are included here from the same paths as in the core, and
//! the key commitment path is the public `unwrap_vk`.
//!
//! The targets and their classes:
//!
//! | target | operation | Left | Right |
//! |---|---|---|---|
//! | `commit_check` | `commit_eq` | equal | first byte wrong |
//! | `mac_verify` | `mac_eq` | first byte wrong | last byte wrong |
//! | `key_eq` | `ConstantTimeEq` of a `VaultKey` | equal | last byte wrong |
//! | `crockford_decode` | `decode_symbols`, 52 letters | all `0` | random letters, mixed case and look-alikes |
//! | `unpad_ct` | `unpad_scan`, 1024 bytes | marker last | marker first |
//! | `base32_decode` | `decode_letters`, 32 letters | all `A` | random letters, mixed case |
//! | `kek_pw_commit_path` | `unwrap_vk`, whole path | commit: first byte wrong | commit: last byte wrong |
//! | `info_unwrap_valid_vs_bad_commit` | `unwrap_vk` | intact (AEAD runs) | commit wrong (AEAD skipped) |
//! | `control_null` | `commit_eq`, same inputs in both classes | equal | equal |
//! | `control_leaky` | a comparison that stops at the first difference | equal | first byte wrong |
//! | `control_unpad_leaky` | a scan of the padding that stops at the marker | marker last | marker first |
//!
//! The two controls check the measuring system. `control_null` must stay
//! below the threshold (the classes are the same, so a high t would be noise
//! or a flaw in the setup); `control_leaky` must be far above it (a
//! comparison that stops at the first difference leaks, and the setup must be
//! able to see that).
//!
//! `info_unwrap_valid_vs_bad_commit` is information only: the spec checks
//! `commit` before the AEAD (Fase 1 section 4.3), so a wrong commit is faster
//! by design. It leaks nothing the caller does not get from the `Err`.

// The harness files are the core's, not ours: they are formatted and linted
// with the core's rules in the core.
#![allow(clippy::all)]
#![allow(missing_docs)]

use ferret_core::testing::TestRng;
use ferret_core::{
    AccountId, Kek, KsfProfile, Method, MethodId, UnlockedVault, VaultContext, VaultId, VaultKey,
    WrapRecord, unwrap_vk, wrap_vk,
};
use std::hint::black_box;
use subtle::ConstantTimeEq;

/// The single-file harness code, included from the same files as in the core.
pub mod harness {
    pub mod ct_eq {
        include!("../../harness/ct_eq.rs");
    }
    pub mod crockford {
        include!("../../harness/crockford.rs");
    }
    pub mod unpad {
        include!("../../harness/unpad.rs");
    }
    pub mod base32 {
        include!("../../harness/base32.rs");
    }
}

/// The number of inputs in each class pool. A measurement takes input
/// `i % POOL`.
pub const POOL: usize = 1024;

/// Which dudect class a measurement belongs to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Class {
    Left = 0,
    Right = 1,
}

impl Class {
    /// The class of a bit (0 left, 1 right).
    pub fn from_bit(bit: u32) -> Class {
        [Class::Left, Class::Right][(bit & 1) as usize]
    }
}

/// One timing test.
pub trait Target {
    /// The name, as the bench prints it.
    fn name(&self) -> &'static str;
    /// How often one measurement repeats the operation on the same input.
    /// Operations of a few nanoseconds are repeated so that the timer can
    /// see them.
    fn reps(&self) -> u32;
    /// Copies input `i % POOL` of `class` into the working cell. Not timed.
    fn prepare(&mut self, class: Class, i: usize);
    /// Runs the operation `reps` times on the working cell and returns a
    /// value that depends on every result. This is what is timed.
    fn run(&self, reps: u32) -> u64;
    /// True for a target that is reported but does not gate.
    fn informational(&self) -> bool {
        false
    }
}

/// A small deterministic generator (SplitMix64). Timing inputs need no
/// secrecy, only repeatability.
pub struct Mix(u64);

impl Mix {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    pub fn fill(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(8) {
            let word = self.next().to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
    }
    pub fn array<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        self.fill(&mut out);
        out
    }
}

/// The inputs of both classes: index `i` holds a left and a right input.
struct Pools<I> {
    items: Vec<[I; 2]>,
}

impl<I> Pools<I> {
    /// Builds the pools; `make` returns the left and the right input of one
    /// index.
    fn new(mix: &mut Mix, mut make: impl FnMut(&mut Mix) -> (I, I)) -> Self {
        Pools {
            items: (0..POOL)
                .map(|_| {
                    let (left, right) = make(mix);
                    [left, right]
                })
                .collect(),
        }
    }

    fn get(&self, class: Class, i: usize) -> &I {
        &self.items[i % POOL][class as usize]
    }
}

/// `a` with one byte changed.
fn with_wrong(mut a: [u8; 32], at: usize, mix: &mut Mix) -> [u8; 32] {
    a[at] ^= (mix.next() as u8) | 1;
    a
}

// ---------------------------------------------------------- comparisons

#[derive(Clone, Copy)]
enum Compare {
    Commit,
    Mac,
    /// A comparison that stops at the first difference (the control).
    Leaky,
}

/// A comparison that returns at the first difference, written so that the
/// compiler keeps it that way (a plain `a == b` on 32 bytes becomes a few
/// wide compares without an early exit in WebAssembly).
#[inline(never)]
fn early_exit_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for i in 0..32 {
        if black_box(a[i]) != black_box(b[i]) {
            return false;
        }
    }
    true
}

struct Eq32 {
    name: &'static str,
    which: Compare,
    info: bool,
    pools: Pools<([u8; 32], [u8; 32])>,
    cell: ([u8; 32], [u8; 32]),
}

impl Eq32 {
    fn new(
        name: &'static str,
        which: Compare,
        info: bool,
        pools: Pools<([u8; 32], [u8; 32])>,
    ) -> Self {
        Eq32 {
            name,
            which,
            info,
            pools,
            cell: ([0; 32], [0; 32]),
        }
    }
}

impl Target for Eq32 {
    fn name(&self) -> &'static str {
        self.name
    }
    fn reps(&self) -> u32 {
        64
    }
    fn informational(&self) -> bool {
        self.info
    }
    fn prepare(&mut self, class: Class, i: usize) {
        self.cell = *self.pools.get(class, i);
    }
    fn run(&self, reps: u32) -> u64 {
        let mut acc = 0u64;
        for _ in 0..reps {
            let (a, b) = black_box(&self.cell);
            let same = match self.which {
                Compare::Commit => harness::ct_eq::commit_eq(a, b),
                Compare::Mac => harness::ct_eq::mac_eq(a, b),
                Compare::Leaky => early_exit_eq(a, b),
            };
            acc = acc.wrapping_add(u64::from(same));
        }
        black_box(acc)
    }
}

fn commit_check(mix: &mut Mix) -> Eq32 {
    let pools = Pools::new(mix, |m| {
        let a = m.array::<32>();
        ((a, a), (a, with_wrong(a, 0, m)))
    });
    Eq32::new("commit_check", Compare::Commit, false, pools)
}

fn mac_verify(mix: &mut Mix) -> Eq32 {
    let pools = Pools::new(mix, |m| {
        let a = m.array::<32>();
        ((a, with_wrong(a, 0, m)), (a, with_wrong(a, 31, m)))
    });
    Eq32::new("mac_verify", Compare::Mac, false, pools)
}

fn control_null(mix: &mut Mix) -> Eq32 {
    let pools = Pools::new(mix, |m| {
        let a = m.array::<32>();
        ((a, a), (a, a))
    });
    Eq32::new("control_null", Compare::Commit, true, pools)
}

fn control_leaky(mix: &mut Mix) -> Eq32 {
    let pools = Pools::new(mix, |m| {
        let a = m.array::<32>();
        ((a, a), (a, with_wrong(a, 0, m)))
    });
    Eq32::new("control_leaky", Compare::Leaky, true, pools)
}

struct KeyEq {
    pools: Pools<([u8; 32], [u8; 32])>,
    cell: (VaultKey, VaultKey),
}

impl Target for KeyEq {
    fn name(&self) -> &'static str {
        "key_eq"
    }
    fn reps(&self) -> u32 {
        64
    }
    fn prepare(&mut self, class: Class, i: usize) {
        let (a, b) = self.pools.get(class, i);
        self.cell = (VaultKey::from_test_bytes(*a), VaultKey::from_test_bytes(*b));
    }
    fn run(&self, reps: u32) -> u64 {
        let mut acc = 0u64;
        for _ in 0..reps {
            let (a, b) = black_box(&self.cell);
            acc = acc.wrapping_add(u64::from(a.ct_eq(b).unwrap_u8()));
        }
        black_box(acc)
    }
}

fn key_eq(mix: &mut Mix) -> KeyEq {
    KeyEq {
        pools: Pools::new(mix, |m| {
            let a = m.array::<32>();
            ((a, a), (a, with_wrong(a, 31, m)))
        }),
        cell: (
            VaultKey::from_test_bytes([0; 32]),
            VaultKey::from_test_bytes([0; 32]),
        ),
    }
}

// ------------------------------------------------------------ decoding

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// A letter of the Crockford alphabet as a person might type it: any case,
/// and `O`, `I` or `L` for look-alikes.
fn typed_crockford(m: &mut Mix) -> u8 {
    let letter = CROCKFORD[m.below(32)];
    let look_alike = match letter {
        b'0' if m.below(2) == 0 => b'O',
        b'1' => [b'1', b'I', b'L'][m.below(3)],
        other => other,
    };
    if look_alike.is_ascii_uppercase() && m.below(2) == 0 {
        look_alike.to_ascii_lowercase()
    } else {
        look_alike
    }
}

struct Crockford {
    pools: Pools<[u8; 52]>,
    cell: [u8; 52],
}

impl Target for Crockford {
    fn name(&self) -> &'static str {
        "crockford_decode"
    }
    fn reps(&self) -> u32 {
        1
    }
    fn prepare(&mut self, class: Class, i: usize) {
        self.cell = *self.pools.get(class, i);
    }
    fn run(&self, reps: u32) -> u64 {
        let mut acc = 0u64;
        for _ in 0..reps {
            let mut out = [0u8; 32];
            let d = harness::crockford::decode_symbols(black_box(&self.cell), &mut out);
            acc = acc
                .wrapping_add(u64::from(d.all_valid))
                .wrapping_add(u64::from(d.spare))
                .wrapping_add(u64::from(black_box(out)[0]));
        }
        black_box(acc)
    }
}

fn crockford_decode(mix: &mut Mix) -> Crockford {
    Crockford {
        pools: Pools::new(mix, |m| {
            let mut s = [0u8; 52];
            for slot in s.iter_mut() {
                *slot = typed_crockford(m);
            }
            ([b'0'; 52], s)
        }),
        cell: [b'0'; 52],
    }
}

struct Base32 {
    name: &'static str,
    info: bool,
    pools: Pools<[u8; 32]>,
    cell: [u8; 32],
}

impl Target for Base32 {
    fn name(&self) -> &'static str {
        self.name
    }
    fn informational(&self) -> bool {
        self.info
    }
    fn reps(&self) -> u32 {
        1
    }
    fn prepare(&mut self, class: Class, i: usize) {
        self.cell = *self.pools.get(class, i);
    }
    fn run(&self, reps: u32) -> u64 {
        let mut acc = 0u64;
        for _ in 0..reps {
            let mut out = [0u8; 20];
            let valid = harness::base32::decode_letters(black_box(&self.cell), &mut out);
            acc = acc
                .wrapping_add(u64::from(valid))
                .wrapping_add(u64::from(black_box(out)[0]));
        }
        black_box(acc)
    }
}

/// A random base32 string of 32 letters; `case` 0 mixed, 1 upper, 2 lower.
fn random_base32(m: &mut Mix, case: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    for slot in s.iter_mut() {
        let letter = BASE32[m.below(32)];
        let lower = match case {
            0 => m.below(2) == 0,
            1 => false,
            _ => true,
        };
        *slot = if letter.is_ascii_uppercase() && lower {
            letter.to_ascii_lowercase()
        } else {
            letter
        };
    }
    s
}

/// `base32_decode`: all `A` against random letters (the gate). The `info_`
/// variants say where a difference comes from: `a_vs_z` is two fixed strings,
/// `upper_vs_lower` two random pools that differ only in case, and
/// `random_pair` two random pools of the same kind (the null of a target whose
/// left class is not fixed).
fn base32_target(mix: &mut Mix, name: &'static str) -> Base32 {
    let pools = match name {
        "info_base32_a_vs_z" => Pools::new(mix, |_| ([b'A'; 32], [b'z'; 32])),
        "info_base32_upper_vs_lower" => {
            Pools::new(mix, |m| (random_base32(m, 1), random_base32(m, 2)))
        }
        "info_base32_random_pair" => {
            Pools::new(mix, |m| (random_base32(m, 0), random_base32(m, 0)))
        }
        _ => Pools::new(mix, |m| ([b'A'; 32], random_base32(m, 0))),
    };
    Base32 {
        name,
        info: name != "base32_decode",
        pools,
        cell: [b'A'; 32],
    }
}

// -------------------------------------------------------------- padding

const PADDED: usize = 1024;

/// The scan of `unpad_scan` with an early exit at the marker: the control that
/// shows the setup can see a leak in a 1024-byte scan (marker last against
/// marker first is 1023 bytes of difference).
#[inline(never)]
fn unpad_scan_leaky(padded: &[u8]) -> (u32, usize) {
    for (i, &byte) in padded.iter().enumerate().rev() {
        if black_box(byte) == 0x80 {
            return (1, i);
        }
        if black_box(byte) != 0 {
            return (0, 0);
        }
    }
    (0, 0)
}

struct Unpad {
    name: &'static str,
    info: bool,
    leaky: bool,
    pools: Pools<Vec<u8>>,
    cell: Vec<u8>,
}

impl Target for Unpad {
    fn name(&self) -> &'static str {
        self.name
    }
    fn informational(&self) -> bool {
        self.info
    }
    fn reps(&self) -> u32 {
        1
    }
    fn prepare(&mut self, class: Class, i: usize) {
        self.cell.copy_from_slice(self.pools.get(class, i));
    }
    fn run(&self, reps: u32) -> u64 {
        let mut acc = 0u64;
        for _ in 0..reps {
            let (ok, len) = if self.leaky {
                unpad_scan_leaky(black_box(&self.cell))
            } else {
                harness::unpad::unpad_scan(black_box(&self.cell))
            };
            acc = acc.wrapping_add(u64::from(ok)).wrapping_add(len as u64);
        }
        black_box(acc)
    }
}

/// A padded buffer: `plain` bytes, the marker, zeros.
fn padded(plain: &[u8], total: usize) -> Vec<u8> {
    // Not `vec![0; total]`: that is `calloc`, and the pages of an all-zero
    // input would be the shared zero page, which is not what the other class
    // reads from. Written first with ones, so that every page is a page of its own.
    let mut v = vec![1u8; total];
    black_box(&mut v);
    v.fill(0);
    v[..plain.len()].copy_from_slice(plain);
    v[plain.len()] = 0x80;
    v
}

/// `unpad_scan` on 1024 bytes. `kind` says what differs between the classes:
/// the position of the marker with random plaintext (`unpad_ct`), the
/// position of the marker with all-zero plaintext, or the content only.
fn unpad_target(mix: &mut Mix, name: &'static str, info: bool, kind: UnpadKind) -> Unpad {
    Unpad {
        name,
        info,
        leaky: matches!(kind, UnpadKind::Leaky),
        pools: Pools::new(mix, |m| {
            let random = m.array::<1023>().to_vec();
            let zeros = vec![0u8; 1023];
            // The plaintext of each class.
            let (left, right) = match kind {
                // Marker last (a full plaintext of 1023 random bytes) against
                // marker first (a plaintext of length 0).
                UnpadKind::Position | UnpadKind::Leaky => (random, Vec::new()),
                // The same positions, but the plaintext is zeros: only the
                // position of the marker differs.
                UnpadKind::PositionZeros => (zeros, Vec::new()),
                // Marker last in both; random plaintext against zeros.
                UnpadKind::Content => (random, zeros),
                // Marker last in both; two random plaintexts from the same
                // distribution (the null of a target with random inputs), and
                // the same plaintext in both classes (the null of the setup).
                UnpadKind::RandomPair => (random, m.array::<1023>().to_vec()),
                UnpadKind::Same => (random.clone(), random),
            };
            // The two buffers are allocated in a random order, so that where a
            // buffer sits (its offset in a cache line, which the allocator
            // decides by the order of the allocations) is not a function of its
            // class.
            if m.below(2) == 0 {
                let l = padded(&left, PADDED);
                let r = padded(&right, PADDED);
                (l, r)
            } else {
                let r = padded(&right, PADDED);
                let l = padded(&left, PADDED);
                (l, r)
            }
        }),
        cell: vec![0u8; PADDED],
    }
}

#[derive(Clone, Copy)]
enum UnpadKind {
    RandomPair,
    Same,
    Position,
    Leaky,
    PositionZeros,
    Content,
}

// ------------------------------------------------------ unwrap (commit)

const COMMIT_AT: usize = 72;

fn context() -> VaultContext {
    VaultContext {
        account_id: AccountId::from_bytes([0x11; 16]),
        vault_id: VaultId::from_bytes([0x22; 16]),
        vk_epoch: 1,
    }
}

struct Unwrap {
    name: &'static str,
    info: bool,
    ctx: VaultContext,
    kek: Kek,
    /// The wrap bytes of each input; the rest of a record is the same.
    pools: Pools<Vec<u8>>,
    cell: WrapRecord,
}

impl Target for Unwrap {
    fn name(&self) -> &'static str {
        self.name
    }
    fn reps(&self) -> u32 {
        1
    }
    fn informational(&self) -> bool {
        self.info
    }
    fn prepare(&mut self, class: Class, i: usize) {
        self.cell.wrap.copy_from_slice(self.pools.get(class, i));
    }
    fn run(&self, reps: u32) -> u64 {
        let mut acc = 0u64;
        for _ in 0..reps {
            let vault: Result<UnlockedVault, _> =
                unwrap_vk(&self.ctx, &self.kek, black_box(&self.cell));
            acc = acc.wrapping_add(u64::from(vault.is_ok()));
        }
        black_box(acc)
    }
}

/// A `password` wrap of a vault key under `kek`, with the byte at `flip` (an
/// index into the wrap) changed, or intact for `None`.
fn wrap_record(mix: &mut Mix, kek: &Kek, ctx: &VaultContext, flip: Option<usize>) -> WrapRecord {
    let mut rng = TestRng::new(&mix.next().to_le_bytes());
    let vk = VaultKey::from_test_bytes(mix.array::<32>());
    let mut rec = wrap_vk(
        &mut rng,
        ctx,
        &vk,
        kek,
        MethodId::from_bytes([0x33; 16]),
        1,
        Method::Password {
            ksf: KsfProfile::P1,
        },
    )
    .expect("a wrap under a fixed KEK");
    if let Some(at) = flip {
        rec.wrap[at] ^= (mix.next() as u8) | 1;
    }
    rec
}

fn unwrap_target(
    mix: &mut Mix,
    name: &'static str,
    info: bool,
    left: Option<usize>,
    right: Option<usize>,
) -> Unwrap {
    let ctx = context();
    let kek = Kek::from_test_bytes(mix.array::<32>());
    let pools = Pools::new(mix, |m| {
        (
            wrap_record(m, &kek, &ctx, left).wrap,
            wrap_record(m, &kek, &ctx, right).wrap,
        )
    });
    let cell = wrap_record(mix, &kek, &ctx, None);
    Unwrap {
        name,
        info,
        ctx,
        kek,
        pools,
        cell,
    }
}

/// Every target, with inputs made from `seed`.
pub fn targets(seed: u64) -> Vec<Box<dyn Target + Send>> {
    let mut mix = Mix::new(seed);
    vec![
        Box::new(commit_check(&mut mix)),
        Box::new(mac_verify(&mut mix)),
        Box::new(key_eq(&mut mix)),
        Box::new(crockford_decode(&mut mix)),
        Box::new(unpad_target(
            &mut mix,
            "unpad_ct",
            false,
            UnpadKind::Position,
        )),
        Box::new(unpad_target(
            &mut mix,
            "info_unpad_position_zeros",
            true,
            UnpadKind::PositionZeros,
        )),
        Box::new(unpad_target(
            &mut mix,
            "info_unpad_content",
            true,
            UnpadKind::Content,
        )),
        Box::new(unpad_target(
            &mut mix,
            "info_unpad_random_pair",
            true,
            UnpadKind::RandomPair,
        )),
        Box::new(unpad_target(
            &mut mix,
            "info_unpad_same",
            true,
            UnpadKind::Same,
        )),
        Box::new(base32_target(&mut mix, "base32_decode")),
        Box::new(base32_target(&mut mix, "info_base32_a_vs_z")),
        Box::new(base32_target(&mut mix, "info_base32_upper_vs_lower")),
        Box::new(base32_target(&mut mix, "info_base32_random_pair")),
        Box::new(unwrap_target(
            &mut mix,
            "kek_pw_commit_path",
            false,
            Some(COMMIT_AT),
            Some(COMMIT_AT + 31),
        )),
        Box::new(unwrap_target(
            &mut mix,
            "info_unwrap_valid_vs_bad_commit",
            true,
            None,
            Some(COMMIT_AT),
        )),
        Box::new(unpad_target(
            &mut mix,
            "control_unpad_leaky",
            true,
            UnpadKind::Leaky,
        )),
        Box::new(control_null(&mut mix)),
        Box::new(control_leaky(&mut mix)),
    ]
}

// ------------------------------------------------------- WebAssembly ABI

/// The exports that `ct/dudect-wasm/run.mjs` calls. Plain C ABI, no
/// `wasm-bindgen`: the module has no imports.
#[cfg(target_arch = "wasm32")]
mod abi {
    use super::{Class, Target, targets};
    use std::sync::Mutex;

    static STATE: Mutex<Vec<Box<dyn Target + Send>>> = Mutex::new(Vec::new());

    fn with<R>(f: impl FnOnce(&mut Vec<Box<dyn Target + Send>>) -> R) -> R {
        match STATE.lock() {
            Ok(mut guard) => f(&mut guard),
            Err(poisoned) => f(&mut poisoned.into_inner()),
        }
    }

    /// Builds all targets from the seed and returns how many there are.
    #[unsafe(no_mangle)]
    pub extern "C" fn ct_setup(seed_lo: u32, seed_hi: u32) -> u32 {
        let seed = (u64::from(seed_hi) << 32) | u64::from(seed_lo);
        with(|state| {
            *state = targets(seed);
            state.len() as u32
        })
    }

    /// Pointer to the UTF-8 name of target `t`.
    #[unsafe(no_mangle)]
    pub extern "C" fn ct_name_ptr(t: u32) -> *const u8 {
        with(|state| {
            state
                .get(t as usize)
                .map_or(core::ptr::null(), |x| x.name().as_ptr())
        })
    }

    /// Length of the name of target `t`.
    #[unsafe(no_mangle)]
    pub extern "C" fn ct_name_len(t: u32) -> u32 {
        with(|state| state.get(t as usize).map_or(0, |x| x.name().len() as u32))
    }

    /// 1 if target `t` is informational.
    #[unsafe(no_mangle)]
    pub extern "C" fn ct_info(t: u32) -> u32 {
        with(|state| {
            state
                .get(t as usize)
                .map_or(0, |x| u32::from(x.informational()))
        })
    }

    /// The repetitions per measurement of target `t`.
    #[unsafe(no_mangle)]
    pub extern "C" fn ct_reps(t: u32) -> u32 {
        with(|state| state.get(t as usize).map_or(0, |x| x.reps()))
    }

    /// Copies input `i` of class `class` (0 left, 1 right) into the working
    /// cell of target `t`. Not timed.
    #[unsafe(no_mangle)]
    pub extern "C" fn ct_prepare(t: u32, class: u32, i: u32) {
        with(|state| {
            if let Some(x) = state.get_mut(t as usize) {
                x.prepare(Class::from_bit(class), i as usize);
            }
        })
    }

    /// One measurement: `reps` runs on the working cell. Returns the low 32
    /// bits of the result so that the call is not optimized away.
    #[unsafe(no_mangle)]
    pub extern "C" fn ct_run(t: u32, reps: u32) -> u32 {
        with(|state| state.get(t as usize).map_or(0, |x| x.run(reps) as u32))
    }
}
