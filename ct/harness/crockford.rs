// Crockford Base32 without lookup tables and without data-dependent
// branches. Spec: Fase 1 section 6.1 and 6.2 (F-26).
//
// This file is the single source of the code: `crates/ferret-core/src/codes.rs`
// includes it with `include!`, and the constant-time analyzer reads the same
// file on its own. So it uses `core` only (no `std`, no `alloc`), has no
// inner attributes and no `use` of the crate it is included in, and compiles
// as a library on its own:
//
//     rustc --crate-type=lib --edition=2024 ct/harness/crockford.rs
//
// Every public function is `#[inline(never)]`. Without it rustc leaves a
// small function out of the compiled library when nothing in the file calls
// it, and the analyzer would find nothing to look at. With it, the code the
// analyzer reads is a function of its own, and so it is in the core.
//
// What may depend on secret data here is the *value* of the bytes and the
// symbols. Every loop count, every branch and every index depends on the
// lengths of the slices only, which are public. Symbol values are turned into
// letters, and letters into symbol values, with arithmetic and masks.
//
// The alphabet is 0123456789ABCDEFGHJKMNPQRSTVWXYZ (no I, L, O, U). On
// reading, lower case is accepted, `O` means `0`, and `I` and `L` mean `1`.

/// 1 if `value >= bound`, else 0. Both must be below 2^31.
#[inline(always)]
fn ge(value: u32, bound: u32) -> u32 {
    value.wrapping_sub(bound).wrapping_shr(31) ^ 1
}

/// 1 if `lo <= value <= hi`, else 0. All must be below 2^31.
#[inline(always)]
fn in_range(value: u32, lo: u32, hi: u32) -> u32 {
    ge(value, lo) & ge(hi, value)
}

/// 1 if `a == b`, else 0. Both must be below 2^31.
#[inline(always)]
fn is_equal(a: u32, b: u32) -> u32 {
    ge(a, b) & ge(b, a)
}

/// The letter for a 5-bit value (only the low five bits are used).
///
/// `0..=9` are `'0'..='9'`; the letters start at value 10 and skip `I`
/// (after value 17), `L` (after 19), `O` (after 21) and `U` (after 26).
#[inline(never)]
pub fn encode_symbol(value: u8) -> u8 {
    let v = u32::from(value) & 31;
    let ch = v
        .wrapping_add(48)
        .wrapping_add(ge(v, 10).wrapping_mul(7))
        .wrapping_add(ge(v, 18))
        .wrapping_add(ge(v, 20))
        .wrapping_add(ge(v, 22))
        .wrapping_add(ge(v, 27));
    (ch & 0xff) as u8
}

/// Folds a typed character to its canonical form: lower case to upper case,
/// `O` to `0`, `I` and `L` to `1`. Every other byte is returned unchanged.
#[inline(never)]
pub fn normalize_byte(byte: u8) -> u8 {
    let c = u32::from(byte);
    let upper = c.wrapping_sub(in_range(c, 97, 122).wrapping_mul(32));
    // 'O' is 79 and becomes 48; 'I' (73) and 'L' (76) become 49.
    let to_zero = is_equal(upper, 79);
    let to_one = is_equal(upper, 73) | is_equal(upper, 76);
    let folded = upper
        .wrapping_sub(to_zero.wrapping_mul(79 - 48))
        .wrapping_sub(to_one.wrapping_mul(upper.wrapping_sub(49)));
    (folded & 0xff) as u8
}

/// The 5-bit value of a canonical letter and 1 if the letter is valid, else
/// 0. Call it after [`normalize_byte`]. The value of an invalid letter is 0.
#[inline(never)]
pub fn decode_symbol(canonical: u8) -> (u8, u8) {
    let c = u32::from(canonical);
    let digit = in_range(c, 48, 57);
    let a_h = in_range(c, 65, 72);
    let j_k = in_range(c, 74, 75);
    let m_n = in_range(c, 77, 78);
    let p_t = in_range(c, 80, 84);
    let v_z = in_range(c, 86, 90);
    // Each term is multiplied by its range flag, so a letter outside every
    // range gives 0.
    let value = digit
        .wrapping_mul(c.wrapping_sub(48))
        .wrapping_add(a_h.wrapping_mul(c.wrapping_sub(55)))
        .wrapping_add(j_k.wrapping_mul(c.wrapping_sub(56)))
        .wrapping_add(m_n.wrapping_mul(c.wrapping_sub(57)))
        .wrapping_add(p_t.wrapping_mul(c.wrapping_sub(58)))
        .wrapping_add(v_z.wrapping_mul(c.wrapping_sub(59)));
    let valid = digit | a_h | j_k | m_n | p_t | v_z;
    ((value & 31) as u8, (valid & 1) as u8)
}

/// Writes `out.len()` symbols (letters) for the bit stream of `data`, most
/// significant bit first, padded with zero bits when the stream is shorter
/// than `5 * out.len()` bits. Bits of `data` beyond `5 * out.len()` are not
/// written.
///
/// Fase 1 section 6.1: 256 bits plus 4 zero bits give 52 symbols; section 6.2:
/// 128 bits plus 2 zero bits give 26 symbols.
#[inline(never)]
pub fn encode_symbols(data: &[u8], out: &mut [u8]) {
    let mut bytes = data.iter();
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for slot in out.iter_mut() {
        // At most one byte is added: `bits < 5` before, so `acc` stays small.
        while bits < 5 {
            acc = acc.wrapping_shl(8) | u32::from(bytes.next().copied().unwrap_or(0));
            bits = bits.wrapping_add(8);
        }
        bits = bits.wrapping_sub(5);
        *slot = encode_symbol((acc.wrapping_shr(bits) & 31) as u8);
        acc &= 1u32.wrapping_shl(bits).wrapping_sub(1);
    }
}

/// What [`decode_symbols`] found.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Decoded {
    /// True if every symbol was a valid letter.
    pub all_valid: bool,
    /// The bits left over after `out` was filled, as a number (the "spare"
    /// bits of the code; zero in a canonical code).
    pub spare: u32,
}

/// Reads letters into bytes: each letter of `symbols` is normalized with
/// [`normalize_byte`], turned into five bits, and the bit stream is written
/// most significant bit first into `out`. The bits that do not fill a whole
/// byte at the end are returned in [`Decoded::spare`]. An invalid letter
/// reads as five zero bits and clears [`Decoded::all_valid`].
///
/// The caller passes lengths with `5 * symbols.len() - 8 * out.len()` in
/// `0..8`; with any other lengths `out` is only partly written.
#[inline(never)]
pub fn decode_symbols(symbols: &[u8], out: &mut [u8]) -> Decoded {
    let mut slots = out.iter_mut();
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut all_valid: u32 = 1;
    for &letter in symbols {
        let (value, valid) = decode_symbol(normalize_byte(letter));
        all_valid &= u32::from(valid);
        acc = acc.wrapping_shl(5) | u32::from(value);
        bits = bits.wrapping_add(5);
        if bits >= 8 {
            bits = bits.wrapping_sub(8);
            if let Some(slot) = slots.next() {
                *slot = (acc.wrapping_shr(bits) & 0xff) as u8;
            }
            acc &= 1u32.wrapping_shl(bits).wrapping_sub(1);
        }
    }
    Decoded {
        all_valid: all_valid == 1,
        spare: acc,
    }
}
