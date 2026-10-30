// A KNOWN-BAD select, kept to prove that `ct/run.sh select-asm` can fail.
// Never included in the core.
//
// This is the first version of `ct/harness/ct_select.rs`: the mask is made with
// arithmetic and LLVM can see that it is all ones or all zeros, so it compiles
// `ct_select_bytes` to "choose the source pointer with a conditional move, then
// copy" (x86_64) or to tests of bit 0 of the flag (arm64), and only one of the
// two slices is read. `ct/run.sh select-asm-negative` must flag this file on
// both architectures; if it does not, the check has rotted into a pass that
// looks at nothing.

#[inline(never)]
pub fn ct_select_bytes(flag: u8, a: &[u8], b: &[u8], out: &mut [u8]) {
    let mask = 0u8.wrapping_sub(flag & 1);
    for ((slot, &x), &y) in out.iter_mut().zip(a.iter()).zip(b.iter()) {
        *slot = (x & mask) | (y & !mask);
    }
}
