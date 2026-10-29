//! Strict CBOR for item bodies, manifests and (later) export files.
//!
//! Spec: Fase 1 § 5.2 and plan U10. No existing CBOR crate enforces all the
//! rules, so the decoder in [`decode`] is a small tree builder over the
//! low-level `minicbor::Decoder`, and [`encode`] writes the same tree again.
//!
//! The data model ([`Value`]) is what the format allows and nothing more:
//! `null`, booleans, integers in `u64`/`i64`, floats (kept as their bits),
//! bytes, text, definite arrays and maps with text keys. Everything else
//! (tags, indefinite lengths, `undefined`, other simple values, keys
//! that are not text, duplicate keys, nesting deeper than 16, more than
//! 10 000 entries, text or bytes over 64 KiB) is rejected, each with its own
//! stable `malformed_cbor_*` code.
//!
//! The encoder always writes the shortest form and definite lengths, and
//! refuses a tree the decoder would refuse, so everything it writes can be
//! read back. The decoder accepts any valid head length (the format is not
//! canonical, Fase 1 § 5.2) and maps keep their order.

mod decode;
mod encode;
mod value;

pub use decode::{MAX_BYTES, MAX_DEPTH, MAX_ITEMS, decode};
pub use encode::{encode, encoded_len};
pub use value::Value;
pub(crate) use value::{Entries, redacted_debug};
