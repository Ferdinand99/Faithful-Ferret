//! Property tests for the TLV builder.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use ferret_core::{Error, Tlv};
use proptest::prelude::*;

fn config() -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(512);
    ProptestConfig {
        cases,
        ..ProptestConfig::default()
    }
}

/// A field as `(tag, value)`; one-byte and eight-byte fields are just values
/// of those lengths.
type Field = (u8, Vec<u8>);

/// Encodes a list of fields with the builder, through whichever method fits.
fn encode(fields: &[Field]) -> Vec<u8> {
    let mut tlv = Tlv::new();
    for (tag, value) in fields {
        tlv = match value.len() {
            1 => tlv.u8(*tag, value[0]),
            8 => tlv.u64(
                *tag,
                u64::from_be_bytes(value.as_slice().try_into().unwrap()),
            ),
            _ => tlv.bytes(*tag, value).unwrap(),
        };
    }
    tlv.finish().unwrap()
}

/// An independent parser: `tag ‖ len(u16be) ‖ value`, repeated, nothing left
/// over. `None` if the bytes are not a whole number of fields.
fn parse(mut bytes: &[u8]) -> Option<Vec<Field>> {
    let mut fields = Vec::new();
    while !bytes.is_empty() {
        let (head, rest) = bytes.split_at_checked(3)?;
        let len = usize::from(u16::from_be_bytes([head[1], head[2]]));
        let (value, rest) = rest.split_at_checked(len)?;
        fields.push((head[0], value.to_vec()));
        bytes = rest;
    }
    Some(fields)
}

fn field() -> impl Strategy<Value = Field> {
    // Short values most of the time, with many one- and eight-byte values and
    // empty ones, because those are the boundaries between fields.
    (
        any::<u8>(),
        prop_oneof![
            prop::collection::vec(any::<u8>(), 0..=3),
            prop::collection::vec(any::<u8>(), 8..=8),
            prop::collection::vec(any::<u8>(), 0..=300),
        ],
    )
}

fn fields() -> impl Strategy<Value = Vec<Field>> {
    prop::collection::vec(field(), 0..=6)
}

/// Changes a list of fields in a way that keeps the concatenated value bytes
/// as alike as possible, which is where a bad encoding would collide.
fn mutate(list: &[Field], kind: u8, at: usize, cut: usize) -> Vec<Field> {
    let mut out = list.to_vec();
    if out.is_empty() {
        out.push((0x31, vec![]));
        return out;
    }
    let i = at % out.len();
    match kind % 4 {
        // Split a value into two fields with the same tag.
        0 => {
            let (tag, value) = out[i].clone();
            let k = cut % (value.len() + 1);
            out[i] = (tag, value[..k].to_vec());
            out.insert(i + 1, (tag, value[k..].to_vec()));
        }
        // Merge a field with the next one when the tags are equal, else swap.
        1 => {
            if i + 1 < out.len() {
                if out[i].0 == out[i + 1].0 {
                    let next = out.remove(i + 1);
                    out[i].1.extend_from_slice(&next.1);
                } else {
                    out.swap(i, i + 1);
                }
            }
        }
        // Change the tag.
        2 => out[i].0 = out[i].0.wrapping_add(1),
        // Move one byte from this value to the start of the next field.
        _ => {
            if i + 1 < out.len() && !out[i].1.is_empty() {
                let b = out[i].1.pop().unwrap();
                out[i + 1].1.insert(0, b);
            }
        }
    }
    out
}

proptest! {
    #![proptest_config(config())]

    /// Two different field lists never give the same bytes, and two equal
    /// lists give equal bytes (Fase 1 § 3.1: every field carries its length).
    #[test]
    fn tlv_unambiguous(a in fields(), b in fields(), kind in any::<u8>(), at in any::<usize>(), cut in any::<usize>()) {
        // Equal lists, equal bytes; and the bytes parse back to the list.
        prop_assert_eq!(encode(&a), encode(&a));
        prop_assert_eq!(parse(&encode(&a)), Some(a.clone()));

        // Unrelated lists.
        prop_assert_eq!(encode(&a) == encode(&b), a == b);

        // A list and a near-identical one.
        let m = mutate(&a, kind, at, cut);
        prop_assert_eq!(encode(&a) == encode(&m), a == m);
    }

    /// A value over 65 535 bytes is an error, never a truncation.
    #[test]
    fn tlv_rejects_oversize(extra in 1usize..=64, byte in any::<u8>(), tag in any::<u8>()) {
        let value = vec![byte; 65_535 + extra];
        prop_assert_eq!(Tlv::new().bytes(tag, &value).unwrap_err(), Error::TooLarge);
        // And one byte fewer than the limit fits and keeps every byte.
        let fits = vec![byte; 65_535];
        let encoded = Tlv::new().bytes(tag, &fits).unwrap().finish().unwrap();
        prop_assert_eq!(parse(&encoded), Some(vec![(tag, fits)]));
    }
}
