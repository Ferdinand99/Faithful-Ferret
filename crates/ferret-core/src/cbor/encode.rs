//! The CBOR encoder: the shortest form, definite lengths, the same limits
//! as the decoder.

use super::Value;
use super::decode::{MAX_BYTES, MAX_DEPTH, MAX_ITEMS};
use crate::error::{Error, MalformedKind};
use minicbor::Encoder;
use std::collections::BTreeSet;

const fn malformed(kind: MalformedKind) -> Error {
    Error::Malformed(kind)
}

fn write_error<E>(_: minicbor::encode::Error<E>) -> Error {
    malformed(MalformedKind::Cbor)
}

/// Size of the head of a data item with argument `n`.
fn head_len(n: u64) -> usize {
    match n {
        0..=23 => 1,
        24..=0xff => 2,
        0x100..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

fn len_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// The number of bytes [`encode`] writes for `value`, without checking the
/// limits. Lets the caller reserve the exact buffer, so no reallocation
/// leaves an unwiped copy of the contents behind.
pub fn encoded_len(value: &Value) -> usize {
    match value {
        Value::Null | Value::Bool(_) => 1,
        Value::Int(n) => {
            // The argument of a negative integer is `-1 - n`.
            let arg = if *n < 0 { !*n } else { *n };
            head_len(u64::try_from(arg).unwrap_or(u64::MAX))
        }
        Value::Float(_) => 9,
        Value::Bytes(b) => head_len(len_u64(b.len())).saturating_add(b.len()),
        Value::Text(s) => head_len(len_u64(s.len())).saturating_add(s.len()),
        Value::Array(items) => items.iter().fold(head_len(len_u64(items.len())), |n, v| {
            n.saturating_add(encoded_len(v))
        }),
        Value::Map(entries) => {
            entries
                .iter()
                .fold(head_len(len_u64(entries.len())), |n, (k, v)| {
                    n.saturating_add(head_len(len_u64(k.len())))
                        .saturating_add(k.len())
                        .saturating_add(encoded_len(v))
                })
        }
    }
}

/// Encodes `value`.
///
/// Fails with the same `Malformed(..)` kinds the decoder would give for the
/// bytes: nesting over 16, over 10 000 entries, text or bytes over 64 KiB,
/// a duplicate key, an integer outside `-2^63 ..= 2^64 - 1`.
pub fn encode(value: &Value) -> Result<Vec<u8>, Error> {
    let mut enc = Encoder::new(Vec::with_capacity(encoded_len(value)));
    write(&mut enc, value, 0)?;
    Ok(enc.into_writer())
}

fn write(enc: &mut Encoder<Vec<u8>>, value: &Value, depth: usize) -> Result<(), Error> {
    match value {
        Value::Null => {
            enc.null().map_err(write_error)?;
        }
        Value::Bool(b) => {
            enc.bool(*b).map_err(write_error)?;
        }
        Value::Int(n) => {
            if let Ok(u) = u64::try_from(*n) {
                enc.u64(u).map_err(write_error)?;
            } else if let Ok(i) = i64::try_from(*n) {
                enc.i64(i).map_err(write_error)?;
            } else {
                return Err(malformed(MalformedKind::CborInt));
            }
        }
        Value::Float(bits) => {
            enc.f64(f64::from_bits(*bits)).map_err(write_error)?;
        }
        Value::Bytes(b) => {
            if b.len() > MAX_BYTES {
                return Err(malformed(MalformedKind::CborSize));
            }
            enc.bytes(b).map_err(write_error)?;
        }
        Value::Text(s) => {
            if s.len() > MAX_BYTES {
                return Err(malformed(MalformedKind::CborSize));
            }
            enc.str(s).map_err(write_error)?;
        }
        Value::Array(items) => {
            let depth = enter(depth, items.len())?;
            enc.array(len_u64(items.len())).map_err(write_error)?;
            for item in items {
                write(enc, item, depth)?;
            }
        }
        Value::Map(entries) => {
            let depth = enter(depth, entries.len())?;
            enc.map(len_u64(entries.len())).map_err(write_error)?;
            let mut keys = BTreeSet::new();
            for (k, v) in entries {
                if k.len() > MAX_BYTES {
                    return Err(malformed(MalformedKind::CborSize));
                }
                if !keys.insert(k.as_str()) {
                    return Err(malformed(MalformedKind::CborDuplicateKey));
                }
                enc.str(k).map_err(write_error)?;
                write(enc, v, depth)?;
            }
        }
    }
    Ok(())
}

/// One level deeper into a container of `len` entries, or the error.
fn enter(depth: usize, len: usize) -> Result<usize, Error> {
    let next = depth.saturating_add(1);
    if next > MAX_DEPTH {
        return Err(malformed(MalformedKind::CborDepth));
    }
    if len_u64(len) > MAX_ITEMS {
        return Err(malformed(MalformedKind::CborCount));
    }
    Ok(next)
}
