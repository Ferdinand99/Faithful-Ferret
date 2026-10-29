//! The strict CBOR decoder.
//!
//! Spec: Fase 1 § 5.2 ("Dekoderen avviser ...") and plan U10.

use super::Value;
use crate::error::{Error, MalformedKind};
use minicbor::Decoder;
use minicbor::data::Type;
use std::collections::BTreeSet;

/// Deepest nesting of arrays and maps. A scalar at the top is depth 0, an
/// array holding a scalar is depth 1.
pub const MAX_DEPTH: usize = 16;
/// Most entries in one array or map.
pub const MAX_ITEMS: u64 = 10_000;
/// Longest text or byte string in bytes.
pub const MAX_BYTES: usize = 65_536;

const fn malformed(kind: MalformedKind) -> Error {
    Error::Malformed(kind)
}

/// Any error from the low-level decoder: syntax, truncation, bad UTF-8.
fn syntax(_: minicbor::decode::Error) -> Error {
    malformed(MalformedKind::Cbor)
}

/// Decodes exactly one data item from `input` and checks it against the
/// limits. Bytes after the item are an error.
///
/// Every failure is `Error::Malformed(..)` with the code of the rule that
/// was broken. The decoder never panics and never reserves more memory than
/// the input could fill.
///
/// Spec: Fase 1 § 5.2.
pub fn decode(input: &[u8]) -> Result<Value, Error> {
    let mut d = Decoder::new(input);
    let value = item(&mut d, 0)?;
    if d.position() != input.len() {
        return Err(malformed(MalformedKind::CborTrailing));
    }
    Ok(value)
}

/// How many bytes are left to read.
fn remaining(d: &Decoder<'_>) -> usize {
    d.input().len().saturating_sub(d.position())
}

/// The number of entries of a definite array or map, within the limit.
fn count(len: Option<u64>) -> Result<usize, Error> {
    let len = len.ok_or(malformed(MalformedKind::CborIndefinite))?;
    if len > MAX_ITEMS {
        return Err(malformed(MalformedKind::CborCount));
    }
    usize::try_from(len).map_err(|_| malformed(MalformedKind::CborCount))
}

fn item(d: &mut Decoder<'_>, depth: usize) -> Result<Value, Error> {
    match d.datatype().map_err(syntax)? {
        Type::Null => d.null().map(|()| Value::Null).map_err(syntax),
        Type::Bool => d.bool().map(Value::Bool).map_err(syntax),
        Type::U8 | Type::U16 | Type::U32 | Type::U64 => d.u64().map(Value::uint).map_err(syntax),
        Type::I8 | Type::I16 | Type::I32 | Type::I64 => d.i64().map(Value::int).map_err(syntax),
        // A negative integer below -2^63 (head `0x3b` with the top bit set).
        Type::Int => Err(malformed(MalformedKind::CborInt)),
        Type::F64 => d.f64().map(Value::float).map_err(syntax),
        Type::F16 | Type::F32 => Err(malformed(MalformedKind::CborFloat)),
        Type::Undefined | Type::Simple => Err(malformed(MalformedKind::CborSimple)),
        Type::Tag => Err(malformed(MalformedKind::CborTag)),
        Type::BytesIndef | Type::StringIndef | Type::ArrayIndef | Type::MapIndef => {
            Err(malformed(MalformedKind::CborIndefinite))
        }
        Type::Bytes => {
            let bytes = d.bytes().map_err(syntax)?;
            if bytes.len() > MAX_BYTES {
                return Err(malformed(MalformedKind::CborSize));
            }
            Ok(Value::Bytes(bytes.to_vec()))
        }
        Type::String => text(d).map(|s| Value::Text(s.to_owned())),
        Type::Array => {
            let depth = enter(depth)?;
            let n = count(d.array().map_err(syntax)?)?;
            // One entry takes at least one byte.
            let mut items = Vec::with_capacity(n.min(remaining(d)));
            for _ in 0..n {
                items.push(item(d, depth)?);
            }
            Ok(Value::Array(items))
        }
        Type::Map => {
            let depth = enter(depth)?;
            let n = count(d.map().map_err(syntax)?)?;
            // One entry takes at least two bytes.
            let mut entries = Vec::with_capacity(n.min(remaining(d) / 2));
            let mut keys = BTreeSet::new();
            for _ in 0..n {
                let k = key(d)?;
                if !keys.insert(k) {
                    return Err(malformed(MalformedKind::CborDuplicateKey));
                }
                entries.push((k.to_owned(), item(d, depth)?));
            }
            Ok(Value::Map(entries))
        }
        Type::Break | Type::Unknown(_) => Err(malformed(MalformedKind::Cbor)),
    }
}

/// One level deeper, or the depth error.
fn enter(depth: usize) -> Result<usize, Error> {
    let next = depth.saturating_add(1);
    if next > MAX_DEPTH {
        return Err(malformed(MalformedKind::CborDepth));
    }
    Ok(next)
}

/// A text string within the size limit.
fn text<'b>(d: &mut Decoder<'b>) -> Result<&'b str, Error> {
    let s = d.str().map_err(syntax)?;
    if s.len() > MAX_BYTES {
        return Err(malformed(MalformedKind::CborSize));
    }
    Ok(s)
}

/// A map key: text, and nothing else.
fn key<'b>(d: &mut Decoder<'b>) -> Result<&'b str, Error> {
    match d.datatype().map_err(syntax)? {
        Type::String => text(d),
        Type::StringIndef => Err(malformed(MalformedKind::CborIndefinite)),
        _ => Err(malformed(MalformedKind::CborKeyType)),
    }
}
