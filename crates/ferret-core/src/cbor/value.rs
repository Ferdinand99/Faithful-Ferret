//! The CBOR data model of the core.

use zeroize::Zeroize;

/// A CBOR data item as the core allows it.
///
/// A map is a list of `(key, value)` pairs in the order they were read or
/// will be written; keys are text and are unique (the decoder and encoder
/// check it). Floats are kept as their IEEE 754 bit pattern so that equality
/// is exact and a NaN round-trips unchanged.
///
/// The value wipes its text and bytes when it is dropped, because a body
/// holds passwords and key material. That means a `Value` cannot be taken
/// apart by moving fields out of a pattern; use the `into_*` methods.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Value {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// An integer in `-2^63 ..= 2^64 - 1`. Use [`Value::uint`] and
    /// [`Value::int`] to build one without thinking about the range.
    Int(i128),
    /// A 64-bit float, as its bit pattern. Use [`Value::float`].
    Float(u64),
    /// A byte string.
    Bytes(Vec<u8>),
    /// A text string.
    Text(String),
    /// A definite-length array.
    Array(Vec<Value>),
    /// A definite-length map with unique text keys.
    Map(Vec<(String, Value)>),
}

impl Value {
    /// An unsigned integer.
    pub fn uint(n: u64) -> Self {
        Value::Int(i128::from(n))
    }

    /// A signed integer.
    pub fn int(n: i64) -> Self {
        Value::Int(i128::from(n))
    }

    /// A float.
    pub fn float(x: f64) -> Self {
        Value::Float(x.to_bits())
    }

    /// A text value.
    pub fn text(s: impl Into<String>) -> Self {
        Value::Text(s.into())
    }

    /// The text, if this is text.
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(s) => Some(s),
            _ => None,
        }
    }

    /// The value as `u64`, if it is an integer in that range.
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Int(n) => u64::try_from(*n).ok(),
            _ => None,
        }
    }

    /// The value of the key in a map, if this is a map that has the key.
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Map(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// Takes the text out, leaving an empty text behind. `Err(self)` for
    /// any other kind of value.
    pub fn into_text(mut self) -> Result<String, Value> {
        match &mut self {
            Value::Text(s) => Ok(core::mem::take(s)),
            _ => Err(self),
        }
    }

    /// Takes the bytes out. `Err(self)` for any other kind of value.
    pub fn into_bytes(mut self) -> Result<Vec<u8>, Value> {
        match &mut self {
            Value::Bytes(b) => Ok(core::mem::take(b)),
            _ => Err(self),
        }
    }

    /// Takes the elements out. `Err(self)` for any other kind of value.
    pub fn into_array(mut self) -> Result<Vec<Value>, Value> {
        match &mut self {
            Value::Array(a) => Ok(core::mem::take(a)),
            _ => Err(self),
        }
    }

    /// Takes the entries out. `Err(self)` for any other kind of value.
    pub fn into_map(mut self) -> Result<Vec<(String, Value)>, Value> {
        match &mut self {
            Value::Map(m) => Ok(core::mem::take(m)),
            _ => Err(self),
        }
    }
}

impl Zeroize for Value {
    fn zeroize(&mut self) {
        match self {
            Value::Null | Value::Bool(_) => {}
            Value::Int(n) => n.zeroize(),
            Value::Float(bits) => bits.zeroize(),
            Value::Bytes(b) => b.zeroize(),
            Value::Text(s) => s.zeroize(),
            Value::Array(items) => {
                for item in items.iter_mut() {
                    item.zeroize();
                }
                items.clear();
            }
            Value::Map(entries) => {
                for (k, v) in entries.iter_mut() {
                    k.zeroize();
                    v.zeroize();
                }
                entries.clear();
            }
        }
    }
}

impl Drop for Value {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Entries of a map that is being taken apart field by field: the known
/// keys are removed one at a time and what is left, in the original order,
/// is the unknown part that must be written back unchanged.
pub(crate) struct Entries(Vec<(String, Value)>);

impl Entries {
    pub(crate) fn new(entries: Vec<(String, Value)>) -> Self {
        Self(entries)
    }

    /// Removes and returns the value of `key`.
    pub(crate) fn take(&mut self, key: &str) -> Option<Value> {
        let at = self.0.iter().position(|(k, _)| k == key)?;
        let (mut k, v) = self.0.remove(at);
        k.zeroize();
        Some(v)
    }

    /// The entries that were not taken, in their original order.
    pub fn into_rest(self) -> Vec<(String, Value)> {
        self.0
    }
}

/// Marks a type whose `Debug` must not print its contents.
macro_rules! redacted_debug {
    ($($ty:ty),+ $(,)?) => {$(
        impl ::core::fmt::Debug for $ty {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.debug_struct(stringify!($ty)).finish_non_exhaustive()
            }
        }
    )+};
}
pub(crate) use redacted_debug;
