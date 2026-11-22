//! Earlier passwords of an item, kept inside the encrypted body.
//!
//! Spec: Fase 1 § 5.2 and Appendix B (the optional `password_history` key of
//! the body).
//!
//! ```text
//! "password_history": [ { "value": text, "until": u64 } ]?   // at most 5, newest first
//! ```
//!
//! When an update replaces the password of an item and asks for the history
//! to be kept, the old value of the field with the id `password`
//! ([`PASSWORD_FIELD_ID`]) goes to the front of this list, with `until`, the
//! time (unix milliseconds) at which it stopped being the password. The list
//! holds at most [`MAX_PASSWORD_HISTORY`] entries; the oldest goes first.
//!
//! As with `folders`, the key is stored with the keys this version does not
//! type ([`ItemBody::extra`]): at the place it was read, or after them when
//! it is new. A body without history is written byte for byte as before, an
//! older client keeps the key as an unknown one, and every other unknown key
//! stays where it was.
//!
//! **Reading** ([`ItemBody::password_history`]) is lenient, because another
//! client may have written the key: a value that is not a list, an entry that
//! is not a map with a text `value` and an unsigned `until`, and every entry
//! after the fifth are left out of what is returned. The body is not changed
//! by a read.
//!
//! **Writing** ([`ItemBody::push_password_history`]) puts the new entry first,
//! keeps the entries that the read returns (with any keys of their own that
//! this version does not know), and drops the rest; the entries that are
//! dropped are wiped. A body of a newer schema is `read_only_schema`.
//!
//! Nothing here goes to the interface except through the redacted view
//! ([`super::view::ItemView::password_history`]: the dates only) and the one
//! value that the user asks to see.

use super::body::ItemBody;
use crate::cbor::{Value, redacted_debug};
use crate::error::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The key of the earlier passwords in the body.
pub const PASSWORD_HISTORY_KEY: &str = "password_history";

/// The most earlier passwords one item keeps.
pub const MAX_PASSWORD_HISTORY: usize = 5;

/// The id of the field whose earlier values the history keeps.
pub const PASSWORD_FIELD_ID: &str = "password";

/// One earlier password. Wiped when it is dropped; `Debug` shows nothing.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct PasswordHistoryEntry {
    /// The password as it was.
    pub value: String,
    /// When it stopped being the password, unix milliseconds.
    pub until: u64,
}

redacted_debug!(PasswordHistoryEntry);

/// The value and the date of an entry that has the form of the module
/// documentation, without a copy.
fn read_entry(entry: &Value) -> Option<(&str, u64)> {
    let value = entry.get("value")?.as_text()?;
    let until = entry.get("until")?.as_u64()?;
    Some((value, until))
}

impl ItemBody {
    /// The stored list, if the key is there and holds a list.
    fn history_list(&self) -> Option<&Vec<Value>> {
        match self.extra.iter().find(|(k, _)| k == PASSWORD_HISTORY_KEY) {
            Some((_, Value::Array(entries))) => Some(entries),
            _ => None,
        }
    }

    /// The entries that a read returns, borrowed: newest first, at most
    /// [`MAX_PASSWORD_HISTORY`], the ones without the right form left out.
    pub(crate) fn password_history_refs(&self) -> Vec<(&str, u64)> {
        self.history_list()
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(read_entry)
                    .take(MAX_PASSWORD_HISTORY)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The earlier passwords of the item, newest first (see the module
    /// documentation). Empty when the body has no `password_history` key.
    pub fn password_history(&self) -> Vec<PasswordHistoryEntry> {
        self.password_history_refs()
            .into_iter()
            .map(|(value, until)| PasswordHistoryEntry {
                value: value.to_owned(),
                until,
            })
            .collect()
    }

    /// Puts `old` at the front of the earlier passwords, with the time
    /// `until_ms` at which it stopped being the password, and keeps at most
    /// [`MAX_PASSWORD_HISTORY`] entries (see the module documentation). A
    /// body of a newer schema is `read_only_schema`, and is left as it was.
    pub fn push_password_history(&mut self, old: &str, until_ms: u64) -> Result<(), Error> {
        if self.is_read_only() {
            return Err(Error::ReadOnlySchema);
        }
        let at = self
            .extra
            .iter()
            .position(|(k, _)| k == PASSWORD_HISTORY_KEY);
        let mut previous = match at.and_then(|i| self.extra.get_mut(i)) {
            Some((_, value)) => core::mem::replace(value, Value::Null),
            None => Value::Null,
        };
        let mut kept: Vec<Value> = Vec::with_capacity(MAX_PASSWORD_HISTORY);
        kept.push(Value::Map(vec![
            ("value".to_owned(), Value::text(old)),
            ("until".to_owned(), Value::uint(until_ms)),
        ]));
        if let Value::Array(entries) = &mut previous {
            for entry in entries.iter_mut() {
                if kept.len() < MAX_PASSWORD_HISTORY && read_entry(entry).is_some() {
                    kept.push(core::mem::replace(entry, Value::Null));
                }
            }
        }
        // What is left of the old value (entries past the fifth, entries of
        // the wrong form, a value that was not a list) is wiped.
        previous.zeroize();
        let list = Value::Array(kept);
        match at.and_then(|i| self.extra.get_mut(i)) {
            Some(entry) => entry.1 = list,
            None => self.extra.push((PASSWORD_HISTORY_KEY.to_owned(), list)),
        }
        Ok(())
    }

    /// Keeps the old password of an edit: when `previous` (the body before
    /// the edit) has a field with the id [`PASSWORD_FIELD_ID`] whose value is
    /// not empty, and this body (after the edit) does not have the same value
    /// there (compared in constant time; a field that is gone counts as
    /// empty), the old value goes to the front of this body's history with
    /// `until_ms`. Returns whether it did. Nothing leaves the core: the old
    /// value is copied from one body to the other.
    ///
    /// A body of a newer schema is `read_only_schema`.
    pub fn keep_replaced_password(
        &mut self,
        previous: &ItemBody,
        until_ms: u64,
    ) -> Result<bool, Error> {
        let Some(old) = previous
            .fields
            .iter()
            .find(|f| f.id == PASSWORD_FIELD_ID)
            .map(|f| f.value.as_str())
            .filter(|v| !v.is_empty())
        else {
            return Ok(false);
        };
        if self.field_value_equals(PASSWORD_FIELD_ID, old.as_bytes()) {
            return Ok(false);
        }
        self.push_password_history(old, until_ms)?;
        Ok(true)
    }

    /// Whether the value of the first field with the id `field_id` is
    /// `candidate`, byte for byte (UTF-8, no normalisation). The bytes are
    /// compared in constant time (`subtle`, through the core's `ct_eq`); the
    /// lengths are compared first and are not hidden. `false` when the item
    /// has no field with that id. Only that one field is read.
    pub fn field_value_equals(&self, field_id: &str, candidate: &[u8]) -> bool {
        self.fields
            .iter()
            .find(|f| f.id == field_id)
            .is_some_and(|f| crate::prim::ct::ct_eq(f.value.as_bytes(), candidate))
    }
}
