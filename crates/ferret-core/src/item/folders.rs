//! Folder names of an item: labels kept inside the encrypted body.
//!
//! Spec: Fase 1 § 5.2 and Appendix B (the optional `folders` key of the body).
//!
//! ```text
//! "folders": [ text ]?        // at most 20 names, each 1..=64 characters, NFC
//! ```
//!
//! An item can be in several folders, or in none. A folder exists only as a
//! name that one or more items carry: there is no list of folders anywhere
//! else, and the server never sees a name.
//!
//! The key is stored with the keys this version does not type
//! ([`ItemBody::extra`]), at the place it was read or, when it is new, after
//! them. So a body without folders is written byte for byte as before, an
//! older client keeps the key as an unknown one, and every other unknown key
//! stays where it was.
//!
//! **Rules for a write** ([`normalize_folders`], [`ItemBody::set_folders`]):
//!
//! * each name is put in Unicode NFC and then trimmed of white space at both
//!   ends, and that form is what is stored;
//! * a name must then have 1 to 64 characters (Unicode scalar values);
//! * a name must not hold a control character (general category Cc), the
//!   line or paragraph separator (U+2028, U+2029), a bidirectional mark,
//!   embedding, override or isolate (U+061C, U+200E, U+200F, U+202A to
//!   U+202E, U+2066 to U+2069), the zero width space (U+200B) or the byte
//!   order mark (U+FEFF). The zero width joiner and non-joiner (U+200C,
//!   U+200D) are allowed: scripts and emoji need them;
//! * an item has at most 20 names;
//! * two names that are equal when case is ignored are refused. Case is
//!   ignored by putting each character of the NFC form in lower case, as
//!   `char::to_lowercase` maps it ([`same_folder`]). This is simple lowercase
//!   mapping, not full case folding: "Straße" and "STRASSE" are two names.
//!
//! A name that breaks a rule is an error, never dropped. The order is kept as
//! given; a list is sorted for display only. An empty list removes the key.
//!
//! **Reading** ([`ItemBody::folders`]) is lenient, because another client may
//! have written the key: a value that is not a list, an entry that is not
//! text, a name that breaks a rule once in NFC and trimmed, a repeat of an
//! earlier name and every name after the 20th are left out of what is
//! returned, and the names that are returned are in NFC. The body itself is
//! not changed by a read, so such a value is kept until a write sets the
//! folders. A write that sets them stores the list it is given; a client that
//! sends back the list it read (to rename a folder, say) therefore drops the
//! entries the read left out. That is expected: they broke the rules.

use super::body::ItemBody;
use crate::cbor::Value;
use crate::error::{Error, FolderError};
use unicode_normalization::UnicodeNormalization;

/// The key of the folder names in the body.
pub const FOLDERS_KEY: &str = "folders";

/// The most folder names one item may carry.
pub const MAX_FOLDERS: usize = 20;

/// The most characters (Unicode scalar values) in one folder name, after it
/// is put in NFC and trimmed.
pub const MAX_FOLDER_CHARS: usize = 64;

/// Whether `c` may not appear in a folder name (see the module
/// documentation).
pub(crate) fn is_refused(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{2028}'
                | '\u{2029}'
                | '\u{061C}'
                | '\u{200E}'
                | '\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2066}'..='\u{2069}'
                | '\u{200B}'
                | '\u{FEFF}'
        )
}

/// The NFC form of `raw`, trimmed.
pub(crate) fn nfc_trimmed(raw: &str) -> String {
    let nfc: String = raw.nfc().collect();
    nfc.trim().to_owned()
}

/// Checks one name in NFC, trimmed, against the rules for one name.
fn check_name(name: &str) -> Result<(), FolderError> {
    if name.is_empty() {
        return Err(FolderError::Empty);
    }
    if name.chars().any(is_refused) {
        return Err(FolderError::BadCharacter);
    }
    if name.chars().nth(MAX_FOLDER_CHARS).is_some() {
        return Err(FolderError::TooLong);
    }
    Ok(())
}

/// Whether two names are the same folder: equal when both are put in NFC and
/// every character is put in lower case.
pub fn same_folder(a: &str, b: &str) -> bool {
    a.nfc()
        .flat_map(char::to_lowercase)
        .eq(b.nfc().flat_map(char::to_lowercase))
}

/// The folder names of `names` as they are stored: each in NFC and trimmed,
/// in the order given.
///
/// Fails with `Folder(TooMany)` for more than [`MAX_FOLDERS`] names,
/// `Folder(Empty)` for a name that is only white space,
/// `Folder(BadCharacter)` for a name with a character the module
/// documentation lists, `Folder(TooLong)` for one over [`MAX_FOLDER_CHARS`]
/// characters, and `Folder(Duplicate)` for two names that are equal when
/// case is ignored.
pub fn normalize_folders(names: &[String]) -> Result<Vec<String>, Error> {
    if names.len() > MAX_FOLDERS {
        return Err(Error::Folder(FolderError::TooMany));
    }
    let mut out: Vec<String> = Vec::with_capacity(names.len());
    for raw in names {
        let name = nfc_trimmed(raw);
        check_name(&name).map_err(Error::Folder)?;
        if out.iter().any(|seen| same_folder(seen, &name)) {
            return Err(Error::Folder(FolderError::Duplicate));
        }
        out.push(name);
    }
    Ok(out)
}

impl ItemBody {
    /// The folder names of the item, in the order they are stored and in
    /// NFC. Empty when the body has no `folders` key (every item written
    /// before folders existed). A stored value that breaks the rules is read
    /// leniently (see the module documentation); the body is not changed.
    pub fn folders(&self) -> Vec<String> {
        let Some((_, Value::Array(entries))) = self.extra.iter().find(|(k, _)| k == FOLDERS_KEY)
        else {
            return Vec::new();
        };
        let mut out: Vec<String> = Vec::new();
        for entry in entries {
            if out.len() >= MAX_FOLDERS {
                break;
            }
            let Some(name) = entry.as_text().map(nfc_trimmed) else {
                continue;
            };
            if check_name(&name).is_err() || out.iter().any(|seen| same_folder(seen, &name)) {
                continue;
            }
            out.push(name);
        }
        out
    }

    /// Sets the folder names of the item to `names`, checked and put in NFC
    /// by [`normalize_folders`]. An empty list removes the `folders` key. The
    /// key keeps its place among the unknown keys; a new one goes after
    /// them. A body of a newer schema is `read_only_schema`.
    ///
    /// On an error the body is left as it was.
    pub fn set_folders(&mut self, names: &[String]) -> Result<(), Error> {
        if self.is_read_only() {
            return Err(Error::ReadOnlySchema);
        }
        let folders = normalize_folders(names)?;
        let at = self.extra.iter().position(|(k, _)| k == FOLDERS_KEY);
        if folders.is_empty() {
            if let Some(i) = at {
                self.extra.remove(i);
            }
            return Ok(());
        }
        let value = Value::Array(folders.into_iter().map(Value::Text).collect());
        match at.and_then(|i| self.extra.get_mut(i)) {
            Some(entry) => entry.1 = value,
            None => self.extra.push((FOLDERS_KEY.to_owned(), value)),
        }
        Ok(())
    }
}
