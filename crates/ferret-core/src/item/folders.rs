//! Folder names of an item: labels kept inside the encrypted body.
//!
//! Spec: Fase 1 § 5.2 (the optional `folders` key of the body).
//!
//! ```text
//! "folders": [ text ]?        // at most 20 names, each 1..=64 characters
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
//! each name is trimmed of white space at both ends; a trimmed name must have
//! 1 to 64 characters (Unicode scalar values); an item has at most 20 names;
//! two names that are equal when case is ignored (each character in lower
//! case, as `char::to_lowercase` maps it) are refused. A name that breaks a
//! rule is an error, never dropped. The order is kept as given; a list is
//! sorted for display only. An empty list removes the key.
//!
//! **Reading** ([`ItemBody::folders`]) is lenient, because another client may
//! have written the key: a value that is not a list, an entry that is not
//! text, a name that breaks a rule once trimmed, a repeat of an earlier name
//! and every name after the 20th are left out of what is returned. The body
//! itself is not changed by a read, so such a value is kept until a write
//! sets the folders.

use super::body::ItemBody;
use crate::cbor::Value;
use crate::error::{Error, FolderError};

/// The key of the folder names in the body.
pub const FOLDERS_KEY: &str = "folders";

/// The most folder names one item may carry.
pub const MAX_FOLDERS: usize = 20;

/// The most characters (Unicode scalar values) in one folder name, after it
/// is trimmed.
pub const MAX_FOLDER_CHARS: usize = 64;

/// Checks one trimmed name against the length rules.
fn check_name(name: &str) -> Result<(), FolderError> {
    if name.is_empty() {
        return Err(FolderError::Empty);
    }
    if name.chars().nth(MAX_FOLDER_CHARS).is_some() {
        return Err(FolderError::TooLong);
    }
    Ok(())
}

/// Whether two names are the same folder: equal when every character is put
/// in lower case.
pub fn same_folder(a: &str, b: &str) -> bool {
    a.chars()
        .flat_map(char::to_lowercase)
        .eq(b.chars().flat_map(char::to_lowercase))
}

/// The folder names of `names` as they are stored: each trimmed, in the
/// order given.
///
/// Fails with `Folder(TooMany)` for more than [`MAX_FOLDERS`] names,
/// `Folder(Empty)` for a name that is only white space, `Folder(TooLong)`
/// for one over [`MAX_FOLDER_CHARS`] characters once trimmed, and
/// `Folder(Duplicate)` for two names that are equal when case is ignored.
pub fn normalize_folders(names: &[String]) -> Result<Vec<String>, Error> {
    if names.len() > MAX_FOLDERS {
        return Err(Error::Folder(FolderError::TooMany));
    }
    let mut out: Vec<String> = Vec::with_capacity(names.len());
    for raw in names {
        let name = raw.trim();
        check_name(name).map_err(Error::Folder)?;
        if out.iter().any(|seen| same_folder(seen, name)) {
            return Err(Error::Folder(FolderError::Duplicate));
        }
        out.push(name.to_owned());
    }
    Ok(out)
}

impl ItemBody {
    /// The folder names of the item, in the order they are stored. Empty
    /// when the body has no `folders` key (every item written before folders
    /// existed). A stored value that breaks the rules is read leniently (see
    /// the module documentation); the body is not changed.
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
            let Some(name) = entry.as_text().map(str::trim) else {
                continue;
            };
            if check_name(name).is_err() || out.iter().any(|seen| same_folder(seen, name)) {
                continue;
            }
            out.push(name.to_owned());
        }
        out
    }

    /// Sets the folder names of the item to `names`, checked and trimmed by
    /// [`normalize_folders`]. An empty list removes the `folders` key. The
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
