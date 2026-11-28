//! A link that the Users page shows once, after the redirect of the post that
//! made it (Spec: Fase 1 § 11, "Invitations").
//!
//! The post that makes an invitation (or sends one again) answers `303` to
//! `GET /settings/accounts?shown=<slot>`, so a reload of the page that shows
//! the link reads the page again and never makes a second invitation. The
//! link itself is never in the redirect, a cookie or a log line: it waits here,
//! in the server's memory, under a random slot id, for the administrator who
//! made it, and the first read of the slot takes it out. A slot that nobody
//! reads goes after [`LIFE_SECS`], and at most [`MAX_SLOTS`] wait at once (the
//! oldest goes first). A slot read by another account, read late or read a
//! second time shows nothing; the invitation is still listed on the page,
//! and "Send again" makes a new link. A restart of the server forgets every
//! slot.

use std::collections::VecDeque;
use std::sync::{Mutex, PoisonError};

use ferret_core::{OsRng, SecureRng as _};
use zeroize::Zeroizing;

/// How long a link waits for its page, in seconds.
pub const LIFE_SECS: i64 = 300;

/// The most links that wait at once.
pub const MAX_SLOTS: usize = 32;

/// The bytes of a slot id (written as 32 hex digits).
const SLOT_BYTES: usize = 16;

struct Slot {
    id: String,
    user_id: i64,
    made_at: i64,
    link: Zeroizing<String>,
}

/// The links that wait to be shown once.
#[derive(Default)]
pub struct ShownOnce {
    slots: Mutex<VecDeque<Slot>>,
}

impl std::fmt::Debug for ShownOnce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The links are secrets: only their number.
        let waiting = self
            .slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len();
        f.debug_struct("ShownOnce")
            .field("waiting", &waiting)
            .finish()
    }
}

impl ShownOnce {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Keeps `link` for `user_id` at `now` (Unix seconds); answers the slot id
    /// that the redirect names.
    pub fn put(&self, user_id: i64, now: i64, link: Zeroizing<String>) -> String {
        let mut bytes = [0u8; SLOT_BYTES];
        OsRng.fill(&mut bytes);
        let id: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let mut slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        slots.retain(|slot| !expired(slot, now));
        while slots.len() >= MAX_SLOTS {
            slots.pop_front();
        }
        slots.push_back(Slot {
            id: id.clone(),
            user_id,
            made_at: now,
            link,
        });
        id
    }

    /// The link of the slot `id`, taken out, when `user_id` made it and it has
    /// not run out; otherwise nothing. A slot is read once, whoever asks.
    pub fn take(&self, id: &str, user_id: i64, now: i64) -> Option<Zeroizing<String>> {
        let mut slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        slots.retain(|slot| !expired(slot, now));
        let at = slots.iter().position(|slot| slot.id == id)?;
        let slot = slots.remove(at)?;
        (slot.user_id == user_id).then_some(slot.link)
    }

    /// How many links wait.
    pub fn waiting(&self) -> usize {
        self.slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

fn expired(slot: &Slot, now: i64) -> bool {
    now < slot.made_at || now - slot.made_at >= LIFE_SECS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(text: &str) -> Zeroizing<String> {
        Zeroizing::new(text.to_string())
    }

    #[test]
    fn a_link_is_read_once_by_the_one_who_made_it() {
        let shown = ShownOnce::new();
        let slot = shown.put(7, 100, link("first"));
        assert_eq!(slot.len(), 32);
        assert!(slot.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(
            shown.take(&slot, 7, 101).as_deref().map(String::as_str),
            Some("first")
        );
        assert!(shown.take(&slot, 7, 102).is_none(), "read once");

        // Another account gets nothing, and the slot is gone for its maker too.
        let slot = shown.put(7, 100, link("second"));
        assert!(shown.take(&slot, 8, 101).is_none());
        assert!(shown.take(&slot, 7, 101).is_none());
        assert!(shown.take("00", 7, 101).is_none());
        assert_eq!(shown.waiting(), 0);
    }

    #[test]
    fn a_link_runs_out_and_the_store_has_a_cap() {
        let shown = ShownOnce::new();
        let slot = shown.put(7, 100, link("late"));
        assert!(shown.take(&slot, 7, 100 + LIFE_SECS).is_none(), "run out");
        let slots: Vec<String> = (0..=MAX_SLOTS)
            .map(|n| shown.put(7, 200, link(&format!("secret-link-{n}"))))
            .collect();
        assert_eq!(shown.waiting(), MAX_SLOTS);
        assert!(
            shown.take(&slots[0], 7, 201).is_none(),
            "the oldest went first"
        );
        assert_eq!(
            shown
                .take(&slots[MAX_SLOTS], 7, 201)
                .as_deref()
                .map(String::as_str),
            Some(format!("secret-link-{MAX_SLOTS}").as_str())
        );
        assert!(
            !format!("{shown:?}").contains("secret-link"),
            "the debug output holds no link: {shown:?}"
        );
    }
}
