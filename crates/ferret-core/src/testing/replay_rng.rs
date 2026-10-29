//! `ReplayRng` plays back the recorded draws of a test vector; `TestRng`
//! creates those recordings. Neither is secure.

use crate::rng::SecureRng;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::collections::VecDeque;

/// Why [`ReplayRng::finish`] failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayError {
    /// The core made fewer draws than the vector records.
    NotExhausted {
        /// Number of recorded draws that were never consumed.
        remaining: usize,
    },
}

/// Plays back a fixed list of draws, in order.
///
/// A vector records the sequence of *draws* the core makes (one entry per
/// `fill` call). Every consumer uses `ReplayRng`, so a difference in the
/// number, length or order of draws is an error, and the vectors do not
/// depend on which RNG made them.
///
/// `fill` panics on a mismatch (no draws left, or a different length): the
/// vector runner catches the panic and reports a failed case. After the
/// operation, [`ReplayRng::finish`] must succeed.
#[derive(Debug)]
pub struct ReplayRng {
    draws: VecDeque<Vec<u8>>,
}

impl ReplayRng {
    /// A replay of `draws`, first draw first.
    pub fn new(draws: Vec<Vec<u8>>) -> Self {
        Self {
            draws: draws.into(),
        }
    }

    /// Number of draws not yet consumed.
    pub fn remaining(&self) -> usize {
        self.draws.len()
    }

    /// Succeeds only if every recorded draw was consumed.
    pub fn finish(self) -> Result<(), ReplayError> {
        if self.draws.is_empty() {
            Ok(())
        } else {
            Err(ReplayError::NotExhausted {
                remaining: self.draws.len(),
            })
        }
    }
}

impl SecureRng for ReplayRng {
    fn fill(&mut self, dest: &mut [u8]) {
        let Some(next) = self.draws.pop_front() else {
            panic!("replay rng: draw of {} bytes but no draws left", dest.len());
        };
        assert!(
            next.len() == dest.len(),
            "replay rng: draw of {} bytes but the recorded draw has {} bytes",
            dest.len(),
            next.len()
        );
        dest.copy_from_slice(&next);
    }
}

/// Deterministic generator for *making* vectors: HMAC-SHA256 in counter mode
/// over a seed (`hmac-sha256-ctr(seed)`). Block `i` is
/// `HMAC-SHA256(key = seed, msg = u64be(i))`, and draws consume the
/// concatenated blocks in order. Never secure; never used in production.
#[derive(Debug)]
pub struct TestRng {
    mac: Hmac<Sha256>,
    counter: u64,
    block: [u8; 32],
    used: usize,
}

impl TestRng {
    /// A generator over `seed`.
    pub fn new(seed: &[u8]) -> Self {
        Self {
            mac: <Hmac<Sha256> as KeyInit>::new_from_slice(seed)
                .expect("HMAC accepts keys of any length"),
            counter: 0,
            block: [0; 32],
            used: 32,
        }
    }

    fn refill(&mut self) {
        let mut mac = self.mac.clone();
        mac.update(&self.counter.to_be_bytes());
        self.block.copy_from_slice(&mac.finalize().into_bytes());
        self.counter += 1;
        self.used = 0;
    }
}

impl SecureRng for TestRng {
    fn fill(&mut self, dest: &mut [u8]) {
        let mut written = 0;
        while written < dest.len() {
            if self.used == self.block.len() {
                self.refill();
            }
            let n = (dest.len() - written).min(self.block.len() - self.used);
            dest[written..written + n].copy_from_slice(&self.block[self.used..self.used + n]);
            self.used += n;
            written += n;
        }
    }
}
