//! Ferret's own sessions: a random session id in `__Host-ferret_sid`, a row in
//! `ferret_sessions` keyed by its hash, and the kit's signed cookie next to it.
//! Both must agree on every request. Spec: Fase 1 § 7.6.
//!
//! Limits: the vault origin 12 hours idle and 7 days absolute, the admin origin
//! 1 hour idle and 12 hours absolute.
