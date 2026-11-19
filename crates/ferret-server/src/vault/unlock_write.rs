//! The one way to write a change of unlock methods (a later milestone).
//!
//! A change of the password wrap, of the recovery wrap, or of both goes through
//! one transaction that reads the account, checks the permit that the OPAQUE
//! library gives (and the generation, the manifest and the envelope), writes
//! the account, the wrap, the manifest row and the vault's `seq`, and ends the
//! sessions. Nothing else writes these rows. Spec: Fase 1 § 4.6, § 6.3.
