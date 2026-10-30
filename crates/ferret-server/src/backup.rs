//! Backups of the database and the secret files (a later milestone).
//!
//! The kit makes a copy before a migration and nothing else, so the server builds
//! its own scheduled backup. The set holds the database, `opaque_setup`,
//! `prelogin_secret` and `session.key`: without the three secrets a restored
//! database cannot log anybody in.
