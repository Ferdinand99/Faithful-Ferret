//! Several accounts on one server: the account log and the actions an
//! administrator (or a command on the server) takes on an account.
//!
//! * [`log`]: the account log (`ferret_account_events`), what was done to an
//!   account and by whom, and `GET /api/account/events`, where the account
//!   reads its own.
//! * [`actions`]: the actions on another account, each with its event, and the
//!   one set of rules that says which account may be acted on.
//!
//! Spec: Fase 1 § 11 ("Several accounts") and § 6.3 (every code is in the
//! account log).

pub mod actions;
pub mod log;
