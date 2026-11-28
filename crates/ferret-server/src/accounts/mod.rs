//! Several accounts on one server: the account log and the actions an
//! administrator (or a command on the server) takes on an account.
//!
//! * [`log`]: the account log (`ferret_account_events`), what was done to an
//!   account and by whom, and `GET /api/account/events`, where the account
//!   reads its own.
//! * [`actions`]: the actions on another account, each with its event, and the
//!   one set of rules that says which account may be acted on.
//! * [`invites`]: invitations, how a new account is made from one, the check
//!   of a link (`POST /api/auth/invite/check`) and the count of starts per
//!   invitation.
//!
//! Spec: Fase 1 § 11 ("Several accounts"), § 6.3 (every code is in the
//! account log) and § 4.2 (registration with an invitation).

pub mod actions;
pub mod invites;
pub mod log;
