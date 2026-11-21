//! The proof check of a signed request, as the vault routes may run it.
//!
//! The routes that change the keys, wraps or record of an account (the master
//! password, the recovery, the recovery key) live in `vault/`, which may not
//! name the server's secrets, the throttle or the store of nonces. They take a
//! [`Proofs`] instead: a handle that runs the OPAQUE library's
//! `authorize_signed` and `authorize_replacement` with all of those, and hands
//! back the library's permit and nothing else.
//!
//! What the handle gives:
//!
//! * [`Proofs::signed`]: the permit of a signed request that does not replace
//!   the record (`unlock-method.add`, `.remove`, `.recovery.put`). It needs a
//!   [`FreshReauth`].
//! * [`Proofs::password_put`]: the permit to replace the record with a new
//!   password's (`unlock-method.password.put`). It needs a [`FreshReauth`].
//! * [`Proofs::recover`]: the permit of a recovery, signed with the recovery
//!   key. It needs no re-authentication: a reset session cannot have one.
//!
//! What it does not give: a key, the pre-login secret, the seal key, the
//! pre-login policy, the throttle, the store, a nonce, a sign-in, a
//! registration, or a check of a proof without a nonce bound to the session of
//! the request (the library consumes the nonce before it looks at the proof).
//! Its fields are private, it has no accessor, its `Debug` prints nothing, and
//! the only way to get one is `FromRef` from the server's state. The scope and
//! the session binding come from the [`ScopedSession`], never from the request.
//!
//! The methods are synchronous, so a route can call one inside the transaction
//! that writes the result, against the row it has just read.
//!
//! Spec: Fase 1 § 4.6 and § 6.3.

use std::fmt;
use std::sync::{Arc, OnceLock, PoisonError, RwLock};

use axum::extract::FromRef;
use ferret_core::MutationOp;
use ferret_server_auth::{
    AccountAuthState, AuthContext, AuthError, Caller, Capability, Clock, PreloginPolicy,
    ProfileRules, ReplaceFields, ReplaceKind, ReplacePermit, SignedAccount, SignedPermit, Throttle,
    authorize_replacement, authorize_signed,
};

use crate::auth::secrets::Secrets;
use crate::auth::session::REAUTH_SECS;
use crate::error::ApiError;
use crate::http::extract::{Cap, FreshReauth, ScopedSession, SessionFacts, SignedBody, caps};
use crate::ids::AccountId;
use crate::state::{Challenges, FerretState};

/// The proof checks of signed requests, for the vault routes.
///
/// `Clone` shares everything: the secrets, the clock, the throttle, the
/// pre-login policy and the one store of nonces of the process.
#[derive(Clone)]
pub struct Proofs {
    secrets: Arc<Secrets>,
    clock: Arc<dyn Clock>,
    throttle: Arc<dyn Throttle>,
    prelogin: Arc<RwLock<PreloginPolicy>>,
    challenges: Challenges,
}

impl FromRef<FerretState> for Proofs {
    fn from_ref(state: &FerretState) -> Proofs {
        Proofs {
            secrets: state.secrets.clone(),
            clock: state.clock.clone(),
            throttle: state.throttle.clone(),
            prelogin: state.prelogin.clone(),
            challenges: state.challenges.clone(),
        }
    }
}

impl fmt::Debug for Proofs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Proofs([redacted])")
    }
}

impl Proofs {
    /// Checks the proof of a signed request that does not replace the record,
    /// and gives the library's permit for it.
    ///
    /// Before the library is asked, and so before the nonce is used up:
    ///
    /// * `op` must be an operation whose capability is the session's `C::CAP`
    ///   (`500 internal` otherwise: the route asked for the wrong one);
    /// * `account` must be the session's own account (`500 internal`
    ///   otherwise);
    /// * the re-authentication must be this session's (`500 internal`
    ///   otherwise) and still be fresh now (`403 reauth_required`), not only
    ///   when the request came in.
    ///
    /// Then the library: scope, clock, throttle, the nonce used up, the proof
    /// of `op` over the account, the server's epoch and the exact body. A
    /// refusal answers with the library's public code (`401 denied`, `400
    /// malformed_nonce`, `429 throttled`, ...).
    ///
    /// Spec: Fase 1 § 4.6.
    pub fn signed<C: Cap>(
        &self,
        session: &ScopedSession<C>,
        fresh: &FreshReauth,
        body: &SignedBody,
        caller: Caller,
        op: MutationOp,
        account: &SignedAccount,
    ) -> Result<SignedPermit, ApiError> {
        if capability_of(op) != Some(C::CAP) {
            tracing::error!(
                "a signed request was checked for an operation its route does not have"
            );
            return Err(ApiError::internal());
        }
        own_account(session, &account.account_id)?;
        self.still_fresh(session.session(), fresh)?;
        let request = body.signed_request(session, caller, op);
        self.with_context(|cx| authorize_signed(cx, self.challenges.store(), account, &request))
            .map_err(refused)
    }

    /// Checks a request that replaces the record with a new password's, and
    /// gives the library's permit for it.
    ///
    /// Before the library: `state` must be the session's own account (`500
    /// internal` otherwise), and the re-authentication must be this session's
    /// (`500 internal` otherwise) and still be fresh now (`403
    /// reauth_required`). Then the library: scope, clock, throttle, the
    /// nonce used up, the proof of `unlock-method.password.put` by `sk_a`,
    /// and only then `parse` over the proven bytes, the record and the profile
    /// (never lower than the stored one).
    ///
    /// Spec: Fase 1 § 4.6.
    pub fn password_put(
        &self,
        session: &ScopedSession<caps::PasswordPut>,
        fresh: &FreshReauth,
        body: &SignedBody,
        caller: Caller,
        state: &AccountAuthState<'_>,
        parse: impl FnOnce(&[u8]) -> Result<ReplaceFields, AuthError>,
    ) -> Result<ReplacePermit, ApiError> {
        own_account(session, &state.account.account_id)?;
        self.still_fresh(session.session(), fresh)?;
        let request = body.replace_request(session, caller, ReplaceKind::PasswordPut);
        self.with_context(|cx| {
            authorize_replacement(cx, self.challenges.store(), state, &request, parse)
        })
        .map_err(refused)
    }

    /// Checks a recovery, signed with the recovery key, and gives the
    /// library's permit for it. No re-authentication is asked for: the session
    /// of a recovery is usually the reset session that a one-time code opened.
    ///
    /// Before the library: `state` must be the session's own account (`500
    /// internal` otherwise). Then the library: scope, clock, throttle, the
    /// nonce used up, the proof of `recover` by `sk_r`, and only then `parse`
    /// over the proven bytes, the record, the profile and the new `pk_r`
    /// (which must differ from the stored one).
    ///
    /// Spec: Fase 1 § 4.6 and § 6.3.
    pub fn recover(
        &self,
        session: &ScopedSession<caps::Recover>,
        body: &SignedBody,
        caller: Caller,
        state: &AccountAuthState<'_>,
        parse: impl FnOnce(&[u8]) -> Result<ReplaceFields, AuthError>,
    ) -> Result<ReplacePermit, ApiError> {
        own_account(session, &state.account.account_id)?;
        let request = body.replace_request(session, caller, ReplaceKind::Recover);
        self.with_context(|cx| {
            authorize_replacement(cx, self.challenges.store(), state, &request, parse)
        })
        .map_err(refused)
    }

    /// Runs `f` with the library's context, built from this handle's parts.
    fn with_context<T>(&self, f: impl FnOnce(&AuthContext<'_>) -> T) -> T {
        let policy = self
            .prelogin
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let cx = AuthContext::new(
            &self.secrets.keys,
            &self.secrets.prelogin,
            &self.secrets.seal,
            self.clock.as_ref(),
            self.throttle.as_ref(),
            &policy,
            profiles(),
        );
        f(&cx)
    }

    /// The re-authentication belongs to `session` (`500 internal` otherwise:
    /// a route mixed up two requests) and is still fresh at the clock's time.
    fn still_fresh(&self, session: &SessionFacts, fresh: &FreshReauth) -> Result<(), ApiError> {
        if fresh.sid() != session.sid() {
            tracing::error!("a re-authentication was used for another session");
            return Err(ApiError::internal());
        }
        let now = self.clock.now_unix();
        if now == u64::MAX {
            tracing::error!("the clock failed; no signed request is checked");
            return Err(ApiError::internal());
        }
        let now = i64::try_from(now).map_err(|_| ApiError::internal())?;
        if fresh_at(fresh.reauth_at(), now) {
            Ok(())
        } else {
            Err(ApiError::coded("reauth_required"))
        }
    }
}

/// The rules of the key stretching profiles that a new record is checked
/// against.
fn profiles() -> &'static ProfileRules {
    static RULES: OnceLock<ProfileRules> = OnceLock::new();
    RULES.get_or_init(ProfileRules::ferret_v1)
}

/// The capability an operation of [`Proofs::signed`] needs, or `None` for one
/// that it does not check (the two that replace the record have methods of
/// their own).
fn capability_of(op: MutationOp) -> Option<Capability> {
    match op {
        MutationOp::UnlockMethodAdd
        | MutationOp::UnlockMethodRemove
        | MutationOp::UnlockMethodRecoveryPut => Some(Capability::UnlockMethodsWrite),
        MutationOp::Rekey => Some(Capability::Rekey),
        _ => None,
    }
}

/// `0 <= now - reauth_at <= REAUTH_SECS`, without overflow.
fn fresh_at(reauth_at: i64, now: i64) -> bool {
    now.checked_sub(reauth_at)
        .is_some_and(|age| (0..=REAUTH_SECS).contains(&age))
}

/// The account a route read must be the one of the session. Another one is a
/// mistake of the route, never something a client chose.
fn own_account<C: Cap>(session: &ScopedSession<C>, account: &AccountId) -> Result<(), ApiError> {
    if session.session().account() == *account {
        Ok(())
    } else {
        tracing::error!("a signed request was checked against another account than the session's");
        Err(ApiError::internal())
    }
}

/// The answer to a refusal of the library. The reason is for this log only.
fn refused(error: AuthError) -> ApiError {
    tracing::info!(reason = ?error, "signed request refused");
    ApiError::from(error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_signed_op_needs_its_own_capability_and_the_replacements_have_none() {
        for op in [
            MutationOp::UnlockMethodAdd,
            MutationOp::UnlockMethodRemove,
            MutationOp::UnlockMethodRecoveryPut,
        ] {
            assert_eq!(capability_of(op), Some(Capability::UnlockMethodsWrite));
        }
        assert_eq!(capability_of(MutationOp::Rekey), Some(Capability::Rekey));
        assert_eq!(capability_of(MutationOp::UnlockMethodPasswordPut), None);
        assert_eq!(capability_of(MutationOp::Recover), None);
    }

    #[test]
    fn a_reauth_is_fresh_for_300_seconds_and_never_from_the_future() {
        assert!(fresh_at(1_000, 1_000));
        assert!(fresh_at(1_000, 1_300));
        assert!(!fresh_at(1_000, 1_301));
        assert!(!fresh_at(1_001, 1_000));
        assert!(!fresh_at(i64::MIN, i64::MAX));
        assert!(!fresh_at(i64::MAX, i64::MIN));
    }
}
