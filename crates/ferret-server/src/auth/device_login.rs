//! The sign-in of a device client (Spec: Fase 1 § 7.6; RFC 9449 § 5).
//!
//! A device client finishes the OPAQUE sign-in on the same path as the web
//! vault, `POST /api/auth/opaque/login/finish`, with the body
//! [`crate::wire::DeviceLoginFinishReq`] (the key `client` tells it from the
//! cookie body, see [`crate::wire::LoginFinishBody`]) and a DPoP proof of its
//! new key in the `DPoP` header. Instead of a session cookie it gets a device
//! row, an access token and a refresh token
//! ([`crate::wire::DeviceLoginFinishRes`]).
//!
//! The proof is checked before the sign-in state is taken and before any
//! account is read, so the answer to a bad proof is the same `401
//! dpop_invalid` for an account that exists and one that does not. The
//! proof's `jti` is recorded only after the device row is written, inside the
//! same transaction.
//!
//! Not built yet: the sign-in route reads the cookie body only.
