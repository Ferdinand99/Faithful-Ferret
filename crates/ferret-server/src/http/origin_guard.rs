//! The `Origin` and `Ferret-Protocol` check on every mutating request, and the
//! fetch-metadata check for requests with a cookie.
//!
//! Spec: Fase 1 § 8.2. The origin is compared with the configured public URL of
//! the listener (`config::Origins`), never with the `Host` header. Ferret sends
//! no CORS headers at all.
