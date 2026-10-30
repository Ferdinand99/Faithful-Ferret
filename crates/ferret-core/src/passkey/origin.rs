//! Origins and relying party IDs.
//!
//! Spec: Fase 1 § 9.2 (F-12). The origin comes from the caller:
//! in the browser extension from `sender.origin` of the calling frame (checked
//! against `webNavigation.getFrame`), never from the page.
//!
//! # Rules
//!
//! * Only `https`, and `http://localhost` for development. Nothing else is an
//!   origin: `null`, `about:blank`, `srcdoc`, `data:`, `file:` and opaque
//!   origins are rejected.
//! * The host is converted to an IDNA (UTS 46, STD3 rules) A-label, in lower
//!   case, with one trailing dot removed. IP hosts are rejected (IPv6 in
//!   brackets, IPv4 in any notation the URL standard reads as an address,
//!   including hexadecimal and full-width digits).
//! * A port that is not the default of the scheme is kept in the origin
//!   (`https://a.b:8443`), because the relying party compares the whole
//!   string in `clientDataJSON.origin`. The default port is dropped. An RP ID
//!   never has a port.
//! * The RP ID is the host, or a dot-delimited suffix of it, and never a
//!   public suffix (the embedded Public Suffix List with the private
//!   domains: `github.io` is a public suffix and `a.github.io` is a host of
//!   its own). `localhost` is the one RP ID that is allowed without being a
//!   registrable domain, for development.
//!
//! # Mobile (recorded, not implemented here: Fase 1 § 7.4, § 7.5, § 9.7, F-36)
//!
//! On iOS (`ASCredentialProviderViewController`) and Android (Credential
//! Manager) the operating system says who the caller is, and Ferret trusts
//! only that. For apps the link is the associated domain (`webcredentials`) on
//! iOS and Digital Asset Links (`assetlinks.json`) on Android; for browsers on
//! Android only a built-in allow-list of privileged callers may state an
//! `origin`. The provider checks the relation and then passes the origin it
//! has established to this module as a [`CallerContext`], so the same
//! canonicalisation and the same exact `rp_id` rule at signing time apply.

use super::psl;
use crate::error::{Error, MalformedKind};
use sha2::{Digest, Sha256};

/// The longest origin text accepted, in bytes.
const MAX_ORIGIN_LEN: usize = 300;
/// The longest host, in bytes (DNS limit).
const MAX_HOST_LEN: usize = 253;
/// The longest label, in bytes (DNS limit).
const MAX_LABEL_LEN: usize = 63;

const fn bad_origin() -> Error {
    Error::Malformed(MalformedKind::Origin)
}

const fn bad_rp_id() -> Error {
    Error::Malformed(MalformedKind::RpId)
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum Scheme {
    Https,
    Http,
}

/// An origin in canonical form: `https://host` or `http://localhost`, with
/// the host as a lower-case A-label and a port only when it is not the
/// default.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct CanonicalOrigin {
    scheme: Scheme,
    host: String,
    port: Option<u16>,
    text: String,
}

impl CanonicalOrigin {
    /// The serialized origin, as it goes in `clientDataJSON.origin`.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The host (A-label, lower case, without port).
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port, if it is not the default of the scheme.
    pub fn port(&self) -> Option<u16> {
        self.port
    }

    /// True for `https`.
    pub fn is_https(&self) -> bool {
        self.scheme == Scheme::Https
    }
}

impl core::fmt::Display for CanonicalOrigin {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.text)
    }
}

/// A relying party ID that has passed [`validate_rp_id`].
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct RpId(String);

impl RpId {
    /// The ID (A-label, lower case).
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// `rpIdHash` of `authenticatorData`: SHA-256 of the ID.
    pub fn hash(&self) -> [u8; 32] {
        Sha256::digest(self.0.as_bytes()).into()
    }
}

/// Is the last label of `host` an address in the sense of the URL standard
/// (all digits, or `0x` and hex digits)?
fn looks_like_ipv4(host: &str) -> bool {
    let last = host.rsplit('.').next().unwrap_or("");
    if last.is_empty() {
        return false;
    }
    if last.bytes().all(|b| b.is_ascii_digit()) {
        return true;
    }
    last.strip_prefix("0x")
        .is_some_and(|hex| hex.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Converts a host or an RP ID to its canonical name: A-label, lower case,
/// one trailing dot removed, LDH labels of 1 to 63 bytes, at most 253 bytes,
/// and not an IP address. `Err(())` for everything else.
fn canonical_host(raw: &str) -> Result<String, ()> {
    if raw.is_empty() || raw.len() > MAX_HOST_LEN.saturating_mul(4) {
        return Err(());
    }
    if raw.contains([':', '[', ']', '/', '\\', '?', '#', '@', '%', '*', ' ']) {
        return Err(());
    }
    let trimmed = raw.strip_suffix('.').unwrap_or(raw);
    if trimmed.is_empty() {
        return Err(());
    }
    let host = idna::domain_to_ascii_strict(trimmed).map_err(|_| ())?;
    if host.is_empty() || host.len() > MAX_HOST_LEN {
        return Err(());
    }
    for label in host.split('.') {
        let ok = !label.is_empty()
            && label.len() <= MAX_LABEL_LEN
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !ok {
            return Err(());
        }
    }
    if looks_like_ipv4(&host) {
        return Err(());
    }
    Ok(host)
}

/// Reads `raw` as an origin and writes it in canonical form.
///
/// Spec: Fase 1 § 9.2. Idempotent: the canonical text read again gives
/// itself.
pub fn canonical_origin(raw: &str) -> Result<CanonicalOrigin, Error> {
    if raw.len() > MAX_ORIGIN_LEN || raw.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(bad_origin());
    }
    let (scheme_text, authority) = raw.split_once("://").ok_or_else(bad_origin)?;
    let scheme = if scheme_text.eq_ignore_ascii_case("https") {
        Scheme::Https
    } else if scheme_text.eq_ignore_ascii_case("http") {
        Scheme::Http
    } else {
        return Err(bad_origin());
    };
    if authority.is_empty() || authority.starts_with('[') {
        return Err(bad_origin());
    }
    let (host_text, port_text) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (authority, None),
    };
    let port = match port_text {
        None => None,
        Some(p) => {
            if p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()) {
                return Err(bad_origin());
            }
            match p.parse::<u16>() {
                Ok(n) if n != 0 => Some(n),
                _ => return Err(bad_origin()),
            }
        }
    };
    let host = canonical_host(host_text).map_err(|()| bad_origin())?;
    if scheme == Scheme::Http && host != "localhost" {
        return Err(bad_origin());
    }
    let default_port = match scheme {
        Scheme::Https => 443,
        Scheme::Http => 80,
    };
    let port = port.filter(|p| *p != default_port);
    let scheme_str = match scheme {
        Scheme::Https => "https",
        Scheme::Http => "http",
    };
    let text = match port {
        Some(p) => format!("{scheme_str}://{host}:{p}"),
        None => format!("{scheme_str}://{host}"),
    };
    Ok(CanonicalOrigin {
        scheme,
        host,
        port,
        text,
    })
}

/// Checks that `rp_id` may be used by `origin` and returns it in canonical
/// form.
///
/// The ID must be the host of the origin or a dot-delimited suffix of it
/// (`example.com` for `login.example.com`, never `ample.com`), must not be a
/// public suffix, and must not carry a port or be an address.
///
/// Spec: Fase 1 § 9.2 (F-12).
pub fn validate_rp_id(origin: &CanonicalOrigin, rp_id: &str) -> Result<RpId, Error> {
    let rp = canonical_host(rp_id).map_err(|()| bad_rp_id())?;
    let host = origin.host();
    let related = rp == host
        || host
            .strip_suffix(rp.as_str())
            .is_some_and(|head| head.ends_with('.'));
    if !related {
        return Err(bad_rp_id());
    }
    // `localhost` is a name the user's own machine answers to: no registrable
    // domain above it, and the one ID allowed without one.
    let is_localhost = rp == "localhost" && host == "localhost";
    if !is_localhost && psl::is_public_suffix(&rp) {
        return Err(bad_rp_id());
    }
    Ok(RpId(rp))
}

/// The host of `origin` as the default RP ID, when a request names none.
pub(crate) fn default_rp_id(origin: &CanonicalOrigin) -> Result<RpId, Error> {
    validate_rp_id(origin, origin.host())
}
