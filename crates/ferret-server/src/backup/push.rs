//! The message to the monitor after a set passed its check.
//!
//! The monitor is a push monitor (Vigilant Vole, or a compatible one): the
//! server calls its address and the monitor raises an alarm when no call has
//! come in for the interval plus two hours. Spec: Fase 1 § 11 (backup status);
//! the monitor stands in for the health path that a stack with no inbound route
//! cannot serve.
//!
//! The address is a secret ([`crate::secret::SecretUrl`]): it is never logged,
//! never shown in the admin pages, never kept in the status and never part of an
//! error. The message is the address with two query values added, `status=up`
//! and a fixed `msg`; nothing of the server goes in it (no names, no paths, no
//! counts, no secrets). A failure here never makes the set bad: it is reported
//! as a fixed code in the status and the panel shows it.

use std::time::Duration;

use crate::secret::SecretUrl;

/// How long the call may take, connection and answer together.
pub const TIMEOUT: Duration = Duration::from_secs(10);

/// The fixed text of the message.
pub const MESSAGE: &str = "backup ok";

/// Why a message did not go through. A code only, never the address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushError {
    /// The address is not usable.
    Address,
    /// No answer within [`TIMEOUT`].
    Timeout,
    /// The connection could not be made.
    Connect,
    /// The monitor answered with a status other than success.
    Status(u16),
    /// Anything else the client reported.
    Request,
}

impl PushError {
    /// A fixed word for the status.
    pub const fn code(self) -> &'static str {
        match self {
            PushError::Address => "address",
            PushError::Timeout => "timeout",
            PushError::Connect => "connect",
            PushError::Status(_) => "status",
            PushError::Request => "request",
        }
    }
}

/// The client for the message: redirects are never followed and no `Referer`
/// is sent, so the secret path of the address goes to the monitor's own host and
/// nowhere else; a `3xx` is a failure, not a success on another host's page.
/// (The kit's shared client follows redirects and would send the path in
/// `Referer`.) It trusts the same roots as the kit's own clients.
pub fn client() -> Result<reqwest::Client, reqwest::Error> {
    vole_kit::tls_roots::http_client()
        .user_agent(crate::product::USER_AGENT)
        .redirect(reqwest::redirect::Policy::none())
        .referer(false)
        .build()
}

/// The address with `status=up` and the fixed `msg` set; the other query values
/// of the address stay. `None` when the address does not parse.
fn message_url(address: &SecretUrl) -> Option<url::Url> {
    let mut url = url::Url::parse(address.expose()).ok()?;
    let kept: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(key, _)| key != "status" && key != "msg")
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    {
        let mut pairs = url.query_pairs_mut();
        pairs.clear();
        for (key, value) in &kept {
            pairs.append_pair(key, value);
        }
        pairs.append_pair("status", "up");
        pairs.append_pair("msg", MESSAGE);
    }
    Some(url)
}

/// Tells the monitor that a set passed its check. One GET, [`TIMEOUT`] long.
/// Only a direct `2xx` counts: with [`client`] a redirect is a failure.
///
/// The reqwest error is classified and dropped: its text names the address.
pub async fn send(http: &reqwest::Client, address: &SecretUrl) -> Result<(), PushError> {
    let url = message_url(address).ok_or(PushError::Address)?;
    let call = http.get(url).timeout(TIMEOUT).send();
    // The request has its own timeout; this one also covers a stalled resolver.
    let answer = match tokio::time::timeout(TIMEOUT, call).await {
        Ok(Ok(answer)) => answer,
        Ok(Err(error)) => {
            return Err(if error.is_timeout() {
                PushError::Timeout
            } else if error.is_connect() {
                PushError::Connect
            } else {
                PushError::Request
            });
        }
        Err(_) => return Err(PushError::Timeout),
    };
    let status = answer.status();
    if status.is_success() {
        Ok(())
    } else {
        Err(PushError::Status(status.as_u16()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_message_adds_two_values_and_keeps_the_rest_of_the_address() {
        let url = message_url(&SecretUrl::new(
            "https://monitor.example.test/api/push/tok123?status=down&keep=1&msg=x",
        ))
        .expect("an address");
        assert_eq!(url.path(), "/api/push/tok123");
        let pairs: Vec<(String, String)> = url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        assert_eq!(
            pairs,
            vec![
                ("keep".to_string(), "1".to_string()),
                ("status".to_string(), "up".to_string()),
                ("msg".to_string(), MESSAGE.to_string()),
            ]
        );
        assert_eq!(
            message_url(&SecretUrl::new("https://m.test/p"))
                .expect("an address")
                .query(),
            Some("status=up&msg=backup+ok")
        );
        assert!(message_url(&SecretUrl::new("not a url")).is_none());
    }

    #[test]
    fn the_codes_hold_no_address() {
        for error in [
            PushError::Address,
            PushError::Timeout,
            PushError::Connect,
            PushError::Status(500),
            PushError::Request,
        ] {
            assert!(error.code().chars().all(|c| c.is_ascii_lowercase()));
        }
    }
}
