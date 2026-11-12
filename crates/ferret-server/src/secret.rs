//! Secret-holding helper types.
//!
//! Types that hold a secret never derive `Debug` or `Clone`, wipe on drop and
//! show `[redacted]` when printed.

use std::convert::Infallible;
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

use zeroize::Zeroizing;

/// An address that is a secret in itself: whoever has it can use it (the push
/// address of the backup monitor works for anyone who knows it).
///
/// It is read from the environment or a flag by clap, which needs a type it can
/// clone out of its matches. The clone shares the one wiped-on-drop copy of the
/// text (an `Arc`), so no second plain copy of the address is made. `Debug`
/// shows nothing, there is no `Display`, and the text comes out only through
/// [`SecretUrl::expose`], which the caller that makes the request calls.
///
/// Reading never fails and never looks at the text, so no error message of
/// clap quotes a bad value; the address is checked later by
/// [`SecretUrl::check`], whose message does not quote it either.
#[derive(Clone)]
pub struct SecretUrl(Arc<Zeroizing<String>>);

impl SecretUrl {
    /// Keeps `raw` as it is, whitespace at the ends cut off.
    pub fn new(raw: &str) -> Self {
        Self(Arc::new(Zeroizing::new(raw.trim().to_string())))
    }

    /// The address. Do not log it, print it or put it in an error.
    pub fn expose(&self) -> &str {
        self.0.as_str()
    }

    /// Whether nothing was given (an empty variable in a compose file).
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Checks that this is an `http` or `https` address with a host name and no
    /// user name or password. The error names what is wrong, never the text.
    pub fn check(&self) -> Result<(), &'static str> {
        let url = url::Url::parse(self.expose()).map_err(|_| "it is not a URL")?;
        if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
            return Err("use an http:// or https:// address with a host name");
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err("it must not hold a user name or password");
        }
        Ok(())
    }
}

impl FromStr for SecretUrl {
    type Err = Infallible;

    fn from_str(raw: &str) -> Result<Self, Infallible> {
        Ok(Self::new(raw))
    }
}

impl fmt::Debug for SecretUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretUrl([redacted])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADDRESS: &str = "https://monitor.example.test/api/push/abc123secret?status=up";

    #[test]
    fn it_shows_nothing_when_printed_and_keeps_the_text_for_the_caller() {
        let url = SecretUrl::new(ADDRESS);
        assert_eq!(format!("{url:?}"), "SecretUrl([redacted])");
        assert_eq!(format!("{url:#?}"), "SecretUrl([redacted])");
        assert_eq!(url.expose(), ADDRESS);
        assert_eq!(
            SecretUrl::new("  https://a.test/p \n").expose(),
            "https://a.test/p"
        );
        // A clone shares the text.
        let copy = url.clone();
        assert_eq!(copy.expose(), ADDRESS);
        assert!(std::ptr::eq(copy.expose(), url.expose()));
    }

    #[test]
    fn only_a_plain_http_or_https_address_passes_the_check_and_no_error_quotes_it() {
        assert_eq!(SecretUrl::new(ADDRESS).check(), Ok(()));
        assert_eq!(
            SecretUrl::new("http://10.0.0.5:3001/api/push/x").check(),
            Ok(())
        );
        for bad in [
            "not a url secret1",
            "ftp://monitor.example.test/secret1",
            "file:///etc/secret1",
            "https://user:secret1@monitor.example.test/",
            "https://secret1@monitor.example.test/",
            "mailto:secret1@example.test",
            "",
        ] {
            let message = SecretUrl::new(bad).check().expect_err(bad);
            assert!(!message.contains("secret1"), "{message}");
        }
        assert!(SecretUrl::new("").is_empty());
        assert!(!SecretUrl::new(ADDRESS).is_empty());
    }
}
