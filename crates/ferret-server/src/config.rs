//! Process configuration: command-line flags, each with a `FERRET_` environment
//! variable. Everything else lives in the database.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use clap::Parser;

use crate::error::ConfigError;

/// The Faithful Ferret server.
#[derive(Debug, Clone, Parser)]
#[command(
    name = "ferret",
    version,
    about,
    long_about = None,
    after_help = "Run `ferret --build-info` on its own to print the version and the cargo features of this build."
)]
pub struct Config {
    /// Directory for the database (ferret.sqlite), the secret files
    /// (opaque_setup, prelogin_secret), the session key and pre-migration
    /// backups.
    #[arg(long, env = "FERRET_DATA_DIR", default_value = "./data")]
    pub data_dir: PathBuf,

    /// Address to listen on (both listeners).
    #[arg(long, env = "FERRET_HOST", default_value_t = IpAddr::V4(Ipv4Addr::UNSPECIFIED))]
    pub host: IpAddr,

    /// Port of the vault listener: the web vault and the vault API.
    #[arg(long, env = "FERRET_VAULT_PORT", default_value_t = 3041)]
    pub vault_port: u16,

    /// Port of the admin listener: the kit's admin pages.
    #[arg(long, env = "FERRET_ADMIN_PORT", default_value_t = 3040)]
    pub admin_port: u16,

    /// The address people use to reach the vault listener, like
    /// https://vault.example.com. The `Origin` check compares with it, never
    /// with the `Host` header.
    #[arg(long, env = "FERRET_VAULT_URL", value_parser = parse_origin_url)]
    pub vault_url: String,

    /// The address people use to reach the admin listener, like
    /// https://ferret.example.com. It must have another host name than the
    /// vault: cookies do not tell ports apart.
    #[arg(long, env = "FERRET_ADMIN_URL", value_parser = parse_origin_url)]
    pub admin_url: String,

    /// Addresses (or networks, like 10.0.0.0/24) of the reverse proxies whose
    /// `X-Forwarded-*` headers are believed. Every other peer's are removed.
    /// Comma separated.
    #[arg(long, env = "FERRET_TRUSTED_PROXIES", value_delimiter = ',')]
    pub trusted_proxies: Vec<String>,
}

impl Config {
    /// Where the vault listener binds.
    pub fn vault_addr(&self) -> SocketAddr {
        SocketAddr::new(self.host, self.vault_port)
    }

    /// Where the admin listener binds.
    pub fn admin_addr(&self) -> SocketAddr {
        SocketAddr::new(self.host, self.admin_port)
    }
}

/// The two public origins, as configured: the one `Origin` header value that
/// each listener accepts, `scheme://host[:port]` without a trailing slash.
///
/// The configured values, never the `Host` header, say what an origin is: a
/// proxy may rewrite `Host`, and a client may send any value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origins {
    vault: String,
    admin: String,
}

impl Origins {
    /// Checks and keeps the two public addresses. They must be http(s)
    /// origins, and their host names must differ (cookies are scoped to a
    /// host, not to a port).
    pub fn parse(vault_url: &str, admin_url: &str) -> Result<Self, ConfigError> {
        let vault =
            parse_origin_url(vault_url).map_err(|e| ConfigError(format!("vault URL: {e}")))?;
        let admin =
            parse_origin_url(admin_url).map_err(|e| ConfigError(format!("admin URL: {e}")))?;
        let host = |origin: &str| {
            url::Url::parse(origin)
                .ok()
                .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
        };
        if host(&vault) == host(&admin) {
            return Err(ConfigError(
                "the vault and the admin URL must have different host names: cookies do not tell ports apart"
                    .to_string(),
            ));
        }
        Ok(Self { vault, admin })
    }

    /// The origin of the vault listener.
    pub fn vault(&self) -> &str {
        &self.vault
    }

    /// The origin of the admin listener.
    pub fn admin(&self) -> &str {
        &self.admin
    }

    /// Whether the vault origin is https (then sign-in needs a trusted proxy
    /// that says so).
    pub fn vault_is_https(&self) -> bool {
        self.vault.starts_with("https://")
    }

    /// Whether the admin origin is https.
    pub fn admin_is_https(&self) -> bool {
        self.admin.starts_with("https://")
    }
}

/// An http(s) origin: no user name, path, query or fragment. Returned as
/// `scheme://host[:port]` in lower case, without a trailing slash.
pub fn parse_origin_url(raw: &str) -> Result<String, String> {
    let raw = raw.trim();
    let url = url::Url::parse(raw).map_err(|e| format!("not a URL ({e})"))?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err("use an http:// or https:// address, like https://vault.example.com".into());
    }
    if url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err("use the address only: no user name, path, query or fragment".into());
    }
    Ok(url.origin().ascii_serialization())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(extra: &[&str]) -> Result<Config, clap::Error> {
        let mut args = vec![
            "ferret",
            "--vault-url",
            "https://vault.example.com",
            "--admin-url",
            "https://admin.example.com",
        ];
        args.extend_from_slice(extra);
        Config::try_parse_from(args)
    }

    #[test]
    fn ports_default_to_3041_vault_and_3040_admin() {
        let c = parse(&[]).unwrap();
        assert_eq!(c.vault_port, 3041);
        assert_eq!(c.admin_port, 3040);
        assert_eq!(c.vault_addr().to_string(), "0.0.0.0:3041");
        assert_eq!(c.admin_addr().to_string(), "0.0.0.0:3040");
        assert_eq!(c.data_dir, PathBuf::from("./data"));
        assert!(c.trusted_proxies.is_empty());
        let c = parse(&[
            "--vault-port",
            "4041",
            "--admin-port",
            "4040",
            "--trusted-proxies",
            "10.0.0.5,10.1.0.0/16",
        ])
        .unwrap();
        assert_eq!((c.vault_port, c.admin_port), (4041, 4040));
        assert_eq!(c.trusted_proxies, ["10.0.0.5", "10.1.0.0/16"]);
    }

    #[test]
    fn urls_are_required_in_production_config() {
        assert!(Config::try_parse_from(["ferret"]).is_err());
        assert!(
            Config::try_parse_from(["ferret", "--vault-url", "https://v.example.com"]).is_err()
        );
        assert!(
            Config::try_parse_from(["ferret", "--admin-url", "https://a.example.com"]).is_err()
        );
        // An address that is not an origin is refused as well.
        for bad in [
            "vault.example.com",
            "ftp://x.example.com",
            "https://x.example.com/vault",
            "https://u@x.example.com",
            "https://x.example.com?a=1",
        ] {
            assert!(
                Config::try_parse_from([
                    "ferret",
                    "--vault-url",
                    bad,
                    "--admin-url",
                    "https://a.example.com"
                ])
                .is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn origins_are_normalised_and_need_different_hosts() {
        let o = Origins::parse(
            "https://Vault.Example.com/",
            "https://admin.example.com:8443",
        )
        .unwrap();
        assert_eq!(o.vault(), "https://vault.example.com");
        assert_eq!(o.admin(), "https://admin.example.com:8443");
        assert!(o.vault_is_https() && o.admin_is_https());
        assert!(
            Origins::parse("https://same.example.com", "https://same.example.com:8443").is_err()
        );
        assert!(Origins::parse("http://localhost:3041", "http://127.0.0.1:3040").is_ok());
        assert!(
            !Origins::parse("http://localhost:3041", "http://127.0.0.1:3040")
                .unwrap()
                .vault_is_https()
        );
    }
}
