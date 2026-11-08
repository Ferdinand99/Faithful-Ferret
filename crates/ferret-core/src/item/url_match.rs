//! Matching a saved address against the page the user is on, and the other
//! questions about a page address that the browser extension asks: its
//! origin, whether two pages are on the same site, and the host to show.
//!
//! Spec: Fase 1 § 10.4 (F-22, E13) and § 10.5. The rule is written here and
//! nowhere else: the extension has no Public Suffix List and no matching rule
//! of its own.
//!
//! Everything is a pure comparison: no I/O, no crypto, no clock.
//!
//! # Parsing
//!
//! Addresses are read with the `url` crate, which implements the WHATWG URL
//! Standard, because the page address comes from a browser that reads it the
//! same way. A parser of our own that disagreed with the browser about user
//! info, backslashes, tabs and line breaks, percent-encoded hosts or numeric
//! IPv4 forms (`3232235777` is `192.168.1.1`) would be a way past the rule.
//!
//! Only `http` and `https` addresses are web pages. Everything else (`data:`,
//! `blob:`, `file:`, `about:`, `javascript:`, an address without a scheme such
//! as `example.com`, anything the parser refuses) is not matched, and neither
//! is an address of more than 8 KiB or one that has a user name or a
//! password. The host is the A-label in lower case, with one trailing dot
//! removed; a host with an empty label is refused. The port is the explicit
//! one or the default of the scheme, so `https://a.example` and
//! `https://a.example:443` are the same; port 0 is refused.
//!
//! # Matching
//!
//! The scheme and the port of the entry and the page must be equal. A saved
//! `https` address is therefore never offered on an `http` page, and a saved
//! `http` address only on an `http` page. Then, by the match kind of the
//! entry:
//!
//! * `host` (the default): the hosts are equal. The result is
//!   [`UrlMatchResult::Host`].
//! * `domain`: the hosts are equal ([`UrlMatchResult::Host`]), or, for an
//!   `https` entry only, both are names with the same registrable domain, by
//!   the Public Suffix List with its private domains
//!   ([`UrlMatchResult::Domain`]). An entry saved with `http` acts as `host`
//!   whatever its match kind. A host with no
//!   registrable domain acts as `host`: a single label (`intranet`), a name
//!   under a top-level domain the list does not know (`router.lan`), under
//!   `arpa` (`nas.home.arpa`) or under `box` (`fritz.box`, a router name), and
//!   a public suffix itself (`github.io`). `a.github.io` and `b.github.io`
//!   have different registrable domains.
//! * `exact`: the scheme, host, port, path and query are equal; only the
//!   fragment is ignored ([`UrlMatchResult::Exact`]).
//! * a match kind this version does not know never matches.
//!
//! An IP host (IPv4 in any form the standard reads, or IPv6) matches only the
//! identical address, whatever the match kind.
//!
//! There is no loopback exception in this comparison: an `https` entry is never
//! matched on `http://localhost`. That a loopback page counts as secure (no
//! warning for an `http` entry, no insecure ancestor) is for the extension's
//! frame and warning checks, not for the match.

use crate::error::{Error, MalformedKind};
use crate::item::{UrlEntry, UrlMatch};
use crate::passkey::registrable_domain;
use unicode_general_category::{GeneralCategory, get_general_category};
use url::{Host, Url};

/// The longest address accepted, in bytes. A longer one never matches and is
/// never an origin.
pub const MAX_URL_LEN: usize = 8 * 1024;

/// Top-level domains under which names are treated as private and local, so
/// that two names under them are never taken for one site, although the list
/// has a rule for them: `arpa` (`home.arpa` is the name of a home network) and
/// `box` (routers such as `fritz.box`).
const LOCAL_TLDS: [&str; 2] = ["arpa", "box"];

/// How an address of a saved item matched a page. Never more than the kind of
/// the entry allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrlMatchResult {
    /// No match.
    None,
    /// The hosts are equal.
    Host,
    /// Only the registrable domains are equal (the entry says `domain`).
    Domain,
    /// The addresses are equal without the fragment (the entry says `exact`).
    Exact,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Scheme {
    Http,
    Https,
}

#[derive(Clone, PartialEq, Eq, Debug)]
enum HostName {
    /// A domain name: A-label, lower case, no trailing dot.
    Name(String),
    /// An IP address as the standard writes it (IPv6 in brackets).
    Ip(String),
}

impl HostName {
    fn as_str(&self) -> &str {
        match self {
            Self::Name(s) | Self::Ip(s) => s,
        }
    }
}

/// A web page address, read.
struct Web {
    url: Url,
    scheme: Scheme,
    host: HostName,
    port: u16,
}

const fn bad_origin() -> Error {
    Error::Malformed(MalformedKind::Origin)
}

fn parse_web(raw: &str) -> Option<Web> {
    if raw.len() > MAX_URL_LEN {
        return None;
    }
    let url = Url::parse(raw).ok()?;
    let scheme = match url.scheme() {
        "http" => Scheme::Http,
        "https" => Scheme::Https,
        _ => return None,
    };
    if !url.username().is_empty() || url.password().is_some() {
        return None;
    }
    let host = match url.host()? {
        Host::Domain(name) => {
            let name = name.strip_suffix('.').unwrap_or(name);
            if name.is_empty() || name.split('.').any(str::is_empty) {
                return None;
            }
            HostName::Name(name.to_owned())
        }
        Host::Ipv4(a) => HostName::Ip(a.to_string()),
        Host::Ipv6(a) => HostName::Ip(format!("[{a}]")),
    };
    // A page is never served from port 0.
    let port = url.port_or_known_default().filter(|p| *p != 0)?;
    Some(Web {
        url,
        scheme,
        host,
        port,
    })
}

/// The registrable domain of a host that is a name, or `None`.
fn registrable(host: &HostName) -> Option<&str> {
    let HostName::Name(name) = host else {
        return None;
    };
    let tld = name.rsplit('.').next().unwrap_or(name);
    if LOCAL_TLDS.contains(&tld) {
        return None;
    }
    registrable_domain(name)
}

/// Whether a saved address matches the page, and how.
///
/// Spec: Fase 1 § 10.4. See the module documentation for the rules. Input
/// over 8 KiB, an address with user info, one the URL parser refuses, one
/// without a scheme, one that is not `http` or `https`, and a match kind this
/// version does not know all give [`UrlMatchResult::None`].
pub fn url_match(entry: &UrlEntry, page_url: &str) -> UrlMatchResult {
    let (Some(saved), Some(page)) = (parse_web(&entry.url), parse_web(page_url)) else {
        return UrlMatchResult::None;
    };
    if saved.scheme != page.scheme || saved.port != page.port {
        return UrlMatchResult::None;
    }
    match &entry.matching {
        UrlMatch::Exact => {
            if saved.host == page.host
                && saved.url.path() == page.url.path()
                && saved.url.query() == page.url.query()
            {
                UrlMatchResult::Exact
            } else {
                UrlMatchResult::None
            }
        }
        UrlMatch::Host => host_match(&saved, &page),
        UrlMatch::Domain => {
            let by_host = host_match(&saved, &page);
            if by_host != UrlMatchResult::None || saved.scheme == Scheme::Http {
                // An address saved with `http` is never widened to other hosts:
                // nothing over plain text ties another host of the domain to the
                // server the user meant.
                return by_host;
            }
            match (registrable(&saved.host), registrable(&page.host)) {
                (Some(a), Some(b)) if a == b => UrlMatchResult::Domain,
                _ => UrlMatchResult::None,
            }
        }
        UrlMatch::Other(_) => UrlMatchResult::None,
    }
}

fn host_match(saved: &Web, page: &Web) -> UrlMatchResult {
    if saved.host == page.host {
        UrlMatchResult::Host
    } else {
        UrlMatchResult::None
    }
}

/// The origin of a web page: scheme, host and port.
///
/// The host is the lower-case A-label with one trailing dot removed, or the
/// IP address as the standard writes it (IPv6 in brackets). The port is
/// always known: the default of the scheme is filled in.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct PageOrigin {
    https: bool,
    ip: bool,
    host: String,
    port: u16,
    text: String,
}

impl PageOrigin {
    /// The serialized origin: `scheme://host`, with `:port` only when the
    /// port is not the default of the scheme.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// `"https"` or `"http"`.
    pub fn scheme(&self) -> &'static str {
        if self.https { "https" } else { "http" }
    }

    /// True for `https`.
    pub fn is_https(&self) -> bool {
        self.https
    }

    /// The host (A-label in lower case, or an IP address).
    pub fn host(&self) -> &str {
        &self.host
    }

    /// True when the host is an IP address.
    pub fn is_ip(&self) -> bool {
        self.ip
    }

    /// The port, the default of the scheme when the address names none.
    pub fn port(&self) -> u16 {
        self.port
    }
}

impl core::fmt::Display for PageOrigin {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.text)
    }
}

/// The canonical origin of an `http` or `https` page.
///
/// Unlike [`canonical_origin`](crate::passkey::origin::canonical_origin),
/// which is for passkeys and takes only `https` and `http://localhost`, this
/// accepts plain `http` and IP hosts, and a whole page address with a path,
/// query and fragment (up to 8 KiB). An address with user info, an opaque or
/// non-web address, and one the URL parser refuses is
/// `Error::Malformed(MalformedKind::Origin)`.
///
/// Spec: Fase 1 § 10.5, § 9.2.
pub fn page_origin(page_url: &str) -> Result<PageOrigin, Error> {
    let web = parse_web(page_url).ok_or_else(bad_origin)?;
    let https = web.scheme == Scheme::Https;
    let scheme = if https { "https" } else { "http" };
    let default_port: u16 = if https { 443 } else { 80 };
    let host = web.host.as_str().to_owned();
    let text = if web.port == default_port {
        format!("{scheme}://{host}")
    } else {
        format!("{scheme}://{host}:{}", web.port)
    };
    Ok(PageOrigin {
        https,
        ip: matches!(web.host, HostName::Ip(_)),
        host,
        port: web.port,
        text,
    })
}

/// Whether two page addresses are on the same site, in the schemeful sense:
/// equal scheme and equal registrable domain (the Public Suffix List with its
/// private domains). The port does not matter. An IP host, and a host with no
/// registrable domain, is on the same site only as the identical host.
/// Anything that is not an `http` or `https` address is on no site.
///
/// Spec: Fase 1 § 10.5.
pub fn same_site(a: &str, b: &str) -> bool {
    let (Some(a), Some(b)) = (parse_web(a), parse_web(b)) else {
        return false;
    };
    if a.scheme != b.scheme {
        return false;
    }
    if a.host == b.host {
        return true;
    }
    match (registrable(&a.host), registrable(&b.host)) {
        (Some(x), Some(y)) => x == y,
        _ => false,
    }
}

/// A host written for people to read.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DisplayHost {
    /// The A-label (`xn--` form), lower case. For an IP host the address.
    pub a_label: String,
    /// The Unicode form, label by label. A label that mixes scripts (see
    /// [`display_host`]) and one that cannot be converted back keeps its
    /// A-label. The same as `a_label` for an ASCII name and for an IP host.
    pub unicode: String,
}

/// The host of a page address for display, in both forms, so that a user
/// interface can show the Unicode name and the A-label next to it when they
/// differ.
///
/// The Unicode form is made label by label. A label whose letters come from
/// more than one script, ignoring digits, hyphens and combining marks, stays in
/// A-label form: `exаmple` (Latin with the Cyrillic `а`) is shown as
/// `xn--exmple-4nf`, as a browser with its default IDN policy shows it. The
/// combinations that are one writing system are allowed: Han with Hiragana and
/// Katakana (Japanese), with Hangul (Korean) or with Bopomofo (Chinese).
///
/// This does not make the Unicode form safe to trust. A label from a single
/// script that looks like another (an all-Cyrillic `аррӏе`
/// next to `apple`) is still shown in Unicode, as in a browser. The security
/// boundary is the matching, which compares A-labels; the interface must show
/// the A-label next to the Unicode form when they differ.
///
/// An address that is not a web address is
/// `Error::Malformed(MalformedKind::Origin)`.
///
/// Spec: Fase 1 § 10.5.
pub fn display_host(page_url: &str) -> Result<DisplayHost, Error> {
    let web = parse_web(page_url).ok_or_else(bad_origin)?;
    let a_label = web.host.as_str().to_owned();
    let unicode = match &web.host {
        HostName::Ip(_) => a_label.clone(),
        HostName::Name(name) => name
            .split('.')
            .map(unicode_label)
            .collect::<Vec<_>>()
            .join("."),
    };
    Ok(DisplayHost { a_label, unicode })
}

/// One label for display: its Unicode form, or the label itself when it is
/// plain ASCII, cannot be converted back, or mixes scripts.
fn unicode_label(label: &str) -> String {
    if !label.starts_with("xn--") {
        return label.to_owned();
    }
    let (text, result) = idna::domain_to_unicode(label);
    if result.is_ok() && !text.is_empty() && !mixes_scripts(&text) {
        text
    } else {
        label.to_owned()
    }
}

/// The writing systems the check tells apart. Letters of a script that has no
/// entry of its own are told apart by their block of 128 code points, so two
/// such letters may count as two scripts when they are one (which only gives
/// the A-label: the safe side).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Script {
    Latin,
    Greek,
    Cyrillic,
    Armenian,
    Han,
    Hiragana,
    Katakana,
    Hangul,
    Bopomofo,
    Block(u32),
}

/// Ranges of code points by script, for the letters the table names.
const SCRIPT_RANGES: &[(u32, u32, Script)] = &[
    (0x0041, 0x005A, Script::Latin),
    (0x0061, 0x007A, Script::Latin),
    (0x00AA, 0x00AA, Script::Latin),
    (0x00BA, 0x00BA, Script::Latin),
    (0x00C0, 0x00D6, Script::Latin),
    (0x00D8, 0x00F6, Script::Latin),
    (0x00F8, 0x02AF, Script::Latin),
    (0x1D00, 0x1D25, Script::Latin),
    (0x1E00, 0x1EFF, Script::Latin),
    (0x2C60, 0x2C7F, Script::Latin),
    (0xA720, 0xA7FF, Script::Latin),
    (0xAB30, 0xAB5A, Script::Latin),
    (0xFF21, 0xFF3A, Script::Latin),
    (0xFF41, 0xFF5A, Script::Latin),
    (0x0370, 0x03FF, Script::Greek),
    (0x1F00, 0x1FFF, Script::Greek),
    (0x0400, 0x052F, Script::Cyrillic),
    (0x1C80, 0x1C8F, Script::Cyrillic),
    (0x2DE0, 0x2DFF, Script::Cyrillic),
    (0xA640, 0xA69F, Script::Cyrillic),
    (0x0530, 0x058F, Script::Armenian),
    (0xFB13, 0xFB17, Script::Armenian),
    (0x2E80, 0x2FDF, Script::Han),
    (0x3005, 0x3005, Script::Han),
    (0x3007, 0x3007, Script::Han),
    (0x3021, 0x3029, Script::Han),
    (0x3038, 0x303B, Script::Han),
    (0x3400, 0x4DBF, Script::Han),
    (0x4E00, 0x9FFF, Script::Han),
    (0xF900, 0xFAFF, Script::Han),
    (0x20000, 0x323AF, Script::Han),
    (0x3041, 0x309F, Script::Hiragana),
    (0x30A0, 0x30FF, Script::Katakana),
    (0x31F0, 0x31FF, Script::Katakana),
    (0xFF66, 0xFF9F, Script::Katakana),
    (0x1100, 0x11FF, Script::Hangul),
    (0x3130, 0x318F, Script::Hangul),
    (0xA960, 0xA97F, Script::Hangul),
    (0xAC00, 0xD7FF, Script::Hangul),
    (0x3100, 0x312F, Script::Bopomofo),
    (0x31A0, 0x31BF, Script::Bopomofo),
];

fn script_of(c: char) -> Script {
    let cp = u32::from(c);
    SCRIPT_RANGES
        .iter()
        .find(|(lo, hi, _)| (*lo..=*hi).contains(&cp))
        .map_or(Script::Block(cp >> 7), |(_, _, script)| *script)
}

/// Whether the letters of a label come from more than one writing system.
/// Digits, hyphens, other symbols and combining marks do not count: they
/// belong to whatever they follow.
fn mixes_scripts(label: &str) -> bool {
    let mut seen: Vec<Script> = Vec::new();
    for c in label.chars() {
        let letter = matches!(
            get_general_category(c),
            GeneralCategory::UppercaseLetter
                | GeneralCategory::LowercaseLetter
                | GeneralCategory::TitlecaseLetter
                | GeneralCategory::ModifierLetter
                | GeneralCategory::OtherLetter
        );
        if !letter {
            continue;
        }
        let script = script_of(c);
        if !seen.contains(&script) {
            seen.push(script);
        }
    }
    if seen.len() < 2 {
        return false;
    }
    // One writing system written with several scripts: the CJK combinations.
    let only = |allowed: &[Script]| seen.iter().all(|s| allowed.contains(s));
    !(only(&[Script::Han, Script::Hiragana, Script::Katakana])
        || only(&[Script::Han, Script::Hangul])
        || only(&[Script::Han, Script::Bopomofo]))
}
