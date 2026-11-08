//! Matching a saved address against a page, the origin of a page, same-site and
//! the host for display (Fase 1 § 10.4, § 10.5) and `vectors/internal/url-match.json`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use common::*;
use ferret_core::testing::vector::Outcome;
use ferret_core::{
    Error, MalformedKind, UrlEntry, UrlMatch, UrlMatchResult, display_host, page_origin, same_site,
    url_match,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::path::Path;

use UrlMatchResult::{Domain, Exact, Host, None as NoMatch};

fn entry(url: &str, matching: UrlMatch) -> UrlEntry {
    UrlEntry {
        url: url.to_owned(),
        matching,
        extra: Vec::new(),
    }
}

fn host_of(entry_url: &str, page: &str) -> UrlMatchResult {
    url_match(&entry(entry_url, UrlMatch::Host), page)
}

fn domain_of(entry_url: &str, page: &str) -> UrlMatchResult {
    url_match(&entry(entry_url, UrlMatch::Domain), page)
}

fn exact_of(entry_url: &str, page: &str) -> UrlMatchResult {
    url_match(&entry(entry_url, UrlMatch::Exact), page)
}

fn match_kind(text: &str) -> UrlMatch {
    UrlMatch::from_text(text.to_owned())
}

fn result_text(r: UrlMatchResult) -> &'static str {
    match r {
        NoMatch => "none",
        Host => "host",
        Domain => "domain",
        Exact => "exact",
    }
}

fn utf8(v: &serde_json::Value) -> String {
    String::from_utf8(hex(v)).unwrap()
}

const BAD_ORIGIN: Error = Error::Malformed(MalformedKind::Origin);

#[test]
fn host_match_is_the_default_and_needs_the_same_host() {
    // A body without a `match` key reads as `host`.
    assert_eq!(UrlMatch::from_text("host".into()), UrlMatch::Host);
    assert_eq!(
        host_of("https://example.com", "https://example.com/login"),
        Host
    );
    assert_eq!(
        host_of(
            "https://example.com/other?x=1",
            "https://example.com/login#a"
        ),
        Host
    );
    assert_eq!(
        host_of("https://example.com", "https://www.example.com"),
        NoMatch
    );
    assert_eq!(
        host_of("https://www.example.com", "https://example.com"),
        NoMatch
    );
    assert_eq!(
        host_of("https://example.com", "https://example.org"),
        NoMatch
    );
    assert_eq!(
        host_of("https://a.example.com", "https://login.a.example.com"),
        NoMatch
    );
}

#[test]
fn domain_match_uses_the_registrable_domain() {
    assert_eq!(
        domain_of("https://login.example.co.uk", "https://www.example.co.uk"),
        Domain
    );
    assert_eq!(
        domain_of("https://example.co.uk", "https://a.b.example.co.uk"),
        Domain
    );
    assert_eq!(
        domain_of("https://example.com", "https://login.example.com"),
        Domain
    );
    // The same host is a host match, even for a `domain` entry.
    assert_eq!(
        domain_of("https://example.com", "https://example.com"),
        Host
    );
    // Private suffixes of the list: each user of `github.io` is a site.
    assert_eq!(
        domain_of("https://a.github.io", "https://b.github.io"),
        NoMatch
    );
    assert_eq!(
        domain_of("https://a.github.io", "https://x.a.github.io"),
        Domain
    );
    assert_eq!(
        domain_of("https://x.y.vercel.app", "https://z.y.vercel.app"),
        Domain
    );
    assert_eq!(
        domain_of("https://x.vercel.app", "https://y.vercel.app"),
        NoMatch
    );
    // Another registrable domain, and `co.uk` itself is a suffix.
    assert_eq!(
        domain_of("https://example.co.uk", "https://other.co.uk"),
        NoMatch
    );
    assert_eq!(
        domain_of("https://example.com", "https://example.co.uk"),
        NoMatch
    );
    // An entry in Unicode meets a page in A-label form.
    assert_eq!(
        domain_of("https://bücher.de", "https://shop.xn--bcher-kva.de"),
        Domain
    );
    // `.example` is reserved and not in the list: no registrable domain.
    assert_eq!(domain_of("https://a.example", "https://b.example"), NoMatch);
    // A `host` entry never widens.
    assert_eq!(
        host_of("https://login.example.co.uk", "https://www.example.co.uk"),
        NoMatch
    );
}

#[test]
fn domain_without_a_registrable_domain_acts_as_host() {
    for name in ["fritz.box", "router.lan", "nas.home.arpa", "intranet"] {
        let saved = format!("https://{name}");
        // The same host: a host match.
        assert_eq!(domain_of(&saved, &saved), Host, "{name}");
        // A sibling or a child name is not the same site.
        let child = format!("https://x.{name}");
        assert_eq!(domain_of(&saved, &child), NoMatch, "{name} child");
        assert_eq!(domain_of(&child, &saved), NoMatch, "{name} parent");
        let other = format!("https://y.{name}");
        assert_eq!(domain_of(&child, &other), NoMatch, "{name} sibling");
    }
    // Two machines of one local name are two hosts.
    assert_eq!(
        domain_of("https://a.fritz.box", "https://b.fritz.box"),
        NoMatch
    );
    assert_eq!(
        domain_of("https://a.home.arpa", "https://b.home.arpa"),
        NoMatch
    );
    assert_eq!(domain_of("https://nas.lan", "https://printer.lan"), NoMatch);
    // A public suffix is a host of its own.
    assert_eq!(domain_of("https://github.io", "https://github.io"), Host);
    assert_eq!(
        domain_of("https://github.io", "https://a.github.io"),
        NoMatch
    );
    // A top-level domain the list does not know has no registrable domain.
    assert_eq!(
        domain_of(
            "https://a.example.zzzunknown",
            "https://b.example.zzzunknown"
        ),
        NoMatch
    );
}

#[test]
fn https_entry_never_matches_an_http_page() {
    for kind in [UrlMatch::Host, UrlMatch::Domain, UrlMatch::Exact] {
        let e = entry("https://example.com/login", kind.clone());
        assert_eq!(url_match(&e, "http://example.com/login"), NoMatch);
        assert_eq!(url_match(&e, "http://example.com"), NoMatch);
    }
    assert_eq!(
        domain_of("https://example.com", "http://www.example.com"),
        NoMatch
    );
    assert_eq!(host_of("https://localhost", "http://localhost"), NoMatch);
}

#[test]
fn http_entry_matches_only_http_with_the_same_host_and_port() {
    assert_eq!(host_of("http://example.com", "http://example.com/x"), Host);
    assert_eq!(
        host_of("http://example.com", "http://example.com:80/x"),
        Host
    );
    // Not an https page, and not another host.
    assert_eq!(
        host_of("http://example.com", "https://example.com"),
        NoMatch
    );
    assert_eq!(
        host_of("http://example.com", "http://www.example.com"),
        NoMatch
    );
    assert_eq!(
        domain_of("http://example.com", "https://www.example.com"),
        NoMatch
    );
    // An address saved with http is never widened to other hosts, whatever its
    // match kind.
    assert_eq!(
        domain_of("http://example.com", "http://www.example.com"),
        NoMatch
    );
    assert_eq!(
        domain_of("http://www.example.com", "http://example.com"),
        NoMatch
    );
    assert_eq!(
        domain_of("http://example.com", "http://example.com/x"),
        Host
    );
    assert_eq!(
        domain_of("http://a.github.io", "http://a.github.io:80"),
        Host
    );
    assert_eq!(
        exact_of("http://example.com/a", "http://www.example.com/a"),
        NoMatch
    );
    assert_eq!(
        exact_of("http://example.com/a", "http://example.com/a#f"),
        Exact
    );
    assert_eq!(
        host_of("http://example.com", "http://example.com:8080"),
        NoMatch
    );
    assert_eq!(
        host_of("http://localhost:3000", "http://localhost:3000/a"),
        Host
    );
    assert_eq!(
        host_of("http://localhost:3000", "http://localhost"),
        NoMatch
    );
}

#[test]
fn different_ports_never_match() {
    for kind in [UrlMatch::Host, UrlMatch::Domain, UrlMatch::Exact] {
        let e = entry("https://example.com:8443/a", kind);
        assert_eq!(url_match(&e, "https://example.com/a"), NoMatch);
        assert_eq!(url_match(&e, "https://example.com:8444/a"), NoMatch);
        assert_ne!(url_match(&e, "https://example.com:8443/a"), NoMatch);
    }
    // The default port is filled in.
    assert_eq!(
        host_of("https://example.com", "https://example.com:443"),
        Host
    );
    assert_eq!(
        host_of("https://example.com:443", "https://example.com"),
        Host
    );
    assert_eq!(
        host_of("https://example.com:0443", "https://example.com"),
        Host
    );
    assert_eq!(
        host_of("https://example.com", "https://example.com:80"),
        NoMatch
    );
    assert_eq!(
        domain_of("https://example.com", "https://login.example.com:8443"),
        NoMatch
    );
}

#[test]
fn lookalikes_and_homographs_do_not_match() {
    for kind in [UrlMatch::Host, UrlMatch::Domain, UrlMatch::Exact] {
        let e = entry("https://example.com", kind);
        for page in [
            "https://examp1e.com",
            "https://example.com.evil.net",
            "https://evil.net/example.com",
            "https://example.com@evil.net",
            "https://evil.net#@example.com",
            "https://exаmple.com", // Cyrillic а
            "https://xn--exmple-4nf.com",
            "https://example.com.evil.net/login?u=https://example.com",
            "https://example-com.net",
            "https://sub.example.com.evil.net",
            "https://examplecom",
            "https://myexample.com",
            "https://example.co",
        ] {
            assert_eq!(url_match(&e, page), NoMatch, "{page}");
        }
    }
    // A Cyrillic entry is a different name from the Latin one and matches only
    // itself.
    let cyr = "https://exаmple.com";
    assert_eq!(host_of(cyr, cyr), Host);
    assert_eq!(host_of(cyr, "https://example.com"), NoMatch);
    assert_eq!(host_of("https://example.com", cyr), NoMatch);
    assert_eq!(domain_of(cyr, "https://www.example.com"), NoMatch);
    // The page address in the form the browser sends is the same thing.
    assert_eq!(host_of(cyr, "https://xn--exmple-4nf.com"), Host);
    assert_eq!(display_host(cyr).unwrap().a_label, "xn--exmple-4nf.com");
}

#[test]
fn ip_hosts_match_only_exactly() {
    for kind in [UrlMatch::Host, UrlMatch::Domain] {
        let e = entry("http://192.168.1.1", kind);
        assert_eq!(url_match(&e, "http://192.168.1.1/admin"), Host);
        assert_eq!(url_match(&e, "http://192.168.1.2"), NoMatch);
        assert_eq!(url_match(&e, "http://192.168.1.10"), NoMatch);
        assert_eq!(url_match(&e, "http://192.168.1"), NoMatch);
        assert_eq!(url_match(&e, "https://192.168.1.1"), NoMatch);
        assert_eq!(url_match(&e, "http://192.168.1.1:8080"), NoMatch);
        // Numeric forms the standard reads as the same address.
        assert_eq!(url_match(&e, "http://3232235777"), Host);
        assert_eq!(url_match(&e, "http://0xc0a80101"), Host);
        assert_eq!(url_match(&e, "http://0300.0250.01.01"), Host);
        assert_eq!(url_match(&e, "http://192.168.257"), Host);
        assert_eq!(url_match(&e, "http://192.11010305"), Host);
        assert_eq!(url_match(&e, "http://192.11010306"), NoMatch);
        // A name is not an address.
        assert_eq!(url_match(&e, "http://example.com"), NoMatch);
        assert_eq!(url_match(&e, "http://192.168.1.1.example.com"), NoMatch);
    }
    // The saved address may be in a numeric form as well.
    assert_eq!(host_of("http://3232235777", "http://192.168.1.1"), Host);
    // No domain match between two addresses of one network.
    assert_eq!(domain_of("http://10.0.0.1", "http://10.0.0.2"), NoMatch);
    // IPv6.
    assert_eq!(host_of("http://[::1]:3000", "http://[::1]:3000/x"), Host);
    assert_eq!(host_of("http://[::1]", "http://[0:0:0:0:0:0:0:1]"), Host);
    assert_eq!(host_of("http://[::1]", "http://[::2]"), NoMatch);
    assert_eq!(
        host_of("https://[2001:db8::1]", "https://[2001:db8::2]"),
        NoMatch
    );
    // Exact needs the same address too.
    assert_eq!(
        exact_of("http://192.168.1.1/a", "http://3232235777/a#f"),
        Exact
    );
    assert_eq!(
        exact_of("http://192.168.1.1/a", "http://192.168.1.2/a"),
        NoMatch
    );
}

#[test]
fn whatwg_edge_cases_parse_like_the_browser() {
    // User info: never.
    for kind in [UrlMatch::Host, UrlMatch::Domain, UrlMatch::Exact] {
        let e = entry("https://example.com", kind.clone());
        assert_eq!(url_match(&e, "https://user@example.com"), NoMatch);
        assert_eq!(url_match(&e, "https://user:pw@example.com"), NoMatch);
        assert_eq!(url_match(&e, "https://:pw@example.com"), NoMatch);
        let with_user = entry("https://user@example.com", kind);
        assert_eq!(url_match(&with_user, "https://example.com"), NoMatch);
        assert_eq!(url_match(&with_user, "https://user@example.com"), NoMatch);
    }
    // A backslash ends the host and starts the path, as in the browser.
    assert_eq!(
        host_of("https://example.com", "https://example.com\\login"),
        Host
    );
    assert_eq!(
        host_of("https://example.com", "https://evil.net\\@example.com"),
        NoMatch
    );
    assert_eq!(
        exact_of("https://example.com/a/b", "https://example.com\\a\\b"),
        Exact
    );
    // Tabs and line breaks are removed before parsing.
    assert_eq!(
        host_of("https://example.com", "https://exam\tple.com"),
        Host
    );
    assert_eq!(
        host_of("https://example.com", "https://exam\nple.com"),
        Host
    );
    assert_eq!(
        host_of("https://example.com", "ht\ttps://example.com"),
        Host
    );
    assert_eq!(
        host_of("https://example.com", "https://example.com\r\n/x"),
        Host
    );
    assert_eq!(
        host_of("https://example.com", "https://example.com\t.evil.net"),
        NoMatch
    );
    // Leading and trailing spaces are removed.
    assert_eq!(
        host_of("https://example.com", "  https://example.com  "),
        Host
    );
    // A percent-encoded host is decoded.
    assert_eq!(
        host_of("https://example.com", "https://%65xample.com"),
        Host
    );
    assert_eq!(
        host_of("https://example.com", "https://exa%6Dple.com"),
        Host
    );
    assert_eq!(
        host_of("https://example.com", "https://example%2Ecom"),
        Host
    );
    assert_eq!(
        host_of("https://example.com", "https://example.com%2F.evil.net"),
        NoMatch
    );
    // Case.
    assert_eq!(host_of("HTTPS://EXAMPLE.COM", "https://example.com"), Host);
    // A fullwidth or ideographic dot or letters map to ASCII.
    assert_eq!(
        host_of("https://example.com", "https://ｅｘａｍｐｌｅ。ｃｏｍ"),
        Host
    );
    // A scheme with no slashes is read as a special scheme.
    assert_eq!(host_of("https://example.com", "https:example.com"), Host);
    assert_eq!(host_of("https://example.com", "https:/example.com"), Host);
    assert_eq!(host_of("https://example.com", "https:///example.com"), Host);
    // Invalid hosts and ports.
    assert_eq!(
        host_of("https://example.com", "https://exa mple.com"),
        NoMatch
    );
    assert_eq!(
        host_of("https://example.com", "https://example.com:99999"),
        NoMatch
    );
    assert_eq!(
        host_of("https://example.com", "https://example.com:abc"),
        NoMatch
    );
    assert_eq!(host_of("https://example.com", "https://"), NoMatch);
    assert_eq!(host_of("https://example.com", "https:///"), NoMatch);
    assert_eq!(host_of("https://example.com", "https://[::1"), NoMatch);
    assert_eq!(host_of("https://example.com", "https://a..b"), NoMatch);
    assert_eq!(host_of("https://a..b", "https://a..b"), NoMatch);
    assert_eq!(
        host_of("https://.example.com", "https://.example.com"),
        NoMatch
    );
    assert_eq!(host_of("https://example.com", ""), NoMatch);
    assert_eq!(host_of("", "https://example.com"), NoMatch);
}

#[test]
fn other_match_kind_and_scheme_less_entries_never_match() {
    let page = "https://example.com/login";
    let other = entry("https://example.com", match_kind("regex"));
    assert!(matches!(other.matching, UrlMatch::Other(_)));
    assert_eq!(url_match(&other, page), NoMatch);
    assert_eq!(
        url_match(&entry("https://example.com", match_kind("")), page),
        NoMatch
    );
    assert_eq!(
        url_match(&entry("https://example.com", match_kind("HOST")), page),
        NoMatch
    );
    for kind in [UrlMatch::Host, UrlMatch::Domain, UrlMatch::Exact] {
        for saved in [
            "example.com",
            "example.com/login",
            "www.example.com",
            "//example.com",
            "/login",
            "example.com:8080",
            "example.com:443/login",
            "localhost",
            "192.168.1.1",
            "mailto:me@example.com",
            "ftp://example.com",
            "ws://example.com",
        ] {
            assert_eq!(
                url_match(&entry(saved, kind.clone()), page),
                NoMatch,
                "{saved}"
            );
        }
    }
}

#[test]
fn inputs_over_8_kib_never_match() {
    let pad = "a".repeat(8 * 1024);
    let long_page = format!("https://example.com/{pad}");
    assert!(long_page.len() > 8 * 1024);
    assert_eq!(host_of("https://example.com", &long_page), NoMatch);
    assert_eq!(host_of(&long_page, "https://example.com"), NoMatch);
    assert_eq!(exact_of(&long_page, &long_page), NoMatch);
    assert_eq!(page_origin(&long_page), Err(BAD_ORIGIN));
    assert_eq!(display_host(&long_page), Err(BAD_ORIGIN));
    assert!(!same_site(&long_page, "https://example.com"));
    assert!(!same_site("https://example.com", &long_page));
    // Exactly 8 KiB is still read.
    let prefix = "https://example.com/";
    let at_limit = format!("{prefix}{}", "a".repeat(8 * 1024 - prefix.len()));
    assert_eq!(at_limit.len(), 8 * 1024);
    assert_eq!(host_of("https://example.com", &at_limit), Host);
    assert_eq!(exact_of(&at_limit, &at_limit), Exact);
    assert!(page_origin(&at_limit).is_ok());
    let over = format!("{at_limit}a");
    assert_eq!(host_of("https://example.com", &over), NoMatch);
}

#[test]
fn opaque_and_non_http_pages_never_match() {
    for kind in [UrlMatch::Host, UrlMatch::Domain, UrlMatch::Exact] {
        let e = entry("https://example.com", kind);
        for page in [
            "data:text/html,<h1>x</h1>",
            "data://example.com",
            "blob:https://example.com/2f6c1f0e-6a52-4f55-9d6e-0c1b3b3f9a10",
            "file:///etc/passwd",
            "file://example.com/x",
            "about:blank",
            "about:srcdoc",
            "javascript:alert(1)",
            "javascript://example.com/%0aalert(1)",
            "view-source:https://example.com",
            "moz-extension://abc/page.html",
            "chrome-extension://abcdefghijklmnop/page.html",
            "ftp://example.com",
            "ws://example.com",
            "wss://example.com",
            "mailto:example.com",
            "null",
            "example.com",
            "//example.com",
            "",
        ] {
            assert_eq!(url_match(&e, page), NoMatch, "{page}");
            assert_eq!(page_origin(page), Err(BAD_ORIGIN), "{page}");
            assert_eq!(display_host(page), Err(BAD_ORIGIN), "{page}");
            assert!(!same_site(page, page), "{page}");
        }
    }
    // An opaque saved address is no web address either.
    assert_eq!(
        host_of("data:text/html,<h1>x</h1>", "data:text/html,<h1>x</h1>"),
        NoMatch
    );
    assert_eq!(host_of("about:blank", "about:blank"), NoMatch);
}

#[test]
fn exact_ignores_only_the_fragment() {
    assert_eq!(
        exact_of("https://example.com/login", "https://example.com/login"),
        Exact
    );
    assert_eq!(
        exact_of("https://example.com/login", "https://example.com/login#top"),
        Exact
    );
    assert_eq!(
        exact_of("https://example.com/login#a", "https://example.com/login#b"),
        Exact
    );
    assert_eq!(
        exact_of("https://example.com", "https://example.com/"),
        Exact
    );
    assert_eq!(
        exact_of("https://example.com/a?x=1", "https://example.com/a?x=1#f"),
        Exact
    );
    for page in [
        "https://example.com/login/",
        "https://example.com/Login",
        "https://example.com/login?x=1",
        "https://example.com/login?",
        "https://example.com/other",
        "https://example.com:8443/login",
        "http://example.com/login",
        "https://www.example.com/login",
    ] {
        assert_eq!(
            exact_of("https://example.com/login", page),
            NoMatch,
            "{page}"
        );
    }
    assert_eq!(
        exact_of("https://example.com/a?x=1", "https://example.com/a?x=2"),
        NoMatch
    );
    assert_eq!(
        exact_of("https://example.com/a?x=1", "https://example.com/a"),
        NoMatch
    );
    // The path is normalized as the browser does.
    assert_eq!(
        exact_of("https://example.com/a/./b/../c", "https://example.com/a/c"),
        Exact
    );
    assert_eq!(
        exact_of("https://example.com/a b", "https://example.com/a%20b"),
        Exact
    );
    // `exact` is never wider than `host`: other hosts of the domain miss.
    assert_eq!(
        exact_of("https://example.com/a", "https://www.example.com/a"),
        NoMatch
    );
}

#[test]
fn trailing_dot_and_case_are_canonical() {
    assert_eq!(host_of("https://example.com.", "https://example.com"), Host);
    assert_eq!(host_of("https://example.com", "https://example.com."), Host);
    assert_eq!(host_of("https://EXAMPLE.Com", "https://example.com"), Host);
    assert_eq!(
        host_of("https://example.com", "https://EXAMPLE.COM./x"),
        Host
    );
    assert_eq!(
        exact_of("https://example.com./a", "https://EXAMPLE.com/a"),
        Exact
    );
    // Only one dot is removed, and an empty label is refused.
    assert_eq!(
        host_of("https://example.com", "https://example.com.."),
        NoMatch
    );
    assert_eq!(
        host_of("https://example.com..", "https://example.com.."),
        NoMatch
    );
    assert_eq!(host_of("https://.", "https://."), NoMatch);
    assert_eq!(
        domain_of("https://example.com.", "https://login.example.com"),
        Domain
    );
}

#[test]
fn page_origin_allows_http_and_ip_hosts() {
    let o = page_origin("https://Example.COM/login?x=1#top").unwrap();
    assert_eq!(o.as_str(), "https://example.com");
    assert_eq!(
        (o.scheme(), o.host(), o.port(), o.is_https(), o.is_ip()),
        ("https", "example.com", 443, true, false)
    );
    let o = page_origin("http://example.com").unwrap();
    assert_eq!(o.as_str(), "http://example.com");
    assert_eq!((o.port(), o.is_https()), (80, false));
    assert_eq!(
        page_origin("http://192.168.1.1:8080/admin")
            .unwrap()
            .as_str(),
        "http://192.168.1.1:8080"
    );
    let o = page_origin("http://3232235777/").unwrap();
    assert_eq!(
        (o.as_str(), o.host(), o.is_ip()),
        ("http://192.168.1.1", "192.168.1.1", true)
    );
    let o = page_origin("https://[2001:DB8::1]:8443/x").unwrap();
    assert_eq!(o.as_str(), "https://[2001:db8::1]:8443");
    assert_eq!(
        (o.host(), o.port(), o.is_ip()),
        ("[2001:db8::1]", 8443, true)
    );
    assert_eq!(
        page_origin("http://[::1]").unwrap().as_str(),
        "http://[::1]"
    );
    assert_eq!(
        page_origin("http://localhost:3000/x").unwrap().as_str(),
        "http://localhost:3000"
    );
    // The default port is dropped from the text and kept in the number; an
    // explicit port that is the other scheme's default is kept.
    assert_eq!(
        page_origin("https://a.example:443").unwrap().as_str(),
        "https://a.example"
    );
    assert_eq!(
        page_origin("http://a.example:80").unwrap().as_str(),
        "http://a.example"
    );
    assert_eq!(
        page_origin("https://a.example:80").unwrap().as_str(),
        "https://a.example:80"
    );
    // A name with a trailing dot, a Unicode name and a name with an
    // underscore.
    assert_eq!(
        page_origin("https://EXAMPLE.com./").unwrap().as_str(),
        "https://example.com"
    );
    assert_eq!(
        page_origin("https://Bücher.example/").unwrap().as_str(),
        "https://xn--bcher-kva.example"
    );
    assert_eq!(
        page_origin("https://exa_mple.example/").unwrap().host(),
        "exa_mple.example"
    );
    // A path longer than the 300 bytes that `canonical_origin` allows.
    let long = format!("https://example.com/{}", "a".repeat(2000));
    assert_eq!(page_origin(&long).unwrap().as_str(), "https://example.com");
    // Idempotent: the text of an origin is an origin that gives itself.
    for page in [
        "https://a.example:8443/x",
        "http://10.0.0.1",
        "http://[::1]:81",
    ] {
        let once = page_origin(page).unwrap();
        assert_eq!(page_origin(once.as_str()).unwrap(), once);
    }
    // What it refuses.
    for bad in [
        "https://user@example.com",
        "https://user:pw@example.com",
        "ftp://example.com",
        "about:blank",
        "example.com",
        "https://",
        "https://example.com:0",
        "https://example.com:65536",
        "https://a..b",
    ] {
        assert_eq!(page_origin(bad), Err(BAD_ORIGIN), "{bad}");
    }
    assert_eq!(BAD_ORIGIN.code(), "malformed_origin");
}

#[test]
fn same_site_is_schemeful_and_uses_private_suffixes() {
    assert!(same_site("https://a.example.com", "https://b.example.com"));
    assert!(same_site(
        "https://example.com",
        "https://www.example.com/x?y#z"
    ));
    assert!(same_site("https://a.example.com", "https://a.example.com"));
    assert!(same_site(
        "https://a.example.com:8443",
        "https://b.example.com"
    ));
    assert!(same_site(
        "https://a.example.co.uk",
        "https://b.example.co.uk"
    ));
    assert!(!same_site(
        "https://a.example.co.uk",
        "https://b.other.co.uk"
    ));
    // Schemeful.
    assert!(!same_site("http://a.example.com", "https://a.example.com"));
    assert!(!same_site("http://a.example.com", "https://b.example.com"));
    assert!(same_site("http://a.example.com", "http://b.example.com"));
    // Private suffixes.
    assert!(!same_site("https://a.github.io", "https://b.github.io"));
    assert!(same_site("https://a.github.io", "https://x.a.github.io"));
    assert!(same_site("https://github.io", "https://github.io"));
    assert!(!same_site("https://github.io", "https://a.github.io"));
    // Another registrable domain.
    assert!(!same_site("https://example.com", "https://example.org"));
    assert!(!same_site(
        "https://example.com",
        "https://example.com.evil.net"
    ));
    // IP hosts: only the identical address.
    assert!(same_site("http://192.168.1.1", "http://192.168.1.1/x"));
    assert!(same_site("http://192.168.1.1:80", "http://3232235777:8080"));
    assert!(!same_site("http://192.168.1.1", "http://192.168.1.2"));
    assert!(!same_site("https://192.168.1.1", "http://192.168.1.1"));
    assert!(same_site("http://[::1]", "http://[0::1]:81"));
    assert!(!same_site("http://[::1]", "http://[::2]"));
    // Hosts without a registrable domain: only the identical host.
    assert!(same_site("https://fritz.box", "https://fritz.box"));
    assert!(!same_site("https://a.fritz.box", "https://b.fritz.box"));
    assert!(same_site("https://intranet", "https://intranet/x"));
    assert!(!same_site("https://intranet", "https://other"));
    assert!(!same_site("https://a.lan", "https://b.lan"));
    assert!(!same_site(
        "https://nas.home.arpa",
        "https://x.nas.home.arpa"
    ));
    assert!(same_site("http://localhost:3000", "http://localhost:4000"));
    // Trailing dots and case.
    assert!(same_site("https://EXAMPLE.com.", "https://www.example.com"));
    // Not web pages.
    assert!(!same_site("about:blank", "about:blank"));
    assert!(!same_site("https://example.com", "data:text/html,x"));
    assert!(!same_site("", ""));
    assert!(!same_site("https://u@example.com", "https://example.com"));
    // The check is symmetric on the examples above.
    for (a, b) in [
        ("https://a.example.com", "https://b.example.com"),
        ("http://a.example.com", "https://a.example.com"),
        ("https://a.github.io", "https://b.github.io"),
        ("http://192.168.1.1", "http://3232235777"),
    ] {
        assert_eq!(same_site(a, b), same_site(b, a), "{a} {b}");
    }
}

#[test]
fn display_host_gives_both_forms() {
    let h = display_host("https://example.com/x").unwrap();
    assert_eq!(
        (h.a_label.as_str(), h.unicode.as_str()),
        ("example.com", "example.com")
    );
    let h = display_host("https://Bücher.example").unwrap();
    assert_eq!(h.a_label, "xn--bcher-kva.example");
    assert_eq!(h.unicode, "bücher.example");
    let h = display_host("https://xn--bcher-kva.example/").unwrap();
    assert_eq!(h.a_label, "xn--bcher-kva.example");
    assert_eq!(h.unicode, "bücher.example");
    let h = display_host("https://пример.рф").unwrap();
    assert_eq!(h.a_label, "xn--e1afmkfd.xn--p1ai");
    assert_eq!(h.unicode, "пример.рф");
    // A label that mixes Latin with Cyrillic, Greek or Armenian stays in
    // A-label form.
    let h = display_host("https://exаmple.com").unwrap();
    assert_eq!(h.a_label, "xn--exmple-4nf.com");
    assert_eq!(h.unicode, "xn--exmple-4nf.com");
    let h = display_host("https://exαmple.com").unwrap();
    assert_eq!(h.unicode, "xn--exmple-qxe.com");
    let h = display_host("https://gօogle.com").unwrap();
    assert_eq!(h.unicode, "xn--gogle-lkg.com");
    let h = display_host("https://абвa.com").unwrap();
    assert_eq!(h.unicode, "xn--a-7sbde.com");
    // Han with Latin is a mix too.
    let h = display_host("https://日本abc.jp").unwrap();
    assert_eq!(h.unicode, "xn--abc-s08fl0d.jp");
    // The decision is per label: the other labels show in Unicode.
    let h = display_host("https://shop.exаmple.com").unwrap();
    assert_eq!(h.a_label, "shop.xn--exmple-4nf.com");
    assert_eq!(h.unicode, "shop.xn--exmple-4nf.com");
    let h = display_host("https://пример.exаmple.рф").unwrap();
    assert_eq!(h.a_label, "xn--e1afmkfd.xn--exmple-4nf.xn--p1ai");
    assert_eq!(h.unicode, "пример.xn--exmple-4nf.рф");
    // A label from one script shows in Unicode: digits and hyphens do not
    // count, and neither does the top-level domain's script.
    let h = display_host("https://пример-1.рф").unwrap();
    assert_eq!(h.unicode, "пример-1.рф");
    let h = display_host("https://αβγ.gr").unwrap();
    assert_eq!(h.unicode, "αβγ.gr");
    let h = display_host("https://café.com").unwrap();
    assert_eq!(h.unicode, "café.com");
    // A digit of another script counts as a letter of that script: a
    // Devanagari or Gujarati zero in a Latin label is a mix.
    let h = display_host("https://faceb\u{966}\u{966}k.com").unwrap();
    assert_eq!(h.unicode, "xn--facebk-09ma.com");
    let h = display_host("https://g\u{ae6}\u{ae6}gle.com").unwrap();
    assert_eq!(h.unicode, "xn--ggle-l4ka.com");
    // ... and a label with the digits of its own script is one script.
    let h = display_host("https://\u{92d}\u{93e}\u{930}\u{924}\u{967}.in").unwrap();
    assert_eq!(h.unicode, "\u{92d}\u{93e}\u{930}\u{924}\u{967}.in");
    let h = display_host("https://\u{e44}\u{e17}\u{e22}\u{e51}.th").unwrap();
    assert_eq!(h.unicode, "\u{e44}\u{e17}\u{e22}\u{e51}.th");
    // The Arabic blocks are one script (Persian, Urdu), digits included.
    let h = display_host("https://\u{6af}\u{686}\u{67e}.ir").unwrap();
    assert_eq!(h.a_label, "xn--3ibp6j.ir");
    assert_eq!(h.unicode, "\u{6af}\u{686}\u{67e}.ir");
    let h = display_host("https://\u{62a}\u{633}\u{62a}\u{661}\u{662}.sa").unwrap();
    assert_eq!(h.unicode, "\u{62a}\u{633}\u{62a}\u{661}\u{662}.sa");
    // The prolonged sound mark belongs to the kana.
    let h = display_host("https://\u{30b3}\u{30fc}\u{30d2}\u{30fc}.jp").unwrap();
    assert_eq!(h.a_label, "xn--tck2c4fb.jp");
    assert_eq!(h.unicode, "\u{30b3}\u{30fc}\u{30d2}\u{30fc}.jp");
    // Japanese, Korean and Chinese writing is one system each.
    for host in [
        "日本語ひらがな.jp",
        "日本カタカナ.jp",
        "한漢字.kr",
        "注音ㄅㄆ.tw",
    ] {
        let h = display_host(&format!("https://{host}/")).unwrap();
        assert_eq!(h.unicode, host);
        assert!(h.a_label.contains("xn--"));
    }
    // A label from a single script that looks like another is still shown in
    // Unicode, as a browser does: the match, which compares A-labels, is the
    // boundary.
    let h = display_host("https://аррӏе.com").unwrap();
    assert_eq!(h.a_label, "xn--80ak6aa92e.com");
    assert_eq!(h.unicode, "аррӏе.com");
    assert_eq!(
        host_of("https://apple.com", "https://xn--80ak6aa92e.com"),
        NoMatch
    );
    // A trailing dot and the case are removed.
    let h = display_host("https://EXAMPLE.com./").unwrap();
    assert_eq!(
        (h.a_label.as_str(), h.unicode.as_str()),
        ("example.com", "example.com")
    );
    // IP hosts: both forms are the address.
    let h = display_host("http://3232235777/").unwrap();
    assert_eq!(
        (h.a_label.as_str(), h.unicode.as_str()),
        ("192.168.1.1", "192.168.1.1")
    );
    let h = display_host("http://[2001:DB8::1]:8080/").unwrap();
    assert_eq!(h.a_label, "[2001:db8::1]");
    assert_eq!(h.unicode, "[2001:db8::1]");
    // A name that is not a valid A-label back to Unicode keeps its A-label.
    let h = display_host("https://xn--a.example/");
    if let Ok(h) = h {
        assert_eq!(h.a_label, "xn--a.example");
        assert!(!h.unicode.is_empty());
    }
    assert_eq!(display_host("ftp://example.com"), Err(BAD_ORIGIN));
    assert_eq!(display_host("https://u@example.com"), Err(BAD_ORIGIN));
    assert_eq!(display_host("example.com"), Err(BAD_ORIGIN));
}

// ------------------------------------------------------------ vectors

fn is_url_op(op: &str) -> bool {
    op.starts_with("url.")
}

#[test]
fn vectors_url_match_pass() {
    let file = load_ops("url-match.json", is_url_op);
    let report = ferret_core::testing::vector::run_all(&file, |case, _rng| {
        let input = &case.input;
        match case.op.as_str() {
            "url.match" => {
                let e = UrlEntry {
                    url: utf8(&input["entry_utf8"]),
                    matching: UrlMatch::from_text(input["match"].as_str().unwrap().to_owned()),
                    extra: Vec::new(),
                };
                let r = url_match(&e, &utf8(&input["page_utf8"]));
                Ok(Outcome {
                    output: json!({ "result": result_text(r) }),
                    intermediate: None,
                })
            }
            "url.page_origin" => {
                let o = page_origin(&utf8(&input["page_utf8"]))?;
                Ok(Outcome {
                    output: json!({
                        "origin": o.as_str(),
                        "scheme": o.scheme(),
                        "host": o.host(),
                        "port": o.port(),
                    }),
                    intermediate: None,
                })
            }
            "url.same_site" => {
                let r = same_site(&utf8(&input["a_utf8"]), &utf8(&input["b_utf8"]));
                Ok(Outcome {
                    output: json!({ "same_site": r }),
                    intermediate: None,
                })
            }
            "url.display_host" => {
                let h = display_host(&utf8(&input["page_utf8"]))?;
                Ok(Outcome {
                    output: json!({ "a_label": h.a_label, "unicode": h.unicode }),
                    intermediate: None,
                })
            }
            other => panic!("unknown op {other}"),
        }
    });
    assert_all_passed(&report, 80);
}

#[test]
fn vectors_cover_the_four_ops() {
    let file = load_ops("url-match.json", |_| true);
    for op in [
        "url.match",
        "url.page_origin",
        "url.same_site",
        "url.display_host",
    ] {
        let n = file.cases.iter().filter(|c| c.op == op).count();
        assert!(n >= 10, "{op} has {n} cases");
    }
    assert!(file.cases.len() >= 80);
    assert!(file.cases.iter().all(|c| is_url_op(&c.op)));
}

#[test]
fn vectors_manifest_lists_the_new_file() {
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(vectors_dir().join("MANIFEST.json")).unwrap())
            .unwrap();
    let listed = manifest["files"]["internal/url-match.json"]
        .as_str()
        .expect("MANIFEST.json lists internal/url-match.json");
    let bytes = std::fs::read(vectors_dir().join("internal/url-match.json")).unwrap();
    assert_eq!(
        listed,
        ferret_core::testing::hex_encode(&Sha256::digest(&bytes))
    );
    // The runner for bindings knows the file: it is native only until a
    // binding exposes the operations.
    let runner = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../bindings/wasm/js/vector-runner.mjs"),
    )
    .unwrap();
    assert!(runner.contains("\"url-match\""));
    // And the register describes the ops.
    let ops = std::fs::read_to_string(vectors_dir().join("OPS.md")).unwrap();
    for op in [
        "url.match",
        "url.page_origin",
        "url.same_site",
        "url.display_host",
    ] {
        assert!(ops.contains(&format!("| `{op}` |")), "{op}");
    }
}
