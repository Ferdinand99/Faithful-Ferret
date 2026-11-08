//! Property tests for site matching, same-site, the origin of a page and the
//! host for display.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use ferret_core::testing::passkey::is_public_suffix;
use ferret_core::{
    UrlEntry, UrlMatch, UrlMatchResult, display_host, page_origin, same_site, url_match,
};
use proptest::prelude::*;

fn config() -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(512);
    ProptestConfig {
        cases,
        ..ProptestConfig::default()
    }
}

fn entry(url: String, matching: UrlMatch) -> UrlEntry {
    UrlEntry {
        url,
        matching,
        extra: Vec::new(),
    }
}

fn label() -> impl Strategy<Value = String> {
    prop_oneof![
        "[a-wyz][a-z0-9-]{0,8}",
        Just("example".to_owned()),
        Just("github".to_owned()),
        Just("co".to_owned()),
        Just("xn--bcher-kva".to_owned()),
    ]
}

fn tld() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("com".to_owned()),
        Just("co.uk".to_owned()),
        Just("github.io".to_owned()),
        Just("lan".to_owned()),
        Just("box".to_owned()),
        Just("home.arpa".to_owned()),
        "[a-z]{2,6}",
    ]
}

fn host() -> impl Strategy<Value = String> {
    prop_oneof![
        (prop::collection::vec(label(), 0..4), tld()).prop_map(|(labels, tld)| {
            let mut h = labels.join(".");
            if !h.is_empty() {
                h.push('.');
            }
            h.push_str(&tld);
            h
        }),
        label(),
        (0u8..=255, 0u8..=255, 0u8..=255, 0u8..=255)
            .prop_map(|(a, b, c, d)| format!("{a}.{b}.{c}.{d}")),
        Just("[::1]".to_owned()),
        Just("3232235777".to_owned()),
        Just("localhost".to_owned()),
    ]
}

fn scheme() -> impl Strategy<Value = &'static str> {
    prop_oneof![Just("http"), Just("https")]
}

fn page() -> impl Strategy<Value = String> {
    (
        scheme(),
        host(),
        prop::option::of(prop_oneof![
            Just(80u16),
            Just(443),
            Just(8080),
            1u16..=65535
        ]),
        prop_oneof![
            Just(String::new()),
            Just("/".to_owned()),
            "/[a-z0-9/]{0,12}",
            "/[a-z]{1,4}\\?[a-z]=[0-9]#[a-z]{0,3}"
        ],
    )
        .prop_map(|(scheme, host, port, path)| match port {
            Some(p) => format!("{scheme}://{host}:{p}{path}"),
            None => format!("{scheme}://{host}{path}"),
        })
}

fn kinds() -> [UrlMatch; 3] {
    [UrlMatch::Host, UrlMatch::Domain, UrlMatch::Exact]
}

proptest! {
    #![proptest_config(config())]

    /// An entry never matches a page of the other scheme, whatever the host,
    /// port and match kind.
    #[test]
    fn url_match_is_none_for_every_scheme_mismatch(
        host in host(),
        port in prop::option::of(1u16..=65535),
        path in "(/[a-z0-9]{0,6}){0,3}",
        entry_https in any::<bool>(),
    ) {
        let (a, b) = if entry_https { ("https", "http") } else { ("http", "https") };
        let port = port.map(|p| format!(":{p}")).unwrap_or_default();
        let saved = format!("{a}://{host}{port}{path}");
        let on_page = format!("{b}://{host}{port}{path}");
        for kind in kinds() {
            prop_assert_eq!(url_match(&entry(saved.clone(), kind), &on_page), UrlMatchResult::None);
        }
    }

    /// Same-site is symmetric, and reflexive for every address it reads.
    #[test]
    fn same_site_is_symmetric(a in page(), b in page()) {
        prop_assert_eq!(same_site(&a, &b), same_site(&b, &a));
        prop_assert!(same_site(&a, &a));
    }

    /// The result never says more than the match kind of the entry: `host`
    /// gives `Host`, `domain` gives `Host` or `Domain`, `exact` gives `Exact`.
    /// A match is on a page whose origin the core can state, with the same
    /// scheme and port.
    #[test]
    fn domain_implies_host_or_domain_result(a in page(), b in page()) {
        let host = url_match(&entry(a.clone(), UrlMatch::Host), &b);
        let domain = url_match(&entry(a.clone(), UrlMatch::Domain), &b);
        let exact = url_match(&entry(a.clone(), UrlMatch::Exact), &b);
        prop_assert!(matches!(host, UrlMatchResult::None | UrlMatchResult::Host));
        prop_assert!(matches!(
            domain,
            UrlMatchResult::None | UrlMatchResult::Host | UrlMatchResult::Domain
        ));
        prop_assert!(matches!(exact, UrlMatchResult::None | UrlMatchResult::Exact));
        // `domain` is at least as wide as `host`, and says `Host` when the
        // hosts are equal.
        if host == UrlMatchResult::Host {
            prop_assert_eq!(domain, UrlMatchResult::Host);
        }
        // `exact` is never wider than `host`.
        if exact == UrlMatchResult::Exact {
            prop_assert_eq!(host, UrlMatchResult::Host);
        }
        if domain != UrlMatchResult::None {
            let (oa, ob) = (page_origin(&a).unwrap(), page_origin(&b).unwrap());
            prop_assert_eq!((oa.scheme(), oa.port()), (ob.scheme(), ob.port()));
            prop_assert!(same_site(&a, &b));
            if oa.is_ip() || ob.is_ip() {
                prop_assert_eq!(domain, UrlMatchResult::Host);
            }
        }
    }

    /// An address saved with http never matches a different host, whatever
    /// its match kind: the answer is `None`, `Host` (the same host) or, for
    /// `exact`, `Exact`.
    #[test]
    fn an_http_entry_never_matches_a_different_host(
        a in host(),
        b in host(),
        port in prop::option::of(1u16..=65535),
    ) {
        let port = port.map(|p| format!(":{p}")).unwrap_or_default();
        let saved = format!("http://{a}{port}/x");
        let on_page = format!("http://{b}{port}/x");
        let same_host = match (page_origin(&saved), page_origin(&on_page)) {
            (Ok(x), Ok(y)) => x.host() == y.host(),
            _ => false,
        };
        for kind in kinds() {
            let r = url_match(&entry(saved.clone(), kind.clone()), &on_page);
            prop_assert_ne!(r, UrlMatchResult::Domain);
            if !same_host {
                prop_assert_eq!(r, UrlMatchResult::None);
            }
        }
    }

    /// Hosts that differ under a private or public suffix are never one site
    /// and never a domain match: `<a>.github.io` and `<b>.github.io`.
    #[test]
    fn siblings_under_a_suffix_are_not_one_site(
        a in "[a-z][a-z0-9]{0,8}",
        b in "[a-z][a-z0-9]{0,8}",
        suffix in prop_oneof![
            Just("github.io"), Just("blogspot.com"), Just("vercel.app"),
            Just("herokuapp.com"), Just("co.uk"), Just("com.au"),
        ],
        deep in any::<bool>(),
    ) {
        prop_assume!(a != b);
        let (x, y) = if deep {
            (format!("https://www.{a}.{suffix}"), format!("https://{b}.{suffix}"))
        } else {
            (format!("https://{a}.{suffix}"), format!("https://{b}.{suffix}"))
        };
        prop_assert!(!same_site(&x, &y));
        prop_assert_eq!(url_match(&entry(x, UrlMatch::Domain), &y), UrlMatchResult::None);
    }

    /// An independent check of a `Domain` result: some suffix R of the saved
    /// host is not a public suffix, its parent is, and both hosts are R or
    /// end with `.R`. It uses the suffix test of the origin rules, not the
    /// registrable-domain code that the match uses.
    #[test]
    fn a_domain_result_has_a_registrable_domain_both_hosts_share(a in page(), b in page()) {
        let saved = entry(a.clone(), UrlMatch::Domain);
        if url_match(&saved, &b) == UrlMatchResult::Domain {
            let (oa, ob) = (page_origin(&a).unwrap(), page_origin(&b).unwrap());
            prop_assert!(oa.is_https() && ob.is_https());
            prop_assert!(!oa.is_ip() && !ob.is_ip());
            let g = oa.host();
            let h = ob.host();
            let mut found = false;
            let mut rest = g;
            while let Some((_, parent)) = rest.split_once('.') {
                if is_public_suffix(parent) && !is_public_suffix(rest) {
                    let dotted = format!(".{rest}");
                    found = (g == rest || g.ends_with(&dotted)) && (h == rest || h.ends_with(&dotted));
                    break;
                }
                rest = parent;
            }
            prop_assert!(found, "{g} and {h}");
            let tld = g.rsplit('.').next().unwrap_or(g);
            prop_assert!(tld != "arpa" && tld != "box");
        }
    }

    /// An address matches itself with every match kind.
    #[test]
    fn an_address_matches_itself(a in page()) {
        prop_assert_eq!(url_match(&entry(a.clone(), UrlMatch::Host), &a), UrlMatchResult::Host);
        prop_assert_eq!(url_match(&entry(a.clone(), UrlMatch::Domain), &a), UrlMatchResult::Host);
        prop_assert_eq!(url_match(&entry(a.clone(), UrlMatch::Exact), &a), UrlMatchResult::Exact);
    }

    /// None of the four functions panics, and the answers agree on any text:
    /// an origin exists exactly when a host for display does and when the
    /// address is the same site as itself; the origin of an origin is itself.
    #[test]
    fn the_functions_agree_on_any_text(text in ".{0,200}") {
        let origin = page_origin(&text);
        let shown = display_host(&text);
        prop_assert_eq!(origin.is_ok(), shown.is_ok());
        prop_assert_eq!(origin.is_ok(), same_site(&text, &text));
        for kind in kinds() {
            let r = url_match(&entry(text.clone(), kind), &text);
            if r != UrlMatchResult::None {
                prop_assert!(origin.is_ok());
            }
        }
        if let (Ok(o), Ok(h)) = (origin, shown) {
            prop_assert_eq!(page_origin(o.as_str()).unwrap(), o.clone());
            prop_assert_eq!(h.a_label.as_str(), o.host());
            prop_assert!(!h.unicode.is_empty());
            prop_assert!(h.a_label.is_ascii());
        }
    }

    /// Text built from the characters that matter to a URL parser.
    #[test]
    fn url_like_text_never_panics_and_never_matches_by_accident(
        text in "[a-zA-Z0-9:/?#@\\\\.%\\[\\]\t\n -]{0,80}",
    ) {
        let _ = page_origin(&text);
        let _ = display_host(&text);
        // A page that carries user info matches nothing.
        let with_user = format!("https://u@{text}");
        prop_assert_eq!(
            url_match(&entry("https://example.com".to_owned(), UrlMatch::Domain), &with_user),
            UrlMatchResult::None
        );
        prop_assert!(page_origin(&with_user).is_err());
    }

    /// Anything over 8 KiB never matches and is never an origin.
    #[test]
    fn long_text_is_refused(extra in 1usize..64) {
        let long = format!("https://example.com/{}", "a".repeat(8 * 1024 + extra));
        prop_assert_eq!(
            url_match(&entry("https://example.com".to_owned(), UrlMatch::Host), &long),
            UrlMatchResult::None
        );
        prop_assert!(page_origin(&long).is_err());
        prop_assert!(!same_site(&long, &long));
    }
}
