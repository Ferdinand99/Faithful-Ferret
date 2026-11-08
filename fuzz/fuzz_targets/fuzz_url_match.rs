//! Site matching and the page address functions on arbitrary text: never a
//! panic, and the four functions agree with one another. The input is a kind
//! byte, the saved address, a NUL byte and the page address; at most 16 KiB
//! (the longest address the core reads is 8 KiB).
#![no_main]

use ferret_core::{
    UrlEntry, UrlMatch, UrlMatchResult, display_host, page_origin, same_site, url_match,
};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT: usize = 16 * 1024;

fn entry(url: &str, matching: UrlMatch) -> UrlEntry {
    UrlEntry {
        url: url.to_owned(),
        matching,
        extra: Vec::new(),
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT {
        return;
    }
    let Some((kind, rest)) = data.split_first() else {
        return;
    };
    let (saved_bytes, page_bytes) = match rest.iter().position(|b| *b == 0) {
        Some(i) => (&rest[..i], &rest[i + 1..]),
        None => (rest, &rest[..0]),
    };
    let (Ok(saved), Ok(page)) = (
        std::str::from_utf8(saved_bytes),
        std::str::from_utf8(page_bytes),
    ) else {
        return;
    };
    let kind = match kind % 4 {
        0 => UrlMatch::Host,
        1 => UrlMatch::Domain,
        2 => UrlMatch::Exact,
        _ => UrlMatch::Other("regex".to_owned()),
    };

    let result = url_match(&entry(saved, kind.clone()), page);
    match (&kind, result) {
        (_, UrlMatchResult::None) => {}
        (UrlMatch::Host, UrlMatchResult::Host) => {}
        (UrlMatch::Domain, UrlMatchResult::Host | UrlMatchResult::Domain) => {}
        (UrlMatch::Exact, UrlMatchResult::Exact) => {}
        _ => panic!("result {result:?} is not one a {kind:?} entry can give"),
    }

    let origin = page_origin(page);
    let shown = display_host(page);
    assert_eq!(origin.is_ok(), shown.is_ok());
    assert_eq!(origin.is_ok(), same_site(page, page));
    assert_eq!(same_site(saved, page), same_site(page, saved));
    if result != UrlMatchResult::None {
        // A match is on a page with an origin, in the same site and at the
        // same scheme and port as the saved address.
        let o = origin.as_ref().expect("a matched page has an origin");
        let saved_origin = page_origin(saved).expect("a matched entry has an origin");
        assert_eq!((o.scheme(), o.port()), (saved_origin.scheme(), saved_origin.port()));
        assert!(same_site(saved, page));
        if result == UrlMatchResult::Exact || result == UrlMatchResult::Host {
            assert_eq!(o.host(), saved_origin.host());
        }
    }
    if let (Ok(o), Ok(h)) = (origin, shown) {
        let again = page_origin(o.as_str()).expect("an origin reads again");
        assert_eq!(o, again);
        assert_eq!(h.a_label, o.host());
        assert!(h.a_label.is_ascii());
        assert!(!h.unicode.is_empty());
        assert!(o.port() != 0);
        // The address is a match for itself with every kind that can match.
        for kind in [UrlMatch::Host, UrlMatch::Domain, UrlMatch::Exact] {
            assert_ne!(url_match(&entry(page, kind), page), UrlMatchResult::None);
        }
    }
});
