//! The vector group for site matching and page addresses (`url-match.json`).
//!
//! Every expected value is written out here by hand from the rules of
//! Fase 1 § 10.4 and § 10.5 and from the URL Standard (WHATWG): what a browser
//! makes of `https://exam\tple.com`, `3232235777`, a backslash or a
//! percent-encoded host, and the A-labels of the IDNA examples that are known
//! independently. The registrable domains come from the Public Suffix List
//! (its own test file is in `vectors/external/`). Nothing is computed by the
//! core.
//!
//! Ops (see `vectors/OPS.md`): `url.match`, `url.page_origin`, `url.same_site`
//! and `url.display_host`. No binding exposes them yet, so every case is
//! `native-only`.

use crate::groups::generator;
use crate::{Error, render};
use ferret_core::testing::hex_encode;
use ferret_core::testing::vector::{Case, Status, Tag, VectorFile};
use serde_json::{Value, json};

const NATIVE_ONLY: &str = "No WebAssembly binding exposes the page address operations yet.";

/// `(saved address, match kind, page address, result)`. The kind is the text
/// of the entry; a text that is none of `host`, `domain` and `exact` is a kind
/// this version does not know.
type MatchRow = (&'static str, &'static str, &'static str, &'static str);

const MATCHES: &[MatchRow] = &[
    // --- host: the default
    ("https://example.com", "host", "https://example.com", "host"),
    (
        "https://example.com",
        "host",
        "https://example.com/login?next=/a#top",
        "host",
    ),
    (
        "https://example.com/a/b",
        "host",
        "https://example.com/c",
        "host",
    ),
    (
        "https://example.com",
        "host",
        "https://www.example.com",
        "none",
    ),
    (
        "https://www.example.com",
        "host",
        "https://example.com",
        "none",
    ),
    ("https://example.com", "host", "https://example.org", "none"),
    (
        "https://a.example.com",
        "host",
        "https://login.a.example.com",
        "none",
    ),
    // --- case, trailing dot, ports
    ("HTTPS://EXAMPLE.COM", "host", "https://example.com", "host"),
    (
        "https://example.com.",
        "host",
        "https://example.com",
        "host",
    ),
    (
        "https://example.com",
        "host",
        "https://EXAMPLE.com./",
        "host",
    ),
    (
        "https://example.com",
        "host",
        "https://example.com..",
        "none",
    ),
    (
        "https://example.com",
        "host",
        "https://example.com:443",
        "host",
    ),
    (
        "https://example.com:0443",
        "host",
        "https://example.com",
        "host",
    ),
    (
        "https://example.com:8443",
        "host",
        "https://example.com:8443/x",
        "host",
    ),
    (
        "https://example.com:8443",
        "host",
        "https://example.com",
        "none",
    ),
    (
        "https://example.com",
        "host",
        "https://example.com:8443",
        "none",
    ),
    (
        "https://example.com",
        "host",
        "https://example.com:80",
        "none",
    ),
    // --- http and https
    ("https://example.com", "host", "http://example.com", "none"),
    (
        "https://example.com/login",
        "exact",
        "http://example.com/login",
        "none",
    ),
    (
        "https://example.com",
        "domain",
        "http://www.example.com",
        "none",
    ),
    ("http://example.com", "host", "http://example.com", "host"),
    ("http://example.com", "host", "https://example.com", "none"),
    (
        "http://example.com:80",
        "host",
        "http://example.com/x",
        "host",
    ),
    (
        "http://example.com",
        "host",
        "http://example.com:8080",
        "none",
    ),
    // An address saved with http is never widened to other hosts.
    (
        "http://example.com",
        "domain",
        "http://www.example.com",
        "none",
    ),
    (
        "http://www.example.com",
        "domain",
        "http://example.com",
        "none",
    ),
    (
        "http://example.com",
        "domain",
        "http://example.com/login",
        "host",
    ),
    (
        "http://example.co.uk",
        "domain",
        "http://shop.example.co.uk",
        "none",
    ),
    (
        "http://example.com/a",
        "exact",
        "http://www.example.com/a",
        "none",
    ),
    (
        "http://example.com",
        "domain",
        "https://www.example.com",
        "none",
    ),
    (
        "http://localhost:3000",
        "host",
        "http://localhost:3000/",
        "host",
    ),
    ("http://localhost:3000", "host", "http://localhost", "none"),
    ("https://localhost", "host", "http://localhost", "none"),
    // --- lookalikes and homographs
    ("https://example.com", "host", "https://examp1e.com", "none"),
    (
        "https://example.com",
        "host",
        "https://example.com.evil.net",
        "none",
    ),
    (
        "https://example.com",
        "domain",
        "https://sub.example.com.evil.net",
        "none",
    ),
    (
        "https://example.com",
        "host",
        "https://evil.net/example.com",
        "none",
    ),
    (
        "https://example.com",
        "host",
        "https://example.com@evil.net",
        "none",
    ),
    (
        "https://example.com",
        "host",
        "https://evil.net#@example.com",
        "none",
    ),
    (
        "https://example.com",
        "host",
        "https://evil.net\\@example.com",
        "none",
    ),
    (
        "https://example.com",
        "host",
        "https://example-com.net",
        "none",
    ),
    ("https://example.com", "host", "https://examplecom", "none"),
    // The Cyrillic letter а (U+0430) in place of the Latin a.
    (
        "https://example.com",
        "host",
        "https://ex\u{0430}mple.com",
        "none",
    ),
    (
        "https://example.com",
        "domain",
        "https://www.ex\u{0430}mple.com",
        "none",
    ),
    (
        "https://ex\u{0430}mple.com",
        "host",
        "https://example.com",
        "none",
    ),
    (
        "https://ex\u{0430}mple.com",
        "host",
        "https://ex\u{0430}mple.com",
        "host",
    ),
    (
        "https://ex\u{0430}mple.com",
        "host",
        "https://xn--exmple-4nf.com",
        "host",
    ),
    // --- WHATWG edge cases
    (
        "https://example.com",
        "host",
        "https://example.com\\login",
        "host",
    ),
    (
        "https://example.com",
        "host",
        "https://example.com\\@evil.net",
        "host",
    ),
    (
        "https://example.com",
        "host",
        "https://exam\tple.com",
        "host",
    ),
    (
        "https://example.com",
        "host",
        "ht\ntps://example.com",
        "host",
    ),
    (
        "https://example.com",
        "host",
        "https://example.com\r\n/x",
        "host",
    ),
    (
        "https://example.com",
        "host",
        "https://example.com\t.evil.net",
        "none",
    ),
    (
        "https://example.com",
        "host",
        "  https://example.com  ",
        "host",
    ),
    (
        "https://example.com",
        "host",
        "https://%65xample.com",
        "host",
    ),
    (
        "https://example.com",
        "host",
        "https://example%2Ecom",
        "host",
    ),
    (
        "https://example.com",
        "host",
        "https://example.com%2F.evil.net",
        "none",
    ),
    (
        "https://example.com",
        "host",
        "https://\u{ff45}\u{ff58}\u{ff41}\u{ff4d}\u{ff50}\u{ff4c}\u{ff45}\u{3002}\u{ff43}\u{ff4f}\u{ff4d}",
        "host",
    ),
    ("https://example.com", "host", "https:example.com", "host"),
    (
        "https://example.com",
        "host",
        "https:///example.com",
        "host",
    ),
    (
        "https://example.com",
        "host",
        "https://exa mple.com",
        "none",
    ),
    (
        "https://example.com",
        "host",
        "https://example.com:99999",
        "none",
    ),
    (
        "https://example.com",
        "host",
        "https://example.com:abc",
        "none",
    ),
    ("https://example.com", "host", "https://", "none"),
    ("https://example.com", "host", "https://[::1", "none"),
    ("https://example.com", "host", "", "none"),
    ("", "host", "https://example.com", "none"),
    ("https://a..b", "host", "https://a..b", "none"),
    // --- user info never matches
    (
        "https://example.com",
        "host",
        "https://user@example.com",
        "none",
    ),
    (
        "https://example.com",
        "host",
        "https://user:pw@example.com",
        "none",
    ),
    (
        "https://example.com",
        "domain",
        "https://:pw@example.com",
        "none",
    ),
    (
        "https://user@example.com",
        "host",
        "https://example.com",
        "none",
    ),
    (
        "https://user@example.com",
        "host",
        "https://user@example.com",
        "none",
    ),
    // --- pages that are not web pages
    (
        "https://example.com",
        "host",
        "data:text/html,<h1>x</h1>",
        "none",
    ),
    (
        "https://example.com",
        "host",
        "blob:https://example.com/2f6c1f0e-6a52-4f55-9d6e-0c1b3b3f9a10",
        "none",
    ),
    ("https://example.com", "host", "file:///etc/passwd", "none"),
    ("https://example.com", "host", "about:blank", "none"),
    ("https://example.com", "host", "javascript:alert(1)", "none"),
    ("https://example.com", "host", "ftp://example.com", "none"),
    (
        "https://example.com",
        "host",
        "moz-extension://abc/page.html",
        "none",
    ),
    ("about:blank", "host", "about:blank", "none"),
    // --- saved addresses without a scheme, and kinds this version does not know
    ("example.com", "host", "https://example.com", "none"),
    ("example.com", "domain", "https://example.com", "none"),
    (
        "www.example.com/login",
        "host",
        "https://www.example.com/login",
        "none",
    ),
    ("//example.com", "host", "https://example.com", "none"),
    ("example.com:8080", "host", "https://example.com", "none"),
    ("example.com", "exact", "https://example.com", "none"),
    (
        "https://example.com",
        "regex",
        "https://example.com",
        "none",
    ),
    ("https://example.com", "", "https://example.com", "none"),
    ("https://example.com", "HOST", "https://example.com", "none"),
    // --- domain: the registrable domain
    (
        "https://login.example.co.uk",
        "domain",
        "https://www.example.co.uk",
        "domain",
    ),
    (
        "https://example.co.uk",
        "domain",
        "https://a.b.example.co.uk",
        "domain",
    ),
    (
        "https://example.com",
        "domain",
        "https://login.example.com",
        "domain",
    ),
    (
        "https://example.com",
        "domain",
        "https://example.com",
        "host",
    ),
    (
        "https://example.com.",
        "domain",
        "https://login.example.com",
        "domain",
    ),
    (
        "https://login.example.co.uk",
        "host",
        "https://www.example.co.uk",
        "none",
    ),
    (
        "https://example.co.uk",
        "domain",
        "https://other.co.uk",
        "none",
    ),
    (
        "https://example.com",
        "domain",
        "https://example.co.uk",
        "none",
    ),
    (
        "https://example.com",
        "domain",
        "https://www.example.com:8443",
        "none",
    ),
    (
        "https://a.example.com",
        "domain",
        "https://example.com.evil.net",
        "none",
    ),
    (
        "https://b\u{fc}cher.de",
        "domain",
        "https://shop.xn--bcher-kva.de",
        "domain",
    ),
    // --- domain: private suffixes of the list
    (
        "https://a.github.io",
        "domain",
        "https://b.github.io",
        "none",
    ),
    (
        "https://a.github.io",
        "domain",
        "https://x.a.github.io",
        "domain",
    ),
    (
        "https://x.y.vercel.app",
        "domain",
        "https://z.y.vercel.app",
        "domain",
    ),
    (
        "https://x.vercel.app",
        "domain",
        "https://y.vercel.app",
        "none",
    ),
    ("https://github.io", "domain", "https://github.io", "host"),
    ("https://github.io", "domain", "https://a.github.io", "none"),
    // --- domain: wildcard and exception rules of the list
    ("https://a.foo.ck", "domain", "https://b.foo.ck", "none"),
    ("https://www.ck", "domain", "https://x.www.ck", "domain"),
    // --- domain: no registrable domain, so it acts as host
    ("https://fritz.box", "domain", "https://fritz.box", "host"),
    (
        "https://a.fritz.box",
        "domain",
        "https://b.fritz.box",
        "none",
    ),
    ("https://fritz.box", "domain", "https://x.fritz.box", "none"),
    ("https://router.lan", "domain", "https://router.lan", "host"),
    (
        "https://a.router.lan",
        "domain",
        "https://b.router.lan",
        "none",
    ),
    (
        "https://nas.home.arpa",
        "domain",
        "https://nas.home.arpa",
        "host",
    ),
    (
        "https://nas.home.arpa",
        "domain",
        "https://x.nas.home.arpa",
        "none",
    ),
    (
        "https://intranet",
        "domain",
        "https://intranet/login",
        "host",
    ),
    ("https://intranet", "domain", "https://other", "none"),
    (
        "https://a.example.zzzunknown",
        "domain",
        "https://b.example.zzzunknown",
        "none",
    ),
    ("https://a.example", "domain", "https://b.example", "none"),
    // --- exact
    (
        "https://example.com/login",
        "exact",
        "https://example.com/login",
        "exact",
    ),
    (
        "https://example.com/login",
        "exact",
        "https://example.com/login#top",
        "exact",
    ),
    (
        "https://example.com/login#a",
        "exact",
        "https://example.com/login#b",
        "exact",
    ),
    (
        "https://example.com",
        "exact",
        "https://example.com/",
        "exact",
    ),
    (
        "https://example.com/a?x=1",
        "exact",
        "https://example.com/a?x=1#f",
        "exact",
    ),
    (
        "https://example.com./a",
        "exact",
        "https://EXAMPLE.com/a",
        "exact",
    ),
    (
        "https://example.com/a/b",
        "exact",
        "https://example.com\\a\\b",
        "exact",
    ),
    (
        "https://example.com/a/./b/../c",
        "exact",
        "https://example.com/a/c",
        "exact",
    ),
    (
        "https://example.com/a b",
        "exact",
        "https://example.com/a%20b",
        "exact",
    ),
    (
        "https://example.com/login",
        "exact",
        "https://example.com/login/",
        "none",
    ),
    (
        "https://example.com/login",
        "exact",
        "https://example.com/Login",
        "none",
    ),
    (
        "https://example.com/login",
        "exact",
        "https://example.com/login?x=1",
        "none",
    ),
    (
        "https://example.com/a?x=1",
        "exact",
        "https://example.com/a?x=2",
        "none",
    ),
    (
        "https://example.com/login",
        "exact",
        "https://example.com/other",
        "none",
    ),
    (
        "https://example.com/login",
        "exact",
        "https://example.com:8443/login",
        "none",
    ),
    (
        "https://example.com/login",
        "exact",
        "https://www.example.com/login",
        "none",
    ),
    // --- IP hosts match only the identical address
    (
        "http://192.168.1.1",
        "host",
        "http://192.168.1.1/admin",
        "host",
    ),
    ("http://192.168.1.1", "host", "http://192.168.1.2", "none"),
    ("http://192.168.1.1", "host", "http://192.168.1.10", "none"),
    ("http://192.168.1.1", "host", "http://192.168.1", "none"),
    ("http://192.168.1.1", "host", "https://192.168.1.1", "none"),
    (
        "http://192.168.1.1",
        "host",
        "http://192.168.1.1:8080",
        "none",
    ),
    ("http://192.168.1.1", "host", "http://3232235777", "host"),
    ("http://192.168.1.1", "host", "http://0xc0a80101", "host"),
    (
        "http://192.168.1.1",
        "host",
        "http://0300.0250.01.01",
        "host",
    ),
    ("http://192.168.1.1", "host", "http://192.168.257", "host"),
    ("http://3232235777", "host", "http://192.168.1.1", "host"),
    (
        "http://192.168.1.1",
        "host",
        "http://192.168.1.1.example.com",
        "none",
    ),
    ("http://192.168.1.1", "domain", "http://192.168.1.1", "host"),
    ("http://10.0.0.1", "domain", "http://10.0.0.2", "none"),
    (
        "http://192.168.1.1/a",
        "exact",
        "http://3232235777/a#f",
        "exact",
    ),
    ("http://[::1]:3000", "host", "http://[::1]:3000/x", "host"),
    ("http://[::1]", "host", "http://[0:0:0:0:0:0:0:1]", "host"),
    ("http://[::1]", "host", "http://[::2]", "none"),
];

/// `(page address, Some((origin, scheme, host, port)))`, or `None` when it has
/// no origin.
type OriginRow = (
    &'static str,
    Option<(&'static str, &'static str, &'static str, u16)>,
);

const ORIGINS: &[OriginRow] = &[
    (
        "https://example.com",
        Some(("https://example.com", "https", "example.com", 443)),
    ),
    (
        "https://Example.COM/login?x=1#top",
        Some(("https://example.com", "https", "example.com", 443)),
    ),
    (
        "http://example.com",
        Some(("http://example.com", "http", "example.com", 80)),
    ),
    (
        "http://example.com:8080/x",
        Some(("http://example.com:8080", "http", "example.com", 8080)),
    ),
    (
        "https://example.com:443/",
        Some(("https://example.com", "https", "example.com", 443)),
    ),
    (
        "https://example.com:8443",
        Some(("https://example.com:8443", "https", "example.com", 8443)),
    ),
    (
        "https://a.example:80",
        Some(("https://a.example:80", "https", "a.example", 80)),
    ),
    (
        "http://a.example:443",
        Some(("http://a.example:443", "http", "a.example", 443)),
    ),
    (
        "https://sub.example.co.uk:8443/a",
        Some((
            "https://sub.example.co.uk:8443",
            "https",
            "sub.example.co.uk",
            8443,
        )),
    ),
    (
        "http://localhost:3000/x",
        Some(("http://localhost:3000", "http", "localhost", 3000)),
    ),
    (
        "http://192.168.1.1:8080/admin",
        Some(("http://192.168.1.1:8080", "http", "192.168.1.1", 8080)),
    ),
    (
        "http://3232235777/",
        Some(("http://192.168.1.1", "http", "192.168.1.1", 80)),
    ),
    (
        "http://0x7f.1/",
        Some(("http://127.0.0.1", "http", "127.0.0.1", 80)),
    ),
    (
        "https://[2001:DB8::1]:8443/x",
        Some(("https://[2001:db8::1]:8443", "https", "[2001:db8::1]", 8443)),
    ),
    ("http://[::1]", Some(("http://[::1]", "http", "[::1]", 80))),
    (
        "https://EXAMPLE.com./",
        Some(("https://example.com", "https", "example.com", 443)),
    ),
    (
        "https://B\u{fc}cher.example/",
        Some((
            "https://xn--bcher-kva.example",
            "https",
            "xn--bcher-kva.example",
            443,
        )),
    ),
    (
        "https://\u{43f}\u{440}\u{438}\u{43c}\u{435}\u{440}.\u{440}\u{444}/",
        Some((
            "https://xn--e1afmkfd.xn--p1ai",
            "https",
            "xn--e1afmkfd.xn--p1ai",
            443,
        )),
    ),
    (
        "https://ex\u{0430}mple.com",
        Some((
            "https://xn--exmple-4nf.com",
            "https",
            "xn--exmple-4nf.com",
            443,
        )),
    ),
    (
        "https://\u{ff45}\u{ff58}\u{ff41}\u{ff4d}\u{ff50}\u{ff4c}\u{ff45}.com",
        Some(("https://example.com", "https", "example.com", 443)),
    ),
    (
        "https://exa%6Dple.com",
        Some(("https://example.com", "https", "example.com", 443)),
    ),
    (
        "https://exam\tple.com",
        Some(("https://example.com", "https", "example.com", 443)),
    ),
    (
        "https://example.com\\login",
        Some(("https://example.com", "https", "example.com", 443)),
    ),
    (
        "  https://example.com/x  ",
        Some(("https://example.com", "https", "example.com", 443)),
    ),
    // --- no origin
    ("https://user@example.com", None),
    ("https://user:pw@example.com", None),
    ("ftp://example.com", None),
    ("ws://example.com", None),
    ("about:blank", None),
    ("data:text/html,<h1>x</h1>", None),
    ("javascript:alert(1)", None),
    ("file:///etc/passwd", None),
    (
        "blob:https://example.com/2f6c1f0e-6a52-4f55-9d6e-0c1b3b3f9a10",
        None,
    ),
    ("example.com", None),
    ("//example.com", None),
    ("", None),
    ("https://", None),
    ("https://example.com:0", None),
    ("https://example.com:65536", None),
    ("https://a..b", None),
    ("https://exa mple.com", None),
    ("https://[::1", None),
];

/// `(a, b, same site)`.
type SiteRow = (&'static str, &'static str, bool);

const SITES: &[SiteRow] = &[
    ("https://a.example.com", "https://b.example.com", true),
    ("https://example.com", "https://www.example.com/x?y#z", true),
    ("https://a.example.com", "https://a.example.com", true),
    ("https://a.example.com:8443", "https://b.example.com", true),
    ("https://a.example.co.uk", "https://b.example.co.uk", true),
    ("https://a.example.co.uk", "https://b.other.co.uk", false),
    ("http://a.example.com", "https://a.example.com", false),
    ("http://a.example.com", "https://b.example.com", false),
    ("http://a.example.com", "http://b.example.com", true),
    ("https://a.github.io", "https://b.github.io", false),
    ("https://a.github.io", "https://x.a.github.io", true),
    ("https://github.io", "https://github.io", true),
    ("https://github.io", "https://a.github.io", false),
    ("https://example.com", "https://example.org", false),
    ("https://example.com", "https://example.com.evil.net", false),
    ("https://EXAMPLE.com.", "https://www.example.com", true),
    ("https://ex\u{0430}mple.com", "https://example.com", false),
    (
        "https://b\u{fc}cher.de",
        "https://shop.xn--bcher-kva.de",
        true,
    ),
    ("http://192.168.1.1", "http://192.168.1.1/x", true),
    ("http://192.168.1.1:80", "http://3232235777:8080", true),
    ("http://192.168.1.1", "http://192.168.1.2", false),
    ("https://192.168.1.1", "http://192.168.1.1", false),
    ("http://[::1]", "http://[0::1]:81", true),
    ("http://[::1]", "http://[::2]", false),
    ("https://fritz.box", "https://fritz.box", true),
    ("https://a.fritz.box", "https://b.fritz.box", false),
    ("https://intranet", "https://intranet/x", true),
    ("https://intranet", "https://other", false),
    ("https://a.router.lan", "https://b.router.lan", false),
    ("https://nas.home.arpa", "https://x.nas.home.arpa", false),
    ("http://localhost:3000", "http://localhost:4000", true),
    ("https://example.com", "data:text/html,x", false),
    ("about:blank", "about:blank", false),
    ("", "", false),
    ("https://u@example.com", "https://example.com", false),
];

/// `(page address, Some((A-label, Unicode form)))`, or `None` when it has no
/// host to show.
type DisplayRow = (&'static str, Option<(&'static str, &'static str)>);

const DISPLAYS: &[DisplayRow] = &[
    (
        "https://example.com/x",
        Some(("example.com", "example.com")),
    ),
    (
        "https://B\u{fc}cher.example",
        Some(("xn--bcher-kva.example", "b\u{fc}cher.example")),
    ),
    (
        "https://xn--bcher-kva.example/",
        Some(("xn--bcher-kva.example", "b\u{fc}cher.example")),
    ),
    (
        "https://\u{43f}\u{440}\u{438}\u{43c}\u{435}\u{440}.\u{440}\u{444}",
        Some((
            "xn--e1afmkfd.xn--p1ai",
            "\u{43f}\u{440}\u{438}\u{43c}\u{435}\u{440}.\u{440}\u{444}",
        )),
    ),
    (
        "https://ex\u{0430}mple.com",
        Some(("xn--exmple-4nf.com", "xn--exmple-4nf.com")),
    ),
    (
        "https://exαmple.com",
        Some(("xn--exmple-qxe.com", "xn--exmple-qxe.com")),
    ),
    (
        "https://gօogle.com",
        Some(("xn--gogle-lkg.com", "xn--gogle-lkg.com")),
    ),
    (
        "https://абвa.com",
        Some(("xn--a-7sbde.com", "xn--a-7sbde.com")),
    ),
    (
        "https://日本abc.jp",
        Some(("xn--abc-s08fl0d.jp", "xn--abc-s08fl0d.jp")),
    ),
    (
        "https://shop.exаmple.com",
        Some(("shop.xn--exmple-4nf.com", "shop.xn--exmple-4nf.com")),
    ),
    (
        "https://пример.exаmple.рф",
        Some((
            "xn--e1afmkfd.xn--exmple-4nf.xn--p1ai",
            "пример.xn--exmple-4nf.рф",
        )),
    ),
    (
        "https://пример-1.рф",
        Some(("xn---1-mlcluqhd.xn--p1ai", "пример-1.рф")),
    ),
    ("https://αβγ.gr", Some(("xn--mxacd.gr", "αβγ.gr"))),
    ("https://café.com", Some(("xn--caf-dma.com", "café.com"))),
    (
        "https://日本語ひらがな.jp",
        Some(("xn--v8j0cwa6g1563acvb2w6i.jp", "日本語ひらがな.jp")),
    ),
    (
        "https://한漢字.kr",
        Some(("xn--p8s937bex8e.kr", "한漢字.kr")),
    ),
    // All one script: still shown in Unicode, as a browser does.
    (
        "https://аррӏе.com",
        Some(("xn--80ak6aa92e.com", "аррӏе.com")),
    ),
    (
        "https://\u{65e5}\u{672c}\u{8a9e}.jp",
        Some(("xn--wgv71a119e.jp", "\u{65e5}\u{672c}\u{8a9e}.jp")),
    ),
    (
        "https://EXAMPLE.com./",
        Some(("example.com", "example.com")),
    ),
    (
        "https://\u{ff45}\u{ff58}\u{ff41}\u{ff4d}\u{ff50}\u{ff4c}\u{ff45}.com",
        Some(("example.com", "example.com")),
    ),
    ("http://3232235777/", Some(("192.168.1.1", "192.168.1.1"))),
    (
        "http://192.168.1.1:8080/",
        Some(("192.168.1.1", "192.168.1.1")),
    ),
    (
        "http://[2001:DB8::1]:8080/",
        Some(("[2001:db8::1]", "[2001:db8::1]")),
    ),
    ("http://localhost:3000", Some(("localhost", "localhost"))),
    ("ftp://example.com", None),
    ("about:blank", None),
    ("data:text/html,x", None),
    ("https://user@example.com", None),
    ("example.com", None),
    ("", None),
    ("https://a..b", None),
];

fn case(id: &str, title: &str, op: &str, input: Value, expect: Result<Value, &str>) -> Case {
    let (status, expect, expect_error) = match expect {
        Ok(v) => (Status::Valid, Some(v), None),
        Err(code) => (Status::Invalid, None, Some(code.to_owned())),
    };
    Case {
        id: id.into(),
        title: title.into(),
        op: op.into(),
        status,
        tags: vec![Tag::NativeOnly],
        synthetic: true,
        skip_reason: Some(NATIVE_ONLY.into()),
        rng: vec![],
        input,
        intermediate: None,
        expect,
        expect_error,
    }
}

/// A text and its UTF-8 bytes in hex: the text is for reading, the bytes are
/// what the runner uses (tabs, line breaks and look-alike letters survive any
/// transport).
fn text_and_hex(key: &str, value: &str, into: &mut serde_json::Map<String, Value>) {
    into.insert(key.to_owned(), json!(value));
    into.insert(format!("{key}_utf8"), json!(hex_encode(value.as_bytes())));
}

fn slug(i: usize) -> String {
    format!("{:03}", i + 1)
}

pub(crate) fn url_match() -> Result<Vec<u8>, Error> {
    let mut cases: Vec<Case> = Vec::new();
    for (i, (saved, kind, page, result)) in MATCHES.iter().enumerate() {
        let mut input = serde_json::Map::new();
        text_and_hex("entry", saved, &mut input);
        input.insert("match".into(), json!(kind));
        text_and_hex("page", page, &mut input);
        cases.push(case(
            &format!("url-match/match/{}", slug(i)),
            &format!("{saved:?} ({kind}) against {page:?} is {result}"),
            "url.match",
            Value::Object(input),
            Ok(json!({ "result": result })),
        ));
    }
    for (i, (page, expect)) in ORIGINS.iter().enumerate() {
        let mut input = serde_json::Map::new();
        text_and_hex("page", page, &mut input);
        let (expect, title) = match expect {
            Some((origin, scheme, host, port)) => (
                Ok(json!({ "origin": origin, "scheme": scheme, "host": host, "port": port })),
                format!("origin of {page:?} is {origin}"),
            ),
            None => (Err("malformed_origin"), format!("{page:?} has no origin")),
        };
        cases.push(case(
            &format!("url-match/page_origin/{}", slug(i)),
            &title,
            "url.page_origin",
            Value::Object(input),
            expect,
        ));
    }
    for (i, (a, b, same)) in SITES.iter().enumerate() {
        let mut input = serde_json::Map::new();
        text_and_hex("a", a, &mut input);
        text_and_hex("b", b, &mut input);
        cases.push(case(
            &format!("url-match/same_site/{}", slug(i)),
            &format!(
                "{a:?} and {b:?} are {}on the same site",
                if *same { "" } else { "not " }
            ),
            "url.same_site",
            Value::Object(input),
            Ok(json!({ "same_site": same })),
        ));
    }
    for (i, (page, expect)) in DISPLAYS.iter().enumerate() {
        let mut input = serde_json::Map::new();
        text_and_hex("page", page, &mut input);
        let (expect, title) = match expect {
            Some((a_label, unicode)) => (
                Ok(json!({ "a_label": a_label, "unicode": unicode })),
                format!("host to show for {page:?} is {unicode}"),
            ),
            None => (
                Err("malformed_origin"),
                format!("{page:?} has no host to show"),
            ),
        };
        cases.push(case(
            &format!("url-match/display_host/{}", slug(i)),
            &title,
            "url.display_host",
            Value::Object(input),
            expect,
        ));
    }
    let file = VectorFile {
        format: ferret_core::testing::vector::FORMAT.into(),
        group: "url-match".into(),
        suite: 1,
        spec: "Fase 1 § 10.4, § 10.5".into(),
        generator: generator(),
        cases,
    };
    render(&file)
}
