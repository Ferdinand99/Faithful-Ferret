//! The vector group for origins and RP IDs (`origin.json`).
//!
//! Every expected value is written out here by hand from the rules of
//! Fase 1 § 9.2 and from the IDNA examples that are known independently
//! (checked against Python's `idna` codec, which implements IDNA 2003 and
//! agrees with UTS 46 for these labels). Nothing is computed by the core.
//!
//! Ops (see `vectors/OPS.md`): `origin.canonical` and `origin.rp_id`.

use crate::groups::{generator, invalid_case, valid_case};
use crate::{Error, render};
use ferret_core::testing::hex_encode;
use ferret_core::testing::vector::{Case, VectorFile};
use serde_json::json;

/// `(raw, Some((origin, host)))` for an origin that is accepted, `None` for
/// one that is not.
type OriginRow = (&'static str, Option<(&'static str, &'static str)>);

const ORIGINS: &[OriginRow] = &[
    // --- accepted
    (
        "https://example.com",
        Some(("https://example.com", "example.com")),
    ),
    (
        "HTTPS://EXAMPLE.COM",
        Some(("https://example.com", "example.com")),
    ),
    (
        "https://EXAMPLE.com.",
        Some(("https://example.com", "example.com")),
    ),
    (
        "https://Bücher.example",
        Some(("https://xn--bcher-kva.example", "xn--bcher-kva.example")),
    ),
    (
        "https://xn--bcher-kva.example",
        Some(("https://xn--bcher-kva.example", "xn--bcher-kva.example")),
    ),
    (
        "https://münchen.de",
        Some(("https://xn--mnchen-3ya.de", "xn--mnchen-3ya.de")),
    ),
    (
        "https://日本語.jp",
        Some(("https://xn--wgv71a119e.jp", "xn--wgv71a119e.jp")),
    ),
    (
        "https://☃.net",
        Some(("https://xn--n3h.net", "xn--n3h.net")),
    ),
    (
        "https://пример.рф",
        Some(("https://xn--e1afmkfd.xn--p1ai", "xn--e1afmkfd.xn--p1ai")),
    ),
    (
        "https://你好.com",
        Some(("https://xn--6qq79v.com", "xn--6qq79v.com")),
    ),
    (
        "https://ｅｘａｍｐｌｅ.com",
        Some(("https://example.com", "example.com")),
    ),
    (
        "https://straße.de",
        Some(("https://xn--strae-oqa.de", "xn--strae-oqa.de")),
    ),
    (
        "https://example.com:443",
        Some(("https://example.com", "example.com")),
    ),
    (
        "https://example.com:8443",
        Some(("https://example.com:8443", "example.com")),
    ),
    ("https://a.b:8443", Some(("https://a.b:8443", "a.b"))),
    ("https://a.b:08443", Some(("https://a.b:8443", "a.b"))),
    (
        "https://EXAMPLE.COM:8443",
        Some(("https://example.com:8443", "example.com")),
    ),
    (
        "https://example.com:80",
        Some(("https://example.com:80", "example.com")),
    ),
    ("http://localhost", Some(("http://localhost", "localhost"))),
    (
        "http://localhost:3000",
        Some(("http://localhost:3000", "localhost")),
    ),
    (
        "http://localhost:80",
        Some(("http://localhost", "localhost")),
    ),
    ("http://LOCALHOST.", Some(("http://localhost", "localhost"))),
    (
        "https://localhost",
        Some(("https://localhost", "localhost")),
    ),
    (
        "https://a.github.io",
        Some(("https://a.github.io", "a.github.io")),
    ),
    (
        "https://github.io",
        Some(("https://github.io", "github.io")),
    ),
    (
        "https://sub.example.co.uk",
        Some(("https://sub.example.co.uk", "sub.example.co.uk")),
    ),
    (
        "https://a-b.example",
        Some(("https://a-b.example", "a-b.example")),
    ),
    (
        "https://123.example",
        Some(("https://123.example", "123.example")),
    ),
    (
        "https://xn--n3h.net",
        Some(("https://xn--n3h.net", "xn--n3h.net")),
    ),
    (
        "https://a.b.c.d.e.f.example",
        Some(("https://a.b.c.d.e.f.example", "a.b.c.d.e.f.example")),
    ),
    // --- not an origin of a web page
    ("null", None),
    ("about:blank", None),
    ("about:srcdoc", None),
    ("srcdoc", None),
    ("data:text/html,<h1>x</h1>", None),
    ("file:///etc/passwd", None),
    ("file://host/share", None),
    (
        "blob:https://example.com/2f6c1f0e-6a52-4f55-9d6e-0c1b3b3f9a10",
        None,
    ),
    ("javascript:alert(1)", None),
    ("chrome-extension://abcdefghijklmnopabcdefghijklmnop", None),
    ("ftp://example.com", None),
    ("ws://example.com", None),
    ("", None),
    ("example.com", None),
    ("//example.com", None),
    ("https://", None),
    ("https://:443", None),
    // --- plain http is only for localhost
    ("http://example.com", None),
    ("http://localhost.example", None),
    ("http://sub.localhost", None),
    // --- IP hosts, in every notation
    ("http://127.0.0.1", None),
    ("https://127.0.0.1", None),
    ("https://1.2.3.4:8443", None),
    ("https://[::1]", None),
    ("https://[::1]:8443", None),
    ("http://[::1]", None),
    ("https://0x7f.0.0.1", None),
    ("https://2130706433", None),
    ("https://127.1", None),
    ("https://１２７.０.０.１", None),
    // --- ports
    ("https://example.com:", None),
    ("https://example.com:0", None),
    ("https://example.com:65536", None),
    ("https://example.com:abc", None),
    // --- not a bare origin
    ("https://user@example.com", None),
    ("https://user:pw@example.com", None),
    ("https://example.com/", None),
    ("https://example.com/path", None),
    ("https://example.com?x=1", None),
    ("https://example.com#frag", None),
    ("https://exa mple.com", None),
    (" https://example.com", None),
    ("https://example.com\n", None),
    ("https://example.com\\", None),
    ("https://exa%6Dple.com", None),
    ("https://*.example.com", None),
    // --- not a valid host
    ("https://-example.com", None),
    ("https://example-.com", None),
    ("https://exa_mple.com", None),
    ("https://a..b", None),
    ("https://.example.com", None),
    ("https://example.com..", None),
];

/// `(origin, rp_id, Some(canonical rp id))` or `None` when it is refused.
type RpRow = (&'static str, &'static str, Option<&'static str>);

const RP_IDS: &[RpRow] = &[
    // The host itself, a parent domain, and what is not one.
    (
        "https://login.example.com",
        "login.example.com",
        Some("login.example.com"),
    ),
    (
        "https://login.example.com",
        "example.com",
        Some("example.com"),
    ),
    (
        "https://login.example.com",
        "LOGIN.Example.COM",
        Some("login.example.com"),
    ),
    (
        "https://login.example.com",
        "login.example.com.",
        Some("login.example.com"),
    ),
    ("https://login.example.com", "com", None),
    ("https://login.example.com", "ample.com", None),
    ("https://login.example.com", "ogin.example.com", None),
    ("https://login.example.com", "other.com", None),
    ("https://login.example.com", "sub.login.example.com", None),
    ("https://login.example.com", "example.com:443", None),
    ("https://login.example.com", "https://example.com", None),
    ("https://login.example.com", "", None),
    ("https://login.example.com", ".example.com", None),
    ("https://login.example.com", "example..com", None),
    ("https://login.example.com", "127.0.0.1", None),
    ("https://login.example.com", "[::1]", None),
    // The port belongs to the origin, not to the RP ID.
    (
        "https://example.com:8443",
        "example.com",
        Some("example.com"),
    ),
    ("https://example.com:8443", "example.com:8443", None),
    // Private domains of the list.
    ("https://a.github.io", "a.github.io", Some("a.github.io")),
    ("https://a.github.io", "github.io", None),
    ("https://a.github.io", "io", None),
    ("https://github.io", "github.io", None),
    ("https://x.y.vercel.app", "vercel.app", None),
    (
        "https://x.y.vercel.app",
        "y.vercel.app",
        Some("y.vercel.app"),
    ),
    (
        "https://x.y.vercel.app",
        "x.y.vercel.app",
        Some("x.y.vercel.app"),
    ),
    // ICANN section, wildcard and exception rules.
    ("https://www.example.co.uk", "co.uk", None),
    ("https://www.example.co.uk", "uk", None),
    (
        "https://www.example.co.uk",
        "example.co.uk",
        Some("example.co.uk"),
    ),
    ("https://a.foo.ck", "foo.ck", None),
    ("https://a.foo.ck", "a.foo.ck", Some("a.foo.ck")),
    ("https://www.ck", "www.ck", Some("www.ck")),
    ("https://www.ck", "ck", None),
    // A top-level domain that is not on the list is a public suffix.
    ("https://intranet", "intranet", None),
    ("https://app.intranet", "intranet", None),
    ("https://app.intranet", "app.intranet", Some("app.intranet")),
    // IDN.
    (
        "https://bücher.example",
        "bücher.example",
        Some("xn--bcher-kva.example"),
    ),
    (
        "https://bücher.example",
        "xn--bcher-kva.example",
        Some("xn--bcher-kva.example"),
    ),
    ("https://bücher.example", "example", None),
    // localhost.
    ("http://localhost", "localhost", Some("localhost")),
    ("http://localhost:3000", "localhost", Some("localhost")),
    ("https://foo.localhost", "localhost", None),
    (
        "https://foo.localhost",
        "foo.localhost",
        Some("foo.localhost"),
    ),
];

fn raw_input(raw: &str) -> serde_json::Value {
    json!({ "raw": raw, "raw_utf8": hex_encode(raw.as_bytes()) })
}

fn slug(i: usize) -> String {
    format!("{:03}", i + 1)
}

pub(crate) fn origin() -> Result<Vec<u8>, Error> {
    let mut cases: Vec<Case> = Vec::new();
    for (i, (raw, expect)) in ORIGINS.iter().enumerate() {
        match expect {
            Some((origin, host)) => cases.push(valid_case(
                &format!("origin/canonical/valid/{}", slug(i)),
                &format!("canonical origin of {raw:?}"),
                "origin.canonical",
                vec![],
                raw_input(raw),
                json!({ "origin": origin, "host": host }),
            )),
            None => cases.push(invalid_case(
                &format!("origin/canonical/invalid/{}", slug(i)),
                &format!("{raw:?} is not an origin a passkey may be used from"),
                "origin.canonical",
                vec![],
                raw_input(raw),
                "malformed_origin",
            )),
        }
    }
    for (i, (origin, rp_id, expect)) in RP_IDS.iter().enumerate() {
        let input = json!({
            "origin": origin,
            "origin_utf8": hex_encode(origin.as_bytes()),
            "rp_id": rp_id,
            "rp_id_utf8": hex_encode(rp_id.as_bytes()),
        });
        match expect {
            Some(id) => cases.push(valid_case(
                &format!("origin/rp_id/valid/{}", slug(i)),
                &format!("RP ID {rp_id:?} for {origin:?}"),
                "origin.rp_id",
                vec![],
                input,
                json!({ "rp_id": id }),
            )),
            None => cases.push(invalid_case(
                &format!("origin/rp_id/invalid/{}", slug(i)),
                &format!("RP ID {rp_id:?} is refused for {origin:?}"),
                "origin.rp_id",
                vec![],
                input,
                "malformed_rp_id",
            )),
        }
    }
    let file = VectorFile {
        format: ferret_core::testing::vector::FORMAT.into(),
        group: "origin".into(),
        suite: 1,
        spec: "Fase 1 § 9.2".into(),
        generator: generator(),
        cases,
    };
    render(&file)
}
