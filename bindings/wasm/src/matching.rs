//! Page addresses: which open items belong to a page, the origin of a page,
//! whether two pages are on the same site, and the host to show.
//!
//! The rule is written once, in the core (`ferret_core::url_match` and its
//! companions). This file only exposes it. The browser extension has no Public
//! Suffix List and no matching rule of its own.
//!
//! `match_page` reads the saved addresses of the items and nothing else: no
//! field value, no note, no TOTP address and no passkey is touched, and the
//! reply holds only a handle and how the address matched. The three functions
//! without a vault need no state.
//!
//! Spec: Fase 1 § 10.4 and § 10.5.

use crate::convert::to_js;
use crate::error::{Fail, run};
use crate::vault::{MAX_OPEN, Vault};
use ferret_core::{
    UrlMatchResult, display_host as core_display_host, page_origin as core_page_origin,
    same_site as core_same_site, url_match,
};
use serde::Serialize;
use wasm_bindgen::prelude::*;

/// One matching item.
#[derive(Serialize)]
struct MatchDto {
    handle: u32,
    /// `"exact"`, `"host"` or `"domain"`.
    how: &'static str,
}

/// How strong a result is. An exact address is the strongest claim, an equal
/// host the next, and a shared registrable domain the weakest. `None` is not
/// a match.
const fn strength(r: UrlMatchResult) -> u8 {
    match r {
        UrlMatchResult::None => 0,
        UrlMatchResult::Domain => 1,
        UrlMatchResult::Host => 2,
        UrlMatchResult::Exact => 3,
    }
}

const fn how(r: UrlMatchResult) -> Option<&'static str> {
    match r {
        UrlMatchResult::None => None,
        UrlMatchResult::Domain => Some("domain"),
        UrlMatchResult::Host => Some("host"),
        UrlMatchResult::Exact => Some("exact"),
    }
}

#[derive(Serialize)]
struct DisplayHostDto {
    a_label: String,
    unicode: String,
}

#[wasm_bindgen]
impl Vault {
    /// The open items whose saved addresses match the page, with the best
    /// result per item: `[{ handle, how }]` in the order of `handles`, where
    /// `how` is `"exact"`, `"host"` or `"domain"`. An item with no match is
    /// left out. It reads the saved addresses only.
    ///
    /// A handle that is not open is `invalid_handle` and nothing is returned:
    /// a caller that has closed an item must not be told about it. More than
    /// the open limit of handles is `invalid_input`. An address of the page
    /// that is no web address (or is over 8 KiB) matches nothing; that is an
    /// empty list, not an error.
    pub fn match_page(&self, page_url: &str, handles: Vec<u32>) -> Result<JsValue, JsValue> {
        run(|| {
            let inner = self.inner()?;
            if handles.len() > MAX_OPEN {
                return Err(Fail::Input);
            }
            let mut found = Vec::new();
            for handle in handles {
                let item = inner.item(handle)?;
                let best = item
                    .body
                    .urls
                    .iter()
                    .map(|entry| url_match(entry, page_url))
                    .max_by_key(|r| strength(*r))
                    .unwrap_or(UrlMatchResult::None);
                if let Some(how) = how(best) {
                    found.push(MatchDto { handle, how });
                }
            }
            to_js(&found)
        })
    }
}

/// The origin of a page address: `scheme://host`, with `:port` only when the
/// port is not the default of the scheme. The host is the lower-case A-label,
/// or the IP address. Accepts `http` and IP hosts. An address that is no web
/// address, has user info or is over 8 KiB is `malformed_origin`.
#[wasm_bindgen]
pub fn page_origin(page_url: &str) -> Result<String, JsValue> {
    run(|| Ok(core_page_origin(page_url)?.as_str().to_owned()))
}

/// Whether two page addresses are on the same site: the same scheme and the
/// same registrable domain (the port does not matter). An address that is no
/// web address is on no site.
#[wasm_bindgen]
pub fn same_site(a: &str, b: &str) -> bool {
    core_same_site(a, b)
}

/// The host of a page address for display: `{ a_label, unicode }`. Show the
/// Unicode name and, when they differ, the A-label next to it. An address
/// that is no web address is `malformed_origin`.
#[wasm_bindgen]
pub fn display_host(page_url: &str) -> Result<JsValue, JsValue> {
    run(|| {
        let host = core_display_host(page_url)?;
        to_js(&DisplayHostDto {
            a_label: host.a_label,
            unicode: host.unicode,
        })
    })
}
