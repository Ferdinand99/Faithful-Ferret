// The adversarial test sites: phishing look-alikes, hostile frames and
// clickjacking tricks that the fill engine and the frame rules are tested
// against. Each site has an id, an origin (origins.mjs), a path, a summary and
// an `expect` that a Firefox run reads. The fill engine's unit tests cover the
// same cases without a browser.
//
// The vault entries the sites are made for:
//
//   host entry    `https://login.example.net/`, matched by host (the default)
//   domain entry  the same address with the match kind `domain`
//   http entry    `http://login.example.net/` (and, on loopback, an entry for
//                 the loopback address itself)
//
// `expect.outcome` is for the host entry. It is one of:
//
//   fill               the entry matches this page and the form is filled
//   fill_in_frame      the entry matches the frame (same site as the top page);
//                      permission for the frame's origin is asked in a tab
//   no_offer           nothing is offered, and nothing is filled
//   no_offer_in_frame  nothing is offered in the frame
//   fields             the fields marked data-fixture-expect decide: "fill" is
//                      filled, "reject" never is
//   origin_changed     the frame's origin changes between the choice and the fill:
//                      the fill fails with origin_changed and nothing is filled
//   turns_hostile      the page changes after the choice (turnHostile(), also on
//                      window blur): the fill is refused
//   shows_host         the popup shows the host name, never the page's title
//
// `expect.domain_entry` and `expect.http_entry` say what the other entries do
// there (the same vocabulary, and `offer_with_warning` for an http entry on its
// own http page). `expect.search` is "copy_only" where a search for the real
// entry must give a Copy button and no Fill button. `expect.display` is what
// the core's display_host returns for the page, `expect.typed` what a person
// types. Nothing here is shipped: test/ never is.
import {
  CONFUSABLE_A_LABEL_HOST, CONFUSABLE_UNICODE_HOST, DIGIT_A_LABEL_HOST, DIGIT_UNICODE_HOST,
  HOMOGRAPH_A_LABEL_HOST, HOMOGRAPH_UNICODE_HOST, ORIGINS,
} from "./origins.mjs";
import { esc, loginForm, page, svgIcon } from "./html.mjs";

/**
 * @typedef {{ url: (origin: string, path?: string) => string }} Context
 * @typedef {{ outcome: string, [key: string]: unknown }} Expectation
 * @typedef {{
 *   id: string, origin: string, path: string, summary: string,
 *   expect: Expectation, render: (context: Context) => string,
 * }} Site
 */

/** @type {Site[]} */
export const SITES = [];

/** @param {Site} site */
function add(site) {
  SITES.push(site);
}

/** Embeds a string in an inline script as a JSON string literal that cannot end the script. @param {string} text */
const literal = (text) => JSON.stringify(text).replaceAll("<", "\\u003c");

/** A plain sign-in page. @param {string} id @param {string} [title] */
const plain = (id, title = "Example sign-in") => () => page({ id, title, body: `<h1>${esc(title)}</h1>\n${loginForm()}` });

// ---------------------------------------------------------------- origins

add({
  id: "login", origin: "login", path: "/",
  summary: "The entry's own page: a host match (and a domain match), and the form is filled.",
  expect: { outcome: "fill", match: "host", domain_entry: "fill", http_entry: "no_offer" },
  render: plain("login"),
});

add({
  id: "sibling", origin: "www", path: "/t/sibling.html",
  summary: "A sign-in page on another host of the same site: a host entry is not offered, a domain entry is.",
  expect: { outcome: "no_offer", domain_entry: "fill", http_entry: "no_offer" },
  render: plain("sibling"),
});

add({
  id: "framed-same-site", origin: "www", path: "/",
  summary: "A page on the same site (www.example.net) with the entry's page in a frame: filled in the frame, the permission asked in a tab.",
  expect: { outcome: "fill_in_frame", domain_entry: "fill_in_frame", frame: "login-frame", frameOrigin: "login" },
  render: ({ url }) => page({
    id: "framed-same-site",
    body: `<h1>Welcome</h1>\n<iframe id="login-frame" title="Sign in" src="${esc(url("login", "/"))}"></iframe>`,
  }),
});

add({
  id: "framed-cross-site", origin: "evil", path: "/t/embed.html",
  summary: "A foreign page that frames the entry's own page: the frame's origin matches the entry but it is not on the top page's site, so nothing is offered in the frame.",
  expect: { outcome: "no_offer_in_frame", domain_entry: "no_offer_in_frame", frame: "login-frame", frameOrigin: "login" },
  render: ({ url }) => page({
    id: "framed-cross-site",
    title: "Free prizes",
    body: `<h1>Free prizes</h1>\n<iframe id="login-frame" title="Sign in" src="${esc(url("login", "/"))}"></iframe>`,
  }),
});

add({
  id: "framed-foreign", origin: "shop", path: "/",
  summary: "A page with a frame from a foreign site whose origin matches no entry: nothing is offered in the frame.",
  expect: { outcome: "no_offer_in_frame", domain_entry: "no_offer_in_frame", frame: "foreign-frame", frameOrigin: "evil" },
  render: ({ url }) => page({
    id: "framed-foreign",
    title: "Shop",
    body: `<h1>Shop</h1>\n<iframe id="foreign-frame" title="Pay" src="${esc(url("evil", "/login"))}"></iframe>`,
  }),
});

add({
  id: "foreign-login", origin: "evil", path: "/login",
  summary: "The foreign sign-in page that the shop frames.",
  expect: { outcome: "no_offer", domain_entry: "no_offer" },
  render: plain("foreign-login", "Secure payment sign-in"),
});

add({
  id: "other-port", origin: "loginAlt", path: "/",
  summary: "The entry's host on another port: no offer.",
  expect: { outcome: "no_offer", domain_entry: "no_offer" },
  render: plain("other-port"),
});

const NO_OFFER = { outcome: "no_offer", domain_entry: "no_offer", search: "copy_only" };

add({
  id: "lookalike-dash", origin: "dash", path: "/",
  summary: "login-example.net: a dash where the entry has a dot (a domain entry does not match either: another registrable domain).",
  expect: { ...NO_OFFER },
  render: plain("lookalike-dash"),
});

add({
  id: "lookalike-suffix", origin: "suffix", path: "/",
  summary: "login.example.net.evil.test: the real host as the left part of a foreign one.",
  expect: { ...NO_OFFER },
  render: plain("lookalike-suffix"),
});

add({
  id: "lookalike-tld", origin: "tld", path: "/",
  summary: "login.example.org: the real name under another top-level domain, so another registrable domain.",
  expect: { ...NO_OFFER },
  render: plain("lookalike-tld"),
});

add({
  id: "lookalike-homograph", origin: "homograph", path: "/",
  summary: "A valid mixed-script homograph in the registrable label: login.example.net with a Cyrillic a in example. The browser turns it into an xn-- host. The core keeps the A-label for a label that mixes scripts, so the popup shows the A-label only. Another registrable domain, so a domain entry does not match.",
  expect: {
    ...NO_OFFER,
    typed: HOMOGRAPH_UNICODE_HOST,
    display: { a_label: HOMOGRAPH_A_LABEL_HOST, unicode: HOMOGRAPH_A_LABEL_HOST },
  },
  render: () => page({
    id: "lookalike-homograph",
    body: `<h1>Example sign-in</h1>\n<p id="host-note">${esc(HOMOGRAPH_UNICODE_HOST)}</p>\n${loginForm()}`,
  }),
});

add({
  id: "lookalike-confusable", origin: "confusable", path: "/",
  summary: "login under a registrable label written entirely in Cyrillic that looks like apple: one script, so the core shows the Unicode form, and the popup must show the A-label beside it. Its own registrable domain, so no entry matches.",
  expect: {
    ...NO_OFFER,
    typed: CONFUSABLE_UNICODE_HOST,
    display: { a_label: CONFUSABLE_A_LABEL_HOST, unicode: CONFUSABLE_UNICODE_HOST },
  },
  render: () => page({
    id: "lookalike-confusable",
    body: `<h1>Example sign-in</h1>\n<p id="host-note">${esc(CONFUSABLE_UNICODE_HOST)}</p>\n${loginForm()}`,
  }),
});

add({
  id: "lookalike-digit", origin: "digit", path: "/",
  summary: "login.example.net with a Devanagari digit zero for the o in example: a digit of another script counts as a letter of its script, so the label mixes scripts and the core keeps the A-label, so the popup shows the A-label only. Another registrable domain, so a domain entry does not match.",
  expect: {
    ...NO_OFFER,
    typed: DIGIT_UNICODE_HOST,
    display: { a_label: DIGIT_A_LABEL_HOST, unicode: DIGIT_A_LABEL_HOST },
  },
  render: () => page({
    id: "lookalike-digit",
    body: `<h1>Example sign-in</h1>\n<p id="host-note">${esc(DIGIT_UNICODE_HOST)}</p>\n${loginForm()}`,
  }),
});

add({
  id: "github-a", origin: "ghA", path: "/",
  summary: "a.github.io: a domain entry for a.github.io matches here.",
  expect: { outcome: "fill", entry: "domain a.github.io" },
  render: plain("github-a", "Sign in to a"),
});

add({
  id: "github-b", origin: "ghB", path: "/",
  summary: "b.github.io: github.io is a private suffix, so a domain entry for a.github.io is not offered here.",
  expect: { outcome: "no_offer", entry: "domain a.github.io" },
  render: plain("github-b", "Sign in to b"),
});

// ------------------------------------------- http, and insecure ancestors

add({
  id: "http-downgrade", origin: "loginHttp", path: "/",
  summary: "The entry's host over http: an https entry is never offered on http; an http entry for this exact address is offered, with the unencrypted-connection warning.",
  expect: { outcome: "no_offer", domain_entry: "no_offer", http_entry: "offer_with_warning" },
  render: plain("http-downgrade"),
});

add({
  id: "http-sibling", origin: "wwwHttp", path: "/",
  summary: "A sibling host over http: an http entry stays on its own host and port, and a domain match never applies to http.",
  expect: { outcome: "no_offer", domain_entry: "no_offer", http_entry: "no_offer" },
  render: plain("http-sibling"),
});

add({
  id: "http-framed-same-site", origin: "wwwHttp", path: "/t/framed.html",
  summary: "An http page that frames an http page of the same site: the schemeful site matches, but every ancestor must be https (except loopback), so nothing is offered in the frame, not even an http entry.",
  expect: { outcome: "no_offer_in_frame", domain_entry: "no_offer_in_frame", http_entry: "no_offer_in_frame", frame: "login-frame", frameOrigin: "loginHttp" },
  render: ({ url }) => page({
    id: "http-framed-same-site",
    body: `<h1>Welcome</h1>\n<iframe id="login-frame" title="Sign in" src="${esc(url("loginHttp", "/"))}"></iframe>`,
  }),
});

add({
  id: "http-top-https-frame", origin: "wwwHttp", path: "/t/https-frame.html",
  summary: "An http page that frames the entry's own https page: the frame's origin matches, but an ancestor is http, so nothing is offered in the frame. It is also refused by the schemeful same-site check (http and https are not the same site); http-framed-same-site is the case that isolates the ancestor rule.",
  expect: { outcome: "no_offer_in_frame", domain_entry: "no_offer_in_frame", http_entry: "no_offer_in_frame", frame: "login-frame", frameOrigin: "login" },
  render: ({ url }) => page({
    id: "http-top-https-frame",
    body: `<h1>Welcome</h1>\n<iframe id="login-frame" title="Sign in" src="${esc(url("login", "/"))}"></iframe>`,
  }),
});

add({
  id: "loopback", origin: "loopback", path: "/",
  summary: "The loopback address over http: a secure context. An http entry for exactly this address is offered without the warning; an https entry never matches an http page.",
  expect: { outcome: "no_offer", http_entry: "fill" },
  render: plain("loopback", "Local sign-in"),
});

add({
  id: "loopback-framed", origin: "loopback", path: "/t/framed.html",
  summary: "A loopback page that frames a loopback page: the one allowed insecure ancestor, so an http entry for this address is filled in the frame.",
  expect: { outcome: "no_offer_in_frame", http_entry: "fill_in_frame", frame: "login-frame", frameOrigin: "loopback" },
  render: ({ url }) => page({
    id: "loopback-framed",
    title: "Local",
    body: `<h1>Local</h1>\n<iframe id="login-frame" title="Sign in" src="${esc(url("loopback", "/"))}"></iframe>`,
  }),
});

// ------------------------------------------------------ frames, by kind

/** The sign-in form that goes into a frame whose fields are never filled. @param {string} prefix */
const frameForm = (prefix) => loginForm({ prefix, expect: "reject" });

add({
  id: "frames-opaque", origin: "login", path: "/t/frames-opaque.html",
  summary: "Frames with no origin the fill may use: about:blank, srcdoc, a sandbox with srcdoc and a sandbox with an https address (its origin is opaque although the address is https).",
  expect: {
    outcome: "no_offer_in_frame",
    domain_entry: "no_offer_in_frame",
    frames: ["frame-blank", "frame-srcdoc", "frame-sandbox-srcdoc", "frame-sandbox-https"],
  },
  render: ({ url }) => page({
    id: "frames-opaque",
    title: "Frames",
    body: `<h1>Frames</h1>
<iframe id="frame-blank" title="about:blank"></iframe>
<iframe id="frame-srcdoc" title="srcdoc" srcdoc="${esc(`<!doctype html><title>srcdoc</title>${frameForm("srcdoc")}`)}"></iframe>
<iframe id="frame-sandbox-srcdoc" title="sandbox srcdoc" sandbox="allow-scripts allow-forms" srcdoc="${esc(`<!doctype html><title>sandbox</title>${frameForm("sandbox-srcdoc")}`)}"></iframe>
<iframe id="frame-sandbox-https" title="sandbox https" sandbox="allow-scripts allow-forms" src="${esc(url("login", "/t/sandboxed-login.html"))}"></iframe>
<script>
document.getElementById("frame-blank").contentDocument.body.innerHTML = ${literal(frameForm("blank"))};
</script>`,
  }),
});

add({
  id: "sandboxed-login", origin: "login", path: "/t/sandboxed-login.html",
  summary: "A plain sign-in page on the entry's own origin. Top-level it is filled; frames-opaque loads it in a sandbox without allow-same-origin, where the same page is refused.",
  expect: { outcome: "fill", domain_entry: "fill", framedBy: "frames-opaque", framedOutcome: "no_offer_in_frame" },
  render: plain("sandboxed-login"),
});

add({
  id: "frames-special", origin: "login", path: "/t/frames-special.html",
  summary: "Frames by address kind: data: (opaque origin), blob: (the page's origin but a blob: address) and javascript: (the page's origin, no real address). None is filled.",
  expect: {
    outcome: "no_offer_in_frame",
    domain_entry: "no_offer_in_frame",
    frames: ["frame-data", "frame-blob", "frame-javascript"],
  },
  render: () => {
    const data = `<!doctype html><title>data</title>${frameForm("data")}`;
    const js = `<!doctype html><title>javascript</title>${frameForm("javascript")}`;
    return page({
      id: "frames-special",
      title: "Frames",
      body: `<h1>Frames</h1>
<iframe id="frame-data" title="data" src="${esc(`data:text/html;charset=utf-8,${encodeURIComponent(data)}`)}"></iframe>
<iframe id="frame-blob" title="blob"></iframe>
<iframe id="frame-javascript" title="javascript" src="${esc(`javascript:${JSON.stringify(js)}`)}"></iframe>
<script>
document.getElementById("frame-blob").src = URL.createObjectURL(new Blob([${literal(`<!doctype html><title>blob</title>${frameForm("blob")}`)}], { type: "text/html" }));
</script>`,
    });
  },
});

add({
  id: "nested-login", origin: "login", path: "/t/nested-login.html",
  summary: "The entry's own page with an about:blank frame inside it that holds a password field.",
  expect: { outcome: "fill", domain_entry: "fill", nested: "nested-blank", nestedOutcome: "no_offer_in_frame" },
  render: () => page({
    id: "nested-login",
    body: `<h1>Example sign-in</h1>
${loginForm()}
<iframe id="nested-blank" title="about:blank"></iframe>
<script>
document.getElementById("nested-blank").contentDocument.body.innerHTML = ${literal(frameForm("nested"))};
</script>`,
  }),
});

add({
  id: "framed-nested", origin: "www", path: "/t/nested.html",
  summary: "A same-site page that frames nested-login: the login frame is filled, the about:blank frame inside it is not.",
  expect: { outcome: "fill_in_frame", domain_entry: "fill_in_frame", frame: "login-frame", frameOrigin: "login", nested: "nested-blank", nestedOutcome: "no_offer_in_frame" },
  render: ({ url }) => page({
    id: "framed-nested",
    body: `<h1>Welcome</h1>\n<iframe id="login-frame" title="Sign in" src="${esc(url("login", "/t/nested-login.html"))}"></iframe>`,
  }),
});

// ----------------------------------------------------- clickjacking tricks

/**
 * A page with a hostile form (its password field must be rejected, for
 * `reason`) and a clear one after it (filled), the hostile one wrapped by `wrap`.
 * `exact`: the reason is the only reason the browser gives for that field.
 * @param {string} id
 * @param {{ summary: string, reason: string, exact?: boolean, wrap?: (form: string) => string, wrapPass?: (input: string) => string, formStyle?: string, css?: string, htmlStyle?: string, control?: boolean }} options
 */
function trick(id, { summary, reason, exact = false, wrap = (form) => form, wrapPass, formStyle, css = "", htmlStyle, control = true }) {
  add({
    id, origin: "login", path: `/t/${id}.html`, summary,
    expect: { outcome: "fields", reason, exact },
    render: () => page({
      id,
      css,
      htmlStyle,
      body: `<h1>Example sign-in</h1>
${wrap(loginForm({ prefix: "bad", expect: "reject", reason, wrapPass, formStyle }))}
${control ? loginForm({ prefix: "ok", expect: "fill" }) : ""}`,
    }),
  });
}

trick("overlay", {
  summary: "A transparent element above the password field: a click would land on it, not on the field.",
  reason: "covered",
  css: ".over { position: relative; width: 240px; } .over input { margin: 0; } .cover { position: absolute; inset: 0; z-index: 10; background: transparent; }",
  wrapPass: (input) => `<div class="over">${input}<div class="cover" id="cover"></div></div>`,
});

trick("opacity-html", {
  summary: "opacity: 0 on <html>: the whole page is invisible, so every field is rejected.",
  reason: "opacity",
  htmlStyle: "opacity: 0",
  control: false,
});

trick("offscreen", {
  summary: "Forms outside the viewport (far to the left, far above), with a visible control form.",
  reason: "offscreen",
  css: ".far-left { position: absolute; left: -10000px; top: 0; } .far-up { position: absolute; left: 0; top: -10000px; }",
  wrap: (form) => `<div id="far-left" class="far-left">${form}</div>
<div id="far-up" class="far-up">${loginForm({ prefix: "up", expect: "reject", reason: "offscreen" })}</div>`,
});

trick("below-fold", {
  summary: "A form 3000 px down the page (scrollable, but outside the viewport), with a visible control form.",
  reason: "offscreen",
  wrap: (form) => `<div id="far-down" style="position: absolute; top: 3000px; left: 16px">${form}</div>`,
});

add({
  id: "overlay-popover", origin: "login", path: "/t/overlay-popover.html",
  summary: "A transparent popover in the top layer above the password field (above any z-index).",
  expect: { outcome: "fields", reason: "covered", exact: false },
  render: () => page({
    id: "overlay-popover",
    body: `<h1>Example sign-in</h1>
${loginForm({ prefix: "bad", expect: "reject", reason: "covered" })}
${loginForm({ prefix: "ok", expect: "fill" })}
<div id="cover" popover="manual"></div>
<script>
var rect = document.getElementById("bad-pass").getBoundingClientRect();
var cover = document.getElementById("cover");
cover.style.cssText = "position: fixed; inset: auto; margin: 0; padding: 0; border: 0; background: transparent; overflow: visible; left: " + rect.left + "px; top: " + rect.top + "px; width: " + rect.width + "px; height: " + rect.height + "px";
cover.showPopover();
</script>`,
  }),
});

add({
  id: "overlay-dialog", origin: "login", path: "/t/overlay-dialog.html",
  summary: "A transparent modal dialog over the whole viewport (top layer, the rest of the page inert); the control form is inside the dialog.",
  expect: { outcome: "fields", reason: "covered", exact: false },
  render: () => page({
    id: "overlay-dialog",
    css: "dialog#cover { position: fixed; inset: 0; width: 100%; height: 100%; max-width: none; max-height: none; margin: 0; padding: 0; border: 0; background: transparent; overflow: visible; } dialog#cover::backdrop { background: transparent; } .control { margin: 240px 0 0 16px; }",
    body: `<h1>Example sign-in</h1>
${loginForm({ prefix: "bad", expect: "reject", reason: "covered" })}
<dialog id="cover"><div class="control">${loginForm({ prefix: "ok", expect: "fill" })}</div></dialog>
<script>
document.getElementById("cover").showModal();
</script>`,
  }),
});

add({
  id: "hidden-fields", origin: "login", path: "/t/hidden-fields.html",
  summary: "Hidden decoys before the visible fields (a username and an e-mail field, and password fields hidden by display:none, visibility:hidden, opacity:0 on the field, no size, the hidden attribute, aria-hidden, disabled and readonly), then one visible user name and password.",
  expect: { outcome: "fields", visible: "ok-pass" },
  render: () => page({
    id: "hidden-fields",
    body: `<h1>Example sign-in</h1>
<form id="hidden-form" method="post" action="/static/login-done.html">
  <input id="hide-user" name="username" type="text" autocomplete="username" style="display: none" data-fixture-expect="reject" data-fixture-reason="display">
  <input id="hide-email" name="email" type="email" autocomplete="email" style="opacity: 0" data-fixture-expect="reject" data-fixture-reason="opacity">
  <input id="hide-display" name="p1" type="password" style="display: none" data-fixture-expect="reject" data-fixture-reason="display">
  <input id="hide-visibility" name="p2" type="password" style="visibility: hidden" data-fixture-expect="reject" data-fixture-reason="visibility">
  <input id="hide-opacity" name="p3" type="password" style="opacity: 0" data-fixture-expect="reject" data-fixture-reason="opacity">
  <input id="hide-size" name="p4" type="password" style="width: 0; height: 0; padding: 0; border: 0; margin: 0" data-fixture-expect="reject" data-fixture-reason="size">
  <input id="hide-attribute" name="p5" type="password" hidden data-fixture-expect="reject" data-fixture-reason="hidden">
  <input id="hide-aria" name="p6" type="password" aria-hidden="true" data-fixture-expect="reject" data-fixture-reason="aria-hidden">
  <input id="hide-disabled" name="p7" type="password" disabled data-fixture-expect="reject" data-fixture-reason="disabled">
  <input id="hide-readonly" name="p8" type="password" readonly data-fixture-expect="reject" data-fixture-reason="readonly">
  <input id="ok-user" name="username" type="text" autocomplete="username">
  <input id="ok-pass" name="password" type="password" autocomplete="current-password" data-fixture-expect="fill">
  <button type="submit">Sign in</button>
</form>`,
  }),
});

add({
  id: "tiny-fields", origin: "login", path: "/t/tiny-fields.html",
  summary: "Password fields of 1, 2 and 4 pixels (before a visible one): far under any sensible minimum size.",
  expect: { outcome: "fields", reason: "size" },
  render: () => page({
    id: "tiny-fields",
    body: `<h1>Example sign-in</h1>
<form id="tiny-form" method="post" action="/static/login-done.html">
  <input id="tiny-1" name="p1" type="password" style="width: 1px; height: 1px; padding: 0; border: 0; margin: 4px 0" data-fixture-expect="reject" data-fixture-reason="size">
  <input id="tiny-2" name="p2" type="password" style="width: 2px; height: 2px; padding: 0; border: 0; margin: 4px 0" data-fixture-expect="reject" data-fixture-reason="size">
  <input id="tiny-4" name="p3" type="password" style="width: 4px; height: 4px; padding: 0; border: 0; margin: 4px 0" data-fixture-expect="reject" data-fixture-reason="size">
  <input id="ok-user" name="username" type="text" autocomplete="username">
  <input id="ok-pass" name="password" type="password" autocomplete="current-password" data-fixture-expect="fill">
  <button type="submit">Sign in</button>
</form>`,
  }),
});

/**
 * Each property on a parent of a hostile form, twice: a hostile value and a
 * subtle one (the page looks the same to the eye; the rule is that any value
 * rejects, and the browser gives no other reason for the subtle one).
 * @type {[string, string, string][]} property, hostile css, subtle css
 */
const PARENT_TRICKS = [
  ["opacity", "opacity: 0.02", "opacity: 0.99"],
  ["filter", "filter: opacity(0.02)", "filter: blur(0px)"],
  ["transform", "transform: scale(0.01)", "transform: translateX(1px)"],
  ["clip-path", "clip-path: inset(100%)", "clip-path: inset(0)"],
  [
    "mask",
    "mask-image: linear-gradient(transparent, transparent); -webkit-mask-image: linear-gradient(transparent, transparent)",
    "mask-image: linear-gradient(#000, #000); -webkit-mask-image: linear-gradient(#000, #000)",
  ],
  ["mix-blend-mode", "mix-blend-mode: screen; background: #fff", "mix-blend-mode: multiply; background: #fff"],
];

for (const [property, hostile, subtle] of PARENT_TRICKS) {
  trick(`css-${property}`, {
    summary: `${property} on a parent of the password field (a hostile value).`,
    reason: property,
    wrap: (form) => `<div id="hostile-parent" style="${esc(hostile)}">${form}</div>`,
  });
  trick(`css-${property}-subtle`, {
    summary: `${property} on a parent of the password field (a value that changes nothing the eye sees: any value rejects).`,
    reason: property,
    exact: true,
    wrap: (form) => `<div id="hostile-parent" style="${esc(subtle)}">${form}</div>`,
  });
}

// visibility: a parent that is hidden with a form that sets visible again, so
// the field's own computed visibility is "visible" and only the ancestor says no.
for (const value of ["hidden", "collapse"]) {
  trick(`css-visibility${value === "hidden" ? "" : "-collapse"}`, {
    summary: `visibility: ${value} on a parent of the password field, with visibility: visible on the form (the field itself looks visible to a check of its own style).`,
    reason: "visibility",
    exact: true,
    formStyle: "visibility: visible",
    wrap: (form) => `<div id="hostile-parent" style="visibility: ${value}">${form}</div>`,
  });
}

add({
  id: "css-shadow", origin: "login", path: "/t/css-shadow.html",
  summary: "A password field in a shadow root whose host has a filter, and a clear one in another shadow root: the ancestor list goes through shadow roots.",
  expect: { outcome: "fields", reason: "filter", exact: true },
  render: () => page({
    id: "css-shadow",
    body: `<h1>Example sign-in</h1>
<div id="shadow-bad-host" style="filter: blur(0px)"></div>
<div id="shadow-ok-host"></div>
<script>
document.getElementById("shadow-bad-host").attachShadow({ mode: "open" }).innerHTML = ${literal(loginForm({ prefix: "shadow-bad", expect: "reject", reason: "filter" }))};
document.getElementById("shadow-ok-host").attachShadow({ mode: "open" }).innerHTML = ${literal(loginForm({ prefix: "shadow-ok", expect: "fill" }))};
</script>`,
  }),
});

// ------------------------------- change between the choice and the fill

/**
 * A page whose form is clear until `turnHostile()` runs (also on window blur,
 * which is what opening the popup does to the page). The fields are not marked:
 * their verdict depends on time. `action` is the body of turnHostile().
 * @param {string} id
 * @param {string} summary
 * @param {string} reason what the browser says about the field afterwards
 * @param {string} action the script of turnHostile()
 * @param {string} [outcome]
 */
function turning(id, summary, reason, action, outcome = "turns_hostile") {
  add({
    id, origin: "login", path: `/t/${id}.html`, summary,
    expect: { outcome, reason },
    render: ({ url }) => page({
      id,
      body: `<h1>Example sign-in</h1>
<div id="wrap">${loginForm()}</div>
<script>
var evilLogin = ${literal(url("evil", "/login"))};
function turnHostile() { ${action} }
window.turnHostile = turnHostile;
window.addEventListener("blur", turnHostile);
</script>`,
    }),
  });
}

turning("blur-opacity", "Turns almost invisible (opacity 0.01 on a parent) when the window loses focus.", "opacity",
  'document.getElementById("wrap").style.opacity = "0.01";');

turning("blur-overlay", "Slides a transparent cover over the password field when the window loses focus.", "covered",
  'var r = document.getElementById("login-pass").getBoundingClientRect(); var c = document.createElement("div"); c.id = "cover"; c.style.cssText = "position: fixed; z-index: 10; background: transparent; left: " + r.left + "px; top: " + r.top + "px; width: " + r.width + "px; height: " + r.height + "px"; document.body.append(c);');

turning("blur-swap", "Replaces the password field with a new, invisible one (same id) when the window loses focus.", "opacity",
  'var old = document.getElementById("login-pass"); var fresh = old.cloneNode(false); fresh.style.opacity = "0"; old.replaceWith(fresh);');

turning("blur-navigate", "Navigates the whole page to a foreign origin when the window loses focus.", "origin",
  "location.href = evilLogin;", "origin_changed");

add({
  id: "forged-events", origin: "login", path: "/t/forged-events.html",
  summary: "A sign-in page that keeps dispatching untrusted focus, click and input events and forged messages shaped like Ferret's (postMessage and a CustomEvent): none of it may fill, ask or change anything. fixtureState() says what the page has seen.",
  expect: { outcome: "fill", domain_entry: "fill", noise: "forged_events" },
  render: () => page({
    id: "forged-events",
    body: `<h1>Example sign-in</h1>
${loginForm()}
<script>
var sent = 0;
var received = [];
var user = document.getElementById("login-user");
var pass = document.getElementById("login-pass");
window.addEventListener("message", function (event) { received.push(event.data && event.data.type); });
function noise() {
  [user, pass].forEach(function (field) {
    field.dispatchEvent(new Event("focus"));
    field.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    field.dispatchEvent(new InputEvent("input", { bubbles: true, data: "x" }));
  });
  window.postMessage({ v: 1, id: "forged", type: "fill_field", body: { value: "stolen" } }, "*");
  document.dispatchEvent(new CustomEvent("ferret-fill", { detail: { value: "stolen" } }));
  sent += 1;
}
setInterval(noise, 100);
window.fixtureState = function () { return { sent: sent, userValue: user.value, passwordValue: pass.value, received: received.length }; };
</script>`,
  }),
});

// ------------------------------------------------- navigation and imitation

add({
  id: "navigate-frame", origin: "www", path: "/t/navigate.html",
  summary: "A same-site page that moves its frame to another origin on request: navigateFrame() or navigateFrame('foreign') to a foreign site, 'data' to a data: page, 'blank' to about:blank (buttons #go, #go-data, #go-blank). For a navigation between the choice and the fill.",
  expect: { outcome: "origin_changed", domain_entry: "origin_changed", frame: "frame", from: "login", to: ["evil", "data", "blank"] },
  render: ({ url }) => page({
    id: "navigate-frame",
    body: `<h1>Welcome</h1>
<iframe id="frame" title="Sign in" src="${esc(url("login", "/"))}"></iframe>
<button id="go" type="button">Continue</button>
<button id="go-data" type="button">Continue (data)</button>
<button id="go-blank" type="button">Continue (blank)</button>
<script>
var targets = {
  foreign: ${literal(url("evil", "/login"))},
  data: "data:text/html;charset=utf-8,<title>data</title><form><input type=password></form>",
  blank: "about:blank"
};
function navigateFrame(kind) { document.getElementById("frame").src = targets[kind || "foreign"]; }
document.getElementById("go").addEventListener("click", function () { navigateFrame("foreign"); });
document.getElementById("go-data").addEventListener("click", function () { navigateFrame("data"); });
document.getElementById("go-blank").addEventListener("click", function () { navigateFrame("blank"); });
window.navigateFrame = navigateFrame;
</script>`,
  }),
});

add({
  id: "ferret-lookalike", origin: "evil", path: "/t/ferret.html",
  summary: "A page with Ferret's name as its title and a favicon of its own, with a fake unlock panel: the popup shows the host name, never the title.",
  expect: { outcome: "shows_host", host: "evil.test", title: "Faithful Ferret - Unlock your vault" },
  render: () => page({
    id: "ferret-lookalike",
    title: "Faithful Ferret - Unlock your vault",
    icon: svgIcon("F", "#2d7d46"),
    body: `<h1>Faithful Ferret</h1>
<p>Your vault is locked. Enter your master password.</p>
${loginForm({ prefix: "fake", label: "Unlock" })}`,
  }),
});

/** @param {string} id */
export function siteById(id) {
  const site = SITES.find((s) => s.id === id);
  if (!site) throw new Error(`fixtures: no site named ${id}`);
  return site;
}

/**
 * The site served for a request.
 * @param {import("./origins.mjs").Listener} listener
 * @param {string} host
 * @param {string} path
 * @returns {Site | undefined}
 */
export function findSite(listener, host, path) {
  return SITES.find((s) => ORIGINS[s.origin].listener === listener && ORIGINS[s.origin].host === host && s.path === path);
}
