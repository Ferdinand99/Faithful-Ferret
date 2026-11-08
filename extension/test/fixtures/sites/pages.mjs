// The adversarial test sites: phishing look-alikes, hostile frames and
// clickjacking tricks that the fill engine and the frame rules are tested
// against. Each site has an id, an origin (origins.mjs), a path, a summary and
// an `expect` that a Firefox run reads. The fill engine's unit tests cover the
// same cases without a browser.
//
// The vault entry the sites are made for is `https://login.example.test/` (match
// by host, no port). `expect.outcome` is one of:
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
//   shows_host         the popup shows the host name, never the page's title
//
// `expect.search` is "copy_only" where a search for the real entry must give a
// Copy button and no Fill button. Nothing here is shipped: test/ never is.
import { HOMOGRAPH_A_LABEL_HOST, HOMOGRAPH_UNICODE_HOST, ORIGINS } from "./origins.mjs";
import { esc, loginForm, page, svgIcon } from "./html.mjs";

/**
 * @typedef {{ url: (origin: string, path?: string) => string }} Context
 * @typedef {{ outcome: string, search?: "copy_only", [key: string]: unknown }} Expectation
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
  summary: "The entry's own page: a host match, and the form is filled.",
  expect: { outcome: "fill", match: "host" },
  render: plain("login"),
});

add({
  id: "framed-same-site", origin: "www", path: "/",
  summary: "A page on the same site (www) with the entry's page in a frame: filled in the frame, the permission asked in a tab.",
  expect: { outcome: "fill_in_frame", frame: "login-frame", frameOrigin: "login" },
  render: ({ url }) => page({
    id: "framed-same-site",
    body: `<h1>Welcome</h1>\n<iframe id="login-frame" title="Sign in" src="${esc(url("login", "/"))}"></iframe>`,
  }),
});

add({
  id: "framed-foreign", origin: "shop", path: "/",
  summary: "A page with a frame from a foreign site: nothing is offered in the frame.",
  expect: { outcome: "no_offer_in_frame", frame: "foreign-frame", frameOrigin: "evil" },
  render: ({ url }) => page({
    id: "framed-foreign",
    title: "Shop",
    body: `<h1>Shop</h1>\n<iframe id="foreign-frame" title="Pay" src="${esc(url("evil", "/login"))}"></iframe>`,
  }),
});

add({
  id: "foreign-login", origin: "evil", path: "/login",
  summary: "The foreign sign-in page that the shop frames.",
  expect: { outcome: "no_offer" },
  render: plain("foreign-login", "Secure payment sign-in"),
});

add({
  id: "http-downgrade", origin: "loginHttp", path: "/",
  summary: "The entry's host over http: an https entry is never offered on http.",
  expect: { outcome: "no_offer" },
  render: plain("http-downgrade"),
});

add({
  id: "other-port", origin: "loginAlt", path: "/",
  summary: "The entry's host on another port: no offer.",
  expect: { outcome: "no_offer" },
  render: plain("other-port"),
});

add({
  id: "lookalike-dash", origin: "dash", path: "/",
  summary: "login-example.test: a dash where the entry has a dot.",
  expect: { outcome: "no_offer", search: "copy_only" },
  render: plain("lookalike-dash"),
});

add({
  id: "lookalike-suffix", origin: "suffix", path: "/",
  summary: "login.example.test.evil.test: the real host as the left part of a foreign one.",
  expect: { outcome: "no_offer", search: "copy_only" },
  render: plain("lookalike-suffix"),
});

add({
  id: "lookalike-homograph", origin: "homograph", path: "/",
  summary: "A valid homograph: a Cyrillic o in login. The browser turns it into an xn-- host; the popup shows the A-label next to the Unicode form.",
  expect: { outcome: "no_offer", search: "copy_only", unicodeHost: HOMOGRAPH_UNICODE_HOST, aLabelHost: HOMOGRAPH_A_LABEL_HOST },
  render: () => page({
    id: "lookalike-homograph",
    body: `<h1>Example sign-in</h1>\n<p id="host-note">${esc(HOMOGRAPH_UNICODE_HOST)}</p>\n${loginForm()}`,
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

// ---------------------------------------------------------- opaque frames

/** The sign-in form that goes into a frame whose fields are never filled. @param {string} prefix */
const frameForm = (prefix) => loginForm({ prefix, expect: "reject" });

add({
  id: "frames-opaque", origin: "login", path: "/t/frames-opaque.html",
  summary: "Frames with no origin the fill may use: about:blank, srcdoc, a sandbox with srcdoc and a sandbox with an https address (its origin is opaque although the address is https).",
  expect: {
    outcome: "no_offer_in_frame",
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
  summary: "The page that the sandbox frame loads: the entry's own https address, in a frame whose origin is opaque.",
  expect: { outcome: "no_offer" },
  render: () => page({ id: "sandboxed-login", body: `<h1>Example sign-in</h1>\n${loginForm({ prefix: "sandboxed", expect: "reject" })}` }),
});

// ----------------------------------------------------- clickjacking tricks

/**
 * A page with a hostile form (its password field must be rejected) and a clear
 * one after it (filled), the hostile one wrapped by `wrap`.
 * @param {string} id
 * @param {{ summary: string, wrap?: (form: string) => string, wrapPass?: (input: string) => string, css?: string, htmlStyle?: string, control?: boolean }} options
 */
function trick(id, { summary, wrap = (form) => form, wrapPass, css = "", htmlStyle, control = true }) {
  add({
    id, origin: "login", path: `/t/${id}.html`, summary,
    expect: { outcome: "fields" },
    render: () => page({
      id,
      css,
      htmlStyle,
      body: `<h1>Example sign-in</h1>
${wrap(loginForm({ prefix: "bad", expect: "reject", wrapPass }))}
${control ? loginForm({ prefix: "ok", expect: "fill" }) : ""}`,
    }),
  });
}

trick("overlay", {
  summary: "A transparent element above the password field: a click would land on it, not on the field.",
  css: ".over { position: relative; width: 240px; } .over input { margin: 0; } .cover { position: absolute; inset: 0; z-index: 10; background: transparent; }",
  wrapPass: (input) => `<div class="over">${input}<div class="cover" id="cover"></div></div>`,
});

trick("opacity-html", {
  summary: "opacity: 0 on <html>: the whole page is invisible, so every field is rejected.",
  htmlStyle: "opacity: 0",
  control: false,
});

trick("offscreen", {
  summary: "Forms outside the viewport (far to the left, far above), with a visible control form.",
  css: ".far-left { position: absolute; left: -10000px; top: 0; } .far-up { position: absolute; left: 0; top: -10000px; }",
  wrap: (form) => `<div id="far-left" class="far-left">${form}</div>
<div id="far-up" class="far-up">${loginForm({ prefix: "up", expect: "reject" })}</div>`,
});

add({
  id: "hidden-fields", origin: "login", path: "/t/hidden-fields.html",
  summary: "One visible password field with hidden ones beside it: display:none, visibility:hidden, opacity:0 on the field, no size, the hidden attribute, aria-hidden, disabled and readonly.",
  expect: { outcome: "fields", visible: "ok-pass" },
  render: () => page({
    id: "hidden-fields",
    body: `<h1>Example sign-in</h1>
<form id="hidden-form" method="post" action="/static/login-done.html">
  <input id="ok-user" name="username" type="text" autocomplete="username">
  <input id="ok-pass" name="password" type="password" autocomplete="current-password" data-fixture-expect="fill">
  <input id="hide-display" name="p1" type="password" style="display: none" data-fixture-expect="reject">
  <input id="hide-visibility" name="p2" type="password" style="visibility: hidden" data-fixture-expect="reject">
  <input id="hide-opacity" name="p3" type="password" style="opacity: 0" data-fixture-expect="reject">
  <input id="hide-size" name="p4" type="password" style="width: 0; height: 0; padding: 0; border: 0; margin: 0" data-fixture-expect="reject">
  <input id="hide-attribute" name="p5" type="password" hidden data-fixture-expect="reject">
  <input id="hide-aria" name="p6" type="password" aria-hidden="true" data-fixture-expect="reject">
  <input id="hide-disabled" name="p7" type="password" disabled data-fixture-expect="reject">
  <input id="hide-readonly" name="p8" type="password" readonly data-fixture-expect="reject">
  <button type="submit">Sign in</button>
</form>`,
  }),
});

/**
 * Each property on a parent of a hostile form, twice: a hostile value and a
 * subtle one (the page looks the same to the eye; the rule is that any value
 * rejects).
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
    wrap: (form) => `<div id="hostile-parent" style="${esc(hostile)}">${form}</div>`,
  });
  trick(`css-${property}-subtle`, {
    summary: `${property} on a parent of the password field (a value that changes nothing the eye sees: any value rejects).`,
    wrap: (form) => `<div id="hostile-parent" style="${esc(subtle)}">${form}</div>`,
  });
}

add({
  id: "css-shadow", origin: "login", path: "/t/css-shadow.html",
  summary: "A password field in a shadow root whose host has a filter, and a clear one in another shadow root: the ancestor list goes through shadow roots.",
  expect: { outcome: "fields" },
  render: () => page({
    id: "css-shadow",
    body: `<h1>Example sign-in</h1>
<div id="shadow-bad-host" style="filter: blur(0px)"></div>
<div id="shadow-ok-host"></div>
<script>
document.getElementById("shadow-bad-host").attachShadow({ mode: "open" }).innerHTML = ${literal(loginForm({ prefix: "shadow-bad", expect: "reject" }))};
document.getElementById("shadow-ok-host").attachShadow({ mode: "open" }).innerHTML = ${literal(loginForm({ prefix: "shadow-ok", expect: "fill" }))};
</script>`,
  }),
});

// ------------------------------------------------- navigation and imitation

add({
  id: "navigate-frame", origin: "www", path: "/t/navigate.html",
  summary: "A page that moves its frame to a foreign origin on request (click #go or call navigateFrame()), for a navigation between the choice and the fill.",
  expect: { outcome: "origin_changed", frame: "frame", from: "login", to: "evil" },
  render: ({ url }) => page({
    id: "navigate-frame",
    body: `<h1>Welcome</h1>
<iframe id="frame" title="Sign in" src="${esc(url("login", "/"))}"></iframe>
<button id="go" type="button">Continue</button>
<script>
function navigateFrame() { document.getElementById("frame").src = ${literal(url("evil", "/login"))}; }
document.getElementById("go").addEventListener("click", navigateFrame);
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
