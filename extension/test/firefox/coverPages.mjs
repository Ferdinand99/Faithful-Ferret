// Static sign-in pages for the fill engine's extra pass for covers that hit testing cannot see, served by the
// fixture server under /static/cover/<id>.html. Each page has a user name field (#username) and a password
// field (#password) and says what a fill must do: "fill" (the password is reported and goes in) or "refuse"
// (the page paints something over the password field that the user would not see through, and nothing goes
// in). The markup is our own; the patterns are the common ones of real sign-in pages: floating labels, input
// groups, icons inside a field, a dark layer behind the card, a hidden overlay.
//
// Not part of the detection corpus (test/fixtures/forms), which is frozen.

/**
 * @typedef {{ id: string, expect: "fill" | "refuse", summary: string, html: string }} CoverPage
 */

/** @param {string} title @param {string} css @param {string} body @param {string} [after] */
const doc = (title, css, body, after = "") => `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>${title}</title>
<style>
body{margin:0;font:16px/1.4 sans-serif;background:#f4f4f4}
main{padding:24px}
form{margin:0}
input{font:16px sans-serif}
button[type=submit]{margin-top:12px;padding:8px 16px}
${css}
</style></head>
<body>
${body}
${after}
</body>
</html>
`;

const PLAIN_FIELDS = `<input id="username" name="username" type="text" autocomplete="username" aria-label="User name" style="display:block;width:300px;box-sizing:border-box;height:40px;margin-bottom:12px;padding:0 10px">
<input id="password" name="password" type="password" autocomplete="current-password" aria-label="Password" style="display:block;width:300px;box-sizing:border-box;height:40px;padding:0 10px">
<button type="submit" id="submit">Sign in</button>`;

const form = (/** @type {string} */ inner) => `<form id="login" method="post" action="/static/login-done.html">${inner}</form>`;

/** @type {CoverPage[]} */
export const COVER_PAGES = [];

/** @param {CoverPage} page */
const add = (page) => COVER_PAGES.push(page);

// ---------------------------------------------------------------- hidden overlay

add({
  id: "hidden-overlay",
  expect: "fill",
  summary: "a full-page wrapper with opacity 0 and pointer-events none, whose child panel has a white background, after the form",
  html: doc("Hidden overlay", "", `<main>${form(PLAIN_FIELDS)}</main>
<div id="veil" style="position:fixed;inset:0;opacity:0;pointer-events:none"><div id="panel" style="position:absolute;top:0;right:0;width:100%;height:100%;background:#fff"></div></div>`),
});

add({
  id: "visible-overlay",
  expect: "refuse",
  summary: "the same wrapper with full opacity: a white layer over the form that clicks pass through",
  html: doc("Visible overlay", "", `<main>${form(PLAIN_FIELDS)}</main>
<div id="veil" style="position:fixed;inset:0;opacity:1;pointer-events:none"><div id="panel" style="position:absolute;top:0;right:0;width:100%;height:100%;background:#fff"></div></div>`),
});

// ---------------------------------------------------------------- decoration below the card

const CARD_CSS = `#card{position:relative;z-index:1;width:340px;margin:60px auto;padding:24px;background:#fff;border-radius:8px}`;

add({
  id: "decoration-behind-card",
  expect: "fill",
  summary: "a darkening layer and a gradient glow with pointer-events none behind a card that is stacked above them",
  html: doc("Decoration behind the card", CARD_CSS, `<div id="dark" style="position:absolute;inset:0;pointer-events:none;background:rgba(0,0,0,.5)"></div>
<div id="glow" style="position:absolute;left:40px;right:40px;top:30px;height:420px;z-index:-1;pointer-events:none;background:linear-gradient(90deg,#4f46e5,#06b6d4);filter:blur(24px)"></div>
<div id="card">${form(PLAIN_FIELDS)}</div>`),
});

add({
  id: "overlay-over-card",
  expect: "refuse",
  summary: "the same darkening layer placed after the card with a higher z-index: it paints over the form",
  html: doc("Overlay over the card", CARD_CSS, `<div id="card">${form(PLAIN_FIELDS)}</div>
<div id="dark" style="position:absolute;inset:0;z-index:2;pointer-events:none;background:#fff"></div>`),
});

// ---------------------------------------------------------------- floating labels

const FLOATING_CSS = `.form-floating{position:relative;width:320px;margin:12px 0}
.form-floating>input{width:100%;box-sizing:border-box;height:58px;padding:1.625rem .75rem .625rem;border:1px solid #ccc;border-radius:6px}
.form-floating>label{position:absolute;top:0;left:0;height:100%;max-width:100%;box-sizing:border-box;padding:1rem .75rem;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;pointer-events:none;border:1px solid transparent;transform-origin:0 0;transition:opacity .1s,transform .1s}
.form-floating>input:focus~label,.form-floating>input:not(:placeholder-shown)~label{opacity:.65;transform:scale(.85) translateY(-.5rem) translateX(.15rem)}
.form-floating>input:not(:placeholder-shown)~label::after{content:"";position:absolute;inset:1rem .375rem;z-index:-1;height:1.5em;background:#fff;border-radius:6px}`;

add({
  id: "floating-label-bootstrap",
  expect: "fill",
  summary: "a floating label as common CSS frameworks write it: an absolutely positioned label with pointer-events none over the empty field, its notch background on a pseudo-element",
  html: doc("Floating labels", FLOATING_CSS, `<main>${form(`<div class="form-floating"><input id="username" name="username" type="text" autocomplete="username" placeholder="User name"><label for="username">User name</label></div>
<div class="form-floating"><input id="password" name="password" type="password" autocomplete="current-password" placeholder="Password"><label for="password">Password</label></div>
<button type="submit" id="submit">Sign in</button>`)}</main>`),
});

const OUTLINED_CSS = `.outlined{position:relative;width:320px;margin:20px 0}
.outlined>input{position:relative;width:100%;box-sizing:border-box;padding:16.5px 14px;border:0;background:transparent;outline:0}
.outlined>label{position:absolute;left:14px;top:16px;color:#666;pointer-events:none}
.outlined>fieldset{position:absolute;inset:-5px 0 0;margin:0;padding:0 8px;overflow:hidden;pointer-events:none;border:1px solid #888;border-radius:4px}
.outlined>fieldset>legend{padding:0;max-width:.01px;visibility:hidden;font-size:.75em}`;

add({
  id: "floating-label-outlined",
  expect: "fill",
  summary: "an outlined field: the label and a notched outline fieldset, both with pointer-events none and no background, over the field",
  html: doc("Outlined fields", OUTLINED_CSS, `<main>${form(`<div class="outlined"><input id="username" name="username" type="text" autocomplete="username"><label for="username">User name</label><fieldset aria-hidden="true"><legend><span>&#8203;</span></legend></fieldset></div>
<div class="outlined"><input id="password" name="password" type="password" autocomplete="current-password"><label for="password">Password</label><fieldset aria-hidden="true"><legend><span>&#8203;</span></legend></fieldset></div>
<button type="submit" id="submit">Sign in</button>`)}</main>`),
});

const LONG_LABEL = "E-postadresse eller mobilnummer, Benutzername oder E-Mail-Adresse";
const LABEL_CSS = `.wrap{position:relative;width:300px;margin:20px 0}
.wrap>input{width:100%;box-sizing:border-box;height:44px;padding:0 10px}
.wrap>.tag{position:absolute;left:8px;top:11px;padding:0 4px;background:#fff;color:#777;white-space:nowrap;pointer-events:none}`;

add({
  id: "floating-label-background",
  expect: "fill",
  summary: "a label with a permanent white background, centred on the empty field, long enough to cross its centre (Norwegian and German text)",
  html: doc("Labels with a background", LABEL_CSS, `<main>${form(`<div class="wrap"><input id="username" name="username" type="text" autocomplete="username"><label class="tag" for="username">${LONG_LABEL}</label></div>
<div class="wrap"><input id="password" name="password" type="password" autocomplete="current-password"><label class="tag" for="password">${LONG_LABEL}</label></div>
<button type="submit" id="submit">Sign in</button>`)}</main>`),
});

add({
  id: "background-box-instead-of-label",
  expect: "refuse",
  summary: "the same white box as a div over the password field: it is no label of the field",
  html: doc("A box over the field", LABEL_CSS, `<main>${form(`<div class="wrap"><input id="username" name="username" type="text" autocomplete="username"></div>
<div class="wrap"><input id="password" name="password" type="password" autocomplete="current-password"><div class="tag">${LONG_LABEL}</div></div>
<button type="submit" id="submit">Sign in</button>`)}</main>`),
});

// ---------------------------------------------------------------- adornments and rings

const ADORN_CSS = `.group{display:flex;width:320px}
.group>.addon{padding:6px 12px;border:1px solid #ccc;border-right:0;background:#e9ecef}
.group>input{flex:1 1 auto;min-width:0;height:40px;padding:0 10px;border:1px solid #ccc}
#username{position:relative;z-index:2;box-shadow:0 0 0 2px rgb(79,70,229)}
.pw{position:relative;width:320px;margin-top:-1px}
.pw>input{width:100%;box-sizing:border-box;height:40px;padding:0 76px 0 36px;border:1px solid #ccc}
.pw>.lead{position:absolute;left:10px;top:10px;pointer-events:none}
.pw>.eye{position:absolute;right:4px;top:6px;width:32px;height:28px;border:0;background:#fff;cursor:pointer}
.pw>#manager{position:absolute;right:40px;top:8px;width:24px;height:24px;pointer-events:none}`;

add({
  id: "adornments",
  expect: "fill",
  summary: "an input group with an addon, a show-password button inside the field, a leading icon with pointer-events none, another manager's icon in a shadow root, and an opaque focus ring on the user name field that overlaps the password field by a pixel",
  html: doc("Adornments", ADORN_CSS, `<main>${form(`<div class="group"><span class="addon">@</span><input id="username" name="username" type="text" autocomplete="username" aria-label="User name"></div>
<div class="pw"><span class="lead"><svg width="20" height="20" viewBox="0 0 20 20" aria-hidden="true"><circle cx="10" cy="10" r="8" fill="#888"></circle></svg></span><input id="password" name="password" type="password" autocomplete="current-password" aria-label="Password"><div id="manager"></div><button type="button" class="eye" aria-label="Show password">o</button></div>
<button type="submit" id="submit">Sign in</button>`)}</main>`,
  `<script>
const host = document.getElementById("manager");
const root = host.attachShadow({ mode: "open" });
root.innerHTML = '<div style="width:24px;height:24px;background:#1a73e8;border-radius:4px"></div>';
</script>`),
});

// ---------------------------------------------------------------- a large page

const FILLERS = Array.from({ length: 6_000 }, (_, i) => `<p class="f">${i}</p>`).join("");
const BIG_CSS = `.f{margin:0;font-size:10px}#banner{position:fixed;left:0;right:0;bottom:0;height:56px;z-index:100;background:#fff;box-shadow:0 -2px 8px rgba(0,0,0,.2)}`;

add({
  id: "large-page-banner",
  expect: "fill",
  summary: "6 000 elements after the form and an opaque cookie banner fixed to the bottom of the window, not over the form",
  html: doc("Large page", BIG_CSS, `<main>${form(PLAIN_FIELDS)}</main>
<div id="banner">We use cookies. <button type="button">OK</button></div>
<div id="filler">${FILLERS}</div>`),
});

add({
  id: "large-page-late-cover",
  expect: "refuse",
  summary: "6 000 elements after the form and, last in the document, a full-page white layer that clicks pass through",
  html: doc("Large page with a late cover", BIG_CSS, `<main>${form(PLAIN_FIELDS)}</main>
<div id="filler">${FILLERS}</div>
<div id="late" style="position:fixed;inset:0;pointer-events:none;background:#fff"></div>`),
});

/** @param {string} id @returns {CoverPage | undefined} */
export const coverPage = (id) => COVER_PAGES.find((page) => page.id === id);
