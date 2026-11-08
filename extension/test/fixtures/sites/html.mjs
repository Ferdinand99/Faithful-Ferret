// Small pieces the test pages are made of. Every password field a test cares
// about carries data-fixture-expect="fill" (a field the fill engine may fill) or
// "reject" (a hidden, covered or otherwise hostile one it must never fill), so a
// test can walk any page and check the engine's verdict field by field. A hostile
// field also carries data-fixture-reason, the one thing that makes it hostile
// (opacity, filter, transform, clip-path, mask, mix-blend-mode, visibility,
// display, size, offscreen, covered, ...), so a check can prove the page is
// hostile for the reason it names.

/** @param {unknown} text */
export function esc(text) {
  return String(text)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

const BASE_CSS = `
body { font: 16px/1.4 sans-serif; margin: 16px; background: #fff; color: #111; }
form { display: block; margin: 0 0 24px; }
input { display: block; box-sizing: border-box; width: 240px; height: 28px; margin: 4px 0; }
iframe { display: block; width: 420px; height: 180px; margin: 8px 0; border: 1px solid #888; }
h1 { font-size: 20px; margin: 0 0 12px; }
`;

/**
 * A whole page.
 * @param {{ id: string, title?: string, icon?: string, css?: string, htmlStyle?: string, body: string }} options
 *   id: the site id, written on the root element (data-fixture-site); icon: a link rel=icon href
 * @returns {string}
 */
export function page({ id, title = "Example sign-in", icon, css = "", htmlStyle, body }) {
  const style = htmlStyle ? ` style="${esc(htmlStyle)}"` : "";
  const link = icon ? `\n<link rel="icon" href="${esc(icon)}">` : "";
  return `<!doctype html>
<html lang="en" data-fixture-site="${esc(id)}"${style}>
<head>
<meta charset="utf-8">
<title>${esc(title)}</title>${link}
<style>${BASE_CSS}${css}</style>
</head>
<body>
${body}
</body>
</html>
`;
}

/**
 * One sign-in form. `prefix` makes the ids (`<prefix>-user`, `<prefix>-pass`);
 * `expect` and `reason` go on the password field; `passAttrs` and `wrapPass`
 * change the password field and what surrounds it; `formStyle` styles the form.
 * @param {{ prefix?: string, expect?: "fill" | "reject", reason?: string, passAttrs?: string, wrapPass?: (input: string) => string, label?: string, formStyle?: string }} [options]
 */
export function loginForm({ prefix = "login", expect, reason, passAttrs = "", wrapPass = (input) => input, label = "Sign in", formStyle } = {}) {
  const mark = (expect ? ` data-fixture-expect="${expect}"` : "") + (reason ? ` data-fixture-reason="${reason}"` : "");
  const pass = `<input id="${prefix}-pass" name="password" type="password" autocomplete="current-password"${mark}${passAttrs ? ` ${passAttrs}` : ""}>`;
  return `<form id="${prefix}-form" method="post" action="/static/login-done.html"${formStyle ? ` style="${esc(formStyle)}"` : ""}>
  <input id="${prefix}-user" name="username" type="text" autocomplete="username">
  ${wrapPass(pass)}
  <button type="submit">${esc(label)}</button>
</form>`;
}

/** A data: URI of a small SVG icon, so a page can carry a favicon without a second request. @param {string} letter @param {string} color */
export function svgIcon(letter, color) {
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><circle cx="16" cy="16" r="15" fill="${color}"/><text x="16" y="22" font-size="18" text-anchor="middle" fill="#fff" font-family="sans-serif">${letter}</text></svg>`;
  return `data:image/svg+xml,${encodeURIComponent(svg)}`;
}
