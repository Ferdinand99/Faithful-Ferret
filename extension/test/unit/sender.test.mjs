import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import {
  contentSender,
  isExtensionPage,
  isTopLevelExtensionPage,
  isUiPort,
} from "../../src/shared/origin.mjs";
import { UI_PORT } from "../../src/shared/protocol.mjs";
import {
  EXTENSION_ID,
  contentScriptSender,
  createFakeBrowser,
  extensionPageSender,
  fakePort,
} from "./fakeBrowser.mjs";

const fake = createFakeBrowser();
const { runtime } = fake;

test("is_extension_page_accepts_the_extensions_own_pages", () => {
  assert.equal(isExtensionPage(extensionPageSender(fake), runtime), true);
  assert.equal(isExtensionPage(extensionPageSender(fake, "pages/popup.html"), runtime), true);
  // The same, without an origin field (older browsers).
  const { origin: _origin, ...bare } = extensionPageSender(fake);
  assert.equal(isExtensionPage(bare, runtime), true);
  // The same for a Chromium-style runtime.
  const chrome = createFakeBrowser({ scheme: "chrome-extension", uuid: "abcdefghijklmnopabcdefghijklmnop" });
  assert.equal(isExtensionPage(extensionPageSender(chrome), chrome.runtime), true);
});

test("is_extension_page_refuses_a_content_script_sender_whose_url_is_a_web_page", () => {
  // A content script has the extension's id, so only the URL tells them apart.
  const sender = contentScriptSender(fake, "https://example.com/login");
  assert.equal(sender.id, runtime.id);
  assert.equal(isExtensionPage(sender, runtime), false);
  assert.equal(isExtensionPage(contentScriptSender(fake, "http://localhost:3000/"), runtime), false);
  // A page that spells our id and URL somewhere else is not ours.
  const lookalike = contentScriptSender(fake, `https://example.com/${fake.base}`);
  assert.equal(isExtensionPage(lookalike, runtime), false);
  const subdomain = contentScriptSender(fake, `https://${fake.base.slice(0, -1).split("//")[1]}.example.com/`);
  assert.equal(isExtensionPage(subdomain, runtime), false);
  // A web page cannot send as an extension page, whatever origin it claims.
  assert.equal(
    isExtensionPage({ ...sender, origin: fake.origin }, runtime),
    false,
  );
});

test("is_extension_page_refuses_data_and_about_blank_senders_and_null_origins", () => {
  const good = extensionPageSender(fake);
  for (const url of [
    "data:text/html,<p>hi</p>",
    "about:blank",
    "about:srcdoc",
    "blob:null/6f2c",
    "javascript:alert(1)",
    "file:///etc/passwd",
    "",
    undefined,
    null,
    42,
  ]) {
    assert.equal(
      isExtensionPage({ ...good, url: /** @type {any} */ (url) }, runtime),
      false,
      String(url),
    );
    assert.equal(
      isExtensionPage({ id: runtime.id, url: /** @type {any} */ (url), origin: "null" }, runtime),
      false,
      `null origin with ${String(url)}`,
    );
  }
  // An opaque origin is refused even with an extension URL.
  assert.equal(isExtensionPage({ ...good, origin: "null" }, runtime), false);
  // An origin that is not ours is refused.
  assert.equal(isExtensionPage({ ...good, origin: "https://example.com" }, runtime), false);
  // The URL is only a prefix match on our base, which ends in a slash.
  assert.equal(
    isExtensionPage({ ...good, url: `${fake.base.slice(0, -1)}.evil/page.html` }, runtime),
    false,
  );
  assert.equal(
    isExtensionPage({ ...good, url: `${fake.base.slice(0, -1)}x/page.html` }, runtime),
    false,
  );
  // A runtime that gives no usable base refuses everything, also "null".
  for (const getURL of [() => "", () => "null", () => "about:blank", () => undefined, () => { throw new Error("x"); }]) {
    assert.equal(
      isExtensionPage(good, { id: runtime.id, getURL: /** @type {any} */ (getURL) }),
      false,
    );
  }
  assert.equal(isExtensionPage(good, { id: "", getURL: runtime.getURL }), false);
  assert.equal(isExtensionPage(good, { getURL: runtime.getURL }), false);
  // No sender at all.
  for (const sender of [null, undefined, "x", 1]) {
    assert.equal(isExtensionPage(/** @type {any} */ (sender), runtime), false);
  }
  assert.equal(isExtensionPage({ url: good.url }, runtime), false);
});

test("is_extension_page_refuses_another_extensions_id", () => {
  const good = extensionPageSender(fake);
  assert.equal(isExtensionPage({ ...good, id: "other@example.com" }, runtime), false);
  assert.equal(isExtensionPage({ ...good, id: undefined }, runtime), false);
  assert.equal(isExtensionPage({ ...good, id: EXTENSION_ID.toUpperCase() }, runtime), false);
  // The same id with another extension's URL.
  const other = createFakeBrowser({ uuid: "11111111-2222-4333-8444-555555555555" });
  assert.equal(isExtensionPage({ ...good, url: other.runtime.getURL("pages/signin.html"), origin: other.origin }, runtime), false);
  // Another extension's sender, id and URL, against our runtime.
  const theirs = extensionPageSender(other);
  theirs.id = "other@example.com";
  assert.equal(isExtensionPage(theirs, runtime), false);
});

test("an extension page that a web page frames is not a top-level page", () => {
  const top = extensionPageSender(fake);
  assert.equal(isTopLevelExtensionPage(top, runtime), true);
  const { frameId: _frameId, ...noFrame } = top;
  assert.equal(isTopLevelExtensionPage(noFrame, runtime), true);
  // A page in a tab always has a frame id, and it must be 0.
  assert.equal(isTopLevelExtensionPage({ ...top, tab: { id: 5 } }, runtime), true);
  assert.equal(isTopLevelExtensionPage({ ...noFrame, tab: { id: 5 } }, runtime), false);
  assert.equal(isTopLevelExtensionPage({ ...top, tab: { id: 5 }, frameId: 2 }, runtime), false);
  // The framed page has the extension's URL and id, but a frame id above 0.
  const framed = extensionPageSender(fake, "pages/signin.html", { frameId: 3 });
  assert.equal(isExtensionPage(framed, runtime), true);
  assert.equal(isTopLevelExtensionPage(framed, runtime), false);
  assert.equal(isTopLevelExtensionPage({ ...top, frameId: -1 }, runtime), false);
  assert.equal(isTopLevelExtensionPage({ ...top, frameId: "0" }, runtime), false);
  assert.equal(isTopLevelExtensionPage(contentScriptSender(fake), runtime), false);
});

test("the ui port is accepted only from a top-level extension page", () => {
  const page = extensionPageSender(fake);
  assert.equal(isUiPort(fakePort(UI_PORT, page), runtime, UI_PORT), true);
  assert.equal(isUiPort(fakePort("other", page), runtime, UI_PORT), false);
  assert.equal(isUiPort(fakePort(UI_PORT, contentScriptSender(fake)), runtime, UI_PORT), false);
  assert.equal(
    isUiPort(fakePort(UI_PORT, extensionPageSender(fake, "pages/signin.html", { frameId: 2 })), runtime, UI_PORT),
    false,
  );
  assert.equal(isUiPort(fakePort(UI_PORT, undefined), runtime, UI_PORT), false);
  assert.equal(isUiPort(/** @type {any} */ (null), runtime, UI_PORT), false);
});

test("content_sender_takes_tab_frame_and_url_from_the_browser", () => {
  const sender = contentScriptSender(fake, "https://example.com/login?next=1");
  assert.deepEqual(contentSender(sender, runtime), {
    tabId: 7,
    frameId: 0,
    documentId: "doc-1",
    url: "https://example.com/login?next=1",
  });
  const noDoc = { ...sender };
  delete (/** @type {any} */ (noDoc)).documentId;
  assert.deepEqual(contentSender(noDoc, runtime), {
    tabId: 7,
    frameId: 0,
    url: "https://example.com/login?next=1",
  });
  assert.equal(contentSender(contentScriptSender(fake, "http://localhost:8080/", { frameId: 4 }), runtime)?.frameId, 4);
});

test("content_sender_refuses_everything_that_is_not_a_web_page_frame", () => {
  const good = contentScriptSender(fake);
  assert.notEqual(contentSender(good, runtime), null);
  // Another extension, or none.
  assert.equal(contentSender({ ...good, id: "other@example.com" }, runtime), null);
  assert.equal(contentSender({ ...good, id: undefined }, runtime), null);
  // Not from a tab: the background, a popup, a page of ours.
  assert.equal(contentSender(extensionPageSender(fake), runtime), null);
  assert.equal(contentSender({ ...good, tab: undefined }, runtime), null);
  assert.equal(contentSender({ ...good, tab: {} }, runtime), null);
  assert.equal(contentSender({ ...good, tab: { id: -1 } }, runtime), null);
  assert.equal(contentSender({ ...good, tab: { id: 1.5 } }, runtime), null);
  // An extension page open in a tab is not a content script.
  assert.equal(
    contentSender({ ...extensionPageSender(fake), tab: { id: 3 } }, runtime),
    null,
  );
  // No frame, or a bad one.
  assert.equal(contentSender({ ...good, frameId: undefined }, runtime), null);
  assert.equal(contentSender({ ...good, frameId: -1 }, runtime), null);
  assert.equal(contentSender({ ...good, frameId: "0" }, runtime), null);
  // Opaque and non-web frames: sandbox, data, blank, srcdoc, blob.
  assert.equal(contentSender({ ...good, origin: "null" }, runtime), null);
  for (const url of ["about:blank", "about:srcdoc", "data:text/html,x", "blob:https://a.example/1", "file:///x", "", undefined, 1]) {
    assert.equal(contentSender({ ...good, url: /** @type {any} */ (url) }, runtime), null, String(url));
  }
  assert.equal(contentSender({ ...good, url: `https://a.example/${"x".repeat(9000)}` }, runtime), null);
  for (const sender of [null, undefined, "x", 1]) {
    assert.equal(contentSender(/** @type {any} */ (sender), runtime), null);
  }
});

const D1 =
  "MP and SK are typed only on the vault origin **or** in the extension's own pages: pages loaded from the package under `moz-extension://<uuid>/` or `chrome-extension://<id>/`, opened as a tab or popup. Never in a web page, a content script, the MAIN world or an extension page that is framed inside a web page. These pages are never listed in `web_accessible_resources` and have `frame-ancestors 'none'`.";

test("the_d1_text_is_in_both_copies_of_the_spec", () => {
  // The Norwegian copy in the notes is checked in review.
  const spec = readFileSync(
    new URL("../../../docs/design/phase-1-security-design.md", import.meta.url),
    "utf8",
  ).replace(/\r\n/g, "\n");
  const between = (/** @type {string} */ from, /** @type {string} */ to) => {
    const start = spec.indexOf(from);
    assert.notEqual(start, -1, `${from} exists`);
    const end = spec.indexOf(to, start);
    assert.notEqual(end, -1, `${to} follows`);
    return spec.slice(start, end);
  };
  assert.ok(between("### 7.2 Browser extension", "### 7.3 Web vault").includes(D1), "in 7.2");
  assert.ok(between("\n7. **No remote code", "\n8. **Bridge").includes(D1), "in 10.7");
  assert.equal(spec.split(D1).length - 1, 2, "exactly twice");
});
