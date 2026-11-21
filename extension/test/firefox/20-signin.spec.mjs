// The sign-in tab and the popup in real Firefox, without a server: no web page
// can frame them (they are not web-accessible, and their CSP has
// frame-ancestors 'none'), the tab takes only an https address and shows its
// host before it asks for the permission, and a new install's popup offers the
// sign-in tab. The sign-in against a real server is 20-signin.e2e.spec.mjs.
import assert from "node:assert/strict";
import { after, test } from "node:test";
import { EXTENSION_ORIGIN, TEST_ADDON_ID, channels, fixtures, launch, openBridge, stopFixtures } from "./harness.mjs";

after(() => stopFixtures());

const SIGNIN_URL = `${EXTENSION_ORIGIN}/pages/signin.html`;
const POPUP_URL = `${EXTENSION_ORIGIN}/pages/popup.html`;

/** @param {import("./driver.mjs").Session} session */
function helpers(session) {
  /** Whether the element is there and shown. @param {string} css */
  const visible = (css) =>
    session.content((/** @type {string} */ selector) => {
      const node = document.querySelector(selector);
      return node !== null && node.closest("[hidden]") === null && node.getClientRects().length > 0;
    }, css);
  return {
    visible,
    /** @param {string} css @param {number} [ms] */
    waitVisible: (css, ms = 15_000) => session.waitFor(() => visible(css), ms, css),
    /** @param {string} css */
    text: (css) => session.content((/** @type {string} */ selector) => document.querySelector(selector)?.textContent ?? "", css),
    /** @param {string} css */
    click: async (css) => {
      const [el] = await session.findAll(css);
      assert.ok(el, css);
      await session.click(el);
    },
    /** @param {string} css @param {string} value */
    type: async (css, value) => {
      const [el] = await session.findAll(css);
      assert.ok(el, css);
      await session.type(el, value);
    },
    /** Empties an input. @param {string} css */
    clear: (css) => session.content((/** @type {string} */ selector) => {
      const node = /** @type {HTMLInputElement} */ (document.querySelector(selector));
      node.value = "";
    }, css),
    /** Waits for a page of the extension to have built itself. */
    ready: () => session.waitFor(() => session.content(() => document.body?.dataset.ready === "1"), 20_000, "the page"),
  };
}

/**
 * What an iframe of the selected tab holds: the URI of its document, read from inside the frame.
 * @param {import("./driver.mjs").Session} session @param {string} css
 */
async function frameDocument(session, css) {
  const [frame] = await session.findAll(css);
  assert.ok(frame, css);
  await session.switchToFrame(frame);
  try {
    return await session.content(() => ({ uri: document.documentURI, ferret: document.querySelector("#root") !== null && document.body?.dataset.ready === "1" }));
  } finally {
    await session.switchToTopFrame();
  }
}

test("a_web_page_cannot_frame_the_signin_page", async () => {
  for (const channel of channels()) {
    const session = await launch({ channel });
    try {
      const server = await fixtures();
      await session.waitFor(() => session.addonInfo(TEST_ADDON_ID), 30_000, "the add-on");
      const control = server.url(server.hosts[0], "/static/login.html");
      await session.navigate(server.url(server.hosts[0], "/static/blank.html"));
      // A web page frames the sign-in tab and the popup, and one of its own pages as a control.
      await session.content((/** @type {string[]} */ sources) => {
        for (const [id, src] of sources.map((s, i) => [`f${i}`, s])) {
          const frame = document.createElement("iframe");
          frame.id = id;
          frame.src = src;
          document.body.append(frame);
        }
      }, [`${EXTENSION_ORIGIN}/pages/signin.html`, `${EXTENSION_ORIGIN}/pages/popup.html`, control]);
      // The control loads: the check below can see a framed document.
      await session.waitFor(async () => (await frameDocument(session, "#f2")).uri === control, 15_000, "the control frame");
      // Give the extension's frames time to load, if they could.
      await new Promise((resolve) => setTimeout(resolve, 2_000));
      for (const id of ["#f0", "#f1"]) {
        const held = await frameDocument(session, id);
        assert.equal(held.uri.startsWith("moz-extension:"), false, `${channel}: ${id} holds ${held.uri}`);
        assert.equal(held.ferret, false, `${channel}: ${id} built a page of the extension`);
      }

      // An extension page cannot frame it either: frame-ancestors 'none' applies to every ancestor.
      await openBridge(session);
      await session.content((/** @type {string} */ src) => {
        const frame = document.createElement("iframe");
        frame.id = "framed-signin";
        frame.src = src;
        document.body.append(frame);
      }, SIGNIN_URL);
      await new Promise((resolve) => setTimeout(resolve, 2_000));
      const inBridge = await frameDocument(session, "#framed-signin");
      assert.equal(inBridge.ferret, false, `${channel}: the bridge framed the sign-in page (${inBridge.uri})`);
    } finally {
      await session.quit();
    }
  }
});

test("the_signin_page_takes_only_https_and_shows_the_host_before_it_asks_for_the_permission", async () => {
  for (const channel of channels()) {
    const session = await launch({ channel });
    try {
      const server = await fixtures();
      await session.waitFor(() => session.addonInfo(TEST_ADDON_ID), 30_000, "the add-on");
      const page = helpers(session);
      const host = new URL(server.url(server.hosts[0], "/")).host;
      await session.navigate(SIGNIN_URL);
      await page.ready();
      await page.waitVisible('[data-role="server"]');

      // http is refused with its own text, and nothing else is offered.
      await page.type('[data-role="server"]', `http://${host}`);
      await page.click('[data-role="server-submit"]');
      await page.waitVisible('[data-role="error"]');
      assert.match(await page.text('[data-role="error"]'), /https only/i, channel);
      assert.equal(await page.visible('[data-role="grant"]'), false, channel);

      // An https address: its host is shown, then the permission is asked for on the click.
      await page.clear('[data-role="server"]');
      await page.type('[data-role="server"]', `https://${host}`);
      await page.click('[data-role="server-submit"]');
      await page.waitVisible('[data-role="grant"]');
      assert.equal((await page.text('[data-role="server-checked"] [data-role="server-host"]')).trim(), new URL(`https://${host}`).hostname, channel);
      await page.click('[data-role="grant"]');
      // The test profile accepts the request without a prompt.
      await page.waitVisible('[data-role="credentials"]');
      for (const role of ["email", "password", "sk-question", "tofu-notice", "submit"]) {
        assert.equal(await page.visible(`[data-role="${role}"]`), true, `${channel}: ${role}`);
      }
      assert.equal((await page.text('[data-role="server-host"]')).trim(), new URL(`https://${host}`).hostname);

      // The permission is that origin's, and only that one was added.
      const bridge = await openBridge(session);
      const granted = await bridge.invoke("permissions.getAll");
      assert.ok(granted.origins.includes(`https://${new URL(`https://${host}`).hostname}/*`), `${channel}: ${JSON.stringify(granted.origins)}`);
      assert.equal(granted.origins.length, 1, `${channel}: ${JSON.stringify(granted.origins)}`);
    } finally {
      await session.quit();
    }
  }
});

test("the_popup_of_a_new_install_offers_the_sign_in_tab", async () => {
  for (const channel of channels()) {
    const session = await launch({ channel });
    try {
      await session.waitFor(() => session.addonInfo(TEST_ADDON_ID), 30_000, "the add-on");
      const page = helpers(session);
      await session.navigate(POPUP_URL);
      await page.ready();
      await page.waitVisible('[data-role="signed-out-view"]');
      assert.equal(await page.visible('[data-role="lock"]'), false, `${channel}: no lock button without a vault`);
      assert.equal(await page.visible('[data-role="avatar"]'), false, `${channel}: no account`);
      assert.equal(await page.visible('[data-role="popout"]'), true, channel);
      const before = await session.windowHandles();
      await page.click('[data-role="open-signin"]');
      // A new tab opens (the popup closes itself; in a tab of its own, that tab may go).
      const opened = await session.waitFor(async () => (await session.windowHandles()).find((/** @type {string} */ h) => !before.includes(h)), 10_000, "the sign-in tab");
      await session.switchTo(opened);
      await session.waitFor(async () => (await session.currentUrl()) === SIGNIN_URL, 10_000, "the sign-in page");
    } finally {
      await session.quit();
    }
  }
});
