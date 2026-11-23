// The frame rules and the list a page is offered, in real Firefox, on the test
// sites (test/fixtures/sites): the frames come from the browser's
// `webNavigation` and every site rule from the real core in the background.
//
// - On each framing site, `fillableFrames` chooses the top and exactly the frames
//   the sites expect: no cross-site frame, no opaque frame, no frame with an
//   http ancestor (loopback apart). The sandboxed frame with an https address is
//   the one the browser's facts cannot refuse: the fill script's own
//   `self.origin` is "null" there, and `confirmFrame` refuses it (in MV3 Firefox
//   already refuses to inject into it).
// - Over the real UI port, the list names the host the core shows (never the
//   page's title) and flags a plain http page. A same-site frame of another
//   origin that no item matches asks for no permission, and the grant tab
//   refuses an origin no list named (the grant itself is in the end-to-end spec,
//   where an item matches the frame).
//
// The vault is "open" without a key here (the test build's `measure_open`): the
// items of a real vault are matched by the end-to-end spec (40-match.e2e.spec.mjs).
import assert from "node:assert/strict";
import { after, test } from "node:test";
import { confirmFrame } from "../../src/background/frames.mjs";
import { CONFUSABLE_A_LABEL_HOST, CONFUSABLE_UNICODE_HOST, HOMOGRAPH_A_LABEL_HOST } from "../fixtures/sites/index.mjs";
import { EXTENSION_ORIGIN, channels, commandOnPage, fixtures, launch, openBridge, stopFixtures, TEST_ADDON_ID, TEST_SHORTCUT } from "./harness.mjs";

after(() => stopFixtures());

/**
 * The frames each framing site offers below the top, by the origin name of the sites (origins.mjs), and why.
 * @type {Record<string, string[]>}
 */
const OFFERED_BELOW = {
  "framed-same-site": ["login"], // same site, another origin: offered (after the grant)
  "framed-nested": ["login"], // the login frame; the about:blank frame inside it is not
  "loopback-framed": ["loopback"], // loopback counts as secure
  "framed-cross-site": [], // the frame's origin matches an entry, but it is another site
  "framed-foreign": [],
  "http-framed-same-site": [], // an http ancestor
  "http-top-https-frame": [], // an http ancestor (and another site, by scheme)
  "frames-special": [], // data:, blob:, javascript:
  "nested-login": [], // about:blank
  // The browser lists the sandboxed frame with its https address and the core gives it an origin: only the fill
  // script can see the sandbox (below). about:blank, srcdoc and the sandboxed srcdoc are refused here.
  "frames-opaque": ["login"],
};

/**
 * One Firefox with the bridge in one tab and the test sites in another.
 * @param {string} channel
 */
async function open(channel) {
  const server = await fixtures();
  const session = await launch({ channel });
  await session.waitFor(() => session.addonInfo(TEST_ADDON_ID), 30_000, "the add-on");
  const bridgeTab = await session.windowHandle();
  const bridge = await openBridge(session);
  const pageTab = await session.newTab();
  await session.switchTo(pageTab);

  /** Runs `body` in the bridge tab and goes back to the page tab. @template T @param {() => Promise<T>} body */
  const fromBridge = async (body) => {
    await session.switchTo(bridgeTab);
    try {
      return await body();
    } finally {
      await session.switchTo(pageTab);
    }
  };
  /** One request on a port of the extension from the bridge page. @param {string} name @param {unknown} message */
  const ask = (name, message) =>
    fromBridge(async () => JSON.parse(await session.content((/** @type {string} */ portName, /** @type {string} */ text) => new Promise((resolve, reject) => {
      const port = browser.runtime.connect({ name: portName });
      const timer = setTimeout(() => reject(new Error(`${portName} did not answer`)), 30_000);
      port.onMessage.addListener((reply) => {
        clearTimeout(timer);
        port.disconnect();
        resolve(typeof reply === "string" ? reply : JSON.stringify(reply));
      });
      // The UI port takes the envelope as a JSON string; the test ports take an object.
      port.postMessage(JSON.parse(text));
    }), name, JSON.stringify(message))));
  /** A core op of the test build. @param {string} op @param {Record<string, unknown>} [args] */
  const core = async (op, args = {}) => {
    const reply = await ask("ferret-test-core", { id: "1", op, args });
    assert.equal(reply.ok, true, `${channel}: ${op}: ${reply.code}`);
    return reply.value;
  };
  /** A message of the UI protocol, as the popup sends it. @param {string} type @param {Record<string, unknown>} body */
  const ui = async (type, body) => {
    const reply = await ask("ferret-ui", JSON.stringify({ v: 1, id: "t1", type, body }));
    assert.equal(reply.type, type, `${channel}: ${type}: ${JSON.stringify(reply.body)}`);
    return reply.body;
  };
  /**
   * Shows a site in the page tab and presses the test shortcut, so Firefox grants activeTab as it does for the
   * popup. Returns the tab's id.
   * @param {string} url
   */
  const visit = async (url) => {
    await fromBridge(() => bridge.clearEvents());
    await session.navigate(url);
    await session.waitFor(() => session.content(() => document.readyState === "complete"), 15_000, url);
    const command = await commandOnPage({
      clear: () => fromBridge(() => bridge.clearEvents()),
      press: () => session.pressShortcut(TEST_SHORTCUT),
      events: () => fromBridge(() => bridge.events()),
    });
    assert.equal(command.tabUrl, url, `${channel}: activeTab was granted on ${url}`);
    return /** @type {number} */ (command.tabId);
  };
  return { session, server, bridge, fromBridge, core, ui, visit, pageTab };
}

test("fixture_frames_follow_the_frame_rules_and_a_sandbox_is_refused_by_its_self_origin", async () => {
  for (const channel of channels()) {
    const { session, server, fromBridge, core, visit } = await open(channel);
    try {
      for (const [id, below] of Object.entries(OFFERED_BELOW)) {
        const tabId = await visit(server.siteUrl(id));
        // The frames load after the page: wait until the browser lists every iframe of it.
        const want = await session.content(() => document.querySelectorAll("iframe").length);
        const { frames } = await session.waitFor(async () => {
          const probe = await core("frames_probe", { tab_id: tabId });
          return probe.listed >= want + 1 ? probe : null;
        }, 10_000, `the frames of ${id}`);
        const top = frames[0];
        assert.equal(top.frameId, 0, `${channel} ${id}: the top first`);
        assert.equal(top.url, server.siteUrl(id), `${channel} ${id}`);
        assert.ok(want > 0, `${channel} ${id}: the site has frames`);
        const offered = frames.slice(1).map((/** @type {{ origin: string }} */ f) => f.origin).sort();
        assert.deepEqual(offered, below.map((name) => server.origin(name)).sort(), `${channel} ${id}: the frames offered below the top`);
      }

      // The sandboxed frame: the browser says https://login.example.net, the frame itself says "null".
      const tabId = await visit(server.siteUrl("frames-opaque"));
      const { frames } = await core("frames_probe", { tab_id: tabId });
      const sandboxed = frames.find((/** @type {{ url: string }} */ f) => f.url === server.siteUrl("sandboxed-login"));
      assert.ok(sandboxed, `${channel}: the browser lists the sandboxed frame with its https address`);
      assert.equal(sandboxed.origin, server.origin("login"));
      const fill = async (/** @type {string} */ op, /** @type {Record<string, unknown>} */ args = {}) => {
        const reply = await fromBridge(async () => JSON.parse(await session.content((/** @type {string} */ name, /** @type {string} */ params) => new Promise((resolve) => {
          const port = browser.runtime.connect({ name: "ferret-test-fill" });
          port.onMessage.addListener((r) => {
            port.disconnect();
            resolve(JSON.stringify(r));
          });
          port.postMessage({ id: "1", op: name, args: JSON.parse(params) });
        }), op, JSON.stringify(args))));
        return reply;
      };
      await fill("clear");
      // What the frame itself says its origin is (`self.origin`, as the fill script reads it for `self_origin`).
      const own = await fromBridge(async () => JSON.parse(await session.content(async (/** @type {number} */ tab, /** @type {number} */ frame) => {
        try {
          const [result] = await browser.scripting.executeScript({ target: { tabId: tab, frameIds: [frame] }, func: () => self.origin });
          return JSON.stringify({ ok: true, origin: result?.result ?? null });
        } catch (error) {
          return JSON.stringify({ ok: false, error: String(/** @type {Error} */ (error)?.message ?? error) });
        }
      }, tabId, sandboxed.frameId)));
      if (own.ok) {
        // MV2: Firefox runs scripts there, and the frame's own origin is opaque.
        assert.equal(own.origin, "null", `${channel}: the sandboxed frame's own origin`);
        assert.equal(confirmFrame(sandboxed, own.origin), false, `${channel}: refused by its self origin`);
        // The fill script runs there as well, and its report never reaches the background: the browser gives the
        // sender the opaque origin, which the router refuses before it reads a word.
        assert.equal((await fill("inject", { tabId, frameId: sandboxed.frameId, requestId: "req-sandbox" })).ok, true, channel);
        await new Promise((resolve) => setTimeout(resolve, 2_000));
        assert.equal((await fill("reports")).value.some((/** @type {any} */ r) => r.body?.request_id === "req-sandbox"), false, `${channel}: no report from the sandbox`);
      } else {
        // MV3: Firefox runs nothing in the sandboxed frame (no report, so it is never confirmed).
        assert.match(own.error, /host permission/i, `${channel}: ${own.error}`);
        assert.equal((await fill("inject", { tabId, frameId: sandboxed.frameId, requestId: "req-sandbox" })).ok, false, channel);
      }
      // The control: the top of the same page reports its real origin and is confirmed.
      const top = frames[0];
      assert.equal((await fill("inject", { tabId, frameId: 0, requestId: "req-top" })).ok, true);
      const topReport = await session.waitFor(async () => (await fill("reports")).value.find((/** @type {any} */ r) => r.body?.request_id === "req-top"), 10_000, "the top report");
      assert.equal(confirmFrame(top, topReport.body.self_origin), true, channel);
    } finally {
      await session.quit();
    }
  }
});

test("the_list_shows_the_core_host_flags_http_and_asks_for_a_frame_permission_in_the_grant_tab", async () => {
  for (const channel of channels()) {
    const { session, server, core, ui, visit, pageTab } = await open(channel);
    try {
      // A vault that is open without a key: the router lets the list through, and it has no items.
      assert.deepEqual(await core("measure_open"), { ok: true });

      // The host is the core's, whatever the page calls itself.
      let tabId = await visit(server.siteUrl("ferret-lookalike"));
      assert.match(await session.content(() => document.title), /Faithful Ferret/);
      let list = await ui("candidates", { tab_id: tabId });
      assert.deepEqual(list.host, { a_label: "evil.test", unicode: "evil.test" }, channel);
      assert.deepEqual(list.handles, []);
      tabId = await visit(server.siteUrl("lookalike-homograph"));
      list = await ui("candidates", { tab_id: tabId });
      assert.deepEqual(list.host, { a_label: HOMOGRAPH_A_LABEL_HOST, unicode: HOMOGRAPH_A_LABEL_HOST }, `${channel}: a label that mixes scripts keeps its A-label`);
      tabId = await visit(server.siteUrl("lookalike-confusable"));
      list = await ui("candidates", { tab_id: tabId });
      assert.deepEqual(list.host, { a_label: CONFUSABLE_A_LABEL_HOST, unicode: CONFUSABLE_UNICODE_HOST }, `${channel}: one script, shown in Unicode beside its A-label`);

      // Plain http is flagged; loopback is not.
      tabId = await visit(server.siteUrl("http-downgrade"));
      list = await ui("candidates", { tab_id: tabId });
      assert.equal(list.insecure, true, `${channel}: http`);
      tabId = await visit(server.siteUrl("loopback"));
      list = await ui("candidates", { tab_id: tabId });
      assert.equal(list.insecure, false, `${channel}: loopback`);
      tabId = await visit(server.siteUrl("login"));
      list = await ui("candidates", { tab_id: tabId });
      assert.equal(list.insecure, false, `${channel}: https`);
      assert.deepEqual(list.grant, []);

      // The same-site frame of another origin: with no item that matches it (this vault has none), it asks for
      // nothing. (The grant with a matching item is the end-to-end spec's.)
      tabId = await visit(server.siteUrl("framed-same-site"));
      list = await ui("candidates", { tab_id: tabId });
      const login = server.origin("login");
      assert.deepEqual(list.grant, [], `${channel}: no item matches the frame, so no permission is asked for`);
      const crossTab = await visit(server.siteUrl("framed-cross-site"));
      assert.deepEqual((await ui("candidates", { tab_id: crossTab })).grant, [], `${channel}: a cross-site frame is never offered a grant`);

      // The grant tab asks only for an origin a list named: neither this origin nor a page address gets a button.
      const grantTab = await session.newTab();
      await session.switchTo(grantTab);
      for (const origin of [login, `${login}/login`]) {
        await session.navigate(`${EXTENSION_ORIGIN}/pages/grant.html?${new URLSearchParams({ origin })}`);
        await session.waitFor(() => session.content(() => document.body.dataset.ready === "1"), 20_000, "the refused grant tab");
        assert.equal((await session.findAll('[data-role="grant-allow"]')).length, 0, `${channel}: ${origin}`);
        assert.equal((await session.findAll('[data-role="grant-invalid"]')).length, 1, `${channel}: ${origin}`);
      }
      await session.closeTab();
      await session.switchTo(pageTab);
    } finally {
      await session.quit();
    }
  }
});
