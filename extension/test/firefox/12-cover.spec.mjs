// The fill engine's extra pass for covers that hit testing cannot see, in real Firefox, on the static pages of
// coverPages.mjs: common sign-in layouts that must still be filled (floating labels, input groups, icons inside the
// field, a dark layer behind the card, a hidden overlay, a large page) and the covers that must be refused. The
// extension injects the fill script after a real shortcut (so Firefox grants activeTab), reports the fields of the
// frame and fills the password through the test build's probe port, as 10-fill.spec.mjs does.
import assert from "node:assert/strict";
import { after, test } from "node:test";
import { COVER_PAGES } from "./coverPages.mjs";
import {
  channels, commandOnPage, fixtures, launch, openBridge, stopFixtures, TEST_ADDON_ID, TEST_COMMAND, TEST_SHORTCUT,
} from "./harness.mjs";

process.env.FERRET_SSE_INTERVAL_MS ??= "300";
after(() => stopFixtures());

const PASSWORD = "correct horse battery staple";

test("covers_that_hit_testing_cannot_see_are_refused_and_common_sign_in_layouts_are_still_filled", async () => {
  for (const channel of channels()) {
    const session = await launch({ channel });
    try {
      const server = await fixtures();
      await session.waitFor(() => session.addonInfo(TEST_ADDON_ID), 30_000, "the add-on");
      const bridgeTab = await session.windowHandle();
      const bridge = await openBridge(session);

      /** Runs `body` in the bridge tab and goes back to `tab`. @template T @param {string} tab @param {() => Promise<T>} body */
      const fromBridge = async (tab, body) => {
        await session.switchTo(bridgeTab);
        try {
          return await body();
        } finally {
          await session.switchTo(tab);
        }
      };

      for (const page of COVER_PAGES) {
        const url = server.url(server.hosts[0], `/static/cover/${page.id}.html`);
        const origin = new URL(url).origin;
        const tab = await session.newTab();
        await session.switchTo(tab);
        await session.navigate(url);
        await session.waitFor(() => session.findAll("#password").then((found) => found.length === 1), 20_000, `the form of ${page.id}`);
        const what = `${channel}: ${page.id}`;

        /** One request on the probe port. @param {string} op @param {Record<string, unknown>} [args] */
        const probe = async (op, args = {}) => {
          const json = await fromBridge(tab, () => session.content((/** @type {string} */ name, /** @type {Record<string, unknown>} */ params) => new Promise((resolve, reject) => {
            const port = browser.runtime.connect({ name: "ferret-test-fill" });
            const timer = setTimeout(() => reject(new Error("the probe port did not answer")), 20_000);
            port.onMessage.addListener((reply) => {
              clearTimeout(timer);
              port.disconnect();
              resolve(JSON.stringify(reply));
            });
            port.postMessage({ id: "1", op: name, args: params });
          }), op, args));
          const reply = JSON.parse(json);
          assert.equal(reply.ok, true, `${what}: ${op}: ${reply.error}`);
          return reply.value;
        };

        const command = await commandOnPage({
          clear: () => fromBridge(tab, () => bridge.clearEvents()),
          press: () => session.pressShortcut(TEST_SHORTCUT),
          events: () => fromBridge(tab, () => bridge.events()),
        });
        assert.equal(command.name, TEST_COMMAND);
        assert.equal(command.tabUrl, url, `${channel}: activeTab was granted on ${page.id}`);
        const tabId = command.tabId;

        const requestId = `req-${page.id}`;
        await probe("clear");
        const startedAt = Date.now();
        await probe("inject", { tabId, frameId: 0, requestId });
        const reports = await session.waitFor(async () => {
          const all = await probe("reports");
          return all.some((r) => r.type === "frame_report") ? all : null;
        }, 20_000, `the frame report of ${page.id}`);
        const reportMs = Date.now() - startedAt;
        const report = reports.find((r) => r.type === "frame_report");
        const kinds = report.body.fields.map((/** @type {{ kind: string }} */ f) => f.kind);

        let fillMs = 0;
        if (page.expect === "fill") {
          assert.ok(kinds.includes("password"), `${what}: the password field is reported (${page.summary}); got ${JSON.stringify(kinds)}`);
          await probe("clear");
          const filling = Date.now();
          await probe("fill", { tabId, frameId: 0, requestId, field: "password", value: PASSWORD, origin, frameUrl: url });
          const result = await session.waitFor(async () => (await probe("reports")).find((r) => r.type === "fill_result"), 10_000, `the fill result of ${page.id}`);
          fillMs = Date.now() - filling;
          assert.deepEqual(result.body, { request_id: requestId, ok: true }, `${what}: the password goes in`);
          assert.equal(await session.content(() => document.getElementById("password").value), PASSWORD, `${what}: the page holds the password`);
        } else {
          let refused = !kinds.includes("password");
          if (!refused) {
            await probe("clear");
            await probe("fill", { tabId, frameId: 0, requestId, field: "password", value: PASSWORD, origin, frameUrl: url });
            const result = await session.waitFor(async () => (await probe("reports")).find((r) => r.type === "fill_result"), 10_000, `the fill result of ${page.id}`);
            refused = result.body.ok === false;
          }
          assert.ok(refused, `${what}: the fill is refused (${page.summary})`);
          assert.equal(await session.content(() => document.getElementById("password").value), "", `${what}: nothing is in the field`);
        }
        console.log(`# cover ${what} ${page.expect}: report ${reportMs} ms, fill ${fillMs} ms`);
        await session.closeTab();
        await session.switchTo(bridgeTab);
      }
    } finally {
      await session.quit();
    }
  }
});
