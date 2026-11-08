// The fill engine in real Firefox: the extension injects the fill script into a
// fixture sign-in page after a real shortcut (so Firefox grants activeTab), the
// script reports the fields of the frame, and one value for each of the two
// fields goes in through the native setter while the page sees input and change.
// The test build's probe port (src/background/test-only/fillProbe.mjs) stands
// in for the background's fill flow, which a later step builds.
import assert from "node:assert/strict";
import { after, test } from "node:test";
import {
  channels, fixtures, launch, openBridge, stopFixtures, TEST_ADDON_ID, TEST_COMMAND, TEST_SHORTCUT,
} from "./harness.mjs";

process.env.FERRET_SSE_INTERVAL_MS ??= "300";
after(() => stopFixtures());

const USER = "alice@fixture.example";
const PASSWORD = "correct horse battery staple";

test("fill_on_the_fixture_login_page_puts_both_values_in_and_the_page_sees_them", async () => {
  for (const channel of channels()) {
    const session = await launch({ channel });
    try {
      const server = await fixtures();
      await session.waitFor(() => session.addonInfo(TEST_ADDON_ID), 30_000, "the add-on");
      const bridgeTab = await session.windowHandle();
      const bridge = await openBridge(session);

      const url = server.url(server.hosts[0], "/static/login.html");
      const origin = new URL(url).origin;
      const pageTab = await session.newTab();
      await session.switchTo(pageTab);
      await session.navigate(url);
      await session.waitFor(() => session.findAll("#username").then((found) => found.length === 1), 10_000, "the sign-in form");

      /** Runs `body` in the bridge tab and goes back to the page tab. @template T @param {() => Promise<T>} body */
      const fromBridge = async (body) => {
        await session.switchTo(bridgeTab);
        try {
          return await body();
        } finally {
          await session.switchTo(pageTab);
        }
      };
      /** One request on the probe port. @param {string} op @param {Record<string, unknown>} [args] */
      const probe = async (op, args = {}) => {
        const json = await fromBridge(() => session.content((/** @type {string} */ name, /** @type {Record<string, unknown>} */ params) => new Promise((resolve, reject) => {
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
        assert.equal(reply.ok, true, `${channel}: ${op}: ${reply.error}`);
        return reply.value;
      };
      const value = (/** @type {string} */ id) => session.content((/** @type {string} */ field) => document.getElementById(field).value, id);

      // A real shortcut on the page tab: Firefox grants activeTab for it.
      await session.pressShortcut(TEST_SHORTCUT);
      const command = await session.waitFor(
        async () => (await fromBridge(() => bridge.events())).find((e) => e.kind === "command"), 10_000, "the command event");
      assert.equal(command.name, TEST_COMMAND);
      assert.equal(command.tabUrl, url, `${channel}: activeTab was granted`);
      const tabId = command.tabId;

      // The page records what it sees: every input and change event, with the value at that moment.
      await session.content(() => {
        const log = [];
        document.documentElement.dataset.seen = "[]";
        for (const id of ["username", "password"]) {
          for (const type of ["input", "change"]) {
            document.getElementById(id).addEventListener(type, (event) => {
              log.push(`${id}:${type}:${event.target.value}`);
              document.documentElement.dataset.seen = JSON.stringify(log);
            });
          }
        }
      });

      // Before anything is injected, a fill message reaches no one: nothing is in the page.
      const early = await probe("fill", { tabId, frameId: 0, requestId: "req-early", field: "password", value: PASSWORD, origin, frameUrl: url });
      assert.deepEqual(early, { delivered: false });
      assert.equal(await value("password"), "");

      // Inject and report.
      await probe("inject", { tabId, frameId: 0, requestId: "req-fill-1" });
      const reports = await session.waitFor(async () => {
        const all = await probe("reports");
        return all.some((r) => r.type === "frame_report") ? all : null;
      }, 10_000, "the frame report");
      const report = reports.find((r) => r.type === "frame_report");
      assert.equal(report.body.request_id, "req-fill-1");
      assert.equal(report.body.self_origin, origin, `${channel}: the script's own origin`);
      assert.equal(report.senderOrigin, origin, `${channel}: the browser's origin of the sender`);
      assert.deepEqual(report.body.fields.map((/** @type {{ kind: string }} */ f) => f.kind), ["username", "password"]);
      for (const { id } of report.body.fields) assert.match(id, /^[0-9a-f]{32}$/);
      assert.equal(report.frameId, 0);

      // A second injection finds the same engine and reports again.
      await probe("inject", { tabId, frameId: 0, requestId: "req-fill-2" });
      await session.waitFor(async () => (await probe("reports")).some((r) => r.body?.request_id === "req-fill-2"), 10_000, "the second report");

      // The replaced request id no longer fills.
      await probe("fill", { tabId, frameId: 0, requestId: "req-fill-1", field: "password", value: PASSWORD, origin, frameUrl: url });
      assert.equal(await value("password"), "", `${channel}: the replaced request does nothing`);

      // A wrong address is refused and nothing is written.
      await probe("clear");
      await probe("fill", { tabId, frameId: 0, requestId: "req-fill-2", field: "password", value: PASSWORD, origin, frameUrl: `${url}#moved` });
      const refused = await session.waitFor(async () => (await probe("reports")).find((r) => r.type === "fill_result"), 10_000, "the refusal");
      assert.deepEqual(refused.body, { request_id: "req-fill-2", ok: false, reason: "origin_changed" });
      assert.equal(await value("password"), "");

      // The refusal ended that request: start another, then fill both fields.
      await probe("inject", { tabId, frameId: 0, requestId: "req-fill-3" });
      await probe("clear");
      await probe("fill", { tabId, frameId: 0, requestId: "req-fill-3", field: "username", value: USER, origin, frameUrl: url });
      await probe("fill", { tabId, frameId: 0, requestId: "req-fill-3", field: "password", value: PASSWORD, origin, frameUrl: url });
      const results = await session.waitFor(async () => {
        const found = (await probe("reports")).filter((r) => r.type === "fill_result");
        return found.length === 2 ? found : null;
      }, 10_000, "two fill results");
      assert.deepEqual(results.map((r) => r.body), [
        { request_id: "req-fill-3", ok: true },
        { request_id: "req-fill-3", ok: true },
      ]);
      // The answers carry no value.
      assert.equal(JSON.stringify(results).includes(PASSWORD), false);
      assert.equal(JSON.stringify(results).includes(USER), false);

      assert.equal(await value("username"), USER);
      assert.equal(await value("password"), PASSWORD);
      const seen = JSON.parse(await session.content(() => document.documentElement.dataset.seen));
      assert.deepEqual(seen, [
        `username:input:${USER}`, `username:change:${USER}`,
        `password:input:${PASSWORD}`, `password:change:${PASSWORD}`,
      ], `${channel}: the page saw input and change`);

      // A field the page hides after the report is not filled.
      await probe("inject", { tabId, frameId: 0, requestId: "req-fill-4" });
      await session.content(() => {
        document.getElementById("password").value = "";
        document.getElementById("password").style.opacity = "0.5";
      });
      await probe("clear");
      await probe("fill", { tabId, frameId: 0, requestId: "req-fill-4", field: "password", value: PASSWORD, origin, frameUrl: url });
      const hidden = await session.waitFor(async () => (await probe("reports")).find((r) => r.type === "fill_result"), 10_000, "the hidden refusal");
      assert.deepEqual(hidden.body, { request_id: "req-fill-4", ok: false, reason: "hidden" });
      assert.equal(await value("password"), "");
    } finally {
      await session.quit();
    }
  }
});
