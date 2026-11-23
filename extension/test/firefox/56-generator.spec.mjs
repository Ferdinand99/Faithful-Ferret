// The fill engine's mode for a generated password in real Firefox: the extension injects the fill script into the
// fixture sign-up page after a real shortcut (so Firefox grants activeTab); the script, asked in the mode of a
// generated fill, reports the new and the confirm field with the `maxlength` of each, and no field to a sign-in request; one
// value for each of the two fields goes in through the native setter while the page sees input and change, and a value
// longer than the field takes is refused.
// The test build's probe port (src/background/test-only/fillProbe.mjs) stands in for the background's fill flow, which
// needs an open vault; the flow itself is tested with a fake core in fillGenerated.test.mjs.
import assert from "node:assert/strict";
import { after, test } from "node:test";
import {
  channels, fixtures, launch, openBridge, stopFixtures, TEST_ADDON_ID, TEST_COMMAND, TEST_SHORTCUT,
} from "./harness.mjs";

process.env.FERRET_SSE_INTERVAL_MS ??= "300";
after(() => stopFixtures());

const GENERATED = "Gen3rated-pass-word!";

test("generated_fill_on_the_fixture_sign_up_page_reports_and_fills_the_new_and_the_confirm_field", async () => {
  for (const channel of channels()) {
    const session = await launch({ channel });
    try {
      const server = await fixtures();
      await session.waitFor(() => session.addonInfo(TEST_ADDON_ID), 30_000, "the add-on");
      const bridgeTab = await session.windowHandle();
      const bridge = await openBridge(session);

      const url = server.url(server.hosts[0], "/static/signup.html");
      const origin = new URL(url).origin;
      const pageTab = await session.newTab();
      await session.switchTo(pageTab);
      await session.navigate(url);
      await session.waitFor(() => session.findAll("#new-password").then((found) => found.length === 1), 10_000, "the sign-up form");

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

      await session.pressShortcut(TEST_SHORTCUT);
      const command = await session.waitFor(
        async () => (await fromBridge(() => bridge.events())).find((e) => e.kind === "command"), 10_000, "the command event");
      assert.equal(command.name, TEST_COMMAND);
      assert.equal(command.tabUrl, url, `${channel}: activeTab was granted`);
      const tabId = command.tabId;

      await session.content(() => {
        const log = [];
        document.documentElement.dataset.seen = "[]";
        for (const id of ["new-password", "confirm-password"]) {
          for (const type of ["input", "change"]) {
            document.getElementById(id).addEventListener(type, (event) => {
              log.push(`${id}:${type}:${event.target.value}`);
              document.documentElement.dataset.seen = JSON.stringify(log);
            });
          }
        }
      });

      // A sign-in request on a sign-up page reports no field: nothing there is a sign-in field.
      await probe("inject", { tabId, frameId: 0, requestId: "req-sign-in" });
      const first = await session.waitFor(async () => (await probe("reports")).find((r) => r.type === "frame_report"), 10_000, "the sign-in report");
      assert.deepEqual(first.body.fields, []);

      // A generated request reports the new and the confirm field, with the new field's maxlength.
      await probe("clear");
      await probe("inject", { tabId, frameId: 0, requestId: "req-gen-1", mode: "generated" });
      const report = await session.waitFor(async () => (await probe("reports")).find((r) => r.type === "frame_report"), 10_000, "the generated report");
      assert.equal(report.body.request_id, "req-gen-1");
      assert.equal(report.body.self_origin, origin);
      assert.deepEqual(report.body.fields.map((/** @type {{ kind: string, max?: number }} */ f) => [f.kind, f.max]), [["new_password", 24], ["confirm_password", undefined]], channel);
      for (const { id } of report.body.fields) assert.match(id, /^[0-9a-f]{32}$/);

      // A value longer than the field takes is refused, and nothing is written.
      await probe("clear");
      await probe("fill", { tabId, frameId: 0, requestId: "req-gen-1", field: "new_password", value: "x".repeat(25), origin, frameUrl: url });
      const tooLong = await session.waitFor(async () => (await probe("reports")).find((r) => r.type === "fill_result"), 10_000, "the refusal");
      assert.deepEqual(tooLong.body, { request_id: "req-gen-1", ok: false, reason: "value_too_long" });
      assert.equal(await value("new-password"), "");

      // Both fields get the value; the page sees input and change on each, and a sign-in kind is not a kind of this request.
      await probe("clear");
      await probe("fill", { tabId, frameId: 0, requestId: "req-gen-1", field: "new_password", value: GENERATED, origin, frameUrl: url });
      await probe("fill", { tabId, frameId: 0, requestId: "req-gen-1", field: "confirm_password", value: GENERATED, origin, frameUrl: url });
      await probe("fill", { tabId, frameId: 0, requestId: "req-gen-1", field: "password", value: GENERATED, origin, frameUrl: url });
      const results = await session.waitFor(async () => {
        const found = (await probe("reports")).filter((r) => r.type === "fill_result");
        return found.length === 3 ? found : null;
      }, 10_000, "three fill results");
      assert.deepEqual(results.map((r) => r.body), [
        { request_id: "req-gen-1", ok: true },
        { request_id: "req-gen-1", ok: true },
        { request_id: "req-gen-1", ok: false, reason: "wrong_kind" },
      ]);
      assert.equal(JSON.stringify(results).includes(GENERATED), false, "the answers carry no value");
      assert.equal(await value("new-password"), GENERATED);
      assert.equal(await value("confirm-password"), GENERATED);
      assert.equal(await value("email"), "");
      const seen = JSON.parse(await session.content(() => document.documentElement.dataset.seen));
      assert.deepEqual(seen, [
        `new-password:input:${GENERATED}`, `new-password:change:${GENERATED}`,
        `confirm-password:input:${GENERATED}`, `confirm-password:change:${GENERATED}`,
      ], `${channel}: the page saw input and change`);
    } finally {
      await session.quit();
    }
  }
});
