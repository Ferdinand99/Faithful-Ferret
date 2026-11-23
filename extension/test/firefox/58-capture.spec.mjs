// The capture script's footprint in real Firefox (the test build, Release and ESR): what it costs on a page of about
// two thousand elements, at rest and on a page that changes all the time, and that it works in the content script's
// world (the browser's own `isTrusted`, `composedPath` and the page behind its wrappers).
//
// The script is put into the page the way the fill engine is (a real shortcut gives `activeTab`; the test build's probe
// port injects the files), between two small files that time it (test/capture-meter-start.js and -end.js): the first
// wraps the window's `addEventListener` and `setTimeout` so that every listener and timer the script registers is
// timed, the second stops the clock for the script's own start. What a listener or a timer costs afterwards adds up in
// the meter, which the probe reads. Timer precision is switched off in the test profile, so that the numbers are not
// rounded to a millisecond.
//
//   capture_costs_under_2_ms_at_idle_on_a_page_with_2000_nodes
//       the script's start and everything its timers run in the next 2.5 seconds, the median of three fresh pages: under
//       2 ms on a page with no password field, under 5 ms on one with a sign-in form (which it reports once)
//   capture_costs_under_2_ms_per_second_on_a_mutating_spa_for_5_seconds
//       everything the script ran in five seconds on a page whose elements change ten times a second, with the person
//       typing a user name and a password in it; and what the submission then costs (one walk of the page)
//   capture_page_ready_in_real_firefox_needs_a_password_field_the_person_can_see
//       a password field that is not displayed, transparent, hidden, aria-hidden or too small is not reported
//   capture_in_real_firefox_sends_what_the_person_typed_and_nothing_the_page_wrote
//       a typed form is sent once with the typed values; a value the page wrote over it is not sent
import assert from "node:assert/strict";
import { after, test } from "node:test";
import {
  channels, fixtures, launch, openBridge, stopFixtures, TEST_COMMAND, TEST_SHORTCUT,
} from "./harness.mjs";

process.env.FERRET_SSE_INTERVAL_MS ??= "300";
after(() => stopFixtures());

const HOST = "forms.example.net";
const FILES = ["test/capture-meter-start.js", "content/capture.inject.js", "test/capture-meter-end.js"];
const sleep = (/** @type {number} */ ms) => new Promise((done) => setTimeout(done, ms));
const PASSWORD = "Zq7!footprint-Vm4$";

/**
 * Firefox with the test build, a bridge tab and a page tab, and the calls these tests make.
 * @param {"release" | "esr"} channel
 */
async function setup(channel) {
  const session = await launch({ channel, prefs: { "privacy.reduceTimerPrecision": false } });
  const server = await fixtures();
  await session.waitFor(() => session.addonInfo("ferret-test@hedgerow.tools"), 30_000, "the add-on");
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

  /** Opens a page of the corpus folder, gives the page `activeTab` with the real shortcut, and returns the tab. @param {string} path */
  const openPage = async (path) => {
    await session.switchTo(pageTab);
    const url = server.url(HOST, path);
    await session.navigate(url);
    await session.waitFor(() => session.content(() => document.readyState === "complete" && document.getElementById("app") !== null), 15_000, "the page");
    await fromBridge(() => bridge.clearEvents());
    await session.pressShortcut(TEST_SHORTCUT);
    const command = await session.waitFor(
      async () => (await fromBridge(() => bridge.events())).find((e) => e.kind === "command"), 10_000, "the command event");
    assert.equal(command.name, TEST_COMMAND);
    assert.equal(command.tabUrl, url, `${channel}: activeTab was granted`);
    await probe("clear");
    return { tabId: /** @type {number} */ (command.tabId), url };
  };

  const inject = async (/** @type {number} */ tabId, files = FILES) => {
    const { loaded } = await probe("inject_files", { tabId, frameId: 0, files });
    assert.equal(loaded, true, `${channel}: the capture script loaded`);
  };

  /** The message types the page's script has sent, in order. */
  const types = async () => (await probe("reports")).map((/** @type {{ type: string }} */ r) => r.type);

  return { session, probe, openPage, inject, types, reports: () => probe("reports") };
}

/** @param {number[]} values */
const median = (values) => [...values].sort((a, b) => a - b)[Math.floor(values.length / 2)];

test("capture_costs_under_2_ms_at_idle_on_a_page_with_2000_nodes", async () => {
  for (const channel of channels()) {
    const { session, probe, openPage, inject, types } = await setup(channel);
    try {
      // What the script costs on a page with nothing to report (no password field) and on one with a sign-in form (which
      // it reports with one page_ready): its start and everything its timers run in the next 2.5 seconds.
      for (const [path, bound, sent] of /** @type {Array<[string, number, string[]]>} */ ([["/_capture-idle/", 2, []], ["/_capture-login/", 5, ["page_ready"]]])) {
        const costs = [];
        for (let run = 0; run < 3; run += 1) {
          const { tabId } = await openPage(path);
          const nodes = await session.content(() => document.getElementsByTagName("*").length);
          assert.ok(nodes >= 2000, `${channel}: the page has ${nodes} elements`);
          await inject(tabId);
          await sleep(2500);
          const meter = await probe("meter", { tabId, frameId: 0 });
          assert.ok(meter, `${channel}: the meter is in the page`);
          // The meter saw the script's listeners and its timers: it timed what it is meant to time.
          assert.ok(meter.listeners >= 4, `${channel}: the meter saw ${meter.listeners} listeners`);
          assert.ok(meter.timers >= 1, `${channel}: the meter saw ${meter.timers} timers`);
          assert.ok(meter.calls >= 1, `${channel}: a timer ran`);
          costs.push(meter.startMs + meter.ms);
          assert.deepEqual(await types(), sent, `${channel}: ${path}: what it sent at rest`);
        }
        const cost = median(costs);
        assert.ok(cost < bound, `${channel}: ${path}: the capture script took ${cost.toFixed(2)} ms (runs: ${costs.map((c) => c.toFixed(2)).join(", ")}), the bound is ${bound} ms`);
      }
    } finally {
      await session.quit();
    }
  }
});

test("capture_costs_under_2_ms_per_second_on_a_mutating_spa_for_5_seconds", async () => {
  for (const channel of channels()) {
    const { session, probe, openPage, inject, reports } = await setup(channel);
    try {
      const { tabId } = await openPage("/_capture-spa/");
      assert.ok((await session.content(() => document.getElementsByTagName("*").length)) >= 2000);
      await inject(tabId);
      // The page changes ten times a second from now on. The person types a user name and a password in it.
      const [user] = await session.findAll("#u");
      const [pass] = await session.findAll("#p");
      await session.type(user, "anna");
      await session.type(pass, PASSWORD);
      await sleep(5200);
      const rest = await probe("meter", { tabId, frameId: 0 });
      assert.ok(rest.now >= 5000, `${channel}: the window is ${rest.now} ms`);
      assert.ok(rest.calls >= "anna".length + PASSWORD.length, `${channel}: the meter timed the typing (${rest.calls} calls)`);
      const perSecond = (rest.startMs + rest.ms) / (rest.now / 1000);
      assert.ok(perSecond < 2, `${channel}: ${perSecond.toFixed(3)} ms per second over ${(rest.now / 1000).toFixed(1)} s (${rest.calls} calls)`);

      // The submission is the one time the script walks the page: it reads the form once, on a page of 2000 elements.
      const before = rest.ms;
      const [go] = await session.findAll("#go");
      await session.click(go);
      const sent = await session.waitFor(async () => {
        const found = (await reports()).filter((/** @type {{ type: string }} */ r) => r.type === "form_capture");
        return found.length > 0 ? found : null;
      }, 10_000, "the capture");
      assert.equal(sent.length, 1);
      assert.deepEqual({ ...sent[0].body, capture_id: "x" }, {
        capture_id: "x", self_origin: `https://${HOST}`, kind: "login", username: "anna", username_from: "typed", password: PASSWORD, current_password: null,
      });
      const after = await probe("meter", { tabId, frameId: 0 });
      const walk = after.ms - before;
      assert.ok(walk < 50, `${channel}: the submission took ${walk.toFixed(1)} ms on a page of 2000 elements`);
    } finally {
      await session.quit();
    }
  }
});

test("capture_in_real_firefox_sends_what_the_person_typed_and_nothing_the_page_wrote", async () => {
  for (const channel of channels()) {
    const { session, openPage, inject, reports } = await setup(channel);
    try {
      const { tabId } = await openPage("/_capture-login/");
      await inject(tabId, ["content/capture.inject.js"]);
      const [user] = await session.findAll("#u");
      const [pass] = await session.findAll("#p");
      const [go] = await session.findAll("#go");
      const captures = async () => (await reports()).filter((/** @type {{ type: string }} */ r) => r.type === "form_capture");

      // The page writes over what the person typed (no event): nothing is sent.
      await session.type(user, "anna");
      await session.type(pass, "typed-first");
      await session.content(() => { /** @type {HTMLInputElement} */ (document.getElementById("p")).value = "written-by-the-page"; });
      await session.click(go);
      await sleep(1000);
      assert.deepEqual(await captures(), [], `${channel}: a value the page wrote is not sent`);

      // A value the page writes with an event of its own (not the browser's) is not the person's either.
      await sleep(2200);
      await session.content(() => {
        const field = /** @type {HTMLInputElement} */ (document.getElementById("p"));
        field.value = "scripted";
        field.dispatchEvent(new Event("input", { bubbles: true }));
      });
      await session.click(go);
      await sleep(1000);
      assert.deepEqual(await captures(), [], `${channel}: a value a script wrote with its own input event is not sent`);

      // The person types again: the field is theirs, and the submission is sent once, with the typed values.
      await sleep(2200);
      await session.content(() => { /** @type {HTMLInputElement} */ (document.getElementById("p")).value = ""; });
      await session.type(pass, PASSWORD);
      await session.click(go);
      const sent = await session.waitFor(async () => {
        const found = await captures();
        return found.length > 0 ? found : null;
      }, 10_000, "the capture");
      await sleep(800);
      assert.equal((await captures()).length, 1, `${channel}: one capture`);
      assert.deepEqual({ ...sent[0].body, capture_id: "x" }, {
        capture_id: "x", self_origin: `https://${HOST}`, kind: "login", username: "anna", username_from: "typed", password: PASSWORD, current_password: null,
      });
      assert.equal(sent[0].senderOrigin, `https://${HOST}`, `${channel}: the browser's origin of the sender`);
    } finally {
      await session.quit();
    }
  }
});

test("capture_page_ready_in_real_firefox_needs_a_password_field_the_person_can_see", async () => {
  for (const channel of channels()) {
    const { session, openPage, inject, types } = await setup(channel);
    try {
      /** @type {Array<[string, () => void]>} */
      const hiding = [
        ["display none", () => { /** @type {HTMLElement} */ (document.getElementById("p")).style.display = "none"; }],
        ["a parent that is not displayed", () => { /** @type {HTMLElement} */ (document.getElementById("login")).style.display = "none"; }],
        ["visibility hidden", () => { /** @type {HTMLElement} */ (document.getElementById("p")).style.visibility = "hidden"; }],
        ["opacity 0", () => { /** @type {HTMLElement} */ (document.getElementById("p")).style.opacity = "0"; }],
        ["aria-hidden on a parent", () => { /** @type {HTMLElement} */ (document.getElementById("login")).setAttribute("aria-hidden", "true"); }],
        ["one pixel", () => { const p = /** @type {HTMLElement} */ (document.getElementById("p")); p.style.width = "1px"; p.style.height = "1px"; p.style.padding = "0"; }],
        ["off the page", () => { const p = /** @type {HTMLElement} */ (document.getElementById("p")); p.style.position = "absolute"; p.style.left = "-9999px"; }],
        ["covered", () => {
          const cover = document.createElement("div");
          cover.style.cssText = "position:absolute;z-index:9;background:#fff;left:0;top:0;width:100%;height:100%";
          document.body.appendChild(cover);
        }],
      ];
      for (const [label, hide] of hiding) {
        const { tabId } = await openPage("/_capture-login/");
        await session.content(hide);
        await inject(tabId, ["content/capture.inject.js"]);
        await sleep(2200);
        assert.deepEqual(await types(), [], `${channel}: no page_ready with a password field that is ${label}`);
      }
      // Control: the same page with nothing done to the field reports it, once.
      const { tabId } = await openPage("/_capture-login/");
      await inject(tabId, ["content/capture.inject.js"]);
      await sleep(2200);
      assert.deepEqual(await types(), ["page_ready"], `${channel}: a field the person can see is reported`);
    } finally {
      await session.quit();
    }
  }
});
