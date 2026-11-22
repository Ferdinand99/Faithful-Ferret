// Firefox probes for the core host: the WASM client starts in the background
// page and answers, in both manifest versions, and the background page leaves
// nothing on its global object for an extension page to find.
//
// Run by the Firefox runner with the test build:
//   FERRET_EXT_XPI    the .xpi of the test build under test
//   FERRET_EXT_UUID   the fixed extension UUID of the test profile
//   FERRET_EXT_CHANNEL "release" or "esr"
// The driver is test/firefox/driver.mjs (startFirefox, Session).
import assert from "node:assert/strict";
import { test } from "node:test";

const xpi = process.env.FERRET_EXT_XPI;
const uuid = process.env.FERRET_EXT_UUID;
const channel = process.env.FERRET_EXT_CHANNEL === "esr" ? "esr" : "release";
const skip = xpi && uuid ? false : "needs the Firefox runner (FERRET_EXT_XPI, FERRET_EXT_UUID)";

const AAGUID = "dc704a44b994410ca689ed8d71a84ac3";

/**
 * Opens the test bridge page of the extension and runs `body` with it.
 * @param {(session: any) => Promise<void>} body
 */
async function withBridge(body) {
  const { startFirefox } = await import("./driver.mjs");
  const session = await startFirefox({ channel, addon: xpi, headless: true });
  try {
    await session.navigate(`moz-extension://${uuid}/test/bridge.html`);
    await body(session);
  } finally {
    await session.quit();
  }
}

/** Sends one `{ op, args }` on the test port from the page and returns the reply. */
const callCore = (/** @type {any} */ session, /** @type {string} */ op, /** @type {unknown} */ args) =>
  session.execute(
    (/** @type {string} */ name, /** @type {unknown} */ params) =>
      new Promise((resolve, reject) => {
        const port = browser.runtime.connect({ name: "ferret-test-core" });
        const timer = setTimeout(() => reject(new Error("no answer")), 60_000);
        port.onMessage.addListener((reply) => {
          clearTimeout(timer);
          port.disconnect();
          resolve(reply);
        });
        port.postMessage({ id: "1", op: name, args: params });
      }),
    op,
    args,
  );

test("the_wasm_client_starts_in_the_background_page_and_answers_ping", { skip }, async () => {
  await withBridge(async (session) => {
    const reply = await callCore(session, "ping", undefined);
    assert.deepEqual(reply, { id: "1", ok: true, value: { ok: true, aaguid: AAGUID } });
    const refused = await callCore(session, "item_list", undefined);
    assert.deepEqual(refused, { id: "1", ok: false, code: "unknown_core_op" });
  });
});

test("argon2_bench_runs_in_the_job_worker", { skip }, async () => {
  await withBridge(async (session) => {
    const reply = await callCore(session, "argon2_bench", { m_kib: 65_536, t: 3, p: 1 });
    assert.equal(reply.ok, true);
    assert.equal(reply.value.key_length, 32);
    assert.ok(reply.value.ms > 0);
    // The vault is still locked: a bench is not an unlock.
    assert.equal(Object.hasOwn(reply.value, "key"), false);
  });
});

test("background_exposes_nothing_on_globalThis", { skip }, async () => {
  await withBridge(async (session) => {
    const found = await session.execute(async () => {
      const background = await browser.runtime.getBackgroundPage();
      if (!background) return { page: false, extra: [] };
      const own = new Set(Object.getOwnPropertyNames(window));
      const extra = Object.getOwnPropertyNames(background).filter((name) => !own.has(name));
      return { page: true, extra };
    });
    // Another extension page has every name the background page has, and the
    // background page has none that another page lacks: no client, no lock, no
    // core host, nothing of ours.
    assert.deepEqual(found.extra, []);
  });
});
