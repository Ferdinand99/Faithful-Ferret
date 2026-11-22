// The list a page is offered, with a real vault, against the end-to-end stack
// (run by the e2e mode of the Firefox runner) and the test sites: a real server,
// the real core, the sync engine of the extension and the real frame rules.
//
// - The entries of the test sites (a host entry, a domain entry and an http
//   entry for login.example.net, an http entry for the loopback address and a
//   domain entry on a private suffix) are made with the sync engine. Every row of
//   the test sites that expects no offer gets no item for that entry (in the
//   frame, for a row about a frame), and a row where no entry is offered gets an
//   empty list. The rows that expect an offer are the control.
// - 1000 items are matched within 300 ms in Firefox, and every handle is closed.
//
// The account is the one the sign-in specs made (or this spec makes it).
import assert from "node:assert/strict";
import { after, test } from "node:test";
import { ORIGINS, SITES } from "../fixtures/sites/index.mjs";
import { POPUP_URL, SLOW, extensionSignIn, helpers, start, webVaultAccount } from "./e2e.mjs";
import { EXTENSION_ORIGIN, channels, fixtures, openBridge, stopFixtures, TEST_SHORTCUT } from "./harness.mjs";

after(() => stopFixtures());

/** The entries, by the key of the sites' expectations that speaks of them. */
const ENTRIES = Object.freeze({
  host: { name: "Host entry", url: "https://login.example.net/", matching: "host", username: "ola" },
  domain: { name: "Domain entry", url: "https://login.example.net/", matching: "domain", username: "ola" },
  http: { name: "Http entry", url: "http://login.example.net/", matching: "host", username: "ola" },
  loopback: { name: "Loopback entry", url: "http://127.0.0.1/", matching: "host", username: "ola" },
  // The test sites' domain entry on a private suffix of the real list (its host is in the sites' table).
  github: { name: "Github entry", url: `https://${ORIGINS.ghA.host}/`, matching: "domain", username: "ola" },
});

/** The outcomes this spec checks; the others (fields, clickjacking, navigation) belong to the fill's specs. */
const CHECKED = new Set(["no_offer", "no_offer_in_frame", "fill", "fill_in_frame", "offer_with_warning"]);

/**
 * Which entry each expectation of a site speaks of.
 * @param {any} site
 * @returns {Array<[string, keyof typeof ENTRIES]>} pairs of the outcome and the entry
 */
function expectations(site) {
  const e = site.expect;
  const loopback = site.origin === "loopback";
  /** @type {Array<[string, keyof typeof ENTRIES]>} */
  const out = [];
  if (typeof e.outcome === "string") out.push([e.outcome, typeof e.entry === "string" && e.entry.includes("github") ? "github" : "host"]);
  if (typeof e.domain_entry === "string") out.push([e.domain_entry, "domain"]);
  if (typeof e.http_entry === "string") out.push([e.http_entry, loopback ? "loopback" : "http"]);
  return out.filter(([outcome]) => CHECKED.has(outcome));
}

/** @param {string} channel */
async function signedIn(channel) {
  const session = await start(channel);
  const account = await webVaultAccount(session, channel);
  const bridgeTab = await session.newTab();
  await session.switchTo(bridgeTab);
  const signed = await extensionSignIn(session, account);
  assert.equal(signed.ok, true, `${channel}: ${signed.text}`);
  const page = helpers(session);
  await session.navigate(POPUP_URL);
  await page.ready();
  await page.waitVisible('[data-role="sync"][data-state="idle"]', SLOW);
  const bridge = await openBridge(session);
  const pageTab = await session.newTab();
  await session.switchTo(pageTab);

  /** @template T @param {() => Promise<T>} body */
  const fromBridge = async (body) => {
    await session.switchTo(bridgeTab);
    try {
      return await body();
    } finally {
      await session.switchTo(pageTab);
    }
  };
  /** @param {string} name @param {unknown} message */
  const ask = (name, message) =>
    fromBridge(async () => JSON.parse(await session.content((/** @type {string} */ portName, /** @type {string} */ text) => new Promise((resolve, reject) => {
      const port = browser.runtime.connect({ name: portName });
      const timer = setTimeout(() => reject(new Error(`${portName} did not answer`)), 120_000);
      port.onMessage.addListener((reply) => {
        clearTimeout(timer);
        port.disconnect();
        resolve(typeof reply === "string" ? reply : JSON.stringify(reply));
      });
      port.onDisconnect.addListener(() => reject(new Error(`${portName} hung up`)));
      port.postMessage(JSON.parse(text));
    }), name, JSON.stringify(message))));
  /** @param {string} op @param {Record<string, unknown>} [args] */
  const core = async (op, args = {}) => {
    const reply = await ask("ferret-test-core", { id: "1", op, args });
    assert.equal(reply.ok, true, `${channel}: ${op}: ${reply.code}`);
    return reply.value;
  };
  /** @param {string} type @param {Record<string, unknown>} body */
  const ui = async (type, body) => {
    const reply = await ask("ferret-ui", JSON.stringify({ v: 1, id: "t1", type, body }));
    assert.equal(reply.type, type, `${channel}: ${type}: ${JSON.stringify(reply.body)}`);
    return reply.body;
  };
  /** @param {string} url */
  const visit = async (url) => {
    await fromBridge(() => bridge.clearEvents());
    await session.navigate(url);
    await session.waitFor(() => session.content(() => document.readyState === "complete"), 15_000, url);
    await session.pressShortcut(TEST_SHORTCUT);
    const command = await session.waitFor(async () => (await fromBridge(() => bridge.events())).find((e) => e.kind === "command"), 15_000, "the command event");
    return /** @type {number} */ (command.tabId);
  };
  return { session, core, ui, visit, pageTab };
}

test("every_no_offer_row_of_the_fixtures_gives_an_empty_list", async () => {
  const server = await fixtures();
  for (const channel of channels()) {
    const { session, core, ui, visit, pageTab } = await signedIn(channel);
    try {
      // The entries (the extension writes no items in this release; the test build's probe uses the sync engine).
      const tag = `${channel}-${Date.now().toString(36)}`;
      /** @type {Record<string, string>} */
      const named = {};
      for (const [key, entry] of Object.entries(ENTRIES)) {
        named[key] = `${entry.name} ${tag}`;
        await core("item_probe", { ...entry, name: named[key] });
      }
      const ours = (/** @type {any[]} */ items) => items.filter((i) => Object.values(named).includes(i.name));
      const keyOf = (/** @type {string} */ name) => Object.keys(named).find((k) => named[k] === name);
      // The engine has them once the login page is offered the host and the domain entry.
      let tabId = await visit(server.siteUrl("login"));
      await session.waitFor(async () => ours((await ui("candidates", { tab_id: tabId })).items).length === 2, 30_000, "the new entries");

      // The same-site frame of another origin is granted once (as a person does in the grant tab), so the rows that
      // fill in that frame are a real control.
      const grantTab = await session.newTab();
      await session.switchTo(grantTab);
      await session.navigate(`${EXTENSION_ORIGIN}/pages/grant.html?${new URLSearchParams({ origin: server.origin("login") })}`);
      await session.waitFor(() => session.content(() => document.body.dataset.ready === "1"), 20_000, "the grant tab");
      const [allow] = await session.findAll('[data-role="grant-allow"]');
      await session.click(allow);
      await session.waitFor(() => session.content(() => document.querySelector('[data-role="grant-status"]')?.getAttribute("data-outcome") === "granted"), 20_000, "the grant");
      await session.closeTab();
      await session.switchTo(pageTab);

      let checked = 0;
      let empty = 0;
      for (const site of SITES) {
        const rows = expectations(site);
        if (rows.length === 0) continue;
        tabId = await visit(server.siteUrl(site.id));
        const list = await ui("candidates", { tab_id: tabId });
        const items = ours(list.items);
        const where = `${channel} ${site.id}`;
        for (const [outcome, key] of rows) {
          const found = items.filter((i) => keyOf(i.name) === key);
          if (outcome === "no_offer") assert.deepEqual(found, [], `${where}: the ${key} entry is not offered`);
          if (outcome === "no_offer_in_frame") assert.deepEqual(found.filter((i) => i.frame_id !== 0), [], `${where}: the ${key} entry is not offered in a frame`);
          if (outcome === "fill") assert.ok(found.some((i) => i.frame_id === 0), `${where}: the ${key} entry is offered (${JSON.stringify(list)})`);
          if (outcome === "fill_in_frame") assert.ok(found.some((i) => i.frame_id !== 0), `${where}: the ${key} entry is offered in the frame (${JSON.stringify(list)})`);
          if (outcome === "offer_with_warning") {
            assert.ok(found.some((i) => i.frame_id === 0), `${where}: the ${key} entry is offered`);
            assert.equal(list.insecure, true, `${where}: with the warning`);
          }
          checked += 1;
        }
        // A row where no entry is offered anywhere gets an empty list.
        if (rows.every(([outcome]) => outcome === "no_offer")) {
          assert.deepEqual(items, [], `${where}: an empty list`);
          empty += 1;
        }
      }
      assert.ok(checked >= 40 && empty >= 8, `${channel}: ${checked} expectations, ${empty} empty lists`);
    } finally {
      await session.quit();
    }
  }
});

test("matching_1000_items_stays_within_300_ms_and_closes_every_handle", async () => {
  for (const channel of channels()) {
    const { session, core } = await signedIn(channel);
    try {
      const bench = await core("match_bench", { n: 1000, url: "https://login.example.net/", other: "https://shop.example.net/" });
      assert.equal(bench.items, 1000);
      assert.equal(bench.matched, 100, `${channel}: every tenth item is for the page`);
      assert.equal(bench.opened, 1000, channel);
      assert.equal(bench.closed, 1000, `${channel}: every handle is closed`);
      assert.equal(bench.still_open, 0, channel);
      assert.equal(bench.closed_is_refused, true, `${channel}: a closed handle is refused by the core`);
      assert.ok(bench.ms <= 300, `${channel}: 1000 items took ${bench.ms} ms (at most 300)`);
      console.log(`# ${channel}: matching 1000 items took ${Math.round(bench.ms)} ms`);
    } finally {
      await session.quit();
    }
  }
});
