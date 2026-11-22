// Phishing against the real extension in a real Firefox, on the end-to-end stack
// (run by the e2e mode of the Firefox runner) and the test sites:
//
// - Every row of the test sites that is about where an entry is offered (look-
//   alikes, other ports and schemes, private suffixes, frames of every kind):
//   the real popup about the page's tab, a screenshot of it, the suggestions it
//   shows for each entry, and one real "Fill" on what it offers. Afterwards the
//   entry's password is in exactly the document the row allows (the top, the
//   frame) and nowhere else, every frame read. A row that offers nothing gets
//   no suggestion of ours. The clickjacking rows are 71-clickjacking's.
// - A page that looks like Ferret's own popup (title, icon, unlock panel) on a
//   foreign origin reaches nothing of the extension: no extension API in the
//   page, no extension page loads in its frames or answers its fetch, the
//   messages it posts go nowhere, and the vault's state and deadline do not
//   move while a person types into it. The popup names the page by its host.
// - On every look-alike, a search for the real entry lists it with copy
//   buttons and no "Fill"; its search reference cannot fill the look-alike
//   (refused, nothing typed), and copying it works.
import assert from "node:assert/strict";
import { after, test } from "node:test";
import { SITES, siteById } from "../fixtures/sites/index.mjs";
import { POPUP_URL, SIGNIN_URL } from "./e2e.mjs";
import { POPUP_TEXT, USERNAME, clipboardText, documentsHolding, expectationsOf, world } from "./adversary.mjs";
import { channels, stopFixtures } from "./harness.mjs";

/** @type {Map<string, Awaited<ReturnType<typeof world>>>} */
const worlds = new Map();
after(async () => {
  for (const w of worlds.values()) await w.quit().catch(() => {});
  await stopFixtures();
});

/** One signed-in Firefox per channel for this file's tests, with the same-site login frame granted. @param {"release" | "esr"} channel */
async function worldOf(channel) {
  let w = worlds.get(channel);
  if (!w) {
    w = await world(channel, { grant: ["framed-same-site"] });
    worlds.set(channel, w);
  }
  return w;
}

/** The rows that 71-clickjacking checks (what the fields and the timing decide). */
const CLICKJACKING = new Set(["fields", "turns_hostile", "covered_after_report", "origin_changed"]);
const PHISHING = SITES.filter((site) => !CLICKJACKING.has(site.expect.outcome) && site.expect.noise === undefined);
/** The outcomes for which the popup offers the entry. */
const OFFERED = new Set(["fill", "fill_in_frame", "offer_with_warning"]);

test("every_phishing_row_of_the_fixtures_matches_its_expectation_in_the_popup", async () => {
  for (const channel of channels()) {
    const w = await worldOf(channel);
    let filled = 0;
    let refused = 0;
    for (const site of PHISHING) {
      const where = `${channel} ${site.id}`;
      const rows = expectationsOf(site);
      const tabId = await w.visit(w.server.siteUrl(site.id));
      // The background's own answer for the tab: a list that failed would show the popup with no suggestions, which a
      // "no offer" row must not take for a pass. The host shown is the core's display form of the page's host.
      await w.ui.open();
      let list;
      try {
        list = await w.ui.body("candidates", { tab_id: tabId });
      } finally {
        await w.ui.close();
      }
      assert.ok(Array.isArray(list.handles), `${where}: the list answered (${JSON.stringify(list)})`);
      if (site.expect.display) assert.deepEqual(list.host, site.expect.display, `${where}: the host shown`);
      for (const [outcome, key] of rows) {
        if (outcome === "no_offer") assert.equal(list.handles.some((/** @type {any} */ h) => h.name === w.named[key]), false, `${where}: the ${key} entry is not in the list`);
      }
      const view = await w.popup(tabId);
      /** @type {{ key: string, outcome: string } | null} */
      let chosen = null;
      try {
        await view.shot(`70-${site.id}`);
        const shown = await view.suggestions();
        const names = shown.map((s) => s.name);
        // The popup shows the host, never the page's title (the look-alike of Ferret sets one).
        const text = await view.text();
        assert.equal(text.includes("Faithful Ferret - Unlock your vault"), false, `${where}: the page's title is not in the popup`);
        for (const [outcome, key] of rows) {
          const name = w.named[key];
          if (OFFERED.has(outcome)) {
            const row = shown.find((s) => s.name === name);
            assert.ok(row, `${where}: the ${key} entry is suggested (${JSON.stringify(names)})`);
            assert.equal(row.insecure, outcome === "offer_with_warning", `${where}: the ${key} entry's warning`);
            chosen ??= { key, outcome };
          } else if (outcome === "no_offer") {
            assert.equal(names.includes(name), false, `${where}: the ${key} entry is not suggested`);
          }
        }
        // The rows that are about a frame: what is offered for the top is filled once, and the frame gets nothing.
        if (chosen === null) {
          const inFrame = rows.find(([outcome, key]) => outcome === "no_offer_in_frame" && names.includes(w.named[key]));
          if (inFrame) chosen = { key: inFrame[1], outcome: "no_offer_in_frame" };
        }
        if (chosen !== null) {
          const toast = await view.fill(w.named[chosen.key]);
          await view.shot(`70-${site.id}-after`);
          if (chosen.outcome === "no_offer_in_frame") {
            // What the top is offered finds nothing it may fill in the top, and the frame is never tried.
            assert.notEqual(toast, POPUP_TEXT["popup.filled"], `${where}: the ${chosen.key} entry fills nothing (${toast})`);
            refused += 1;
          } else {
            assert.equal(toast, POPUP_TEXT["popup.filled"], `${where}: the ${chosen.key} entry fills`);
            filled += 1;
          }
        }
      } finally {
        await view.close();
      }
      // Where the password went: exactly the document the row allows.
      if (chosen !== null) {
        const holding = await documentsHolding(w.session, w.passwords[chosen.key]);
        /** @type {string[]} */
        let allowed = [];
        if (chosen.outcome === "fill" || chosen.outcome === "offer_with_warning") allowed = ["top"];
        if (chosen.outcome === "fill_in_frame") allowed = [String(site.expect.frame)];
        assert.deepEqual(holding, allowed, `${where}: the ${chosen.key} entry's password is in ${JSON.stringify(holding)}`);
        if (allowed.length > 0) {
          const users = await documentsHolding(w.session, USERNAME);
          assert.deepEqual(users, allowed, `${where}: the user name is in ${JSON.stringify(users)}`);
        }
      } else {
        // Nothing offered: nothing was typed anywhere either.
        for (const key of Object.keys(w.named)) {
          assert.deepEqual(await documentsHolding(w.session, w.passwords[key]), [], `${where}: no password of ${key} on the page`);
        }
      }
    }
    assert.ok(PHISHING.length >= 25 && filled >= 10 && refused >= 2, `${channel}: ${PHISHING.length} rows, ${filled} fills, ${refused} frame rows tried`);
  }
});

test("a_page_that_mimics_the_ferret_popup_gets_no_message_through", async () => {
  for (const channel of channels()) {
    const w = await worldOf(channel);
    const site = siteById("ferret-lookalike");
    const tabId = await w.visit(w.server.siteUrl(site.id));
    await w.ui.open();
    try {
      const before = await w.lockState();
      assert.equal(before.core, "unlocked", channel);
      assert.equal(typeof before.lockAt, "number", `${channel}: the open vault has a deadline`);

      // The page itself (its own script, in its own world) tries every way in it has.
      await w.session.content((/** @type {string} */ popupUrl, /** @type {string} */ signinUrl) => {
        const script = document.createElement("script");
        script.textContent = `(async () => {
  const out = { browser: typeof browser, chrome: typeof chrome, runtime: false, fetched: [], posted: 0 };
  try { out.runtime = !!(window.browser && browser.runtime) || !!(window.chrome && chrome.runtime && chrome.runtime.sendMessage); } catch (e) { out.runtime = false; }
  for (const url of ${JSON.stringify([popupUrl, signinUrl])}) {
    try { const r = await fetch(url); out.fetched.push(url + " " + r.status); } catch (e) { out.fetched.push(url + " refused"); }
    const frame = document.createElement("iframe");
    frame.className = "ferret-probe";
    frame.src = url;
    document.body.append(frame);
  }
  for (const target of [window, window.top]) {
    target.postMessage({ v: 1, id: "p1", type: "unlock", body: { mp: "typed-into-the-fake" } }, "*");
    target.postMessage(JSON.stringify({ v: 1, id: "p2", type: "fill_field", body: { kind: "password", value: "x" } }), "*");
    out.posted += 2;
  }
  document.dispatchEvent(new CustomEvent("ferret-ui", { detail: { type: "lock" } }));
  window.__probe = out;
})();`;
        document.head.append(script);
      }, POPUP_URL, SIGNIN_URL);
      const probe = await w.session.waitFor(() => w.session.content(() => /** @type {any} */ (window).__probe ?? null), 15_000, "the page's probe");
      assert.equal(probe.browser, "undefined", `${channel}: no extension API in the page`);
      assert.equal(probe.runtime, false, `${channel}: no runtime in the page`);
      for (const line of probe.fetched) assert.match(line, / refused$/, `${channel}: the page cannot fetch an extension page (${line})`);
      // A person types into the fake unlock panel.
      await w.page.type("#fake-user", "someone@example.test");
      await w.page.type("#fake-pass", "typed-into-the-fake");
      // No extension page loaded in the page's frames.
      await new Promise((resolve) => setTimeout(resolve, 2_000));
      const probes = await w.session.findAll("iframe.ferret-probe");
      assert.equal(probes.length, 2, channel);
      for (const frame of probes) {
        await w.session.switchToFrame(frame);
        try {
          const inside = await w.session.content(() => ({ url: document.URL, roles: document.querySelectorAll("[data-role]").length, ready: document.body?.dataset.ready ?? null }));
          assert.equal(inside.roles, 0, `${channel}: an extension page loaded in the page's frame (${JSON.stringify(inside)})`);
          assert.notEqual(inside.ready, "1", `${channel}: ${JSON.stringify(inside)}`);
        } finally {
          await w.session.switchToTopFrame();
        }
      }
      // Nothing reached the background: the vault is as it was, and its deadline did not move.
      const afterwards = await w.lockState();
      assert.equal(afterwards.core, "unlocked", channel);
      assert.equal(afterwards.lockAt, before.lockAt, `${channel}: the deadline did not move`);
      assert.equal((await w.ui.body("state", {})).state, "unlocked", channel);
      // The extension names the page by its host, offers nothing of ours, and the popup shows no title of the page.
      const list = await w.ui.body("candidates", { tab_id: tabId });
      assert.equal(list.host?.unicode, site.expect.host, `${channel}: ${JSON.stringify(list.host)}`);
      assert.deepEqual(list.handles.filter((/** @type {any} */ h) => Object.values(w.named).includes(h.name)), [], channel);
    } finally {
      await w.ui.close();
    }
    const view = await w.popup(tabId);
    try {
      await view.shot("70-ferret-lookalike-popup");
      assert.equal((await view.text()).includes(String(site.expect.title)), false, `${channel}: the page's title is not in the popup`);
      assert.deepEqual((await view.suggestions()).filter((s) => Object.values(w.named).includes(s.name)), [], channel);
    } finally {
      await view.close();
    }
  }
});

test("searching_the_real_entry_on_a_lookalike_offers_copy_only", async () => {
  for (const channel of channels()) {
    const w = await worldOf(channel);
    const lookalikes = SITES.filter((site) => site.expect.search === "copy_only");
    assert.ok(lookalikes.length >= 6, `${channel}: ${lookalikes.length} look-alikes`);
    for (const site of lookalikes) {
      const where = `${channel} ${site.id}`;
      const tabId = await w.visit(w.server.siteUrl(site.id));
      const view = await w.popup(tabId);
      try {
        // Nothing of ours is suggested (another spec's login for one of these hosts may be, by design of that spec).
        const ours = Object.values(w.named);
        assert.deepEqual((await view.suggestions()).filter((s) => ours.includes(s.name)), [], `${where}: none of the entries is suggested`);
        await w.page.type('[data-role="search"]', w.named.host);
        await w.session.waitFor(() => w.session.content((/** @type {string} */ wanted) => [...document.querySelectorAll('[data-role="results"] [data-role="item-row"] [data-role="row-name"]')].some((n) => n.textContent?.trim() === wanted), w.named.host), 30_000, `${where}: the search result`);
        await view.shot(`70-${site.id}-search`);
        const row = await w.session.content((/** @type {string} */ wanted) => {
          const found = [...document.querySelectorAll('[data-role="results"] [data-role="item-row"]')].find((r) => r.querySelector('[data-role="row-name"]')?.textContent?.trim() === wanted);
          return found ? { copy: found.querySelector('[data-role="copy-password"]') !== null, fill: found.querySelector('[data-role="fill"]') !== null } : null;
        }, w.named.host);
        assert.deepEqual(row, { copy: true, fill: false }, `${where}: copy only`);
        assert.equal(await w.session.content(() => document.querySelectorAll('[data-role="results"] [data-role="fill"]').length), 0, `${where}: no "Fill" among the search results`);
      } finally {
        await view.close();
      }
      // The search reference itself, on the look-alike's tab: never a fill, always a copy.
      await w.ui.open();
      try {
        const found = await w.ui.body("search", { query: w.named.host });
        const hit = found.handles.find((/** @type {any} */ h) => h.name === w.named.host);
        assert.ok(hit, `${where}: the search finds the entry`);
        const fill = await w.ui.body("fill", { ref: hit.ref, tab_id: tabId });
        assert.deepEqual(fill, { ok: false, reason: "not_offered" }, `${where}: a search reference never fills`);
        const copy = await w.ui.body("copy", { ref: hit.ref, field: "password" });
        assert.deepEqual(copy, { ok: true }, `${where}: but it copies`);
        assert.equal(await clipboardText(w.session), w.passwords.host, `${where}: the clipboard has the password`);
      } finally {
        await w.ui.close();
      }
      assert.deepEqual(await documentsHolding(w.session, w.passwords.host), [], `${where}: nothing was typed into the look-alike`);
    }
  }
});
