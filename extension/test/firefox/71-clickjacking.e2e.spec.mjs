// Clickjacking against the real extension in a real Firefox, on the end-to-end
// stack (run by the e2e mode of the Firefox runner) and the test sites:
//
// - Every row of the test sites whose fields or timing decide (covers, opacity,
//   filters, transforms, clip paths, masks, blend modes, hidden ancestors,
//   shadow roots, tiny and far-away fields, a page that turns hostile when the
//   popup opens, forged events): the real popup about the page's tab, a
//   screenshot, and a real "Fill" on the host entry. Afterwards no field the
//   site marks "reject" holds anything, every field it marks "fill" holds the
//   password, and the password is nowhere else.
// - An overlay that the page adds after the fill script reported its fields
//   (when the user name gets its value) stops the password: the fill answers
//   `covered`, and the password field stays empty.
// - A navigation between the choice ("Fill" is pressed on a reference of the
//   list) and the fill, of the page or of the login frame (to a foreign site,
//   a data: page, about:blank), fills nothing anywhere.
import assert from "node:assert/strict";
import { after, test } from "node:test";
import { SITES, siteById } from "../fixtures/sites/index.mjs";
import { POPUP_TEXT, USERNAME, documentsHolding, inputsOf, shotPath, world } from "./adversary.mjs";
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

const FIELD_ROWS = SITES.filter((site) => site.expect.outcome === "fields");
const HOSTILE_ROWS = SITES.filter((site) => site.expect.outcome === "turns_hostile" || site.id === "blur-navigate");

/** @param {number} ms */
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

test("every_clickjacking_row_of_the_fixtures_fills_only_the_clear_fields", async () => {
  for (const channel of channels()) {
    const w = await worldOf(channel);
    const password = w.passwords.host;
    assert.ok(FIELD_ROWS.length >= 20, `${channel}: ${FIELD_ROWS.length} rows`);
    for (const site of FIELD_ROWS) {
      const where = `${channel} ${site.id}`;
      const tabId = await w.visit(w.server.siteUrl(site.id));
      const marked = (await inputsOf(w.session)).filter((input) => input.expect !== null);
      const clear = marked.filter((input) => input.expect === "fill");
      const view = await w.popup(tabId);
      let toast = "";
      try {
        await view.shot(`71-${site.id}`);
        const shown = await view.suggestions();
        if (!shown.some((s) => s.name === w.named.host)) {
          await w.ui.open();
          const list = await w.ui.ask("candidates", { tab_id: tabId }).finally(() => w.ui.close());
          assert.fail(`${where}: the host entry is not suggested (${JSON.stringify(shown)}; the list of tab ${tabId}: ${JSON.stringify(list)})`);
        }
        toast = await view.fill(w.named.host);
      } finally {
        await view.close();
      }
      const after = await inputsOf(w.session);
      for (const input of after.filter((i) => i.expect === "reject")) {
        assert.equal(input.value, "", `${where}: the hostile field #${input.id} stays empty`);
      }
      for (const input of after.filter((i) => i.expect === "fill")) {
        assert.equal(input.value, password, `${where}: the clear field #${input.id} has the password`);
      }
      if (clear.length > 0) {
        assert.equal(toast, POPUP_TEXT["popup.filled"], `${where}: the clear form is filled`);
        assert.equal(after.filter((i) => i.value === password).length, clear.length, `${where}: the password is only in the clear field`);
      } else {
        assert.notEqual(toast, POPUP_TEXT["popup.filled"], `${where}: nothing is clear, nothing is filled`);
        assert.equal(after.some((i) => i.value !== ""), false, `${where}: no field has a value`);
      }
      assert.deepEqual(await documentsHolding(w.session, password), clear.length > 0 ? ["top"] : [], `${where}: no frame has it`);
    }

    // The page turns hostile when the popup takes the focus (and on turnHostile(), called here as well, since a
    // headless window does not always lose it): what is hidden, covered or gone by then is not filled.
    for (const site of HOSTILE_ROWS) {
      const where = `${channel} ${site.id}`;
      const tabId = await w.visit(w.server.siteUrl(site.id));
      const view = await w.popup(tabId);
      let toast = "";
      try {
        await w.session.switchTo(w.pageTab);
        await w.session.content(() => { setTimeout(() => /** @type {any} */ (window).turnHostile(), 0); });
        // A navigation away (blur-navigate) needs a moment to land.
        await sleep(1_000);
        await w.session.switchTo(view.handle);
        await view.shot(`71-${site.id}`);
        // A page that already left the entry's origin when the list was read is not offered it at all.
        const offered = (await view.suggestions()).some((s) => s.name === w.named.host);
        toast = offered ? await view.fill(w.named.host) : "(not offered)";
      } finally {
        await view.close();
      }
      assert.notEqual(toast, POPUP_TEXT["popup.filled"], `${where}: refused (${toast})`);
      await w.session.waitFor(() => w.session.content(() => document.readyState === "complete"), 15_000, where);
      assert.deepEqual(await documentsHolding(w.session, password), [], `${where}: the password is nowhere on the page`);
    }

    // Forged events and messages shaped like Ferret's change nothing; the real fill still works.
    {
      const site = siteById("forged-events");
      const tabId = await w.visit(w.server.siteUrl(site.id));
      const view = await w.popup(tabId);
      let toast = "";
      try {
        await view.shot("71-forged-events");
        toast = await view.fill(w.named.host);
      } finally {
        await view.close();
      }
      assert.equal(toast, POPUP_TEXT["popup.filled"], `${channel} forged-events`);
      const seen = await w.session.content(() => /** @type {any} */ (window).fixtureState());
      assert.ok(seen.sent > 0, `${channel}: the page kept forging (${JSON.stringify(seen)})`);
      assert.equal(seen.userValue, USERNAME, `${channel}: the real user name`);
      assert.equal(seen.passwordValue, password, `${channel}: the real password`);
      assert.deepEqual(await documentsHolding(w.session, "stolen"), [], `${channel}: no forged value landed`);
    }
  }
});

test("an_overlay_added_after_the_report_blocks_the_fill", async () => {
  for (const channel of channels()) {
    const w = await worldOf(channel);
    const site = siteById("late-overlay");
    const tabId = await w.visit(w.server.siteUrl(site.id));
    await w.ui.open();
    let fill;
    try {
      const list = await w.ui.body("candidates", { tab_id: tabId });
      const row = list.handles.find((/** @type {any} */ h) => h.name === w.named.host);
      assert.ok(row, `${channel}: the host entry is offered on the clear page`);
      // The page is clear when the fill script reports its fields; the cover comes with the user name's value.
      fill = await w.ui.body("fill", { ref: row.ref, tab_id: tabId });
    } finally {
      await w.ui.close();
    }
    await w.session.screenshot(shotPath(channel, "71-late-overlay-page"));
    assert.deepEqual(fill, { ok: false, reason: String(site.expect.reason) }, `${channel}: the password is refused`);
    const state = await w.session.content(() => /** @type {any} */ (window).fixtureState());
    assert.equal(state.covered, true, `${channel}: the cover came after the report`);
    const values = Object.fromEntries((await inputsOf(w.session)).map((i) => [i.id, i.value]));
    assert.equal(values["login-user"], USERNAME, `${channel}: the user name went in before the cover`);
    assert.equal(values["login-pass"], "", `${channel}: the covered password field stays empty`);
    assert.deepEqual(await documentsHolding(w.session, w.passwords.host), [], `${channel}: the password is nowhere`);
  }
});

test("navigation_between_pick_and_fill_fills_nothing", async () => {
  for (const channel of channels()) {
    const w = await worldOf(channel);
    const password = w.passwords.host;

    // The page itself: the list is read on the entry's page, then the tab goes to a foreign sign-in page.
    {
      const tabId = await w.visit(w.server.siteUrl("login"));
      await w.ui.open();
      try {
        const list = await w.ui.body("candidates", { tab_id: tabId });
        const row = list.handles.find((/** @type {any} */ h) => h.name === w.named.host);
        assert.ok(row, `${channel}: offered on the entry's page`);
        await w.session.switchTo(w.pageTab);
        await w.session.navigate(w.server.siteUrl("foreign-login"));
        await w.session.waitFor(() => w.session.content(() => document.readyState === "complete"), 15_000, "the foreign page");
        const fill = await w.ui.body("fill", { ref: row.ref, tab_id: tabId });
        assert.equal(fill.ok, false, `${channel}: the page changed: ${JSON.stringify(fill)}`);
      } finally {
        await w.ui.close();
      }
      assert.deepEqual(await documentsHolding(w.session, password), [], `${channel}: nothing on the foreign page`);
      assert.deepEqual(await documentsHolding(w.session, USERNAME), [], `${channel}: no user name either`);
    }

    // The login frame of a same-site page moves to a foreign site, a data: page or about:blank.
    const site = siteById("navigate-frame");
    for (const target of /** @type {string[]} */ (["foreign", "data", "blank"])) {
      const where = `${channel} navigate-frame ${target}`;
      const tabId = await w.visit(w.server.siteUrl(site.id));
      await w.ui.open();
      try {
        const list = await w.ui.body("candidates", { tab_id: tabId });
        const row = list.handles.find((/** @type {any} */ h) => h.name === w.named.host);
        assert.ok(row && row.frame_ids.some((/** @type {number} */ id) => id !== 0), `${where}: offered in the frame (${JSON.stringify(list)})`);
        await w.session.switchTo(w.pageTab);
        const before = await w.session.content(() => document.getElementById("frame")?.getAttribute("src"));
        await w.session.content((/** @type {string} */ kind) => /** @type {any} */ (window).navigateFrame(kind), target);
        // The frame has left the entry's origin before the fill is asked for.
        await w.session.waitFor(async () => {
          const [frame] = await w.session.findAll("#frame");
          await w.session.switchToFrame(frame);
          try {
            return await w.session.content(() => document.readyState === "complete" && !location.href.startsWith("https://login."));
          } finally {
            await w.session.switchToTopFrame();
          }
        }, 15_000, `${where}: the frame moved from ${before}`);
        const fill = await w.ui.body("fill", { ref: row.ref, tab_id: tabId });
        assert.equal(fill.ok, false, `${where}: ${JSON.stringify(fill)}`);
      } finally {
        await w.ui.close();
      }
      assert.deepEqual(await documentsHolding(w.session, password), [], `${where}: the password is nowhere`);
      assert.deepEqual(await documentsHolding(w.session, USERNAME), [], `${where}: nor the user name`);
    }
  }
});
