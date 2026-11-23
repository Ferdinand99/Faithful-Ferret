// What a hostile page, a hurried person or a lock can do to a capture, end to end on the end-to-end stack: the extension is signed in
// to a real server with its vault open, "Offer to save passwords" is on (the settings tab's real click asks for access to https
// pages), and the pages are forms of the corpus, of the hold-out set and of test/fixtures/forms-capture, driven with real key
// events and clicks. One Firefox per channel for the whole file; the last test locks the vault.
//
// - a_page_that_plants_a_password_and_submits_gets_no_offer: a page that writes the password itself and submits (also by a timer
//   after the person typed, with no click and no Enter) is no offer, and nothing is written.
// - an_xss_style_value_swap_after_typing_gets_no_offer: a script that rewrites the typed password (in the submit handler, or a
//   moment after each key) leaves no offer.
// - a_flood_of_submits_gives_one_offer: forty submit events and a burst of requests make one offer.
// - a_lookalike_offer_names_the_lookalike_host_with_its_a_label_and_warns_of_reuse: the card of an offer from a look-alike host
//   shows that host with its A-label and the warning that the password is the one of another item, which it names.
// - navigation_to_another_site_does_not_move_an_offer_to_it: an offer keeps the origin of the page it was captured on after the
//   tab went to another site, and a save from it makes an item with that origin.
// - nothing_is_written_when_the_popup_is_never_opened: an offer nobody answers writes nothing, in twenty seconds or after a lock.
// - a_lock_between_submit_and_click_leaves_no_offer: a lock after the submit and before the click on "Save" leaves no offer
//   and no item; the click writes nothing.
import assert from "node:assert/strict";
import { after, test } from "node:test";
import { channels, fixtures, stopFixtures } from "./harness.mjs";
import { captureCase, captureCasesOf, caseUrl, casesOf, offersPeek } from "./matrix.mjs";
import { allText, newestTab, popupWithCard, readyWorld, sleep, uniqueSignup, vaultItemHref } from "./offerWorld.mjs";
import { SLOW, pace } from "./e2e.mjs";

/** The channel's world, made once. @type {Map<string, Awaited<ReturnType<typeof readyWorld>>>} */
const worlds = new Map();
/** @param {"release" | "esr"} channel */
async function worldOf(channel) {
  let w = worlds.get(channel);
  if (!w) {
    w = await readyWorld(channel);
    worlds.set(channel, w);
  }
  return w;
}
after(async () => {
  for (const w of worlds.values()) await w.quit().catch(() => {});
  await stopFixtures();
});

/** @param {string} id @returns {Record<string, any>} the case from the corpus, the hold-out set or the capture pages */
function caseOf(id) {
  const [c] = id.startsWith("ho-") ? casesOf("holdout", id) : [...casesOf("corpus", id), ...captureCasesOf(id)];
  assert.equal(c?.id, id, `the case ${id}`);
  return c;
}

/**
 * Runs a case and says what the extension holds for its tab: the offers the store lists, and what the popup's own list tells.
 * @param {Awaited<ReturnType<typeof readyWorld>>} w @param {Record<string, any>} c
 */
async function run(w, c) {
  const result = await captureCase(w, c);
  assert.equal(result.error, undefined, `${c.id}: ${result.error}`);
  assert.equal(result.ran.capture, true, c.id);
  const tabId = await newestTab(w);
  await w.ui.open();
  let listed;
  try {
    listed = await w.ui.body("offer_list", { tab_id: tabId });
  } finally {
    await w.ui.close();
  }
  return { result, tabId, listed };
}

test("a_page_that_plants_a_password_and_submits_gets_no_offer", async () => {
  for (const channel of channels()) {
    const w = await worldOf(channel);
    const vault = await w.vaultState();
    for (const id of ["tamper-planted-en", "tamper-timer-submit-en", "ho-planted-autosubmit-en"]) {
      const { result, listed } = await run(w, caseOf(id));
      assert.deepEqual(result.observed?.offers, [], `${channel}: ${id}: the store holds no offer`);
      assert.deepEqual(listed.offers, [], `${channel}: ${id}: the popup is told of none`);
      assert.equal(result.observed?.vault_changed, false, `${channel}: ${id}: nothing was written`);
    }
    assert.deepEqual(await w.vaultState(), vault, `${channel}: the item list stands still`);
  }
});

test("an_xss_style_value_swap_after_typing_gets_no_offer", async () => {
  for (const channel of channels()) {
    const w = await worldOf(channel);
    const vault = await w.vaultState();
    for (const id of ["tamper-swap-de", "tamper-xss-swap-en", "ho-planted-swap-showpw-nl"]) {
      const { result, listed } = await run(w, caseOf(id));
      assert.deepEqual(result.observed?.offers, [], `${channel}: ${id}: the store holds no offer`);
      assert.deepEqual(listed.offers, [], `${channel}: ${id}: the popup is told of none`);
      assert.equal(result.observed?.vault_changed, false, `${channel}: ${id}: nothing was written`);
    }
    assert.deepEqual(await w.vaultState(), vault, `${channel}: the item list stands still`);
  }
});

test("a_flood_of_submits_gives_one_offer", async () => {
  for (const channel of channels()) {
    const w = await worldOf(channel);
    const corpus = await run(w, caseOf("flood-submits-en"));
    assert.equal(corpus.result.observed?.offers.length, 1, `${channel}: forty synthetic submit events and a click: one offer (${JSON.stringify(corpus.result.observed?.offers)})`);
    assert.equal(corpus.listed.offers.length, 1, `${channel}: the popup is told of one`);
    // The burst of the hold-out page (forty requestSubmit calls and requests per click) makes at most one, and the
    // store never holds two for the tab.
    const burst = await run(w, caseOf("ho-flood-submits-en"));
    assert.ok(burst.result.observed?.offers.length <= 1, `${channel}: a burst of requestSubmit calls: at most one offer (${burst.result.observed?.offers.length})`);
    assert.ok(burst.listed.offers.length <= 1, `${channel}: the popup is told of at most one`);
  }
});

test("a_lookalike_offer_names_the_lookalike_host_with_its_a_label_and_warns_of_reuse", async () => {
  for (const channel of channels()) {
    const w = await worldOf(channel);
    const server = await fixtures();
    for (const id of ["lookalike-homograph-de", "lookalike-dash-en"]) {
      const c = caseOf(id);
      const host = new URL(caseUrl(c, server)).hostname;
      const { result, tabId } = await run(w, c);
      assert.equal(result.observed?.offers.length, 1, `${channel}: ${id}: one offer`);
      assert.equal(result.observed?.offers[0].origin, `https://${host}`, `${channel}: ${id}: for the look-alike's own origin`);
      assert.equal(result.observed?.offers[0].reuse, true, `${channel}: ${id}: the store knows the password is another item's`);
      const handle = await popupWithCard(w, tabId, "save");
      try {
        // The card names the host the page is on: its A-label (always), and the Unicode form beside it when they differ.
        assert.equal(await w.session.content(() => document.querySelector('[data-role="offer-card"] [data-role="offer-host"]')?.getAttribute("data-a-label") ?? ""), host, `${channel}: ${id}: the host of the card is the look-alike's`);
        const hostText = await w.session.content(() => (document.querySelector('[data-role="offer-card"] [data-role="offer-host"]')?.textContent ?? "").trim());
        assert.ok(hostText.length > 0, `${channel}: ${id}: the host line is not empty`);
        if (host.includes("xn--")) {
          assert.ok(hostText.includes(host), `${channel}: ${id}: the A-label is shown (${hostText})`);
          assert.equal(await w.page.visible('[data-role="offer-card"] [data-role="offer-a-label"]'), true, `${channel}: ${id}: the A-label is its own element`);
        }
        // The warning names the item that has the same password, and the host that item is for.
        await w.page.waitVisible('[data-role="offer-card"] [data-role="offer-reuse"]', SLOW);
        const warning = await allText(w, '[data-role="offer-card"] [data-role="offer-reuse-item"]');
        assert.ok(warning.some((line) => line.includes(w.named.login) && line.includes("login.example.net")), `${channel}: ${id}: the warning names the Login entry and its host (${JSON.stringify(warning)})`);
        // The password is never in the popup.
        assert.equal((await w.session.content(() => document.body.textContent ?? "")).includes(w.passwords.login), false, `${channel}: ${id}: no password in the popup`);
      } finally {
        await w.session.switchTo(handle).catch(() => {});
        await w.session.closeTab().catch(() => {});
        await w.session.switchTo(w.pageTab);
      }
    }
  }
});

test("navigation_to_another_site_does_not_move_an_offer_to_it", async () => {
  for (const channel of channels()) {
    const w = await worldOf(channel);
    const server = await fixtures();
    const { c, user, tag } = uniqueSignup("signup-confirm-fr");
    const { result, tabId } = await run(w, c);
    assert.equal(result.observed?.offers.length, 1, `${channel}: one offer`);
    const origin = "https://forms.example.net";
    assert.equal(result.observed?.offers[0].origin, origin, channel);
    // The tab now shows another site (an ordinary page of the host the vault has an entry for).
    await w.session.switchTo(w.pageTab);
    await w.session.navigate(server.url("login.example.net", "/static/login.html"));
    await w.session.waitFor(() => w.session.content(() => document.readyState === "complete"), 15_000, "the other site");
    await sleep(3000);
    const after_ = await offersPeek(w, tabId);
    for (const o of after_.offers) assert.equal(o.origin, origin, `${channel}: the offer is still for the page it came from, not for the site the tab shows now`);
    // The card the popup shows about the tab says the same, and a save from it makes an item with that origin.
    const handle = await popupWithCard(w, tabId, "save");
    assert.equal(await w.session.content(() => document.querySelector('[data-role="offer-card"] [data-role="offer-host"]')?.getAttribute("data-a-label") ?? ""), "forms.example.net", `${channel}: the card names the page the form was on`);
    const name = `Offer-nav-${tag}`;
    const [nameField] = await w.session.findAll('[data-role="offer-name"]');
    await w.session.content(() => {
      const input = /** @type {HTMLInputElement} */ (document.querySelector('[data-role="offer-name"]'));
      input.value = "";
      input.focus();
    });
    await w.session.type(nameField, name);
    await w.page.click('[data-role="offer-save"]');
    await w.page.waitVisible('[data-role="offer-result"]', SLOW);
    await w.session.closeTab().catch(() => {});
    void handle;
    const href = await vaultItemHref(w, name);
    await w.session.navigate(`${(await w.session.currentUrl()).split("#")[0]}${href}`);
    await w.page.waitVisible('[data-role="item"] h1', SLOW);
    assert.deepEqual(await allText(w, '[data-role="url"]'), [origin], `${channel}: the item is for the page the form was on`);
    assert.ok((await allText(w, '[data-role="value"]')).includes(user), `${channel}: with the typed user name`);
    await w.session.switchTo(w.pageTab);
  }
});

test("nothing_is_written_when_the_popup_is_never_opened", async () => {
  for (const channel of channels()) {
    const w = await worldOf(channel);
    const vault = await w.vaultState();
    const { c } = uniqueSignup("signup-confirm-nb");
    const { result, tabId } = await run(w, c);
    assert.equal(result.observed?.offers.length, 1, `${channel}: an offer is held`);
    assert.equal(result.observed?.offers[0].written_without_click, undefined, `${channel}: the store says nothing was written`);
    // Twenty seconds in which nobody opens the popup and nobody answers: the vault does not change, and the offer waits.
    await sleep(20_000);
    assert.deepEqual(await w.vaultState(), vault, `${channel}: the item list stands still`);
    assert.equal((await offersPeek(w, tabId)).offers.length, 1, `${channel}: the offer is still held`);
    // Dropped by the test, with nothing written either.
    await w.session.switchTo(w.pageTab);
    await offersPeek(w, tabId, true);
    assert.deepEqual(await w.vaultState(), vault, `${channel}: still the same after the offer is dropped`);
  }
});

test("a_lock_between_submit_and_click_leaves_no_offer", async () => {
  for (const channel of channels()) {
    const w = await worldOf(channel);
    const vault = await w.vaultState();
    const { c, tag } = uniqueSignup("signup-confirm-de");
    const { result, tabId } = await run(w, c);
    assert.equal(result.observed?.offers.length, 1, `${channel}: an offer is held`);
    // The card is up and its guard has passed; the vault locks (the person's own lock, from a popup that is open).
    const handle = await popupWithCard(w, tabId, "save");
    const [nameField] = await w.session.findAll('[data-role="offer-name"]');
    await w.session.content(() => {
      const input = /** @type {HTMLInputElement} */ (document.querySelector('[data-role="offer-name"]'));
      input.value = "";
      input.focus();
    });
    await w.session.type(nameField, `Offer-lock-${tag}`);
    await w.ui.open();
    try {
      assert.equal((await w.ui.ask("lock", {})).type, "lock", `${channel}: the vault locks`);
    } finally {
      await w.ui.close();
    }
    // Every lock clears the offers: the store holds none, and a click on "Save" after it writes nothing.
    assert.deepEqual((await offersPeek(w, tabId)).offers, [], `${channel}: the lock cleared the offer`);
    await w.session.switchTo(handle);
    const clicked = await w.session.content(() => {
      const button = document.querySelector('[data-role="offer-save"]');
      if (button instanceof HTMLElement) {
        button.click();
        return true;
      }
      return false;
    });
    await sleep(1500);
    assert.deepEqual((await offersPeek(w, tabId)).offers, [], `${channel}: still no offer after the click (the button was there: ${clicked})`);
    // The vault, opened again with the password, holds exactly what it held before.
    await w.session.switchTo(w.pageTab);
    await w.ui.open();
    try {
      await pace();
      const unlocked = await w.ui.ask("unlock", { mp: w.account.password });
      assert.equal(unlocked.type, "unlock", `${channel}: ${JSON.stringify(unlocked.body)}`);
      assert.equal(unlocked.body?.ok, true, `${channel}: unlocked again`);
    } finally {
      await w.ui.close();
    }
    await w.session.waitFor(async () => (await w.vaultState()).running === true, 60_000, "the sync engine runs again");
    assert.deepEqual([...(await w.vaultState()).rows].sort(), [...vault.rows].sort(), `${channel}: no item was made by the click`);
    assert.equal((await offersPeek(w, tabId)).offers.length, 0, `${channel}: the offer is gone for good`);
  }
});
