// The toolbar button's badge (badge.mjs) and the popup that opens by itself (autoOpen.mjs): what the button shows on
// which tab, when it clears, and under which conditions the popup is asked to open. The real store of offers, router,
// lock and core host of the built package are behind it (offerUiWorld.mjs).
import assert from "node:assert/strict";
import { test } from "node:test";
import { createFakeTimers, createClock } from "./backgroundHelpers.mjs";
import { item } from "./offerWriteWorld.mjs";
import { ORIGIN, TAB, uiWorld } from "./offerUiWorld.mjs";
import { pkg } from "./sessionHelpers.mjs";

test("badge_shows_on_the_offer_tab_only_and_clears_when_the_offer_ends", async () => {
  const w = await uiWorld();
  // Nothing before there is an offer, and a capture that is not an offer yet shows nothing.
  await w.capture();
  assert.equal(w.badgeText.get(TAB) ?? "", "");
  await w.wait(1000);
  assert.equal(w.badgeText.get(TAB) ?? "", "", "a sign-up form is offered three seconds after its capture, not before");
  await w.wait(2100);
  assert.equal(w.badgeText.get(TAB), "1", "the tab of the offer shows how many offers wait");
  assert.deepEqual([...new Set(w.badgeCalls.map((c) => c.tabId))], [TAB], "the badge is set for the offer's tab and no other");
  assert.equal(w.badgeText.has(TAB + 1), false);

  // The browser resets a tab's badge when the tab goes to a new page: the next navigation paints it again.
  w.badgeText.delete(TAB);
  for (const fn of w.listeners.committed) fn({ tabId: TAB, frameId: 0, url: ORIGIN + "/next" });
  assert.equal(w.badgeText.get(TAB), "1", "painted again after the tab went to a new page");

  // "Not now" ends the offer: the badge clears.
  const popup = w.connectPopup();
  const listed = await popup.ask("offer_list", { tab_id: TAB });
  assert.equal(listed.offers.length, 1);
  assert.deepEqual(await popup.ask("offer_dismiss", { offer_id: listed.offers[0].offer_id }), { ok: true });
  assert.equal(w.badgeText.get(TAB), "", "the badge clears when the offer is answered");

  // The offer runs out by the clock: no popup is open, and the badge clears all the same.
  await w.offerReady({ capture_id: "cap2" });
  assert.equal(w.badgeText.get(TAB), "1");
  await w.wait(5 * 60_000);
  assert.equal(w.badgeText.get(TAB), "", "an offer that ran out takes its badge with it");

  // A tab that closes forgets its badge and its offers.
  await w.offerReady({ capture_id: "cap3" });
  assert.equal(w.badgeText.get(TAB), "1");
  for (const fn of w.listeners.tabRemoved) fn(TAB);
  assert.equal(w.badgeText.get(TAB), "");
  assert.equal(w.offers.size(), 0);

  // A lock clears every offer and every badge.
  await w.offerReady({ capture_id: "cap4" });
  assert.equal(w.badgeText.get(TAB), "1");
  await w.coreHost.lock("manual");
  assert.equal(w.badgeText.get(TAB), "");
  assert.equal(w.offers.size(), 0);
  // The badge holds a number and a reason code, never a host, a user name or a password.
  for (const call of w.badgeCalls) assert.match(call.text, /^(|\d\+?|!)$/);
});

test("the_badge_counts_caps_and_paints_a_refusal_for_thirty_seconds_by_the_clock", async () => {
  const { load } = await pkg();
  const { createBadge, REFUSAL_MS } = await load("background/badge.mjs");
  const clock = createClock();
  const timers = createFakeTimers(clock);
  /** @type {Array<{ text: string, tabId: number }>} */
  const calls = [];
  const colors = [];
  const badge = createBadge({
    action: { setBadgeText: (/** @type {any} */ d) => void calls.push(d), setBadgeBackgroundColor: (/** @type {any} */ d) => void colors.push(d) },
    now: clock.now,
    timers,
  });
  badge.set(3, 2);
  badge.set(3, 2);
  assert.deepEqual(calls, [{ text: "2", tabId: 3 }], "an unchanged count is not painted again");
  badge.set(3, 12);
  assert.equal(calls.at(-1)?.text, "9+");
  badge.set(3, 0);
  assert.equal(calls.at(-1)?.text, "");
  // Not an index or a count: nothing happens.
  const before = calls.length;
  badge.set(-1, 1);
  badge.set(3, -1);
  badge.set(3, 1.5);
  badge.refuse("3", "frame_hidden");
  assert.equal(calls.length, before);

  // A refusal: "!" on that tab, with its reason, and a red mark; another tab is not touched.
  badge.refuse(4, "frame_hidden");
  assert.deepEqual(calls.at(-1), { text: "!", tabId: 4 });
  assert.equal(colors.at(-1).tabId, 4);
  assert.equal(badge.refusalFor(4), "frame_hidden");
  assert.equal(badge.refusalFor(3), null);
  // A reason that is not on the list is `not_filled`: a page never makes a text for the popup.
  badge.refuse(5, "<script>alert(1)</script>");
  assert.equal(badge.refusalFor(5), "not_filled");
  // The refusal ends by the clock, also when no timer ever fires (a sleeping machine).
  clock.advance(REFUSAL_MS - 1);
  assert.equal(badge.refusalFor(4), "frame_hidden");
  clock.advance(1);
  assert.equal(badge.refusalFor(4), null);
  assert.equal(calls.filter((c) => c.tabId === 4).at(-1)?.text, "", "the mark goes when the refusal ended");
  // A clock that went backwards cannot make a refusal last longer than thirty seconds.
  clock.advance(-10 * REFUSAL_MS);
  assert.equal(badge.refusalFor(5), null);
  // The refusal shows over the count, and the count comes back after it. The popup that showed the reason takes it away.
  badge.set(6, 2);
  badge.refuse(6, "no_fields");
  assert.equal(calls.filter((c) => c.tabId === 6).at(-1)?.text, "!");
  badge.acknowledge(6);
  assert.equal(calls.filter((c) => c.tabId === 6).at(-1)?.text, "2");
  assert.equal(badge.refusalFor(6), null);
  // A lock clears everything, and a closed tab forgets its marks.
  badge.refuse(7, "covered");
  badge.clearAll();
  for (const tabId of [3, 4, 5, 6, 7]) assert.equal(calls.filter((c) => c.tabId === tabId).at(-1)?.text ?? "", "", `tab ${tabId} is clear`);
  badge.set(8, 1);
  badge.forget(8);
  badge.reapply(8);
  assert.equal(calls.filter((c) => c.tabId === 8).at(-1)?.text, "1", "a forgotten tab is not painted again");
});

test("auto_open_only_when_the_probe_passed_for_the_active_tab_of_the_focused_window_and_the_setting_is_on", async () => {
  // Everything right: one attempt, and the badge is there too.
  const on = await uiWorld();
  await on.offerReady();
  assert.equal(on.popup.attempts, 1, "the popup is asked to open once");
  assert.equal(on.badgeText.get(TAB), "1");
  assert.equal(on.autoOpen.probe(), "works");

  // A second offer for the same tab does not open it again while the first still waits (the count only went up from one).
  // Each new offer of a tab that had none does; here the tab already shows one, so the badge alone grows.
  await on.offerReady({ capture_id: "cap2", kind: "change", password: "Typed-another-password-7" });
  assert.equal(on.popup.attempts, 2, "a further offer asks again; the browser decides whether the popup is open already");

  // The setting is off: the badge only. It is the popup's own switch, read from the setting page's type.
  const off = await uiWorld();
  const settings = off.connectPopup();
  assert.equal((await settings.ask("capture_settings", { auto_open: false })).auto_open, false);
  await off.offerReady();
  assert.equal(off.popup.attempts, 0, "the setting is off");
  assert.equal(off.badgeText.get(TAB), "1", "the badge shows all the same");
  assert.equal((await settings.ask("capture_settings", { auto_open: true })).auto_open, true);
  await off.offerReady({ capture_id: "cap2", kind: "change", password: "Typed-another-password-7" });
  assert.equal(off.popup.attempts, 1, "turned on again");

  // Not the active tab of its window, or its window has not the focus: no attempt.
  for (const [name, place] of /** @type {Array<[string, Partial<{ active: boolean, focused: boolean }>]>} */ ([
    ["not the active tab", { active: false }],
    ["window without focus", { focused: false }],
  ])) {
    const w = await uiWorld();
    Object.assign(w.place, place);
    await w.offerReady();
    assert.equal(w.popup.attempts, 0, name);
    assert.equal(w.badgeText.get(TAB), "1", `${name}: the badge shows`);
  }

  // A locked vault: the offer is taken and the badge shows it, but the popup does not open to ask for the master password.
  const locked = await uiWorld();
  await locked.coreHost.lock("manual");
  await locked.offerReady();
  assert.equal(locked.popup.attempts, 0, "no popup opens by itself on a locked vault");
  assert.equal(locked.badgeText.get(TAB), "1");

  // The browser refuses to open the popup without a gesture: the first refusal is the probe. From then on the badge alone
  // is used, and the setting page says so.
  const refused = await uiWorld();
  refused.popup.refuse = true;
  await refused.offerReady();
  assert.equal(refused.popup.attempts, 1);
  assert.equal(refused.autoOpen.probe(), "fails");
  await refused.offerReady({ capture_id: "cap2", kind: "change", password: "Typed-another-password-7" });
  assert.equal(refused.popup.attempts, 1, "after a refusal it is not tried again");
  assert.equal(refused.badgeText.get(TAB), "2", "the badge still counts the offers");
  const page = refused.connectPopup();
  assert.equal((await page.ask("capture_settings", {})).auto_open_state, "fails");
});

test("a_login_the_vault_holds_gets_no_badge_and_no_popup", async () => {
  // A login that the vault holds already is no offer: no badge, no popup.
  const holds = item(1, { username: "anna@example.net", password: "Typed-by-the-user-in-the-form-9x", urls: [[`${ORIGIN}/`, "host"]] });
  const w = await uiWorld([holds]);
  await w.capture({ kind: "login", capture_id: "login1" });
  // The page left the form: a new document, finished loading, then the quiet time.
  for (const fn of w.listeners.committed) fn({ tabId: TAB, frameId: 0, url: ORIGIN + "/home", documentId: "doc-new" });
  await w.wait(100);
  for (const fn of w.listeners.completed) fn({ tabId: TAB, frameId: 0, url: ORIGIN + "/home", documentId: "doc-new" });
  await w.wait(3600);
  // The write path's judgement of the login is asked for when the offer is ready, and comes back a moment later.
  for (let i = 0; i < 20 && w.offers.size() > 0; i += 1) await w.wait(100);
  assert.equal(w.offers.size(), 0, "the vault holds this login: nothing to offer");
  assert.equal(w.popup.attempts, 0);
  assert.equal(w.badgeText.get(TAB) ?? "", "");
});

test("a_login_is_not_counted_or_listed_until_the_core_has_said_it_is_not_saved", async () => {
  const w = await uiWorld([item(9, { name: "Other", username: "x", password: "Another-password-1", urls: [["https://other.example.org/", "host"]] })]);
  /** @type {(outcome: { action: string }) => void} */
  let answer = () => {};
  /** @type {any} */ (w.sync).classifyCapture = () => new Promise((resolve) => { answer = resolve; });
  await w.capture({ kind: "login", capture_id: "login1" });
  for (const fn of w.listeners.committed) fn({ tabId: TAB, frameId: 0, url: ORIGIN + "/home", documentId: "doc-new" });
  await w.wait(100);
  for (const fn of w.listeners.completed) fn({ tabId: TAB, frameId: 0, url: ORIGIN + "/home", documentId: "doc-new" });
  await w.wait(3600);
  // The offer is ready, the write path has not answered: nothing is counted, shown on the button or listed to a popup that asks.
  assert.equal(w.badgeText.get(TAB) ?? "", "");
  assert.equal(w.popup.attempts, 0);
  assert.deepEqual(w.offers.forTab(TAB), []);
  w.captureHost.offers.forTab(TAB, "a".repeat(32));
  assert.equal(w.badgeText.get(TAB) ?? "", "", "another look at the tab does not count it either");
  answer({ action: "save" });
  await w.flush();
  assert.equal(w.badgeText.get(TAB), "1");
  assert.equal(w.offers.forTab(TAB).length, 1);
});
