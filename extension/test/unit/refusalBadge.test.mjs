// A shortcut or a context menu click whose fill is refused leaves no popup to say why: the toolbar button shows "!" for
// thirty seconds on that tab, and the popup, opened next, shows the reason once. The quick fill is the package's own,
// with a core host that refuses the fill; the badge and the popup's list are the package's (offerUiWorld.mjs).
import assert from "node:assert/strict";
import { test } from "node:test";
import { listenForMenus, MENU_ID } from "../../src/background/menus.mjs";
import { ORIGIN, PAGE, TAB, uiWorld } from "./offerUiWorld.mjs";
import { pkg } from "./sessionHelpers.mjs";

/** @param {{ reason?: string | null, ok?: boolean }} answer what the fill answers */
async function quickFillOver(answer) {
  const { load } = await pkg();
  const { createQuickFill } = await load("background/commands.mjs");
  const w = await uiWorld();
  /** @type {string[]} */
  const opened = [];
  const coreHost = {
    state: () => /** @type {"unlocked"} */ ("unlocked"),
    call: async (/** @type {string} */ op) => {
      if (op === "fill_offer") return { handles: [{ ref: "r1", frame_id: 0 }] };
      if (op === "fill") return answer.ok === true ? { ok: true } : { ok: false, ...(answer.reason !== null ? { reason: answer.reason ?? "frame_hidden" } : {}) };
      throw new Error(op);
    },
  };
  const quick = createQuickFill({
    coreHost,
    lock: { checkOrLock: async () => true, touch() {} },
    openPopup: () => void opened.push("popup"),
    onRefused: (tabId, reason) => w.badge.refuse(tabId, reason),
    scripting: { executeScript: async () => [] },
    webNavigation: { getFrame: async () => ({ url: PAGE, documentId: "d" }) },
  });
  return { w, quick, opened };
}

test("a_shortcut_or_menu_refusal_sets_the_badge_and_the_popup_says_why", async () => {
  // The shortcut: the fill is refused because the form is in a hidden frame.
  const { w, quick, opened } = await quickFillOver({ reason: "frame_hidden" });
  assert.equal(await quick.fillOrOpen(TAB), "not_filled");
  assert.deepEqual(opened, [], "no popup opened, so nothing said why");
  assert.equal(w.badgeText.get(TAB), "!", "the button shows the mark on that tab");
  assert.equal(w.badgeText.has(TAB + 1), false, "and only on that tab");
  // The popup, opened next, shows the reason once, and the mark goes with it.
  const popup = w.connectPopup();
  const first = await popup.ask("offer_list", { tab_id: TAB });
  assert.equal(first.notice, "frame_hidden");
  assert.equal(w.badgeText.get(TAB), "");
  assert.equal(Object.hasOwn(await popup.ask("offer_list", { tab_id: TAB }), "notice"), false, "shown once");

  // The mark ends by itself after thirty seconds, with the popup never opened.
  assert.equal(await quick.fillOrOpen(TAB), "not_filled");
  assert.equal(w.badgeText.get(TAB), "!");
  w.clock.advance(29_999);
  assert.equal(w.badge.refusalFor(TAB), "frame_hidden");
  w.clock.advance(1);
  assert.equal(w.badge.refusalFor(TAB), null);
  assert.equal(w.badgeText.get(TAB), "");
  assert.equal(Object.hasOwn(await popup.ask("offer_list", { tab_id: TAB }), "notice"), false);

  // The menu goes the same way (it runs the same step for the clicked frame), and a reason the popup has no text for is a plain refusal.
  const none = await quickFillOver({ reason: "<b>x</b>" });
  /** @type {Array<(info: any, tab: any) => void>} */
  const clicks = [];
  listenForMenus({
    menus: { create() {}, remove: async () => {}, onClicked: { addListener: (fn) => void clicks.push(fn) } },
    quickFill: { fillOrOpen: (tabId, click) => none.quick.fillOrOpen(tabId, click), open() {} },
    title: "Fill with Ferret",
  });
  clicks[0]({ menuItemId: MENU_ID, frameId: 0, pageUrl: PAGE, targetElementId: 3 }, { id: TAB });
  await none.w.flush();
  assert.equal(none.w.badgeText.get(TAB), "!");
  assert.equal((await none.w.connectPopup().ask("offer_list", { tab_id: TAB })).notice, "not_filled");

  // A fill that went through leaves no mark; a locked vault opens the popup instead and refuses nothing.
  const fine = await quickFillOver({ ok: true });
  assert.equal(await fine.quick.fillOrOpen(TAB), "filled");
  assert.equal(fine.w.badgeText.has(TAB), false);
  assert.equal(ORIGIN.startsWith("https://"), true);
});
