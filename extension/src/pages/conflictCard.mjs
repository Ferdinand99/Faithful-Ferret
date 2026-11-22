// The items whose change waits to be sent, was refused, or is in conflict, in
// the popup (design document, section 8.5), in a build with saving from the
// extension on (the build flag `save`; without it nothing here is built):
//
//   - the sync's part counts them ("Waiting for sync", and a button to the
//     items that need the user);
//   - the list of those items, each with its state;
//   - the conflict card of one item: the two versions side by side, with the
//     name, the user name, when and on which device each was changed. A
//     password is never on it: the background never sends one, and the card
//     has no place for one. "Keep mine" writes this device's version on top of
//     the server's; "Keep the server's" drops this device's version. Either
//     takes a second click on the same button, because the version that is not
//     kept is gone for good, and a second click that comes too soon after the
//     first (a double click) does not count;
//   - "Discard the draft" of a refused change, after a question.
//
// Every control carries `data-feature="save"`.

import { FEATURES } from "../shared/features.mjs";
import { el, mount } from "../shared/dom.mjs";
import { blockedKey, itemErrorKey } from "./popupFlow.mjs";

/** @typedef {import("./page.mjs").Texts} Texts */
/** @typedef {ReturnType<typeof import("./popupFlow.mjs").createSyncItemsFlow>} ItemsFlow */
/** @typedef {import("./popupFlow.mjs").ConflictSideView} ConflictSideView */
/** @typedef {import("./popupFlow.mjs").SyncView} SyncView */

/** How long after the first click of a choice the second one starts to count (a double click is one action). */
export const SECOND_CLICK_MS = 400;

/** The marker of the feature's controls. */
const FEATURE = Object.freeze({ "data-feature": "save" });

/** A moment as the reader's date and time, or null. @param {number | null} ms @param {string} lang */
function momentOf(ms, lang) {
  if (ms === null) return null;
  try {
    return new Intl.DateTimeFormat(lang, { dateStyle: "medium", timeStyle: "short" }).format(new Date(ms));
  } catch {
    return null;
  }
}

/**
 * What the sync's part shows of the items, or null when nothing waits: how many changes wait to be sent, and how many
 * items need the user (a conflict or a refused change), with the way to them.
 * @param {{ texts: Texts, sync: SyncView, onReview: () => void }} options
 * @returns {HTMLElement | null}
 */
export function createSyncAttention({ texts, sync, onReview }) {
  if (!FEATURES.save) return null;
  const t = texts.t;
  const needs = sync.conflicts + sync.blocked;
  if (sync.pending === 0 && needs === 0) return null;
  const box = el("div", { class: "ff-sync-items", "data-role": "sync-attention" });
  if (sync.pending > 0) box.append(el("p", { class: "ff-hint", "data-role": "sync-pending" }, t("sync.items.pending", { count: sync.pending })));
  if (needs > 0) {
    const review = el("button", { type: "button", class: "ff-button", "data-role": "sync-review", ...FEATURE }, t("sync.items.review"));
    review.addEventListener("click", () => onReview());
    box.append(el("p", { "data-role": "sync-needs" }, t("sync.items.needs", { count: needs })), review);
  }
  return box;
}

/**
 * The list of the items whose change waits, was refused or is in conflict. A conflict opens its card; a refused change
 * can be discarded, after a question.
 * @param {{ texts: Texts, flow: ItemsFlow, onClose: () => void, now?: () => number }} options
 * @returns {{ root: HTMLElement, loaded: Promise<void> }}
 */
export function createSyncItems({ texts, flow, onClose, now = Date.now }) {
  if (!FEATURES.save) throw Object.assign(new Error("not_available"), { code: "not_available" });
  const t = texts.t;
  const root = el("section", { class: "ff-sync-list", "data-role": "sync-items", "data-hold": "1" });
  const message = el("p", { class: "ff-error", role: "alert", "data-role": "sync-items-error", hidden: true });
  /** @param {string | null} key */
  const say = (key) => {
    message.textContent = key === null ? "" : t(key);
    message.hidden = key === null;
  };
  const back = () => {
    const button = el("button", { type: "button", class: "ff-button", "data-role": "sync-items-back", ...FEATURE }, t("sync.items.back"));
    button.addEventListener("click", () => onClose());
    return button;
  };

  /** @param {import("./popupFlow.mjs").SyncItem} item */
  function rowOf(item) {
    const row = el(
      "li",
      { class: "ff-sync-row", "data-role": "sync-item", "data-state": item.state },
      el("span", { class: "ff-sync-row-name", "data-role": "sync-item-name" }, item.name === "" ? t("popup.item.unnamed") : item.name),
      item.username !== "" ? el("span", { class: "ff-hint", "data-role": "sync-item-user" }, item.username) : null,
      el("span", { class: "ff-sync-row-state", "data-role": "sync-item-state" }, t(`sync.items.state.${item.state}`)),
    );
    if (item.state === "conflict") {
      const open = el("button", { type: "button", class: "ff-button ff-primary", "data-role": "sync-item-resolve", ...FEATURE }, t("sync.items.resolve"));
      open.addEventListener("click", () => {
        const card = createConflictCard({ texts, flow, ref: item.ref, now, onDone: () => void load(), onBack: () => void load() });
        mount(root, card.root);
      });
      row.append(open);
    } else if (item.state === "blocked") {
      row.append(el("p", { class: "ff-hint", "data-role": "sync-item-reason" }, t(blockedKey(item.reason))), discardPart(item));
    }
    return row;
  }

  /** "Discard the draft", then a question with its two answers; the focus goes to "Keep it". @param {import("./popupFlow.mjs").SyncItem} item */
  function discardPart(item) {
    const box = el("div", { class: "ff-discard", "data-role": "discard" });
    const start = el("button", { type: "button", class: "ff-button", "data-role": "discard-start", ...FEATURE }, t("sync.items.discard"));
    start.addEventListener("click", () => ask());
    mount(box, start);
    function ask() {
      const confirm = el("button", { type: "button", class: "ff-button ff-danger", "data-role": "discard-confirm", ...FEATURE }, t("sync.items.discard_confirm"));
      const cancel = el("button", { type: "button", class: "ff-button", "data-role": "discard-cancel", ...FEATURE }, t("sync.items.discard_cancel"));
      cancel.addEventListener("click", () => {
        mount(box, start);
        start.focus();
      });
      confirm.addEventListener("click", async () => {
        confirm.setAttribute("disabled", "");
        cancel.setAttribute("disabled", "");
        const done = await flow.discard(item.ref);
        if (done.ok) {
          await load();
          return;
        }
        say(itemErrorKey(done.reason));
        confirm.removeAttribute("disabled");
        cancel.removeAttribute("disabled");
      });
      mount(box, el("p", { "data-role": "discard-question" }, t("sync.items.discard_question")), el("div", { class: "ff-actions" }, confirm, cancel));
      cancel.focus();
    }
    return box;
  }

  async function load() {
    say(null);
    /** @type {{ items: import("./popupFlow.mjs").SyncItem[], total: number }} */
    let found;
    try {
      found = await flow.items();
    } catch {
      mount(root, el("h2", null, t("sync.items.heading")), message, el("div", { class: "ff-actions" }, back()));
      say("sync.item.error.unknown");
      return;
    }
    if (found.items.length === 0) {
      mount(root, el("h2", null, t("sync.items.heading")), el("p", { "data-role": "sync-items-none" }, t("sync.items.none")), el("div", { class: "ff-actions" }, back()));
      return;
    }
    /** @type {HTMLElement[]} */
    const parts = [el("h2", null, t("sync.items.heading")), el("ul", { class: "ff-sync-rows", "data-role": "sync-item-list" }, ...found.items.map(rowOf))];
    if (found.total > found.items.length) {
      parts.push(el("p", { class: "ff-hint", "data-role": "sync-items-more" }, t("sync.items.more", { count: found.total - found.items.length })));
    }
    mount(root, ...parts, message, el("div", { class: "ff-actions" }, back()));
  }

  return { root, loaded: load() };
}

/**
 * The conflict card of one item.
 * @param {{ texts: Texts, flow: ItemsFlow, ref: string, onDone: () => void, onBack: () => void, now?: () => number }} options
 *   `onDone` runs after a choice was carried out, `onBack` when the user goes back without one
 * @returns {{ root: HTMLElement, loaded: Promise<void> }}
 */
export function createConflictCard({ texts, flow, ref, onDone, onBack, now = Date.now }) {
  if (!FEATURES.save) throw Object.assign(new Error("not_available"), { code: "not_available" });
  const t = texts.t;
  const root = el("section", { class: "ff-conflict", "data-role": "conflict-card", "data-hold": "1", "aria-labelledby": "ff-conflict-title" });
  const message = el("p", { class: "ff-error", role: "alert", "data-role": "conflict-error", hidden: true });
  const note = el("p", { class: "ff-hint", role: "status", "data-role": "conflict-note" });
  /** @param {string | null} key */
  const say = (key) => {
    message.textContent = key === null ? "" : t(key);
    message.hidden = key === null;
  };

  /** The choice whose first click came, and when. @type {{ choice: "mine" | "theirs", at: number } | null} */
  let armed = null;
  let busy = false;
  /** @type {Record<"mine" | "theirs", HTMLElement>} */
  const buttons = {
    mine: el("button", { type: "button", class: "ff-button", "data-role": "keep-mine", ...FEATURE }, t("sync.conflict.keep_mine")),
    theirs: el("button", { type: "button", class: "ff-button", "data-role": "keep-theirs", ...FEATURE }, t("sync.conflict.keep_theirs")),
  };
  const cancel = el("button", { type: "button", class: "ff-button", "data-role": "conflict-back", ...FEATURE }, t("sync.conflict.back"));

  /** Back to the state before any first click. */
  function disarm() {
    armed = null;
    for (const choice of /** @type {const} */ (["mine", "theirs"])) {
      buttons[choice].textContent = t(choice === "mine" ? "sync.conflict.keep_mine" : "sync.conflict.keep_theirs");
      buttons[choice].removeAttribute("data-armed");
      buttons[choice].classList?.remove("ff-danger");
    }
    note.textContent = "";
  }

  /** @param {"mine" | "theirs"} choice */
  async function click(choice) {
    if (busy) return;
    const at = now();
    if (armed === null || armed.choice !== choice) {
      // The first click: the button asks again, and says what is dropped for good.
      disarm();
      armed = { choice, at };
      buttons[choice].textContent = t(`sync.conflict.confirm_${choice}`);
      buttons[choice].setAttribute("data-armed", "1");
      buttons[choice].classList?.add("ff-danger");
      note.textContent = t(`sync.conflict.drops_${choice}`);
      return;
    }
    // A second click that comes as part of a double click is not a second decision.
    if (at - armed.at < SECOND_CLICK_MS) return;
    busy = true;
    say(null);
    for (const button of [buttons.mine, buttons.theirs, cancel]) button.setAttribute("disabled", "");
    root.setAttribute("aria-busy", "true");
    note.textContent = t("sync.conflict.saving");
    const done = await flow.resolve(ref, choice);
    root.setAttribute("aria-busy", "false");
    busy = false;
    if (done.ok) {
      onDone();
      return;
    }
    // Nothing was done. The versions are read again before the next choice (the server's may be another one now).
    const reason = done.reason;
    await load();
    say(itemErrorKey(reason));
  }
  buttons.mine.addEventListener("click", () => void click("mine"));
  buttons.theirs.addEventListener("click", () => void click("theirs"));
  cancel.addEventListener("click", () => {
    if (!busy) onBack();
  });

  /** One version: its name, user name, when and where it was changed. @param {"mine" | "theirs"} which @param {ConflictSideView} side */
  function block(which, side) {
    const when = momentOf(side.modified, texts.lang);
    return el(
      "section",
      { class: "ff-conflict-side", "data-role": "conflict-side", "data-side": which },
      el("h3", null, t(`sync.conflict.${which}`)),
      side.deleted ? el("p", { class: "ff-notice", "data-role": "conflict-deleted" }, t(`sync.conflict.deleted_${which}`)) : null,
      side.name !== null ? el("p", { class: "ff-conflict-name", "data-role": "conflict-name" }, side.name === "" ? t("popup.item.unnamed") : side.name) : null,
      el(
        "dl",
        { class: "ff-conflict-facts" },
        side.deleted ? null : el("dt", null, t("sync.conflict.username")),
        side.deleted ? null : el("dd", { "data-role": "conflict-username" }, side.username === "" ? t("sync.conflict.none") : side.username),
        el("dt", null, t("sync.conflict.modified")),
        el("dd", { "data-role": "conflict-modified" }, when ?? t("sync.conflict.unknown")),
        el("dt", null, t("sync.conflict.device")),
        el("dd", { "data-role": "conflict-device" }, side.device === "" ? t("sync.conflict.unknown") : side.device),
      ),
    );
  }

  async function load() {
    disarm();
    const data = await flow.conflict(ref);
    if (!data.ok) {
      mount(root, el("h2", { id: "ff-conflict-title" }, t("sync.conflict.heading")), message, el("div", { class: "ff-actions" }, cancel));
      say(itemErrorKey(data.reason));
      return;
    }
    for (const button of [buttons.mine, buttons.theirs, cancel]) button.removeAttribute("disabled");
    mount(
      root,
      el("h2", { id: "ff-conflict-title" }, t("sync.conflict.heading")),
      el("p", { class: "ff-hint" }, t("sync.conflict.intro")),
      el("div", { class: "ff-conflict-sides" }, block("mine", data.mine), block("theirs", data.theirs)),
      el("p", { class: "ff-hint", "data-role": "conflict-no-password" }, t("sync.conflict.no_password")),
      el("div", { class: "ff-actions", "data-role": "conflict-choices" }, buttons.mine, buttons.theirs, cancel),
      note,
      message,
    );
  }

  return { root, loaded: load() };
}
