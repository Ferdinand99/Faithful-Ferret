// The notice a tab shows when another tab of the same browser holds the vault: "The vault is open in
// another tab", with the button "Use here". The tab has no sync engine, and nothing from the vault is
// decrypted or shown in it. The button moves the vault here: the other tab is asked whether it holds
// changes that are not saved (`sync.askOwner()`), and when it says yes, or says nothing within a second, the
// notice warns and asks once more ("Use here anyway"). Then `sync.takeOver()` moves the vault: the other tab is asked to
// stop and let go, and is taken from after about three seconds without an answer. The tab that held
// the vault shows this same notice from then on.
//
// When the tab had a form with changes that are not saved, the form stays on screen below the notice, read-only,
// and the button says "Take back" (`unsaved`). The notice goes away by itself when the vault comes to this tab
// without a press of the button (the other tab locked, signed out or was closed).
import { el, mount } from "../dom.mjs";
import { listenWhileShown } from "./common.mjs";

/**
 * @typedef {object} StandbyOptions
 * @property {import("./common.mjs").Translate} t
 * @property {{ takeOver(): Promise<unknown>, standby(): boolean, askOwner?(): Promise<"free" | "clear" | "unsaved" | "no_answer">, onStandby?(fn: (standby: boolean) => void): () => void }} sync
 * @property {() => void} onTaken the vault is here now (or the tab is not on standby any more): show the screen again
 * @property {() => Promise<unknown>} lock locks the vault
 * @property {() => boolean} [touch] marks activity; false when the vault just locked
 * @property {boolean} [unsaved] a form with changes that are not saved stays on the screen below the notice
 */

/**
 * @param {StandbyOptions} options
 * @returns {{ root: HTMLElement, focus(): void }}
 */
export function standbyView({ t, sync, onTaken, lock, touch = () => true, unsaved = false }) {
  const heading = el("h1", { id: "standby-title" }, t(unsaved ? "standby.unsaved_title" : "standby.title"));
  const body = el("p", { id: "standby-body" }, t(unsaved ? "standby.unsaved_body" : "standby.body"));
  // The progress and the error share a place whose height is kept, so the card does not change height when either comes.
  const status = el("p", { class: "status standby-status", role: "status", "data-role": "status" });
  const errorBox = el("p", { class: "error standby-error", role: "alert", "data-role": "error" });
  // The warning that the other tab may hold changes that are not saved, with the way on and the way back.
  const warningText = el("p", { "data-role": "warning-text" });
  const confirm = /** @type {HTMLButtonElement} */ (el("button", { type: "button", class: "btn btn-secondary", "data-role": "use-here-anyway" }, t("standby.use_anyway")));
  const cancel = /** @type {HTMLButtonElement} */ (el("button", { type: "button", class: "btn btn-secondary", "data-role": "warning-cancel" }, t("standby.cancel")));
  // The buttons are in the page only while the warning is shown.
  const warning = el("div", { class: "standby-warning", role: "alert", "data-role": "warning" });
  warning.hidden = true;
  /** @param {string} text */
  const showWarning = (text) => {
    say(warningText, text);
    mount(warning, warningText, el("div", { class: "actions" }, confirm, cancel));
    warning.hidden = false;
  };
  const hideWarning = () => {
    mount(warning);
    warning.hidden = true;
  };
  const useHere = /** @type {HTMLButtonElement} */ (el("button", {
    type: "button", class: "btn btn-primary btn-block", "data-role": unsaved ? "take-back" : "use-here",
  }, t(unsaved ? "standby.take_back" : "standby.use_here")));
  const lockButton = el("button", { type: "button", class: "btn btn-secondary btn-block i-lock", "data-role": "lock" }, t("vault.lock"));
  const root = el("section", {
    class: "auth-card standby vault-ui", "data-role": "standby", "aria-labelledby": "standby-title", "aria-describedby": "standby-body",
  }, heading, body, el("div", { class: "standby-message" }, status, errorBox), warning, el("div", { class: "actions" }, useHere, lockButton));

  /** @param {HTMLElement} node @param {string} text */
  const say = (node, text) => mount(node, ...(text === "" ? [] : [document.createTextNode(text)]));
  let busy = false;
  /** @param {boolean} on @param {string} [text] */
  const working = (on, text = "standby.working") => {
    busy = on;
    useHere.setAttribute("aria-disabled", on ? "true" : "false");
    useHere.setAttribute("aria-busy", on ? "true" : "false");
    say(status, on ? t(text) : "");
  };
  let taken = false;
  /** The screen is built again, once. */
  const done = () => {
    if (taken) return;
    taken = true;
    onTaken();
  };

  /** Moves the vault here. */
  async function moveHere() {
    working(true);
    try {
      await sync.takeOver();
    } catch {
      working(false);
      // A failed start of the engine leaves the tab off standby: the screen is built again and says what is wrong.
      if (!sync.standby()) {
        done();
        return;
      }
      say(errorBox, t("standby.error"));
      /** @type {any} */ (useHere).focus?.();
      return;
    }
    working(false);
    done();
  }

  useHere.addEventListener("click", async () => {
    if (busy || touch() === false) return;
    say(errorBox, "");
    hideWarning();
    if (typeof sync.askOwner !== "function") {
      await moveHere();
      return;
    }
    working(true, "standby.checking");
    /** @type {"free" | "clear" | "unsaved" | "no_answer"} */
    let answer;
    try {
      answer = await sync.askOwner();
    } catch {
      working(false);
      if (!sync.standby()) {
        done();
        return;
      }
      say(errorBox, t("standby.error"));
      return;
    }
    working(false);
    if (answer === "unsaved" || answer === "no_answer") {
      showWarning(t(answer === "unsaved" ? "standby.warn_unsaved" : "standby.warn_no_answer"));
      /** @type {any} */ (confirm).focus?.();
      return;
    }
    await moveHere();
  });
  confirm.addEventListener("click", async () => {
    if (busy || touch() === false) return;
    hideWarning();
    await moveHere();
  });
  cancel.addEventListener("click", () => {
    hideWarning();
    /** @type {any} */ (useHere).focus?.();
  });
  lockButton.addEventListener("click", () => {
    void lock();
  });
  // The vault came to this tab without the button (the other tab locked, signed out or closed): the screen is built again.
  if (typeof sync.onStandby === "function") {
    const onStandby = sync.onStandby.bind(sync);
    listenWhileShown(root, { on: (_event, fn) => onStandby(fn) }, "standby", (/** @type {boolean} */ on) => {
      if (on === false) done();
    });
  }
  return { root, focus: () => /** @type {any} */ (useHere).focus?.() };
}
