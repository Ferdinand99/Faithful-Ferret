// The notice a tab shows when another tab of the same browser holds the vault: "The vault is open in
// another tab", with the button "Use here". The tab has no sync engine, and nothing from the vault is
// decrypted or shown in it. The button moves the vault here (`sync.takeOver()`): the other tab is asked to
// stop and let go, and is taken from after about three seconds without an answer. The tab that held
// the vault shows this same notice from then on.
import { el, mount } from "../dom.mjs";

/**
 * @typedef {object} StandbyOptions
 * @property {import("./common.mjs").Translate} t
 * @property {{ takeOver(): Promise<unknown>, standby(): boolean }} sync
 * @property {() => void} onTaken the vault is here now (or the tab is not on standby any more): show the screen again
 * @property {() => Promise<unknown>} lock locks the vault
 * @property {() => boolean} [touch] marks activity; false when the vault just locked
 */

/**
 * @param {StandbyOptions} options
 * @returns {{ root: HTMLElement, focus(): void }}
 */
export function standbyView({ t, sync, onTaken, lock, touch = () => true }) {
  const heading = el("h1", { id: "standby-title" }, t("standby.title"));
  const body = el("p", { id: "standby-body" }, t("standby.body"));
  // The progress and the error share a place whose height is kept, so the card does not change height when either comes.
  const status = el("p", { class: "status standby-status", role: "status", "data-role": "status" });
  const errorBox = el("p", { class: "error standby-error", role: "alert", "data-role": "error" });
  const useHere = /** @type {HTMLButtonElement} */ (el("button", { type: "button", class: "btn btn-primary btn-block", "data-role": "use-here" }, t("standby.use_here")));
  const lockButton = el("button", { type: "button", class: "btn btn-secondary btn-block i-lock", "data-role": "lock" }, t("vault.lock"));
  const root = el("section", {
    class: "auth-card standby vault-ui", "data-role": "standby", "aria-labelledby": "standby-title", "aria-describedby": "standby-body",
  }, heading, body, el("div", { class: "standby-message" }, status, errorBox), el("div", { class: "actions" }, useHere, lockButton));

  /** @param {HTMLElement} node @param {string} text */
  const say = (node, text) => mount(node, ...(text === "" ? [] : [document.createTextNode(text)]));
  let busy = false;
  /** @param {boolean} on */
  const working = (on) => {
    busy = on;
    useHere.setAttribute("aria-disabled", on ? "true" : "false");
    useHere.setAttribute("aria-busy", on ? "true" : "false");
    say(status, on ? t("standby.working") : "");
  };

  useHere.addEventListener("click", async () => {
    if (busy || touch() === false) return;
    say(errorBox, "");
    working(true);
    try {
      await sync.takeOver();
    } catch {
      working(false);
      // A failed start of the engine leaves the tab off standby: the screen is built again and says what is wrong.
      if (!sync.standby()) {
        onTaken();
        return;
      }
      say(errorBox, t("standby.error"));
      /** @type {any} */ (useHere).focus?.();
      return;
    }
    working(false);
    onTaken();
  });
  lockButton.addEventListener("click", () => {
    void lock();
  });
  return { root, focus: () => /** @type {any} */ (useHere).focus?.() };
}
