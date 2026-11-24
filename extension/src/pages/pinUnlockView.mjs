// The PIN part of the popup's locked view: one field for the PIN, the "123" button, "Unlock with PIN", the number of tries
// that are left, the wait after a wrong PIN with its countdown, and "Use master password instead", which is always there.
// Only a build with unlock on has it: this module asks the build flag and gives nothing in a release. The popup (popup.mjs)
// shows it only when the background says a PIN is set and allowed (`pinPolicy` of popupFlow.mjs).
//
// What the part does with the PIN: it is read from the field once, at the click, and the field is emptied at once (before the
// request goes out). It is emptied again when the background answers, when the part is wiped (the popup closes, the view is
// built again, the user chooses the master password) and when the page goes away. The PIN is never written to storage or to a
// log, never put in an attribute, and never sent anywhere but the one `pin_unlock` request. The "123" button changes only the
// `inputmode` of the field, and it is not remembered. A text that tells the user about a try (wrong, wait, wiped, stale, too
// little memory, the offline window) comes from a fixed list of codes; a code that is not on the list never shows.
//
// The wait: after a wrong PIN the background says how long the next try has to wait. While it runs, "Unlock with PIN" is
// disabled, Enter does nothing (the typed PIN stays), a countdown is shown to the eye and not read out second by second, and
// the page says once, politely, when the wait is over; the focus then returns to the field.

import { el } from "../shared/dom.mjs";
import { FEATURES } from "../shared/features.mjs";
import { secretField } from "./unlockDialog.mjs";
import { PIN_MAX_CHARS, checkPin } from "./unlockFlow.mjs";

/** The feature mark on the part and on the controls the tests and the build check look for. */
const FEATURE = Object.freeze({ "data-feature": "unlock" });

const ID = "pin-unlock";

/** The most a countdown tick waits (milliseconds): the page counts in whole seconds. */
const TICK_MS = 1000;

/**
 * @typedef {import("./popupFlow.mjs").PinOffer} PinOffer
 * @typedef {import("./popupFlow.mjs").PopupView} PopupView
 * @param {{
 *   texts: import("./page.mjs").Texts,
 *   flow: { pinUnlock(pin: string): Promise<{ result: import("./popupFlow.mjs").PinResult, view: PopupView }> },
 *   offer: PinOffer,
 *   onDone: (view: PopupView) => void,
 *   onEnded: (message: string) => void,
 *   onUseMaster: () => void,
 *   schedule?: (fn: () => void, ms: number) => unknown,
 *   cancel?: (handle: any) => void,
 *   now?: () => number,
 * }} deps
 *   `onDone` gets the view the background reports after an answer that opened the vault, or that changed the view (a
 *   sign-out); `onEnded` is told that the PIN cannot be tried again, with the text that says why; `onUseMaster`
 *   that the user chose the master password. `schedule`, `cancel` and `now` are the timer and the clock (the tests set them).
 * @returns {{ root: HTMLElement, focus: () => void, wipe: () => void, waiting: () => boolean }}
 */
export function createPinUnlock({ texts, flow, offer, onDone, onEnded, onUseMaster, schedule = (fn, ms) => setTimeout(fn, ms), cancel = (handle) => clearTimeout(handle), now = () => Date.now() }) {
  const t = (/** @type {string} */ key, /** @type {Record<string, string | number>} */ vars = {}) => texts.t(key, vars);
  /** The text of a reason; a reason that has no text here (the catalog gives back the key) gets the general one, never the code. */
  const reasonText = (/** @type {string} */ key, /** @type {Record<string, string | number>} */ vars = {}) => {
    const text = t(key, vars);
    return text === key ? t("session.error.unknown") : text;
  };

  const field = secretField({ id: `${ID}-input`, name: "pin", label: t("unlock.pin.label"), role: "pin-input", toggleLabel: t("unlock.pin.show"), toggleRole: "pin-toggle" });
  const input = field.input;
  input.setAttribute("aria-describedby", `${ID}-hint ${ID}-attempts ${ID}-offline ${ID}-live`);
  const numeric = /** @type {HTMLButtonElement} */ (
    el("button", { type: "button", class: "ff-button ff-pin-numeric", "aria-pressed": "false", "aria-label": t("unlock.pin.numeric.label"), "data-role": "pin-numeric", ...FEATURE }, t("unlock.pin.numeric"))
  );
  const hint = el("p", { class: "ff-hint", id: `${ID}-hint`, "data-role": "pin-hint" }, t("unlock.pin.hint"));
  const attempts = el("p", { class: "ff-hint", id: `${ID}-attempts`, "data-role": "pin-attempts", hidden: true });
  const offline = el("p", { class: "ff-hint", id: `${ID}-offline`, "data-role": "pin-offline", hidden: true });
  // The line the page speaks through: a try that failed, the wait, the end of the wait. It is always in the page (never
  // hidden), so what is put in it is read out politely.
  const live = el("p", { class: "ff-pin-live", id: `${ID}-live`, "aria-live": "polite", "aria-atomic": "true", "data-role": "pin-error" });
  const countdown = el("p", { class: "ff-pin-countdown", "aria-hidden": "true", "data-role": "pin-countdown", hidden: true });
  const submit = /** @type {HTMLButtonElement} */ (el("button", { type: "submit", class: "ff-button ff-primary", "data-role": "pin-unlock", ...FEATURE }, t("unlock.pin.submit")));
  const useMaster = /** @type {HTMLButtonElement} */ (el("button", { type: "button", class: "ff-button", "data-role": "use-master", ...FEATURE }, t("unlock.pin.use_password")));

  const form = /** @type {HTMLFormElement} */ (
    el(
      "form",
      { class: "ff-form ff-pin-unlock", "data-role": "pin-unlock-form", ...FEATURE },
      el("p", { class: "ff-lead" }, t("unlock.pin.lead")),
      field.row,
      el("div", { class: "ff-pin-tools" }, numeric),
      hint,
      attempts,
      offline,
      live,
      countdown,
      el("div", { class: "ff-actions" }, submit, useMaster),
    )
  );

  let busy = false;
  /** Counts the answers that are still wanted: an answer for a part that was wiped since is not shown. */
  let epoch = 0;
  /** When the wait ends (a time of `now()`), or 0. */
  let until = 0;
  /** @type {unknown} */
  let timer = null;

  /** @param {string[]} keys @param {Record<string, string | number>} [vars] @param {"error" | "info"} [kind] */
  const say = (keys, vars = {}, kind = "error") => {
    live.textContent = keys.map((key) => reasonText(key, vars)).join(" ");
    live.setAttribute("data-kind", kind);
  };

  /** @param {number | null} left */
  const showAttempts = (left) => {
    const show = left !== null && left > 0 && left < 5;
    attempts.hidden = !show;
    attempts.textContent = show ? t("unlock.pin.attempts", { count: /** @type {number} */ (left) }) : "";
  };

  const emptyField = () => {
    input.value = "";
    input.setAttribute("type", "password");
    field.display(false);
    // The "123" button is not remembered: the keyboard is the plain one again.
    input.setAttribute("inputmode", "text");
    numeric.setAttribute("aria-pressed", "false");
  };

  const stopTimer = () => {
    if (timer !== null) cancel(timer);
    timer = null;
  };

  const waiting = () => until > now();

  const endWait = () => {
    stopTimer();
    until = 0;
    countdown.hidden = true;
    countdown.textContent = "";
    submit.removeAttribute("disabled");
    say(["unlock.pin.wait_over"], {}, "info");
    // The focus comes back to the field only when it is still in this part or nowhere (not when the person moved on).
    const active = document.activeElement;
    if (active === null || active === document.body || active === input || form.contains?.(active) === true) input.focus();
  };

  const tick = () => {
    timer = null;
    const left = until - now();
    if (left <= 0) {
      endWait();
      return;
    }
    countdown.textContent = t("unlock.pin.wait", { seconds: Math.ceil(left / 1000) });
    timer = schedule(tick, Math.min(TICK_MS, left));
    // A timer must not keep a test process alive (a browser's timer id is a number and has no `unref`).
    /** @type {any} */ (timer)?.unref?.();
  };

  /** @param {number} ms */
  const startWait = (ms) => {
    stopTimer();
    if (ms <= 0) {
      until = 0;
      return;
    }
    until = now() + ms;
    submit.setAttribute("disabled", "");
    countdown.hidden = false;
    tick();
  };

  numeric.addEventListener("click", () => {
    const on = numeric.getAttribute("aria-pressed") !== "true";
    numeric.setAttribute("aria-pressed", on ? "true" : "false");
    input.setAttribute("inputmode", on ? "numeric" : "text");
  });
  field.toggle.addEventListener("click", () => {
    const on = field.toggle.getAttribute("aria-pressed") !== "true";
    input.setAttribute("type", on ? "text" : "password");
    field.display(on);
  });
  useMaster.addEventListener("click", () => {
    emptyField();
    onUseMaster();
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    // During a wait, and while an answer is out, Enter does nothing: not a request, and the typed PIN stays.
    if (busy || waiting()) return;
    if (input.value === "") {
      say(["unlock.pin.error.empty"]);
      input.focus();
      return;
    }
    // The rule is public (the administrator's minimum, and the core's fixed floor and ceiling): a PIN that cannot be right is
    // not sent, so it is not a try, and the typed value stays so the person can finish it.
    const rule = checkPin(input.value, offer.minLength);
    if (!rule.ok) {
      say([rule.reason === "too_short" ? "unlock.pin.error.too_short" : "unlock.pin.error.too_long"], { min: Math.max(offer.minLength, 4), max: PIN_MAX_CHARS });
      input.focus();
      return;
    }
    // Read once, and empty the field before the request goes out: nothing waits in the page for the answer.
    const pin = input.value;
    emptyField();
    say([]);
    busy = true;
    const mine = epoch;
    submit.setAttribute("disabled", "");
    submit.setAttribute("aria-busy", "true");
    form.setAttribute("aria-busy", "true");
    /** @type {Awaited<ReturnType<typeof flow.pinUnlock>> | null} */
    let answer = null;
    try {
      answer = await flow.pinUnlock(pin);
    } catch {
      answer = null;
    }
    // The part was wiped while the request was out (the popup was rebuilt): the answer belongs to nobody.
    if (mine !== epoch) return;
    busy = false;
    submit.removeAttribute("aria-busy");
    form.setAttribute("aria-busy", "false");
    emptyField();
    if (answer === null) {
      // The background did not answer (it stopped): nothing is known of the try, so the part says what the master password does.
      submit.removeAttribute("disabled");
      say(["session.error.disconnected"]);
      input.focus();
      return;
    }
    const { result, view } = answer;
    if (result.ok || view.view !== "locked") {
      submit.removeAttribute("disabled");
      onDone(view);
      return;
    }
    if (result.ended) {
      submit.removeAttribute("disabled");
      onEnded(result.keys.map((key) => reasonText(key)).join(" "));
      return;
    }
    showAttempts(result.left);
    if (result.waitMs > 0) {
      const keys = [...result.keys, "unlock.pin.wait_say"];
      say(keys, { count: result.left ?? 0, seconds: Math.ceil(result.waitMs / 1000) });
      startWait(result.waitMs);
    } else {
      submit.removeAttribute("disabled");
      say(result.keys, { count: result.left ?? 0 });
    }
    // The answer was a refusal that keeps the PIN: the focus is back on the field (also during a wait, so a person can type on).
    input.focus();
  });

  // The page goes away (the popup closed): nothing typed stays in the field.
  if (typeof globalThis.addEventListener === "function") globalThis.addEventListener("pagehide", () => wipe(), { once: true });

  function wipe() {
    epoch += 1;
    busy = false;
    stopTimer();
    emptyField();
    submit.removeAttribute("aria-busy");
    form.setAttribute("aria-busy", "false");
    if (!waiting()) submit.removeAttribute("disabled");
  }

  // What is true when the part is shown: the tries that are left, the offline window, and a wait that is still running.
  showAttempts(offer.failuresLeft);
  if (!offer.offlineOk) {
    offline.hidden = false;
    offline.textContent = t("unlock.pin.offline_first");
  }
  if (offer.waitMs > 0) {
    say(["unlock.pin.error.pin_wait", "unlock.pin.wait_say"], { seconds: Math.ceil(offer.waitMs / 1000) }, "info");
    startWait(offer.waitMs);
  }

  return {
    root: form,
    focus: () => input.focus(),
    wipe,
    waiting,
  };
}

/**
 * The part, or null in a build without the feature. The only way the popup reaches the part, so a release holds no path to it.
 * @param {Parameters<typeof createPinUnlock>[0]} deps
 */
export function createPinUnlockPart(deps) {
  return FEATURES.unlock ? createPinUnlock(deps) : null;
}
