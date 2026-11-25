// The one-time code of an item in the popup: the code, grouped for reading, the seconds it still holds, "Copy" and, on a
// page the popup is about, "Fill the code". It shows in the item's view and under a suggestion whose sign-in Ferret has
// just filled, because the page that follows may ask for the code.
//
// The code is made by the background in the core, from the device's clock (`fetchCode`); the secret it comes from never
// reaches this page. The page asks once, counts the seconds down on its own clock, and asks again when the period is over
// (the background answers with the new code and its seconds). Nothing is kept: when the card is stopped (the item's view
// closes, the list is built again) its timer ends, and a refusal of the background (a locked vault, a lost reference)
// clears the code at once and ends the card.
//
// A screen reader hears the code when it changes and nowhere else: the code is a polite live region that is written
// only when its text changes, and the countdown is a timer role, which announces nothing by itself.

import { el } from "../shared/dom.mjs";

/** The tick of the countdown. */
const TICK_MS = 1000;

/** What a code shows instead of digits before the first answer and after a refusal. */
export const CODE_PLACEHOLDER = "••• •••";

/**
 * A code grouped for reading: 3+3 for six digits, 4+4 for eight, 3+3+3 for nine; any other length is left as it is.
 * @param {string} code
 */
export function groupCode(code) {
  if (!/^[0-9]+$/.test(code)) return code;
  if (code.length === 8) return `${code.slice(0, 4)} ${code.slice(4)}`;
  if (code.length === 6) return `${code.slice(0, 3)} ${code.slice(3)}`;
  if (code.length === 9) return `${code.slice(0, 3)} ${code.slice(3, 6)} ${code.slice(6)}`;
  return code;
}

/**
 * @typedef {{ ok: boolean, reason?: string, code?: string, seconds_left?: number }} CodeAnswer
 * @typedef {{ setTimeout(fn: () => void, ms: number): unknown, clearTimeout(id: any): void }} Timers
 */

/**
 * @param {{
 *   t: (key: string, vars?: Record<string, string | number>) => string,
 *   fetchCode: (automatic: boolean) => Promise<CodeAnswer>,
 *   copy: () => unknown,
 *   fill?: (() => unknown) | null,
 *   fillLabel?: string,
 *   onRefused?: (reason: string | undefined) => void,
 *   now?: () => number,
 *   timers?: Timers,
 *   emphasis?: boolean,
 *   quiet?: boolean,
 * }} options `copy` and `fill` run the action and say how it went (the list's toast); `fill` is null where nothing can
 *   be filled (an item found by search); `onRefused` is told why the background gave no code; `now` is the clock the
 *   countdown follows (a deadline, so a pause of the page does not stretch a code); `emphasis` marks the card of a code the
 *   page may ask for now; `quiet`: the first ask is not the user's activity
 */
export function createCodeCard({
  t,
  fetchCode,
  copy,
  fill = null,
  fillLabel = "popup.row.fill_totp",
  onRefused = () => {},
  now = Date.now,
  timers = { setTimeout: (fn, ms) => globalThis.setTimeout(fn, ms), clearTimeout: (id) => globalThis.clearTimeout(id) },
  emphasis = false,
  quiet = false,
}) {
  const code = el("span", { class: "ff-code", "data-role": "totp-code", dir: "ltr", "aria-live": "polite", "aria-atomic": "true" }, CODE_PLACEHOLDER);
  const left = el("span", { class: "ff-code-left", "data-role": "totp-left", role: "timer" });
  const copyButton = el("button", { type: "button", class: "ff-button ff-code-action", "data-role": "totp-copy" }, t("popup.row.copy_totp"));
  const fillButton = fill === null ? null : el("button", { type: "button", class: "ff-button ff-code-action", "data-role": "totp-fill" }, t(fillLabel));
  const root = el(
    "div",
    { class: `ff-code-card${emphasis ? " ff-code-next" : ""}`, "data-role": "totp-card" },
    el("span", { class: "ff-value-label" }, t("popup.item.totp")),
    el("span", { class: "ff-code-line" }, code, left),
    el("span", { class: "ff-code-actions" }, copyButton, fillButton),
  );
  copyButton.addEventListener("click", () => void copy());
  fillButton?.addEventListener("click", () => void fill?.());

  let stopped = false;
  /** The moment the code on show stops holding (the clock's ms), or null before the first answer. @type {number | null} */
  let deadline = null;
  /** The text of the code on show, so a live region is written only when it changes. */
  let shown = CODE_PLACEHOLDER;
  /** @type {unknown} */
  let timer = null;
  let asking = false;

  /** @param {string} text */
  function showCode(text) {
    if (text === shown) return;
    shown = text;
    code.textContent = text;
  }

  function clear() {
    deadline = null;
    showCode(CODE_PLACEHOLDER);
    left.textContent = "";
  }

  /** Shows the seconds left; false when the period is over. */
  function count() {
    if (deadline === null) return false;
    const seconds = Math.ceil((deadline - now()) / 1000);
    if (seconds <= 0) return false;
    left.textContent = t("popup.totp.left", { seconds });
    return true;
  }

  /** @param {boolean} automatic */
  async function ask(automatic) {
    if (stopped || asking) return;
    asking = true;
    /** @type {CodeAnswer} */
    let answer;
    try {
      answer = await fetchCode(automatic);
    } catch (error) {
      answer = { ok: false, reason: typeof (/** @type {any} */ (error)?.code) === "string" ? /** @type {any} */ (error).code : "unknown" };
    } finally {
      asking = false;
    }
    if (stopped) return;
    if (!answer?.ok || typeof answer.code !== "string" || !Number.isSafeInteger(answer.seconds_left)) {
      // No code (a lock, a lost reference): nothing stays on show, and the card does not ask again.
      clear();
      stop();
      onRefused(answer?.reason);
      return;
    }
    deadline = now() + /** @type {number} */ (answer.seconds_left) * 1000;
    showCode(groupCode(answer.code));
    count();
    schedule();
  }

  function schedule() {
    if (stopped) return;
    if (timer !== null) timers.clearTimeout(timer);
    timer = timers.setTimeout(() => {
      timer = null;
      if (stopped) return;
      // The period is over: ask for the next code (a read the page made by itself, not an action of the user).
      if (!count()) void ask(true);
      else schedule();
    }, TICK_MS);
  }

  function stop() {
    stopped = true;
    if (timer !== null) timers.clearTimeout(timer);
    timer = null;
  }

  // The first ask is the user's, unless the popup built the list by itself (the sync changed something).
  void ask(quiet);

  return {
    root,
    /** Ends the card's timer. */
    stop,
    /** The code as shown (for the tests). */
    get shown() {
      return shown;
    },
  };
}
