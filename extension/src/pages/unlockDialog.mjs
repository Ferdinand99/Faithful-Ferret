// The dialog that sets or changes the PIN (inside the "Unlock" part of the settings view): the master password again, the
// PIN twice, the "123" button, the choice about the browser restart, the warning every time, and the acknowledgement that a
// PIN kept on disk needs. It is a form in the page (not a window), so it fits the popup as well as the settings tab.
//
// What the dialog does with a secret: the master password, the secret key and the PIN are read from the fields at the
// moment of the click, the fields are emptied at once (before the request goes out), and they are emptied again when the
// dialog closes, when the background answers, when Ferret locks and when the page goes away. Nothing is written to storage
// or to a log, and the PIN is never put in an attribute or a message to anything but the one request.
//
// This module is only reached from the section of unlockSettings.mjs, which asks the build flag; it asks none itself.

import { el } from "../shared/dom.mjs";
import { PIN_MAX_CHARS, checkPin, unlockErrorKey } from "./unlockFlow.mjs";

/** How often an open dialog asks whether the vault is still open (milliseconds). */
export const LOCK_POLL_MS = 4000;

/**
 * A field for a secret with the web vault's eye button at its end: one fixed name for the button and `aria-pressed` for the
 * state (the name does not flip).
 * @param {{ id: string, name: string, label: string, role: string, toggleLabel: string, toggleRole: string, hint?: string }} o
 */
function secretField({ id, name, label, role, toggleLabel, toggleRole, hint }) {
  const input = /** @type {HTMLInputElement} */ (el("input", { id, name, type: "password", class: "ff-input", autocomplete: "off", "data-role": role }));
  const eye = el("span", { class: "ff-eye", "aria-hidden": "true", "data-icon": "eye" });
  const toggle = /** @type {HTMLButtonElement} */ (el("button", { type: "button", class: "ff-reveal-toggle", "aria-pressed": "false", "aria-label": toggleLabel, "data-role": toggleRole }, eye));
  const row = el(
    "div",
    { class: "ff-field" },
    el("label", { for: id, class: "ff-label" }, label),
    el("div", { class: "ff-secret-input" }, input, toggle),
    hint ? el("p", { class: "ff-hint", id: `${id}-hint` }, hint) : null,
  );
  if (hint) input.setAttribute("aria-describedby", `${id}-hint`);
  /** @param {boolean} on */
  const display = (on) => {
    toggle.setAttribute("aria-pressed", on ? "true" : "false");
    eye.setAttribute("data-icon", on ? "eye-off" : "eye");
  };
  return { row, input, toggle, display };
}

/**
 * @typedef {import("./unlockFlow.mjs").Outcome} Outcome
 * @typedef {{ mode: "set" | "change", minLength: number, afterRestart: boolean, location?: "disk" | "session" | null }} OpenOptions
 * @param {{
 *   texts: import("./page.mjs").Texts,
 *   flow: ReturnType<typeof import("./unlockFlow.mjs").createUnlockFlow>,
 *   onDone: (result: { mode: "set" | "change" }) => void,
 *   onClosed: (why: "cancel" | "done" | "locked" | "gone") => void,
 *   onLate?: () => void,
 *   pollMs?: number,
 * }} deps
 *   `onDone` is told the PIN was saved (the dialog is closed already); `onClosed` that the dialog is closed and emptied, and why;
 *   `onLate` that a PIN was saved after the dialog had been closed (the section reads what is true again)
 */
export function createPinDialog({ texts, flow, onDone, onClosed, onLate = () => {}, pollMs = LOCK_POLL_MS }) {
  const t = (/** @type {string} */ key, /** @type {Record<string, string | number>} */ vars = {}) => texts.t(key, vars);
  const ID = "unlock-pin";

  const title = el("h4", { id: `${ID}-title`, class: "ff-pin-title", tabindex: "-1", "data-role": "pin-title" });
  const rule = el("p", { class: "ff-hint", id: `${ID}-rule`, "data-role": "pin-rule" });
  const password = secretField({ id: `${ID}-password`, name: "master-password", label: t("settings.unlock.dialog.password.label"), role: "pin-password", toggleLabel: t("settings.unlock.dialog.password.show"), toggleRole: "pin-password-toggle" });
  const secret = secretField({ id: `${ID}-secret`, name: "secret-key", label: t("settings.unlock.dialog.secret.label"), role: "pin-secret", toggleLabel: t("settings.unlock.dialog.secret.show"), toggleRole: "pin-secret-toggle" });
  const pin = secretField({ id: `${ID}-pin`, name: "pin", label: t("settings.unlock.dialog.pin.label"), role: "pin-pin", toggleLabel: t("settings.unlock.dialog.pin.show"), toggleRole: "pin-pin-toggle" });
  const again = /** @type {HTMLInputElement} */ (el("input", { id: `${ID}-again`, name: "pin-again", type: "password", class: "ff-input", autocomplete: "off", "data-role": "pin-again" }));
  const againRow = el("div", { class: "ff-field" }, el("label", { for: `${ID}-again`, class: "ff-label" }, t("settings.unlock.dialog.pin.again")), again);
  // The "123" button: it only changes the keyboard a phone or a tablet opens. It is not remembered and limits nothing.
  const numeric = /** @type {HTMLButtonElement} */ (
    el("button", { type: "button", class: "ff-button ff-pin-numeric", "aria-pressed": "false", "aria-label": t("settings.unlock.dialog.pin.numeric.label"), "data-role": "pin-numeric" }, t("settings.unlock.dialog.pin.numeric"))
  );
  const pinHint = el("p", { class: "ff-hint", id: `${ID}-hint`, "data-role": "pin-hint" }, t("settings.unlock.dialog.pin.hint"));

  const restart = /** @type {HTMLInputElement} */ (el("input", { id: `${ID}-restart`, name: "require-master-password-after-restart", type: "checkbox", "aria-describedby": `${ID}-restart-hint`, "data-role": "pin-restart" }));
  const restartHint = el("p", { class: "ff-hint", id: `${ID}-restart-hint`, "data-role": "pin-restart-hint" });
  const restartRow = el("div", { class: "ff-check", "data-role": "pin-restart-row" }, restart, el("label", { for: `${ID}-restart`, class: "ff-label" }, t("settings.unlock.restart.label")), restartHint);

  // The warning is in the dialog every time it opens, for a new PIN and for a changed one, whichever way the restart choice
  // stands; the dialog's description is the warning, so a screen reader reads it when the dialog is entered.
  const warning = el(
    "div",
    { class: "ff-pin-warning", id: `${ID}-warning`, "data-role": "pin-warning" },
    el("p", { class: "ff-pin-warning-title", id: `${ID}-warning-title` }, t("settings.unlock.warning.title")),
    el("p", { "data-role": "pin-warning-text" }, t("settings.unlock.warning.body")),
  );
  const acknowledge = /** @type {HTMLInputElement} */ (el("input", { id: `${ID}-ack`, name: "acknowledge-pin-risk", type: "checkbox", "aria-describedby": `${ID}-warning-title`, "data-role": "pin-ack" }));
  const acknowledgeRow = el("div", { class: "ff-check", "data-role": "pin-ack-row" }, acknowledge, el("label", { for: `${ID}-ack`, class: "ff-label" }, t("settings.unlock.warning.acknowledge")));

  const error = el("p", { class: "ff-error", role: "alert", "data-role": "pin-error", hidden: true });
  const submitButton = /** @type {HTMLButtonElement} */ (el("button", { type: "submit", class: "ff-button ff-primary", "data-role": "pin-submit" }, t("settings.unlock.dialog.submit")));
  const cancelButton = /** @type {HTMLButtonElement} */ (el("button", { type: "button", class: "ff-button", "data-role": "pin-cancel" }, t("settings.unlock.dialog.cancel")));

  const form = /** @type {HTMLFormElement} */ (
    el(
      "form",
      {
        class: "ff-form ff-pin-dialog",
        role: "dialog",
        "aria-labelledby": `${ID}-title`,
        "aria-describedby": `${ID}-warning`,
        "data-role": "pin-dialog",
        hidden: true,
      },
      title,
      rule,
      password.row,
      secret.row,
      pin.row,
      againRow,
      el("div", { class: "ff-pin-tools" }, numeric),
      pinHint,
      restartRow,
      warning,
      acknowledgeRow,
      error,
      el("div", { class: "ff-actions" }, submitButton, cancelButton),
    )
  );

  // The rule and the note about the "123" button are read out with the PIN fields.
  for (const input of [pin.input, again]) input.setAttribute("aria-describedby", `${ID}-rule ${ID}-hint`);

  let open = false;
  let busy = false;
  /** @type {"set" | "change"} */
  let mode = "set";
  let minLength = 4;
  /** The restart choice is forced to memory (the administrator does not allow disk). */
  let forced = false;
  /** Counts the dialogs and answers: an answer that belongs to a dialog that was closed since is not shown. */
  let epoch = 0;
  /** @type {ReturnType<typeof setTimeout> | null} */
  let timer = null;

  /** @param {string | null} key @param {Record<string, string | number>} [vars] */
  const say = (key, vars = {}) => {
    error.textContent = key === null ? "" : t(key, vars);
    error.hidden = key === null;
  };

  const wipeFields = () => {
    for (const input of [password.input, secret.input, pin.input, again]) {
      input.value = "";
      input.setAttribute("type", "password");
    }
    password.display(false);
    secret.display(false);
    pin.display(false);
    // The "123" button is not remembered: the keyboard is the plain one again.
    pin.input.setAttribute("inputmode", "text");
    again.setAttribute("inputmode", "text");
    numeric.setAttribute("aria-pressed", "false");
    acknowledge.checked = false;
  };

  /** Shows or hides what only a PIN on disk needs: the acknowledgement. */
  const syncDisk = () => {
    acknowledgeRow.hidden = restart.checked;
  };

  /** @param {boolean} on @param {ReturnType<typeof secretField>} field @param {HTMLInputElement[]} inputs */
  const reveal = (on, field, inputs) => {
    for (const input of inputs) input.setAttribute("type", on ? "text" : "password");
    field.display(on);
  };
  password.toggle.addEventListener("click", () => reveal(password.toggle.getAttribute("aria-pressed") !== "true", password, [password.input]));
  secret.toggle.addEventListener("click", () => reveal(secret.toggle.getAttribute("aria-pressed") !== "true", secret, [secret.input]));
  pin.toggle.addEventListener("click", () => reveal(pin.toggle.getAttribute("aria-pressed") !== "true", pin, [pin.input, again]));
  numeric.addEventListener("click", () => {
    const on = numeric.getAttribute("aria-pressed") !== "true";
    numeric.setAttribute("aria-pressed", on ? "true" : "false");
    for (const input of [pin.input, again]) input.setAttribute("inputmode", on ? "numeric" : "text");
  });
  restart.addEventListener("change", syncDisk);

  const stopPolling = () => {
    if (timer !== null) clearTimeout(timer);
    timer = null;
  };

  /**
   * Closes the dialog and empties it.
   * @param {"cancel" | "done" | "locked" | "gone"} why
   */
  function close(why) {
    if (!open) {
      wipeFields();
      return;
    }
    open = false;
    epoch += 1;
    busy = false;
    stopPolling();
    wipeFields();
    say(null);
    submitButton.removeAttribute("disabled");
    submitButton.removeAttribute("aria-busy");
    submitButton.textContent = t("settings.unlock.dialog.submit");
    form.hidden = true;
    onClosed(why);
  }

  /** Asks whether the vault is still open; a dialog on a locked vault is closed and emptied. */
  async function checkLock() {
    if (!open) return;
    const mine = epoch;
    const state = await flow.vaultState();
    if (mine !== epoch || !open) return;
    if (state === "locked" || state === "signed_out") close("locked");
  }

  function schedule() {
    stopPolling();
    if (!open || pollMs <= 0) return;
    timer = setTimeout(async () => {
      timer = null;
      await checkLock();
      if (open) schedule();
    }, pollMs);
    // A timer must not keep a test process alive (a browser's timer id is a number and has no `unref`).
    /** @type {any} */ (timer).unref?.();
  }

  cancelButton.addEventListener("click", () => close("cancel"));
  form.addEventListener("keydown", (event) => {
    if (/** @type {KeyboardEvent} */ (event).key !== "Escape") return;
    event.preventDefault();
    // The popup would close on Escape; the dialog takes it first.
    /** @type {KeyboardEvent} */ (event).stopPropagation?.();
    close("cancel");
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!open || busy) return;
    // What the page can say before it asks anything: nothing is sent for these, and the fields keep what was typed.
    if (password.input.value === "") {
      say("settings.unlock.error.password_missing");
      password.input.focus();
      return;
    }
    const checked = checkPin(pin.input.value, minLength);
    if (!checked.ok) {
      say(unlockErrorKey(checked.reason), { min: minLength, max: PIN_MAX_CHARS });
      pin.input.focus();
      return;
    }
    if (pin.input.value !== again.value) {
      say("settings.unlock.error.mismatch");
      again.focus();
      return;
    }
    const disk = !restart.checked;
    if (disk && !acknowledge.checked) {
      say("settings.unlock.error.not_acknowledged");
      acknowledge.focus();
      return;
    }
    say(null);
    // Read once, and empty the fields before the request goes out: nothing waits in the page for the answer.
    const fields = { password: password.input.value, secretKey: secret.input.value, pin: pin.input.value, location: disk ? "disk" : "session", acknowledged: disk && acknowledge.checked };
    wipeFields();
    busy = true;
    const mine = epoch;
    submitButton.setAttribute("disabled", "");
    submitButton.setAttribute("aria-busy", "true");
    submitButton.textContent = t("settings.unlock.dialog.saving");
    const outcome = await flow.setPin(fields);
    fields.password = "";
    fields.secretKey = "";
    fields.pin = "";
    // The dialog was closed (cancelled, locked, the page went away) while the request was out: the answer is not shown.
    if (mine !== epoch) {
      // The dialog was closed meanwhile; a PIN that did get saved is read again, so the section does not say otherwise.
      if (outcome.ok) onLate();
      return;
    }
    busy = false;
    submitButton.removeAttribute("disabled");
    submitButton.removeAttribute("aria-busy");
    submitButton.textContent = t("settings.unlock.dialog.submit");
    wipeFields();
    if (outcome.ok) {
      const done = mode;
      close("done");
      onDone({ mode: done });
      return;
    }
    say(unlockErrorKey(outcome.reason), { min: minLength, max: PIN_MAX_CHARS });
    password.input.focus();
  });

  return {
    /** The dialog's form (hidden until it is opened). */
    node: form,
    /** @param {OpenOptions} options */
    open(options) {
      if (open) close("cancel");
      mode = options.mode;
      minLength = options.minLength;
      forced = options.afterRestart === false;
      open = true;
      busy = false;
      epoch += 1;
      wipeFields();
      say(null);
      title.textContent = t(mode === "change" ? "settings.unlock.dialog.title.change" : "settings.unlock.dialog.title.set");
      rule.textContent = t("settings.unlock.dialog.rule", { min: minLength, max: PIN_MAX_CHARS });
      // The restart choice is off unless the administrator forbids a PIN on disk: then it is on, locked, and says why.
      // A PIN that is kept in memory stays there when it is changed; moving it to disk is the user's own choice.
      restart.checked = forced || (mode === "change" && options.location === "session");
      if (forced) restart.setAttribute("disabled", "");
      else restart.removeAttribute("disabled");
      restartHint.textContent = t(forced ? "settings.unlock.restart.locked" : "settings.unlock.restart.hint");
      syncDisk();
      form.hidden = false;
      title.focus();
      schedule();
    },
    /** Closes and empties the dialog (the section calls it when the page goes away). @param {"cancel" | "done" | "locked" | "gone"} [why] */
    close: (why = "cancel") => close(why),
    /** Empties the fields without closing. */
    wipe: wipeFields,
    /** Whether the dialog is open. */
    isOpen: () => open,
    /** Asks the background whether the vault is still open and closes the dialog when it is not. */
    checkLock,
    /** The element that has the focus when the dialog opens. */
    title,
  };
}
