// `#/recovery-key`: a new recovery key (spec Fase 1 § 4.6, § 6.1), and "reapply the unlock methods"
// after an accepted restore (J25 (i)). The page says first what a new key does and does not do; the
// button asks for the master password again, then shows the new page 2 once (the emergency sheet in
// its "renew" mode). Nothing is sent until the new key has been typed back. "Do not use the new key",
// a lock of the vault or leaving the page discards it, and the old key goes on working.
//
// After the server has the new key, the page says what changed and what did not, and that an older
// backup of the server still holds the old key (J48): the old sheet is kept until a new backup has
// been seen.
//
// The reapply part is shown only when this device keeps a restore note that applies and the server's
// recovery key is below this device's floor (`flows/reapplyMethods.mjs`). A password below the floor
// is sent to the password change.
//
// The new key is on the page only inside the sheet, which is wiped when it is confirmed, refused or
// left. An error is shown by its code, from a fixed list; its message is never shown.
import { clear, el, mount } from "../dom.mjs";
import { codeOf } from "../crypto/errors.mjs";
import { formatMoment } from "./common.mjs";
import { setText } from "./form.mjs";
import { reauthDialog } from "./reauthDialog.mjs";
import { securityErrorText } from "./securityError.mjs";
import { sheetView } from "./sheet.mjs";

/** @typedef {import("./form.mjs").Translate} Translate */
/** @typedef {import("../flows/renewRecovery.mjs").ConfirmNewRk} ConfirmNewRk */
/** @typedef {{ add(fn: () => void): () => void }} Scope */
/** @typedef {{ addEventListener?: Function, removeEventListener?: Function }} Win */

/** The codes with a text of their own in the keys catalog (`keys.error.<code>`). */
export const KEYS_ERRORS = Object.freeze([
  "cancelled", "pinned_floor_downgrade", "pinned_kek_generation", "reapply_not_offered", "renew_pin_save_failed",
  "renew_unconfirmed", "sheet_server_key_missing", "sk_not_remembered",
]);

/**
 * The text of an error on the key pages. `pinned_kek_generation` here is a renewal that the core refused
 * because the server shows an older recovery key than this device has seen: a rollback, or a restore.
 * @param {Translate} t
 * @param {unknown} error
 */
export function keysErrorText(t, error) {
  const code = codeOf(error);
  return KEYS_ERRORS.includes(code) ? t(`keys.error.${code}`) : securityErrorText(t, error);
}

/**
 * The password check of the key pages: the dialog, skipped while the last check covers the next minute.
 * @param {{ t: Translate, session: any, scope?: Scope }} options `session` is the account session
 * @returns {() => Promise<"ok" | "cancelled">}
 */
export function pageReauth({ t, session, scope }) {
  return async () => {
    const email = session.current?.()?.email ?? null;
    let skRequired = false;
    try {
      const status = email === null ? null : await session.deviceStatus(email);
      skRequired = status?.skBit === true && status.skStored !== true;
    } catch {
      skRequired = false;
    }
    return reauthDialog({ t, run: (typed) => session.reauthenticate(typed), until: session.reauthUntil(), skRequired, scope });
  };
}

/**
 * Calls `fn` once when the page is left (the address changes) or the vault locks. Returns what stops it.
 * @param {{ scope?: Scope, win?: Win }} where
 * @param {() => void} fn
 */
export function onLeave({ scope, win }, fn) {
  /** @type {Array<() => void>} */
  const offs = [];
  let gone = false;
  const once = () => {
    if (gone) return;
    gone = true;
    for (const off of offs) off();
    fn();
  };
  if (scope) offs.push(scope.add(once));
  if (typeof win?.addEventListener === "function") {
    win.addEventListener("hashchange", once);
    offs.push(() => win.removeEventListener?.("hashchange", once));
  }
  return () => {
    gone = true;
    for (const off of offs) off();
  };
}

/**
 * The step of the flows that shows the new page 2: the sheet in `host`, with "Do not use the new key" under it.
 * The answer is true once the typed key has passed the core's check, false on "no", a lock or leaving the page.
 * @param {{
 *   t: Translate,
 *   host: HTMLElement,
 *   scope?: Scope,
 *   win?: Win,
 *   download?: (bytes: Uint8Array, filename: string, mime: string) => void,
 *   print?: () => void,
 * }} options
 * @returns {ConfirmNewRk}
 */
export function confirmInPage({ t, host, scope, win, download, print }) {
  return ({ sheet, verify }) => new Promise((resolve) => {
    let done = false;
    /** @type {{ root: HTMLElement, wipe(): void } | null} */
    let view = null;
    /** @param {boolean} answer */
    const finish = (answer) => {
      if (done) return;
      done = true;
      stop();
      view?.wipe();
      view = null;
      clear(host);
      resolve(answer);
    };
    view = sheetView({
      t,
      sheet,
      mode: "renew",
      // A rejection keeps the sheet and says why (a typo, another key); the user tries again.
      onConfirm: async (typed) => {
        await verify(typed);
        finish(true);
      },
      ...(download ? { download } : {}),
      ...(print ? { print } : {}),
    });
    const cancel = el("button", { type: "button", class: "btn btn-secondary", "data-role": "renew-cancel" }, t("keys.recovery.cancel"));
    cancel.addEventListener("click", () => finish(false));
    const stop = onLeave({ scope, win }, () => finish(false));
    mount(host, view.root, el("div", { class: "actions no-print" }, cancel));
    /** @type {any} */ (cancel).focus?.();
  });
}

/**
 * @param {{
 *   t: Translate,
 *   renew: (args: { confirmNewRk: ConfirmNewRk }) => Promise<{ kekGeneration: number }>,
 *   offer?: () => Promise<{ note: import("../store/restoreNote.mjs").RestoreNote | null, below: string[] }>,
 *   reapply?: (args: { note: import("../store/restoreNote.mjs").RestoreNote, confirmNewRk: ConfirmNewRk }) => Promise<string[]>,
 *   scope?: Scope,
 *   win?: Win,
 *   locale?: string,
 *   download?: (bytes: Uint8Array, filename: string, mime: string) => void,
 *   print?: () => void,
 * }} options `renew` and `reapply` are the session's, with the password check bound in. `offer` says whether an
 * accepted restore left the server's unlock methods below this device's floors; without it there is no reapply part.
 * @returns {HTMLElement}
 */
export function renewRecoveryView({ t, renew, offer, reapply, scope, win = globalThis, locale, download, print }) {
  const root = el("section", { class: "card account keys-page", "data-role": "renew-page" });
  const status = el("p", { class: "status", role: "status", "data-role": "renew-status" });
  const note = el("p", { class: "notice", role: "note", "data-role": "renew-note" });
  note.hidden = true;
  const errorBox = el("p", { class: "error", role: "alert", "data-role": "renew-error" });
  errorBox.hidden = true;
  const sheetHost = el("div", { class: "keys-sheet", "data-role": "renew-sheet" });
  const start = /** @type {HTMLButtonElement} */ (el("button", { type: "button", class: "btn btn-primary", "data-role": "renew-start" }, t("keys.recovery.start")));
  const startRow = el("div", { class: "actions", "data-role": "renew-start-row" }, start);
  const reapplySlot = el("div", { class: "stack keys-reapply", "data-role": "reapply-slot" });
  reapplySlot.hidden = true;
  /** @type {HTMLButtonElement | null} */
  let reapplyButton = null;
  /** Whether the reapply part was put on the page (it comes back after a failure). */
  let reapplyShown = false;

  const done = el("div", { class: "stack", "data-role": "renew-done" },
    el("h2", null, t("keys.recovery.done_heading")),
    el("p", { "data-role": "renew-done-old-key" }, t("keys.recovery.done_old_key")),
    el("p", { "data-role": "renew-done-backup" }, t("keys.recovery.done_backup")),
    el("p", { class: "notice notice-warning", role: "note", "data-role": "renew-keep-old" }, t("keys.recovery.done_keep_old")));
  done.hidden = true;
  const doneExtra = el("p", { "data-role": "renew-done-reapplied" });
  doneExtra.hidden = true;
  done.appendChild(doneExtra);

  /** The confirmation of the new key: the status line steps aside while the sheet is up. */
  const inPage = confirmInPage({ t, host: sheetHost, scope, win, download, print });
  /** @type {ConfirmNewRk} */
  const confirmNewRk = async (shown) => {
    setText(status, "");
    startRow.hidden = true;
    reapplySlot.hidden = true;
    const answer = await inPage(shown);
    if (answer) setText(status, t("keys.recovery.busy_saving"));
    return answer;
  };

  let running = false;
  /** @param {boolean} on */
  function busy(on) {
    start.disabled = on;
    if (reapplyButton) reapplyButton.disabled = on;
    root.setAttribute("aria-busy", on ? "true" : "false");
  }

  /** @param {() => Promise<string[] | null>} work @param {HTMLElement} again where the focus goes on a failure */
  async function run(work, again) {
    if (running) return;
    running = true;
    errorBox.hidden = true;
    note.hidden = true;
    busy(true);
    setText(status, t("keys.recovery.busy_making"));
    try {
      const reapplied = await work();
      setText(status, "");
      if (reapplied !== null && reapplied.length === 0) {
        // Nothing was below the floor: nothing was made or sent.
        setText(note, t("keys.reapply.nothing"));
        note.hidden = false;
        startRow.hidden = false;
        return;
      }
      if (reapplied !== null) {
        setText(doneExtra, t("keys.reapply.done"));
        doneExtra.hidden = false;
      }
      startRow.hidden = true;
      reapplySlot.hidden = true;
      done.hidden = false;
      /** @type {any} */ (done.firstChild)?.focus?.();
    } catch (error) {
      setText(status, "");
      clear(sheetHost);
      startRow.hidden = false;
      reapplySlot.hidden = !reapplyShown;
      if (codeOf(error) === "cancelled") {
        setText(note, t("keys.error.cancelled"));
        note.hidden = false;
      } else {
        setText(errorBox, keysErrorText(t, error));
        errorBox.hidden = false;
      }
      /** @type {any} */ (again).focus?.();
    } finally {
      busy(false);
      running = false;
    }
  }

  start.addEventListener("click", () => void run(async () => {
    await renew({ confirmNewRk });
    return null;
  }, start));

  mount(root,
    el("h1", null, t("keys.recovery.heading")),
    el("p", null, t("keys.recovery.intro")),
    el("p", { "data-role": "renew-effects" }, t("keys.recovery.effects")),
    reapplySlot,
    startRow,
    sheetHost,
    status,
    note,
    errorBox,
    done,
    el("p", { class: "aside" }, el("a", { href: "#/account", "data-role": "back" }, t("keys.recovery.back"))));

  // The reapply part: only for a note that applies and a method below this device's floor.
  if (offer && reapply) {
    void (async () => {
      /** @type {Awaited<ReturnType<typeof offer>> | null} */
      let offered = null;
      try {
        offered = await offer();
      } catch {
        offered = null;
      }
      const restoreNote = offered?.note ?? null;
      if (restoreNote === null || restoreNote.manifestOlder !== true || !offered || offered.below.length === 0 || running || !done.hidden) return;
      /** @type {HTMLElement[]} */
      const parts = [
        el("h2", null, t("keys.reapply.heading")),
        el("p", { "data-role": "reapply-intro" }, t("keys.reapply.intro", { date: formatMoment(restoreNote.acceptedAt, locale) ?? "" })),
      ];
      if (offered.below.includes("recovery")) {
        const button = /** @type {HTMLButtonElement} */ (el("button", { type: "button", class: "btn btn-primary", "data-role": "reapply-button" }, t("keys.reapply.button")));
        reapplyButton = button;
        button.addEventListener("click", () => void run(() => reapply({ note: restoreNote, confirmNewRk }), button));
        parts.push(el("p", null, t("keys.reapply.recovery")), el("div", { class: "actions" }, button));
      }
      if (offered.below.includes("password")) {
        parts.push(el("p", { "data-role": "reapply-password" }, t("keys.reapply.password")),
          el("p", null, el("a", { href: "#/password", "data-role": "reapply-password-link" }, t("keys.reapply.password_link"))));
      }
      mount(reapplySlot, ...parts);
      reapplyShown = true;
      reapplySlot.hidden = false;
    })();
  }
  return root;
}
