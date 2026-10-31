// Pieces the vault screens share: the wipe scope, the event subscription that
// ends with the screen, the text of an error, the marks on an item and the
// confirmation dialog. Nothing in this file holds a secret.
import { el } from "../dom.mjs";

/** @typedef {(key: string, vars?: Record<string, string | number>) => string} Translate */

// ------------------------------------------------------------- wipe scope

/**
 * Things to run when the vault locks (clear a form, hide a revealed value).
 * @returns {{ add(fn: () => void): () => void, run(): void }}
 */
export function createWipeScope() {
  /** @type {Set<() => void>} */
  const wipers = new Set();
  return {
    add(fn) {
      wipers.add(fn);
      return () => void wipers.delete(fn);
    },
    run() {
      const all = [...wipers];
      wipers.clear();
      for (const fn of all) {
        try {
          fn();
        } catch {
          // One wiper failing must not keep the others from running.
        }
      }
    },
  };
}

// ----------------------------------------------------------------- events

/**
 * Subscribes to an engine event for as long as the screen is on the page: once
 * the node has been shown and is later gone, the next event removes the
 * listener instead of calling it.
 * @param {HTMLElement} root
 * @param {{ on(event: string, fn: (payload: any) => void): () => void }} engine
 * @param {string} event
 * @param {(payload: any) => void} fn
 */
export function listenWhileShown(root, engine, event, fn) {
  let shown = false;
  const off = engine.on(event, (payload) => {
    if (/** @type {any} */ (root).isConnected === true) shown = true;
    else if (shown) {
      off();
      return;
    }
    fn(payload);
  });
  return off;
}

// ------------------------------------------------------------------ errors

/**
 * The code of any error the screens can meet: the core's, the client's, the
 * sync engine's or the account session's. Anything else is `unknown`.
 * @param {unknown} error
 * @returns {string}
 */
export function codeOf(error) {
  const code = /** @type {any} */ (error)?.code;
  return typeof code === "string" && /^[a-z0-9_]{1,64}$/.test(code) ? code : "unknown";
}

/** Codes with a text under `sync.error.`. */
const SYNC_ERRORS = new Set([
  "bad_feed", "bad_request", "blocked", "conflict", "damaged", "draft_unreadable", "epoch_mismatch", "forbidden",
  "gone", "idem_reuse", "manifest_not_writable", "missing_on_server", "not_found", "quarantined", "quota_exceeded",
  "read_only", "storage", "tombstone_invalid", "too_large", "unsupported_envelope", "upload_again_failed",
]);

/** Codes with a text under `vault.error.`. */
const VAULT_ERRORS = new Set([
  "clipboard", "item_changed", "name_required", "read_only_schema", "reveal_failed", "stopped", "unknown", "worker_failed",
]);

/**
 * The text for an error. Codes are matched against a fixed list; the message
 * of an error is never shown, because it can quote what the user typed.
 * @param {Translate} t
 * @param {unknown} error
 */
export function describeError(t, error) {
  const code = codeOf(error);
  if (code === "blocked") {
    const reason = /** @type {any} */ (error)?.reason;
    const why = typeof reason === "string" && SYNC_ERRORS.has(reason) ? ` ${t(`sync.error.${reason}`)}` : "";
    return `${t("sync.error.blocked")}${why}`;
  }
  if (SYNC_ERRORS.has(code)) return t(`sync.error.${code}`);
  if (VAULT_ERRORS.has(code)) return t(`vault.error.${code}`);
  return t("vault.error.unknown");
}

// ------------------------------------------------------------------- marks

/**
 * The marks that show how an item stands with the server, in the order they
 * matter. Each is a word the screen shows as text, never only a colour.
 * @param {{ pending?: boolean, damaged?: boolean, quarantined?: boolean, missingOnServer?: boolean, blocked?: boolean, readOnly?: boolean }} item
 * @returns {string[]} mark names
 */
export function marksOf(item) {
  /** @type {string[]} */
  const marks = [];
  if (item.damaged) marks.push("damaged");
  if (item.quarantined) marks.push("quarantined");
  if (item.missingOnServer) marks.push("missing");
  if (item.blocked) marks.push("blocked");
  if (item.readOnly) marks.push("read_only");
  if (item.pending && !item.blocked) marks.push("pending");
  return marks;
}

/**
 * Whether an item may be edited or deleted: not when it is damaged,
 * quarantined, missing on the server, blocked or read only.
 * @param {Parameters<typeof marksOf>[0]} item
 */
export function canChange(item) {
  return !(item.damaged || item.quarantined || item.missingOnServer || item.blocked || item.readOnly);
}

/**
 * @param {Translate} t
 * @param {Parameters<typeof marksOf>[0] & { blockedReason?: string | null }} item
 * @returns {HTMLElement[]} one badge per mark
 */
export function markBadges(t, item) {
  return marksOf(item).map((mark) =>
    el("span", { class: `mark mark-${mark}`, "data-mark": mark }, t(`vault.mark.${mark}`)));
}

// ------------------------------------------------------------------ dialog

/**
 * Asks the user to confirm in a dialog that sits in `host`. Cancel has the
 * focus, and Escape cancels. The dialog is removed when it is answered.
 * @param {{
 *   t: Translate, host: HTMLElement, title: string, body: string, confirm: string,
 *   cancel?: string, vars?: Record<string, string | number>,
 * }} options keys of the catalog, not texts
 * @returns {Promise<boolean>}
 */
export function askConfirm({ t, host, title, body, confirm, cancel = "vault.dialog.cancel", vars }) {
  return new Promise((resolve) => {
    const heading = el("h2", { id: "vault-dialog-title" }, t(title, vars));
    const text = el("p", { id: "vault-dialog-body" }, t(body, vars));
    const no = el("button", { type: "button", class: "secondary", "data-role": "dialog-cancel" }, t(cancel));
    const yes = el("button", { type: "button", class: "danger", "data-role": "dialog-confirm" }, t(confirm, vars));
    const dialog = el("div", {
      class: "dialog", role: "alertdialog",
      "aria-labelledby": "vault-dialog-title", "aria-describedby": "vault-dialog-body", "data-role": "dialog",
    }, heading, text, el("div", { class: "actions" }, no, yes));
    /** @param {boolean} answer */
    const finish = (answer) => {
      dialog.remove();
      resolve(answer);
    };
    no.addEventListener("click", () => finish(false));
    yes.addEventListener("click", () => finish(true));
    dialog.addEventListener("keydown", (/** @type {any} */ event) => {
      if (event?.key === "Escape") finish(false);
    });
    host.appendChild(dialog);
    /** @type {any} */ (no).focus?.();
  });
}
