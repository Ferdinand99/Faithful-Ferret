// `#/export`: the encrypted export (the backup the user keeps) and the plain export (for moving
// to another service), spec Fase 1 § 6.4. Both ask for the master password again and say what they
// do not do. Before anything starts, the page checks that this device has no writes the server has not
// accepted and has read the server's newest state, and warns first when that is not so: the user can
// look again, or go on after ticking that the file may miss recent changes.
//
// The plain export has two separate confirmations (a box on the page and a dialog after the button) and
// a warning about search indexing, previews, synced folders and backups; the flow refuses without
// `confirmed: true`. Passkey keys are in it only when asked for, and only in JSON.
//
// All typed values leave the fields before the slow call starts (the key takes seconds), and a lock of
// the vault empties them too. Nothing typed is kept, logged, stored or put in an address. An error is
// shown by its code from a fixed list, never by its message.
import { el, mount } from "../dom.mjs";
import { askConfirm, formatMoment } from "./common.mjs";
import { busyState, choice, field, setText } from "./form.mjs";
import { securityErrorText } from "./securityError.mjs";

/** @typedef {import("./form.mjs").Translate} Translate */

/** The codes with a text of their own in the export catalog (`export.error.<code>`). */
export const EXPORT_ERRORS = Object.freeze([
  "export_item_unreadable", "input_same_as_master_password", "input_too_short", "kdf_out_of_memory", "kdf_out_of_range", "nothing_to_export",
  "plain_not_confirmed", "too_large", "unsupported",
]);

/**
 * @param {Translate} t
 * @param {unknown} error
 * @param {(id: string) => string | null} [nameOf] the name the list shows for an item id
 * @returns {string}
 */
export function exportErrorText(t, error, nameOf = () => null) {
  const code = /** @type {any} */ (error)?.code;
  if (code === "export_item_unreadable") {
    // The items are named as the list shows them (an item the list has not got is named by the start of its id).
    const ids = /** @type {any} */ (error)?.details?.ids;
    const names = (Array.isArray(ids) ? ids : []).filter((id) => typeof id === "string").map((id) => nameOf(id) || id.slice(0, 8));
    return t("export.error.export_item_unreadable", { names: names.length > 0 ? names.join(", ") : t("export.error.unreadable_unknown") });
  }
  if (typeof code === "string" && EXPORT_ERRORS.includes(code)) return t(`export.error.${code}`);
  return securityErrorText(t, error);
}

/**
 * @param {{
 *   t: Translate,
 *   exportEncrypted: (args: { masterPassword: string, exportPassword: string, exportPasswordAgain: string, skCode?: string, onProgress: (progress: { phase: string, items?: number }) => void }) => Promise<{ items: number }>,
 *   exportPlain: (args: { masterPassword: string, format: "json" | "csv", includePasskeys: boolean, confirmed: boolean, skCode?: string }) => Promise<void>,
 *   readiness: () => Promise<{ pendingWrites: number, atTop: boolean, damaged?: number }>,
 *   nameOf?: (id: string) => string | null,
 *   skRequired?: boolean,
 *   lastExportAt?: number | null,
 *   locale?: string,
 *   scope?: { add(fn: () => void): () => void },
 * }} options `exportEncrypted` and `exportPlain` are the session's. `readiness` reads the feed once more and says what the
 * page warns about. `skRequired`: the account has a secret key that this device does not hold. `lastExportAt`: when the last
 * encrypted export was made here (ms since 1970), if known.
 * @returns {HTMLElement}
 */
export function exportView({ t, exportEncrypted, exportPlain, readiness, nameOf = () => null, skRequired = false, lastExportAt = null, locale, scope }) {
  const root = el("section", { class: "card account export-page", "data-role": "export-page" });

  // ----------------------------------------------------------- readiness
  const checking = el("p", { class: "status", role: "status", "data-role": "readiness-status" }, t("export.readiness.checking"));
  const warning = el("div", { class: "notice notice-warning", role: "alert", "data-role": "readiness-warning" });
  warning.hidden = true;
  const ack = choice(t, { id: "export-ack", role: "readiness-ack", label: "export.readiness.ack" });
  const recheck = /** @type {HTMLButtonElement} */ (el("button", { type: "button", class: "btn btn-secondary btn-sm", "data-role": "readiness-recheck" }, t("export.readiness.check_again")));
  /** Whether the warning stands (so the buttons wait for the tick). */
  let warned = false;
  /** @type {Array<() => void>} */
  const gates = [];
  const applyGates = () => gates.forEach((apply) => apply());
  ack.input.addEventListener("change", applyGates);
  recheck.addEventListener("click", () => void look());

  async function look() {
    recheck.disabled = true;
    warning.hidden = true;
    mount(checking, document.createTextNode(t("export.readiness.checking")));
    /** @type {{ pendingWrites: number, atTop: boolean, damaged?: number }} */
    let state = { pendingWrites: 0, atTop: false };
    try {
      state = await readiness();
    } catch {
      state = { pendingWrites: 0, atTop: false };
    }
    recheck.disabled = false;
    warned = state.pendingWrites > 0 || !state.atTop || (state.damaged ?? 0) > 0;
    ack.input.checked = false;
    if (warned) {
      const lines = [];
      if (state.pendingWrites > 0) lines.push(el("p", { "data-role": "readiness-pending" }, t("export.readiness.pending", { count: state.pendingWrites })));
      if ((state.damaged ?? 0) > 0) lines.push(el("p", { "data-role": "readiness-damaged" }, t("export.readiness.damaged", { count: state.damaged ?? 0 })));
      if (!state.atTop) lines.push(el("p", { "data-role": "readiness-behind" }, t("export.readiness.behind")));
      mount(warning, el("h2", null, t("export.readiness.warning_heading")), ...lines, el("div", { class: "actions" }, recheck), ack.row);
      warning.hidden = false;
      mount(checking, document.createTextNode(""));
    } else {
      mount(checking, document.createTextNode(t("export.readiness.ok")));
    }
    applyGates();
  }

  // ----------------------------------------------------------- encrypted
  const master = field(t, { id: "export-master", role: "master-password", label: "export.encrypted.master", type: "password", autocomplete: "current-password", help: "export.encrypted.master_help" });
  const password = field(t, { id: "export-password", role: "export-password", label: "export.encrypted.password", type: "password", autocomplete: "off", help: "export.encrypted.password_help" });
  const again = field(t, { id: "export-password-again", role: "export-password-again", label: "export.encrypted.again", type: "password", autocomplete: "off" });
  const sk = field(t, { id: "export-sk", role: "secret-key", label: "export.encrypted.secret_key", autocomplete: "off", secret: true, help: "export.encrypted.secret_key_help" });
  const skRow = el("div", { "data-role": "sk-slot" });
  if (skRequired) mount(skRow, sk.row);
  const encInputs = [master.input, password.input, again.input, sk.input];
  const encStatus = el("p", { class: "status", role: "status", "data-role": "status" });
  const encError = el("p", { class: "error", role: "alert", "data-role": "error" });
  encError.hidden = true;
  const encSubmit = /** @type {HTMLButtonElement} */ (el("button", { type: "submit", class: "btn btn-primary", "data-role": "submit" }, t("export.encrypted.submit")));
  const encBusy = busyState({ root, status: encStatus, controls: [...encInputs, encSubmit], t, key: "export.progress.checking" });

  /** @param {string} text */
  function showEncError(text) {
    mount(encError, document.createTextNode(text));
    encError.hidden = false;
  }
  const wipeEncrypted = () => {
    for (const input of encInputs) input.value = "";
  };
  scope?.add(wipeEncrypted);

  const encDone = el("div", { class: "stack", role: "status", "data-role": "encrypted-done" });
  encDone.hidden = true;

  /** @type {HTMLElement} */
  const encForm = el("form", {
    class: "stack",
    "data-role": "encrypted-form",
    onsubmit: async (/** @type {Event} */ event) => {
      event.preventDefault();
      encError.hidden = true;
      if (warned && !ack.input.checked) return;
      const skTyped = sk.input.value.trim();
      const args = { masterPassword: master.input.value, exportPassword: password.input.value, exportPasswordAgain: again.input.value };
      if (args.masterPassword === "" || args.exportPassword === "") {
        showEncError(exportErrorText(t, { code: "password_required" }));
        return;
      }
      if (args.exportPassword !== args.exportPasswordAgain) {
        showEncError(exportErrorText(t, { code: "password_mismatch" }));
        return;
      }
      if (skRequired && skTyped === "") {
        showEncError(exportErrorText(t, { code: "sk_required" }));
        return;
      }
      // Out of the fields before the slow call: a failed attempt leaves nothing on the page.
      wipeEncrypted();
      encBusy.set(true);
      /** @param {{ phase: string, items?: number }} progress */
      const onProgress = (progress) => {
        if (!["checking", "reading", "stretching", "sealing", "saving"].includes(progress?.phase)) return;
        setText(encStatus, t(`export.progress.${progress.phase}`, { items: progress.items ?? 0 }));
      };
      try {
        const incomplete = warned;
        const done = await exportEncrypted({ ...args, ...(skTyped === "" ? {} : { skCode: skTyped }), ...(incomplete ? { incomplete } : {}), onProgress });
        encBusy.set(false);
        applyGates();
        encForm.hidden = true;
        if (!incomplete) showLast(Date.now());
        mount(encDone, ...[
          el("h2", null, t("export.done.heading")),
          incomplete ? el("p", { class: "notice notice-warning", role: "note", "data-role": "done-incomplete" }, t("export.done.incomplete")) : null,
          el("p", { "data-role": "done-items" }, t("export.done.items", { count: done.items })),
          el("p", null, t("export.done.saved")),
          el("p", { "data-role": "done-password" }, t("export.done.password")),
          el("p", null, t("export.done.master")),
          el("div", { class: "actions" }, makeAgainButton()),
        ].filter((node) => node !== null));
        encDone.hidden = false;
      } catch (error) {
        encBusy.set(false);
        applyGates();
        const code = /** @type {any} */ (error)?.code;
        if (code === "sk_required" && !skRequired) mount(skRow, sk.row);
        showEncError(exportErrorText(t, error, nameOf));
      }
    },
  },
  master.row, password.row, again.row, skRow, encStatus, encError,
  el("div", { class: "actions" }, encSubmit));

  function makeAgainButton() {
    const button = el("button", { type: "button", class: "btn btn-secondary", "data-role": "export-again" }, t("export.done.again"));
    button.addEventListener("click", () => {
      encDone.hidden = true;
      encForm.hidden = false;
      void look();
    });
    return button;
  }

  gates.push(() => {
    // A form that is busy keeps its own state; the warning only decides the button when nothing runs.
    if (root.getAttribute("aria-busy") === "true") return;
    encSubmit.disabled = warned && !ack.input.checked;
    plainSubmit.disabled = warned && !ack.input.checked;
  });

  // --------------------------------------------------------------- plain
  const plainMaster = field(t, { id: "plain-master", role: "plain-master-password", label: "export.plain.master", type: "password", autocomplete: "current-password" });
  const plainSk = field(t, { id: "plain-sk", role: "plain-secret-key", label: "export.plain.secret_key", autocomplete: "off", secret: true, help: "export.plain.secret_key_help" });
  const plainSkRow = el("div", { "data-role": "plain-sk-slot" });
  if (skRequired) mount(plainSkRow, plainSk.row);
  const json = choice(t, { id: "plain-json", role: "format-json", label: "export.plain.format_json", type: "radio", name: "plain-format", value: "json", checked: true });
  const csv = choice(t, { id: "plain-csv", role: "format-csv", label: "export.plain.format_csv", type: "radio", name: "plain-format", value: "csv" });
  const passkeys = choice(t, { id: "plain-passkeys", role: "include-passkeys", label: "export.plain.passkeys" });
  const passkeysHelp = el("small", { class: "help" }, t("export.plain.passkeys_help"));
  const understood = choice(t, { id: "plain-confirm", role: "plain-confirm", label: "export.plain.confirm" });
  const plainInputs = [plainMaster.input, plainSk.input, json.input, csv.input, passkeys.input, understood.input];
  const plainStatus = el("p", { class: "status", role: "status", "data-role": "plain-status" });
  const plainError = el("p", { class: "error", role: "alert", "data-role": "plain-error" });
  plainError.hidden = true;
  const plainSubmit = /** @type {HTMLButtonElement} */ (el("button", { type: "submit", class: "btn btn-primary", "data-role": "plain-submit" }, t("export.plain.submit")));
  const plainBusy = busyState({ root, status: plainStatus, controls: [...plainInputs, plainSubmit], t, key: "export.plain.busy" });
  const format = () => (csv.input.checked ? "csv" : "json");
  const syncPasskeys = () => {
    // CSV never has passkeys: the box is off and cannot be ticked.
    if (format() === "csv") passkeys.input.checked = false;
    passkeys.input.disabled = format() === "csv";
  };
  json.input.addEventListener("change", syncPasskeys);
  csv.input.addEventListener("change", syncPasskeys);

  /** @param {string} text */
  function showPlainError(text) {
    mount(plainError, document.createTextNode(text));
    plainError.hidden = false;
  }
  const wipePlain = () => {
    plainMaster.input.value = "";
    plainSk.input.value = "";
    understood.input.checked = false;
    passkeys.input.checked = false;
  };
  scope?.add(wipePlain);

  const plainDone = el("div", { class: "stack", role: "status", "data-role": "plain-done" });
  plainDone.hidden = true;

  /** @type {HTMLElement} */
  const plainForm = el("form", {
    class: "stack",
    "data-role": "plain-form",
    onsubmit: async (/** @type {Event} */ event) => {
      event.preventDefault();
      plainError.hidden = true;
      if (warned && !ack.input.checked) return;
      const typed = plainMaster.input.value;
      const skTyped = plainSk.input.value.trim();
      if (typed === "") {
        showPlainError(exportErrorText(t, { code: "password_required" }));
        return;
      }
      if (skRequired && skTyped === "") {
        showPlainError(exportErrorText(t, { code: "sk_required" }));
        return;
      }
      // The first confirmation: the box on the page.
      if (!understood.input.checked) {
        showPlainError(exportErrorText(t, { code: "plain_not_confirmed" }));
        return;
      }
      const chosen = format();
      const withPasskeys = chosen === "json" && passkeys.input.checked;
      // The second confirmation: a question of its own, after the button.
      const yes = await askConfirm({
        t, host: root, title: "export.plain.dialog_title", body: "export.plain.dialog_body", confirm: "export.plain.dialog_confirm",
      });
      if (!yes) return;
      // Out of the fields before the slow call: a failed attempt leaves nothing on the page.
      wipePlain();
      plainBusy.set(true);
      try {
        await exportPlain({ masterPassword: typed, format: chosen, includePasskeys: withPasskeys, confirmed: true, ...(skTyped === "" ? {} : { skCode: skTyped }) });
        plainBusy.set(false);
        applyGates();
        plainForm.hidden = true;
        mount(plainDone, ...[
          el("h2", null, t("export.plain.done_heading")),
          el("p", null, t("export.plain.done_items")),
          chosen === "csv" ? el("p", { "data-role": "done-csv" }, t("export.plain.done_csv")) : null,
        ].filter((node) => node !== null));
        plainDone.hidden = false;
      } catch (error) {
        plainBusy.set(false);
        syncPasskeys();
        applyGates();
        const code = /** @type {any} */ (error)?.code;
        if (code === "sk_required" && !skRequired) mount(plainSkRow, plainSk.row);
        showPlainError(exportErrorText(t, error, nameOf));
      }
    },
  },
  plainMaster.row, plainSkRow,
  el("fieldset", { class: "stack" }, el("legend", null, t("export.plain.format")), json.row, csv.row),
  el("div", { class: "field" }, passkeys.row, passkeysHelp),
  understood.row, plainStatus, plainError,
  el("div", { class: "actions" }, plainSubmit));
  plainForm.hidden = true;

  const plainOpen = /** @type {HTMLButtonElement} */ (el("button", { type: "button", class: "btn btn-secondary", "data-role": "plain-open" }, t("export.plain.open")));
  plainOpen.addEventListener("click", () => {
    plainOpen.hidden = true;
    plainForm.hidden = false;
    /** @type {any} */ (plainMaster.input).focus?.();
  });

  // ------------------------------------------------------------- the page
  const last = el("p", { "data-role": "export-last" });
  /** @param {number | null} at */
  function showLast(at) {
    const date = at === null ? null : formatMoment(at, locale);
    setText(last, date === null ? t("export.last.never") : t("export.last.date", { date }));
  }
  showLast(lastExportAt);

  mount(root,
    el("h1", null, t("export.heading")),
    el("p", null, t("export.intro")),
    last,
    checking,
    warning,
    el("h2", null, t("export.encrypted.heading")),
    el("p", null, t("export.encrypted.intro")),
    encForm,
    encDone,
    el("h2", null, t("export.plain.heading")),
    el("p", null, t("export.plain.intro")),
    el("p", { class: "notice notice-warning", role: "note", "data-role": "plain-warning" }, t("export.plain.warning_files")),
    el("p", { "data-role": "plain-warning-sync" }, t("export.plain.warning_sync")),
    plainOpen,
    plainForm,
    plainDone,
    el("p", { class: "aside" }, el("a", { href: "#/account", "data-role": "back" }, t("security.password.done_back"))));
  // The buttons wait for the readiness check, and the check starts now.
  encSubmit.disabled = true;
  plainSubmit.disabled = true;
  void look();
  return root;
}
