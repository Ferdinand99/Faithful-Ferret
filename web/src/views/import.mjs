// `#/import`: bring items into the vault from a file of Ferret's own (`.ferretexport`) or from an unencrypted export of
// Bitwarden (JSON or CSV) or of AliasVault (`.avux` or CSV), spec Fase 1 § 6.4. The page reads the file into a preview first (what is in it, how much room the
// vault has, and a warning when the vault is not empty), and nothing is sent until the user has confirmed the master password
// again. A file that is not an export of Ferret's holds every password in the clear: the page says to delete it for good
// afterwards, before the import and again when it has finished.
//
// What the page may show of a file is counts and codes: no name, address or value of an item ever reaches it (the import worker
// and the vault keep those). The file's own name, as the user's device gives it, is shown beside the button that chose it.
// The typed passwords leave their fields before the slow call starts, and a lock of the vault empties them and drops the preview.
// An error is shown by its code from a fixed list, never by its message.
//
// After the items are queued, the sending goes on in the engine. The page follows it with the engine's `import` events, and it
// shows "Continue import" when the server has closed the import window (`import_window_closed`), or when the page was loaded
// again after that: a fresh confirmation of the master password, a new window for the items that are left, and only those are sent.
import { codeOf } from "../crypto/errors.mjs";
import { PASSKEY_SKIP_REASONS } from "../import/passkeys.mjs";
import { el, mount } from "../dom.mjs";
import { formatMoment, listenWhileShown } from "./common.mjs";
import { busyState, field, setText } from "./form.mjs";
import { securityErrorText } from "./securityError.mjs";

/** @typedef {import("./form.mjs").Translate} Translate */

/** The codes with a text of their own in the import catalog (`import.error.<code>`). */
export const IMPORT_ERRORS = Object.freeze([
  "import_bad_answer", "import_bad_csv", "import_bad_export", "import_bad_format", "import_bad_json", "import_bad_key", "import_bad_zip",
  "import_busy", "import_does_not_fit", "import_empty", "import_encrypted_export", "import_export_password_required", "import_export_too_large",
  "import_field_too_large", "import_archive_too_large", "import_archive_too_many", "import_manifest_too_large", "import_nothing_left", "import_port_closed", "import_preview_gone", "import_seal_failed", "import_timeout",
  "import_too_deep", "import_too_large", "import_too_many", "import_unreadable", "import_window_open", "import_worker_failed",
  "import_wrong_export_password", "import_zip", "import_zip_encrypted", "import_zip_entry_missing", "locked", "quota_exceeded", "unsupported",
]);

/** The progress phases of an import (`import.progress.<phase>`). */
export const IMPORT_PHASES = Object.freeze(["checking", "stretching", "opening", "sealing", "window", "queueing"]);

/** What is left out of a file, counted by the worker (`import.skipped.<key>`), in the order the page lists it. */
export const SKIPPED_KEYS = Object.freeze([
  "passkeys", "folders", "tags", "attachments", "fieldHistory", "linked", "unknownKeys", "otherTypes", "trashed", "tooLarge",
  "passwordHistory", "reprompt",
]);

/** The warnings the page explains (`import.warning.<code>`); the ones that only repeat a count of what is left out are not here. */
export const WARNING_CODES = Object.freeze([
  "alias_needs_aliasvault", "card_and_login", "field_type_unknown", "field_unreadable", "item_archived", "match_never", "match_regex",
  "match_starts_with", "match_unknown", "passkey_extra_item", "passkey_prf_dropped", "totp_extra", "totp_invalid", "totp_steam", "uri_https_added",
]);

/** The notes the page writes from the counts of an import (`import.note.<key>`). */
export const COUNT_NOTES = Object.freeze(["matchNull", "http", "textAddresses"]);

/** The kinds of file that were exported unencrypted: their file holds every secret in the clear. */
const PLAIN_KINDS = Object.freeze(["bitwarden_json", "bitwarden_csv", "aliasvault_csv", "aliasvault_avux"]);

/**
 * The text of an error on this page. An error of the import has its own text; a refusal of the server's import window and the
 * codes of the sign-in and the re-authentication have theirs. A line number (a CSV file) is added where there is one.
 * @param {Translate} t
 * @param {unknown} error
 * @param {{ continuing?: boolean }} [where] `continuing`: the error is the answer to "Continue import", part-way through an import
 * @returns {string}
 */
export function importErrorText(t, error, { continuing = false } = {}) {
  const code = codeOf(error);
  // In the middle of an import "nothing was imported" would be wrong: what was sent stays.
  if (continuing && code === "quota_exceeded") return t("import.error.quota_exceeded_continue");
  if (!IMPORT_ERRORS.includes(code)) return securityErrorText(t, error);
  const text = t(`import.error.${code}`);
  const line = /** @type {any} */ (error)?.details?.line;
  return Number.isSafeInteger(line) && line > 0 ? `${text} ${t("import.error.at_line", { line })}` : text;
}

/**
 * @typedef {{
 *   kind: string, counts: Record<string, number> | null, skipped: Record<string, number> | null,
 *   passkeys?: { skipped: Record<string, number>, registerAgain: number, prfDropped: number, extra: number, sites: ReadonlyArray<string> } | null,
 *   warnings: ReadonlyArray<{ code: string, count: number }>, warningsDropped: number,
 *   free: number, used: number, vaultEmpty: boolean, fits: boolean, createdAt: number | null,
 * }} Preview
 *
 * @typedef {{ queued: number, refused: number, sent: number, total: number, failed: number, windowClosed: boolean }} ImportStatus
 */

/**
 * @param {{
 *   t: Translate,
 *   previewFile: (file: File, options: { signal: AbortSignal }) => Promise<Preview>,
 *   runImport: (preview: Preview, args: { masterPassword: string, exportPassword?: string, skCode?: string, onProgress: (progress: { phase: string, items?: number }) => void }) => Promise<{ queued: number }>,
 *   continueImport: (args: { masterPassword: string, skCode?: string, onProgress: (progress: { phase: string, items?: number }) => void }) => Promise<unknown>,
 *   discard: (preview: Preview) => void,
 *   status: () => ImportStatus,
 *   on: (event: "import" | "import_window_closed", fn: (payload: any) => void) => () => void,
 *   skRequired?: boolean,
 *   locale?: string,
 *   leavePollMs?: number,
 *   scope?: { add(fn: () => void): () => void },
 * }} options `leavePollMs`: how often the page looks whether the user has left it while a file is being read or a preview is held. `previewFile`, `runImport`, `continueImport` and `discard` are the session's, `status` and `on` the engine's. `skRequired`: the account has a
 * secret key that this device does not hold.
 * @returns {HTMLElement}
 */
export function importView({ t, previewFile, runImport, continueImport, discard, status, on, skRequired = false, locale, leavePollMs = 500, scope }) {
  const root = el("section", { class: "card account import-page", "data-role": "import-page" });

  /** The preview that is on the page now, or null. @type {Preview | null} */
  let preview = null;
  /** An import that this page started or found unfinished is followed to its end. */
  let tracking = false;
  /** The kind of the file this page imported (null when the page was loaded in the middle of an import). @type {string | null} */
  let importedKind = null;
  /** The passkeys of the file this page imported (what to register again), or null. @type {NonNullable<Preview["passkeys"]> | null} */
  let importedPasskeys = null;
  /** How many items this page queued. */
  let queuedHere = 0;
  /** The import itself is running (the preview is spent when it ends, not before). */
  let running = false;
  /** Ends the reading of the file when the user leaves the page. @type {AbortController | null} */
  let previewAbort = null;
  /** The timer that looks whether the page has been left. @type {any} */
  let watch = null;
  /** The page has been in the document (a page that was never shown cannot have been left). */
  let wasShown = false;
  /** The user left the page: what an import that was still running leaves behind is let go of when it ends. */
  let gone = false;

  /**
   * The user left the page (the router put another one in its place): the worker that reads the file is ended and a preview that is
   * held is let go of, as for a lock. An import that is running is not touched.
   */
  function left() {
    gone = true;
    stopWatch();
    previewAbort?.abort();
    previewAbort = null;
    if (preview !== null && !running) {
      discard(preview);
      preview = null;
    }
  }
  function look() {
    const connected = /** @type {any} */ (root).isConnected;
    if (connected === true) wasShown = true;
    else if (connected === false && wasShown) left();
  }
  function startWatch() {
    if (watch !== null) return;
    // The page is on screen when the user picks a file: a page that is left before the first look is still a page that was left.
    if (/** @type {any} */ (root).isConnected === true) wasShown = true;
    watch = setInterval(look, leavePollMs);
    // A timer must not keep a process alive (the tests); the handle of a browser is a number.
    watch?.unref?.();
  }
  function stopWatch() {
    if (watch !== null) clearInterval(watch);
    watch = null;
  }

  // ------------------------------------------------------------- the file
  const fileInput = /** @type {HTMLInputElement} */ (el("input", {
    id: "import-file", name: "import-file", type: "file", accept: ".ferretexport,.json,.csv,.avux", "data-role": "file", required: true, class: "visually-hidden",
  }));
  // The input is hidden from the eye only (it keeps the keyboard and the screen reader); the label that names it is drawn as a
  // button, and the zone around both takes a file that is dropped on it. Only the file's own name is shown, as text.
  const fileName = el("span", { class: "file-name", "data-role": "file-name" }, t("import.file.none"));
  const fileDrop = el("div", { class: "file-drop", "data-role": "file-drop", "data-over": "false" },
    fileInput,
    el("label", { class: "btn btn-secondary", for: "import-file", "data-role": "file-choose" }, t("import.file.choose")),
    fileName,
    el("span", { class: "help file-drop-hint" }, t("import.file.drop")));
  const fileStatus = el("p", { class: "status", role: "status", "data-role": "file-status" });
  const fileError = el("p", { class: "error", role: "alert", "data-role": "file-error" });
  fileError.hidden = true;
  const fileRow = el("div", { class: "field" }, el("label", { for: "import-file" }, t("import.file.label")), fileDrop, el("small", { class: "help" }, t("import.file.help")));
  const fileForm = el("div", { class: "stack", "data-role": "file-form" }, fileRow, fileStatus, fileError);

  /** @param {string} text */
  function showFileError(text) {
    mount(fileError, document.createTextNode(text));
    fileError.hidden = false;
  }

  // -------------------------------------------------------------- the preview
  const previewBox = el("div", { class: "stack", "data-role": "preview" });
  previewBox.hidden = true;
  const master = field(t, { id: "import-master", role: "master-password", label: "import.form.master", type: "password", autocomplete: "current-password", help: "import.form.master_help" });
  const exportPassword = field(t, { id: "import-export-password", role: "export-password", label: "import.form.export_password", type: "password", autocomplete: "off", help: "import.form.export_password_help" });
  const exportRow = el("div", { "data-role": "export-password-slot" });
  const sk = field(t, { id: "import-sk", role: "secret-key", label: "import.form.secret_key", autocomplete: "off", secret: true, help: "import.form.secret_key_help" });
  const skRow = el("div", { "data-role": "sk-slot" });
  if (skRequired) mount(skRow, sk.row);
  const inputs = [master.input, exportPassword.input, sk.input];
  const importStatusLine = el("p", { class: "status", role: "status", "data-role": "status" });
  const importError = el("p", { class: "error", role: "alert", "data-role": "error" });
  importError.hidden = true;
  const submit = /** @type {HTMLButtonElement} */ (el("button", { type: "submit", class: "btn btn-primary", "data-role": "submit" }, t("import.form.submit")));
  const cancel = /** @type {HTMLButtonElement} */ (el("button", { type: "button", class: "btn btn-secondary", "data-role": "cancel" }, t("import.form.cancel")));
  const busy = busyState({ root, status: importStatusLine, controls: [...inputs, submit, cancel, fileInput], t, key: "import.progress.checking" });

  /** @param {string} text */
  function showImportError(text) {
    mount(importError, document.createTextNode(text));
    importError.hidden = false;
  }
  const wipeForm = () => {
    for (const input of inputs) input.value = "";
  };

  /** @param {{ phase: string, items?: number }} progress */
  function onProgress(progress) {
    if (!IMPORT_PHASES.includes(progress?.phase)) return;
    setText(importStatusLine, t(`import.progress.${progress.phase}`, { items: progress.items ?? 0 }));
  }

  /**
   * What to tell about the passkeys that must be registered at their site again (null when there are none). The sites are the vault's own
   * spelling of them; a list that is cut says so.
   * @param {NonNullable<Preview["passkeys"]>} passkeys
   */
  function registerAgainNote(passkeys) {
    if (passkeys.registerAgain <= 0) return null;
    const all = passkeys.sites.length >= passkeys.registerAgain;
    return el("p", { class: "notice notice-warning", role: "note", "data-role": "passkey-register-again" },
      t(all ? "import.passkey.register_again" : "import.passkey.register_again_more", { count: passkeys.registerAgain, sites: passkeys.sites.join(", ") }));
  }

  /** @param {string} key @param {Record<string, string | number>} [vars] @param {string} [role] */
  const line = (key, vars, role) => el("li", role ? { "data-role": role } : null, t(key, vars));

  /** @param {Preview} shown */
  function describe(shown) {
    const counts = shown.counts;
    const skipped = shown.skipped;
    /** @type {Array<HTMLElement>} */
    const blocks = [el("h2", null, t("import.preview.heading")), el("p", { "data-role": "preview-kind" }, t(`import.kind.${shown.kind}`))];
    if (counts === null) {
      const made = shown.createdAt === null ? null : formatMoment(shown.createdAt, locale);
      blocks.push(el("p", { "data-role": "preview-export" }, made === null ? t("import.preview.export_unknown_date") : t("import.preview.export_made", { date: made })));
      blocks.push(el("p", { "data-role": "preview-export-count" }, t("import.preview.export_count_later")));
    } else {
      blocks.push(el("p", { "data-role": "preview-items" }, t("import.preview.items", { count: counts.items })));
      const parts = [];
      if (counts.login > 0) parts.push(line("import.preview.login", { count: counts.login }, "count-login"));
      if (counts.note > 0) parts.push(line("import.preview.note", { count: counts.note }, "count-note"));
      if (counts.card > 0) parts.push(line("import.preview.card", { count: counts.card }, "count-card"));
      if (counts.identity > 0) parts.push(line("import.preview.identity", { count: counts.identity }, "count-identity"));
      if (counts.urls > 0) parts.push(line("import.preview.urls", { count: counts.urls }, "count-urls"));
      if (counts.totp > 0) parts.push(line("import.preview.totp", { count: counts.totp }, "count-totp"));
      if (counts.passkeys > 0) parts.push(line("import.preview.passkeys", { count: counts.passkeys }, "count-passkeys"));
      if (counts.customFields > 0) parts.push(line("import.preview.custom_fields", { count: counts.customFields }, "count-custom-fields"));
      if (parts.length > 0) blocks.push(el("ul", { class: "import-list", "data-role": "preview-counts" }, ...parts));
    }

    // Room in the vault, and the warning when it is not empty or does not fit.
    blocks.push(el("p", { "data-role": "preview-room" }, t("import.preview.room", { free: shown.free, used: shown.used })));
    if (!shown.fits) {
      blocks.push(el("p", { class: "notice notice-warning", role: "alert", "data-role": "does-not-fit" },
        counts === null ? t("import.preview.no_room") : t("import.preview.too_many", { count: counts.items, free: shown.free })));
    }
    if (!shown.vaultEmpty) {
      blocks.push(el("p", { class: "notice notice-warning", role: "note", "data-role": "not-empty" }, t("import.preview.not_empty", { count: shown.used })));
    }

    // What the import does not take with it, and what it changed on the way.
    if (skipped !== null) {
      /** @type {HTMLElement[]} */
      const left = [];
      for (const key of SKIPPED_KEYS) {
        if (!(skipped[key] > 0)) continue;
        if (key === "passkeys" && shown.passkeys) {
          // The import of passkeys is on: each reason has its own line, and the generic "cannot be imported" is not true.
          for (const reason of PASSKEY_SKIP_REASONS) {
            const n = shown.passkeys.skipped[reason];
            if (n > 0) left.push(line(`import.skipped.passkey_${reason}`, { count: n }, `skipped-passkey-${reason}`));
          }
        } else left.push(line(`import.skipped.${key}`, { count: skipped[key] }, `skipped-${key}`));
      }
      if (left.length > 0) blocks.push(el("h3", null, t("import.preview.skipped_heading")), el("ul", { class: "import-list", "data-role": "preview-skipped" }, ...left));
    }
    if (shown.passkeys) {
      const again = registerAgainNote(shown.passkeys);
      if (again !== null) blocks.push(again);
    }
    const notes = counts === null ? [] : COUNT_NOTES.filter((key) => counts[key] > 0).map((key) => line(`import.note.${key}`, { count: counts[key] }, `note-${key}`));
    const warned = shown.warnings.filter((w) => WARNING_CODES.includes(w.code)).map((w) => line(`import.warning.${w.code}`, { count: w.count }, `warning-${w.code}`));
    if (shown.warningsDropped > 0) warned.push(line("import.warning.dropped", { count: shown.warningsDropped }, "warning-dropped"));
    if (notes.length + warned.length > 0) blocks.push(el("h3", null, t("import.preview.notes_heading")), el("ul", { class: "import-list", "data-role": "preview-notes" }, ...notes, ...warned));

    if (PLAIN_KINDS.includes(shown.kind)) {
      blocks.push(el("p", { class: "notice notice-warning", role: "note", "data-role": "plain-file-warning" }, t("import.plain.before")));
    }
    return blocks;
  }

  /** @param {Preview} shown */
  function showPreview(shown) {
    preview = shown;
    wipeForm();
    importError.hidden = true;
    mount(exportRow, ...(shown.kind === "ferretexport" ? [exportPassword.row] : []));
    submit.disabled = !shown.fits;
    mount(submit, document.createTextNode(shown.counts === null ? t("import.form.submit") : t("import.form.submit_count", { count: shown.counts.items })));
    mount(previewBox,
      ...describe(shown),
      el("form", { class: "stack", "data-role": "import-form", onsubmit: onSubmit },
        master.row, exportRow, skRow, importStatusLine, importError, el("div", { class: "actions" }, cancel, submit)));
    previewBox.hidden = false;
  }

  function resetFile() {
    if (preview !== null) discard(preview);
    preview = null;
    stopWatch();
    previewBox.hidden = true;
    mount(previewBox);
    wipeForm();
    fileInput.value = "";
    setText(fileName, t("import.file.none"));
    fileError.hidden = true;
    setText(fileStatus, "");
  }
  scope?.add(() => {
    wipeForm();
    wipeContinue();
    stopWatch();
    previewAbort?.abort();
    gone = true;
    // An import that is running (re-authenticating, opening, sealing) is left alone, as in `left()`: it needs its preview.
    if (preview !== null && !running) {
      discard(preview);
      preview = null;
    }
  });

  cancel.addEventListener("click", () => resetFile());

  /** @param {File | undefined | null} file the file the user chose, or dropped on the zone */
  async function onFile(file) {
    fileError.hidden = true;
    if (preview !== null) {
      discard(preview);
      preview = null;
      previewBox.hidden = true;
    }
    if (!file) {
      setText(fileName, t("import.file.none"));
      return;
    }
    setText(fileName, typeof file.name === "string" && file.name !== "" ? file.name : t("import.file.none"));
    fileInput.disabled = true;
    setText(fileStatus, t("import.file.reading"));
    const controller = new AbortController();
    previewAbort = controller;
    startWatch();
    try {
      const shown = await previewFile(file, { signal: controller.signal });
      setText(fileStatus, "");
      // The user left the page while the file was read: nothing is shown and nothing is kept.
      if (controller.signal.aborted) {
        discard(shown);
        return;
      }
      showPreview(shown);
    } catch (error) {
      stopWatch();
      setText(fileStatus, "");
      showFileError(importErrorText(t, error));
      fileInput.value = "";
      setText(fileName, t("import.file.none"));
    } finally {
      fileInput.disabled = false;
    }
  }
  fileInput.addEventListener("change", () => onFile(/** @type {any} */ (fileInput).files?.[0]));

  // A file dropped on the zone is the same as one chosen with the button (nothing is uploaded: it is read on this device). The
  // browser's own answer to a drop, opening the file, is stopped; a drop while the page is busy is ignored.
  /** @param {boolean} over */
  const markOver = (over) => fileDrop.setAttribute("data-over", over ? "true" : "false");
  for (const type of ["dragenter", "dragover"]) {
    fileDrop.addEventListener(type, (/** @type {any} */ event) => {
      event.preventDefault();
      markOver(!fileInput.disabled);
    });
  }
  fileDrop.addEventListener("dragleave", () => markOver(false));
  fileDrop.addEventListener("drop", (/** @type {any} */ event) => {
    event.preventDefault();
    markOver(false);
    if (fileInput.disabled) return Promise.resolve();
    // Dragged text or a link has no file: what is on the page stays as it is.
    const file = event.dataTransfer?.files?.[0];
    if (!file) return Promise.resolve();
    return onFile(file);
  });

  /** @param {Event} event */
  async function onSubmit(event) {
    event.preventDefault();
    importError.hidden = true;
    const shown = preview;
    if (shown === null || !shown.fits) return;
    const typed = master.input.value;
    const exportTyped = exportPassword.input.value;
    const skTyped = sk.input.value.trim();
    if (typed === "") return showImportError(importErrorText(t, { code: "password_required" }));
    if (shown.kind === "ferretexport" && exportTyped === "") return showImportError(importErrorText(t, { code: "import_export_password_required" }));
    if (skRequired && skTyped === "") return showImportError(importErrorText(t, { code: "sk_required" }));
    // Out of the fields before the slow calls: a failed attempt leaves nothing on the page.
    wipeForm();
    busy.set(true);
    running = true;
    try {
      const done = await runImport(shown, {
        masterPassword: typed,
        ...(shown.kind === "ferretexport" ? { exportPassword: exportTyped } : {}),
        ...(skTyped === "" ? {} : { skCode: skTyped }),
        onProgress,
      });
      busy.set(false);
      running = false;
      stopWatch();
      preview = null;
      previewBox.hidden = true;
      mount(previewBox);
      fileInput.value = "";
      importedKind = shown.kind;
      importedPasskeys = shown.passkeys ?? null;
      queuedHere = done.queued;
      tracking = true;
      renderTracker();
    } catch (error) {
      busy.set(false);
      running = false;
      // The page was left while the import ran, and it did not start: nobody is looking at the error, and nothing refers to the sealed items.
      if (gone) {
        discard(shown);
        preview = null;
        return;
      }
      const code = codeOf(error);
      // The file was let go of, or the vault locked: there is nothing to try again, and the page goes back to choosing a file.
      if (code === "import_preview_gone" || code === "locked") {
        resetFile();
        showFileError(importErrorText(t, error));
        return;
      }
      showImportError(importErrorText(t, error));
      // A code that asks for the secret key shows its field for the next try.
      if (code === "sk_required" && !skRequired) mount(skRow, sk.row);
    }
  }

  // -------------------------------------------------- following the import
  const tracker = el("div", { class: "stack", role: "status", "data-role": "tracker" });
  tracker.hidden = true;
  const continueMaster = field(t, { id: "continue-master", role: "continue-master-password", label: "import.form.master", type: "password", autocomplete: "current-password", help: "import.continue.master_help" });
  const continueSk = field(t, { id: "continue-sk", role: "continue-secret-key", label: "import.form.secret_key", autocomplete: "off", secret: true, help: "import.form.secret_key_help" });
  const continueSkRow = el("div", { "data-role": "continue-sk-slot" });
  if (skRequired) mount(continueSkRow, continueSk.row);
  const continueInputs = [continueMaster.input, continueSk.input];
  const continueStatus = el("p", { class: "status", role: "status", "data-role": "continue-status" });
  const continueError = el("p", { class: "error", role: "alert", "data-role": "continue-error" });
  continueError.hidden = true;
  const continueSubmit = /** @type {HTMLButtonElement} */ (el("button", { type: "submit", class: "btn btn-primary", "data-role": "continue-submit" }, t("import.continue.submit")));
  const continueBusy = busyState({ root, status: continueStatus, controls: [...continueInputs, continueSubmit], t, key: "import.progress.checking" });
  const wipeContinue = () => {
    for (const input of continueInputs) input.value = "";
  };

  /** @param {string} text */
  function showContinueError(text) {
    mount(continueError, document.createTextNode(text));
    continueError.hidden = false;
  }

  /** @type {HTMLElement} */
  const continueForm = el("form", {
    class: "stack",
    "data-role": "continue-form",
    onsubmit: async (/** @type {Event} */ event) => {
      event.preventDefault();
      continueError.hidden = true;
      const typed = continueMaster.input.value;
      const skTyped = continueSk.input.value.trim();
      if (typed === "") return showContinueError(importErrorText(t, { code: "password_required" }));
      if (skRequired && skTyped === "") return showContinueError(importErrorText(t, { code: "sk_required" }));
      wipeContinue();
      continueBusy.set(true);
      try {
        await continueImport({
          masterPassword: typed,
          ...(skTyped === "" ? {} : { skCode: skTyped }),
          onProgress: (progress) => {
            if (IMPORT_PHASES.includes(progress?.phase)) setText(continueStatus, t(`import.progress.${progress.phase}`, { items: progress.items ?? 0 }));
          },
        });
        continueBusy.set(false);
        renderTracker();
      } catch (error) {
        continueBusy.set(false);
        const code = codeOf(error);
        // The engine has nothing left: the import is over, and the tracker says so.
        if (code === "import_nothing_left") {
          renderTracker();
          return;
        }
        if (code === "sk_required" && !skRequired) mount(continueSkRow, continueSk.row);
        showContinueError(importErrorText(t, error, { continuing: true }));
      }
    },
  }, continueMaster.row, continueSkRow, continueStatus, continueError, el("div", { class: "actions" }, continueSubmit));

  /** Draws what the engine says about the import: sending, paused (the window is closed), or finished. */
  function renderTracker() {
    if (!tracking) {
      tracker.hidden = true;
      return;
    }
    /** @type {ImportStatus} */
    let now;
    try {
      now = status();
    } catch {
      now = { queued: 0, refused: 0, sent: 0, total: 0, failed: 0, windowClosed: false };
    }
    tracker.hidden = false;
    if (now.queued > 0 && now.windowClosed) {
      mount(tracker,
        el("h2", null, t("import.continue.heading")),
        el("p", { "data-role": "tracker-paused" }, t("import.continue.text", { queued: now.queued })),
        el("p", { "data-role": "tracker-window-note" }, t("import.continue.window_note")),
        continueForm);
      return;
    }
    if (now.queued > 0) {
      mount(tracker,
        el("h2", null, t("import.sending.heading")),
        el("p", { "data-role": "tracker-sending" }, t("import.sending.text", { sent: now.sent, total: now.total, queued: now.queued })),
        el("p", { "data-role": "tracker-keep-open" }, t("import.sending.keep_open")),
        ...(importedKind !== null && PLAIN_KINDS.includes(importedKind)
          ? [el("p", { class: "notice notice-warning", role: "note", "data-role": "plain-file-reminder" }, t("import.plain.after"))]
          : []));
      return;
    }
    // Nothing is left to send.
    tracking = false;
    const count = now.sent > 0 ? now.sent : queuedHere;
    const plain = importedKind === null || PLAIN_KINDS.includes(importedKind);
    const again = /** @type {HTMLButtonElement} */ (el("button", { type: "button", class: "btn btn-secondary", "data-role": "import-again" }, t("import.done.again")));
    again.addEventListener("click", () => {
      tracker.hidden = true;
      mount(tracker);
      fileForm.hidden = false;
      importedKind = null;
      importedPasskeys = null;
    });
    const againNote = importedPasskeys === null ? null : registerAgainNote(importedPasskeys);
    mount(tracker,
      el("h2", null, t("import.done.heading")),
      el("p", { "data-role": "done-items" }, t("import.done.items", { count })),
      ...(now.refused > 0 ? [el("p", { class: "notice notice-warning", role: "alert", "data-role": "done-failed" }, t("import.done.failed", { count: now.refused }))] : []),
      el("p", { "data-role": "done-next" }, t("import.done.next")),
      ...(againNote === null ? [] : [againNote]),
      ...(plain ? [el("p", { class: "notice notice-warning", role: "note", "data-role": "plain-file-after" }, t("import.plain.after"))] : []),
      el("div", { class: "actions" }, again, el("a", { class: "btn btn-primary", href: "#/", "data-role": "done-list" }, t("import.done.list"))));
  }

  const stopImport = listenWhileShown(root, { on }, "import", () => renderTracker());
  const stopClosed = listenWhileShown(root, { on }, "import_window_closed", () => {
    // A closed window ends the wait for the sending, whether or not this page started the import.
    if (!tracking) tracking = true;
    renderTracker();
  });
  scope?.add(() => {
    stopImport();
    stopClosed();
  });

  // An import that was under way when the page was loaded is followed from here.
  try {
    if (status().queued > 0) tracking = true;
  } catch {
    // No engine state: nothing to follow.
  }

  // ------------------------------------------------------------- the page
  mount(root,
    el("h1", null, t("import.heading")),
    el("p", null, t("import.intro")),
    el("ul", { class: "import-list", "data-role": "formats" },
      line("import.formats.ferret", undefined, "format-ferret"),
      line("import.formats.bitwarden", undefined, "format-bitwarden"),
      line("import.formats.aliasvault", undefined, "format-aliasvault"),
      line("import.formats.not", undefined, "format-not")),
    el("p", { class: "notice notice-warning", role: "note", "data-role": "plain-file-note" }, t("import.plain.note")),
    tracker,
    fileForm,
    previewBox,
    el("p", { class: "aside" }, el("a", { href: "#/account", "data-role": "back" }, t("security.password.done_back"))));
  renderTracker();
  return root;
}
