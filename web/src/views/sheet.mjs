// The emergency sheet on the screen (spec Fase 1 § 6.1): page 1 (address, e-mail, account id,
// secret key, the QR code and its text) and page 2 (the recovery key), shown once. The user can
// save the PDF (after a warning about synced folders) or print the screen version (the print
// styles put page 2 on a sheet of its own). Nothing is uploaded until the user has typed the
// recovery key (and the secret key) back and the core has checked them; after that the sheet is
// removed from the page.
//
// Modes: "setup" shows both pages and asks for both keys. "recover" and "renew" show a new
// recovery key only (page 2) and ask for that key alone; page 1 does not change then. A sheet
// whose page 1 cannot be made (no page 1 given, or a secret key that the QR text promises and
// the sheet lacks) is shown as page 2 only, with a notice: a QR code is never made for an
// account with a secret key and no secret key.
import { clear, el, mount } from "../dom.mjs";
import { checkAccessPage, httpWarning, sheetPdf } from "../flows/emergencySheet.mjs";
import { downloadBlob } from "../download.mjs";
import { qrModules } from "../qr.mjs";
import { wipe as wipeBytes } from "../pdf.mjs";
import { busyState, describeError, field, setText } from "./form.mjs";

const FILE_NAME = "ferret-emergency-sheet.pdf";
const QUIET = 4;

/**
 * Draws the code on a canvas, one pixel to a module (the style scales it). Without a canvas (a
 * plain document), nothing is drawn: the setup text is on the page as well.
 * @param {HTMLElement} canvas
 * @param {{ size: number, dark: (x: number, y: number) => boolean }} code
 */
function drawQr(canvas, code) {
  const node = /** @type {HTMLCanvasElement} */ (canvas);
  if (typeof node.getContext !== "function") return;
  const side = code.size + 2 * QUIET;
  node.width = side;
  node.height = side;
  const context = node.getContext("2d");
  if (context === null) return;
  context.fillStyle = "#fff";
  context.fillRect(0, 0, side, side);
  context.fillStyle = "#000";
  for (let y = 0; y < code.size; y += 1) {
    for (let x = 0; x < code.size; x += 1) if (code.dark(x, y)) context.fillRect(x + QUIET, y + QUIET, 1, 1);
  }
}

/**
 * @param {{
 *   t: import("./form.mjs").Translate,
 *   sheet: { access?: Record<string, any> | null, recoveryKeyCode: string },
 *   useSecretKey?: boolean,
 *   mode?: "setup" | "recover" | "renew",
 *   onConfirm: (recoveryKey: string, secretKey: string) => Promise<void>,
 *   download?: (bytes: Uint8Array, filename: string, mime: string) => void,
 *   print?: () => void,
 * }} options
 * @returns {{ root: HTMLElement, wipe(): void }}
 */
export function sheetView({ t, sheet, useSecretKey = false, mode = "setup", onConfirm, download = downloadBlob, print = () => window.print() }) {
  const setup = mode === "setup";
  const root = el("section", { class: "auth-card account sheet", "data-role": "sheet-page" });
  const status = el("p", { class: "status", role: "status", "data-role": "status" });
  const errorBox = el("p", { class: "error", role: "alert", "data-role": "error" });
  errorBox.hidden = true;

  // Page 1 is made only for a setup, and only from a sheet that agrees with itself about the secret key.
  /** @type {Record<string, any> | null} */
  let access = setup ? (sheet.access ?? null) : null;
  let pageOneMissing = setup && access === null;
  if (access !== null) {
    try {
      checkAccessPage(/** @type {any} */ (access), useSecretKey === true);
    } catch {
      access = null;
      pageOneMissing = true;
    }
  }
  /** @type {{ access: any, recoveryKeyCode: string } | null} */
  let held = { access, recoveryKeyCode: sheet.recoveryKeyCode };

  /** @param {string} label @param {string} role @param {string} value */
  const row = (label, role, value) => [el("dt", null, t(label)), el("dd", { class: "secret", "data-role": role }, value)];

  /** @type {HTMLElement[]} */
  const pageOne = [];
  if (access !== null) {
    const code = (() => {
      try {
        return qrModules(String(access.qr_payload));
      } catch {
        return null;
      }
    })();
    const canvas = code === null ? null : el("canvas", { class: "sheet-qr", role: "img", "aria-label": t("sheet.qr_alt"), "data-role": "sheet-qr-image" });
    if (canvas !== null && code !== null) drawQr(canvas, code);
    pageOne.push(
      el("h2", null, t("sheet.page_access")),
      ...(httpWarning(access.server_url) ? [el("p", { class: "notice notice-warning", role: "note", "data-role": "http-warning" }, t("sheet.http_warning"))] : []),
      ...(canvas === null ? [] : [canvas]),
      el(
        "dl",
        { class: "sheet-fields", "data-role": "sheet" },
        ...row("sheet.server", "sheet-server", String(access.server_url)),
        ...row("sheet.email", "sheet-email", String(access.email)),
        ...row("sheet.account_id", "sheet-account-id", String(access.account_id)),
        ...row("sheet.profile", "sheet-profile", String(access.ksf_profile)),
        ...(typeof access.secret_key_code === "string" && access.secret_key_code !== "" ? row("sheet.secret_key", "sheet-secret-key", access.secret_key_code) : []),
        ...row("sheet.qr", "sheet-qr", String(access.qr_payload)),
      ),
    );
  }

  const recovery = el("dl", { class: "sheet-fields", "data-role": "sheet-recovery" }, ...row("sheet.recovery_key", "sheet-recovery-key", sheet.recoveryKeyCode));

  // The keys typed back: the recovery key always, the secret key only at setup and only when the account has one.
  const rk = field(t, { id: "rk-typed", role: "rk-typed", label: "sheet.type_recovery", autocomplete: "off", secret: true });
  const sk = setup && useSecretKey ? field(t, { id: "sk-typed", role: "sk-typed", label: "sheet.type_secret", autocomplete: "off", secret: true }) : null;
  const submit = el("button", { type: "submit", class: "btn btn-primary btn-block", "data-role": "confirm" }, t(setup ? "sheet.confirm" : "sheet.confirm_new"));
  const form = el("form", { class: "stack", "data-role": "confirm-form" }, rk.row, ...(sk ? [sk.row] : []), submit);
  const busy = busyState({ root: form, status, controls: [rk.input, submit, ...(sk ? [sk.input] : [])], t, key: "sheet.checking" });

  let running = false;
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    if (running || held === null) return;
    running = true;
    errorBox.hidden = true;
    busy.set(true);
    // What was typed is read and emptied before the check starts.
    const typedRk = rk.input.value;
    const typedSk = sk ? sk.input.value : "";
    rk.input.value = "";
    if (sk) sk.input.value = "";
    void onConfirm(typedRk, typedSk)
      // The check passed: the sheet leaves the page.
      .then(() => view.wipe())
      .catch((error) => {
        setText(errorBox, describeError(t, error));
        errorBox.hidden = false;
      })
      .finally(() => {
        busy.set(false);
        running = false;
      });
  });

  // Saving the file: a warning about synced folders first, the bytes only after a second click.
  const saveWarning = el("div", { class: "notice notice-warning sheet-download no-print", role: "note", "data-role": "download-warning" });
  // The warning is in the page only while it is asked for.
  const saveSlot = el("div", { "data-role": "download-slot" });
  const downloadButton = el("button", { type: "button", class: "btn btn-secondary", "data-role": "download" }, t("sheet.download"));
  const printButton = el("button", { type: "button", class: "btn btn-secondary", "data-role": "print" }, t("sheet.print"));
  const proceed = el("button", { type: "button", class: "btn btn-primary", "data-role": "download-continue" }, t("sheet.download_continue"));
  const cancel = el("button", { type: "button", class: "btn btn-secondary", "data-role": "download-cancel" }, t("sheet.download_cancel"));
  mount(
    saveWarning,
    el("strong", null, t("sheet.download_heading")),
    el("p", null, t("sheet.download_warning")),
    ...(access !== null && httpWarning(access.server_url) ? [el("p", null, t("sheet.http_warning"))] : []),
    el("div", { class: "actions" }, proceed, cancel),
  );
  downloadButton.addEventListener("click", () => {
    mount(saveSlot, saveWarning);
    errorBox.hidden = true;
  });
  cancel.addEventListener("click", () => clear(saveSlot));
  proceed.addEventListener("click", () => {
    clear(saveSlot);
    if (held === null) return;
    /** @type {Uint8Array | null} */
    let bytes = null;
    try {
      bytes = sheetPdf({ sheet: /** @type {any} */ (held), t });
      download(bytes, FILE_NAME, "application/pdf");
      setText(status, t("sheet.download_done"));
    } catch {
      // A fixed text: the reason can name what was on the sheet.
      setText(errorBox, t("sheet.download_failed"));
      errorBox.hidden = false;
    } finally {
      // The bytes are zeroed after the hand-over (the download made its own copy).
      if (bytes !== null) wipeBytes(bytes);
    }
  });
  printButton.addEventListener("click", () => print());

  mount(
    root,
    el("h1", null, t(setup ? "sheet.heading" : "sheet.heading_new")),
    el("p", { class: "notice notice-warning", role: "note" }, t(setup ? "sheet.warning" : "sheet.warning_new")),
    ...(pageOneMissing ? [el("p", { class: "notice notice-warning", role: "note", "data-role": "page-one-missing" }, t("sheet.page_one_missing"))] : []),
    ...(!setup ? [el("p", { class: "notice", role: "note", "data-role": "page-one-unchanged" }, t("sheet.page_one_unchanged"))] : []),
    el("p", { "data-role": "new-browser" }, t("sheet.new_browser")),
    ...pageOne,
    el("h2", { class: "sheet-page-two" }, t("sheet.page_recovery")),
    el("p", { "data-role": "recovery-note" }, t("sheet.recovery_note")),
    recovery,
    el("div", { class: "actions no-print" }, downloadButton, printButton),
    saveSlot,
    el("h2", { class: "no-print" }, t(setup ? "sheet.confirm_heading" : "sheet.confirm_heading_new")),
    el("p", { class: "no-print" }, t(setup ? "sheet.confirm_note" : "sheet.confirm_note_new")),
    form,
    status,
    errorBox,
  );

  const view = {
    root,
    /** Removes the sheet's text, the QR code and the form from the page, and lets go of the sheet. */
    wipe() {
      held = null;
      access = null;
      for (const canvas of root.querySelectorAll?.("canvas") ?? []) /** @type {HTMLCanvasElement} */ (canvas).width = 0;
      clear(root);
    },
  };
  return view;
}
