// `#/secret-key` and `#/sheet`: the secret key shown again, and page 1 of the emergency sheet printed
// again (spec Fase 1 § 6.1, § 6.2). Both ask for the master password first (a sensitive operation,
// § 4.6 (a)) and read only what this device remembers; nothing is sent to the server.
//
// The secret key is shown as text or as a QR code of that text, one at a time, never both, until
// "Hide", a lock of the vault or leaving the page; then it leaves the page. When this device does not
// remember the key, the page says where it is: page 1 of the emergency sheet.
//
// Page 1 again is a PDF of one page, saved after a warning about synced folders. Page 2 (the recovery
// key) cannot be made again, because no device keeps the key; the page points to a new recovery key.
// The PDF bytes are zeroed after the hand-over; the copy the download makes cannot be.
//
// An error is shown by its code, from a fixed list; its message is never shown.
import { clear, el, mount } from "../dom.mjs";
import { codeOf } from "../crypto/errors.mjs";
import { downloadBlob } from "../download.mjs";
import { wipe as wipeBytes } from "../pdf.mjs";
import { setText } from "./form.mjs";
import { keysErrorText, onLeave } from "./renewRecovery.mjs";

/** @typedef {import("./form.mjs").Translate} Translate */
/** @typedef {{ add(fn: () => void): () => void }} Scope */
/** @typedef {{ addEventListener?: Function, removeEventListener?: Function }} Win */
/** @typedef {{ skBit: boolean | null, skStored: boolean } | null} DeviceStatus */
/** @typedef {{ size: number, dark: (x: number, y: number) => boolean }} QrCode */

const QUIET = 4;
const PAGE_ONE_FILE = "ferret-emergency-sheet-page-1.pdf";

/**
 * Draws the code on a canvas, one pixel to a module (the style scales it). Without a canvas (a plain
 * document), nothing is drawn.
 * @param {HTMLElement} canvas
 * @param {QrCode} code
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

/** The pointer to where the key is, for a device that does not remember it. @param {Translate} t */
const notRemembered = (t) => el("p", { class: "notice", role: "note", "data-role": "sk-not-remembered" }, t("keys.secret.not_remembered"));

/**
 * @param {{
 *   t: Translate,
 *   show: () => Promise<{ code: string, qr: QrCode } | "not_remembered" | "no_secret_key">,
 *   status?: DeviceStatus,
 *   scope?: Scope,
 *   win?: Win,
 * }} options `show` is the session's `showSecretKey` with the password check bound in. `status` is what this device
 * knows of the account (`deviceStatus`): without a remembered key the page says where the key is and asks for nothing.
 * @returns {HTMLElement}
 */
export function secretKeyView({ t, show, status = null, scope, win = globalThis }) {
  const root = el("section", { class: "card account keys-page", "data-role": "secret-page" });
  const body = el("div", { class: "stack" });
  mount(root, el("h1", null, t("keys.secret.heading")), el("p", null, t("keys.secret.intro")), body);
  if (status?.skBit === false) {
    mount(body, el("p", { "data-role": "sk-none" }, t("keys.secret.no_secret_key")));
    return root;
  }
  if (status?.skStored === false) {
    mount(body, notRemembered(t));
    return root;
  }

  const shown = el("div", { class: "keys-secret", "data-role": "sk-shown" });
  const statusLine = el("p", { class: "status", role: "status", "data-role": "sk-status" });
  const errorBox = el("p", { class: "error", role: "alert", "data-role": "sk-error" });
  errorBox.hidden = true;
  const showButton = /** @type {HTMLButtonElement} */ (el("button", { type: "button", class: "btn btn-primary", "data-role": "sk-show" }, t("keys.secret.show")));
  const toggle = /** @type {HTMLButtonElement} */ (el("button", { type: "button", class: "btn btn-secondary", "data-role": "sk-toggle" }));
  const hideButton = /** @type {HTMLButtonElement} */ (el("button", { type: "button", class: "btn btn-secondary", "data-role": "sk-hide" }, t("keys.secret.hide")));
  const controls = el("div", { class: "actions" }, showButton, toggle, hideButton);

  /** @type {{ code: string, qr: QrCode } | null} */
  let held = null;
  /** @type {"text" | "qr"} */
  let as = "text";
  /** @type {(() => void) | null} */
  let stop = null;

  /** Empties what is shown: a canvas loses its pixels, the text node goes. */
  function blank() {
    for (const node of shown.childNodes ?? []) {
      if (String(/** @type {any} */ (node).tagName).toLowerCase() === "canvas") /** @type {HTMLCanvasElement} */ (node).width = 0;
    }
    clear(shown);
  }

  function render() {
    blank();
    const open = held !== null;
    showButton.hidden = open;
    toggle.hidden = !open;
    hideButton.hidden = !open;
    if (held === null) return;
    if (as === "text") {
      mount(shown, el("p", { class: "secret keys-code", "data-role": "sk-code" }, held.code));
      setText(toggle, t("keys.secret.as_qr"));
    } else {
      const canvas = el("canvas", { class: "keys-qr", role: "img", "aria-label": t("keys.secret.qr_alt"), "data-role": "sk-qr" });
      drawQr(canvas, held.qr);
      mount(shown, canvas);
      setText(toggle, t("keys.secret.as_text"));
    }
  }

  /** The key leaves the page and this view lets go of it. */
  function hide() {
    held = null;
    as = "text";
    stop?.();
    stop = null;
    render();
  }

  toggle.addEventListener("click", () => {
    if (held === null) return;
    as = as === "text" ? "qr" : "text";
    render();
  });
  hideButton.addEventListener("click", () => {
    hide();
    setText(statusLine, t("keys.secret.hidden"));
    /** @type {any} */ (showButton).focus?.();
  });

  let running = false;
  showButton.addEventListener("click", async () => {
    if (running || held !== null) return;
    running = true;
    errorBox.hidden = true;
    showButton.disabled = true;
    setText(statusLine, t("keys.secret.busy"));
    try {
      const answer = await show();
      setText(statusLine, "");
      if (answer === "not_remembered" || answer === "no_secret_key") {
        mount(body, answer === "not_remembered" ? notRemembered(t) : el("p", { "data-role": "sk-none" }, t("keys.secret.no_secret_key")));
        return;
      }
      held = { code: answer.code, qr: answer.qr };
      as = "text";
      stop = onLeave({ scope, win }, hide);
      render();
    } catch (error) {
      setText(statusLine, "");
      if (codeOf(error) !== "cancelled") {
        setText(errorBox, keysErrorText(t, error));
        errorBox.hidden = false;
      }
    } finally {
      showButton.disabled = false;
      running = false;
    }
  });

  render();
  mount(body, el("p", { class: "notice notice-warning", role: "note", "data-role": "sk-warning" }, t("keys.secret.warning")),
    controls, shown, statusLine, errorBox);
  return root;
}

/**
 * @param {{
 *   t: Translate,
 *   make: () => Promise<Uint8Array>,
 *   status?: DeviceStatus,
 *   download?: (bytes: Uint8Array, filename: string, mime: string) => void,
 * }} options `make` is the session's `accessSheet` with the password check bound in.
 * @returns {HTMLElement}
 */
export function accessSheetView({ t, make, status = null, download = downloadBlob }) {
  const root = el("section", { class: "card account keys-page", "data-role": "sheet-again-page" });
  const body = el("div", { class: "stack" });
  mount(root,
    el("h1", null, t("keys.sheet.heading")),
    el("p", null, t("keys.sheet.intro")),
    el("p", { "data-role": "sheet-new-browser" }, t("sheet.new_browser")),
    el("p", { "data-role": "sheet-page-two" }, t("keys.sheet.page_two"), " ",
      el("a", { href: "#/recovery-key", "data-role": "sheet-new-key" }, t("keys.sheet.page_two_link"))),
    body);
  if (status?.skBit === true && status.skStored === false) {
    mount(body, el("p", { class: "notice", role: "note", "data-role": "sheet-not-remembered" }, t("keys.sheet.not_remembered")));
    return root;
  }

  const statusLine = el("p", { class: "status", role: "status", "data-role": "sheet-status" });
  const errorBox = el("p", { class: "error", role: "alert", "data-role": "sheet-error" });
  errorBox.hidden = true;
  const downloadButton = /** @type {HTMLButtonElement} */ (el("button", { type: "button", class: "btn btn-primary", "data-role": "sheet-download" }, t("keys.sheet.download")));
  const proceed = /** @type {HTMLButtonElement} */ (el("button", { type: "button", class: "btn btn-primary", "data-role": "sheet-download-continue" }, t("sheet.download_continue")));
  const cancel = el("button", { type: "button", class: "btn btn-secondary", "data-role": "sheet-download-cancel" }, t("sheet.download_cancel"));
  // The warning is in the page only while it is asked for.
  const warning = el("div", { class: "notice notice-warning", role: "note", "data-role": "sheet-download-warning" },
    el("strong", null, t("keys.sheet.download_heading")),
    el("p", null, t("keys.sheet.download_warning")),
    el("div", { class: "actions" }, proceed, cancel));
  const slot = el("div", { "data-role": "sheet-download-slot" });

  downloadButton.addEventListener("click", () => {
    errorBox.hidden = true;
    mount(slot, warning);
  });
  cancel.addEventListener("click", () => clear(slot));
  let running = false;
  proceed.addEventListener("click", async () => {
    if (running) return;
    running = true;
    clear(slot);
    downloadButton.disabled = true;
    setText(statusLine, t("keys.sheet.busy"));
    /** @type {Uint8Array | null} */
    let bytes = null;
    try {
      bytes = await make();
      download(bytes, PAGE_ONE_FILE, "application/pdf");
      setText(statusLine, t("sheet.download_done"));
    } catch (error) {
      setText(statusLine, "");
      const code = codeOf(error);
      if (code !== "cancelled") {
        // A PDF that could not be made has a fixed text: the reason can name what was on the sheet.
        setText(errorBox, KNOWN_PAGE_ONE.includes(code) ? keysErrorText(t, error) : t("keys.sheet.failed"));
        errorBox.hidden = false;
      }
    } finally {
      // The bytes are zeroed after the hand-over (the download made its own copy).
      if (bytes !== null) wipeBytes(bytes);
      downloadButton.disabled = false;
      running = false;
    }
  });

  mount(body, el("div", { class: "actions" }, downloadButton), slot, statusLine, errorBox);
  return root;
}

/** The refusals of page 1 that say something the user can act on; any other failure is "the PDF could not be made". */
const KNOWN_PAGE_ONE = Object.freeze([
  "decrypt", "denied", "reauth_required", "second_factor_required", "session_ended", "sheet_server_key_missing", "sk_not_remembered",
  "pin_missing", "network", "throttled", "two_factor_unsupported",
]);
