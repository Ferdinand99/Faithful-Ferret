// "The server was restored": what the user sees when the engine has stopped
// because the server shows an older state than this device remembers. The page
// says what is certain (nothing here was deleted), shows what accepting the
// older state would do before anything is done, and asks for a typed word
// before it does it.
//
// Nothing here is a secret: the counts come from the engine's preview, and no
// item name or value is read or shown.
import { el, mount } from "../dom.mjs";

/** @typedef {import("./common.mjs").Translate} Translate */
/** @typedef {import("./syncBanner.mjs").WarningsEngine} WarningsEngine */

/** The form of a word for comparing: composed, trimmed and in lower case. @param {string} word */
const plain = (word) => word.normalize("NFC").trim().toLocaleLowerCase();

/**
 * @param {{ engine: WarningsEngine, t: Translate, router?: { go(path: string): void } }} options
 * @returns {HTMLElement}
 */
export function restoredView({ engine, t, router = { go() {} } }) {
  const root = el("section", { class: "card restored", "data-role": "restored" });
  const body = el("div", { class: "stack" });
  const status = el("p", { class: "status", role: "status", "data-role": "restored-status" });
  const errorBox = el("p", { class: "error", role: "alert", "data-role": "restored-error" });
  errorBox.hidden = true;
  mount(root, el("h1", null, t("syncwarnings.restored.heading")), body);

  /** @param {HTMLElement} node @param {string} text */
  const setText = (node, text) => mount(node, document.createTextNode(text));
  /** @param {string} text */
  const fail = (text) => {
    setText(errorBox, text);
    errorBox.hidden = false;
  };
  const clearError = () => {
    setText(errorBox, "");
    errorBox.hidden = true;
  };
  /** @param {string} label @param {string} role @param {() => void} go */
  const link = (label, role, go) => {
    const button = el("button", { type: "button", class: "btn btn-secondary", "data-role": role }, t(label));
    button.addEventListener("click", go);
    return button;
  };
  const toItems = () => link("syncwarnings.restored.back", "restored-back", () => router.go("/items"));

  if (engine.health().halted !== "server_restored") {
    mount(body, el("p", { "data-role": "restored-na" }, t("syncwarnings.restored.not_applicable")), el("div", { class: "actions" }, toItems()));
    return root;
  }

  // The preview: counts only.
  const reupload = el("li", { "data-role": "preview-reupload" });
  const conflicts = el("li", { "data-role": "preview-conflicts" });
  const preview = el("ul", { class: "restored-preview", "data-role": "restored-preview" }, reupload, conflicts);
  preview.hidden = true;
  const retry = el("button", { type: "button", class: "btn btn-secondary", "data-role": "preview-retry" }, t("syncwarnings.restored.preview_retry"));
  // The button is only on the page while the preview has failed.
  const retryRow = el("div", { class: "actions", "data-role": "preview-retry-row" });
  retryRow.hidden = true;

  // The confirmation: the word is typed, then the button is pressed.
  const word = t("syncwarnings.restored.word");
  const input = el("input", {
    id: "restored-word", name: "restored-word", type: "text", autocomplete: "off", required: true,
    "aria-describedby": "restored-word-help", "data-role": "restored-word",
  });
  const label = el("label", { for: "restored-word" }, t("syncwarnings.restored.word_label", { word }));
  const accept = el("button", { type: "submit", class: "btn btn-primary", "data-role": "restored-accept" }, t("syncwarnings.restored.accept"));
  /** @type {any} */ (accept).disabled = true;
  const form = el("form", { class: "stack", "data-role": "restored-form" },
    el("div", { class: "field" }, label, input),
    el("p", { id: "restored-word-help", class: "help" }, t("syncwarnings.restored.intro_warn")),
    el("div", { class: "actions" }, accept));
  const forget = link("syncwarnings.restored.forget", "restored-forget", () => router.go("/forget"));
  /** @type {any[]} */
  const controls = [input, accept, retry, forget];
  /** @param {boolean} on */
  const lock = (on) => {
    for (const control of controls) control.disabled = on;
    root.setAttribute("aria-busy", on ? "true" : "false");
  };

  mount(body,
    el("p", null, t("syncwarnings.restored.intro_safe")),
    el("p", null, t("syncwarnings.restored.intro_choice")),
    preview, status, retryRow, form, errorBox, el("div", { class: "actions" }, forget, toItems()));

  let ready = false;
  let running = false;

  async function loadPreview() {
    clearError();
    retryRow.hidden = true;
    mount(retryRow);
    setText(status, t("syncwarnings.restored.preview_loading"));
    try {
      const counts = await engine.restorePreview();
      setText(reupload, t("syncwarnings.restored.preview_reupload", { count: counts.reupload }));
      setText(conflicts, t("syncwarnings.restored.preview_conflicts", { count: counts.conflicts }));
      preview.hidden = false;
      ready = true;
      /** @type {any} */ (accept).disabled = false;
      setText(status, "");
    } catch {
      ready = false;
      setText(status, "");
      fail(t("syncwarnings.restored.preview_failed"));
      mount(retryRow, retry);
      retryRow.hidden = false;
    }
  }
  retry.addEventListener("click", () => void loadPreview());

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (running || !ready) return;
    clearError();
    if (plain(String(/** @type {any} */ (input).value ?? "")) !== plain(word)) {
      fail(t("syncwarnings.restored.word_wrong"));
      /** @type {any} */ (input).focus?.();
      return;
    }
    running = true;
    lock(true);
    setText(status, t("syncwarnings.restored.working"));
    try {
      const done = await engine.acceptOlderState();
      const parts = [
        el("p", { role: "status", tabindex: "-1", "data-role": "restored-done" }, t("syncwarnings.restored.done", { reuploaded: done.reuploaded, conflicts: done.conflicts })),
      ];
      if (done.conflicts > 0) parts.push(el("p", { "data-role": "restored-conflicts" }, t("syncwarnings.restored.done_conflicts")));
      parts.push(el("div", { class: "actions" }, toItems()));
      mount(body, ...parts);
      // Focus moves to the result: the form it was typed in is gone.
      /** @type {any} */ (parts[0]).focus?.();
    } catch {
      setText(status, "");
      fail(t("syncwarnings.restored.failed"));
      lock(false);
      /** @type {any} */ (input).value = "";
    } finally {
      running = false;
    }
  });

  void loadPreview();
  return root;
}
