// "Accept the older state" in the popup (design document, section 8.6,
// "Legitimate rollbacks"): what the user sees when the sync stopped because the
// server shows an older state than this device remembers, the way the web
// vault's "The server was restored" page shows it. The panel says what is
// certain (nothing here was deleted), shows what accepting would do before
// anything is done (how many of this device's newer changes would be sent, how
// many items would become conflicts), and accepts only after the user typed
// the word it asks for.
//
// Nothing here is a secret: the counts come from the engine's preview, and no
// item name or value is read or shown. A refusal is shown by its code, from a
// fixed list.
//
// The conflicts that accepting leaves are this device's own unsent drafts. A
// build with saving from the extension on lists them and lets the user choose
// (conflictCard.mjs); a build without it cannot, so there the panel says that
// they stay as drafts that nothing sends, instead of asking for a decision.

import { FEATURES } from "../shared/features.mjs";
import { el, mount } from "../shared/dom.mjs";
import { olderErrorKey } from "./popupFlow.mjs";

/** @typedef {import("./page.mjs").Texts} Texts */
/** @typedef {ReturnType<typeof import("./popupFlow.mjs").createOlderFlow>} OlderFlow */

/**
 * The panel. `onClose` is called when the user goes back (sync stays stopped) or after the accept is done; the popup
 * then shows the sync as it stands.
 * @param {{ texts: Texts, flow: OlderFlow, onClose: () => void }} options
 * @returns {{ root: HTMLElement, loaded: Promise<void> }} `loaded` settles once the preview has been read (for the tests)
 */
export function createOlderPanel({ texts, flow, onClose }) {
  const t = texts.t;
  // `data-hold`: the popup does not build the sync's part again while this panel is open.
  const root = el("section", { class: "ff-older", "data-role": "older", "data-hold": "1", "aria-labelledby": "ff-older-title" });
  const status = el("p", { class: "ff-hint", role: "status", "data-role": "older-status" });
  const error = el("p", { class: "ff-error", role: "alert", "data-role": "older-error", hidden: true });
  const reupload = el("li", { "data-role": "older-reupload" });
  const conflicts = el("li", { "data-role": "older-conflicts" });
  const preview = el("ul", { class: "ff-older-preview", "data-role": "older-preview", hidden: true }, reupload, conflicts);
  const notes = el("div", { class: "ff-older-notes", "data-role": "older-notes" });
  const retry = el("button", { type: "button", class: "ff-button", "data-role": "older-retry", hidden: true }, t("sync.older.preview_retry"));
  const word = t("sync.older.word");
  const input = /** @type {HTMLInputElement} */ (
    el("input", { id: "ff-older-word", type: "text", class: "ff-input", autocomplete: "off", "aria-describedby": "ff-older-warn", "data-role": "older-word" })
  );
  // No button is pressed by Enter until the preview is there: the accept starts disabled.
  const accept = el("button", { type: "submit", class: "ff-button ff-danger", "data-role": "older-accept", disabled: true }, t("sync.older.accept"));
  const back = el("button", { type: "button", class: "ff-button", "data-role": "older-back" }, t("sync.older.back"));
  const form = el(
    "form",
    { class: "ff-form", "data-role": "older-form" },
    el("div", { class: "ff-field" }, el("label", { for: "ff-older-word", class: "ff-label" }, t("sync.older.word_label", { word })), input),
    el("p", { id: "ff-older-warn", class: "ff-hint" }, t("sync.older.intro_warn")),
    el("div", { class: "ff-actions" }, accept),
  );
  const exits = el("div", { class: "ff-actions", "data-role": "older-exits" }, back);
  mount(
    root,
    el("h2", { id: "ff-older-title" }, t("sync.older.heading")),
    el("p", null, t("sync.older.intro_safe")),
    el("p", null, t("sync.older.intro_choice")),
    preview,
    notes,
    status,
    retry,
    error,
    form,
    exits,
  );

  let ready = false;
  let running = false;

  /** @param {HTMLElement} node @param {string} text */
  const say = (node, text) => {
    node.textContent = text;
  };
  /** @param {string | null} key */
  const fail = (key) => {
    say(error, key === null ? "" : t(key));
    error.hidden = key === null;
  };
  /** The older state is not to be accepted from here any more: the form goes, the way back stays. */
  const closeForm = () => {
    ready = false;
    form.remove();
  };

  back.addEventListener("click", () => {
    if (!running) onClose();
  });

  async function loadPreview() {
    fail(null);
    retry.hidden = true;
    say(status, t("sync.older.preview_loading"));
    const answer = await flow.preview();
    say(status, "");
    if (!answer.ok) {
      if (answer.reason === "not_verified" || answer.reason === "not_verified_no_checkpoint" || answer.reason === "invalid_state" || answer.reason === "vault_locked") {
        closeForm();
      } else {
        retry.hidden = false;
      }
      fail(olderErrorKey(answer.reason, "preview"));
      return;
    }
    say(reupload, t("sync.older.preview_reupload", { count: answer.reupload }));
    say(conflicts, t("sync.older.preview_conflicts", { count: answer.conflicts }));
    /** @type {HTMLElement[]} */
    const lines = [];
    if (answer.conflicts > 0) {
      lines.push(el("p", { class: "ff-hint", "data-role": "older-conflicts-note" }, t(FEATURES.save ? "sync.older.conflicts_note" : "sync.older.release_conflicts")));
    }
    if (answer.manifestOlder) lines.push(el("p", { class: "ff-notice", role: "note", "data-role": "older-manifest" }, t("sync.older.manifest_older")));
    mount(notes, ...lines);
    preview.hidden = false;
    ready = true;
    accept.removeAttribute("disabled");
  }
  retry.addEventListener("click", () => void loadPreview());

  form.addEventListener("submit", async (/** @type {Event} */ event) => {
    event.preventDefault();
    if (running || !ready) return;
    fail(null);
    running = true;
    accept.setAttribute("disabled", "");
    root.setAttribute("aria-busy", "true");
    say(status, t("sync.older.working"));
    const done = await flow.accept(input.value, word);
    root.setAttribute("aria-busy", "false");
    say(status, "");
    running = false;
    if (!done.ok) {
      if (done.reason === "not_verified" || done.reason === "not_verified_no_checkpoint" || done.reason === "invalid_state" || done.reason === "vault_locked") {
        closeForm();
      } else {
        accept.removeAttribute("disabled");
        input.value = "";
        input.focus();
      }
      fail(olderErrorKey(done.reason, "accept"));
      return;
    }
    /** @type {HTMLElement[]} */
    const parts = [
      el("p", { role: "status", tabindex: "-1", "data-role": "older-done" }, t(FEATURES.save ? "sync.older.done" : "sync.older.done_release", { reuploaded: done.reuploaded, conflicts: done.conflicts })),
    ];
    if (done.conflicts > 0) {
      parts.push(el("p", { class: "ff-hint", "data-role": "older-done-conflicts" }, FEATURES.save ? t("sync.older.done_conflicts", { count: done.conflicts }) : t("sync.older.release_conflicts")));
    }
    if (done.unreadable > 0) parts.push(el("p", { class: "ff-hint", "data-role": "older-unreadable" }, t("sync.older.unreadable", { count: done.unreadable })));
    if (done.manifestOlder) parts.push(el("p", { class: "ff-notice", role: "note", "data-role": "older-manifest" }, t("sync.older.manifest_older")));
    const close = el("button", { type: "button", class: "ff-button ff-primary", "data-role": "older-close" }, t("sync.older.close"));
    close.addEventListener("click", () => onClose());
    parts.push(el("div", { class: "ff-actions" }, close));
    mount(root, el("h2", { id: "ff-older-title" }, t("sync.older.heading")), ...parts);
    /** @type {any} */ (parts[0]).focus?.();
  });

  const loaded = loadPreview().catch(() => {
    fail("sync.older.error.preview_failed");
  });
  return { root, loaded };
}
