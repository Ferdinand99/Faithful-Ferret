// "The server was restored": what the user sees when the engine has stopped
// because the server shows an older state than this device remembers. The page
// says what is certain (nothing here was deleted), shows what accepting the
// older state would do before anything is done, and asks for a typed word
// before it does it.
//
// Nothing here is a secret: the counts come from the engine's preview, and no
// item name or value is read or shown. An error is shown by its code, from a
// fixed list; its message is never shown.
import { el, mount } from "../dom.mjs";

/** @typedef {import("./common.mjs").Translate} Translate */
/** @typedef {import("./syncBanner.mjs").WarningsEngine} WarningsEngine */

/** The form of a word for comparing: composed, trimmed and in lower case. @param {string} word */
const plain = (word) => word.normalize("NFC").trim().toLocaleLowerCase();

/**
 * What went wrong, as a kind the page has a text for. `restore_not_verified` is the engine saying
 * that the older state does not check out; `invalid_state` that there is nothing to accept any more
 * (another tab did it, or the server changed); `busy` that an older state is being accepted right now.
 * @param {unknown} error
 * @returns {{ kind: "not_verified" | "invalid_state" | "busy" | "bad_feed" | "stopped" | "other", reason: string | null }}
 */
function kindOf(error) {
  const code = /** @type {any} */ (error)?.code;
  const reason = /** @type {any} */ (error)?.reason;
  if (code === "restore_not_verified") return { kind: "not_verified", reason: typeof reason === "string" ? reason : null };
  if (code === "invalid_state") return { kind: "invalid_state", reason: null };
  if (code === "busy") return { kind: "busy", reason: null };
  if (code === "bad_feed") return { kind: "bad_feed", reason: null };
  if (code === "stopped" || code === "locked" || code === "vault_locked") return { kind: "stopped", reason: null };
  return { kind: "other", reason: null };
}

/** The reasons of `restore_not_verified` that have a sentence of their own; any other is left out. */
const REASONS = Object.freeze(["no_checkpoint"]);

/**
 * @param {{
 *   engine: WarningsEngine,
 *   t: Translate,
 *   router?: { go(path: string): void },
 *   reload?: () => void,
 *   onAccepted?: (result: { reuploaded: number, conflicts: number, manifestOlder?: boolean }) => unknown,
 * }} options `reload` reloads the page; it is the page's own `location.reload` unless a test gives another.
 * `onAccepted` is called once after the engine has accepted the older state (the route keeps a local note there when the
 * unlock methods went back); what it does or throws never changes what the page shows.
 * @returns {HTMLElement}
 */
export function restoredView({ engine, t, router = { go() {} }, reload = () => /** @type {any} */ (globalThis).location?.reload(), onAccepted = () => {} }) {
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
  const forgetLink = () => link("syncwarnings.restored.forget", "restored-forget", () => router.go("/forget"));
  /** The line about the unlock methods, when the engine says the restored account settings are older. @param {boolean | undefined} older */
  const manifestLine = (older) =>
    older === true ? el("p", { class: "notice notice-warning", role: "note", "data-role": "restored-manifest-older" }, t("syncwarnings.restored.manifest_older")) : null;

  if (engine.health().halted !== "server_restored") {
    mount(body, el("p", { "data-role": "restored-na" }, t("syncwarnings.restored.not_applicable")), el("div", { class: "actions" }, toItems()));
    return root;
  }

  // The preview: counts only.
  const reupload = el("li", { "data-role": "preview-reupload" });
  const conflicts = el("li", { "data-role": "preview-conflicts" });
  const preview = el("ul", { class: "restored-preview", "data-role": "restored-preview" }, reupload, conflicts);
  preview.hidden = true;
  /** What the preview adds under the counts: the conflicts that will come back, and the older account settings. */
  const previewNotes = el("div", { class: "stack", "data-role": "restored-preview-notes" });
  // The retry button is only on the page while the preview has failed in a way a new try can mend.
  const retry = el("button", { type: "button", class: "btn btn-secondary", "data-role": "preview-retry" }, t("syncwarnings.restored.preview_retry"));
  const retryRow = el("div", { class: "actions", "data-role": "preview-retry-row" });
  retryRow.hidden = true;
  /** The way on after an error that a new try would not mend (see `problem`). */
  const exits = el("div", { class: "actions", "data-role": "restored-exits" });
  exits.hidden = true;

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
  const forget = forgetLink();
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
    preview, previewNotes, status, retryRow, exits, form, errorBox, el("div", { class: "actions" }, forget, toItems()));

  let ready = false;
  let running = false;

  /** Takes the form and the retry away: there is nothing here to press again. */
  function closeForm() {
    ready = false;
    mount(retryRow);
    retryRow.hidden = true;
    form.remove();
  }

  /** @param {HTMLElement} button */
  async function resumeSync(button) {
    if (running) return;
    running = true;
    clearError();
    setText(status, t("syncwarnings.action.busy"));
    button.setAttribute("aria-disabled", "true");
    try {
      await engine.resumeAfterHalt();
      setText(status, "");
      if (engine.health().halted === null) {
        mount(body, el("p", { role: "status", tabindex: "-1", "data-role": "restored-resumed" }, t("syncwarnings.restored.resumed")), el("div", { class: "actions" }, toItems()));
        /** @type {any} */ (body.firstChild)?.focus?.();
      } else {
        fail(t("syncwarnings.restored.resume_still"));
        button.focus?.();
      }
    } catch {
      setText(status, "");
      fail(t("syncwarnings.restored.failed"));
      button.focus?.();
    } finally {
      button.setAttribute("aria-disabled", "false");
      running = false;
    }
  }

  /**
   * Shows what went wrong, by its code. An older state that does not check out is not to be tried again: the form goes,
   * and the way on is to leave sync stopped or to forget the server. "Out of date" offers to let sync try again or to
   * reload. "Busy" says to wait, and keeps the form (or the retry) so that the user can. Anything else keeps them too.
   * @param {unknown} error @param {"preview" | "accept"} phase
   */
  function problem(error, phase) {
    const { kind, reason } = kindOf(error);
    setText(status, "");
    if (kind === "not_verified") {
      const extra = reason !== null && REASONS.includes(reason) ? ` ${t(`syncwarnings.restored.not_verified_${reason}`)}` : "";
      closeForm();
      fail(`${t("syncwarnings.restored.not_verified")}${extra}`);
      mount(exits, forgetLink(), toItems());
      exits.hidden = false;
      /** @type {any} */ (exits.firstChild)?.focus?.();
      return;
    }
    if (kind === "invalid_state") {
      closeForm();
      fail(t("syncwarnings.restored.invalid_state"));
      const resume = el("button", { type: "button", class: "btn btn-primary", "data-role": "restored-resume" }, t("syncwarnings.restored.resume"));
      resume.addEventListener("click", () => void resumeSync(resume));
      mount(exits, resume, link("syncwarnings.restored.reload", "restored-reload", () => reload()), forgetLink());
      exits.hidden = false;
      /** @type {any} */ (resume).focus?.();
      return;
    }
    if (kind === "stopped") {
      closeForm();
      fail(t("syncwarnings.restored.stopped"));
      mount(exits, toItems());
      exits.hidden = false;
      return;
    }
    // Busy, or a failure the page has no name for: the user may try again, and the focus goes back to where it was.
    fail(t(kind === "busy" ? "syncwarnings.restored.busy" : kind === "bad_feed" ? "syncwarnings.banner.bad_feed" : phase === "preview" ? "syncwarnings.restored.preview_failed" : "syncwarnings.restored.failed"));
    if (phase === "preview") {
      /** @type {any} */ (retry).disabled = false;
      mount(retryRow, retry);
      retryRow.hidden = false;
      /** @type {any} */ (retry).focus?.();
    } else {
      lock(false);
      /** @type {any} */ (input).value = "";
      /** @type {any} */ (input).focus?.();
    }
  }

  async function loadPreview() {
    clearError();
    retryRow.hidden = true;
    mount(retryRow);
    setText(status, t("syncwarnings.restored.preview_loading"));
    try {
      const counts = await engine.restorePreview();
      setText(reupload, t("syncwarnings.restored.preview_reupload", { count: counts.reupload }));
      setText(conflicts, t("syncwarnings.restored.preview_conflicts", { count: counts.conflicts }));
      /** @type {HTMLElement[]} */
      const notes = [];
      // Every item that already exists on the server comes back as a conflict, so there can be many.
      if (counts.conflicts > 0) notes.push(el("p", { "data-role": "restored-conflicts-note" }, t("syncwarnings.restored.conflicts_note")));
      const older = manifestLine(counts.manifestOlder);
      if (older) notes.push(older);
      mount(previewNotes, ...notes);
      preview.hidden = false;
      ready = true;
      /** @type {any} */ (accept).disabled = false;
      setText(status, "");
    } catch (error) {
      ready = false;
      problem(error, "preview");
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
    // The engine says, one by one, which items it cannot open; the page counts them and names none.
    /** @type {Set<string>} */
    const unreadable = new Set();
    const off = engine.on("error", (payload) => {
      if (payload?.code === "restore_item_unreadable") unreadable.add(String(payload.id ?? unreadable.size));
    });
    try {
      const done = await engine.acceptOlderState();
      /** @type {HTMLElement[]} */
      const parts = [
        el("p", { role: "status", tabindex: "-1", "data-role": "restored-done" }, t("syncwarnings.restored.done", { reuploaded: done.reuploaded, conflicts: done.conflicts })),
      ];
      // The conflicts are what the user has to do something about, so they have a line of their own and the way to them.
      if (done.conflicts > 0) parts.push(el("p", { class: "restored-conflicts", "data-role": "restored-conflicts" }, t("syncwarnings.restored.done_conflicts", { count: done.conflicts })));
      if (unreadable.size > 0) parts.push(el("p", { "data-role": "restored-unreadable" }, t("syncwarnings.restored.unreadable", { count: unreadable.size })));
      const older = manifestLine(done.manifestOlder);
      if (older) parts.push(older);
      parts.push(el("div", { class: "actions" }, toItems()));
      mount(body, ...parts);
      // Focus moves to the result: the form it was typed in is gone.
      /** @type {any} */ (parts[0]).focus?.();
      void (async () => {
        try {
          await onAccepted(done);
        } catch {
          // A note that cannot be kept is no reason to change the result.
        }
      })();
    } catch (error) {
      problem(error, "accept");
    } finally {
      off();
      running = false;
    }
  });

  void loadPreview();
  return root;
}
