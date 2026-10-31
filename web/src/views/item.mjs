// One item. Fields that are secret show as dots. "Show" asks the worker for ONE
// field's value, on the user's click, and puts it in the page; showing another
// field hides the first. "Copy" asks the worker for the value and hands it to
// the clipboard without putting it on the page.
//
// The view never keeps an item open. It opens the item to read what the core
// shows without secrets, closes it again, and opens it once more for each
// reveal or copy, so a handle lives for the length of one call. Because the
// item can change between the two, a reveal checks that the field it asks for
// still has the same id and stops with `item_changed` if not.
import { el, mount } from "../dom.mjs";
import { askConfirm, canChange, describeError, listenWhileShown, markBadges } from "./common.mjs";

/** What a hidden value looks like. */
const DOTS = "••••••••";

/** The name of an item type; a type this version does not know shows as it is written. @param {import("./common.mjs").Translate} t @param {unknown} type */
export function typeLabel(t, type) {
  return ["login", "note", "card", "identity"].includes(String(type)) ? t(`vault.type.${String(type)}`) : String(type ?? "");
}

/** @param {unknown} error */
const isNotFound = (error) => /** @type {any} */ (error)?.code === "not_found";

/**
 * @param {{
 *   engine: any,
 *   sync: { discard(id: string): Promise<unknown>, discardMissing(id: string): Promise<unknown> },
 *   client: { vault: Record<string, (...args: any[]) => Promise<any>> },
 *   id: string,
 *   t: import("./common.mjs").Translate,
 *   go?: (path: string) => void,
 *   touch?: () => boolean,
 *   scope?: { add(fn: () => void): () => void },
 *   clipboard?: { writeText(text: string): Promise<void> } | null,
 * }} options
 * @returns {Promise<HTMLElement>}
 */
export async function itemView({
  engine, sync, client, id, t, go = () => {}, touch = () => true, scope,
  clipboard = globalThis.navigator?.clipboard ?? null,
}) {
  const root = el("section", { class: "card item", "data-role": "item" });
  const message = el("p", { class: "message", role: "status", "data-role": "message" });
  const host = el("div", { class: "dialog-host", "data-role": "dialog-host" });

  /** Which secret is on the page: its key only, never the value. @type {string | null} */
  let revealedKey = null;
  /** The slots that show a value, by key. @type {Map<string, { slot: HTMLElement, toggle: HTMLButtonElement }>} */
  const slots = new Map();

  /** @param {string} text */
  function say(text) {
    mount(message, document.createTextNode(text));
  }

  /** Hides whatever is shown. */
  function hideAll() {
    revealedKey = null;
    for (const { slot, toggle } of slots.values()) {
      mount(slot, document.createTextNode(DOTS));
      mount(toggle, document.createTextNode(t("vault.item.show")));
    }
  }
  scope?.add(() => {
    hideAll();
    slots.clear();
    mount(root);
  });

  /**
   * Opens the item for one call, runs `fn` with the handle, closes it.
   * @template T
   * @param {(opened: { handle: number, view: any }) => Promise<T>} fn
   * @returns {Promise<T>}
   */
  async function withOpen(fn) {
    const opened = await engine.open(id);
    try {
      return await fn(opened);
    } finally {
      await opened.close();
    }
  }

  /**
   * The value of one field, checked against the id the page saw.
   * @param {number} index @param {string} fieldId
   */
  function fieldValue(index, fieldId) {
    return withOpen(async ({ handle, view }) => {
      if (view.fields?.[index]?.id !== fieldId) throw Object.assign(new Error("item_changed"), { code: "item_changed" });
      return client.vault.reveal_item_field(handle, index);
    });
  }

  /** @param {string} text */
  async function toClipboard(text) {
    if (!clipboard?.writeText) throw Object.assign(new Error("clipboard"), { code: "clipboard" });
    try {
      await clipboard.writeText(text);
    } catch {
      throw Object.assign(new Error("clipboard"), { code: "clipboard" });
    }
  }

  /**
   * One value that may be secret.
   * @param {{ key: string, label: string, plain: string | null, get(): Promise<string> }} spec
   *   `plain` is the value when the core shows it, else null; `get` asks the worker.
   */
  function valueRow({ key, label, plain, get }) {
    const slot = el("span", { class: "value", "data-role": "value", "data-key": key }, plain ?? DOTS);
    const copy = el("button", { type: "button", class: "secondary", "data-role": "copy", "data-key": key }, t("vault.item.copy"));
    /** @type {HTMLButtonElement | null} */
    let toggle = null;
    if (plain === null) {
      toggle = /** @type {HTMLButtonElement} */ (el("button", { type: "button", class: "secondary", "data-role": "reveal", "data-key": key }, t("vault.item.show")));
      slots.set(key, { slot, toggle });
      toggle.addEventListener("click", async () => {
        if (!touch()) return;
        if (revealedKey === key) {
          hideAll();
          return;
        }
        try {
          const value = await get();
          if (!touch()) return;
          hideAll(); // one at a time: the first goes before the second shows
          revealedKey = key;
          mount(slot, document.createTextNode(value));
          mount(/** @type {HTMLButtonElement} */ (toggle), document.createTextNode(t("vault.item.hide")));
        } catch (error) {
          hideAll();
          say(describeError(t, error));
        }
      });
    }
    copy.addEventListener("click", async () => {
      if (!touch()) return;
      try {
        await toClipboard(plain ?? (await get()));
        say(t("vault.item.copied", { label }));
      } catch (error) {
        say(describeError(t, error));
      }
    });
    return el("div", { class: "field-row", "data-role": "field", "data-key": key },
      el("span", { class: "label" }, label),
      slot,
      el("span", { class: "actions" }, toggle, copy));
  }

  /** Reads the item and builds the screen again. */
  async function load() {
    hideAll();
    slots.clear();
    /** @type {any} */
    let view;
    try {
      view = await withOpen(async ({ view: v }) => v);
    } catch (error) {
      const known = engine.list().find((/** @type {any} */ i) => i.id === id);
      mount(root, el("p", { role: "alert", "data-role": "unavailable" },
        t(isNotFound(error) && !known ? "vault.item.not_found" : "vault.item.cannot_open")),
      el("p", null, el("a", { href: "#/items" }, t("vault.item.back"))));
      return;
    }
    const entry = engine.list().find((/** @type {any} */ i) => i.id === id) ?? {};
    const marks = markBadges(t, entry);
    /** @type {Node[]} */
    const notices = [];
    if (entry.damaged) notices.push(notice("damaged", t("vault.notice.damaged")));
    if (entry.quarantined) notices.push(notice("quarantined", t("vault.notice.quarantined")));
    if (entry.readOnly) notices.push(notice("read_only", t("vault.notice.read_only")));
    if (entry.missingOnServer) {
      const discard = el("button", { type: "button", class: "danger", "data-role": "discard-missing" }, t("vault.notice.discard_missing"));
      discard.addEventListener("click", async () => {
        if (!touch()) return;
        const yes = await askConfirm({
          t, host, title: "vault.dialog.missing_title", body: "vault.dialog.missing_body", confirm: "vault.dialog.missing_confirm",
        });
        if (!yes) return;
        try {
          await sync.discardMissing(id);
          go("/items");
        } catch (error) {
          say(describeError(t, error));
        }
      });
      notices.push(notice("missing", t("vault.notice.missing"), discard));
    }
    if (entry.blocked) {
      const discard = el("button", { type: "button", "data-role": "discard-change" }, t("vault.notice.discard_change"));
      discard.addEventListener("click", async () => {
        if (!touch()) return;
        try {
          await sync.discard(id);
          await load();
        } catch (error) {
          say(describeError(t, error));
        }
      });
      const why = describeError(t, { code: "blocked", reason: entry.blockedReason });
      notices.push(notice("blocked", why, discard));
    }

    /** @type {HTMLElement[]} */
    const rows = [];
    /** @type {any[]} */
    const fields = Array.isArray(view.fields) ? view.fields : [];
    fields.forEach((field, index) => {
      const label = String(field.label ?? "") || t("vault.item.field");
      const plain = typeof field.value === "string" ? field.value : null;
      rows.push(valueRow({
        key: `f${index}`, label, plain,
        get: () => fieldValue(index, String(field.id)),
      }));
    });
    /** @type {any[]} */
    const urls = Array.isArray(view.urls) ? view.urls : [];
    if (view.has_notes) {
      rows.push(valueRow({
        key: "notes", label: t("vault.item.notes"), plain: null,
        get: () => withOpen(({ handle }) => client.vault.reveal_item_notes(handle)),
      }));
    }

    const editable = canChange(entry);
    const actions = el("div", { class: "actions", "data-role": "actions" });
    if (editable) {
      const del = el("button", { type: "button", class: "danger", "data-role": "delete" }, t("vault.item.delete"));
      del.addEventListener("click", async () => {
        if (!touch()) return;
        const yes = await askConfirm({
          t, host, title: "vault.dialog.delete_title", body: "vault.dialog.delete_body", confirm: "vault.dialog.delete_confirm",
          vars: { name: String(view.name ?? "") },
        });
        if (!yes) return;
        try {
          await engine.remove(id);
          go("/items");
        } catch (error) {
          say(describeError(t, error));
        }
      });
      mount(actions, el("a", { class: "button", href: `#/items/${id}/edit`, "data-role": "edit" }, t("vault.item.edit")), del);
    }

    mount(root, ...[
      el("h1", null, view.favorite ? el("span", { class: "star", role: "img", "aria-label": t("vault.item.favorite") }, "★ ") : null,
        String(view.name ?? "") === "" ? t("vault.item.unnamed") : String(view.name)),
      el("p", { class: "type", "data-role": "type" }, typeLabel(t, view.item_type)),
      el("div", { class: "marks" }, ...marks),
      ...notices,
      el("div", { class: "fields" }, ...rows),
      urls.length === 0 ? null : el("div", { class: "urls", "data-role": "urls" },
        el("h2", null, t("vault.item.addresses")),
        el("ul", null, ...urls.map((u) => el("li", { "data-role": "url" }, String(u.url ?? ""))))),
      view.has_totp ? el("p", { class: "aside", "data-role": "totp-note" }, t("vault.item.totp_note")) : null,
      message,
      host,
      actions,
      el("p", { class: "aside" }, el("a", { href: "#/items", "data-role": "back" }, t("vault.item.back")))].filter((node) => node !== null));
  }

  /** @param {string} kind @param {string} text @param {Node} [action] */
  function notice(kind, text, action) {
    return el("div", { class: `notice notice-${kind}`, role: "note", "data-role": "notice", "data-notice": kind },
      el("p", null, text), action ?? null);
  }

  await load();
  listenWhileShown(root, engine, "changed", (/** @type {{ ids?: string[] }} */ event) => {
    if (Array.isArray(event?.ids) && event.ids.includes(id)) void load();
  });
  return root;
}
