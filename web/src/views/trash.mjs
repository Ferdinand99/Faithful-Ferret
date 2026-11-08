// The local trash: items deleted on this device or on another one, kept here as
// encrypted copies for a while so a deletion can be undone. The names come from
// the engine's memory (the copies are opened for the name when the vault opens);
// the page never reads the store and never shows more than a name and a date.
// "Restore" writes the item back to the server. "Remove for good" asks first.
import { el, mount } from "../dom.mjs";
import { askConfirm, describeError, formatMoment, listenWhileShown } from "./common.mjs";

/**
 * @param {{
 *   engine: import("./conflict.mjs").ConflictEngine,
 *   t: import("./common.mjs").Translate,
 *   locale?: string,
 *   touch?: () => boolean,
 *   scope?: { add(fn: () => void): () => void },
 * }} options
 * @returns {Promise<HTMLElement>}
 */
export async function trashView({ engine, t, locale, touch = () => true, scope }) {
  const root = el("section", { class: "card trash-card", "data-role": "trash" });
  const message = el("p", { class: "message", role: "status", "data-role": "message" });
  const host = el("div", { class: "dialog-host", "data-role": "dialog-host" });
  const list = el("ul", { class: "trash-items", "data-role": "trash-items" });
  const empty = el("p", { class: "count", "data-role": "trash-empty" });
  /** One action at a time: a second click while one runs is ignored. */
  let busy = false;
  let wiped = false;
  /** A newer reading makes an older answer stale. */
  let reading = 0;

  /** @param {string} text */
  function say(text) {
    if (wiped) return;
    mount(message, document.createTextNode(text));
  }

  scope?.add(() => {
    wiped = true;
    mount(list);
    mount(empty);
    mount(message);
    mount(root);
  });

  /** @param {{ id: string, name: string, deletedAt: number }} entry */
  function row(entry) {
    const name = typeof entry.name === "string" && entry.name !== "" ? entry.name : t("vault.item.unnamed");
    const when = formatMoment(entry.deletedAt, locale);
    const restore = el("button", { type: "button", class: "btn btn-secondary btn-sm", "data-role": "restore", "aria-label": t("conflict.trash.restore_label", { name }) }, t("conflict.trash.restore"));
    const remove = el("button", { type: "button", class: "btn btn-danger btn-sm", "data-role": "remove", "aria-label": t("conflict.trash.remove_label", { name }) }, t("conflict.trash.remove"));
    restore.addEventListener("click", () => act(entry.id, name, "restore", restore));
    remove.addEventListener("click", () => act(entry.id, name, "remove", remove));
    return el("li", { class: "trash-item", "data-role": "trash-item", "data-id": entry.id },
      el("span", { class: "trash-name", "data-role": "trash-name" }, name),
      el("span", { class: "detail", "data-role": "trash-deleted" }, when === null ? t("conflict.trash.when_unknown") : t("conflict.trash.deleted", { when })),
      el("span", { class: "actions" }, restore, remove));
  }

  /** Reads the trash again and shows it. */
  async function refresh() {
    if (wiped) return;
    const mine = (reading += 1);
    /** @type {Array<{ id: string, name: string, deletedAt: number }>} */
    let entries;
    try {
      entries = await engine.trash();
    } catch (error) {
      if (mine === reading) say(describeError(t, error));
      return;
    }
    if (wiped || mine !== reading) return;
    const sorted = [...entries].sort((a, b) => (b.deletedAt ?? 0) - (a.deletedAt ?? 0));
    mount(list, ...sorted.map(row));
    mount(empty, document.createTextNode(sorted.length === 0 ? t("conflict.trash.empty") : t("conflict.trash.count", { count: sorted.length })));
  }

  /**
   * @param {string} id @param {string} name @param {"restore" | "remove"} what @param {HTMLElement} button
   */
  async function act(id, name, what, button) {
    if (busy || !touch()) return;
    busy = true;
    try {
      if (what === "remove") {
        const yes = await askConfirm({
          t, host, title: "conflict.trash.remove_title", body: "conflict.trash.remove_body", confirm: "conflict.trash.remove_confirm",
          vars: { name },
        });
        if (!yes) {
          /** @type {any} */ (button).focus?.();
          return;
        }
        if (wiped) return;
      }
      try {
        if (what === "restore") await engine.restoreFromTrash(id);
        else await engine.removeFromTrash(id);
      } catch (error) {
        say(describeError(t, error));
        return;
      }
      say(t(what === "restore" ? "conflict.trash.restored" : "conflict.trash.removed", { name }));
      await refresh();
      // The button that was pressed is gone with its row; the focus goes to the top of the page's own content.
      /** @type {any} */ (heading).focus?.();
    } finally {
      busy = false;
    }
  }

  const heading = el("h1", { tabindex: "-1" }, t("conflict.trash.heading"));
  mount(root, heading, el("p", { class: "cf-intro" }, t("conflict.trash.intro")), empty, list, message, host,
    el("p", { class: "aside" }, el("a", { href: "#/items", "data-role": "back" }, t("conflict.trash.back"))));
  await refresh();
  // A deletion or a restore on another device, or a purge, changes what the trash holds.
  if (typeof engine.on === "function") listenWhileShown(root, /** @type {any} */ (engine), "changed", () => void refresh());
  return root;
}
