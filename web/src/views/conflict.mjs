// The conflict view: one item that was changed here and somewhere else, side by
// side, field by field. The user chooses which version to keep. Nothing is merged
// and nothing is chosen for them (Spec: Fase 1 § 8.5).
//
// Secret values stay out of the page. A hidden field shows as dots; "Show" asks
// the worker for that one value, on the user's click, and puts it in the page as
// text. Only one value is on the page at a time, across both versions: showing a
// second one hides the first. Every value leaves the page when it is hidden, when
// a choice is made, when the vault locks and when the item is read again. The
// handles that the engine opens for the two versions are closed on the same
// occasions.
import { hex16 } from "../b64.mjs";
import { el, mount } from "../dom.mjs";
import { describeError, formatMoment, listenWhileShown } from "./common.mjs";

/** What a hidden value looks like. */
const DOTS = "••••••••";

/** The most rows the view builds: an item with more fields than this is not one a person edits. */
const MAX_ROWS = 200;

/**
 * One side of a conflict, as the engine hands it over.
 * @typedef {object} ConflictSide
 * @property {number} rev
 * @property {boolean} deleted
 * @property {any} view the core's view of the item (no secrets), or null when that side is a deletion
 * @property {number} handle an open item for `client.vault.reveal_*`; closed by `close()`
 *
 * @typedef {object} ConflictData
 * @property {ConflictSide} local the version on this device
 * @property {ConflictSide} server the version on the server
 * @property {Array<{ key: string, label: string, kind: string, same: boolean | null }>} fields `same` is null when a value is hidden and so not compared
 * @property {() => Promise<void>} close
 *
 * The engine as this view needs it. A narrow structural type: the real engine has more.
 * @typedef {object} ConflictEngine
 * @property {(id: string) => Promise<any>} conflict
 * @property {(id: string, choice: "mine" | "theirs") => Promise<void>} resolve
 * @property {(id: string) => Promise<void>} keepMine
 * @property {() => Promise<Array<{ id: string, name: string, deletedAt: number }>>} trash
 * @property {(id: string) => Promise<void>} restoreFromTrash
 * @property {(id: string) => Promise<void>} removeFromTrash
 * @property {() => any[]} [list]
 * @property {(event: string, fn: (payload: any) => void) => () => void} [on]
 */

/** @param {unknown} error */
const isNotFound = (error) => /** @type {any} */ (error)?.code === "not_found";

/**
 * Which rows show first: the ones that differ, then the ones that could not be compared.
 * @param {boolean | null} same
 */
const rank = (same) => (same === false ? 0 : same === null ? 1 : 2);

/**
 * The rows of the table: what the engine compared, plus the notes when a version has
 * them and the engine did not list them. Rows that differ come first.
 * @param {ConflictData} data
 */
function rowsOf(data) {
  /** @type {Array<{ key: string, label: string, kind: string, same: boolean | null }>} */
  const rows = [];
  const seen = new Set();
  for (const field of Array.isArray(data.fields) ? data.fields : []) {
    const key = typeof field?.key === "string" ? field.key : "";
    if (key === "" || seen.has(key) || rows.length >= MAX_ROWS) continue;
    seen.add(key);
    rows.push({ key, label: typeof field.label === "string" ? field.label : "", kind: String(field.kind ?? ""), same: typeof field.same === "boolean" ? field.same : null });
  }
  if (!seen.has("notes") && (data.local?.view?.has_notes === true || data.server?.view?.has_notes === true)) {
    rows.push({ key: "notes", label: "", kind: "notes", same: null });
  }
  return rows
    .map((row, index) => ({ row, index }))
    .sort((a, b) => rank(a.row.same) - rank(b.row.same) || a.index - b.index)
    .map(({ row }) => row);
}

/**
 * @param {{
 *   engine: ConflictEngine,
 *   client: { vault: Record<string, (...args: any[]) => Promise<any>> },
 *   id: string,
 *   t: import("./common.mjs").Translate,
 *   router: { go(path: string): void },
 *   locale?: string,
 *   touch?: () => boolean,
 *   scope?: { add(fn: () => void): () => void },
 * }} options
 * @returns {Promise<HTMLElement>}
 */
export async function conflictView({ engine, client, id, t, router, locale, touch = () => true, scope }) {
  const root = el("section", { class: "card conflict-card", "data-role": "conflict" });
  const message = el("p", { class: "message", role: "status", "data-role": "message" });

  /** @type {ConflictData | null} */
  let data = null;
  /** The one value on the page: which version and which row. Never the value. @type {{ side: string, key: string } | null} */
  let shown = null;
  /** The slots and buttons of the hidden values, by "side.key". @type {Map<string, { slot: HTMLElement, toggle: HTMLElement, show: string }>} */
  const cells = new Map();
  /** A newer read of the item makes an older answer stale. */
  let generation = 0;
  /** The two choice buttons of the screen that is built. @type {HTMLElement[]} */
  let chooseButtons = [];
  let busy = false;
  let finished = false;
  let wiped = false;

  /** @param {string} text */
  function say(text) {
    mount(message, document.createTextNode(text));
  }

  /** Takes the one shown value off the page. */
  function hideAll() {
    shown = null;
    for (const { slot, toggle, show } of cells.values()) {
      mount(slot, document.createTextNode(DOTS));
      mount(toggle, document.createTextNode(t("conflict.show")));
      toggle.setAttribute("aria-pressed", "false");
      toggle.setAttribute("aria-label", show);
    }
  }

  /** Closes the handles of the version that is held. */
  async function closeData() {
    const held = data;
    data = null;
    try {
      await held?.close();
    } catch {
      // A handle that cannot be closed is dropped with the engine.
    }
  }

  scope?.add(() => {
    wiped = true;
    generation += 1;
    hideAll();
    cells.clear();
    const held = data;
    data = null;
    void Promise.resolve(held?.close()).catch(() => {});
    mount(root);
  });

  /** @param {ConflictSide} side @param {string} key @returns {number} the index of the field in the side's view, or -1 */
  function indexOf(side, key) {
    const fields = Array.isArray(side?.view?.fields) ? side.view.fields : [];
    return fields.findIndex((/** @type {any} */ f) => f?.id === key);
  }

  /**
   * The value of one hidden field, for one version. The handle is the one the engine opened for that version.
   * @param {ConflictSide} side @param {string} key
   */
  function fetchValue(side, key) {
    if (key === "notes" && indexOf(side, key) < 0) return client.vault.reveal_item_notes(side.handle);
    return client.vault.reveal_item_field(side.handle, indexOf(side, key));
  }

  /**
   * One value in one version.
   * @param {"local" | "server"} sideName
   * @param {{ key: string, label: string }} row
   * @param {string} label the name of the row
   */
  function valueCell(sideName, row, label) {
    const side = /** @type {ConflictData} */ (data)[sideName];
    const sideText = t(sideName === "local" ? "conflict.mine" : "conflict.theirs");
    const cell = el("div", { class: "cf-cell", "data-role": "cell", "data-side": sideName, "data-key": `${sideName}.${row.key}` },
      el("span", { class: "cf-side" }, sideText));
    const index = indexOf(side, row.key);
    const field = index >= 0 ? side.view.fields[index] : null;
    const hasNotes = row.key === "notes" && index < 0 && side?.view?.has_notes === true;
    if (side.deleted || (!field && !hasNotes)) {
      cell.appendChild(el("span", { class: "cf-absent", "data-role": "absent" }, t("conflict.absent")));
      return cell;
    }
    const plain = field && typeof field.value === "string" ? field.value : null;
    const slot = el("span", { class: "value", "data-role": "value", "data-key": `${sideName}.${row.key}` }, plain ?? DOTS);
    cell.appendChild(slot);
    if (plain !== null) return cell;

    const show = t("conflict.show_label", { label, side: sideText });
    const toggle = el("button", {
      type: "button", class: "btn btn-secondary btn-sm", "aria-pressed": "false", "aria-label": show,
      "data-role": "reveal", "data-key": `${sideName}.${row.key}`,
    }, t("conflict.show"));
    cells.set(`${sideName}.${row.key}`, { slot, toggle, show });
    toggle.addEventListener("click", async () => {
      if (!touch() || busy) return;
      if (shown?.side === sideName && shown.key === row.key) {
        hideAll();
        return;
      }
      const mine = generation;
      try {
        const value = await fetchValue(side, row.key);
        if (!touch() || mine !== generation || wiped || busy) return;
        hideAll(); // one at a time, across both versions: the first goes before the second shows
        shown = { side: sideName, key: row.key };
        mount(slot, document.createTextNode(String(value)));
        mount(toggle, document.createTextNode(t("conflict.hide")));
        toggle.setAttribute("aria-pressed", "true");
        toggle.setAttribute("aria-label", t("conflict.hide_label", { label, side: sideText }));
      } catch (error) {
        hideAll();
        say(describeError(t, error));
      }
    });
    cell.appendChild(toggle);
    return cell;
  }

  /**
   * The summary of one version: name, time, device.
   * @param {"local" | "server"} sideName
   */
  function sideBlock(sideName) {
    const side = /** @type {ConflictData} */ (data)[sideName];
    const heading = t(sideName === "local" ? "conflict.mine" : "conflict.theirs");
    const view = side.view && typeof side.view === "object" ? side.view : null;
    const when = formatMoment(view?.modified, locale);
    const device = typeof view?.device === "string" && view.device.trim() !== "" ? view.device : null;
    const name = typeof view?.name === "string" ? view.name : "";
    /** @type {Array<HTMLElement | null>} */
    const lines = [];
    if (side.deleted) {
      lines.push(el("p", { class: "cf-deleted", "data-role": "deleted" }, t(sideName === "local" ? "conflict.deleted_local" : "conflict.deleted_server")));
    }
    if (view) lines.push(el("p", { class: "cf-name", "data-role": "name" }, name === "" ? t("vault.item.unnamed") : name));
    if (view || side.deleted) {
      lines.push(el("dl", { class: "cf-facts" },
        el("dt", null, t("conflict.modified")),
        el("dd", { "data-role": "modified" }, when ?? t("conflict.when_unknown")),
        el("dt", null, t("conflict.device")),
        el("dd", { "data-role": "device" }, device ?? t("conflict.device_unknown"))));
    }
    return el("section", { class: "cf-block", "data-role": "side", "data-side": sideName },
      el("h2", null, heading), ...lines);
  }

  /** @param {{ key: string, label: string, kind: string, same: boolean | null }} row @param {number} number */
  function rowView(row, number) {
    const label = row.key === "notes" && row.label === "" ? t("vault.item.notes") : row.label !== "" ? row.label : t("vault.item.field");
    const status = row.same === true ? "same" : row.same === false ? "differs" : "hidden";
    const titleId = `cf-field-${number}`;
    return el("section", { class: "cf-row", "data-role": "conflict-field", "data-key": row.key, "data-same": status, "aria-labelledby": titleId },
      el("h3", { class: "label", id: titleId }, label),
      el("span", { class: `cf-status cf-${status}`, "data-role": "status-word" }, t(`conflict.${status}`)),
      valueCell("local", row, label), valueCell("server", row, label));
  }

  /** Where a choice leads: back to the item, or to the list when the item is gone afterwards. @param {"mine" | "theirs"} choice */
  function target(choice) {
    const gone = choice === "mine" ? /** @type {ConflictData} */ (data).local.deleted : /** @type {ConflictData} */ (data).server.deleted;
    return gone ? "/items" : `/items/${id}`;
  }

  /** @param {"mine" | "theirs"} choice @param {HTMLElement} button */
  async function choose(choice, button) {
    if (busy || finished || !data || !touch()) return;
    busy = true;
    root.setAttribute("aria-busy", "true");
    for (const b of chooseButtons) b.setAttribute("aria-disabled", "true");
    hideAll();
    say(t("conflict.saving"));
    const where = target(choice);
    try {
      await engine.resolve(id, choice);
    } catch (error) {
      busy = false;
      root.setAttribute("aria-busy", "false");
      for (const b of chooseButtons) b.setAttribute("aria-disabled", "false");
      say(describeError(t, error));
      /** @type {any} */ (button).focus?.();
      return;
    }
    finished = true;
    generation += 1;
    await closeData();
    router.go(where);
  }

  /** @returns {HTMLElement} */
  function choices() {
    const current = /** @type {ConflictData} */ (data);
    const serverGone = current.server.deleted;
    const localGone = current.local.deleted;
    const keys = serverGone
      ? ["conflict.restore_mine", "conflict.restore_help", "conflict.accept_deletion", "conflict.accept_deletion_help"]
      : localGone
        ? ["conflict.delete_mine", "conflict.delete_help", "conflict.keep_server_version", "conflict.keep_server_version_help"]
        : ["conflict.keep_mine", "conflict.keep_mine_help", "conflict.keep_theirs", "conflict.keep_theirs_help"];
    chooseButtons = [];
    const make = (/** @type {"mine" | "theirs"} */ choice, /** @type {string} */ label, /** @type {string} */ help) => {
      const helpId = `cf-help-${choice}`;
      const button = el("button", { type: "button", class: "btn btn-secondary", "aria-describedby": helpId, "data-role": choice === "mine" ? "keep-mine" : "keep-theirs" }, t(label));
      button.addEventListener("click", () => choose(choice, button));
      chooseButtons.push(button);
      return el("div", { class: "cf-choice" }, button, el("p", { class: "cf-help", id: helpId }, t(help)));
    };
    return el("div", { class: "cf-choices", "data-role": "choices" }, make("mine", keys[0], keys[1]), make("theirs", keys[2], keys[3]));
  }

  /** The other items in conflict, as a note with a link to the next one. */
  function others() {
    const next = (typeof engine.list === "function" ? engine.list() : [])
      .filter((/** @type {any} */ i) => i?.conflict === true && i.id !== id && hex16.is(i.id));
    if (next.length === 0) return null;
    return el("p", { class: "aside", "data-role": "more-conflicts" },
      `${t("conflict.others", { count: next.length })} `,
      el("a", { href: `#/items/${next[0].id}/conflict`, "data-role": "next-conflict" }, t("conflict.next")));
  }

  /** Builds the screen from the data held. */
  function render() {
    const current = /** @type {ConflictData} */ (data);
    cells.clear();
    const hasPasskey = Boolean(current.local?.view?.passkey) || Boolean(current.server?.view?.passkey);
    const passkeyRows = hasPasskey
      ? [el("section", { class: "cf-row", "data-role": "passkey-row" },
        el("h3", { class: "label" }, t("conflict.passkey")),
        ...(["local", "server"]).map((sideName) => {
          const pk = /** @type {any} */ (current)[sideName]?.view?.passkey;
          return el("div", { class: "cf-cell", "data-side": sideName },
            el("span", { class: "cf-side" }, t(sideName === "local" ? "conflict.mine" : "conflict.theirs")),
            el("span", { class: "value" }, pk ? t("conflict.passkey_for", { site: String(pk.rp_id ?? ""), user: String(pk.user_name ?? "") }) : t("conflict.absent")));
        }))]
      : [];
    const rows = rowsOf(current).map((row, number) => rowView(row, number));
    mount(root, ...[
      el("h1", null, t("conflict.heading")),
      el("p", { class: "cf-intro" }, t("conflict.intro")),
      hasPasskey ? el("p", { class: "notice notice-conflict", role: "note", "data-role": "passkey-note" }, t("conflict.passkey_note")) : null,
      el("div", { class: "cf-blocks" }, sideBlock("local"), sideBlock("server")),
      el("div", { class: "cf-fields", "data-role": "conflict-fields" }, ...passkeyRows, ...rows),
      message,
      choices(),
      others(),
      el("p", { class: "aside" }, el("a", { href: `#/items/${id}`, "data-role": "back" }, t("conflict.back")))].filter((node) => node !== null));
  }

  /** Reads the item's conflict and builds the screen again. */
  async function load() {
    const mine = (generation += 1);
    hideAll();
    cells.clear();
    await closeData();
    /** @type {ConflictData} */
    let next;
    try {
      next = await engine.conflict(id);
    } catch (error) {
      if (mine !== generation || wiped || finished) return;
      mount(root,
        el("h1", null, t("conflict.heading")),
        el("p", { role: "alert", "data-role": "no-conflict" }, isNotFound(error) ? t("conflict.not_in_conflict") : describeError(t, error)),
        el("p", { class: "aside" }, el("a", { href: `#/items/${id}`, "data-role": "back" }, t("conflict.back")), " ",
          el("a", { href: "#/items", "data-role": "back-list" }, t("vault.item.back"))));
      return;
    }
    if (mine !== generation || wiped || finished) {
      try {
        await next.close();
      } catch {
        // Dropped with the engine.
      }
      return;
    }
    data = next;
    render();
  }

  await load();
  if (typeof engine.on === "function") {
    listenWhileShown(root, /** @type {any} */ (engine), "changed", (/** @type {{ ids?: string[] }} */ event) => {
      if (!busy && !finished && Array.isArray(event?.ids) && event.ids.includes(id)) void load();
    });
  }
  return root;
}
