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
import { askConfirm, describeError, formatMoment } from "./common.mjs";

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

/** The ids of the two rows the view adds itself; no field id of the core starts with a tilde. */
const URLS = "~urls";
const TOTP = "~totp";

/** @param {any} view @returns {string[]} the addresses of a version, sorted */
const urlsOf = (view) => (Array.isArray(view?.urls) ? view.urls.map((/** @type {any} */ u) => String(u?.url ?? "")).sort() : []);

/**
 * The rows of the table: what the engine compared, the addresses, whether a one-time password is set up (yes or no, never
 * the code), and the notes when a version has them and the engine did not list them. Rows that differ come first, and the
 * cut at MAX_ROWS is made after that, so what is left out is what agrees.
 * @param {ConflictData} data
 * @returns {{ rows: Array<{ key: string, label: string, kind: string, same: boolean | null }>, cut: number }}
 */
function rowsOf(data) {
  /** @type {Array<{ key: string, label: string, kind: string, same: boolean | null }>} */
  const rows = [];
  const seen = new Set();
  for (const field of Array.isArray(data.fields) ? data.fields : []) {
    const key = typeof field?.key === "string" ? field.key : "";
    if (key === "" || seen.has(key)) continue;
    seen.add(key);
    rows.push({ key, label: typeof field.label === "string" ? field.label : "", kind: String(field.kind ?? ""), same: typeof field.same === "boolean" ? field.same : null });
  }
  if (!seen.has("notes") && (data.local?.view?.has_notes === true || data.server?.view?.has_notes === true)) {
    rows.push({ key: "notes", label: "", kind: "notes", same: null });
  }
  const mine = data.local?.view;
  const theirs = data.server?.view;
  const bothShown = Boolean(mine) && Boolean(theirs);
  if (urlsOf(mine).length > 0 || urlsOf(theirs).length > 0) {
    rows.push({ key: URLS, label: "", kind: "urls", same: bothShown && JSON.stringify(urlsOf(mine)) === JSON.stringify(urlsOf(theirs)) });
  }
  if (mine?.has_totp === true || theirs?.has_totp === true) {
    rows.push({ key: TOTP, label: "", kind: "totp", same: bothShown && (mine.has_totp === true) === (theirs.has_totp === true) });
  }
  const sorted = rows
    .map((row, index) => ({ row, index }))
    .sort((a, b) => rank(a.row.same) - rank(b.row.same) || a.index - b.index)
    .map(({ row }) => row);
  return { rows: sorted.slice(0, MAX_ROWS), cut: Math.max(0, sorted.length - MAX_ROWS) };
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
 *   win?: { addEventListener?: Function, removeEventListener?: Function },
 * }} options
 * @returns {Promise<HTMLElement>}
 */
export async function conflictView({ engine, client, id, t, router, locale, touch = () => true, scope, win = /** @type {any} */ (globalThis).window }) {
  const root = el("section", { class: "card conflict-card", "data-role": "conflict" });
  const message = el("p", { class: "message", role: "status", "data-role": "message" });
  const host = el("div", { class: "dialog-host", "data-role": "dialog-host" });

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
  /** A choice is being written. */
  let busy = false;
  /** A question about a choice is on the page. */
  let asking = false;
  let finished = false;
  /** The view was left or the vault locked: nothing is shown or opened any more. */
  let wiped = false;
  /** The view was on the page at some point, so a later `isConnected` of false means it has been left. */
  let seen = false;
  /** Stops listening to the engine. */
  let unsubscribe = () => {};

  /** @param {string} text */
  function say(text) {
    if (wiped) return;
    mount(message, document.createTextNode(text));
  }

  /** Takes the one shown value off the page. */
  function hideAll() {
    shown = null;
    for (const { slot, toggle, show } of cells.values()) {
      mount(slot, document.createTextNode(DOTS));
      mount(toggle, document.createTextNode(t("conflict.show")));
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

  /** Leaves the page empty and the engine's handles closed: on a lock, when the view is left, and when it is found detached. */
  function wipe() {
    if (wiped) return;
    wiped = true;
    generation += 1;
    win?.removeEventListener?.("hashchange", wipe);
    win?.removeEventListener?.("pagehide", wipe);
    unsubscribe();
    hideAll();
    cells.clear();
    const held = data;
    data = null;
    void Promise.resolve(held?.close()).catch(() => {});
    mount(root);
  }
  scope?.add(wipe);
  win?.addEventListener?.("hashchange", wipe);
  win?.addEventListener?.("pagehide", wipe);

  /** False once the view has been on the page and is not any more. */
  function attached() {
    const connected = /** @type {any} */ (root).isConnected;
    if (connected === true) seen = true;
    return !(seen && connected === false);
  }

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

  /** @param {"local" | "server"} sideName */
  const sideText = (sideName) => t(sideName === "local" ? "conflict.mine" : "conflict.theirs");

  /**
   * A cell that holds plain content, or says the version does not have it.
   * @param {"local" | "server"} sideName @param {string} key @param {() => Node | null} content null when the version has nothing here
   */
  function plainCell(sideName, key, content) {
    const side = /** @type {ConflictData} */ (data)[sideName];
    const node = side.deleted ? null : content();
    return el("div", { class: "cf-cell", "data-role": "cell", "data-side": sideName, "data-key": `${sideName}.${key}` },
      el("span", { class: "cf-side" }, sideText(sideName)),
      node ?? el("span", { class: "cf-absent", "data-role": "absent" }, t("conflict.absent")));
  }

  /**
   * One value in one version. The button comes before the value, so a long value never moves it.
   * @param {"local" | "server"} sideName
   * @param {{ key: string, label: string }} row
   * @param {string} label the name of the row
   */
  function valueCell(sideName, row, label) {
    const side = /** @type {ConflictData} */ (data)[sideName];
    const index = indexOf(side, row.key);
    const field = index >= 0 ? side.view.fields[index] : null;
    const hasNotes = row.key === "notes" && index < 0 && side?.view?.has_notes === true;
    if (side.deleted || (!field && !hasNotes)) return plainCell(sideName, row.key, () => null);
    const plain = field && typeof field.value === "string" ? field.value : null;
    const key = `${sideName}.${row.key}`;
    const slot = el("span", { class: "value", "data-role": "value", "data-key": key }, plain ?? DOTS);
    const cell = el("div", { class: "cf-cell", "data-role": "cell", "data-side": sideName, "data-key": key },
      el("span", { class: "cf-side" }, sideText(sideName)));
    if (plain !== null) {
      cell.appendChild(slot);
      return cell;
    }
    const show = t("conflict.show_label", { label, side: sideText(sideName) });
    const toggle = el("button", {
      type: "button", class: "btn btn-secondary btn-sm", "aria-label": show, "data-role": "reveal", "data-key": key,
    }, t("conflict.show"));
    cells.set(key, { slot, toggle, show });
    toggle.addEventListener("click", async () => {
      if (!touch() || busy || asking) return;
      if (shown?.side === sideName && shown.key === row.key) {
        hideAll();
        return;
      }
      const mine = generation;
      try {
        const value = await fetchValue(side, row.key);
        if (!touch() || mine !== generation || wiped || busy || asking) return;
        hideAll(); // one at a time, across both versions: the first goes before the second shows
        shown = { side: sideName, key: row.key };
        mount(slot, document.createTextNode(String(value)));
        mount(toggle, document.createTextNode(t("conflict.hide")));
        toggle.setAttribute("aria-label", t("conflict.hide_label", { label, side: sideText(sideName) }));
      } catch (error) {
        hideAll();
        say(describeError(t, error));
      }
    });
    cell.appendChild(toggle);
    cell.appendChild(slot);
    return cell;
  }

  /**
   * The summary of one version: name, time, device.
   * @param {"local" | "server"} sideName
   */
  function sideBlock(sideName) {
    const side = /** @type {ConflictData} */ (data)[sideName];
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
      el("h2", null, sideText(sideName)), ...lines);
  }

  /** @param {{ key: string, label: string, kind: string, same: boolean | null }} row @param {number} number */
  function rowView(row, number) {
    const label = row.key === URLS ? t("conflict.urls")
      : row.key === TOTP ? t("conflict.totp")
        : row.key === "notes" && row.label === "" ? t("vault.item.notes") : row.label !== "" ? row.label : t("vault.item.field");
    const status = row.same === true ? "same" : row.same === false ? "differs" : "hidden";
    const titleId = `cf-field-${number}`;
    /** @param {"local" | "server"} sideName */
    const cellOf = (sideName) => {
      if (row.key === URLS) {
        return plainCell(sideName, row.key, () => {
          const urls = urlsOf(/** @type {ConflictData} */ (data)[sideName].view);
          return urls.length === 0
            ? el("span", { class: "cf-absent", "data-role": "none" }, t("conflict.no_urls"))
            : el("ul", { class: "cf-urls", "data-role": "urls" }, ...urls.map((u) => el("li", { class: "value", "data-role": "url" }, u)));
        });
      }
      if (row.key === TOTP) {
        return plainCell(sideName, row.key, () => el("span", { class: "value", "data-role": "totp" },
          t(/** @type {ConflictData} */ (data)[sideName].view?.has_totp === true ? "conflict.totp_yes" : "conflict.totp_no")));
      }
      return valueCell(sideName, row, label);
    };
    return el("div", { class: "cf-row", role: "group", "aria-labelledby": titleId, "data-role": "conflict-field", "data-key": row.key, "data-same": status },
      el("span", { class: "label", id: titleId }, label),
      el("span", { class: `cf-status cf-${status}`, "data-role": "status-word" }, t(`conflict.${status}`)),
      cellOf("local"), cellOf("server"));
  }

  /** Where a choice leads: back to the item, or to the list when the item is gone afterwards. @param {"mine" | "theirs"} choice */
  function target(choice) {
    const gone = choice === "mine" ? /** @type {ConflictData} */ (data).local.deleted : /** @type {ConflictData} */ (data).server.deleted;
    return gone ? "/items" : `/items/${id}`;
  }

  /**
   * Which case the screen is in; it decides the buttons and the question that is asked first.
   * @returns {{ mine: string, theirs: string, ask: boolean }}
   */
  function caseOf() {
    const current = /** @type {ConflictData} */ (data);
    if (current.local.deleted && current.server.deleted) return { mine: "delete_both_mine", theirs: "delete_both_theirs", ask: false };
    if (current.server.deleted) return { mine: "restore", theirs: "accept_deletion", ask: true };
    if (current.local.deleted) return { mine: "delete_mine", theirs: "keep_server_version", ask: true };
    return { mine: "keep_mine", theirs: "keep_theirs", ask: true };
  }

  /** @param {"mine" | "theirs"} choice @param {HTMLElement} button */
  async function choose(choice, button) {
    if (busy || asking || finished || !data || !touch()) return;
    const which = caseOf();
    const name = which[choice];
    if (which.ask) {
      // What is dropped for good is named, and Cancel has the focus.
      asking = true;
      hideAll();
      const yes = await askConfirm({
        t, host, title: `conflict.dialog.${name}_title`, body: `conflict.dialog.${name}_body`, confirm: `conflict.dialog.${name}_confirm`,
      });
      asking = false;
      if (!yes) {
        /** @type {any} */ (button).focus?.();
        return;
      }
      if (wiped || finished || !data || !touch()) return;
    }
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
      if (isNotFound(error)) {
        // Another tab or another pass has settled the conflict already: read the item again, which says so.
        await load();
        return;
      }
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
    const which = caseOf();
    chooseButtons = [];
    const make = (/** @type {"mine" | "theirs"} */ choice) => {
      const name = which[choice];
      const helpId = `cf-help-${choice}`;
      const button = el("button", { type: "button", class: "btn btn-secondary", "aria-describedby": helpId, "data-role": choice === "mine" ? "keep-mine" : "keep-theirs" }, t(`conflict.choice.${name}`));
      button.addEventListener("click", () => choose(choice, button));
      chooseButtons.push(button);
      return el("div", { class: "cf-choice" }, button, el("p", { class: "cf-help", id: helpId }, t(`conflict.help.${name}`)));
    };
    return el("div", { class: "cf-choices", "data-role": "choices" }, make("mine"), make("theirs"));
  }

  /** The other items in conflict, as a note with a link to the next one after this one in the list, and round again from the top. */
  function others() {
    const inConflict = (typeof engine.list === "function" ? engine.list() : [])
      .filter((/** @type {any} */ i) => i?.conflict === true && hex16.is(i.id));
    const here = inConflict.findIndex((/** @type {any} */ i) => i.id === id);
    const rest = inConflict.filter((/** @type {any} */ i) => i.id !== id);
    if (rest.length === 0) return null;
    const next = here < 0 ? rest[0] : inConflict[(here + 1) % inConflict.length];
    return el("p", { class: "aside", "data-role": "more-conflicts" },
      `${t("conflict.others", { count: rest.length })} `,
      el("a", { href: `#/items/${next.id}/conflict`, "data-role": "next-conflict" }, t("conflict.next")));
  }

  /** Builds the screen from the data held. */
  function render() {
    const current = /** @type {ConflictData} */ (data);
    cells.clear();
    const hasPasskey = Boolean(current.local?.view?.passkey) || Boolean(current.server?.view?.passkey);
    const passkeyRows = hasPasskey
      ? [el("div", { class: "cf-row", role: "group", "aria-labelledby": "cf-passkey", "data-role": "passkey-row" },
        el("span", { class: "label", id: "cf-passkey" }, t("conflict.passkey")),
        ...(["local", "server"]).map((sideName) => plainCell(sideName === "local" ? "local" : "server", "passkey", () => {
          const pk = /** @type {any} */ (current)[sideName]?.view?.passkey;
          return pk ? el("span", { class: "value" }, t("conflict.passkey_for", { site: String(pk.rp_id ?? ""), user: String(pk.user_name ?? "") })) : null;
        })))]
      : [];
    const { rows: shownRows, cut } = rowsOf(current);
    const rows = shownRows.map((row, number) => rowView(row, number));
    mount(root, ...[
      el("h1", null, t("conflict.heading")),
      el("p", { class: "cf-intro" }, t("conflict.intro")),
      current.local.deleted && current.server.deleted ? el("p", { class: "notice notice-conflict", role: "note", "data-role": "both-deleted-note" }, t("conflict.both_deleted")) : null,
      hasPasskey ? el("p", { class: "notice notice-conflict", role: "note", "data-role": "passkey-note" }, t("conflict.passkey_note")) : null,
      el("div", { class: "cf-blocks" }, sideBlock("local"), sideBlock("server")),
      el("div", { class: "cf-fields", "data-role": "conflict-fields" }, ...passkeyRows, ...rows),
      cut > 0 ? el("p", { class: "aside", "data-role": "rows-cut" }, t("conflict.more_rows", { count: cut })) : null,
      message,
      host,
      choices(),
      others(),
      el("p", { class: "aside" }, el("a", { href: `#/items/${id}`, "data-role": "back" }, t("conflict.back")))].filter((node) => node !== null));
  }

  /** Reads the item's conflict and builds the screen again. */
  async function load() {
    if (wiped) return;
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
    // A view that has been left, or locked, never opens handles again: what it was given is closed at once.
    if (mine !== generation || wiped || finished || !attached()) {
      try {
        await next.close();
      } catch {
        // Dropped with the engine.
      }
      if (!finished && mine === generation) wipe();
      return;
    }
    data = next;
    render();
  }

  await load();
  if (typeof engine.on === "function" && !wiped) {
    unsubscribe = engine.on("changed", (/** @type {{ ids?: string[] }} */ event) => {
      if (!attached()) {
        wipe();
        return;
      }
      if (!busy && !asking && !finished && Array.isArray(event?.ids) && event.ids.includes(id)) void load();
    });
  }
  return root;
}
