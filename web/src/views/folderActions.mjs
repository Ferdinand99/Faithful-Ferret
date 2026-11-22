// What the folder screens change, and how: every change of folders is an edit of the items that carry them, one write
// per item through the engine (each one queued in the outbox, which the sync sends in its batches), with a draft that
// holds the item's whole new list of folders and nothing else. The core starts each write from the item's own body, so
// every other part of the item, and every key this version does not know, stays as it was.
//
// - rename: every item in the folder gets the new name where the old one stood;
// - delete: every item in the folder loses the label; the items stay;
// - "Move to folder": the folders of one item are set in a dialog (or, for several items, the chosen folders are added).
import { el, mount } from "../dom.mjs";
import { folderIndex, renamedList, sameFolder, withoutFolder } from "../folders.mjs";
import { canChange, codeOf, describeError } from "./common.mjs";
import { FOLDER_ERRORS, folderPicker } from "./folderPicker.mjs";

/**
 * @typedef {object} RunResult
 * @property {number} done items written
 * @property {number} skipped items in the folder that cannot be changed now (read only, refused, in conflict)
 * @property {number} failed items whose write failed (they keep the old list)
 * @property {unknown} first the first failure
 * @property {boolean} stopped the vault locked during the run, which ended it
 */

/**
 * Writes a new list of folders to every item that `next` gives one for. The newest revision of each item is used, so a
 * change that came in since the screen was drawn is never overwritten (the write is refused with `item_changed` and
 * counted as failed).
 * @param {{
 *   engine: { list(): any[], update(id: string, draft: object, rev: number): Promise<void> },
 *   next: (folders: readonly string[]) => string[] | null,
 *   touch?: () => boolean,
 *   progress?: (done: number, total: number) => void,
 * }} options `next` gives the new list of an item, or null when the item is not to be written
 * @returns {Promise<RunResult & { total: number }>}
 */
export async function rewriteFolders({ engine, next, touch = () => true, progress = () => {} }) {
  const targets = engine.list().filter((item) => Array.isArray(item.folders) && next(item.folders) !== null);
  /** @type {RunResult & { total: number }} */
  const result = { done: 0, skipped: 0, failed: 0, first: null, stopped: false, total: targets.length };
  let count = 0;
  for (const target of targets) {
    // Each write is the user's own action, so the idle lock does not cut a long run; a lock that happened ends it.
    if (!touch()) {
      result.stopped = true;
      break;
    }
    count += 1;
    const item = engine.list().find((entry) => entry.id === target.id) ?? target;
    const list = Array.isArray(item.folders) ? next(item.folders) : null;
    if (list === null) continue; // the item has left the folder meanwhile
    if (!canChange(item)) {
      result.skipped += 1;
    } else {
      try {
        await engine.update(item.id, { folders: list }, item.rev);
        result.done += 1;
      } catch (error) {
        result.failed += 1;
        result.first ??= error;
      }
    }
    if (count % 25 === 0) progress(count, targets.length);
  }
  return result;
}

/**
 * Renames a folder on every item that carries it.
 * @param {{ engine: any, from: string, to: string, touch?: () => boolean, progress?: (done: number, total: number) => void }} options
 */
export const renameFolder = ({ engine, from, to, touch, progress }) =>
  rewriteFolders({ engine, touch, progress, next: (folders) => renamedList(folders, from, to) });

/**
 * Takes a folder off every item that carries it; the items stay.
 * @param {{ engine: any, name: string, touch?: () => boolean, progress?: (done: number, total: number) => void }} options
 */
export const deleteFolder = ({ engine, name, touch, progress }) =>
  rewriteFolders({ engine, touch, progress, next: (folders) => withoutFolder(folders, name) });

/**
 * The line that tells how a run went: how many were changed, how many could not be, and the first reason.
 * @param {import("./common.mjs").Translate} t
 * @param {RunResult} result
 * @param {"rename" | "delete" | "move"} kind
 */
export function runText(t, result, kind) {
  return [
    result.done > 0 ? t(`folders.done_${kind}`, { count: result.done }) : "",
    result.skipped > 0 ? t("folders.done_skipped", { count: result.skipped }) : "",
    result.failed > 0 ? `${t("folders.done_failed", { count: result.failed })} ${describeError(t, result.first)}` : "",
    result.stopped ? t("folders.done_stopped") : "",
    result.done + result.skipped + result.failed === 0 && !result.stopped ? t("folders.done_none") : "",
  ].filter((part) => part !== "").join(" ");
}

/**
 * The dialog of "Move to folder": the folders of one item, or folders to add to several. It is put in `host` and is gone
 * when it is closed or the vault locks.
 * @param {{
 *   t: import("./common.mjs").Translate,
 *   host: HTMLElement,
 *   engine: any,
 *   ids: readonly string[],
 *   locale?: string,
 *   touch?: () => boolean,
 *   scope?: { add(fn: () => void): () => void },
 * }} options
 * @returns {Promise<string>} the line that says what was done ("" when it was cancelled)
 */
export function moveDialog({ t, host, engine, ids, locale, touch = () => true, scope }) {
  // Only the items of the dialog are written: the run is given a list that holds them alone.
  const own = {
    list: () => engine.list().filter((/** @type {any} */ item) => ids.includes(item.id)),
    update: (/** @type {string} */ id, /** @type {object} */ draft, /** @type {number} */ rev) => engine.update(id, draft, rev),
  };
  return new Promise((resolve) => {
    const items = own.list();
    const one = items.length === 1 ? items[0] : null;
    const picker = folderPicker({
      t, locale,
      initial: one && Array.isArray(one.folders) ? one.folders : [],
      suggestions: () => folderIndex(engine.list(), locale).map((folder) => folder.name),
    });
    const titleText = one ? t("folders.move.title_one", { name: one.name === "" ? t("vault.item.unnamed") : one.name }) : t("folders.move.title_many", { count: items.length });
    const heading = el("h2", { id: "folder-dialog-title" }, titleText);
    const status = el("p", { class: "status", role: "status", "data-role": "folder-dialog-status" });
    const cancel = el("button", { type: "button", class: "btn btn-secondary", "data-role": "dialog-cancel" }, t("vault.dialog.cancel"));
    const save = el("button", { type: "button", class: "btn btn-primary", "data-role": "dialog-confirm" }, t("folders.move.save"));
    const dialog = el("div", { class: "dialog folder-dialog", role: "dialog", "aria-labelledby": "folder-dialog-title", "data-role": "folder-dialog" },
      heading, one ? null : el("p", null, t("folders.move.many_help")), picker.root, status, el("div", { class: "actions" }, cancel, save));
    let closed = false;
    /** @type {(() => void) | undefined} */
    let off;
    /** @param {string} text */
    const finish = (text) => {
      if (closed) return;
      closed = true;
      picker.wipe();
      dialog.remove();
      off?.();
      resolve(text);
    };
    off = scope?.add(() => finish(""));
    cancel.addEventListener("click", () => finish(""));
    dialog.addEventListener("keydown", (/** @type {any} */ event) => {
      if (event?.key === "Escape") finish("");
    });
    save.addEventListener("click", async () => {
      if (closed || !touch()) return;
      if (!picker.commitTyped()) return;
      const problem = picker.check();
      if (problem !== null) {
        picker.showError(problem);
        return;
      }
      const chosen = picker.value();
      /** @type {any} */ (save).disabled = true;
      mount(status, document.createTextNode(t("folders.working")));
      // One item: its list is what the picker holds. Several: the chosen folders are added to what each has.
      const result = await rewriteFolders({
        engine: own, touch,
        next: (folders) => (one !== null ? (sameNames(folders, chosen) ? null : [...chosen]) : added(folders, chosen)),
        progress: (done, total) => mount(status, document.createTextNode(t("folders.progress", { done, total }))),
      }).catch((error) => ({ done: 0, skipped: 0, failed: 1, first: error, stopped: false, total: 1 }));
      if (closed) return;
      /** @type {any} */ (save).disabled = false;
      if (result.failed > 0 && one !== null && FOLDER_ERRORS.includes(codeOf(result.first))) {
        // The core refused the list: the dialog stays, with the reason under the picker.
        picker.showError(codeOf(result.first));
        mount(status);
        return;
      }
      finish(runText(t, result, "move"));
    });
    host.appendChild(dialog);
    /** @type {any} */ (picker.root).querySelector?.("input")?.focus?.();
  });
}

/** @param {readonly string[]} a @param {readonly string[]} b */
function sameNames(a, b) {
  return a.length === b.length && a.every((name, i) => name === b[i]);
}

/**
 * The list of an item with `picked` added (a folder it has already is not added twice); null when nothing changes.
 * @param {readonly string[]} folders @param {readonly string[]} picked
 */
function added(folders, picked) {
  const extra = picked.filter((name) => !folders.some((have) => sameFolder(have, name)));
  return extra.length === 0 ? null : [...folders, ...extra];
}

/**
 * The folder hooks of the list and the item page: "Move to folder" opens the dialog in the screen's own place for dialogs
 * and says what was done in its message line.
 * @param {{ t: import("./common.mjs").Translate, engine: any, locale?: string, touch?: () => boolean, scope?: { add(fn: () => void): () => void } }} options
 */
export function moveHook({ t, engine, locale, touch, scope }) {
  return (/** @type {readonly string[]} */ ids, /** @type {{ host: HTMLElement, say: (text: string) => void }} */ where) => {
    void moveDialog({ t, host: where.host, engine, ids, locale, touch, scope }).then((text) => {
      if (text !== "") where.say(text);
    });
  };
}
