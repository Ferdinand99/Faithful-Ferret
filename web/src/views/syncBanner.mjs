// The banner for what the sync engine has found out about the server: warnings
// that stand until a later check clears them, and the stops that hold sync
// until the user chooses. `BANNERS` follows the one table of warnings
// (`WARNING_TABLE`), so a code the engine can raise has a text here and the
// action the design names for it.
//
// Nothing on a banner names an item or shows a value: the events carry ids and
// counts, and this file reads neither. Text goes in as text nodes, from the
// catalog; a banner for a code that is not in the table is never made.
import { el, mount } from "../dom.mjs";
import { listenWhileShown } from "./common.mjs";

/** @typedef {import("./common.mjs").Translate} Translate */

/**
 * The part of the sync engine the banner and the restored screen use, written out
 * here so that a view does not depend on the engine's own file.
 * @typedef {object} WarningsEngine
 * @property {() => { halted: string | null, warnings: string[] }} health
 * @property {() => Promise<string>} verifyNow
 * @property {() => Promise<void>} resumeAfterHalt
 * @property {() => Promise<{ reupload: number, conflicts: number }>} restorePreview
 * @property {() => Promise<{ reuploaded: number, conflicts: number }>} acceptOlderState
 * @property {(event: string, fn: (payload: any) => void) => () => void} on
 */

/**
 * What a banner is and offers, by code. `level`: `info` is a notice that can be
 * hidden, `warning` a warning that stands until a check clears it, `stop`
 * holds sync. Actions: `check_again` and `try_again` read the feed and verify
 * the checkpoint again (on a stop, `try_again` lifts the stop and runs a pass);
 * `see_what_happened` and `forget` go to the screens of those names.
 * @type {Readonly<Record<string, { level: "info" | "warning" | "stop", actions: readonly ("check_again" | "try_again" | "see_what_happened" | "forget")[] }>>}
 */
export const BANNERS = Object.freeze({
  server_shows_older_state: { level: "warning", actions: ["check_again"] },
  checkpoint_rolled_back: { level: "warning", actions: ["check_again"] },
  checkpoint_forged: { level: "warning", actions: ["check_again"] },
  bad_feed: { level: "warning", actions: ["try_again"] },
  server_hid_item: { level: "info", actions: [] },
  verify_deferred: { level: "warning", actions: [] },
  rollback_suspected: { level: "stop", actions: ["try_again", "forget"] },
  server_restored: { level: "stop", actions: ["see_what_happened"] },
  restore_epoch_lowered: { level: "stop", actions: ["try_again", "forget"] },
  sync_memory_full: { level: "stop", actions: ["forget"] },
  unsupported: { level: "stop", actions: [] },
});

/** Whether the banner has a text for the code. @param {unknown} code @returns {code is string} */
export const isBannerCode = (code) => typeof code === "string" && Object.hasOwn(BANNERS, code);

/** The screens the navigating actions lead to. */
const SCREENS = Object.freeze({ see_what_happened: "/restored", forget: "/forget" });

/**
 * @param {{ engine: WarningsEngine, router: { go(path: string): void }, t: Translate }} options
 * @returns {HTMLElement} a container with one banner for each warning or stop that stands
 */
export function syncBanner({ engine, router, t }) {
  const root = el("div", { class: "sync-banners", "data-role": "sync-banners" });
  /** What stands now. @type {Set<string>} */
  const active = new Set();
  /** The banners on the page, by code. @type {Map<string, HTMLElement>} */
  const shown = new Map();
  /** Notices the user hid. @type {Set<string>} */
  const hidden = new Set();
  /** A pass ended with a bad feed (an error event); unlike a failed check it is not in `health()`. */
  let feedError = false;

  /** Puts the page in line with `active`. */
  function settle() {
    for (const [code, node] of [...shown]) {
      if (!active.has(code) || hidden.has(code)) {
        node.remove();
        shown.delete(code);
      }
    }
    for (const code of active) {
      if (shown.has(code) || hidden.has(code)) continue;
      const node = make(code);
      shown.set(code, node);
      root.appendChild(node);
    }
  }

  /** Takes the engine's own account of what stands. */
  function read() {
    const health = engine.health();
    active.clear();
    if (isBannerCode(health.halted)) active.add(health.halted);
    for (const code of health.warnings) if (isBannerCode(code) && BANNERS[code].level !== "stop") active.add(code);
    if (feedError) active.add("bad_feed");
  }

  /** @param {string} code */
  function make(code) {
    const spec = BANNERS[code];
    // The message is an alert: it is read out when it appears. The note below it is polite and changes with each try.
    const text = el("p", { class: "sync-banner-text", role: spec.level === "info" ? "status" : "alert", "data-role": "banner-text" },
      el("strong", { class: "sync-banner-kind" }, t(`syncwarnings.kind.${spec.level}`)),
      " ",
      t(`syncwarnings.banner.${code}`));
    const note = el("p", { class: "sync-banner-note", role: "status", "data-role": "banner-note", "data-empty": "true" });
    /** @param {string} key a catalog key, or "" for no note */
    const say = (key) => {
      mount(note, document.createTextNode(key === "" ? "" : t(key)));
      note.setAttribute("data-empty", key === "" ? "true" : "false");
    };
    /** @type {HTMLElement[]} */
    const buttons = [];
    let running = false;

    /** @param {() => Promise<void>} work */
    const guarded = (work) => async () => {
      if (running) return;
      running = true;
      for (const button of buttons) /** @type {any} */ (button).disabled = true;
      node.setAttribute("aria-busy", "true");
      say("syncwarnings.action.busy");
      try {
        await work();
      } catch {
        say("syncwarnings.note.failed");
      } finally {
        for (const button of buttons) /** @type {any} */ (button).disabled = false;
        node.setAttribute("aria-busy", "false");
        running = false;
      }
    };

    /** Reads the feed and checks the checkpoint again. */
    const check = guarded(async () => {
      const result = await engine.verifyNow();
      if (result === "not_checked") {
        say("syncwarnings.note.not_checked");
        return;
      }
      if (result === "ok") feedError = false;
      read();
      settle();
      // The banner may be gone now; if it stands, say so.
      say(result === "ok" ? "" : "syncwarnings.note.checked_still");
    });

    /** Lifts the stop and runs a pass; the stop comes back if its cause is still there. */
    const resume = guarded(async () => {
      await engine.resumeAfterHalt();
      read();
      settle();
      say(engine.health().halted === null ? "" : "syncwarnings.note.resume_still");
    });

    for (const action of spec.actions) {
      const button = el("button", { type: "button", class: "btn btn-secondary btn-sm", "data-role": "banner-action", "data-action": action },
        t(`syncwarnings.action.${action}`));
      if (action === "check_again" || (action === "try_again" && spec.level !== "stop")) button.addEventListener("click", () => void check());
      else if (action === "try_again") button.addEventListener("click", () => void resume());
      else button.addEventListener("click", () => router.go(SCREENS[action]));
      buttons.push(button);
    }
    if (spec.level === "info") {
      const dismiss = el("button", { type: "button", class: "btn btn-secondary btn-sm", "data-role": "banner-dismiss" }, t("syncwarnings.action.dismiss"));
      dismiss.addEventListener("click", () => {
        hidden.add(code);
        settle();
      });
      buttons.push(dismiss);
    }
    const node = el("div", { class: `sync-banner sync-banner-${spec.level}`, "data-role": "sync-banner", "data-code": code, "data-level": spec.level },
      text, buttons.length > 0 ? el("div", { class: "actions" }, ...buttons) : null, note);
    return node;
  }

  /** @param {any} payload */
  function onState(payload) {
    const kind = payload?.kind;
    const code = payload?.code;
    if (kind === "warning" && isBannerCode(code) && BANNERS[code].level !== "stop") {
      hidden.delete(code); // a notice that is raised again is shown again
      active.add(code);
    } else if (kind === "warning_cleared" && isBannerCode(code)) {
      active.delete(code);
      hidden.delete(code);
      if (code === "bad_feed") feedError = false;
    } else if (kind === "halted" && isBannerCode(code)) {
      active.add(code);
    } else if (kind === "idle") {
      // A pass that read the whole feed: a listing that was refused before it is behind us.
      feedError = false;
      read();
    } else if (kind === "syncing") {
      // A stop that was lifted (a retry, or an older state accepted): the engine says what stands.
      read();
    }
    settle();
  }

  /** @param {any} payload */
  function onError(payload) {
    if (payload?.code !== "bad_feed") return;
    feedError = true;
    active.add("bad_feed");
    settle();
  }

  read();
  settle();
  listenWhileShown(root, engine, "state", onState);
  listenWhileShown(root, engine, "error", onError);
  return root;
}
