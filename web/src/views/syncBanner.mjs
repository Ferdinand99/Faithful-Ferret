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
 * @property {() => Promise<{ reupload: number, conflicts: number, manifestOlder?: boolean }>} restorePreview
 * @property {() => Promise<{ reuploaded: number, conflicts: number, manifestOlder?: boolean }>} acceptOlderState
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

/**
 * A stop that has no entry in `BANNERS` (a code the engine can halt with and this page was not told
 * about) still holds sync, so it still gets a banner: a general one, with the way out. It fails closed.
 * @type {{ level: "stop", actions: readonly ("try_again" | "forget")[] }}
 */
const GENERIC_STOP = Object.freeze({ level: "stop", actions: /** @type {readonly ("try_again" | "forget")[]} */ (Object.freeze(["try_again", "forget"])) });

/** A code the engine halted with, as far as it can be put in an attribute and a key: letters, digits, underscore. @param {unknown} code @returns {code is string} */
const isStopCode = (code) => typeof code === "string" && /^[a-z][a-z0-9_]{0,63}$/.test(code);

/** @param {string} code */
const specOf = (code) => (isBannerCode(code) ? BANNERS[code] : GENERIC_STOP);

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
  /** The codes whose own action is running: their banner stays, with its note and its focus, until the action is over. @type {Set<string>} */
  const pending = new Set();
  /** How many bad feeds have come as errors, so that a try can tell whether it met another. */
  let feedErrors = 0;
  /** The banners on the page, by code. @type {Map<string, HTMLElement>} */
  const shown = new Map();
  /** Notices the user hid. @type {Set<string>} */
  const hidden = new Set();
  /** A pass ended with a bad feed (an error event); unlike a failed check it is not in `health()`. */
  let feedError = false;

  /** Puts the page in line with `active`. */
  function settle() {
    for (const [code, node] of [...shown]) {
      if ((!active.has(code) || hidden.has(code)) && !pending.has(code)) {
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
    if (isStopCode(health.halted)) active.add(health.halted);
    for (const code of health.warnings) if (isBannerCode(code) && BANNERS[code].level !== "stop") active.add(code);
    if (feedError) active.add("bad_feed");
  }

  /** @param {string} code */
  function make(code) {
    const spec = specOf(code);
    // The message is an alert: it is read out when it appears. The note below it is polite and changes with each try.
    const text = el("p", { class: "sync-banner-text", role: spec.level === "info" ? "status" : "alert", "data-role": "banner-text" },
      el("strong", { class: "sync-banner-kind" }, t(`syncwarnings.kind.${spec.level}`)),
      " ",
      t(isBannerCode(code) ? `syncwarnings.banner.${code}` : "syncwarnings.banner.generic_stop"));
    const note = el("p", { class: "sync-banner-note", role: "status", "data-role": "banner-note", "data-empty": "true" });
    /** @param {string} key a catalog key, or "" for no note */
    const say = (key) => {
      mount(note, document.createTextNode(key === "" ? "" : t(key)));
      note.setAttribute("data-empty", key === "" ? "true" : "false");
    };
    /** @type {HTMLElement[]} */
    const buttons = [];
    let running = false;

    /**
     * One run at a time. The buttons are marked busy, not disabled: a disabled button loses the focus, and the focus
     * must still be there when the note says what happened. The banner stays until the run is over.
     * @param {() => Promise<void>} work
     */
    const guarded = (work) => async () => {
      if (running) return;
      running = true;
      pending.add(code);
      for (const button of buttons) button.setAttribute("aria-disabled", "true");
      node.setAttribute("aria-busy", "true");
      say("syncwarnings.action.busy");
      try {
        await work();
      } catch {
        say("syncwarnings.note.failed");
      } finally {
        for (const button of buttons) button.setAttribute("aria-disabled", "false");
        node.setAttribute("aria-busy", "false");
        running = false;
        pending.delete(code);
        // Now that the run is over, what no longer stands goes.
        read();
        settle();
      }
    };

    /** Reads the feed and checks the checkpoint again. */
    const check = guarded(async () => {
      const before = feedErrors;
      const result = await engine.verifyNow();
      if (result === "ok") {
        feedError = false;
        say("");
      } else if (result === "not_checked" && feedErrors === before) {
        say("syncwarnings.note.not_checked");
      } else {
        // It still stands: a bad feed that came again is one of these, though no check ran.
        say("syncwarnings.note.checked_still");
      }
    });

    /** Lifts the stop and runs a pass; the stop comes back if its cause is still there. */
    const resume = guarded(async () => {
      await engine.resumeAfterHalt();
      say(isStopCode(engine.health().halted) ? "syncwarnings.note.resume_still" : "");
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
    } else if (kind === "halted" && isStopCode(code)) {
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
    feedErrors += 1;
    active.add("bad_feed");
    settle();
  }

  read();
  settle();
  listenWhileShown(root, engine, "state", onState);
  listenWhileShown(root, engine, "error", onError);
  return root;
}
