// The popup's passkey part (the `passkeys` feature, design document § 9.2 and § 9.5): what a page's passkey request looks like in
// Ferret's toolbar popup, at the top of the popup for the tab it is about.
//
//   - A modal request that waits without a window (the page had no user activation, or Ferret's window is busy): a card "<host> asks
//     for a passkey" whose click opens Ferret's window. The click in the popup is the activation the page did not have.
//   - A conditional request (the site's autofill UI): "Passkeys for <site>" with a button for each of Ferret's passkeys that the core
//     says may answer it. The click is the person's presence. Verification, when the site asks for it, is the recent unlock (the
//     background's own), the PIN or the master password here; Windows Hello and other passkeys open Ferret's window, because the popup
//     closes when the system's dialog takes the focus. Without a conditional request the passkeys of the site are listed for
//     information only, with no button (the site has not asked yet).
//   - After "use the browser" in Ferret's window: one line, "click the button on the page again".
//
// The popup names its tab, never a request: the background finds the tab's request (passkey_tab, passkey_tab_list, passkey_tab_open,
// and passkey_choose / passkey_verify with the tab). The list stays in the popup. A click counts only when the person made it
// (`isTrusted`) and 400 ms after the part last changed. Names of items are cleaned and isolated as in Ferret's window; the hosts are
// the browser's and the core's, never a text of the page.
//
// It asks `passkey_tab` (which works locked and does not keep the vault open) once a second; the list (which needs the open vault)
// only when the popup opens and when a conditional request comes or goes.

import { el, mount } from "../shared/dom.mjs";
import { chooserErrorKey, createGuard, siteText, sortCandidates } from "./passkeyFlow.mjs";
import { createVerifyStep } from "./passkeyVerify.mjs";

/** The feature mark on every control of the part (the build's checks look for it). */
const FEATURE = Object.freeze({ "data-feature": "passkeys" });

/** How often the part asks what waits for its tab (milliseconds). */
export const TAB_POLL_MS = 1000;

/** The ways to verify the popup offers itself (a passkey of the vault needs Ferret's window). */
const POPUP_WAYS = Object.freeze(["pin", "password"]);

/** @param {unknown} value @returns {value is Record<string, unknown>} */
const isRecord = (value) => typeof value === "object" && value !== null && !Array.isArray(value);

/** The host of an https origin the browser gave, or "". @param {unknown} origin */
function hostOf(origin) {
  try {
    const url = new URL(String(origin));
    return url.protocol === "https:" ? url.hostname : "";
  } catch {
    return "";
  }
}

/**
 * @typedef {{ waiting: { host: string, kind: "create" | "get" } | null, conditional: boolean, pass: boolean, foreign: boolean }} TabState
 * @typedef {{ itemId: string, name: string, userName: string, created: number | null }} Candidate
 * @typedef {{ mode: "none" | "pick" | "info", host: string, candidates: Candidate[], methods: string[] }} TabList
 */

/**
 * The popup's side of the messages, for one tab. Every answer is read into a plain shape here; anything of another shape counts as
 * nothing to show.
 * @param {import("./ui.mjs").Request} request
 * @param {number} tabId
 */
export function createTabBackend(request, tabId) {
  /** @param {string} type @param {Record<string, unknown>} body @returns {Promise<any>} */
  const ask = async (type, body) => {
    try {
      return await request(type, { tab_id: tabId, ...body });
    } catch (error) {
      const code = /** @type {{ code?: unknown }} */ (error)?.code;
      return { ok: false, reason: typeof code === "string" ? code : "internal_error" };
    }
  };
  return Object.freeze({
    /** @returns {Promise<TabState>} */
    async state() {
      const reply = await ask("passkey_tab", {});
      const none = { waiting: null, conditional: false, pass: false, foreign: false };
      if (!isRecord(reply) || reply.ok !== true) return none;
      const w = isRecord(reply.waiting) ? reply.waiting : null;
      const host = w === null ? "" : hostOf(w.origin);
      return {
        waiting: w !== null && host !== "" && (w.kind === "create" || w.kind === "get") ? { host, kind: w.kind } : null,
        conditional: reply.conditional === true,
        pass: reply.again === "create" || reply.again === "get",
        foreign: reply.foreign === true,
      };
    },
    /** @returns {Promise<TabList>} */
    async list() {
      const reply = await ask("passkey_tab_list", {});
      if (!isRecord(reply) || reply.ok !== true || (reply.mode !== "pick" && reply.mode !== "info")) return { mode: "none", host: "", candidates: [], methods: [] };
      /** @type {Candidate[]} */
      const candidates = [];
      for (const raw of Array.isArray(reply.candidates) ? reply.candidates.slice(0, 200) : []) {
        if (!isRecord(raw) || typeof raw.item_id !== "string" || !/^[0-9a-f]{32}$/.test(raw.item_id)) continue;
        const created = typeof raw.created === "number" && Number.isSafeInteger(raw.created) && raw.created > 0 ? raw.created : null;
        candidates.push({ itemId: raw.item_id, name: siteText(raw.name), userName: siteText(raw.user_name), created });
      }
      return {
        mode: reply.mode,
        host: siteText(reply.host, 253),
        candidates: sortCandidates(candidates),
        methods: (Array.isArray(reply.methods) ? reply.methods : []).filter((m) => typeof m === "string"),
      };
    },
    /** The person's click on a passkey. @param {string} itemId @returns {Promise<{ ok: true } | { ok: false, reason: string }>} */
    async choose(itemId) {
      const reply = await ask("passkey_choose", { kind: "get", item_id: itemId });
      return reply?.ok === true ? { ok: true } : { ok: false, reason: typeof reply?.reason === "string" ? reply.reason : "internal_error" };
    },
    /**
     * One try of the verification step (the PIN or the master password).
     * @param {"prf" | "pin" | "password"} method @param {Record<string, string>} input
     * @returns {Promise<{ ok: true } | { ok: false, reason: string, left?: number, wait_ms?: number }>}
     */
    async verify(method, input) {
      if (!POPUP_WAYS.includes(method)) return { ok: false, reason: "not_available" };
      const reply = await ask("passkey_verify", { method, ...input });
      if (reply?.ok === true) return { ok: true };
      return {
        ok: false,
        reason: typeof reply?.reason === "string" ? reply.reason : "internal_error",
        ...(Number.isSafeInteger(reply?.left) ? { left: reply.left } : {}),
        ...(Number.isSafeInteger(reply?.wait_ms) ? { wait_ms: reply.wait_ms } : {}),
      };
    },
    /** Opens Ferret's window for the waiting request or the conditional one. @param {"waiting" | "conditional"} which */
    async open(which) {
      const reply = await ask("passkey_tab_open", { which });
      return reply?.ok === true ? { ok: true } : { ok: false, reason: typeof reply?.reason === "string" ? reply.reason : "internal_error" };
    },
  });
}

/**
 * The part. `unlocked`: the vault is open (the list needs it; a locked popup shows only the card and the line). `onAnswered`: the
 * page got its answer (the popup may close).
 * @param {{
 *   texts: import("./page.mjs").Texts,
 *   request: import("./ui.mjs").Request,
 *   tabId: number,
 *   unlocked: boolean,
 *   onAnswered?: () => void,
 *   now?: () => number,
 *   schedule?: (fn: () => void, ms: number) => unknown,
 *   cancel?: (id: any) => void,
 * }} deps
 */
export function createPopupPasskeys({
  texts,
  request,
  tabId,
  unlocked,
  onAnswered = () => {},
  now = () => Date.now(),
  schedule = (fn, ms) => {
    const timer = setTimeout(fn, ms);
    // (In a test's process the look must not keep it alive.)
    /** @type {any} */ (timer)?.unref?.();
    return timer;
  },
  cancel = (id) => clearTimeout(id),
}) {
  const t = (/** @type {string} */ key, /** @type {Record<string, string | number>} */ vars = {}) => texts.t(key, vars);
  const backend = createTabBackend(request, tabId);
  const guard = createGuard({ now });
  const root = el("section", { class: "ff-pk-popup", "data-role": "passkey-popup", "aria-live": "polite", hidden: true, ...FEATURE });
  const alertNode = el("p", { class: "ff-error", role: "alert", "data-role": "passkey-popup-error", hidden: true });
  /** @type {TabState} */
  let state = { waiting: null, conditional: false, pass: false, foreign: false };
  /** @type {TabList} */
  let list = { mode: "none", host: "", candidates: [], methods: [] };
  /** The verification step that is shown, for the passkey the person clicked. @type {{ step: ReturnType<typeof createVerifyStep>, itemId: string } | null} */
  let verifying = null;
  let busy = false;
  let stopped = false;
  /** @type {unknown} */
  let timer = null;
  /** The key of what is shown, so a poll that finds nothing new builds nothing (and does not start the guard again). */
  let shownKey = "";

  /** @param {string} value */
  const bdi = (value) => el("bdi", { "data-site-text": "" }, value);

  /** @param {string | null} key @param {Record<string, string | number>} [vars] */
  function say(key, vars = {}) {
    alertNode.textContent = key === null ? "" : t(key, vars);
    alertNode.hidden = key === null;
  }

  /** @param {Record<string, string | number | boolean | null>} attrs @param {string} label @param {() => void | Promise<void>} run */
  function action(attrs, label, run) {
    const button = /** @type {HTMLButtonElement} */ (el("button", { type: "button", ...attrs, ...FEATURE }, label));
    button.addEventListener("click", (event) => {
      // A click counts only when the person made it, after the guard, and while nothing else is on its way.
      if (busy || stopped || !guard.accepts(/** @type {any} */ (event))) return;
      void run();
    });
    return button;
  }

  /** @param {() => Promise<void>} work */
  async function holding(work) {
    busy = true;
    root.setAttribute("aria-busy", "true");
    try {
      await work();
    } finally {
      busy = false;
      root.setAttribute("aria-busy", "false");
    }
  }

  /** Opens Ferret's window (the card, or Windows Hello for the conditional request). @param {"waiting" | "conditional"} which */
  const openWindow = (which) =>
    holding(async () => {
      say(null);
      const opened = await backend.open(which);
      if (!opened.ok) say(chooserErrorKey(opened.reason === "busy" ? "busy" : "unknown"));
    });

  /** The person clicked a passkey of the list (or verified, and the same choice goes again). @param {string} itemId */
  const pick = (itemId) =>
    holding(async () => {
      say(null);
      const outcome = await backend.choose(itemId);
      if (outcome.ok) {
        verifying?.step.wipe();
        verifying = null;
        onAnswered();
        await refresh(true);
        return;
      }
      if (outcome.reason === "verification_needed") {
        showVerify(itemId);
        return;
      }
      if (outcome.reason === "verification_unavailable") say("passkeys.verify.none");
      else if (outcome.reason === "gone") await refresh(true);
      else say(chooserErrorKey(outcome.reason));
    });

  /** The verification step in place of the list, for one passkey. @param {string} itemId */
  function showVerify(itemId) {
    verifying?.step.wipe();
    const step = createVerifyStep({
      texts,
      ways: list.methods.filter((m) => POPUP_WAYS.includes(m)),
      verify: (method, input) => backend.verify(method, input),
      proof: null,
      action,
      onVerified: () => void pick(itemId),
    });
    verifying = { step, itemId };
    render(true);
  }

  /** Back to the list from the verification step. */
  function back() {
    verifying?.step.wipe();
    verifying = null;
    render(true);
  }

  /** @param {Candidate} c @param {boolean} button */
  function row(c, button) {
    const name = c.name !== "" ? bdi(c.name) : el("span", { class: "ff-pk-none" }, t("passkeys.unnamed"));
    const user = c.userName !== "" ? bdi(c.userName) : el("span", { class: "ff-pk-none" }, t("passkeys.no_username"));
    const main = el("span", { class: "ff-pk-row-main" }, el("span", { class: "ff-pk-row-name" }, name), el("span", { class: "ff-pk-row-sub" }, user));
    if (!button) return el("div", { class: "ff-pk-row ff-pk-row-info", "data-role": "passkey-popup-info", "data-item": c.itemId }, main);
    const node = action({ class: "ff-pk-row", "data-role": "passkey-popup-pick", "data-item": c.itemId }, "", () => pick(c.itemId));
    node.append(main, el("span", { class: "ff-pk-row-go", "aria-hidden": "true" }, t("passkeys.get.use")));
    return node;
  }

  /** The list of the conditional request (buttons) or of the site (information). */
  function listPart() {
    if (!unlocked || list.mode === "none" || (list.mode === "info" && list.candidates.length === 0)) return null;
    const pickable = list.mode === "pick" && state.conditional;
    const heading = el("h2", { class: "ff-pk-h2", "data-role": "passkey-popup-title" });
    // The site's name goes into the heading as an isolated part (it is the core's RP ID, shown left to right).
    const [before, after] = t("passkeys.popup.title", { host: "\u0000" }).split("\u0000");
    heading.append(before ?? "", el("bdi", { class: "ff-host", dir: "ltr", "data-role": "passkey-popup-host" }, list.host), after ?? "");
    if (verifying !== null) {
      const backButton = action({ class: "ff-pk-link", "data-role": "passkey-popup-back" }, t("passkeys.verify.back"), () => back());
      // Windows Hello, Touch ID or another passkey of the vault: only Ferret's window can ask for it.
      const prf = list.methods.includes("prf")
        ? el("div", { class: "ff-actions" }, action({ class: "ff-button", "data-role": "passkey-popup-prf" }, t("passkeys.verify.prf"), () => openWindow("conditional")))
        : null;
      return el("div", { class: "ff-pk-popup-list", "data-role": "passkey-popup-verify" }, heading, prf, verifying.step.root, backButton);
    }
    const rows = list.candidates.map((c) => row(c, pickable));
    return el(
      "div",
      { class: "ff-pk-popup-list", "data-role": pickable ? "passkey-popup-list" : "passkey-popup-known" },
      heading,
      pickable && rows.length === 0 ? el("p", { class: "ff-hint", "data-role": "passkey-popup-empty" }, t("passkeys.get.none")) : null,
      rows.length > 0 ? el("div", { class: "ff-pk-rows", tabindex: rows.length > 3 ? "0" : null }, ...rows) : null,
      pickable ? null : el("p", { class: "ff-hint", "data-role": "passkey-popup-not-asked" }, t("passkeys.popup.not_asked")),
    );
  }

  /** Builds the part from what is known now. @param {boolean} [force] build even when nothing changed */
  function render(force = false) {
    const key = JSON.stringify([state, list, verifying?.itemId ?? null, unlocked]);
    if (!force && key === shownKey) return;
    shownKey = key;
    /** @type {Array<HTMLElement | null>} */
    const parts = [];
    if (state.pass) parts.push(el("p", { class: "ff-notice ff-pk-again", "data-role": "passkey-popup-again" }, t("passkeys.popup.again")));
    if (state.waiting !== null) {
      const words = t(`passkeys.popup.${state.waiting.kind === "get" ? "asks" : "saves"}`, { host: "\u0000" }).split("\u0000");
      parts.push(
        el(
          "div",
          { class: "ff-pk-card", "data-role": "passkey-popup-card", "data-kind": state.waiting.kind },
          el("p", { class: "ff-pk-card-text" }, words[0] ?? "", el("bdi", { class: "ff-host", dir: "ltr", "data-role": "passkey-popup-card-host" }, state.waiting.host), words[1] ?? ""),
          action({ class: "ff-button ff-primary", "data-role": "passkey-popup-open" }, t("passkeys.popup.open"), () => openWindow("waiting")),
        ),
      );
    }
    parts.push(listPart());
    if (state.foreign && (state.waiting !== null || state.conditional)) parts.push(el("p", { class: "ff-hint", "data-role": "passkey-popup-foreign" }, t("passkeys.popup.foreign")));
    const shown = parts.filter((p) => p !== null);
    if (shown.length === 0) {
      verifying?.step.wipe();
      root.hidden = true;
      mount(root);
      return;
    }
    mount(root, ...shown, alertNode);
    root.hidden = false;
    // New content: a click counts again only after the guard (design § 10.3.3).
    guard.touch();
  }

  /**
   * Asks the background again: what waits for the tab, and the list when the popup is open and a conditional request came or went.
   * @param {boolean} [relist] read the list again whatever changed
   */
  async function refresh(relist = false) {
    const next = await backend.state();
    if (stopped) return;
    const changed = next.conditional !== state.conditional;
    state = next;
    if (unlocked && (relist || changed)) {
      list = await backend.list();
      if (stopped) return;
      if (list.mode !== "pick" || !state.conditional) {
        verifying?.step.wipe();
        verifying = null;
      }
    }
    render();
  }

  function poll() {
    timer = schedule(async () => {
      timer = null;
      if (stopped) return;
      // A poll while a choice is on its way waits; one that finds nothing new builds nothing (what is typed stays).
      if (!busy) await refresh().catch(() => {});
      if (!stopped) poll();
    }, TAB_POLL_MS);
  }

  return {
    root,
    /** Reads the part once (the list too, when the vault is open) and then follows the tab. */
    async start() {
      await refresh(true).catch(() => {});
      if (!stopped) poll();
    },
    /** Stops following the tab and empties what was typed. */
    stop() {
      stopped = true;
      if (timer !== null) cancel(timer);
      timer = null;
      verifying?.step.wipe();
    },
    /** For the tests: the part as it is now. */
    current: () => ({ state, list, verifying: verifying?.itemId ?? null }),
  };
}
