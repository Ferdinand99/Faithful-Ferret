// Which frames of a tab may be offered items, and the list of items a page is
// offered (design document, sections 10.4 and 10.5).
//
// Every site rule comes from the core. This file asks the core for a frame's
// origin (`page_origin`), whether two addresses are on the same site
// (`same_site`) and how a host is shown (`display_host`); the core alone
// decides which saved address matches which page (`match_page`, in the core
// host). There is no Public Suffix List here and no rule of our own that reads
// a host: the only thing this file decides by itself is that `https` and the
// loopback addresses are secure, which the core leaves to the extension.
//
// The frames come from the browser (`webNavigation.getAllFrames`), never from
// a page or a message. A frame may be offered items when:
//
//   - it is the top of the tab, with an `http` or `https` address; or
//   - it is a frame below the top whose origin is not opaque (the core gives it
//     an origin: `about:blank`, `about:srcdoc`, `data:`, `blob:` and
//     `javascript:` have none), whose address is `https` or loopback, which is
//     on the same site as the top (the core's `same_site`), and every frame
//     above it up to the top is such a frame as well, the top itself `https`
//     or loopback. A frame inside a cross-site frame is refused, also when it
//     is on the top's site again.
//
// A sandboxed frame with an `https` address has an opaque origin that only
// the frame itself sees. The browser's facts cannot show it, so the final
// word comes after the fill script has reported from the frame: its
// `self_origin` can only narrow what the browser said (`confirmFrame`).
//
// A frame of the same site with another origin than the top is not covered by
// the permission the toolbar button gives (`activeTab`, the top's origin). It
// is offered nothing until its host permission is granted, which is asked for
// in a tab of the extension (`pages/grant.html`, see `grantUrl`): a request
// from the popup would close the popup. It is matched all the same (matching
// needs no permission), and named for the grant only when some item matches
// it: a frame no item could fill never asks for a permission.
//
// Before a value goes into a frame below the top, every document above it is
// asked whether the frame is shown there, and asking a document needs its
// origin's permission too. A frame below a middle frame of another origin than
// the top is therefore checked only when that origin's permission is granted
// (with the optional permission for `https` pages, every one is); without it,
// the frame is marked `unchecked` and the fill refuses it (`frame_unchecked`).
//
// The items: the core host opens the vault's items in batches, asks the core
// which of them match each chosen frame and closes every handle again. What
// comes back is, per item, its id, name and user name and the frames it may be
// filled in (those that tie on its closest match, the top first, at most 4). A
// handle never leaves the core host, and there is no reference here: the fill
// flow (fillFlow.mjs) makes the popup's references from this answer.

import { narrowOrigin } from "../shared/origin.mjs";

/** The most frames of one tab that are looked at; the frames after them are offered nothing. */
export const MAX_FRAMES = 32;
/** The most items one list holds (the best ones). */
export const MAX_CANDIDATES = 100;
/** The longest address that is looked at (the core refuses a longer one anyway). */
const MAX_URL = 8192;
const ITEM_ID = /^[0-9a-f]{32}$/;

// The loopback origins as the core writes them: lower case, IPv4 in dotted form, IPv6 in brackets, the port only
// when it is not 80. Not a rule about names: `localhost` and the loopback addresses only.
const LOOPBACK = /^http:\/\/(?:localhost|127(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}|\[::1\])(?::\d{1,5})?$/;

/**
 * @typedef {{ frameId: number, documentId?: string }} FrameRef one frame's document, as the browser names it
 * @typedef {{ frameId: number, documentId?: string, url: string, origin: string, ancestors: FrameRef[], unchecked?: true }} FillableFrame
 *   `ancestors`: the frames above it, its parent first and the top last (none for the top); `unchecked`: a frame
 *   above it (not the top) has another origin than the top and no host permission, so the fill cannot ask that
 *   document whether the frame is shown, and refuses the frame (`frame_unchecked`)
 * @typedef {{
 *   page_origin(url: string): Promise<string>,
 *   same_site(a: string, b: string): Promise<boolean>,
 * }} FrameCore the core's answers: `page_origin` rejects for an address that has no origin
 * @typedef {{
 *   getAllFrames(details: { tabId: number }): Promise<Array<{
 *     frameId: number, parentFrameId: number, url: string, documentId?: string, errorOccurred?: boolean,
 *   }> | null | undefined>,
 * }} WebNavigation
 * @typedef {{ a_label: string, unicode: string }} Host
 * @typedef {{
 *   itemId: string,
 *   name: string,
 *   username: string | null,
 *   how: "host" | "domain" | "exact",
 *   frames: FillableFrame[],
 * }} Candidate `frames`: where the item may be filled, the top first (at most 4)
 * @typedef {{ origin: string, host: Host }} GrantNeeded a frame of the same site that waits for its host permission
 * @typedef {{
 *   host: Host | null,
 *   insecure: boolean,
 *   items: Candidate[],
 *   grant: GrantNeeded[],
 * }} CandidateList `host` is null when the tab shows no web page (then everything else is empty)
 * @typedef {{
 *   candidates(tabId: number, options?: { frameId?: number }): Promise<CandidateList>,
 * }} CandidateSource what the fill flow, the shortcut and the menu use
 * @typedef {{ call(op: string, args?: unknown): Promise<unknown> }} CoreHostCall
 */

/** @param {unknown} n @returns {n is number} */
const isIndex = (n) => typeof n === "number" && Number.isSafeInteger(n) && n >= 0;

/**
 * True when an origin of the core is secure: `https`, or `http` on `localhost`
 * or a loopback address (section 10.4: loopback counts as secure).
 * @param {unknown} origin
 * @returns {boolean}
 */
export function isSecureOrigin(origin) {
  if (typeof origin !== "string") return false;
  return origin.startsWith("https://") || LOOPBACK.test(origin);
}

/**
 * The origin the core gives an address, or null when it has none (an opaque or
 * non-web address, one the parser refuses).
 * @param {FrameCore} core @param {string} url
 * @returns {Promise<string | null>}
 */
async function originOf(core, url) {
  try {
    const origin = await core.page_origin(url);
    return typeof origin === "string" && origin !== "" && origin !== "null" && origin.length <= 300 ? origin : null;
  } catch {
    return null;
  }
}

/** @param {any} f */
function wellFormed(f) {
  return (
    typeof f === "object" &&
    f !== null &&
    isIndex(f.frameId) &&
    Number.isSafeInteger(f.parentFrameId) &&
    f.parentFrameId >= -1 &&
    typeof f.url === "string" &&
    f.url !== "" &&
    f.url.length <= MAX_URL
  );
}

/**
 * The frames of a tab that may be offered items: the top first, then the
 * frames below it that pass every rule above, in the browser's order.
 *
 * @param {number} tabId
 * @param {{ webNavigation: WebNavigation, core: FrameCore }} deps
 * @returns {Promise<FillableFrame[]>}
 */
export async function fillableFrames(tabId, { webNavigation, core }) {
  if (!isIndex(tabId)) return [];
  /** @type {unknown} */
  let listed;
  try {
    listed = await webNavigation.getAllFrames({ tabId });
  } catch {
    return [];
  }
  if (!Array.isArray(listed)) return [];
  /** @type {Map<number, any>} */
  const byId = new Map();
  for (const frame of listed) {
    // A frame the browser lists twice is not a frame anyone can trust: none of the tab is offered.
    if (wellFormed(frame) && byId.has(frame.frameId)) return [];
    if (wellFormed(frame)) byId.set(frame.frameId, frame);
  }
  const top = byId.get(0);
  if (top === undefined || top.parentFrameId !== -1 || top.errorOccurred === true) return [];
  const topOrigin = await originOf(core, top.url);
  if (topOrigin === null) return [];
  const topSecure = isSecureOrigin(topOrigin);

  /** @param {any} frame @returns {FrameRef} */
  const refOf = (frame) => ({
    frameId: frame.frameId,
    ...(typeof frame.documentId === "string" && frame.documentId !== "" && frame.documentId.length <= 64 ? { documentId: frame.documentId } : {}),
  });
  /**
   * The frames above `frame`, its parent first, up to the top (a frame is offered only when that chain is whole).
   * @param {any} frame @returns {FrameRef[]}
   */
  const ancestorsOf = (frame) => {
    /** @type {FrameRef[]} */
    const out = [];
    for (let up = frame.frameId === 0 ? undefined : byId.get(frame.parentFrameId); up !== undefined && out.length < byId.size; up = up.frameId === 0 ? undefined : byId.get(up.parentFrameId)) {
      out.push(refOf(up));
    }
    return out;
  };
  /** @param {any} frame @param {string} origin @returns {FillableFrame} */
  const entry = (frame, origin) => ({ ...refOf(frame), url: frame.url, origin, ancestors: ancestorsOf(frame) });

  /** The verdict of each frame looked at: its origin when it may be offered items, else null. @type {Map<number, string | null>} */
  const verdicts = new Map([[0, topOrigin]]);
  /**
   * @param {any} frame
   * @param {Set<number>} seen the frames on the way down (a cycle refuses)
   * @returns {Promise<string | null>}
   */
  const judge = async (frame, seen) => {
    if (verdicts.has(frame.frameId)) return /** @type {string | null} */ (verdicts.get(frame.frameId));
    let verdict = null;
    if (!seen.has(frame.frameId) && frame.errorOccurred !== true && frame.parentFrameId >= 0) {
      seen.add(frame.frameId);
      const parent = byId.get(frame.parentFrameId);
      // Every frame above must be offerable too (and the top secure), so the whole chain is secure and same-site.
      const parentOk = parent === undefined ? false : parent.frameId === 0 ? topSecure : (await judge(parent, seen)) !== null;
      if (parentOk) {
        const origin = await originOf(core, frame.url);
        if (origin !== null && isSecureOrigin(origin) && (await core.same_site(origin, topOrigin)) === true) verdict = origin;
      }
    }
    verdicts.set(frame.frameId, verdict);
    return verdict;
  };

  /** @type {FillableFrame[]} */
  const out = [entry(top, topOrigin)];
  for (const frame of byId.values()) {
    if (frame.frameId === 0) continue;
    if (out.length >= MAX_FRAMES) break;
    const origin = await judge(frame, new Set());
    if (origin !== null) out.push(entry(frame, origin));
  }
  return out;
}

/**
 * The final word on a frame after the fill script has reported from it: the
 * origin the browser gave, narrowed by the script's own `self.origin`. A
 * sandboxed frame reports "null" and is refused, and so is a frame whose origin
 * changed. The report never adds anything the browser did not say.
 *
 * @param {{ origin: string }} frame the frame as the browser gave it (only its origin is read)
 * @param {unknown} selfOrigin `frame_report.self_origin`
 * @returns {boolean}
 */
export function confirmFrame(frame, selfOrigin) {
  if (typeof frame?.origin !== "string" || typeof selfOrigin !== "string") return false;
  return narrowOrigin(frame.origin, selfOrigin) !== null;
}

/**
 * The page that asks for a frame's host permission.
 * @param {(path: string) => string} getURL `runtime.getURL`
 * @param {string} origin
 */
export function grantUrl(getURL, origin) {
  return `${getURL("pages/grant.html")}?${new URLSearchParams({ origin }).toString()}`;
}

/**
 * The host permission pattern of an `https` origin, from the host the core
 * gives (a pattern has no port, so it covers the host on every port).
 * @param {Host} host
 */
export function permissionPattern(host) {
  return `https://${host.a_label}/*`;
}

/** @param {CoreHostCall} coreHost @param {string} url @returns {Promise<Host>} */
async function displayHost(coreHost, url) {
  const shown = /** @type {any} */ (await coreHost.call("display_host", { url }));
  const aLabel = typeof shown?.a_label === "string" ? shown.a_label : "";
  const unicode = typeof shown?.unicode === "string" ? shown.unicode : "";
  if (aLabel === "" || unicode === "" || aLabel.length > 300 || unicode.length > 300) throw Object.assign(new Error("internal"), { code: "internal" });
  return { a_label: aLabel, unicode };
}

/**
 * The items a tab is offered. The host shown is the core's `display_host` of
 * the top's address (never the tab's title); `insecure` says the top is plain
 * `http` (not loopback), where the core offers only `http` items. A frame of
 * another origin than the top whose host permission is missing is matched too
 * (matching needs no permission), but offered nothing: it is listed in `grant`
 * when some item matches it, and only then.
 *
 * @param {number} tabId
 * @param {{
 *   coreHost: CoreHostCall,
 *   frames: (tabId: number) => Promise<FillableFrame[]>,
 *   permissions?: { contains(p: { origins: string[] }): Promise<boolean> },
 *   frameId?: number,
 * }} deps `frames` is `fillableFrames` with its browser and core; `frameId` keeps only that frame (the menu's frame)
 * @returns {Promise<CandidateList>}
 */
export async function candidates(tabId, { coreHost, frames, permissions, frameId }) {
  const all = await frames(tabId);
  const top = all.find((f) => f.frameId === 0);
  if (top === undefined) return { host: null, insecure: false, items: [], grant: [] };
  const host = await displayHost(coreHost, top.url);
  const insecure = !isSecureOrigin(top.origin);
  const chosen = frameId === undefined ? all : all.filter((f) => f.frameId === frameId);

  /** The chosen frames in the browser's order, each either usable now or waiting for its permission. */
  /** @type {Array<FillableFrame & { waiting: boolean }>} */
  const asked = [];
  /** @type {Map<string, boolean>} origin -> whether its permission is granted */
  const permitted = new Map();
  /** Whether the host permission of a frame's origin is granted (asked once per origin). @param {FillableFrame} frame */
  const permittedFor = async (frame) => {
    // Only an `https` origin can be granted (the optional permission is `https://*/*`).
    if (!frame.origin.startsWith("https://")) return false;
    if (!permitted.has(frame.origin)) {
      const frameHost = await displayHost(coreHost, frame.url);
      let granted = false;
      try {
        granted = (await permissions?.contains({ origins: [permissionPattern(frameHost)] })) === true;
      } catch {
        granted = false;
      }
      permitted.set(frame.origin, granted);
    }
    return permitted.get(frame.origin) === true;
  };
  for (const frame of chosen) {
    if (frame.origin === top.origin) {
      asked.push({ ...frame, waiting: false });
      continue;
    }
    if (!frame.origin.startsWith("https://")) continue;
    asked.push({ ...frame, waiting: !(await permittedFor(frame)) });
  }
  if (asked.length === 0) return { host, insecure, items: [], grant: [] };

  const reply = /** @type {any} */ (
    await coreHost.call("candidates_match", {
      frames: asked.map((f) => ({
        frame_id: f.frameId,
        ...(f.documentId !== undefined ? { document_id: f.documentId } : {}),
        url: f.url,
        origin: f.origin,
        ...(f.waiting ? { waiting: true } : {}),
      })),
    })
  );
  // A frame whose middle frames (the ones above it, the top left out) have another origin than the top can be checked
  // only with the permission of each such origin.
  const byId = new Map(all.map((f) => [f.frameId, f]));
  /** @param {FillableFrame} frame @returns {Promise<boolean>} */
  const checkable = async (frame) => {
    for (const above of frame.ancestors) {
      if (above.frameId === 0) continue;
      const middle = byId.get(above.frameId);
      if (middle === undefined) return false;
      if (middle.origin === top.origin) continue;
      if (!(await permittedFor(middle))) return false;
    }
    return true;
  };
  /** The frames an item may be filled in, by id: only frames that were asked for and do not wait for a permission. */
  const usable = new Map();
  for (const f of asked) {
    if (f.waiting) continue;
    const unchecked = !(await checkable(f));
    usable.set(
      f.frameId,
      /** @type {FillableFrame} */ ({ frameId: f.frameId, ...(f.documentId !== undefined ? { documentId: f.documentId } : {}), url: f.url, origin: f.origin, ancestors: f.ancestors, ...(unchecked ? { unchecked: true } : {}) }),
    );
  }
  /** @type {Candidate[]} */
  const items = [];
  for (const item of Array.isArray(reply?.items) ? reply.items : []) {
    if (items.length >= MAX_CANDIDATES) break;
    if (
      typeof item?.item_id !== "string" ||
      !ITEM_ID.test(item.item_id) ||
      typeof item.name !== "string" ||
      !(item.username === null || typeof item.username === "string") ||
      !["host", "domain", "exact"].includes(item.how) ||
      !Array.isArray(item.frame_ids)
    ) {
      continue;
    }
    /** @type {FillableFrame[]} */
    const where = [];
    for (const id of item.frame_ids) {
      const frame = usable.get(id);
      if (frame !== undefined && !where.includes(frame)) where.push(frame);
    }
    if (where.length === 0) continue;
    items.push({ itemId: item.item_id, name: item.name, username: item.username, how: item.how, frames: where.slice(0, 4) });
  }

  // The frames waiting for their permission that some item matches, one entry per origin.
  const matchedWaiting = new Set(Array.isArray(reply?.grant_frames) ? reply.grant_frames : []);
  /** @type {GrantNeeded[]} */
  const grant = [];
  for (const frame of asked) {
    if (!frame.waiting || !matchedWaiting.has(frame.frameId) || grant.some((g) => g.origin === frame.origin)) continue;
    grant.push({ origin: frame.origin, host: await displayHost(coreHost, frame.url) });
  }
  return { host, insecure, items, grant };
}

/**
 * The page matching as one object, for the fill flow: the frames from the
 * browser (`webNavigation`), the site rules and the match from the core (over
 * the core host's operations), and the host permissions the browser holds.
 *
 * @param {{
 *   webNavigation: WebNavigation,
 *   permissions?: { contains(p: { origins: string[] }): Promise<boolean> },
 *   call: CoreHostCall["call"],
 * }} deps
 * @returns {CandidateSource}
 */
export function createCandidateSource({ webNavigation, permissions, call }) {
  /** @type {FrameCore} */
  const core = {
    page_origin: async (url) => /** @type {any} */ (await call("page_origin", { url })).origin,
    same_site: async (a, b) => /** @type {any} */ (await call("same_site", { a, b })).same === true,
  };
  return {
    candidates: (tabId, { frameId } = {}) =>
      candidates(tabId, {
        coreHost: { call },
        frames: (id) => fillableFrames(id, { webNavigation, core }),
        ...(permissions ? { permissions } : {}),
        ...(frameId !== undefined ? { frameId } : {}),
      }),
  };
}
