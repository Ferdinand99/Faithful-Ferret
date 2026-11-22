// Puts the fill script into one frame of one tab, for a pending action in the
// extension's own UI. Nothing else: which frame, which request and what is
// filled are decided elsewhere. There is no fixed content script in the
// manifest, so no page gets this code unless the user acted on it, and the
// permission for it is `activeTab` (granted by the toolbar popup, the shortcut
// or the menu item) together with `scripting`.
//
// Two calls, in this order, to the same target: the file (the engine, which
// starts once and waits for messages) and then a function that asks the engine
// to begin the request and report the fields. The function is serialised by the
// browser, so it cannot name anything outside itself.
//
// Before a value goes into a frame below the top, the frame's fill script says
// where the field is, and the same two calls ask every document above the frame
// whether the field is shown there too (`frameChainShown`).

const REQUEST_ID = /^[A-Za-z0-9_-]{1,64}$/;
// The script the build writes from content/entry.mjs and what it imports (scripts/lib/classic.mjs).
// The leading slash makes it the extension's root in MV2 as well, where a relative path is
// read from the background page's folder.
const ENTRY = "/content/fill.inject.js";

/** @param {unknown} n @returns {n is number} */
const isIndex = (n) => typeof n === "number" && Number.isSafeInteger(n) && n >= 0;

/**
 * @param {{
 *   scripting: { executeScript: (injection: any) => Promise<Array<{ frameId?: number, result?: unknown, error?: unknown }>> },
 *   tabId: number,
 *   frameId: number,
 *   documentId?: string,
 *   requestId: string,
 * }} request `documentId`, when the browser gives one, pins both calls to that exact document
 * @returns {Promise<void>} resolves when the engine has begun the request
 */
export async function injectFill({ scripting, tabId, frameId, documentId, requestId }) {
  if (!isIndex(tabId) || !isIndex(frameId)) throw new TypeError("inject: bad target");
  if (typeof requestId !== "string" || !REQUEST_ID.test(requestId)) throw new TypeError("inject: bad request id");
  const target = typeof documentId === "string" && documentId !== ""
    ? { tabId, documentIds: [documentId] }
    : { tabId, frameIds: [frameId] };
  const loaded = await scripting.executeScript({ target, files: [ENTRY] });
  // A script that failed to load or threw is reported in the result, not as a rejection.
  if (!Array.isArray(loaded) || loaded.length !== 1 || loaded[0]?.error !== undefined) throw new Error("inject: the script did not load");
  const results = await scripting.executeScript({
    target,
    func: (/** @type {string} */ id) => {
      const api = /** @type {any} */ (globalThis).__ferretFill;
      return api !== undefined && api.begin(id) === true;
    },
    args: [requestId],
  });
  if (!Array.isArray(results) || results.length !== 1 || results[0]?.result !== true) {
    throw new Error("inject: the engine did not begin");
  }
}

/**
 * Aims the fill script of one frame at the field of a context menu click
 * (`menus.getTargetElement` in that frame), so the next request of that frame
 * fills the clicked field's group and nothing else. The same two calls as
 * `injectFill`: the file (the engine starts once), then a function that hands
 * the engine the click's `targetElementId`.
 *
 * @param {{
 *   scripting: { executeScript: (injection: any) => Promise<Array<{ frameId?: number, result?: unknown, error?: unknown }>> },
 *   tabId: number,
 *   frameId: number,
 *   documentId?: string,
 *   targetElementId: number,
 * }} request
 * @returns {Promise<void>} resolves when the engine holds the clicked field
 */
export async function aimFill({ scripting, tabId, frameId, documentId, targetElementId }) {
  if (!isIndex(tabId) || !isIndex(frameId)) throw new TypeError("inject: bad target");
  if (typeof targetElementId !== "number" || !Number.isSafeInteger(targetElementId)) throw new TypeError("inject: bad element id");
  const target = typeof documentId === "string" && documentId !== ""
    ? { tabId, documentIds: [documentId] }
    : { tabId, frameIds: [frameId] };
  const loaded = await scripting.executeScript({ target, files: [ENTRY] });
  if (!Array.isArray(loaded) || loaded.length !== 1 || loaded[0]?.error !== undefined) throw new Error("inject: the script did not load");
  const results = await scripting.executeScript({
    target,
    func: (/** @type {number} */ id) => {
      const api = /** @type {any} */ (globalThis).__ferretFill;
      return api !== undefined && typeof api.aim === "function" && api.aim(id) === true;
    },
    args: [targetElementId],
  });
  if (!Array.isArray(results) || results.length !== 1 || results[0]?.result !== true) {
    throw new Error("inject: the engine found no clicked field");
  }
}

/** The most points of a field that are checked in the documents above its frame (content/fill.mjs). */
const MAX_POINTS = 5;
/** What the fill script of a frame can say against a field of its own (content/fill.mjs `where`). */
const FIELD_PROBLEMS = new Set(["gone", "hidden", "covered", "wrong_kind"]);

/**
 * Whether `points` is a list of 1 to MAX_POINTS points [x, y] of finite numbers.
 * @param {unknown} points
 * @returns {points is Array<[number, number]>}
 */
function validPoints(points) {
  return (
    Array.isArray(points) &&
    points.length >= 1 &&
    points.length <= MAX_POINTS &&
    points.every((p) => Array.isArray(p) && p.length === 2 && p.every((v) => typeof v === "number" && Number.isFinite(v) && Math.abs(v) <= 1e7))
  );
}

/**
 * @typedef {{ executeScript: (injection: any) => Promise<Array<{ frameId?: number, result?: unknown, error?: unknown }>> }} Scripting
 * @typedef {{ frameId: number, documentId?: string }} FrameRef
 */

/** @param {number} tabId @param {FrameRef} frame */
const targetOf = (tabId, frame) =>
  typeof frame.documentId === "string" && frame.documentId !== "" ? { tabId, documentIds: [frame.documentId] } : { tabId, frameIds: [frame.frameId] };

/**
 * The one result of a call into one document, or undefined when the call failed or gave anything else.
 * @param {Scripting} scripting @param {any} injection
 */
async function resultOf(scripting, injection) {
  const results = await scripting.executeScript(injection);
  if (!Array.isArray(results) || results.length !== 1 || results[0]?.error !== undefined) return undefined;
  return results[0]?.result;
}

/**
 * Asks the fill script of a frame where the field of `kind` of its pending
 * request is: its sample points in the frame's own viewport, after the field
 * checks of the fill script. The engine is in the frame already (it reported).
 * Any failure is the problem "gone".
 *
 * @param {{ scripting: Scripting, tabId: number, frame: FrameRef, requestId: string, kind: string }} request
 * @returns {Promise<{ points: Array<[number, number]> } | { problem: string }>}
 */
export async function fieldPointsIn({ scripting, tabId, frame, requestId, kind }) {
  if (!isIndex(tabId) || !isIndex(frame?.frameId) || typeof requestId !== "string" || !REQUEST_ID.test(requestId) || typeof kind !== "string") {
    return { problem: "gone" };
  }
  try {
    const answer = /** @type {any} */ (
      await resultOf(scripting, {
        target: targetOf(tabId, frame),
        func: (/** @type {string} */ id, /** @type {string} */ wanted) => {
          const api = /** @type {any} */ (globalThis).__ferretFill;
          return api !== undefined && typeof api.where === "function" ? api.where(id, wanted) : null;
        },
        args: [requestId, kind],
      })
    );
    if (validPoints(answer?.points)) return { points: answer.points };
    return { problem: typeof answer?.problem === "string" && FIELD_PROBLEMS.has(answer.problem) ? answer.problem : "gone" };
  } catch {
    return { problem: "gone" };
  }
}

/**
 * Asks the fill script of one document whether a field of its frame
 * `childFrameId`, at `points` in that frame's viewport, is shown there: the
 * element that holds the frame passes the ancestor chain and the size rule,
 * and each point, moved into this document, is in its viewport and reaches
 * the holder. The question is the extension's own call into that document,
 * and the answer is its result: no message a page or a frame could send
 * counts. Any failure (no permission, the document is gone, the script did
 * not load, an answer of another shape) is "unchecked".
 *
 * @param {{ scripting: Scripting, tabId: number, parent: FrameRef, childFrameId: number, points: Array<[number, number]> }} request
 * @returns {Promise<{ verdict: "shown", points: Array<[number, number]> } | { verdict: "gone" | "hidden" | "covered" | "unchecked" }>}
 */
export async function frameShownIn({ scripting, tabId, parent, childFrameId, points }) {
  if (!isIndex(tabId) || !isIndex(parent?.frameId) || !isIndex(childFrameId) || childFrameId === parent.frameId || !validPoints(points)) {
    return { verdict: "unchecked" };
  }
  const target = targetOf(tabId, parent);
  try {
    const loaded = await scripting.executeScript({ target, files: [ENTRY] });
    if (!Array.isArray(loaded) || loaded.length !== 1 || loaded[0]?.error !== undefined) return { verdict: "unchecked" };
    const answer = /** @type {any} */ (
      await resultOf(scripting, {
        target,
        func: (/** @type {number} */ id, /** @type {Array<[number, number]>} */ at) => {
          const api = /** @type {any} */ (globalThis).__ferretFill;
          return api !== undefined && typeof api.frameShown === "function" ? api.frameShown(id, at) : null;
        },
        args: [childFrameId, points],
      })
    );
    const verdict = answer?.verdict;
    if (verdict === "shown") {
      return validPoints(answer.points) && answer.points.length === points.length ? { verdict, points: answer.points } : { verdict: "unchecked" };
    }
    return verdict === "gone" || verdict === "hidden" || verdict === "covered" ? { verdict } : { verdict: "unchecked" };
  } catch {
    return { verdict: "unchecked" };
  }
}

/**
 * Whether the field of `kind` of the pending request `requestId` in a frame is
 * shown on the page: the frame's own fill script gives the field's points
 * (after its field checks), and every document above the frame, from its
 * parent up to the top, must show the field at those points, each moved into
 * its own coordinates on the way up. The top frame (0) has nothing above it.
 * `ancestors` is the chain from the browser (`webNavigation`), parent first,
 * the top last; a chain that does not end at the top is refused. Resolves to
 * null when the field is shown everywhere; to the frame's own problem with the
 * field when it has one; else to the refusal `frame_hidden` (also when a
 * document could not be asked).
 *
 * @param {{
 *   scripting: Scripting,
 *   tabId: number,
 *   frame: { frameId: number, documentId?: string, ancestors?: FrameRef[] },
 *   requestId: string,
 *   kind: string,
 * }} request
 * @returns {Promise<null | string>}
 */
export async function frameChainShown({ scripting, tabId, frame, requestId, kind }) {
  if (frame?.frameId === 0) return null;
  const chain = Array.isArray(frame?.ancestors) ? frame.ancestors : [];
  if (!isIndex(frame?.frameId) || chain.length === 0 || chain.at(-1)?.frameId !== 0) return "frame_hidden";
  const field = await fieldPointsIn({ scripting, tabId, frame, requestId, kind });
  if ("problem" in field) return field.problem;
  let { points } = field;
  let child = frame.frameId;
  for (const parent of chain) {
    const answer = await frameShownIn({ scripting, tabId, parent, childFrameId: child, points });
    if (answer.verdict !== "shown" || !("points" in answer)) return "frame_hidden";
    points = answer.points;
    child = parent.frameId;
  }
  return null;
}

/**
 * Takes back an aim that no request used (the fill ended before it began): the
 * engine of that document, if it is there, forgets the clicked field. Nothing
 * is loaded into a document that has no engine.
 *
 * @param {{
 *   scripting: { executeScript: (injection: any) => Promise<unknown> },
 *   tabId: number,
 *   documentId: string,
 * }} request
 * @returns {Promise<void>}
 */
export async function disarmFill({ scripting, tabId, documentId }) {
  if (!isIndex(tabId) || typeof documentId !== "string" || documentId === "") throw new TypeError("inject: bad target");
  await scripting.executeScript({
    target: { tabId, documentIds: [documentId] },
    func: () => {
      const api = /** @type {any} */ (globalThis).__ferretFill;
      if (api !== undefined && typeof api.aim === "function") api.aim(null);
      return true;
    },
  });
}
