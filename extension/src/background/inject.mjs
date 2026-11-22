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
// The same two calls ask the documents above a frame whether that frame is
// shown in them (`frameChainShown`), before a value goes into it.

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

/** What the engine of a parent document can say about a frame of it (content/fill.mjs `frameShown`). */
const FRAME_VERDICTS = new Set(["shown", "gone", "hidden", "covered"]);

/**
 * Asks the fill script of one document whether the element that holds the
 * frame `childFrameId` is shown there (the field checks, in that document's
 * own coordinates). The question is the extension's own call into that
 * document, and the answer is its result: no message a page or a frame could
 * send counts. Any failure (no permission, the document is gone, the script did
 * not load) is "unchecked".
 *
 * @param {{
 *   scripting: { executeScript: (injection: any) => Promise<Array<{ frameId?: number, result?: unknown, error?: unknown }>> },
 *   tabId: number,
 *   parent: { frameId: number, documentId?: string },
 *   childFrameId: number,
 * }} request
 * @returns {Promise<"shown" | "gone" | "hidden" | "covered" | "unchecked">}
 */
export async function frameShownIn({ scripting, tabId, parent, childFrameId }) {
  if (!isIndex(tabId) || !isIndex(parent?.frameId) || !isIndex(childFrameId) || childFrameId === parent.frameId) return "unchecked";
  const target = typeof parent.documentId === "string" && parent.documentId !== ""
    ? { tabId, documentIds: [parent.documentId] }
    : { tabId, frameIds: [parent.frameId] };
  try {
    const loaded = await scripting.executeScript({ target, files: [ENTRY] });
    if (!Array.isArray(loaded) || loaded.length !== 1 || loaded[0]?.error !== undefined) return "unchecked";
    const results = await scripting.executeScript({
      target,
      func: (/** @type {number} */ id) => {
        const api = /** @type {any} */ (globalThis).__ferretFill;
        return api !== undefined && typeof api.frameShown === "function" ? api.frameShown(id) : "unchecked";
      },
      args: [childFrameId],
    });
    if (!Array.isArray(results) || results.length !== 1 || results[0]?.error !== undefined) return "unchecked";
    const verdict = results[0]?.result;
    return typeof verdict === "string" && FRAME_VERDICTS.has(verdict) ? /** @type {any} */ (verdict) : "unchecked";
  } catch {
    return "unchecked";
  }
}

/**
 * Whether a frame is shown in every document above it, up to the top: in the
 * frame's parent, the element that holds the frame must be shown; in the
 * grandparent, the element that holds the parent; and so on. The top frame
 * (0) has nothing above it. `ancestors` is the chain from the browser
 * (`webNavigation`), parent first, the top last; a chain that does not end at
 * the top is refused. Resolves to null when the frame is shown everywhere,
 * else to the refusal `frame_hidden` (also when a document could not be
 * asked).
 *
 * @param {{
 *   scripting: { executeScript: (injection: any) => Promise<Array<{ frameId?: number, result?: unknown, error?: unknown }>> },
 *   tabId: number,
 *   frame: { frameId: number, ancestors?: Array<{ frameId: number, documentId?: string }> },
 * }} request
 * @returns {Promise<null | "frame_hidden">}
 */
export async function frameChainShown({ scripting, tabId, frame }) {
  if (frame?.frameId === 0) return null;
  const chain = Array.isArray(frame?.ancestors) ? frame.ancestors : [];
  if (!isIndex(frame?.frameId) || chain.length === 0 || chain.at(-1)?.frameId !== 0) return "frame_hidden";
  let child = frame.frameId;
  for (const parent of chain) {
    if ((await frameShownIn({ scripting, tabId, parent, childFrameId: child })) !== "shown") return "frame_hidden";
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
