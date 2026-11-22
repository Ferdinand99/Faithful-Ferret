// The fill engine: it runs in the isolated world of a web page (a content
// script), finds the sign-in fields of one frame and fills exactly one value
// when the extension asks for it. Phishing and clickjacking safety is its whole
// point, so it is small, holds no key and no crypto code, and decides nothing
// about origins.
//
// What it does:
//
// 1. `begin(requestId)` runs when the extension injects the script for a
//    pending action in its own UI. The engine reports the fields it found
//    (`frame_report`): their kind and a random id made now, never a name or id
//    from the page. It reports `self.origin` too, so the extension can tell a
//    sandboxed frame (origin "null") from the browser's own answer. The origin
//    comes from the browser; this value can only narrow it.
// 2. `fill_field` carries one value for one field kind. The engine fills only
//    when the request id is the pending one, the frame still has the origin and
//    the address the extension expects, and the field passes every check below
//    at that moment. Then it sets the value with the native setter and fires
//    `input` and `change`. The answer is a `fill_result`.
//
// A field passes only when it is a visible, enabled, writable input that the
// user can see and nothing covers:
//
// - it is in the page, not `:disabled` (also through a disabled fieldset), not `readonly`, and neither it nor an
//   ancestor has `aria-hidden="true"` or is `inert`;
// - from the field up to the root of the document, through shadow roots and
//   slots, nothing has `opacity` below 1, a `visibility` other than `visible`,
//   `display: none`, or any `filter`, `transform` (also `translate`, `rotate`,
//   `scale` and `perspective`), `clip-path`, `mask` or `mix-blend-mode`;
// - it is at least MIN_SIDE pixels each way and mostly inside the viewport;
// - the topmost element at the centre and four more points of the field is the
//   field itself, asked of the document and of every shadow root on the way.
//
// Limit of the last check: it asks the browser what a click at those points
// would hit, so it does not see a cover that a click passes through or that
// paints outside its own box: an element with `pointer-events: none`, a
// `box-shadow` with a large spread, an `outline`, a `filter: drop-shadow()`
// or a `border-image-outset` that another element draws over the field. The
// design document (section on clickjacking) states this limit too, and a test
// pins it, so that a later change is deliberate.
//
// Which field: one request fills one group (see `scan`): the password field of
// a form, the user name before it and the one-time code in the same form, and
// never a field that sets a new password or a site search field. At the fill
// the field must still be in the form it had at the report and must not set a
// new password. A field id is only a handle for the report. A `fill_field` names the kind, and the engine fills the field of that
// kind in the group. The engine answers only to a message that the extension
// itself sent.
//
// The context menu (`aim`): a click on Ferret's menu item names one field
// (`menus.getTargetElement`). The extension aims the engine at it before the
// request begins, and that request fills the group of the clicked field
// instead of the first one of the page. The clicked field gets the value of its
// own kind, so a password goes into it only when it is a password input. An
// element that is no text or password input is refused at the aim. An input the
// engine would not fill (hidden, covered, one that sets a new password) gives
// an empty report: an aimed request never falls back to another field of the
// page. An aim is good for the next request only, and for AIM_MS at most;
// `aim(null)` takes it back.
//
// A frame (`where`, `frameShown`): the checks above see only the frame's own
// document. Before a value goes into a frame below the top, the extension asks
// the engine of that frame where the field is (its sample points, after the
// field checks), and then the engine of each document above it whether the
// field is shown there too: the element that holds the frame below (an
// `iframe`, `frame`, `object` or `embed`, found by the browser's own
// `runtime.getFrameId`) must pass the ancestor chain (and have no `zoom`) and
// the size rule, and each of the field's points, moved into that document by
// the holder's content box, must be in its viewport and reach the holder in
// the hit test. A page that covers or clips only the form inside a larger
// frame is caught that way. The answers go back as the results of the
// extension's own calls, never as messages a page or a frame could send.

import { PUSH_TYPES, decode, encode } from "../shared/protocol.mjs";

/** The smallest width and height, in CSS pixels, of a field the engine fills. */
export const MIN_SIDE = 8;
/** The share of a field that must lie inside the viewport. */
const MIN_VISIBLE_SHARE = 0.5;
/** Bounds that stop a hostile page from making the walks run long. */
const MAX_NODES = 20_000;
const MAX_DEPTH = 1_000;
/** The name under which the injected script offers `begin` and `aim` to the extension (not reachable by the page). */
export const FILL_GLOBAL = "__ferretFill";
/** How long an aim at a clicked field waits for its request, in milliseconds. */
export const AIM_MS = 3_000;

const REQUEST_ID = /^[A-Za-z0-9_-]{1,64}$/;
/** The elements that can hold a frame. */
const FRAME_HOLDERS = new Set(["iframe", "frame", "object", "embed"]);
/** The most points of a field that are checked in the documents above its frame. */
const MAX_POINTS = 5;

/**
 * Whether `points` is a list of 1 to MAX_POINTS points [x, y] of finite numbers.
 * @param {unknown} points
 */
function validPoints(points) {
  return (
    Array.isArray(points) &&
    points.length >= 1 &&
    points.length <= MAX_POINTS &&
    points.every((p) => Array.isArray(p) && p.length === 2 && p.every((v) => typeof v === "number" && Number.isFinite(v) && Math.abs(v) <= 1e7))
  );
}
const TEXT_TYPES = new Set(["text", "email", "tel", "number", "search", "url"]);
const USERNAME_TYPES = new Set(["text", "email", "tel"]);
const TOTP_HINT = /(?:^|[^a-z])(?:otp|totp|2fa|mfa|tfa)(?:[^a-z]|$)|one.?time|verification.?code|authenticator|auth.?code|two.?factor/;
const USERNAME_HINT = /user|login|e-?mail|account|identif|sign-?in/;

/** The values that mean "no effect" for the properties that would hide or move a field. */
const REQUIRED_DEFAULTS = Object.freeze([
  ["filter", "none"],
  ["transform", "none"],
  ["clip-path", "none"],
  ["mix-blend-mode", "normal"],
  ["mask-image", "none"],
]);
/** Properties that older engines may not know; an empty answer is no effect. */
const OPTIONAL_DEFAULTS = Object.freeze([
  ["-webkit-mask-image", "none"],
  ["mask-border-source", "none"],
  ["translate", "none"],
  ["rotate", "none"],
  ["scale", "none"],
  ["perspective", "none"],
  ["clip", "auto"],
]);

/**
 * @typedef {"username" | "password" | "totp"} Kind
 * @typedef {{ kind: Kind, id: string, element: any, form: any }} Field
 * @typedef {"origin_changed" | "hidden" | "covered" | "gone" | "wrong_kind"} Reason
 */

/** @param {any} node */
const isElement = (node) => typeof node === "object" && node !== null && node.nodeType === 1;

/**
 * The shadow root of an element, open or closed (Firefox lets a content script
 * see closed ones), or null.
 * @param {any} element
 */
function shadowOf(element) {
  return element.openOrClosedShadowRoot ?? element.shadowRoot ?? null;
}

const UNRENDERED = Symbol("unrendered");

/**
 * The parent of a node in the flat tree, which is the tree the page is drawn
 * from: a slotted node's parent is its slot, and a shadow root's parent is its
 * host. Null at the top. UNRENDERED for a child of a shadow host that has no
 * slot for it (the browser does not draw it).
 *
 * @param {any} node
 * @returns {any}
 */
function flatParent(node) {
  if (node.assignedSlot) return node.assignedSlot;
  const parent = node.parentElement;
  if (parent) {
    const root = shadowOf(parent);
    if (root) {
      const name = node.getAttribute("slot") ?? "";
      for (const slot of root.querySelectorAll("slot")) {
        if ((slot.getAttribute("name") ?? "") === name) return slot;
      }
      return UNRENDERED;
    }
    return parent;
  }
  const up = node.parentNode;
  if (up && up.host) return up.host;
  return null;
}

/**
 * @param {any} style a computed style
 * @param {string} name
 * @returns {string}
 */
function read(style, name) {
  const value = style.getPropertyValue(name);
  return typeof value === "string" ? value.trim().toLowerCase() : "";
}

/**
 * Why the styles of one element hide the field or move it, or null.
 * @param {any} style
 */
function styleProblem(style) {
  const opacity = Number.parseFloat(read(style, "opacity"));
  if (!(opacity >= 1)) return "opacity";
  if (read(style, "visibility") !== "visible") return "visibility";
  if (read(style, "display") === "none") return "display";
  for (const [name, normal] of REQUIRED_DEFAULTS) {
    if (read(style, name) !== normal) return name;
  }
  for (const [name, normal] of OPTIONAL_DEFAULTS) {
    const value = read(style, name);
    if (value !== "" && value !== normal) return name;
  }
  return null;
}

/**
 * A random handle: 16 bytes as hex. Never taken from the page.
 * @param {any} random an object with getRandomValues
 */
function newFieldId(random) {
  const bytes = new Uint8Array(16);
  random.getRandomValues(bytes);
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

/**
 * @param {any} element
 * @returns {string} lower-case text of the attributes that name a field's purpose
 */
function hintsOf(element) {
  const parts = ["name", "id", "aria-label", "placeholder"].map((a) => element.getAttribute(a) ?? "");
  return parts.join(" ").toLowerCase();
}

/** @param {any} element */
function autocompleteTokens(element) {
  return (element.getAttribute("autocomplete") ?? "").toLowerCase().split(/\s+/).filter(Boolean);
}

/**
 * Whether a text input is part of a site search rather than a sign-in: its
 * type is `search`, its role is `searchbox`, its name is `q`, or it lies in a
 * `<search>` element or an element (its form too) with `role="search"`. Such
 * a field never gets a user name or a code.
 * @param {any} element
 */
function isSearchField(element) {
  if (String(element.type ?? "").toLowerCase() === "search") return true;
  if ((element.getAttribute("role") ?? "").toLowerCase() === "searchbox") return true;
  if ((element.getAttribute("name") ?? "").toLowerCase() === "q") return true;
  const form = element.form;
  if (isElement(form) && (form.getAttribute("role") ?? "").toLowerCase() === "search") return true;
  for (let node = flatParent(element), depth = 0; node && node !== UNRENDERED && depth <= MAX_DEPTH; node = flatParent(node), depth += 1) {
    if (node.localName === "search" || (node.getAttribute("role") ?? "").toLowerCase() === "search") return true;
  }
  return false;
}

/**
 * @typedef {{ element: any, role: "password" | "totp" | "username" | "text", order: number }} Candidate
 */

/**
 * Whether `node` is `container` or lies inside it, in the flat tree.
 * @param {any} container
 * @param {any} node
 */
function isInside(container, node) {
  for (let n = node, depth = 0; n && n !== UNRENDERED && depth <= MAX_DEPTH; n = flatParent(n), depth += 1) {
    if (n === container) return true;
  }
  return false;
}

/**
 * The candidates that belong with the anchor: those of its form, or, without a
 * form, those without a form inside the nearest container of the anchor that
 * holds a candidate of another kind (the anchor alone when there is none).
 * When that container is the whole page (the body or the root element), an
 * unnamed text field there is no user name field: only fields named for one
 * (see `scan`) join the anchor, so a password-only step never sends the user
 * name into some other text field of the page.
 *
 * @param {Candidate} anchor
 * @param {Candidate[]} candidates
 * @param {any} document
 * @returns {Candidate[]}
 */
function groupOf(anchor, candidates, document) {
  const form = anchor.element.form;
  if (form) return candidates.filter((c) => c.element.form === form);
  const loose = candidates.filter((c) => !c.element.form);
  for (let node = flatParent(anchor.element), depth = 0; node && node !== UNRENDERED && depth <= MAX_DEPTH; node = flatParent(node), depth += 1) {
    const inside = loose.filter((c) => isInside(node, c.element));
    if (inside.some((c) => c.role !== anchor.role)) {
      const wholePage = node === document.body || node === document.documentElement;
      return wholePage ? inside.filter((c) => c === anchor || c.role !== "text") : inside;
    }
  }
  return [anchor];
}

/**
 * Makes the engine. Everything the engine touches comes in through `deps`, so a
 * test can run it on a fake page.
 *
 * @param {{
 *   window: any,
 *   document: any,
 *   send: (raw: string) => unknown,
 *   runtimeId: string,
 *   extensionBase: string,
 *   targetOf?: (targetElementId: number) => any,
 *   frameIdOf?: (element: any) => number,
 *   clock?: () => number,
 * }} deps `send` delivers a message to the extension; `runtimeId` and `extensionBase` (`moz-extension://<uuid>/`) say who may talk to the engine;
 *   `targetOf` is `menus.getTargetElement` (the element of a context menu click), `frameIdOf` is `runtime.getFrameId`
 *   (the frame id of the frame an element holds) and `clock` the time in milliseconds
 */
export function createFillEngine({ window, document, send, runtimeId, extensionBase, targetOf = () => null, frameIdOf = () => -1, clock = () => Date.now() }) {
  // The native setter. In Firefox the content script reads the page through
  // Xray wrappers, so this is the browser's own setter whatever the page has
  // replaced; taking it once here is only a second line of defence.
  const nativeSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value")?.set;
  const random = window.crypto;

  /** @type {{ requestId: string, fields: Field[] } | null} */
  let pending = null;
  /** The field of a context menu click, for the next request only. @type {{ element: any, until: number } | null} */
  let aimed = null;

  /**
   * Whether `element` may be filled, and if not, why. This is the whole list.
   * @param {any} element
   * @returns {"gone" | "hidden" | "covered" | null}
   */
  function inspect(element) {
    if (!isElement(element) || element.localName !== "input") return "gone";
    if (element.ownerDocument !== document || element.isConnected !== true) return "gone";
    // :disabled also covers an input inside a disabled fieldset.
    if (element.matches(":disabled") || element.readOnly === true) return "hidden";
    return shown(element);
  }

  /**
   * Why the ancestor chain of `element` hides it, or null: from the element up
   * to the root, through shadow roots and slots. `holder`: the element holds a
   * frame, so `zoom` is refused as well (a frame's points are mapped into this
   * document by translation only).
   * @param {any} element
   * @param {boolean} [holder]
   * @returns {"hidden" | null}
   */
  function chainProblem(element, holder = false) {
    /** @type {any} */
    let node = element;
    for (let depth = 0; node !== null; depth += 1) {
      if (depth > MAX_DEPTH || node === UNRENDERED) return "hidden";
      if (node.getAttribute("aria-hidden") === "true") return "hidden";
      if (node.inert === true || node.hasAttribute("inert")) return "hidden";
      const style = window.getComputedStyle(node);
      if (!style || styleProblem(style) !== null) return "hidden";
      if (holder) {
        const zoom = read(style, "zoom");
        if (zoom !== "" && zoom !== "1" && zoom !== "normal") return "hidden";
      }
      node = flatParent(node);
    }
    return null;
  }

  /** The size of this document's viewport. */
  const viewport = () => ({
    width: document.documentElement.clientWidth || window.innerWidth,
    height: document.documentElement.clientHeight || window.innerHeight,
  });

  /**
   * Whether a click at (x, y) reaches `element`: the document, then every
   * shadow root down to it, must each name the next level (or the element) as
   * the topmost element there. "gone" when the element is not in this document.
   * @param {any} element @param {number} x @param {number} y
   * @returns {"gone" | "hidden" | "covered" | null}
   */
  function hitProblem(element, x, y) {
    /** @type {any[]} */
    const roots = [];
    for (let root = element.getRootNode(); root; root = root.host ? root.host.getRootNode() : null) {
      roots.unshift(root);
      if (roots.length > MAX_DEPTH) return "hidden";
    }
    if (roots[0] !== document) return "gone";
    for (let i = 0; i < roots.length; i += 1) {
      const expected = i < roots.length - 1 ? roots[i + 1].host : element;
      const hits = roots[i].elementsFromPoint(x, y);
      if (!hits || hits[0] !== expected) return "covered";
    }
    return null;
  }

  /**
   * The sample points of a rectangle (the centre and four more) that lie in
   * the viewport: where the hit test asks, and what a frame's parent checks.
   * @param {{ left: number, top: number, width: number, height: number }} rect
   * @returns {Array<[number, number]>}
   */
  function samplePoints({ left, top, width, height }) {
    const view = viewport();
    /** @type {Array<[number, number]>} */
    const out = [];
    for (const [fx, fy] of [[0.5, 0.5], [0.25, 0.5], [0.75, 0.5], [0.5, 0.25], [0.5, 0.75]]) {
      const x = left + width * fx;
      const y = top + height * fy;
      if (x >= 0 && y >= 0 && x < view.width && y < view.height) out.push([x, y]);
    }
    return out;
  }

  /**
   * Whether the user sees the field `element` in this document, and if not,
   * why: the ancestor chain, the size, the viewport and the hit test.
   * Everything but what only an input has.
   * @param {any} element
   * @returns {"gone" | "hidden" | "covered" | null}
   */
  function shown(element) {
    if (!isElement(element) || element.ownerDocument !== document || element.isConnected !== true) return "gone";
    if (chainProblem(element) !== null) return "hidden";

    const rect = element.getBoundingClientRect();
    const { left, top, width, height } = rect;
    if (![left, top, width, height].every(Number.isFinite)) return "hidden";
    if (width < MIN_SIDE || height < MIN_SIDE) return "hidden";
    const view = viewport();
    const shownWidth = Math.min(left + width, view.width) - Math.max(left, 0);
    const shownHeight = Math.min(top + height, view.height) - Math.max(top, 0);
    if (!(shownWidth > 0) || !(shownHeight > 0)) return "hidden";
    if ((shownWidth * shownHeight) / (width * height) < MIN_VISIBLE_SHARE) return "hidden";
    const cx = left + width / 2;
    const cy = top + height / 2;
    if (!(cx >= 0 && cy >= 0 && cx < view.width && cy < view.height)) return "hidden";

    for (const [x, y] of samplePoints(rect)) {
      const problem = hitProblem(element, x, y);
      if (problem !== null) return problem;
    }
    return null;
  }

  /**
   * Every element of the frame whose local name `wanted` accepts, in document
   * order, through shadow roots.
   * @param {(name: string) => boolean} wanted
   * @returns {any[]}
   */
  function allElements(wanted) {
    /** @type {any[]} */
    const out = [];
    let seen = 0;
    /** @param {any} root */
    const visit = (root) => {
      for (const node of root.querySelectorAll("*")) {
        seen += 1;
        if (seen > MAX_NODES) return;
        if (wanted(node.localName)) out.push(node);
        const inner = shadowOf(node);
        if (inner) visit(inner);
      }
    };
    visit(document);
    return out;
  }

  /** Every input of the frame in document order, through shadow roots. */
  const allInputs = () => allElements((name) => name === "input");

  /**
   * Whether a field of the frame `frameId` (a frame of this document) is shown
   * here: the one element that holds the frame (the browser names the frame
   * each element holds) must pass the ancestor chain (and have no `zoom`) and
   * be at least MIN_SIDE pixels each way, and each of the field's points, given
   * in the frame's own viewport and moved into this document by the holder's
   * content box, must be inside this viewport and reach the holder in the hit
   * test. The answer carries the moved points, for the document above this
   * one. "gone" when no element, or more than one, holds the frame.
   * @param {unknown} frameId
   * @param {unknown} points
   * @returns {{ verdict: "shown", points: Array<[number, number]> } | { verdict: "gone" | "hidden" | "covered" }}
   */
  function frameShown(frameId, points) {
    if (typeof frameId !== "number" || !Number.isSafeInteger(frameId) || frameId <= 0) return { verdict: "gone" };
    if (!validPoints(points)) return { verdict: "hidden" };
    const holders = allElements((name) => FRAME_HOLDERS.has(name)).filter((element) => {
      try {
        return frameIdOf(element) === frameId;
      } catch {
        // An element that holds no frame (an object showing an image, say).
        return false;
      }
    });
    if (holders.length !== 1) return { verdict: "gone" };
    const [holder] = holders;
    if (!isElement(holder) || holder.ownerDocument !== document || holder.isConnected !== true) return { verdict: "gone" };
    if (chainProblem(holder, true) !== null) return { verdict: "hidden" };
    const rect = holder.getBoundingClientRect();
    if (![rect.left, rect.top, rect.width, rect.height].every(Number.isFinite)) return { verdict: "hidden" };
    if (rect.width < MIN_SIDE || rect.height < MIN_SIDE) return { verdict: "hidden" };
    // The frame's viewport starts at the holder's content box: inside its border and its padding.
    const style = window.getComputedStyle(holder);
    const px = (/** @type {string} */ name) => {
      const value = Number.parseFloat(read(style, name));
      return Number.isFinite(value) ? value : 0;
    };
    const originX = rect.left + (Number.isFinite(holder.clientLeft) ? holder.clientLeft : 0) + px("padding-left");
    const originY = rect.top + (Number.isFinite(holder.clientTop) ? holder.clientTop : 0) + px("padding-top");
    const view = viewport();
    /** @type {Array<[number, number]>} */
    const moved = [];
    for (const [x, y] of /** @type {Array<[number, number]>} */ (points)) {
      const ax = originX + x;
      const ay = originY + y;
      if (!(ax >= 0 && ay >= 0 && ax < view.width && ay < view.height)) return { verdict: "hidden" };
      const problem = hitProblem(holder, ax, ay);
      if (problem === "gone") return { verdict: "gone" };
      if (problem !== null) return { verdict: problem };
      moved.push([ax, ay]);
    }
    return { verdict: "shown", points: moved };
  }

  /**
   * Where the field of `kind` of the pending request `requestId` is: its
   * sample points in this frame's viewport, when it passes every check now,
   * else why not. For the documents above this frame (see `frameShown`).
   * @param {unknown} requestId
   * @param {unknown} kind
   * @returns {{ points: Array<[number, number]> } | { problem: "gone" | "hidden" | "covered" | "wrong_kind" }}
   */
  function where(requestId, kind) {
    if (pending === null || typeof requestId !== "string" || pending.requestId !== requestId) return { problem: "gone" };
    const field = pending.fields.find((f) => f.kind === kind);
    if (!field) return { problem: "wrong_kind" };
    const problem = inspect(field.element);
    if (problem !== null) return { problem };
    const points = samplePoints(field.element.getBoundingClientRect());
    return points.length > 0 ? { points } : { problem: "hidden" };
  }

  /**
   * The group of fields that one request fills, found in four steps:
   *
   * 1. Every input that passes `inspect` is a candidate. A field with
   *    autocomplete "new-password" is not (a stored password never goes into a
   *    field that sets a new one), and neither is a text field of a site search
   *    (`isSearchField`).
   * 2. The anchor is the first candidate password field. A page with no password
   *    field (the first step of a two-step sign-in) anchors on the first user
   *    name field, then on the first one-time-code field.
   * 3. The group is the anchor's form. Without a form it is the nearest
   *    container of the anchor that also holds a candidate of another kind;
   *    when that is the whole page, only fields named for their purpose.
   * 4. The group gives at most one field per kind: the password, the user name
   *    (the last text field before the password, else the first user name field
   *    after it) and the first one-time-code field.
   *
   * Nothing outside the group is reported, so no kind can land in another form
   * than the one that gets the password.
   *
   * With `target` (the field of a context menu click), that field is the anchor
   * instead, and it must be a candidate itself, or nothing is reported. A
   * password field anchors as in step 2. A user name field gets the user name,
   * and its group gives the password field after it (else the last one before
   * it) and the one-time code. A one-time-code field gets the code only.
   *
   * @param {any} [target]
   * @returns {Field[]}
   */
  function scan(target) {
    /** @type {Candidate[]} */
    const candidates = [];
    allInputs().forEach((element, order) => {
      const type = String(element.type ?? "").toLowerCase();
      const tokens = autocompleteTokens(element);
      if (type === "password") {
        if (tokens.includes("new-password") || inspect(element) !== null) return;
        candidates.push({ element, role: "password", order });
        return;
      }
      if (!TEXT_TYPES.has(type) || tokens.includes("new-password") || isSearchField(element)) return;
      if (tokens.includes("one-time-code") || TOTP_HINT.test(hintsOf(element))) {
        if (inspect(element) === null) candidates.push({ element, role: "totp", order });
        return;
      }
      if (!USERNAME_TYPES.has(type) || inspect(element) !== null) return;
      const named = tokens.includes("username") || tokens.includes("email") || USERNAME_HINT.test(hintsOf(element));
      candidates.push({ element, role: named ? "username" : "text", order });
    });

    if (target !== undefined) {
      const clicked = candidates.find((c) => c.element === target);
      if (!clicked) return [];
      if (clicked.role !== "password") return fieldsOf(aimedGroup(clicked, candidates));
    }
    const anchor =
      (target !== undefined ? candidates.find((c) => c.element === target) : undefined) ??
      candidates.find((c) => c.role === "password") ??
      candidates.find((c) => c.role === "username" && autocompleteTokens(c.element).includes("username")) ??
      candidates.find((c) => c.role === "username") ??
      candidates.find((c) => c.role === "totp");
    if (!anchor) return [];
    const group = groupOf(anchor, candidates, document);

    /** @type {Candidate[]} */
    const chosen = [anchor];
    if (anchor.role === "password") {
      const before = group.filter((c) => (c.role === "username" || c.role === "text") && c.order < anchor.order);
      const user = before.at(-1) ?? group.find((c) => c.role === "username" && c.order > anchor.order);
      if (user) chosen.push(user);
    }
    if (anchor.role !== "totp") {
      const code = group.find((c) => c.role === "totp");
      if (code) chosen.push(code);
    }
    return fieldsOf(chosen);
  }

  /**
   * The group of a clicked field that is not a password field: the field
   * itself, and for a user name field the password field and the one-time code
   * of its group.
   * @param {Candidate} clicked
   * @param {Candidate[]} candidates
   * @returns {Candidate[]}
   */
  function aimedGroup(clicked, candidates) {
    if (clicked.role === "totp") return [clicked];
    const group = groupOf(clicked, candidates, document);
    const passwords = group.filter((c) => c.role === "password");
    const password = passwords.find((c) => c.order > clicked.order) ?? passwords.at(-1);
    const code = group.find((c) => c.role === "totp");
    return [clicked, ...(password ? [password] : []), ...(code ? [code] : [])];
  }

  /**
   * The report entries of the chosen candidates, in document order, each with
   * a new random id and the form it belongs to now (checked again at fill).
   * @param {Candidate[]} chosen
   * @returns {Field[]}
   */
  function fieldsOf(chosen) {
    return [...chosen].sort((x, y) => x.order - y.order).map(({ element, role }) => ({
      kind: /** @type {Kind} */ (role === "text" ? "username" : role),
      id: newFieldId(random),
      element,
      form: element.form ?? null,
    }));
  }

  /**
   * Aims the next request at the field of a context menu click. False, and no
   * aim, when the browser names no element of this document or no input the
   * engine fills. `aim(null)` takes an aim back.
   * @param {unknown} targetElementId
   * @returns {boolean}
   */
  function aim(targetElementId) {
    aimed = null;
    if (typeof targetElementId !== "number" || !Number.isSafeInteger(targetElementId)) return false;
    /** @type {any} */
    let element = null;
    try {
      element = targetOf(targetElementId);
    } catch {
      return false;
    }
    if (!isElement(element) || element.ownerDocument !== document) return false;
    // Only an input the engine could ever fill: anything else (a text area, an editable block, a checkbox) is
    // refused here, so the menu says so instead of doing nothing.
    const type = String(element.type ?? "").toLowerCase();
    if (element.localName !== "input" || !(type === "password" || TEXT_TYPES.has(type))) return false;
    aimed = { element, until: clock() + AIM_MS };
    return true;
  }

  /** @returns {string} */
  function selfOrigin() {
    const value = window.origin;
    return typeof value === "string" && value.length > 0 && value.length <= 300 ? value : "null";
  }

  /**
   * Starts a pending request: finds the fields and reports them.
   * @param {string} requestId
   * @returns {boolean} whether a report was sent
   */
  function begin(requestId) {
    pending = null;
    // An aim counts for this request only, whatever becomes of it.
    const target = aimed !== null && clock() <= aimed.until ? aimed.element : undefined;
    aimed = null;
    if (typeof requestId !== "string" || !REQUEST_ID.test(requestId)) return false;
    const fields = scan(target);
    pending = { requestId, fields };
    const raw = encode("frame_report", {
      request_id: requestId,
      self_origin: selfOrigin(),
      fields: fields.map(({ kind, id }) => ({ kind, id })),
    });
    Promise.resolve(send(raw)).catch(() => {});
    return true;
  }

  /**
   * @param {string} requestId
   * @param {boolean} ok
   * @param {Reason} [reason]
   */
  function answer(requestId, ok, reason) {
    const body = reason === undefined ? { request_id: requestId, ok } : { request_id: requestId, ok, reason };
    Promise.resolve(send(encode("fill_result", body))).catch(() => {});
  }

  /**
   * @param {Kind} kind
   * @param {string} value
   * @param {{ origin: string, frameUrl: string }} expect
   * @returns {{ ok: true } | { ok: false, reason: Reason }}
   */
  function fill(kind, value, expect) {
    const { location } = window;
    // The frame must still be what the extension chose: same origin, same
    // address, and a real origin (a sandboxed frame has an https address and
    // an opaque origin, and only `self.origin` shows it).
    if (
      window.origin !== location.origin ||
      location.origin === "null" ||
      location.origin !== expect.origin ||
      location.href !== expect.frameUrl
    ) {
      pending = null;
      return { ok: false, reason: "origin_changed" };
    }
    const target = pending?.fields.find((f) => f.kind === kind);
    if (!target) return { ok: false, reason: "wrong_kind" };
    const { element } = target;
    // The kind is checked again on the live element: a password goes only into
    // a password input, and nothing else goes into one.
    // The group is checked again too: the field must still belong to the form
    // it had at the report, and must not have become a field that sets a new
    // password. Only the page's own script can change either.
    const type = isElement(element) ? String(element.type ?? "").toLowerCase() : "";
    if (isElement(element) && element.isConnected === true) {
      if (kind === "password" ? type !== "password" : type === "password" || !TEXT_TYPES.has(type)) {
        return { ok: false, reason: "wrong_kind" };
      }
      if ((element.form ?? null) !== target.form || autocompleteTokens(element).includes("new-password")) {
        return { ok: false, reason: "wrong_kind" };
      }
    }
    const problem = inspect(element);
    if (problem !== null) return { ok: false, reason: problem };
    if (!nativeSetter) return { ok: false, reason: "gone" };
    nativeSetter.call(element, value);
    for (const name of ["input", "change"]) {
      element.dispatchEvent(new window.Event(name, { bubbles: true }));
    }
    return { ok: true };
  }

  /**
   * @param {any} sender
   * @returns {boolean} whether the message came from this extension's own code
   */
  function fromExtension(sender) {
    if (typeof sender !== "object" || sender === null) return false;
    if (typeof runtimeId !== "string" || runtimeId === "" || sender.id !== runtimeId) return false;
    return typeof sender.url === "string" && sender.url.startsWith(extensionBase);
  }

  /**
   * A message from the extension. Anything that is not a valid `fill_field`
   * for the pending request is dropped without a trace.
   * @param {unknown} raw
   * @param {any} sender
   */
  function onMessage(raw, sender) {
    if (!fromExtension(sender)) return;
    /** @type {any} */
    let message;
    try {
      message = decode(raw, PUSH_TYPES);
    } catch {
      return;
    }
    if (message.type !== "fill_field") return;
    const { request_id: requestId, field, value, expect } = message.body;
    if (pending === null || pending.requestId !== requestId) return;
    const result = fill(field, value, expect);
    if (result.ok) answer(requestId, true);
    else answer(requestId, false, result.reason);
  }

  return Object.freeze({ begin, aim, where, frameShown, onMessage });
}

/**
 * Starts the engine once per page: a second injection finds the first and
 * changes nothing. The extension asks for a report through
 * `globalThis.__ferretFill.begin(id)`, aims it at a clicked field through
 * `aim(targetElementId)`, asks where a field of the pending request is through
 * `where(requestId, kind)` and whether a field of a frame of the page is shown
 * through `frameShown(frameId, points)`: properties of the isolated world that
 * the page cannot see.
 *
 * @param {any} [api] the `browser` object
 * @param {any} [scope] the global object of the script (the page window)
 * @returns {{ begin: (requestId: string) => boolean, aim: (targetElementId: number) => boolean, where: (requestId: string, kind: string) => object, frameShown: (frameId: number, points: unknown) => object }}
 */
export function start(api = /** @type {any} */ (globalThis).browser, scope = globalThis) {
  const existing = Object.getOwnPropertyDescriptor(scope, FILL_GLOBAL);
  if (existing) return existing.value;
  const { runtime } = api;
  const engine = createFillEngine({
    window: scope,
    document: scope.document,
    send: (raw) => runtime.sendMessage(raw),
    runtimeId: runtime.id,
    extensionBase: runtime.getURL(""),
    targetOf: (id) => api.menus?.getTargetElement?.(id) ?? null,
    frameIdOf: (element) => runtime.getFrameId(element),
  });
  runtime.onMessage.addListener((/** @type {unknown} */ raw, /** @type {unknown} */ sender) => {
    engine.onMessage(raw, sender);
  });
  const offer = Object.freeze({ begin: engine.begin, aim: engine.aim, where: engine.where, frameShown: engine.frameShown });
  Object.defineProperty(scope, FILL_GLOBAL, { value: offer, configurable: false, enumerable: false, writable: false });
  return offer;
}
