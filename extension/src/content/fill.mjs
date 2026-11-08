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
// never a field that sets a new password. A field id is only a handle for the
// report. A `fill_field` names the kind, and the engine fills the field of that
// kind in the group. The engine answers only to a message that the extension
// itself sent.

import { PUSH_TYPES, decode, encode } from "../shared/protocol.mjs";

/** The smallest width and height, in CSS pixels, of a field the engine fills. */
export const MIN_SIDE = 8;
/** The share of a field that must lie inside the viewport. */
const MIN_VISIBLE_SHARE = 0.5;
/** Bounds that stop a hostile page from making the walks run long. */
const MAX_NODES = 20_000;
const MAX_DEPTH = 1_000;
/** The name under which the injected script offers `begin` to the extension (not reachable by the page). */
export const FILL_GLOBAL = "__ferretFill";

const REQUEST_ID = /^[A-Za-z0-9_-]{1,64}$/;
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
 * @typedef {{ kind: Kind, id: string, element: any }} Field
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
 *
 * @param {Candidate} anchor
 * @param {Candidate[]} candidates
 * @returns {Candidate[]}
 */
function groupOf(anchor, candidates) {
  const form = anchor.element.form;
  if (form) return candidates.filter((c) => c.element.form === form);
  const loose = candidates.filter((c) => !c.element.form);
  for (let node = flatParent(anchor.element), depth = 0; node && node !== UNRENDERED && depth <= MAX_DEPTH; node = flatParent(node), depth += 1) {
    const inside = loose.filter((c) => isInside(node, c.element));
    if (inside.some((c) => c.role !== anchor.role)) return inside;
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
 * }} deps `send` delivers a message to the extension; `runtimeId` and `extensionBase` (`moz-extension://<uuid>/`) say who may talk to the engine
 */
export function createFillEngine({ window, document, send, runtimeId, extensionBase }) {
  // The native setter. In Firefox the content script reads the page through
  // Xray wrappers, so this is the browser's own setter whatever the page has
  // replaced; taking it once here is only a second line of defence.
  const nativeSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value")?.set;
  const random = window.crypto;

  /** @type {{ requestId: string, fields: Field[] } | null} */
  let pending = null;

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

    // From the field up to the root, through shadow roots and slots.
    /** @type {any} */
    let node = element;
    for (let depth = 0; node !== null; depth += 1) {
      if (depth > MAX_DEPTH || node === UNRENDERED) return "hidden";
      if (node.getAttribute("aria-hidden") === "true") return "hidden";
      if (node.inert === true || node.hasAttribute("inert")) return "hidden";
      const style = window.getComputedStyle(node);
      if (!style || styleProblem(style) !== null) return "hidden";
      node = flatParent(node);
    }

    const rect = element.getBoundingClientRect();
    const { left, top, width, height } = rect;
    if (![left, top, width, height].every(Number.isFinite)) return "hidden";
    if (width < MIN_SIDE || height < MIN_SIDE) return "hidden";
    const viewWidth = document.documentElement.clientWidth || window.innerWidth;
    const viewHeight = document.documentElement.clientHeight || window.innerHeight;
    const inside = (/** @type {number} */ x, /** @type {number} */ y) => x >= 0 && y >= 0 && x < viewWidth && y < viewHeight;
    const shownWidth = Math.min(left + width, viewWidth) - Math.max(left, 0);
    const shownHeight = Math.min(top + height, viewHeight) - Math.max(top, 0);
    if (!(shownWidth > 0) || !(shownHeight > 0)) return "hidden";
    if ((shownWidth * shownHeight) / (width * height) < MIN_VISIBLE_SHARE) return "hidden";
    if (!inside(left + width / 2, top + height / 2)) return "hidden";

    // The document, then every shadow root down to the field, must each name
    // the next level (or the field) as the topmost element at the point.
    /** @type {any[]} */
    const roots = [];
    for (let root = element.getRootNode(); root; root = root.host ? root.host.getRootNode() : null) {
      roots.unshift(root);
      if (roots.length > MAX_DEPTH) return "hidden";
    }
    if (roots[0] !== document) return "gone";
    for (const [fx, fy] of [[0.5, 0.5], [0.25, 0.5], [0.75, 0.5], [0.5, 0.25], [0.5, 0.75]]) {
      const x = left + width * fx;
      const y = top + height * fy;
      if (!inside(x, y)) continue;
      for (let i = 0; i < roots.length; i += 1) {
        const expected = i < roots.length - 1 ? roots[i + 1].host : element;
        const hits = roots[i].elementsFromPoint(x, y);
        if (!hits || hits[0] !== expected) return "covered";
      }
    }
    return null;
  }

  /**
   * Every input of the frame in document order, through shadow roots.
   * @returns {any[]}
   */
  function allInputs() {
    /** @type {any[]} */
    const out = [];
    let seen = 0;
    /** @param {any} root */
    const visit = (root) => {
      for (const node of root.querySelectorAll("*")) {
        seen += 1;
        if (seen > MAX_NODES) return;
        if (node.localName === "input") out.push(node);
        const inner = shadowOf(node);
        if (inner) visit(inner);
      }
    };
    visit(document);
    return out;
  }

  /**
   * The group of fields that one request fills, found in four steps:
   *
   * 1. Every input that passes `inspect` is a candidate. A password field with
   *    autocomplete "new-password" is not (a stored password never goes into a
   *    field that sets a new one).
   * 2. The anchor is the first candidate password field. A page with no password
   *    field (the first step of a two-step sign-in) anchors on the first user
   *    name field, then on the first one-time-code field.
   * 3. The group is the anchor's form. Without a form it is the nearest
   *    container of the anchor that also holds a candidate of another kind.
   * 4. The group gives at most one field per kind: the password, the user name
   *    (the last text field before the password, else the first user name field
   *    after it) and the first one-time-code field.
   *
   * Nothing outside the group is reported, so no kind can land in another form
   * than the one that gets the password.
   *
   * @returns {Field[]}
   */
  function scan() {
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
      if (!TEXT_TYPES.has(type)) return;
      if (tokens.includes("one-time-code") || TOTP_HINT.test(hintsOf(element))) {
        if (inspect(element) === null) candidates.push({ element, role: "totp", order });
        return;
      }
      if (!USERNAME_TYPES.has(type) || inspect(element) !== null) return;
      const named = tokens.includes("username") || tokens.includes("email") || USERNAME_HINT.test(hintsOf(element));
      candidates.push({ element, role: named ? "username" : "text", order });
    });

    const anchor =
      candidates.find((c) => c.role === "password") ??
      candidates.find((c) => c.role === "username" && autocompleteTokens(c.element).includes("username")) ??
      candidates.find((c) => c.role === "username") ??
      candidates.find((c) => c.role === "totp");
    if (!anchor) return [];
    const group = groupOf(anchor, candidates);

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
    chosen.sort((x, y) => x.order - y.order);
    return chosen.map(({ element, role }) => ({
      kind: /** @type {Kind} */ (role === "text" ? "username" : role),
      id: newFieldId(random),
      element,
    }));
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
    if (typeof requestId !== "string" || !REQUEST_ID.test(requestId)) return false;
    const fields = scan();
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
    const type = isElement(element) ? String(element.type ?? "").toLowerCase() : "";
    if (isElement(element) && element.isConnected === true) {
      if (kind === "password" ? type !== "password" : type === "password" || !TEXT_TYPES.has(type)) {
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

  return Object.freeze({ begin, onMessage });
}

/**
 * Starts the engine once per page: a second injection finds the first and
 * changes nothing. The extension asks for a report through
 * `globalThis.__ferretFill.begin(id)`, a property of the isolated world that
 * the page cannot see.
 *
 * @param {any} [api] the `browser` object
 * @param {any} [scope] the global object of the script (the page window)
 * @returns {{ begin: (requestId: string) => boolean }}
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
  });
  runtime.onMessage.addListener((/** @type {unknown} */ raw, /** @type {unknown} */ sender) => {
    engine.onMessage(raw, sender);
  });
  const offer = Object.freeze({ begin: engine.begin });
  Object.defineProperty(scope, FILL_GLOBAL, { value: offer, configurable: false, enumerable: false, writable: false });
  return offer;
}
