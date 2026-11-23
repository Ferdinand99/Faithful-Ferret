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
// Which field: one request fills one group, found by the detection module
// (forms.mjs): the first sign-in or change group of the page whose password the
// user can see, else a user name step, else a one-time code. A sign-in gives the
// user name, the password and its one-time code; a change form the user name
// and the password in use; a user name step the user name; a code page the
// code. A sign-up or reset form, a card or PIN form and any other form give
// nothing: a stored password never goes into a field that sets a new one, nor
// into a card's security code, a PIN or a code field, and a user name never
// into a search box or an e-mail field of a newsletter. A split code (one box
// per digit) is one field: each box gets one digit, and only when the code has
// as many digits as there are boxes. At the fill the field must still be in the
// form it had at the report and must still be a field of its kind. A field id is
// only a handle for the report. A `fill_field` names the kind, and the engine
// fills the field of that kind in the group. The engine answers only to a
// message that the extension itself sent.
//
// A frame whose document its parent wrote (`document.open()` into a frame with
// no address of its own, which gives the frame the parent's address) is not a
// page the user opened: it reports no field.
//
// A generated password (`begin(requestId, "generated")`): the request is for the
// new and the confirm field of the first sign-up, change or reset group of the
// page, and for nothing else. A sign-in group and the password in use of a
// change group are not reported, and an aim is not used. The report also names
// each field's `maxlength`, so the extension can make the value fit. At the
// fill the field must still be the new (or confirm) field of such a group, shown
// and inside its `maxlength`.
//
// The context menu (`aim`): a click on Ferret's menu item names one field
// (`menus.getTargetElement`). The extension aims the engine at it before the
// request begins, and that request fills the group of the clicked field
// instead of the first one of the page. The clicked field gets the value of its
// own kind, so a password goes into it only when it is the password of a
// sign-in or change group, and a code only when it is a code field. A clicked
// text field that is no search, card or code field gets the user name. An
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
import { TEXT_TYPES, UNRENDERED, autocompleteTokens, classifyField, findGroups, flatParent, isElement, shadowOf } from "./forms.mjs";

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
/** The groups whose new and confirm fields take a generated password. */
const NEW_PASSWORD_GROUPS = Object.freeze(["signup", "change", "reset"]);
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
 * @typedef {"username" | "password" | "totp" | "new_password" | "confirm_password"} Kind
 * @typedef {{ kind: Kind, id: string, element: any, form: any }} Field `element`: the input, or the boxes of a split code
 * @typedef {"origin_changed" | "hidden" | "covered" | "gone" | "wrong_kind" | "value_too_long"} Reason
 */

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
  /** The kind of the group the last generated scan found (signup, change or reset), or null. @type {string | null} */
  let foundGroup = null;
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

  /** The boxes of a split code, or the one element of a field, as a list. @param {any} element @returns {any[]} */
  const elementsOf = (element) => (Array.isArray(element) ? element : [element]);

  /**
   * Where the field of `kind` of the pending request `requestId` is: its
   * sample points in this frame's viewport, when it passes every check now,
   * else why not. For the documents above this frame (see `frameShown`). The
   * boxes of a split code give the centre of each box (at most MAX_POINTS of
   * them, the first and the last among them), and every box must pass.
   * @param {unknown} requestId
   * @param {unknown} kind
   * @returns {{ points: Array<[number, number]> } | { problem: "gone" | "hidden" | "covered" | "wrong_kind" }}
   */
  function where(requestId, kind) {
    if (pending === null || typeof requestId !== "string" || pending.requestId !== requestId) return { problem: "gone" };
    const field = pending.fields.find((f) => f.kind === kind);
    if (!field) return { problem: "wrong_kind" };
    if (Array.isArray(field.element)) {
      const boxes = field.element;
      for (const box of boxes) {
        const problem = inspect(box);
        if (problem !== null) return { problem };
      }
      const picked = boxes.length <= MAX_POINTS ? boxes : [0, 1, Math.floor(boxes.length / 2), boxes.length - 2, boxes.length - 1].map((i) => boxes[i]);
      /** @type {Array<[number, number]>} */
      const points = [];
      for (const box of picked) {
        const [centre] = samplePoints(box.getBoundingClientRect());
        if (!centre) return { problem: "hidden" };
        points.push(centre);
      }
      return { points };
    }
    const problem = inspect(field.element);
    if (problem !== null) return { problem };
    const points = samplePoints(field.element.getBoundingClientRect());
    return points.length > 0 ? { points } : { problem: "hidden" };
  }

  /**
   * Whether this frame's document was written by its parent rather than
   * loaded: a frame below the top whose holder (the parent's `iframe`,
   * `frame`, `object` or `embed`, reachable only when the parent has this
   * frame's origin) has a `srcdoc`, or whose document has the parent
   * document's own address, which is what `document.open()` from the parent
   * gives it (with or without a `src` on the holder). Such a document is the
   * parent page's markup in a frame, not a page the user opened, and it
   * reports no field. A frame navigated to an address of its own (by its name,
   * say) is a page, also without a `src`. The top has no holder, and a frame
   * below a parent of another origin cannot see its holder (the parent could
   * not have written it either).
   * @returns {boolean}
   */
  function writtenByParent() {
    try {
      const holder = window.frameElement;
      if (!isElement(holder)) return false;
      if (holder.hasAttribute("srcdoc")) return true;
      const own = document.URL;
      const above = holder.ownerDocument?.URL;
      return typeof own === "string" && typeof above === "string" && own === above;
    } catch {
      return false;
    }
  }

  /**
   * The fields one request fills, from the groups of the page (forms.mjs). A
   * field takes a role in a group only when it passes `inspect` now.
   *
   * Without `target`: the first sign-in or change group whose password the
   * user can see, else the first user name step, else the first code page. A
   * sign-in gives its user name, its password and its code; a change form its
   * user name and the password in use; a user name step the user name; a code
   * page the code (one field, or the boxes of a split code).
   *
   * With `target` (the field of a context menu click), that field must pass
   * `inspect` and be one the engine fills, or nothing is reported. The password
   * of a sign-in or change group gives that group, with the clicked field as the
   * password. A code field gives the code. Any other text field that is no
   * search, card, PIN or code field gets the user name, and in a sign-in or
   * change group the password and the code of its group as well.
   *
   * Nothing outside the group is reported, so no kind can land in another form
   * than the one that gets the password.
   *
   * With `generated`: only the new and the confirm field of the first sign-up, change or reset group whose new field
   * the user can see (a sign-in group and a password in use give nothing).
   *
   * @param {any} [target]
   * @param {boolean} [generated]
   * @returns {Field[]}
   */
  function scan(target, generated = false) {
    if (writtenByParent()) return [];
    /** @type {Map<any, boolean>} */
    const seen = new Map();
    const usable = (/** @type {any} */ element) => {
      if (!seen.has(element)) seen.set(element, inspect(element) === null);
      return /** @type {boolean} */ (seen.get(element));
    };
    const groups = findGroups(document, { maxNodes: MAX_NODES, shown: usable });
    /** @type {Map<any, number>} */
    const order = new Map();
    for (const group of groups) for (const f of group.fields) order.set(f.element, f.order);

    /** @type {Array<{ kind: Kind, element: any }>} */
    const chosen = [];
    /** @param {Kind} kind @param {any} element */
    const take = (kind, element) => {
      if (element !== undefined && element !== null) chosen.push({ kind, element });
    };
    /** @param {import("./forms.mjs").Group} group @param {any} [password] */
    const report = (group, password) => {
      if (group.kind === "login" || group.kind === "change") {
        take("username", group.username);
        take("password", password ?? group.password ?? group.current);
        if (group.kind === "login") take("totp", group.otp);
      } else if (group.kind === "identifier") {
        take("username", group.username);
      } else if (group.kind === "otp") {
        take("totp", group.otp);
      }
    };

    if (generated) {
      const group = groups.find((g) => NEW_PASSWORD_GROUPS.includes(g.kind) && g.new);
      if (group) {
        take("new_password", group.new);
        take("confirm_password", group.confirm);
        foundGroup = group.kind;
      }
      return fieldsOf(chosen, order);
    }

    if (target !== undefined) {
      if (!usable(target)) return [];
      const group = groups.find((g) => g.fields.some((f) => f.element === target));
      const field = group?.fields.find((f) => f.element === target);
      if (!group || !field) return [];
      const signIn = group.kind === "login" || group.kind === "change";
      if (field.password) {
        // Only the password the group fills: never its new or confirm field, whatever the field says of itself.
        if (signIn && (target === group.password || target === group.current)) report(group, target);
      } else if (field.kind === "otp" || field.kind === "otp_digit") {
        const code = group.otp;
        if (code === target || (Array.isArray(code) && code.includes(target))) take("totp", code);
      } else if (["username", "email", "other"].includes(field.kind) && !field.reasons.includes("card")) {
        take("username", target);
        if (signIn) {
          take("password", group.password ?? group.current);
          if (group.kind === "login") take("totp", group.otp);
        }
      }
      return fieldsOf(chosen, order);
    }

    const pick =
      groups.find((g) => (g.kind === "login" && g.password) || (g.kind === "change" && g.current)) ??
      groups.find((g) => g.kind === "identifier" && g.username) ??
      groups.find((g) => g.kind === "otp" && g.otp);
    if (pick) report(pick);
    return fieldsOf(chosen, order);
  }

  /**
   * The report entries of the chosen fields, in document order, each with a
   * new random id and the form it belongs to now (checked again at fill).
   * @param {Array<{ kind: Kind, element: any }>} chosen
   * @param {Map<any, number>} order
   * @returns {Field[]}
   */
  function fieldsOf(chosen, order) {
    const at = (/** @type {any} */ element) => order.get(elementsOf(element)[0]) ?? 0;
    return [...chosen].sort((x, y) => at(x.element) - at(y.element)).map(({ kind, element }) => ({
      kind,
      id: newFieldId(random),
      element,
      form: elementsOf(element)[0].form ?? null,
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
   * The `maxlength` of a new or confirm field, or undefined when it has none.
   * @param {Field} field
   * @returns {number | undefined}
   */
  function limitOf({ kind, element }) {
    if (kind !== "new_password" && kind !== "confirm_password") return undefined;
    // The attribute, as the detection reads it: a value that is not a whole number is no limit (the browser ignores it too).
    const raw = String(element.getAttribute("maxlength") ?? "").trim();
    return /^\d{1,6}$/.test(raw) ? Number(raw) : undefined;
  }

  /**
   * Starts a pending request: finds the fields and reports them.
   * @param {string} requestId
   * @param {string} [mode] "generated": the new and the confirm field of a sign-up, change or reset group
   * @returns {boolean} whether a report was sent
   */
  function begin(requestId, mode) {
    pending = null;
    // An aim counts for this request only, whatever becomes of it.
    const target = aimed !== null && clock() <= aimed.until ? aimed.element : undefined;
    aimed = null;
    if (typeof requestId !== "string" || !REQUEST_ID.test(requestId)) return false;
    if (mode !== undefined && mode !== "generated") return false;
    const generated = mode === "generated";
    foundGroup = null;
    const fields = scan(generated ? undefined : target, generated);
    pending = { requestId, fields };
    const raw = encode("frame_report", {
      request_id: requestId,
      self_origin: selfOrigin(),
      fields: fields.map((field) => {
        const max = limitOf(field);
        return { kind: field.kind, id: field.id, ...(max !== undefined ? { max } : {}) };
      }),
      ...(generated && foundGroup !== null && fields.length > 0 ? { group: foundGroup } : {}),
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
    if (kind === "new_password" || kind === "confirm_password") return fillNew(target, value);
    if (Array.isArray(target.element)) return fillBoxes(target, value);
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
      // A password field the page has turned into a code, PIN or card field, or into one that sets a new password.
      if (kind === "password" && classifyField(element).kind !== "current_password") return { ok: false, reason: "wrong_kind" };
    }
    const problem = inspect(element);
    if (problem !== null) return { ok: false, reason: problem };
    if (!nativeSetter) return { ok: false, reason: "gone" };
    put(element, value);
    return { ok: true };
  }

  /**
   * A generated password into the new or the confirm field of a sign-up, change or reset group. The field must still
   * be a masked input of the form it had at the report and still be that group's new (or confirm) field, so a page
   * that turned it into a sign-in or a code field gets nothing; it must pass every check of `inspect`, and take the
   * value inside its `maxlength`.
   * @param {Field} target
   * @param {string} value
   * @returns {{ ok: true } | { ok: false, reason: Reason }}
   */
  function fillNew(target, value) {
    const { element } = target;
    if (!isElement(element) || Array.isArray(element) || element.isConnected !== true) return { ok: false, reason: "gone" };
    if (String(element.type ?? "").toLowerCase() !== "password" || (element.form ?? null) !== target.form) return { ok: false, reason: "wrong_kind" };
    const problem = inspect(element);
    if (problem !== null) return { ok: false, reason: problem };
    /** @type {Map<any, boolean>} */
    const seen = new Map();
    const usable = (/** @type {any} */ el) => {
      if (!seen.has(el)) seen.set(el, inspect(el) === null);
      return seen.get(el) === true;
    };
    const now = findGroups(document, { maxNodes: MAX_NODES, shown: usable });
    const role = target.kind === "new_password" ? "new" : "confirm";
    if (!now.some((g) => NEW_PASSWORD_GROUPS.includes(g.kind) && g[role] === element)) return { ok: false, reason: "wrong_kind" };
    const max = limitOf(target);
    if (max !== undefined && value.length > max) return { ok: false, reason: "value_too_long" };
    if (!nativeSetter) return { ok: false, reason: "gone" };
    put(element, value);
    return { ok: true };
  }

  /** Sets a value with the native setter and fires `input` and `change`. @param {any} element @param {string} value */
  function put(element, value) {
    /** @type {any} */ (nativeSetter).call(element, value);
    for (const name of ["input", "change"]) {
      element.dispatchEvent(new window.Event(name, { bubbles: true }));
    }
  }

  /**
   * A code into the boxes of a split code: one digit each, only when the code
   * has exactly as many digits as there are boxes, and every box still passes
   * every check (a text input of its form, shown, nothing over it).
   * @param {Field} target
   * @param {string} value
   * @returns {{ ok: true } | { ok: false, reason: Reason }}
   */
  function fillBoxes(target, value) {
    const boxes = /** @type {any[]} */ (target.element);
    if (!/^[0-9]+$/.test(value) || value.length !== boxes.length) return { ok: false, reason: "wrong_kind" };
    for (const box of boxes) {
      if (!isElement(box) || box.isConnected !== true) return { ok: false, reason: "gone" };
      const type = String(box.type ?? "").toLowerCase();
      if (type === "password" || !TEXT_TYPES.has(type) || (box.form ?? null) !== target.form) return { ok: false, reason: "wrong_kind" };
      const problem = inspect(box);
      if (problem !== null) return { ok: false, reason: problem };
    }
    if (!nativeSetter) return { ok: false, reason: "gone" };
    boxes.forEach((box, i) => put(box, value[i]));
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
 * @returns {{ begin: (requestId: string, mode?: string) => boolean, aim: (targetElementId: number) => boolean, where: (requestId: string, kind: string) => object, frameShown: (frameId: number, points: unknown) => object }}
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
