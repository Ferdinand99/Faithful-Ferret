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
// or a `border-image-outset` that another element draws over the field.
//
// A second, bounded pass (COVERAGE_PASS) looks for those covers: an element that is no ancestor of the field and
// that, in its computed styles, paints over it opaquely (an opaque `box-shadow`, `outline` or `drop-shadow` outside
// its own box, or the box of an element with `pointer-events: none` that has a background or is an image, a video or the
// like), and whose painted area holds the centre of the field or a quarter of its area. The opacity of the elements above
// an element counts (a faded wrapper fades what is in it). The field's own labels count like its ancestors for the
// click-through case: a label at rest sits over its empty field. An element that paints below the field in the stack is
// no cover (a heuristic: `z-index`, positioning, tree order and the contexts that opacity, transforms and filters make;
// an outline always counts). A floating label, which has no background or covers a small part of the field, passes. The
// pass looks at most MAX_PAINT_NODES elements, the last of the document first, and keeps MAX_PAINTS areas that meet the
// viewport; past those a page can hide a cover from it. It cannot see a cover that `border-image`, a pseudo-element or a
// canvas that is not click-through draws, and it does not clip a painted area by an `overflow` of an element above it
// (a refusal that the user would not see the reason for).
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

import { PUSH_TYPES, decode, encode } from "../shared/contentProtocol.mjs";
import { TEXT_TYPES, UNRENDERED, autocompleteTokens, classifyField, findGroups, flatParent, isElement, isInside, shadowOf } from "./forms.mjs";
import { refusedClasses } from "./passwordRules.mjs";

/** The smallest width and height, in CSS pixels, of a field the engine fills. */
export const MIN_SIDE = 8;
/** The share of a field that must lie inside the viewport. */
const MIN_VISIBLE_SHARE = 0.5;
/** Bounds that stop a hostile page from making the walks run long. */
const MAX_NODES = 20_000;
const MAX_DEPTH = 1_000;
/**
 * Whether the extra pass for covers that hit testing cannot see is on (see the
 * header). It is on: the fill matrix lost no case with it, in both Firefox
 * channels. A test builds an engine with it off to pin the limit of hit testing alone.
 */
export const COVERAGE_PASS = true;
/** The most elements the extra pass looks at, and the most painted areas it keeps. */
const MAX_PAINT_NODES = 5_000;
const MAX_PAINTS = 256;
/** The share of a field's area that a painted area must hold to count as a cover (the centre of the field counts alone). */
const COVER_SHARE = 0.25;
/** The least opacity (colour alpha times element opacity) that counts as hiding what is below. */
const OPAQUE = 0.9;
/** The least alpha of a background that counts as a cover when the element lets clicks through. */
const BACKGROUND_COVER = 0.5;
/**
 * The share of the viewport that a click-through canvas, SVG or background image must reach to count as decoration
 * (grain, confetti, a scrim: mostly transparent, and the pass cannot see its alpha) and not as a cover.
 */
const DECORATION_SHARE = 0.9;
/** The most a label may stick out of its field, in pixels, and still count as the field's label. */
const LABEL_SLACK = 4;
/** Elements whose content is no background but is drawn all the same. */
const REPLACED = new Set(["img", "video", "canvas", "svg", "iframe", "embed", "object"]);
/** Elements that paint nothing the page shows. */
/** The selectors of the elements that paint in the top layer. */
const TOP_LAYER = Object.freeze([":popover-open", ":modal", ":fullscreen"]);
const NOT_PAINTED = new Set(["head", "script", "style", "meta", "link", "title", "noscript", "template", "base"]);
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
const MAX_POINTS = 8;

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
 * @typedef {{ left: number, top: number, right: number, bottom: number }} Box
 * @typedef {{ element: any, kind: "through" | "shadow" | "outline", box: Box, hole: Box | null }} Paint the area `box` that `element` paints over (what lies below it), but not the `hole` inside it; `through`: the element's own box, which clicks go through; `shadow`: a shadow outside its box; `outline`: a ring around it
 */

const LENGTH = /^[+-]?(?:\d+\.?\d*|\.\d+)(?:px)?$/;

/**
 * `text` cut at the commas (or the white space) that are not inside parentheses.
 * @param {string} text @param {"," | " "} separator
 * @returns {string[]}
 */
function splitTop(text, separator) {
  /** @type {string[]} */
  const out = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < text.length; i += 1) {
    const c = text[i];
    if (c === "(") depth += 1;
    else if (c === ")") depth = Math.max(0, depth - 1);
    else if (depth === 0 && (separator === "," ? c === "," : /\s/.test(c))) {
      out.push(text.slice(start, i));
      start = i + 1;
    }
  }
  out.push(text.slice(start));
  return out.map((part) => part.trim()).filter((part) => part !== "");
}

/**
 * Whether a background image is a gradient (no `url()` in it) all of whose colour stops are opaque enough, drawn at `shown`
 * opacity, to hide what is below. A value with no colour the pass can read is not.
 * @param {string} image @param {number} shown
 */
function opaqueGradient(image, shown) {
  if (image === "" || image === "none" || /url\(|image-set\(|element\(|cross-fade\(/i.test(image)) return false;
  const stops = image.match(/(?:rgba?|hsla?)\([^)]*\)/gi) ?? [];
  return stops.length > 0 && stops.every((stop) => alphaOf(stop) * shown >= BACKGROUND_COVER);
}

/**
 * The alpha of a computed colour: 1 for anything that carries none (so an
 * unknown colour counts as opaque, the side that detects more).
 * @param {string} color
 */
function alphaOf(color) {
  const text = color.trim().toLowerCase();
  if (text === "transparent") return 0;
  const number = (/** @type {string} */ part) => {
    const value = part.trim();
    const n = Number.parseFloat(value);
    if (!Number.isFinite(n)) return 1;
    return Math.min(1, Math.max(0, value.endsWith("%") ? n / 100 : n));
  };
  const slash = /\/\s*([^)\s]+)\s*\)\s*$/.exec(text);
  if (slash) return number(slash[1]);
  const legacy = /^(?:rgba|hsla)\(([^)]*)\)$/.exec(text);
  if (legacy) {
    const parts = legacy[1].split(",");
    return parts.length === 4 ? number(parts[3]) : 1;
  }
  return 1;
}

/**
 * The layers of a computed `box-shadow`, or the one of a `drop-shadow()` (without the spread).
 * @param {string} value
 * @returns {Array<{ inset: boolean, ox: number, oy: number, blur: number, spread: number, alpha: number }>}
 */
function parseShadows(value) {
  /** @type {Array<{ inset: boolean, ox: number, oy: number, blur: number, spread: number, alpha: number }>} */
  const out = [];
  if (value === "" || value === "none") return out;
  for (const layer of splitTop(value, ",").slice(0, 8)) {
    let inset = false;
    /** @type {number[]} */
    const lengths = [];
    /** @type {string[]} */
    const rest = [];
    for (const token of splitTop(layer, " ")) {
      if (token === "inset") inset = true;
      else if (LENGTH.test(token)) lengths.push(Number.parseFloat(token));
      else rest.push(token);
    }
    if (lengths.length < 2) continue;
    out.push({ inset, ox: lengths[0], oy: lengths[1], blur: Math.max(0, lengths[2] ?? 0), spread: lengths[3] ?? 0, alpha: alphaOf(rest.join(" ")) });
  }
  return out;
}

/** @param {{ left: number, top: number, width: number, height: number }} rect @returns {Box} */
const boxOf = ({ left, top, width, height }) => ({ left, top, right: left + width, bottom: top + height });
/** @param {Box} box @param {number} by @returns {Box} */
const grown = (box, by) => ({ left: box.left - by, top: box.top - by, right: box.right + by, bottom: box.bottom + by });
/** @param {Box} box @param {number} dx @param {number} dy @returns {Box} */
const shifted = (box, dx, dy) => ({ left: box.left + dx, top: box.top + dy, right: box.right + dx, bottom: box.bottom + dy });
/** @param {Box} a @param {Box} b @returns {Box} */
const meet = (a, b) => ({ left: Math.max(a.left, b.left), top: Math.max(a.top, b.top), right: Math.min(a.right, b.right), bottom: Math.min(a.bottom, b.bottom) });
/** @param {Box} box */
const areaOf = (box) => Math.max(0, box.right - box.left) * Math.max(0, box.bottom - box.top);
/** @param {Box} box @param {number} x @param {number} y */
const holds = (box, x, y) => x >= box.left && x < box.right && y >= box.top && y < box.bottom;

/**
 * Whether what `paint` draws holds the point (x, y).
 * @param {Paint} paint @param {number} x @param {number} y
 */
const paintsAt = (paint, x, y) => holds(paint.box, x, y) && !(paint.hole !== null && holds(paint.hole, x, y));

/**
 * Whether `paint` is a cover of `field`: it holds the centre of the field, or a share COVER_SHARE of its area.
 * @param {Paint} paint @param {Box} field
 */
function coversField(paint, field) {
  const area = areaOf(field);
  if (!(area > 0)) return false;
  if (paintsAt(paint, (field.left + field.right) / 2, (field.top + field.bottom) / 2)) return true;
  const inside = areaOf(meet(paint.box, field)) - (paint.hole === null ? 0 : areaOf(meet(meet(paint.box, paint.hole), field)));
  return inside / area >= COVER_SHARE;
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
 *   coveragePass?: boolean,
 * }} deps `send` delivers a message to the extension; `runtimeId` and `extensionBase` (`moz-extension://<uuid>/`) say who may talk to the engine;
 *   `targetOf` is `menus.getTargetElement` (the element of a context menu click), `frameIdOf` is `runtime.getFrameId`
 *   (the frame id of the frame an element holds), `clock` the time in milliseconds and `coveragePass` whether the extra
 *   pass for covers that hit testing cannot see is on (default COVERAGE_PASS)
 */
export function createFillEngine({ window, document, send, runtimeId, extensionBase, targetOf = () => null, frameIdOf = () => -1, clock = () => Date.now(), coveragePass = COVERAGE_PASS }) {
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
  /** What the extra pass found in the document, and what it worked out about elements, for the call being served only (see `fresh`). @type {Paint[] | null} */
  let paintsMemo = null;
  /** The opacity of an element times that of everything above it. @type {Map<any, number>} */
  let opacityMemo = new Map();
  /** What decides where an element paints in the stack (see `stackNode`). @type {Map<any, { z: number | null, context: boolean, positioned: boolean }>} */
  let stackMemo = new Map();

  /**
   * The opacity an element is drawn with: its own times that of every element above it (opacity is not inherited,
   * but a faded parent fades what is in it). A node that no slot takes is not drawn at all.
   * @param {any} node
   * @returns {number}
   */
  function effectiveOpacity(node) {
    /** @type {any[]} */
    const chain = [];
    let product = 1;
    /** @type {any} */
    let up = node;
    for (let depth = 0; up !== null; depth += 1) {
      if (up === UNRENDERED) {
        product = 0;
        break;
      }
      const known = opacityMemo.get(up);
      if (known !== undefined) {
        product = known;
        break;
      }
      // Deeper than any walk goes: count what is left as opaque (the side that detects more).
      if (depth > MAX_DEPTH) break;
      chain.push(up);
      up = flatParent(up);
    }
    for (let i = chain.length - 1; i >= 0; i -= 1) {
      const style = window.getComputedStyle(chain[i]);
      const own = style ? Number.parseFloat(read(style, "opacity")) : 1;
      product *= Number.isFinite(own) ? Math.min(1, Math.max(0, own)) : 1;
      opacityMemo.set(chain[i], product);
    }
    return product;
  }

  /**
   * What one element contributes to where it paints: an explicit `z-index` (on a positioned element or a flex or grid
   * item), whether it makes a stacking context of its own at level 0 (opacity, transform, filter, isolation, blend
   * mode, clip or mask), and whether it is positioned.
   * @param {any} node
   * @returns {{ z: number | null, context: boolean, positioned: boolean }}
   */
  function stackNode(node) {
    const known = stackMemo.get(node);
    if (known) return known;
    const style = window.getComputedStyle(node);
    const position = style ? read(style, "position") : "";
    const positioned = position !== "" && position !== "static";
    const opacity = style ? Number.parseFloat(read(style, "opacity")) : 1;
    const plain = (/** @type {string} */ name, /** @type {string} */ normal) => {
      const value = style ? read(style, name) : "";
      return value === "" || value === normal;
    };
    // What the page may make a stacking context of: the values that do so by themselves, and a will-change that names one
    // (position included, for fixed and sticky), containment, a container query, a backdrop filter, a mask and a view transition.
    const will = style ? read(style, "will-change") : "";
    const contain = style ? read(style, "contain") : "";
    const containerType = style ? read(style, "container-type") : "";
    const contentVisibility = style ? read(style, "content-visibility") : "";
    const context =
      position === "fixed" || position === "sticky" ||
      /(^|[\s,])(opacity|transform|translate|rotate|scale|filter|backdrop-filter|perspective|clip-path|mask|mask-image|mask-border|mask-border-source|isolation|position|contain|view-transition-name)([\s,]|$)/.test(will) ||
      /\b(layout|paint|strict|content)\b/.test(contain) ||
      containerType.includes("size") ||
      contentVisibility === "auto" || contentVisibility === "hidden" ||
      !plain("backdrop-filter", "none") || !plain("-webkit-backdrop-filter", "none") || !plain("-webkit-mask-image", "none") || !plain("mask-border-source", "none") || !plain("view-transition-name", "none") ||
      (Number.isFinite(opacity) && opacity < 1) ||
      !plain("transform", "none") || !plain("filter", "none") || !plain("perspective", "none") ||
      !plain("translate", "none") || !plain("rotate", "none") || !plain("scale", "none") ||
      !plain("clip-path", "none") || !plain("mask-image", "none") || !plain("mix-blend-mode", "normal") ||
      (style ? read(style, "isolation") === "isolate" : false);
    /** @type {number | null} */
    let z = null;
    const raw = style ? read(style, "z-index") : "";
    if (/^[+-]?\d+$/.test(raw)) {
      let counts = positioned;
      if (!counts) {
        // A flex or grid item takes part in the stack with its z-index, positioned or not.
        const parent = node.parentElement;
        const display = parent ? read(window.getComputedStyle(parent), "display") : "";
        counts = display.includes("flex") || display.includes("grid");
      }
      if (counts) z = Number.parseInt(raw, 10);
    }
    const info = { z, context, positioned };
    stackMemo.set(node, info);
    return info;
  }

  /**
   * Where a chain of elements (innermost first, below a common ancestor) paints in that ancestor's stack: the
   * explicit `z-index` of its outermost element that has one, 0 for a chain that makes a context or is positioned
   * without one, and a half step below 0 for a chain that is not positioned at all (its backgrounds come before
   * positioned content and above negative layers). A heuristic: the page may stack in ways this does not model.
   * @param {any[]} chain
   * @returns {number}
   */
  function levelOf(chain) {
    let positioned = false;
    for (let i = chain.length - 1; i >= 0; i -= 1) {
      const info = stackNode(chain[i]);
      if (info.z !== null) return info.z;
      if (info.context) return 0;
      if (info.positioned) positioned = true;
    }
    return positioned ? 0 : -0.5;
  }

  /**
   * The elements from `node` up to the root of the flat tree, innermost first.
   * @param {any} node
   * @returns {any[]}
   */
  function flatChain(node) {
    /** @type {any[]} */
    const out = [];
    /** @type {any} */
    let up = node;
    for (let depth = 0; up !== null && up !== UNRENDERED && depth <= MAX_DEPTH; depth += 1) {
      out.push(up);
      up = flatParent(up);
    }
    return out;
  }

  /**
   * Whether an element of the chain is in the top layer. An engine that does not know a pseudo-class throws for it: each
   * is asked on its own.
   * @param {any[]} chain
   */
  function inTopLayer(chain) {
    for (const node of chain) {
      if (typeof node.matches !== "function") continue;
      for (const selector of TOP_LAYER) {
        try {
          if (node.matches(selector)) return true;
        } catch {
          // Not known here: the element cannot be in that layer.
        }
      }
    }
    return false;
  }

  /**
   * Whether `painter` paints below `field` in the stack: it can then not cover the field, whatever its box is. A
   * heuristic (see `levelOf`); "no" whenever it cannot tell.
   * @param {any} painter @param {any} field
   * @returns {boolean}
   */
  function paintsBelow(painter, field) {
    const above = flatChain(painter);
    const here = flatChain(field);
    const inside = new Set(here);
    const meeting = above.findIndex((node) => inside.has(node));
    if (meeting <= 0) return false;
    const fieldIndex = here.indexOf(above[meeting]);
    if (fieldIndex <= 0) return false;
    const painterChain = above.slice(0, meeting);
    // An element in the top layer (a popover that is open, a modal dialog, a fullscreen element) paints above the whole page,
    // whatever its z-index: it never lies below the field.
    if (inTopLayer(painterChain)) return false;
    const fieldChain = here.slice(0, fieldIndex);
    const painterLevel = levelOf(painterChain);
    const fieldLevel = levelOf(fieldChain);
    if (painterLevel !== fieldLevel) return painterLevel < fieldLevel;
    // The same level, also for two branches that are not positioned: tree order decides. (Only a block background paints
    // before inline content, and an inline or replaced element later in the tree, pulled over the field with a negative
    // margin, paints over it.)
    const first = painterChain[painterChain.length - 1];
    const second = fieldChain[fieldChain.length - 1];
    if (typeof first.compareDocumentPosition !== "function") return false;
    const relation = first.compareDocumentPosition(second);
    // The field's branch comes later in the tree (and the two are in one tree): it paints over the painter.
    return (relation & 4) !== 0 && (relation & 1) === 0;
  }

  /**
   * The areas that elements of the document paint over what lies below, for the extra pass: an opaque `box-shadow`,
   * `outline` or `drop-shadow` outside the element's own box, and the box of an element that lets clicks through
   * (`pointer-events: none`) and has a background or is an image, a video, an SVG or the like. Only areas that meet
   * the viewport are kept. At most MAX_PAINT_NODES elements are looked at, the last of the document first (overlays
   * and portals are usually added there), and MAX_PAINTS areas kept; what lies beyond is not seen.
   * @returns {Paint[]}
   */
  function collectPaints() {
    /** @type {Paint[]} */
    const out = [];
    let seen = 0;
    const { width, height } = viewport();
    /** @type {Box} */
    const screen = { left: 0, top: 0, right: width, bottom: height };
    /** @param {any} root */
    const visit = (root) => {
      const all = root.querySelectorAll("*");
      for (let i = all.length - 1; i >= 0; i -= 1) {
        const node = all[i];
        seen += 1;
        if (seen > MAX_PAINT_NODES || out.length >= MAX_PAINTS) return;
        if (!NOT_PAINTED.has(node.localName)) paintsOf(node, out, screen);
        const inner = shadowOf(node);
        if (inner) visit(inner);
      }
    };
    visit(document);
    return out;
  }

  /**
   * Adds the areas one element paints to `out`.
   * @param {any} node @param {Paint[]} out @param {Box} screen
   */
  function paintsOf(node, out, screen) {
    const style = window.getComputedStyle(node);
    if (!style || read(style, "display") === "none" || read(style, "visibility") !== "visible") return;
    // Most elements paint nothing the pass looks for: leave them before the more costly questions.
    const clickThrough = read(style, "pointer-events") === "none";
    const background = read(style, "background-color");
    const image = read(style, "background-image");
    const throughPaints = clickThrough && (REPLACED.has(node.localName) || (background !== "" && alphaOf(background) > 0) || (image !== "" && image !== "none"));
    const shadows = read(style, "box-shadow");
    const lineStyle = read(style, "outline-style");
    const filter = read(style, "filter");
    const shadowed = shadows !== "" && shadows !== "none";
    const outlined = lineStyle !== "" && lineStyle !== "none" && lineStyle !== "hidden";
    const dropped = filter.includes("drop-shadow(");
    if (!throughPaints && !shadowed && !outlined && !dropped) return;
    // The opacity it is drawn with, that of the elements above it included.
    const shown = effectiveOpacity(node);
    if (shown < BACKGROUND_COVER) return;
    // An element without a box paints nothing (`display: contents`, or below a `display: none`).
    if (typeof node.getClientRects === "function" && node.getClientRects().length === 0) return;
    /** @type {Box | null} */
    let border = null;
    const own = () => {
      if (border === null) {
        const rect = node.getBoundingClientRect();
        border = [rect.left, rect.top, rect.width, rect.height].every(Number.isFinite) ? boxOf(rect) : { left: 0, top: 0, right: 0, bottom: 0 };
      }
      return border;
    };
    const add = (/** @type {Paint["kind"]} */ kind, /** @type {Box} */ box, /** @type {Box | null} */ hole) => {
      if (out.length < MAX_PAINTS && areaOf(meet(box, screen)) > 0) out.push({ element: node, kind, box, hole });
    };

    // A cover that clicks go through: only when it has a background of its own (a label with none shows only its text),
    // or is an image or the like.
    if (throughPaints) {
      const coloured = background !== "" && alphaOf(background) * shown >= BACKGROUND_COVER;
      if (REPLACED.has(node.localName) || coloured || (image !== "" && image !== "none")) {
        // A click-through canvas, SVG or background picture over most of the viewport is decoration (grain, confetti, a scrim):
        // the pass cannot see its alpha, and a page can hide a field with a pseudo-element anyway. A background image that is no
        // picture (a gradient) shows its colours: when they are opaque it is a colour, like a background colour.
        const picture = !coloured && !opaqueGradient(image, shown) && (node.localName === "canvas" || node.localName === "svg" || !REPLACED.has(node.localName));
        const full = areaOf(meet(own(), screen)) >= DECORATION_SHARE * areaOf(screen);
        if (!(picture && full)) add("through", own(), null);
      }
    }
    // An opaque shadow of the element, outside its own box (which the hit test sees).
    for (const layer of parseShadows(shadows)) {
      if (layer.inset || layer.alpha * shown < OPAQUE) continue;
      add("shadow", grown(shifted(own(), layer.ox, layer.oy), layer.spread - layer.blur / 2), own());
    }
    // An outline is a ring around the box, grown by its offset.
    if (outlined) {
      const width = Number.parseFloat(read(style, "outline-width"));
      const offset = Number.parseFloat(read(style, "outline-offset"));
      if (width > 0 && alphaOf(read(style, "outline-color")) * shown >= OPAQUE) {
        const gap = Number.isFinite(offset) ? offset : 0;
        add("outline", grown(own(), gap + width), grown(own(), gap));
      }
    }
    // A drop shadow is a copy of the element, moved by its offset; its blur only softens the edge.
    if (dropped) {
      for (const token of splitTop(filter, " ")) {
        if (!token.startsWith("drop-shadow(") || !token.endsWith(")")) continue;
        const [layer] = parseShadows(token.slice("drop-shadow(".length, -1));
        if (layer && layer.alpha * shown >= OPAQUE) add("shadow", grown(shifted(own(), layer.ox, layer.oy), -layer.blur / 2), own());
      }
    }
  }

  /**
   * Whether a label's paint stays within the field's box: no taller than the field (a few pixels more allowed) and no
   * larger in area, so a long text that crosses the field's centre is still a label, and a layer that fills the page is not.
   * @param {Box} box @param {any} target
   */
  function fitsLabel(box, target) {
    try {
      const rect = target.getBoundingClientRect();
      const field = boxOf(rect);
      return box.bottom - box.top <= field.bottom - field.top + LABEL_SLACK && areaOf(box) <= areaOf(field) + LABEL_SLACK * (field.right - field.left);
    } catch {
      return false;
    }
  }

  /**
   * Whether `paint` counts against the element `target`: its element is not the target or above it (which paint below
   * it), it is not the label of the target when it only lets clicks through (a label at rest sits over its field), and
   * it does not paint below the target in the stack (an outline always paints on top).
   * @param {Paint} paint @param {any} target @param {Set<any>} mine @param {any[]} labels
   */
  function counts(paint, target, mine, labels) {
    if (mine.has(paint.element)) return false;
    if (paint.kind === "through" && labels.some((label) => isInside(label, paint.element)) && fitsLabel(paint.box, target)) return false;
    if (paint.kind !== "outline" && paintsBelow(paint.element, target)) return false;
    return true;
  }

  /**
   * The extra pass, when it is on: whether something that is no ancestor of `element` paints over the field `rect`.
   * @param {any} element @param {{ left: number, top: number, width: number, height: number }} rect
   * @returns {"covered" | null}
   */
  function paintedOver(element, rect) {
    if (!coveragePass) return null;
    paintsMemo ??= collectPaints();
    if (paintsMemo.length === 0) return null;
    const field = boxOf(rect);
    const near = paintsMemo.filter((paint) => coversField(paint, field));
    if (near.length === 0) return null;
    const mine = new Set(flatChain(element));
    /** @type {any[]} */
    let labels = [];
    try {
      labels = element.labels ? Array.from(element.labels) : [];
    } catch {
      labels = [];
    }
    return near.some((paint) => counts(paint, element, mine, labels)) ? "covered" : null;
  }

  /**
   * The extra pass for the element that holds a frame: whether something that is no ancestor of it paints over the
   * centre of the field, moved into this document, or over two of its points.
   * @param {any} holder @param {Array<[number, number]>} points
   * @returns {"covered" | null}
   */
  function paintedOverPoints(holder, points) {
    if (!coveragePass) return null;
    paintsMemo ??= collectPaints();
    if (paintsMemo.length === 0) return null;
    const mine = new Set(flatChain(holder));
    const near = paintsMemo.filter((paint) => points.some(([x, y]) => paintsAt(paint, x, y)));
    if (near.length === 0) return null;
    const counting = near.filter((paint) => counts(paint, holder, mine, []));
    const painted = points.filter(([x, y]) => counting.some((paint) => paintsAt(paint, x, y)));
    return painted.length >= 2 || (painted.length === 1 && painted[0] === points[0]) ? "covered" : null;
  }

  /**
   * Makes `fn` start with an empty memory of the page's paints and leave it empty: a paint list is good for
   * the one call only, because the page may change between two calls.
   * @template {(...args: any[]) => any} F
   * @param {F} fn
   * @returns {F}
   */
  function fresh(fn) {
    const forget = () => {
      paintsMemo = null;
      opacityMemo = new Map();
      stackMemo = new Map();
    };
    return /** @type {F} */ (
      (/** @type {any[]} */ ...args) => {
        forget();
        try {
          return fn(...args);
        } finally {
          forget();
        }
      }
    );
  }

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
    return paintedOver(element, rect);
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
    if (paintedOverPoints(holder, moved) !== null) return { verdict: "covered" };
    return { verdict: "shown", points: moved };
  }

  /** The boxes of a split code, or the one element of a field, as a list. @param {any} element @returns {any[]} */
  const elementsOf = (element) => (Array.isArray(element) ? element : [element]);

  /**
   * Where the field of `kind` of the pending request `requestId` is: its
   * sample points in this frame's viewport, when it passes every check now,
   * else why not. For the documents above this frame (see `frameShown`). The
   * boxes of a split code give the centre of each box (all of them up to MAX_POINTS,
   * which holds the longest code of eight boxes; beyond that the first two, the middle
   * one and the last two), and every box must pass.
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
   * The classes of characters (lower, upper, digit, symbol) that a new or confirm field refuses by its `passwordrules` or its
   * `pattern`, for the generator to leave out; none for any other field.
   * @param {Field} field
   * @returns {string[]}
   */
  function refusedOf({ kind, element }) {
    if (kind !== "new_password" && kind !== "confirm_password") return [];
    return isElement(element) ? refusedClasses(element) : [];
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
        const forbid = refusedOf(field);
        return { kind: field.kind, id: field.id, ...(max !== undefined ? { max } : {}), ...(forbid.length > 0 ? { forbid } : {}) };
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

  return Object.freeze({ begin: fresh(begin), aim, where: fresh(where), frameShown: fresh(frameShown), onMessage: fresh(onMessage) });
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
