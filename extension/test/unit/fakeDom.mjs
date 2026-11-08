// A small stand-in for a web page, for the fill engine's unit tests: elements,
// forms, shadow roots (open and closed), slots, computed styles, rectangles and
// a hit test (`elementsFromPoint`) that follows z-order and shadow retargeting.
// No jsdom. Not a test file (the runner picks up *.test.mjs only).
//
// Styles are set per element in `style` (CSS property names); anything not set
// has the value of an ordinary element. Rectangles are set in `rect`; an
// element without one cannot be hit. `hitBlocked` takes an element out of the
// hit test the way a clipping ancestor or `pointer-events: none` would.
import { CONTENT_TYPES, PUSH_TYPES, decode, encode } from "../../src/shared/protocol.mjs";
import { EXTENSION_ID, EXTENSION_UUID } from "./fakeBrowser.mjs";

const DEFAULT_STYLE = Object.freeze({
  opacity: "1",
  visibility: "visible",
  display: "block",
  filter: "none",
  transform: "none",
  "clip-path": "none",
  "mix-blend-mode": "normal",
  "mask-image": "none",
  "-webkit-mask-image": "none",
  "mask-border-source": "none",
  translate: "none",
  rotate: "none",
  scale: "none",
  perspective: "none",
  clip: "auto",
});

let sequence = 0;

class FakeEvent {
  /** @param {string} type @param {{ bubbles?: boolean }} [init] */
  constructor(type, init = {}) {
    this.type = type;
    this.bubbles = init.bubbles === true;
    this.isTrusted = false;
  }
}

/** The value setter and getter that a real input has on its prototype. */
class FakeHTMLInputElement {
  get value() {
    return /** @type {any} */ (this)._value ?? "";
  }

  set value(next) {
    /** @type {any} */ (this)._value = String(next);
  }
}

export class FakeNode {
  constructor() {
    /** @type {any} */
    this.parentNode = null;
    /** @type {any[]} */
    this.childNodes = [];
    this.seq = sequence++;
  }

  get children() {
    return this.childNodes;
  }

  /** @param {any} child */
  append(child) {
    child.parentNode = this;
    this.childNodes.push(child);
    return child;
  }

  /** @param {any} child */
  remove(child) {
    this.childNodes = this.childNodes.filter((c) => c !== child);
    child.parentNode = null;
  }

  /** All descendant elements in document order, not entering shadow trees. @returns {any[]} */
  descendants() {
    /** @type {any[]} */
    const out = [];
    const visit = (/** @type {any} */ node) => {
      for (const child of node.childNodes) {
        out.push(child);
        visit(child);
      }
    };
    visit(this);
    return out;
  }

  /** @param {string} selector "*" or a tag name */
  querySelectorAll(selector) {
    return this.descendants().filter((e) => selector === "*" || e.localName === selector);
  }

  getRootNode() {
    /** @type {any} */
    let node = this;
    while (node.parentNode) node = node.parentNode;
    return node;
  }
}

export class FakeShadowRoot extends FakeNode {
  /** @param {any} host @param {"open" | "closed"} mode */
  constructor(host, mode) {
    super();
    this.nodeType = 11;
    this.host = host;
    this.mode = mode;
    this.ownerDocument = host.ownerDocument;
  }

  /** @param {number} x @param {number} y */
  elementsFromPoint(x, y) {
    return hitTest(this.ownerDocument, this, x, y);
  }
}

export class FakeElement extends FakeNode {
  /**
   * @param {any} document
   * @param {string} tag
   * @param {Record<string, string>} [attributes]
   */
  constructor(document, tag, attributes = {}) {
    super();
    this.nodeType = 1;
    this.ownerDocument = document;
    this.localName = tag;
    this.attributes = new Map(Object.entries(attributes));
    /** @type {Record<string, string>} */
    this.style = {};
    /** @type {{ left: number, top: number, width: number, height: number } | null} */
    this.rect = null;
    this.z = 0;
    this.hitBlocked = false;
    this.disabled = false;
    this.readOnly = false;
    this.inert = false;
    /** @type {any} */
    this.form = null;
    /** @type {any} */
    this._shadow = null;
    /** @type {Map<string, Array<(event: any) => void>>} */
    this.listeners = new Map();
    /** @type {string[]} */
    this.events = [];
    if (tag === "input") Object.setPrototypeOf(this, FakeInput.prototype);
  }

  get type() {
    return (this.attributes.get("type") ?? (this.localName === "input" ? "text" : "")).toLowerCase();
  }

  /** @param {string} name */
  getAttribute(name) {
    return this.attributes.has(name) ? this.attributes.get(name) : null;
  }

  /** @param {string} name */
  hasAttribute(name) {
    return this.attributes.has(name);
  }

  /** @param {string} name @param {string} value */
  setAttribute(name, value) {
    this.attributes.set(name, value);
  }

  /** Only `:disabled`: the element itself, or a fieldset with the disabled attribute above it. @param {string} selector */
  matches(selector) {
    if (selector !== ":disabled") throw new Error(`the fake page does not know ${selector}`);
    for (let node = this; node && node.nodeType === 1; node = node.parentNode) {
      if (node.disabled === true || (node.localName === "fieldset" && node.hasAttribute("disabled"))) return true;
    }
    return false;
  }

  get parentElement() {
    return this.parentNode && this.parentNode.nodeType === 1 ? this.parentNode : null;
  }

  // A real browser gives the slot; the engine must also manage without it.
  get assignedSlot() {
    return null;
  }

  get shadowRoot() {
    return this._shadow && this._shadow.mode === "open" ? this._shadow : null;
  }

  get openOrClosedShadowRoot() {
    return this._shadow;
  }

  /** @param {{ mode: "open" | "closed" }} init */
  attachShadow({ mode }) {
    this._shadow = new FakeShadowRoot(this, mode);
    return this._shadow;
  }

  get isConnected() {
    const root = this.getRootNode();
    return root.host ? root.host.isConnected : root.nodeType === 9;
  }

  getBoundingClientRect() {
    const r = this.rect ?? { left: 0, top: 0, width: 0, height: 0 };
    return { ...r, right: r.left + r.width, bottom: r.top + r.height };
  }

  /** @param {string} type @param {(event: any) => void} fn */
  addEventListener(type, fn) {
    const list = this.listeners.get(type) ?? [];
    list.push(fn);
    this.listeners.set(type, list);
  }

  /** @param {any} event */
  dispatchEvent(event) {
    /** @type {any} */
    let node = this;
    while (node && node.nodeType === 1) {
      if (node === this || event.bubbles) {
        if (node === this) node.events.push(event.type);
        for (const fn of node.listeners.get(event.type) ?? []) fn(event);
      }
      node = node.parentNode && node.parentNode.nodeType === 11 ? node.parentNode.host : node.parentNode;
    }
    return true;
  }
}

class FakeInput extends FakeElement {}
// The native accessors a real input has, found where the engine looks for them.
const nativeValue = /** @type {PropertyDescriptor} */ (Object.getOwnPropertyDescriptor(FakeHTMLInputElement.prototype, "value"));
Object.defineProperty(FakeInput.prototype, "value", nativeValue);

/** @param {any} document @param {any} root @param {number} x @param {number} y */
function hitTest(document, root, x, y) {
  /** @type {any[]} */
  const all = [];
  const collect = (/** @type {any} */ container) => {
    for (const element of container.descendants()) {
      all.push(element);
      if (element._shadow) collect(element._shadow);
    }
  };
  collect(document);
  const hits = all
    .filter((e) => e.rect && !e.hitBlocked && e.style["pointer-events"] !== "none")
    .filter((e) => x >= e.rect.left && x < e.rect.left + e.rect.width && y >= e.rect.top && y < e.rect.top + e.rect.height)
    .sort((a, b) => b.z - a.z || b.seq - a.seq);
  /** @type {any[]} */
  const out = [];
  for (const hit of hits) {
    /** @type {any} */
    let node = hit;
    while (node && node.getRootNode() !== root) {
      const top = node.getRootNode();
      node = top.host ?? null;
    }
    if (node) out.push(node);
  }
  return out;
}

export class FakeDocument extends FakeNode {
  constructor() {
    super();
    this.nodeType = 9;
    this.ownerDocument = this;
    this.documentElement = new FakeElement(this, "html");
    this.documentElement.clientWidth = 1280;
    this.documentElement.clientHeight = 800;
    this.append(this.documentElement);
    this.body = this.documentElement.append(new FakeElement(this, "body"));
  }

  /** @param {number} x @param {number} y */
  elementsFromPoint(x, y) {
    return hitTest(this, this, x, y);
  }

  /** @param {string} tag @param {Record<string, string>} [attributes] */
  createElement(tag, attributes = {}) {
    return new FakeElement(this, tag, attributes);
  }
}

/**
 * A page: a document and the window object the engine reads.
 * @param {{ url?: string, origin?: string, selfOrigin?: string }} [options] `selfOrigin` is `window.origin` (the page's real origin; "null" in a sandboxed frame)
 */
export function createPage({ url = "https://example.com/login", origin, selfOrigin } = {}) {
  const document = new FakeDocument();
  const parsed = new URL(url);
  const window = {
    origin: selfOrigin ?? origin ?? parsed.origin,
    location: { origin: origin ?? parsed.origin, href: url },
    document,
    crypto: globalThis.crypto,
    innerWidth: 1280,
    innerHeight: 800,
    HTMLInputElement: FakeHTMLInputElement,
    Event: FakeEvent,
    getComputedStyle: (/** @type {FakeElement} */ element) => ({
      getPropertyValue: (/** @type {string} */ name) => element.style[name] ?? /** @type {any} */ (DEFAULT_STYLE)[name] ?? "",
    }),
  };
  return { window, document };
}

/**
 * Adds an input to `parent` with a visible rectangle.
 * @param {any} document
 * @param {any} parent
 * @param {Record<string, string>} attributes
 * @param {{ left?: number, top?: number, width?: number, height?: number } | null} [rect]
 */
export function addInput(document, parent, attributes, rect = {}) {
  const input = document.createElement("input", attributes);
  parent.append(input);
  input.rect = rect === null ? null : { left: 100, top: 100, width: 240, height: 32, ...rect };
  return input;
}

/**
 * A sign-in form with a user name and a password field, one under the other.
 * @param {any} document
 * @param {any} [parent]
 */
export function addLoginForm(document, parent = document.body) {
  const form = parent.append(document.createElement("form", { id: "login" }));
  const user = addInput(document, form, { type: "text", name: "username", id: "user" }, { top: 100 });
  const pass = addInput(document, form, { type: "password", name: "password", id: "pass" }, { top: 160 });
  user.form = form;
  pass.form = form;
  return { form, user, pass };
}

/** The runtime ids the engine needs: the same as the fake browser's. */
export const RUNTIME_ID = EXTENSION_ID;
export const EXTENSION_BASE = `moz-extension://${EXTENSION_UUID}/`;

/** The sender of a message from the extension's background page. */
export const BACKGROUND_SENDER = Object.freeze({ id: RUNTIME_ID, url: `${EXTENSION_BASE}background/main.mjs` });

/**
 * What the engine sent, decoded.
 * @param {string[]} sent
 * @returns {Array<{ type: string, body: any }>}
 */
export function decodeSent(sent) {
  return sent.map((raw) => {
    const { type, body } = decode(raw, CONTENT_TYPES);
    return { type, body };
  });
}

/**
 * A `fill_field` message as the background would send it.
 * @param {{ requestId?: string, field?: string, value?: string, origin?: string, frameUrl?: string }} [options]
 */
export function fillMessage({ requestId = "req-1", field = "password", value = "s3cret", origin = "https://example.com", frameUrl = "https://example.com/login" } = {}) {
  return encode("fill_field", { request_id: requestId, field, value, expect: { origin, frameUrl } });
}

export { PUSH_TYPES };
