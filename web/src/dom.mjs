// DOM helpers. The vault never builds markup from strings: elements are made
// with `el()`, text always goes in as a text node, and an attribute outside
// the allow-list is a TypeError, so a mistake cannot become an injection.

const ATTRIBUTES = new Set([
  "class", "id", "type", "name", "value", "href", "for", "role", "placeholder",
  "autocomplete", "disabled", "hidden", "tabindex", "title", "lang", "dir", "rel",
  "accept", "inputmode", "maxlength", "min", "max", "step", "rows", "checked",
  "selected", "readonly", "required",
]);

const PREFIXED = /^(?:aria|data)-[a-z0-9][a-z0-9._-]*$/;
const EVENT = /^on[a-z]+$/;
const TAG = /^[a-z][a-z0-9-]*$/;

// Elements that load code or styles, change how the page is parsed, or escape
// the HTML namespace. None of them is ever needed to build the interface.
const FORBIDDEN_TAGS = new Set([
  "script", "style", "iframe", "frame", "frameset", "object", "embed", "applet",
  "link", "meta", "base", "noscript", "template", "svg", "math",
]);

/** @param {unknown} value @returns {value is Node} */
function isNode(value) {
  return typeof value === "object" && value !== null && typeof (/** @type {any} */ (value).nodeType) === "number";
}

/**
 * Only an in-page anchor or a path on this origin: no scheme, no `//host`.
 * @param {unknown} value
 */
function checkHref(value) {
  const ok =
    typeof value === "string" &&
    !/[\u0000-\u001f\u007f\\]/.test(value) &&
    (value.startsWith("#") || (value.startsWith("/") && !value.startsWith("//")));
  if (!ok) throw new TypeError("el: href must be #... or a path starting with a single /");
}

/**
 * @param {Element} node
 * @param {string} name
 * @param {unknown} value
 */
function applyAttribute(node, name, value) {
  if (name.startsWith("on")) {
    if (typeof value === "function" && EVENT.test(name)) {
      node.addEventListener(name.slice(2), /** @type {EventListener} */ (value));
      return;
    }
    if (value === null && EVENT.test(name)) return;
    throw new TypeError(`el: ${name} needs a function value`);
  }
  if (!ATTRIBUTES.has(name) && !PREFIXED.test(name)) {
    throw new TypeError(`el: attribute not allowed: ${name}`);
  }
  if (value === null || value === false) return;
  if (typeof value !== "string" && typeof value !== "number" && value !== true) {
    throw new TypeError(`el: attribute ${name} needs a string, number or boolean`);
  }
  if (name === "href") checkHref(value);
  node.setAttribute(name, value === true ? "" : String(value));
}

/**
 * Makes an element. Strings in `children` become text nodes.
 * @param {string} tag
 * @param {Record<string, string | number | boolean | null | ((e: Event) => void)> | null} [attrs]
 * @param {...(Node | string | number | null | false | undefined)} children
 * @returns {HTMLElement}
 */
export function el(tag, attrs, ...children) {
  if (typeof tag !== "string" || !TAG.test(tag) || FORBIDDEN_TAGS.has(tag)) {
    throw new TypeError(`el: tag not allowed: ${String(tag)}`);
  }
  if (attrs !== undefined && attrs !== null && (typeof attrs !== "object" || isNode(attrs))) {
    throw new TypeError("el: the second argument is an attribute object or null");
  }
  const node = document.createElement(tag);
  for (const [name, value] of Object.entries(attrs ?? {})) applyAttribute(node, name, value);
  for (const child of children) {
    if (child === null || child === false || child === undefined) continue;
    if (typeof child === "string" || typeof child === "number") {
      node.appendChild(document.createTextNode(String(child)));
    } else if (isNode(child)) {
      node.appendChild(child);
    } else {
      throw new TypeError("el: a child is a node, a string, a number or empty");
    }
  }
  return node;
}

/** Removes every child of `node`. @param {Node} node */
export function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

/** Replaces the children of `root` with `nodes`. @param {Node} root @param {...Node} nodes */
export function mount(root, ...nodes) {
  clear(root);
  for (const node of nodes) root.appendChild(node);
}
