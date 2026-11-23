// A small stand-in for the DOM of an extension page, for the unit tests of the
// page modules that build their part with `el()` (the popup's panels): elements
// with attributes, text, children and listeners, a document with the element
// that has the focus, and the steps a person takes (a click, which a disabled
// button does not get, typing, a submit). No jsdom. Not a test file (the runner
// picks up *.test.mjs only).

class FakeNode {
  /** @param {number} nodeType */
  constructor(nodeType) {
    this.nodeType = nodeType;
    /** @type {FakeElement | null} */
    this.parentNode = null;
    /** @type {FakeNode[]} */
    this.childNodes = [];
  }

  get firstChild() {
    return this.childNodes[0] ?? null;
  }

  /** @param {FakeNode} child */
  appendChild(child) {
    child.parentNode?.removeChild(child);
    child.parentNode = /** @type {any} */ (this);
    this.childNodes.push(child);
    return child;
  }

  /** @param {FakeNode} child */
  removeChild(child) {
    this.childNodes = this.childNodes.filter((c) => c !== child);
    child.parentNode = null;
    return child;
  }

  remove() {
    this.parentNode?.removeChild(this);
  }

  /** @returns {string} */
  get textContent() {
    return this.childNodes.map((c) => c.textContent).join("");
  }
}

class FakeText extends FakeNode {
  /** @param {string} data */
  constructor(data) {
    super(3);
    this.data = data;
  }

  get textContent() {
    return this.data;
  }
}

export class FakeElement extends FakeNode {
  /** @param {any} doc @param {string} tagName */
  constructor(doc, tagName) {
    super(1);
    this.doc = doc;
    this.tagName = tagName.toUpperCase();
    /** @type {Map<string, string>} */
    this.attributes = new Map();
    /** @type {Array<[string, (event: any) => void]>} */
    this.listeners = [];
    this.value = "";
    const element = this;
    this.classList = {
      /** @param {string} name */
      add(name) {
        const names = new Set((element.getAttribute("class") ?? "").split(/\s+/).filter(Boolean));
        names.add(name);
        element.setAttribute("class", [...names].join(" "));
      },
      /** @param {string} name */
      remove(name) {
        const names = (element.getAttribute("class") ?? "").split(/\s+/).filter((n) => n !== "" && n !== name);
        element.setAttribute("class", names.join(" "));
      },
      /** @param {string} name */
      contains: (name) => (element.getAttribute("class") ?? "").split(/\s+/).includes(name),
    };
  }

  get textContent() {
    return super.textContent;
  }

  set textContent(text) {
    for (const child of [...this.childNodes]) this.removeChild(child);
    if (text !== "") this.appendChild(new FakeText(String(text)));
  }

  /** @param {...(FakeNode | string)} nodes */
  append(...nodes) {
    for (const node of nodes) this.appendChild(typeof node === "string" ? new FakeText(node) : node);
  }

  /** @param {string} name @param {string} value */
  setAttribute(name, value) {
    this.attributes.set(name, String(value));
  }

  /** @param {string} name */
  getAttribute(name) {
    return this.attributes.get(name) ?? null;
  }

  /** @param {string} name */
  hasAttribute(name) {
    return this.attributes.has(name);
  }

  /** @param {string} name */
  removeAttribute(name) {
    this.attributes.delete(name);
  }

  get hidden() {
    return this.attributes.has("hidden");
  }

  set hidden(value) {
    if (value) this.attributes.set("hidden", "");
    else this.attributes.delete("hidden");
  }

  /** @param {string} type @param {(event: any) => void} fn */
  addEventListener(type, fn) {
    this.listeners.push([type, fn]);
  }

  focus() {
    this.doc.activeElement = this;
  }
}

/** A document with an `activeElement`, set as the global one. */
export function useDocument() {
  const doc = {
    /** @type {FakeElement | null} */
    activeElement: null,
    /** @param {string} tag */
    createElement: (tag) => new FakeElement(doc, tag),
    /** @param {string} data */
    createTextNode: (data) => new FakeText(data),
  };
  /** @type {any} */ (globalThis).document = doc;
  return doc;
}

/**
 * Every element below `root` (and `root`) whose `data-role` is `role`.
 * @param {any} root @param {string} role @returns {FakeElement[]}
 */
export function byRole(root, role) {
  /** @type {FakeElement[]} */
  const out = [];
  const walk = (/** @type {FakeNode} */ n) => {
    if (n instanceof FakeElement && n.getAttribute("data-role") === role) out.push(n);
    for (const c of n.childNodes) walk(c);
  };
  walk(root);
  return out;
}

/** The one element with `data-role` `role` below `root`, or null. @param {any} root @param {string} role */
export const one = (root, role) => byRole(root, role)[0] ?? null;

/** Every element below `root` that carries `attribute`. @param {any} root @param {string} attribute @returns {FakeElement[]} */
export function withAttribute(root, attribute) {
  /** @type {FakeElement[]} */
  const out = [];
  const walk = (/** @type {FakeNode} */ n) => {
    if (n instanceof FakeElement && n.hasAttribute(attribute)) out.push(n);
    for (const c of n.childNodes) walk(c);
  };
  walk(root);
  return out;
}

/** Lets the handlers that a step started run to their end (they wait for the background). */
export async function settle() {
  for (let i = 0; i < 20; i += 1) await new Promise((resolve) => setTimeout(resolve, 0));
}

/**
 * An event on `target` for its own listeners, as the browser gives it; a disabled control gets no click.
 * @param {FakeElement | null} target @param {string} type
 */
export function fire(target, type) {
  if (target === null) throw new Error(`no element to ${type}`);
  if (type === "click" && target.hasAttribute("disabled")) return null;
  const event = {
    type,
    target,
    defaultPrevented: false,
    preventDefault() {
      event.defaultPrevented = true;
    },
  };
  for (const [t, fn] of target.listeners) if (t === type) fn(event);
  return event;
}

/** A click, and what it started. @param {FakeElement | null} target */
export async function click(target) {
  fire(target, "click");
  await settle();
}

/** Submits a form, and what it started. @param {FakeElement | null} form */
export async function submit(form) {
  fire(form, "submit");
  await settle();
}

/**
 * The texts of a language from the built package's catalog, as the pages get them (`texts.t`), with `{name}` filled.
 * @param {Record<string, string>} catalog @param {string} lang
 */
export function textsOf(catalog, lang) {
  return {
    lang,
    /** @param {string} key @param {Record<string, string | number>} [vars] */
    t: (key, vars = {}) => {
      const text = catalog[key];
      if (typeof text !== "string") throw new Error(`no text for ${key}`);
      return text.replace(/\{(\w+)\}/g, (all, name) => (name in vars ? String(vars[name]) : all));
    },
  };
}
