// What the fields and forms of a page are for: the one detection module of the
// content scripts (the fill engine reads it; the capture script will too). It
// reads the page and changes nothing, holds no value of the page, and decides
// nothing about origins or visibility: the caller says which fields the user
// can see (`shown`), and the fill engine still checks each field again when it
// fills.
//
// A field (`classifyField`) is one of FIELD_KINDS. The `autocomplete` token the
// page gives decides first (`one-time-code`, `current-password`,
// `new-password`, `username`, `email`, the `cc-*` tokens and the tokens of
// personal data). Without one that says it, the words of the field decide:
// its name, id, label, `aria-label`, `placeholder` and `title`, in English,
// Norwegian, German, French and Dutch (patterns.mjs), with its type and its
// shape (a short numeric field). The rules that matter for safety:
//
// - a card's security code, a PIN and a one-time code are never a password,
//   also when the page makes them `type=password`;
// - a search box is never a user name, nor is a name, address, phone, coupon
//   or card field;
// - a password field that repeats, or sets, a new password is never the
//   account's password.
//
// A group (`findGroups`) is the fields of one form (or, without a form, the
// fields of the nearest container that holds more than one of them; on the
// whole page only fields named for what they are), with one of GROUP_KINDS:
//
//   login       a password in use (and maybe a user name and a code)
//   change      the password in use and a new one
//   signup      a new password, no password in use, and a user name or e-mail
//   reset       a new password and no user name
//   identifier  a user name step without a password the user can see
//   otp         one-time code fields only (one field, or split boxes)
//   none        anything else: card and PIN forms, newsletters, contact forms
//
// Split one-time codes (4 to 8 boxes of one character in a row) are one
// field of the group: `otp` is then the list of boxes.

import {
  CARD, CARD_FIELD, COUPON, CONFIRM, CURRENT, CVC, EMAIL, LOGIN, NAME, NEW, NEXT, NOT_LOGIN, OTP, OTP_WEAK,
  PASSWORD, PHONE, PIN, RESET, SEARCH, SHOW, SIGNUP, SUBMIT, SUBMIT_WORDS, USERNAME, normalize,
} from "./patterns.mjs";

export { SUBMIT_WORDS };

export const FIELD_KINDS = Object.freeze([
  "username", "email", "current_password", "new_password", "confirm_password", "otp", "otp_digit", "search",
  "card_number", "card_cvc", "pin", "other",
]);

export const GROUP_KINDS = Object.freeze(["login", "signup", "change", "reset", "identifier", "otp", "none"]);

/** The input types that hold text a person types. */
export const TEXT_TYPES = Object.freeze(new Set(["text", "email", "tel", "number", "search", "url"]));
/** Bounds that stop a hostile page from making the walks run long. */
const MAX_NODES = 20_000;
const MAX_DEPTH = 1_000;
/** The most fields of one page that are classified. */
const MAX_FIELDS = 500;
/** The longest text read from one label, button or heading. */
const MAX_TEXT = 200;
/** A split code has this many boxes. */
const SPLIT_MIN = 4;
const SPLIT_MAX = 8;

/** Autocomplete tokens that only qualify the field name (HTML, "autofill detail tokens"). */
const QUALIFIERS = new Set(["shipping", "billing", "home", "work", "mobile", "fax", "pager", "webauthn"]);
/** Autocomplete field names of personal data that is never a user name. */
const PERSONAL = /^(?:name|honorific-prefix|given-name|additional-name|family-name|honorific-suffix|nickname|organization-title|organization|street-address|address-line\d|address-level\d|country|country-name|postal-code|bday.*|sex|tel.*|url|photo|language|transaction-.*|impp)$/;

/** @param {any} node */
export const isElement = (node) => typeof node === "object" && node !== null && node.nodeType === 1;

/**
 * The shadow root of an element, open or closed (Firefox lets a content script
 * see closed ones), or null.
 * @param {any} element
 */
export function shadowOf(element) {
  return element.openOrClosedShadowRoot ?? element.shadowRoot ?? null;
}

/** The parent of a child of a shadow host that no slot takes: the browser does not draw it. */
export const UNRENDERED = Symbol("unrendered");

/**
 * The parent of a node in the flat tree, which is the tree the page is drawn
 * from: a slotted node's parent is its slot, and a shadow root's parent is its
 * host. Null at the top. UNRENDERED for a child of a shadow host that has no
 * slot for it.
 *
 * @param {any} node
 * @returns {any}
 */
export function flatParent(node) {
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
 * Whether `node` is `container` or lies inside it, in the flat tree.
 * @param {any} container
 * @param {any} node
 */
export function isInside(container, node) {
  for (let n = node, depth = 0; n && n !== UNRENDERED && depth <= MAX_DEPTH; n = flatParent(n), depth += 1) {
    if (n === container) return true;
  }
  return false;
}

/** @param {any} element @param {string} name */
const attr = (element, name) => {
  const value = element.getAttribute(name);
  return typeof value === "string" ? value : "";
};

/** The text of a node, bounded. @param {any} node */
function textOf(node) {
  try {
    const text = node?.textContent;
    return typeof text === "string" ? text.slice(0, MAX_TEXT) : "";
  } catch {
    return "";
  }
}

/** @param {any} element @returns {string} the input's type, lower case */
const typeOf = (element) => String(element.type ?? "").toLowerCase();

/** @param {any} element @returns {string[]} */
export function autocompleteTokens(element) {
  return attr(element, "autocomplete").toLowerCase().split(/\s+/).filter(Boolean);
}

/** The field name of the autocomplete attribute (the last token that is not a qualifier), or "". @param {any} element */
function autocompleteField(element) {
  const tokens = autocompleteTokens(element).filter((t) => !t.startsWith("section-") && !QUALIFIERS.has(t));
  return tokens.at(-1) ?? "";
}

/**
 * The words that say what a field is for: its name, id, label, `aria-label`,
 * `aria-labelledby`, `placeholder` and `title`, as patterns.mjs compares them.
 * @param {any} element
 */
export function hintsOf(element) {
  const parts = ["name", "id", "aria-label", "placeholder", "title"].map((a) => attr(element, a));
  try {
    for (const label of element.labels ?? []) parts.push(textOf(label));
  } catch {
    // No labels to read.
  }
  const labelledBy = attr(element, "aria-labelledby").split(/\s+/).filter(Boolean).slice(0, 4);
  if (labelledBy.length > 0) {
    try {
      const root = element.getRootNode();
      for (const id of labelledBy) parts.push(textOf(root.getElementById?.(id)));
    } catch {
      // A root without ids.
    }
  }
  return normalize(parts.join(" "));
}

/**
 * Whether a text input is part of a site search rather than a sign-in: its
 * type is `search`, its role is `searchbox`, its name is `q`, its words say
 * so, or it lies in a `<search>` element or an element (its form too) with
 * `role="search"`.
 * @param {any} element
 * @param {string} [hints]
 */
export function isSearchField(element, hints = hintsOf(element)) {
  if (typeOf(element) === "search") return true;
  if (attr(element, "role").toLowerCase() === "searchbox") return true;
  if (attr(element, "name").toLowerCase() === "q") return true;
  if (SEARCH.test(hints)) return true;
  const form = element.form;
  if (isElement(form) && attr(form, "role").toLowerCase() === "search") return true;
  for (let node = flatParent(element), depth = 0; node && node !== UNRENDERED && depth <= MAX_DEPTH; node = flatParent(node), depth += 1) {
    if (node.localName === "search" || attr(node, "role").toLowerCase() === "search") return true;
  }
  return false;
}

/** The `maxlength` the page set, or null. @param {any} element */
function maxLengthOf(element) {
  const raw = attr(element, "maxlength").trim();
  if (!/^\d{1,6}$/.test(raw)) return null;
  return Number(raw);
}

/**
 * Whether a field is shaped for a short number: a numeric keyboard, a pattern of digits, or the type `number` or
 * `tel`, and room for at most 8 characters when the page says how many.
 * @param {any} element
 */
function isShortNumeric(element) {
  const mode = attr(element, "inputmode").toLowerCase();
  const pattern = attr(element, "pattern");
  const numeric = mode === "numeric" || mode === "decimal" || /^(?:\[0-9\]|\\d)(?:\{\d+(?:,\d*)?\}|\+|\*)?$/.test(pattern) || ["number", "tel"].includes(typeOf(element));
  const max = maxLengthOf(element);
  return numeric && (max === null || max <= 8);
}

/** A one-time-code field, or one box of a split code. @param {any} element */
const codeKind = (element) => (maxLengthOf(element) === 1 ? "otp_digit" : "otp");

/**
 * What one field is for.
 * @param {any} element an input
 * @param {{ hints?: string }} [ctx] `hints`: the field's words, when the caller has them already
 * @returns {{ kind: string, reasons: string[] }}
 */
export function classifyField(element, ctx = {}) {
  if (!isElement(element) || element.localName !== "input") return { kind: "other", reasons: ["not_input"] };
  const type = typeOf(element);
  const password = type === "password";
  if (!password && !TEXT_TYPES.has(type)) return { kind: "other", reasons: ["type"] };
  const hints = ctx.hints ?? hintsOf(element);
  if (!password && isSearchField(element, hints)) return { kind: "search", reasons: ["search"] };

  // The page's own token decides first.
  const token = autocompleteField(element);
  if (token === "one-time-code") return { kind: codeKind(element), reasons: ["autocomplete"] };
  if (token === "cc-csc") return { kind: "card_cvc", reasons: ["autocomplete"] };
  if (token === "cc-number") return { kind: "card_number", reasons: ["autocomplete"] };
  if (token.startsWith("cc-")) return { kind: "other", reasons: ["autocomplete", "card"] };
  if (password) {
    if (token === "current-password") return { kind: "current_password", reasons: ["autocomplete"] };
    if (token === "new-password") return { kind: CONFIRM.test(hints) ? "confirm_password" : "new_password", reasons: ["autocomplete"] };
  } else {
    if (token === "username") return { kind: "username", reasons: ["autocomplete", ...(USERNAME.test(hints) ? ["word"] : [])] };
    if (token === "email") return { kind: "email", reasons: ["autocomplete"] };
    if (token === "current-password" || token === "new-password") return { kind: "other", reasons: ["autocomplete", "password_text"] };
    if (PERSONAL.test(token)) return { kind: "other", reasons: ["autocomplete", "personal"] };
  }

  // Then the words, the type and the shape.
  if (COUPON.test(hints)) return { kind: "other", reasons: ["coupon"] };
  if (CVC.test(hints)) return { kind: "card_cvc", reasons: ["word"] };
  if (CARD.test(hints)) return { kind: "card_number", reasons: ["word"] };
  if (CARD_FIELD.test(hints)) return { kind: "other", reasons: ["word", "card"] };
  if (PIN.test(hints)) return { kind: "pin", reasons: ["word"] };
  const passwordWord = PASSWORD.test(hints);
  const oneTimePassword = /one time password|engangspassord|einmalpasswort/.test(hints);
  if (OTP.test(hints) && (!passwordWord || oneTimePassword)) return { kind: codeKind(element), reasons: ["word"] };
  if (OTP_WEAK.test(hints) && isShortNumeric(element) && !passwordWord && !USERNAME.test(hints)) return { kind: codeKind(element), reasons: ["word", "numeric"] };

  if (password) {
    // A masked short number is a PIN: a site's password field never asks for a numeric keyboard or digits only.
    if (isShortNumeric(element)) return { kind: "pin", reasons: ["numeric"] };
    if (CONFIRM.test(hints)) return { kind: "confirm_password", reasons: ["word"] };
    if (NEW.test(hints)) return { kind: "new_password", reasons: ["word"] };
    if (CURRENT.test(hints)) return { kind: "current_password", reasons: ["word"] };
    return { kind: "current_password", reasons: ["default"] };
  }

  if (USERNAME.test(hints)) return { kind: "username", reasons: ["word"] };
  if (EMAIL.test(hints) || type === "email") return { kind: "email", reasons: [EMAIL.test(hints) ? "word" : "type"] };
  if (PHONE.test(hints) || type === "tel") return { kind: "other", reasons: ["phone"] };
  if (NAME.test(hints)) return { kind: "other", reasons: ["name"] };
  if (passwordWord) return { kind: "other", reasons: ["password_text"] };
  if (type === "number" || type === "url") return { kind: "other", reasons: ["type"] };
  return { kind: "other", reasons: ["unnamed"] };
}

/**
 * @typedef {{ element: any, kind: string, reasons: string[], order: number, shown: boolean, password: boolean }} Field
 * @typedef {{
 *   kind: string,
 *   form: any,
 *   username?: any, email?: any, current?: any, password?: any, new?: any, confirm?: any, otp?: any,
 *   submit?: any,
 *   fields: Field[],
 * }} Group `fields`: every classified field of the group, in document order
 */

/** The text of a submit control or a button. @param {any} element */
function controlText(element) {
  const value = element.localName === "input" ? attr(element, "value") : textOf(element);
  return normalize([value, attr(element, "aria-label"), attr(element, "title")].join(" "));
}

/** Whether a button or an input sends its form. @param {any} element */
function isSubmitControl(element) {
  const type = attr(element, "type").toLowerCase();
  if (element.localName === "button") return type === "" || type === "submit";
  return element.localName === "input" && (type === "submit" || type === "image");
}

/**
 * Whether a control shows or hides a password rather than sending the form: its words say so, or it sits in the
 * wrapper of a password field (its parent holds that field and no other, and is not the form) and has no word of a
 * submit control.
 * @param {any} control @param {Field[]} members
 */
function isToggle(control, members) {
  const text = controlText(control);
  if (SHOW.test(text)) return true;
  if (SUBMIT.test(text)) return false;
  const wrapper = control.parentElement;
  if (!isElement(wrapper) || wrapper.localName === "form" || wrapper.localName === "body") return false;
  return members.some((f) => f.password && isInside(wrapper, f.element)) && !members.some((f) => !f.password && isInside(wrapper, f.element));
}

/** Whether an element is a control a person clicks (a button, or an input of a button type). @param {any} element */
function isControl(element) {
  if (element.localName === "button") return true;
  return element.localName === "input" && ["submit", "image", "button"].includes(attr(element, "type").toLowerCase());
}

/**
 * Walks every element of `root` in document order, through shadow roots, up to `maxNodes`.
 * @param {any} root @param {number} maxNodes @param {(element: any) => void} visit
 */
function walk(root, maxNodes, visit) {
  let seen = 0;
  /** @param {any} node */
  const go = (node) => {
    for (const element of node.querySelectorAll("*")) {
      seen += 1;
      if (seen > maxNodes) return;
      visit(element);
      const inner = shadowOf(element);
      if (inner) go(inner);
    }
  };
  go(root);
}

/**
 * The groups of a page, in document order.
 * @param {any} root a document (or a shadow root)
 * @param {{ maxNodes?: number, shown?: (element: any) => boolean }} [options] `shown`: whether the user can see a field
 *   (the caller's visibility rules); a field that is not shown takes no role, but still says what its form is
 * @returns {Group[]}
 */
export function findGroups(root, { maxNodes = MAX_NODES, shown = () => true } = {}) {
  /** @type {any[]} */
  const inputs = [];
  /** @type {any[]} */
  const controls = [];
  /** @type {any[]} */
  const areas = [];
  /** @type {any[]} */
  const headings = [];
  walk(root, maxNodes, (element) => {
    const name = element.localName;
    if (name === "input") {
      const type = typeOf(element);
      if (type === "password" || TEXT_TYPES.has(type)) {
        if (inputs.length < MAX_FIELDS) inputs.push(element);
      } else if (isControl(element)) {
        controls.push(element);
      }
    } else if (name === "button") {
      controls.push(element);
    } else if (name === "textarea") {
      areas.push(element);
    } else if (name === "h1" || name === "h2" || name === "h3" || name === "legend") {
      headings.push(element);
    }
  });

  /** @type {Field[]} */
  const fields = inputs.map((element, order) => {
    const { kind, reasons } = classifyField(element);
    let visible = false;
    try {
      visible = shown(element) === true;
    } catch {
      visible = false;
    }
    return { element, kind, reasons, order, shown: visible, password: typeOf(element) === "password" };
  });

  // The container of a field without a form: the nearest ancestor that holds another field without a form.
  const loose = fields.filter((f) => !isElement(f.element.form));
  /** @type {Map<Field, any>} */
  const containerOf = new Map();
  for (const field of loose) {
    let container = null;
    for (let node = flatParent(field.element), depth = 0; node && node !== UNRENDERED && depth <= MAX_DEPTH; node = flatParent(node), depth += 1) {
      if (loose.some((other) => other !== field && isInside(node, other.element))) {
        container = node;
        break;
      }
    }
    containerOf.set(field, container ?? field.element);
  }

  /** @type {Map<any, Field[]>} */
  const byKey = new Map();
  for (const field of fields) {
    const key = isElement(field.element.form) ? field.element.form : containerOf.get(field);
    const list = byKey.get(key) ?? [];
    list.push(field);
    byKey.set(key, list);
  }

  const document = root.ownerDocument ?? root;
  const title = normalize(typeof document.title === "string" ? document.title : "");
  const firstHeading = headings.find((h) => h.localName === "h1") ?? headings[0];
  const pageText = `${title} ${firstHeading ? normalize(textOf(firstHeading)) : ""}`;

  /** @type {Group[]} */
  const groups = [];
  for (const [key, members] of byKey) {
    const form = isElement(members[0].element.form) ? key : null;
    const wholePage = form === null && (key === document.body || key === document.documentElement);
    const inGroup = (/** @type {any} */ element) =>
      form !== null ? element.form === form || isInside(form, element) : key !== members[0].element && isInside(key, element);
    const own = controls.filter(inGroup).filter((control) => !isToggle(control, members));
    const submit = own.find(isSubmitControl) ?? own.find((control) => SUBMIT.test(controlText(control)));
    const context = {
      submit: own.map(controlText).join(" ").slice(0, 600),
      form: form !== null ? normalize(["id", "name", "aria-label", "class"].map((a) => attr(form, a)).concat(headings.filter((h) => isInside(form, h)).map(textOf)).join(" ")) : normalize(headings.filter((h) => !wholePage && inGroup(h)).map(textOf).join(" ")),
      page: pageText,
      areas: areas.some(inGroup),
    };
    groups.push(decide(form, members, wholePage, context, submit));
  }
  groups.sort((a, b) => (a.fields[0]?.order ?? 0) - (b.fields[0]?.order ?? 0));
  return groups;
}

/**
 * The runs of split code boxes in a group: 4 to 8 fields in a row of one character each, numeric or marked as a code.
 * Their fields become `otp_digit`.
 * @param {Field[]} members
 * @returns {Field[][]}
 */
function splitRuns(members) {
  /** @type {Field[][]} */
  const runs = [];
  /** @type {Field[]} */
  let run = [];
  const close = () => {
    if (run.length >= SPLIT_MIN && run.length <= SPLIT_MAX && run.some((f) => f.kind === "otp_digit" || f.kind === "otp" || isShortNumeric(f.element))) runs.push(run);
    run = [];
  };
  for (const field of members) {
    const box = maxLengthOf(field.element) === 1 && ["otp", "otp_digit", "other", "pin", "current_password"].includes(field.kind);
    if (box) run.push(field);
    else close();
  }
  close();
  for (const r of runs) for (const f of r) f.kind = "otp_digit";
  return runs;
}

/**
 * The kind of one group and the field of each role.
 * @param {any} form @param {Field[]} members @param {boolean} wholePage
 * @param {{ submit: string, form: string, page: string, areas: boolean }} context
 * @param {any} submit
 * @returns {Group}
 */
function decide(form, members, wholePage, context, submit) {
  const runs = splitRuns(members);
  /** @type {Group} */
  const group = { kind: "none", form, fields: members, ...(submit ? { submit } : {}) };
  const visible = members.filter((f) => f.shown);
  const passwords = visible.filter((f) => f.password && ["current_password", "new_password", "confirm_password"].includes(f.kind));
  const anyPasswordInput = members.some((f) => f.password && ["current_password", "new_password", "confirm_password"].includes(f.kind));
  const users = visible.filter((f) => f.kind === "username" || f.kind === "email");
  const anyUser = members.some((f) => f.kind === "username" || f.kind === "email");
  const email = visible.find((f) => f.kind === "email");
  if (email) group.email = email.element;

  // Card and PIN forms are never sign-in forms for a fill.
  if (members.some((f) => f.kind === "card_cvc" || f.kind === "card_number" || f.kind === "pin" || f.reasons.includes("card"))) return group;

  const code = () => {
    const run = runs.find((r) => r.every((f) => f.shown && !f.password));
    if (run) return run.map((f) => f.element);
    const single = visible.find((f) => f.kind === "otp" && !f.password);
    return single?.element;
  };

  /** The user name of a sign-in: the last user name or e-mail field before `anchor`, else the first after it, else (not
   * on the whole page) the last unnamed text field before it. @param {Field} anchor */
  const userFor = (anchor) => {
    const before = users.filter((f) => f.order < anchor.order);
    const named = before.at(-1) ?? users.find((f) => f.order > anchor.order);
    if (named) return named.element;
    if (wholePage) return undefined;
    return visible.filter((f) => f.order < anchor.order && f.kind === "other" && f.reasons.includes("unnamed") && !f.password).at(-1)?.element;
  };

  const resetWords = RESET.test(context.submit) || RESET.test(context.form);

  if (passwords.length >= 2 && passwords.length <= 3) {
    const explicit = (/** @type {Field} */ f) => f.kind !== "current_password" || !f.reasons.includes("default");
    let current = passwords.find((f) => f.kind === "current_password" && explicit(f));
    // Three password fields: the first is the password in use when nothing says otherwise.
    if (!current && passwords.length === 3 && passwords[0].kind === "current_password") current = passwords[0];
    const rest = passwords.filter((f) => f !== current);
    const fresh = rest.find((f) => f.kind === "new_password") ?? rest.find((f) => f.kind !== "confirm_password");
    const again = rest.find((f) => f !== fresh);
    if (fresh) group.new = fresh.element;
    if (again) group.confirm = again.element;
    if (current) {
      group.kind = "change";
      group.current = current.element;
      const user = userFor(current);
      if (user) group.username = user;
      return group;
    }
    group.kind = resetWords || !anyUser ? "reset" : "signup";
    const user = users[0];
    if (user) group.username = user.element;
    return group;
  }

  if (passwords.length >= 1) {
    const [first] = passwords;
    if (first.kind === "new_password" || first.kind === "confirm_password") {
      group.new = first.element;
      group.kind = resetWords || !anyUser ? "reset" : "signup";
      if (users[0]) group.username = users[0].element;
      return group;
    }
    // One password in use (or more than three fields, where nothing can be told apart: the first one).
    let kind = "login";
    if (passwords.length === 1 && first.reasons.includes("default")) {
      const login = LOGIN.test(context.submit);
      if (SIGNUP.test(context.submit) && !login) kind = "signup";
      else if (!login && RESET.test(context.submit)) kind = "reset";
      else if (!login && SIGNUP.test(context.form) && !LOGIN.test(context.form)) kind = "signup";
      else if (!login && !LOGIN.test(context.form) && SIGNUP.test(context.page) && !LOGIN.test(context.page)) kind = "signup";
    }
    if (kind !== "login") {
      group.kind = kind;
      group.new = first.element;
      if (users[0]) group.username = users[0].element;
      return group;
    }
    group.kind = "login";
    group.password = first.element;
    const user = userFor(first);
    if (user) group.username = user;
    const otp = code();
    if (otp) group.otp = otp;
    return group;
  }

  // No password the user can see.
  if (users.length === 1) {
    const [user] = users;
    const others = visible.filter((f) => f !== user && (f.kind === "other" || f.kind === "username" || f.kind === "email") && !f.password);
    const cue =
      anyPasswordInput ||
      LOGIN.test(context.submit) ||
      NEXT.test(context.submit) ||
      LOGIN.test(context.form) ||
      LOGIN.test(context.page) ||
      (user.kind === "username" && user.reasons.includes("word"));
    const veto = NOT_LOGIN.test(context.submit) || SIGNUP.test(context.submit) || NOT_LOGIN.test(context.form) || context.areas || others.length > 0;
    if (cue && !veto) {
      group.kind = "identifier";
      group.username = user.element;
      return group;
    }
  }
  const otp = code();
  if (otp && users.length === 0) {
    group.kind = "otp";
    group.otp = otp;
  }
  return group;
}
