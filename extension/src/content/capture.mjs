// The capture script: it runs in every https page and frame once the user has switched on "Offer to save
// passwords", watches for the moment a person submits a sign-in, sign-up, change or reset form, and reports what the
// person typed so that the extension can offer to save it. It reads the page and changes nothing: no element, no
// attribute, no marker, no request, no `postMessage`, no storage. Everything it knows about forms comes from the
// detection module of the fill engine (forms.mjs), which the entry hands in as `forms`.
//
// What it sends (one message type each, built by the entry; nothing is ever sent back to it):
//
//   page_ready    a visible password field is on the page. Sent at most once per sign-in attempt, and never on a page
//                 without such a field. The extension uses it to tell a failed sign-in (the form is back) from a
//                 successful one.
//   form_capture  a form was submitted: its kind, the user name, and the password (or, in a change form, the new one and
//                 the one in use) that the person typed.
//   form_gone     after a capture the password field was removed or hidden (not merely covered) at two checks in a row, and no
//                 password field the person can see has come back; if one does come back, page_ready is sent instead.
//
// Rules for what counts as typed (the page is not trusted):
//
// - A password counts only when its last change was an `input` event the browser made for the person (`isTrusted`:
//   typing, paste, drop and the browser's own autofill), the value is read in that capture-phase listener, and it is
//   the same value when the form is read after the page's own handlers have run. A value the page set, replaced or
//   changed after the last typing is dropped, and so is a field whose last input event came from a script. A key press
//   never counts: a page can cancel the key and write the value itself.
// - A user name may come from the page (a field that was filled in already; `username_from: "page"`). A step that asks
//   for the user name only (`identifier`) is sent when the person typed the name, with both passwords null: it is the one
//   message on a page with no password field, and it never leads to an offer by itself.
// - A sign-up, change or reset form whose new password is in its field but did not come from the person's typing (the
//   extension filled it) is sent with `password: null` and `current_password: null`, a request to join the form to the
//   password the extension generated for it; no value the page could have set goes up. A sign-in form is never sent so.
// - Only fields the person could see count (a hidden, honeypot, zero-size, off-screen, covered or `aria-hidden` field
//   takes no role); the detection module gives roles to the fields passed by `shown` only.
// - A submission is a trusted `submit` event, a trusted click on a submit control or on an element with the submit words
//   of patterns.mjs, or a trusted Enter in a field. A control that shows or hides the password, or that sits in the
//   password field's wrapper, never counts. The page is looked at in the trigger itself (this script's listener is on the
//   window, in the capture phase, and runs before the page's own handlers): which groups and fields the person could see
//   is decided there, so a form that the page hides, replaces or covers in its own submit or click handler is still the
//   form the person submitted. The values are read one task later, after the page's handlers, and must be what the person
//   typed; the triggers of one burst are one submission. At most one capture per frame in two seconds, and a step that asks for the user name only has
//   a gap of its own (the newer one is dropped, so a mis-detected early trigger can cost the real submission that follows
//   within two seconds, but the password step that follows an identifier step on the same page is not lost). The groups a
//   trigger belongs to are found in the trigger too, for a page that removes the fields from their wrapper in its handler.
// - A value over the size limits drops the capture (a password over 1 024 characters), or the user name (over 512).
//
// Limits that are accepted and stated: a page's own listener on the window in the capture phase runs before this one (it is
// registered earlier) and can rewrite a value inside the trusted event before it is read, or stop the event; the page
// can then only choose what is offered for its own origin, which the browser names. An input inside a closed shadow root
// is retargeted to its host and is not seen, so a form there gives no capture. At rest, only password fields in the
// page's own tree are looked for (a form in a shadow root is found at a submission and in the checks after one).
//
// What it costs: while idle it holds five listeners and one look at the page's inputs when it starts (and again once
// at load and once after 1.5 seconds, for a form drawn late). It has no MutationObserver: after a capture it looks at
// the form's password fields at four fixed moments within five seconds, which is also what bounds its cost on a page
// that changes all the time. The detection module walks the page once per submission, not at rest.

/** When, after a capture, the form is looked at again (ms). */
const RECHECK = [700, 1500, 3000, 4900];
const MAX_USER = 512;
const MAX_PASSWORD = 1024;
/** One capture per frame in this many milliseconds. */
const MIN_GAP = 2000;
/** The smallest side of a field that counts as shown (as in the fill engine). */
const MIN_SIDE = 8;
const SENT_KINDS = new Set(["login", "signup", "change", "reset", "identifier"]);

/**
 * @param {{
 *   window: any, document: any,
 *   send: (type: string, body: Record<string, unknown>) => void,
 *   clock: { now: () => number, setTimeout: (fn: () => void, ms: number) => any, clearTimeout: (id: any) => void },
 *   forms: { findGroups: Function, isInside: Function, isSubmitControl: Function, isToggle: Function, controlText: Function,
 *     flatParent: Function, SUBMIT: RegExp, TEXT_TYPES: Set<string> },
 * }} deps
 * @returns {{ stop: () => void }}
 */
export function createCapture({ window, document, send, clock, forms }) {
  const { findGroups, isInside, isSubmitControl, isToggle, controlText, flatParent, SUBMIT, TEXT_TYPES } = forms;
  /** The value of each field at its last trusted input event. @type {WeakMap<object, string>} */
  const typed = new WeakMap();
  /** @type {Set<any>} */
  const timers = new Set();
  /** @type {Array<() => void>} */
  const undo = [];
  /** @type {any[]} */
  let triggers = [];
  /** The groups the person could see when the first trigger of the current burst came, or null. @type {any[] | null} */
  let snapshot = null;
  /** The timer that runs the submission of the current burst of triggers. @type {any} */
  let waiting = null;
  let lastCapture = -Infinity;
  let lastIdentifier = -Infinity;
  let readySent = false;
  let stopped = false;
  /** Whether an input was recorded in this document (a trusted one, or any in a password field). */
  let typedAny = false;

  /** Runs `fn` after `ms`, unless the script was stopped. @param {() => void} fn @param {number} ms */
  const later = (fn, ms) => {
    const id = clock.setTimeout(() => {
      timers.delete(id);
      try {
        if (!stopped) fn();
      } catch {
        // A page that breaks the walk gives no capture; nothing else is lost.
      }
    }, ms);
    timers.add(id);
    return id;
  };

  const on = (/** @type {string} */ type, /** @type {(event: any) => void} */ fn) => {
    window.addEventListener(type, fn, { capture: true, passive: true });
    undo.push(() => window.removeEventListener(type, fn, { capture: true }));
  };

  /** The element an event came from, through open shadow roots. @param {any} event */
  const targetOf = (event) => {
    const path = typeof event.composedPath === "function" ? event.composedPath() : [];
    return path[0] ?? event.target;
  };

  /**
   * Whether the person can see a field: a size, nothing that hides it on the way up (the browser's own
   * `checkVisibility`: not displayed, not visible, transparent; and no `aria-hidden` or inert ancestor, through shadow
   * roots), not off the page, and nothing on top of its centre.
   * @param {any} el
   */
  const shown = (el) => {
    try {
      const box = el.getBoundingClientRect();
      if (box.width < MIN_SIDE || box.height < MIN_SIDE || box.right <= 0 || box.bottom <= 0 || box.left >= window.innerWidth) return false;
      if (!el.checkVisibility({ checkOpacity: true, checkVisibilityCSS: true })) return false;
      for (let node = el, depth = 0; node && depth < 20; node = node.getRootNode().host, depth += 1) {
        if (node.closest('[aria-hidden="true"], [inert]')) return false;
        const around = node.getBoundingClientRect();
        // A host with no box of its own (`display: contents`) cannot be hit.
        if (around.width === 0 || around.height === 0) continue;
        const top = node.getRootNode().elementsFromPoint?.(around.left + around.width / 2, around.top + around.height / 2)?.[0];
        if (top !== undefined && top !== node) return false;
      }
      return true;
    } catch {
      return false;
    }
  };

  /** The password fields of the page (the ones in the page's own tree) that the person can see. */
  const passwords = () => [...document.querySelectorAll('input[type="password"]')].filter(shown);

  const ready = () => {
    if (readySent || passwords().length === 0) return;
    readySent = true;
    send("page_ready", {});
  };

  /** What a trusted input left in a field, if it is still there. @param {any} el */
  const typedValue = (el) => (el && typed.get(el) === el.value && el.value !== "" ? el.value : null);

  /** Whether the element is `a` or lies within a few levels below an ancestor of `a`. @param {any} a @param {any} b */
  const near = (a, b) => {
    for (let node = a, depth = 0; node && depth < 4; node = node.parentElement, depth += 1) if (isInside(node, b)) return true;
    return false;
  };

  /**
   * The message for one group, or null when nothing in it counts.
   * @param {any} group
   */
  const messageFor = (group) => {
    const kind = group.kind;
    if (!SENT_KINDS.has(kind)) return null;
    let password = null;
    let current = null;
    if (kind === "identifier") {
      if (typedValue(group.username) === null) return null;
    } else {
      const field = kind === "login" ? group.password : group.new;
      password = typedValue(field);
      if (password === null) {
        // A sign-up, change or reset form whose new password is in the field but did not come from the person's own
        // typing (the extension filled it): reported with no password at all, so that the extension can join it to the
        // password it generated for the form. Nothing a page could have set goes up.
        if (kind === "login" || !field || field.value === "") return null;
      } else if (password.length > MAX_PASSWORD || (group.confirm && group.confirm.value !== password)) {
        return null;
      } else if (kind === "change") {
        current = typedValue(group.current);
        if (current !== null && current.length > MAX_PASSWORD) current = null;
      }
    }
    const field = group.username;
    const name = field ? field.value : "";
    const named = name !== "" && name.length <= MAX_USER;
    if (kind === "identifier" && !named) return null;
    return {
      capture_id: hex(),
      self_origin: String(window.origin),
      kind,
      username: named ? name : null,
      username_from: named ? (typed.get(field) === name ? "typed" : "page") : null,
      password,
      current_password: current,
    };
  };

  const hex = () => {
    const bytes = new Uint8Array(16);
    window.crypto.getRandomValues(bytes);
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  };

  /** The password fields a group gives a role to (so only fields that are shown, in the page and in shadow roots). @param {any} group */
  const rolesOf = (group) => [group.password, group.new, group.current, group.confirm].filter(Boolean);

  /**
   * After a capture: is the form's password field still there? The form is "gone" only when the browser says it is: removed,
   * not displayed, not visible, or too small. A cover ("Signing in..."), an error modal that sets `aria-hidden` on the
   * rest of the page, or a dialog's backdrop does not make it gone, and the form must be seen gone at two checks in a row
   * (the first check only looks) before form_gone is sent. If a password field the person can see comes back (the original
   * or a new one, also inside a shadow root) before or after that, page_ready is sent, once, so that a failed attempt is
   * never taken for a successful one.
   * @param {any[]} fields @param {string} id @param {Set<any>} seen the password fields shown when the capture was made
   */
  const watch = (fields, id, seen) => {
    let goneChecks = 0;
    let sentGone = false;
    let back = false;
    const goneNow = (/** @type {any} */ el) => !el.isConnected || !el.checkVisibility({ checkVisibilityCSS: true }) || el.getBoundingClientRect().width < MIN_SIDE;
    RECHECK.forEach((ms, index) => later(() => {
      if (back) return;
      /** @type {any[]} */
      const found = findGroups(document, { shown }).flatMap(rolesOf);
      if (found.some((el) => !seen.has(el)) || (sentGone && fields.some((el) => found.includes(el)))) {
        back = true;
        readySent = true;
        send("page_ready", {});
        return;
      }
      if (fields.some((el) => !goneNow(el))) {
        goneChecks = 0;
        return;
      }
      goneChecks += 1;
      if (index >= 1 && goneChecks >= 2 && !sentGone) {
        sentGone = true;
        readySent = false;
        send("form_gone", { capture_id: id });
      }
    }, ms));
  };

  /**
   * A control deeper than one level inside a password field's wrapper (an icon button in a span in the wrapper) is a toggle
   * too: the nearest ancestor within three levels that holds a field of the group holds exactly one, a password field, and
   * is not the form; and the control has no submit words.
   * @param {any} control @param {any[]} fields
   */
  const nestedToggle = (control, fields) => {
    if (SUBMIT.test(controlText(control))) return false;
    for (let node = control.parentElement, depth = 0; node && depth < 3; node = node.parentElement, depth += 1) {
      if (node.localName === "form" || node.localName === "body") return false;
      const inside = fields.filter((f) => isInside(node, f.element));
      if (inside.length > 0) return inside.length === 1 && inside[0].password;
    }
    return false;
  };

  /** Whether a trigger belongs to a group. @param {any} trigger @param {any} group */
  const belongs = (trigger, group) => {
    const { how, node } = trigger;
    if (how === "submit") return group.form === node;
    if (how === "enter") return group.fields.some((/** @type {any} */ f) => f.element === node);
    if (isToggle(node, group.fields) || nestedToggle(node, group.fields)) return false;
    if (group.form) return isInside(group.form, node);
    return isInside(group.container, node) || near(group.fields[0].element, node);
  };

  /** The submission of one burst of triggers: read the page, and send at most one capture. */
  const submitted = () => {
    waiting = null;
    const burst = triggers;
    const groups = snapshot;
    triggers = [];
    snapshot = null;
    const now = clock.now();
    // Nothing was typed in this document yet (no snapshot was taken).
    if (groups === null) return;
    const seen = new Set(groups.flatMap(rolesOf));
    for (const trigger of burst) {
      for (const group of trigger.groups) {
        const message = messageFor(group);
        if (message === null) continue;
        // The step that asks for the user name only has a gap of its own, so that the password step that follows it on
        // the same page within two seconds is not lost.
        if (now - (message.kind === "identifier" ? lastIdentifier : lastCapture) < MIN_GAP) continue;
        if (message.kind === "identifier") lastIdentifier = now;
        else lastCapture = now;
        send("form_capture", message);
        if (message.kind !== "identifier") {
          watch(rolesOf(group), message.capture_id, seen);
        }
        return;
      }
    }
  };

  /** @param {string} how @param {any} node */
  const trigger = (how, node) => {
    // Before the page's own handlers run: the groups and the fields the person could see, and which of them the trigger
    // belongs to (nothing is read from the fields but their roles; the values are read in `submitted`). Only when
    // something was typed here and a capture is not ruled out by the gap.
    if (waiting === null) {
      snapshot = null;
      const now = clock.now();
      if (typedAny && (now - lastCapture >= MIN_GAP || now - lastIdentifier >= MIN_GAP)) {
        try {
          snapshot = findGroups(document, { shown });
        } catch {
          // A page that breaks the walk gives no capture.
        }
      }
      waiting = later(submitted, 0);
    }
    /** @type {any[]} */
    let groups = [];
    try {
      groups = snapshot === null ? [] : snapshot.filter((group) => belongs({ how, node }, group));
    } catch {
      // A page that breaks the walk gives no capture.
    }
    triggers.push({ how, node, groups });
  };

  /**
   * The control a click went to: a button, a button-like input, a link or a `role="button"` element, else an element
   * whose own words are the submit words (a styled `div` or `span`).
   * @param {any} target
   */
  const controlOf = (target) => {
    /** @type {any} */
    let words = null;
    for (let node = target, depth = 0; node && node.nodeType === 1 && depth < 6; node = flatParent(node), depth += 1) {
      const tag = node.localName;
      const role = node.getAttribute("role");
      if (tag === "button" || tag === "a" || role === "button" || (tag === "input" && ["submit", "image", "button"].includes(node.type))) return node;
      if (words === null && depth < 4 && (node.textContent ?? "").length <= 40 && SUBMIT.test(controlText(node))) words = node;
    }
    return words;
  };

  on("input", (event) => {
    const el = targetOf(event);
    if (!el || el.localName !== "input") return;
    if (!event.isTrusted) {
      typed.delete(el);
      // A script that fills a password field (the extension's own fill, too) leaves a form that may be reported.
      if (el.type === "password") typedAny = true;
      return;
    }
    if (el.type === "password" || TEXT_TYPES.has(el.type)) {
      typed.set(el, el.value);
      typedAny = true;
    }
  });
  on("submit", (event) => {
    const form = targetOf(event);
    if (event.isTrusted && form && form.localName === "form") trigger("submit", form);
  });
  on("click", (event) => {
    if (!event.isTrusted) return;
    const control = controlOf(targetOf(event));
    if (control && (isSubmitControl(control) || SUBMIT.test(controlText(control)))) trigger("click", control);
  });
  on("keydown", (event) => {
    const el = targetOf(event);
    if (event.isTrusted && event.key === "Enter" && !event.isComposing && el && el.localName === "input") trigger("enter", el);
  });

  ready();
  if (document.readyState !== "complete") on("load", ready);
  later(ready, 1500);
  // A page that draws its form late (a failed sign-in whose error form comes after the page's own scripts): one more look.
  later(ready, 3000);

  return {
    stop() {
      stopped = true;
      for (const off of undo) off();
      for (const id of timers) clock.clearTimeout(id);
      timers.clear();
    },
  };
}
