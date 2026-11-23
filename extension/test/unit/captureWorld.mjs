// A page with events, for the capture script's unit tests: the fake page of fakeDom.mjs, an event dispatcher that follows
// the browser's order (the window's capture listeners, then the target and its ancestors, then the window's bubble
// listeners), a clock that runs timers when told to, and a few helpers that do what a person does (type, click, press
// Enter, submit). Not a test file (the runner picks up *.test.mjs only).
import {
  SUBMIT, TEXT_TYPES, controlText, findGroups, flatParent, isInside, isSubmitControl, isToggle,
} from "../../src/content/forms.mjs";
import { createCapture } from "../../src/content/capture.mjs";
import { addInput, addText, createPage } from "./fakeDom.mjs";

/** The detection module as the entry hands it to the capture. */
export const FORMS = Object.freeze({ findGroups, isInside, isSubmitControl, isToggle, controlText, flatParent, SUBMIT, TEXT_TYPES });

/** A clock that only moves when `advance` says so. */
export function fakeClock() {
  let now = 1_000_000;
  let sequence = 0;
  /** @type {Array<{ id: number, at: number, fn: () => void }>} */
  let timers = [];
  return {
    now: () => now,
    setTimeout(/** @type {() => void} */ fn, /** @type {number} */ ms) {
      sequence += 1;
      timers.push({ id: sequence, at: now + ms, fn });
      return sequence;
    },
    clearTimeout(/** @type {number} */ id) {
      timers = timers.filter((t) => t.id !== id);
    },
    /** Runs every timer that falls due within `ms`, in order, and leaves the clock `ms` later. @param {number} ms */
    advance(ms) {
      const end = now + ms;
      for (;;) {
        const due = timers.filter((t) => t.at <= end).sort((a, b) => a.at - b.at || a.id - b.id)[0];
        if (!due) break;
        timers = timers.filter((t) => t !== due);
        now = Math.max(now, due.at);
        due.fn();
      }
      now = end;
    },
    pending: () => timers.length,
  };
}

/** @param {{ url?: string }} [options] */
export function createWorld({ url } = {}) {
  const { window, document } = createPage(url ? { url } : {});
  /** @type {Map<string, Array<{ fn: (event: any) => void, capture: boolean }>>} */
  const handlers = new Map();
  const clock = fakeClock();
  /** @type {Array<{ type: string, body: any }>} */
  const sent = [];
  const world = {
    window: /** @type {any} */ (window),
    document: /** @type {any} */ (document),
    clock,
    sent,
    /** How many MutationObservers were made. */
    observers: 0,
  };
  Object.assign(window, {
    addEventListener(/** @type {string} */ type, /** @type {(event: any) => void} */ fn, /** @type {any} */ options) {
      const list = handlers.get(type) ?? [];
      list.push({ fn, capture: options === true || options?.capture === true });
      handlers.set(type, list);
    },
    removeEventListener(/** @type {string} */ type, /** @type {(event: any) => void} */ fn) {
      handlers.set(type, (handlers.get(type) ?? []).filter((h) => h.fn !== fn));
    },
    MutationObserver: class {
      constructor() {
        world.observers += 1;
      }

      observe() {}

      disconnect() {}
    },
  });
  /** @type {any} */ (document).readyState = "complete";

  /**
   * An event the way the browser delivers it. `trusted: false` is an event a script made.
   * @param {any} target @param {string} type @param {Record<string, unknown>} [init]
   */
  function fire(target, type, init = {}) {
    const { trusted = true, ...rest } = init;
    const event = {
      type, target, isTrusted: trusted, bubbles: true, isComposing: false, defaultPrevented: false,
      composedPath: () => [target],
      preventDefault() { this.defaultPrevented = true; },
      ...rest,
    };
    const list = () => handlers.get(type) ?? [];
    for (const h of [...list()].filter((x) => x.capture)) h.fn(event);
    target.dispatchEvent?.(event);
    for (const h of [...list()].filter((x) => !x.capture)) h.fn(event);
    return event;
  }

  /** Types into a field the way a person does: the value changes, then a trusted `input` event. @param {any} el @param {string} text @param {{ trusted?: boolean }} [options] */
  function type(el, text, options = {}) {
    for (const ch of text) {
      el.value += ch;
      fire(el, "input", { trusted: options.trusted !== false });
    }
  }

  return {
    window: world.window,
    document: world.document,
    clock,
    sent,
    /** How many MutationObservers the page has seen made. */
    get observers() {
      return world.observers;
    },
    fire,
    type,
    /** Starts the capture script on the page. @param {{ clock?: any }} [options] */
    start(options = {}) {
      return createCapture({
        window,
        document,
        send: (/** @type {string} */ typeName, /** @type {any} */ body) => { sent.push({ type: typeName, body }); },
        clock: options.clock ?? clock,
        forms: FORMS,
      });
    },
    /** The messages of one type. @param {string} typeName */
    of: (typeName) => sent.filter((m) => m.type === typeName),
    click: (/** @type {any} */ el, /** @type {Record<string, unknown>} */ init) => fire(el, "click", init),
    enter: (/** @type {any} */ el) => fire(el, "keydown", { key: "Enter" }),
    /**
     * A submit event. A person's submit comes after a click or an Enter, so by default a trusted click on the page's body
     * (no control, no trigger of its own) goes first; `gesture: false` leaves it out (a page that submits by itself).
     */
    submit: (/** @type {any} */ form, /** @type {Record<string, unknown>} */ init = {}) => {
      const { gesture = true, ...rest } = init;
      if (gesture !== false && rest.trusted !== false) fire(world.document.body, "click");
      return fire(form, "submit", rest);
    },
    /** Lets the burst of triggers of one submission run (the capture reads the page one task later). */
    settle: () => clock.advance(0),
  };
}

/**
 * A sign-in form: user name (top 100) and password (top 160) in a form, and a submit button.
 * @param {ReturnType<typeof createWorld>} world
 * @param {{ passwordAttributes?: Record<string, string>, userAttributes?: Record<string, string>, button?: string, parent?: any }} [options]
 */
export function loginForm(world, { passwordAttributes = {}, userAttributes = {}, button = "Sign in", parent } = {}) {
  const { document } = world;
  const form = (parent ?? document.body).append(document.createElement("form", { id: "login" }));
  const user = addInput(document, form, { type: "text", name: "username", id: "user", ...userAttributes }, { top: 100 });
  const pass = addInput(document, form, { type: "password", name: "password", id: "pass", ...passwordAttributes }, { top: 160 });
  user.form = form;
  pass.form = form;
  const go = addText(document, form, "button", button, { type: "submit", id: "go" });
  go.form = form;
  return { form, user, pass, go };
}

/**
 * A sign-up form: user name, new password, confirmation, a submit button.
 * @param {ReturnType<typeof createWorld>} world
 */
export function signupForm(world) {
  const { document } = world;
  const form = document.body.append(document.createElement("form", { id: "signup" }));
  const user = addInput(document, form, { type: "text", name: "username", id: "user", autocomplete: "username" }, { top: 100 });
  const fresh = addInput(document, form, { type: "password", name: "password", id: "pw", autocomplete: "new-password" }, { top: 160 });
  const again = addInput(document, form, { type: "password", name: "password2", id: "pw2", autocomplete: "new-password" }, { top: 220 });
  for (const input of [user, fresh, again]) input.form = form;
  const go = addText(document, form, "button", "Sign up", { type: "submit", id: "go" });
  go.form = form;
  return { form, user, fresh, again, go };
}

/**
 * A change form: the password in use, a new one, a confirmation.
 * @param {ReturnType<typeof createWorld>} world
 */
export function changeForm(world) {
  const { document } = world;
  const form = document.body.append(document.createElement("form", { id: "change" }));
  const current = addInput(document, form, { type: "password", name: "current", id: "cur", autocomplete: "current-password" }, { top: 100 });
  const fresh = addInput(document, form, { type: "password", name: "new", id: "new", autocomplete: "new-password" }, { top: 160 });
  const again = addInput(document, form, { type: "password", name: "new2", id: "new2", autocomplete: "new-password" }, { top: 220 });
  for (const input of [current, fresh, again]) input.form = form;
  const go = addText(document, form, "button", "Change password", { type: "submit", id: "go" });
  go.form = form;
  return { form, current, fresh, again, go };
}
