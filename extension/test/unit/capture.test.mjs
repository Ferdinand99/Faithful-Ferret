// The capture script (src/content/capture.mjs) on fake pages: what it sends, when, and what it leaves alone. The
// detection it uses is the fill engine's own (forms.mjs); its classification is tested in forms.test.mjs. The
// script built from these files (size, no dependencies, one message per envelope) is at the end.
import assert from "node:assert/strict";
import vm from "node:vm";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, posix, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { CAPTURE_BUNDLE, CAPTURE_ENTRY, CAPTURE_MAX_BYTES, classicScript, contentMayInclude, slimSource } from "../../scripts/lib/classic.mjs";
import { CONTENT_TYPES, decode } from "../../src/shared/protocol.mjs";
import { addInput, addText, createPage } from "./fakeDom.mjs";
import { changeForm, createWorld, fakeClock, loginForm, signupForm } from "./captureWorld.mjs";

const PASSWORD = "Zq7!sentinel-Vm4$";

/** @param {ReturnType<typeof createWorld>} world */
const captures = (world) => world.of("form_capture").map((m) => m.body);

/** A snapshot of a page that notices any change to its tree, its attributes, its text and its styles. @param {any} document */
function snapshot(document) {
  /** @param {any} node @returns {any} */
  const walk = (node) => ({
    tag: node.localName ?? node.nodeType,
    attributes: node.attributes ? [...node.attributes.entries()] : [],
    text: node.text ?? "",
    style: node.style ? { ...node.style } : {},
    rect: node.rect ? { ...node.rect } : null,
    children: node.childNodes.map(walk),
  });
  return JSON.stringify(walk(document));
}

test("the_capture_script_changes_nothing_in_the_dom_and_leaves_no_marker", () => {
  const world = createWorld();
  const { user, pass, go, form } = loginForm(world);
  const names = new Set(Object.getOwnPropertyNames(world.window));
  const attributes = new Map(world.document.descendants().map((/** @type {any} */ e) => [e, [...e.attributes.entries()].join("|")]));
  const before = snapshot(world.document);
  const listenersBefore = world.document.descendants().map((/** @type {any} */ e) => e.listeners.size);
  const spies = { post: 0, fetch: 0, beacon: 0, xhr: 0, open: 0, storage: 0 };
  Object.assign(world.window, {
    postMessage: () => { spies.post += 1; },
    fetch: () => { spies.fetch += 1; },
    XMLHttpRequest: class { constructor() { spies.xhr += 1; } },
    open: () => { spies.open += 1; },
    navigator: { sendBeacon: () => { spies.beacon += 1; } },
    localStorage: { setItem: () => { spies.storage += 1; }, getItem: () => { spies.storage += 1; } },
    sessionStorage: { setItem: () => { spies.storage += 1; }, getItem: () => { spies.storage += 1; } },
  });
  const known = new Set(Object.getOwnPropertyNames(world.window));
  world.start();
  world.type(user, "anna");
  world.type(pass, PASSWORD);
  world.click(go);
  world.settle();
  world.enter(pass);
  world.submit(form);
  world.clock.advance(6000);
  assert.equal(captures(world).length >= 1, true, "it ran");

  // The page: the same tree, attributes, text, styles and rectangles (the values the person typed are the test's own).
  assert.equal(snapshot(world.document), before);
  for (const element of world.document.descendants()) assert.equal([...element.attributes.entries()].join("|"), attributes.get(element), "no attribute");
  assert.deepEqual(world.document.descendants().map((/** @type {any} */ e) => e.listeners.size), listenersBefore, "no listener on an element");
  assert.equal(world.document.descendants().length, [...attributes.keys()].length, "no element added");
  // The window: no property added, listed or hidden; no request, no message to the page, no storage.
  assert.deepEqual(new Set(Object.getOwnPropertyNames(world.window)), known);
  assert.equal(known.size >= names.size, true);
  assert.deepEqual(spies, { post: 0, fetch: 0, beacon: 0, xhr: 0, open: 0, storage: 0 });
});

test("the_capture_script_sends_nothing_on_a_page_without_a_password_field", () => {
  /** @type {Array<[string, (world: ReturnType<typeof createWorld>) => any[]]>} */
  const pages = [
    ["an empty page", () => []],
    ["a search box", (world) => {
      const form = world.document.body.append(world.document.createElement("form", { role: "search" }));
      const q = addInput(world.document, form, { type: "search", name: "q", "aria-label": "Search" }, { top: 100 });
      q.form = form;
      const go = addText(world.document, form, "button", "Search", { type: "submit" });
      go.form = form;
      return [q, form, go];
    }],
    ["a newsletter box", (world) => {
      const form = world.document.body.append(world.document.createElement("form", { id: "news" }));
      addText(world.document, form, "h2", "Subscribe to our newsletter");
      const mail = addInput(world.document, form, { type: "email", name: "email", placeholder: "Your e-mail" }, { top: 100 });
      mail.form = form;
      const go = addText(world.document, form, "button", "Subscribe", { type: "submit" });
      go.form = form;
      return [mail, form, go];
    }],
    ["a contact form", (world) => {
      const form = world.document.body.append(world.document.createElement("form", { id: "contact" }));
      addText(world.document, form, "h2", "Contact us");
      const name = addInput(world.document, form, { type: "text", name: "name", placeholder: "Full name" }, { top: 100 });
      const mail = addInput(world.document, form, { type: "email", name: "email", placeholder: "E-mail" }, { top: 160 });
      for (const input of [name, mail]) input.form = form;
      const go = addText(world.document, form, "button", "Send", { type: "submit" });
      go.form = form;
      return [name, mail, form, go];
    }],
    ["a coupon box and an address", (world) => {
      const form = world.document.body.append(world.document.createElement("form", { id: "order" }));
      const coupon = addInput(world.document, form, { type: "text", name: "coupon", placeholder: "Coupon code" }, { top: 100 });
      const street = addInput(world.document, form, { type: "text", name: "street", autocomplete: "street-address" }, { top: 160 });
      for (const input of [coupon, street]) input.form = form;
      const go = addText(world.document, form, "button", "Apply", { type: "submit" });
      go.form = form;
      return [coupon, street, form, go];
    }],
    ["a text field with no form", (world) => [addInput(world.document, world.document.body, { type: "text", name: "note" }, { top: 100 })]],
    ["a password field that is hidden", (world) => {
      const form = world.document.body.append(world.document.createElement("form", { id: "f" }));
      const who = addInput(world.document, form, { type: "text", name: "navn", placeholder: "Full name" }, { top: 100 });
      const trap = addInput(world.document, form, { type: "password", name: "password" }, { top: 160 });
      trap.style.display = "none";
      for (const input of [who, trap]) input.form = form;
      const go = addText(world.document, form, "button", "Send", { type: "submit" });
      go.form = form;
      return [who, trap, form, go];
    }],
  ];
  for (const [label, build] of pages) {
    const world = createWorld();
    const parts = build(world);
    world.start();
    world.clock.advance(6000);
    // The person types into every field, clicks every button and presses Enter, in every order.
    for (const part of parts) {
      if (part.localName === "input" && part.type !== "password") world.type(part, "something");
    }
    for (const part of parts) {
      if (part.localName === "button") world.click(part);
      if (part.localName === "form") world.submit(part);
      if (part.localName === "input") world.enter(part);
    }
    world.settle();
    world.clock.advance(6000);
    assert.deepEqual(world.sent, [], label);
  }

  // Not vacuous: the same fields with a visible password do send.
  const world = createWorld();
  const { user, pass, form } = loginForm(world);
  world.start();
  world.type(user, "anna");
  world.type(pass, PASSWORD);
  world.submit(form);
  world.settle();
  assert.equal(captures(world).length, 1);
});

test("no_mutation_observer_before_a_trusted_event_in_a_password_field", () => {
  const world = createWorld();
  const { user, pass, form, go } = loginForm(world);
  world.start();
  world.clock.advance(6000);
  // Nothing that is not a trusted input in a password field: a user name, a click, a script's input, the page changing.
  world.type(user, "anna");
  world.type(pass, "x", { trusted: false });
  world.click(go);
  world.enter(user);
  world.settle();
  world.document.body.append(world.document.createElement("div"));
  assert.equal(world.observers, 0, "no observer before a trusted event in a password field");
  // The trusted event, the submission and the five seconds after it: the script has no observer of its own. It looks at
  // the form at fixed moments instead, which is what keeps its cost flat on a page that changes all the time.
  world.type(pass, PASSWORD);
  assert.equal(world.observers, 0, "no observer after it either");
  world.submit(form);
  world.settle();
  world.clock.advance(6000);
  assert.equal(world.observers, 0);
  assert.equal(captures(world).length, 1);
});

test("a_submit_the_page_fires_itself_is_no_submission_without_a_trusted_click_or_enter", () => {
  // `form.requestSubmit()` makes the browser fire a trusted `submit` event, so a page can do it on a timer or on blur.
  const world = createWorld();
  const { user, pass, form, go } = loginForm(world);
  world.start();
  world.type(user, "anna");
  world.type(pass, PASSWORD);
  world.submit(form, { gesture: false });
  world.settle();
  assert.equal(captures(world).length, 0, "a trusted submit with no click or Enter before it");
  // A click that a script made is no gesture.
  world.click(world.document.body, { trusted: false });
  world.submit(form, { gesture: false });
  world.settle();
  assert.equal(captures(world).length, 0, "after a click from a script");
  // The person's click is one, for two seconds (a page that checks the form with a request first).
  world.click(world.document.body);
  world.clock.advance(2001);
  world.submit(form, { gesture: false });
  world.settle();
  assert.equal(captures(world).length, 0, "a click more than two seconds earlier");
  world.click(world.document.body);
  world.clock.advance(1500);
  world.submit(form, { gesture: false });
  world.settle();
  assert.equal(captures(world).length, 1, "a click one and a half seconds earlier (positive control)");
  assert.equal(captures(world)[0].password, PASSWORD);
  // Enter pressed anywhere is one too (on a button, which is no field: no trigger of its own).
  world.clock.advance(2001);
  world.fire(go, "keydown", { key: "Enter" });
  world.submit(form, { gesture: false });
  world.settle();
  assert.equal(captures(world).length, 2, "Enter on a button, then the submit");
  // The person typed, and the page fires the submit on its own a moment later, long after the last click: nothing.
  world.clock.advance(10_000);
  world.submit(form, { gesture: false });
  world.settle();
  assert.equal(captures(world).length, 2, "a submit ten seconds after the last gesture");
});

test("submit_click_and_enter_each_capture_once", () => {
  // In a form: a click on the submit button and the submit event that follows it are one submission. So are Enter and
  // the submit event it causes, and a submit event alone. A second submission within two seconds gives nothing.
  const world = createWorld();
  const { user, pass, form, go } = loginForm(world);
  world.start();
  world.type(user, "anna");
  world.type(pass, PASSWORD);
  world.click(go);
  world.submit(form);
  world.settle();
  assert.equal(captures(world).length, 1, "click and submit");
  world.click(go);
  world.submit(form);
  world.settle();
  assert.equal(captures(world).length, 1, "a second submission within two seconds");
  world.clock.advance(2001);
  world.enter(pass);
  world.submit(form);
  world.settle();
  assert.equal(captures(world).length, 2, "Enter and the submit event that follows");
  world.clock.advance(2001);
  world.submit(form);
  world.settle();
  assert.equal(captures(world).length, 3, "a submit event alone");
  world.clock.advance(2001);
  world.click(go);
  world.settle();
  assert.equal(captures(world).length, 4, "a click alone (a page that handles the click itself)");
  assert.deepEqual(captures(world).map((c) => c.password), [PASSWORD, PASSWORD, PASSWORD, PASSWORD]);

  // Without a form: a click on a styled element with the submit words, a link, a button of type button, and Enter.
  /** @type {Array<[string, (world: ReturnType<typeof createWorld>, parent: any) => any, (world: ReturnType<typeof createWorld>, control: any, pass: any) => void]>} */
  const ways = [
    ["a styled div", (w, parent) => addText(w.document, parent, "div", "Sign in", { role: "button" }), (w, c) => w.click(c)],
    ["a span with the words", (w, parent) => addText(w.document, parent, "span", "Se connecter"), (w, c) => w.click(c)],
    ["a link", (w, parent) => addText(w.document, parent, "a", "Log in", { href: "#" }), (w, c) => w.click(c)],
    ["a button of type button", (w, parent) => addText(w.document, parent, "button", "Anmelden", { type: "button" }), (w, c) => w.click(c)],
    ["a button with no type", (w, parent) => addText(w.document, parent, "button", "Go", {}), (w, c) => w.click(c)],
    ["Enter in the password field", (w, parent) => addText(w.document, parent, "div", "", {}), (w, _c, pass) => w.enter(pass)],
  ];
  for (const [label, makeControl, act] of ways) {
    const bare = createWorld();
    const box = bare.document.body.append(bare.document.createElement("div", { id: "box" }));
    const u = addInput(bare.document, box, { type: "text", name: "username", id: "u" }, { top: 100 });
    const p = addInput(bare.document, box, { type: "password", name: "password", id: "p" }, { top: 160 });
    const control = makeControl(bare, box);
    bare.start();
    bare.type(u, "anna");
    bare.type(p, PASSWORD);
    act(bare, control, p);
    act(bare, control, p);
    bare.settle();
    assert.equal(captures(bare).length, 1, label);
    assert.equal(captures(bare)[0].kind, "login", label);
    assert.equal(captures(bare)[0].password, PASSWORD, label);
  }

  // A trigger that a script made counts for nothing: forty synthetic submit events, a synthetic click, an Enter from a script.
  const flood = createWorld();
  const f = loginForm(flood);
  flood.start();
  flood.type(f.user, "anna");
  flood.type(f.pass, PASSWORD);
  for (let i = 0; i < 40; i += 1) flood.submit(f.form, { trusted: false });
  flood.click(f.go, { trusted: false });
  flood.fire(f.pass, "keydown", { key: "Enter", trusted: false });
  flood.settle();
  assert.deepEqual(flood.of("form_capture"), []);
  // And a flood of real ones is one capture in two seconds.
  for (let i = 0; i < 40; i += 1) flood.submit(f.form);
  flood.settle();
  assert.equal(captures(flood).length, 1);
});

test("a_click_on_a_show_password_toggle_captures_nothing", () => {
  /** @type {Array<[string, Record<string, string>, string, boolean]>} */
  const toggles = [
    ["a Show button in the field's wrapper", { type: "button" }, "Show", true],
    ["a button with only an icon in the wrapper", { type: "button" }, "\u{1f441}", true],
    ["a button with no type in the wrapper (it would send the form)", {}, "\u{1f441}", true],
    ["Afficher", { type: "button" }, "Afficher", true],
    ["Vis passord", { type: "button" }, "Vis passord", true],
    ["a toggle with the words of a hidden label", { type: "button", "aria-label": "Hide password" }, "", true],
    ["a real submit control in the wrapper's form", { type: "submit" }, "Sign in", false],
  ];
  for (const [label, attributes, text, nothing] of toggles) {
    const world = createWorld();
    const form = world.document.body.append(world.document.createElement("form", { id: "login" }));
    const user = addInput(world.document, form, { type: "text", name: "username" }, { top: 100 });
    const wrapper = form.append(world.document.createElement("div", { class: "pw" }));
    const pass = addInput(world.document, wrapper, { type: "password", name: "password" }, { top: 160 });
    const eye = addText(world.document, wrapper, "button", text, attributes);
    user.form = form;
    pass.form = form;
    eye.form = form;
    world.start();
    world.type(user, "anna");
    world.type(pass, PASSWORD);
    // The page makes the click send nothing and keeps the form (a toggle); the form's own submit event is not fired here.
    world.click(eye);
    world.settle();
    world.clock.advance(6000);
    assert.equal(captures(world).length, nothing ? 0 : 1, label);
  }

  // The page turns the field into a text field and back, which is not a submission either.
  const world = createWorld();
  const { user, pass } = loginForm(world);
  world.start();
  world.type(user, "anna");
  world.type(pass, PASSWORD);
  pass.setAttribute("type", "text");
  pass.setAttribute("type", "password");
  world.settle();
  world.clock.advance(6000);
  assert.deepEqual(world.of("form_capture"), []);
});

test("a_value_without_trusted_input_is_not_captured", () => {
  // A value the page sets, with or without an input event of its own, is not what the person typed.
  /** @type {Array<[string, (world: ReturnType<typeof createWorld>, pass: any) => void]>} */
  const plants = [
    ["a value set and nothing else", (_w, pass) => { pass.value = "planted-by-the-page"; }],
    ["a value set and an input event a script made", (w, pass) => { pass.value = "planted-by-the-page"; w.fire(pass, "input", { trusted: false }); }],
    ["a value set, an input event and a change event", (w, pass) => {
      pass.value = "planted-by-the-page";
      w.fire(pass, "input", { trusted: false });
      w.fire(pass, "change", { trusted: false });
    }],
    ["a value from a script that fills (as the fill engine does)", (w, pass) => {
      pass.value = "filled-by-a-script";
      w.fire(pass, "input", { trusted: false });
      w.fire(pass, "change", { trusted: false });
    }],
  ];
  for (const [label, plant] of plants) {
    const world = createWorld();
    const { user, pass, form } = loginForm(world);
    world.start();
    world.type(user, "anna");
    plant(world, pass);
    world.submit(form);
    world.settle();
    world.clock.advance(6000);
    assert.deepEqual(world.of("form_capture"), [], label);
  }
  // Control: the same form with the person's own typing is captured, with the user name.
  const world = createWorld();
  const { user, pass, form } = loginForm(world);
  world.start();
  world.type(user, "anna");
  world.type(pass, PASSWORD);
  world.submit(form);
  world.settle();
  assert.deepEqual(captures(world).map(({ capture_id: id, ...rest }) => ({ ...rest, id: typeof id })), [
    { self_origin: "https://example.com", kind: "login", username: "anna", username_from: "typed", password: PASSWORD, current_password: null, id: "string" },
  ]);
  assert.match(captures(world)[0].capture_id, /^[0-9a-f]{32}$/);
  // Paste, drop and the browser's autofill are trusted input events too: the value changes in one step.
  const autofilled = createWorld();
  const a = loginForm(autofilled);
  autofilled.start();
  a.user.value = "anna@example.net";
  autofilled.fire(a.user, "input");
  a.pass.value = PASSWORD;
  autofilled.fire(a.pass, "input");
  autofilled.submit(a.form);
  autofilled.settle();
  assert.equal(captures(autofilled)[0].password, PASSWORD);
  assert.equal(captures(autofilled)[0].username_from, "typed");
});

test("a_value_the_page_changed_after_the_last_trusted_input_is_not_captured", () => {
  /** @type {Array<[string, (world: ReturnType<typeof createWorld>, f: ReturnType<typeof loginForm>) => void]>} */
  const swaps = [
    ["a value set with no event", (_w, f) => { f.pass.value = "swapped-by-the-page"; }],
    ["a value set with an input event a script made", (w, f) => { f.pass.value = "swapped-by-the-page"; w.fire(f.pass, "input", { trusted: false }); }],
    ["the same value written again by a script (the field is no longer the person's)", (w, f) => {
      f.pass.value = PASSWORD;
      w.fire(f.pass, "input", { trusted: false });
    }],
    ["a value cut short", (_w, f) => { f.pass.value = PASSWORD.slice(0, 4); }],
    ["a value emptied", (_w, f) => { f.pass.value = ""; }],
  ];
  for (const [label, swap] of swaps) {
    const world = createWorld();
    const f = loginForm(world);
    world.start();
    world.type(f.user, "anna");
    world.type(f.pass, PASSWORD);
    swap(world, f);
    world.submit(f.form);
    world.settle();
    assert.deepEqual(world.of("form_capture"), [], label);
  }

  // The page swaps the value in its own submit handler, which runs after the capture's listener: the script reads the form
  // after the page's handlers, so it sees the swap.
  const world = createWorld();
  const f = loginForm(world);
  f.form.addEventListener("submit", () => { f.pass.value = "swapped-by-the-page"; });
  world.start();
  world.type(f.user, "anna");
  world.type(f.pass, PASSWORD);
  world.submit(f.form);
  world.settle();
  assert.deepEqual(world.of("form_capture"), [], "swapped in the page's submit handler");
  // Likewise in a click handler.
  const clicked = createWorld();
  const c = loginForm(clicked);
  c.go.addEventListener("click", () => { c.pass.value = "swapped-by-the-page"; });
  clicked.start();
  clicked.type(c.user, "anna");
  clicked.type(c.pass, PASSWORD);
  clicked.click(c.go);
  clicked.settle();
  assert.deepEqual(clicked.of("form_capture"), [], "swapped in the page's click handler");

  // The person types again after the page's change: the new value is theirs.
  const again = createWorld();
  const g = loginForm(again);
  again.start();
  again.type(g.user, "anna");
  again.type(g.pass, "first");
  g.pass.value = "swapped-by-the-page";
  g.pass.value = "";
  again.type(g.pass, PASSWORD);
  again.submit(g.form);
  again.settle();
  assert.equal(captures(again)[0].password, PASSWORD);
});

test("a_form_the_page_hides_in_its_own_submit_handler_is_captured", () => {
  /** @type {Array<[string, (world: ReturnType<typeof createWorld>, f: ReturnType<typeof loginForm>) => void]>} */
  const hides = [
    ["display none on the form", (_w, f) => { f.form.style.display = "none"; }],
    ["the form removed", (w, f) => { w.document.body.remove(f.form); }],
    ["a cover over the form", (w) => {
      const cover = addText(w.document, w.document.body, "div", "Signing in", { id: "cover" });
      cover.rect = { left: 0, top: 0, right: 1000, bottom: 1000, width: 1000, height: 1000 };
    }],
    ["aria-hidden on the form", (_w, f) => { f.form.setAttribute("aria-hidden", "true"); }],
  ];
  for (const [label, hide] of hides) {
    const world = createWorld();
    const f = loginForm(world);
    f.form.addEventListener("submit", () => hide(world, f));
    world.start();
    world.type(f.user, "anna");
    world.type(f.pass, PASSWORD);
    world.submit(f.form);
    world.settle();
    assert.deepEqual(captures(world).map((c) => [c.kind, c.username, c.username_from, c.password]), [["login", "anna", "typed", PASSWORD]], label);
  }

  // A page that reveals a decoy password field with a value of its own in its submit handler, and hides the real one: the
  // roles were given at the trigger, so the typed password is the one sent (a login), and a sign-up is not a join request.
  const decoyLogin = createWorld();
  const dl = loginForm(decoyLogin);
  const trap = addInput(decoyLogin.document, dl.form, { type: "password", name: "password", id: "trap" }, { top: 220 });
  trap.style.display = "none";
  trap.value = "decoy-from-the-page";
  dl.form.addEventListener("submit", () => { trap.style.display = "block"; dl.pass.style.display = "none"; });
  decoyLogin.start();
  decoyLogin.type(dl.user, "anna");
  decoyLogin.type(dl.pass, PASSWORD);
  decoyLogin.submit(dl.form);
  decoyLogin.settle();
  assert.deepEqual(captures(decoyLogin).map((m) => [m.kind, m.password]), [["login", PASSWORD]], "a decoy revealed in a login");
  const decoySignup = createWorld();
  const ds = signupForm(decoySignup);
  const spare = addInput(decoySignup.document, ds.form, { type: "password", name: "extra", id: "spare", autocomplete: "new-password" }, { top: 280 });
  spare.style.display = "none";
  spare.value = "decoy-from-the-page";
  ds.form.addEventListener("submit", () => { spare.style.display = "block"; ds.fresh.style.display = "none"; ds.again.style.display = "none"; });
  decoySignup.start();
  decoySignup.type(ds.user, "anna");
  decoySignup.type(ds.fresh, PASSWORD);
  decoySignup.type(ds.again, PASSWORD);
  decoySignup.submit(ds.form);
  decoySignup.settle();
  assert.deepEqual(captures(decoySignup).map((m) => [m.kind, m.password]), [["signup", PASSWORD]], "a decoy revealed in a sign-up");

  // The click on the button hides the form (a page that handles the click itself), and so does a key handler.
  const clicked = createWorld();
  const c = loginForm(clicked);
  c.go.addEventListener("click", () => { c.form.style.display = "none"; });
  clicked.start();
  clicked.type(c.user, "anna");
  clicked.type(c.pass, PASSWORD);
  clicked.click(c.go);
  clicked.settle();
  assert.deepEqual(captures(clicked).map((m) => m.password), [PASSWORD], "hidden in the click");
  const pressed = createWorld();
  const e = loginForm(pressed);
  e.pass.addEventListener("keydown", () => { e.form.style.display = "none"; });
  pressed.start();
  pressed.type(e.pass, PASSWORD);
  pressed.enter(e.pass);
  pressed.settle();
  assert.deepEqual(captures(pressed).map((m) => m.password), [PASSWORD], "hidden in the key handler");

  // The form was already hidden when the person submitted: it is not what the person saw, nothing is sent.
  const before = createWorld();
  const b = loginForm(before);
  before.start();
  before.type(b.user, "anna");
  before.type(b.pass, PASSWORD);
  b.form.style.display = "none";
  before.submit(b.form);
  before.settle();
  assert.deepEqual(before.of("form_capture"), []);

  // After the capture the hidden form is gone for the extension: two checks in a row, then form_gone, once.
  const gone = createWorld();
  const g = loginForm(gone);
  g.form.addEventListener("submit", () => { g.form.style.display = "none"; });
  gone.start();
  gone.type(g.pass, PASSWORD);
  gone.submit(g.form);
  gone.settle();
  const [capture] = captures(gone);
  gone.clock.advance(6000);
  assert.deepEqual(gone.of("form_gone"), [{ type: "form_gone", body: { capture_id: capture.capture_id } }]);
});

test("a_form_replaced_by_a_route_change_in_the_click_is_captured", () => {
  const world = createWorld();
  const f = loginForm(world);
  f.go.addEventListener("click", () => {
    // The page's router swaps the sign-in view for the signed-in one in the same turn.
    world.document.body.remove(f.form);
    addText(world.document, world.document.body, "h1", "Welcome back", { id: "home" });
  });
  world.start();
  world.type(f.user, "anna");
  world.type(f.pass, PASSWORD);
  world.click(f.go);
  world.settle();
  assert.deepEqual(captures(world).map((m) => [m.kind, m.username, m.password]), [["login", "anna", PASSWORD]]);
  world.clock.advance(6000);
  assert.equal(world.of("form_gone").length, 1, "the replaced view is gone");
  assert.equal(world.of("page_ready").length, 1, "no password form came back: only the start");

  // A route that swaps in another sign-in form (a failed attempt drawn again) is not "gone": the form is back.
  const again = createWorld();
  const a = loginForm(again);
  a.go.addEventListener("click", () => {
    again.document.body.remove(a.form);
    loginForm(again);
  });
  again.start();
  again.type(a.pass, PASSWORD);
  again.click(a.go);
  again.settle();
  assert.equal(captures(again).length, 1);
  again.clock.advance(6000);
  assert.deepEqual(again.of("form_gone"), []);
  assert.equal(again.of("page_ready").length, 2);

  // A route that empties the view the way `innerHTML = ""` does: each field and the button become a root of their own.
  const bare = createWorld();
  const view = bare.document.body.append(bare.document.createElement("div", { id: "view" }));
  const bu = addInput(bare.document, view, { type: "text", name: "username", id: "u" }, { top: 100 });
  const bp = addInput(bare.document, view, { type: "password", name: "password", id: "p" }, { top: 160 });
  const bgo = addText(bare.document, view, "button", "Sign in", { type: "button" });
  bgo.addEventListener("click", () => { for (const child of [...view.childNodes]) view.remove(child); });
  bare.start();
  bare.type(bu, "anna");
  bare.type(bp, PASSWORD);
  bare.click(bgo);
  bare.settle();
  assert.deepEqual(captures(bare).map((m) => [m.kind, m.username, m.password]), [["login", "anna", PASSWORD]]);

  // A hash route: the page hides the sign-in view in a click, with no form around the fields.
  const hash = createWorld();
  const box = hash.document.body.append(hash.document.createElement("div", { id: "view" }));
  const u = addInput(hash.document, box, { type: "text", name: "username", id: "u" }, { top: 100 });
  const p = addInput(hash.document, box, { type: "password", name: "password", id: "p" }, { top: 160 });
  const go = addText(hash.document, box, "button", "Sign in", { type: "button" });
  go.addEventListener("click", () => { box.style.display = "none"; });
  hash.start();
  hash.type(u, "anna");
  hash.type(p, PASSWORD);
  hash.click(go);
  hash.settle();
  assert.deepEqual(captures(hash).map((m) => [m.kind, m.username, m.password]), [["login", "anna", PASSWORD]]);
  hash.clock.advance(6000);
  assert.equal(hash.of("form_gone").length, 1);
});

test("an_identifier_step_hidden_by_its_own_next_click_is_captured", () => {
  const same = createWorld();
  const form = same.document.body.append(same.document.createElement("form", { id: "login" }));
  const step1 = form.append(same.document.createElement("div", { id: "step1" }));
  const step2 = form.append(same.document.createElement("div", { id: "step2" }));
  const who = addInput(same.document, step1, { type: "text", name: "identifier", autocomplete: "username" }, { top: 100 });
  const next = addText(same.document, step1, "button", "Next", { type: "button" });
  const pass = addInput(same.document, step2, { type: "password", name: "password", autocomplete: "current-password" }, { top: 160 });
  const go = addText(same.document, step2, "button", "Sign in", { type: "submit" });
  for (const el of [who, pass, next, go]) el.form = form;
  step2.style.display = "none";
  next.addEventListener("click", () => {
    step1.style.display = "none";
    step2.style.display = "block";
  });
  same.start();
  same.type(who, "anna@example.net");
  same.click(next);
  same.settle();
  assert.deepEqual(captures(same).map((c) => [c.kind, c.username, c.username_from, c.password, c.current_password]), [["identifier", "anna@example.net", "typed", null, null]]);
  // The password step that follows on the same page, a moment later, is not lost to the gap after the name step.
  same.clock.advance(300);
  same.type(pass, PASSWORD);
  same.click(go);
  same.settle();
  assert.deepEqual(captures(same).map((c) => [c.kind, c.password]), [["identifier", null], ["login", PASSWORD]]);

  // The gap is per kind: a second step that asks for the name within two seconds gives nothing, a second form capture
  // within two seconds gives nothing, and each is free again after two seconds.
  const twice = createWorld();
  const t = loginForm(twice);
  const idForm = twice.document.body.append(twice.document.createElement("form", { id: "identify" }));
  addText(twice.document, idForm, "h1", "Sign in");
  const who2 = addInput(twice.document, idForm, { type: "text", name: "identifier", autocomplete: "username" }, { top: 400 });
  who2.form = idForm;
  const next2 = addText(twice.document, idForm, "button", "Next", { type: "submit" });
  next2.form = idForm;
  twice.start();
  twice.type(who2, "anna@example.net");
  twice.submit(idForm);
  twice.settle();
  twice.clock.advance(300);
  twice.submit(idForm);
  twice.settle();
  assert.deepEqual(captures(twice).map((c) => c.kind), ["identifier"], "two identifier steps within two seconds");
  twice.type(t.user, "anna");
  twice.type(t.pass, PASSWORD);
  twice.submit(t.form);
  twice.settle();
  twice.clock.advance(300);
  twice.submit(t.form);
  twice.settle();
  assert.deepEqual(captures(twice).map((c) => c.kind), ["identifier", "login"], "a login right after an identifier step, and not twice");
  twice.clock.advance(2001);
  twice.submit(idForm);
  twice.settle();
  assert.deepEqual(captures(twice).map((c) => c.kind), ["identifier", "login", "identifier"], "an identifier step is free after two seconds");

  // A name the page put there is still no step, even when the page hides the step in its own handler.
  const quiet = createWorld();
  const qform = quiet.document.body.append(quiet.document.createElement("form", { id: "identify" }));
  addText(quiet.document, qform, "h1", "Sign in");
  const q = addInput(quiet.document, qform, { type: "text", name: "identifier", autocomplete: "username" }, { top: 100 });
  q.form = qform;
  q.value = "anna@example.net";
  const qnext = addText(quiet.document, qform, "button", "Next", { type: "submit" });
  qnext.form = qform;
  qform.addEventListener("submit", () => { qform.style.display = "none"; });
  quiet.start();
  quiet.submit(qform);
  quiet.settle();
  assert.deepEqual(quiet.sent, []);
});

test("a_value_the_page_changed_in_its_own_submit_handler_is_still_not_captured", () => {
  // The page hides the form and also rewrites or empties the password in its own handler: the snapshot only decides what
  // the person could see, the value must still be what the person typed.
  /** @type {Array<[string, (f: ReturnType<typeof loginForm>, w: ReturnType<typeof createWorld>) => void]>} */
  const changes = [
    ["a value written by the page", (f) => { f.pass.value = "swapped-by-the-page"; }],
    ["a value emptied", (f) => { f.pass.value = ""; }],
    ["a value written again by a script", (f, w) => { f.pass.value = PASSWORD; w.fire(f.pass, "input", { trusted: false }); }],
  ];
  for (const [label, change] of changes) {
    const world = createWorld();
    const f = loginForm(world);
    f.form.addEventListener("submit", () => {
      f.form.style.display = "none";
      change(f, world);
    });
    world.start();
    world.type(f.user, "anna");
    world.type(f.pass, PASSWORD);
    world.submit(f.form);
    world.settle();
    world.clock.advance(6000);
    assert.deepEqual(world.of("form_capture"), [], label);
    assert.deepEqual(world.of("form_gone"), [], label);
  }

  // The same through a click handler, with the form replaced.
  const clicked = createWorld();
  const c = loginForm(clicked);
  c.go.addEventListener("click", () => {
    c.pass.value = "swapped-by-the-page";
    clicked.document.body.remove(c.form);
  });
  clicked.start();
  clicked.type(c.user, "anna");
  clicked.type(c.pass, PASSWORD);
  clicked.click(c.go);
  clicked.settle();
  assert.deepEqual(clicked.of("form_capture"), []);

  // A page that fills a form the person never typed a password into cannot make it count.
  const planted = createWorld();
  const p = loginForm(planted);
  p.form.addEventListener("submit", () => { p.form.style.display = "none"; p.pass.value = "planted"; });
  planted.start();
  planted.type(p.user, "anna");
  planted.submit(p.form);
  planted.settle();
  assert.deepEqual(planted.of("form_capture"), []);
});

test("a_value_set_by_the_page_in_a_keydown_handler_is_not_captured", () => {
  // The page cancels each key and writes the character itself (so no input event comes), then the person submits.
  const world = createWorld();
  const { user, pass, form } = loginForm(world);
  pass.addEventListener("keydown", (/** @type {any} */ event) => {
    event.preventDefault();
    if (typeof event.key === "string" && event.key.length === 1) pass.value += event.key;
  });
  world.start();
  world.type(user, "anna");
  for (const ch of "abcdefgh") world.fire(pass, "keydown", { key: ch });
  assert.equal(pass.value, "abcdefgh", "the page did write the value");
  world.fire(pass, "keyup", { key: "h" });
  world.submit(form);
  world.settle();
  world.clock.advance(6000);
  assert.deepEqual(world.of("form_capture"), []);

  // A keydown never counts, not even next to a trusted input: a key press after the last input does not make the value the person's.
  const mixed = createWorld();
  const m = loginForm(mixed);
  m.pass.addEventListener("keydown", (/** @type {any} */ event) => {
    if (event.key === "Enter") return;
    event.preventDefault();
    m.pass.value += "!";
  });
  mixed.start();
  mixed.type(m.user, "anna");
  mixed.type(m.pass, "typed");
  mixed.fire(m.pass, "keydown", { key: "x" });
  assert.equal(m.pass.value, "typed!");
  mixed.enter(m.pass);
  mixed.submit(m.form);
  mixed.settle();
  assert.deepEqual(mixed.of("form_capture"), []);
});

test("a_hidden_or_honeypot_password_is_not_captured", () => {
  /** @type {Array<[string, (world: ReturnType<typeof createWorld>, trap: any, wrapper: any) => void]>} */
  const hiding = [
    ["display none", (_w, trap) => { trap.style.display = "none"; }],
    ["a parent with display none", (_w, _trap, wrapper) => { wrapper.style.display = "none"; }],
    ["visibility hidden", (_w, trap) => { trap.style.visibility = "hidden"; }],
    ["opacity 0", (_w, trap) => { trap.style.opacity = "0"; }],
    ["a parent with opacity 0", (_w, _trap, wrapper) => { wrapper.style.opacity = "0"; }],
    ["zero size", (_w, trap) => { trap.rect = { left: 100, top: 160, width: 0, height: 0 }; }],
    ["one pixel", (_w, trap) => { trap.rect = { left: 100, top: 160, width: 1, height: 1 }; }],
    ["off the page, to the left", (_w, trap) => { trap.rect = { left: -9999, top: 160, width: 240, height: 32 }; }],
    ["off the page, above", (_w, trap) => { trap.rect = { left: 100, top: -9999, width: 240, height: 32 }; }],
    ["aria-hidden", (_w, trap) => { trap.setAttribute("aria-hidden", "true"); }],
    ["a parent with aria-hidden", (_w, _trap, wrapper) => { wrapper.setAttribute("aria-hidden", "true"); }],
    ["inert", (_w, trap) => { trap.inert = true; }],
    ["covered by another element", (w, trap) => {
      const cover = addText(w.document, w.document.body, "div", "Must have 12 characters");
      cover.rect = { ...trap.rect };
      cover.z = 10;
    }],
  ];
  for (const [label, hide] of hiding) {
    const world = createWorld();
    const form = world.document.body.append(world.document.createElement("form", { id: "f" }));
    const who = addInput(world.document, form, { type: "text", name: "navn", placeholder: "Full name" }, { top: 100 });
    const wrapper = form.append(world.document.createElement("div", { class: "trap" }));
    const trap = addInput(world.document, wrapper, { type: "password", name: "password" }, { top: 160 });
    who.form = form;
    trap.form = form;
    const go = addText(world.document, form, "button", "Send", { type: "submit" });
    go.form = form;
    hide(world, trap, wrapper);
    world.start();
    world.type(who, "Anna");
    // Something types into the trap (an assistive tool, a script that sends real-looking events is untrusted and is
    // covered by the tests above): it is not shown, so it takes no part.
    world.type(trap, PASSWORD);
    world.click(go);
    world.submit(form);
    world.settle();
    world.clock.advance(6000);
    assert.deepEqual(world.of("form_capture"), [], label);
  }

  // The same form with a visible field is captured (so the pages above are what stops it).
  const world = createWorld();
  const { user, pass, form } = loginForm(world);
  world.start();
  world.type(user, "anna");
  world.type(pass, PASSWORD);
  world.submit(form);
  world.settle();
  assert.equal(captures(world).length, 1);

  // A real field next to a honeypot: the real one is sent, the honeypot never is.
  const both = createWorld();
  const b = loginForm(both);
  const trap = addInput(both.document, b.form, { type: "password", name: "pass2" }, { top: 260 });
  trap.style.display = "none";
  trap.form = b.form;
  both.start();
  both.type(b.user, "anna");
  both.type(b.pass, PASSWORD);
  both.type(trap, "honeypot-value");
  both.submit(b.form);
  both.settle();
  assert.equal(captures(both).length, 1);
  assert.equal(captures(both)[0].password, PASSWORD);
  assert.equal(JSON.stringify(both.sent).includes("honeypot-value"), false);
});

test("a_prefilled_username_is_sent_as_from_page", () => {
  const prefilled = createWorld();
  const p = loginForm(prefilled);
  p.user.value = "anna@example.net";
  prefilled.start();
  prefilled.type(p.pass, PASSWORD);
  prefilled.submit(p.form);
  prefilled.settle();
  assert.equal(captures(prefilled)[0].username, "anna@example.net");
  assert.equal(captures(prefilled)[0].username_from, "page");

  // Typed over a prefilled value: the person's.
  const typed = createWorld();
  const t = loginForm(typed);
  t.user.value = "old";
  typed.start();
  t.user.value = "";
  typed.type(t.user, "anna");
  typed.type(t.pass, PASSWORD);
  typed.submit(t.form);
  typed.settle();
  assert.equal(captures(typed)[0].username_from, "typed");

  // Typed and then changed by the page: from the page.
  const changed = createWorld();
  const c = loginForm(changed);
  changed.start();
  changed.type(c.user, "anna");
  c.user.value = "someone-else";
  changed.type(c.pass, PASSWORD);
  changed.submit(c.form);
  changed.settle();
  assert.equal(captures(changed)[0].username, "someone-else");
  assert.equal(captures(changed)[0].username_from, "page");

  // No user name: nothing is sent for it. Over 512 characters: dropped, the password stays.
  const none = createWorld();
  const n = loginForm(none);
  none.start();
  none.type(n.pass, PASSWORD);
  none.submit(n.form);
  none.settle();
  assert.equal(captures(none)[0].username, null);
  assert.equal(captures(none)[0].username_from, null);
  const long = createWorld();
  const l = loginForm(long);
  l.user.value = "u".repeat(513);
  long.start();
  long.type(l.pass, PASSWORD);
  long.submit(l.form);
  long.settle();
  assert.equal(captures(long)[0].username, null);
  assert.equal(captures(long)[0].username_from, null);
  assert.equal(captures(long)[0].password, PASSWORD);
});

test("page_ready_is_sent_only_with_a_visible_password_field", () => {
  // No password field, or none the person can see: never.
  for (const hide of [(/** @type {any} */ el) => { el.style.display = "none"; }, (/** @type {any} */ el) => { el.style.opacity = "0"; }, (/** @type {any} */ el) => { el.rect = null; }, (/** @type {any} */ el) => el.setAttribute("aria-hidden", "true")]) {
    const world = createWorld();
    const { pass } = loginForm(world);
    hide(pass);
    world.start();
    world.clock.advance(6000);
    assert.deepEqual(world.of("page_ready"), []);
  }
  const bare = createWorld();
  bare.start();
  bare.clock.advance(6000);
  assert.deepEqual(bare.sent, []);

  // A visible one: once, at the start, with an empty body.
  const world = createWorld();
  loginForm(world);
  world.start();
  assert.deepEqual(world.sent, [{ type: "page_ready", body: {} }]);
  world.clock.advance(6000);
  assert.equal(world.of("page_ready").length, 1);

  // Drawn late, after the script started (a page that renders its form): found at the look after the load or 1.5 seconds on.
  const late = createWorld();
  late.start();
  late.clock.advance(1000);
  assert.deepEqual(late.sent, []);
  loginForm(late);
  late.clock.advance(1000);
  assert.deepEqual(late.sent, [{ type: "page_ready", body: {} }]);
  late.clock.advance(6000);
  assert.equal(late.of("page_ready").length, 1);

  // A form drawn after the 1.5 second look (an error form that a failed sign-in draws late): the look at 3 seconds finds it.
  const slow = createWorld();
  slow.start();
  slow.clock.advance(2000);
  assert.deepEqual(slow.sent, []);
  loginForm(slow);
  slow.clock.advance(1100);
  assert.deepEqual(slow.sent, [{ type: "page_ready", body: {} }]);
  slow.clock.advance(6000);
  assert.equal(slow.of("page_ready").length, 1);

  // A page that is still loading: the look at the load event.
  const loading = createWorld();
  /** @type {any} */ (loading.document).readyState = "loading";
  loading.start();
  assert.deepEqual(loading.sent, []);
  loginForm(loading);
  loading.fire(loading.window, "load");
  assert.equal(loading.of("page_ready").length, 1);
});

test("a_sign_in_form_that_goes_away_sends_form_gone_and_one_that_comes_back_sends_page_ready", () => {
  // The form goes away and nothing like it comes back: form_gone, once, with the capture's id.
  const world = createWorld();
  const { user, pass, form, go } = loginForm(world);
  world.start();
  assert.equal(world.of("page_ready").length, 1);
  world.type(user, "anna");
  world.type(pass, PASSWORD);
  world.click(go);
  world.settle();
  const [capture] = captures(world);
  world.clock.advance(1000);
  assert.deepEqual(world.of("form_gone"), [], "still there");
  world.document.body.remove(form);
  world.clock.advance(6000);
  assert.deepEqual(world.of("form_gone"), [{ type: "form_gone", body: { capture_id: capture.capture_id } }]);

  // A form that is hidden counts as gone.
  const hidden = createWorld();
  const h = loginForm(hidden);
  hidden.start();
  hidden.type(h.pass, PASSWORD);
  hidden.submit(h.form);
  hidden.settle();
  h.form.style.display = "none";
  hidden.clock.advance(6000);
  assert.equal(hidden.of("form_gone").length, 1);

  // A form that stays: nothing. A form replaced by a new one with a password field (a failed attempt): page_ready, not form_gone.
  const stays = createWorld();
  const s = loginForm(stays);
  stays.start();
  stays.type(s.pass, PASSWORD);
  stays.submit(s.form);
  stays.settle();
  stays.clock.advance(6000);
  assert.deepEqual(stays.of("form_gone"), []);
  const failed = createWorld();
  const f = loginForm(failed);
  failed.start();
  failed.type(f.pass, PASSWORD);
  failed.submit(f.form);
  failed.settle();
  failed.clock.advance(300);
  failed.document.body.remove(f.form);
  loginForm(failed);
  failed.clock.advance(6000);
  assert.deepEqual(failed.of("form_gone"), []);
  assert.equal(failed.of("page_ready").length, 2, "the start, and the form that came back");

  // Another password form on the page that was there already does not keep the form from being gone.
  const two = createWorld();
  const first = loginForm(two);
  const other = two.document.body.append(two.document.createElement("form", { id: "other" }));
  const spare = addInput(two.document, other, { type: "password", name: "x", autocomplete: "new-password" }, { top: 400 });
  spare.form = other;
  two.start();
  two.type(first.pass, PASSWORD);
  two.submit(first.form);
  two.settle();
  two.document.body.remove(first.form);
  two.clock.advance(6000);
  assert.equal(two.of("form_gone").length, 1);

  // An identifier step sends no form_gone (it has no password field).
  const step = createWorld();
  const form1 = step.document.body.append(step.document.createElement("form", { id: "identify" }));
  addText(step.document, form1, "h1", "Sign in");
  const who = addInput(step.document, form1, { type: "text", name: "identifier", autocomplete: "username" }, { top: 100 });
  who.form = form1;
  const next = addText(step.document, form1, "button", "Next", { type: "submit" });
  next.form = form1;
  step.start();
  step.type(who, "anna@example.net");
  step.submit(form1);
  step.settle();
  step.document.body.remove(form1);
  step.clock.advance(6000);
  assert.deepEqual(step.of("form_gone"), []);
});

test("an_identifier_step_is_sent_when_the_person_typed_the_name", () => {
  const build = (/** @type {{ typed?: boolean, prefilled?: boolean, button?: string, title?: string }} */ { typed = true, prefilled = false, button = "Next", title = "Sign in" } = {}) => {
    const world = createWorld();
    const form = world.document.body.append(world.document.createElement("form", { id: "identify" }));
    addText(world.document, form, "h1", title);
    const who = addInput(world.document, form, { type: "text", name: "identifier", autocomplete: "username" }, { top: 100 });
    who.form = form;
    if (prefilled) who.value = "anna@example.net";
    const next = addText(world.document, form, "button", button, { type: "submit" });
    next.form = form;
    world.start();
    if (typed) world.type(who, "anna@example.net");
    world.submit(form);
    world.settle();
    return world;
  };
  const world = build();
  assert.deepEqual(captures(world).map(({ capture_id: id, ...rest }) => ({ ...rest, id: typeof id })), [
    { self_origin: "https://example.com", kind: "identifier", username: "anna@example.net", username_from: "typed", password: null, current_password: null, id: "string" },
  ]);
  // A name the page put there is not sent as a step; neither is an empty field; neither is a form that is not a sign-in.
  assert.deepEqual(build({ typed: false, prefilled: true }).sent, []);
  assert.deepEqual(build({ typed: false }).sent, []);
  assert.deepEqual(build({ button: "Subscribe", title: "Newsletter" }).sent, []);

  // The password step that follows (a second page, or the same page) is sent without the user name the first step held.
  const same = createWorld();
  const form = same.document.body.append(same.document.createElement("form", { id: "login" }));
  const step1 = form.append(same.document.createElement("div", { id: "step1" }));
  const step2 = form.append(same.document.createElement("div", { id: "step2" }));
  const who = addInput(same.document, step1, { type: "text", name: "identifier", autocomplete: "username" }, { top: 100 });
  const next = addText(same.document, step1, "button", "Next", { type: "button" });
  const pass = addInput(same.document, step2, { type: "password", name: "password", autocomplete: "current-password" }, { top: 160 });
  const go = addText(same.document, step2, "button", "Sign in", { type: "submit" });
  for (const el of [who, pass, next, go]) el.form = form;
  step2.style.display = "none";
  same.start();
  same.type(who, "anna@example.net");
  same.click(next);
  same.settle();
  assert.deepEqual(captures(same).map((c) => [c.kind, c.username, c.password]), [["identifier", "anna@example.net", null]]);
  step1.style.display = "none";
  step2.style.display = "block";
  same.clock.advance(2500);
  same.type(pass, PASSWORD);
  same.click(go);
  same.settle();
  assert.deepEqual(captures(same).map((c) => [c.kind, c.username, c.password]), [["identifier", "anna@example.net", null], ["login", null, PASSWORD]]);
});

test("sign_up_change_and_reset_forms_send_the_new_password_and_the_one_in_use", () => {
  // Sign-up: the new password, with the user name; a confirmation that differs sends nothing, one that matches is not sent.
  const signup = createWorld();
  const s = signupForm(signup);
  signup.start();
  signup.type(s.user, "anna");
  signup.type(s.fresh, PASSWORD);
  signup.type(s.again, "something-else");
  signup.submit(s.form);
  signup.settle();
  assert.deepEqual(signup.sent.filter((m) => m.type === "form_capture"), [], "the confirmation differs");
  s.again.value = "";
  signup.type(s.again, PASSWORD);
  signup.clock.advance(2001);
  signup.submit(s.form);
  signup.settle();
  assert.deepEqual(captures(signup).map((c) => [c.kind, c.username, c.password, c.current_password]), [["signup", "anna", PASSWORD, null]]);
  assert.equal(JSON.stringify(signup.sent).split(PASSWORD).length, 2, "the password is in one place of the message");

  // The confirmation set by the page or the generator (no input of the person's) is fine when it is the same value: the
  // new password is the person's.
  const filled = createWorld();
  const f = signupForm(filled);
  filled.start();
  filled.type(f.user, "anna");
  filled.type(f.fresh, PASSWORD);
  f.again.value = PASSWORD;
  filled.fire(f.again, "input", { trusted: false });
  filled.submit(f.form);
  filled.settle();
  assert.equal(captures(filled)[0].password, PASSWORD);

  // Change: the new one and the one in use; a current password the person did not type (Ferret filled it) is left out.
  const change = createWorld();
  const c = changeForm(change);
  change.start();
  change.type(c.current, "old-password-1");
  change.type(c.fresh, PASSWORD);
  change.type(c.again, PASSWORD);
  change.submit(c.form);
  change.settle();
  assert.deepEqual(captures(change).map((x) => [x.kind, x.username, x.password, x.current_password]), [["change", null, PASSWORD, "old-password-1"]]);
  const filledCurrent = createWorld();
  const d = changeForm(filledCurrent);
  filledCurrent.start();
  d.current.value = "old-password-1";
  filledCurrent.fire(d.current, "input", { trusted: false });
  filledCurrent.fire(d.current, "change", { trusted: false });
  filledCurrent.type(d.fresh, PASSWORD);
  filledCurrent.type(d.again, PASSWORD);
  filledCurrent.submit(d.form);
  filledCurrent.settle();
  assert.deepEqual(captures(filledCurrent).map((x) => [x.kind, x.password, x.current_password]), [["change", PASSWORD, null]]);
  // A new password the person did not type (the page wrote it, or the extension filled it): the form is reported with no
  // password at all, whatever the current one is, as a request to join it to a generated password. The value never goes up.
  const planted = createWorld();
  const p = changeForm(planted);
  planted.start();
  planted.type(p.current, "old-password-1");
  p.fresh.value = "planted";
  p.again.value = "planted";
  planted.submit(p.form);
  planted.settle();
  assert.deepEqual(captures(planted).map((x) => [x.kind, x.username, x.password, x.current_password]), [["change", null, null, null]]);
  assert.equal(JSON.stringify(planted.sent).includes("planted"), false);
  assert.equal(JSON.stringify(planted.sent).includes("old-password-1"), false);

  // A sign-up form that the extension filled (new and confirm, with events a script made), with a user name the person typed:
  // reported with the user name and no password. The same form with the new field empty, or a sign-in form with a value
  // the page wrote, is not reported.
  const generated = createWorld();
  const g = signupForm(generated);
  generated.start();
  generated.type(g.user, "anna");
  for (const field of [g.fresh, g.again]) {
    field.value = "Gen-erated-1!";
    generated.fire(field, "input", { trusted: false });
    generated.fire(field, "change", { trusted: false });
  }
  generated.submit(g.form);
  generated.settle();
  assert.deepEqual(captures(generated).map((x) => [x.kind, x.username, x.username_from, x.password, x.current_password]), [["signup", "anna", "typed", null, null]]);
  assert.equal(JSON.stringify(generated.sent).includes("Gen-erated-1!"), false);
  const emptyNew = createWorld();
  const e = signupForm(emptyNew);
  emptyNew.start();
  emptyNew.type(e.user, "anna");
  emptyNew.submit(e.form);
  emptyNew.settle();
  assert.deepEqual(emptyNew.of("form_capture"), []);
  const plantedLogin = createWorld();
  const pl = loginForm(plantedLogin);
  plantedLogin.start();
  plantedLogin.type(pl.user, "anna");
  pl.pass.value = "written-by-the-page";
  plantedLogin.fire(pl.pass, "input", { trusted: false });
  plantedLogin.submit(pl.form);
  plantedLogin.settle();
  assert.deepEqual(plantedLogin.of("form_capture"), [], "a sign-in form is never reported without its password");

  // Over the limits: a password over 1 024 characters is dropped, and so is a current password over it (the new one stays).
  const huge = createWorld();
  const h = loginForm(huge);
  huge.start();
  huge.type(h.user, "anna");
  huge.type(h.pass, "p".repeat(1025));
  huge.submit(h.form);
  huge.settle();
  assert.deepEqual(huge.sent.filter((m) => m.type === "form_capture"), []);
  const limit = createWorld();
  const l = loginForm(limit);
  limit.start();
  limit.type(l.pass, "p".repeat(1024));
  limit.submit(l.form);
  limit.settle();
  assert.equal(captures(limit)[0].password.length, 1024);
});

test("a_covered_or_modal_hidden_form_is_not_reported_gone_and_a_form_that_comes_back_sends_page_ready", () => {
  /** A signed-in-looking attempt: typed and submitted, with the start's page_ready already sent. */
  const attempt = () => {
    const world = createWorld();
    const f = loginForm(world);
    world.start();
    world.type(f.user, "anna");
    world.type(f.pass, PASSWORD);
    world.submit(f.form);
    world.settle();
    assert.equal(captures(world).length, 1);
    return { world, f };
  };
  // The form stays in the page but is covered, or the page behind an error modal is aria-hidden or inert: not gone, and
  // nothing else is sent either (the form did not come back, it never left).
  /** @type {Array<[string, (w: ReturnType<typeof createWorld>, f: ReturnType<typeof loginForm>) => void]>} */
  const stays = [
    ["a Signing in overlay", (w, f) => {
      const cover = addText(w.document, w.document.body, "div", "Signing in...");
      cover.rect = { ...f.pass.rect };
      cover.z = 10;
    }],
    ["aria-hidden on the app root (an error modal library)", (w) => { w.document.body.setAttribute("aria-hidden", "true"); }],
    ["an inert page behind a dialog", (_w, f) => { f.form.inert = true; }],
    ["a dialog backdrop over the whole page", (w) => {
      const backdrop = addText(w.document, w.document.body, "div", "");
      backdrop.rect = { left: 0, top: 0, width: 1280, height: 800 };
      backdrop.z = 10;
    }],
  ];
  for (const [label, cover] of stays) {
    const { world, f } = attempt();
    world.clock.advance(300);
    cover(world, f);
    world.clock.advance(6000);
    assert.deepEqual(world.of("form_gone"), [], label);
    assert.equal(world.of("page_ready").length, 1, `${label}: only the start's page_ready`);
  }

  // Gone for real (removed) at two checks in a row: form_gone, once. Hidden or too small count as gone as well.
  /** @type {Array<[string, (w: ReturnType<typeof createWorld>, f: ReturnType<typeof loginForm>) => void]>} */
  const leaves = [
    ["removed", (w, f) => { w.document.body.remove(f.form); }],
    ["not displayed", (_w, f) => { f.form.style.display = "none"; }],
    ["visibility hidden", (_w, f) => { f.form.style.visibility = "hidden"; }],
  ];
  for (const [label, leave] of leaves) {
    const { world, f } = attempt();
    world.clock.advance(300);
    leave(world, f);
    world.clock.advance(1000);
    assert.deepEqual(world.of("form_gone"), [], `${label}: one check is not enough`);
    world.clock.advance(6000);
    assert.equal(world.of("form_gone").length, 1, label);
  }

  // Gone at one check only (an overlay-less flicker: removed and back within the first check): never form_gone.
  const flicker = attempt();
  flicker.world.clock.advance(100);
  flicker.world.document.body.remove(flicker.f.form);
  flicker.world.clock.advance(100);
  flicker.f.form.style.display = "block";
  flicker.world.document.body.append(flicker.f.form);
  flicker.world.clock.advance(6000);
  assert.deepEqual(flicker.world.of("form_gone"), []);

  // A form that is replaced by a new one before the first check (a failed attempt): page_ready, no form_gone.
  const failed = attempt();
  failed.world.clock.advance(300);
  failed.world.document.body.remove(failed.f.form);
  loginForm(failed.world);
  failed.world.clock.advance(6000);
  assert.deepEqual(failed.world.of("form_gone"), []);
  assert.equal(failed.world.of("page_ready").length, 2);

  // form_gone first, then the form comes back (a slow failed attempt): page_ready after it, once.
  const slow = attempt();
  slow.world.clock.advance(300);
  slow.world.document.body.remove(slow.f.form);
  slow.world.clock.advance(2900);
  assert.equal(slow.world.of("form_gone").length, 1);
  loginForm(slow.world);
  slow.world.clock.advance(6000);
  assert.equal(slow.world.of("page_ready").length, 2);
  assert.equal(slow.world.of("form_gone").length, 1);

  // The form that comes back is in a shadow root: found there too.
  const shadow = attempt();
  shadow.world.clock.advance(300);
  shadow.world.document.body.remove(shadow.f.form);
  const host = shadow.world.document.body.append(shadow.world.document.createElement("login-box"));
  loginForm(shadow.world, { parent: host.attachShadow({ mode: "open" }) });
  shadow.world.clock.advance(6000);
  assert.deepEqual(shadow.world.of("form_gone"), []);
  assert.equal(shadow.world.of("page_ready").length, 2);
});

test("a_control_deeper_in_the_password_fields_wrapper_is_a_toggle_and_an_offscreen_field_is_not_shown", () => {
  // An icon button with no words, one level deeper than the wrapper's child: not a submission, however the page types it.
  for (const attributes of [{}, { type: "button" }]) {
    const world = createWorld();
    const form = world.document.body.append(world.document.createElement("form", { id: "login" }));
    const user = addInput(world.document, form, { type: "text", name: "username" }, { top: 100 });
    const wrapper = form.append(world.document.createElement("div", { class: "pw" }));
    const pass = addInput(world.document, wrapper, { type: "password", name: "password" }, { top: 160 });
    const inner = wrapper.append(world.document.createElement("span"));
    const eye = addText(world.document, inner, "button", "", attributes);
    for (const el of [user, pass, eye]) el.form = form;
    world.start();
    world.type(user, "anna");
    world.type(pass, PASSWORD);
    world.click(eye);
    world.settle();
    world.clock.advance(6000);
    assert.deepEqual(world.of("form_capture"), [], JSON.stringify(attributes));
  }
  // A user name field that lies wholly to the right of the page is not shown: its value is not sent as the user name.
  const world = createWorld();
  const f = loginForm(world);
  f.user.value = "honeypot-name";
  f.user.rect = { left: 5000, top: 100, width: 240, height: 32 };
  world.start();
  world.type(f.pass, PASSWORD);
  world.submit(f.form);
  world.settle();
  assert.equal(JSON.stringify(world.sent).includes("honeypot-name"), false);
  assert.equal(captures(world).length, 1);

  // A text field wholly below the window with a value the page wrote is no user name either, and the field the person typed in
  // (before it in the page) is the user name instead.
  const below = createWorld();
  const g = /** @type {any} */ ({});
  g.form = below.document.body.append(below.document.createElement("form", { id: "login" }));
  g.user = addInput(below.document, g.form, { type: "text", name: "username", id: "user" }, { top: 100 });
  const honeypot = addInput(below.document, g.form, { type: "text", name: "alt", id: "alt", autocomplete: "username" }, { top: 4000 });
  g.pass = addInput(below.document, g.form, { type: "password", name: "password", id: "pass" }, { top: 160 });
  for (const el of [g.user, honeypot, g.pass]) el.form = g.form;
  honeypot.value = "honeypot@example.net";
  below.start();
  below.type(g.user, "anna");
  below.type(g.pass, PASSWORD);
  below.submit(g.form);
  below.settle();
  assert.equal(JSON.stringify(below.sent).includes("honeypot@example.net"), false, "the honeypot's value is not sent");
  assert.equal(captures(below)[0]?.username, "anna", "the typed user name is the one sent");
  // The same field once the person typed in it (it scrolled into reach) counts, and so does a password field below the window.
  const typedBelow = createWorld();
  const h = loginForm(typedBelow);
  h.user.rect = { left: 100, top: 4000, width: 240, height: 32 };
  typedBelow.start();
  typedBelow.type(h.user, "anna");
  typedBelow.type(h.pass, PASSWORD);
  typedBelow.submit(h.form);
  typedBelow.settle();
  assert.equal(captures(typedBelow)[0]?.username, "anna", "a user name the person typed in below the window");
});

test("the_capture_script_stops_and_reads_nothing_after_it", () => {
  const world = createWorld();
  const { user, pass, form } = loginForm(world);
  const script = world.start();
  world.type(user, "anna");
  world.type(pass, PASSWORD);
  world.submit(form);
  script.stop();
  world.settle();
  world.clock.advance(6000);
  assert.deepEqual(world.of("form_capture"), []);
  assert.equal(world.clock.pending(), 0, "no timer left");
  world.type(pass, "more");
  world.clock.advance(3000);
  world.submit(form);
  world.settle();
  assert.deepEqual(world.of("form_capture"), []);
});

test("the_capture_script_keeps_no_value_beyond_what_it_needs", () => {
  // The values it holds are the fields' own: it keeps no list and no copy outside a weak map, and it reads values only
  // of the two kinds of field the detection gives a role (the person's search and card boxes are never read).
  const world = createWorld();
  const { form, user, pass } = loginForm(world);
  const order = world.document.body.append(world.document.createElement("form", { id: "order" }));
  const card = addInput(world.document, order, { type: "text", name: "cardnumber", autocomplete: "cc-number" }, { top: 300 });
  card.form = order;
  let reads = 0;
  for (const element of [card]) {
    const own = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(element), "value");
    Object.defineProperty(element, "value", {
      get() { reads += 1; return own?.get?.call(element); },
      set(v) { own?.set?.call(element, v); },
    });
  }
  world.start();
  world.type(user, "anna");
  world.type(pass, PASSWORD);
  world.type(card, "4111111111111111");
  const readsAfterTyping = reads;
  world.submit(form);
  world.settle();
  assert.equal(captures(world).length, 1);
  assert.equal(JSON.stringify(world.sent).includes("4111"), false);
  assert.ok(reads - readsAfterTyping <= 0, "the card number was not read at the submission");
});

// ------------------------------------------------------------------ the script as it is built and run

const SRC = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "src");

/** @returns {Map<string, Buffer>} */
function sources() {
  /** @param {string} dir @returns {string[]} */
  const walk = (dir) => readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(join(dir, e.name)) : [join(dir, e.name)]));
  return new Map(walk(SRC).filter((p) => /\.mjs$/.test(p)).map((p) => [posix.normalize(p.slice(SRC.length + 1).split("\\").join("/")), readFileSync(p)]));
}

test("the_capture_script_is_one_classic_script_with_no_dependency_of_at_most_40_kib", () => {
  const files = sources();
  const script = classicScript(CAPTURE_ENTRY, files, contentMayInclude, { slim: true, name: CAPTURE_BUNDLE });
  assert.ok(Buffer.byteLength(script) <= 40 * 1024, `${Buffer.byteLength(script)} bytes`);
  assert.equal(CAPTURE_MAX_BYTES, 40 * 1024);
  // The files it is joined from: the entry, the capture, the detection module with its word lists. No protocol, no
  // schema checker, nothing of the background, nothing of the page's own.
  const joined = [...script.matchAll(/^\/\/ ---- (.+)$/gm)].map((m) => m[1]);
  assert.deepEqual(joined, ["content/capture.mjs", "content/patterns.mjs", "content/forms.mjs", "content/capture.entry.mjs"]);
  assert.doesNotMatch(script, /^\s*(?:import|export)\b/m);
  assert.doesNotMatch(script, /\bimport\s*\(|\bimport\.meta\b|\beval\s*\(|new Function|MutationObserver|postMessage|sendBeacon|XMLHttpRequest|\bfetch\s*\(|\bWebSocket\b|\bsubtle\b|localStorage|sessionStorage|indexedDB|\.storage\b|background\/|\bWorker\b|WebAssembly/);
  new vm.Script(script);
  // The script is slimmer than the fill script's way of joining and has no comment line of its own.
  assert.ok(!/^\s*\/\/(?! ----)/m.test(script.split("\n").slice(4).join("\n")), "no comment line below the header");
  // The capture itself imports nothing at all (the detection is handed in), and the entry only the two content files.
  assert.deepEqual([...(files.get("content/capture.mjs")?.toString("utf8").matchAll(/^import\b.*$/gm) ?? [])], []);
  assert.deepEqual([...(files.get("content/capture.entry.mjs")?.toString("utf8").matchAll(/from "([^"]+)"/g) ?? [])].map((m) => m[1]), ["./capture.mjs", "./forms.mjs"]);
});

test("slimming_a_module_drops_comment_lines_and_indentation_and_nothing_else", () => {
  const source = [
    "// header",
    "/* block",
    "   still a comment */",
    "const a = 1; // a trailing comment stays",
    "  /** @type {number} */ const b = 2;",
    "function f() {",
    "    return `x`;   ",
    "}",
    "",
    "  /**",
    "   * doc",
    "   */",
    "const re = /\\/\\//;",
    "",
  ].join("\n");
  // Only indentation goes: spaces at the end of a line stay.
  assert.equal(slimSource("x.mjs", source), [
    "const a = 1; // a trailing comment stays",
    "/** @type {number} */ const b = 2;",
    "function f() {",
    "return `x`;   ",
    "}",
    "const re = /\\/\\//;",
  ].join("\n"));
  assert.throws(() => slimSource("x.mjs", 'const s = "a\\\nb";\n'), /ends in a backslash/);
  // A literal over several lines is refused, whether it is real or a regular expression that made the lexer open one.
  for (const text of ["const t = `a   \nb`;\n", "const t = `x\n  // inside\n  y`;\n", "const r = /`/;\nconst t = `\n    inner\n`;\n"]) {
    assert.throws(() => slimSource("x.mjs", text), /runs over several lines/, text);
  }
  // On the real detection module and the word lists it removes only what is not code (the same lines, found another way).
  for (const name of ["forms", "patterns", "capture", "capture.entry"]) {
    const text = readFileSync(join(SRC, "content", `${name}.mjs`), "utf8");
    const expected = text.split("\n").map((l) => l.trimStart()).filter((l) => l.trim() !== "" && !/^(?:\/\/|\/\*|\*)/.test(l)).join("\n");
    assert.equal(slimSource(name, text), expected, name);
  }
});

/**
 * The built capture script run in a page of its own (a vm), with the browser's messaging faked: what it sends is what the
 * extension would decode.
 * @param {{ url?: string, origin?: string, withRuntime?: boolean }} [options]
 */
function runBuilt({ url = "https://example.com/login", origin, withRuntime = true } = {}) {
  const script = classicScript(CAPTURE_ENTRY, sources(), contentMayInclude, { slim: true, name: CAPTURE_BUNDLE });
  const { window, document } = createPage({ url, ...(origin ? { origin } : {}) });
  /** @type {string[]} */
  const raw = [];
  /** @type {Array<{ type: string, fn: (event: any) => void }>} */
  const listeners = [];
  const clock = fakeClock();
  Object.assign(window, {
    window,
    TextEncoder,
    JSON,
    Date: { now: () => clock.now() },
    setTimeout: (/** @type {() => void} */ fn, /** @type {number} */ ms) => clock.setTimeout(fn, ms),
    clearTimeout: (/** @type {number} */ id) => clock.clearTimeout(id),
    addEventListener: (/** @type {string} */ type, /** @type {(event: any) => void} */ fn) => { listeners.push({ type, fn }); },
    removeEventListener: () => {},
    ...(withRuntime ? { browser: { runtime: { sendMessage: async (/** @type {string} */ message) => { raw.push(message); } } } } : {}),
  });
  /** @type {any} */ (document).readyState = "complete";
  vm.runInContext(script, vm.createContext(window));
  return { window, document, raw, listeners, clock };
}

test("the_built_capture_script_starts_on_https_only_and_sends_what_the_extension_decodes", () => {
  // Not on http (loopback included), not in an opaque origin.
  for (const options of [{ url: "http://example.com/login" }, { url: "http://localhost/login" }, { url: "https://example.com/x", origin: "null" }]) {
    const page = runBuilt(options);
    assert.deepEqual(page.listeners, [], JSON.stringify(options));
    assert.equal(page.clock.pending(), 0, JSON.stringify(options));
  }

  // Without the extension's messaging (it is looked up when a message goes) a message is dropped and nothing throws.
  const unplugged = runBuilt({ withRuntime: false });
  assert.deepEqual(unplugged.raw, []);

  // On https it listens (five listeners at most, all on the window) and sends nothing until a password field is shown.
  const quiet = runBuilt();
  assert.deepEqual(quiet.raw, []);
  assert.ok(quiet.listeners.length <= 5, String(quiet.listeners.length));
  assert.deepEqual(quiet.listeners.map((l) => l.type).sort(), ["click", "input", "keydown", "submit"]);

  // A page with a sign-in form: page_ready, then a capture, as messages of the protocol.
  const loginPage = () => {
    const { window, document } = createPage({ url: "https://example.com/login" });
    const form = document.body.append(document.createElement("form", { id: "login" }));
    const user = addInput(document, form, { type: "text", name: "username" }, { top: 100 });
    const pass = addInput(document, form, { type: "password", name: "password" }, { top: 160 });
    user.form = form;
    pass.form = form;
    return { window, document, form, user, pass };
  };
  const { window, document, form, user, pass } = loginPage();
  const script = classicScript(CAPTURE_ENTRY, sources(), contentMayInclude, { slim: true, name: CAPTURE_BUNDLE });
  /** @type {string[]} */
  const raw = [];
  /** @type {Array<{ type: string, fn: (event: any) => void }>} */
  const listeners = [];
  const clock = fakeClock();
  Object.assign(window, {
    window,
    TextEncoder,
    Date: { now: () => clock.now() },
    setTimeout: (/** @type {() => void} */ fn, /** @type {number} */ ms) => clock.setTimeout(fn, ms),
    clearTimeout: (/** @type {number} */ id) => clock.clearTimeout(id),
    addEventListener: (/** @type {string} */ type, /** @type {(event: any) => void} */ fn) => { listeners.push({ type, fn }); },
    removeEventListener: () => {},
    browser: { runtime: { sendMessage: async (/** @type {string} */ message) => { raw.push(message); } } },
  });
  /** @type {any} */ (document).readyState = "complete";
  vm.runInContext(script, vm.createContext(window));
  const fire = (/** @type {string} */ type, /** @type {any} */ target, /** @type {Record<string, unknown>} */ init = {}) => {
    const event = { type, target, isTrusted: true, bubbles: true, composedPath: () => [target], ...init };
    for (const l of listeners.filter((x) => x.type === type)) l.fn(event);
  };
  for (const [el, text] of [[user, "anna"], [pass, PASSWORD]]) {
    for (const ch of text) {
      el.value += ch;
      fire("input", el);
    }
  }
  // The person clicks (the body: no control), and the form is submitted.
  fire("click", document.body);
  fire("submit", form);
  clock.advance(0);
  const messages = raw.map((r) => decode(r, CONTENT_TYPES));
  assert.deepEqual(messages.map((m) => m.type), ["page_ready", "form_capture"]);
  assert.deepEqual(messages[0].body, {});
  assert.deepEqual({ ...messages[1].body, capture_id: "x" }, {
    capture_id: "x", self_origin: "https://example.com", kind: "login", username: "anna", username_from: "typed", password: PASSWORD, current_password: null,
  });
  for (const m of messages) assert.match(m.id, /^[0-9a-f]{24}$/);
  // The form goes away: form_gone with the capture's id.
  document.body.remove(form);
  clock.advance(6000);
  const gone = raw.map((r) => decode(r, CONTENT_TYPES)).at(-1);
  assert.deepEqual(gone && { type: gone.type, body: gone.body }, { type: "form_gone", body: { capture_id: messages[1].body.capture_id } });

  // A message over 4 KiB is not sent (a control character takes six bytes in JSON).
  const wide = loginPage();
  const bigWindow = wide.window;
  /** @type {string[]} */
  const bigRaw = [];
  /** @type {Array<{ type: string, fn: (event: any) => void }>} */
  const bigListeners = [];
  const bigClock = fakeClock();
  Object.assign(bigWindow, {
    window: bigWindow, TextEncoder, Date: { now: () => bigClock.now() },
    setTimeout: (/** @type {() => void} */ fn, /** @type {number} */ ms) => bigClock.setTimeout(fn, ms),
    clearTimeout: (/** @type {number} */ id) => bigClock.clearTimeout(id),
    addEventListener: (/** @type {string} */ type, /** @type {(event: any) => void} */ fn) => { bigListeners.push({ type, fn }); },
    removeEventListener: () => {},
    browser: { runtime: { sendMessage: async (/** @type {string} */ message) => { bigRaw.push(message); } } },
  });
  /** @type {any} */ (wide.document).readyState = "complete";
  vm.runInContext(script, vm.createContext(bigWindow));
  wide.pass.value = "\u0001".repeat(1000);
  for (const l of bigListeners.filter((x) => x.type === "input")) l.fn({ type: "input", target: wide.pass, isTrusted: true, composedPath: () => [wide.pass] });
  wide.user.value = "\u0001".repeat(500);
  for (const l of bigListeners.filter((x) => x.type === "input")) l.fn({ type: "input", target: wide.user, isTrusted: true, composedPath: () => [wide.user] });
  for (const l of bigListeners.filter((x) => x.type === "submit")) l.fn({ type: "submit", target: wide.form, isTrusted: true, bubbles: true, composedPath: () => [wide.form] });
  bigClock.advance(0);
  assert.deepEqual(bigRaw.map((r) => JSON.parse(r).type), ["page_ready"], "the capture was too big to send");
});

test("the_capture_files_import_no_crypto_no_store_and_no_other_shared_module", () => {
  const files = sources();
  for (const name of ["content/capture.mjs", "content/capture.entry.mjs"]) {
    const text = slimSource(name, files.get(name)?.toString("utf8") ?? "");
    assert.doesNotMatch(text, /\bsubtle\b|SubtleCrypto|importKey|deriveKey|deriveBits|WebAssembly|\bWorker\b|indexedDB|localStorage|sessionStorage|\.storage\b|background\/|pkg-web|client\.mjs|\bargon2|\bhkdf\b|\bsha-?256\b/i, name);
    assert.doesNotMatch(text, /Math\.random|MutationObserver|postMessage|sendBeacon|XMLHttpRequest|\bfetch\s*\(|document\.(?:createElement|write)|\.(?:append|appendChild|insertBefore|prepend|replaceWith|setAttribute|removeAttribute|remove|innerHTML|outerHTML|insertAdjacentHTML)\b|\.style\b|\.classList\b|\.dataset\b/, `${name}: it reads the page and changes nothing`);
  }
});
