// The fill engine (src/content/fill.mjs) on fake pages: which fields it reports,
// which it refuses and why, and that it fills one value, once the extension
// asks, with the native setter. The ancestor rules have one test each.
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join, posix, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { createFillEngine, MIN_SIDE } from "../../src/content/fill.mjs";
import { importsOf, reach, readGraph } from "./importGraph.mjs";
import {
  addInput, addLoginForm, BACKGROUND_SENDER, createPage, decodeSent, EXTENSION_BASE, fillMessage, RUNTIME_ID,
} from "./fakeDom.mjs";

/** Starts an engine on a page. `begin()` reports and returns the fields. */
function setup(options = {}, build = addLoginForm) {
  const page = createPage(options);
  const parts = build(page.document);
  const sent = /** @type {string[]} */ ([]);
  const engine = createFillEngine({
    window: page.window,
    document: page.document,
    send: (raw) => { sent.push(raw); },
    runtimeId: RUNTIME_ID,
    extensionBase: EXTENSION_BASE,
  });
  const api = {
    ...page,
    ...parts,
    sent,
    engine,
    /** Reports under `requestId` and returns the reported fields. */
    begin(requestId = "req-1") {
      sent.length = 0;
      assert.equal(engine.begin(requestId), true);
      const [report] = decodeSent(sent);
      assert.equal(report.type, "frame_report");
      assert.equal(report.body.request_id, requestId);
      return /** @type {Array<{ kind: string, id: string }>} */ (report.body.fields);
    },
    /** Sends a fill_field from the background and returns the answer (or null when there is none). */
    fill(message = fillMessage(), sender = BACKGROUND_SENDER) {
      sent.length = 0;
      engine.onMessage(message, sender);
      const replies = decodeSent(sent);
      assert.ok(replies.length <= 1, "at most one answer");
      return replies.length === 0 ? null : replies[0].body;
    },
  };
  return api;
}

/** The value of an input as the browser holds it, past anything the page defined on the element. */
const nativeValue = (/** @type {any} */ input) =>
  /** @type {any} */ (Object.getOwnPropertyDescriptor(Object.getPrototypeOf(input), "value")).get.call(input);

const kinds = (/** @type {Array<{ kind: string }>} */ fields) => fields.map((f) => f.kind);

test("finds_username_and_password_fields_in_common_login_forms", () => {
  // The plain form: user name, then password.
  let t = setup();
  assert.deepEqual(kinds(t.begin()), ["username", "password"]);

  // An e-mail field that says so, with the autocomplete hints a site gives.
  t = setup({}, (document) => {
    const form = document.body.append(document.createElement("form"));
    const email = addInput(document, form, { type: "email", name: "x1", autocomplete: "username" }, { top: 100 });
    const pass = addInput(document, form, { type: "password", name: "x2", autocomplete: "current-password" }, { top: 160 });
    email.form = pass.form = form;
    return {};
  });
  assert.deepEqual(kinds(t.begin()), ["username", "password"]);

  // A text field with no hints, last before the password of its form: the user name.
  t = setup({}, (document) => {
    const form = document.body.append(document.createElement("form"));
    const first = addInput(document, form, { type: "text", name: "q1" }, { top: 100 });
    const second = addInput(document, form, { type: "text", name: "q2" }, { top: 140 });
    const pass = addInput(document, form, { type: "password", name: "q3" }, { top: 180 });
    first.form = second.form = pass.form = form;
    return { first, second, pass };
  });
  assert.deepEqual(kinds(t.begin()), ["username", "password"]);

  // A user name by its label, with no password on the page (the first step of a two-step form).
  t = setup({}, (document) => {
    addInput(document, document.body, { type: "text", "aria-label": "Your Login" });
    return {};
  });
  assert.deepEqual(kinds(t.begin()), ["username"]);

  // A password alone, and a one-time-code field.
  t = setup({}, (document) => {
    addInput(document, document.body, { type: "password" }, { top: 100 });
    addInput(document, document.body, { type: "text", autocomplete: "one-time-code" }, { top: 160 });
    addInput(document, document.body, { type: "text", name: "totp_code" }, { top: 220 });
    return {};
  });
  assert.deepEqual(kinds(t.begin()), ["password", "totp", "totp"]);

  // A form inside an open shadow root.
  t = setup({}, (document) => {
    const host = document.body.append(document.createElement("login-box"));
    const root = host.attachShadow({ mode: "open" });
    addInput(document, root, { type: "text", name: "user" }, { top: 100 });
    addInput(document, root, { type: "password" }, { top: 160 });
    return {};
  });
  assert.deepEqual(kinds(t.begin()), ["username", "password"]);

  // Other inputs are not fields: a checkbox, a hidden input, a search box, a button.
  t = setup({}, (document) => {
    for (const type of ["checkbox", "hidden", "submit", "radio", "file"]) addInput(document, document.body, { type });
    return {};
  });
  assert.deepEqual(t.begin(), []);

  // The report names the origin the page says it has, and carries no page text.
  t = setup({ url: "https://example.com:8443/in?x=1" });
  t.begin();
  assert.equal(decodeSent(t.sent)[0].body.self_origin, "https://example.com:8443");
});

test("never_fills_a_hidden_disabled_readonly_or_zero_size_field", () => {
  /** @type {Array<[string, (t: any) => void]>} */
  const cases = [
    ["display none", (t) => { t.pass.style.display = "none"; }],
    ["disabled", (t) => { t.pass.disabled = true; }],
    ["readonly", (t) => { t.pass.readOnly = true; }],
    ["zero width", (t) => { t.pass.rect.width = 0; }],
    ["zero height", (t) => { t.pass.rect.height = 0; }],
    ["one pixel", (t) => { t.pass.rect = { left: 100, top: 160, width: 1, height: 1 }; }],
    [`just under ${MIN_SIDE} pixels`, (t) => { t.pass.rect.width = MIN_SIDE - 1; }],
    ["moved far off screen", (t) => { t.pass.rect.left = -5000; }],
    ["below the viewport", (t) => { t.pass.rect.top = 5000; }],
    ["mostly outside the viewport", (t) => { t.pass.rect.left = 1280 - 40; }],
    ["half outside the viewport, the centre on its edge", (t) => { t.pass.rect.left = 1280 - 120; }],
    ["aria-hidden on the field", (t) => { t.pass.setAttribute("aria-hidden", "true"); }],
    ["aria-hidden on the form", (t) => { t.form.setAttribute("aria-hidden", "true"); }],
    ["inert form", (t) => { t.form.inert = true; }],
    ["not a number rect", (t) => { t.pass.rect.width = Number.NaN; }],
    ["removed from the page", (t) => { t.form.remove(t.pass); }],
  ];
  for (const [label, hide] of cases) {
    // Hidden after the report: the fill is refused and nothing is written.
    const t = setup();
    t.begin();
    hide(t);
    const answer = t.fill();
    assert.equal(answer?.ok, false, label);
    assert.equal(answer?.reason, label === "removed from the page" ? "gone" : "hidden", label);
    assert.equal(nativeValue(t.pass), "", label);
    assert.deepEqual(t.pass.events, [], label);

    // Hidden before the report: the field is not reported at all.
    const u = setup();
    hide(u);
    assert.deepEqual(kinds(u.begin()).filter((k) => k === "password"), [], `${label}: not reported`);
  }
  // Control: the same page unhidden fills.
  const control = setup();
  control.begin();
  assert.deepEqual(control.fill(), { request_id: "req-1", ok: true });
  assert.equal(nativeValue(control.pass), "s3cret");
});

test("refuses_a_field_under_an_overlay", () => {
  /** @type {Array<[string, (t: any) => any]>} */
  const overlays = [
    ["a full overlay", (t) => ({ left: 90, top: 150, width: 260, height: 52 })],
    ["an overlay over the right half", (t) => ({ left: 220, top: 150, width: 200, height: 52 })],
    ["an overlay over the left quarter", (t) => ({ left: 80, top: 150, width: 90, height: 52 })],
    ["an overlay over the upper half", (t) => ({ left: 90, top: 150, width: 260, height: 20 })],
  ];
  for (const [label, rect] of overlays) {
    const t = setup();
    t.begin();
    const cover = t.document.createElement("div");
    t.document.body.append(cover);
    cover.rect = rect(t);
    cover.z = 10;
    const answer = t.fill();
    assert.deepEqual(answer, { request_id: "req-1", ok: false, reason: "covered" }, label);
    assert.equal(nativeValue(t.pass), "", label);

    // An overlay already there is never reported over.
    const u = setup();
    const c2 = u.document.createElement("div");
    u.document.body.append(c2);
    c2.rect = rect(u);
    c2.z = 10;
    assert.equal(kinds(u.begin()).includes("password"), false, `${label}: not reported`);
  }
  // A field that a clipping ancestor cuts out of the hit test is covered too.
  const clipped = setup();
  clipped.begin();
  clipped.pass.hitBlocked = true;
  assert.equal(clipped.fill()?.reason, "covered");
  // A cover that is not over the field leaves it alone.
  const away = setup();
  away.begin();
  const aside = away.document.createElement("div");
  away.document.body.append(aside);
  aside.rect = { left: 600, top: 150, width: 100, height: 52 };
  aside.z = 10;
  assert.equal(away.fill()?.ok, true);
});

/**
 * One ancestor rule: a style on a wrapper above the field, put there before or
 * after the report, refuses the field.
 * @param {Record<string, string>} style
 * @param {string} label
 */
function ancestorRefuses(style, label) {
  const build = (/** @type {any} */ document) => {
    const outer = document.body.append(document.createElement("div"));
    const inner = outer.append(document.createElement("div"));
    const form = inner.append(document.createElement("form"));
    const user = addInput(document, form, { type: "text", name: "username" }, { top: 100 });
    const pass = addInput(document, form, { type: "password" }, { top: 160 });
    user.form = pass.form = form;
    return { outer, inner, form, user, pass };
  };
  for (const level of ["outer", "inner", "form"]) {
    // After the report.
    const t = setup({}, build);
    t.begin();
    Object.assign(t[level].style, style);
    assert.deepEqual(t.fill(), { request_id: "req-1", ok: false, reason: "hidden" }, `${label} on ${level}`);
    assert.equal(nativeValue(t.pass), "", label);
    assert.deepEqual(t.pass.events, [], label);
    // Before the report.
    const u = setup({}, build);
    Object.assign(u[level].style, style);
    assert.deepEqual(u.begin(), [], `${label} on ${level}: nothing reported`);
  }
  // Control: without the style the same page fills.
  const control = setup({}, build);
  control.begin();
  assert.equal(control.fill()?.ok, true, `${label}: control`);
}

test("refuses_when_an_ancestor_has_opacity_below_one", () => {
  ancestorRefuses({ opacity: "0.99" }, "opacity 0.99");
  ancestorRefuses({ opacity: "0" }, "opacity 0");
  ancestorRefuses({ opacity: "" }, "an opacity that cannot be read");
});

test("refuses_when_an_ancestor_has_visibility_not_visible", () => {
  ancestorRefuses({ visibility: "hidden" }, "visibility hidden");
  ancestorRefuses({ visibility: "collapse" }, "visibility collapse");
});

test("refuses_when_an_ancestor_has_a_filter", () => {
  ancestorRefuses({ filter: "opacity(0.05)" }, "filter opacity()");
  ancestorRefuses({ filter: "blur(0px)" }, "filter blur(0)");
  ancestorRefuses({ filter: "invert(1)" }, "filter invert");
});

test("refuses_when_an_ancestor_has_a_transform", () => {
  ancestorRefuses({ transform: "matrix(1, 0, 0, 1, 0, 0)" }, "an identity transform");
  ancestorRefuses({ transform: "translateY(-9000px)" }, "a translation");
  // The separate transform properties move a field and leave `transform` at none.
  ancestorRefuses({ translate: "0 5000px" }, "translate");
  ancestorRefuses({ rotate: "180deg" }, "rotate");
  ancestorRefuses({ scale: "0" }, "scale");
  ancestorRefuses({ perspective: "100px" }, "perspective");
});

test("refuses_when_an_ancestor_has_a_clip_path", () => {
  ancestorRefuses({ "clip-path": "inset(100%)" }, "clip-path inset");
  ancestorRefuses({ "clip-path": "circle(0)" }, "clip-path circle");
  ancestorRefuses({ clip: "rect(0, 0, 0, 0)" }, "the old clip property");
});

test("refuses_when_an_ancestor_has_a_mask", () => {
  ancestorRefuses({ "mask-image": "linear-gradient(transparent, transparent)" }, "mask-image");
  ancestorRefuses({ "-webkit-mask-image": "url(x.svg)" }, "-webkit-mask-image");
  ancestorRefuses({ "mask-border-source": "url(x.png)" }, "mask-border-source");
});

test("refuses_when_an_ancestor_has_a_mix_blend_mode", () => {
  ancestorRefuses({ "mix-blend-mode": "multiply" }, "multiply");
  ancestorRefuses({ "mix-blend-mode": "difference" }, "difference");
});

test("the_field_itself_and_a_non_rendered_ancestor_are_refused_too", () => {
  ancestorRefuses({ display: "none" }, "display none");
  // The same properties on the field itself.
  for (const style of [{ opacity: "0.5" }, { filter: "blur(1px)" }, { transform: "scale(1)" }, { "mix-blend-mode": "screen" }, { visibility: "hidden" }]) {
    const t = setup();
    t.begin();
    Object.assign(t.pass.style, style);
    assert.equal(t.fill()?.reason, "hidden", JSON.stringify(style));
  }
  // An ancestor with aria-hidden or inert.
  const aria = setup({}, (document) => {
    const wrap = document.body.append(document.createElement("div", { "aria-hidden": "true" }));
    addInput(document, wrap, { type: "password" });
    return {};
  });
  assert.deepEqual(aria.begin(), []);
  // `aria-hidden="false"` is not a reason.
  const open = setup({}, (document) => {
    const wrap = document.body.append(document.createElement("div", { "aria-hidden": "false" }));
    addInput(document, wrap, { type: "password" });
    return {};
  });
  assert.deepEqual(kinds(open.begin()), ["password"]);
});

test("the_ancestor_walk_reaches_the_document_element", () => {
  for (const style of [{ opacity: "0.9" }, { filter: "grayscale(0)" }, { transform: "translateX(0)" }]) {
    const t = setup();
    t.begin();
    Object.assign(t.document.documentElement.style, style);
    assert.equal(t.fill()?.reason, "hidden", `html ${JSON.stringify(style)}`);
    const u = setup();
    Object.assign(u.document.body.style, style);
    assert.deepEqual(u.begin(), [], `body ${JSON.stringify(style)}`);
  }
});

test("the_ancestor_walk_crosses_shadow_roots", () => {
  /** A field in a shadow tree: wrapper > host > (shadow) shell > field. */
  const build = (/** @type {"open" | "closed"} */ mode) => (/** @type {any} */ document) => {
    const wrapper = document.body.append(document.createElement("div"));
    const host = wrapper.append(document.createElement("login-box"));
    const root = host.attachShadow({ mode });
    const shell = root.append(document.createElement("div"));
    const pass = addInput(document, shell, { type: "password" }, { top: 160 });
    return { wrapper, host, root, shell, pass };
  };
  for (const mode of /** @type {const} */ (["open", "closed"])) {
    // Control first: the field is found and filled.
    const control = setup({}, build(mode));
    assert.deepEqual(kinds(control.begin()), ["password"], `${mode}: found`);
    assert.equal(control.fill()?.ok, true, `${mode}: control`);

    // A style inside the shadow tree, on the host, and above the host.
    for (const level of ["shell", "host", "wrapper"]) {
      for (const style of [{ opacity: "0.5" }, { filter: "blur(2px)" }, { "mix-blend-mode": "multiply" }]) {
        const t = setup({}, build(mode));
        t.begin();
        Object.assign(t[level].style, style);
        assert.deepEqual(t.fill(), { request_id: "req-1", ok: false, reason: "hidden" }, `${mode} ${level} ${JSON.stringify(style)}`);
        assert.equal(nativeValue(t.pass), "");
        const u = setup({}, build(mode));
        Object.assign(u[level].style, style);
        assert.deepEqual(u.begin(), [], `${mode} ${level} ${JSON.stringify(style)}: not reported`);
      }
    }
    // An overlay in the outer document over the host: the shadow root alone cannot see it.
    const over = setup({}, build(mode));
    over.begin();
    const cover = over.document.createElement("div");
    over.document.body.append(cover);
    cover.rect = { left: 90, top: 150, width: 260, height: 52 };
    cover.z = 10;
    assert.equal(over.fill()?.reason, "covered", `${mode}: overlay above the host`);
  }

  // A field in the light tree that a shadow host slots: the slot's ancestors count.
  const slotted = (/** @type {"open" | "closed"} */ mode, /** @type {boolean} */ withSlot) => (/** @type {any} */ document) => {
    const host = document.body.append(document.createElement("login-box"));
    const root = host.attachShadow({ mode });
    const frame = root.append(document.createElement("div"));
    if (withSlot) frame.append(document.createElement("slot"));
    const pass = addInput(document, host, { type: "password" }, { top: 160 });
    return { host, root, frame, pass };
  };
  for (const mode of /** @type {const} */ (["open", "closed"])) {
    const control = setup({}, slotted(mode, true));
    assert.deepEqual(kinds(control.begin()), ["password"], `${mode} slotted: found`);
    const t = setup({}, slotted(mode, true));
    t.begin();
    t.frame.style.opacity = "0.01";
    assert.equal(t.fill()?.reason, "hidden", `${mode}: a style on the slot's parent in the shadow tree`);
    const u = setup({}, slotted(mode, true));
    u.frame.style.filter = "blur(1px)";
    assert.deepEqual(u.begin(), [], `${mode}: reported before`);
    // A child that no slot takes is not drawn.
    const none = setup({}, slotted(mode, false));
    assert.deepEqual(none.begin(), [], `${mode}: no slot, not drawn`);
  }
});

test("a_password_value_goes_only_into_a_password_input", () => {
  // The field turns into a text field after the report (a "show password" switch).
  const shown = setup();
  shown.begin();
  shown.pass.setAttribute("type", "text");
  assert.deepEqual(shown.fill(), { request_id: "req-1", ok: false, reason: "wrong_kind" });
  assert.equal(nativeValue(shown.pass), "");
  assert.deepEqual(shown.pass.events, []);

  // A page with a text field and no password input.
  const textOnly = setup({}, (document) => {
    addInput(document, document.body, { type: "text", name: "username" });
    return {};
  });
  assert.deepEqual(kinds(textOnly.begin()), ["username"]);
  assert.deepEqual(textOnly.fill(), { request_id: "req-1", ok: false, reason: "wrong_kind" });

  // A user name never goes into a password input, a one-time code neither.
  const swapped = setup();
  swapped.begin();
  swapped.user.setAttribute("type", "password");
  assert.equal(swapped.fill(fillMessage({ field: "username", value: "alice" }))?.reason, "wrong_kind");
  assert.equal(nativeValue(swapped.user), "");

  // A password goes into the password input, and only there.
  const fine = setup();
  fine.begin();
  assert.equal(fine.fill(fillMessage({ field: "password", value: "pw-1" }))?.ok, true);
  assert.equal(nativeValue(fine.pass), "pw-1");
  assert.equal(nativeValue(fine.user), "");
  assert.equal(fine.fill(fillMessage({ field: "username", value: "alice" }))?.ok, true);
  assert.equal(nativeValue(fine.user), "alice");
  assert.equal(nativeValue(fine.pass), "pw-1");
});

test("refuses_when_the_frame_navigated_after_the_report", () => {
  const expectations = {
    "a new address in the same document (a fragment)": (t) => { t.window.location.href = "https://example.com/login#x"; },
    "a new path": (t) => { t.window.location.href = "https://example.com/other"; },
    "a new origin": (t) => {
      t.window.location.href = "https://evil.example/login";
      t.window.location.origin = "https://evil.example";
      t.window.origin = "https://evil.example";
    },
  };
  for (const [label, navigate] of Object.entries(expectations)) {
    const t = setup();
    t.begin();
    navigate(t);
    assert.deepEqual(t.fill(), { request_id: "req-1", ok: false, reason: "origin_changed" }, label);
    assert.equal(nativeValue(t.pass), "", label);
    // The request is over: going back to the old address does not revive it.
    t.window.location.href = "https://example.com/login";
    t.window.location.origin = "https://example.com";
    t.window.origin = "https://example.com";
    assert.equal(t.fill(), null, `${label}: the request ended`);
    assert.equal(nativeValue(t.pass), "", label);
  }
  // The extension's expectation decides, not the report: a different origin or address in the message.
  for (const override of [{ origin: "https://other.example" }, { frameUrl: "https://example.com/elsewhere" }, { origin: "null" }]) {
    const t = setup();
    t.begin();
    assert.equal(t.fill(fillMessage(override))?.reason, "origin_changed", JSON.stringify(override));
    assert.equal(nativeValue(t.pass), "");
  }
});

test("reports_self_origin_null_in_a_sandboxed_frame", () => {
  // A sandboxed frame has an https address, an opaque origin, and the address still shows "https://...".
  const t = setup({ url: "https://example.com/login", selfOrigin: "null" });
  const fields = t.begin();
  assert.deepEqual(kinds(fields), ["username", "password"]);
  t.sent.length = 0;
  t.engine.begin("req-2");
  assert.equal(decodeSent(t.sent)[0].body.self_origin, "null");
  // Even if the extension named this address as the origin, the frame is not filled.
  const answer = t.fill(fillMessage({ requestId: "req-2" }));
  assert.deepEqual(answer, { request_id: "req-2", ok: false, reason: "origin_changed" });
  assert.equal(nativeValue(t.pass), "");
  // A frame with no origin value at all reports "null" as well.
  const odd = setup();
  odd.window.origin = undefined;
  odd.sent.length = 0;
  odd.engine.begin("req-3");
  assert.equal(decodeSent(odd.sent)[0].body.self_origin, "null");
});

test("a_fill_without_the_pending_request_id_does_nothing", () => {
  const t = setup();
  // Nothing pending yet.
  assert.equal(t.fill(), null);
  assert.equal(nativeValue(t.pass), "");
  t.begin("req-1");
  // Another id.
  assert.equal(t.fill(fillMessage({ requestId: "req-2" })), null);
  assert.equal(nativeValue(t.pass), "");
  assert.deepEqual(t.pass.events, []);
  // A new request replaces the old one: the old id no longer works.
  t.begin("req-3");
  assert.equal(t.fill(fillMessage({ requestId: "req-1" })), null);
  assert.equal(nativeValue(t.pass), "");
  assert.equal(t.fill(fillMessage({ requestId: "req-3" }))?.ok, true);
  assert.equal(nativeValue(t.pass), "s3cret");
  // An id that is not a valid request id does not start a request.
  const u = setup();
  for (const bad of ["", "has space", "x".repeat(65), "a/b", undefined, 5]) {
    assert.equal(u.engine.begin(/** @type {any} */ (bad)), false);
  }
  assert.deepEqual(u.sent, []);
  assert.equal(u.fill(), null);
});

test("only_the_extension_can_ask_for_a_fill", () => {
  const t = setup();
  t.begin();
  const bad = [
    ["no sender", null],
    ["another extension", { id: "other@example.org", url: `${EXTENSION_BASE}background/main.mjs` }],
    ["a web page url", { id: RUNTIME_ID, url: "https://example.com/login" }],
    ["a data url", { id: RUNTIME_ID, url: "data:text/html,x" }],
    ["no url", { id: RUNTIME_ID }],
    ["a look-alike extension url", { id: RUNTIME_ID, url: "moz-extension://00000000-0000-4000-8000-000000000000/x.html" }],
  ];
  for (const [label, sender] of bad) {
    assert.equal(t.fill(fillMessage(), /** @type {any} */ (sender)), null, String(label));
    assert.equal(nativeValue(t.pass), "", String(label));
  }
  // Messages that are not a valid fill_field are dropped without an answer.
  const garbage = [
    "not json",
    "{}",
    JSON.stringify({ v: 1, id: "a", type: "fill_field", body: { request_id: "req-1", field: "password", value: "x", expect: { origin: "https://example.com", frameUrl: "https://example.com/login" }, extra: 1 } }),
    JSON.stringify({ v: 1, id: "a", type: "frame_report", body: { request_id: "req-1", self_origin: "x", fields: [] } }),
    JSON.stringify({ v: 1, id: "a", type: "copy", body: { ref: "r", field: "password" } }),
    42,
    null,
  ];
  for (const message of garbage) {
    assert.equal(t.fill(/** @type {any} */ (message)), null, String(message).slice(0, 40));
  }
  assert.equal(nativeValue(t.pass), "");
  // And the real one still works.
  assert.equal(t.fill()?.ok, true);
});

test("fills_with_the_native_setter_and_fires_input_and_change", () => {
  const t = setup();
  t.begin();
  // The page tries to intercept: a setter on the element, and one on the prototype it can reach.
  const intercepted = /** @type {string[]} */ ([]);
  Object.defineProperty(t.user, "value", { configurable: true, get: () => "spoofed", set: (v) => { intercepted.push(v); } });
  Object.defineProperty(t.pass, "value", { configurable: true, get: () => "spoofed", set: (v) => { intercepted.push(v); } });
  const seen = /** @type {string[]} */ ([]);
  t.form.addEventListener("input", (/** @type {any} */ e) => seen.push(`input:${e.type}`));
  t.form.addEventListener("change", (/** @type {any} */ e) => seen.push(`change:${e.type}`));

  assert.deepEqual(t.fill(fillMessage({ field: "username", value: "alice@example.com" })), { request_id: "req-1", ok: true });
  assert.deepEqual(t.fill(fillMessage({ field: "password", value: "p\u00e5ssw\u00f8rd \u{1F600}" })), { request_id: "req-1", ok: true });
  assert.deepEqual(intercepted, [], "the page's own setter was never called");
  assert.equal(nativeValue(t.user), "alice@example.com");
  assert.equal(nativeValue(t.pass), "p\u00e5ssw\u00f8rd \u{1F600}");
  assert.deepEqual(t.user.events, ["input", "change"]);
  assert.deepEqual(t.pass.events, ["input", "change"]);
  assert.deepEqual(seen, ["input:input", "change:change", "input:input", "change:change"], "both events bubble");
  // The answer carries no value.
  const raw = t.sent.join("");
  assert.equal(raw.includes("p\u00e5ssw"), false);

  // A page that replaced the prototype setter after the engine started does not matter either.
  const late = setup();
  const proto = late.window.HTMLInputElement.prototype;
  const original = /** @type {PropertyDescriptor} */ (Object.getOwnPropertyDescriptor(proto, "value"));
  late.begin();
  Object.defineProperty(proto, "value", { configurable: true, get: () => "spoofed", set: () => { throw new Error("the page's setter ran"); } });
  try {
    assert.equal(late.fill()?.ok, true);
  } finally {
    Object.defineProperty(proto, "value", original);
  }
  assert.equal(nativeValue(late.pass), "s3cret");
});

test("fills_one_value_at_a_time_into_the_first_field_of_the_kind", () => {
  const t = setup({}, (document) => {
    const form = document.body.append(document.createElement("form"));
    const user = addInput(document, form, { type: "text", name: "username" }, { top: 100 });
    const pass = addInput(document, form, { type: "password", name: "current" }, { top: 160 });
    const again = addInput(document, form, { type: "password", name: "repeat" }, { top: 220 });
    user.form = pass.form = again.form = form;
    return { user, pass, again };
  });
  assert.deepEqual(kinds(t.begin()), ["username", "password", "password"]);
  assert.equal(t.fill()?.ok, true);
  assert.equal(nativeValue(t.pass), "s3cret");
  assert.equal(nativeValue(t.again), "");
  assert.equal(nativeValue(t.user), "");
});

test("field_ids_are_random_per_injection_and_never_page_supplied", () => {
  const t = setup({}, (document) => {
    const form = document.body.append(document.createElement("form", { id: "form-id" }));
    const user = addInput(document, form, { type: "text", id: "user", name: "username", "data-ferret-id": "abc", class: "u1" }, { top: 100 });
    const pass = addInput(document, form, { type: "password", id: "pass", name: "password" }, { top: 160 });
    user.form = pass.form = form;
    return {};
  });
  const seen = new Set();
  const pageText = new Set(["user", "pass", "username", "password", "abc", "form-id", "u1"]);
  for (let i = 0; i < 20; i += 1) {
    const fields = t.begin(`req-${i}`);
    assert.equal(fields.length, 2);
    for (const { id } of fields) {
      assert.match(id, /^[0-9a-f]{32}$/);
      assert.equal(pageText.has(id), false, "not an attribute of the page");
      assert.equal(seen.has(id), false, "never repeated");
      seen.add(id);
    }
    assert.notEqual(fields[0].id, fields[1].id);
  }
  assert.equal(seen.size, 40);
  // A second engine on the same page makes other ids.
  const other = setup();
  assert.equal([...other.begin().map((f) => f.id)].some((id) => seen.has(id)), false);
});

test("a_report_lists_at_most_64_fields_and_nothing_is_sent_before_begin", () => {
  const many = setup({}, (document) => {
    // 80 fields that all pass: 4 columns, 20 rows, none over another.
    for (let i = 0; i < 80; i += 1) {
      addInput(document, document.body, { type: "password" }, { left: (i % 4) * 300, top: 10 + Math.floor(i / 4) * 38, width: 240, height: 30 });
    }
    return {};
  });
  assert.deepEqual(many.sent, [], "creating an engine reports nothing");
  assert.equal(many.begin().length, 64);
});

test("the_content_script_imports_no_crypto_and_no_shared_store", () => {
  const src = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "src");
  /** @param {string} dir @returns {string[]} */
  const walk = (dir) => readdirSync(join(dir), { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(join(dir, e.name)) : [join(dir, e.name)]));
  const files = new Map(walk(src).filter((p) => /\.(?:mjs|js)$/.test(p)).map((p) => [posix.normalize(p.slice(src.length + 1).split("\\").join("/")), Buffer.from(readFileSync(p))]));

  const ALLOWED = new Set(["content/entry.mjs", "content/fill.mjs", "shared/protocol.mjs", "shared/schema.mjs"]);
  const FORBIDDEN_TEXT = /\bsubtle\b|SubtleCrypto|importKey|deriveKey|deriveBits|WebAssembly|\bWorker\b|indexedDB|localStorage|sessionStorage|\.storage\b|background\/|pkg-web|client\.mjs|\bargon2|\bhkdf\b|\bsha-?256\b/i;
  /** @param {Map<string, Buffer>} map @returns {string[]} */
  const problems = (map) => {
    const graph = readGraph(map);
    const roots = [...map.keys()].filter((p) => p.startsWith("content/"));
    const reached = reach(graph.edges, roots);
    /** @type {string[]} */
    const out = [];
    for (const p of reached) {
      if (!ALLOWED.has(p)) out.push(`${p}: reached from content/`);
      else if (FORBIDDEN_TEXT.test(map.get(p)?.toString("utf8") ?? "")) out.push(`${p}: names crypto, storage or the background`);
    }
    for (const p of graph.hidden) if (reached.has(p)) out.push(`${p}: an import() with no string literal`);
    for (const [path, edges] of graph.edges) {
      if (!path.startsWith("content/")) continue;
      for (const { specifier, target } of edges) if (target === null) out.push(`${path}: imports ${specifier}`);
    }
    return out;
  };

  assert.deepEqual(problems(files), []);
  // Not vacuous: the content files exist, reach the protocol, and the reader sees their imports.
  assert.ok(files.has("content/fill.mjs") && files.has("content/entry.mjs"));
  assert.deepEqual(importsOf(files.get("content/fill.mjs")?.toString("utf8") ?? "").specifiers, ["../shared/protocol.mjs"]);
  assert.deepEqual(importsOf(files.get("content/entry.mjs")?.toString("utf8") ?? "").specifiers, ["./fill.mjs"]);

  // The check finds what it is for.
  const plant = (/** @type {string} */ text) => problems(new Map([...files, ["content/fill.mjs", Buffer.from(`${files.get("content/fill.mjs")}\n${text}\n`)]]));
  assert.notDeepEqual(plant('import "../shared/origin.mjs";'), [], "another shared module");
  assert.notDeepEqual(plant('import "../background/coreHost.mjs";'), [], "the core host");
  assert.notDeepEqual(plant('import "../js/client.mjs";'), [], "the wasm client");
  assert.notDeepEqual(plant('import "../store/db.mjs";'), [], "a store");
  assert.notDeepEqual(plant("export const k = (p) => import(p);"), [], "a hidden import");
  assert.notDeepEqual(plant("export const k = () => crypto.subtle.digest('SHA-256', new Uint8Array());"), [], "WebCrypto");
  assert.notDeepEqual(plant("export const s = () => browser.storage.local.get();"), [], "the extension storage");
  assert.notDeepEqual(plant("export const s = () => indexedDB.open('x');"), [], "IndexedDB");
  assert.notDeepEqual(plant('import "lodash";'), [], "a package");
});
