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
  addInput, addLoginForm, addText, BACKGROUND_SENDER, createPage, decodeSent, EXTENSION_BASE, fillMessage, RUNTIME_ID,
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
  assert.deepEqual(kinds(t.begin()), ["password", "totp"], "the first code field of the group");

  // A page with a code field only (the second step of a sign-in).
  t = setup({}, (document) => {
    addInput(document, document.body, { type: "text", autocomplete: "one-time-code" }, { top: 100 });
    return {};
  });
  assert.deepEqual(kinds(t.begin()), ["totp"]);

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

test("fills_one_value_at_a_time_and_a_second_password_field_is_left_alone", () => {
  const t = setup({}, (document) => {
    const form = document.body.append(document.createElement("form"));
    const user = addInput(document, form, { type: "text", name: "username" }, { top: 100 });
    const pass = addInput(document, form, { type: "password", name: "current" }, { top: 160 });
    const again = addInput(document, form, { type: "password", name: "repeat" }, { top: 220 });
    user.form = pass.form = again.form = form;
    return { user, pass, again };
  });
  assert.deepEqual(kinds(t.begin()), ["username", "password"]);
  assert.equal(t.fill()?.ok, true);
  assert.equal(nativeValue(t.pass), "s3cret");
  assert.equal(nativeValue(t.again), "");
  assert.equal(nativeValue(t.user), "");
});

/** A form with a user name and a password at `top`, under `parent`. */
function formAt(/** @type {any} */ document, /** @type {any} */ parent, /** @type {string} */ prefix, /** @type {number} */ top, /** @type {Record<string, string>} */ userAttrs = { autocomplete: "username" }) {
  const form = parent.append(document.createElement("form", { id: `${prefix}-form` }));
  const user = addInput(document, form, { type: "text", name: `${prefix}-user`, ...userAttrs }, { top });
  const pass = addInput(document, form, { type: "password", name: `${prefix}-pass`, autocomplete: "current-password" }, { top: top + 60 });
  user.form = pass.form = form;
  return { form, user, pass };
}

/** Fills the kinds in turn and says where the values went. */
function fillBoth(/** @type {any} */ t, /** @type {Record<string, any>} */ elements) {
  assert.equal(t.fill(fillMessage({ field: "username", value: "alice" }))?.ok, true);
  assert.equal(t.fill(fillMessage({ field: "password", value: "pw-1" }))?.ok, true);
  return Object.fromEntries(Object.entries(elements).map(([name, element]) => [name, nativeValue(element)]));
}

test("a_hostile_form_with_a_visible_user_name_and_a_covered_password_gets_nothing", () => {
  // The layout of the overlay test page: the first form has its password under a
  // transparent cover and a visible user name; a clear form follows.
  const t = setup({}, (document) => {
    const bad = formAt(document, document.body, "bad", 100);
    const cover = document.createElement("div");
    document.body.append(cover);
    cover.rect = { left: 90, top: 150, width: 260, height: 52 };
    cover.z = 10;
    const ok = formAt(document, document.body, "ok", 300);
    return { bad, ok };
  });
  assert.deepEqual(kinds(t.begin()), ["username", "password"]);
  const placed = fillBoth(t, { badUser: t.bad.user, badPass: t.bad.pass, okUser: t.ok.user, okPass: t.ok.pass });
  assert.deepEqual(placed, { badUser: "", badPass: "", okUser: "alice", okPass: "pw-1" });
});

test("a_newsletter_box_before_the_sign_in_form_gets_nothing", () => {
  // With a form around the sign-in fields.
  const withForm = setup({}, (document) => {
    const header = document.body.append(document.createElement("header"));
    const news = addInput(document, header, { type: "email", name: "email", placeholder: "Your e-mail" }, { top: 20 });
    const login = formAt(document, document.body, "login", 100, { name: "q1" });
    return { news, login };
  });
  assert.deepEqual(kinds(withForm.begin()), ["username", "password"]);
  assert.deepEqual(fillBoth(withForm, { news: withForm.news, user: withForm.login.user, pass: withForm.login.pass }), { news: "", user: "alice", pass: "pw-1" });

  // Without any form: the sign-in fields share a container, the newsletter box is outside it.
  const loose = setup({}, (document) => {
    const header = document.body.append(document.createElement("header"));
    const news = addInput(document, header, { type: "email", name: "email" }, { top: 20 });
    const main = document.body.append(document.createElement("main"));
    const user = addInput(document, main, { type: "text", name: "q1" }, { top: 100 });
    const pass = addInput(document, main, { type: "password" }, { top: 160 });
    // A code field in another part of the page is not part of this sign-in.
    const aside = document.body.append(document.createElement("aside"));
    addInput(document, aside, { type: "text", autocomplete: "one-time-code" }, { top: 400 });
    return { news, user, pass };
  });
  assert.deepEqual(kinds(loose.begin()), ["username", "password"]);
  assert.deepEqual(fillBoth(loose, { news: loose.news, user: loose.user, pass: loose.pass }), { news: "", user: "alice", pass: "pw-1" });

  // Everything directly under the body: the user name field nearest the password is the user name.
  // (On the whole page an unnamed text field is never taken: see the password-only test below.)
  const flat = setup({}, (document) => {
    const news = addInput(document, document.body, { type: "email", name: "email" }, { top: 20 });
    const user = addInput(document, document.body, { type: "text", name: "login" }, { top: 100 });
    const pass = addInput(document, document.body, { type: "password" }, { top: 160 });
    return { news, user, pass };
  });
  assert.deepEqual(kinds(flat.begin()), ["username", "password"]);
  assert.deepEqual(fillBoth(flat, { news: flat.news, user: flat.user, pass: flat.pass }), { news: "", user: "alice", pass: "pw-1" });
});

test("a_change_password_page_fills_the_current_password_and_never_a_new_one", () => {
  const t = setup({}, (document) => {
    const form = document.body.append(document.createElement("form"));
    const user = addInput(document, form, { type: "text", name: "username", autocomplete: "username" }, { top: 100 });
    const current = addInput(document, form, { type: "password", name: "old", autocomplete: "current-password" }, { top: 160 });
    const fresh = addInput(document, form, { type: "password", name: "new", autocomplete: "new-password" }, { top: 220 });
    const again = addInput(document, form, { type: "password", name: "new2", autocomplete: "new-password" }, { top: 280 });
    for (const input of [user, current, fresh, again]) input.form = form;
    return { user, current, fresh, again };
  });
  assert.deepEqual(kinds(t.begin()), ["username", "password"]);
  assert.deepEqual(fillBoth(t, { user: t.user, current: t.current, fresh: t.fresh, again: t.again }), { user: "alice", current: "pw-1", fresh: "", again: "" });

  // A page whose first password field sets a new one: the stored password goes into the other.
  const firstNew = setup({}, (document) => {
    const form = document.body.append(document.createElement("form"));
    const fresh = addInput(document, form, { type: "password", autocomplete: "new-password" }, { top: 160 });
    const current = addInput(document, form, { type: "password", autocomplete: "current-password" }, { top: 220 });
    fresh.form = current.form = form;
    return { fresh, current };
  });
  assert.deepEqual(kinds(firstNew.begin()), ["password"]);
  assert.equal(firstNew.fill()?.ok, true);
  assert.equal(nativeValue(firstNew.fresh), "");
  assert.equal(nativeValue(firstNew.current), "s3cret");

  // A sign-up page: only new-password fields, so no password is reported and none is filled.
  const signUp = setup({}, (document) => {
    const form = document.body.append(document.createElement("form"));
    const fresh = addInput(document, form, { type: "password", autocomplete: "new-password" }, { top: 160 });
    fresh.form = form;
    return { fresh };
  });
  assert.deepEqual(signUp.begin(), []);
  assert.deepEqual(signUp.fill(), { request_id: "req-1", ok: false, reason: "wrong_kind" });
  assert.equal(nativeValue(signUp.fresh), "");
});

test("a_second_form_and_a_loose_code_field_outside_the_group_are_not_reported", () => {
  const t = setup({}, (document) => {
    const login = formAt(document, document.body, "login", 100);
    const other = formAt(document, document.body, "other", 300);
    const code = addInput(document, document.body, { type: "text", autocomplete: "one-time-code" }, { top: 500 });
    return { login, other, code };
  });
  assert.deepEqual(kinds(t.begin()), ["username", "password"]);
  assert.deepEqual(fillBoth(t, { a: t.login.user, b: t.login.pass, c: t.other.user, d: t.other.pass }), { a: "alice", b: "pw-1", c: "", d: "" });
  assert.equal(t.fill(fillMessage({ field: "totp", value: "123456" }))?.reason, "wrong_kind");
  assert.equal(nativeValue(t.code), "");

  // The code field of the same form is part of the group.
  const same = setup({}, (document) => {
    const form = document.body.append(document.createElement("form"));
    const pass = addInput(document, form, { type: "password" }, { top: 100 });
    const code = addInput(document, form, { type: "text", autocomplete: "one-time-code" }, { top: 160 });
    pass.form = code.form = form;
    return { pass, code };
  });
  assert.deepEqual(kinds(same.begin()), ["password", "totp"]);
});

test("a_password_only_page_without_a_form_never_puts_the_user_name_into_a_search_box", () => {
  // A second sign-in step without a form: only a password field, and around it the site's
  // search box in every common shape and an unnamed text field. None of them is part of a
  // sign-in, so the report has the password only and a user name goes nowhere.
  /** @type {Array<[string, (document: any) => any]>} */
  const searchBoxes = [
    ["name q", (document) => addInput(document, document.body, { type: "text", name: "q" }, { top: 20 })],
    ["type search", (document) => addInput(document, document.body, { type: "search", name: "query" }, { top: 20 })],
    ["role searchbox", (document) => addInput(document, document.body, { type: "text", role: "searchbox", placeholder: "Search users" }, { top: 20 })],
    ["in a search element", (document) => {
      const box = document.body.append(document.createElement("search"));
      return addInput(document, box, { type: "text", name: "user-search" }, { top: 20 });
    }],
    ["in role search", (document) => {
      const box = document.body.append(document.createElement("div", { role: "search" }));
      return addInput(document, box, { type: "email", name: "find" }, { top: 20 });
    }],
    ["in a search form", (document) => {
      const form = document.body.append(document.createElement("form", { role: "search" }));
      const input = addInput(document, form, { type: "text", name: "login-lookup" }, { top: 20 });
      input.form = form;
      return input;
    }],
  ];
  for (const [shape, addSearch] of searchBoxes) {
    const t = setup({}, (document) => {
      const search = addSearch(document);
      const note = addInput(document, document.body, { type: "text", name: "comment" }, { top: 60 });
      const step = document.body.append(document.createElement("div"));
      const pass = addInput(document, step, { type: "password" }, { top: 160 });
      return { search, note, pass };
    });
    assert.deepEqual(kinds(t.begin()), ["password"], shape);
    assert.deepEqual(t.fill(fillMessage({ field: "username", value: "alice" })), { request_id: "req-1", ok: false, reason: "wrong_kind" }, shape);
    assert.equal(t.fill()?.ok, true, shape);
    assert.deepEqual([nativeValue(t.search), nativeValue(t.note), nativeValue(t.pass)], ["", "", "s3cret"], shape);
  }

  // A search box and no form and no password: nothing to fill at all.
  const only = setup({}, (document) => ({
    search: addInput(document, document.body, { type: "text", name: "q", placeholder: "Search by user name or e-mail" }, { top: 20 }),
  }));
  assert.deepEqual(only.begin(), []);
  assert.deepEqual(only.fill(fillMessage({ field: "username", value: "alice" })), { request_id: "req-1", ok: false, reason: "wrong_kind" });
  assert.equal(nativeValue(only.search), "");

  // A named user name field on the whole page still joins the password.
  const named = setup({}, (document) => {
    const user = addInput(document, document.body, { type: "email", autocomplete: "username" }, { top: 100 });
    const step = document.body.append(document.createElement("div"));
    const pass = addInput(document, step, { type: "password" }, { top: 160 });
    return { user, pass };
  });
  assert.deepEqual(kinds(named.begin()), ["username", "password"]);
  assert.deepEqual(fillBoth(named, { user: named.user, pass: named.pass }), { user: "alice", pass: "pw-1" });
});

test("the_group_is_checked_again_at_fill_time", () => {
  // The page moves the reported user name into another form after the report.
  const moved = setup({}, (document) => {
    const login = formAt(document, document.body, "login", 100);
    const other = document.body.append(document.createElement("form", { id: "other" }));
    return { login, other };
  });
  assert.deepEqual(kinds(moved.begin()), ["username", "password"]);
  moved.login.user.form = moved.other;
  assert.deepEqual(moved.fill(fillMessage({ field: "username", value: "alice" })), { request_id: "req-1", ok: false, reason: "wrong_kind" });
  assert.equal(nativeValue(moved.login.user), "");
  // The password, still in its form, is filled.
  assert.equal(moved.fill()?.ok, true);

  // A form-less field that gains a form, or a field that loses its form.
  const gained = setup({}, (document) => {
    const main = document.body.append(document.createElement("main"));
    const user = addInput(document, main, { type: "text", name: "username" }, { top: 100 });
    const pass = addInput(document, main, { type: "password" }, { top: 160 });
    const form = document.body.append(document.createElement("form"));
    return { user, pass, form };
  });
  assert.deepEqual(kinds(gained.begin()), ["username", "password"]);
  gained.pass.form = gained.form;
  assert.deepEqual(gained.fill(), { request_id: "req-1", ok: false, reason: "wrong_kind" });
  assert.equal(nativeValue(gained.pass), "");
  const lost = setup();
  lost.begin();
  lost.pass.form = null;
  assert.deepEqual(lost.fill(), { request_id: "req-1", ok: false, reason: "wrong_kind" });
  assert.equal(nativeValue(lost.pass), "");

  // The page turns the reported password field into one that sets a new password
  // (a sign-up or change form): the stored password never goes into it.
  const turned = setup();
  turned.begin();
  turned.pass.setAttribute("autocomplete", "new-password");
  assert.deepEqual(turned.fill(), { request_id: "req-1", ok: false, reason: "wrong_kind" });
  assert.equal(nativeValue(turned.pass), "");
  turned.user.setAttribute("autocomplete", "username new-password");
  assert.deepEqual(turned.fill(fillMessage({ field: "username", value: "alice" })), { request_id: "req-1", ok: false, reason: "wrong_kind" });
  assert.equal(nativeValue(turned.user), "");
});

test("an_input_in_a_disabled_fieldset_is_not_filled", () => {
  const build = (/** @type {any} */ document) => {
    const fieldset = document.body.append(document.createElement("fieldset"));
    const pass = addInput(document, fieldset, { type: "password" }, { top: 100 });
    return { fieldset, pass };
  };
  const after = setup({}, build);
  assert.deepEqual(kinds(after.begin()), ["password"]);
  after.fieldset.setAttribute("disabled", "");
  assert.deepEqual(after.fill(), { request_id: "req-1", ok: false, reason: "hidden" });
  assert.equal(nativeValue(after.pass), "");
  const before = setup({}, build);
  before.fieldset.setAttribute("disabled", "");
  assert.deepEqual(before.begin(), []);
});

test("a_cover_that_hit_testing_cannot_see_is_not_detected_today", () => {
  // The hit test sees what a click would reach. It does not see a cover with
  // pointer-events: none, nor paint outside a box (a box-shadow spread, an
  // outline, a drop-shadow). This test pins that limit, which the design
  // document states; a later change that closes it should change this test on purpose.
  const t = setup();
  t.begin();
  const cover = t.document.createElement("div");
  t.document.body.append(cover);
  cover.rect = { left: 90, top: 150, width: 260, height: 52 };
  cover.z = 10;
  cover.style["pointer-events"] = "none";
  const painter = t.document.createElement("div");
  t.document.body.append(painter);
  painter.style["box-shadow"] = "0 0 0 9999px white";
  painter.style.outline = "9999px solid white";
  painter.style.filter = "drop-shadow(0 0 9999px white)";
  assert.deepEqual(t.fill(), { request_id: "req-1", ok: true });
  assert.equal(nativeValue(t.pass), "s3cret");
});

test("a_report_has_at_most_three_fields_and_nothing_is_sent_before_begin", () => {
  const many = setup({}, (document) => {
    // 80 fields that all pass: 4 columns, 20 rows, none over another.
    for (let i = 0; i < 80; i += 1) {
      addInput(document, document.body, { type: "password" }, { left: (i % 4) * 300, top: 10 + Math.floor(i / 4) * 38, width: 240, height: 30 });
    }
    return {};
  });
  assert.deepEqual(many.sent, [], "creating an engine reports nothing");
  assert.deepEqual(kinds(many.begin()), ["password"]);
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

test("the_content_script_imports_no_crypto_and_no_shared_store", () => {
  const src = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "src");
  /** @param {string} dir @returns {string[]} */
  const walk = (dir) => readdirSync(join(dir), { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(join(dir, e.name)) : [join(dir, e.name)]));
  const files = new Map(walk(src).filter((p) => /\.(?:mjs|js)$/.test(p)).map((p) => [posix.normalize(p.slice(src.length + 1).split("\\").join("/")), Buffer.from(readFileSync(p))]));

  const ALLOWED = new Set(["content/entry.mjs", "content/fill.mjs", "content/forms.mjs", "content/patterns.mjs", "content/capture.mjs", "content/capture.entry.mjs", "shared/protocol.mjs", "shared/schema.mjs"]);
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
  assert.deepEqual(importsOf(files.get("content/fill.mjs")?.toString("utf8") ?? "").specifiers, ["../shared/protocol.mjs", "./forms.mjs"]);
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

// ------------------------------------------------------------ a field of a frame, seen from the documents above

/** The points of the login form's password field (100, 160, 240 × 32) in the frame's own viewport. */
const PASS_POINTS = /** @type {Array<[number, number]>} */ ([[220, 176], [160, 176], [280, 176], [220, 168], [220, 184]]);

/**
 * A parent page with its own form and an iframe at (400, 100), 400 × 300, that holds frame `FRAME` (as
 * `runtime.getFrameId` says), beside the form.
 * @param {(page: ReturnType<typeof createPage> & { iframe: any }) => void} [arrange] changes the page before the question
 */
function framePage(arrange = () => {}) {
  const FRAME = 17179869185;
  const page = createPage({ url: "https://www.example.net/" });
  addLoginForm(page.document);
  const iframe = page.document.body.append(page.document.createElement("iframe", { id: "login-frame" }));
  iframe.rect = { left: 400, top: 100, width: 400, height: 300 };
  /** @type {Map<any, number>} */
  const holds = new Map([[iframe, FRAME]]);
  const asked = /** @type {any[]} */ ([]);
  const engine = createFillEngine({
    window: page.window,
    document: page.document,
    send: () => {},
    runtimeId: RUNTIME_ID,
    extensionBase: EXTENSION_BASE,
    frameIdOf: (element) => {
      asked.push(element);
      const id = holds.get(element);
      if (id === undefined) throw new Error("not a frame");
      return id;
    },
  });
  arrange({ ...page, iframe });
  return {
    ...page, iframe, holds, asked, engine, FRAME,
    /** The verdict for the password field's points (or `points`). @param {any} [points] */
    shown: (points = PASS_POINTS) => /** @type {any} */ (engine.frameShown(FRAME, points)).verdict,
  };
}

/** Adds a cover to a page. @param {any} document @param {{ left: number, top: number, width: number, height: number }} rect */
function cover(document, rect) {
  const element = document.body.append(document.createElement("div", { id: "cover" }));
  element.rect = rect;
  element.z = 10;
  return element;
}

test("a_field_of_a_frame_is_shown_only_when_the_holder_passes_the_chain_and_the_fields_points_reach_it", () => {
  // A plain iframe beside the form: shown, and the points come back moved by the holder's content box.
  const plain = framePage();
  assert.deepEqual(plain.engine.frameShown(plain.FRAME, PASS_POINTS), { verdict: "shown", points: PASS_POINTS.map(([x, y]) => [x + 400, y + 100]) });
  assert.deepEqual(plain.asked, [plain.iframe], "only elements that can hold a frame are asked about");
  // Border and padding move the frame's viewport inside the holder.
  const boxed = framePage((p) => {
    p.iframe.clientLeft = 2;
    p.iframe.clientTop = 3;
    p.iframe.style["padding-left"] = "5px";
    p.iframe.style["padding-top"] = "7px";
  });
  assert.deepEqual(/** @type {any} */ (boxed.engine.frameShown(boxed.FRAME, [[10, 10]])).points, [[417, 120]]);

  // The ancestor rules, on the iframe itself and on a parent of it; zoom only for a holder.
  const cases = /** @type {Array<[string, (p: any) => void, string]>} */ ([
    ["opacity 0 on the iframe", (p) => { p.iframe.style.opacity = "0"; }, "hidden"],
    ["opacity 0.99 on the iframe", (p) => { p.iframe.style.opacity = "0.99"; }, "hidden"],
    ["visibility hidden on the iframe", (p) => { p.iframe.style.visibility = "hidden"; }, "hidden"],
    ["display none on the iframe", (p) => { p.iframe.style.display = "none"; }, "hidden"],
    ["a filter on the body", (p) => { p.document.body.style.filter = "opacity(0.02)"; }, "hidden"],
    ["a transform on the iframe", (p) => { p.iframe.style.transform = "scale(0.01)"; }, "hidden"],
    ["a clip path on the iframe", (p) => { p.iframe.style["clip-path"] = "inset(100%)"; }, "hidden"],
    ["a mask on the html element", (p) => { p.document.documentElement.style["mask-image"] = "linear-gradient(transparent, transparent)"; }, "hidden"],
    ["mix-blend-mode on the iframe", (p) => { p.iframe.style["mix-blend-mode"] = "screen"; }, "hidden"],
    ["zoom on the iframe", (p) => { p.iframe.style.zoom = "0.5"; }, "hidden"],
    ["zoom on the body", (p) => { p.document.body.style.zoom = "2"; }, "hidden"],
    ["aria-hidden on the body", (p) => { p.document.body.setAttribute("aria-hidden", "true"); }, "hidden"],
    ["an inert iframe", (p) => { p.iframe.inert = true; }, "hidden"],
    ["a 4 px iframe", (p) => { p.iframe.rect = { left: 400, top: 100, width: 4, height: 4 }; }, "hidden"],
    ["far to the left", (p) => { p.iframe.rect = { left: -10_000, top: 100, width: 400, height: 300 }; }, "hidden"],
    ["below the fold", (p) => { p.iframe.rect = { left: 400, top: 3000, width: 400, height: 300 }; }, "hidden"],
    ["the field's row below the fold", (p) => { p.iframe.rect = { left: 400, top: 700, width: 400, height: 300 }; }, "hidden"],
    ["a cover over the whole iframe", (p) => { cover(p.document, { left: 400, top: 100, width: 400, height: 300 }); }, "covered"],
    // Only the form's area inside the frame is covered: the iframe's own centre and quarter points stay clear.
    ["a cover over the field only", (p) => { cover(p.document, { left: 490, top: 255, width: 260, height: 40 }); }, "covered"],
    ["a cover over one of the field's points", (p) => { cover(p.document, { left: 555, top: 271, width: 10, height: 10 }); }, "covered"],
  ]);
  for (const [label, arrange, verdict] of cases) assert.equal(framePage(arrange).shown(), verdict, label);
  // A zoom of 1 on the holder is no zoom.
  assert.equal(framePage((p) => { p.iframe.style.zoom = "1"; }).shown(), "shown");
  // A cover beside the field (over the iframe's centre, not over the field) is not the field's business.
  assert.equal(framePage((p) => { cover(p.document, { left: 590, top: 240, width: 20, height: 20 }); }).shown(), "shown");

  // A frame far taller than the viewport is shown when its field is in view (no share of the holder is asked for).
  const tall = framePage((p) => { p.iframe.rect = { left: 400, top: -2000, width: 400, height: 6000 }; });
  assert.equal(tall.shown([[220, 2176]]), "shown");
  assert.equal(tall.shown([[220, 5000]]), "hidden", "the same frame, its field out of view");
  // No points, or points of another shape, are no answer.
  for (const bad of [undefined, [], [[1]], [[1, Number.NaN]], [["1", 2]], Array.from({ length: 6 }, () => [1, 1]), [[1e9, 1]]]) {
    assert.deepEqual(plain.engine.frameShown(plain.FRAME, bad), { verdict: "hidden" }, String(JSON.stringify(bad)));
  }
});

test("a_frame_is_found_by_the_browsers_frame_id_and_nothing_else", () => {
  // No element holds the frame: gone. Two elements that claim it: gone (the browser never names two).
  const none = framePage((p) => { p.iframe.localName = "div"; });
  assert.equal(none.shown(), "gone");
  const twice = framePage();
  const second = twice.document.body.append(twice.document.createElement("frame"));
  second.rect = { left: 400, top: 420, width: 400, height: 300 };
  twice.holds.set(second, twice.FRAME);
  assert.equal(twice.shown(), "gone");
  // Another frame id, the top, and ids that are not frame ids name nothing.
  const page = framePage();
  for (const id of [page.FRAME + 1, 0, -1, 1.5, "17179869185", null, undefined, Number.MAX_SAFE_INTEGER + 2]) {
    assert.equal(/** @type {any} */ (page.engine.frameShown(/** @type {any} */ (id), PASS_POINTS)).verdict, "gone", String(id));
  }
  // An element whose frame id the browser cannot give (an object showing an image) is passed over.
  const object = framePage((p) => {
    const img = p.document.body.append(p.document.createElement("object"));
    img.rect = { left: 0, top: 500, width: 100, height: 100 };
  });
  assert.equal(object.shown(), "shown");
  // A holder inside a shadow root (closed too) is found, and a transparent host hides it.
  for (const mode of /** @type {const} */ (["open", "closed"])) {
    const inShadow = (/** @type {string} */ opacity) => framePage((p) => {
      p.document.body.remove(p.iframe);
      const host = p.document.body.append(p.document.createElement("div", { id: "host" }));
      host.rect = { left: 400, top: 100, width: 400, height: 300 };
      host.style.opacity = opacity;
      host.attachShadow({ mode }).append(p.iframe);
    });
    assert.equal(inShadow("1").shown(), "shown", mode);
    assert.equal(inShadow("0").shown(), "hidden", `${mode}: the host is transparent`);
  }
  // Without the browser's frame ids (the default), no element holds a frame, and the question sends nothing.
  const quiet = framePage();
  const sent = /** @type {string[]} */ ([]);
  const engine = createFillEngine({ window: quiet.window, document: quiet.document, send: (raw) => { sent.push(raw); }, runtimeId: RUNTIME_ID, extensionBase: EXTENSION_BASE });
  assert.equal(/** @type {any} */ (engine.frameShown(quiet.FRAME, PASS_POINTS)).verdict, "gone");
  assert.deepEqual(sent, []);
});

test("the_frame_gives_the_points_of_the_field_it_would_fill_and_two_levels_move_them_up", () => {
  // The frame: the pending request's password field, after the field checks.
  const frame = setup({ url: "https://login.example.net/" });
  const [field] = frame.begin("req-7").filter((f) => f.kind === "password");
  assert.ok(field);
  assert.deepEqual(frame.engine.where("req-7", "password"), { points: PASS_POINTS });
  assert.deepEqual(frame.engine.where("req-8", "password"), { problem: "gone" }, "another request");
  assert.deepEqual(frame.engine.where("req-7", "totp"), { problem: "wrong_kind" });
  // A field that fails its own checks gives its own reason, not points.
  frame.pass.style.opacity = "0";
  assert.deepEqual(frame.engine.where("req-7", "password"), { problem: "hidden" });
  frame.pass.style.opacity = "1";
  const over = frame.document.body.append(frame.document.createElement("div"));
  over.rect = { left: 100, top: 160, width: 240, height: 32 };
  over.z = 5;
  assert.deepEqual(frame.engine.where("req-7", "password"), { problem: "covered" });
  // Only the points inside the frame's viewport are given.
  over.rect = null;
  frame.pass.rect = { left: 1180, top: 160, width: 240, height: 32 };
  assert.deepEqual(frame.engine.where("req-7", "password"), { problem: "hidden" }, "mostly outside the viewport");
  frame.pass.rect = { left: 1100, top: 160, width: 240, height: 32 };
  assert.deepEqual(frame.engine.where("req-7", "password"), { points: [[1220, 176], [1160, 176], [1220, 168], [1220, 184]] });

  // Two levels: the middle page holds the login frame at (50, 40), the top holds the middle frame at (400, 100).
  const middle = framePage((p) => { p.iframe.rect = { left: 50, top: 40, width: 600, height: 500 }; });
  const fromMiddle = /** @type {any} */ (middle.engine.frameShown(middle.FRAME, PASS_POINTS));
  assert.equal(fromMiddle.verdict, "shown");
  const top = framePage((p) => { p.iframe.rect = { left: 400, top: 100, width: 700, height: 600 }; });
  const fromTop = /** @type {any} */ (top.engine.frameShown(top.FRAME, fromMiddle.points));
  assert.deepEqual(fromTop, { verdict: "shown", points: PASS_POINTS.map(([x, y]) => [x + 450, y + 140]) });
  // The top covers only where the field ends up: refused at the top, although the middle frame is mostly clear.
  const coveredTop = framePage((p) => {
    p.iframe.rect = { left: 400, top: 100, width: 700, height: 600 };
    cover(p.document, { left: 595, top: 300, width: 260, height: 40 });
  });
  assert.equal(/** @type {any} */ (coveredTop.engine.frameShown(coveredTop.FRAME, fromMiddle.points)).verdict, "covered");
});

// ------------------------------------------------------------ the detection module (forms.mjs) in the fill engine

/**
 * A form built from a list: `["input", attributes]` or `[tag, text, attributes]`; inputs and buttons belong to it.
 * @param {any} document @param {Array<[string, ...any[]]>} parts @param {{ form?: boolean }} [options]
 * @returns {Record<string, any>} the elements by id
 */
function formOf(document, parts, { form = true } = {}) {
  const parent = form ? document.body.append(document.createElement("form", { id: "f" })) : document.body;
  /** @type {Record<string, any>} */
  const byId = {};
  let top = 40;
  for (const [tag, ...rest] of parts) {
    const element = tag === "input" ? addInput(document, parent, rest[0], { top }) : addText(document, parent, tag, rest[0], rest[1] ?? {});
    if (tag === "input") top += 50;
    if (form && (tag === "input" || tag === "button")) element.form = parent;
    const id = (tag === "input" ? rest[0] : rest[1] ?? {}).id;
    if (id) byId[id] = element;
  }
  return byId;
}

/** Every kind of value, sent to the page in turn: none of them may land anywhere. @param {any} t */
function tryEveryValue(t) {
  return ["username", "password", "totp"].map((field) => t.fill(fillMessage({ field, value: field === "totp" ? "123456" : `v-${field}` }))?.ok === true);
}

test("the_unsafe_fill_classes_of_the_corpus_get_no_value", () => {
  /** @type {Array<[string, Array<[string, ...any[]]>]>} */
  const pages = [
    ["a card form with its security code as a password", [["label", "Navn på kortet", { for: "holder" }], ["input", { id: "holder", type: "text", name: "kortholder", autocomplete: "cc-name" }], ["label", "Sikkerhetskode", { for: "cvc" }], ["input", { id: "cvc", type: "password", name: "cvv", maxlength: "3" }], ["button", "Fortsett", { type: "submit" }]]],
    ["a checkout with an e-mail field", [["input", { id: "email", type: "email", name: "email", autocomplete: "email" }], ["input", { id: "card", type: "text", name: "card", inputmode: "numeric", autocomplete: "cc-number" }], ["input", { id: "exp", type: "text", name: "exp", autocomplete: "cc-exp" }], ["input", { id: "cvc", type: "password", name: "cvc", inputmode: "numeric", maxlength: "4", autocomplete: "cc-csc" }]]],
    ["a customer number and a PIN", [["label", "Kundennummer", { for: "cust" }], ["input", { id: "cust", type: "text", name: "kunde", inputmode: "numeric", autocomplete: "off" }], ["label", "PIN", { for: "pin" }], ["input", { id: "pin", type: "password", name: "pin", inputmode: "numeric", maxlength: "4", autocomplete: "off" }], ["button", "Anmelden", { type: "submit" }]]],
    ["a PIN pad field", [["label", "Code PIN", { for: "pin" }], ["input", { id: "pin", type: "password", name: "code_secret", inputmode: "numeric", maxlength: "4", autocomplete: "off" }]]],
    ["a one-time code typed as password", [["label", "Bekreftelseskode", { for: "code" }], ["input", { id: "code", type: "password", name: "engangskode", autocomplete: "one-time-code", inputmode: "numeric", maxlength: "6" }]]],
    ["an SMS code typed as password", [["label", "Verification code", { for: "code" }], ["input", { id: "code", type: "password", name: "sms_code", inputmode: "numeric", maxlength: "6", autocomplete: "off" }]]],
    ["a sign-up form with a confirm field and no tokens", [["input", { id: "email", type: "text", name: "mail", placeholder: "E-mailadres" }], ["input", { id: "pw", type: "password", name: "wachtwoord", placeholder: "Wachtwoord" }], ["input", { id: "pw2", type: "password", name: "wachtwoord2", placeholder: "Bevestig wachtwoord" }], ["button", "Account aanmaken", { type: "submit" }]]],
    ["a sign-up form with one password and no tokens", [["input", { id: "user", type: "text", name: "nutzer", autocomplete: "username" }], ["input", { id: "pw", type: "password", name: "kennwort" }], ["button", "Konto erstellen", { type: "submit" }]]],
    ["a newsletter box", [["label", "E-postadresse", { for: "mail" }], ["input", { id: "mail", type: "email", name: "epost", autocomplete: "email" }], ["button", "Send", { type: "submit" }]]],
    ["a newsletter box marked as a user name", [["label", "Adresse e-mail", { for: "mail" }], ["input", { id: "mail", type: "text", name: "courriel", autocomplete: "username" }], ["button", "Envoyer", { type: "submit" }]]],
    ["a contact form", [["input", { id: "name", type: "text", name: "name", autocomplete: "name" }], ["input", { id: "mail", type: "email", name: "email", autocomplete: "email" }], ["textarea", ""], ["button", "Senden", { type: "submit" }]]],
  ];
  for (const [shape, parts] of pages) {
    const t = setup({}, (document) => formOf(document, parts));
    assert.deepEqual(t.begin(), [], `${shape}: nothing reported`);
    assert.deepEqual(tryEveryValue(t), [false, false, false], `${shape}: no value accepted`);
    for (const [id, element] of Object.entries(t)) {
      if (element?.localName === "input") assert.equal(nativeValue(element), "", `${shape}: #${id} stays empty`);
    }
  }
});

test("a_frame_whose_document_its_parent_wrote_reports_no_field", () => {
  /**
   * A frame page at `own`, whose holder in a parent document at `above` has `attributes`.
   * @param {string} own @param {string | null} above @param {Record<string, string>} [attributes]
   */
  const framed = (own, above, attributes = {}) => {
    const t = setup({ url: own });
    t.document.URL = own;
    if (above !== null) {
      const parent = createPage({ url: above }).document;
      parent.URL = above;
      t.window.frameElement = parent.createElement("iframe", attributes);
    } else {
      t.window.frameElement = null;
    }
    return t;
  };
  // `document.open()` from the parent: the frame has the address of the parent, with or without a `src` of its own.
  assert.deepEqual(framed("https://example.com/login", "https://example.com/login").begin(), [], "no src");
  assert.deepEqual(framed("https://example.com/login", "https://example.com/login", { src: "/blank.html" }).begin(), [], "a src the parent wrote over");
  // A `srcdoc` holder.
  assert.deepEqual(framed("https://example.com/x", "https://example.com/", { srcdoc: "<form></form>", src: "https://example.com/x" }).begin(), []);
  // Pages: a frame loaded from its own address, a frame with no src that was navigated (by its name), a frame below a
  // parent of another origin (nothing can be read), and the top (no holder).
  assert.deepEqual(kinds(framed("https://example.com/login", "https://example.com/", { src: "/login" }).begin()), ["username", "password"]);
  assert.deepEqual(kinds(framed("https://example.com/login", "https://example.com/", { name: "x" }).begin()), ["username", "password"]);
  const foreignParent = setup({ url: "https://example.com/login" });
  Object.defineProperty(foreignParent.window, "frameElement", { get() { throw new Error("cross-origin"); } });
  assert.deepEqual(kinds(foreignParent.begin()), ["username", "password"]);
  assert.deepEqual(kinds(framed("https://example.com/login", null).begin()), ["username", "password"]);
});

test("a_one_time_password_named_as_a_password_is_a_code_in_every_language", () => {
  // Masked, with nothing numeric about it: only the words say it is a one-time password.
  for (const label of ["One-time password", "Engangspassord", "Engangs-passord", "Einmal-Passwort", "Einmalkennwort", "Mot de passe à usage unique", "Mot de passe unique", "Eenmalig wachtwoord"]) {
    const t = setup({}, (document) => formOf(document, [["label", label, { for: "c" }], ["input", { id: "c", type: "password", name: "f" }]]));
    assert.deepEqual(t.begin(), [], label);
    assert.equal(t.fill()?.ok, false, label);
    assert.equal(nativeValue(t.c), "", label);
  }
  // A masked field with a one-time-code term and room for a code only is a code too, whatever else it says.
  const sized = setup({}, (document) => formOf(document, [["label", "Authenticator password", { for: "c" }], ["input", { id: "c", type: "password", name: "f", maxlength: "6" }]]));
  assert.deepEqual(sized.begin(), []);
  // Control: a password field is still a password field.
  const control = setup({}, (document) => formOf(document, [["label", "Password", { for: "p" }], ["input", { id: "p", type: "password", name: "f" }]]));
  assert.deepEqual(kinds(control.begin()), ["password"]);
});

test("a_postal_or_area_code_is_never_a_one_time_code", () => {
  for (const label of ["Postal code", "Code postal", "Postleitzahl", "Area code", "Sort code"]) {
    const t = setup({}, (document) => formOf(document, [["label", label, { for: "z" }], ["input", { id: "z", type: "text", name: "f", inputmode: "numeric", maxlength: "6" }]]));
    assert.deepEqual(t.begin(), [], label);
    assert.equal(t.fill(fillMessage({ field: "totp", value: "123456" }))?.ok, false, label);
  }
  // Control: a numeric field named for a code.
  const code = setup({}, (document) => formOf(document, [["label", "Code", { for: "z" }], ["input", { id: "z", type: "text", name: "f", inputmode: "numeric", maxlength: "6" }]]));
  assert.deepEqual(kinds(code.begin()), ["totp"]);
});

test("sign_up_and_sign_in_are_told_apart_by_the_control_that_sends_the_form", () => {
  // A sign-up form with a "Log in instead" button beside its submit: a sign-up, nothing reported.
  const signup = setup({}, (document) => formOf(document, [
    ["input", { id: "e", type: "email", name: "email" }], ["input", { id: "p", type: "password", name: "pw" }],
    ["button", "Log in instead", { type: "button" }], ["button", "Create account", { type: "submit" }],
  ]));
  assert.deepEqual(signup.begin(), []);
  // The reverse: a sign-in form with a "Create account" button beside its submit.
  const login = setup({}, (document) => formOf(document, [
    ["input", { id: "e", type: "email", name: "email" }], ["input", { id: "p", type: "password", name: "pw" }],
    ["button", "Create account", { type: "button" }], ["button", "Sign in", { type: "submit" }],
  ]));
  assert.deepEqual(kinds(login.begin()), ["username", "password"]);
  // "Aanmelden" means both in Dutch: the page decides. A page that says "Registreren" is a sign-up.
  const dutch = setup({}, (document) => {
    document.title = "Registreren";
    return formOf(document, [["input", { id: "e", type: "email", name: "email" }], ["input", { id: "p", type: "password", name: "wachtwoord" }], ["button", "Aanmelden", { type: "submit" }]]);
  });
  assert.deepEqual(dutch.begin(), []);
  const dutchLogin = setup({}, (document) => {
    document.title = "Inloggen";
    return formOf(document, [["input", { id: "e", type: "email", name: "email" }], ["input", { id: "p", type: "password", name: "wachtwoord" }], ["button", "Aanmelden", { type: "submit" }]]);
  });
  assert.deepEqual(kinds(dutchLogin.begin()), ["username", "password"]);
});

test("fill_keeps_every_visibility_rule", () => {
  /** The ways a page hides or covers a field, each applied to one element. @type {Array<[string, (element: any, t: any) => void]>} */
  const hides = [
    ["display none", (e) => { e.style.display = "none"; }],
    ["opacity", (e) => { e.style.opacity = "0.2"; }],
    ["visibility", (e) => { e.style.visibility = "hidden"; }],
    ["transform", (e) => { e.style.transform = "translateX(-50%)"; }],
    ["filter", (e) => { e.style.filter = "blur(1px)"; }],
    ["aria-hidden", (e) => { e.setAttribute("aria-hidden", "true"); }],
    ["inert", (e) => { e.inert = true; }],
    ["zero size", (e) => { e.rect = { ...e.rect, width: 0, height: 0 }; }],
    ["off the page", (e) => { e.rect = { ...e.rect, left: -2000 }; }],
    ["disabled", (e) => { e.disabled = true; }],
    ["read-only", (e) => { e.readOnly = true; }],
    ["covered", (e, t) => {
      const cover = t.document.body.append(t.document.createElement("div"));
      cover.rect = { left: e.rect.left - 5, top: e.rect.top - 5, width: e.rect.width + 10, height: e.rect.height + 10 };
      cover.z = 10;
    }],
  ];
  /** The fields of each kind of group the engine fills: [shape, parts, the id of the field, its kind, a value]. @type {Array<[string, Array<[string, ...any[]]>, string, string, string]>} */
  const fields = [
    ["the password of a sign-in", [["input", { id: "u", type: "text", name: "username" }], ["input", { id: "p", type: "password", name: "password" }]], "p", "password", "pw-1"],
    ["the user name of a sign-in", [["input", { id: "u", type: "text", name: "username" }], ["input", { id: "p", type: "password", name: "password" }]], "u", "username", "alice"],
    ["a user name step", [["input", { id: "u", type: "text", name: "username" }], ["button", "Next", { type: "submit" }]], "u", "username", "alice"],
    ["the password in use of a change form", [["input", { id: "c", type: "password", autocomplete: "current-password" }], ["input", { id: "n", type: "password", autocomplete: "new-password" }]], "c", "password", "pw-1"],
    ["a code field", [["input", { id: "o", type: "text", name: "otp", inputmode: "numeric", maxlength: "6" }]], "o", "totp", "123456"],
  ];
  for (const [shape, parts, id, kind, value] of fields) {
    // Control: shown, it is reported and filled.
    const control = setup({}, (document) => formOf(document, parts));
    assert.ok(kinds(control.begin()).includes(kind), `${shape}: reported`);
    assert.equal(control.fill(fillMessage({ field: kind, value }))?.ok, true, `${shape}: filled`);
    for (const [how, hide] of hides) {
      // Hidden before the report: not reported (the group gives no field the user cannot see).
      const before = setup({}, (document) => formOf(document, parts));
      hide(before[id], before);
      assert.equal(kinds(before.begin()).includes(kind), false, `${shape}, ${how}: not reported`);
      // Hidden after the report: refused, and nothing goes in.
      const after = setup({}, (document) => formOf(document, parts));
      after.begin();
      hide(after[id], after);
      assert.equal(after.fill(fillMessage({ field: kind, value }))?.ok, false, `${shape}, ${how}: refused`);
      assert.equal(nativeValue(after[id]), "", `${shape}, ${how}: empty`);
    }
  }
});

test("a_password_field_that_the_page_turns_into_a_code_field_after_the_report_gets_no_password", () => {
  const t = setup();
  t.begin();
  t.pass.setAttribute("autocomplete", "one-time-code");
  assert.deepEqual(t.fill(), { request_id: "req-1", ok: false, reason: "wrong_kind" });
  t.pass.setAttribute("autocomplete", "cc-csc");
  assert.deepEqual(t.fill(), { request_id: "req-1", ok: false, reason: "wrong_kind" });
  t.pass.setAttribute("autocomplete", "off");
  t.pass.setAttribute("inputmode", "numeric");
  assert.deepEqual(t.fill(), { request_id: "req-1", ok: false, reason: "wrong_kind" }, "a PIN by its shape");
  t.pass.setAttribute("inputmode", "text");
  assert.equal(t.fill()?.ok, true, "control");
});

test("a_click_on_the_new_or_confirm_field_of_a_change_form_never_gets_the_stored_password", () => {
  const page = createPage();
  const fields = formOf(page.document, [["input", { id: "a", type: "password", name: "f1" }], ["input", { id: "b", type: "password", name: "f2" }], ["input", { id: "c", type: "password", name: "f3" }]]);
  const sent = /** @type {string[]} */ ([]);
  const engine = createFillEngine({
    window: page.window, document: page.document, send: (raw) => { sent.push(raw); }, runtimeId: RUNTIME_ID, extensionBase: EXTENSION_BASE,
    targetOf: (id) => [fields.a, fields.b, fields.c][id - 1],
  });
  for (const [id, expected] of /** @type {Array<[number, string[]]>} */ ([[2, []], [3, []], [1, ["password"]]])) {
    assert.equal(engine.aim(id), true);
    sent.length = 0;
    engine.begin("req-1");
    assert.deepEqual(decodeSent(sent)[0].body.fields.map((/** @type {any} */ f) => f.kind), expected, `field ${id}`);
    sent.length = 0;
    engine.onMessage(fillMessage(), BACKGROUND_SENDER);
    if (expected.length === 0) assert.deepEqual(decodeSent(sent)[0].body, { request_id: "req-1", ok: false, reason: "wrong_kind" }, `field ${id}`);
  }
  assert.deepEqual([fields.a, fields.b, fields.c].map(nativeValue), ["s3cret", "", ""]);
});
