// The fill engine (src/content/fill.mjs) on fake pages: which fields it reports,
// which it refuses and why, and that it fills one value, once the extension
// asks, with the native setter. The ancestor rules have one test each.
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join, posix, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { COVERAGE_PASS, createFillEngine, MIN_SIDE } from "../../src/content/fill.mjs";
import { importsOf, reach, readGraph } from "./importGraph.mjs";
import {
  addInput, addLoginForm, addText, BACKGROUND_SENDER, createPage, decodeSent, EXTENSION_BASE, fillMessage, RUNTIME_ID,
} from "./fakeDom.mjs";

/** Starts an engine on a page. `begin()` reports and returns the fields. */
function setup(options = {}, build = addLoginForm, engineOptions = {}) {
  const page = createPage(options);
  const parts = build(page.document);
  const sent = /** @type {string[]} */ ([]);
  const engine = createFillEngine({
    window: page.window,
    document: page.document,
    send: (raw) => { sent.push(raw); },
    runtimeId: RUNTIME_ID,
    extensionBase: EXTENSION_BASE,
    ...engineOptions,
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

test("a_cover_that_hit_testing_cannot_see_is_detected_by_the_coverage_pass", () => {
  // The hit test sees what a click would reach. It does not see a cover with
  // pointer-events: none, nor paint outside a box (a box-shadow spread, an
  // outline, a drop-shadow). The extra pass is on, and with it off the limit of
  // hit testing alone stands.
  assert.equal(COVERAGE_PASS, true);
  const build = (/** @type {object} */ options) => {
    const t = setup({}, addLoginForm, options);
    t.begin();
    const cover = t.document.createElement("div");
    t.document.body.append(cover);
    cover.rect = { left: 90, top: 150, width: 260, height: 52 };
    cover.z = 10;
    Object.assign(cover.style, { position: "absolute", "pointer-events": "none", "background-color": "rgb(255, 255, 255)" });
    const painter = t.document.createElement("div");
    t.document.body.append(painter);
    painter.rect = { left: 10, top: 400, width: 20, height: 20 };
    Object.assign(painter.style, { position: "absolute", "box-shadow": "rgb(255, 255, 255) 0px 0px 0px 9999px" });
    return t;
  };
  const on = build({});
  assert.deepEqual(on.fill(), { request_id: "req-1", ok: false, reason: "covered" });
  assert.equal(nativeValue(on.pass), "");
  const off = build({ coveragePass: false });
  assert.deepEqual(off.fill(), { request_id: "req-1", ok: true });
  assert.equal(nativeValue(off.pass), "s3cret");
});

const COVERAGE_ON = Object.freeze({ coveragePass: true });

/**
 * Adds an element to `parent` with a rectangle (or none) and styles. Positioned unless the styles say otherwise: a box that
 * is not positioned paints its background below the content of the field, so it cannot cover it.
 * @param {any} document @param {{ left: number, top: number, width: number, height: number } | null} rect @param {Record<string, string>} style @param {any} [parent] @param {string} [tag]
 */
function painter(document, rect, style, parent = document.body, tag = "div") {
  const element = parent.append(document.createElement(tag));
  if (rect !== null) element.rect = rect;
  Object.assign(element.style, { position: "absolute", ...style });
  return element;
}

/**
 * A sign-in form and one more element with these styles, placed after the request began: the fill's answer.
 * @param {{ left: number, top: number, width: number, height: number } | null} rect
 * @param {Record<string, string>} style
 * @param {object} [engineOptions]
 */
function fillWith(rect, style, engineOptions = COVERAGE_ON) {
  const t = setup({}, addLoginForm, engineOptions);
  t.begin();
  painter(t.document, rect, style);
  return { t, answer: t.fill() };
}

const FILLED = { request_id: "req-1", ok: true };
const COVERED = { request_id: "req-1", ok: false, reason: "covered" };
const WHITE = "rgb(255, 255, 255)";

test("the_coverage_pass_refuses_a_pointer_events_none_cover", () => {
  const OVER_FIELD = { left: 90, top: 150, width: 260, height: 52 };
  // A cover that clicks go through, with a background of its own, over the field.
  for (const [name, style] of /** @type {Array<[string, Record<string, string>]>} */ ([
    ["a background colour", { "background-color": WHITE }],
    ["a translucent background of half or more", { "background-color": "rgba(255, 255, 255, 0.6)" }],
    ["a background image", { "background-image": 'url("https://cdn.example/cover.png")' }],
  ])) {
    const { t, answer } = fillWith(OVER_FIELD, { "pointer-events": "none", ...style });
    assert.deepEqual(answer, COVERED, name);
    assert.equal(nativeValue(t.pass), "", name);
    // A request that starts under the cover reports no password.
    const later = setup({}, addLoginForm, COVERAGE_ON);
    painter(later.document, OVER_FIELD, { "pointer-events": "none", ...style });
    assert.ok(!kinds(later.begin()).includes("password"), name);
    // With the pass off the limit stands.
    assert.deepEqual(fillWith(OVER_FIELD, { "pointer-events": "none", ...style }, { coveragePass: false }).answer, FILLED, `${name}, pass off`);
  }

  // Not a cover.
  const ELSEWHERE = { left: 500, top: 150, width: 260, height: 52 };
  for (const [name, rect, style] of /** @type {Array<[string, typeof OVER_FIELD, Record<string, string>]>} */ ([
    ["no background", OVER_FIELD, { "pointer-events": "none" }],
    ["a transparent background", OVER_FIELD, { "pointer-events": "none", "background-color": "transparent" }],
    ["a thin background", OVER_FIELD, { "pointer-events": "none", "background-color": "rgba(255, 255, 255, 0.3)" }],
    ["a faded element", OVER_FIELD, { "pointer-events": "none", "background-color": WHITE, opacity: "0.3" }],
    ["a hidden element", OVER_FIELD, { "pointer-events": "none", "background-color": WHITE, visibility: "hidden" }],
    ["an element that is not drawn", OVER_FIELD, { "pointer-events": "none", "background-color": WHITE, display: "none" }],
    ["somewhere else", ELSEWHERE, { "pointer-events": "none", "background-color": WHITE }],
    ["a background that clicks reach (the hit test decides)", ELSEWHERE, { "background-color": WHITE }],
  ])) {
    assert.deepEqual(fillWith(rect, style).answer, FILLED, name);
  }

  // A panel with a background that lies below the field (clicks reach the field, so the hit test says it is not covered).
  const panel = setup({}, addLoginForm, COVERAGE_ON);
  panel.pass.z = 5;
  painter(panel.document, OVER_FIELD, { "background-color": WHITE }).z = 1;
  panel.begin();
  assert.deepEqual(panel.fill(), FILLED);

  // An ancestor of the field never covers it, whatever it has.
  const wrapped = setup({}, (/** @type {any} */ document) => {
    const wrap = painter(document, { left: 0, top: 0, width: 1000, height: 600 }, { "pointer-events": "none", "background-color": WHITE, "box-shadow": `${WHITE} 0px 0px 0px 9999px` });
    return addLoginForm(document, wrap);
  }, COVERAGE_ON);
  wrapped.begin();
  assert.deepEqual(wrapped.fill(), FILLED);

  // What the pass found is kept for one call only: take the cover away and the next request fills.
  const moving = setup({}, addLoginForm, COVERAGE_ON);
  const cap = painter(moving.document, OVER_FIELD, { "pointer-events": "none", "background-color": WHITE });
  assert.ok(!kinds(moving.begin()).includes("password"));
  moving.document.body.remove(cap);
  assert.deepEqual(kinds(moving.begin()), ["username", "password"]);
  assert.deepEqual(moving.fill(), FILLED);

  // An image or the like that clicks go through is a cover too, with no background at all.
  for (const tag of ["img", "video", "canvas", "svg", "iframe"]) {
    const t = setup({}, addLoginForm, COVERAGE_ON);
    t.begin();
    painter(t.document, OVER_FIELD, { "pointer-events": "none" }, t.document.body, tag);
    assert.deepEqual(t.fill(), COVERED, tag);
  }

  // The same for the element that holds a frame: a cover over the framed field in the parent page.
  const cover = { left: 400, top: 100, width: 400, height: 300 };
  assert.equal(framePage(() => {}, COVERAGE_ON).shown(), "shown");
  assert.equal(framePage((p) => { painter(p.document, cover, { "pointer-events": "none", "background-color": WHITE }); }, COVERAGE_ON).shown(), "covered");
  assert.equal(framePage((p) => { painter(p.document, cover, { "pointer-events": "none" }); }, COVERAGE_ON).shown(), "shown", "no background");
  assert.equal(framePage((p) => { painter(p.document, cover, { "pointer-events": "none", "background-color": WHITE }); }, { coveragePass: false }).shown(), "shown", "pass off");
  // A badge over one of the field's other points is not a cover; over its centre, or over two points, it is.
  const badge = (/** @type {number} */ x, /** @type {number} */ y, size = 6) => ({ left: x - size / 2, top: y - size / 2, width: size, height: size });
  const covered = (/** @type {Array<[number, number]>} */ at) => framePage((p) => {
    for (const [x, y] of at) painter(p.document, badge(x, y), { "pointer-events": "none", "background-color": WHITE });
  }, COVERAGE_ON).shown();
  assert.equal(covered([[560, 276]]), "shown", "one point beside the centre");
  assert.equal(covered([[620, 276]]), "covered", "the centre");
  assert.equal(covered([[560, 276], [680, 276]]), "covered", "two points");
});

test("an_overlay_that_is_hidden_by_an_ancestors_opacity_is_not_a_cover", () => {
  // `opacity` is not inherited but a faded parent fades everything in it; `pointer-events` is inherited, so the child of a hidden,
  // click-through wrapper is click-through too (set here, the fake page has no inheritance).
  const OVER_FIELD = { left: 90, top: 150, width: 260, height: 52 };
  /** @param {string} opacity @param {Record<string, string>} [childStyle] */
  const under = (opacity, childStyle = {}) => {
    const t = setup({}, addLoginForm, COVERAGE_ON);
    t.begin();
    const wrapper = painter(t.document, { left: 0, top: 0, width: 1280, height: 800 }, { opacity, "pointer-events": "none" });
    painter(t.document, OVER_FIELD, { "pointer-events": "none", "background-color": WHITE, ...childStyle }, wrapper);
    return t.fill();
  };
  assert.deepEqual(under("0"), FILLED, "a hidden wrapper");
  assert.deepEqual(under("0.3"), FILLED, "a faded wrapper");
  assert.deepEqual(under("1"), COVERED, "the same wrapper with full opacity");
  assert.deepEqual(under("0.6", { "box-shadow": `${WHITE} 0px 0px 0px 9999px`, "background-color": "transparent" }), FILLED, "a shadow of a faded child");
  // Three levels: the product counts.
  const t = setup({}, addLoginForm, COVERAGE_ON);
  t.begin();
  const a = painter(t.document, null, { opacity: "0.8" });
  const b = painter(t.document, null, { opacity: "0.6" }, a);
  painter(t.document, OVER_FIELD, { "pointer-events": "none", "background-color": WHITE }, b);
  assert.deepEqual(t.fill(), FILLED, "0.8 times 0.6 is below half");
});

test("a_layer_that_paints_below_the_field_is_not_a_cover", () => {
  const PAGE = { left: 0, top: 0, width: 1280, height: 800 };
  const SHADE = { "pointer-events": "none", "background-color": "rgba(0, 0, 0, 0.5)" };
  /** A card (positioned, with `z`) around the sign-in form, and a layer (full-page unless it has a box of its own) before or after it. @param {Record<string, string>} card @param {Record<string, string>} layer @param {boolean} before @param {typeof PAGE} [box] */
  const page = (card, layer, before, box = PAGE) => {
    const t = setup({}, (/** @type {any} */ document) => {
      if (before) painter(document, box, layer);
      const wrap = painter(document, { left: 80, top: 80, width: 300, height: 200 }, card);
      const form = addLoginForm(document, wrap);
      if (!before) painter(document, box, layer);
      return form;
    }, COVERAGE_ON);
    t.begin();
    // A cover that was there at the report leaves the field out of it, so the answer is no fill (any reason).
    const answer = t.fill();
    return answer.ok ? answer : COVERED;
  };
  // A darkening layer or a glow behind a card that is stacked above it.
  assert.deepEqual(page({ "z-index": "1" }, SHADE, true), FILLED, "a layer before a card with a z-index");
  assert.deepEqual(page({}, SHADE, true), FILLED, "a layer before a positioned card (tree order)");
  assert.deepEqual(page({ "z-index": "1" }, { ...SHADE, "z-index": "-1" }, false), FILLED, "a layer with a negative z-index, after the card");
  assert.deepEqual(page({ "z-index": "3" }, { ...SHADE, "z-index": "2" }, false), FILLED, "a lower z-index, after the card");
  assert.deepEqual(page({ position: "static" }, { ...SHADE, "z-index": "-1" }, true), FILLED, "a negative layer behind plain content");
  // The same layers where they do paint over the card.
  assert.deepEqual(page({}, SHADE, false), COVERED, "a layer after a positioned card");
  assert.deepEqual(page({ "z-index": "1" }, { ...SHADE, "z-index": "2" }, true), COVERED, "a layer with a higher z-index, before the card");
  assert.deepEqual(page({ "z-index": "1" }, { ...SHADE, "z-index": "2" }, false), COVERED, "a layer with a higher z-index, after the card");
  assert.deepEqual(page({ position: "static" }, SHADE, false), COVERED, "a positioned layer over plain content");
  // A layer that makes a stacking context of its own (a transform, a filter) paints with the positioned content.
  assert.deepEqual(page({ position: "static" }, { ...SHADE, position: "static", transform: "translateZ(0)" }, false), COVERED, "a transformed layer that is not positioned");
  // Not positioned, like the content: tree order decides (a block background before the field is below its content; one after
  // it is not known to be, and an inline or replaced element pulled over the field with a negative margin paints over it).
  assert.deepEqual(page({ position: "static" }, { ...SHADE, position: "static" }, true), FILLED, "plain boxes, the layer first");
  assert.deepEqual(page({ position: "static" }, { ...SHADE, position: "static" }, false), COVERED, "plain boxes, the layer after the card");
  // A shadow of a layer below the card is no cover either, an outline always is.
  const shadow = { "box-shadow": `${WHITE} 0px 0px 0px 9999px` };
  assert.deepEqual(page({ "z-index": "1" }, shadow, true, { left: 10, top: 400, width: 20, height: 20 }), FILLED, "a shadow of a layer below the card");
  assert.deepEqual(page({ "z-index": "1" }, { "z-index": "2", ...shadow }, true, { left: 10, top: 400, width: 20, height: 20 }), COVERED, "a shadow of a layer above the card");
  assert.deepEqual(page({ "z-index": "1" }, { "outline-style": "solid", "outline-width": "9999px", "outline-color": WHITE }, true, { left: 10, top: 400, width: 20, height: 20 }), COVERED, "an outline paints on top, whatever its level");
});

test("a_layer_in_the_top_layer_or_in_a_context_the_pass_did_not_know_is_a_cover", () => {
  const PAGE = { left: 0, top: 0, width: 1280, height: 800 };
  const WHITE_FILL = { "pointer-events": "none", "background-color": WHITE, "z-index": "-1" };
  /** @param {Record<string, string>} wrapper */
  const nested = (wrapper) => {
    const t = setup({}, addLoginForm, COVERAGE_ON);
    t.begin();
    const outer = painter(t.document, PAGE, { "pointer-events": "none", ...wrapper });
    painter(t.document, PAGE, WHITE_FILL, outer);
    return t.fill();
  };
  // A negative z-index inside a wrapper that makes no stacking context of its own is below the page's content.
  assert.deepEqual(nested({ position: "absolute" }), FILLED, "an absolute wrapper with no context (positive control)");
  // Inside a wrapper that does make one, the child's negative level is local to it: the wrapper paints over a plain field.
  for (const [name, wrapper] of /** @type {Array<[string, Record<string, string>]>} */ ([
    ["position fixed", { position: "fixed" }],
    ["position sticky", { position: "sticky" }],
    ["will-change: transform", { "will-change": "transform" }],
    ["will-change: opacity, filter", { "will-change": "opacity, filter" }],
    ["contain: paint", { contain: "paint" }],
    ["contain: layout style", { contain: "layout style" }],
    ["container-type: size", { "container-type": "size" }],
    ["backdrop-filter", { "backdrop-filter": "blur(2px)" }],
    ["a mask", { "-webkit-mask-image": "linear-gradient(black, black)" }],
    ["content-visibility: auto", { "content-visibility": "auto" }],
    ["view-transition-name", { "view-transition-name": "page" }],
  ])) assert.deepEqual(nested(wrapper), COVERED, name);
  assert.deepEqual(nested({ position: "absolute", "will-change": "scroll-position" }), FILLED, "a will-change that makes no context");
  assert.deepEqual(nested({ position: "absolute", contain: "size style" }), FILLED, "containment that makes no context");

  // The top layer paints above the page, whatever the z-index.
  for (const layer of [":popover-open", ":modal", ":fullscreen"]) {
    const t = setup({}, addLoginForm, COVERAGE_ON);
    t.begin();
    const dialog = painter(t.document, PAGE, WHITE_FILL);
    /** @type {any} */ (dialog).topLayer = layer;
    assert.deepEqual(t.fill(), COVERED, layer);
    const calm = setup({}, addLoginForm, COVERAGE_ON);
    calm.begin();
    painter(calm.document, PAGE, WHITE_FILL);
    assert.deepEqual(calm.fill(), FILLED, `${layer}: the same layer when it is not in the top layer (positive control)`);
  }
  // An engine that does not know the pseudo-class: the element is not in that layer, and nothing breaks.
  const unknown = setup({}, addLoginForm, COVERAGE_ON);
  unknown.begin();
  const odd = painter(unknown.document, PAGE, WHITE_FILL);
  odd.matches = () => { throw new Error("unknown pseudo-class"); };
  assert.deepEqual(unknown.fill(), FILLED);
});

test("a_click_through_picture_over_most_of_the_viewport_is_decoration_and_a_smaller_one_is_a_cover", () => {
  const PAGE = { left: 0, top: 0, width: 1280, height: 800 };
  const MOST = { left: 0, top: 0, width: 1280, height: 740 };
  const HALF = { left: 0, top: 0, width: 1280, height: 400 };
  for (const [name, tag, style] of /** @type {Array<[string, string, Record<string, string>]>} */ ([
    ["a canvas", "canvas", {}],
    ["an svg", "svg", {}],
    ["a background image", "div", { "background-image": 'url("https://cdn.example/grain.png")' }],
    ["a gradient scrim", "div", { "background-image": "linear-gradient(rgba(0, 0, 0, 0.1), rgba(0, 0, 0, 0.1))" }],
  ])) {
    const over = (/** @type {typeof PAGE} */ rect) => {
      const t = setup({}, addLoginForm, COVERAGE_ON);
      t.begin();
      painter(t.document, rect, { "pointer-events": "none", ...style }, t.document.body, tag);
      return t.fill();
    };
    assert.deepEqual(over(PAGE), FILLED, `${name} over the whole viewport`);
    assert.deepEqual(over(MOST), FILLED, `${name} over 90 percent of it`);
    assert.deepEqual(over(HALF), COVERED, `${name} over half of it (it holds the field)`);
  }
  // A gradient of opaque colours is a colour (a white sheet), whatever its size; a faint one stays decoration (above).
  for (const style of [{ "background-image": "linear-gradient(rgb(255, 255, 255), rgb(255, 255, 255))" }, { "background-image": "linear-gradient(rgb(255, 255, 255), rgba(255, 255, 255, 0.2))" }]) {
    const t = setup({}, addLoginForm, COVERAGE_ON);
    t.begin();
    painter(t.document, PAGE, { "pointer-events": "none", ...style }, t.document.body, "div");
    assert.deepEqual(t.fill(), style["background-image"].includes("0.2") ? FILLED : COVERED, JSON.stringify(style));
  }
  // An opaque colour, a video or an image is no decoration, whatever its size.
  for (const [name, tag, style] of /** @type {Array<[string, string, Record<string, string>]>} */ ([
    ["a white layer", "div", { "background-color": WHITE }],
    ["an image", "img", {}],
    ["a video", "video", {}],
    ["a frame", "iframe", {}],
  ])) {
    const t = setup({}, addLoginForm, COVERAGE_ON);
    t.begin();
    painter(t.document, PAGE, { "pointer-events": "none", ...style }, t.document.body, tag);
    assert.deepEqual(t.fill(), COVERED, name);
  }
});

test("the_coverage_pass_refuses_a_box_shadow_cover", () => {
  const AWAY = { left: 10, top: 400, width: 20, height: 20 };
  // Paint that hit testing cannot see, from an element that is itself nowhere near the field.
  for (const [name, rect, style] of /** @type {Array<[string, typeof AWAY, Record<string, string>]>} */ ([
    ["a large spread", AWAY, { "box-shadow": `${WHITE} 0px 0px 0px 9999px` }],
    ["a large spread, colour last", AWAY, { "box-shadow": "0 0 0 9999px white" }],
    ["a large spread on an element of no size", { left: 10, top: 400, width: 0, height: 0 }, { "box-shadow": `${WHITE} 0px 0px 0px 9999px` }],
    ["a large spread after a soft layer", AWAY, { "box-shadow": `rgba(0, 0, 0, 0.2) 0px 0px 4px 0px, ${WHITE} 0px 0px 0px 9999px` }],
    ["a shadow moved onto the field", { left: 500, top: 150, width: 260, height: 52 }, { "box-shadow": `${WHITE} -400px 0px 0px 0px` }],
    ["an outline", AWAY, { "outline-style": "solid", "outline-width": "9999px", "outline-offset": "0px", "outline-color": WHITE }],
    ["an outline with an offset", AWAY, { "outline-style": "solid", "outline-width": "300px", "outline-offset": "100px", "outline-color": "rgb(0, 0, 0)" }],
    ["a drop shadow moved onto the field", { left: -300, top: 150, width: 260, height: 52 }, { filter: `drop-shadow(${WHITE} 400px 0px 0px)` }],
  ])) {
    const { t, answer } = fillWith(rect, style);
    assert.deepEqual(answer, COVERED, name);
    assert.equal(nativeValue(t.pass), "", name);
    assert.deepEqual(fillWith(rect, style, { coveragePass: false }).answer, FILLED, `${name}, pass off`);
  }

  // Not a cover.
  for (const [name, rect, style] of /** @type {Array<[string, typeof AWAY, Record<string, string>]>} */ ([
    ["a soft shadow", AWAY, { "box-shadow": "rgba(0, 0, 0, 0.2) 0px 0px 0px 9999px" }],
    ["an inset shadow", AWAY, { "box-shadow": `inset ${WHITE} 0px 0px 0px 9999px` }],
    ["a card shadow", { left: 500, top: 150, width: 260, height: 52 }, { "box-shadow": "rgba(0, 0, 0, 0.9) 0px 2px 8px 0px" }],
    ["a hairline around a card beside the field", { left: 500, top: 150, width: 260, height: 52 }, { "box-shadow": "rgb(221, 221, 221) 0px 0px 0px 1px" }],
    ["a shadow too small to reach the field", AWAY, { "box-shadow": `${WHITE} 0px 0px 0px 20px` }],
    ["a thin outline", AWAY, { "outline-style": "solid", "outline-width": "2px", "outline-offset": "0px", "outline-color": WHITE }],
    ["no outline style", AWAY, { "outline-style": "none", "outline-width": "9999px", "outline-color": WHITE }],
    ["a faint outline", AWAY, { "outline-style": "solid", "outline-width": "9999px", "outline-offset": "0px", "outline-color": "rgba(0, 0, 0, 0.3)" }],
    ["a faint drop shadow", AWAY, { filter: "drop-shadow(rgba(0, 0, 0, 0.3) 0px 0px 9999px)" }],
    ["a drop shadow whose blur only softens its edge", AWAY, { filter: `drop-shadow(${WHITE} 0px 0px 9999px)` }],
    ["a large spread of a hidden element", AWAY, { "box-shadow": `${WHITE} 0px 0px 0px 9999px`, visibility: "hidden" }],
    ["a large spread of an element that is not drawn", AWAY, { "box-shadow": `${WHITE} 0px 0px 0px 9999px`, display: "none" }],
    ["a large spread of a faded element", AWAY, { "box-shadow": `${WHITE} 0px 0px 0px 9999px`, opacity: "0.5" }],
    ["the hole of a ring that holds the field", { left: 0, top: 100, width: 600, height: 200 }, { "pointer-events": "none", "outline-style": "solid", "outline-width": "9999px", "outline-offset": "0px", "outline-color": WHITE }],
  ])) {
    assert.deepEqual(fillWith(rect, style).answer, FILLED, name);
  }

  // The field's own outline, a neighbour's focus ring and the shadow of an ancestor are no cover.
  const ring = setup({}, addLoginForm, COVERAGE_ON);
  Object.assign(ring.user.style, { "outline-style": "solid", "outline-width": "2px", "outline-offset": "0px", "outline-color": "rgb(13, 110, 253)" });
  Object.assign(ring.pass.style, { "outline-style": "solid", "outline-width": "3px", "outline-offset": "0px", "outline-color": "rgb(13, 110, 253)" });
  ring.begin();
  assert.deepEqual(ring.fill(), FILLED);
  const card = setup({}, (/** @type {any} */ document) => {
    const wrap = painter(document, { left: 0, top: 0, width: 1000, height: 600 }, { "box-shadow": `${WHITE} 0px 0px 0px 9999px`, "outline-style": "solid", "outline-width": "999px", "outline-color": WHITE });
    return addLoginForm(document, wrap);
  }, COVERAGE_ON);
  card.begin();
  assert.deepEqual(card.fill(), FILLED);
});

test("a_floating_label_is_not_a_cover", () => {
  const FIELD = { left: 100, top: 160, width: 240, height: 32 };
  // A label over the empty field that clicks pass through and that has no background of its own (the common form).
  assert.deepEqual(fillWith(FIELD, { "pointer-events": "none" }).answer, FILLED, "no background");
  assert.deepEqual(fillWith(FIELD, { "pointer-events": "none", "background-color": "rgba(0, 0, 0, 0)" }).answer, FILLED, "a transparent background");
  // A label that sits on the border, with a background that hides the border behind it: a small part of the field.
  const notch = { left: 108, top: 152, width: 60, height: 16 };
  assert.deepEqual(fillWith(notch, { "pointer-events": "none", "background-color": WHITE }).answer, FILLED, "a notch with a background");
  assert.deepEqual(fillWith(notch, { "pointer-events": "none", "background-color": WHITE, filter: `drop-shadow(${WHITE} 0px 0px 2px)` }).answer, FILLED, "a notch with a glow");
  assert.deepEqual(fillWith(notch, { "pointer-events": "none", "background-color": WHITE, "box-shadow": `${WHITE} 0px 0px 0px 2px` }).answer, FILLED, "a notch with a rim");
  // The threshold: an element that holds a quarter of the field's area or its centre is a cover.
  assert.deepEqual(fillWith({ left: 100, top: 160, width: 50, height: 32 }, { "pointer-events": "none", "background-color": WHITE }).answer, FILLED, "under a quarter");
  assert.deepEqual(fillWith({ left: 100, top: 160, width: 70, height: 32 }, { "pointer-events": "none", "background-color": WHITE }).answer, COVERED, "over a quarter");
  assert.deepEqual(fillWith({ left: 200, top: 170, width: 40, height: 10 }, { "pointer-events": "none", "background-color": WHITE }).answer, COVERED, "over the centre");

  // The label of the field itself, at rest over an empty field with a background of its own that crosses the centre: not a cover.
  // The same box as any other element is one.
  const long = { left: 104, top: 166, width: 220, height: 20 };
  const labelled = (/** @type {string} */ tag, /** @type {Record<string, string>} */ attributes) => {
    const t = setup({}, addLoginForm, COVERAGE_ON);
    t.begin();
    const label = t.document.body.append(t.document.createElement(tag, attributes));
    label.rect = long;
    Object.assign(label.style, { position: "absolute", "pointer-events": "none", "background-color": WHITE });
    return { t, label };
  };
  const forPass = labelled("label", { for: "pass" });
  assert.deepEqual(forPass.t.fill(), FILLED, "a label for the field");
  // A label that is larger than its field is no label at rest: a layer that fills the page, or one taller than the field.
  const huge = labelled("label", { for: "pass" });
  huge.label.rect = { left: 0, top: 0, width: 1280, height: 800 };
  assert.deepEqual(huge.t.fill(), COVERED, "a label as large as the page");
  const tall = labelled("label", { for: "pass" });
  tall.label.rect = { left: 104, top: 140, width: 220, height: 80 };
  assert.deepEqual(tall.t.fill(), COVERED, "a label much taller than the field");
  const wide = labelled("label", { for: "pass" });
  wide.label.rect = { left: 90, top: 166, width: 400, height: 20 };
  assert.deepEqual(wide.t.fill(), FILLED, "a long label that crosses the centre but is smaller than the field in area (positive control)");
  assert.deepEqual(labelled("label", { for: "user" }).t.fill(), COVERED, "the label of another field");
  assert.deepEqual(labelled("div", { for: "pass" }).t.fill(), COVERED, "a div is no label");
  // What is inside the label is the label's.
  const nested = setup({}, addLoginForm, COVERAGE_ON);
  nested.begin();
  const outer = nested.document.body.append(nested.document.createElement("label", { for: "pass" }));
  Object.assign(outer.style, { position: "absolute", "pointer-events": "none" });
  painter(nested.document, long, { "pointer-events": "none", "background-color": WHITE }, outer);
  assert.deepEqual(nested.fill(), FILLED, "a span in the label");
  // A label does not excuse a shadow, an outline or a drop shadow over the field.
  const rim = labelled("label", { for: "pass" });
  rim.label.rect = { left: 10, top: 400, width: 20, height: 20 };
  Object.assign(rim.label.style, { "background-color": "transparent", "box-shadow": `${WHITE} 0px 0px 0px 9999px` });
  assert.deepEqual(rim.t.fill(), COVERED, "a label with a large shadow");
});

test("the_coverage_pass_sees_a_late_cover_on_a_large_page", () => {
  const OVER_FIELD = { left: 90, top: 150, width: 260, height: 52 };
  // 5 200 harmless elements, then the cover: the walk starts from the end of the document.
  const crowded = setup({}, (/** @type {any} */ document) => {
    const forms = addLoginForm(document);
    for (let i = 0; i < 5_200; i += 1) {
      const filler = document.body.append(document.createElement("div"));
      filler.rect = { left: 500, top: 500, width: 5, height: 5 };
    }
    return forms;
  }, COVERAGE_ON);
  crowded.begin();
  painter(crowded.document, OVER_FIELD, { "pointer-events": "none", "background-color": WHITE });
  assert.deepEqual(crowded.fill(), COVERED, "a cover after 5 200 elements");
  // 300 tiny outlines far off the screen cannot fill the list before a cover that comes earlier in the document.
  const noisy = setup({}, (/** @type {any} */ document) => {
    const forms = addLoginForm(document);
    painter(document, OVER_FIELD, { "pointer-events": "none", "background-color": WHITE });
    for (let i = 0; i < 300; i += 1) {
      painter(document, { left: 5_000 + i, top: 5_000, width: 1, height: 1 }, { "outline-style": "solid", "outline-width": "1px", "outline-color": WHITE });
    }
    return forms;
  }, COVERAGE_ON);
  assert.ok(!kinds(noisy.begin()).includes("password"), "a cover before 300 outlines off the screen");
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

  const ALLOWED = new Set(["content/entry.mjs", "content/fill.mjs", "content/forms.mjs", "content/passwordRules.mjs", "content/patterns.mjs", "content/capture.mjs", "content/capture.entry.mjs", "shared/contentProtocol.mjs", "shared/schema.mjs",
    // The passkey scripts of a page (each its own bundle: the one in the page's world reaches nothing; the bridge also reads the wire form).
    "content/passkey.main.entry.mjs", "content/passkeyResponse.mjs", "content/passkey.bridge.entry.mjs", "shared/webauthnWire.mjs"]);
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
  assert.deepEqual(importsOf(files.get("content/fill.mjs")?.toString("utf8") ?? "").specifiers, ["../shared/contentProtocol.mjs", "./forms.mjs", "./passwordRules.mjs"]);
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
 * @param {object} [engineOptions] more options of the engine
 */
function framePage(arrange = () => {}, engineOptions = {}) {
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
    ...engineOptions,
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
  for (const bad of [undefined, [], [[1]], [[1, Number.NaN]], [["1", 2]], Array.from({ length: 9 }, () => [1, 1]), [[1e9, 1]]]) {
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
