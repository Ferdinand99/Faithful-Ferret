// The fill engine's mode for a generated password (src/content/fill.mjs, `begin(requestId, "generated")`) on fake pages:
// it reports only the new and the confirm field of a sign-up, change or reset form (with each field's `maxlength`),
// never a sign-in form and never the password in use; at the fill the field must still be that group's new (or confirm)
// field, shown, a masked input of its form and inside its `maxlength`, and the value goes in with the native setter.
import assert from "node:assert/strict";
import { test } from "node:test";
import { createFillEngine } from "../../src/content/fill.mjs";
import {
  addInput, addLoginForm, BACKGROUND_SENDER, createPage, decodeSent, EXTENSION_BASE, fillMessage, RUNTIME_ID,
} from "./fakeDom.mjs";

/** Starts an engine on a page. @param {Parameters<typeof createPage>[0]} options @param {(document: any) => any} build */
function setup(options, build) {
  const page = createPage(options);
  const parts = build(page.document);
  const sent = /** @type {string[]} */ ([]);
  /** The elements a context-menu click can name, by id. @type {Map<number, any>} */
  const aimTargets = new Map();
  const engine = createFillEngine({ window: page.window, document: page.document, send: (raw) => { sent.push(raw); }, runtimeId: RUNTIME_ID, extensionBase: EXTENSION_BASE, targetOf: (id) => aimTargets.get(id) ?? null });
  return {
    ...page,
    aimTargets,
    ...parts,
    sent,
    engine,
    /** Reports in `mode` ("generated", or undefined for a sign-in request) and returns what was reported. @param {string | undefined} mode */
    begin(mode) {
      sent.length = 0;
      assert.equal(engine.begin("req-1", mode), true);
      return /** @type {Array<{ kind: string, id: string, max?: number }>} */ (decodeSent(sent)[0].body.fields);
    },
    /** One value for one kind, and the answer. @param {string} field @param {string} value */
    fill(field, value) {
      sent.length = 0;
      engine.onMessage(fillMessage({ field, value, frameUrl: options.url ?? "https://example.com/login" }), BACKGROUND_SENDER);
      const replies = decodeSent(sent);
      return replies.length === 0 ? null : replies[0].body;
    },
  };
}

const nativeValue = (/** @type {any} */ input) =>
  /** @type {any} */ (Object.getOwnPropertyDescriptor(Object.getPrototypeOf(input), "value")).get.call(input);

/** A form with the given fields: `[attributes, top]` in order. @param {any} document @param {Array<Record<string, string>>} fields @param {string} [submit] */
function formWith(document, fields, submit = "Create account") {
  const form = document.body.append(document.createElement("form"));
  const inputs = fields.map((attributes, i) => {
    const input = addInput(document, form, attributes, { top: 100 + i * 60 });
    input.form = form;
    return input;
  });
  const button = document.createElement("button", { type: "submit" });
  form.append(button);
  button.text = submit;
  button.rect = { left: 100, top: 100 + fields.length * 60, width: 120, height: 32 };
  return { form, inputs };
}

const SIGN_UP = [
  { type: "email", name: "email", autocomplete: "email" },
  { type: "password", name: "pw", autocomplete: "new-password", maxlength: "24" },
  { type: "password", name: "pw2", autocomplete: "new-password" },
];

test("a_generated_request_reports_the_new_and_the_confirm_field_of_a_sign_up_with_their_maxlength", () => {
  const t = setup({ url: "https://example.com/signup" }, (document) => formWith(document, SIGN_UP));
  const fields = t.begin("generated");
  assert.deepEqual(fields.map((f) => [f.kind, f.max]), [["new_password", 24], ["confirm_password", undefined]]);
  // Ids are made now and are not the page's.
  for (const field of fields) assert.match(field.id, /^[0-9a-f]{32}$/);
  // The same page asked in the sign-in mode reports nothing: the fields of a sign-up are no sign-in fields.
  assert.deepEqual(t.begin(undefined), []);

  // A reset form (a new password and its confirmation, no user name) is one too.
  const reset = setup({ url: "https://example.com/reset" }, (document) => formWith(document, [
    { type: "password", name: "a", autocomplete: "new-password" },
    { type: "password", name: "b", autocomplete: "new-password" },
  ], "Reset password"));
  assert.deepEqual(reset.begin("generated").map((f) => f.kind), ["new_password", "confirm_password"]);

  // A change form: the password in use is never reported, the new and the confirm field are.
  const change = setup({ url: "https://example.com/account/password" }, (document) => formWith(document, [
    { type: "text", name: "username", autocomplete: "username" },
    { type: "password", name: "old", autocomplete: "current-password" },
    { type: "password", name: "new", autocomplete: "new-password" },
    { type: "password", name: "new2", autocomplete: "new-password" },
  ], "Change password"));
  assert.deepEqual(change.begin("generated").map((f) => f.kind), ["new_password", "confirm_password"]);
  assert.deepEqual(change.fill("new_password", "Generated-1!"), { request_id: "req-1", ok: true });
  assert.deepEqual(change.fill("confirm_password", "Generated-1!"), { request_id: "req-1", ok: true });
  assert.deepEqual(change.fill("password", "Generated-1!"), { request_id: "req-1", ok: false, reason: "wrong_kind" });
  assert.deepEqual(change.inputs.map(nativeValue), ["", "", "Generated-1!", "Generated-1!"], "the password in use is untouched");

  // One new-password field only.
  const single = setup({ url: "https://example.com/join" }, (document) => formWith(document, [
    { type: "email", name: "email", autocomplete: "email" },
    { type: "password", name: "pw", autocomplete: "new-password" },
  ]));
  assert.deepEqual(single.begin("generated").map((f) => f.kind), ["new_password"]);

  // A sign-in form gives a generated fill nothing, and so does a page with no form at all, a code or a card form.
  const login = setup({ url: "https://example.com/login" }, (document) => addLoginForm(document));
  assert.deepEqual(login.begin("generated"), []);
  assert.deepEqual(login.fill("password", "x"), { request_id: "req-1", ok: false, reason: "wrong_kind" });
  assert.deepEqual(login.fill("new_password", "x"), { request_id: "req-1", ok: false, reason: "wrong_kind" });
  const empty = setup({}, () => ({}));
  assert.deepEqual(empty.begin("generated"), []);
  const code = setup({}, (document) => formWith(document, [{ type: "text", autocomplete: "one-time-code" }], "Verify"));
  assert.deepEqual(code.begin("generated"), []);

  // A mode this engine does not know is no request.
  const odd = setup({ url: "https://example.com/signup" }, (document) => formWith(document, SIGN_UP));
  assert.equal(odd.engine.begin("req-2", "anything"), false);
});

test("a_generated_value_goes_into_the_new_and_the_confirm_field_with_the_native_setter", () => {
  const t = setup({ url: "https://example.com/signup" }, (document) => formWith(document, SIGN_UP));
  t.begin("generated");
  /** Every event a field got, by name. */
  const events = /** @type {string[]} */ ([]);
  for (const input of t.inputs) {
    input.addEventListener("input", () => events.push(`${input.getAttribute("name")}:input`));
    input.addEventListener("change", () => events.push(`${input.getAttribute("name")}:change`));
  }
  assert.deepEqual(t.fill("new_password", "Generated-1!"), { request_id: "req-1", ok: true });
  assert.deepEqual(t.fill("confirm_password", "Generated-1!"), { request_id: "req-1", ok: true });
  assert.deepEqual(t.inputs.map(nativeValue), ["", "Generated-1!", "Generated-1!"]);
  assert.deepEqual(events, ["pw:input", "pw:change", "pw2:input", "pw2:change"]);
  // A kind that was not reported is wrong, a user name kind most of all.
  assert.deepEqual(t.fill("username", "ola"), { request_id: "req-1", ok: false, reason: "wrong_kind" });
  assert.deepEqual(t.fill("password", "x"), { request_id: "req-1", ok: false, reason: "wrong_kind" });
  assert.equal(nativeValue(t.inputs[0]), "");
});

test("a_generated_fill_refuses_a_value_over_the_maxlength_a_hidden_field_and_a_page_that_changed", () => {
  // The value is longer than the field takes: refused, nothing is put in.
  const t = setup({ url: "https://example.com/signup" }, (document) => formWith(document, SIGN_UP));
  t.begin("generated");
  assert.deepEqual(t.fill("new_password", "x".repeat(25)), { request_id: "req-1", ok: false, reason: "value_too_long" });
  assert.equal(nativeValue(t.inputs[1]), "");
  assert.deepEqual(t.fill("new_password", "x".repeat(24)), { request_id: "req-1", ok: true });
  // The limit is read again at the fill: a page that lowers it after the report gets nothing too long.
  t.inputs[1].setAttribute("maxlength", "10");
  assert.deepEqual(t.fill("new_password", "x".repeat(12)), { request_id: "req-1", ok: false, reason: "value_too_long" });

  // A field that is hidden or covered after the report gets nothing.
  const hidden = setup({ url: "https://example.com/signup" }, (document) => formWith(document, SIGN_UP));
  hidden.begin("generated");
  hidden.inputs[1].style.display = "none";
  assert.equal(hidden.fill("new_password", "Generated-1!")?.ok, false);
  assert.equal(nativeValue(hidden.inputs[1]), "");

  // The page turns the new-password field into a sign-in one (the group is now a login form): nothing goes in.
  const turned = setup({ url: "https://example.com/signup" }, (document) => formWith(document, [
    { type: "text", name: "user", autocomplete: "username" },
    { type: "password", name: "pw", autocomplete: "new-password" },
  ], "Create account"));
  turned.begin("generated");
  turned.inputs[1].setAttribute("autocomplete", "current-password");
  assert.deepEqual(turned.fill("new_password", "Generated-1!"), { request_id: "req-1", ok: false, reason: "wrong_kind" });
  assert.equal(nativeValue(turned.inputs[1]), "");

  // The field leaves its form: wrong kind.
  const moved = setup({ url: "https://example.com/signup" }, (document) => formWith(document, SIGN_UP));
  moved.begin("generated");
  moved.inputs[1].form = null;
  assert.deepEqual(moved.fill("new_password", "Generated-1!"), { request_id: "req-1", ok: false, reason: "wrong_kind" });
  assert.equal(nativeValue(moved.inputs[1]), "");

  // A frame that is not what the extension chose gets nothing, as for any fill.
  const frame = setup({ url: "https://example.com/signup" }, (document) => formWith(document, SIGN_UP));
  frame.begin("generated");
  frame.engine.onMessage(fillMessage({ field: "new_password", value: "Generated-1!", frameUrl: "https://example.com/elsewhere" }), BACKGROUND_SENDER);
  assert.equal(nativeValue(frame.inputs[1]), "");
});

test("a_generated_request_ignores_an_aim_and_a_sign_in_request_never_reports_a_new_field", () => {
  // A click on the password in use of a change form aims the next request at it. A generated request does not use the
  // aim: it still reports the new and the confirm field only, and the aim is spent.
  const aimed = setup({ url: "https://example.com/account/password" }, (document) => formWith(document, [
    { type: "text", name: "username", autocomplete: "username" },
    { type: "password", name: "old", autocomplete: "current-password" },
    { type: "password", name: "new", autocomplete: "new-password" },
    { type: "password", name: "new2", autocomplete: "new-password" },
  ], "Change password"));
  aimed.aimTargets.set(1, aimed.inputs[1]);
  assert.equal(aimed.engine.aim(1), true, "the aim was taken (positive control)");
  assert.deepEqual(aimed.begin("generated").map((f) => f.kind), ["new_password", "confirm_password"]);
  // The aim does not wait for the next sign-in request either: that one reports the group, not the clicked field.
  assert.deepEqual(aimed.begin(undefined).map((f) => f.kind), ["username", "password"]);
  // And without an aim the generated request is the same.
  const t = setup({ url: "https://example.com/signup" }, (document) => formWith(document, SIGN_UP));
  assert.deepEqual(t.begin("generated").map((f) => f.kind), ["new_password", "confirm_password"]);
  // A sign-in request on a change form reports the user name and the password in use, never the new fields.
  const change = setup({ url: "https://example.com/account/password" }, (document) => formWith(document, [
    { type: "text", name: "username", autocomplete: "username" },
    { type: "password", name: "old", autocomplete: "current-password" },
    { type: "password", name: "new", autocomplete: "new-password" },
  ], "Change password"));
  assert.deepEqual(change.begin(undefined).map((f) => f.kind), ["username", "password"]);
});
