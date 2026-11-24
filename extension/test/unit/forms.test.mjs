// The detection module of the content scripts (src/content/forms.mjs) on fake pages: what a field is for, and what a
// form is for. The fill engine's use of it is in fillDom.test.mjs; the split one-time code in splitOtp.test.mjs.
import assert from "node:assert/strict";
import { test } from "node:test";
import { FIELD_KINDS, GROUP_KINDS, SUBMIT_WORDS, classifyField, findGroups } from "../../src/content/forms.mjs";
import { addInput, addText, createPage } from "./fakeDom.mjs";

/**
 * A page with one form (or none) built from a list: `["input", attributes]`, `["label", text, attributes]`,
 * `["button", text, attributes]`, `["h1", text]`. Inputs and buttons belong to the form.
 * @param {Array<[string, ...any[]]>} parts
 * @param {{ form?: boolean, title?: string, formAttributes?: Record<string, string> }} [options]
 */
function page(parts, { form = true, title = "", formAttributes = {} } = {}) {
  const { document, window } = createPage();
  document.title = title;
  const parent = form ? document.body.append(document.createElement("form", formAttributes)) : document.body;
  /** @type {Record<string, any>} */
  const byId = {};
  let top = 20;
  for (const [tag, ...rest] of parts) {
    if (tag === "input") {
      const input = addInput(document, parent, rest[0], { top });
      top += 40;
      if (form) input.form = parent;
      if (rest[0].id) byId[rest[0].id] = input;
    } else {
      const element = addText(document, parent, tag, rest[0], rest[1] ?? {});
      if (form && tag === "button") element.form = parent;
      if (rest[1]?.id) byId[rest[1].id] = element;
    }
  }
  return { document, window, form: form ? parent : null, byId };
}

/** The kind of each input of a page, by id. @param {ReturnType<typeof page>} p */
const kindsOf = (p) => Object.fromEntries(Object.entries(p.byId).filter(([, e]) => e.localName === "input").map(([id, e]) => [id, classifyField(e).kind]));

/** The groups of a page as `kind` and the id of each role. @param {ReturnType<typeof page>} p */
function groupsOf(p) {
  const idOf = (/** @type {any} */ e) => (Array.isArray(e) ? e.map(idOf) : e?.getAttribute("id"));
  return findGroups(p.document).map((g) => {
    /** @type {Record<string, any>} */
    const out = { kind: g.kind };
    for (const role of ["username", "email", "current", "password", "new", "confirm", "otp"]) {
      const element = /** @type {any} */ (g)[role];
      if (element !== undefined) out[role] = idOf(element);
    }
    return out;
  });
}

test("the_kinds_are_the_ones_of_the_plan", () => {
  assert.deepEqual([...FIELD_KINDS], ["username", "email", "current_password", "new_password", "confirm_password", "otp", "otp_digit", "search", "card_number", "card_cvc", "pin", "other"]);
  assert.deepEqual([...GROUP_KINDS], ["login", "signup", "change", "reset", "identifier", "otp", "none"]);
  assert.deepEqual(Object.keys(SUBMIT_WORDS).sort(), ["de", "en", "fr", "nb", "nl"]);
  for (const words of Object.values(SUBMIT_WORDS)) assert.ok(words.length > 5 && words.every((w) => w === w.toLowerCase()));
});

test("autocomplete_tokens_decide_before_keywords", () => {
  const p = page([
    // The words say user name, the token says one-time code: the token wins.
    ["input", { id: "a", type: "text", name: "username", autocomplete: "one-time-code" }],
    // The words say password, the token says new password.
    ["input", { id: "b", type: "password", name: "current_password", autocomplete: "new-password" }],
    // The words say new, the token says the password in use.
    ["input", { id: "c", type: "password", name: "new_password", autocomplete: "current-password" }],
    // The words say search, the token says e-mail: a search box stays a search box (it never gets a user name).
    ["input", { id: "d", type: "text", name: "q", autocomplete: "email" }],
    // A qualified token: `section-x billing email`.
    ["input", { id: "e", type: "text", name: "zzz", autocomplete: "section-a billing email" }],
    // `off` says nothing: the words decide.
    ["input", { id: "f", type: "text", name: "benutzername", autocomplete: "off" }],
    // A token of personal data: never a user name, whatever the words.
    ["input", { id: "g", type: "text", name: "login", autocomplete: "given-name" }],
    // The card tokens.
    ["input", { id: "h", type: "password", name: "password", autocomplete: "cc-csc" }],
    ["input", { id: "i", type: "text", name: "user", autocomplete: "cc-number" }],
  ]);
  assert.deepEqual(kindsOf(p), {
    a: "otp", b: "new_password", c: "current_password", d: "search", e: "email", f: "username", g: "other", h: "card_cvc", i: "card_number",
  });
  assert.deepEqual(classifyField(p.byId.a).reasons, ["autocomplete"]);
  assert.deepEqual(classifyField(p.byId.f).reasons, ["word"]);
});

test("a_card_cvc_typed_as_password_is_not_a_password", () => {
  // The token, the field's name, its label: each alone makes it a card's security code.
  const byToken = page([["input", { id: "card", type: "text", autocomplete: "cc-number" }], ["input", { id: "cvc", type: "password", autocomplete: "cc-csc" }]]);
  const byName = page([["label", "Navn på kortet", { for: "holder" }], ["input", { id: "holder", type: "text", name: "kortholder" }], ["input", { id: "cvc", type: "password", name: "cvv", maxlength: "3" }]]);
  const byLabel = page([["label", "Card verification code", { for: "cvc" }], ["input", { id: "cvc", type: "password", name: "x2" }]]);
  for (const p of [byToken, byName, byLabel]) {
    assert.equal(classifyField(p.byId.cvc).kind, "card_cvc");
    // The whole form is a card form: nothing in it is a sign-in, so nothing is filled there.
    assert.deepEqual(groupsOf(p).map((g) => g.kind), ["none"]);
  }
  assert.equal(classifyField(byName.byId.holder).kind, "other", "the card holder is never a user name");
  // An e-mail field in a card form is not a sign-in either.
  const checkout = page([
    ["input", { id: "email", type: "email", name: "email", autocomplete: "email" }],
    ["input", { id: "card", type: "text", name: "card", inputmode: "numeric", autocomplete: "cc-number" }],
    ["input", { id: "exp", type: "text", name: "exp", autocomplete: "cc-exp" }],
    ["input", { id: "cvc", type: "password", name: "cvc", inputmode: "numeric", maxlength: "4", autocomplete: "cc-csc" }],
  ]);
  assert.deepEqual(groupsOf(checkout), [{ kind: "none", email: "email" }]);
});

test("an_otp_masked_as_password_is_otp", () => {
  const cases = [
    page([["label", "Bekreftelseskode", { for: "code" }], ["input", { id: "code", type: "password", name: "engangskode", autocomplete: "one-time-code", inputmode: "numeric", maxlength: "6" }]]),
    page([["label", "Verification code", { for: "code" }], ["input", { id: "code", type: "password", name: "sms_code", inputmode: "numeric", maxlength: "6", autocomplete: "off" }]]),
    page([["label", "Bestätigungscode", { for: "code" }], ["input", { id: "code", type: "password", name: "token", placeholder: "000000", maxlength: "6", pattern: "[0-9]{6}" }]]),
    page([["input", { id: "code", type: "password", name: "totp" }]]),
  ];
  for (const p of cases) {
    assert.equal(classifyField(p.byId.code).kind, "otp", p.byId.code.getAttribute("name"));
    // A code page, never a sign-in; the masked field takes no role (the fill never puts a code into a password input).
    assert.deepEqual(groupsOf(p), [{ kind: "none" }]);
  }
  // A plain code field is a code page.
  const plain = page([["input", { id: "code", type: "text", name: "otp", inputmode: "numeric", maxlength: "6" }]]);
  assert.deepEqual(groupsOf(plain), [{ kind: "otp", otp: "code" }]);
  // "Password" words veto a weak code term: a password field named for a pass code with a password label is a password.
  const named = page([["label", "Password", { for: "p" }], ["input", { id: "p", type: "password", name: "passcode" }]]);
  assert.equal(classifyField(named.byId.p).kind, "current_password");
});

test("a_pin_field_is_not_a_password", () => {
  const byWord = page([["label", "Kundennummer", { for: "cust" }], ["input", { id: "cust", type: "text", name: "kunde", inputmode: "numeric", autocomplete: "off" }], ["label", "PIN", { for: "pin" }], ["input", { id: "pin", type: "password", name: "pin", inputmode: "numeric", maxlength: "4", autocomplete: "off" }]]);
  const byShape = page([["input", { id: "pin", type: "password", name: "code_secret", inputmode: "numeric", maxlength: "4" }]]);
  const byLabel = page([["label", "Code PIN", { for: "pin" }], ["input", { id: "pin", type: "password", name: "zz" }]]);
  for (const p of [byWord, byShape, byLabel]) {
    assert.equal(classifyField(p.byId.pin).kind, "pin");
    assert.deepEqual(groupsOf(p).map((g) => g.kind), ["none"], "a PIN form is no sign-in: no user name goes into its other field either");
  }
  // A pinned word inside another word is not a PIN.
  const spin = page([["input", { id: "p", type: "password", name: "spinner_password" }]]);
  assert.equal(classifyField(spin.byId.p).kind, "current_password");
});

test("search_and_newsletter_boxes_are_never_username", () => {
  // Search boxes in their common shapes.
  for (const attributes of [{ type: "search", name: "x" }, { type: "text", name: "q" }, { type: "text", role: "searchbox" }, { type: "text", name: "user-search" }, { type: "text", placeholder: "Søk etter brukere" }, { type: "text", "aria-label": "Zoeken" }]) {
    const p = page([["input", { id: "s", ...attributes }]], { form: false });
    assert.equal(classifyField(p.byId.s).kind, "search", JSON.stringify(attributes));
    assert.deepEqual(groupsOf(p), [{ kind: "none" }], JSON.stringify(attributes));
  }
  // A newsletter box: an e-mail field (also one marked with the user name token) and a send button.
  const newsletters = [
    page([["h1", "Send meg nyheter"], ["label", "E-postadresse", { for: "mail" }], ["input", { id: "mail", type: "email", name: "epost", autocomplete: "email" }], ["button", "Send", { id: "go", type: "submit" }]], { title: "Velkommen tilbake" }),
    page([["label", "Adresse e-mail", { for: "mail" }], ["input", { id: "mail", type: "text", name: "courriel", autocomplete: "username" }], ["input", { id: "agree", type: "checkbox" }], ["button", "Envoyer", { id: "go", type: "submit" }]], { title: "Bon retour" }),
    // A contact form: a name, an e-mail address and a message.
    page([["input", { id: "name", type: "text", name: "name", autocomplete: "name" }], ["input", { id: "mail", type: "email", name: "email", autocomplete: "email" }], ["textarea", ""], ["button", "Senden", { id: "go", type: "submit" }]], { title: "Willkommen zurück" }),
    // A feedback form: a rating and an e-mail address.
    page([["input", { id: "r", type: "radio", name: "r" }], ["input", { id: "mail", type: "email", name: "email", autocomplete: "email" }], ["textarea", ""], ["button", "Senden", { id: "go", type: "submit" }]]),
  ];
  for (const p of newsletters) assert.deepEqual(groupsOf(p).map((g) => g.kind), ["none"]);
  // The same e-mail field with a sign-in's words is the user name step.
  const step = page([["label", "Email address", { for: "u" }], ["input", { id: "u", type: "text", name: "u", autocomplete: "username" }], ["button", "Next", { id: "next", type: "submit" }]], { title: "Sign in" });
  assert.deepEqual(groupsOf(step), [{ kind: "identifier", username: "u" }]);
});

test("norwegian_labels_are_recognised", () => {
  const p = page([
    ["label", "Brukernavn", { for: "u" }], ["input", { id: "u", type: "text", name: "f1" }],
    ["label", "Passord", { for: "p" }], ["input", { id: "p", type: "password", name: "f2" }],
    ["button", "Logg inn", { id: "go", type: "submit" }],
  ]);
  assert.deepEqual(kindsOf(p), { u: "username", p: "current_password" });
  assert.deepEqual(groupsOf(p), [{ kind: "login", username: "u", password: "p" }]);
  // A change form in Norwegian, by its labels only.
  const change = page([
    ["label", "Nåværende passord", { for: "cur" }], ["input", { id: "cur", type: "password", name: "a" }],
    ["label", "Nytt passord", { for: "new" }], ["input", { id: "new", type: "password", name: "b" }],
    ["label", "Gjenta passord", { for: "new2" }], ["input", { id: "new2", type: "password", name: "c" }],
  ]);
  assert.deepEqual(kindsOf(change), { cur: "current_password", new: "new_password", new2: "confirm_password" });
  assert.deepEqual(groupsOf(change), [{ kind: "change", current: "cur", new: "new", confirm: "new2" }]);
  // A sign-up form whose button says so, and an e-mail field by its Norwegian label.
  const signup = page([["label", "E-postadresse", { for: "e" }], ["input", { id: "e", type: "text", name: "x" }], ["label", "Passord", { for: "pw" }], ["input", { id: "pw", type: "password", name: "y" }], ["button", "Opprett konto", { id: "go", type: "submit" }]]);
  assert.deepEqual(groupsOf(signup), [{ kind: "signup", username: "e", email: "e", new: "pw" }]);
  // A code page in Norwegian.
  const code = page([["label", "Engangskode", { for: "c" }], ["input", { id: "c", type: "text", name: "c" }]]);
  assert.deepEqual(groupsOf(code), [{ kind: "otp", otp: "c" }]);
});

test("login_signup_change_reset_and_identifier_are_told_apart", () => {
  const login = page([["input", { id: "u", type: "text", name: "username", autocomplete: "username" }], ["input", { id: "p", type: "password", name: "password", autocomplete: "current-password" }], ["button", "Sign in", { id: "go", type: "submit" }]]);
  assert.deepEqual(groupsOf(login), [{ kind: "login", username: "u", password: "p" }]);

  // Sign-up: by the tokens; by a confirm field without tokens; by the submit words with one password and no tokens.
  const signupTokens = page([["input", { id: "email", type: "email", name: "email", autocomplete: "email" }], ["input", { id: "pw", type: "password", name: "password", autocomplete: "new-password" }], ["input", { id: "pw2", type: "password", name: "password2", autocomplete: "new-password" }]]);
  assert.deepEqual(groupsOf(signupTokens), [{ kind: "signup", username: "email", email: "email", new: "pw", confirm: "pw2" }]);
  const signupWords = page([["input", { id: "email", type: "email", name: "courriel" }], ["input", { id: "pw", type: "password", name: "mdp" }], ["input", { id: "pw2", type: "password", name: "mdp_confirmation" }]]);
  assert.deepEqual(groupsOf(signupWords), [{ kind: "signup", username: "email", email: "email", new: "pw", confirm: "pw2" }]);
  const signupButton = page([["input", { id: "user", type: "text", name: "nutzer", autocomplete: "username" }], ["input", { id: "pw", type: "password", name: "kennwort" }], ["button", "Konto erstellen", { id: "go", type: "submit" }]]);
  assert.deepEqual(groupsOf(signupButton), [{ kind: "signup", username: "user", new: "pw" }]);
  // The same form with a sign-in button is a sign-in: a link elsewhere on the page does not count.
  const loginButton = page([["input", { id: "user", type: "text", name: "nutzer", autocomplete: "username" }], ["input", { id: "pw", type: "password", name: "kennwort" }], ["button", "Anmelden", { id: "go", type: "submit" }]], { title: "Konto erstellen oder anmelden" });
  assert.deepEqual(groupsOf(loginButton), [{ kind: "login", username: "user", password: "pw" }]);
  // Only the page's title says sign-up, and nothing says sign-in: a sign-up.
  const titled = page([["input", { id: "email", type: "email", name: "email" }], ["input", { id: "pw", type: "password", name: "pw" }]], { title: "Create account" });
  assert.deepEqual(groupsOf(titled).map((g) => g.kind), ["signup"]);

  // Change: the password in use and a new one, with or without a confirm field.
  const change = page([["input", { id: "cur", type: "password", autocomplete: "current-password" }], ["input", { id: "new", type: "password", autocomplete: "new-password" }]]);
  assert.deepEqual(groupsOf(change), [{ kind: "change", current: "cur", new: "new" }]);
  const three = page([["input", { id: "a", type: "password", name: "f1" }], ["input", { id: "b", type: "password", name: "f2" }], ["input", { id: "c", type: "password", name: "f3" }]]);
  assert.deepEqual(groupsOf(three), [{ kind: "change", current: "a", new: "b", confirm: "c" }], "three plain password fields: in use, new, again");

  // Reset: new password fields and no user name.
  const reset = page([["input", { id: "token", type: "hidden", name: "token" }], ["input", { id: "new", type: "password", name: "password", autocomplete: "new-password" }], ["input", { id: "new2", type: "password", name: "password_confirmation", autocomplete: "new-password" }], ["button", "Reset password", { id: "go", type: "submit" }]]);
  assert.deepEqual(groupsOf(reset), [{ kind: "reset", new: "new", confirm: "new2" }]);
  const twoPlain = page([["input", { id: "a", type: "password", name: "f1" }], ["input", { id: "b", type: "password", name: "f2" }]]);
  assert.deepEqual(groupsOf(twoPlain), [{ kind: "reset", new: "a", confirm: "b" }]);

  // Identifier: a user name step whose password field is not shown yet, or whose button moves on, or a page that says sign-in.
  const { document } = createPage();
  const form = document.body.append(document.createElement("form"));
  const user = addInput(document, form, { id: "u", type: "text", name: "identifier", autocomplete: "username" }, { top: 20 });
  const pass = addInput(document, form, { id: "p", type: "password", name: "password", autocomplete: "current-password" }, null);
  user.form = pass.form = form;
  const sameStep = findGroups(document, { shown: (e) => e !== pass });
  assert.equal(sameStep[0].kind, "identifier");
  assert.equal(sameStep[0].username, user);
  assert.equal(sameStep[0].password, undefined, "a password field the user cannot see takes no role");
  // Shown, the same form is a sign-in.
  assert.equal(findGroups(document)[0].kind, "login");
  const nextButton = page([["input", { id: "u", type: "email", name: "x", autocomplete: "email" }], ["button", "Weiter", { id: "next", type: "submit" }]]);
  assert.deepEqual(groupsOf(nextButton), [{ kind: "identifier", username: "u", email: "u" }]);
  // Without any word of a sign-in, an e-mail field alone is nothing.
  const bare = page([["input", { id: "u", type: "email", name: "x", autocomplete: "email" }], ["button", "Go", { id: "go", type: "submit" }]]);
  assert.deepEqual(groupsOf(bare), [{ kind: "none", email: "u" }]);
});

test("a_show_password_toggle_is_not_a_submit_control", () => {
  // In a form: the toggle (a button by its words, or a button in the password field's wrapper) is passed over.
  const { document } = createPage();
  const form = document.body.append(document.createElement("form"));
  const user = addInput(document, form, { id: "u", type: "text", name: "username" }, { top: 20 });
  const wrap = form.append(document.createElement("div"));
  const pass = addInput(document, wrap, { id: "p", type: "password", name: "password" }, { top: 60 });
  const eye = addText(document, wrap, "button", "", { type: "button", "aria-label": "Afficher le mot de passe" });
  const bare = addText(document, wrap, "button", "", { type: "button" });
  const go = addText(document, form, "button", "Se connecter", { type: "submit" });
  user.form = pass.form = eye.form = bare.form = go.form = form;
  const [group] = findGroups(document);
  assert.equal(group.kind, "login");
  assert.equal(group.submit, go);

  // Without a form: only a control with a submit word counts; the toggle beside the password field never does.
  const loose = createPage().document;
  const box = loose.body.append(loose.createElement("div"));
  addInput(loose, box, { id: "u", type: "text", name: "username" }, { top: 20 });
  const field = box.append(loose.createElement("span"));
  addInput(loose, field, { id: "p", type: "password", name: "password" }, { top: 60 });
  addText(loose, field, "button", "Vis", { type: "button" });
  const send = addText(loose, box, "button", "Logg inn", { type: "button" });
  const [looseGroup] = findGroups(loose);
  assert.equal(looseGroup.kind, "login");
  assert.equal(looseGroup.submit, send);
  // A page with the toggle and no other control has no submit control.
  send.text = "";
  send.setAttribute("aria-label", "Vis passord");
  assert.equal(findGroups(loose)[0].submit, undefined);
});

test("fields_without_a_form_are_grouped_by_their_container_and_only_named_ones_on_the_whole_page", () => {
  const { document } = createPage();
  const header = document.body.append(document.createElement("header"));
  addInput(document, header, { id: "news", type: "email", name: "email" }, { top: 20 });
  const main = document.body.append(document.createElement("main"));
  const user = addInput(document, main, { id: "u", type: "text", name: "q1" }, { top: 100 });
  const pass = addInput(document, main, { id: "p", type: "password" }, { top: 160 });
  const groups = findGroups(document);
  const login = groups.find((g) => g.kind === "login");
  assert.equal(login?.password, pass);
  assert.equal(login?.username, user, "an unnamed text field right before the password in its container");
  // On the whole page, an unnamed text field is never the user name.
  const flat = createPage().document;
  addInput(flat, flat.body, { id: "note", type: "text", name: "zz" }, { top: 20 });
  const flatPass = addInput(flat, flat.body, { id: "p", type: "password" }, { top: 60 });
  const [whole] = findGroups(flat);
  assert.equal(whole.password, flatPass);
  assert.equal(whole.username, undefined);
});

test("a_change_form_takes_a_user_name_only_from_a_field_the_page_marks_as_one", () => {
  const profile = (/** @type {Record<string, string>} */ mail) => page([
    ["input", { id: "dname", type: "text", name: "visningsnavn", value: "Anna" }],
    ["input", { id: "mail", type: "email", value: "anna@example.net", ...mail }],
    ["input", { id: "cur", type: "password", autocomplete: "current-password" }],
    ["input", { id: "new", type: "password", autocomplete: "new-password" }],
    ["input", { id: "new2", type: "password", autocomplete: "new-password" }],
  ]);
  // A profile e-mail address in the same form is no user name of the change.
  assert.deepEqual(groupsOf(profile({ name: "epost", autocomplete: "email" })), [{ kind: "change", email: "mail", current: "cur", new: "new", confirm: "new2" }]);
  // A field the page marks as the user name is one, an e-mail one too.
  assert.deepEqual(groupsOf(profile({ name: "login", autocomplete: "username" })), [{ kind: "change", username: "mail", current: "cur", new: "new", confirm: "new2" }]);
  // A read-only account field with a user name token (the common change form) is one.
  const account = page([
    ["input", { id: "acct", type: "text", name: "login", value: "ola", readonly: "", autocomplete: "username" }],
    ["input", { id: "cur", type: "password", autocomplete: "current-password" }],
    ["input", { id: "new", type: "password", autocomplete: "new-password" }],
  ]);
  assert.deepEqual(groupsOf(account), [{ kind: "change", username: "acct", current: "cur", new: "new" }]);
  // A sign-up form still takes the e-mail field (the positive control: the rule is about change forms).
  const signup = page([
    ["input", { id: "mail", type: "email", autocomplete: "email" }],
    ["input", { id: "pw", type: "password", autocomplete: "new-password" }],
    ["input", { id: "pw2", type: "password", autocomplete: "new-password" }],
  ]);
  assert.equal(groupsOf(signup)[0].username, "mail");
});

test("the_search_for_the_container_of_a_field_without_a_form_stops_at_a_fixed_depth", () => {
  const nest = (/** @type {number} */ levels) => {
    const { document } = createPage();
    addInput(document, document.body, { id: "u", type: "text", autocomplete: "username" }, { top: 20 });
    /** @type {any} */
    let node = document.body;
    for (let i = 0; i < levels; i += 1) node = node.append(document.createElement("div"));
    addInput(document, node, { id: "p", type: "password", autocomplete: "current-password" }, { top: 60 });
    return document;
  };
  const together = (/** @type {any} */ document) => findGroups(document).some((g) => g.username?.getAttribute("id") === "u" && g.password?.getAttribute("id") === "p");
  assert.equal(together(nest(10)), true, "a field ten levels down shares its container with the user name (positive control)");
  assert.equal(together(nest(100)), false, "a field a hundred levels down is not searched for: it is its own group");
});

test("a_search_box_the_page_marks_as_a_user_name_is_one_and_only_then", () => {
  // The type alone does not decide when the page's own token says username.
  const marked = page([["label", "User name", { for: "u" }], ["input", { id: "u", type: "search", name: "username", autocomplete: "username" }], ["input", { id: "p", type: "password", autocomplete: "current-password" }], ["button", "Sign in", { id: "go", type: "submit" }]], { title: "Sign in" });
  assert.equal(classifyField(marked.byId.u).kind, "username");
  assert.deepEqual(groupsOf(marked), [{ kind: "login", username: "u", password: "p" }]);
  // Without the token, or with another mark of a search box (the role, the name q, the words), it stays a search box.
  for (const attributes of [{ type: "search", name: "x" }, { type: "search", name: "x", autocomplete: "off" }, { type: "search", name: "q", autocomplete: "username" }, { type: "search", role: "searchbox", autocomplete: "username" }, { type: "search", placeholder: "Search", autocomplete: "username" }]) {
    const p = page([["input", { id: "s", ...attributes }]], { form: false });
    assert.equal(classifyField(p.byId.s).kind, "search", JSON.stringify(attributes));
  }
  // A search box in a search form stays one, whatever its token.
  const inSearch = page([["input", { id: "s", type: "search", autocomplete: "username" }], ["button", "Go", { type: "submit" }]], { formAttributes: { role: "search" } });
  assert.equal(classifyField(inSearch.byId.s).kind, "search");
});

test("a_lone_player_or_member_id_box_under_a_sign_in_button_is_a_user_name_step", () => {
  for (const label of ["Player ID", "Member ID", "Customer ID"]) {
    const p = page([["label", label, { for: "u" }], ["input", { id: "u", type: "text", name: "ident", required: "" }], ["button", "Sign in", { id: "go", type: "submit" }]], { title: "Sign in" });
    assert.equal(classifyField(p.byId.u).kind, "username", label);
    assert.deepEqual(groupsOf(p), [{ kind: "identifier", username: "u" }], label);
  }
  // The same boxes under a button that looks something up are no sign-in step: they classify as a user name but need a
  // sign-in or next cue on the page. "Client ID" is no user name word at all (an OAuth or API client field).
  for (const [label, button] of [["Member ID", "Find my plan"], ["Customer ID", "Check status"], ["Player ID", "Look up"]]) {
    const p = page([["label", label, { for: "u" }], ["input", { id: "u", type: "text", name: "ident" }], ["button", button, { id: "go", type: "submit" }]], { title: "Account tools" });
    assert.equal(classifyField(p.byId.u).kind, "username", label);
    assert.deepEqual(groupsOf(p).map((g) => g.kind), ["none"], `${label} / ${button}`);
  }
  const client = page([["label", "Client ID", { for: "u" }], ["input", { id: "u", type: "text", name: "ident" }], ["button", "Sign in", { id: "go", type: "submit" }]], { title: "Sign in" });
  assert.notEqual(classifyField(client.byId.u).kind, "username");
  // Other ids are no user name: an order, a coupon, a gift card.
  for (const label of ["Order ID", "Gift card ID", "Tracking ID"]) {
    const p = page([["label", label, { for: "u" }], ["input", { id: "u", type: "text", name: "ident" }], ["button", "Continue", { id: "go", type: "submit" }]], { title: "Track" });
    assert.notEqual(classifyField(p.byId.u).kind, "username", label);
    assert.deepEqual(groupsOf(p).map((g) => g.kind), ["none"], label);
  }
});

test("a_sign_up_with_an_email_and_a_user_name_gives_the_user_name_and_keeps_the_email_apart", () => {
  const both = page([["label", "Email", { for: "e" }], ["input", { id: "e", type: "email", name: "email", autocomplete: "email" }], ["label", "User name", { for: "u" }], ["input", { id: "u", type: "text", name: "username", autocomplete: "username" }], ["input", { id: "p", type: "password", autocomplete: "new-password" }], ["input", { id: "p2", type: "password", autocomplete: "new-password" }], ["button", "Create account", { id: "go", type: "submit" }]]);
  const [signup] = findGroups(both.document);
  assert.equal(signup.kind, "signup");
  assert.equal(signup.username.getAttribute("id"), "u");
  assert.equal(signup.email.getAttribute("id"), "e");
  // The user name first on the page, with one new password: the same.
  const one = page([["input", { id: "u", type: "text", name: "username", autocomplete: "username" }], ["input", { id: "e", type: "email", name: "email", autocomplete: "email" }], ["input", { id: "p", type: "password", autocomplete: "new-password" }], ["button", "Sign up", { id: "go", type: "submit" }]]);
  assert.equal(findGroups(one.document)[0].username.getAttribute("id"), "u");
  // Only an e-mail address: that is the name.
  const mail = page([["input", { id: "e", type: "email", name: "email", autocomplete: "email" }], ["input", { id: "p", type: "password", autocomplete: "new-password" }], ["input", { id: "p2", type: "password", autocomplete: "new-password" }], ["button", "Create account", { id: "go", type: "submit" }]]);
  assert.equal(findGroups(mail.document)[0].username.getAttribute("id"), "e");
});
