// The sign-in tab and the popup: where the master password is typed (design
// document, sections 7.2 and 10.7), and the steps of the sign-in page.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { EXTENSION_CSP, build } from "../../scripts/build.mjs";
import { createPopupFlow, viewOf } from "../../src/pages/popupFlow.mjs";
import { createSignInFlow, unlockWith } from "../../src/pages/signinFlow.mjs";
import { UiError, connectUi, initialsOf, reasonKey, shownHost } from "../../src/pages/ui.mjs";
import { UI_TYPES, decode, encode, encodeRefusal } from "../../src/shared/protocol.mjs";
import { extensionRoot, makeRoot } from "./buildHelpers.mjs";
import { importsOf } from "./importGraph.mjs";

const SERVER = "https://vault.example.com";

/** A `request` that records what a page asks and answers from `answers`. */
function recorder(/** @type {Record<string, (body: any) => any>} */ answers = {}) {
  /** @type {Array<[string, any]>} */
  const sent = [];
  /** @type {import("../../src/pages/ui.mjs").Request} */
  const request = async (type, body) => {
    // What a page sends must pass the protocol.
    encode(type, body);
    sent.push([type, body]);
    const answer = answers[type];
    if (!answer) throw new Error(`no answer for ${type}`);
    return answer(body);
  };
  return { request, sent };
}

const checkedServer = () => ({ ok: true, server: SERVER, host: "vault.example.com", host_a_label: "vault.example.com" });

test("signin_page_and_popup_are_not_web_accessible_and_have_frame_ancestors_none", async () => {
  for (const manifest of ["mv3", "mv2"]) {
    for (const variant of ["release", "test"]) {
      const env = makeRoot();
      try {
        const result = await build({ root: env.root, webRoot: env.webRoot, out: env.out, wasmTar: env.tarPath, manifest, variant });
        const json = JSON.parse(readFileSync(join(result.dir, "manifest.json"), "utf8"));
        const where = `${manifest} ${variant}`;
        // No page of the package is reachable from a web page.
        assert.equal("web_accessible_resources" in json, false, where);
        assert.equal("externally_connectable" in json, false, where);
        // The CSP of every extension page forbids being framed.
        const csp = manifest === "mv3" ? json.content_security_policy.extension_pages : json.content_security_policy;
        assert.equal(csp, EXTENSION_CSP, where);
        assert.match(csp, /(?:^|;)\s*frame-ancestors 'none'(?:;|$)/, where);
        assert.match(csp, /(?:^|;)\s*script-src 'self' 'wasm-unsafe-eval'(?:;|$)/, where);
        // The toolbar button opens the popup; both pages are in the package.
        const action = manifest === "mv3" ? json.action : json.browser_action;
        assert.equal(action.default_popup, "pages/popup.html", where);
        assert.equal(manifest === "mv3" ? json.browser_action : json.action, undefined, where);
        for (const page of ["signin", "popup"]) {
          const html = result.files.get(`pages/${page}.html`)?.toString("utf8") ?? "";
          assert.ok(html.length > 0, `${where}: pages/${page}.html`);
          // One script, the page's own module, and nothing inline.
          assert.deepEqual([...html.matchAll(/<script\b([^>]*)>/g)].map((m) => m[1].trim()), [`type="module" src="${page}.mjs"`], `${where}: ${page}`);
          assert.doesNotMatch(html, /\son[a-z]+\s*=|\sstyle\s*=|<style|javascript:/i, `${where}: ${page}`);
          // The page and what it imports reach nothing of the background.
          const module = result.files.get(`pages/${page}.mjs`)?.toString("utf8") ?? "";
          for (const specifier of importsOf(module).specifiers) assert.doesNotMatch(specifier, /background\//, `${where}: ${page} imports ${specifier}`);
        }
      } finally {
        env.cleanup();
      }
    }
  }
});

test("signin_needs_the_host_permission_and_a_refusal_stops_with_a_message", async () => {
  const { request, sent } = recorder({ server_check: checkedServer, sign_in: () => ({ ok: true, account_email: "a@b.c", server: SERVER }) });
  /** @type {Array<{ origins: string[] }>} */
  const asked = [];
  let give = false;
  const flow = createSignInFlow({
    request,
    requestPermission: async (wanted) => {
      asked.push(wanted);
      return give;
    },
  });
  const fields = { email: "a@b.c", password: "pw", skAnswer: /** @type {const} */ ("no") };
  // Before the server is checked, and before the permission is given, nothing is sent.
  assert.deepEqual(await flow.signIn(fields), { ok: false, reason: "server_invalid" });
  assert.deepEqual(await flow.grant(), { ok: false, reason: "server_invalid" });
  assert.equal((await flow.check(" vault.example.com ")).ok, true);
  assert.deepEqual(sent, [["server_check", { server: "vault.example.com" }]]);
  assert.deepEqual(await flow.signIn(fields), { ok: false, reason: "permission_needed" });

  // A refusal stops the flow with its own text.
  assert.deepEqual(await flow.grant(), { ok: false, reason: "permission_refused" });
  assert.deepEqual(asked, [{ origins: [`${SERVER}/*`] }], "only the origin of the checked server");
  assert.equal(flow.granted(), false);
  assert.deepEqual(await flow.signIn(fields), { ok: false, reason: "permission_needed" });
  assert.deepEqual(sent.map(([type]) => type), ["server_check"], "no sign-in went out");
  for (const lang of ["en", "nb"]) {
    const texts = JSON.parse(readFileSync(join(extensionRoot, "src", "locales", lang, "session.json"), "utf8"));
    assert.ok(texts[reasonKey("permission_refused")]?.length > 20, lang);
    assert.ok(texts[reasonKey("permission_needed")]?.length > 20, lang);
  }

  // A browser that throws is a refusal too.
  const throwing = createSignInFlow({ request, requestPermission: async () => Promise.reject(new Error("no user input")) });
  await throwing.check(SERVER);
  assert.deepEqual(await throwing.grant(), { ok: false, reason: "permission_refused" });

  // Given: the sign-in goes out, for the checked server.
  give = true;
  assert.deepEqual(await flow.grant(), { ok: true });
  assert.equal(flow.granted(), true);
  assert.equal((await flow.signIn(fields)).ok, true);
  assert.deepEqual(sent.at(-1), ["sign_in", { server: SERVER, email: "a@b.c", mp: "pw", remember_sk: true, sk_bit: false }]);
  // Checking another address takes the permission back from the flow.
  await flow.check("https://other.example.com");
  assert.equal(flow.granted(), false);
});

test("the_permission_is_asked_in_the_turn_of_the_click", async () => {
  const { request } = recorder({ server_check: checkedServer });
  let calledSync = false;
  const flow = createSignInFlow({
    request,
    requestPermission: (wanted) => {
      calledSync = true;
      return Promise.resolve(wanted.origins.length === 1);
    },
  });
  await flow.check(SERVER);
  const pending = flow.grant();
  // No await before the browser's request: the click's user input is still there.
  assert.equal(calledSync, true);
  assert.deepEqual(await pending, { ok: true });
});

test("the_sign_in_fields_are_checked_and_sent_as_the_protocol_has_them", async () => {
  const { request, sent } = recorder({ server_check: checkedServer, sign_in: () => ({ ok: false, reason: "wrong_credentials" }) });
  const flow = createSignInFlow({ request, requestPermission: async () => true });
  await flow.check(SERVER);
  await flow.grant();
  sent.length = 0;
  assert.deepEqual(await flow.signIn({ email: "  ", password: "pw" }), { ok: false, reason: "email_required" });
  assert.deepEqual(await flow.signIn({ email: "a@b.c", password: "" }), { ok: false, reason: "password_required" });
  assert.deepEqual(await flow.signIn({ email: "a@b.c", password: "pw", skAnswer: "yes", secretKey: " " }), { ok: false, reason: "sk_required" });
  assert.deepEqual(sent, [], "nothing goes out for a form that is not filled in");
  // A password is sent as it was typed (spaces are part of it); the rest is trimmed.
  await flow.signIn({ email: " a@b.c ", password: " p w ", skAnswer: "yes", secretKey: " FFS1-X ", remember: false, qrText: " ferret-setup:v1?x " });
  await flow.signIn({ email: "a@b.c", password: "pw", skAnswer: null });
  assert.deepEqual(sent, [
    ["sign_in", { server: SERVER, email: "a@b.c", mp: " p w ", remember_sk: false, sk: "FFS1-X", qr_text: "ferret-setup:v1?x" }],
    ["sign_in", { server: SERVER, email: "a@b.c", mp: "pw", remember_sk: true }],
  ]);
  // The unlock: the password, and the secret key only when it was asked for.
  const unlocked = recorder({ unlock: () => ({ ok: true }) });
  assert.deepEqual(await unlockWith(unlocked.request, { password: "" }), { ok: false, reason: "password_required" });
  await unlockWith(unlocked.request, { password: "pw" });
  await unlockWith(unlocked.request, { password: "pw", secretKey: " FFS1-X " });
  assert.deepEqual(unlocked.sent, [["unlock", { mp: "pw" }], ["unlock", { mp: "pw", sk: "FFS1-X" }]]);
});

test("a_check_that_the_background_refuses_shows_its_reason", async () => {
  const { request } = recorder({ server_check: () => ({ ok: false, reason: "server_not_https" }) });
  const flow = createSignInFlow({ request, requestPermission: async () => true });
  assert.deepEqual(await flow.check("http://vault.example.com"), { ok: false, reason: "server_not_https" });
  assert.equal(flow.server(), null);
  assert.deepEqual(await flow.check(""), { ok: false, reason: "server_invalid" });
});

/** A fake runtime whose ports answer like the router; `drop()` ends the newest port, as an unloaded background does. */
function fakeRuntime(/** @type {(message: { id: string, type: string, body: any }) => string | null} */ reply) {
  /** @type {Array<{ listeners: Array<(raw: unknown) => void>, gone: Array<() => void> }>} */
  const ports = [];
  const runtime = {
    connect: () => {
      /** @type {{ listeners: Array<(raw: unknown) => void>, gone: Array<() => void> }} */
      const ends = { listeners: [], gone: [] };
      ports.push(ends);
      return {
        postMessage(/** @type {string} */ raw) {
          const message = decode(raw, UI_TYPES);
          const answer = reply(message);
          if (answer !== null) setTimeout(() => ends.listeners.forEach((fn) => fn(answer)), 0);
        },
        disconnect() {},
        onMessage: { addListener: (/** @type {any} */ fn) => ends.listeners.push(fn) },
        onDisconnect: { addListener: (/** @type {any} */ fn) => ends.gone.push(fn) },
      };
    },
  };
  return {
    runtime,
    ports,
    drop: () => ports.at(-1)?.gone.forEach((fn) => fn()),
    send: (/** @type {unknown} */ raw) => ports.at(-1)?.listeners.forEach((fn) => fn(raw)),
  };
}

test("the_ui_port_takes_only_the_answer_of_its_request", async () => {
  const { runtime, ports, drop, send } = fakeRuntime(({ id, type }) => {
    if (type === "state") return encode("state", { state: "locked" }, { id, reply: true });
    if (type === "lock") return encodeRefusal(id, "internal_error");
    if (type === "unlock") return encode("lock", { ok: true }, { id, reply: true });
    return null;
  });
  const ui = connectUi(runtime);
  assert.equal(ports.length, 0, "the port opens with the first request");
  assert.deepEqual(await ui.request("state", {}), { state: "locked" });
  await assert.rejects(ui.request("lock", {}), (error) => error instanceof UiError && error.code === "internal_error");
  // An answer of another type for the same id is no answer.
  await assert.rejects(ui.request("unlock", { mp: "pw" }), (error) => error instanceof UiError && error.code === "internal_error");
  // A message that is not a reply, or names no waiting request, is dropped.
  send("junk");
  send(encode("state", { state: "unlocked" }, { id: "nobody", reply: true }));
  // A body that does not fit the protocol is never sent.
  assert.throws(() => ui.request("unlock", { mp: "" }));
  assert.equal(ports.length, 1, "one port for all of that");
  // The background going away (an unloaded page) fails what waits; the next request opens a new port.
  const waiting = ui.request("server_check", { server: SERVER });
  drop();
  await assert.rejects(waiting, (error) => error instanceof UiError && error.code === "disconnected");
  assert.deepEqual(await ui.request("state", {}), { state: "locked" });
  assert.equal(ports.length, 2);
  // A port the page closed stays closed.
  ui.close();
  await assert.rejects(ui.request("state", {}), (error) => error instanceof UiError && error.code === "disconnected");
});

test("the_popup_views_follow_the_state_of_the_background", async () => {
  assert.deepEqual(viewOf({ state: "signed_out" }), { view: "signed_out", host: "", account: "" });
  assert.deepEqual(viewOf({ state: "locked", server: SERVER, host: "vault.example.com", host_a_label: "vault.example.com", account: "ola@example.com" }), {
    view: "locked",
    host: "vault.example.com",
    account: "ola@example.com",
  });
  assert.deepEqual(viewOf({ state: "unlocked", server: SERVER }), { view: "unlocked", host: SERVER, account: "" });
  assert.equal(viewOf(/** @type {any} */ ({ state: "weird" })).view, "signed_out");

  let state = "unlocked";
  const { request, sent } = recorder({
    state: () => ({ state, server: SERVER, host: "vault.example.com", host_a_label: "vault.example.com", account: "ola@example.com" }),
    lock: () => {
      state = "locked";
      return { ok: true };
    },
    unlock: () => ({ ok: false, reason: "wrong_credentials" }),
  });
  const popup = createPopupFlow(request);
  assert.equal((await popup.load()).view, "unlocked");
  assert.equal((await popup.lock()).view, "locked");
  const { result, view } = await popup.unlock({ password: "pw" });
  assert.deepEqual(result, { ok: false, reason: "wrong_credentials" });
  assert.equal(view.view, "locked");
  assert.deepEqual(sent.map(([type]) => type), ["state", "lock", "state", "unlock", "state"]);
});

test("the_pages_show_the_host_and_the_account_initials", () => {
  assert.equal(shownHost({ host: "bücher.example", host_a_label: "xn--bcher-kva.example" }), "bücher.example (xn--bcher-kva.example)");
  assert.equal(shownHost({ host: "vault.example.com", host_a_label: "vault.example.com" }), "vault.example.com");
  assert.equal(shownHost({ server: SERVER }), SERVER);
  assert.equal(initialsOf("ola.nordmann@example.com"), "ON");
  assert.equal(initialsOf("ola@example.com"), "O");
  assert.equal(initialsOf("åse_berg@example.com"), "ÅB");
  assert.equal(initialsOf(""), "");
  assert.equal(initialsOf(undefined), "");
  assert.equal(reasonKey("wrong_credentials"), "session.error.wrong_credentials");
  assert.equal(reasonKey("<script>"), "session.error.unknown");
  assert.equal(reasonKey(undefined), "session.error.unknown");
});
