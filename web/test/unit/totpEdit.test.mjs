// The one-time password field of the edit form: an address or a bare secret is read by the core and previewed, a refusal is one
// plain error and nothing is saved, an empty field keeps the stored secret, the stored secret is on the page only while it is
// shown, removing needs a confirmation, and Ferret's own host gets a warning. The codes are checked against the reference in
// totpHelpers.mjs (backed by the RFC 6238 vectors in totpModel.test.mjs).
import assert from "node:assert/strict";
import { test } from "node:test";
import { createWipeScope } from "../../src/views/common.mjs";
import { editView } from "../../src/views/edit.mjs";
import { RFC_SECRET, RFC_URI, everything, fakeTotpClient, reference } from "./totpHelpers.mjs";
import { all, click, fakeClock, fakeEngine, find, fire, settle, submit, t, textOf, withDom } from "./vaultHelpers.mjs";

const ID = "11".repeat(16);
const NEW_ID = "ab".repeat(16);
const OTHER_SECRET = "JBSWY3DPEHPK3PXP";

const VIEW = Object.freeze({
  item_type: "login", name: "Bank",
  fields: [{ id: "username", label: "User name", kind: "text", value: "ada" }, { id: "password", label: "Password", kind: "password", value: null }],
  urls: [{ url: "https://bank.example", matching: "host" }],
  has_totp: true, has_notes: false, favorite: false, read_only: false,
});
const ENTRY = Object.freeze({
  id: ID, name: "Bank", type: "login", favorite: false, urls: [], username: "ada", rev: 1,
  pending: false, damaged: false, quarantined: false, missingOnServer: false, blocked: false, blockedReason: null, readOnly: false,
});

/** An edit form over fakes; `id: null` is a new item. The clock stands at 59 s (Unix time). */
async function edit({ id = ID, view = {}, hosts = ["vault.example.test"], scope, withTotp = true, client: given } = {}) {
  const engine = fakeEngine({ items: [ENTRY], views: { [ID]: { ...VIEW, has_totp: withTotp, ...view } }, secrets: { [ID]: ["ada", "pw-SECRET-1"] } });
  const client = given?.(engine) ?? fakeTotpClient(engine, { uris: withTotp ? { [ID]: RFC_URI } : {} });
  const clock = fakeClock(59_000);
  const moves = [];
  const root = await editView({ engine, client, id, t, go: (path) => moves.push(path), scope, clock, hosts });
  return { engine, client, clock, root, moves };
}

/** Types into a field and lets the form read it. */
async function type(root, role, value) {
  find(root, role).value = value;
  await fire(find(root, role), "input");
  await settle();
}

/** The writes an edit made (opening the item is a call of the engine too). */
const updates = (engine) => engine.calls.filter((c) => c[0] === "update");

const facts = (root) => Object.fromEntries(all(root, "totp-fact").map((f) => [f.getAttribute("data-key"), textOf(f).trim()]));
const previewCode = (root) => textOf(find(root, "totp-preview-code")).trim();
const grouped = (code) => (code.length === 8 ? `${code.slice(0, 4)} ${code.slice(4)}` : `${code.slice(0, 3)} ${code.slice(3)}`);

test("a_uri_or_a_bare_secret_is_accepted_and_previewed", async () => {
  await withDom(async () => {
    const { root, engine, client, moves } = await edit({ id: null, withTotp: false });
    await type(root, "name", "Bank");
    // A bare secret, in lower case and with spaces: the core's reading is shown before anything is saved.
    await type(root, "totp", "gezd gnbv gy3t qojq gezd gnbv gy3t qojq");
    assert.deepEqual(facts(root), {
      account: 'vault.edit.totp_account {"value":"Bank"}',
      digits: 'vault.edit.totp_digits {"count":6}',
      period: 'vault.edit.totp_period {"count":30}',
    });
    assert.equal(previewCode(root), "287 082", "the live code at the page's clock");
    assert.equal(find(root, "totp").getAttribute("aria-invalid"), "false");
    assert.equal(find(root, "totp-error"), null);
    await submit(find(root, "edit-form"));
    assert.deepEqual(engine.calls, [["create", {
      item_type: "login", name: "Bank", favorite: false,
      totp: { uri: `otpauth://totp/Bank?secret=${RFC_SECRET}&algorithm=SHA1&digits=6&period=30` },
    }]], "a bare secret is saved as an address with the defaults and the name as its label");
    assert.deepEqual(moves, [`/items/${NEW_ID}`]);
    // The preview item was never saved: it is the worker's alone, and every one of them was closed again.
    assert.equal(client.previews.size, 0);
  });
});

test("an_address_shows_its_issuer_digits_period_and_algorithm", async () => {
  await withDom(async () => {
    const { root, engine, clock } = await edit({ id: null, withTotp: false });
    await type(root, "name", "Mail");
    const uri = `  otpauth://totp/Acme:ada?secret=${RFC_SECRET}&issuer=Acme&digits=8&algorithm=SHA256&period=60  `;
    await type(root, "totp", uri);
    assert.deepEqual(facts(root), {
      issuer: 'vault.edit.totp_issuer {"value":"Acme"}',
      account: 'vault.edit.totp_account {"value":"ada"}',
      digits: 'vault.edit.totp_digits {"count":8}',
      period: 'vault.edit.totp_period {"count":60}',
      algorithm: 'vault.edit.totp_algorithm {"value":"SHA256"}',
    });
    assert.equal(previewCode(root), grouped(reference({ secret: RFC_SECRET, digits: 8, period: 60, algorithm: "SHA256" }, 59)));
    // The preview follows the clock: a new code when the period is over.
    clock.advance(1_010);
    await settle();
    assert.equal(previewCode(root), grouped(reference({ secret: RFC_SECRET, digits: 8, period: 60, algorithm: "SHA256" }, 60)));
    await submit(find(root, "edit-form"));
    assert.equal(engine.calls[0][1].totp.uri, uri.trim());
  });
});

test("an_invalid_or_hotp_or_steam_secret_is_refused_with_one_error", async () => {
  const refused = [
    ["hotp", `otpauth://hotp/Acme:ada?secret=${RFC_SECRET}&counter=1`],
    ["steam", `steam://${RFC_SECRET}`],
    ["a digit that Base32 does not have", "JBSWY3DP1"],
    ["a counter on a totp address", `otpauth://totp/x?secret=${RFC_SECRET}&counter=1`],
    ["a web address", "https://example.test"],
    ["an unknown parameter", `otpauth://totp/x?secret=${RFC_SECRET}&image=x`],
  ];
  for (const [what, text] of refused) {
    await withDom(async () => {
      const { root, engine } = await edit({ id: null, withTotp: false });
      await type(root, "name", "Bank");
      await type(root, "totp", text);
      assert.equal(textOf(find(root, "totp-error")).trim(), "vault.error.malformed_otpauth", `${what}: the field says so`);
      assert.equal(find(root, "totp").getAttribute("aria-invalid"), "true", what);
      assert.equal(all(root, "totp-fact").length, 0, `${what}: nothing is shown as read`);
      assert.equal(find(root, "totp-preview"), null, `${what}: no preview`);
      await submit(find(root, "edit-form"));
      assert.deepEqual(engine.calls, [], `${what}: nothing is saved`);
      const box = find(root, "error");
      assert.equal(box.hidden, false);
      assert.equal(textOf(box).trim(), "vault.error.malformed_otpauth", `${what}: one plain error`);
      // The same text for every kind of refusal, and the form still has what was typed so it can be fixed.
      assert.equal(find(root, "totp").value, text);
    });
  }
});

test("an_empty_field_keeps_the_stored_secret", async () => {
  await withDom(async () => {
    const { root, engine, client } = await edit();
    const input = find(root, "totp");
    assert.equal(input.value, "", "the field starts empty");
    assert.equal(input.getAttribute("type"), "password");
    assert.equal(client.calls.some((c) => c[0] === "reveal_totp_secret"), false, "the form did not ask for the secret to draw itself");
    assert.ok(textOf(root).includes("vault.edit.totp_help_keep"));
    assert.ok(!everything(root).includes(RFC_SECRET));
    await type(root, "username", "ada2");
    await submit(find(root, "edit-form"));
    assert.equal(updates(engine).length, 1);
    const draft = updates(engine)[0][2];
    assert.equal(draft.totp, undefined, "no address in the draft: the worker keeps the stored one");
    assert.equal(draft.remove_totp, undefined);
    assert.deepEqual(draft.fields, [{ id: "username", value: "ada2" }, { id: "password" }]);
  });
});

test("show_asks_for_the_stored_address_and_hide_takes_it_off_the_page", async () => {
  await withDom(async () => {
    const { root, engine, client } = await edit();
    const toggle = find(root, "totp-toggle");
    const input = find(root, "totp");
    await click(toggle);
    await settle();
    assert.equal(client.calls.filter((c) => c[0] === "reveal_totp_secret").length, 1);
    assert.equal(input.value, RFC_URI);
    assert.equal(input.getAttribute("type"), "text");
    assert.equal(toggle.getAttribute("aria-pressed"), "true");
    assert.equal(facts(root).issuer, 'vault.edit.totp_issuer {"value":"Example"}', "what the core reads from it is shown");
    assert.equal(previewCode(root), "287 082");
    assert.equal(engine.handles.size, 0, "the handle lived for the one call");
    await click(toggle);
    assert.equal(input.value, "", "hiding it takes it off the page");
    assert.equal(input.getAttribute("type"), "password");
    assert.equal(toggle.getAttribute("aria-pressed"), "false");
    assert.ok(!everything(root).includes(RFC_SECRET));
    assert.equal(all(root, "totp-fact").length, 0);
    // Shown and saved without a change: still nothing in the draft.
    await click(toggle);
    await settle();
    await type(root, "username", "ada3");
    await submit(find(root, "edit-form"));
    assert.equal(updates(engine)[0][2].totp, undefined);
  });
});

test("a_changed_address_replaces_the_stored_one_and_a_cancelled_form_takes_it_off_the_page", async () => {
  await withDom(async () => {
    const { root, engine } = await edit();
    await click(find(root, "totp-toggle"));
    await settle();
    await type(root, "totp", OTHER_SECRET);
    await submit(find(root, "edit-form"));
    assert.equal(updates(engine)[0][2].totp.uri, `otpauth://totp/Bank?secret=${OTHER_SECRET}&algorithm=SHA1&digits=6&period=30`);
    assert.equal(updates(engine)[0][2].remove_totp, undefined);
  });
  await withDom(async () => {
    const { root } = await edit();
    await click(find(root, "totp-toggle"));
    await settle();
    assert.equal(find(root, "totp").value, RFC_URI);
    await click(find(root, "cancel"));
    assert.equal(find(root, "totp").value, "");
    assert.ok(!everything(root).includes(RFC_SECRET));
  });
});

test("remove_needs_confirmation", async () => {
  await withDom(async () => {
    const { root, engine } = await edit();
    assert.notEqual(find(root, "totp-remove").hidden, true, "the control is there for an item that has a one-time password");
    // Asked first: nothing happens until the answer is yes, and No leaves everything as it was. (The click waits for the answer.)
    const asked = click(find(root, "totp-remove"));
    await settle();
    assert.ok(find(root, "dialog") !== null, "a confirmation is asked");
    assert.equal(find(root, "dialog").getAttribute("role"), "alertdialog");
    assert.equal(find(root, "totp-keep").hidden, true, "nothing has changed yet");
    await click(find(root, "dialog-cancel"));
    await asked;
    assert.equal(find(root, "dialog"), null);
    assert.equal(find(root, "totp-keep").hidden, true);
    await type(root, "username", "ada4");
    await submit(find(root, "edit-form"));
    assert.equal(updates(engine)[0][2].remove_totp, undefined, "a refused removal sends nothing");
  });
  await withDom(async () => {
    const { root, engine } = await edit();
    const first = click(find(root, "totp-remove"));
    await settle();
    await click(find(root, "dialog-confirm"));
    await first;
    assert.equal(find(root, "totp-removed").hidden, false, "the form says it will be removed");
    assert.equal(find(root, "totp").disabled, true);
    assert.equal(find(root, "totp-keep").hidden, false);
    // It can be taken back until the item is saved.
    await click(find(root, "totp-keep"));
    assert.equal(find(root, "totp").disabled, false);
    assert.equal(find(root, "totp-removed").hidden, true);
    const second = click(find(root, "totp-remove"));
    await settle();
    await click(find(root, "dialog-confirm"));
    await second;
    await submit(find(root, "edit-form"));
    const draft = updates(engine)[0][2];
    assert.equal(draft.remove_totp, true);
    assert.equal(draft.totp, undefined);
  });
});

test("a_new_item_has_no_remove_control_and_a_note_has_no_field", async () => {
  await withDom(async () => {
    const { root, engine } = await edit({ id: null, withTotp: false });
    assert.equal(find(root, "totp-remove-bar"), null);
    await type(root, "name", "Wifi");
    await type(root, "totp", RFC_SECRET);
    find(root, "type").value = "note";
    await fire(find(root, "type"), "change");
    assert.equal(find(root, "login-fields").hidden, true, "the field goes with the sign-in card");
    await submit(find(root, "edit-form"));
    assert.equal(engine.calls[0][1].totp, undefined, "a note never carries one");
    assert.equal(engine.calls[0][1].remove_totp, undefined);
  });
});

test("ferrets_own_host_gives_a_warning", async () => {
  await withDom(async () => {
    const { root, engine } = await edit({ id: null, withTotp: false, hosts: ["vault.example.test", "vault.example.test:8443"] });
    await type(root, "name", "Ferret");
    await type(root, "totp", `otpauth://totp/Vault.Example.Test:ada?secret=${RFC_SECRET}`);
    const warning = find(root, "totp-own-host");
    assert.ok(warning !== null);
    assert.equal(warning.getAttribute("role"), "note", "a note, not an alert");
    assert.equal(textOf(warning).trim(), "vault.edit.totp_own_host");
    // A warning, not a block: it still has its preview and can be saved.
    assert.equal(previewCode(root), "287 082");
    await submit(find(root, "edit-form"));
    assert.equal(engine.calls.length, 1);
    assert.ok(engine.calls[0][1].totp.uri.includes("Vault.Example.Test"));
  });
  await withDom(async () => {
    const { root } = await edit({ id: null, withTotp: false, hosts: ["vault.example.test"] });
    await type(root, "name", "GitHub");
    await type(root, "totp", `otpauth://totp/GitHub:ada?secret=${RFC_SECRET}&issuer=GitHub`);
    assert.equal(find(root, "totp-own-host"), null, "another service gets none");
    await type(root, "totp", `otpauth://totp/ada@vault.example.test?secret=${RFC_SECRET}`);
    assert.ok(find(root, "totp-own-host") !== null, "the label counts too");
  });
});

test("a_bare_secret_takes_the_name_the_item_has_when_it_is_saved", async () => {
  await withDom(async () => {
    const { root, engine } = await edit({ id: null, withTotp: false });
    await type(root, "totp", OTHER_SECRET);
    await type(root, "name", "Late name: a bank");
    await submit(find(root, "edit-form"));
    const uri = engine.calls[0][1].totp.uri;
    assert.equal(uri, `otpauth://totp/Late%20name%20a%20bank?secret=${OTHER_SECRET}&algorithm=SHA1&digits=6&period=30`, "the colon would have read as an issuer");
  });
});

test("the_secret_is_never_in_the_dom_storage_console_or_a_request_in_plain", async () => {
  const secrets = [RFC_SECRET, OTHER_SECRET, RFC_URI];
  const spy = { console: [], storage: [], fetch: 0 };
  const saved = {};
  for (const name of ["log", "info", "warn", "error", "debug"]) {
    saved[name] = console[name];
    console[name] = (...args) => void spy.console.push(args.map(String).join(" "));
  }
  const store = { setItem: (...args) => void spy.storage.push(args.join("=")), getItem: () => null, removeItem() {}, clear() {} };
  const had = Object.getOwnPropertyDescriptor(globalThis, "localStorage");
  const hadSession = Object.getOwnPropertyDescriptor(globalThis, "sessionStorage");
  Object.defineProperty(globalThis, "localStorage", { value: store, configurable: true });
  Object.defineProperty(globalThis, "sessionStorage", { value: store, configurable: true });
  const savedFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    spy.fetch += 1;
    throw new Error("no request");
  };
  try {
    await withDom(async () => {
      const scope = createWipeScope();
      const { root, engine } = await edit({ scope });
      await click(find(root, "totp-toggle"));
      await settle();
      assert.ok(everything(root).includes(RFC_SECRET), "while it is shown on request, it is on the page");
      await click(find(root, "totp-toggle"));
      await type(root, "totp", OTHER_SECRET);
      await click(find(root, "totp-toggle"));
      assert.ok(everything(root).includes(OTHER_SECRET), "what the user typed and shows is on the page");
      await submit(find(root, "edit-form"));
      await settle();
      // After the save the form is wiped, and so is the draft the screen built.
      assert.equal(find(root, "totp").value, "");
      for (const secret of secrets) assert.ok(!everything(root).includes(secret), `the page holds ${secret} after the save`);
      assert.equal(updates(engine).length, 1);
    });
    await withDom(async () => {
      const scope = createWipeScope();
      const { root } = await edit({ scope });
      await click(find(root, "totp-toggle"));
      await settle();
      scope.run();
      await settle();
      for (const secret of secrets) assert.ok(!everything(root).includes(secret), `the page holds ${secret} after a lock`);
    });
  } finally {
    for (const [name, fn] of Object.entries(saved)) console[name] = fn;
    for (const [name, d] of [["localStorage", had], ["sessionStorage", hadSession]]) {
      if (d) Object.defineProperty(globalThis, name, d);
      else delete globalThis[name];
    }
    globalThis.fetch = savedFetch;
  }
  assert.deepEqual(spy.console.filter((line) => secrets.some((s) => line.includes(s))), [], "nothing was logged");
  assert.deepEqual(spy.storage, [], "nothing was kept in a store");
  assert.equal(spy.fetch, 0, "the form makes no request of its own: what leaves is the draft, which the worker seals");
});

test("a_lock_stops_the_preview_and_takes_the_facts_off_the_form", async () => {
  await withDom(async () => {
    const scope = createWipeScope();
    const { root, clock, client } = await edit({ id: null, withTotp: false, scope });
    await type(root, "name", "Bank");
    await type(root, "totp", RFC_SECRET);
    assert.ok(find(root, "totp-preview") !== null);
    scope.run();
    await settle();
    assert.equal(clock.pending, 0, "no timer is left");
    const asked = client.calls.length;
    clock.advance(120_000);
    await settle();
    assert.equal(client.calls.length, asked, "nothing is made after the lock");
    assert.equal(textOf(root).trim(), "");
  });
});

test("without_the_throwaway_item_calls_the_form_still_reads_and_saves", async () => {
  // A worker stand-in that has `totp_parse` only: the facts show, no preview, and the save sends the address.
  await withDom(async () => {
    const { root, engine } = await edit({
      id: null, withTotp: false,
      client: (e) => {
        const full = fakeTotpClient(e);
        return { calls: full.calls, vault: { totp_parse: full.vault.totp_parse } };
      },
    });
    await type(root, "name", "Bank");
    await type(root, "totp", RFC_SECRET);
    assert.equal(all(root, "totp-fact").length, 3);
    assert.equal(find(root, "totp-preview"), null);
    await submit(find(root, "edit-form"));
    assert.equal(engine.calls.length, 1);
  });
});
