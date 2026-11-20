// The export page (spec Fase 1 § 6.4): the warning before an export, the encrypted form, the plain form with its two
// confirmations, the route, and the texts, against a small fake DOM and a fake session.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { autoLockFor } from "../../src/lock.mjs";
import { createI18n } from "../../src/i18n.mjs";
import { createWipeScope } from "../../src/views/common.mjs";
import { EXPORT_ERRORS, exportErrorText, exportView } from "../../src/views/export.mjs";
import { SECURITY_ERRORS } from "../../src/views/securityError.mjs";
import { accountDocument } from "./accountHelpers.mjs";
import { web } from "./helpers.mjs";
import { click, fakeClient, fakeEngine, fakeSession, find, fire, settle, t as keyT, textOf } from "./vaultHelpers.mjs";

const read = (lang) => ({
  ...JSON.parse(readFileSync(join(web, "src", "locales", lang, "export.json"), "utf8")),
  ...JSON.parse(readFileSync(join(web, "src", "locales", lang, "security.json"), "utf8")),
  ...JSON.parse(readFileSync(join(web, "src", "locales", lang, "account.json"), "utf8")),
});
const i18n = (lang) => createI18n({ en: read("en"), nb: read("nb") }, lang);

/** Runs an async body with a fake document whose inputs start empty, as real ones do. */
async function withDom(body) {
  const saved = globalThis.document;
  globalThis.document = accountDocument();
  try {
    return await body();
  } finally {
    if (saved === undefined) delete globalThis.document;
    else globalThis.document = saved;
  }
}

const coded = (code) => Object.assign(new Error(code), { code });
const READY = async () => ({ pendingWrites: 0, atTop: true });
const type = (root, values) => {
  for (const [role, value] of Object.entries(values)) find(root, role).value = value;
};
const submit = (root, form) => fire(find(root, form), "submit");
const MASTER = "master-pass-for-unit-tests";
const EXPORT_PW = "export-pass-for-unit-tests";

/** The page over fakes. `calls` records what the page asked of the session. */
function page(options = {}) {
  const calls = { encrypted: [], plain: [], readiness: 0 };
  const scope = createWipeScope();
  const root = exportView({
    t: i18n("en").t,
    exportEncrypted: async (args) => {
      calls.encrypted.push({ ...args, fieldAtCall: find(root, "master-password").value });
      args.onProgress({ phase: "checking" });
      args.onProgress({ phase: "stretching" });
      return { items: 7 };
    },
    exportPlain: async (args) => {
      calls.plain.push({ ...args, fieldAtCall: find(root, "plain-master-password").value });
    },
    readiness: async () => {
      calls.readiness += 1;
      return READY();
    },
    scope,
    ...options,
  });
  return { root, calls, scope };
}

// ------------------------------------------------------------------ the warning

test("an_export_with_unsent_writes_or_behind_the_top_warns_first_on_the_page", async () => {
  await withDom(async () => {
    let state = { pendingWrites: 2, atTop: false };
    const encrypted = [];
    const { root, calls } = page({ readiness: async () => state, exportEncrypted: async (args) => encrypted.push(args) });
    await settle();
    const warning = find(root, "readiness-warning");
    assert.equal(warning.hidden, false);
    assert.match(textOf(find(warning, "readiness-pending")), /2 item\(s\) have changes/);
    assert.ok(find(warning, "readiness-behind"));
    // Both buttons wait for the tick.
    assert.equal(find(root, "submit").disabled, true);
    assert.equal(find(root, "plain-submit").disabled, true);
    type(root, { "master-password": MASTER, "export-password": EXPORT_PW, "export-password-again": EXPORT_PW });
    await submit(root, "encrypted-form");
    assert.equal(encrypted.length, 0, "nothing starts behind the warning");
    const ack = find(root, "readiness-ack");
    ack.checked = true;
    await fire(ack, "change");
    assert.equal(find(root, "submit").disabled, false);
    assert.equal(find(root, "plain-submit").disabled, false);
    await submit(root, "encrypted-form");
    assert.equal(encrypted.length, 1, "after the tick it goes ahead");

    // Look again: the warning goes when the state is good, and a tick that was given does not carry over.
    state = { pendingWrites: 0, atTop: true };
    await click(find(root, "readiness-recheck"));
    await settle();
    assert.equal(find(root, "readiness-warning").hidden, true);
    assert.match(textOf(find(root, "readiness-status")), /up to date with the server and has no changes/);
    assert.equal(find(root, "submit").disabled, false);
  });
  await withDom(async () => {
    // A check that cannot be made is the same as being behind.
    const { root } = page({ readiness: async () => Promise.reject(new Error("offline")) });
    await settle();
    assert.equal(find(root, "readiness-warning").hidden, false);
    assert.equal(find(root, "readiness-pending"), null);
    assert.ok(find(root, "readiness-behind"));
    // A page that is ready has no warning and starts at once.
    const ready = page();
    await settle();
    assert.equal(find(ready.root, "readiness-warning").hidden, true);
    assert.equal(find(ready.root, "submit").disabled, false);
  });
});

// ---------------------------------------------------------------- encrypted form

test("the_encrypted_form_checks_what_it_can_and_clears_the_fields_before_the_slow_call", async () => {
  await withDom(async () => {
    const { root, calls } = page();
    await settle();
    // Nothing is sent for what the page can see is wrong, and what was typed stays for another look.
    type(root, { "master-password": MASTER, "export-password": EXPORT_PW, "export-password-again": `${EXPORT_PW}!` });
    await submit(root, "encrypted-form");
    assert.deepEqual(calls.encrypted, []);
    assert.match(textOf(find(root, "error")), /not the same/);
    assert.equal(find(root, "export-password").value, EXPORT_PW);
    type(root, { "master-password": "", "export-password-again": EXPORT_PW });
    await submit(root, "encrypted-form");
    assert.deepEqual(calls.encrypted, []);

    type(root, { "master-password": MASTER });
    await submit(root, "encrypted-form");
    assert.equal(calls.encrypted.length, 1);
    const [call] = calls.encrypted;
    assert.equal(call.masterPassword, MASTER);
    assert.equal(call.exportPassword, EXPORT_PW);
    assert.equal(call.exportPasswordAgain, EXPORT_PW);
    assert.equal(call.fieldAtCall, "", "the field was empty when the slow call started");
    for (const role of ["master-password", "export-password", "export-password-again"]) assert.equal(find(root, role).value, "", role);
    assert.ok(!("skCode" in call), "this device holds the secret key");
    // The progress is on the page while it runs; at the end the page says what was made.
    assert.equal(find(root, "encrypted-form").hidden, true);
    assert.match(textOf(find(root, "done-items")), /Items in the file: 7/);
    assert.match(textOf(find(root, "done-password")), /only with the export password/);
    assert.equal(find(root, "encrypted-done").hidden, false);
    // Another export can be made from the same page.
    await click(find(root, "export-again"));
    await settle();
    assert.equal(find(root, "encrypted-form").hidden, false);
    assert.equal(find(root, "encrypted-done").hidden, true);
  });
});

test("an_acknowledged_incomplete_export_says_so_and_asks_for_no_reset", async () => {
  await withDom(async () => {
    const seen = [];
    const { root } = page({
      readiness: async () => ({ pendingWrites: 1, atTop: true, damaged: 2 }),
      exportEncrypted: async (args) => {
        seen.push(args);
        return { items: 4 };
      },
    });
    await settle();
    assert.match(textOf(find(root, "readiness-damaged")), /2 item\(s\) could not be read/);
    find(root, "readiness-ack").checked = true;
    await fire(find(root, "readiness-ack"), "change");
    type(root, { "master-password": MASTER, "export-password": EXPORT_PW, "export-password-again": EXPORT_PW });
    const before = textOf(find(root, "export-last"));
    await submit(root, "encrypted-form");
    assert.equal(seen[0].incomplete, true);
    assert.match(textOf(find(root, "done-incomplete")), /file is incomplete/);
    assert.match(textOf(find(root, "done-incomplete")), /not reset/);
    assert.equal(textOf(find(root, "export-last")), before, "the page does not claim a new export date");
  });
  await withDom(async () => {
    // A clean export has no such line and does not ask for it.
    const seen = [];
    const { root } = page({ exportEncrypted: async (args) => (seen.push(args), { items: 4 }) });
    await settle();
    type(root, { "master-password": MASTER, "export-password": EXPORT_PW, "export-password-again": EXPORT_PW });
    await submit(root, "encrypted-form");
    assert.ok(!("incomplete" in seen[0]));
    assert.equal(find(root, "done-incomplete"), null);
  });
});

test("the_export_password_fields_do_not_let_the_browser_overwrite_the_saved_master_password", async () => {
  await withDom(async () => {
    const { root } = page({ skRequired: true });
    await settle();
    await click(find(root, "plain-open"));
    assert.equal(find(root, "master-password").getAttribute("autocomplete"), "current-password");
    assert.equal(find(root, "plain-master-password").getAttribute("autocomplete"), "current-password");
    assert.equal(find(root, "export-password").getAttribute("autocomplete"), "off");
    assert.equal(find(root, "export-password-again").getAttribute("autocomplete"), "off");
    for (const node of [...(function* walk(n) { yield n; for (const c of n.childNodes ?? []) yield* walk(c); })(root)]) {
      assert.notEqual(node.getAttribute?.("autocomplete"), "new-password");
    }
  });
});

test("an_unreadable_item_is_named_as_the_list_shows_it", async () => {
  await withDom(async () => {
    const t = i18n("en").t;
    const error = Object.assign(new Error("x"), { code: "export_item_unreadable", details: { ids: ["aa".repeat(16), "bb".repeat(16)] } });
    const names = { [`${"aa".repeat(16)}`]: "Mail" };
    const text = exportErrorText(t, error, (id) => names[id] ?? null);
    assert.match(text, /Mail, bbbbbbbb/);
    assert.match(text, /Reload the page/);
    // No ids at all: an honest fallback, never an empty list.
    assert.match(exportErrorText(t, Object.assign(new Error("x"), { code: "export_item_unreadable" })), /whose name is not known/);
  });
});

test("progress_is_shown_on_the_page_while_the_key_is_stretched", async () => {
  await withDom(async () => {
    let release;
    const gate = new Promise((resolve) => (release = resolve));
    const { root } = page({
      exportEncrypted: async ({ onProgress }) => {
        onProgress({ phase: "reading", items: 12 });
        onProgress({ phase: "stretching" });
        await gate;
        return { items: 12 };
      },
    });
    await settle();
    type(root, { "master-password": MASTER, "export-password": EXPORT_PW, "export-password-again": EXPORT_PW });
    const pending = submit(root, "encrypted-form");
    await settle();
    assert.match(textOf(find(root, "status")), /Making the key from the export password/);
    assert.equal(find(root, "submit").disabled, true, "no second click while it runs");
    assert.equal(find(root, "export-password").disabled, true);
    // A phase the page has no text for is ignored.
    release();
    await pending;
    assert.equal(find(root, "status").childNodes.length, 0, "the status line is empty again");
  });
});

test("an_error_is_shown_by_its_code_and_the_form_stays_usable", async () => {
  await withDom(async () => {
    const t = i18n("en").t;
    const failing = (code) => page({
      t,
      exportEncrypted: async () => {
        throw Object.assign(new Error(`typed ${EXPORT_PW}`), { code });
      },
    });
    for (const code of ["input_same_as_master_password", "kdf_out_of_memory", "decrypt", "export_item_unreadable", "nothing_to_export", "unsupported"]) {
      const { root } = failing(code);
      await settle();
      type(root, { "master-password": MASTER, "export-password": EXPORT_PW, "export-password-again": EXPORT_PW });
      await submit(root, "encrypted-form");
      const text = textOf(find(root, "error"));
      assert.ok(text.trim().length > 0 && !text.includes(EXPORT_PW), code);
      assert.equal(find(root, "error").hidden, false);
      assert.equal(find(root, "submit").disabled, false, "another try is possible");
      assert.equal(find(root, "encrypted-form").hidden, false);
    }
    // An unknown code gets the general text, with the code and never the message.
    assert.match(exportErrorText(t, coded("something_new")), /something_new/);
    assert.ok(!exportErrorText(t, new Error(`typed ${EXPORT_PW}`)).includes(EXPORT_PW));
    for (const code of EXPORT_ERRORS.filter((c) => c !== "export_item_unreadable")) assert.equal(exportErrorText(t, coded(code)), t(`export.error.${code}`));
    // The sign-in's codes keep their texts.
    assert.equal(exportErrorText(t, coded("reauth_required")), t("security.error.reauth_required"));
  });
});

test("a_lock_of_the_vault_empties_the_fields", async () => {
  await withDom(async () => {
    const { root, scope } = page();
    await settle();
    type(root, { "master-password": MASTER, "export-password": EXPORT_PW, "export-password-again": EXPORT_PW });
    await click(find(root, "plain-open"));
    type(root, { "plain-master-password": MASTER });
    find(root, "plain-confirm").checked = true;
    scope.run();
    for (const role of ["master-password", "export-password", "export-password-again", "plain-master-password"]) assert.equal(find(root, role).value, "", role);
    assert.equal(find(root, "plain-confirm").checked, false);
  });
});

test("the_secret_key_is_asked_for_only_when_the_device_does_not_hold_it_in_the_export", async () => {
  await withDom(async () => {
    const without = page();
    await settle();
    assert.equal(find(without.root, "secret-key"), null);
    assert.equal(find(without.root, "plain-secret-key"), null);
    const asked = page({ skRequired: true });
    await settle();
    type(asked.root, { "master-password": MASTER, "export-password": EXPORT_PW, "export-password-again": EXPORT_PW });
    await submit(asked.root, "encrypted-form");
    assert.deepEqual(asked.calls.encrypted, [], "nothing is sent without the code");
    find(asked.root, "secret-key").value = " FFS1-TEST ";
    await submit(asked.root, "encrypted-form");
    assert.equal(asked.calls.encrypted[0].skCode, "FFS1-TEST");
    // A flow that finds out late shows the field.
    const late = page({ exportEncrypted: async () => Promise.reject(coded("sk_required")) });
    await settle();
    type(late.root, { "master-password": MASTER, "export-password": EXPORT_PW, "export-password-again": EXPORT_PW });
    await submit(late.root, "encrypted-form");
    assert.ok(find(late.root, "secret-key"));
  });
});

// ------------------------------------------------------------------- plain form

test("plain_export_needs_two_confirmations_on_the_page", async () => {
  await withDom(async () => {
    const { root, calls } = page();
    await settle();
    // The warning about indexing, previews, synced folders and backups is on the page before the form is.
    assert.match(textOf(find(root, "plain-warning")), /index it for search/);
    assert.equal(find(root, "plain-form").hidden, true, "the plain form is behind a button");
    await click(find(root, "plain-open"));
    assert.equal(find(root, "plain-form").hidden, false);
    type(root, { "plain-master-password": MASTER });

    // The first confirmation is the box. Without it: an error, no question, no call.
    await submit(root, "plain-form");
    assert.deepEqual(calls.plain, []);
    assert.equal(find(root, "dialog"), null);
    assert.equal(find(root, "plain-error").hidden, false);
    find(root, "plain-confirm").checked = true;

    // The second is the question after the button. Cancelling it ends there.
    const first = submit(root, "plain-form");
    await settle();
    assert.ok(find(root, "dialog"), "a question comes first");
    await click(find(root, "dialog-cancel"));
    await first;
    assert.deepEqual(calls.plain, []);
    assert.equal(find(root, "plain-master-password").value, MASTER, "nothing was wiped: nothing was started");

    // Answering yes starts it, with the explicit confirmation, and the fields are empty by then.
    const second = submit(root, "plain-form");
    await settle();
    await click(find(root, "dialog-confirm"));
    await second;
    assert.equal(calls.plain.length, 1);
    const [call] = calls.plain;
    assert.deepEqual({ masterPassword: call.masterPassword, format: call.format, includePasskeys: call.includePasskeys, confirmed: call.confirmed },
      { masterPassword: MASTER, format: "json", includePasskeys: false, confirmed: true });
    assert.equal(call.fieldAtCall, "");
    assert.equal(find(root, "plain-confirm").checked, false);
    assert.equal(find(root, "plain-form").hidden, true);
    assert.ok(find(root, "plain-done"));
    assert.equal(find(root, "plain-done").hidden, false);
    assert.equal(find(root, "done-csv"), null);
  });
});

test("the_plain_form_leaves_passkeys_out_unless_asked_for_and_never_in_csv", async () => {
  await withDom(async () => {
    const run = async (setup) => {
      const { root, calls } = page();
      await settle();
      await click(find(root, "plain-open"));
      type(root, { "plain-master-password": MASTER });
      find(root, "plain-confirm").checked = true;
      await setup(root);
      const pending = submit(root, "plain-form");
      await settle();
      await click(find(root, "dialog-confirm"));
      await pending;
      return { call: calls.plain[0], root };
    };
    assert.equal((await run(() => {})).call.includePasskeys, false, "left out by default");
    assert.equal((await run((root) => (find(root, "include-passkeys").checked = true))).call.includePasskeys, true);
    // Choosing CSV turns the box off and keeps it off.
    const csv = await run((root) => {
      find(root, "include-passkeys").checked = true;
      find(root, "format-json").checked = false;
      find(root, "format-csv").checked = true;
      return fire(find(root, "format-csv"), "change");
    });
    assert.equal(csv.call.format, "csv");
    assert.equal(csv.call.includePasskeys, false);
    assert.ok(find(csv.root, "done-csv"), "the page says what the CSV rule did");
    const live = page();
    await settle();
    find(live.root, "format-json").checked = false;
    find(live.root, "format-csv").checked = true;
    await fire(find(live.root, "format-csv"), "change");
    assert.equal(find(live.root, "include-passkeys").disabled, true);
    assert.equal(find(live.root, "include-passkeys").checked, false);
  });
});

test("a_plain_export_that_fails_says_why_and_can_be_tried_again", async () => {
  await withDom(async () => {
    const { root } = page({ exportPlain: async () => Promise.reject(coded("reauth_required")) });
    await settle();
    await click(find(root, "plain-open"));
    type(root, { "plain-master-password": MASTER });
    find(root, "plain-confirm").checked = true;
    const pending = submit(root, "plain-form");
    await settle();
    await click(find(root, "dialog-confirm"));
    await pending;
    assert.match(textOf(find(root, "plain-error")), /password check has run out of time/);
    assert.equal(find(root, "plain-submit").disabled, false);
    assert.equal(find(root, "plain-form").hidden, false);
    assert.equal(find(root, "plain-confirm").checked, false, "the confirmations are asked again");
  });
});

// -------------------------------------------------------------------- the route

function rig({ open = true, status = { pinned: true, skBit: true, skStored: true }, lastExportAt = null } = {}) {
  const engine = fakeEngine();
  engine.health = () => ({ halted: null, warnings: [] });
  engine.syncNow = async () => engine.emit("state", { kind: "idle" });
  const client = fakeClient(engine);
  const session = fakeSession({ client, open, status });
  session.serverUrl = "https://vault.example";
  const encrypted = [];
  const plain = [];
  session.exportEncrypted = async (args) => {
    encrypted.push(args);
    return { items: 1 };
  };
  session.exportPlain = async (args) => {
    plain.push(args);
  };
  const store = { open: async () => ({}), exportReminder: { status: async () => ({ due: false, lastExportAt }), snooze: async () => {} } };
  const sync = { current: () => engine, start: async () => engine, stop: () => engine.stop(), discard: engine.discard };
  const ctx = () => ({
    params: {}, path: "/export", i18n: { t: keyT, lang: "en", missing: [] }, client, services: { crypto: session, sync, store }, go: () => {}, routes: [],
  });
  return { engine, session, encrypted, plain, ctx, done: () => autoLockFor(session, sync).stop() };
}

test("the_export_route_is_an_account_page_in_the_vault_frame", async () => {
  await withDom(async () => {
    const route = (await import("../../src/routes/export.route.mjs")).default;
    assert.equal(route.path, "/export");
    assert.equal(route.menu, "account");
    assert.equal(route.title, "export.title");

    const closed = rig({ open: false });
    try {
      const node = await route.load(closed.ctx());
      await settle();
      assert.ok(find(node, "unlock"));
      assert.equal(find(node, "export-page"), null);
    } finally {
      closed.done();
    }

    const r = rig({ lastExportAt: 1_800_000_000_000 });
    try {
      const node = await route.load(r.ctx());
      await settle();
      assert.ok(find(node, "shell"), "inside the vault frame");
      assert.ok(find(node, "export-page"));
      assert.match(textOf(find(node, "export-last")), /export\.last\.date/);
      assert.equal(find(node, "secret-key"), null, "this device holds the secret key");
      assert.equal(find(node, "readiness-warning").hidden, true, "a pass that ended well: nothing to warn about");
      type(node, { "master-password": MASTER, "export-password": EXPORT_PW, "export-password-again": EXPORT_PW });
      await fire(find(node, "encrypted-form"), "submit");
      await settle();
      assert.equal(r.encrypted.length, 1);
      assert.equal(r.encrypted[0].masterPassword, MASTER);
      assert.equal(typeof r.encrypted[0].onProgress, "function");
    } finally {
      r.done();
    }

    // Never exported: the page says so. A device without the secret key asks for it.
    const asking = rig({ status: { pinned: true, skBit: true, skStored: false } });
    try {
      const node = await route.load(asking.ctx());
      await settle();
      assert.ok(find(node, "secret-key"));
      assert.match(textOf(find(node, "export-last")), /export\.last\.never/);
    } finally {
      asking.done();
    }
  });
});

// ---------------------------------------------------------------------- the texts

test("export_texts_exist_in_both_languages", () => {
  const en = JSON.parse(readFileSync(join(web, "src", "locales", "en", "export.json"), "utf8"));
  const nb = JSON.parse(readFileSync(join(web, "src", "locales", "nb", "export.json"), "utf8"));
  assert.deepEqual(Object.keys(nb).sort(), Object.keys(en).sort(), "the same keys in both languages");
  for (const [key, text] of Object.entries(en)) {
    assert.ok(key.startsWith("export."), key);
    assert.ok(typeof nb[key] === "string" && nb[key].trim() !== "" && text.trim() !== "", key);
    const holes = (s) => [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort().join();
    assert.equal(holes(nb[key]), holes(text), `${key}: the same variables in both`);
  }
  // Every key the sources ask for exists, and every key is used.
  const sources = ["flows/export.mjs", "views/export.mjs", "routes/export.route.mjs", "views/shell.mjs"].map((f) => readFileSync(join(web, "src", f), "utf8")).join("\n");
  const used = new Set([...sources.matchAll(/["'`](export\.[a-z_.]+?)["'`]/g)].map((m) => m[1]));
  for (const key of used) assert.ok(key in en, `missing text: ${key}`);
  const dynamic = [
    ...EXPORT_ERRORS.map((code) => `export.error.${code}`),
    ...["checking", "reading", "stretching", "sealing", "saving"].map((phase) => `export.progress.${phase}`),
  ];
  for (const key of dynamic) assert.ok(key in en && key in nb, key);
  for (const key of Object.keys(en)) assert.ok(used.has(key) || dynamic.includes(key), `unused text: ${key}`);
  // The codes the page translates with another catalog exist there.
  for (const code of ["reauth_required", "decrypt"]) assert.ok(SECURITY_ERRORS.includes(code));
  // The words the user is told are the numbers of the format.
  assert.match(en["export.progress.stretching"], /256 MiB/);
  assert.match(nb["export.progress.stretching"], /256 MiB/);
  assert.match(en["export.encrypted.password_help"], /12/);
  assert.match(nb["export.encrypted.password_help"], /12/);
});
