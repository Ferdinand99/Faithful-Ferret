// The import page (spec Fase 1 § 6.4): choose a file, the preview, the fresh confirmation of the master password, the sending that the
// engine does, "Continue import" when the server closed the window, the route and the texts, against a small fake DOM and fakes of the
// session and the engine. The flow itself is in importFlow.test.mjs.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { createI18n } from "../../src/i18n.mjs";
import { autoLockFor } from "../../src/lock.mjs";
import { createWipeScope } from "../../src/views/common.mjs";
import { COUNT_NOTES, IMPORT_ERRORS, IMPORT_PHASES, SKIPPED_KEYS, WARNING_CODES, importErrorText, importView } from "../../src/views/import.mjs";
import { SECURITY_ERRORS } from "../../src/views/securityError.mjs";
import { accountDocument } from "./accountHelpers.mjs";
import { web } from "./helpers.mjs";
import { fakeImportEngine } from "./importFlowHelpers.mjs";
import { click, fakeClient, fakeEngine, fakeSession, find, fire, settle, t as keyT, textOf } from "./vaultHelpers.mjs";

const read = (lang) => ({
  ...JSON.parse(readFileSync(join(web, "src", "locales", lang, "import.json"), "utf8")),
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

const coded = (code, details = null) => Object.assign(new Error(code), { code, details });
const MASTER = "master-pass-for-unit-tests";
const EXPORT_PW = "export-pass-for-unit-tests";

const COUNTS = { items: 12, login: 9, note: 2, card: 1, identity: 0, urls: 14, totp: 3, customFields: 4, matchNull: 5, http: 2, textAddresses: 1, sealed: 12 };
const SKIPPED = {
  passkeys: 1, folders: 2, linked: 1, unknownKeys: 3, otherTypes: 2, trashed: 1, tooLarge: 1, passwordHistory: 4, reprompt: 2,
  attachments: 3, fieldHistory: 5, tags: 2,
};
/** A preview as the flow gives it for a Bitwarden file. */
const bitwarden = (extra = {}) => Object.freeze({
  kind: "bitwarden_json", counts: COUNTS, skipped: SKIPPED,
  warnings: [
    { code: "uri_https_added", count: 6 }, { code: "totp_invalid", count: 1 }, { code: "match_regex", count: 1 }, { code: "match_starts_with", count: 2 },
    { code: "type_ssh_key", count: 1 }, { code: "passkey_skipped", count: 1 },
  ],
  warningsDropped: 7, free: 9_900, used: 99, vaultEmpty: false, fits: true, createdAt: null, ...extra,
});
const ferret = (extra = {}) => Object.freeze({
  kind: "ferretexport", counts: null, skipped: null, warnings: [], warningsDropped: 0, free: 9_999, used: 0, vaultEmpty: true, fits: true, createdAt: 1_800_000_000_000, ...extra,
});

const type = (root, values) => {
  for (const [role, value] of Object.entries(values)) find(root, role).value = value;
};
const choose = async (root, name = "export.json") => {
  find(root, "file").files = [{ name }];
  await fire(find(root, "file"), "change");
  await settle();
};
const submit = (root, form = "import-form") => fire(find(root, form), "submit");

/** The page over fakes. `calls` records what the page asked of the session. */
function page(options = {}) {
  const calls = { previews: [], signals: [], runs: [], continues: [], discards: [] };
  const engine = options.engine ?? fakeImportEngine();
  const scope = createWipeScope();
  const root = importView({
    t: i18n("en").t,
    previewFile: async (file, { signal }) => {
      calls.previews.push(file.name);
      calls.signals.push(signal);
      if (options.previewGate) await options.previewGate;
      if (options.previewError) throw options.previewError;
      return options.preview ?? bitwarden();
    },
    runImport: async (preview, args) => {
      calls.runs.push({ preview, ...args, fieldAtCall: find(root, "master-password").value, exportFieldAtCall: find(root, "export-password")?.value });
      args.onProgress({ phase: "checking" });
      args.onProgress({ phase: "window", items: 12 });
      if (options.runGate) await options.runGate;
      if (options.runError) throw options.runError;
      return { queued: 12 };
    },
    continueImport: async (args) => {
      calls.continues.push({ ...args, fieldAtCall: find(root, "continue-master-password").value });
      args.onProgress({ phase: "checking" });
      if (options.continueError) throw options.continueError;
      engine.status = { ...engine.status, windowClosed: false };
      return { remaining: engine.status.queued };
    },
    discard: (preview) => calls.discards.push(preview),
    status: () => engine.importStatus(),
    on: (event, fn) => engine.on(event, fn),
    scope,
    ...options.view,
  });
  return { root, calls, engine, scope };
}

// ------------------------------------------------------------------ the preview

test("preview_shows_counts_free_space_and_warns_when_the_vault_is_not_empty", async () => {
  await withDom(async () => {
    const { root, calls } = page();
    assert.equal(find(root, "preview").hidden, true, "nothing is shown before a file is chosen");
    await choose(root);
    assert.deepEqual(calls.previews, ["export.json"]);
    const preview = find(root, "preview");
    assert.equal(preview.hidden, false);
    const shown = textOf(preview);
    assert.match(textOf(find(preview, "preview-kind")), /A Bitwarden export \(JSON\)/);
    assert.match(textOf(find(preview, "preview-items")), /Items to import: 12\./);
    assert.match(textOf(find(preview, "count-login")), /9 login\(s\)/);
    assert.match(textOf(find(preview, "count-note")), /2 note\(s\)/);
    assert.match(textOf(find(preview, "count-card")), /1 card\(s\)/);
    assert.equal(find(preview, "count-identity"), null, "what is zero is not listed");
    assert.match(textOf(find(preview, "count-urls")), /14 web address/);
    assert.match(textOf(find(preview, "count-totp")), /3 one-time password/);
    assert.match(textOf(find(preview, "count-custom-fields")), /4 custom field/);
    // The room in the vault, and the warning that the vault is not empty.
    assert.match(textOf(find(preview, "preview-room")), /has 99 item\(s\) and room for 9900 more/);
    assert.match(textOf(find(preview, "not-empty")), /already holds 99 item\(s\).*does not look for duplicates/);
    assert.equal(find(preview, "does-not-fit"), null);
    assert.match(textOf(find(preview, "submit")), /Import 12 item\(s\)/);
    assert.equal(find(preview, "submit").disabled, false);

    // What the report says about addresses (the preview texts for the new report fields).
    assert.match(textOf(find(preview, "note-matchNull")), /5 address\(es\) had no matching rule.*exact host/);
    assert.match(textOf(find(preview, "note-http")), /2 address\(es\) start with http:\/\/.*does not fill them on pages that use https/);
    assert.match(textOf(find(preview, "note-textAddresses")), /1 address\(es\) are not web addresses/);
    // What is left out, each by its count.
    for (const key of SKIPPED_KEYS) assert.ok(find(preview, `skipped-${key}`), `left out: ${key}`);
    assert.match(textOf(find(preview, "skipped-passwordHistory")), /password history of 4 item/);
    assert.match(textOf(find(preview, "skipped-reprompt")), /2 item\(s\) asked for the master password/);
    assert.match(textOf(find(preview, "skipped-folders")), /2 folder/);
    assert.match(textOf(find(preview, "skipped-attachments")), /3 attachment/);
    assert.match(textOf(find(preview, "skipped-fieldHistory")), /earlier values of 5 field/);
    assert.match(textOf(find(preview, "skipped-tags")), /2 tag/);
    // Warnings by code; the ones that only repeat a count of what is left out are not listed twice.
    assert.match(textOf(find(preview, "warning-uri_https_added")), /6 address\(es\) had no http/);
    assert.match(textOf(find(preview, "warning-totp_invalid")), /1 one-time password secret/);
    assert.ok(find(preview, "warning-match_regex") && find(preview, "warning-match_starts_with"));
    assert.equal(find(preview, "warning-type_ssh_key"), null);
    assert.equal(find(preview, "warning-passkey_skipped"), null);
    assert.match(textOf(find(preview, "warning-dropped")), /7 more notes/);
    // A page of text, not markup: every line is a text node.
    assert.ok(!shown.includes("<"));

    // An empty vault is not warned about.
    const empty = page({ preview: bitwarden({ vaultEmpty: true, used: 0, free: 9_999 }) });
    await choose(empty.root);
    assert.equal(find(empty.root, "not-empty"), null);
    assert.match(textOf(find(empty.root, "preview-room")), /has 0 item\(s\) and room for 9999 more/);

    // A file that does not fit says so and cannot be imported.
    const crowded = page({ preview: bitwarden({ fits: false, free: 4, used: 9_995 }) });
    await choose(crowded.root);
    assert.match(textOf(find(crowded.root, "does-not-fit")), /holds 12 items, but your vault has room for 4/);
    assert.equal(find(crowded.root, "submit").disabled, true);
  });
});

test("an_export_of_ferrets_is_previewed_by_its_date_and_asks_for_its_password", async () => {
  await withDom(async () => {
    const { root } = page({ preview: ferret() });
    await choose(root, "backup.ferretexport");
    const preview = find(root, "preview");
    assert.match(textOf(find(preview, "preview-kind")), /A Ferret export \(encrypted\)/);
    assert.match(textOf(find(preview, "preview-export")), /A Ferret export made on /);
    assert.match(textOf(find(preview, "preview-export-count")), /How many items it holds is known once the export password has opened it/);
    assert.equal(find(preview, "preview-items"), null, "no count is known before the file is opened");
    assert.ok(find(preview, "export-password"), "the export password is asked for");
    assert.equal(find(preview, "plain-file-warning"), null, "an export of Ferret's is encrypted");
    assert.equal(find(preview, "skipped-passkeys"), null);
    assert.match(textOf(find(preview, "submit")), /^Import\s*$/);
    // A Bitwarden file does not ask for an export password.
    const other = page();
    await choose(other.root);
    assert.equal(find(find(other.root, "preview"), "export-password"), null);
    // A full vault cannot take an export either.
    const full = page({ preview: ferret({ fits: false, free: 0, used: 9_999, vaultEmpty: false }) });
    await choose(full.root, "backup.ferretexport");
    assert.match(textOf(find(full.root, "does-not-fit")), /no room for more items/);
  });
});

test("a_file_that_is_refused_shows_its_text_and_a_line_number_and_no_preview", async () => {
  await withDom(async () => {
    const { root, calls } = page({ previewError: coded("import_bad_csv", { line: 12 }) });
    await choose(root, "x.csv");
    assert.equal(find(root, "preview").hidden, true);
    assert.equal(find(root, "file-error").hidden, false);
    assert.match(textOf(find(root, "file-error")), /not a valid CSV file\. \(line 12\)/);
    assert.equal(find(root, "file").disabled, false, "another file can be chosen");
    assert.deepEqual(calls.discards, []);
    // The text is the code's, never a message that could hold a value of the file.
    const evil = page({ previewError: Object.assign(new Error("password=hunter2"), { code: "unknown" }) });
    await choose(evil.root);
    assert.ok(!textOf(find(evil.root, "file-error")).includes("hunter2"));
    // Choosing nothing changes nothing.
    const none = page();
    find(none.root, "file").files = [];
    await fire(find(none.root, "file"), "change");
    assert.equal(find(none.root, "preview").hidden, true);
  });
});

// --------------------------------------------------------------------- the import

test("the_import_asks_for_the_master_password_again_and_clears_the_fields_before_the_calls", async () => {
  await withDom(async () => {
    const { root, calls, engine } = page({ engine: fakeImportEngine({ status: { queued: 12, total: 12, sent: 0 } }) });
    await choose(root);
    // Nothing typed: refused on the page, nothing asked.
    await submit(root);
    assert.match(textOf(find(root, "error")), /master password/i);
    assert.deepEqual(calls.runs, []);
    type(root, { "master-password": MASTER });
    const pending = submit(root);
    await pending;
    assert.equal(calls.runs.length, 1);
    assert.equal(calls.runs[0].masterPassword, MASTER);
    assert.equal(calls.runs[0].fieldAtCall, "", "the field was empty when the call started");
    assert.equal(calls.runs[0].exportPassword, undefined, "a Bitwarden file has no export password");
    assert.equal(calls.runs[0].skCode, undefined);
    assert.equal(calls.runs[0].preview.kind, "bitwarden_json");
    // The preview goes, the progress of the sending comes.
    assert.equal(find(root, "preview").hidden, true);
    assert.equal(find(root, "file").value, "");
    const tracker = find(root, "tracker");
    assert.equal(tracker.hidden, false);
    assert.match(textOf(find(tracker, "tracker-sending")), /0 of 12 item\(s\) are on the server; 12 are still waiting/);
    assert.ok(find(tracker, "plain-file-reminder"), "the file is still to be deleted");

    // The engine's events move it, and the end is a page that says what to do next.
    engine.status = { queued: 5, total: 12, sent: 7, failed: 0, windowClosed: false };
    engine.emit("import", { sent: 7, total: 12, failed: 0 });
    assert.match(textOf(find(tracker, "tracker-sending")), /7 of 12 item\(s\) are on the server; 5 are still waiting/);
    engine.status = { queued: 0, total: 12, sent: 12, failed: 0, windowClosed: false };
    engine.emit("import", { sent: 12, total: 12, failed: 0 });
    assert.match(textOf(find(tracker, "done-items")), /Items sent to the server: 12\./);
    assert.match(textOf(find(tracker, "done-next")), /does not remove duplicates/);
    assert.equal(find(tracker, "done-failed"), null);
    assert.equal(find(tracker, "done-list").getAttribute("href"), "#/");
    // The page can take another file.
    await click(find(tracker, "import-again"));
    assert.equal(tracker.hidden, true);
  });
});

test("an_export_of_ferrets_needs_its_password_typed_and_sends_it_with_the_master_password", async () => {
  await withDom(async () => {
    const { root, calls } = page({ preview: ferret(), engine: fakeImportEngine({ status: { queued: 3, total: 3 } }) });
    await choose(root, "backup.ferretexport");
    type(root, { "master-password": MASTER });
    await submit(root);
    assert.match(textOf(find(root, "error")), /export password/i);
    assert.deepEqual(calls.runs, []);
    type(root, { "master-password": MASTER, "export-password": EXPORT_PW });
    await submit(root);
    assert.equal(calls.runs.length, 1);
    assert.equal(calls.runs[0].exportPassword, EXPORT_PW);
    assert.equal(calls.runs[0].masterPassword, MASTER);
    assert.equal(calls.runs[0].exportFieldAtCall, "", "both fields were emptied before the slow calls");
    assert.equal(calls.runs[0].fieldAtCall, "");
  });
});

test("an_import_that_fails_says_why_clears_the_fields_and_can_be_tried_again", async () => {
  await withDom(async () => {
    for (const [code, text] of [
      ["decrypt", /password/i],
      ["import_window_open", /Another device has an import open/],
      ["quota_exceeded", /no room for this many items/],
      ["reauth_required", /password check has run out of time/],
      ["import_wrong_export_password", /export password is wrong/],
      ["import_does_not_fit", /more items than your vault has room for/],
      ["import_timeout", /took too long/],
    ]) {
      const { root, calls } = page({ runError: coded(code) });
      await choose(root);
      type(root, { "master-password": MASTER });
      await submit(root);
      assert.equal(calls.runs.length, 1, code);
      assert.match(textOf(find(root, "error")), text, code);
      assert.equal(find(root, "master-password").value, "", `${code}: nothing stays in the field`);
      assert.equal(find(root, "submit").disabled, false, `${code}: the button works again`);
      assert.equal(find(root, "preview").hidden, false, `${code}: the preview stays`);
      assert.equal(find(root, "tracker").hidden, true);
    }
    // A preview that was let go of, and a lock, send the page back to the file.
    for (const code of ["import_preview_gone", "locked"]) {
      const { root } = page({ runError: coded(code) });
      await choose(root);
      type(root, { "master-password": MASTER });
      await submit(root);
      assert.equal(find(root, "preview").hidden, true, code);
      assert.equal(find(root, "file-error").hidden, false, code);
      assert.ok(textOf(find(root, "file-error")).length > 0, code);
    }
  });
});

test("a_secret_key_is_asked_for_only_when_this_device_does_not_hold_it", async () => {
  await withDom(async () => {
    const withKey = page({ view: { skRequired: true } });
    await choose(withKey.root);
    assert.ok(find(withKey.root, "secret-key"));
    type(withKey.root, { "master-password": MASTER });
    await submit(withKey.root);
    assert.match(textOf(find(withKey.root, "error")), /secret key/i);
    assert.deepEqual(withKey.calls.runs, []);
    type(withKey.root, { "master-password": MASTER, "secret-key": " FFS1-TESTA-TESTB " });
    const skField = find(withKey.root, "secret-key");
    await submit(withKey.root);
    assert.equal(withKey.calls.runs[0].skCode, "FFS1-TESTA-TESTB");
    assert.equal(skField.value, "");
    // Not asked for when the device holds it, and shown when the flow says it is needed.
    const without = page({ runError: coded("sk_required") });
    await choose(without.root);
    assert.equal(find(without.root, "secret-key"), null);
    type(without.root, { "master-password": MASTER });
    await submit(without.root);
    assert.ok(find(without.root, "secret-key"));
  });
});

test("choosing_another_file_or_a_lock_lets_go_of_the_preview_and_empties_the_fields", async () => {
  await withDom(async () => {
    const { root, calls, scope } = page({ preview: ferret() });
    await choose(root, "backup.ferretexport");
    type(root, { "master-password": MASTER, "export-password": EXPORT_PW });
    const masterField = find(root, "master-password");
    const exportField = find(root, "export-password");
    await click(find(root, "cancel"));
    assert.equal(calls.discards.length, 1, "the preview was let go of");
    assert.equal(find(root, "preview").hidden, true);
    assert.equal(masterField.value, "");
    assert.equal(exportField.value, "");
    // A new file after a preview lets go of the old one.
    await choose(root, "a.json");
    await choose(root, "b.json");
    assert.equal(calls.discards.length, 2);
    // A lock empties what is typed and lets go of the preview that is held.
    type(root, { "master-password": MASTER });
    scope.run();
    assert.equal(find(root, "master-password").value, "");
    assert.equal(calls.discards.length, 3);
  });
});

test("the_progress_phases_have_texts_and_the_button_waits_while_the_import_runs", async () => {
  await withDom(async () => {
    /** @type {() => void} */
    let release = () => {};
    const gate = new Promise((resolve) => {
      release = resolve;
    });
    const calls = { phases: [] };
    const engine = fakeImportEngine();
    const scope = createWipeScope();
    const root = importView({
      t: i18n("en").t,
      previewFile: async () => bitwarden(),
      runImport: async (_preview, { onProgress }) => {
        for (const phase of IMPORT_PHASES) {
          onProgress({ phase, items: 12 });
          calls.phases.push(textOf(find(root, "status")).trim());
        }
        // A phase that is not in the list is ignored.
        onProgress({ phase: "something-else" });
        assert.equal(find(root, "submit").disabled, true, "the button waits");
        assert.equal(root.getAttribute("aria-busy"), "true");
        await gate;
        return { queued: 12 };
      },
      continueImport: async () => ({}),
      discard: () => {},
      status: () => engine.importStatus(),
      on: (event, fn) => engine.on(event, fn),
      scope,
    });
    await choose(root);
    type(root, { "master-password": MASTER });
    const pending = submit(root);
    await settle();
    assert.equal(calls.phases.length, IMPORT_PHASES.length);
    assert.deepEqual(calls.phases.map((text) => text.length > 0), IMPORT_PHASES.map(() => true));
    assert.match(calls.phases[0], /Checking your master password/);
    assert.match(calls.phases[3], /Sealing 12 item\(s\)/);
    release();
    await pending;
    assert.equal(root.getAttribute("aria-busy"), "false");
  });
});

// --------------------------------------------------- the plain file and the tracker

test("the_page_tells_you_to_delete_the_plain_export_file_afterwards", async () => {
  await withDom(async () => {
    // On the page from the start: what a file from Bitwarden is, and what to do with it afterwards.
    const { root, engine } = page({ engine: fakeImportEngine({ status: { queued: 12, total: 12 } }) });
    const note = textOf(find(root, "plain-file-note"));
    assert.match(note, /not encrypted: it holds every password in plain text/);
    assert.match(note, /delete the file for good and empty the trash or recycle bin/);
    // Again with the preview of a Bitwarden file, before the import.
    await choose(root);
    assert.match(textOf(find(root, "plain-file-warning")), /delete it for good/);
    // While the items are sent, and when it is over.
    type(root, { "master-password": MASTER });
    await submit(root);
    assert.match(textOf(find(root, "plain-file-reminder")), /Delete the file you imported from, for good, and empty the trash or recycle bin/);
    engine.status = { queued: 0, total: 12, sent: 12, failed: 0, windowClosed: false };
    engine.emit("import", { sent: 12, total: 12, failed: 0 });
    assert.match(textOf(find(root, "plain-file-after")), /Delete the file you imported from, for good, and empty the trash or recycle bin\. It holds every one of these passwords in plain text/);
    assert.equal(find(root, "plain-file-reminder"), null);

    // An export of Ferret's is encrypted: no such reminder after it.
    const x = page({ preview: ferret(), engine: fakeImportEngine({ status: { queued: 3, total: 3 } }) });
    await choose(x.root, "backup.ferretexport");
    assert.equal(find(x.root, "plain-file-warning"), null);
    type(x.root, { "master-password": MASTER, "export-password": EXPORT_PW });
    await submit(x.root);
    assert.equal(find(x.root, "plain-file-reminder"), null);
    x.engine.status = { queued: 0, total: 3, sent: 3, failed: 0, windowClosed: false };
    x.engine.emit("import", { sent: 3, total: 3, failed: 0 });
    assert.ok(find(x.root, "done-items"));
    assert.equal(find(x.root, "plain-file-after"), null);

    // The same words in Norwegian.
    const nb = i18n("nb").t;
    assert.match(nb("import.plain.after"), /Slett filen du importerte fra, for godt, og tøm papirkurven/);
    assert.match(nb("import.plain.before"), /slett den så for godt/);
    assert.match(nb("import.plain.note"), /slett filen for godt og tøm papirkurven/);
  });
});

test("items_the_server_refused_are_counted_when_the_import_ends", async () => {
  await withDom(async () => {
    const { root, engine } = page({ engine: fakeImportEngine({ status: { queued: 12, total: 12 } }) });
    await choose(root);
    type(root, { "master-password": MASTER });
    await submit(root);
    // The engine's own picture: two items were refused and stay as drafts, nothing is waiting to be sent, so the import is over.
    engine.status = { queued: 0, refused: 2, total: 12, sent: 10, failed: 2, windowClosed: false };
    engine.emit("import", { sent: 10, total: 12, failed: 2 });
    assert.match(textOf(find(root, "done-items")), /Items sent to the server: 10\./);
    assert.match(textOf(find(root, "done-failed")), /2 item\(s\) were refused by the server/);
    assert.equal(find(root, "tracker-sending"), null);
  });
});

// ---------------------------------------------------------- continue, and a reload

test("a_closed_window_shows_continue_import_and_the_new_window_needs_the_master_password_again", async () => {
  await withDom(async () => {
    const { root, calls, engine } = page({ engine: fakeImportEngine({ status: { queued: 12, total: 12, sent: 0 } }) });
    await choose(root);
    type(root, { "master-password": MASTER });
    await submit(root);
    assert.ok(find(root, "tracker-sending"), "sending");
    assert.equal(find(root, "continue-form"), null);

    // The server closed the window: the engine says so, and the page offers to continue.
    engine.status = { queued: 5, total: 12, sent: 7, failed: 0, windowClosed: true };
    engine.emit("import_window_closed", { remaining: 5 });
    assert.match(textOf(find(root, "tracker-paused")), /5 item\(s\) are still waiting on this device\. Nothing is lost\./);
    assert.match(textOf(find(root, "tracker-window-note")), /Confirm your master password to get a new one: only the items that are left are sent/);
    assert.ok(find(root, "continue-form"));
    assert.equal(find(root, "tracker-sending"), null);

    // Nothing typed: refused on the page. Typed: the flow gets it, and the fields are empty when it starts.
    await fire(find(root, "continue-form"), "submit");
    assert.match(textOf(find(root, "continue-error")), /master password/i);
    assert.deepEqual(calls.continues, []);
    type(root, { "continue-master-password": MASTER });
    const continueField = find(root, "continue-master-password");
    await fire(find(root, "continue-form"), "submit");
    assert.equal(calls.continues.length, 1);
    assert.equal(calls.continues[0].masterPassword, MASTER);
    assert.equal(calls.continues[0].fieldAtCall, "");
    assert.equal(continueField.value, "");
    // The engine is sending again: the page says so.
    assert.ok(find(root, "tracker-sending"));
    assert.equal(find(root, "continue-form"), null);
  });
});

test("a_continue_that_fails_says_why_and_keeps_the_form", async () => {
  await withDom(async () => {
    for (const [code, text] of [["import_window_open", /Another device has an import open/], ["decrypt", /password/i], ["quota_exceeded", /no room/]]) {
      const { root } = page({ engine: fakeImportEngine({ status: { queued: 5, total: 12, sent: 7, windowClosed: true } }), continueError: coded(code) });
      // Loaded after the window closed: the page finds the import without a file chosen on it.
      assert.ok(find(root, "continue-form"), code);
      type(root, { "continue-master-password": MASTER });
      await fire(find(root, "continue-form"), "submit");
      assert.match(textOf(find(root, "continue-error")), text, code);
      assert.equal(find(root, "continue-submit").disabled, false, code);
      assert.ok(find(root, "continue-form"), code);
    }
    // When there is nothing left, the page says the import is over.
    const { root, engine } = page({ engine: fakeImportEngine({ status: { queued: 5, total: 12, sent: 7, windowClosed: true } }), continueError: coded("import_nothing_left") });
    engine.status = { queued: 0, total: 12, sent: 12, failed: 0, windowClosed: false };
    type(root, { "continue-master-password": MASTER });
    await fire(find(root, "continue-form"), "submit");
    assert.ok(find(root, "done-items"));
    // A secret key is asked for in the continue form only when needed.
    const needs = page({ engine: fakeImportEngine({ status: { queued: 5, total: 12, windowClosed: true } }), view: { skRequired: true } });
    assert.ok(find(needs.root, "continue-secret-key"));
    type(needs.root, { "continue-master-password": MASTER });
    await fire(find(needs.root, "continue-form"), "submit");
    assert.match(textOf(find(needs.root, "continue-error")), /secret key/i);
    assert.deepEqual(needs.calls.continues, []);
  });
});

test("a_page_loaded_in_the_middle_of_an_import_follows_it_and_a_page_with_none_shows_nothing", async () => {
  await withDom(async () => {
    // The engine has the rest of an import in its outbox (the page was loaded again): the sending is followed from the start.
    const mid = page({ engine: fakeImportEngine({ status: { queued: 30, total: 30, sent: 0 } }) });
    assert.equal(find(mid.root, "tracker").hidden, false);
    assert.match(textOf(find(mid.root, "tracker-sending")), /0 of 30 item\(s\) are on the server; 30 are still waiting/);
    mid.engine.status = { queued: 10, total: 30, sent: 20, failed: 0, windowClosed: false };
    mid.engine.emit("import", { sent: 20, total: 30, failed: 0 });
    assert.match(textOf(find(mid.root, "tracker-sending")), /20 of 30/);
    mid.engine.status = { queued: 0, total: 30, sent: 30, failed: 0, windowClosed: false };
    mid.engine.emit("import", { sent: 30, total: 30, failed: 0 });
    assert.match(textOf(find(mid.root, "done-items")), /Items sent to the server: 30\./);
    // After a reload the page does not know what kind of file it was, so the reminder about a plain file is given.
    assert.ok(find(mid.root, "plain-file-after"));

    // No import: no tracker.
    const none = page();
    assert.equal(find(none.root, "tracker").hidden, true);
    // The engine's events that come when no import is followed are ignored, except a closed window, which is followed from there.
    none.engine.emit("import", { sent: 1, total: 2, failed: 0 });
    assert.equal(find(none.root, "tracker").hidden, true);
    none.engine.status = { queued: 4, total: 4, sent: 0, failed: 0, windowClosed: true };
    none.engine.emit("import_window_closed", { remaining: 4 });
    assert.ok(find(none.root, "continue-form"));
  });
});

// ------------------------------------------------------------------ the texts

test("import_error_texts_come_from_the_code_and_a_line_number_is_added", () => {
  const t = i18n("en").t;
  assert.match(importErrorText(t, coded("import_zip")), /ZIP file/);
  assert.match(importErrorText(t, coded("import_bad_csv", { line: 4 })), /valid CSV file\. \(line 4\)/);
  assert.doesNotMatch(importErrorText(t, coded("import_bad_csv", { line: "4; drop" })), /drop/);
  // Codes of the sign-in and the re-authentication have the texts of the other pages; an unknown one is plain.
  assert.match(importErrorText(t, coded("reauth_required")), /password check has run out of time/);
  assert.match(importErrorText(t, coded("something_new")), /something_new|went wrong|try again/i);
  assert.ok(!importErrorText(t, Object.assign(new Error("hunter2 is the password"), { code: "unknown" })).includes("hunter2"));
  for (const code of IMPORT_ERRORS) assert.ok(i18n("en").t(`import.error.${code}`) !== `import.error.${code}`, code);
});

test("import_texts_exist_in_both_languages", async () => {
  const en = JSON.parse(readFileSync(join(web, "src", "locales", "en", "import.json"), "utf8"));
  const nb = JSON.parse(readFileSync(join(web, "src", "locales", "nb", "import.json"), "utf8"));
  assert.deepEqual(Object.keys(nb).sort(), Object.keys(en).sort(), "the same keys in both languages");
  for (const [key, text] of Object.entries(en)) {
    assert.ok(key.startsWith("import."), key);
    assert.ok(typeof nb[key] === "string" && nb[key].trim() !== "" && text.trim() !== "", key);
    const holes = (s) => [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort().join();
    assert.equal(holes(nb[key]), holes(text), `${key}: the same variables in both`);
  }
  // Every key the sources ask for exists, and every key is used.
  const sources = ["flows/import.mjs", "views/import.mjs", "routes/import.route.mjs"].map((f) => readFileSync(join(web, "src", f), "utf8")).join("\n");
  const used = new Set([...sources.matchAll(/["'`](import\.[A-Za-z_.]+?)["'`]/g)].map((m) => m[1]));
  for (const key of used) assert.ok(key in en, `missing text: ${key}`);
  const labels = ["username", "password", "totp", "address", "field", "untitled", "cardholder_name", "brand", "number", "exp_month", "exp_year", "code", "title", "first_name", "middle_name", "last_name", "address1", "address2", "address3", "city", "state", "postal_code", "country", "company", "email", "phone", "ssn", "identity_username", "passport_number", "license_number", "gender", "birthdate", "nickname", "pin"];
  const dynamic = [
    ...IMPORT_ERRORS.map((code) => `import.error.${code}`),
    ...IMPORT_PHASES.map((phase) => `import.progress.${phase}`),
    ...SKIPPED_KEYS.map((key) => `import.skipped.${key}`),
    ...WARNING_CODES.map((code) => `import.warning.${code}`),
    ...COUNT_NOTES.map((key) => `import.note.${key}`),
    ...["ferretexport", "bitwarden_json", "bitwarden_csv", "aliasvault_csv", "aliasvault_avux"].map((kind) => `import.kind.${kind}`),
    ...labels.map((key) => `import.label.${key}`),
  ];
  for (const key of dynamic) assert.ok(key in en && key in nb, key);
  for (const key of Object.keys(en)) assert.ok(used.has(key) || dynamic.includes(key), `unused text: ${key}`);
  // The labels the route passes are exactly the labels of the import worker.
  const route = readFileSync(join(web, "src", "routes", "import.route.mjs"), "utf8");
  const { DEFAULT_LABELS } = await import("../../src/import/map.mjs");
  assert.deepEqual([...labels].sort(), Object.keys(DEFAULT_LABELS).sort());
  for (const key of Object.keys(DEFAULT_LABELS)) assert.ok(route.includes(`"${key}"`), `the route passes ${key}`);
  // The codes the page translates with another catalog exist there.
  for (const code of ["reauth_required", "decrypt"]) assert.ok(SECURITY_ERRORS.includes(code));
  // The numbers the user is told are the numbers of the import.
  assert.match(en["import.error.import_too_large"], /50 MiB/);
  assert.match(nb["import.error.import_too_large"], /50 MiB/);
  assert.match(en["import.error.import_window_open"], /30 minutes/);
  assert.match(nb["import.error.import_window_open"], /30 minutter/);
});

// -------------------------------------------------------------------- the route

function rig({ open = true, status = { pinned: true, skBit: true, skStored: true } } = {}) {
  const engine = fakeEngine();
  engine.health = () => ({ halted: null, warnings: [] });
  engine.syncNow = async () => engine.emit("state", { kind: "idle" });
  engine.listeners.import = new Set();
  engine.listeners.import_window_closed = new Set();
  engine.importStatus = () => ({ queued: 0, sent: 0, total: 0, failed: 0, windowClosed: false });
  const client = fakeClient(engine);
  const session = fakeSession({ client, open, status });
  session.serverUrl = "https://vault.example";
  const calls = { previews: [], runs: [], continues: [], discards: [] };
  session.importPreview = async (file, args) => {
    calls.previews.push({ name: file.name, ...args });
    return bitwarden();
  };
  session.importRun = async (preview, args) => {
    calls.runs.push(args);
    return { queued: 12 };
  };
  session.importContinue = async (args) => {
    calls.continues.push(args);
    return { remaining: 0 };
  };
  session.importDiscard = (preview) => calls.discards.push(preview);
  const store = { open: async () => ({}), exportReminder: { status: async () => ({ due: false, lastExportAt: null }), snooze: async () => {} } };
  const sync = { current: () => engine, start: async () => engine, stop: () => engine.stop(), discard: engine.discard };
  const ctx = (lang = "en") => ({
    params: {}, path: "/import", i18n: { ...i18n(lang), t: lang === "en" ? keyT : i18n(lang).t, lang }, client, services: { crypto: session, sync, store }, go: () => {}, routes: [],
  });
  return { engine, session, calls, ctx, done: () => autoLockFor(session, sync).stop() };
}

test("the_import_route_is_an_account_page_in_the_vault_frame_and_passes_the_page_language", async () => {
  await withDom(async () => {
    const route = (await import("../../src/routes/import.route.mjs")).default;
    assert.equal(route.path, "/import");
    assert.equal(route.menu, "account");
    assert.equal(route.title, "import.title");

    const closed = rig({ open: false });
    try {
      const node = await route.load(closed.ctx());
      await settle();
      assert.ok(find(node, "unlock"));
      assert.equal(find(node, "import-page"), null);
    } finally {
      closed.done();
    }

    const r = rig();
    try {
      const node = await route.load(r.ctx("nb"));
      await settle();
      assert.ok(find(node, "shell"), "inside the vault frame");
      assert.ok(find(node, "import-page"));
      assert.equal(find(node, "secret-key"), null, "this device holds the secret key");
      await choose(node, "x.json");
      assert.equal(r.calls.previews.length, 1);
      // The preview is read by the session with the engine of the open vault and the labels in the language of the page.
      assert.equal(r.calls.previews[0].engine, r.engine);
      assert.equal(r.calls.previews[0].labels.username, "Brukernavn");
      assert.equal(r.calls.previews[0].labels.password, "Passord");
      assert.equal(r.calls.previews[0].labels.untitled, "(uten navn)");
      type(node, { "master-password": MASTER });
      await submit(node);
      assert.equal(r.calls.runs.length, 1);
      assert.equal(r.calls.runs[0].engine, r.engine);
      assert.equal(r.calls.runs[0].masterPassword, MASTER);
    } finally {
      r.done();
    }

    // A device without the secret key asks for it.
    const asking = rig({ status: { pinned: true, skBit: true, skStored: false } });
    try {
      const node = await route.load(asking.ctx());
      await settle();
      await choose(node, "x.json");
      assert.ok(find(node, "secret-key"));
    } finally {
      asking.done();
    }
  });
});

// ------------------------------------------------------------- leaving the page

const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

test("leaving_the_page_ends_the_reading_and_lets_go_of_a_held_preview", async () => {
  await withDom(async () => {
    // While the file is read: the signal handed to the session is aborted, and what comes back afterwards is dropped.
    /** @type {() => void} */
    let release = () => {};
    const gate = new Promise((resolve) => {
      release = resolve;
    });
    const reading = page({ previewGate: gate, view: { leavePollMs: 5 } });
    reading.root.isConnected = true;
    find(reading.root, "file").files = [{ name: "x.json" }];
    const pending = fire(find(reading.root, "file"), "change");
    await pause(30);
    assert.equal(reading.calls.signals[0].aborted, false, "the page is still shown");
    reading.root.isConnected = false;
    await pause(30);
    assert.equal(reading.calls.signals[0].aborted, true, "the page was left");
    release();
    await pending;
    assert.equal(reading.calls.discards.length, 1, "the preview that arrived is let go of");
    assert.equal(find(reading.root, "preview").hidden, true);

    // A preview that is held is let go of when the page is left.
    const held = page({ view: { leavePollMs: 5 } });
    held.root.isConnected = true;
    await choose(held.root);
    await pause(30);
    assert.equal(held.calls.discards.length, 0);
    held.root.isConnected = false;
    await pause(30);
    assert.equal(held.calls.discards.length, 1);
  });
});

test("leaving_within_the_first_look_still_ends_the_reading", async () => {
  await withDom(async () => {
    // The page is on screen when the file is chosen. A page that is left before the first look of the timer is still a page that was left.
    /** @type {() => void} */
    let release = () => {};
    const gate = new Promise((resolve) => {
      release = resolve;
    });
    const quick = page({ previewGate: gate, view: { leavePollMs: 5 } });
    quick.root.isConnected = true;
    find(quick.root, "file").files = [{ name: "x.json" }];
    const pending = fire(find(quick.root, "file"), "change");
    quick.root.isConnected = false;
    await pause(30);
    assert.equal(quick.calls.signals[0].aborted, true, "the reading ended although the timer had not seen the page before");
    release();
    await pending;
    assert.equal(quick.calls.discards.length, 1);
  });
});

test("an_import_that_is_running_keeps_its_preview_when_another_page_is_opened", async () => {
  await withDom(async () => {
    /** @type {() => void} */
    let release = () => {};
    const gate = new Promise((resolve) => {
      release = resolve;
    });
    const running = page({ runGate: gate });
    await choose(running.root);
    type(running.root, { "master-password": MASTER });
    const sending = submit(running.root);
    await settle();
    // Another page of the vault is opened while the master password is checked and the items are sealed: the wipe of the page runs.
    running.scope.run();
    assert.equal(running.calls.discards.length, 0, "the preview of a running import is not let go of");
    release();
    await sending;
    await settle();
    assert.equal(running.calls.runs.length, 1);

    // The page was left and the import that was running then fails: nobody sees the error, and the sealed items are let go of.
    let release2 = () => {};
    const gateB = new Promise((resolve) => {
      release2 = resolve;
    });
    const failed = page({ runGate: gateB, runError: coded("quota_exceeded") });
    await choose(failed.root);
    type(failed.root, { "master-password": MASTER });
    const failing = submit(failed.root);
    await settle();
    failed.scope.run();
    assert.equal(failed.calls.discards.length, 0);
    release2();
    await failing;
    await settle();
    assert.equal(failed.calls.discards.length, 1, "a failed import whose page is gone drops its preview");

    // A preview that no import is using is let go of, as before.
    const idle = page();
    await choose(idle.root);
    idle.scope.run();
    assert.equal(idle.calls.discards.length, 1);
  });
});

test("an_aliasvault_file_is_named_and_the_page_says_to_delete_it_and_which_notes_apply", async () => {
  await withDom(async () => {
    const root = page().root;
    assert.match(find(root, "file").getAttribute("accept"), /\.avux/);
    assert.match(textOf(find(root, "format-aliasvault")), /AliasVault export without encryption, as \.avux or CSV.*not the encrypted \.avex/);
    assert.match(textOf(find(root, "format-not")), /AliasVault's encrypted \.avex/);
    for (const kind of ["aliasvault_avux", "aliasvault_csv"]) {
      const shown = page({
        preview: bitwarden({
          kind,
          warnings: [{ code: "alias_needs_aliasvault", count: 4 }, { code: "item_archived", count: 1 }, { code: "totp_extra", count: 2 }, { code: "card_and_login", count: 1 }],
        }),
      });
      await choose(shown.root, kind === "aliasvault_csv" ? "export.csv" : "export.avux");
      assert.match(textOf(find(shown.root, "preview-kind")), /An AliasVault export/);
      assert.match(textOf(find(shown.root, "plain-file-warning")), /delete it for good/, kind);
      assert.match(textOf(find(shown.root, "warning-alias_needs_aliasvault")), /4 item\(s\) have an e-mail address that may be an alias.*only receives mail while your AliasVault server runs/);
      assert.ok(find(shown.root, "warning-item_archived") && find(shown.root, "warning-totp_extra") && find(shown.root, "warning-card_and_login"));
    }
    const nb = i18n("nb").t;
    assert.match(nb("import.warning.alias_needs_aliasvault", { count: 4 }), /4 element\(er\).*AliasVault-tjeneren din kjører/);
    assert.match(nb("import.kind.aliasvault_avux"), /AliasVault-eksport \(\.avux\)/);
  });
});

// ------------------------------------------------------------------ the file picker

test("the_file_picker_is_a_button_for_a_hidden_input_and_shows_the_name_of_the_chosen_file", async () => {
  await withDom(async () => {
    const { root, calls } = page();
    const input = find(root, "file");
    // The input stays in the page for the keyboard and the screen reader (hidden from the eye only), with the same accepted kinds.
    assert.equal(input.getAttribute("class"), "visually-hidden");
    assert.equal(input.getAttribute("type"), "file");
    assert.match(input.getAttribute("accept"), /^\.ferretexport,\.json,\.csv,\.avux$/);
    // Two labels name it: the field's and the button.
    const labels = [...walkAll(root)].filter((n) => n.tagName === "label" && n.getAttribute("for") === "import-file");
    assert.deepEqual(labels.map((n) => textOf(n).trim()), ["File to import", "Choose file"]);
    assert.equal(find(root, "file-choose").getAttribute("class"), "btn btn-secondary");
    assert.match(textOf(find(root, "file-name")), /No file chosen/);
    // Choosing a file starts the same step as before and names the file.
    await choose(root, "moved.json");
    assert.deepEqual(calls.previews, ["moved.json"]);
    assert.match(textOf(find(root, "file-name")), /moved\.json/);
    assert.equal(find(root, "preview").hidden, false);
    // Cancelling the preview forgets the name.
    await click(find(root, "cancel"));
    assert.match(textOf(find(root, "file-name")), /No file chosen/);
    // A file the page refuses is not left named.
    const bad = page({ previewError: coded("import_bad_csv", { line: 3 }) });
    await choose(bad.root, "bad.csv");
    assert.match(textOf(find(bad.root, "file-name")), /No file chosen/);
    const nb = i18n("nb").t;
    assert.equal(nb("import.file.choose"), "Velg fil");
    assert.equal(nb("import.file.none"), "Ingen fil valgt");
  });
});

test("a_file_dropped_on_the_zone_starts_the_same_step_and_a_drop_while_busy_is_ignored", async () => {
  await withDom(async () => {
    let release;
    const gate = new Promise((resolve) => { release = resolve; });
    const { root, calls } = page({ previewGate: gate });
    const zone = find(root, "file-drop");
    const over = await fire(zone, "dragover");
    assert.equal(over.prevented, true, "the browser does not open the file");
    assert.equal(zone.getAttribute("data-over"), "true");
    await fire(zone, "dragleave");
    assert.equal(zone.getAttribute("data-over"), "false");
    const pending = fire(zone, "drop", { dataTransfer: { files: [{ name: "dropped.json" }, { name: "second.json" }] } });
    await settle();
    assert.deepEqual(calls.previews, ["dropped.json"], "the first file only");
    assert.match(textOf(find(root, "file-name")), /dropped\.json/);
    assert.equal(find(root, "file").disabled, true, "the file is being read");
    await fire(zone, "drop", { dataTransfer: { files: [{ name: "again.json" }] } });
    assert.deepEqual(calls.previews, ["dropped.json"], "a drop while the file is read is ignored");
    release();
    await pending;
    await settle();
    assert.equal(find(root, "preview").hidden, false);
    // A drop with no file changes nothing.
    const none = page();
    await fire(find(none.root, "file-drop"), "drop", { dataTransfer: { files: [] } });
    assert.deepEqual(none.calls.previews, []);
    assert.equal(find(none.root, "preview").hidden, true);
  });
});

test("a_drop_with_no_file_leaves_a_preview_that_is_showing_as_it_is", async () => {
  await withDom(async () => {
    const { root, calls } = page();
    await choose(root, "shown.json");
    assert.equal(find(root, "preview").hidden, false);
    const zone = find(root, "file-drop");
    // Dragged text or a link: no files at all, or an empty list.
    for (const dataTransfer of [undefined, { files: [] }, { files: undefined }]) await fire(zone, "drop", { dataTransfer });
    assert.equal(find(root, "preview").hidden, false, "the preview stays");
    assert.match(textOf(find(root, "file-name")), /shown.json/);
    assert.deepEqual(calls.previews, ["shown.json"]);
    assert.deepEqual(calls.discards, [], "nothing was discarded");
  });
});

/** Every node below `root`. */
function* walkAll(root) {
  yield root;
  for (const child of root.childNodes ?? []) yield* walkAll(child);
}
