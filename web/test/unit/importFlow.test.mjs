// The import flow (spec Fase 1 § 5.2 and § 6.4): preview, the fit check, the fresh re-authentication, the import window, the hand-over to
// the sync engine, a closed window and a reload. The import worker body runs in this process behind the worker interface, the core is a
// fake that records what it was given (the real cipher is the core's), and the engine is either a recorder or the real one over the sync
// tests' model of the server. Every value is a test value.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { kindOfFile, previewImport, vaultRoom } from "../../src/flows/import.mjs";
import { dumpDatabase } from "./accountHelpers.mjs";
import { web } from "./helpers.mjs";
import { allStrings, avFile, fixtureFile, textFile } from "./importHelpers.mjs";
import { EXPORT_PASSWORD, NOW, PASSWORD, WINDOW, answer, coded, fakeExportFileCore, fakeImportEngine, importWorld, sealingPort } from "./importFlowHelpers.mjs";
import { EMAIL, SK_CODE } from "./securityHelpers.mjs";
import { Model, createFakeClient, settle, syncDevice, until } from "./syncHelpers.mjs";

const idx = (log, entry) => log.findIndex((line) => line === entry);
const hexOf = (bytes) => Buffer.from(bytes).toString("hex");
/** The words of the fixtures that must never be in what the page gets or what is sent. */
const WORDS = ["synthetic-password-1", "synthetic-password-2", "alice@example.test", "bob@example.test", "www.example.test", "Example login", "Example note", "GEZDGNBV"];

/** A Bitwarden JSON file with `count` logins named `Imported <n>`. */
const manyLogins = (count, name = "many.json") =>
  textFile(JSON.stringify({
    encrypted: false,
    folders: [],
    items: Array.from({ length: count }, (_, n) => ({ type: 1, name: `Imported ${n + 1}`, login: { username: `user${n}`, password: `synthetic-pw-${n}`, uris: [] } })),
  }), name);

// ----------------------------------------------------------------- the preview

test("a_preview_gives_the_page_counts_and_codes_never_a_value_of_the_file", async () => {
  const w = await importWorld();
  const engine = fakeImportEngine({ used: 5 });
  const preview = await w.session.importPreview(fixtureFile("every-type.json"), { engine });
  // Nothing was asked of the server, and the page did not seal anything itself.
  assert.equal(w.requests.length, 0);
  assert.ok(!w.log.includes("vault.encrypt_item"));
  assert.equal(preview.kind, "bitwarden_json");
  assert.equal(preview.counts.items, 8);
  assert.equal(preview.counts.sealed, 8);
  assert.deepEqual([preview.counts.login, preview.counts.note, preview.counts.card, preview.counts.identity], [5, 1, 1, 1]);
  assert.equal(preview.counts.matchNull, 2);
  assert.equal(preview.counts.http, 1);
  assert.equal(preview.counts.textAddresses, 2);
  assert.deepEqual(
    { passkeys: preview.skipped.passkeys, folders: preview.skipped.folders, otherTypes: preview.skipped.otherTypes, trashed: preview.skipped.trashed, passwordHistory: preview.skipped.passwordHistory },
    { passkeys: 1, folders: 0, otherTypes: 2, trashed: 1, passwordHistory: 1 },
  );
  // Warnings are counted by code (the index of an item in the file is not given on).
  const byCode = Object.fromEntries(preview.warnings.map((warning) => [warning.code, warning.count]));
  assert.equal(byCode.match_starts_with, 1);
  assert.equal(byCode.totp_steam, 1);
  assert.equal(byCode.totp_invalid, 1);
  assert.ok(preview.warnings.every((warning) => Object.keys(warning).sort().join() === "code,count"));
  assert.equal(preview.free, 9_999 - 5);
  assert.equal(preview.used, 5);
  assert.equal(preview.vaultEmpty, false);
  assert.equal(preview.fits, true);
  // No word of the file is in the preview.
  const seen = JSON.stringify(preview);
  for (const word of ["synthetic-password", "alice@example.test", "example.test", "GEZDGNBV", "Alice Example", "hidden value"]) assert.ok(!seen.includes(word), word);
  assert.ok(Object.isFrozen(preview));

  // An empty vault is said to be empty.
  const empty = await w.session.importPreview(fixtureFile("small.json"), { engine: fakeImportEngine({ used: 0 }) });
  assert.equal(empty.vaultEmpty, true);
  assert.equal(empty.counts.items, 2);
});

test("the_page_passes_its_language_to_the_worker_and_the_worker_gets_the_file_and_the_port", async () => {
  const w = await importWorld();
  const labels = { username: "Brukernavn", password: "Passord", untitled: "(uten navn)" };
  await w.session.importPreview(fixtureFile("small.json"), { engine: fakeImportEngine(), labels });
  assert.equal(w.workers.made.length, 1);
  const { message, transfer } = w.workers.made[0].posted[0];
  assert.deepEqual(Object.keys(message).sort(), ["file", "id", "kind", "labels", "port"]);
  assert.ok(message.file instanceof File, "the file itself goes to the worker");
  assert.deepEqual(message.labels, labels);
  assert.equal(message.kind, "bitwarden_json");
  assert.deepEqual(transfer, [message.port], "the port is handed over, not copied");
  // The labels the worker used for the fields are the page's language.
  const drafts = w.ports[0].sent.map((m) => m.args[2]);
  const login = drafts.find((draft) => draft.item_type === "login");
  assert.ok(login.fields.some((field) => field.label === "Brukernavn"));
  assert.ok(login.fields.some((field) => field.label === "Passord"));
  assert.ok(w.workers.made[0].terminated, "the worker is ended after its answer");
});

test("an_aliasvault_file_is_previewed_by_what_the_worker_read_it_as", async () => {
  const engine = fakeImportEngine({ used: 2 });
  const w = await importWorld();
  const avux = await w.session.importPreview(avFile("synthetic.avux"), { engine });
  assert.equal(avux.kind, "aliasvault_avux");
  assert.equal(avux.counts.items, 8);
  assert.equal(avux.counts.sealed, 8);
  assert.equal(avux.skipped.attachments, 1);
  assert.equal(avux.skipped.fieldHistory, 1);
  assert.equal(avux.skipped.tags, 1);
  assert.equal(avux.skipped.passkeys, 1);
  assert.equal(avux.counts.matchNull, 4);
  assert.deepEqual(w.workers.made[0].posted[0].message.kind, "aliasvault_avux");

  // A `.csv` file is asked for as `csv`, and its header says whose it is.
  const csv = await w.session.importPreview(avFile("synthetic.csv"), { engine });
  assert.equal(csv.kind, "aliasvault_csv");
  assert.equal(csv.counts.items, 8);
  assert.equal(w.workers.made[1].posted[0].message.kind, "csv");
  const bitwarden = await w.session.importPreview(fixtureFile("small.csv"), { engine });
  assert.equal(bitwarden.kind, "bitwarden_csv");
  assert.ok(w.workers.made.every((worker) => worker.terminated));

  // Nothing of the files is in a preview, and the page counts the warnings by code.
  const seen = JSON.stringify([avux, csv]);
  for (const word of ["synthetic-password", "alice@example.test", "Mail login", "PRIVATE-KEY", "GEZDGNBV", "Alice Synthetic", "Syntetisk"]) assert.ok(!seen.includes(word), word);
  assert.ok(avux.warnings.some((warning) => warning.code === "alias_needs_aliasvault" && warning.count === 1));

  // The encrypted export of AliasVault is refused by its name before any worker starts, and by the worker when it is named .avux.
  const before = w.workers.made.length;
  await assert.rejects(w.session.importPreview(new File(["{}"], "vault.avex"), { engine }), (e) => e.code === "import_encrypted_export");
  assert.equal(w.workers.made.length, before);
  await assert.rejects(w.session.importPreview(avFile("encrypted.avex", "vault.avux"), { engine }), (e) => e.code === "import_encrypted_export");
});

test("an_avux_archive_is_held_to_its_own_size_limit_and_says_which", async () => {
  const w = await importWorld();
  const engine = fakeImportEngine();
  const sized = (name, size) => {
    const file = new File(["x"], name);
    Object.defineProperty(file, "size", { value: size });
    return file;
  };
  await assert.rejects(w.session.importPreview(sized("a.avux", 2 * 1024 * 1024 * 1024 + 1), { engine }), (e) => e.code === "import_archive_too_large");
  await assert.rejects(w.session.importPreview(sized("a.json", 51 * 1024 * 1024), { engine }), (e) => e.code === "import_too_large");
  await assert.rejects(w.session.importPreview(sized("a.csv", 51 * 1024 * 1024), { engine }), (e) => e.code === "import_too_large");
  assert.equal(w.workers.made.length, 0, "no worker was started for any of these");
  // Over 50 MiB is not too large for an archive: the file goes to the worker (which refuses this one as no archive).
  await assert.rejects(w.session.importPreview(sized("a.avux", 60 * 1024 * 1024), { engine }), (e) => e.code !== "import_too_large" && e.code !== "import_archive_too_large");
  assert.equal(w.workers.made.length, 1);
});

test("an_answer_that_names_a_kind_the_name_did_not_allow_is_refused", async () => {
  const sealed = [{ id: new Uint8Array(16).fill(1), rev: 1, envelope: new Uint8Array([1]), tag: new Uint8Array(32) }];
  for (const [name, kind] of [["x.csv", "bitwarden_json"], ["x.csv", "ferretexport"], ["x.json", "aliasvault_csv"], ["x.avux", "bitwarden_csv"], ["x.json", undefined], ["x.csv", {}]]) {
    const w = await importWorld({ mode: "garbage", garbage: { id: 1, ok: true, kind, sealed, report: { counts: { sealed: 1 } } } });
    await assert.rejects(w.session.importPreview(new File(["x"], name), { engine: fakeImportEngine() }), (e) => e.code === "import_bad_answer", `${name} ${String(kind)}`);
  }
  // The kinds the name does allow are taken.
  for (const [name, kind] of [["x.csv", "aliasvault_csv"], ["x.csv", "bitwarden_csv"], ["x.json", "bitwarden_json"], ["x.avux", "aliasvault_avux"]]) {
    const w = await importWorld({ mode: "garbage", garbage: { id: 1, ok: true, kind, sealed, report: { counts: { sealed: 1 } } } });
    assert.equal((await w.session.importPreview(new File(["x"], name), { engine: fakeImportEngine() })).kind, kind);
  }
});

test("the_kind_of_a_file_comes_from_its_name_and_a_zip_or_an_unknown_name_is_refused_before_a_worker_starts", async () => {
  assert.equal(kindOfFile({ name: "Backup.FerretExport" }), "ferretexport");
  assert.equal(kindOfFile({ name: "bitwarden_export.json" }), "bitwarden_json");
  // A CSV file is Bitwarden's or AliasVault's: the worker says which, by its header.
  assert.equal(kindOfFile({ name: "export.CSV" }), "csv");
  assert.equal(kindOfFile({ name: "Vault.AVUX" }), "aliasvault_avux");
  // The encrypted export of AliasVault is not read.
  assert.throws(() => kindOfFile({ name: "vault.avex" }), (e) => e.code === "import_encrypted_export");
  assert.throws(() => kindOfFile({ name: "export.zip" }), (e) => e.code === "import_zip");
  assert.throws(() => kindOfFile({ name: "export.txt" }), (e) => e.code === "import_bad_format");
  assert.throws(() => kindOfFile({}), (e) => e.code === "import_bad_format");

  const w = await importWorld();
  const engine = fakeImportEngine();
  for (const [file, code] of [
    [new File(["PK"], "export.zip"), "import_zip"],
    [new File(["x"], "export.txt"), "import_bad_format"],
    [new File([""], "empty.json"), "import_empty"],
  ]) {
    await assert.rejects(w.session.importPreview(file, { engine }), (e) => e.code === code, code);
  }
  assert.equal(w.workers.made.length, 0, "no worker was started for any of these");
  // A ZIP file with a JSON name is found by the worker and refused with the same code.
  await assert.rejects(w.session.importPreview(new File([new Uint8Array([0x50, 0x4b, 3, 4, 0])], "export.json"), { engine }), (e) => e.code === "import_zip");
  // Bitwarden's encrypted export and a file nested too deeply are refused by the worker, with its codes.
  await assert.rejects(w.session.importPreview(fixtureFile("encrypted.json"), { engine }), (e) => e.code === "import_encrypted_export");
  await assert.rejects(w.session.importPreview(fixtureFile("huge-depth.json"), { engine }), (e) => e.code === "import_too_deep");
  assert.ok(w.workers.made.every((worker) => worker.terminated), "every worker was ended");
});

test("a_worker_that_fails_or_answers_nonsense_stops_the_import_and_is_ended", async () => {
  for (const [mode, code] of [["error", "import_worker_failed"], ["garbage", "import_bad_answer"]]) {
    const w = await importWorld({ mode });
    await assert.rejects(w.session.importPreview(fixtureFile("small.json"), { engine: fakeImportEngine() }), (e) => e.code === code, mode);
    assert.ok(w.workers.made[0].terminated, mode);
    assert.equal(w.requests.length, 0);
  }
  // An answer whose items are not what the vault makes (a short tag, an id used twice, a revision other than 1, the id of the manifest, a
  // report that does not agree with the items) is refused.
  const item = (extra = {}) => ({ id: new Uint8Array(16).fill(1), rev: 1, envelope: new Uint8Array([1]), tag: new Uint8Array(32), ...extra });
  const bad = [
    { sealed: [item({ tag: new Uint8Array(31) })], count: 1 },
    { sealed: [item(), item()], count: 2 },
    { sealed: [item({ rev: 2 })], count: 1 },
    { sealed: [item({ id: new Uint8Array(16) })], count: 1 },
    { sealed: [item({ envelope: new Uint8Array(0) })], count: 1 },
    { sealed: [item()], count: 2 },
  ];
  for (const { sealed, count } of bad) {
    const w = await importWorld({ mode: "garbage", garbage: { id: 1, ok: true, sealed, report: { counts: { sealed: count } } } });
    await assert.rejects(w.session.importPreview(fixtureFile("small.json"), { engine: fakeImportEngine() }), (e) => e.code === "import_bad_answer");
    assert.ok(w.workers.made[0].terminated);
  }
  // A refusal of the worker keeps its code and a line number; a code it does not have is "unreadable", and no text of it is passed on.
  const refusal = await importWorld({ mode: "garbage", garbage: { id: 1, ok: false, error: "import_bad_csv", line: 7 } });
  await assert.rejects(refusal.session.importPreview(fixtureFile("small.csv"), { engine: fakeImportEngine() }), (e) => e.code === "import_bad_csv" && e.details.line === 7);
  const odd = await importWorld({ mode: "garbage", garbage: { id: 1, ok: false, error: "evil: <b>text</b> of the file" } });
  await assert.rejects(odd.session.importPreview(fixtureFile("small.json"), { engine: fakeImportEngine() }), (e) => e.code === "import_unreadable" && !String(e.message).includes("evil"));
  // The answer to another request is not this one's.
  const other = await importWorld({ mode: "garbage", garbage: { id: 2, ok: true, sealed: [], report: {} } });
  await assert.rejects(other.session.importPreview(fixtureFile("small.json"), { engine: fakeImportEngine() }), (e) => e.code === "import_bad_answer");
});

// ---------------------------------------------------- re-authentication and window

test("import_needs_fresh_reauth_and_opens_a_window_first", async () => {
  const w = await importWorld();
  const engine = fakeImportEngine({ log: w.log });
  const preview = await w.session.importPreview(fixtureFile("small.json"), { engine });
  assert.equal(w.requests.length, 0, "the preview asks the server for nothing");

  // What the page can see is wrong stops here: no request, nothing written.
  await assert.rejects(w.session.importRun(preview, { masterPassword: "", engine }), (e) => e.code === "password_required");
  assert.equal(w.requests.length, 0);
  assert.deepEqual(engine.calls, []);

  /** @type {string[]} */
  const phases = [];
  const done = await w.session.importRun(preview, { masterPassword: PASSWORD, engine, onProgress: ({ phase }) => phases.push(phase) });
  assert.deepEqual(done, { queued: 2 });
  assert.deepEqual(phases, ["checking", "window", "queueing"]);

  // The order: a fresh sign-in, then the window, and only then does the engine get the items.
  const finish = idx(w.log, "POST /api/auth/opaque/login/finish");
  const window = idx(w.log, "POST /api/sync/import");
  const handed = idx(w.log, "engine.importItems");
  assert.ok(finish >= 0 && window > finish && handed > window, `${finish} < ${window} < ${handed}`);
  const reauth = w.requests.find((r) => r.url === "/api/auth/opaque/login/finish");
  assert.equal(reauth.body.purpose, "reauth", "it is a re-authentication");
  // The vault that is open is not touched: no unlock, no lock.
  assert.deepEqual(w.client.called("unlock_password"), []);
  assert.equal(w.client.locked, 0);

  // The window is for as many items as there are, and the engine counts against that window.
  assert.deepEqual(w.windows, [{ ops: 2 }]);
  assert.equal(engine.imported.length, 1);
  assert.equal(engine.imported[0].windowId, WINDOW);
  assert.equal(engine.imported[0].items.length, 2);
  for (const item of engine.imported[0].items) {
    assert.deepEqual(Object.keys(item).sort(), ["envelope", "id", "rev", "tag"]);
    assert.match(item.id, /^[0-9a-f]{32}$/);
    assert.equal(item.rev, 1);
    assert.ok(item.envelope instanceof Uint8Array && item.tag instanceof Uint8Array);
  }

  // The preview is spent: the same file cannot be imported twice by one preview.
  await assert.rejects(w.session.importRun(preview, { masterPassword: PASSWORD, engine }), (e) => e.code === "import_preview_gone");
  assert.equal(engine.imported.length, 1);

  // Nothing of the file was sent, and nothing is in a store outside the vault.
  const sent = JSON.stringify(w.requests);
  const stored = await dumpDatabase(w.db.store);
  for (const word of WORDS) {
    assert.ok(!sent.includes(word), `${word} was not sent`);
    assert.ok(!stored.includes(word), `${word} is not in the stores`);
  }
});

test("a_wrong_master_password_stops_before_the_window_and_the_preview_can_be_used_again", async () => {
  let wrong = true;
  const w = await importWorld({ handlers: { login_finish: () => (wrong ? Promise.reject(coded("decrypt")) : { ke3: new Uint8Array(64).fill(2), server_public_key: new Uint8Array(32).fill(9) }) } });
  const engine = fakeImportEngine({ log: w.log });
  const preview = await w.session.importPreview(fixtureFile("small.json"), { engine });
  await assert.rejects(w.session.importRun(preview, { masterPassword: "not-the-password", engine }), (e) => e.code === "decrypt");
  assert.deepEqual(w.windows, [], "no window was asked for");
  assert.deepEqual(engine.calls, []);
  wrong = false;
  assert.deepEqual(await w.session.importRun(preview, { masterPassword: PASSWORD, engine }), { queued: 2 });
  assert.equal(w.windows.length, 1);
});

test("a_window_the_server_refuses_leaves_the_preview_and_writes_nothing", async () => {
  /** @type {Array<Record<string, any> | Response>} */
  const answers = [answer(409, { error: "import_window_open" }), answer(413, { error: "quota_exceeded" }), { window_id: WINDOW, ops: 1, expires_in: 1800 }, { window_id: WINDOW, ops: 2, expires_in: 1800 }];
  const w = await importWorld({ windowFor: () => /** @type {any} */ (answers.shift()) });
  const engine = fakeImportEngine({ log: w.log });
  const preview = await w.session.importPreview(fixtureFile("small.json"), { engine });
  // Another device holds a window.
  await assert.rejects(w.session.importRun(preview, { masterPassword: PASSWORD, engine }), (e) => e.code === "import_window_open");
  // The server says the vault has no room.
  await assert.rejects(w.session.importRun(preview, { masterPassword: PASSWORD, engine }), (e) => e.code === "quota_exceeded");
  // A window for fewer operations than asked for is not enough.
  await assert.rejects(w.session.importRun(preview, { masterPassword: PASSWORD, engine }), (e) => e.code === "quota_exceeded");
  assert.deepEqual(engine.calls, [], "nothing was handed to the engine");
  // The next try, with a window that fits, goes through with the same preview.
  assert.deepEqual(await w.session.importRun(preview, { masterPassword: PASSWORD, engine }), { queued: 2 });
  assert.equal(w.windows.length, 4);
});

test("an_import_that_does_not_fit_stops_before_any_write", async () => {
  // A file that is read by the worker: the preview already says it does not fit, and the run stops before it asks anything.
  const w = await importWorld();
  const engine = fakeImportEngine({ used: 9_995, log: w.log });
  assert.deepEqual(vaultRoom(engine), { used: 9_995, free: 4 });
  const preview = await w.session.importPreview(fixtureFile("every-type.json"), { engine });
  assert.equal(preview.counts.items, 8);
  assert.equal(preview.free, 4);
  assert.equal(preview.fits, false);
  await assert.rejects(w.session.importRun(preview, { masterPassword: PASSWORD, engine }), (e) => e.code === "import_does_not_fit" && e.details.items === 8 && e.details.free === 4);
  assert.equal(w.requests.length, 0, "not even a sign-in was made");
  assert.deepEqual(engine.calls, []);

  // A full vault has no room at all.
  const full = fakeImportEngine({ used: 9_999 });
  const small = await w.session.importPreview(fixtureFile("small.json"), { engine: full });
  assert.equal(small.free, 0);
  assert.equal(small.fits, false);
  await assert.rejects(w.session.importRun(small, { masterPassword: PASSWORD, engine: full }), (e) => e.code === "import_does_not_fit");

  // An export of Ferret's is known only once it is open: it stops there, after the open items are dropped and before a window or a write.
  const core = fakeExportFileCore({ items: 12 });
  const x = await importWorld({ file: core });
  const crowded = fakeImportEngine({ used: 9_990, log: x.log });
  const exportFile = new File([new Uint8Array(64).fill(7)], "backup.ferretexport");
  const asked = await x.session.importPreview(exportFile, { engine: crowded });
  assert.equal(asked.kind, "ferretexport");
  assert.equal(asked.counts, null);
  await assert.rejects(
    x.session.importRun(asked, { masterPassword: PASSWORD, exportPassword: EXPORT_PASSWORD, engine: crowded }),
    (e) => e.code === "import_does_not_fit" && e.details.items === 12 && e.details.free === 9,
  );
  assert.deepEqual(x.windows, [], "no window was asked for");
  assert.deepEqual(crowded.calls, []);
  assert.deepEqual(core.seals, [], "nothing was sealed");
  assert.equal(core.closed, 1, "the open items were dropped");

  // The server's own answer to a window that is too big is the same refusal.
  const y = await importWorld({ windowFor: () => answer(413, { error: "quota_exceeded" }) });
  const near = fakeImportEngine({ used: 100, log: y.log });
  const mine = await y.session.importPreview(fixtureFile("small.json"), { engine: near });
  await assert.rejects(y.session.importRun(mine, { masterPassword: PASSWORD, engine: near }), (e) => e.code === "quota_exceeded");
  assert.deepEqual(near.calls, []);
});

// ------------------------------------------------------------ an export of Ferret's

test("a_ferretexport_import_seals_inside_wasm", async () => {
  const core = fakeExportFileCore({ items: 3 });
  const w = await importWorld({ file: core });
  const engine = fakeImportEngine({ log: w.log });
  const bytes = new Uint8Array(200).map((_, n) => n);
  const file = new File([bytes], "ferret-export-2026-11-20.ferretexport");
  const preview = await w.session.importPreview(file, { engine });
  // Only the header is read at this point, and no worker is started: this kind of file is not read by the import worker.
  assert.equal(preview.kind, "ferretexport");
  assert.equal(preview.counts, null);
  assert.equal(preview.createdAt, NOW);
  assert.equal(w.requests.length, 0);
  assert.deepEqual(core.headers, [200]);
  assert.equal(w.workers.made.length, 0);

  // The export password is needed, and the page sees that before it asks the server for anything.
  await assert.rejects(w.session.importRun(preview, { masterPassword: PASSWORD, engine }), (e) => e.code === "import_export_password_required");
  assert.equal(w.requests.length, 0);

  // A wrong export password is refused by the core when it opens the file: nothing is sealed, no window is asked for.
  await assert.rejects(w.session.importRun(preview, { masterPassword: PASSWORD, exportPassword: "not-the-export-password", engine }), (e) => e.code === "import_wrong_export_password");
  assert.deepEqual(w.windows, []);
  assert.deepEqual(engine.calls, []);
  assert.equal(core.closed, 0, "the core had opened nothing");
  assert.deepEqual(core.seals, []);

  /** @type {string[]} */
  const phases = [];
  const done = await w.session.importRun(preview, { masterPassword: PASSWORD, exportPassword: EXPORT_PASSWORD, engine, onProgress: ({ phase }) => phases.push(phase) });
  assert.deepEqual(done, { queued: 3 });
  assert.equal(core.closed, 1, "what the core had opened is dropped when the items are sealed");
  assert.deepEqual(phases, ["checking", "stretching", "opening", "sealing", "window", "queueing"]);

  // The key is made by the job worker from the export password for this file's header, in "open" mode (no master password).
  const job = core.jobs.at(-1);
  assert.equal(job.password, EXPORT_PASSWORD);
  assert.equal(job.mode, "open");
  assert.equal(job.masterPassword, undefined);
  assert.deepEqual(job.kdf, { m_kib: 262_144, t: 3, p: 1 });
  assert.deepEqual([...job.salt], new Array(16).fill(4));
  // The core opened the file with that key, and every item was sealed inside it: the page only chose the ids.
  const opened = core.opens.at(-1);
  assert.deepEqual([...opened.file], [...bytes]);
  assert.equal(core.seals.length, 3);
  assert.deepEqual(core.seals.map((s) => s.index), [0, 1, 2]);
  assert.ok(core.seals.every((s) => s.rev === 1 && s.id.length === 16 && !s.id.every((b) => b === 0)));
  assert.equal(new Set(core.seals.map((s) => hexOf(s.id))).size, 3, "an id for each item");
  assert.deepEqual(core.seals.map((s) => hexOf(s.id)), engine.imported[0].items.map((item) => item.id), "the engine gets the ids the core sealed under");
  assert.deepEqual(engine.imported[0].items.map((item) => [...item.envelope].slice(0, 2)), [[0xe1, 0], [0xe1, 1], [0xe1, 2]]);
  // The page never opened, read or sealed an item itself, and no worker was involved.
  for (const name of ["vault.encrypt_item", "vault.open_item", "vault.item_view", "vault.reveal_item_field"]) assert.ok(!w.log.includes(name), name);
  assert.equal(w.workers.made.length, 0);
  // The key and the file's bytes were wiped after use.
  const [openCall] = w.client.called("import_open").slice(-1);
  assert.ok(openCall.args[1].every((n) => n === 0), "the key array was wiped");
  assert.ok(openCall.args[0].every((n) => n === 0), "the copy of the file was wiped");
  // Order: the sign-in, the core opening and sealing, then the window, then the engine.
  const order = ["POST /api/auth/opaque/login/finish", "vault.import_open", "vault.import_seal", "vault.import_close", "POST /api/sync/import", "engine.importItems"].map((entry) => w.log.lastIndexOf(entry));
  assert.deepEqual([...order].sort((a, b) => a - b), order, `in order: ${order}`);
  assert.deepEqual(w.windows, [{ ops: 3 }]);
});

test("a_sealed_export_is_kept_for_a_second_try_after_a_refused_window", async () => {
  const core = fakeExportFileCore({ items: 2 });
  const answers = [answer(409, { error: "import_window_open" }), { window_id: WINDOW, ops: 2, expires_in: 1800 }];
  const w = await importWorld({ file: core, windowFor: () => /** @type {any} */ (answers.shift()) });
  const engine = fakeImportEngine({ log: w.log });
  const preview = await w.session.importPreview(new File([new Uint8Array(32)], "x.ferretexport"), { engine });
  await assert.rejects(w.session.importRun(preview, { masterPassword: PASSWORD, exportPassword: EXPORT_PASSWORD, engine }), (e) => e.code === "import_window_open");
  assert.equal(core.seals.length, 2);
  // The second try needs no export password and does not stretch the key or seal again.
  assert.deepEqual(await w.session.importRun(preview, { masterPassword: PASSWORD, engine }), { queued: 2 });
  assert.equal(core.seals.length, 2);
  assert.equal(core.jobs.length, 1);
  assert.equal(engine.imported.length, 1);
});

test("a_file_that_is_not_an_export_of_ferrets_is_refused_with_a_text_of_its_own", async () => {
  const w = await importWorld({ handlers: { import_header: () => Promise.reject(coded("malformed_export")) } });
  await assert.rejects(w.session.importPreview(new File([new Uint8Array(40)], "x.ferretexport"), { engine: fakeImportEngine() }), (e) => e.code === "import_bad_export" && e.details.reason === "malformed_export");
  // A lock that ended the vault worker is not a bad file.
  const locked = await importWorld({ handlers: { import_header: () => Promise.reject(coded("locked")) } });
  await assert.rejects(locked.session.importPreview(new File([new Uint8Array(40)], "x.ferretexport"), { engine: fakeImportEngine() }), (e) => e.code === "locked");
});

// ------------------------------------------------------- lock, timeout, previews

test("a_lock_ends_the_import_worker_and_lets_go_of_the_preview", async () => {
  const w = await importWorld({ mode: "silent" });
  const engine = fakeImportEngine();
  const pending = w.session.importPreview(fixtureFile("small.json"), { engine });
  const outcome = assert.rejects(pending, (e) => e.code === "locked");
  await settle();
  assert.equal(w.workers.made.length, 1);
  assert.equal(w.workers.made[0].terminated, false, "it is waiting for a vault worker that never answers");
  await w.session.lock();
  await outcome;
  assert.equal(w.workers.made[0].terminated, true, "the lock ended the worker");
  assert.ok(w.ports[0].closed, "and let go of the port");

  // A preview that is held when the vault locks is let go of: after the next sign-in it cannot be imported.
  const x = await importWorld();
  const engineX = fakeImportEngine();
  const held = await x.session.importPreview(fixtureFile("small.json"), { engine: engineX });
  await x.session.lock();
  await assert.rejects(x.session.importRun(held, { masterPassword: PASSWORD, engine: engineX }), (e) => e.code === "session_ended");
  await x.session.signIn({ email: EMAIL, password: PASSWORD, skBit: true, skCode: SK_CODE, rememberSk: true });
  await assert.rejects(x.session.importRun(held, { masterPassword: PASSWORD, engine: engineX }), (e) => e.code === "import_preview_gone");
  assert.deepEqual(engineX.calls, []);
  // And with the vault locked, a preview cannot be started.
  await x.session.lock();
  await assert.rejects(x.session.importPreview(fixtureFile("small.json"), { engine: engineX }), (e) => e.code === "session_ended");
});

test("a_worker_that_never_answers_is_ended_when_the_time_is_up", async () => {
  const w = await importWorld({ mode: "silent" });
  await assert.rejects(w.session.importPreview(fixtureFile("small.json"), { engine: fakeImportEngine(), timeoutMs: 30 }), (e) => e.code === "import_timeout");
  assert.equal(w.workers.made[0].terminated, true);
  assert.ok(w.ports[0].closed);
  assert.equal(w.requests.length, 0);
});

test("a_preview_that_is_discarded_cannot_be_imported", async () => {
  const w = await importWorld();
  const engine = fakeImportEngine();
  const preview = await w.session.importPreview(fixtureFile("small.json"), { engine });
  w.session.importDiscard(preview);
  await assert.rejects(w.session.importRun(preview, { masterPassword: PASSWORD, engine }), (e) => e.code === "import_preview_gone");
  assert.equal(w.requests.length, 0);
});

// -------------------------------------------- with the real engine: a reload, a closed window

/** The window the model gives for as many operations as are asked for; `limit` makes the first one smaller than it was asked for. */
function modelWindows(model, { firstLimit = null } = {}) {
  return (body, count) => {
    const id = model.openImportWindow(body.ops);
    if (count === 1 && firstLimit !== null) model.importWindows.get(id).ops = firstLimit;
    return { window_id: id, ops: body.ops, expires_in: 1800 };
  };
}

test("a_reload_during_an_import_resumes_without_duplicates", async () => {
  const model = new Model();
  const client = createFakeClient();
  const first = await syncDevice({ model, client });
  await first.engine.start();
  const w = await importWorld({ port: () => sealingPort(client), windowFor: modelWindows(model) });
  const preview = await w.session.importPreview(manyLogins(30), { engine: first.engine });
  assert.equal(preview.counts.items, 30);

  first.api.batchFaults.push({ kind: "lost" }); // the server takes the batch and the answer never comes
  await w.session.importRun(preview, { masterPassword: PASSWORD, engine: first.engine });
  await until(() => first.api.batches.length === 1 && model.items.size === 30);
  await settle(20);
  const sentFirst = JSON.parse(first.api.batches[0].text).ops.map((op) => op.idem);
  first.engine.stop();

  // The page is loaded again over the same storage: the engine finds the import in the outbox and carries it on under its own
  // window and keys, so the page asks for no second window and the server stores nothing twice.
  const second = await syncDevice({ model, client, db: first.store.database, locks: first.locks });
  second.api.batchFaults.push({ kind: "network" });
  await second.engine.start();
  assert.equal(second.engine.importStatus().queued, 30, "the import is found again");
  assert.equal(second.engine.importStatus().windowClosed, false);
  second.timers.advance(1000);
  await until(() => second.api.batches.length >= 2 && model.items.size === 30);
  await until(() => second.engine.importStatus().queued === 0, "the outbox is empty");

  const sentAgain = JSON.parse(second.api.batches.at(-1).text);
  assert.equal(sentAgain.import_window, JSON.parse(first.api.batches[0].text).import_window, "under the window it had");
  assert.deepEqual(sentAgain.ops.map((op) => op.idem), sentFirst, "under the same keys");
  assert.equal(model.items.size, 30);
  assert.equal(model.writes.length, 30, "every item was stored once");
  assert.equal(second.api.puts.length, 0);
  const windowOf = [...model.importWindows.values()][0];
  assert.equal(windowOf.used, 30, "and the replays did not use the window again");
  assert.equal(w.windows.length, 1, "no second window was asked for");
  assert.equal(w.requests.filter((r) => r.url === "/api/auth/opaque/login/finish").length, 1, "and no second sign-in");
  await until(() => second.engine.list().length === 30 && second.engine.list().every((item) => !item.pending));
  second.engine.stop();
});

test("continue_import_after_a_closed_window_needs_reauth_and_sends_only_the_rest", async () => {
  const model = new Model();
  const client = createFakeClient();
  const d = await syncDevice({ model, client });
  const closed = [];
  d.engine.on("import_window_closed", (info) => closed.push(info));
  await d.engine.start();
  // The first window holds only 100 of the 150 operations that were asked for (it ran out of time, say).
  const w = await importWorld({ port: () => sealingPort(client), windowFor: modelWindows(model, { firstLimit: 100 }) });
  const preview = await w.session.importPreview(manyLogins(150), { engine: d.engine });
  await w.session.importRun(preview, { masterPassword: PASSWORD, engine: d.engine });
  await until(() => closed.length === 1, "the server closes the window after 100");
  assert.deepEqual(closed, [{ remaining: 50 }]);
  assert.equal(model.items.size, 100);
  assert.deepEqual(d.engine.importStatus().queued, 50);
  assert.equal(d.engine.importStatus().windowClosed, true);
  const storedBefore = new Set(model.items.keys());
  const signIns = () => w.requests.filter((r) => r.url === "/api/auth/opaque/login/finish").length;
  assert.equal(signIns(), 1);

  // Nothing is sent until the user confirms: a wrong password, or none, does not open a window.
  await assert.rejects(w.session.importContinue({ masterPassword: "", engine: d.engine }), (e) => e.code === "password_required");
  assert.equal(w.windows.length, 1);
  assert.equal(model.items.size, 100);

  /** @type {string[]} */
  const phases = [];
  const done = await w.session.importContinue({ masterPassword: PASSWORD, engine: d.engine, onProgress: ({ phase }) => phases.push(phase) });
  assert.deepEqual(done, { remaining: 50 });
  assert.deepEqual(phases, ["checking", "window", "queueing"]);
  // A fresh sign-in (purpose reauth), then a new window for exactly the items that are left.
  assert.equal(signIns(), 2);
  const reauth = w.requests.filter((r) => r.url === "/api/auth/opaque/login/finish").at(-1);
  assert.equal(reauth.body.purpose, "reauth");
  assert.deepEqual(w.windows, [{ ops: 150 }, { ops: 50 }]);
  const at = (entry) => w.log.map((line, n) => (line === entry ? n : -1)).filter((n) => n >= 0);
  const [firstFinish, secondFinish] = at("POST /api/auth/opaque/login/finish");
  const [firstWindow, secondWindow] = at("POST /api/sync/import");
  assert.ok(firstFinish < firstWindow && secondFinish > firstWindow && secondFinish < secondWindow, "the second window follows the second sign-in");

  await until(() => model.items.size === 150, "the rest arrives");
  await until(() => d.engine.importStatus().queued === 0, "the rest is reported");
  assert.equal(d.engine.importStatus().sent, 150, "the count is right at the moment nothing is left");
  // Only the rest was sent with the new window, under keys the entries had; nothing went twice.
  const second = [...model.importWindows.keys()][1];
  const resent = d.api.batches.filter((batch) => batch.window === second);
  assert.deepEqual(resent.map((batch) => batch.ids.length), [50]);
  assert.ok(resent[0].ids.every((id) => !storedBefore.has(id)), "none of the 100 that were stored is in it");
  assert.equal(model.writes.length, 150);
  assert.equal(new Set(model.writes.map((write) => write.id)).size, 150);
  assert.equal(d.api.puts.length, 0);

  // With nothing left, there is nothing to confirm: no request is made.
  const before = w.requests.length;
  await assert.rejects(w.session.importContinue({ masterPassword: PASSWORD, engine: d.engine }), (e) => e.code === "import_nothing_left");
  assert.equal(w.requests.length, before);
  d.engine.stop();
});

test("an_import_file_never_reaches_a_store_a_log_or_an_address", async () => {
  const lines = [];
  const saved = { log: console.log, info: console.info, warn: console.warn, error: console.error, debug: console.debug };
  for (const name of Object.keys(saved)) console[name] = (...args) => lines.push(args.map((a) => allStrings(a).join(" ")).join(" "));
  try {
    const w = await importWorld();
    const engine = fakeImportEngine({ log: w.log });
    const preview = await w.session.importPreview(fixtureFile("small.csv"), { engine });
    await w.session.importRun(preview, { masterPassword: PASSWORD, engine });
    const stored = await dumpDatabase(w.db.store);
    for (const word of [...WORDS, "Pin: 0000", "Quoted"]) {
      assert.ok(!stored.includes(word), `${word} is not in a store`);
      assert.ok(!JSON.stringify(w.requests).includes(word), `${word} is not in a request`);
      assert.ok(!w.requests.some((r) => String(r.url).includes(word)), `${word} is not in an address`);
      assert.ok(!lines.join("\n").includes(word), `${word} was not logged`);
    }
    assert.equal(w.requests.every((r) => !String(r.url).includes("?") && !String(r.url).includes("#")), true);
  } finally {
    Object.assign(console, saved);
  }
});

test("the_import_sources_keep_nothing_in_storage_the_console_or_the_address", () => {
  for (const file of ["flows/import.mjs", "views/import.mjs", "routes/import.route.mjs"]) {
    const source = readFileSync(join(web, "src", file), "utf8");
    assert.doesNotMatch(source, /localStorage|sessionStorage|console\.|indexedDB|document\.cookie|\.innerHTML|\.outerHTML|eval\(|new Function/, file);
    assert.doesNotMatch(source, /location\s*[.=]|history\.|window\.open|navigator\.clipboard|fetch\(/, `${file} never writes the address or leaves the API client`);
  }
  // The flow never opens an item or reads a field: it only moves ciphertext, ids and counts.
  const flow = readFileSync(join(web, "src", "flows", "import.mjs"), "utf8");
  assert.doesNotMatch(flow, /open_item|item_view|reveal_|encrypt_item|import_view|JSON\.parse|\.text\(\)/);
});

test("a_new_import_beside_an_unfinished_one_asks_for_a_window_for_both", async () => {
  const w = await importWorld();
  // Seven writes of an earlier import can still be sent; the engine moves them onto the new window with the two new items.
  const engine = fakeImportEngine({ status: { queued: 7 }, log: w.log });
  const preview = await w.session.importPreview(fixtureFile("small.json"), { engine });
  await w.session.importRun(preview, { masterPassword: PASSWORD, engine });
  assert.deepEqual(w.windows, [{ ops: 9 }]);
});

test("the_page_ending_the_preview_ends_the_worker_and_keeps_nothing", async () => {
  const w = await importWorld({ mode: "silent" });
  const engine = fakeImportEngine();
  const controller = new AbortController();
  const outcome = assert.rejects(w.session.importPreview(fixtureFile("small.json"), { engine, signal: controller.signal }), (e) => e.code === "locked");
  await settle();
  assert.equal(w.workers.made[0].terminated, false, "it is waiting for the worker");
  controller.abort();
  await outcome;
  assert.equal(w.workers.made[0].terminated, true, "leaving the page ended the worker");
  assert.ok(w.ports[0].closed);
  // A signal that is aborted already starts no worker.
  const late = new AbortController();
  late.abort();
  await assert.rejects(w.session.importPreview(fixtureFile("small.json"), { engine, signal: late.signal }), (e) => e.code === "locked");
  assert.equal(w.workers.made.length, 1);

  // A preview that has arrived is not touched by a later abort of the reading; the page lets go of it with importDiscard.
  const x = await importWorld();
  const reading = new AbortController();
  const held = await x.session.importPreview(fixtureFile("small.json"), { engine, signal: reading.signal });
  reading.abort();
  assert.deepEqual(await x.session.importRun(held, { masterPassword: PASSWORD, engine }), { queued: 2 });
  // And one that was let go of cannot be imported.
  const gone = await x.session.importPreview(fixtureFile("small.json"), { engine });
  x.session.importDiscard(gone);
  await assert.rejects(x.session.importRun(gone, { masterPassword: PASSWORD, engine }), (e) => e.code === "import_preview_gone");
});
