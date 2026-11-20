// The export flows (spec Fase 1 § 6.4): the encrypted file and the plain copy, over a fake core and a fake server, with the
// real local stores. The cipher, the Argon2id cost and the CSV rule are the core's and are tested there; these tests check
// what the page does around them: the order of the calls, what it refuses before anything is sent, what it passes on, and
// what it wipes.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { EXPORT_KDF, exportReadiness, refreshReadiness } from "../../src/flows/export.mjs";
import { dumpDatabase, until, wiped } from "./accountHelpers.mjs";
import { BODIES, EXPORT_PASSWORD, GRANT, ID_A, ID_B, ID_C, ID_GONE, MANIFEST, PASSWORD, coded, exportWorld, filled, recordingDownload } from "./exportHelpers.mjs";
import { web } from "./helpers.mjs";

const dec = new TextDecoder();
const deferred = () => {
  let resolve;
  const promise = new Promise((a) => {
    resolve = a;
  });
  return { promise, resolve };
};
const idx = (log, entry) => log.findIndex((line) => line === entry);
const args = (extra = {}) => ({ masterPassword: PASSWORD, exportPassword: EXPORT_PASSWORD, exportPasswordAgain: EXPORT_PASSWORD, ...extra });

// ------------------------------------------------------------- the encrypted export

test("export_needs_fresh_reauth_and_an_export_password_of_12_or_more_typed_twice", async () => {
  const w = await exportWorld();
  const { files, download } = recordingDownload();
  /** A refusal that the page sees: no request, no call to the core, no file. */
  const refused = async (extra, code) => {
    await assert.rejects(w.session.exportEncrypted({ ...args(extra), download }), (error) => error.code === code);
    assert.equal(w.requests.length, 0, `${code}: nothing was sent`);
    assert.deepEqual(w.core.calls, [], `${code}: the core was not asked`);
    assert.equal(files.length, 0);
  };
  await refused({ exportPasswordAgain: `${EXPORT_PASSWORD}x` }, "password_mismatch");
  await refused({ exportPassword: "short-pw-11", exportPasswordAgain: "short-pw-11" }, "input_too_short");
  await refused({ exportPassword: "", exportPasswordAgain: "" }, "password_required");
  await refused({ masterPassword: "" }, "password_required");

  // Exactly 12 characters is enough, and a fresh sign-in comes before the core opens a single row.
  const twelve = "twelve-chars";
  assert.equal(twelve.length, 12);
  const done = await w.session.exportEncrypted({ ...args({ exportPassword: twelve, exportPasswordAgain: twelve }), download });
  assert.equal(done.items, 3);
  const finish = idx(w.log, "POST /api/auth/opaque/login/finish");
  const begin = idx(w.log, "vault.export_begin");
  assert.ok(finish >= 0 && begin > finish, "the sign-in is finished before the rows are opened");
  const reauth = w.requests.find((r) => r.url === "/api/auth/opaque/login/finish");
  assert.equal(reauth.body.purpose, "reauth", "it is a re-authentication");
  assert.equal(files.length, 1);

  // A wrong master password stops at the sign-in: nothing is opened and no file is made.
  const wrong = await exportWorld({ handlers: { login_finish: () => Promise.reject(coded("decrypt")) } });
  const second = recordingDownload();
  await assert.rejects(wrong.session.exportEncrypted({ ...args(), download: second.download }), (error) => error.code === "decrypt");
  assert.deepEqual(wrong.core.calls, []);
  assert.equal(second.files.length, 0);
});

test("an_export_password_equal_to_the_master_password_is_refused_by_the_core", async () => {
  const w = await exportWorld();
  const { files, download } = recordingDownload();
  await assert.rejects(
    w.session.exportEncrypted({ ...args({ exportPassword: PASSWORD, exportPasswordAgain: PASSWORD }), download }),
    (error) => error.code === "input_same_as_master_password",
  );
  // The page does not decide this: it hands the master password to the core's write mode, which compares.
  assert.equal(w.core.jobArgs.mode, "write");
  assert.equal(w.core.jobArgs.masterPassword, PASSWORD);
  assert.equal(w.core.jobArgs.password, PASSWORD);
  assert.equal(files.length, 0);
  assert.equal(w.core.aborted, 1, "the draft the core held is dropped");
  assert.ok(!w.core.calls.some(([name]) => name === "export_finish"));
  // No date was kept for an export that was not made.
  assert.equal((await w.store.exportReminder.status(w.db, w.session.serverUrl, w.scope.accountId, 1_800_000_000_000)).lastExportAt, null);
});

test("export_uses_256_mib_and_three_passes", async () => {
  assert.deepEqual({ ...EXPORT_KDF }, { m_kib: 262_144, t: 3, p: 1 });
  assert.equal(EXPORT_KDF.m_kib, 256 * 1024, "256 MiB in KiB");
  const w = await exportWorld();
  const { download } = recordingDownload();
  await w.session.exportEncrypted({ ...args(), download });
  const begin = w.core.calls.find(([name]) => name === "export_begin");
  assert.deepEqual(begin[3], { m_kib: 262_144, t: 3, p: 1 }, "the page asks for the cost itself");
  const job = w.core.calls.find(([name]) => name === "argon2_export_key");
  assert.deepEqual(job[1], { m_kib: 262_144, t: 3, p: 1 });
  assert.equal(job[2], "write");

  // A core that answered with a weaker cost does not get a file out of the page.
  for (const weaker of [{ m_kib: 65_536, t: 3, p: 1 }, { m_kib: 262_144, t: 2, p: 1 }, { m_kib: 262_144, t: 3, p: 0 }]) {
    const low = await exportWorld({ begunKdf: weaker });
    const kept = recordingDownload();
    await assert.rejects(low.session.exportEncrypted({ ...args(), download: kept.download }), (error) => error.code === "kdf_out_of_range");
    assert.ok(!low.core.calls.some(([name]) => name === "argon2_export_key"), "no key is made for a weak cost");
    assert.equal(low.core.aborted, 1);
    assert.equal(kept.files.length, 0);
  }
});

test("progress_is_shown_while_the_key_is_stretched", async () => {
  const gate = deferred();
  const w = await exportWorld({ jobGate: gate.promise });
  const { files, download } = recordingDownload();
  const seen = [];
  const pending = w.session.exportEncrypted({ ...args(), download, onProgress: (progress) => seen.push({ ...progress }) });
  // The key is being made: the page has said so, and nothing later has happened.
  await until(() => seen.some((p) => p.phase === "stretching"));
  assert.deepEqual(seen.map((p) => p.phase), ["checking", "reading", "stretching"]);
  assert.equal(seen[1].items, 3);
  assert.equal(files.length, 0, "no file while the key is made");
  gate.resolve();
  await pending;
  assert.deepEqual(seen.map((p) => p.phase), ["checking", "reading", "stretching", "sealing", "saving"]);
  // A progress message says where it is and never what was typed.
  const text = JSON.stringify(seen);
  assert.ok(!text.includes(PASSWORD) && !text.includes(EXPORT_PASSWORD));
});

test("an_export_with_unsent_writes_or_behind_the_top_warns_first", async () => {
  const engine = (items, health = { halted: null, warnings: [] }) => ({ list: () => items, health: () => health });
  const idle = [{ id: "a", pending: false, blocked: false, conflict: false, missingOnServer: false }];
  assert.deepEqual(exportReadiness(engine(idle)), { pendingWrites: 0, atTop: true });
  // Items with something the server has not accepted: waiting, refused, in conflict, being uploaded again.
  const unsent = [
    { id: "a", pending: true },
    { id: "b", blocked: true },
    { id: "c", conflict: true },
    { id: "d", missingOnServer: true },
    { id: "e", pending: false },
  ];
  assert.equal(exportReadiness(engine(unsent)).pendingWrites, 4);
  // Behind the top: a stop, a standing warning, or a last pass that did not end well.
  assert.equal(exportReadiness(engine(idle, { halted: "server_restored", warnings: [] })).atTop, false);
  assert.equal(exportReadiness(engine(idle, { halted: null, warnings: ["verify_deferred"] })).atTop, false);
  assert.equal(exportReadiness(engine(idle), { lastState: "offline" }).atTop, false);
  assert.equal(exportReadiness(engine(idle), { lastState: "failed" }).atTop, false);
  assert.equal(exportReadiness(engine(idle), { lastState: "idle" }).atTop, true);

  // `refreshReadiness` reads the feed once more and listens to the engine for that pass only.
  const live = (outcome) => {
    const listeners = new Set();
    return {
      listeners,
      list: () => idle,
      health: () => ({ halted: null, warnings: [] }),
      on: (event, fn) => {
        assert.equal(event, "state");
        listeners.add(fn);
        return () => listeners.delete(fn);
      },
      syncNow: async () => {
        for (const fn of [...listeners]) fn({ kind: "syncing" });
        for (const fn of [...listeners]) fn({ kind: outcome });
      },
    };
  };
  const good = live("idle");
  assert.deepEqual(await refreshReadiness(good), { pendingWrites: 0, atTop: true });
  assert.equal(good.listeners.size, 0, "the listener is gone");
  const off = live("offline");
  assert.equal((await refreshReadiness(off)).atTop, false);
  // A pass that never ends is not "at the top" either, and does not hold the page.
  const stuck = { ...live("idle"), syncNow: () => new Promise(() => {}) };
  assert.equal((await refreshReadiness(stuck, { timeoutMs: 5 })).atTop, false);
  const broken = { ...live("idle"), syncNow: () => Promise.reject(new Error("x")) };
  assert.equal((await refreshReadiness(broken)).atTop, false);
});

test("the_file_round_trips_through_import_open_with_the_same_items", async () => {
  const w = await exportWorld();
  const { files, download } = recordingDownload();
  const done = await w.session.exportEncrypted({ ...args(), download });
  assert.equal(done.items, 3);
  assert.equal(files.length, 1);
  assert.match(files[0].name, /^ferret-export-\d{4}-\d{2}-\d{2}\.ferretexport$/);
  assert.equal(files[0].mime, "application/octet-stream");
  // Opened again with the key the export password makes: the same three items, and not the manifest or the deleted one.
  const opened = await w.client.vault.import_open(files[0].copy, filled(32, 9));
  assert.equal(opened.count, 3);
  const ids = w.core.imported.map((item) => item.id).sort();
  assert.deepEqual(ids, [ID_A, ID_B, ID_C]);
  assert.ok(!ids.includes(MANIFEST) && !ids.includes(ID_GONE));
  for (const item of w.core.imported) assert.deepEqual(item.body, BODIES[item.id]);
  // The revision the server holds goes into the core with each row.
  const rows = w.core.calls.find(([name]) => name === "export_begin");
  assert.equal(rows[1], 3);
});

test("the_file_and_the_key_are_wiped_after_the_download", async () => {
  const w = await exportWorld();
  const { files, download } = recordingDownload();
  await w.session.exportEncrypted({ ...args(), download });
  assert.ok(files[0].copy.some((n) => n !== 0), "the download got a real file");
  assert.ok(wiped(files[0].bytes), "the array the file was made in is zero afterwards");
  assert.ok(wiped(w.core.lastKey), "so is the key");

  // The same when the download itself fails.
  const failing = await exportWorld();
  let given = null;
  await assert.rejects(
    failing.session.exportEncrypted({
      ...args(),
      download: (bytes) => {
        given = bytes;
        throw new Error("the browser refused");
      },
    }),
  );
  assert.ok(given !== null && wiped(given));
  assert.ok(wiped(failing.core.lastKey));
  // A refusal in the middle: the key made so far is wiped, the draft is dropped, and a vault that a lock has ended is not called again.
  const stuck = await exportWorld({ jobFails: coded("kdf_out_of_memory") });
  await assert.rejects(stuck.session.exportEncrypted({ ...args(), download }), (error) => error.code === "kdf_out_of_memory");
  assert.equal(stuck.core.aborted, 1);
  const locked = await exportWorld({ jobFails: coded("locked") });
  await assert.rejects(locked.session.exportEncrypted({ ...args(), download }), (error) => error.code === "locked");
  assert.equal(locked.core.aborted, 0, "no new worker is started for a draft that went with the old one");
  // Nothing the user typed or the file held reached a store.
  const dump = await dumpDatabase(w.db);
  for (const secret of [PASSWORD, EXPORT_PASSWORD]) assert.ok(!dump.includes(secret), secret);
});

test("an_item_that_does_not_open_stops_the_export_and_leaves_no_file", async () => {
  const w = await exportWorld({ extraRows: [{ itemId: "55".repeat(16), rev: 1, seq: 9, deleted: false, envelope: new TextEncoder().encode("DAMAGED"), tag: filled(32, 5), tomb: null }] });
  const { files, download } = recordingDownload();
  await assert.rejects(w.session.exportEncrypted({ ...args(), download }), (error) => error.code === "export_item_unreadable");
  assert.equal(files.length, 0);
  assert.equal(w.core.aborted, 0, "no draft was begun");
  // A wrong master password is `decrypt`; an unreadable item is not mistaken for it.
});

test("an_empty_vault_is_not_exported_and_costs_no_sign_in", async () => {
  const w = await exportWorld();
  await w.store.cache.removeRows(w.db, w.scope, [ID_A, ID_B, ID_C]);
  const { files, download } = recordingDownload();
  await assert.rejects(w.session.exportEncrypted({ ...args(), download }), (error) => error.code === "nothing_to_export");
  assert.equal(w.requests.length, 0);
  assert.equal(files.length, 0);
});

test("the_reminder_date_is_kept_by_an_encrypted_export_and_not_by_a_plain_one", async () => {
  const w = await exportWorld();
  const { download } = recordingDownload();
  const before = await w.store.exportReminder.status(w.db, w.session.serverUrl, w.scope.accountId, 1_700_000_000_000);
  assert.equal(before.lastExportAt, null);
  await w.session.exportPlain({ masterPassword: PASSWORD, format: "json", confirmed: true, download });
  assert.equal((await w.store.exportReminder.status(w.db, w.session.serverUrl, w.scope.accountId, 1_700_000_000_000)).lastExportAt, null, "a plain export is not a backup");
  await w.session.exportEncrypted({ ...args(), download });
  const after = await w.store.exportReminder.status(w.db, w.session.serverUrl, w.scope.accountId, Date.now());
  assert.ok(after.lastExportAt !== null && after.lastExportAt > 1_700_000_000_000);
});

// ----------------------------------------------------------------- the plain export

test("plain_export_needs_two_confirmations_and_a_fresh_grant", async () => {
  const w = await exportWorld();
  const { files, download } = recordingDownload();
  // Without an explicit `true` nothing happens: no sign-in, no call to the core.
  for (const confirmed of [undefined, false, "yes", 1, null]) {
    await assert.rejects(
      w.session.exportPlain({ masterPassword: PASSWORD, format: "json", confirmed, download }),
      (error) => error.code === "plain_not_confirmed",
    );
  }
  assert.equal(w.requests.length, 0);
  assert.deepEqual(w.core.calls, []);
  await assert.rejects(w.session.exportPlain({ masterPassword: PASSWORD, format: "xml", confirmed: true, download }), (error) => error.code === "invalid_input");
  await assert.rejects(w.session.exportPlain({ masterPassword: "", format: "json", confirmed: true, download }), (error) => error.code === "password_required");
  assert.equal(w.requests.length, 0);

  // The grant comes from a fresh sign-in made for it, and is the one the core is given, once.
  await w.session.exportPlain({ masterPassword: PASSWORD, format: "json", confirmed: true, download });
  const login = idx(w.log, "POST /api/auth/opaque/login/finish");
  const grant = idx(w.log, "vault.reauth_grant");
  const reveal = idx(w.log, "vault.reveal_plain_export");
  assert.ok(login >= 0 && grant > login && reveal > grant, "sign-in, then the grant, then the plain text");
  assert.deepEqual([...w.core.reveals[0].token], [...GRANT]);
  assert.equal(files.length, 1);
  assert.equal(files[0].mime, "application/json");
  assert.match(files[0].name, /^ferret-plain-export-\d{4}-\d{2}-\d{2}\.json$/);
  // The grant array that was held is wiped, and so are the bytes of the file.
  assert.ok(wiped(files[0].bytes));

  // A grant that the core does not accept (already used, replaced, too old) is `reauth_required`, and no file is made.
  const stale = await exportWorld({ handlers: { reauth_grant: () => filled(32, 77) } });
  const none = recordingDownload();
  await assert.rejects(stale.session.exportPlain({ masterPassword: PASSWORD, format: "csv", confirmed: true, download: none.download }), (error) => error.code === "reauth_required");
  assert.equal(none.files.length, 0);
  // No grant from the sign-in: the flow does not go on without one.
  const missing = await exportWorld({ handlers: { reauth_grant: () => undefined } });
  await assert.rejects(missing.session.exportPlain({ masterPassword: PASSWORD, format: "csv", confirmed: true, download: none.download }), (error) => error.code === "reauth_required");
  assert.ok(!missing.core.calls.some(([name]) => name === "reveal_plain_export"));
  // A wrong master password stops at the sign-in.
  const wrong = await exportWorld({ handlers: { login_finish: () => Promise.reject(coded("decrypt")) } });
  await assert.rejects(wrong.session.exportPlain({ masterPassword: PASSWORD, format: "json", confirmed: true, download: none.download }), (error) => error.code === "decrypt");
  assert.deepEqual(wrong.core.calls, []);
});

test("plain_csv_neutralizes_formulas", async () => {
  // The rule is the core's (`crates/ferret-core/tests/export.rs`, `plain_csv_neutralizes_formulas`); the page hands over
  // what the core wrote, byte for byte, and writes no CSV of its own.
  const w = await exportWorld();
  const { files, download } = recordingDownload();
  await w.session.exportPlain({ masterPassword: PASSWORD, format: "csv", confirmed: true, download });
  assert.equal(files[0].mime, "text/csv");
  assert.match(files[0].name, /\.csv$/);
  const text = dec.decode(files[0].copy);
  assert.ok(text.includes("'=cmd|' /C calc'!A0"), "the formula cell has its apostrophe");
  assert.ok(text.includes("'+bob"));
  assert.ok(!/(^|\n)=cmd/.test(text) && !/,\+bob/.test(text));
  assert.equal(w.core.reveals[0].format, "csv");
  const source = readFileSync(join(web, "src", "flows", "export.mjs"), "utf8");
  assert.doesNotMatch(source, /replace\(|split\(","\)|join\(","\)/, "no CSV is built or edited in the flow");
});

test("passkeys_are_left_out_unless_asked_for", async () => {
  const { download } = recordingDownload();
  const asked = async (format, include) => {
    const w = await exportWorld();
    await w.session.exportPlain({ masterPassword: PASSWORD, format, ...(include === undefined ? {} : { includePasskeys: include }), confirmed: true, download });
    return w.core.reveals[0].includePasskeys;
  };
  assert.equal(await asked("json"), false, "not asked for: left out");
  assert.equal(await asked("json", false), false);
  assert.equal(await asked("json", "yes"), false, "only an explicit true counts");
  assert.equal(await asked("json", true), true);
  assert.equal(await asked("csv", true), false, "CSV never has them, whatever is asked");
  assert.equal(await asked("csv"), false);
  // What the core did with the flag is in the text: the passkey key is in the JSON only when asked for.
  const left = await exportWorld();
  const keep = recordingDownload();
  await left.session.exportPlain({ masterPassword: PASSWORD, format: "json", confirmed: true, download: keep.download });
  assert.ok(!dec.decode(keep.files[0].copy).includes("private-test-bytes"));
  const withKeys = await exportWorld();
  const more = recordingDownload();
  await withKeys.session.exportPlain({ masterPassword: PASSWORD, format: "json", includePasskeys: true, confirmed: true, download: more.download });
  assert.ok(dec.decode(more.files[0].copy).includes("private-test-bytes"));
});

test("the_export_flows_keep_nothing_in_storage_the_console_or_the_address", () => {
  for (const file of ["flows/export.mjs", "views/export.mjs", "routes/export.route.mjs"]) {
    const source = readFileSync(join(web, "src", file), "utf8");
    assert.doesNotMatch(source, /localStorage|sessionStorage|console\.|indexedDB|document\.cookie|\.innerHTML|\.outerHTML|eval\(|new Function/, file);
    assert.doesNotMatch(source, /location\s*[.=]|history\.|window\.open|navigator\.clipboard|fetch\(/, `${file} never writes the address or leaves the API client`);
  }
});
