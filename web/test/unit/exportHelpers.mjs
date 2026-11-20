// Helpers for the export tests: a fake core that "seals" an export as plain JSON (the real cipher is the core's, tested
// there), a signed-in world whose cache holds rows for it, and a download that keeps a copy of what it was given.
// Every value here is a test value; none is a real key, password or item.
import { hex16 } from "../../src/b64.mjs";
import { coded } from "./accountHelpers.mjs";
import { ACCOUNT, EMAIL, PASSWORD, filled, signedInWorld, GRANT, answer } from "./securityHelpers.mjs";

export { ACCOUNT, EMAIL, PASSWORD, GRANT, answer, coded, filled };

export const EXPORT_PASSWORD = "export-pass-for-unit-tests-1";
export const ID_A = "11".repeat(16);
export const ID_B = "22".repeat(16);
export const ID_C = "33".repeat(16);
export const ID_GONE = "44".repeat(16);
export const MANIFEST = "00".repeat(16);

const enc = new TextEncoder();
const dec = new TextDecoder();
const same = (a, b) => a.length === b.length && a.every((n, i) => n === b[i]);

/** The bodies the test items have; the fake core "opens" a row by reading its envelope as JSON. */
export const BODIES = Object.freeze({
  [ID_A]: { item_type: "login", name: "Mail", fields: [{ id: "username", kind: "text", value: "ada" }, { id: "password", kind: "password", value: "pw-one" }] },
  [ID_B]: { item_type: "login", name: "=cmd|' /C calc'!A0", fields: [{ id: "username", kind: "text", value: "+bob" }, { id: "password", kind: "password", value: "pw-two" }] },
  [ID_C]: { item_type: "note", name: "Passkey holder", fields: [], passkey: { cred_id: "cred", priv: "private-test-bytes" } },
});

const rowOf = (id, rev, seq, body) => ({ itemId: id, rev, seq, deleted: false, envelope: enc.encode(JSON.stringify(body)), tag: filled(32, 5), tomb: null });

/**
 * The fake core's export methods and its job worker, with a record of every call. `vault` holds the handlers for
 * `signedInWorld`; `job` replaces `client.job`.
 */
export function fakeExportCore({ jobGate = null, begunKdf = null, jobFails = null, grant = GRANT } = {}) {
  const calls = [];
  /** @type {{ rows: any[], kdf: any } | null} */
  let draft = null;
  let grantUsed = false;
  const core = {
    calls,
    /** The key array the last `export_finish` was given: the flow must have wiped it by the end. */
    lastKey: null,
    /** What `reveal_plain_export` was given. */
    reveals: [],
    begins: [],
    aborted: 0,
    vault: {
      // Each fresh sign-in makes a new one-time grant (the same bytes, so that tests can compare).
      reauth_grant() {
        grantUsed = false;
        return new Uint8Array(grant);
      },
      export_begin(rows, now, kdf, token) {
        calls.push(["export_begin", rows.length, now, kdf]);
        core.begins.push({ token: token?.slice() ?? null });
        // The core's gate: only the vault's one-time grant starts an export, and one attempt uses it up.
        const ok = !grantUsed && token instanceof Uint8Array && same(token, grant);
        grantUsed = true;
        if (!ok) throw coded("reauth_required");
        for (const row of rows) {
          if (new TextDecoder().decode(row.envelope).startsWith("DAMAGED")) throw coded("decrypt");
        }
        draft = { rows, kdf: begunKdf ?? kdf };
        return { salt: filled(16, 4), kdf: begunKdf ?? kdf };
      },
      export_finish(key) {
        calls.push(["export_finish", key.length]);
        core.lastKey = key;
        if (draft === null) throw coded("invalid_input");
        if (key.every((n) => n === 0)) throw coded("input_all_zero");
        const items = draft.rows.map((row) => ({ id: hex16.encode(row.item_id), rev: row.rev, body: JSON.parse(dec.decode(row.envelope)) }));
        const file = enc.encode(JSON.stringify({ magic: "fake-ferretexport", kdf: draft.kdf, key: [...key], items }));
        draft = null;
        return file;
      },
      // What the page uses to find the rows that do not open (no secret comes back, no grant is spent).
      open_item(id, rev, envelope) {
        calls.push(["open_item"]);
        if (new TextDecoder().decode(envelope).startsWith("DAMAGED")) throw coded("decrypt");
        return 1;
      },
      close_item() {
        calls.push(["close_item"]);
      },
      export_abort() {
        calls.push(["export_abort"]);
        core.aborted += 1;
        draft = null;
      },
      reveal_plain_export(rows, format, includePasskeys, token, now) {
        calls.push(["reveal_plain_export", rows.length, format, includePasskeys, token.length, now]);
        core.reveals.push({ rows, format, includePasskeys, token: token.slice() });
        // One attempt per token, and only the token of the grant.
        const ok = !grantUsed && same(token, grant);
        grantUsed = true;
        if (!ok) throw coded("reauth_required");
        if (new TextDecoder().decode(rows[0].envelope).startsWith("DAMAGED")) throw coded("decrypt");
        const items = rows.map((row) => ({ id: hex16.encode(row.item_id), body: JSON.parse(dec.decode(row.envelope)) }));
        if (format === "json") {
          return JSON.stringify({ items: items.map(({ id, body }) => (includePasskeys || !body.passkey ? { id, ...body } : { id, ...body, passkey: undefined })) });
        }
        // The rule of the core (spec Fase 1 § 6.4): a cell that starts with = + - @ tab or CR gets an apostrophe.
        const cell = (text) => (/^[=+\-@\t\r]/.test(text) ? `'${text}` : text);
        return ["name,username", ...items.map(({ body }) => `${cell(body.name)},${cell(body.fields.find((f) => f.id === "username")?.value ?? "")}`)].join("\n");
      },
      // What an import does with a file: only for the round trip test.
      import_open(file, key) {
        const parsed = JSON.parse(dec.decode(file));
        if (parsed.magic !== "fake-ferretexport" || !same(Uint8Array.from(parsed.key), key)) throw coded("decrypt");
        core.imported = parsed.items;
        return { count: parsed.items.length, created_at: 1 };
      },
    },
    job: {
      async argon2_export_key(password, salt, kdf, mode, masterPassword) {
        calls.push(["argon2_export_key", kdf, mode]);
        core.jobArgs = { password, salt, kdf, mode, masterPassword };
        if (jobGate) await jobGate;
        if (jobFails) throw jobFails;
        if (mode === "write") {
          if ([...password].length < 12) throw coded("input_too_short");
          // The core compares the two in constant time before it spends any memory.
          if (password === masterPassword) throw coded("input_same_as_master_password");
        }
        return filled(32, 9);
      },
    },
  };
  return core;
}

/**
 * A signed-in world with a fake export core, and rows in the cache: three live items, the unlock-method manifest row and
 * a deleted item (a tombstone), as a synced vault holds them.
 * @param {Parameters<typeof fakeExportCore>[0] & { skBit?: boolean, handlers?: object, extraRows?: any[] }} [options]
 */
export async function exportWorld({ skBit = true, handlers = {}, extraRows = [], reauthUntil = null, ...coreOptions } = {}) {
  const core = fakeExportCore(coreOptions);
  const world = await signedInWorld({
    skBit,
    reauthUntil,
    handlers: { reauth_grant: () => new Uint8Array(GRANT), ...core.vault, ...handlers },
  });
  world.client.job = core.job;
  const open = world.session.current();
  const scope = { accountId: open.accountId, vaultId: open.vaultId, vkEpoch: open.vkEpoch };
  const db = await world.store.open();
  await world.store.cache.putRows(db, scope, [
    rowOf(ID_A, 3, 5, BODIES[ID_A]),
    rowOf(ID_B, 1, 6, BODIES[ID_B]),
    rowOf(ID_C, 2, 7, BODIES[ID_C]),
    { itemId: MANIFEST, rev: 4, seq: 2, deleted: false, envelope: filled(80, 4), tag: filled(32, 5), tomb: null },
    { itemId: ID_GONE, rev: 2, seq: 8, deleted: true, envelope: null, tag: null, tomb: filled(40, 6) },
    ...extraRows,
  ]);
  world.client.calls.length = 0;
  world.log.length = 0;
  world.requests.length = 0;
  core.calls.length = 0;
  return { ...world, core, scope, db };
}

/** A download that keeps a copy of what it was given, and the array itself (the flow wipes that one afterwards). */
export function recordingDownload() {
  /** @type {Array<{ bytes: Uint8Array, copy: Uint8Array, name: string, mime: string }>} */
  const files = [];
  const download = (bytes, name, mime) => {
    files.push({ bytes, copy: bytes.slice(), name, mime });
  };
  return { files, download };
}

export { rowOf };
