// The extension's write path (extension/src/background/offerWrite.mjs) over
// the real core: passwords are compared inside WASM and never read out, a new
// login opens with the web vault's fields, and an update changes the password
// and nothing else of the item (fields, folders, one-time code, passkey, notes,
// addresses and keys the core does not know stay as they were), with the old
// password in the item's history. The engine here is a small stand-in that
// seals and opens through the core as the sync engine does.
// Run: node --test tests/node/offerWrite.test.mjs (against pkg-node-test).
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { test } from "node:test";
import { createOfferWriter, PASSWORD_FIELD } from "../../extension/src/background/offerWrite.mjs";
import { NO_EXISTING, NOW, enc, fill, newAccount, passkeyCreate, reauthToken, row, wasm } from "./helpers.mjs";

const PAGE_URL = "https://login.example.net/signin";
const ORIGIN = "https://login.example.net";
const OLD = "Old-pässword-of-the-item";
const NEW = "New-password-typed-in-the-form";

const CALLER = { origin: "https://login.example.net", top_origin_is_same: true };
const UV = { user_present: true, user_verified: true };
const CREATE = {
  challenge: fill(32, 9),
  rp_id: "login.example.net",
  rp_name: "Example",
  user_id: fill(8, 1),
  user_name: "ola",
  user_display_name: "Ola",
  algorithms: [-7],
  exclude: [],
  user_verification: "preferred",
  prf: {},
};

/** @param {Uint8Array} bytes */
const hex = (bytes) => Buffer.from(bytes).toString("hex");

/** A minimal CBOR encoder for a hand-made body (short texts and small numbers). */
function cbor(value) {
  const head = (major, n) => (n < 24 ? [(major << 5) | n] : [(major << 5) | 24, n]);
  if (typeof value === "number") return head(0, value);
  if (typeof value === "boolean") return [value ? 0xf5 : 0xf4];
  if (typeof value === "string") {
    const bytes = enc.encode(value);
    return [...head(3, bytes.length), ...bytes];
  }
  if (Array.isArray(value)) return [...head(4, value.length), ...value.flatMap(cbor)];
  return [...head(5, Object.keys(value).length), ...Object.entries(value).flatMap(([k, v]) => [...cbor(k), ...cbor(v)])];
}

/**
 * The part of the sync engine the writer uses, over the real core: rows sealed by the core, opened by the core, an
 * edit sealed from the open item with the draft (as the engine's `update` does).
 * @param {any} vault
 */
function realEngine(vault) {
  /** @type {Map<string, { idBytes: Uint8Array, rev: number, envelope: Uint8Array, tag: Uint8Array }>} */
  const rows = new Map();
  let clock = NOW;
  const put = (idBytes, sealed) => rows.set(hex(idBytes), { idBytes, rev: sealed.rev, envelope: sealed.envelope, tag: sealed.tag });
  const openRow = (r) => vault.open_item(r.idBytes.slice(), r.rev, r.envelope, r.tag);
  return {
    rows,
    put,
    list() {
      return [...rows.entries()].map(([id, r]) => {
        const h = openRow(r);
        try {
          const view = vault.item_view(h);
          return {
            id, rev: r.rev, name: view.name, username: view.fields.find((f) => f.id === "username")?.value ?? "",
            urls: view.urls.map((u) => u.url), folders: view.folders, readOnly: view.read_only, pending: false,
          };
        } finally {
          vault.close_item(h);
        }
      });
    },
    async open(id) {
      const handle = openRow(rows.get(id));
      const view = vault.item_view(handle);
      return { handle, view, close: async () => vault.close_item(handle) };
    },
    async create(draft) {
      const idBytes = new Uint8Array(randomBytes(16));
      clock += 1;
      put(idBytes, vault.encrypt_item(idBytes.slice(), 1, draft, undefined, clock));
      return hex(idBytes);
    },
    async update(id, draft, expectedRev) {
      const r = rows.get(id);
      if (r.rev !== expectedRev) throw Object.assign(new Error("item_changed"), { code: "item_changed" });
      const h = openRow(r);
      try {
        clock += 1;
        put(r.idBytes, vault.encrypt_item(r.idBytes.slice(), r.rev + 1, draft, h, clock));
      } finally {
        vault.close_item(h);
      }
    },
  };
}

/** The functions of the binding that are not methods of a vault (the worker client offers them on `vault`). */
const PAGE_FUNCTIONS = ["page_origin", "display_host", "same_site"];

/**
 * The core as the worker client shows it to the background, behind a spy that notes every method asked for (and the
 * field id of a comparison).
 * @param {any} vault
 */
function spied(vault) {
  /** @type {Array<{ method: string, field?: string }>} */
  const asked = [];
  const proxy = new Proxy(vault, {
    get(target, method) {
      const value = PAGE_FUNCTIONS.includes(String(method)) ? wasm[method] : target[method];
      if (typeof value !== "function") return value;
      return (...args) => {
        asked.push({ method: String(method), ...(String(method).includes("field") ? { field: args[1] } : {}) });
        return PAGE_FUNCTIONS.includes(String(method)) ? value(...args) : value.apply(target, args);
      };
    },
  });
  return { proxy, asked };
}

/** A captured form for the page. @param {Record<string, unknown>} [over] */
const capture = (over = {}) => ({
  tabId: 1, frameId: 0, frameUrl: PAGE_URL, origin: ORIGIN, kind: "login", username: "ola", usernameFrom: "typed",
  password: NEW, currentPassword: null, generated: false, ...over,
});

/** A login sealed by the core for the engine. */
function seal(vault, engine, n, draft) {
  const idBytes = fill(16, n);
  engine.put(idBytes, vault.encrypt_item(idBytes.slice(), 1, { item_type: "login", ...draft }, undefined, NOW));
  return hex(idBytes);
}

const field = (id, kind, value, label = id) => ({ id, label, kind, value });

/** The whole stored body of an item, read with a fresh re-authentication (the plain export). */
function bodyOf(account, engine, id) {
  const r = engine.rows.get(id);
  const text = account.vault.reveal_plain_export([row(r.idBytes, r)], "json", false, reauthToken(account), NOW);
  return JSON.parse(text).items[0].body;
}

test("classify_compares_passwords_in_the_real_core_and_never_reveals_them", async () => {
  const account = newAccount("offer-classify");
  const { vault } = account;
  const engine = realEngine(vault);
  const mine = seal(vault, engine, 1, { name: "Mine", fields: [field("username", "text", "ola"), field("password", "password", OLD)], urls: [{ url: ORIGIN, matching: "host" }] });
  seal(vault, engine, 2, { name: "Shop", fields: [field("username", "text", "x"), field("password", "password", NEW)], urls: [{ url: "https://shop.example.org", matching: "host" }] });
  // An AliasVault import with a second password under `password-2`: only the field `password` is compared.
  const imported = seal(vault, engine, 3, { name: "Imported", fields: [field("email", "email", "kari@example.net"), field("password-2", "password", NEW)], urls: [{ url: ORIGIN, matching: "host" }] });
  const { proxy, asked } = spied(vault);
  const writer = createOfferWriter({ engine, liveClient: { vault: proxy } });

  const c = await writer.classify(capture());
  assert.equal(c.action, "update");
  assert.deepEqual(c.targets.map((t) => [t.id, t.how]), [[mine, "username"]]);
  assert.deepEqual(c.reused, [{ name: "Shop", host: { a_label: "shop.example.org", unicode: "shop.example.org" } }]);
  // The current password of a change form, compared in the core.
  const change = await writer.classify(capture({ kind: "change", username: null, usernameFrom: null, currentPassword: OLD }));
  assert.deepEqual(change.targets.map((t) => [t.id, t.how]), [[mine, "current_password"]]);
  // `password-2` holds the typed value, but it is no saved password: the item is matched by its email field.
  const byEmail = await writer.classify(capture({ username: "Kari@example.net" }));
  assert.equal(byEmail.action, "update");
  assert.deepEqual(byEmail.targets.map((t) => [t.id, t.how]), [[imported, "email"]]);

  for (const call of asked) {
    assert.equal(call.method.startsWith("reveal_"), false, call.method);
    if (call.method.includes("field")) assert.equal(call.field, PASSWORD_FIELD);
  }
  assert.ok(asked.some((a) => a.method === "items_with_field_value"));
  for (const outcome of [c, change, byEmail]) {
    const text = JSON.stringify(outcome);
    assert.equal(text.includes(NEW) || text.includes(OLD), false);
  }

  // After the update the core says the item holds the new password: nothing more to offer.
  await writer.update(capture(), { id: mine, rev: 1 });
  assert.equal((await writer.classify(capture())).action, "none");
});

test("save_in_the_real_core_opens_with_the_web_vault_fields_and_a_refused_folder_saves_nothing", async () => {
  const { vault } = newAccount("offer-save");
  const engine = realEngine(vault);
  const writer = createOfferWriter({ engine, liveClient: { vault: spied(vault).proxy } });
  const { id } = await writer.save(capture({ frameUrl: "https://www.example.net/a/b?c=d", origin: "https://www.example.net" }), { name: "", username: "ola", folder: "Work" });
  const opened = await engine.open(id);
  try {
    assert.equal(opened.view.item_type, "login");
    assert.equal(opened.view.name, "example.net");
    assert.deepEqual(opened.view.fields.map((f) => [f.id, f.label, f.kind, f.value]), [["username", "User name", "text", "ola"], ["password", "Password", "password", null]]);
    assert.deepEqual(opened.view.urls.map((u) => [u.url, u.matching]), [["https://www.example.net", "host"]]);
    assert.deepEqual(opened.view.folders, ["Work"]);
    assert.equal(vault.item_field_equals(opened.handle, "password", NEW), true);
  } finally {
    await opened.close();
  }
  // A folder name the core refuses: its code, and nothing stored.
  await assert.rejects(writer.save(capture(), { name: "x", username: null, folder: "" }), { code: "folder_empty" });
  await assert.rejects(writer.save(capture(), { name: "x", username: null, folder: "‮bad" }), { code: "folder_bad_character" });
  assert.equal(engine.rows.size, 1);
});

test("update_keeps_folders_totp_passkey_notes_urls_and_unknown_keys_in_the_real_core", async () => {
  const account = newAccount("offer-update");
  const { vault } = account;
  const engine = realEngine(vault);

  // A passkey item for the page, then given a user name, a password, folders, a one-time code, notes and addresses.
  const pkId = fill(16, 0x31);
  const made = passkeyCreate(vault, pkId.slice(), 1, "Example", CREATE, CALLER, UV, NO_EXISTING, NOW, undefined);
  const edited = vault.encrypt_item(pkId.slice(), 2, {
    fields: [field("username", "text", "ola", "User name"), field("password", "password", OLD, "Password"), field("pin", "hidden", "1234")],
    folders: ["Work", "Bank"],
    totp: { uri: "otpauth://totp/Example:ola?secret=JBSWY3DPEHPK3PXP&issuer=Example" },
    notes: "private notes",
    urls: [{ url: ORIGIN, matching: "host" }, { url: "https://example.net", matching: "domain" }, { url: "https://login.example.net/x?y=1", matching: "exact" }],
    favorite: true,
  }, made.handle, NOW + 1);
  engine.put(pkId, edited);
  const passkeyItem = hex(pkId);

  // A body written by a newer version: keys the core does not know, on the body, a field and an address.
  const oldId = fill(16, 0x32);
  const hand = {
    schema: 1, type: "login", name: "Hand made",
    fields: [{ id: "username", label: "User name", kind: "text", value: "kari", zz: "field key" }, { id: "password", label: "Password", kind: "password", value: OLD }],
    urls: [{ url: ORIGIN, match: "host", qq: "url key" }],
    created: 1, modified: 2, favorite: false, folders: ["Old folder"], zeta: "body key",
  };
  engine.put(oldId, vault.test_seal_plaintext(oldId.slice(), 1, new Uint8Array(cbor(hand))));
  const unknownItem = hex(oldId);

  const writer = createOfferWriter({ engine, liveClient: { vault: spied(vault).proxy } });
  /** Everything but the password, its history and the time of the change. */
  const comparable = (body) => {
    const copy = structuredClone(body);
    delete copy.password_history;
    delete copy.modified;
    copy.fields = copy.fields.map((f) => (f.id === "password" ? { ...f, value: "*" } : f));
    return copy;
  };
  for (const [id, username] of [[passkeyItem, "ola"], [unknownItem, "kari"]]) {
    const before = bodyOf(account, engine, id);
    const rev = engine.rows.get(id).rev;
    const c = await writer.classify(capture({ username }));
    assert.equal(c.action, "update", username);
    assert.deepEqual(c.targets.map((t) => [t.id, t.rev]), [[id, rev]]);
    await writer.update(capture({ username }), { id, rev });
    const after = bodyOf(account, engine, id);
    assert.deepEqual(comparable(after), comparable(before), username);
    assert.equal(after.fields.find((f) => f.id === "password").value, NEW);
    // The old password is the newest in the history.
    const h = vault.open_item(engine.rows.get(id).idBytes.slice(), engine.rows.get(id).rev, engine.rows.get(id).envelope, engine.rows.get(id).tag);
    try {
      assert.equal(vault.item_view(h).password_history.length, 1);
      assert.equal(vault.reveal_password_history(h, 0), OLD);
    } finally {
      vault.close_item(h);
    }
  }
  // The keys of the newer version are still there, and so are the passkey and the one-time code.
  const kept = bodyOf(account, engine, unknownItem);
  assert.equal(kept.zeta, "body key");
  assert.equal(kept.fields[0].zz, "field key");
  assert.equal(kept.urls[0].qq, "url key");
  const pk = bodyOf(account, engine, passkeyItem);
  assert.ok(pk.passkey, "the passkey is kept");
  assert.ok(pk.totp, "the one-time code is kept");
});
