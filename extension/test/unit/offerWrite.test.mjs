// The write path of an offer (offerWrite.mjs and the offer ops of sync.mjs):
// which item a captured form is about, decided in the core without reading a
// password out; a new login with the web vault's fields and the frame's origin;
// an update that changes the password and nothing else, with the old one kept
// in the item's history; a stale revision refused; and no write anywhere in the
// extension's own code but this one module's.
//
// The core and the engine are fakes here with the core's draft rules (a field
// sent by its id alone keeps its label, kind, value and unknown keys; a key left
// out keeps what the item has). tests/node/offerWrite.test.mjs runs the same
// write path over the real core.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { createOfferWriter, FIELD_LABELS, folderNames, labelLanguage, MAX_REUSED, PASSWORD_FIELD } from "../../src/background/offerWrite.mjs";
import { createFillContext } from "../../src/background/fillContext.mjs";
import { build, isTestOnlyPath, TEST_ONLY_FILES, WASM_FILES } from "../../scripts/build.mjs";
import { makeRoot } from "./buildHelpers.mjs";
import { pkg } from "./sessionHelpers.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const extensionDir = join(here, "..", "..");
const webDir = join(extensionDir, "..", "web");

const PAGE_URL = "https://login.example.net/signin?next=%2Fhome";
const ORIGIN = "https://login.example.net";
const OLD = "Old-PASSWORD-of-the-item-1";
const NEW = "New-PASSWORD-typed-in-form";
const SECRETS = [OLD, NEW, "Second-item-PASSWORD", "Current-PASSWORD-x"];
const SESSION = "5e".repeat(16);

/** An item id from one number. @param {number} n */
const idOf = (n) => n.toString(16).padStart(2, "0").repeat(16);

/**
 * A stored item as the fake core keeps it: the body (what the core would seal) and the engine's marks.
 * @param {number} n
 * @param {{
 *   name?: string, username?: string, email?: string, password?: string | null,
 *   urls?: Array<[string, string]>, flags?: Record<string, boolean>, rev?: number, body?: Record<string, unknown>,
 *   fields?: any[],
 * }} [spec]
 */
function item(n, { name = `Item ${n}`, username, email, password = OLD, urls = [[`${ORIGIN}/`, "host"]], flags = {}, rev = 1, body = {}, fields } = {}) {
  /** @type {any[]} */
  const own = fields ?? [
    ...(username !== undefined ? [{ id: "username", label: "User name", kind: "text", value: username }] : []),
    ...(password !== null ? [{ id: "password", label: "Password", kind: "password", value: password }] : []),
    ...(email !== undefined ? [{ id: "email", label: "Email", kind: "email", value: email }] : []),
  ];
  return { id: idOf(n), rev, flags, body: { item_type: "login", name, fields: own, urls: urls.map(([url, matching]) => ({ url, matching })), ...body } };
}

/** The registrable domain of a host, as far as these tests need it (the last two labels). @param {string} host */
const registrable = (host) => host.split(".").slice(-2).join(".");

/**
 * How a saved address matches a page, by the core's rule (url_match.rs), for the addresses of these tests.
 * @param {{ url: string, matching: string }} entry @param {string} page
 */
function howOf(entry, page) {
  const saved = new URL(entry.url);
  const at = new URL(page);
  if (saved.protocol !== at.protocol || saved.port !== at.port) return null;
  if (entry.matching === "exact") return saved.host === at.host && saved.pathname === at.pathname && saved.search === at.search ? "exact" : null;
  if (saved.host === at.host) return "host";
  if (entry.matching === "domain" && saved.protocol === "https:" && registrable(saved.hostname) === registrable(at.hostname)) return "domain";
  return null;
}

/** The core's rules for a draft on an existing body (bindings/wasm/src/item.rs `build_body`), for the keys used here. @param {any} prev @param {any} draft @param {number} now */
function applyDraft(prev, draft, now) {
  const next = structuredClone(prev);
  for (const [key, value] of Object.entries(draft)) {
    if (key === "fields") {
      const ids = value.map((/** @type {any} */ f) => f.id);
      if (new Set(ids).size !== ids.length) throw Object.assign(new Error("invalid_input"), { code: "invalid_input" });
      next.fields = value.map((/** @type {any} */ f) => {
        const p = prev.fields.find((/** @type {any} */ g) => g.id === f.id);
        return { ...(p ?? {}), id: f.id, label: f.label ?? p?.label ?? "", kind: f.kind ?? p?.kind ?? "text", value: f.value ?? p?.value ?? "" };
      });
    } else if (key === "keep_password_history" || key === "device") {
      // below
    } else if (key === "folders") {
      if (value === null) continue;
      if (value.length === 0) delete next.folders;
      else next.folders = value;
    } else {
      next[key] = value;
    }
  }
  if (draft.keep_password_history === true) {
    const before = prev.fields.find((/** @type {any} */ f) => f.id === PASSWORD_FIELD)?.value ?? "";
    const after = next.fields.find((/** @type {any} */ f) => f.id === PASSWORD_FIELD)?.value;
    if (before !== "" && before !== after) next.password_history = [{ value: before, until: now }, ...(prev.password_history ?? [])].slice(0, 5);
  }
  next.modified = now;
  return next;
}

/**
 * A fake core and sync engine over `items`: the core answers `page_origin`, `display_host`, `match_page` and
 * `items_with_field_value`, and has no way to read a password out; every method asked for is noted.
 * @param {ReturnType<typeof item>[]} items
 */
function fakeVault(items) {
  const byId = new Map(items.map((i) => [i.id, i]));
  /** @type {Map<number, string>} */
  const handles = new Map();
  let nextHandle = 1;
  let created = 0;
  /** Every method of the core that was asked for, with its field id where it has one. @type {Array<{ method: string, field?: string }>} */
  const asked = [];
  /** The engine's writes. @type {Array<{ op: string, id?: string, draft: any, expectedRev?: number }>} */
  const writes = [];
  const now = 1_763_800_000_000;
  const core = {
    page_origin: (/** @type {string} */ url) => new URL(url).origin,
    display_host: (/** @type {string} */ url) => {
      const host = new URL(url).hostname;
      return { a_label: host, unicode: host };
    },
    match_page: (/** @type {string} */ url, /** @type {number[]} */ list) => {
      const out = [];
      for (const handle of list) {
        const it = byId.get(/** @type {string} */ (handles.get(handle)));
        const hows = (it?.body.urls ?? []).map((/** @type {any} */ u) => howOf(u, url)).filter(Boolean);
        const best = ["exact", "host", "domain"].find((h) => hows.includes(h));
        if (best) out.push({ handle, how: best });
      }
      return out;
    },
    items_with_field_value: (/** @type {number[]} */ list, /** @type {string} */ field, /** @type {string} */ value) =>
      list.filter((handle) => byId.get(/** @type {string} */ (handles.get(handle)))?.body.fields.find((/** @type {any} */ f) => f.id === field)?.value === value),
  };
  const vault = new Proxy(core, {
    get(target, method) {
      if (typeof method !== "string" || method === "then") return undefined;
      return (/** @type {any[]} */ ...args) => {
        asked.push({ method, ...(typeof args[1] === "string" && method.includes("field") ? { field: args[1] } : {}) });
        const fn = /** @type {any} */ (target)[method];
        if (typeof fn !== "function") return Promise.reject(Object.assign(new Error("no such method"), { code: "unknown_method" }));
        try {
          return Promise.resolve(fn(...args));
        } catch (error) {
          return Promise.reject(error);
        }
      };
    },
  });
  /** @param {ReturnType<typeof item>} it */
  const summaryOf = (it) => ({
    id: it.id,
    rev: it.rev,
    type: it.body.item_type,
    name: it.body.name,
    username: it.body.fields.find((/** @type {any} */ f) => f.id === "username")?.value ?? "",
    urls: it.body.urls.map((/** @type {any} */ u) => u.url),
    folders: [...(it.body.folders ?? [])],
    pending: it.flags.pending ?? false,
    readOnly: it.flags.readOnly ?? false,
    damaged: it.flags.damaged ?? false,
    quarantined: it.flags.quarantined ?? false,
    blocked: it.flags.blocked ?? false,
    conflict: it.flags.conflict ?? false,
    missingOnServer: it.flags.missingOnServer ?? false,
  });
  /** What the engine does before a write: refused for a stale revision, then sealed. @type {{ beforeUpdate: (id: string) => void }} */
  const hooks = { beforeUpdate: () => {} };
  const engine = {
    list: () => items.map(summaryOf),
    async open(/** @type {string} */ id) {
      const it = byId.get(id);
      if (!it || it.flags.damaged) throw Object.assign(new Error("not_found"), { code: it ? "damaged" : "not_found" });
      const handle = nextHandle;
      nextHandle += 1;
      handles.set(handle, id);
      const view = {
        item_type: it.body.item_type,
        name: it.body.name,
        // Like the core: a secret kind has no value in the view.
        fields: it.body.fields.map((/** @type {any} */ f) => ({ id: f.id, label: f.label, kind: f.kind, value: ["password", "hidden"].includes(f.kind) ? null : f.value })),
        urls: it.body.urls,
        read_only: it.flags.readOnly === true,
      };
      return { handle, view, close: async () => void handles.delete(handle) };
    },
    async create(/** @type {any} */ draft) {
      writes.push({ op: "create", draft: structuredClone(draft) });
      created += 1;
      const it = { id: idOf(200 + created), rev: 1, flags: { pending: true }, body: applyDraft({ fields: [] }, draft, now) };
      items.push(it);
      byId.set(it.id, it);
      return it.id;
    },
    async update(/** @type {string} */ id, /** @type {any} */ draft, /** @type {number} */ expectedRev) {
      hooks.beforeUpdate(id);
      const it = byId.get(id);
      if (!it) throw Object.assign(new Error("not_found"), { code: "not_found" });
      if (it.rev !== expectedRev) throw Object.assign(new Error("item_changed"), { code: "item_changed" });
      writes.push({ op: "update", id, draft: structuredClone(draft), expectedRev });
      it.body = applyDraft(it.body, draft, now);
      it.rev += 1;
      it.flags = { ...it.flags, pending: true };
    },
  };
  return { vault, engine, asked, writes, handles, byId, hooks, now };
}

/**
 * A captured form for the page.
 * @param {Record<string, unknown>} [over]
 */
const capture = (over = {}) => ({
  tabId: 7, frameId: 0, documentId: "doc-1", frameUrl: PAGE_URL, origin: ORIGIN, kind: "login",
  username: "ola", usernameFrom: "typed", password: NEW, currentPassword: null, generated: false, ...over,
});

/**
 * A writer over a fake vault of `items`.
 * @param {ReturnType<typeof item>[]} items
 * @param {{ fillContext?: any, language?: string }} [options]
 */
function writerOver(items, options = {}) {
  const fake = fakeVault(items);
  const writer = createOfferWriter({ engine: fake.engine, liveClient: { vault: fake.vault }, ...options });
  return { ...fake, writer };
}

/** No call of the core reads a value out, and every comparison is on the password field. @param {Array<{ method: string, field?: string }>} asked */
function assertNothingRevealed(asked) {
  assert.ok(asked.length > 0, "the core was asked");
  for (const call of asked) {
    assert.equal(call.method.startsWith("reveal_"), false, `the write path asked the core for ${call.method}`);
    if (call.method === "items_with_field_value" || call.method === "item_field_equals") assert.equal(call.field, PASSWORD_FIELD);
  }
}

// ---------------------------------------------------------------- save

test("save_makes_a_login_with_the_web_vault_field_ids_and_labels_and_the_origin_as_url_with_host_match", async () => {
  // The web vault's own labels, ids and kinds (edit.mjs and its catalogs).
  for (const lang of ["en", "nb"]) {
    const catalog = JSON.parse(readFileSync(join(webDir, "src", "locales", lang, "vault.json"), "utf8"));
    assert.deepEqual(FIELD_LABELS[/** @type {"en" | "nb"} */ (lang)], { username: catalog["vault.edit.username"], password: catalog["vault.edit.password"] }, lang);
  }
  const edit = readFileSync(join(webDir, "src", "views", "edit.mjs"), "utf8");
  assert.match(edit, /set\("username", t\("vault\.edit\.username"\), "text",/);
  assert.match(edit, /set\("password", t\("vault\.edit\.password"\), "password",/);

  const w = writerOver([]);
  const page = capture({ frameUrl: "https://www.example.org/account/login?next=/x#top", origin: "https://www.example.org" });
  const saved = await w.writer.save(page, { name: "", username: "ola", folder: null });
  assert.equal(saved.pending, true, "the write waits in the outbox until the server has it");
  assert.deepEqual(w.writes, [{
    op: "create",
    draft: {
      item_type: "login",
      // The host without `www.`, when the card left the name empty.
      name: "example.org",
      fields: [
        { id: "username", label: "User name", kind: "text", value: "ola" },
        { id: "password", label: "Password", kind: "password", value: NEW },
      ],
      // The frame's origin: no path, no query, no fragment; matched by host.
      urls: [{ url: "https://www.example.org", matching: "host" }],
    },
  }]);
  assert.equal(saved.id, idOf(201));

  // The labels' language is the browser's first one the web vault has.
  assert.equal(labelLanguage(["nb-NO", "en"]), "nb");
  assert.equal(labelLanguage(["nn"]), "nb");
  assert.equal(labelLanguage(["de-DE", "en-GB", "nb"]), "en");
  assert.equal(labelLanguage(["fr"]), "en");
  // The name the user typed, trimmed; no user name, no user name field; Norwegian labels in Norwegian.
  const nb = writerOver([], { language: "nb" });
  await nb.writer.save(capture(), { name: "  Min konto ", username: null, folder: null });
  assert.deepEqual(nb.writes[0].draft, {
    item_type: "login",
    name: "Min konto",
    fields: [{ id: "password", label: "Passord", kind: "password", value: NEW }],
    urls: [{ url: ORIGIN, matching: "host" }],
  });
  // A capture whose origin is not the one the core reads from its address is not saved.
  await assert.rejects(w.writer.save(capture({ origin: "https://evil.example.org" }), { name: "x", username: null, folder: null }), { code: "origin_changed" });
  // Nor one from plain http.
  await assert.rejects(w.writer.save(capture({ frameUrl: "http://login.example.net/", origin: "http://login.example.net" }), { name: "x", username: null, folder: null }), { code: "invalid_input" });
  assert.equal(w.writes.length, 1);
});

test("save_puts_the_item_in_the_chosen_folder_and_in_none_by_default", async () => {
  const w = writerOver([]);
  await w.writer.save(capture(), { name: "A", username: "ola", folder: "Work" });
  await w.writer.save(capture(), { name: "B", username: "ola", folder: null });
  assert.deepEqual(w.writes[0].draft.folders, ["Work"]);
  assert.equal("folders" in w.writes[1].draft, false, "no folder key: in none");
  assert.deepEqual(w.byId.get(idOf(201))?.body.folders, ["Work"]);
  assert.equal(w.byId.get(idOf(202))?.body.folders, undefined);
  // The folders the card offers: each once, whatever the case, sorted.
  assert.deepEqual(folderNames([{ folders: ["Work", "home"] }, { folders: ["work", "Travel"] }, { folders: [] }].map((f, i) => ({ id: idOf(i), rev: 1, name: "", username: "", urls: [], ...f }))), ["home", "Travel", "Work"]);
});

// ---------------------------------------------------------------- update

test("update_sends_every_existing_field_id_without_a_value_the_new_password_and_keep_history", async () => {
  const fields = [
    { id: "username", label: "User name", kind: "text", value: "ola" },
    { id: "password", label: "Password", kind: "password", value: OLD },
    { id: "email", label: "Email", kind: "email", value: "ola@example.net" },
    { id: "pin", label: "PIN", kind: "hidden", value: "1234" },
    { id: "password-2", label: "Password", kind: "password", value: "kept-too" },
  ];
  const w = writerOver([item(1, { fields, rev: 4 })]);
  const result = await w.writer.update(capture(), { id: idOf(1), rev: 4 });
  assert.deepEqual(result, { pending: true });
  assert.deepEqual(w.writes, [{
    op: "update",
    id: idOf(1),
    expectedRev: 4,
    draft: {
      fields: [{ id: "username" }, { id: "password", value: NEW }, { id: "email" }, { id: "pin" }, { id: "password-2" }],
      keep_password_history: true,
    },
  }]);
  // An item without a password field gets one, with the web vault's label and kind; nothing else is named.
  const bare = writerOver([item(2, { username: "ola", password: null })]);
  await bare.writer.update(capture(), { id: idOf(2), rev: 1 });
  assert.deepEqual(bare.writes[0].draft, {
    fields: [{ id: "username" }, { id: "password", label: "Password", kind: "password", value: NEW }],
    keep_password_history: true,
  });
  // Two fields with one id could not both be named: refused, nothing written.
  const twice = writerOver([item(3, { fields: [{ id: "x", label: "", kind: "text", value: "a" }, { id: "x", label: "", kind: "text", value: "b" }, { id: "password", label: "", kind: "password", value: OLD }] })]);
  await assert.rejects(twice.writer.update(capture(), { id: idOf(3), rev: 1 }), { code: "not_updatable" });
  assert.deepEqual(twice.writes, []);
});

test("update_keeps_folders_totp_passkey_notes_urls_and_unknown_keys", async () => {
  const body = {
    folders: ["Work", "Bank"],
    totp: { uri: "otpauth://totp/Example:ola?secret=JBSWY3DPEHPK3PXP", extra_totp_key: 1 },
    passkey: { user_name: "ola", rp_id: "example.net", credential: "opaque" },
    notes: "private notes",
    favorite: true,
    zeta: { from: "a newer version" },
  };
  const fields = [
    { id: "username", label: "User name", kind: "text", value: "ola", extra_field_key: "kept" },
    { id: "password", label: "Password", kind: "password", value: OLD },
    { id: "custom", label: "Custom", kind: "text", value: "c" },
  ];
  const urls = /** @type {Array<[string, string]>} */ ([[`${ORIGIN}/`, "host"], ["https://example.net/", "domain"], ["https://app.example.net/x", "exact"]]);
  const w = writerOver([item(1, { fields, urls, body })]);
  const before = structuredClone(w.byId.get(idOf(1))?.body);
  await w.writer.update(capture(), { id: idOf(1), rev: 1 });
  const after = structuredClone(w.byId.get(idOf(1))?.body);
  // Everything but the password and its history is as it was (and the time of the change).
  const without = (/** @type {any} */ b) => {
    const copy = structuredClone(b);
    delete copy.password_history;
    delete copy.modified;
    copy.fields = copy.fields.map((/** @type {any} */ f) => (f.id === PASSWORD_FIELD ? { ...f, value: "*" } : f));
    return copy;
  };
  assert.deepEqual(without(after), without(before));
  assert.equal(after.fields.find((/** @type {any} */ f) => f.id === PASSWORD_FIELD).value, NEW);
  assert.deepEqual(after.password_history.map((/** @type {any} */ h) => h.value), [OLD], "the old password is in the history");
  // The draft named no folders, addresses, one-time code, notes, passkey or any other key.
  assert.deepEqual(Object.keys(w.writes[0].draft).sort(), ["fields", "keep_password_history"]);
});

test("update_with_a_stale_rev_is_refused_as_item_changed_and_classified_again", async () => {
  // Refused before anything is opened when the list shows a newer revision.
  const w = writerOver([item(1, { username: "ola" })]);
  const first = await w.writer.classify(capture());
  assert.deepEqual(first.targets.map((t) => [t.id, t.rev]), [[idOf(1), 1]]);
  const it = /** @type {any} */ (w.byId.get(idOf(1)));
  it.rev = 2; // another device's change arrived
  await assert.rejects(w.writer.update(capture(), { id: idOf(1), rev: 1 }), { code: "item_changed" });
  // And by the engine when the change comes in while the draft is being made.
  it.rev = 1;
  w.hooks.beforeUpdate = () => {
    it.rev = 3;
  };
  await assert.rejects(w.writer.update(capture(), { id: idOf(1), rev: 1 }), { code: "item_changed" });
  assert.deepEqual(w.writes, [], "nothing was written");

  // Through the sync's ops: the answer carries the new classification, and the offer stays for another click.
  const world = await syncWorld([item(1, { username: "ola" })]);
  const offerId = world.plant(capture());
  const classified = await world.call("offer_classify", { session: SESSION, offer_id: offerId });
  assert.equal(classified.action, "update");
  world.byId.get(idOf(1)).rev = 2;
  const stale = await world.call("offer_update", { session: SESSION, offer_id: offerId, id: idOf(1), rev: classified.targets[0].rev });
  assert.equal(stale.ok, false);
  assert.equal(stale.reason, "item_changed");
  assert.deepEqual(stale.classification.targets.map((/** @type {any} */ t) => [t.id, t.rev]), [[idOf(1), 2]]);
  assert.deepEqual(world.writes, []);
  assert.notEqual(world.captures.peek(offerId, SESSION), null, "the offer is still there");
  const done = await world.call("offer_update", { session: SESSION, offer_id: offerId, id: idOf(1), rev: 2 });
  assert.deepEqual(done, { ok: true, pending: true });
  assert.equal(world.writes.length, 1);
  assert.equal(world.captures.peek(offerId, SESSION), null, "used once");
});

// ---------------------------------------------------------------- targets

test("read_only_damaged_quarantined_blocked_and_conflicted_items_are_never_targets", async () => {
  for (const flag of ["readOnly", "damaged", "quarantined", "blocked", "conflict", "missingOnServer"]) {
    const w = writerOver([item(1, { username: "ola", flags: { [flag]: true } })]);
    const c = await w.writer.classify(capture());
    assert.equal(c.action, "save", flag);
    assert.deepEqual(c.targets, [], flag);
    await assert.rejects(w.writer.update(capture(), { id: idOf(1), rev: 1 }), { code: "not_a_target" }, flag);
    assert.deepEqual(w.writes, [], flag);
    // Not even from a list of several.
    const two = writerOver([item(1, { username: "ola", flags: { [flag]: true } }), item(2, { username: "kari" }), item(3, { username: "per" })]);
    const choose = await two.writer.classify(capture({ username: null, usernameFrom: null }));
    assert.equal(choose.action, "choose", flag);
    assert.deepEqual(choose.targets.map((t) => t.id).sort(), [idOf(2), idOf(3)], flag);
  }
});

test("classify_says_none_when_username_and_password_are_equal", async () => {
  const w = writerOver([item(1, { username: "Ola", password: NEW })]);
  assert.equal((await w.writer.classify(capture())).action, "none");
  // NFC, trimmed, any case.
  assert.equal((await w.writer.classify(capture({ username: " OLA " }))).action, "none");
  const composed = writerOver([item(1, { username: "Åse", password: NEW })]);
  assert.equal((await composed.writer.classify(capture({ username: "A\u030Ase" }))).action, "none");
  // No user name typed and the password is saved for the page: nothing to do.
  assert.equal((await w.writer.classify(capture({ username: null, usernameFrom: null }))).action, "none");
  // Another user name with the same password is not "already saved".
  assert.notEqual((await w.writer.classify(capture({ username: "kari" }))).action, "none");
  assert.deepEqual(w.writes, []);
});

test("an_email_only_item_is_matched_by_its_email_field", async () => {
  // An AliasVault import: the address in the email field, no user name.
  const w = writerOver([item(1, { email: "ola@example.net" }), item(2, { username: "kari" })]);
  const c = await w.writer.classify(capture({ username: "Ola@Example.net" }));
  assert.equal(c.action, "update");
  assert.deepEqual(c.targets, [{ id: idOf(1), rev: 1, name: "Item 1", username: "ola@example.net", how: "email" }]);
  // The user name field wins when there is one.
  const both = writerOver([item(1, { username: "ola", email: "other@example.net" })]);
  assert.equal((await both.writer.classify(capture({ username: "other@example.net" }))).action, "save");
});

test("a_null_username_with_two_candidates_asks_which_one", async () => {
  const w = writerOver([item(1, { username: "ola" }), item(2, { username: "kari" })]);
  const c = await w.writer.classify(capture({ username: null, usernameFrom: null }));
  assert.equal(c.action, "choose");
  assert.deepEqual(c.targets.map((t) => t.id).sort(), [idOf(1), idOf(2)]);
  // With one candidate it is that one.
  const one = writerOver([item(1, { username: "ola" })]);
  const only = await one.writer.classify(capture({ username: null, usernameFrom: null }));
  assert.equal(only.action, "update");
  assert.equal(only.targets[0].how, "only");
});

test("a_prefilled_username_is_taken_but_marked_from_page", async () => {
  // Taken: it picks the one item with that name, and the outcome says where it came from.
  const one = writerOver([item(1, { username: "ola" })]);
  const c = await one.writer.classify(capture({ usernameFrom: "page" }));
  assert.equal(c.action, "update");
  assert.equal(c.usernameFrom, "page");
  // But a name the page put there never picks one of several items, even when one has that name.
  const two = writerOver([item(1, { username: "ola" }), item(2, { username: "kari" })]);
  const several = await two.writer.classify(capture({ usernameFrom: "page" }));
  assert.equal(several.action, "choose");
  assert.equal(several.usernameFrom, "page");
  // Typed, the same name does pick it.
  assert.equal((await two.writer.classify(capture({ usernameFrom: "typed" }))).action, "update");
});

test("a_change_form_after_a_ferret_fill_targets_the_filled_item", async () => {
  const fill = createFillContext();
  fill.record({ tabId: 7, frameId: 0, documentId: "doc-1", url: PAGE_URL, fieldKind: "password", itemId: idOf(2) });
  const items = [item(1, { username: "ola" }), item(2, { username: "kari", password: "Second-item-PASSWORD" })];
  const w = writerOver(items, { fillContext: fill });
  // The page's change form has no user name, and the current password field holds what Ferret filled.
  const change = capture({ kind: "change", username: null, usernameFrom: null, currentPassword: "Second-item-PASSWORD" });
  const c = await w.writer.classify(change);
  assert.equal(c.action, "update");
  assert.deepEqual(c.targets.map((t) => [t.id, t.how]), [[idOf(2), "filled"]]);
  // In another document the fill says nothing: the current password decides.
  const elsewhere = await w.writer.classify({ ...change, documentId: "doc-9", currentPassword: "Current-PASSWORD-x" });
  assert.equal(elsewhere.action, "choose");
});

test("a_change_form_targets_the_item_whose_password_is_the_current_one", async () => {
  const items = [item(1, { username: "ola", password: OLD }), item(2, { username: "kari", password: "Second-item-PASSWORD" })];
  const w = writerOver(items);
  const c = await w.writer.classify(capture({ kind: "change", username: null, usernameFrom: null, currentPassword: OLD }));
  assert.equal(c.action, "update");
  assert.deepEqual(c.targets.map((t) => [t.id, t.how]), [[idOf(1), "current_password"]]);
  assertNothingRevealed(w.asked);
});

test("a_domain_only_match_is_never_an_update_target", async () => {
  // Saved for example.net with domain matching: login.example.net matches it by domain only.
  const w = writerOver([item(1, { username: "ola", urls: [["https://example.net/", "domain"]] })]);
  const c = await w.writer.classify(capture());
  assert.equal(c.action, "save");
  assert.deepEqual(c.targets, []);
  assert.deepEqual(c.domainOnly, [{ id: idOf(1), rev: 1, name: "Item 1", host: { a_label: "example.net", unicode: "example.net" } }]);
  // Not by an id the popup sends…
  await assert.rejects(w.writer.update(capture(), { id: idOf(1), rev: 1 }), { code: "not_a_target" });
  assert.deepEqual(w.writes, []);
  // …only when the user picked it from the list that shows its host.
  await w.writer.update(capture(), { id: idOf(1), rev: 1, picked: true });
  assert.equal(w.writes.length, 1);
  // An item of another host never, picked or not.
  const other = writerOver([item(1, { username: "ola", urls: [["https://shop.example.org/", "host"]] })]);
  await assert.rejects(other.writer.update(capture(), { id: idOf(1), rev: 1, picked: true }), { code: "not_a_target" });
});

test("classify_compares_passwords_in_the_core_and_never_reveals_them", async () => {
  const items = [
    item(1, { username: "ola", password: OLD }),
    item(2, { username: "kari", password: NEW, urls: [["https://shop.example.org/", "host"]] }),
    item(3, { username: "per", password: "Second-item-PASSWORD" }),
  ];
  const w = writerOver(items);
  const c = await w.writer.classify(capture({ kind: "change", currentPassword: OLD }));
  assert.equal(c.action, "update");
  assertNothingRevealed(w.asked);
  assert.ok(w.asked.some((a) => a.method === "items_with_field_value"), "compared in the core");
  // What comes back names items, never a value.
  const text = JSON.stringify(c);
  for (const secret of SECRETS) assert.equal(text.includes(secret), false, secret);
  // Every handle is closed again.
  assert.equal(w.handles.size, 0);
  // No module of the offers names a call that reads a value out of the core.
  for (const file of ["offerWrite.mjs", "fillContext.mjs", "test-only/offerProbe.mjs", "offers.mjs"]) {
    let source;
    try {
      source = readFileSync(join(extensionDir, "src", "background", ...file.split("/")), "utf8");
    } catch {
      continue; // a module that a later change adds
    }
    assert.equal(/reveal_/.test(source), false, `${file} names reveal_`);
  }
});

test("a_password_used_for_another_host_is_reported_as_reused_with_at_most_three_names", async () => {
  const items = [
    item(1, { username: "ola" }),
    ...[5, 4, 3, 2].map((n) => item(10 + n, { name: `Other ${n}`, username: "x", password: NEW, urls: [[`https://site${n}.example.org/`, "host"]] })),
    item(20, { name: "No address", username: "x", password: NEW, urls: [] }),
    item(21, { name: "Different", username: "x", password: "Second-item-PASSWORD", urls: [["https://other.example.org/", "host"]] }),
  ];
  const w = writerOver(items);
  const c = await w.writer.classify(capture());
  assert.equal(c.reused.length, MAX_REUSED);
  assert.deepEqual(c.reused, [
    { name: "No address", host: null },
    { name: "Other 2", host: { a_label: "site2.example.org", unicode: "site2.example.org" } },
    { name: "Other 3", host: { a_label: "site3.example.org", unicode: "site3.example.org" } },
  ]);
  const text = JSON.stringify(c);
  for (const secret of SECRETS) assert.equal(text.includes(secret), false, secret);
  // The page's own item is no reuse.
  assert.equal(c.reused.some((r) => r.name === "Item 1"), false);
});

test("only_a_login_item_can_be_an_update_target", async () => {
  // A note, a card and an identity with the page's address, and the same user name: never a target, never listed.
  for (const type of ["note", "card", "identity"]) {
    const w = writerOver([item(1, { username: "ola", body: { item_type: type } })]);
    const c = await w.writer.classify(capture());
    assert.equal(c.action, "save", type);
    assert.deepEqual(c.targets, [], type);
    const none = await w.writer.classify(capture({ username: null, usernameFrom: null }));
    assert.equal(none.action, "save", `${type}: not even the only candidate`);
    await assert.rejects(w.writer.update(capture(), { id: idOf(1), rev: 1 }), { code: "not_a_target" }, type);
    assert.deepEqual(w.writes, [], type);
    // Nor by domain.
    const domain = writerOver([item(2, { username: "ola", urls: [["https://example.net/", "domain"]], body: { item_type: type } })]);
    assert.deepEqual((await domain.writer.classify(capture())).domainOnly, [], type);
    await assert.rejects(domain.writer.update(capture(), { id: idOf(2), rev: 1, picked: true }), { code: "not_a_target" }, type);
  }
  // A login beside them is the target.
  const mixed = writerOver([item(1, { username: "ola", body: { item_type: "note" } }), item(2, { username: "ola" })]);
  assert.deepEqual((await mixed.writer.classify(capture())).targets.map((t) => t.id), [idOf(2)]);
});

test("a_change_form_whose_current_password_matches_no_item_asks_which_one", async () => {
  // One item, no user name, and a current password that is not the item's: no automatic update.
  const one = writerOver([item(1, { username: "ola", password: OLD })]);
  const c = await one.writer.classify(capture({ kind: "change", username: null, usernameFrom: null, currentPassword: "Current-PASSWORD-x" }));
  assert.equal(c.action, "choose");
  assert.deepEqual(c.targets.map((t) => t.id), [idOf(1)]);
  // Even with the item's user name typed: the current password speaks against it.
  const named = await one.writer.classify(capture({ kind: "change", currentPassword: "Current-PASSWORD-x" }));
  assert.equal(named.action, "choose");
  // No item for the page: a new one.
  const empty = writerOver([]);
  assert.equal((await empty.writer.classify(capture({ kind: "change", currentPassword: "Current-PASSWORD-x" }))).action, "save");
  // The matching current password still decides at once.
  assert.equal((await one.writer.classify(capture({ kind: "change", username: null, usernameFrom: null, currentPassword: OLD }))).action, "update");
  assert.deepEqual(one.writes, []);
});

// ---------------------------------------------------------------- the sync's ops

/**
 * The sync host of the built package with a fake engine over `items`, its offer ops on a core host, and the test's
 * own store of offers.
 * @param {ReturnType<typeof item>[]} items
 * @param {{ halted?: string | null, offers?: { peek: Function, take: Function } }} [options] `offers`: the store the offers
 *   are read from instead of the test's own
 */
async function syncWorld(items, { halted = null, offers = undefined } = {}) {
  const { load } = await pkg();
  const [{ createSyncHost }, { createCoreHost, CORE_OPS }] = await Promise.all([load("background/sync.mjs"), load("background/coreHost.mjs")]);
  const fake = fakeVault(items);
  /** @type {Map<string, { session: string, capture: any }>} */
  const planted = new Map();
  let next = 0;
  const captures = {
    peek: (/** @type {string} */ id, /** @type {string} */ session) => (planted.get(id)?.session === session ? { ...planted.get(id)?.capture } : null),
    take(/** @type {string} */ id, /** @type {string} */ session) {
      const found = this.peek(id, session);
      if (found !== null) planted.delete(id);
      return found;
    },
  };
  const engine = {
    ...fake.engine,
    async start() {},
    stop() {},
    status: () => (halted ? "halted" : "idle"),
    health: () => ({ halted, warnings: [] }),
    async resumeAfterHalt() {},
    async syncNow() {},
    on: () => () => {},
  };
  /** @type {any} */
  let opened = null;
  const sessionHost = {
    store: {},
    onOpen: (/** @type {any} */ fn) => {
      opened = fn;
    },
    storedServer: async () => null,
    sessionFor: async () => {
      throw new Error("not in this test");
    },
    deviceName: async () => "Test device",
    forget: async () => {},
    exclusive: (/** @type {() => Promise<any>} */ fn) => fn(),
  };
  /** @type {any[]} */
  const madeWith = [];
  const sync = createSyncHost({
    sessionHost,
    locks: null,
    win: { addEventListener() {}, removeEventListener() {} },
    createEngine: (/** @type {any} */ options) => {
      madeWith.push(options);
      return /** @type {any} */ (engine);
    },
    createChannel: () => ({ start() {}, stop() {}, state: () => "offline" }),
    captures: offers ?? captures,
  });
  const client = { vault: fake.vault, job: {}, lock: async () => {} };
  const probes = {
    unlock_probe: {
      vault: false,
      worker: "none",
      run: async (/** @type {any} */ _c, /** @type {any} */ _a, /** @type {any} */ ctx) => {
        ctx.setUnlocked();
        return { ok: true };
      },
    },
  };
  const coreHost = createCoreHost({ createClient: () => client, ops: { ...sync.ops, ...probes }, names: [...CORE_OPS, "unlock_probe"] });
  sync.attach(coreHost);
  await coreHost.call("unlock_probe");
  opened({ server: "https://vault.example.net", session: { current: () => ({ accountId: "11".repeat(16), vaultId: "22".repeat(16), vkEpoch: 1 }), api: {}, deviceState: async () => "ok" } });
  return {
    ...fake,
    engine,
    sync,
    coreHost,
    captures,
    madeWith,
    /** @param {any} c */
    plant(c, session = SESSION) {
      next += 1;
      const id = next.toString(16).padStart(32, "0");
      planted.set(id, { session, capture: c });
      return id;
    },
    /** @param {string} op @param {any} args */
    call: (op, args) => /** @type {Promise<any>} */ (coreHost.call(op, args)),
  };
}

test("an_offer_is_written_once_on_a_click_of_its_own_session", async () => {
  const world = await syncWorld([]);
  const offerId = world.plant(capture());
  // Another popup session, or an id that was never given, writes nothing.
  assert.deepEqual(await world.call("offer_save", { session: "77".repeat(16), offer_id: offerId, name: "A", username: "ola", folder: null }), { ok: false, reason: "not_offered" });
  assert.deepEqual(await world.call("offer_save", { session: SESSION, offer_id: "ab".repeat(16), name: "A", username: "ola", folder: null }), { ok: false, reason: "not_offered" });
  await assert.rejects(world.call("offer_save", { session: SESSION, offer_id: "not-an-id", name: "A", username: "ola", folder: null }), { code: "invalid_input" });
  assert.deepEqual(world.writes, []);
  // Two clicks at once: one write.
  const [a, b] = await Promise.all([
    world.call("offer_save", { session: SESSION, offer_id: offerId, name: "A", username: "ola", folder: null }),
    world.call("offer_save", { session: SESSION, offer_id: offerId, name: "A", username: "ola", folder: null }),
  ]);
  assert.deepEqual([a.ok, b.ok].sort(), [false, true]);
  assert.equal([a, b].find((r) => !r.ok).reason, "busy");
  assert.equal(world.writes.length, 1);
  // Then it is gone.
  assert.deepEqual(await world.call("offer_save", { session: SESSION, offer_id: offerId, name: "A", username: "ola", folder: null }), { ok: false, reason: "not_offered" });
  assert.equal(world.writes.length, 1);
  // A refused write leaves the offer for another try.
  const again = world.plant(capture());
  assert.deepEqual(await world.call("offer_save", { session: SESSION, offer_id: again, name: 5, username: "ola", folder: null }), { ok: false, reason: "invalid_input" });
  assert.notEqual(world.captures.peek(again, SESSION), null);
  assert.deepEqual(await world.call("offer_save", { session: SESSION, offer_id: again, name: "A", username: "ola", folder: null }), { ok: true, id: idOf(202), pending: true });
  assert.equal(world.captures.peek(again, SESSION), null);
  assert.equal(world.writes.length, 2);
});

test("the_offer_answers_carry_ids_names_and_hosts_and_never_a_value", async () => {
  const world = await syncWorld([item(1, { username: "ola", password: OLD, body: { folders: ["Work"] } }), item(2, { name: "Elsewhere", username: "x", password: NEW, urls: [["https://shop.example.org/", "host"]] })]);
  const offerId = world.plant(capture());
  const answers = [
    await world.call("offer_classify", { session: SESSION, offer_id: offerId }),
    await world.call("folder_names", {}),
    await world.call("offer_update", { session: SESSION, offer_id: offerId, id: idOf(1), rev: 1 }),
  ];
  assert.deepEqual(answers[0], {
    ok: true,
    action: "update",
    targets: [{ id: idOf(1), rev: 1, name: "Item 1", username: "ola", how: "username" }],
    domain_only: [],
    reused: [{ name: "Elsewhere", host: { a_label: "shop.example.org", unicode: "shop.example.org" } }],
    username_from: "typed",
  });
  assert.deepEqual(answers[1], { folders: ["Work"] });
  assert.deepEqual(answers[2], { ok: true, pending: true });
  const text = JSON.stringify(answers);
  for (const secret of SECRETS) assert.equal(text.includes(secret), false, secret);
  assertNothingRevealed(world.asked);
});

test("a_pending_write_is_answered_as_pending_and_a_lock_ends_the_writer", async () => {
  // The engine stopped for the user to act: the write still goes into its outbox, and the answer says it waits.
  const world = await syncWorld([], { halted: "unsupported" });
  const offerId = world.plant(capture());
  const saved = await world.call("offer_save", { session: SESSION, offer_id: offerId, name: "A", username: null, folder: null });
  assert.deepEqual(saved, { ok: true, id: idOf(201), pending: true });
  // After a lock nothing of the writer is reachable.
  await world.coreHost.lock("manual");
  const later = world.plant(capture());
  await assert.rejects(world.call("offer_save", { session: SESSION, offer_id: later, name: "A", username: null, folder: null }), { code: "vault_locked" });
  assert.equal(world.writes.length, 1);
});

test("a_lock_during_a_write_gives_vault_locked_writes_nothing_and_leaves_no_offer", async () => {
  // The real store of offers, cleared by the lock, is what the write reads from.
  const { load } = await pkg();
  const { createOffers } = await load("background/offers.mjs");
  let counter = 0;
  const offers = createOffers({
    now: () => 1_763_800_000_000,
    random: (/** @type {Uint8Array} */ bytes) => {
      counter += 1;
      bytes.fill(counter);
      return bytes;
    },
    frames: {
      origin: async (/** @type {string} */ url) => new URL(url).origin,
      sameSite: async () => true,
      host: async (/** @type {string} */ url) => ({ a_label: new URL(url).hostname, unicode: new URL(url).hostname }),
      frame: async () => null,
      shown: async () => true,
      incognito: async () => false,
    },
  });
  const world = await syncWorld([], { offers });
  world.coreHost.onLocked(() => offers.clear("lock"));
  const offerId = await offers.onGenerated({ tabId: 3, frameId: 0, frameUrl: PAGE_URL, kind: "signup", password: NEW });
  assert.ok(offerId);
  offers.forTab(3, SESSION);

  // The engine is busy with the write when the lock comes; it then stops, as the real one does.
  /** @type {() => void} */
  let release = () => {};
  const gate = new Promise((resolve) => {
    release = () => resolve(undefined);
  });
  world.engine.create = async () => {
    await gate;
    throw Object.assign(new Error("stopped"), { code: "stopped" });
  };
  const pending = world.call("offer_save", { session: SESSION, offer_id: offerId, name: "A", username: null, folder: null });
  await new Promise((resolve) => setTimeout(resolve, 5));
  await world.coreHost.lock("manual");
  release();
  await assert.rejects(pending, { code: "vault_locked" });
  assert.deepEqual(world.writes, [], "nothing was queued");
  assert.equal(offers.peek(offerId, SESSION), null, "the lock took the offer and its password");
  assert.equal(offers.size(), 0);
});

// ---------------------------------------------------------------- the engine stays with the writer

/** Code without its comments, for a structural check. @param {string} text */
const codeOf = (text) => text.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'\\])\/\/[^\n]*/g, "$1");

/** Code without its comments and its import lines (they name module paths such as "sync/engine.mjs", not the engine). @param {string} text */
const withoutComments = (text) => codeOf(text).replace(/^\s*import\s[^;]*;/gm, "");

/**
 * The methods of the engine that the sync itself may call. None of them makes or changes an item from a form: they
 * are the sync's own work and the writes the sync may make itself (the choice in a conflict, dropping a refused write,
 * accepting an older state); never `create`, `update` or `remove`.
 */
const SYNC_ENGINE_METHODS = Object.freeze([
  "start", "stop", "health", "status", "syncNow", "discard", "resumeAfterHalt", "on", "list", "open",
  "restorePreview", "acceptOlderState", "conflict", "resolve", "keepMine",
]);

/**
 * Every place in sync.mjs where the engine appears and is not one of the allowed forms: a call of one of
 * SYNC_ENGINE_METHODS, its making, the running record, and the offer writer's options.
 * @param {string} source
 */
function engineLeaks(source) {
  const code = withoutComments(source);
  /** @type {string[]} */
  const out = [];
  for (const match of code.matchAll(/\bengine\b/g)) {
    const at = /** @type {number} */ (match.index);
    const after = code.slice(at);
    const before = code.slice(Math.max(0, at - 40), at);
    const call = /^engine\s*\.\s*([A-Za-z_$][\w$]*)\s*\(/.exec(after);
    if (call && SYNC_ENGINE_METHODS.includes(call[1])) continue;
    if (/^engine\s*=\s*createEngine\s*\(/.test(after) && /const\s+$/.test(before)) continue;
    if (/^engine\s*,/.test(after) && /createOfferWriter\(\{\s*$/.test(before)) continue;
    if (/^engine\s*,\s*writer\s*,/.test(after) && /const run = \{\s*$/.test(before)) continue;
    out.push(code.slice(Math.max(0, at - 30), at + 40).replace(/\s+/g, " "));
  }
  return out;
}

test("sync_passes_the_engine_only_to_the_offer_writer", async () => {
  const source = readFileSync(join(extensionDir, "src", "background", "sync.mjs"), "utf8");
  assert.deepEqual(engineLeaks(source), []);
  // The check finds the ways an engine could leave (positive controls).
  for (const leak of [
    "return { engine: () => running?.engine };",
    "const e = run.engine; e.create(draft);",
    "run.engine.update(id, draft, rev);",
    "matchHost({ engine });",
    "items: () => run.engine,",
    "run.engine.remove(id);",
  ]) {
    assert.notDeepEqual(engineLeaks(leak), [], leak);
  }
  assert.deepEqual(engineLeaks("const engine = createEngine({ api }); createOfferWriter({ engine, liveClient }); const run = { engine, writer, api }; run.engine.stop(); engine.on('state', f);"), []);

  // At run time: the host hands out its items to read, never the engine or a method of it that writes.
  const world = await syncWorld([item(1, { username: "ola" })]);
  const items = /** @type {any} */ (world.sync).items();
  assert.deepEqual(Object.keys(items).sort(), ["list", "open"]);
  assert.notEqual(items, world.engine);
  assert.deepEqual(items.list().map((/** @type {any} */ s) => s.id), [idOf(1)]);
  /** @param {unknown} value @param {Set<unknown>} seen */
  const reaches = (value, seen = new Set()) => {
    if (value === world.engine || value === world.engine.create || value === world.engine.update) return true;
    if (value === null || (typeof value !== "object" && typeof value !== "function") || seen.has(value)) return false;
    seen.add(value);
    return Object.values(/** @type {any} */ (value)).some((v) => reaches(v, seen));
  };
  assert.equal(reaches(world.sync), false, "nothing the sync host returns holds the engine");
  assert.equal(reaches(items), false);
  // The engine was made once, by the sync, with the options of the shared engine.
  assert.equal(world.madeWith.length, 1);
});

/**
 * Every place in a file's code that reaches a `create` or `update`: a member access in any form (a call, `?.(`,
 * `.call`, `.apply`, `.bind`, or the method read into a variable), named by the path in front of it (`)` or `]` when
 * that is an expression), a bracket access, and a destructuring that takes one of the two.
 * @param {string} text
 * @returns {string[]}
 */
function writesIn(text) {
  const code = withoutComments(text);
  /** @type {string[]} */
  const out = [];
  for (const m of code.matchAll(/((?:[\w$]+\s*\??\.\s*)*[\w$]+|[)\]])?\s*\??\.\s*(create|update)\b/g)) {
    out.push(`${(m[1] ?? "").replace(/\s+/g, "").replace(/\?/g, "")}.${m[2]}`);
  }
  for (const m of code.matchAll(/\[\s*["'`](create|update)["'`]\s*\]/g)) out.push(`[${m[1]}]`);
  for (const m of code.matchAll(/\{[^{}]*\b(create|update)\b[^{}]*\}\s*=(?!=)/g)) out.push(`{${m[1]}} =`);
  return out.sort();
}

/**
 * The only `create` and `update` the extension's own code may reach, per file of the package: the browser's
 * (alarms, menus, tabs, windows), the offer writer's own `update`, and the engine's two in the offer writer.
 * @type {Readonly<Record<string, string[]>>}
 */
const ALLOWED_WRITES = Object.freeze({
  "background/clipboard.mjs": ["alarms.create"],
  "background/lock.mjs": ["alarms.create"],
  "background/menus.mjs": ["menus.create"],
  "background/fillFlow.mjs": ["tabs.create"],
  "pages/popup.mjs": ["browser.tabs.create", "browser.tabs.create", "browser.windows.create"],
  "background/sync.mjs": ["run.writer.update"],
  "background/offerWrite.mjs": ["engine.create", "engine.update"],
});

test("only_offer_write_calls_engine_create_or_update", async () => {
  const shared = new Set(/** @type {string[]} */ (JSON.parse(readFileSync(join(extensionDir, "shared.json"), "utf8"))).map((p) => `shared/${p}`));
  // The matcher finds every form of reaching the two methods.
  for (const [text, found] of /** @type {Array<[string, string[]]>} */ ([
    ["await engine.create(draft);", ["engine.create"]],
    ["await engine().update(id, d, 1);", [").update"]],
    ["await run.engine\n  .update(id, d, 1);", ["run.engine.update"]],
    ["await engine.create?.(d);", ["engine.create"]],
    ["await engine?.update(id, d, 1);", ["engine.update"]],
    ["engine.update.call(engine, id, d, 1);", ["engine.update"]],
    ["Reflect.apply(engine.create, engine, [d]);", ["engine.create"]],
    ["const f = e.update.bind(e);", ["e.update"]],
    ["e[\"create\"](d);", ["[create]"]],
    ["const { create, list } = engine;", ["{create} ="]],
    ["await s.items()[0].create(d)", ["].create"]],
    ["const writer = engine; await writer.create(d);", ["writer.create"]],
  ])) {
    assert.deepEqual(writesIn(text), found, text);
  }
  assert.deepEqual(writesIn("const created = a.createdAt; x.updateFound(); if (a == { create }) {} // engine.create(x)"), []);

  for (const variant of ["release", "test"]) {
    for (const manifest of ["mv3", "mv2"]) {
      const env = makeRoot();
      try {
        const { files } = await build({ root: env.root, webRoot: env.webRoot, out: env.out, wasmTar: env.tarPath, manifest, variant });
        /** @type {string[]} */
        const scanned = [];
        /** @type {string[]} */
        const makers = [];
        /** @type {string[]} */
        const factories = [];
        for (const [path, bytes] of files) {
          if (!/\.(?:mjs|js)$/.test(path) || shared.has(path) || WASM_FILES.includes(path)) continue;
          const text = bytes.toString("utf8");
          const code = codeOf(text);
          // Who may make an engine: the sync alone (and the test build's hooks, through the sync's factory).
          if (/\bcreateSyncEngine\b/.test(code) || /["']\.\.?\/(?:[\w.]+\/)*sync\/engine\.mjs["']/.test(code)) makers.push(path);
          if (/\bdefaultCreateEngine\b/.test(code)) factories.push(path);
          // The test build's own test code, by the build's own lists (a release refuses any such path).
          if (variant === "test" && (isTestOnlyPath(path) || TEST_ONLY_FILES.includes(path))) {
            if (path === "background/test-only/matchProbe.mjs") {
              // Positive control in a real package: the probe that makes test items with the engine is found.
              assert.ok(writesIn(text).includes("running.create"), `${manifest}: the check finds the probe's write`);
            }
            if (path === "background/test-only/writeProbe.mjs") {
              // The same for the probe that edits a test item through the engine.
              assert.ok(writesIn(text).includes("running.update"), `${manifest}: the check finds the rename probe's write`);
            }
            continue;
          }
          scanned.push(path);
          assert.deepEqual(writesIn(text), [...(ALLOWED_WRITES[path] ?? [])].sort(), `${variant} ${manifest}: ${path}`);
        }
        for (const path of Object.keys(ALLOWED_WRITES)) assert.ok(scanned.includes(path), `${variant} ${manifest}: ${path} is in the package`);
        assert.deepEqual(makers, ["background/sync.mjs"], `${variant} ${manifest}: only the sync makes an engine`);
        // The test build's hooks get the sync's engine only as the second argument of their factory.
        assert.deepEqual(factories, ["background/sync.mjs"], `${variant} ${manifest}: the engine's factory is named in the sync only`);
        if (variant === "test") {
          assert.ok(files.has("background/test-only/matchProbe.mjs"), `${manifest}: the control file is there`);
          assert.ok(files.has("background/test-only/writeProbe.mjs"), `${manifest}: the second control file is there`);
        }
      } finally {
        env.cleanup();
      }
    }
  }
});
