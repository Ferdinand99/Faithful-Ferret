// The world of the offer tests: a fake core and sync engine over a few items (`fakeVault`), the sync host of the built
// package on a core host with a fake engine (`syncWorld`), and the captured forms and secrets they use. Not a test file
// (the runner picks up *.test.mjs only).
import { PASSWORD_FIELD } from "../../src/background/offerWrite.mjs";
import { pkg } from "./sessionHelpers.mjs";

export const PAGE_URL = "https://login.example.net/signin?next=%2Fhome";
export const ORIGIN = "https://login.example.net";
export const OLD = "Old-PASSWORD-of-the-item-1";
export const NEW = "New-PASSWORD-typed-in-form";
export const SECRETS = [OLD, NEW, "Second-item-PASSWORD", "Current-PASSWORD-x"];
export const SESSION = "5e".repeat(16);

/** An item id from one number. @param {number} n */
export const idOf = (n) => n.toString(16).padStart(2, "0").repeat(16);

/**
 * A stored item as the fake core keeps it: the body (what the core would seal) and the engine's marks.
 * @param {number} n
 * @param {{
 *   name?: string, username?: string, email?: string, password?: string | null,
 *   urls?: Array<[string, string]>, flags?: Record<string, boolean>, rev?: number, body?: Record<string, unknown>,
 *   fields?: any[],
 * }} [spec]
 */
export function item(n, { name = `Item ${n}`, username, email, password = OLD, urls = [[`${ORIGIN}/`, "host"]], flags = {}, rev = 1, body = {}, fields } = {}) {
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
export function fakeVault(items) {
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
export const capture = (over = {}) => ({
  tabId: 7, frameId: 0, documentId: "doc-1", frameUrl: PAGE_URL, origin: ORIGIN, kind: "login",
  username: "ola", usernameFrom: "typed", password: NEW, currentPassword: null, generated: false, ...over,
});

/**
 * The sync host of the built package with a fake engine over `items`, its offer ops on a core host, and the test's
 * own store of offers.
 * @param {ReturnType<typeof item>[]} items
 * @param {{
 *   halted?: string | null, offers?: { peek: Function, take: Function }, extraOps?: Record<string, any>,
 *   extraNames?: string[], attach?: ((coreHost: any) => void) | null,
 * }} [options] `offers`: the store the offers are read from instead of the test's own; `extraOps`: more operations on
 *   the core host (with their names in `extraNames`), which `attach` is given the host of
 */
export async function syncWorld(items, { halted = null, offers = undefined, extraOps = {}, extraNames = [], attach = null } = {}) {
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
  const coreHost = createCoreHost({ createClient: () => client, ops: { ...sync.ops, ...probes, ...extraOps }, names: [...CORE_OPS, "unlock_probe", ...extraNames] });
  sync.attach(coreHost);
  attach?.(coreHost);
  /** Opens the vault again (after a lock): the sync starts its engine. */
  const reopen = async () => {
    await coreHost.call("unlock_probe");
    opened({ server: "https://vault.example.net", session: { current: () => ({ accountId: "11".repeat(16), vaultId: "22".repeat(16), vkEpoch: 1 }), api: {}, deviceState: async () => "ok" } });
  };
  await reopen();
  return {
    ...fake,
    reopen,
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
