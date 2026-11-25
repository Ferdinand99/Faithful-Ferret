// The chooser window with a canned background (test build only): the page of the passkey chooser (passkeyChooser.mjs) as the Firefox
// specs and the screenshots see it, without a request of a website. The scenario is in the address (`?s=get2&theme=dark`), the
// window's messages are answered here and written to the body's data-calls and data-closed ("close the window" only sets data-closed).
//
// Scenarios: get1, get2, get3 (many), none (no Ferret passkey), create, create_attach, create_existing, offline, locked, foreign,
// hostile (names with direction and control characters, very long names).
import { mount } from "../../shared/dom.mjs";
import { loadTexts, translateStatic } from "../page.mjs";
import { viewOf } from "../passkeyFlow.mjs";
import { createChooser } from "../passkeyChooser.mjs";

const ID = (/** @type {number} */ n) => n.toString(16).padStart(32, "0");
const RLO = String.fromCharCode(0x202e);
const ZWSP = String.fromCharCode(0x200b);
const SITE = { origin: "https://www.example.com", host_unicode: "www.example.com", rp_id: "example.com", rp_id_unicode: "example.com" };
const IDN = { origin: "https://xn--bcher-kva.example", host_unicode: "bücher.example", rp_id: "xn--bcher-kva.example", rp_id_unicode: "bücher.example" };

/** @param {Record<string, unknown>} over */
const base = (over) => ({ ok: true, kind: "get", state: "ready", origin: SITE.origin, site: SITE, rp_name: null, user: {}, online: true, foreign: false, candidates: [], targets: [], existing: null, folders: [], recent: false, ...over });

const CANDIDATES = [
  { item_id: ID(3), name: "Example (work)", user_name: "anna@example.com", created: Date.UTC(2026, 9, 21) },
  { item_id: ID(1), name: "Example", user_name: "anna.nordmann@example.net", created: Date.UTC(2026, 10, 2) },
  { item_id: ID(2), name: "Example (old)", user_name: "anna", created: Date.UTC(2025, 2, 14) },
];

/** @type {Record<string, Record<string, unknown>>} */
const SCENARIOS = {
  get1: base({ candidates: CANDIDATES.slice(1, 2) }),
  get2: base({ candidates: CANDIDATES.slice(0, 2) }),
  get3: base({ candidates: CANDIDATES }),
  none: base({}),
  create: base({ kind: "create", rp_name: "Example", user: { name: "anna@example.com", display_name: "Anna Nordmann" }, folders: [{ id: ID(9), name: "Work" }, { id: ID(8), name: "Private" }] }),
  create_attach: base({
    kind: "create",
    rp_name: "Example",
    user: { name: "anna@example.com", display_name: "Anna Nordmann" },
    targets: [
      { item_id: ID(5), name: "Example login", user_name: "anna@example.com", same_user: true },
      { item_id: ID(6), name: "Example (shared)", user_name: "team@example.com", same_user: false },
    ],
  }),
  attach_many: base({
    kind: "create",
    rp_name: "Example",
    user: { name: "anna@example.com", display_name: "Anna Nordmann" },
    targets: [1, 2, 3, 4, 5].map((n) => ({ item_id: ID(20 + n), name: `Example login ${n}`, user_name: `user${n}@example.com`, same_user: n === 1 })),
  }),
  create_existing: base({ kind: "create", user: { name: "anna@example.com", display_name: "Anna Nordmann" }, existing: { item_id: ID(5), name: "Example login" } }),
  offline: base({ kind: "create", user: { name: "anna@example.com", display_name: "" }, online: false }),
  locked: base({ state: "locked", site: null }),
  foreign: base({ foreign: true, candidates: CANDIDATES.slice(0, 1) }),
  idn: base({ site: IDN, origin: IDN.origin, candidates: CANDIDATES.slice(0, 1) }),
  hostile: base({
    site: IDN,
    origin: IDN.origin,
    kind: "create",
    rp_name: `Your bank${RLO}moc.knab${ZWSP} ${"very long ".repeat(30)}`,
    user: { name: `${"a".repeat(80)}@${"b".repeat(80)}.example`, display_name: `مرحبا ${RLO}evil` },
    targets: [{ item_id: ID(5), name: `${"Long item name ".repeat(12)}`, user_name: `${RLO}gnp.txt`, same_user: true }],
  }),
};

async function main() {
  const root = /** @type {HTMLElement} */ (document.getElementById("root"));
  const params = new URLSearchParams(location.search);
  const scenario = params.get("s") ?? "get2";
  if (params.get("theme") === "dark" || params.get("theme") === "light") document.documentElement.style.setProperty("color-scheme", /** @type {string} */ (params.get("theme")));
  const texts = await loadTexts();
  translateStatic(document, texts);
  /** @type {{ calls: any[], closed: boolean, scenario: string }} */
  const probe = { calls: [], closed: false, scenario };
  // What the specs read: the calls and whether the window was closed, as JSON on the body (the page's own variables are not
  // visible to a script that a driver runs).
  const publish = () => {
    document.body.dataset.calls = JSON.stringify(probe.calls);
    document.body.dataset.closed = probe.closed ? "1" : "0";
  };
  publish();
  let current = SCENARIOS[scenario] ?? SCENARIOS.get2;
  const view = () => {
    const v = viewOf(current);
    return v === null ? { ok: false, reason: "internal_error" } : { ok: true, view: v };
  };
  const record = (/** @type {string} */ call, /** @type {any} */ arg = null) => async () => {
    probe.calls.push({ call, arg });
    publish();
    return { ok: true };
  };
  const backend = {
    view: async () => view(),
    alive: async () => ({ ok: true }),
    choose: async (/** @type {any} */ choice) => {
      probe.calls.push({ call: "choose", arg: choice });
      publish();
      return { ok: true };
    },
    browser: record("browser"),
    never: record("never"),
    cancel: record("cancel"),
  };
  const unlock = {
    unlock: async (/** @type {any} */ fields) => {
      probe.calls.push({ call: "unlock", arg: { passwordLength: String(fields.password).length } });
      publish();
      current = SCENARIOS.get2;
      return { result: { ok: true }, view: {} };
    },
    pinPolicy: async () => null,
    passkeyOffer: async () => false,
    openPasskeyWindow: async () => true,
  };
  const chooser = createChooser({
    texts,
    // @ts-ignore -- a canned backend with the same methods
    backend,
    // @ts-ignore -- a canned flow with the same methods
    unlock,
    pollMs: 0,
    closeWindow: () => {
      probe.closed = true;
      publish();
    },
    formatDate: (ms) => new Intl.DateTimeFormat(texts.lang, { dateStyle: "medium", timeZone: "UTC" }).format(new Date(ms)),
  });
  mount(root, chooser.root);
  window.addEventListener("focus", () => chooser.focused());
  await chooser.loaded;
  chooser.focus();
  document.body.dataset.ready = "1";
}

main().catch(() => {});
