// The chooser window for passkey requests (pages/passkey.html, passkeyChooser.mjs, passkeyFlow.mjs; the `passkeys` feature): what it
// shows (the site from the core first, the website's own texts apart and labelled, Ferret's choices before the browser and "Never"),
// what keeps a click from counting too early (no default button, no initial focus, Enter does nothing, 400 ms from the focus and
// from each change of content, only a click the person made), a locked vault unlocked in the window, a new passkey refused with the
// server out of reach, the window with no passkey of Ferret, the end of the window, and the "never" list. The steps and the view run on
// the DOM stand-in against a fake background; the package is the test variant, built once.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { test } from "node:test";
import { fire, one, byRole, settle, textsOf, useDocument } from "./pageDom.mjs";
import { pkg } from "./sessionHelpers.mjs";

const ID = (/** @type {number} */ n) => n.toString(16).padStart(32, "0");
const REQUEST = "ab".repeat(16);
const RLO = String.fromCharCode(0x202e);
const LRI = String.fromCharCode(0x2066);
const ZWSP = String.fromCharCode(0x200b);
const BOM = String.fromCharCode(0xfeff);
const SITE = { origin: "https://www.example.com", host_unicode: "www.example.com", rp_id: "example.com", rp_id_unicode: "example.com" };

/** The test variant's package: its modules, the catalogs and the files. */
async function setup() {
  useDocument();
  const { dir } = await pkg();
  const load = (/** @type {string} */ path) => import(pathToFileURL(join(dir, ...path.split("/"))).href);
  const catalog = (/** @type {string} */ lang) => JSON.parse(readFileSync(join(dir, `locales.${lang}.json`), "utf8"));
  return {
    dir,
    flow: await load("pages/passkeyFlow.mjs"),
    view: await load("pages/passkeyChooser.mjs"),
    never: await load("background/passkeyNever.mjs"),
    catalog,
    texts: textsOf(catalog("en"), "en"),
    load,
  };
}

/** The raw view the broker's answers make, before the window cleans it. @param {Record<string, unknown>} [over] */
const raw = (over = {}) => ({
  ok: true, kind: "get", state: "ready", origin: SITE.origin, site: SITE, rp_name: null, user: {}, online: true, foreign: false,
  candidates: [], targets: [], existing: null, folders: [], recent: false, ...over,
});
const CANDIDATES = [
  { item_id: ID(3), name: "Example (work)", user_name: "anna@example.com", created: 1_700_000_000_000 },
  { item_id: ID(1), name: "Example", user_name: "anna.nordmann@example.net", created: 1_800_000_000_000 },
];

/** A clock and timers that the test moves. */
function clockWorld() {
  const clock = { t: 100_000 };
  /** @type {Array<{ fn: () => void, at: number }>} */
  let timers = [];
  return {
    clock,
    now: () => clock.t,
    schedule: (/** @type {() => void} */ fn, /** @type {number} */ ms) => {
      const handle = { fn, at: clock.t + ms };
      timers.push(handle);
      return handle;
    },
    cancel: (/** @type {any} */ handle) => {
      timers = timers.filter((t) => t !== handle);
    },
    /** Moves the clock and runs the timers that are due. @param {number} ms */
    async tick(ms) {
      clock.t += ms;
      for (const due of timers.filter((t) => t.at <= clock.t)) {
        timers = timers.filter((t) => t !== due);
        due.fn();
      }
      await settle();
    },
    pending: () => timers.length,
  };
}

/**
 * A fake background for the window: it serves `state.view` (or the refusal `state.fail`) and records every call.
 * @param {any} flow
 * @param {{ view: any, fail?: string | null, choose?: any }} state
 */
function fakeBackend(flow, state) {
  /** @type {Array<{ call: string, arg?: any }>} */
  const calls = [];
  const answer = (/** @type {string} */ call, /** @type {any} */ result = { ok: true }) => async (/** @type {any} */ arg) => {
    calls.push({ call, arg });
    return result;
  };
  return {
    calls,
    backend: {
      alive: async () => {
        calls.push({ call: "alive" });
        return state.fail ? { ok: false, reason: state.fail } : { ok: true };
      },
      view: async () => {
        calls.push({ call: "view" });
        if (state.fail) return { ok: false, reason: state.fail };
        const view = flow.viewOf(state.view);
        return view === null ? { ok: false, reason: "internal_error" } : { ok: true, view };
      },
      choose: async (/** @type {any} */ choice) => {
        calls.push({ call: "choose", arg: choice });
        return state.choose ?? { ok: true };
      },
      browser: answer("browser"),
      never: answer("never"),
      cancel: answer("cancel"),
    },
  };
}

/** The window over a fake background. @param {Awaited<ReturnType<typeof setup>>} world @param {any} state @param {Record<string, any>} [extra] */
async function open(world, state, extra = {}) {
  const time = clockWorld();
  const fake = fakeBackend(world.flow, state);
  const closed = { n: 0 };
  const chooser = world.view.createChooser({
    texts: world.texts,
    backend: fake.backend,
    now: time.now,
    schedule: time.schedule,
    cancel: time.cancel,
    closeWindow: () => {
      closed.n += 1;
    },
    pollMs: 0,
    ...extra,
  });
  await chooser.loaded;
  await settle();
  return { chooser, time, fake, closed, root: chooser.root };
}

/** A click, as the browser makes it for the person (`isTrusted`) or for a script. @param {any} target @param {boolean} [trusted] */
async function tap(target, trusted = true) {
  const event = { type: "click", isTrusted: trusted, target, defaultPrevented: false, preventDefault() {} };
  for (const [type, fn] of target.listeners) if (type === "click") fn(event);
  await settle();
}

/** @param {any} root */
const every = (root) => {
  /** @type {any[]} */
  const out = [];
  const walk = (/** @type {any} */ n) => {
    if (n.tagName) out.push(n);
    for (const c of n.childNodes ?? []) walk(c);
  };
  walk(root);
  return out;
};
/** The place of an element in the window, top to bottom. @param {any} root @param {any} node */
const order = (root, node) => every(root).indexOf(node);

/** Whether a text holds any character the window must never show of a website. @param {string} value */
const hasRefused = (value) =>
  [...value].some((ch) => {
    const cp = /** @type {number} */ (ch.codePointAt(0));
    return cp <= 0x1f || (cp >= 0x7f && cp <= 0x9f) || (cp >= 0x200b && cp <= 0x200f) || (cp >= 0x2028 && cp <= 0x202e) || (cp >= 0x2060 && cp <= 0x206f) || cp === 0xfeff || (cp >= 0xe0000 && cp <= 0xe0fff);
  });

test("the_window_shows_ferrets_host_and_rp_id_above_the_sites_texts", async () => {
  const world = await setup();
  // A website that calls itself by the name of another one: its own text never stands in the place of the site.
  const { root } = await open(world, { view: raw({ kind: "create", rp_name: "paypal.com", user: { name: "anna@paypal.com", display_name: "Anna" }, site: { ...SITE, origin: "https://evil.example", host_unicode: "evil.example", rp_id: "evil.example", rp_id_unicode: "evil.example" } }) });
  const site = one(root, "passkey-site");
  const texts = one(root, "passkey-site-texts");
  assert.ok(site && texts, "the site and the website's texts are there");
  assert.ok(order(root, site) < order(root, texts), "the site comes first");
  assert.equal(one(root, "passkey-host").textContent, "evil.example", "the host is the core's");
  assert.equal(one(root, "passkey-rp-id").textContent, "Passkey for evil.example", "the RP ID is the core's");
  assert.equal(one(root, "passkey-origin"), null, "the exact address is added only when it is more than https and the host");
  assert.equal(site.textContent.includes("paypal"), false, "nothing the website wrote is in the site's part");
  // The host and the RP ID are read left to right, each in its own isolation.
  for (const node of every(site).filter((n) => n.tagName === "BDI")) assert.equal(node.getAttribute("dir"), "ltr");
  // The website's texts are named as the website's, in a part of their own.
  assert.match(texts.textContent, /From the website \(unchecked\)/);
  assert.equal(one(texts, "passkey-rp-name").textContent, "paypal.com");
  assert.equal(one(texts, "passkey-user-name").textContent, "anna@paypal.com");
  // An IDN host: the Unicode form and its A-label both show, left to right.
  const idn = await open(world, { view: raw({ site: { origin: "https://xn--bcher-kva.example", host_unicode: "bücher.example", rp_id: "xn--bcher-kva.example", rp_id_unicode: "bücher.example" }, origin: "https://xn--bcher-kva.example" }) });
  assert.equal(one(idn.root, "passkey-host").textContent, "bücher.example");
  assert.match(one(idn.root, "passkey-rp-id").textContent, /Passkey for bücher\.example \(xn--bcher-kva\.example\)/);
  assert.equal(one(idn.root, "passkey-origin").textContent, "https://xn--bcher-kva.example");
});

test("ferret_is_the_first_choice_and_browser_and_never_are_beside_it", async () => {
  const world = await setup();
  const get = await open(world, { view: raw({ candidates: CANDIDATES }) });
  const ferret = one(get.root, "passkey-ferret");
  const others = one(get.root, "passkey-others");
  assert.ok(order(get.root, ferret) < order(get.root, others), "Ferret's choices come first");
  assert.equal(byRole(ferret, "passkey-candidate").length, 2);
  for (const role of ["passkey-browser", "passkey-never", "passkey-cancel"]) {
    assert.equal(byRole(others, role).length, 1, `${role} is beside Ferret's choices`);
    assert.equal(byRole(ferret, role).length, 0, `${role} is not one of Ferret's choices`);
  }
  assert.equal(one(others, "passkey-browser").textContent, "Use the browser or a security key");
  // The person is told BEFORE the choice that the page's button is clicked once more (the window closes as soon as it is made).
  assert.equal(one(others, "passkey-browser-again").textContent, "Then click the button on the page once more.");
  assert.ok(order(get.root, one(others, "passkey-browser")) < order(get.root, one(others, "passkey-browser-again")), "right under the browser button");
  assert.equal(one(others, "passkey-never").textContent, "Never on this site");
  // A new passkey: Ferret first as well, with "Use the browser instead".
  const create = await open(world, { view: raw({ kind: "create", user: { name: "anna", display_name: "" }, targets: [{ item_id: ID(5), name: "Example login", user_name: "anna", same_user: true }] }) });
  assert.ok(order(create.root, one(create.root, "passkey-new")) < order(create.root, one(create.root, "passkey-others")));
  assert.ok(order(create.root, one(create.root, "passkey-attach")) < order(create.root, one(create.root, "passkey-others")));
  assert.equal(one(create.root, "passkey-browser").textContent, "Use the browser instead");
  assert.equal(one(create.root, "passkey-never").textContent, "Never on this site");
  // The choices answer through the background and nothing else: the item's id, the browser, never, cancel.
  await create.time.tick(400);
  await tap(one(create.root, "passkey-never"));
  assert.deepEqual(create.fake.calls.filter((c) => c.call !== "view"), [{ call: "never", arg: undefined }]);
  assert.equal(create.closed.n, 0, "the window closes after a moment, not before it said what happened");
  await create.time.tick(1000);
  assert.equal(create.closed.n, 1);
});

test("site_texts_are_labelled_ltr_isolated_and_stripped_of_controls", async () => {
  const world = await setup();
  const hostile = {
    rp_name: `Your bank${RLO}moc.knab${ZWSP}${BOM} ${"very long ".repeat(40)}`,
    user: { name: `${LRI}anna${RLO}@example.com`, display_name: `مرحبا ${RLO}evil` },
  };
  const { root } = await open(world, { view: raw({ kind: "create", ...hostile }) });
  const claims = one(root, "passkey-site-texts");
  assert.ok(claims);
  const isolated = every(claims).filter((n) => n.getAttribute("data-site-text") !== null);
  assert.equal(isolated.length, 3, "each text of the website is its own isolated element");
  for (const node of isolated) {
    assert.equal(node.tagName, "BDI", "isolated with bdi, so it cannot reorder the text around it");
    assert.equal(hasRefused(node.textContent), false, `no control or direction character in ${JSON.stringify(node.textContent)}`);
    assert.ok([...node.textContent].length <= 128, "shortened");
  }
  assert.match(one(claims, "passkey-rp-name").textContent, /^Your bank moc\.knab very long/);
  assert.equal(one(claims, "passkey-rp-name").textContent.endsWith("…"), true, "a long text ends with an ellipsis");
  // The label names whose text it is.
  assert.match(claims.textContent, /Site name/);
  assert.match(claims.textContent, /User name/);
  // The cleaning on its own: what is left of a name made of nothing, the length, the plain text.
  assert.equal(world.flow.siteText(`${RLO}${ZWSP}`), "");
  assert.equal(world.flow.siteText("  a \n\t b  "), "a b");
  assert.equal(world.flow.siteText(7), "");
  assert.equal([...world.flow.siteText("x".repeat(500))].length, world.flow.SITE_TEXT_MAX);
  assert.equal(world.flow.siteText("a" + String.fromCharCode(0xd800) + "b"), "a b", "a lone surrogate goes");
  // A name that is empty after the cleaning has the plain stand-in, never a hole.
  const empty = await open(world, { view: raw({ candidates: [{ item_id: ID(1), name: `${RLO}`, user_name: "", created: null }] }) });
  const row = one(empty.root, "passkey-candidate");
  assert.match(row.textContent, /No name/);
  assert.match(row.textContent, /No user name/);
  // The candidates are in order: created, then the item's id.
  const sorted = world.flow.sortCandidates([
    { itemId: ID(9), name: "c", userName: "", created: 5 },
    { itemId: ID(2), name: "b", userName: "", created: 5 },
    { itemId: ID(3), name: "a", userName: "", created: null },
    { itemId: ID(7), name: "d", userName: "", created: 1 },
  ]);
  assert.deepEqual(sorted.map((c) => c.itemId), [ID(7), ID(2), ID(9), ID(3)]);
  assert.equal(world.flow.defaultItemName("www.Example.com"), "Example.com");
  assert.equal(world.flow.defaultItemName("wwwx.example.com"), "wwwx.example.com");
});

test("no_default_button_no_initial_focus_enter_does_nothing", async () => {
  const world = await setup();
  for (const over of [{ candidates: CANDIDATES }, { kind: "create", user: { name: "anna", display_name: "" } }, { candidates: [] }]) {
    const { root, chooser, fake } = await open(world, { view: raw(over) });
    chooser.focus();
    const all = every(root);
    assert.equal(all.filter((n) => n.tagName === "FORM").length, 0, "no form, so nothing submits on Enter");
    assert.equal(all.filter((n) => n.getAttribute("type") === "submit" || n.hasAttribute("autofocus")).length, 0, "no default button, no autofocus");
    assert.equal(/** @type {any} */ (globalThis).document.activeElement?.getAttribute("data-role"), "passkey-title", "the focus starts on the heading");
    // Enter in a field of the window, and on the window itself, does nothing.
    const keydown = (/** @type {any} */ target, /** @type {string} */ key) => {
      const event = { type: "keydown", key, target, defaultPrevented: false, preventDefault() { event.defaultPrevented = true; } };
      for (const [type, fn] of target.listeners) if (type === "keydown") fn(event);
      for (let up = target.parentNode; up; up = up.parentNode) for (const [type, fn] of up.listeners ?? []) if (type === "keydown") fn(event);
      return event;
    };
    const name = one(root, "passkey-name");
    if (name) assert.equal(keydown(name, "Enter").defaultPrevented, true, "Enter in the name field is swallowed");
    assert.equal(keydown(one(root, "passkey-title"), "Enter").defaultPrevented, true, "Enter on the heading is swallowed");
    assert.deepEqual(fake.calls.filter((c) => c.call !== "view"), [], "nothing was sent");
  }
});

test("clicks_count_400_ms_after_focus_and_after_each_content_change_and_only_when_trusted", async () => {
  const world = await setup();
  const state = { view: raw({ candidates: CANDIDATES }) };
  const { root, chooser, fake, time } = await open(world, state);
  const row = () => byRole(root, "passkey-candidate")[0];
  const sent = () => fake.calls.filter((c) => c.call === "choose").length;
  assert.equal(world.flow.GUARD_MS, 400);
  assert.equal(root.getAttribute("data-guarded"), "1", "the window says that it is guarded");
  // Not at once, not at 399 ms.
  await tap(row());
  await time.tick(399);
  await tap(row());
  assert.equal(sent(), 0, "no click counted in the first 400 ms");
  // A click that a script made does not count, whenever it comes.
  await time.tick(1);
  assert.equal(root.getAttribute("data-guarded"), null, "the guard ended");
  await tap(row(), false);
  assert.equal(sent(), 0, "an untrusted click does not count");
  // The focus came to the window again: the 400 ms start again.
  chooser.touch();
  await time.tick(200);
  await tap(row());
  assert.equal(sent(), 0, "400 ms from the focus");
  await time.tick(200);
  // The content changed (a new list): built again, and the 400 ms start again.
  chooser.stop();
  const again = await open(world, { view: raw({ candidates: CANDIDATES.slice(0, 1) }) });
  await again.time.tick(400);
  await tap(byRole(again.root, "passkey-candidate")[0]);
  assert.equal(again.fake.calls.filter((c) => c.call === "choose").length, 1, "a click after the guard, from the person, counts");
  assert.deepEqual(again.fake.calls.find((c) => c.call === "choose")?.arg, { kind: "get", itemId: ID(3) }, "only the item's id is sent, and no claim of presence or verification");
  // A change of content while the window is open starts the guard again (the window got the focus and read a new list).
  const live = { view: raw({ candidates: CANDIDATES.slice(0, 1) }) };
  const polled = await open(world, live, { pollMs: 2000 });
  await polled.time.tick(400);
  assert.equal(polled.root.getAttribute("data-guarded"), null);
  live.view = raw({ candidates: CANDIDATES });
  polled.chooser.focused();
  await polled.time.tick(0);
  assert.equal(byRole(polled.root, "passkey-candidate").length, 2, "the new list is on screen");
  assert.equal(polled.root.getAttribute("data-guarded"), "1", "the guard started again");
  await tap(byRole(polled.root, "passkey-candidate")[0]);
  assert.equal(polled.fake.calls.filter((c) => c.call === "choose").length, 0, "a click on the new list in its first 400 ms does not count");
  await polled.time.tick(400);
  await tap(byRole(polled.root, "passkey-candidate")[0]);
  assert.equal(polled.fake.calls.filter((c) => c.call === "choose").length, 1);
});

test("the_window_cannot_be_framed_and_is_not_web_accessible", async () => {
  const world = await setup();
  for (const manifest of ["mv2", "mv3"]) {
    // The test variant of each manifest version, from the repository's own sources.
    const { build } = await import("../../scripts/build.mjs");
    const { makeRoot } = await import("./buildHelpers.mjs");
    const env = makeRoot();
    try {
      const built = await build({ root: env.root, webRoot: env.webRoot, wasmTar: env.tarPath, out: join(env.out, manifest), manifest, variant: "test" });
      const json = JSON.parse(/** @type {Buffer} */ (built.files.get("manifest.json")).toString("utf8"));
      assert.equal(json.web_accessible_resources, undefined, `${manifest}: no web_accessible_resources, so no page can load the window`);
      const csp = typeof json.content_security_policy === "string" ? json.content_security_policy : json.content_security_policy?.extension_pages;
      assert.match(csp, /frame-ancestors 'none'/, `${manifest}: no page can frame it`);
      assert.equal(built.files.has("pages/passkey.html"), true);
      assert.doesNotMatch(JSON.stringify(json), /passkey\.html/, `${manifest}: the manifest does not name the window`);
      const html = /** @type {Buffer} */ (built.files.get("pages/passkey.html")).toString("utf8");
      assert.match(html, /<script type="module" src="passkey\.mjs"><\/script>/);
      assert.doesNotMatch(html, /<iframe|<form|autofocus|<script>(?!<)/i);
    } finally {
      env.cleanup();
    }
  }
  // The page itself builds nothing inside a frame, and takes a request id of its own only.
  const entry = readFileSync(join(world.dir, "pages", "passkey.mjs"), "utf8");
  assert.match(entry, /window\.top !== window\.self/);
  assert.equal(world.flow.requestIdOf(`?r=${REQUEST}`), REQUEST);
  for (const bad of ["", "?r=", `?r=${REQUEST.toUpperCase()}`, `?r=${REQUEST}&x=1`, `?r=${REQUEST.slice(2)}`, `?x=${REQUEST}`, `#${REQUEST}`]) assert.equal(world.flow.requestIdOf(bad), null, bad);
});

test("a_locked_vault_unlocks_in_the_window_and_that_counts_as_verification", async () => {
  const world = await setup();
  const state = { view: raw({ state: "locked", site: null, candidates: [] }) };
  /** @type {Array<{ call: string, arg?: any }>} */
  const unlockCalls = [];
  /** @type {any} */
  let box = null;
  const unlock = {
    unlock: async (/** @type {any} */ fields) => {
      // The field was emptied before the request went out.
      unlockCalls.push({ call: "unlock", arg: { ...fields, fieldAtTheTime: box.value } });
      // The background opened the vault, took the unlock as the user's (a recent unlock) and says what it holds now.
      state.view = raw({ candidates: CANDIDATES, recent: true });
      return { result: { ok: true }, view: {} };
    },
    pinPolicy: async () => null,
    passkeyOffer: async () => false,
    openPasskeyWindow: async () => true,
  };
  const { root, fake, time } = await open(world, state, { unlock });
  // Locked: the browser's origin is shown (the core says nothing of the site yet), nothing of the vault, and the way on.
  assert.equal(root.getAttribute("data-state"), "locked");
  assert.equal(one(root, "passkey-origin").textContent, "https://www.example.com");
  assert.equal(one(root, "passkey-rp-id"), null, "the RP ID is not shown before the core says it");
  assert.equal(byRole(root, "passkey-candidate").length, 0);
  assert.equal(one(root, "passkey-title").textContent, "Unlock Ferret");
  assert.ok(one(root, "passkey-browser") && one(root, "passkey-cancel"), "the browser and cancel need no unlock");
  assert.equal(one(root, "passkey-never"), null, "\"never\" is not offered while locked: the core says the RP ID only with the vault open");
  const password = one(root, "passkey-password");
  box = password;
  password.value = "correct horse";
  fire(one(root, "passkey-unlock-form"), "submit");
  await settle();
  assert.deepEqual(unlockCalls, [{ call: "unlock", arg: { password: "correct horse", secretKey: "", fieldAtTheTime: "" } }]);
  assert.equal(password.value, "", "the master password is not left in the page");
  // The window reads the view again: the site from the core, the passkeys, and the note that one click is enough.
  assert.equal(root.getAttribute("data-state"), "ready");
  assert.equal(one(root, "passkey-rp-id").textContent, "Passkey for example.com");
  assert.equal(byRole(root, "passkey-candidate").length, 2);
  assert.match(one(root, "passkey-recent").textContent, /one click is enough/);
  // The click is the person's, after the guard; the window says nothing of verification: it is the background's to decide.
  await time.tick(400);
  await tap(byRole(root, "passkey-candidate")[0]);
  const choose = fake.calls.filter((c) => c.call === "choose");
  assert.equal(choose.length, 1);
  assert.deepEqual(Object.keys(choose[0].arg).sort(), ["itemId", "kind"]);
  // A refused password says why and keeps the window locked.
  const refused = { view: raw({ state: "locked", site: null }) };
  const bad = await open(world, refused, { unlock: { ...unlock, unlock: async () => ({ result: { ok: false, reason: "wrong_credentials" }, view: {} }) } });
  const field = one(bad.root, "passkey-password");
  field.value = "x";
  fire(one(bad.root, "passkey-unlock-form"), "submit");
  await settle();
  assert.equal(bad.root.getAttribute("data-state"), "locked");
  assert.equal(one(bad.root, "passkey-unlock-error").hidden, false);
  assert.equal(field.value, "");
});

test("create_says_offline_before_any_verification", async () => {
  const world = await setup();
  const { root, fake } = await open(world, { view: raw({ kind: "create", online: false, user: { name: "anna", display_name: "" }, targets: [{ item_id: ID(5), name: "Example login", user_name: "anna", same_user: true }] }) });
  assert.match(one(root, "passkey-offline").textContent, /cannot save a new passkey without contact with the server/);
  // Nothing to fill in or verify: no new item, no list to add to, no verification place; the browser is the way on.
  for (const role of ["passkey-new", "passkey-attach", "passkey-name", "passkey-create-new", "passkey-verify"]) assert.equal(one(root, role), null, role);
  assert.ok(one(root, "passkey-browser") && one(root, "passkey-never") && one(root, "passkey-cancel"));
  assert.match(one(root, "passkey-browser").getAttribute("class"), /ff-primary/, "the browser is the clear way on");
  assert.deepEqual(fake.calls.filter((c) => c.call !== "view"), [], "no verification was asked for, nothing was sent");
  // The background's own answers decide it: the sync that cannot reach the server makes the window say so; the fake request
  // answers what the real one is told to.
  const requests = [];
  const answers = {
    passkey_pending: { ok: true, request: { request_id: REQUEST, kind: "create", mediation: "optional", origin: SITE.origin, rp_id: null, rp_name: null, user_name: "anna", user_display_name: null, user_verification: "preferred", credentials: 0, prf: false, expires_in: 100, foreign: false, incognito: false } },
    passkey_site: { ok: true, site: SITE },
    sync_state: { running: true, status: "offline", live: "offline", warnings: [] },
  };
  const request = async (/** @type {string} */ type, /** @type {any} */ body) => {
    requests.push({ type, body });
    return answers[/** @type {keyof typeof answers} */ (type)] ?? Promise.reject(Object.assign(new Error("x"), { code: "not_available" }));
  };
  const backend = world.flow.createChooserBackend(request, REQUEST, { has: (/** @type {string} */ type) => type in answers });
  const view = await backend.view();
  assert.equal(view.ok && view.view.online, false);
  answers.sync_state.status = "idle";
  assert.equal((await backend.view()).view.online, true);
});

test("no_match_still_shows_the_window_with_the_browser_choice", async () => {
  const world = await setup();
  const { root, fake } = await open(world, { view: raw({ candidates: [] }) });
  assert.equal(root.getAttribute("data-state"), "ready");
  assert.equal(one(root, "passkey-none").textContent, "No Ferret passkey for this website");
  assert.match(one(root, "passkey-ferret").textContent, /It may be in the browser, on your phone or on a security key/);
  assert.match(one(root, "passkey-more").textContent, /cannot tell that Ferret has none/, "the privacy line is in the disclosure");
  assert.equal(byRole(root, "passkey-candidate").length, 0);
  const browser = one(root, "passkey-browser");
  assert.equal(browser.textContent, "Use the browser or a security key");
  assert.match(browser.getAttribute("class"), /ff-primary/, "the browser is the clear choice");
  assert.deepEqual(fake.calls.filter((c) => c.call !== "view"), []);
  // The window does not depend on a list of Ferret: a background that has no list yet gives the same window.
  const requests = [];
  const answers = {
    passkey_pending: { ok: true, request: { request_id: REQUEST, kind: "get", mediation: "required", origin: SITE.origin, rp_id: null, rp_name: null, user_name: null, user_display_name: null, user_verification: "preferred", credentials: 3, prf: false, expires_in: 100, foreign: false, incognito: false } },
    passkey_site: { ok: true, site: SITE },
  };
  const request = async (/** @type {string} */ type, /** @type {any} */ body) => {
    requests.push({ type, body });
    return answers[/** @type {keyof typeof answers} */ (type)];
  };
  // A background that answers the window's two questions and has no list of Ferret's passkeys (a build whose table lacks the
  // type): the list is not asked for, and the window is the same.
  const { UI_TYPES } = await world.load("shared/protocol.mjs");
  const backend = world.flow.createChooserBackend(request, REQUEST, { has: (/** @type {string} */ type) => type in answers || (Object.hasOwn(UI_TYPES, type) && type !== "passkey_candidates") });
  const view = await backend.view();
  assert.ok(view.ok);
  assert.equal(view.view.candidates.length, 0);
  assert.deepEqual(requests.map((r) => r.type), ["passkey_pending", "passkey_site"]);
  // Only the request's id goes with each message of the window.
  for (const r of requests) assert.deepEqual(Object.keys(r.body), ["request_id"]);
  assert.equal(requests[0].body.request_id, REQUEST);
  // A locked vault: the core refuses the site, the window asks for the unlock, and still has the browser.
  answers.passkey_site = /** @type {any} */ ({ ok: false, reason: "vault_locked" });
  const locked = await backend.view();
  assert.ok(locked.ok);
  assert.equal(locked.view.state, "locked");
  assert.equal(locked.view.site, null);
});

test("the_window_closes_on_answer_abort_timeout_and_navigation", async () => {
  const world = await setup();
  // Answered: the fields go, the window says what happened, and closes after a moment.
  const state = { view: raw({ kind: "create", user: { name: "anna", display_name: "" } }) };
  const created = await open(world, state);
  await created.time.tick(400);
  const name = one(created.root, "passkey-name");
  assert.equal(name.value, "example.com", "the name starts as the host without www");
  name.value = "My login";
  fire(name, "input");
  await tap(one(created.root, "passkey-create-new"));
  assert.deepEqual(created.fake.calls.find((c) => c.call === "choose")?.arg, { kind: "create", mode: "new", name: "My login", folderId: null });
  assert.equal(name.value, "", "what was typed is emptied when the answer goes");
  assert.equal(created.root.getAttribute("data-state"), "ended");
  assert.equal(created.closed.n, 0);
  await created.time.tick(world.view.CLOSE_AFTER_MS);
  assert.equal(created.closed.n, 1);
  assert.equal(created.time.pending(), 0, "no timer is left");
  // An empty name is not sent.
  const empty = await open(world, { view: raw({ kind: "create", user: { name: "anna", display_name: "" } }) });
  await empty.time.tick(400);
  one(empty.root, "passkey-name").value = "   ";
  await tap(one(empty.root, "passkey-create-new"));
  assert.equal(empty.fake.calls.filter((c) => c.call === "choose").length, 0);
  assert.match(one(empty.root, "passkey-error").textContent, /Give the item a name/);
  // The page's abort, the timeout and a navigation end the request in the background; the window finds out and closes, with the
  // same words for each (it is told only that the request is gone).
  for (const reason of ["request_gone", "disconnected", "signed_out"]) {
    const live = { view: raw({ candidates: CANDIDATES }), fail: /** @type {string | null} */ (null) };
    const w = await open(world, live, { pollMs: 2000 });
    await w.time.tick(400);
    live.fail = reason;
    await w.time.tick(2000);
    assert.equal(w.root.getAttribute("data-state"), "ended", reason);
    assert.equal(one(w.root, "passkey-title").textContent, "This request has ended.", reason);
    assert.equal(byRole(w.root, "passkey-candidate").length, 0, "nothing can be chosen any more");
    await w.time.tick(world.view.CLOSE_AFTER_MS);
    assert.equal(w.closed.n, 1, reason);
    assert.equal(w.time.pending(), 0, `${reason}: the poll stopped`);
  }
  // A site the core refuses ends the request with its own words.
  const refused = await open(world, { view: raw({}), fail: "security_error" });
  assert.match(one(refused.root, "passkey-title").textContent, /may not use/);
  await refused.time.tick(world.view.CLOSE_AFTER_MS);
  assert.equal(refused.closed.n, 1);
  // Cancel goes to the background and closes; a refusal that is not "gone" leaves the window and says why.
  const cancelled = await open(world, { view: raw({ candidates: CANDIDATES }) });
  await cancelled.time.tick(400);
  await tap(one(cancelled.root, "passkey-cancel"));
  assert.deepEqual(cancelled.fake.calls.filter((c) => c.call !== "view").map((c) => c.call), ["cancel"]);
  const busy = await open(world, { view: raw({ candidates: CANDIDATES }), choose: { ok: false, reason: "busy" } });
  await busy.time.tick(400);
  await tap(byRole(busy.root, "passkey-candidate")[0]);
  assert.equal(busy.root.getAttribute("data-state"), "ready", "the window stays");
  assert.equal(one(busy.root, "passkey-error").textContent, "Ferret is busy. Try again.");
  // The vault locked while the window waited: what was typed goes, and the unlock shows.
  const lockState = { view: raw({ kind: "create", user: { name: "anna", display_name: "" } }) };
  const lock = await open(world, lockState, { pollMs: 2000 });
  const typed = one(lock.root, "passkey-name");
  typed.value = "half written";
  fire(typed, "input");
  lockState.view = raw({ kind: "create", state: "locked", site: null });
  lock.chooser.focused();
  await lock.time.tick(0);
  assert.equal(lock.root.getAttribute("data-state"), "locked");
  assert.equal(typed.value, "", "a lock empties the fields");
  assert.equal(one(lock.root, "passkey-name"), null);
  // The window closing (the page goes away) empties them too.
  const away = await open(world, { view: raw({ kind: "create", user: { name: "anna", display_name: "" } }) });
  const field = one(away.root, "passkey-name");
  field.value = "left here";
  away.chooser.stop();
  assert.equal(field.value, "");
  assert.equal(away.time.pending(), 0);
});

test("never_on_this_site_is_kept_per_host_and_in_memory_in_private_windows", async () => {
  const world = await setup();
  /** @type {Record<string, unknown>} */
  const disk = {};
  const storageLocal = {
    get: async (/** @type {string} */ key) => (key in disk ? { [key]: structuredClone(disk[key]) } : {}),
    set: async (/** @type {Record<string, unknown>} */ items) => {
      Object.assign(disk, structuredClone(items));
    },
  };
  const never = world.never.createPasskeyNever({ storageLocal });
  assert.equal(world.never.PASSKEY_NEVER_KEY, "passkey_never");
  assert.equal(await never.has("example.com"), false);
  await never.add("Example.com");
  await never.add("xn--bcher-kva.example");
  assert.deepEqual(disk.passkey_never, ["example.com", "xn--bcher-kva.example"], "per RP ID, in the order added, on disk under its own key");
  assert.equal(await never.has("example.com"), true);
  assert.equal(await never.has("EXAMPLE.com"), true);
  assert.equal(await never.has("login.example.com"), false, "per host: a sub-domain is another RP ID");
  assert.equal(await never.has("example.org"), false);
  // A private window's choice stays in memory: never on disk, gone with the browser.
  await never.add("private.example", { incognito: true });
  assert.equal(await never.has("private.example"), true);
  assert.deepEqual(disk.passkey_never, ["example.com", "xn--bcher-kva.example"], "a private window's host never reaches the disk");
  assert.deepEqual(await never.list(), ["example.com", "private.example", "xn--bcher-kva.example"]);
  const restarted = world.never.createPasskeyNever({ storageLocal });
  assert.equal(await restarted.has("example.com"), true, "the disk's entries survive a restart");
  assert.equal(await restarted.has("private.example"), false, "a private window's do not");
  // Not a host name: refused; the list of the offers is a different one.
  await never.add("not a host");
  await never.add("");
  assert.deepEqual(disk.passkey_never, ["example.com", "xn--bcher-kva.example"]);
  assert.equal("capture_never" in disk, false, "the offers' own list is not touched");
  // The newest 500 stay.
  for (let i = 0; i < 510; i += 1) await never.add(`h${i}.example`);
  assert.equal(/** @type {string[]} */ (disk.passkey_never).length, 500);
  assert.equal(/** @type {string[]} */ (disk.passkey_never).at(-1), "h509.example");
  await never.remove("h509.example");
  assert.equal(await never.has("h509.example"), false);
  // The window's side: "Never" sends the request's id and nothing else (the background knows the host and the private window).
  const requests = [];
  const backend = world.flow.createChooserBackend(async (/** @type {string} */ type, /** @type {any} */ body) => {
    requests.push({ type, body });
    return { ok: true };
  }, REQUEST);
  assert.deepEqual(await backend.never(), { ok: true });
  assert.deepEqual(requests, [{ type: "passkey_never", body: { request_id: REQUEST } }]);
  const { UI_TYPES } = await world.load("shared/protocol.mjs");
  assert.ok(UI_TYPES.passkey_never, "the type is in the UI table");
});

test("texts_exist_in_en_and_nb", async () => {
  const world = await setup();
  const en = world.catalog("en");
  const nb = world.catalog("nb");
  const own = (/** @type {Record<string, string>} */ c) => Object.keys(c).filter((k) => k.startsWith("passkeys.")).sort();
  assert.deepEqual(own(nb), own(en), "the two catalogs have the same keys");
  assert.ok(own(en).length > 40);
  for (const key of own(en)) {
    assert.equal(typeof nb[key], "string", key);
    assert.deepEqual([...nb[key].matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort(), [...en[key].matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort(), `${key}: the same placeholders`);
    assert.notEqual(nb[key].trim(), "", key);
  }
  // Every key the page and the steps name is in the catalog; every reason has its text.
  for (const file of ["pages/passkeyChooser.mjs", "pages/passkeyFlow.mjs", "pages/passkey.mjs"]) {
    const source = readFileSync(join(world.dir, ...file.split("/")), "utf8");
    for (const [, key] of source.matchAll(/["'`](passkeys\.[a-z0-9_.]+)["'`]/g)) assert.ok(key in en, `${file}: ${key}`);
  }
  for (const reason of world.flow.CHOOSER_ERRORS) {
    assert.ok(`passkeys.error.${reason}` in en && `passkeys.error.${reason}` in nb, reason);
    assert.equal(world.flow.chooserErrorKey(reason), `passkeys.error.${reason}`);
  }
  assert.equal(world.flow.chooserErrorKey("anything else"), "passkeys.error.unknown");
  assert.ok("passkeys.error.unknown" in en && "passkeys.error.unknown" in nb && "passkeys.error.name_required" in en);
  // Wording: "passkey" stays in Norwegian, the browser and "never" are named as asked.
  assert.equal(nb["passkeys.never"], "Aldri på dette nettstedet");
  assert.match(nb["passkeys.browser.new"], /nettleseren i stedet/);
  assert.match(nb["passkeys.get.none"], /passkey/);
  assert.match(en["passkeys.foreign"], /another password manager or the site itself/i);
  assert.match(nb["passkeys.foreign"], /nettstedet selv/);
  // The texts of a build are those the window uses: it throws on a missing key in the test world's own `textsOf`.
  const { root } = await open(world, { view: raw({ foreign: true, candidates: CANDIDATES }) });
  assert.match(one(root, "passkey-foreign").textContent, /Another password manager or the site itself also handles passkeys here/);
  assert.equal(root.textContent.includes("passkeys."), false, "no key shows as a text");
});

test("the_poll_asks_only_pending_and_never_the_site_so_an_open_window_does_not_keep_the_vault_awake", async () => {
  const world = await setup();
  const state = { view: raw({ candidates: CANDIDATES }), fail: /** @type {string | null} */ (null) };
  const w = await open(world, state, { pollMs: 2000 });
  const before = w.fake.calls.filter((c) => c.call === "view").length;
  for (let i = 0; i < 5; i += 1) await w.time.tick(2000);
  assert.equal(w.fake.calls.filter((c) => c.call === "alive").length, 5, "each tick asks whether the request is still there");
  assert.equal(w.fake.calls.filter((c) => c.call === "view").length, before, "and nothing reads the site or the vault again");
  // The backend's `alive` is the one lock-exempt message, and only that.
  const requests = [];
  const backend = world.flow.createChooserBackend(async (/** @type {string} */ type, /** @type {any} */ body) => {
    requests.push({ type, body });
    return { ok: true, request: {} };
  }, REQUEST, { has: () => true });
  assert.deepEqual(await backend.alive(), { ok: true });
  assert.deepEqual(requests, [{ type: "passkey_pending", body: { request_id: REQUEST } }]);
  // The window reads the view again when it gets the focus, and builds again only if something changed.
  const refreshed = w.fake.calls.filter((c) => c.call === "view").length;
  w.chooser.focused();
  await w.time.tick(0);
  assert.equal(w.fake.calls.filter((c) => c.call === "view").length, refreshed + 1);
});

test("a_locked_window_leaves_the_unlock_by_itself_when_the_vault_is_opened_elsewhere", async () => {
  const world = await setup();
  const state = { view: raw({ state: "locked", site: null }), fail: /** @type {string | null} */ (null) };
  const w = await open(world, state, { pollMs: 2000 });
  assert.equal(w.root.getAttribute("data-state"), "locked");
  // Locked: the poll reads the view (a refused site moves no timer while locked), not only the request.
  await w.time.tick(2000);
  assert.equal(w.root.getAttribute("data-state"), "locked", "nothing changed yet");
  assert.ok(w.fake.calls.filter((c) => c.call === "view").length >= 2, "the poll read the view");
  // The vault is opened in another window (a passkey unlock, the popup): one tick later the window shows the passkeys.
  state.view = raw({ candidates: CANDIDATES });
  await w.time.tick(2000);
  assert.equal(w.root.getAttribute("data-state"), "ready");
  assert.equal(byRole(w.root, "passkey-candidate").length, 2);
  // Once open it asks only whether the request is there.
  const views = w.fake.calls.filter((c) => c.call === "view").length;
  await w.time.tick(2000);
  assert.equal(w.fake.calls.filter((c) => c.call === "view").length, views);
});

test("a_pin_offer_does_not_take_the_focus_and_enter_may_submit_the_unlock_forms", async () => {
  const world = await setup();
  const offer = { allowed: true, afterRestart: true, minLength: 6, set: true, location: "disk", failuresLeft: 5, waitMs: 0, offlineOk: true, lastContactAt: null };
  const unlock = {
    unlock: async () => ({ result: { ok: true }, view: {} }),
    pinPolicy: async () => offer,
    passkeyOffer: async () => false,
    openPasskeyWindow: async () => true,
    pinUnlock: async () => ({ result: { ok: false, reason: "wrong_pin", keys: [], left: 4, waitMs: 0, ended: false }, view: {} }),
  };
  const { root, chooser } = await open(world, { view: raw({ state: "locked", site: null }) }, { unlock });
  chooser.focus();
  await settle();
  assert.ok(one(root, "pin-unlock-form"), "the PIN part is there");
  assert.equal(one(root, "passkey-unlock-form").hidden, true, "and takes the master password's place");
  assert.equal(/** @type {any} */ (globalThis).document.activeElement?.getAttribute("data-role"), "passkey-title", "the focus stays on the heading: nothing the person types lands in the PIN field");
  // Enter in a field of an unlock form is not swallowed (it submits that form); anywhere else on the window it is.
  const keydown = (/** @type {any} */ target) => {
    const event = { type: "keydown", key: "Enter", target, defaultPrevented: false, preventDefault() { event.defaultPrevented = true; } };
    for (let at = target; at; at = at.parentNode) for (const [type, fn] of at.listeners ?? []) if (type === "keydown") fn(event);
    return event;
  };
  assert.equal(keydown(one(root, "passkey-password")).defaultPrevented, false, "Enter in the master password field");
  assert.equal(keydown(byRole(root, "pin-input")[0] ?? one(root, "passkey-password")).defaultPrevented, false, "Enter in the PIN field");
  assert.equal(keydown(one(root, "passkey-title")).defaultPrevented, true, "Enter on the heading");
});

test("the_other_choices_are_one_button_one_row_and_one_disclosure_and_the_rows_are_short", async () => {
  const world = await setup();
  const get = await open(world, { view: raw({ candidates: CANDIDATES }) });
  const others = one(get.root, "passkey-others");
  assert.equal(byRole(get.root, "passkey-more").length, 1, "the explanations are in one disclosure");
  assert.equal(byRole(others, "passkey-more").length, 1);
  assert.match(one(get.root, "passkey-more").textContent, /Windows Hello/);
  assert.match(one(get.root, "passkey-more").textContent, /Never: Ferret leaves passkeys/);
  // No lead paragraph, no "Or".
  assert.equal(one(get.root, "passkey-lead"), null);
  assert.equal(/\bOr\b/.test(get.root.textContent), false);
  // A row: the item and, on one muted line, the user name and the date (the date only when there are several passkeys).
  const row = byRole(get.root, "passkey-candidate")[0];
  assert.match(row.textContent, /anna@example\.com \u00b7 2023-11-14/);
  const single = await open(world, { view: raw({ candidates: CANDIDATES.slice(0, 1) }) });
  assert.equal(/\u00b7/.test(byRole(single.root, "passkey-candidate")[0].textContent), false, "no date for a single passkey");
  // A long list scrolls inside itself: it is focusable, so the keyboard reaches it.
  const many = await open(world, { view: raw({ kind: "create", targets: [1, 2, 3, 4].map((n) => ({ item_id: ID(40 + n), name: "Item " + n, user_name: "u" + n, same_user: false })) }) });
  assert.equal(one(many.root, "passkey-targets").getAttribute("tabindex"), "0");
  assert.equal(one(get.root, "passkey-candidates").getAttribute("tabindex"), null, "a short list does not need it");
  // The mark is in the title row, there is no brand header, and the heading has no ring style of its own to show.
  const head = every(get.root).find((n) => n.getAttribute("class") === "ff-pk-head");
  assert.ok(head && every(head).some((n) => n.getAttribute("class") === "ff-mark"), "the mark sits in the title row");
  const css = readFileSync(join(world.dir, "assets", "app.css"), "utf8");
  assert.doesNotMatch(css, /ff-pk-title:focus-visible/, "the heading shows no focus ring");
  // Name and folder share a row.
  const create = await open(world, { view: raw({ kind: "create", user: { name: "a", display_name: "" }, folders: [{ id: ID(9), name: "Work" }] }) });
  const namerow = every(create.root).find((n) => n.getAttribute("class") === "ff-pk-namerow");
  assert.ok(namerow && one(namerow, "passkey-name") && one(namerow, "passkey-folder"));
});

test("verification_needed_shows_the_step_in_the_window_and_the_same_choice_goes_again_after_it", async () => {
  const world = await setup();
  const state = { view: raw({ candidates: [CANDIDATES[0]], methods: ["prf", "pin", "password", "nonsense"] }) };
  const { root, fake, time } = await open(world, state);
  /** @type {any[]} */
  const verified = [];
  let chooses = 0;
  fake.backend.choose = async (/** @type {any} */ choice) => {
    fake.calls.push({ call: "choose", arg: choice });
    chooses += 1;
    return chooses === 1 ? { ok: false, reason: "verification_needed" } : { ok: true };
  };
  /** @type {any} */ (fake.backend).verify = async (/** @type {string} */ method, /** @type {any} */ input) => {
    verified.push({ method, input, field: one(root, "passkey-verify-pin")?.value });
    return input.pin === "123456" ? { ok: true } : { ok: false, reason: "wrong_pin", left: 4 };
  };
  await time.tick(400);
  await tap(byRole(root, "passkey-candidate")[0]);
  // The step takes the list's place: the chosen passkey, the PIN and the master password (which says it signs in). No passkey
  // button without the window's WebAuthn call (none was given), and only the ways the background named.
  assert.ok(one(root, "passkey-verify-step"));
  assert.equal(one(root, "passkey-chosen").getAttribute("data-item"), CANDIDATES[0].item_id);
  assert.equal(byRole(root, "passkey-candidate").length, 0);
  assert.equal(one(root, "passkey-verify-prf"), null);
  assert.ok(one(root, "passkey-verify-pin-form") && one(root, "passkey-verify-password-form"));
  assert.match(one(root, "passkey-verify-signs-in").textContent, /signing in to your server/);
  assert.ok(one(root, "passkey-browser") && one(root, "passkey-cancel"), "the other choices stay");
  // A wrong PIN: the field is emptied before the request goes out, and the window says how many tries are left.
  const pin = one(root, "passkey-verify-pin");
  pin.value = "000000";
  fire(one(root, "passkey-verify-pin-form"), "submit");
  await settle();
  assert.deepEqual(verified[0], { method: "pin", input: { pin: "000000" }, field: "" });
  assert.match(one(root, "passkey-verify-error").textContent, /4 tries left/);
  assert.equal(chooses, 1);
  // The right PIN: the background issued the mark, and the window sends the same choice again (and closes on the answer).
  one(root, "passkey-verify-pin").value = "123456";
  fire(one(root, "passkey-verify-pin-form"), "submit");
  await settle();
  assert.equal(chooses, 2);
  const choices = fake.calls.filter((c) => c.call === "choose").map((c) => c.arg);
  assert.deepEqual(choices[1], choices[0]);
  assert.equal(root.getAttribute("data-state"), "ended");
});

test("the_verification_step_has_a_passkey_button_only_with_the_windows_call_and_back_returns_to_the_list", async () => {
  const world = await setup();
  const step = await world.load("pages/passkeyVerify.mjs");
  const state = { view: raw({ candidates: CANDIDATES, methods: ["prf"] }) };
  /** @type {any[]} */
  const proved = [];
  const proof = {
    options: async () => ({ ok: true, offer: { rpId: "vault.example", credentials: [{ id: new Uint8Array([1]), salt: new Uint8Array(32) }] } }),
    prove: async (/** @type {any} */ offer) => {
      proved.push(offer.rpId);
      return { ok: true, credential_id: "AQ", prf_output: "x".repeat(43) };
    },
  };
  const { root, fake, time } = await open(world, state, { proof });
  fake.backend.choose = async () => ({ ok: false, reason: "verification_needed" });
  /** @type {any[]} */
  const verified = [];
  /** @type {any} */ (fake.backend).verify = async (/** @type {string} */ method, /** @type {any} */ input) => {
    verified.push({ method, input });
    return { ok: false, reason: "prf_failed" };
  };
  await time.tick(400);
  await tap(byRole(root, "passkey-candidate")[1]);
  await settle();
  const button = one(root, "passkey-verify-prf");
  assert.ok(button, "the passkey of the vault is offered in the window");
  assert.equal(button.hasAttribute("disabled"), false, "once what the call needs is there");
  // A click counts only after the guard, and only when the person made it.
  await tap(button, false);
  assert.equal(proved.length, 0);
  await time.tick(400);
  await tap(button);
  assert.deepEqual(proved, ["vault.example"]);
  assert.deepEqual(verified, [{ method: "prf", input: { credential_id: "AQ", prf_output: "x".repeat(43) } }]);
  assert.match(one(root, "passkey-verify-error").textContent, /does not open your vault/);
  // "Back to the list".
  await time.tick(400);
  await tap(one(root, "passkey-verify-back"));
  assert.equal(byRole(root, "passkey-candidate").length, 2);
  assert.equal(one(root, "passkey-verify-step"), null);
  // Every reason of the step has a text in both languages, and no step text is missing.
  for (const lang of ["en", "nb"]) {
    const catalog = world.catalog(lang);
    for (const reason of [...step.VERIFY_REASONS, "unknown"]) assert.ok(catalog[`passkeys.verify.error.${reason}`], `${lang}: ${reason}`);
    for (const key of ["title", "prf", "pin", "confirm", "signs_in", "back", "none"]) assert.ok(catalog[`passkeys.verify.${key}`], `${lang}: ${key}`);
    assert.ok(catalog["passkeys.error.verification_unavailable"], lang);
  }
});
