// The account page, the password page and their routes, the link in the frame, and the texts.
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { autoLockFor } from "../../src/lock.mjs";
import { createI18n } from "../../src/i18n.mjs";
import { createWipeScope } from "../../src/views/common.mjs";
import { accountView, menuRoutes } from "../../src/views/account.mjs";
import { passwordView } from "../../src/views/password.mjs";
import { SECURITY_ERRORS } from "../../src/views/securityError.mjs";
import { shellView } from "../../src/views/shell.mjs";
import { KNOWN_ERRORS } from "../../src/views/form.mjs";
import { web } from "./helpers.mjs";
import { accountDocument } from "./accountHelpers.mjs";
import { all, click, fakeClient, fakeEngine, fakeSession, find, fire, settle, t as keyT, textOf } from "./vaultHelpers.mjs";

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

const read = (lang, name) => JSON.parse(readFileSync(join(web, "src", "locales", lang, `${name}.json`), "utf8"));
const catalog = (lang) => ({ ...read(lang, "account"), ...read(lang, "security") });
const i18n = (lang) => createI18n({ en: catalog("en"), nb: catalog("nb") }, lang);

/** Every route file of the build, as the generated list would have them. */
async function realRoutes() {
  const dir = join(web, "src", "routes");
  const routes = [];
  for (const file of readdirSync(dir).filter((name) => name.endsWith(".route.mjs")).sort()) {
    routes.push((await import(`../../src/routes/${file}`)).default);
  }
  return routes;
}

// --------------------------------------------------------------- the account page

test("account_page_lists_every_route_with_menu_account", async () => {
  await withDom(async () => {
    const fake = [
      { path: "/b", title: "k.b", menu: "account" },
      { path: "/a", title: "k.a", menu: "account", menuOrder: 5 },
      { path: "/c", title: "k.c", menu: "account", menuOrder: 5 },
      { path: "/items/:id", title: "k.id", menu: "account" },
      { path: "*", title: "k.star", menu: "account" },
      { path: "/other", title: "k.other", menu: "other" },
      { path: "/plain", title: "k.plain" },
    ];
    // The order says first, then the path; a route with a parameter has no address to link to; another menu or none is left out.
    assert.deepEqual(menuRoutes(fake).map((r) => r.path), ["/a", "/c", "/b"]);
    const page = accountView({ t: keyT, routes: fake });
    const links = all(page, "account-link");
    assert.deepEqual(links.map((n) => [n.getAttribute("href"), textOf(n).trim()]), [["#/a", "k.a"], ["#/c", "k.c"], ["#/b", "k.b"]]);
    assert.equal(find(page, "account-menu-empty"), null);

    // A route file added tomorrow with `menu: "account"` shows up with no change to the page.
    const later = accountView({ t: keyT, routes: [...fake, { path: "/later", title: "k.later", menu: "account", menuOrder: 1 }] });
    assert.equal(all(later, "account-link")[0].getAttribute("href"), "#/later");
    // No account page at all says so.
    assert.ok(find(accountView({ t: keyT, routes: [] }), "account-menu-empty"));

    // The real routes: each one that says `menu: "account"` and has a plain address is listed, and the password page is one.
    const routes = await realRoutes();
    const expected = routes.filter((r) => r.menu === "account" && !/[:*]/.test(r.path)).map((r) => r.path).sort();
    assert.ok(expected.includes("/password"));
    const real = accountView({ t: keyT, routes });
    assert.deepEqual(all(real, "account-link").map((n) => n.getAttribute("data-path")).sort(), expected);
    // The account page is not one of its own entries.
    assert.ok(!expected.includes("/account"));
    for (const route of routes.filter((r) => r.menu !== undefined)) assert.equal(typeof route.menu, "string");
  });
});

test("the_account_page_shows_whether_the_password_was_confirmed_and_opens_the_dialog", async () => {
  await withDom(async () => {
    let until = null;
    const opened = [];
    const page = accountView({
      t: keyT,
      routes: [],
      email: "ada@example.test",
      locale: "en",
      fresh: () => until,
      reauth: async () => {
        opened.push("dialog");
        until = 1_900_000_000_000;
        return "ok";
      },
    });
    assert.match(textOf(find(page, "account-email")), /ada@example.test/);
    assert.equal(find(page, "reauth-state").getAttribute("data-fresh"), "false");
    await click(find(page, "reauth-button"));
    await settle();
    assert.deepEqual(opened, ["dialog"]);
    assert.equal(find(page, "reauth-state").getAttribute("data-fresh"), "true");
    assert.equal(find(page, "reauth-done").hidden, false);
    // A dialog that was cancelled says nothing new.
    const cancelled = accountView({ t: keyT, routes: [], reauth: async () => "cancelled" });
    await click(find(cancelled, "reauth-button"));
    await settle();
    assert.equal(find(cancelled, "reauth-done").hidden, true);
    // Without a way to open the dialog there is no button.
    assert.equal(find(accountView({ t: keyT, routes: [] }), "reauth-button"), null);
  });
});

// ------------------------------------------------------------ the password page

const typeInto = (page, values) => {
  for (const [role, value] of Object.entries(values)) find(page, role).value = value;
};

test("the_page_says_old_exports_and_backups_still_open_with_the_old_password", async () => {
  for (const [lang, before, after] of [
    ["en", /still open with your old password/, /still open with the old password/],
    ["nb", /åpnes fortsatt med det gamle passordet ditt/, /åpnes fortsatt med det gamle passordet/],
  ]) {
    await withDom(async () => {
      const page = passwordView({ t: i18n(lang).t, change: async () => ({ kekGeneration: 2 }), skBit: true });
      // Said before the change, where the user decides ...
      assert.match(textOf(find(page, "old-files-notice")), before);
      assert.equal(find(page, "old-files-notice").hidden === true, false);
      typeInto(page, { "current-password": "a-current-password", "new-password": "a-new-password-1", "new-password-again": "a-new-password-1" });
      await fire(find(page, "password-form"), "submit");
      await settle();
      // ... and again after it, on the page that tells what happened.
      assert.equal(find(page, "password-done").hidden, false);
      assert.match(textOf(find(page, "done-old-files")), after);
    });
  }
});

test("the_page_says_other_devices_are_signed_out_and_a_backup_was_asked_for", async () => {
  for (const [lang, devices, backup] of [
    ["en", /Every other device and browser was signed out/, /asked to make a new backup/],
    ["nb", /Alle andre enheter og nettlesere ble logget ut/, /bedt om å ta en ny backup/],
  ]) {
    await withDom(async () => {
      const page = passwordView({ t: i18n(lang).t, change: async () => ({ kekGeneration: 2 }) });
      // Nothing of it is claimed before the server has accepted the change.
      assert.equal(find(page, "password-done").hidden, true);
      typeInto(page, { "current-password": "a-current-password", "new-password": "a-new-password-1", "new-password-again": "a-new-password-1" });
      await fire(find(page, "password-form"), "submit");
      await settle();
      assert.match(textOf(find(page, "done-devices")), devices);
      assert.match(textOf(find(page, "done-backup")), backup);
      // The form is gone, and the sheet is said to be valid as it is.
      assert.equal(find(page, "password-form").hidden, true);
      assert.ok(textOf(find(page, "done-sheet")).length > 20);
    });
  }
});

test("the_password_page_empties_the_fields_before_the_call_and_names_a_refusal_without_the_password", async () => {
  await withDom(async () => {
    const seen = [];
    let release;
    const gate = new Promise((resolve) => {
      release = resolve;
    });
    let failWith = Object.assign(new Error("x"), { code: "write_conflict" });
    const change = async (args) => {
      seen.push({ ...args, fields: ["current-password", "new-password", "new-password-again"].map((role) => find(page, role).value) });
      await gate;
      if (failWith) throw failWith;
      return { kekGeneration: 2 };
    };
    const page = passwordView({ t: i18n("en").t, change, skBit: true });
    typeInto(page, { "current-password": "a-current-password", "new-password": "a-new-password-1", "new-password-again": "a-new-password-1" });
    const submitted = fire(find(page, "password-form"), "submit");
    await settle();
    assert.deepEqual(seen[0].fields, ["", "", ""], "the fields were empty when the call started");
    assert.equal(find(page, "submit").disabled, true);
    assert.equal(page.getAttribute("aria-busy"), "true");
    release();
    await submitted;
    assert.match(textOf(find(page, "error")), /unlock methods changed on the server/);
    assert.doesNotMatch(textOf(page), /a-current-password|a-new-password-1/);
    assert.equal(find(page, "password-done").hidden, true, "a refused change is not reported as done");
    assert.equal(find(page, "password-form").hidden === true, false, "the form is there for another try");

    // The page stops what it can see is wrong, without calling anything, and keeps what was typed.
    const calls = [];
    const stopper = passwordView({ t: i18n("en").t, change: async (args) => calls.push(args) });
    typeInto(stopper, { "current-password": "a-current-password", "new-password": "a-new-password-1", "new-password-again": "a-new-password-2" });
    await fire(find(stopper, "password-form"), "submit");
    assert.match(textOf(find(stopper, "error")), /not the same/);
    typeInto(stopper, { "new-password": "a-current-password", "new-password-again": "a-current-password" });
    await fire(find(stopper, "password-form"), "submit");
    assert.match(textOf(find(stopper, "error")), /same as the current/);
    typeInto(stopper, { "current-password": "", "new-password": "", "new-password-again": "" });
    await fire(find(stopper, "password-form"), "submit");
    assert.match(textOf(find(stopper, "error")), /Enter the master password/);
    assert.deepEqual(calls, []);

    // A lock of the vault empties the fields.
    const scope = createWipeScope();
    const locked = passwordView({ t: i18n("en").t, change: async () => ({}), scope });
    typeInto(locked, { "current-password": "a-current-password", "new-password": "x" });
    scope.run();
    assert.equal(find(locked, "current-password").value, "");
    assert.equal(find(locked, "new-password").value, "");
    failWith = null;
  });
});

test("an_unknown_outcome_hides_the_form_and_tells_the_user_to_try_the_new_password_first", async () => {
  for (const [lang, text] of [["en", /unlock it with the new master password first/], ["nb", /lås det opp med det nye hovedpassordet først/]]) {
    await withDom(async () => {
      let calls = 0;
      const change = async () => {
        calls += 1;
        throw Object.assign(new Error("x"), { code: "change_unconfirmed" });
      };
      const page = passwordView({ t: i18n(lang).t, change, skBit: true });
      typeInto(page, { "current-password": "a-current-password", "new-password": "a-new-password-1", "new-password-again": "a-new-password-1" });
      await fire(find(page, "password-form"), "submit");
      await settle();
      assert.match(textOf(find(page, "error")), text);
      // The form is gone, so the same change is not sent again with the old password as "current", and no success is claimed.
      assert.equal(find(page, "password-form").hidden, true);
      assert.equal(find(page, "password-done").hidden, true);
      assert.equal(calls, 1);
    });
  }
});

test("the_secret_key_is_asked_for_only_when_the_device_does_not_hold_it", async () => {
  await withDom(async () => {
    const calls = [];
    const change = async (args) => {
      calls.push(args);
      return { kekGeneration: 2 };
    };
    const without = passwordView({ t: i18n("en").t, change, skRequired: false });
    assert.equal(find(without, "secret-key"), null);
    const asked = passwordView({ t: i18n("en").t, change, skRequired: true });
    assert.ok(find(asked, "secret-key"));
    typeInto(asked, { "current-password": "a-current-password", "new-password": "a-new-password-1", "new-password-again": "a-new-password-1" });
    await fire(find(asked, "password-form"), "submit");
    assert.deepEqual(calls, [], "nothing is sent without the code");
    assert.match(textOf(find(asked, "error")), /secret key/);
    find(asked, "secret-key").value = " FFS1-TEST ";
    await fire(find(asked, "password-form"), "submit");
    assert.equal(calls[0].skCode, "FFS1-TEST");
    // A flow that finds out late that it needs the code shows the field.
    const late = passwordView({ t: i18n("en").t, change: async () => { throw Object.assign(new Error("x"), { code: "sk_required" }); } });
    typeInto(late, { "current-password": "a-current-password", "new-password": "a-new-password-1", "new-password-again": "a-new-password-1" });
    await fire(find(late, "password-form"), "submit");
    assert.ok(find(late, "secret-key"));
  });
});

// ------------------------------------------------------------------ the routes

function rig({ open = true, status = { pinned: true, skBit: true, skStored: true } } = {}) {
  const engine = fakeEngine();
  const client = fakeClient(engine);
  const session = fakeSession({ client, open, status });
  const changes = [];
  const reauths = [];
  session.changePassword = async (args) => {
    changes.push(args);
    return { kekGeneration: 2, until: 1 };
  };
  session.reauthenticate = async (args) => {
    reauths.push(args);
    return { until: 1 };
  };
  session.reauthUntil = () => null;
  const sync = { current: () => engine, start: async () => engine, stop: () => engine.stop(), discard: engine.discard };
  const moves = [];
  const routes = [];
  const ctx = (path) => ({
    params: {}, path, i18n: { t: keyT, lang: "en", missing: [] }, client, services: { crypto: session, sync }, go: (p) => moves.push(p), routes,
  });
  return { engine, session, sync, changes, reauths, moves, routes, ctx, done: () => autoLockFor(session, sync).stop() };
}

test("password_route_is_no_longer_the_placeholder", async () => {
  await withDom(async () => {
    const route = (await import("../../src/routes/password.route.mjs")).default;
    assert.equal(route.path, "/password");
    assert.equal(route.menu, "account");
    assert.equal(route.title, "security.password.title");

    // A locked vault shows the unlock screen, and the page comes back after it.
    const closed = rig({ open: false });
    try {
      const node = await route.load(closed.ctx("/password"));
      await settle();
      assert.ok(find(node, "unlock"));
      assert.equal(find(node, "password-form"), null);
    } finally {
      closed.done();
    }

    // An open vault shows the real page in the vault frame, with the three fields and no "not available" text.
    const r = rig();
    try {
      const node = await route.load(r.ctx("/password"));
      assert.ok(find(node, "shell"), "inside the vault frame");
      assert.ok(find(node, "password-page"));
      for (const role of ["current-password", "new-password", "new-password-again", "submit"]) assert.ok(find(node, role), role);
      assert.equal(find(node, "secret-key"), null, "this device holds the secret key");
      assert.doesNotMatch(textOf(node), /not_available|not available/);
      // Submitting reaches the session's change with exactly what was typed.
      typeInto(node, { "current-password": "a-current-password", "new-password": "a-new-password-1", "new-password-again": "a-new-password-1" });
      await fire(find(node, "password-form"), "submit");
      await settle();
      assert.deepEqual(r.changes, [{ current: "a-current-password", next: "a-new-password-1", nextAgain: "a-new-password-1" }]);
    } finally {
      r.done();
    }

    // A device that does not hold the secret key asks for it.
    const asking = rig({ status: { pinned: true, skBit: true, skStored: false } });
    try {
      assert.ok(find(await route.load(asking.ctx("/password")), "secret-key"));
    } finally {
      asking.done();
    }
  });
});

test("the_account_route_lists_the_pages_and_opens_the_dialog_in_the_page", async () => {
  await withDom(async () => {
    const route = (await import("../../src/routes/account.route.mjs")).default;
    assert.equal(route.path, "/account");
    assert.equal(route.menu, undefined, "the account page is not an entry of its own menu");
    const r = rig();
    r.routes.push(...(await realRoutes()));
    try {
      const node = await route.load(r.ctx("/account"));
      assert.ok(find(node, "account-page"));
      assert.ok(all(node, "account-link").some((n) => n.getAttribute("data-path") === "/password"));
      // The button opens the dialog in the page; the typed password goes to the session's re-authentication.
      const clicking = click(find(node, "reauth-button")); // it ends when the dialog is answered
      await settle();
      const dialog = globalThis.document.body.childNodes.find((n) => n.getAttribute?.("data-role") === "reauth-dialog");
      assert.ok(dialog, "the dialog is in the page");
      find(dialog, "reauth-password").value = "a-current-password";
      await fire(find(dialog, "reauth-form"), "submit");
      await settle();
      await clicking;
      assert.deepEqual(r.reauths, [{ password: "a-current-password" }]);
      assert.equal(globalThis.document.body.childNodes.find((n) => n.getAttribute?.("data-role") === "reauth-dialog"), undefined);
    } finally {
      r.done();
    }
  });
});

test("the_frame_has_an_account_link_that_is_marked_on_the_pages_of_the_account", async () => {
  await withDom(async () => {
    const win = { location: { hash: "#/items" }, addEventListener() {}, removeEventListener() {} };
    const root = shellView({
      t: keyT, engine: fakeEngine(), session: { onLock() {} }, content: globalThis.document.createElement("div"),
      lock: async () => {}, touch: () => true, scope: createWipeScope(), onLocked: () => globalThis.document.createElement("div"), win,
    });
    const link = find(root, "nav-account");
    assert.equal(link.getAttribute("href"), "#/account");
    assert.equal(textOf(link).trim(), "security.nav.account");
    assert.equal(link.getAttribute("aria-current"), "false");
    // It stands in a landmark of its own, with its own name.
    const nav = [...allNodes(root)].find((n) => n.tagName === "nav" && n.getAttribute("data-role") === null && n.getAttribute("aria-label") === "security.nav.account");
    assert.ok(nav, "an account navigation landmark");
    assert.ok([...allNodes(nav)].includes(link));
  });
});

function* allNodes(node) {
  yield node;
  for (const child of node.childNodes ?? []) yield* allNodes(child);
}

test("the_account_link_is_marked_on_the_account_page_and_on_every_page_it_lists", async () => {
  await withDom(async () => {
    const listeners = [];
    const win = { location: { hash: "#/items" }, addEventListener: (type, fn) => listeners.push([type, fn]), removeEventListener() {} };
    const root = shellView({
      t: keyT, engine: fakeEngine(), session: { onLock() {} }, content: globalThis.document.createElement("div"),
      lock: async () => {}, touch: () => true, scope: createWipeScope(), onLocked: () => globalThis.document.createElement("div"), win,
      accountPaths: menuRoutes([{ path: "/password", title: "k", menu: "account" }, { path: "/later-page", title: "k", menu: "account" }]).map((r) => r.path),
    });
    const link = find(root, "nav-account");
    const mark = (hash) => {
      win.location.hash = hash;
      for (const [type, fn] of listeners) if (type === "hashchange") fn();
      return link.getAttribute("aria-current");
    };
    assert.equal(mark("#/account"), "page");
    assert.equal(mark("#/password"), "page");
    // A page that a later task adds to the menu is marked with no change to the frame.
    assert.equal(mark("#/later-page"), "page");
    assert.equal(mark("#/items"), "false");
    assert.equal(mark("#/not-listed"), "false");
  });
});

// ---------------------------------------------------------------------- the texts

test("security_texts_exist_in_both_languages", () => {
  const en = read("en", "security");
  const nb = read("nb", "security");
  assert.deepEqual(Object.keys(en).sort(), Object.keys(nb).sort());
  const placeholders = (text) => [...text.matchAll(/\{([a-z]+)\}/g)].map((m) => m[1]).sort().join(",");
  for (const [key, value] of Object.entries(en)) {
    assert.ok(key.startsWith("security."), key);
    assert.equal(typeof value, "string");
    assert.ok(value.length > 0 && nb[key].length > 0, key);
    assert.equal(placeholders(value), placeholders(nb[key]), `${key}: the same placeholders in both languages`);
  }
  // Every text the sources name exists, and every text is named (the error texts by the list of codes).
  const used = new Set();
  for (const dir of ["views", "flows", "crypto", "routes"]) {
    for (const file of readdirSync(join(web, "src", dir))) {
      const source = readFileSync(join(web, "src", dir, file), "utf8");
      for (const match of source.matchAll(/["'`](security\.[a-z0-9_.]+)["'`]/g)) used.add(match[1]);
    }
  }
  for (const key of used) assert.ok(key in en, `missing text: ${key}`);
  for (const code of SECURITY_ERRORS) assert.ok(`security.error.${code}` in en, `missing error text: ${code}`);
  for (const key of Object.keys(en)) {
    const code = key.startsWith("security.error.") ? key.slice("security.error.".length) : null;
    assert.ok(used.has(key) || (code !== null && SECURITY_ERRORS.includes(code)), `unused text: ${key}`);
  }
  // The codes the core and the server added for these flows have their texts in both languages.
  for (const code of ["generation_exhausted", "secret_key_not_held", "reauth_required", "second_factor_required", "write_conflict"]) {
    assert.ok(`security.error.${code}` in en && `security.error.${code}` in nb, code);
  }
  // The codes the pages translate without a text of their own are the sign-in's, which exist.
  for (const code of ["password_mismatch", "password_required", "sk_required", "session_ended", "input_too_short", "network", "throttled", "two_factor_unsupported", "pinned_auth_key"]) {
    assert.ok(KNOWN_ERRORS.includes(code), code);
  }
});

test("the_new_sources_never_keep_a_secret_in_storage_the_console_or_the_address", () => {
  const files = [
    "flows/reauth.mjs", "flows/signedCall.mjs", "flows/opaqueRegister.mjs", "flows/changePassword.mjs",
    "views/reauthDialog.mjs", "views/account.mjs", "views/password.mjs", "views/securityError.mjs",
    "routes/account.route.mjs", "routes/password.route.mjs",
  ];
  for (const file of files) {
    const source = readFileSync(join(web, "src", file), "utf8");
    assert.doesNotMatch(source, /localStorage|sessionStorage|console\.|indexedDB|document\.cookie|\.innerHTML|\.outerHTML|eval\(|new Function/, file);
    assert.doesNotMatch(source, /location\s*[.=]|history\.|window\.open|navigator\.clipboard|fetch\(/, `${file} never writes the address or leaves the API client`);
  }
});
