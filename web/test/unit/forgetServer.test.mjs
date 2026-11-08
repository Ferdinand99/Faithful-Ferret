// "Forget this server": the flow (in order, under the lock of the sync memory, after one
// confirmation), what it removes from the real stores, the page, and the link on the
// sign-in page.
import assert from "node:assert/strict";
import { test } from "node:test";
import { b64u, hex16 } from "../../src/b64.mjs";
import { forgetServer, resolveForgetTarget } from "../../src/flows/forgetServer.mjs";
import { cache } from "../../src/store/cache.mjs";
import { forgetServer as forgetRecords, pendingWrites, sharedAccount } from "../../src/store/forget.mjs";
import { outbox } from "../../src/store/outbox.mjs";
import { loadPinned, loadPinnedAccount, loadPinnedByAccount, pinnedForSignIn, savePinned } from "../../src/store/pinned.mjs";
import { deviceSecrets } from "../../src/store/settings.mjs";
import { loadSyncState, saveSyncState } from "../../src/store/syncState.mjs";
import { forgetView } from "../../src/views/forget.mjs";
import { loginView } from "../../src/views/login.mjs";
import { ACCOUNT, SERVER, VAULT, freshStore, pinnedRecord, scope } from "./idbHelpers.mjs";
import { accountDocument } from "./accountHelpers.mjs";
import { click, find, settle, submit, textOf } from "./vaultHelpers.mjs";
import { EN, NB, textFor, translator, withFocus } from "./syncWarningsHelpers.mjs";

const EMAIL = "ada@example.test";

/** Runs a test body with a fake document whose elements start with the properties a real one has. */
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
const OTHER_ORIGIN = "https://other.example";
const bytes = (n, fill) => new Uint8Array(n).fill(fill);
const id = (n) => n.toString(16).padStart(32, "0");

/** A queued write, as the outbox wants it. */
function queued(n) {
  const blob = bytes(48, n);
  const tag = bytes(32, n + 100);
  const fields = { base_rev: 0, blob: b64u.encode(blob), tag: b64u.encode(tag), idem: id(n + 1000) };
  return { idem: id(n + 1000), itemId: id(n), baseRev: 0, body: { blob, tag }, bytes: new TextEncoder().encode(JSON.stringify(fields)) };
}

/** What a device holds for an account on a server: a pinned record, a sync state, a sealed secret key, rows and queued writes. */
async function populate(db, server, accountId, { writes = 0, email = EMAIL } = {}) {
  await savePinned(db, server, accountId, email, pinnedRecord({ accountId, server }));
  await saveSyncState(db, server, accountId, { memory: bytes(8, 1), restoreEpoch: 1, verifiedAt: 10, verifiedSeq: 5, uploadedAt: 20, uploadedSeq: 5, hardWarning: null, restore: null });
  await deviceSecrets.put(db, server, accountId, {
    key: await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]),
    iv: bytes(12, 1),
    sealed: bytes(40, 2),
  });
  await cache.putRows(db, scope(1, accountId, VAULT), [{ itemId: id(1), rev: 1, seq: 1, deleted: false, envelope: bytes(16, 1), tag: bytes(32, 1), tomb: null }]);
  for (let n = 0; n < writes; n += 1) await outbox.enqueue(db, scope(1, accountId, VAULT), queued(n + 1));
}

/** The pieces of the flow over a real database, with a log of what happens in what order. */
async function rig({ writes = 0, confirm = async () => true, server = SERVER } = {}) {
  const opened = await freshStore();
  const db = opened.store;
  await populate(db, server, ACCOUNT, { writes });
  const log = [];
  let heldLock = null;
  const store = {
    open: async () => db,
    pendingWrites,
    sharedAccount,
    loadPinnedAccount,
    pinHintForEmail: loadPinned,
    forgetServer: async (...args) => {
      log.push(["forgetServer", heldLock]);
      return forgetRecords(...args);
    },
  };
  const locks = {
    async request(name, callback) {
      log.push(["lock request", name]);
      heldLock = name;
      try {
        return await callback();
      } finally {
        heldLock = null;
      }
    },
  };
  const session = {
    async lock() {
      log.push(["session.lock"]);
    },
    async forgetSecretKey(accountId) {
      log.push(["forgetSecretKey", accountId]);
      await deviceSecrets.delete(db, server, accountId);
    },
  };
  const api = {
    failLogout: false,
    async post(path) {
      log.push(["post", path]);
      if (api.failLogout) throw new Error("offline");
      return {};
    },
  };
  const channel = { postMessage: (message) => log.push(["channel", message]), close: () => log.push(["channel closed"]) };
  const navigated = [];
  const options = {
    api, session, store, serverUrl: server, accountId: ACCOUNT, locks, channel,
    confirm: async (info) => {
      log.push(["confirm", info]);
      return confirm(info);
    },
    navigate: (hash, result) => {
      log.push(["navigate", hash]);
      navigated.push([hash, result]);
    },
  };
  return { db, store, session, api, locks, channel, log, navigated, options, server };
}

test("forget_warns_with_the_count_of_unsent_writes_and_does_nothing_on_cancel", async () => {
  const r = await rig({ writes: 3, confirm: async () => false });
  assert.equal(await forgetServer(r.options), "cancelled");
  assert.deepEqual(r.log, [["confirm", { pending: 3, shared: false }]], "the user is asked with the count, and nothing else happens");
  assert.deepEqual(r.navigated, []);
  // Everything is where it was.
  assert.ok(await loadPinnedByAccount(r.db, SERVER, ACCOUNT));
  assert.ok(await loadSyncState(r.db, SERVER, ACCOUNT));
  assert.equal(await pendingWrites(r.db, ACCOUNT), 3);
  // With nothing unsent the count is zero, which the dialog says by leaving the warning out.
  const none = await rig({ writes: 0, confirm: async () => false });
  await forgetServer(none.options);
  assert.deepEqual(none.log, [["confirm", { pending: 0, shared: false }]]);
  // A confirm that answers anything but true is a no (a truthy value that is not true does not count).
  const odd = await rig({ confirm: async () => "yes" });
  assert.equal(await forgetServer(odd.options), "cancelled");
  assert.ok(await loadPinnedByAccount(odd.db, SERVER, ACCOUNT));
});

test("forget_signs_out_locks_and_removes_the_account_data_and_the_sealed_sk", async () => {
  const r = await rig({ writes: 2 });
  assert.equal(await forgetServer(r.options), "forgotten");
  const name = `ferret-sync-memory:${SERVER}:${ACCOUNT}`;
  assert.deepEqual(r.log.map((entry) => entry[0]), [
    "confirm", "channel", "post", "session.lock", "lock request", "forgetServer", "forgetSecretKey", "channel", "navigate",
  ], "the order of the design: the other tabs are told before anything is removed, and again when it is done");
  const told = r.log.filter((entry) => entry[0] === "channel").map((entry) => entry[1].type);
  assert.deepEqual(told, ["forgetting", "forgotten"]);
  assert.deepEqual(r.log.find((entry) => entry[0] === "post"), ["post", "/api/auth/logout"]);
  // The records are removed inside the lock of the sync memory of this server and account.
  assert.deepEqual(r.log.find((entry) => entry[0] === "forgetServer"), ["forgetServer", name]);
  assert.deepEqual(r.log.find((entry) => entry[0] === "lock request"), ["lock request", name]);
  assert.deepEqual(r.log.find((entry) => entry[0] === "forgetSecretKey"), ["forgetSecretKey", ACCOUNT]);
  assert.deepEqual(r.log.filter((entry) => entry[0] === "channel").at(-1), ["channel", { type: "forgotten", serverKey: SERVER, accountId: ACCOUNT }]);
  assert.deepEqual(r.navigated[0][0], "#/login");
  assert.equal(r.navigated[0][1].shared, undefined);
  // Gone: the pinned record, the sync state, the sealed secret key, the rows and the queued writes.
  assert.equal(await loadPinnedByAccount(r.db, SERVER, ACCOUNT), null);
  assert.equal(await loadSyncState(r.db, SERVER, ACCOUNT), null);
  assert.equal(await deviceSecrets.get(r.db, SERVER, ACCOUNT), null);
  assert.equal(await pendingWrites(r.db, ACCOUNT), 0);
  assert.deepEqual(await cache.getRows(r.db, scope(1, ACCOUNT, VAULT)), []);
  assert.deepEqual(r.navigated[0][1].removed.outbox, 2);
});

test("forget_goes_on_when_the_server_cannot_be_reached_and_says_nothing_of_its_failure", async () => {
  const r = await rig();
  r.api.failLogout = true;
  assert.equal(await forgetServer(r.options), "forgotten");
  assert.equal(await loadPinnedByAccount(r.db, SERVER, ACCOUNT), null);
  // A failing lock stops it before anything is removed.
  const stuck = await rig();
  stuck.session.lock = async () => {
    throw new Error("worker gone");
  };
  await assert.rejects(forgetServer(stuck.options), /worker gone/);
  assert.ok(await loadPinnedByAccount(stuck.db, SERVER, ACCOUNT), "nothing was removed");
  assert.deepEqual(stuck.navigated, []);
});

test("forget_runs_without_web_locks_and_without_a_channel_it_made_itself", async () => {
  const r = await rig();
  const { locks, channel, ...rest } = r.options;
  const posted = [];
  const saved = globalThis.BroadcastChannel;
  globalThis.BroadcastChannel = class {
    constructor(name) {
      this.name = name;
    }
    postMessage(message) {
      posted.push([this.name, message]);
    }
    close() {
      posted.push(["closed"]);
    }
  };
  try {
    assert.equal(await forgetServer({ ...rest, locks: null }), "forgotten");
  } finally {
    if (saved === undefined) delete globalThis.BroadcastChannel;
    else globalThis.BroadcastChannel = saved;
  }
  assert.deepEqual(posted, [
    ["ferret", { type: "forgetting", serverKey: SERVER, accountId: ACCOUNT }],
    ["ferret", { type: "forgotten", serverKey: SERVER, accountId: ACCOUNT }],
    ["closed"],
  ]);
  assert.equal(await loadPinnedByAccount(r.db, SERVER, ACCOUNT), null);
});

test("after_forget_the_next_sign_in_is_first_use", async () => {
  const r = await rig();
  // Before: the device knows the account by its e-mail address.
  assert.ok(await loadPinned(r.db, SERVER, EMAIL));
  assert.ok(await pinnedForSignIn(r.db, SERVER, EMAIL, ACCOUNT));
  await forgetServer(r.options);
  // After: neither the e-mail nor the account id finds a record, which is what a first use is.
  assert.equal(await loadPinned(r.db, SERVER, EMAIL), null);
  assert.equal(await pinnedForSignIn(r.db, SERVER, EMAIL, ACCOUNT), null);
  assert.equal(await loadSyncState(r.db, SERVER, ACCOUNT), null, "the memory starts empty, which the engine seeds again");
});

test("forget_reports_shared_records_and_keeps_them_when_another_address_has_the_same_account", async () => {
  const r = await rig();
  await populate(r.db, OTHER_ORIGIN, ACCOUNT, { writes: 1 });
  await forgetServer(r.options);
  const [, result] = r.navigated[0];
  assert.equal(result.shared, true);
  assert.equal(result.removed.rows, 0, "the rows are kept, and reported as kept");
  // This address is forgotten; the other keeps its rows and its queued write.
  assert.equal(await loadPinnedByAccount(r.db, SERVER, ACCOUNT), null);
  assert.ok(await loadPinnedByAccount(r.db, OTHER_ORIGIN, ACCOUNT));
  assert.equal(await pendingWrites(r.db, ACCOUNT), 1);
});

// ------------------------------------------------------------------ the page

/** The page over the real flow, with a dialog that the test answers. */
async function pageRig({ writes = 0, accountId = ACCOUNT, email = EMAIL, lang = "en", extra } = {}) {
  const r = await rig({ writes });
  if (extra) await extra(r);
  const went = [];
  const flow = (options) => forgetServer({ ...options, locks: r.locks, channel: r.channel });
  const root = forgetView({
    t: translator(lang), session: r.session, store: r.store, api: r.api, serverUrl: SERVER, accountId, email, go: (path) => went.push(path), forget: flow,
  });
  return { ...r, root, went };
}

const dialog = (root) => find(root, "dialog");

test("the_forget_page_asks_in_a_dialog_with_the_count_and_does_nothing_on_cancel", async () => {
  await withDom(async () => {
    const p = await pageRig({ writes: 2 });
    await click(find(p.root, "forget-start"));
    await settle();
    const text = textOf(dialog(p.root));
    assert.ok(text.includes(textFor(EN, "syncwarnings.forget.dialog_title")));
    assert.ok(text.includes(textFor(EN, "syncwarnings.forget.dialog_body_pending", { count: 2, email: EMAIL })), "the count of unsent changes is in the text");
    assert.ok(text.includes("Nothing on the server is deleted"), "what is certain is said");
    assert.ok(text.includes(EMAIL), "the dialog names the account by the address of this device's own record");
    // Cancel is what has the focus and what Escape does; here it is pressed.
    await click(find(p.root, "dialog-cancel"));
    await settle();
    assert.equal(dialog(p.root), null);
    assert.match(textOf(find(p.root, "forget-note")), /Nothing was changed/);
    assert.equal(find(p.root, "forget-start").disabled, false);
    assert.ok(await loadPinnedByAccount(p.db, SERVER, ACCOUNT));
    assert.deepEqual(p.log, [], "nothing was done");
    // Without unsent writes the dialog has no warning about them.
    const none = await pageRig({ writes: 0, lang: "nb" });
    await click(find(none.root, "forget-start"));
    await settle();
    assert.ok(textOf(dialog(none.root)).includes(textFor(NB, "syncwarnings.forget.dialog_body", { email: EMAIL })));
    assert.ok(textOf(dialog(none.root)).includes("tjeneren"), "one word for the server in Norwegian");
    assert.doesNotMatch(textOf(dialog(none.root)), /serveren/);
    assert.ok(!textOf(dialog(none.root)).includes("som går tapt"));
  });
});

test("the_forget_page_confirms_forgets_and_says_what_stayed_when_the_records_are_shared", async () => {
  await withDom(async () => {
    const p = await pageRig({ writes: 1 });
    await click(find(p.root, "forget-start"));
    await settle();
    await click(find(p.root, "dialog-confirm"));
    await settle(60);
    const done = find(p.root, "forget-done");
    assert.ok(done, "the result replaces the page");
    assert.equal(done.getAttribute("data-shared"), "false");
    assert.equal(textOf(done).trim(), EN["syncwarnings.forget.done"]);
    assert.equal(await loadPinnedByAccount(p.db, SERVER, ACCOUNT), null);
    await click(find(p.root, "forget-to-login"));
    assert.deepEqual(p.went, ["/login"]);
    // Another address has the same account: the page says that records were kept, and does not report them as none.
    const shared = await pageRig({ extra: (r) => populate(r.db, OTHER_ORIGIN, ACCOUNT, { writes: 1 }) });
    await click(find(shared.root, "forget-start"));
    await settle();
    await click(find(shared.root, "dialog-confirm"));
    await settle(60);
    const note = find(shared.root, "forget-done");
    assert.equal(note.getAttribute("data-shared"), "true");
    assert.equal(textOf(note).trim(), EN["syncwarnings.forget.done_shared"]);
    assert.match(textOf(note), /were kept/);
  });
});

test("the_forget_page_says_when_it_failed_and_removed_nothing", async () => {
  await withDom(async () => {
    const p = await pageRig();
    p.store.forgetServer = async () => {
      throw new Error("db closed");
    };
    await click(find(p.root, "forget-start"));
    await settle();
    await click(find(p.root, "dialog-confirm"));
    await settle(60);
    assert.match(textOf(find(p.root, "forget-error")), /could not forget the server/);
    assert.doesNotMatch(textOf(p.root), /db closed/);
    assert.equal(find(p.root, "forget-start").disabled, false);
    assert.ok(await loadPinnedByAccount(p.db, SERVER, ACCOUNT));
  });
});

test("a_signed_out_device_finds_the_account_by_its_e_mail_among_its_own_records", async () => {
  await withDom(async () => {
    const p = await pageRig({ accountId: null });
    assert.equal(find(p.root, "forget-start"), null);
    const type = (text) => {
      find(p.root, "forget-email").value = text;
    };
    // An address this device has no record of: it says so, and asks nothing.
    type("nobody@example.test");
    await submit(find(p.root, "forget-form"));
    await settle();
    assert.match(textOf(find(p.root, "forget-note")), /holds nothing for that address/);
    assert.equal(dialog(p.root), null);
    // The address of the account: the dialog, and then the same flow for that account.
    type(EMAIL);
    const asking = submit(find(p.root, "forget-form")); // it waits for the answer of the dialog
    await settle();
    assert.ok(dialog(p.root));
    await click(find(p.root, "dialog-confirm"));
    await asking;
    await settle(60);
    assert.ok(find(p.root, "forget-done"));
    assert.equal(await loadPinnedByAccount(p.db, SERVER, ACCOUNT), null);
    assert.ok(hex16.is(ACCOUNT));
  });
});

// ------------------------------------------------------------ the sign-in page

test("forget_link_is_on_the_login_page", async () => {
  await withDom(async () => {
    const session = {
      deviceStatus: async () => ({ pinned: false, skBit: null, skStored: false }),
      current: () => null,
      freshReauth: () => false,
    };
    const deps = (lang, extra = {}) => ({
      t: translator(lang), session, entry: { page: "login", handoff: null, brokenHandoff: false, setupToken: null }, adminUrl: null,
      api: {}, go() {}, handoff: {}, info: null, ...extra,
    });
    for (const [lang, catalog] of [["en", EN], ["nb", NB]]) {
      // Signed out, and signed in but locked: both have the link.
      for (const info of [null, { accountId: ACCOUNT, email: EMAIL }]) {
        const root = loginView(deps(lang, { info }));
        const link = find(root, "forget-link");
        assert.ok(link, `${lang}: the link is there${info ? " when locked" : " when signed out"}`);
        assert.equal(link.getAttribute("href"), "#/forget");
        assert.equal(textOf(link).trim(), catalog["syncwarnings.forget.link"]);
        // The notice about trust stays the last thing in the card.
        assert.equal(find(root, "trust-notice"), root.childNodes.at(-1));
      }
    }
    // The page that re-authenticates for the admin pages has no way out of the server.
    const reauth = loginView(deps("en", { reauth: true, info: { accountId: ACCOUNT, email: EMAIL } }));
    assert.equal(find(reauth, "forget-link"), null);
  });
});

test("the_dialog_says_beforehand_whether_the_unsent_writes_are_lost_or_kept", async () => {
  await withDom(async () => {
    for (const [lang, catalog] of [["en", EN], ["nb", NB]]) {
      // Not shared: the unsent writes are lost.
      const lost = await pageRig({ writes: 2, lang });
      await click(find(lost.root, "forget-start"));
      await settle();
      assert.ok(textOf(dialog(lost.root)).includes(textFor(catalog, "syncwarnings.forget.dialog_body_pending", { count: 2, email: EMAIL })), `${lang}: lost`);
      await click(find(lost.root, "dialog-cancel"));
      await settle();
      // Shared with another address: they are kept, and the dialog says so before anything is done.
      const kept = await pageRig({ writes: 2, lang, extra: (r) => populate(r.db, OTHER_ORIGIN, ACCOUNT) });
      await click(find(kept.root, "forget-start"));
      await settle();
      assert.ok(textOf(dialog(kept.root)).includes(textFor(catalog, "syncwarnings.forget.dialog_body_shared_pending", { count: 2, email: EMAIL })), `${lang}: kept`);
      assert.doesNotMatch(textOf(dialog(kept.root)), lang === "en" ? /which will be lost/ : /og som går tapt/);
      await click(find(kept.root, "dialog-cancel"));
      await settle();
      // Shared and nothing unsent.
      const sharedOnly = await pageRig({ writes: 0, lang, extra: (r) => populate(r.db, OTHER_ORIGIN, ACCOUNT) });
      await click(find(sharedOnly.root, "forget-start"));
      await settle();
      assert.ok(textOf(dialog(sharedOnly.root)).includes(textFor(catalog, "syncwarnings.forget.dialog_body_shared", { email: EMAIL })), `${lang}: shared`);
    }
    // The question the dialog depends on, asked of the real store.
    const r = await rig();
    assert.equal(await sharedAccount(r.db, SERVER, ACCOUNT), false);
    await populate(r.db, OTHER_ORIGIN, ACCOUNT);
    assert.equal(await sharedAccount(r.db, SERVER, ACCOUNT), true);
    assert.equal(await sharedAccount(r.db, SERVER, "ffeeddccbbaa99887766554433221100"), false);
  });
});

test("the_page_says_working_only_after_the_confirmation_and_gives_the_focus_back", async () => {
  await withDom(() => withFocus(async () => {
    const p = await pageRig({ writes: 1 });
    const start = find(p.root, "forget-start");
    start.focus();
    await click(start);
    await settle();
    assert.ok(dialog(p.root));
    assert.equal(textOf(find(p.root, "forget-status")).trim(), "", "nothing is said to be going on while the dialog asks");
    assert.equal(find(p.root, "forget-start").disabled, false);
    // A cancel leaves the focus on the button that started it.
    await click(find(p.root, "dialog-cancel"));
    await settle();
    assert.equal(globalThis.document.activeElement, start);
    assert.equal(textOf(find(p.root, "forget-status")).trim(), "");
    // A failure after a yes: it was working, then it says it failed, and the focus is back on the button.
    p.store.forgetServer = async () => {
      throw new Error("db closed");
    };
    await click(start);
    await settle();
    await click(find(p.root, "dialog-confirm"));
    await settle(60);
    assert.match(textOf(find(p.root, "forget-error")), /could not forget the server/);
    assert.equal(textOf(find(p.root, "forget-status")).trim(), "");
    assert.equal(globalThis.document.activeElement, start);
    // And on the page that asks for the address, the focus goes back to the field.
    const signedOut = await pageRig({ accountId: null });
    const field = find(signedOut.root, "forget-email");
    field.focus();
    field.value = EMAIL;
    const asking = submit(find(signedOut.root, "forget-form"));
    await settle();
    await click(find(signedOut.root, "dialog-cancel"));
    await asking;
    assert.equal(globalThis.document.activeElement, field);
  }));
});

test("a_server_that_names_another_account_is_not_trusted_to_say_which_one_to_forget", async () => {
  const r = await rig();
  const OTHER = "ffeeddccbbaa99887766554433221100";
  const info = (accountId) => ({ current: () => null, info: async () => ({ accountId, email: "liar@example.test" }) });
  // The server names the account this device holds: it is the target, with the address of the local record.
  const found = await resolveForgetTarget({ session: info(ACCOUNT), store: r.store, serverUrl: SERVER });
  assert.deepEqual(found, { accountId: ACCOUNT, email: EMAIL });
  // The server names an account this device has no record of: not accepted, and the page asks for the address.
  assert.equal(await resolveForgetTarget({ session: info(OTHER), store: r.store, serverUrl: SERVER }), null);
  // Not an account id at all, no session, a server that cannot be asked: the same.
  assert.equal(await resolveForgetTarget({ session: info("not hex"), store: r.store, serverUrl: SERVER }), null);
  assert.equal(await resolveForgetTarget({ session: info(null), store: r.store, serverUrl: SERVER }), null);
  assert.equal(await resolveForgetTarget({ session: { current: () => null, info: async () => { throw new Error("offline"); } }, store: r.store, serverUrl: SERVER }), null);
  // An open vault names its own account, and it still has to be one this device holds.
  const open = await resolveForgetTarget({ session: { current: () => ({ accountId: ACCOUNT }), info: async () => assert.fail("not asked") }, store: r.store, serverUrl: SERVER });
  assert.deepEqual(open, { accountId: ACCOUNT, email: EMAIL });
  assert.equal(await resolveForgetTarget({ session: { current: () => ({ accountId: OTHER }) }, store: r.store, serverUrl: SERVER }), null);
  // The store's answer: the record's address, or nothing.
  assert.deepEqual(await loadPinnedAccount(r.db, SERVER, ACCOUNT), { email: EMAIL });
  assert.equal(await loadPinnedAccount(r.db, SERVER, OTHER), null);
  assert.equal(await loadPinnedAccount(r.db, OTHER_ORIGIN, ACCOUNT), null);
});
