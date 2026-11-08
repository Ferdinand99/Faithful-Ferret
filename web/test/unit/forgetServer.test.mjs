// "Forget this server": the flow (in order, under the lock of the sync memory, after one
// confirmation), what it removes from the real stores, the page, and the link on the
// sign-in page.
import assert from "node:assert/strict";
import { test } from "node:test";
import { b64u, hex16 } from "../../src/b64.mjs";
import { forgetServer } from "../../src/flows/forgetServer.mjs";
import { cache } from "../../src/store/cache.mjs";
import { forgetServer as forgetRecords, pendingWrites } from "../../src/store/forget.mjs";
import { outbox } from "../../src/store/outbox.mjs";
import { loadPinned, loadPinnedByAccount, pinnedForSignIn, savePinned } from "../../src/store/pinned.mjs";
import { deviceSecrets } from "../../src/store/settings.mjs";
import { loadSyncState, saveSyncState } from "../../src/store/syncState.mjs";
import { forgetView } from "../../src/views/forget.mjs";
import { loginView } from "../../src/views/login.mjs";
import { ACCOUNT, SERVER, VAULT, freshStore, pinnedRecord, scope } from "./idbHelpers.mjs";
import { accountDocument } from "./accountHelpers.mjs";
import { click, find, settle, submit, textOf } from "./vaultHelpers.mjs";
import { EN, NB, textFor, translator } from "./syncWarningsHelpers.mjs";

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
  assert.deepEqual(r.log, [["confirm", { pending: 3 }]], "the user is asked with the count, and nothing else happens");
  assert.deepEqual(r.navigated, []);
  // Everything is where it was.
  assert.ok(await loadPinnedByAccount(r.db, SERVER, ACCOUNT));
  assert.ok(await loadSyncState(r.db, SERVER, ACCOUNT));
  assert.equal(await pendingWrites(r.db, ACCOUNT), 3);
  // With nothing unsent the count is zero, which the dialog says by leaving the warning out.
  const none = await rig({ writes: 0, confirm: async () => false });
  await forgetServer(none.options);
  assert.deepEqual(none.log, [["confirm", { pending: 0 }]]);
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
    "confirm", "post", "session.lock", "lock request", "forgetServer", "forgetSecretKey", "channel", "navigate",
  ], "the order of the design");
  assert.deepEqual(r.log.find((entry) => entry[0] === "post"), ["post", "/api/auth/logout"]);
  // The records are removed inside the lock of the sync memory of this server and account.
  assert.deepEqual(r.log.find((entry) => entry[0] === "forgetServer"), ["forgetServer", name]);
  assert.deepEqual(r.log.find((entry) => entry[0] === "lock request"), ["lock request", name]);
  assert.deepEqual(r.log.find((entry) => entry[0] === "forgetSecretKey"), ["forgetSecretKey", ACCOUNT]);
  assert.deepEqual(r.log.find((entry) => entry[0] === "channel"), ["channel", { type: "forgotten", serverKey: SERVER, accountId: ACCOUNT }]);
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
  assert.deepEqual(posted, [["ferret", { type: "forgotten", serverKey: SERVER, accountId: ACCOUNT }], ["closed"]]);
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
async function pageRig({ writes = 0, accountId = ACCOUNT, lang = "en", extra } = {}) {
  const r = await rig({ writes });
  if (extra) await extra(r);
  const went = [];
  const flow = (options) => forgetServer({ ...options, locks: r.locks, channel: r.channel });
  const root = forgetView({
    t: translator(lang), session: r.session, store: r.store, api: r.api, serverUrl: SERVER, accountId, go: (path) => went.push(path), forget: flow,
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
    assert.ok(text.includes(textFor(EN, "syncwarnings.forget.dialog_body_pending", { count: 2 })), "the count of unsent changes is in the text");
    assert.ok(text.includes("Nothing on the server is deleted"), "what is certain is said");
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
    assert.ok(textOf(dialog(none.root)).includes(textFor(NB, "syncwarnings.forget.dialog_body")));
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
