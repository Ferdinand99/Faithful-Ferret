// The notice at an unlock: what an administrator, a command on the server or the server did to the account since this
// browser last showed "Activity". A browser that has shown none starts at the newest event (so the account's own
// creation is no notice), the account's own events are never one, and showing "Activity" clears it. The last-seen
// mark is kept per server and account on this device, and it starts again when the ids of the log went backwards
// (a restore from a backup).
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { createApi } from "../../src/api.mjs";
import { clearNotice, loadEvents, markSeen, noticeEvents, noticeOnce, reconcileSeen, unseenAdminEvents } from "../../src/flows/accountEvents.mjs";
import { createI18n } from "../../src/i18n.mjs";
import { autoLockFor } from "../../src/lock.mjs";
import activityRoute from "../../src/routes/activity.route.mjs";
import listRoute from "../../src/routes/list.route.mjs";
import { activitySeen, activitySeenKey } from "../../src/store/activitySeen.mjs";
import { forgetServer } from "../../src/store/forget.mjs";
import { getSetting, setSetting } from "../../src/store/settings.mjs";
import { accountNoticeView } from "../../src/views/accountNotice.mjs";
import { createWipeScope } from "../../src/views/common.mjs";
import { shellView } from "../../src/views/shell.mjs";
import { web } from "./helpers.mjs";
import { ACCOUNT, SERVER, freshStore } from "./idbHelpers.mjs";
import { click, fakeClient, fakeEngine, fakeSession, find, settle, t as keyT, textOf, withDom } from "./vaultHelpers.mjs";

const read = (lang) => JSON.parse(readFileSync(join(web, "src", "locales", lang, "activity.json"), "utf8"));
const i18n = (lang) => createI18n({ en: read("en"), nb: read("nb") }, lang);
const norm = (text) => text.replace(/\s+/g, " ").trim();

/** 27 November at 14:02 in the time zone of the test, in seconds. */
const AT = Math.floor(new Date(2026, 10, 27, 14, 2).getTime() / 1000);
const event = (id, kind, actor = "admin", actorName = "ada@example.test", at = AT - (100 - id) * 60) => ({ id, at, kind, actor, actor_name: actorName });

/** The mark of a browser, kept in a fresh local store for one server and account. */
async function seenStore(accountId = ACCOUNT, serverUrl = SERVER) {
  const { store } = await freshStore();
  const seen = {
    load: () => activitySeen.load(store, serverUrl, accountId),
    save: (mark) => activitySeen.save(store, serverUrl, accountId, mark),
  };
  return { store, seen };
}

/** The session answer of a full vault session of `accountId`. @param {string} accountId */
const sessionOf = (accountId) => ({ account_id: accountId, email: "ada@example.test", scope: "full", origin: "vault" });

/**
 * An API client whose log is `log` (newest first); it answers pages as the server does. The session it answers with is
 * the one of `accounts()` (called for each ask of the session; by default always `ACCOUNT`).
 */
function logApi(log, accounts = () => ACCOUNT) {
  const urls = [];
  const fetchImpl = async (url) => {
    urls.push(url);
    if (new URL(url, "https://vault.example").pathname === "/api/auth/session") {
      return new Response(JSON.stringify(sessionOf(accounts())), { status: 200, headers: { "content-type": "application/json" } });
    }
    const query = new URL(url, "https://vault.example").searchParams;
    const before = query.has("before") ? Number(query.get("before")) : Infinity;
    const limit = Number(query.get("limit") ?? 50);
    const below = log.events.filter((e) => e.id < before);
    return new Response(JSON.stringify({ events: below.slice(0, limit), more: below.length > limit }), { status: 200, headers: { "content-type": "application/json" } });
  };
  return { api: createApi({ fetchImpl }), urls };
}

test("the_notice_shows_admin_events_since_the_last_visit_only", async () => {
  const { store, seen } = await seenStore();
  const log = { events: [event(2, "account_created", "admin", "ada@example.test")] };
  const { api, urls } = logApi(log);

  // The first unlock in this browser starts at the newest event: the account's own creation is no notice.
  assert.deepEqual(await noticeEvents({ api, seen }), []);
  assert.deepEqual(await seen.load(), { id: 2, at: log.events[0].at });
  assert.deepEqual(urls, ["/api/account/events?limit=100"]);

  // An administrator makes a sign-in code: the next unlock shows it.
  log.events.unshift(event(3, "sign_in_code_issued", "admin", "ada@example.test", AT));
  const once = await noticeEvents({ api, seen });
  assert.deepEqual(once.map((e) => e.id), [3]);
  // The notice does not move the mark: it stays until "Activity" is shown.
  assert.deepEqual((await noticeEvents({ api, seen })).map((e) => e.id), [3]);

  // The words, as the plan has them, in both languages.
  await withDom(async () => {
    const nb = accountNoticeView({ t: i18n("nb").t, events: once, locale: "nb", now: AT * 1000 });
    assert.equal(nb.getAttribute("data-role"), "account-notice");
    assert.equal(norm(textOf(find(nb, "account-notice-text"))), "Admin laget en engangskode for kontoen din 27.11. kl. 14:02");
    assert.equal(norm(textOf(nb)), "Admin laget en engangskode for kontoen din 27.11. kl. 14:02 – Se aktivitet Lukk");
    assert.equal(find(nb, "account-notice-link").getAttribute("href"), "#/activity");
    const en = accountNoticeView({ t: i18n("en").t, events: once, locale: "en", now: AT * 1000 });
    assert.equal(norm(textOf(find(en, "account-notice-text"))), "An administrator made a sign-in code for your account on Nov 27 at 2:02 PM");
    // Several: the newest is told, and how many more there are.
    const many = accountNoticeView({ t: i18n("en").t, events: [event(9, "account_enabled", "admin", "", AT), event(8, "account_disabled"), event(7, "sign_in_code_issued", "server_command", "")], locale: "en", now: AT * 1000 });
    assert.equal(norm(textOf(find(many, "account-notice-text"))), "An administrator enabled your account again on Nov 27 at 2:02 PM. 2 more in the log.");
    // A command on the server and a restore have their own subjects; an event of another year names the year.
    const restored = accountNoticeView({ t: i18n("nb").t, events: [event(4, "server_restored", "server", "", AT)], locale: "nb", now: AT * 1000 });
    assert.equal(norm(textOf(find(restored, "account-notice-text"))), "Serveren ble gjenopprettet fra en sikkerhetskopi 27.11. kl. 14:02");
    const command = accountNoticeView({ t: i18n("nb").t, events: [event(5, "sign_in_code_issued", "server_command", "", AT - 400 * 86_400)], locale: "nb", now: AT * 1000 });
    assert.match(norm(textOf(find(command, "account-notice-text"))), /^En kommando på serveren laget en engangskode for kontoen din .*2025/);
    // No events: no notice.
    assert.equal(accountNoticeView({ t: i18n("en").t, events: [], locale: "en" }), null);
  });

  // An administrator's e-mail is never in the notice, so a name that looks like markup cannot be either.
  await withDom(async () => {
    const odd = accountNoticeView({ t: keyT, events: [event(3, "account_disabled", "admin", "<b>x</b>")], locale: "en" });
    assert.ok(!norm(textOf(odd)).includes("<b>"));
  });

  // Two accounts in one browser share nothing: each has its own mark.
  const other = "cd".repeat(16);
  assert.equal(await activitySeen.load(store, SERVER, other), null);
  await activitySeen.save(store, SERVER, other, { id: 50, at: 1 });
  assert.deepEqual(await seen.load(), { id: 2, at: log.events[1].at });
  assert.deepEqual(await activitySeen.load(store, "https://other.example", ACCOUNT), null);
  assert.notEqual(activitySeenKey(SERVER, other), activitySeenKey(SERVER, ACCOUNT));
  // The mark holds two numbers and nothing else; anything else stored reads as none.
  assert.deepEqual(Object.keys(await getSetting(store, activitySeenKey(SERVER, ACCOUNT))).sort(), ["at", "id"]);
  for (const junk of ["x", 5, null, [], { id: 1 }, { id: -1, at: 0 }, { id: 1.5, at: 0 }, { id: 1, at: 0, extra: 1 }]) {
    await setSetting(store, activitySeenKey(SERVER, ACCOUNT), junk);
    assert.equal(await seen.load(), null);
  }
  await assert.rejects(activitySeen.save(store, SERVER, ACCOUNT, { id: -1, at: 0 }), TypeError);
  await assert.rejects(activitySeen.save(store, SERVER, "not-an-id", { id: 1, at: 0 }), TypeError);

  // "Forget this server" takes the mark of that server and account with it, and only that one.
  await activitySeen.save(store, SERVER, ACCOUNT, { id: 3, at: AT });
  const gone = await forgetServer(store, SERVER, ACCOUNT);
  assert.equal(gone.removed.settings, 1);
  assert.equal(await activitySeen.load(store, SERVER, ACCOUNT), null);
  assert.deepEqual(await activitySeen.load(store, SERVER, other), { id: 50, at: 1 });
});

test("the_notice_never_shows_for_the_accounts_own_events", async () => {
  const events = [
    event(10, "sign_in_code_redeemed", "account", ""),
    event(9, "later_kind", "account", ""),
    event(8, "account_disabled", "admin"),
    event(7, "sign_in_code_issued", "server_command", ""),
    event(6, "server_restored", "server", ""),
    event(5, "account_enabled", "admin"),
  ];
  // Only the actors `admin`, `server_command` and `server`, and only after the last-seen id.
  assert.deepEqual(unseenAdminEvents(events, 5).map((e) => e.id), [8, 7, 6]);
  assert.deepEqual(unseenAdminEvents(events, 8).map((e) => e.id), []);
  assert.deepEqual(unseenAdminEvents([], 0), []);

  // Through the flow: a redeemed code of the account itself is no notice.
  const { seen } = await seenStore();
  await seen.save({ id: 8, at: events[2].at });
  const { api } = logApi({ events });
  assert.deepEqual(await noticeEvents({ api, seen }), []);
});

test("a_restore_starts_the_last_seen_id_again", async () => {
  // This browser saw up to id 500. The server was then restored from a set whose newest event is 300: the sweep wrote
  // `server_restored` as 301, below what the browser saw, and an administrator made a code after it (302).
  const marked = { id: 500, at: AT - 3600 };
  const after = [event(302, "sign_in_code_issued", "admin", "ada@example.test", AT), event(301, "server_restored", "server", "", AT - 60), event(300, "account_enabled", "admin", "ada@example.test", AT - 7200)];
  assert.deepEqual(reconcileSeen(after, marked), { lastSeenId: 300, save: { id: 300, at: marked.at } });
  assert.deepEqual(unseenAdminEvents(after, 300).map((e) => e.id), [302, 301]);

  // The newest id is above what was seen (more events after the restore), yet the restore is newer than the mark.
  const later = [event(520, "account_disabled", "admin", "ada@example.test", AT + 60), ...after];
  assert.deepEqual(reconcileSeen(later, marked).lastSeenId, 300);
  // A restore before what was seen is old news; ids above the mark are new as usual.
  const old = [event(510, "account_disabled", "admin", "ada@example.test", AT), event(400, "server_restored", "server", "", AT - 7200)];
  assert.deepEqual(reconcileSeen(old, marked), { lastSeenId: 500, save: null });
  // A restore that came after the last visit but kept every id above the mark: the events in between still count.
  const kept = [event(520, "server_restored", "server", "", AT), event(510, "account_disabled", "admin", "ada@example.test", AT - 60)];
  assert.deepEqual(reconcileSeen(kept, marked), { lastSeenId: 500, save: null });

  // Through the flow and the store: the new start is kept, so a later unlock agrees.
  const { seen } = await seenStore();
  await seen.save(marked);
  const { api } = logApi({ events: after });
  assert.deepEqual((await noticeEvents({ api, seen })).map((e) => e.id), [302, 301]);
  assert.deepEqual(await seen.load(), { id: 300, at: marked.at });
  assert.deepEqual((await noticeEvents({ api, seen })).map((e) => e.id), [302, 301]);
});

test("an_id_below_the_last_seen_one_starts_it_again", async () => {
  // The newest id is below the stored one and no restore is in sight (the log was replaced some other way): the browser
  // starts again at the newest event, as a browser that has shown nothing does, and keeps that.
  const marked = { id: 500, at: AT - 60 };
  const events = [event(40, "account_disabled", "admin", "ada@example.test", AT - 3600), event(39, "account_created", "admin", "", AT - 7200)];
  assert.deepEqual(reconcileSeen(events, marked), { lastSeenId: 40, save: { id: 40, at: events[0].at } });
  const { seen } = await seenStore();
  await seen.save(marked);
  const log = { events };
  const { api } = logApi(log);
  assert.deepEqual(await noticeEvents({ api, seen }), []);
  assert.deepEqual(await seen.load(), { id: 40, at: events[0].at });
  // An administrator acts after that: id 41 is below the old mark of 500, and is still a notice.
  log.events.unshift(event(41, "sign_in_code_issued", "admin", "ada@example.test", AT));
  assert.deepEqual((await noticeEvents({ api, seen })).map((e) => e.id), [41]);

  // An empty log with no mark starts at nothing, so the first event an administrator makes is a notice.
  assert.deepEqual(reconcileSeen([], null), { lastSeenId: 0, save: { id: 0, at: 0 } });
  assert.deepEqual(reconcileSeen([event(1, "account_created")], null), { lastSeenId: 1, save: { id: 1, at: event(1, "account_created").at } });
});

test("visiting_activity_clears_the_notice", async () => {
  // The flow: showing the first page moves the mark to its newest event, and clears the notice of this unlock.
  const { seen } = await seenStore();
  await seen.save({ id: 2, at: 1 });
  const log = { events: [event(4, "account_disabled"), event(3, "sign_in_code_issued"), event(2, "account_created")] };
  const { api } = logApi(log);
  const open = {};
  let computed = 0;
  const compute = () => {
    computed += 1;
    return noticeEvents({ api, seen });
  };
  assert.deepEqual((await noticeOnce(open, compute)).map((e) => e.id), [4, 3]);
  // Asked once per unlock, not on every page.
  await noticeOnce(open, compute);
  assert.equal(computed, 1);
  await markSeen(seen, (await loadEvents(api)).events);
  clearNotice(open);
  assert.deepEqual(await noticeOnce(open, compute), []);
  assert.deepEqual(await seen.load(), { id: 4, at: log.events[0].at });
  // The next unlock asks again and finds nothing new.
  assert.deepEqual(await noticeOnce({}, compute), []);
  // A check that fails is no notice, and is asked again at the next page of the same unlock.
  const failing = {};
  let tries = 0;
  const flaky = async () => {
    tries += 1;
    if (tries === 1) throw new Error("network");
    return [event(9, "account_disabled")];
  };
  assert.deepEqual(await noticeOnce(failing, flaky), []);
  assert.deepEqual((await noticeOnce(failing, flaky)).map((e) => e.id), [9]);
  assert.equal(tries, 2);

  // Through the routes: the list shows the notice in the frame, "Activity" does not, and after it the list has none.
  await withDom(async () => {
    const { store } = await freshStore();
    await activitySeen.save(store, SERVER, ACCOUNT, { id: 2, at: 1 });
    const r = rig({ store, api: logApi(log).api });
    try {
      const list = await listRoute.load(r.ctx("/items"));
      await settle();
      const notice = find(list, "account-notice");
      assert.ok(notice, "the notice is in the frame");
      assert.match(textOf(notice), /activity\.notice\.account_disabled/);
      const page = await activityRoute.load(r.ctx("/activity"));
      await settle();
      assert.equal(find(page, "account-notice"), null, "the Activity page shows no notice of itself");
      assert.ok(find(page, "activity-page"));
      assert.equal(find(page, "activity-row") !== null, true);
      assert.deepEqual(await activitySeen.load(store, SERVER, ACCOUNT), { id: 4, at: log.events[0].at });
      const again = await listRoute.load(r.ctx("/items"));
      await settle();
      assert.equal(find(again, "account-notice"), null, "cleared");
      // Another account in the same browser has its own mark and its own notice.
      await activitySeen.save(store, SERVER, "cd".repeat(16), { id: 3, at: 1 });
      const b = rig({ store, api: logApi(log, () => "cd".repeat(16)).api, accountId: "cd".repeat(16) });
      try {
        const listB = await listRoute.load(b.ctx("/items"));
        await settle();
        assert.ok(find(listB, "account-notice"), "B's mark is not A's");
      } finally {
        b.done();
      }
    } finally {
      r.done();
    }
  });

  // The frame: the dismiss button hides the notice; a check that fails or is late shows nothing.
  await withDom(async () => {
    const frame = (accountNotice, hash = "#/items") => {
      const scope = createWipeScope();
      const root = shellView({
        t: keyT, engine: fakeEngine(), session: { onLock() {} }, content: globalThis.document.createElement("div"), lock: async () => {}, touch: () => true,
        scope, onLocked: () => globalThis.document.createElement("div"), win: { location: { hash } }, accountNotice,
      });
      return { root, scope };
    };
    let dismissed = 0;
    const shown = frame({ check: async () => [event(3, "sign_in_code_issued")], dismiss: () => void (dismissed += 1) });
    await settle();
    const notice = find(shown.root, "account-notice");
    assert.ok(notice);
    await click(find(notice, "account-notice-dismiss"));
    assert.equal(find(shown.root, "account-notice"), null);
    assert.equal(dismissed, 1, "the rest of this unlock has no notice");
    const onPage = frame({ check: async () => [event(3, "sign_in_code_issued")] }, "#/activity");
    await settle();
    assert.equal(find(onPage.root, "account-notice"), null);
    const broken = frame({ check: async () => Promise.reject(new Error("network")) });
    await settle();
    assert.equal(find(broken.root, "account-notice"), null);
    let release;
    const late = frame({ check: () => new Promise((resolve) => (release = resolve)) });
    late.scope.run();
    release([event(3, "sign_in_code_issued")]);
    await settle();
    assert.equal(find(late.root, "account-notice"), null);
  });
});

test("the_log_of_another_account_is_never_shown_or_marked", async () => {
  // The answer of the log names no account: the session of the browser profile decides whose log it is. Another tab
  // that signs in as another account changes that session under a tab that is open, so the log is used only when the
  // session is the unlocked account's both before and after it was read.
  const other = "cd".repeat(16);
  const log = { events: [event(4, "account_created")] };
  const pathOf = (/** @type {string} */ url) => new URL(url, "https://vault.example").pathname;
  const isUnauthorized = (/** @type {any} */ error) => error.status === 401 && error.code === "unauthorized";

  // The session is the other account's from the start: the log is not even asked for.
  const { seen } = await seenStore();
  const theirs = logApi(log, () => other);
  await assert.rejects(loadEvents(theirs.api, { accountId: ACCOUNT }), isUnauthorized);
  assert.deepEqual(theirs.urls.map(pathOf), ["/api/auth/session"]);
  await assert.rejects(noticeEvents({ api: theirs.api, seen, accountId: ACCOUNT }), isUnauthorized);
  assert.equal(await seen.load(), null, "no mark from another account's log");

  // The session turns into the other account's while the log is read: the page that came is not used.
  const turns = [ACCOUNT, other];
  const turning = logApi(log, () => turns.shift() ?? other);
  await assert.rejects(loadEvents(turning.api, { accountId: ACCOUNT }), isUnauthorized);
  assert.deepEqual(turning.urls.map(pathOf), ["/api/auth/session", "/api/account/events", "/api/auth/session"]);
  const turnsAgain = [ACCOUNT, other];
  await assert.rejects(noticeEvents({ api: logApi(log, () => turnsAgain.shift() ?? other).api, seen, accountId: ACCOUNT }), isUnauthorized);
  assert.equal(await seen.load(), null);

  // The same account before and after: the log is the account's.
  const ours = logApi(log);
  assert.deepEqual((await loadEvents(ours.api, { accountId: ACCOUNT })).events.map((e) => e.id), [4]);
  await assert.rejects(loadEvents(ours.api, { accountId: "not an id" }), TypeError);

  // Through the routes, in a tab of this account whose browser now holds the other account's session: "Activity" says
  // the session has ended, lists nothing and keeps no mark, and the list shows no notice.
  await withDom(async () => {
    const { store } = await freshStore();
    const r = rig({ store, api: logApi(log, () => other).api });
    try {
      const page = await activityRoute.load(r.ctx("/activity"));
      await settle();
      const error = find(page, "activity-error");
      assert.ok(error && !error.hidden, "the page says why");
      assert.match(textOf(error), /activity.error.unauthorized/);
      assert.equal(find(page, "activity-row"), null);
      assert.equal(find(page, "activity-empty"), null);
      assert.equal(await activitySeen.load(store, SERVER, ACCOUNT), null);
      const list = await listRoute.load(r.ctx("/items"));
      await settle();
      assert.equal(find(list, "account-notice"), null);
      assert.equal(await activitySeen.load(store, SERVER, ACCOUNT), null);
    } finally {
      r.done();
    }
  });
});

test("the_notice_texts_exist_for_every_kind_and_actor", async () => {
  for (const lang of ["en", "nb"]) {
    const { t, missing } = i18n(lang);
    await withDom(async () => {
      const kinds = ["account_created", "sign_in_code_issued", "sign_in_code_redeemed", "account_disabled", "account_enabled", "signed_out_everywhere", "server_restored", "later_kind"];
      for (const [i, kind] of kinds.entries()) {
        for (const actor of ["admin", "server_command", "server", "account"]) {
          accountNoticeView({ t, events: [event(10 + i, kind, actor, ""), event(5, "account_disabled")], locale: lang, now: AT * 1000 });
          accountNoticeView({ t, events: [event(10 + i, kind, actor, "", AT - 400 * 86_400)], locale: lang, now: AT * 1000 });
        }
      }
    });
    assert.deepEqual(missing, [], lang);
  }
});

/** The routes over fakes, with a local store and an API that holds the log. */
function rig({ store, api, accountId = ACCOUNT }) {
  const engine = fakeEngine();
  const client = fakeClient(engine);
  const session = fakeSession({ client, info: { accountId, email: "ada@example.test" } });
  session.serverUrl = SERVER;
  const sync = { engine, current: () => engine, start: async () => engine, stop: () => engine.stop() };
  const services = { crypto: session, sync, api, store: { open: async () => store, activitySeen } };
  const ctx = (path) => ({ params: {}, path, i18n: { t: keyT, lang: "en", missing: [] }, client, services, go() {} });
  const done = () => autoLockFor(session, sync).stop();
  return { ctx, done, session };
}
