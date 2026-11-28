// The page "Activity": the account log as the server keeps it (`GET /api/account/events`), newest first, with who did
// it and when; a kind the page does not know is "Other event"; "Show older" asks for the next page. An administrator's
// e-mail comes from the server and is shown as text only.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { createApi } from "../../src/api.mjs";
import { EVENT_KINDS, loadEvents } from "../../src/flows/accountEvents.mjs";
import { createI18n } from "../../src/i18n.mjs";
import route from "../../src/routes/activity.route.mjs";
import { menuRoutes } from "../../src/views/account.mjs";
import { accountNoticeView } from "../../src/views/accountNotice.mjs";
import { activityErrorText, activityView } from "../../src/views/activity.mjs";
import { formatMoment } from "../../src/views/common.mjs";
import { web } from "./helpers.mjs";
import { all, click, find, settle, t as keyT, textOf, walk, withDom } from "./vaultHelpers.mjs";

const read = (lang) => JSON.parse(readFileSync(join(web, "src", "locales", lang, "activity.json"), "utf8"));
const i18n = (lang) => createI18n({ en: read("en"), nb: read("nb") }, lang);
const fixture = (name) => readFileSync(join(web, "..", "crates", "ferret-server", "tests", "fixtures", "wire", name), "utf8");

const json = (value, status = 200) => new Response(typeof value === "string" ? value : JSON.stringify(value), { status, headers: { "content-type": "application/json" } });

/** An API client whose server answers each request with `answer(url)`, and records the addresses it was asked. */
function apiAnswering(answer) {
  const urls = [];
  const fetchImpl = async (url, init) => {
    urls.push(`${init.method} ${url}`);
    return answer(url);
  };
  return { api: createApi({ fetchImpl }), urls };
}

const event = (id, kind, actor = "admin", actorName = "ada@example.test", at = 1_800_000_000 + id * 60) => ({ id, at, kind, actor, actor_name: actorName });

/** The page over a fake `load` that answers `pages` in turn and records each `before`. */
function page({ t = keyT, pages = [{ events: [], more: false }], shown = [] } = {}) {
  const asked = [];
  let turn = 0;
  const view = activityView({
    t,
    locale: "en",
    load: async (before) => {
      asked.push(before);
      const next = pages[Math.min(turn, pages.length - 1)];
      turn += 1;
      if (next instanceof Error) throw next;
      return next;
    },
    onShown: async (events) => {
      shown.push(events.map((e) => e.id));
    },
  });
  return { view, asked, shown };
}

test("activity_lists_events_newest_first_with_actor_and_time", async () => {
  // The flow reads the server's own fixture: newest first, checked against the wire shape.
  const { api, urls } = apiAnswering(() => json(fixture("account_events_res.json")));
  const answer = await loadEvents(api);
  assert.deepEqual(urls, ["GET /api/account/events?limit=50"]);
  assert.deepEqual(answer.events.map((e) => e.id), [9, 8, 7, 6, 5, 4, 2]);
  assert.equal(answer.more, false);

  const { t } = i18n("en");
  await withDom(async () => {
    const { view, shown } = page({ t, pages: [answer] });
    await settle();
    const rows = all(view, "activity-row");
    assert.equal(rows.length, 7);
    assert.deepEqual(rows.map((row) => row.getAttribute("data-kind")), [
      "server_restored", "signed_out_everywhere", "account_enabled", "account_disabled", "sign_in_code_redeemed", "sign_in_code_issued", "account_created",
    ]);
    // What happened, who did it and when, in words.
    assert.equal(textOf(find(rows[0], "activity-what")).trim(), "Server restored from a backup");
    assert.equal(textOf(find(rows[0], "activity-who")).trim(), "By the server");
    assert.equal(textOf(find(rows[1], "activity-who")).trim(), "By the administrator ada@example.test");
    assert.equal(textOf(find(rows[4], "activity-what")).trim(), "Sign-in code used");
    assert.equal(textOf(find(rows[4], "activity-who")).trim(), "By you");
    assert.equal(textOf(find(rows[5], "activity-what")).trim(), "Sign-in code made");
    assert.equal(textOf(find(rows[5], "activity-who")).trim(), "By a command on the server");
    // An administrator whose account is gone has a neutral label, never an empty name.
    assert.equal(textOf(find(rows[6], "activity-who")).trim(), "By an administrator whose account no longer exists");
    const when = formatMoment(1_800_003_600 * 1000, "en");
    assert.equal(textOf(find(rows[0], "activity-when")).trim(), when);
    // The page tells its route what it showed, once, so the notice can be cleared.
    assert.deepEqual(shown, [[9, 8, 7, 6, 5, 4, 2]]);
    // No more pages: no button.
    assert.equal(find(view, "activity-more"), null);
  });

  // A name that looks like markup is text, and the page holds no event id.
  await withDom(async () => {
    const marked = page({ pages: [{ events: [event(77_777, "account_disabled", "admin", "<img src=x onerror=alert(1)>")], more: false }] });
    await settle();
    assert.match(textOf(find(marked.view, "activity-who")), /<img src=x onerror=alert\(1\)>/);
    assert.ok(![...walk(marked.view)].some((n) => n.tagName === "img"));
    for (const node of walk(marked.view)) {
      for (const text of [node.data ?? "", ...(node.attributes ? [...node.attributes.values()] : [])]) assert.ok(!String(text).includes("77777"), "an event id reached the page");
    }
  });

  // An answer that is not newest first, or holds a field the shape does not know, is refused.
  const shuffled = apiAnswering(() => json({ events: [event(1, "account_created"), event(2, "account_disabled")], more: false }));
  await assert.rejects(loadEvents(shuffled.api), (error) => error.code === "bad_response");
  const extra = apiAnswering(() => json({ events: [{ ...event(2, "account_disabled"), code: "123456" }], more: false }));
  await assert.rejects(loadEvents(extra.api));
});

test("an_unknown_kind_shows_as_another_event", async () => {
  // A kind of a later version passes the wire check (the set is open) and is "Other event" on the page.
  const { api } = apiAnswering(() => json({ events: [event(12, "emergency_access_asked", "account", ""), event(11, "sign_in_code_issued")], more: false }));
  const answer = await loadEvents(api);
  for (const lang of ["en", "nb"]) {
    const { t } = i18n(lang);
    await withDom(async () => {
      const { view } = page({ t, pages: [answer] });
      await settle();
      const rows = all(view, "activity-row");
      assert.equal(rows[0].getAttribute("data-kind"), "other");
      assert.equal(textOf(find(rows[0], "activity-what")).trim(), lang === "en" ? "Other event" : "Annen hendelse");
      assert.equal(rows[1].getAttribute("data-kind"), "sign_in_code_issued");
    });
  }
  // The known kinds are the seven of delivery 1.
  assert.deepEqual([...EVENT_KINDS].sort(), [
    "account_created", "account_disabled", "account_enabled", "server_restored", "sign_in_code_issued", "sign_in_code_redeemed", "signed_out_everywhere",
  ]);
});

test("more_loads_the_next_page", async () => {
  // The flow: `before` is the oldest id shown, and every id of the page must be below it.
  const full = JSON.parse(fixture("account_events_res.more.json"));
  assert.equal(full.events.length, 100);
  assert.equal(full.more, true);
  const { api, urls } = apiAnswering((url) => (url.includes("before=") ? json({ events: [event(900, "account_enabled")], more: false }) : json(full)));
  const first = await loadEvents(api, { limit: 100 });
  assert.equal(first.events.length, 100);
  const oldest = first.events.at(-1).id;
  const second = await loadEvents(api, { before: oldest });
  assert.deepEqual(second.events.map((e) => e.id), [900]);
  assert.deepEqual(urls, ["GET /api/account/events?limit=100", `GET /api/account/events?limit=50&before=${oldest}`]);
  // A page that holds an id at or above `before` is refused.
  const wrong = apiAnswering(() => json({ events: [event(oldest, "account_enabled")], more: false }));
  await assert.rejects(loadEvents(wrong.api, { before: oldest }), (error) => error.code === "bad_response");
  // The arguments are checked before anything is sent.
  const none = apiAnswering(() => json(full));
  for (const bad of [0, -1, 1.5, "5", Number.MAX_SAFE_INTEGER + 1]) await assert.rejects(loadEvents(none.api, { before: bad }), TypeError);
  for (const bad of [0, 101, 2.5]) await assert.rejects(loadEvents(none.api, { limit: bad }), TypeError);
  assert.equal(none.urls.length, 0);

  // The page: "Show older" asks for the page before the oldest row, adds it below, and goes away after the last page.
  await withDom(async () => {
    const { view, asked, shown } = page({
      pages: [{ events: [event(30, "account_disabled"), event(29, "account_enabled")], more: true }, { events: [event(5, "account_created")], more: false }],
    });
    await settle();
    assert.equal(all(view, "activity-row").length, 2);
    const more = find(view, "activity-more");
    assert.ok(more);
    await click(more);
    await settle();
    assert.deepEqual(asked, [undefined, 29]);
    assert.equal(all(view, "activity-row").length, 3);
    assert.equal(find(view, "activity-more"), null);
    // Only the first page marks what was seen.
    assert.deepEqual(shown, [[30, 29]]);
  });

  // A failed older page keeps what is shown, says so, and can be asked again.
  await withDom(async () => {
    const failure = Object.assign(new Error("network"), { code: "network" });
    const { view, asked } = page({ pages: [{ events: [event(30, "account_disabled")], more: true }, failure, { events: [event(4, "account_enabled")], more: false }] });
    await settle();
    await click(find(view, "activity-more"));
    await settle();
    assert.equal(all(view, "activity-row").length, 1);
    assert.equal(find(view, "activity-error").hidden, false);
    assert.equal(textOf(find(view, "activity-error")).trim(), "activity.error.network");
    await click(find(view, "activity-more"));
    await settle();
    assert.deepEqual(asked, [undefined, 30, 30]);
    assert.equal(all(view, "activity-row").length, 2);
    assert.equal(find(view, "activity-error").hidden, true);
  });
});

test("an_empty_log_and_a_failed_first_page_say_so", async () => {
  await withDom(async () => {
    const empty = page();
    await settle();
    assert.ok(find(empty.view, "activity-empty"));
    assert.equal(all(empty.view, "activity-row").length, 0);
    // An empty log is seen as well: the notice starts at nothing.
    assert.deepEqual(empty.shown, [[]]);

    const failure = Object.assign(new Error("unauthorized"), { code: "unauthorized" });
    const failed = page({ pages: [failure, { events: [event(3, "account_enabled")], more: false }] });
    await settle();
    assert.equal(textOf(find(failed.view, "activity-error")).trim(), "activity.error.unauthorized");
    assert.deepEqual(failed.shown, [], "nothing was shown, so nothing is marked as seen");
    await click(find(failed.view, "activity-retry"));
    await settle();
    assert.equal(all(failed.view, "activity-row").length, 1);
    assert.deepEqual(failed.shown, [[3]]);
  });
});

test("activity_texts_exist_in_both_languages", async () => {
  const en = read("en");
  const nb = read("nb");
  assert.deepEqual(Object.keys(nb).sort(), Object.keys(en).sort());
  const holes = (s) => [...s.matchAll(/\{([a-z_]+)\}/g)].map((m) => m[1]).sort();
  for (const [key, text] of Object.entries(en)) {
    assert.ok(key.startsWith("activity."), key);
    assert.ok(text.trim() !== "" && nb[key].trim() !== "", key);
    assert.deepEqual(holes(nb[key]), holes(text), key);
  }
  // Every key the page, its route, its errors and the notice ask for is there, in both languages, and every text is asked for.
  for (const lang of ["en", "nb"]) {
    const { t: translate, missing } = i18n(lang);
    const used = new Set();
    const t = (key, vars) => {
      used.add(key);
      return translate(key, vars);
    };
    await withDom(async () => {
      const events = [...EVENT_KINDS, "later_kind"].map((kind, i) => event(100 - i, kind, ["admin", "server_command", "server", "account"][i % 4], i === 0 ? "" : "ada@example.test"));
      events.push(event(10, "account_disabled", "admin", ""), { ...event(9, "account_enabled"), at: 0 });
      const { view } = page({ t, pages: [{ events, more: true }, { events: [], more: false }] });
      await settle();
      await click(find(view, "activity-more"));
      await settle();
      page({ t });
      await settle();
      page({ t, pages: [Object.assign(new Error("network"), { code: "network" })] });
      await settle();
      for (const [i, kind] of [...EVENT_KINDS, "later_kind"].entries()) {
        for (const actor of ["admin", "server_command", "server", "account"]) accountNoticeView({ t, events: [event(50 + i, kind, actor, ""), event(5, kind)], locale: lang });
      }
    });
    for (const code of ["bad_response", "busy", "forbidden", "network", "throttled", "unauthorized", "something_else"]) activityErrorText(t, { code });
    t(route.title);
    assert.deepEqual(missing, [], lang);
    assert.deepEqual(Object.keys(read(lang)).filter((key) => !used.has(key)), [], `${lang}: unused texts`);
  }
  // The page is on the account menu.
  assert.equal(route.path, "/activity");
  assert.equal(route.menu, "account");
  assert.deepEqual(menuRoutes([route]).map((r) => r.path), ["/activity"]);
});
