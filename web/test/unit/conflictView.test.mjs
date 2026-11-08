// The conflict view: both versions side by side, one secret on the page at a time,
// a choice that is made once, and nothing left on the page or open in the engine
// after a choice, a lock or a new reading.
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { test } from "node:test";
import { createWipeScope, formatMoment } from "../../src/views/common.mjs";
import { conflictView } from "../../src/views/conflict.mjs";
import { itemView } from "../../src/views/item.mjs";
import { listView } from "../../src/views/list.mjs";
import {
  ID, MINE_NOTES, MINE_PASSWORD, MINE_PIN, MODIFIED_MINE, MODIFIED_THEIRS, OTHER, THEIR_NOTES, THEIR_PASSWORD, THEIR_PIN,
  bankConflict, fakeConflictEngine, fakeReveal, loginView,
} from "./conflictHelpers.mjs";
import { all, click, coded, fakeClient, fakeEngine, find, settle, t, textOf, withDom } from "./vaultHelpers.mjs";

const SECRETS = [MINE_PASSWORD, THEIR_PASSWORD, MINE_PIN, THEIR_PIN, MINE_NOTES, THEIR_NOTES];

/** The view over fakes. `spec` is the conflict of the item. */
async function open({ spec = bankConflict(), touch, extra = {} } = {}) {
  const engine = fakeConflictEngine({ conflicts: { [ID]: spec } });
  const client = fakeReveal(engine);
  const scope = createWipeScope();
  const moves = [];
  const root = await conflictView({
    engine, client, id: ID, t, router: { go: (path) => moves.push(path) }, locale: "en", scope, touch, ...extra,
  });
  return { engine, client, scope, moves, root };
}

const cellKey = (side, key) => `${side}.${key}`;
const reveal = (root, side, key) => click(find(root, "reveal", cellKey(side, key)));
const value = (root, side, key) => textOf(find(root, "value", cellKey(side, key)));
const noSecretIn = (root, except = []) => {
  const text = textOf(root);
  for (const secret of SECRETS) if (!except.includes(secret)) assert.ok(!text.includes(secret), `${secret} is not on the page`);
};

test("conflict_view_shows_both_sides_with_time_and_device", async () => {
  await withDom(async () => {
    const { root, engine } = await open();
    const mine = find(root, "side");
    const sides = all(root, "side");
    assert.equal(sides.length, 2);
    assert.equal(mine.getAttribute("data-side"), "local");
    const [local, server] = sides;
    assert.ok(textOf(local).includes("conflict.mine"));
    assert.ok(textOf(server).includes("conflict.theirs"));
    assert.equal(textOf(find(local, "modified")).trim(), formatMoment(MODIFIED_MINE, "en"));
    assert.equal(textOf(find(server, "modified")).trim(), formatMoment(MODIFIED_THEIRS, "en"));
    assert.notEqual(formatMoment(MODIFIED_MINE, "en"), formatMoment(MODIFIED_THEIRS, "en"));
    assert.equal(textOf(find(local, "device")).trim(), "Firefox on Windows");
    assert.equal(textOf(find(server, "device")).trim(), "Safari on iPhone");
    assert.equal(textOf(find(local, "name")).trim(), "Bank");

    // The plain user name shows on both sides; the hidden values are dots; the rows say what could be compared.
    assert.equal(value(root, "local", "username").trim(), "ada");
    assert.equal(value(root, "server", "username").trim(), "ada");
    assert.equal(value(root, "local", "password").trim(), "••••••••");
    assert.equal(find(root, "conflict-field", "username").getAttribute("data-same"), "same");
    assert.equal(find(root, "conflict-field", "password").getAttribute("data-same"), "hidden");
    assert.ok(textOf(find(root, "conflict-field", "username")).includes("conflict.same"));
    assert.ok(textOf(find(root, "conflict-field", "password")).includes("conflict.hidden"));
    // The notes are a row even though the engine did not list them.
    assert.ok(find(root, "conflict-field", "notes"));
    noSecretIn(root);
    // Opening the view reveals nothing and closes nothing; the engine's handles stay open until the view is done with them.
    assert.deepEqual(engine.calls, [["conflict", ID]]);
    assert.equal(engine.handles.size, 2);
  });
});

test("rows_that_differ_come_first_and_a_version_without_the_field_says_so", async () => {
  await withDom(async () => {
    const spec = bankConflict({
      fields: [
        { key: "username", label: "User name", kind: "text", same: true },
        { key: "extra", label: "Extra", kind: "text", same: false },
        { key: "password", label: "Password", kind: "password", same: null },
      ],
    });
    spec.local.view = loginView({ fields: [
      { id: "username", label: "User name", kind: "text", value: "ada" },
      { id: "extra", label: "Extra", kind: "text", value: "one" },
      { id: "password", label: "Password", kind: "password", value: null },
    ] });
    spec.server.view = loginView({ fields: [
      { id: "username", label: "User name", kind: "text", value: "ada" },
      { id: "password", label: "Password", kind: "password", value: null },
    ], modified: MODIFIED_THEIRS });
    const { root } = await open({ spec });
    const keys = all(root, "conflict-field").map((n) => n.getAttribute("data-key"));
    assert.deepEqual(keys, ["extra", "password", "notes", "username"]);
    assert.equal(value(root, "local", "extra").trim(), "one");
    assert.ok(textOf(find(find(root, "conflict-field", "extra"), "absent")).includes("conflict.absent"));
  });
});

test("only_one_secret_is_revealed_at_a_time_across_both_sides", async () => {
  await withDom(async () => {
    const { root, client, engine } = await open();
    await reveal(root, "local", "password");
    assert.ok(textOf(root).includes(MINE_PASSWORD));
    assert.equal(find(root, "reveal", cellKey("local", "password")).getAttribute("aria-pressed"), "true");
    noSecretIn(root, [MINE_PASSWORD]);

    // The same field on the other side: the first goes, the second shows.
    await reveal(root, "server", "password");
    assert.ok(textOf(root).includes(THEIR_PASSWORD));
    assert.ok(!textOf(root).includes(MINE_PASSWORD));
    assert.equal(find(root, "reveal", cellKey("local", "password")).getAttribute("aria-pressed"), "false");
    assert.equal(value(root, "local", "password").trim(), "••••••••");

    // Another field, on the first side again.
    await reveal(root, "local", "pin");
    assert.ok(textOf(root).includes(MINE_PIN));
    noSecretIn(root, [MINE_PIN]);
    // The button names the row and the version, for a screen reader.
    assert.match(find(root, "reveal", cellKey("local", "pin")).getAttribute("aria-label"), /conflict\.hide_label/);
    assert.match(find(root, "reveal", cellKey("server", "password")).getAttribute("aria-label"), /conflict\.show_label/);
    assert.match(find(root, "reveal", cellKey("server", "password")).getAttribute("aria-label"), /Password/);
    // The notes, from either version.
    await reveal(root, "server", "notes");
    assert.ok(textOf(root).includes(THEIR_NOTES));
    noSecretIn(root, [THEIR_NOTES]);
    const [localHandle, serverHandle] = [...engine.handles.keys()];
    assert.deepEqual(client.calls, [
      ["reveal_item_field", localHandle, 1],
      ["reveal_item_field", serverHandle, 1],
      ["reveal_item_field", localHandle, 2],
      ["reveal_item_notes", serverHandle],
    ]);
  });
});

test("a_second_press_hides_the_value_and_a_failed_reveal_hides_everything", async () => {
  await withDom(async () => {
    const { root, engine } = await open();
    await reveal(root, "local", "password");
    await reveal(root, "local", "password");
    noSecretIn(root);
    assert.equal(find(root, "reveal", cellKey("local", "password")).childNodes[0].data, "conflict.show");

    await reveal(root, "server", "password");
    assert.ok(textOf(root).includes(THEIR_PASSWORD));
    // The engine lost the handle: the shown value goes too, and the message says something went wrong, without detail.
    engine.handles.clear();
    await reveal(root, "local", "pin");
    noSecretIn(root);
    assert.ok(textOf(find(root, "message")).includes("vault.error.unknown"));
  });
});

test("revealed_values_leave_the_dom_on_hide_resolve_and_lock", async () => {
  await withDom(async () => {
    // On hide.
    {
      const { root } = await open();
      await reveal(root, "local", "password");
      await reveal(root, "local", "password");
      noSecretIn(root);
    }
    // On resolve: the value is gone before the engine is asked, and after.
    {
      const { root, engine } = await open();
      await reveal(root, "server", "pin");
      let seen = null;
      engine.onResolve = async () => {
        seen = textOf(root);
      };
      await click(find(root, "keep-mine"));
      assert.ok(seen !== null && !seen.includes(THEIR_PIN), "gone while the engine works");
      noSecretIn(root);
    }
    // On lock: the page is empty and the handles are closed.
    {
      const { root, engine, scope } = await open();
      await reveal(root, "local", "password");
      assert.equal(engine.handles.size, 2);
      scope.run();
      await settle();
      assert.equal(textOf(root).trim(), "");
      assert.equal(root.childNodes.length, 0);
      assert.equal(engine.handles.size, 0, "both handles closed");
    }
  });
});

test("a_reveal_that_finishes_after_a_lock_never_reaches_the_page", async () => {
  await withDom(async () => {
    const { root, client, scope } = await open();
    let release;
    client.delay = new Promise((resolve) => {
      release = resolve;
    });
    const pending = reveal(root, "local", "password");
    await settle(3);
    scope.run();
    release();
    await pending;
    await settle();
    assert.ok(!textOf(root).includes(MINE_PASSWORD));
    assert.equal(root.childNodes.length, 0);
  });
});

test("keep_mine_and_keep_theirs_call_resolve_once_and_return_to_the_item", async () => {
  await withDom(async () => {
    for (const [role, choice] of [["keep-mine", "mine"], ["keep-theirs", "theirs"]]) {
      const { root, engine, moves } = await open();
      const button = find(root, "keep-" + choice);
      assert.equal(button, find(root, role));
      // Two quick presses are one choice.
      await Promise.all([click(button), click(button)]);
      await settle();
      assert.deepEqual(engine.calls.filter((c) => c[0] === "resolve"), [["resolve", ID, choice]]);
      assert.deepEqual(moves, [`/items/${ID}`]);
      assert.equal(engine.handles.size, 0, "the handles are closed once the choice is made");
      assert.equal(engine.closed, 1);
    }
  });
});

test("a_refused_choice_says_so_and_can_be_tried_again", async () => {
  await withDom(async () => {
    const { root, engine, moves } = await open();
    engine.failWith = coded("conflict");
    await click(find(root, "keep-mine"));
    assert.deepEqual(moves, []);
    assert.ok(textOf(find(root, "message")).includes("sync.error.conflict"));
    assert.equal(find(root, "keep-mine").getAttribute("aria-disabled"), "false");
    assert.equal(engine.handles.size, 2, "the versions stay open for the next try");
    engine.failWith = null;
    await click(find(root, "keep-mine"));
    assert.deepEqual(moves, [`/items/${ID}`]);
    assert.equal(engine.calls.filter((c) => c[0] === "resolve").length, 2);
  });
});

test("a_deleted_server_side_offers_restore_and_accept_deletion", async () => {
  await withDom(async () => {
    const spec = bankConflict();
    spec.server = { rev: 4, deleted: true, view: null };
    {
      const { root, engine, moves } = await open({ spec });
      assert.ok(textOf(all(root, "side")[1]).includes("conflict.deleted_server"));
      assert.equal(textOf(find(root, "keep-mine")).trim(), "conflict.restore_mine");
      assert.equal(textOf(find(root, "keep-theirs")).trim(), "conflict.accept_deletion");
      assert.ok(textOf(root).includes("conflict.restore_help"));
      assert.ok(textOf(root).includes("conflict.accept_deletion_help"));
      // The deleted side has no values to show: every cell says so.
      assert.equal(all(root, "reveal", cellKey("server", "password")).length, 0);
      await click(find(root, "keep-mine"));
      assert.deepEqual(engine.calls.filter((c) => c[0] === "resolve"), [["resolve", ID, "mine"]]);
      assert.deepEqual(moves, [`/items/${ID}`], "a restored item is shown");
    }
    {
      const { root, engine, moves } = await open({ spec });
      await click(find(root, "keep-theirs"));
      assert.deepEqual(engine.calls.filter((c) => c[0] === "resolve"), [["resolve", ID, "theirs"]]);
      assert.deepEqual(moves, ["/items"], "an accepted deletion leaves the item, which is gone, for the list");
    }
  });
});

test("a_local_deletion_against_a_server_edit_has_its_own_choices", async () => {
  await withDom(async () => {
    const spec = bankConflict();
    spec.local = { rev: 3, deleted: true, view: null };
    const { root, moves, engine } = await open({ spec });
    assert.ok(textOf(all(root, "side")[0]).includes("conflict.deleted_local"));
    assert.equal(textOf(find(root, "keep-mine")).trim(), "conflict.delete_mine");
    assert.equal(textOf(find(root, "keep-theirs")).trim(), "conflict.keep_server_version");
    // The server's version can still be read.
    await reveal(root, "server", "password");
    assert.ok(textOf(root).includes(THEIR_PASSWORD));
    await click(find(root, "keep-mine"));
    assert.deepEqual(moves, ["/items"], "a deletion that is kept leaves the item for the list");
    assert.deepEqual(engine.calls.filter((c) => c[0] === "resolve"), [["resolve", ID, "mine"]]);
  });
});

test("there_is_no_keep_both_button_in_m2", async () => {
  await withDom(async () => {
    for (const spec of [bankConflict(), bankConflict({ local: { rev: 3, view: loginView({ passkey: { rp_id: "bank.example", user_name: "ada" } }) } })]) {
      const { root } = await open({ spec });
      const buttons = all(root, "keep-mine").length + all(root, "keep-theirs").length + all(root, "reveal").length;
      const everyButton = [];
      const visit = (node) => {
        if (node.tagName === "button") everyButton.push(node.getAttribute("data-role"));
        for (const child of node.childNodes) visit(child);
      };
      visit(root);
      assert.ok(everyButton.length >= 2 && everyButton.length === buttons, "every button is a choice or a reveal");
      assert.ok(everyButton.every((role) => ["keep-mine", "keep-theirs", "reveal"].includes(role)));
      assert.ok(!/both/i.test(textOf(root)), "no word about keeping both");
    }
    const source = readFileSync(new URL("../../src/views/conflict.mjs", import.meta.url), "utf8");
    assert.ok(!/"both"/.test(source) && !/keep_both/.test(source));
    for (const lang of ["en", "nb"]) {
      const catalog = readFileSync(new URL(`../../src/locales/${lang}/conflict.json`, import.meta.url), "utf8");
      assert.ok(!/keep_both/.test(catalog));
    }
  });
});

test("a_passkey_item_says_only_keep_mine_or_keep_theirs_is_possible", async () => {
  await withDom(async () => {
    const passkey = { rp_id: "bank.example", user_name: "ada", created: 1, has_prf: false };
    const spec = bankConflict();
    spec.local.view = loginView({ passkey, modified: MODIFIED_MINE });
    const { root } = await open({ spec });
    assert.ok(find(root, "passkey-note"));
    assert.ok(textOf(find(root, "passkey-note")).includes("conflict.passkey_note"));
    assert.ok(textOf(find(root, "passkey-row")).includes("bank.example"));
    assert.equal(all(root, "keep-mine").length + all(root, "keep-theirs").length, 2);
    // An item without a passkey has no such note.
    const plain = await open();
    assert.equal(find(plain.root, "passkey-note"), null);
  });
});

test("many_conflicts_link_to_the_next_one", async () => {
  await withDom(async () => {
    const { root, engine } = await open();
    assert.equal(find(root, "more-conflicts"), null, "no note when this is the only conflict");
    engine.items = [
      { id: ID, conflict: true }, { id: OTHER, conflict: true }, { id: "33".repeat(16), conflict: true },
      { id: "44".repeat(16), conflict: false }, { id: "not-an-id", conflict: true },
    ];
    // The note is built with the screen: read the item again.
    engine.emit("changed", { ids: [ID] });
    await settle();
    const note = find(root, "more-conflicts");
    assert.ok(note, "the note is there");
    assert.ok(textOf(note).includes('"count":2'));
    assert.equal(find(note, "next-conflict").getAttribute("href"), `#/items/${OTHER}/conflict`);
  });
});

test("an_item_that_is_not_in_conflict_says_so_and_offers_no_choice", async () => {
  await withDom(async () => {
    const engine = fakeConflictEngine({ conflicts: {} });
    const root = await conflictView({ engine, client: fakeReveal(engine), id: ID, t, router: { go() {} } });
    assert.ok(textOf(find(root, "no-conflict")).includes("conflict.not_in_conflict"));
    assert.equal(all(root, "keep-mine").length + all(root, "keep-theirs").length, 0);
    assert.equal(find(root, "back").getAttribute("href"), `#/items/${ID}`);

    // Another failure shows the engine's code as a general text, never its message.
    engine.failConflict = Object.assign(new Error("secret-detail"), { code: "storage" });
    const failed = await conflictView({ engine, client: fakeReveal(engine), id: ID, t, router: { go() {} } });
    assert.ok(textOf(failed).includes("sync.error.storage"));
    assert.ok(!textOf(failed).includes("secret-detail"));
  });
});

test("a_change_to_the_item_reads_it_again_and_closes_the_old_handles", async () => {
  await withDom(async () => {
    const { root, engine } = await open();
    await reveal(root, "local", "password");
    const before = [...engine.handles.keys()];
    engine.emit("changed", { ids: [OTHER] });
    await settle();
    assert.deepEqual([...engine.handles.keys()], before, "a change to another item does nothing");
    assert.ok(textOf(root).includes(MINE_PASSWORD));

    engine.emit("changed", { ids: [ID] });
    await settle();
    noSecretIn(root);
    assert.equal(engine.handles.size, 2, "two new handles, the old two closed");
    assert.ok(![...engine.handles.keys()].some((h) => before.includes(h)));
    assert.equal(engine.closed, 1);
  });
});

test("an_action_after_the_lock_time_is_not_carried_out", async () => {
  await withDom(async () => {
    const { root, client, engine } = await open({ touch: () => false });
    await reveal(root, "local", "password");
    await click(find(root, "keep-mine"));
    assert.deepEqual(client.calls, []);
    assert.deepEqual(engine.calls.filter((c) => c[0] === "resolve"), []);
  });
});

test("the_view_builds_text_only_and_never_logs_or_stores_a_value", () => {
  for (const file of ["conflict.mjs", "trash.mjs"]) {
    const source = readFileSync(new URL(`../../src/views/${file}`, import.meta.url), "utf8");
    assert.ok(!/innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function/.test(source), `${file}: no markup from strings`);
    assert.ok(!/console\.|localStorage|sessionStorage|indexedDB|clipboard/.test(source), `${file}: no logging, storage or clipboard`);
  }
});

// ------------------------------------------------------------ list and item

test("list_shows_a_conflict_badge_and_the_item_view_links_to_the_conflict", async () => {
  await withDom(async () => {
    const entry = (id, over = {}) => ({
      id, name: `Item ${id.slice(0, 2)}`, type: "login", favorite: false, urls: [], username: "", rev: 2,
      pending: false, damaged: false, quarantined: false, missingOnServer: false, blocked: false, blockedReason: null,
      readOnly: false, conflict: false, ...over,
    });
    const engine = fakeEngine({ items: [entry(ID, { conflict: true, blocked: true, blockedReason: "conflict" }), entry(OTHER)] });
    const list = listView({ engine, router: { go() {} }, t });
    const rows = all(list, "item");
    const badge = (id) => all(list, "item").find((r) => r.getAttribute("data-id") === id);
    const marksOf = (node) => {
      const out = [];
      const visit = (n) => {
        if (n.getAttribute?.("data-mark")) out.push(n.getAttribute("data-mark"));
        for (const c of n.childNodes) visit(c);
      };
      visit(node);
      return out;
    };
    assert.deepEqual(marksOf(badge(ID)), ["conflict"], "a conflict shows as a conflict, not as a refused change");
    assert.deepEqual(marksOf(badge(OTHER)), []);
    assert.equal(rows.length, 2);
    const note = find(list, "conflict-note");
    assert.ok(note && textOf(note).includes('"count":1'));
    assert.equal(find(note, "first-conflict").getAttribute("href"), `#/items/${ID}/conflict`);

    // The note and the mark follow the engine.
    engine.items = [entry(ID), entry(OTHER)];
    engine.emit("changed", { ids: [ID] });
    assert.equal(find(list, "conflict-note"), null);
    assert.equal(find(list, "trash-link").getAttribute("href"), "#/trash");

    // The item screen: a link to the conflict, and no discard button that would drop one side unseen.
    const view = loginView();
    const itemEngine = fakeEngine({ items: [entry(ID, { conflict: true, blocked: true, blockedReason: "conflict" })], views: { [ID]: view }, secrets: { [ID]: ["ada", "x", "y"] } });
    const root = await itemView({ engine: itemEngine, sync: itemEngine, client: fakeClient(itemEngine), id: ID, t });
    const link = find(root, "open-conflict");
    assert.equal(link.getAttribute("href"), `#/items/${ID}/conflict`);
    assert.equal(find(root, "discard-change"), null);
    assert.equal(find(root, "edit"), null, "a conflicted item is not edited");
    assert.ok(textOf(find(root, "notice")).includes("conflict.notice"));
  });
});

test("damaged_and_quarantined_items_offer_keep_mine_after_a_confirmation", async () => {
  await withDom(async () => {
    for (const kind of ["damaged", "quarantined"]) {
      const flags = kind === "damaged" ? { damaged: true } : { quarantined: true };
      const entry = {
        id: ID, name: "Bank", type: "login", favorite: false, urls: [], username: "", rev: 2,
        pending: false, damaged: false, quarantined: false, missingOnServer: false, blocked: false, blockedReason: null, readOnly: false, ...flags,
      };
      const engine = fakeEngine({ items: [entry], views: { [ID]: loginView() }, secrets: { [ID]: ["ada", "x", "y"] } });
      engine.keepMine = async (id) => void engine.calls.push(["keepMine", id]);
      const root = await itemView({ engine, sync: engine, client: fakeClient(engine), id: ID, t });
      const button = find(root, "keep-mine");
      assert.equal(textOf(button).trim(), `conflict.keep_mine_${kind}`);
      const first = click(button);
      await settle();
      assert.ok(textOf(find(root, "dialog")).includes(`conflict.dialog.keep_mine_${kind}_body`));
      assert.ok(!engine.calls.some((c) => c[0] === "keepMine"), "nothing is written before the yes");
      await click(find(root, "dialog-cancel"));
      await first;
      assert.ok(!engine.calls.some((c) => c[0] === "keepMine"));
      const second = click(button);
      await settle();
      await click(find(root, "dialog-confirm"));
      await second;
      await settle();
      assert.deepEqual(engine.calls.filter((c) => c[0] === "keepMine"), [["keepMine", ID]]);
    }
  });
});

// -------------------------------------------------------------------- texts

test("conflict_and_trash_texts_exist_in_both_languages", () => {
  const read = (lang) => JSON.parse(readFileSync(new URL(`../../src/locales/${lang}/conflict.json`, import.meta.url), "utf8"));
  const en = read("en");
  const nb = read("nb");
  assert.deepEqual(Object.keys(en).sort(), Object.keys(nb).sort());
  const placeholders = (text) => [...text.matchAll(/\{([A-Za-z0-9_]+)\}/g)].map((m) => m[1]).sort();
  for (const key of Object.keys(en)) {
    assert.ok(key.startsWith("conflict."), key);
    assert.equal(typeof nb[key], "string");
    assert.ok(nb[key].trim() !== "", key);
    assert.deepEqual(placeholders(nb[key]), placeholders(en[key]), key);
    assert.ok(!/\bserver(?:en|ens)?\b/i.test(nb[key]), `${key}: the Norwegian text says "tjeneren"`);
  }
  for (const lang of ["en", "nb"]) {
    const vault = JSON.parse(readFileSync(new URL(`../../src/locales/${lang}/vault.json`, import.meta.url), "utf8"));
    assert.equal(typeof vault["vault.mark.conflict"], "string");
  }
  // Every key that the views ask for exists, written out or built from a short list.
  const dynamic = [
    "conflict.same", "conflict.differs", "conflict.hidden",
    "conflict.keep_mine_damaged", "conflict.keep_mine_quarantined",
    "conflict.dialog.keep_mine_damaged_body", "conflict.dialog.keep_mine_quarantined_body",
  ];
  const wanted = new Set(dynamic);
  for (const file of ["conflict.mjs", "trash.mjs", "item.mjs", "list.mjs"]) {
    const source = readFileSync(new URL(`../../src/views/${file}`, import.meta.url), "utf8");
    for (const m of source.matchAll(/"(conflict\.[a-z_.]+)"/g)) wanted.add(m[1]);
  }
  for (const key of wanted) assert.ok(Object.hasOwn(en, key), `en has ${key}`);
  // And every text is used.
  const sources = ["conflict.mjs", "trash.mjs", "item.mjs", "list.mjs"].map((f) => readFileSync(new URL(`../../src/views/${f}`, import.meta.url), "utf8")).join("\n");
  const routes = readdirSync(new URL("../../src/routes/", import.meta.url)).map((f) => readFileSync(new URL(`../../src/routes/${f}`, import.meta.url), "utf8")).join("\n");
  for (const key of Object.keys(en)) assert.ok(wanted.has(key) || routes.includes(`"${key}"`) || sources.includes(`"${key}"`), `${key} is used`);
});

test("the_conflict_and_trash_routes_are_registered_and_only_plain_ids_reach_the_view", async () => {
  const conflict = (await import("../../src/routes/conflict.route.mjs")).default;
  const trash = (await import("../../src/routes/trash.route.mjs")).default;
  assert.equal(conflict.path, "/items/:id/conflict");
  assert.equal(trash.path, "/trash");
  assert.equal(conflict.title, "conflict.title");
  assert.equal(trash.title, "conflict.trash.title");
});
