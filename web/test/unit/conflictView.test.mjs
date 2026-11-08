// The conflict view: both versions side by side, one secret on the page at a time,
// a choice that is made once, and nothing left on the page or open in the engine
// after a choice, a lock or a new reading.
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { test } from "node:test";
import conflictRoute from "../../src/routes/conflict.route.mjs";
import trashRoute from "../../src/routes/trash.route.mjs";
import { autoLockFor } from "../../src/lock.mjs";
import { createWipeScope, formatMoment } from "../../src/views/common.mjs";
import { conflictView } from "../../src/views/conflict.mjs";
import { itemView } from "../../src/views/item.mjs";
import { listView } from "../../src/views/list.mjs";
import {
  ID, MINE_NOTES, MINE_PASSWORD, MINE_PIN, MODIFIED_MINE, MODIFIED_THEIRS, OTHER, THEIR_NOTES, THEIR_PASSWORD, THEIR_PIN,
  bankConflict, fakeConflictEngine, fakeReveal, loginView,
} from "./conflictHelpers.mjs";
import { all, click, coded, fakeClient, fakeEngine, fakeSession, find, settle, t, textOf, withDom } from "./vaultHelpers.mjs";

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
/** Presses a choice and answers the question that comes first with yes. */
async function choose(root, role) {
  const pending = click(find(root, role));
  await settle();
  if (find(root, "dialog")) await click(find(root, "dialog-confirm"));
  await pending;
  await settle();
}
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
    assert.deepEqual(keys, ["extra", "password", "notes", "username", "~urls"]);
    assert.equal(value(root, "local", "extra").trim(), "one");
    assert.ok(textOf(find(find(root, "conflict-field", "extra"), "absent")).includes("conflict.absent"));
  });
});

test("only_one_secret_is_revealed_at_a_time_across_both_sides", async () => {
  await withDom(async () => {
    const { root, client, engine } = await open();
    await reveal(root, "local", "password");
    assert.ok(textOf(root).includes(MINE_PASSWORD));
    assert.equal(find(root, "reveal", cellKey("local", "password")).getAttribute("aria-pressed"), null, "one pattern: the label is swapped, nothing is pressed");
    assert.match(find(root, "reveal", cellKey("local", "password")).getAttribute("aria-label"), /conflict\.hide_label/);
    noSecretIn(root, [MINE_PASSWORD]);

    // The same field on the other side: the first goes, the second shows.
    await reveal(root, "server", "password");
    assert.ok(textOf(root).includes(THEIR_PASSWORD));
    assert.ok(!textOf(root).includes(MINE_PASSWORD));
    assert.match(find(root, "reveal", cellKey("local", "password")).getAttribute("aria-label"), /conflict\.show_label/);
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
      await choose(root, "keep-mine");
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
    for (const choice of ["mine", "theirs"]) {
      const { root, engine, moves } = await open();
      const button = find(root, `keep-${choice}`);
      // Two quick presses are one question and one choice.
      const both = Promise.all([click(button), click(button)]);
      await settle();
      assert.equal(all(root, "dialog").length, 1);
      assert.deepEqual(engine.calls.filter((c) => c[0] === "resolve"), [], "nothing is written before the yes");
      await click(find(root, "dialog-confirm"));
      await both;
      await settle();
      assert.deepEqual(engine.calls.filter((c) => c[0] === "resolve"), [["resolve", ID, choice]]);
      assert.deepEqual(moves, [`/items/${ID}`]);
      assert.equal(engine.handles.size, 0, "the handles are closed once the choice is made");
      assert.equal(engine.closed, 1);
    }
  });
});

test("every_choice_asks_first_and_names_what_is_dropped_for_good", async () => {
  await withDom(async () => {
    const cases = [
      ["keep_mine", bankConflict()],
      ["restore", { ...bankConflict(), server: { rev: 4, deleted: true, view: null } }],
      ["delete_mine", { ...bankConflict(), local: { rev: 3, deleted: true, view: null } }],
    ];
    for (const [mine, spec] of cases) {
      const theirs = { keep_mine: "keep_theirs", restore: "accept_deletion", delete_mine: "keep_server_version" }[mine];
      for (const [role, choice, name] of [["keep-mine", "mine", mine], ["keep-theirs", "theirs", theirs]]) {
        const { root, engine, moves } = await open({ spec });
        const first = click(find(root, role));
        await settle();
        const dialog = find(root, "dialog");
        assert.ok(dialog, `${name}: a question is on the page`);
        assert.ok(textOf(dialog).includes(`conflict.dialog.${name}_title`));
        assert.ok(textOf(dialog).includes(`conflict.dialog.${name}_body`));
        assert.ok(textOf(dialog).includes(`conflict.dialog.${name}_confirm`));
        assert.deepEqual(engine.calls.filter((c) => c[0] === "resolve"), []);
        // Cancel: nothing is written, the view is as it was and a choice can be made again.
        await click(find(root, "dialog-cancel"));
        await first;
        assert.equal(find(root, "dialog"), null);
        assert.deepEqual(engine.calls.filter((c) => c[0] === "resolve"), []);
        assert.deepEqual(moves, []);
        assert.equal(engine.handles.size, 2);
        // Yes: one choice.
        const second = click(find(root, role));
        await settle();
        await click(find(root, "dialog-confirm"));
        await second;
        await settle();
        assert.deepEqual(engine.calls.filter((c) => c[0] === "resolve"), [["resolve", ID, choice]]);
      }
    }
  });
});

test("the_questions_say_which_version_is_lost", () => {
  const en = JSON.parse(readFileSync(new URL("../../src/locales/en/conflict.json", import.meta.url), "utf8"));
  // Keeping mine drops the server's version; keeping the server's drops this device's version.
  assert.match(en["conflict.dialog.keep_mine_body"], /server's version.*dropped for good/);
  assert.match(en["conflict.dialog.keep_theirs_body"], /Your version on this device is dropped for good/);
  assert.match(en["conflict.dialog.accept_deletion_body"], /Your version on this device is dropped for good/);
  assert.match(en["conflict.dialog.delete_mine_body"], /server's version.*dropped for good/);
});


test("a_refused_choice_says_so_and_can_be_tried_again", async () => {
  await withDom(async () => {
    const { root, engine, moves } = await open();
    engine.failWith = coded("conflict");
    await choose(root, "keep-mine");
    assert.deepEqual(moves, []);
    assert.ok(textOf(find(root, "message")).includes("sync.error.conflict"));
    assert.equal(find(root, "keep-mine").getAttribute("aria-disabled"), "false");
    assert.equal(engine.handles.size, 2, "the versions stay open for the next try");
    engine.failWith = null;
    await choose(root, "keep-mine");
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
      assert.equal(textOf(find(root, "keep-mine")).trim(), "conflict.choice.restore");
      assert.equal(textOf(find(root, "keep-theirs")).trim(), "conflict.choice.accept_deletion");
      assert.ok(textOf(root).includes("conflict.help.restore"));
      assert.ok(textOf(root).includes("conflict.help.accept_deletion"));
      // The deleted side has no values to show: every cell says so.
      assert.equal(all(root, "reveal", cellKey("server", "password")).length, 0);
      await choose(root, "keep-mine");
      assert.deepEqual(engine.calls.filter((c) => c[0] === "resolve"), [["resolve", ID, "mine"]]);
      assert.deepEqual(moves, [`/items/${ID}`], "a restored item is shown");
    }
    {
      const { root, engine, moves } = await open({ spec });
      await choose(root, "keep-theirs");
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
    assert.equal(textOf(find(root, "keep-mine")).trim(), "conflict.choice.delete_mine");
    assert.equal(textOf(find(root, "keep-theirs")).trim(), "conflict.choice.keep_server_version");
    // The server's version can still be read.
    await reveal(root, "server", "password");
    assert.ok(textOf(root).includes(THEIR_PASSWORD));
    await choose(root, "keep-mine");
    assert.deepEqual(moves, ["/items"], "a deletion that is kept leaves the item for the list");
    assert.deepEqual(engine.calls.filter((c) => c[0] === "resolve"), [["resolve", ID, "mine"]]);
  });
});

test("a_deletion_on_both_sides_says_the_item_stays_deleted_and_asks_nothing", async () => {
  await withDom(async () => {
    const spec = bankConflict();
    spec.local = { rev: 3, deleted: true, view: null };
    spec.server = { rev: 4, deleted: true, view: null };
    for (const [role, choice] of [["keep-mine", "mine"], ["keep-theirs", "theirs"]]) {
      const { root, engine, moves } = await open({ spec });
      assert.ok(find(root, "both-deleted-note"));
      assert.ok(textOf(find(root, "both-deleted-note")).includes("conflict.both_deleted"));
      assert.equal(textOf(find(root, "keep-mine")).trim(), "conflict.choice.delete_both_mine");
      assert.equal(textOf(find(root, "keep-theirs")).trim(), "conflict.choice.delete_both_theirs");
      await click(find(root, role));
      await settle();
      assert.equal(find(root, "dialog"), null, "nothing is lost, so nothing is asked");
      assert.deepEqual(engine.calls.filter((c) => c[0] === "resolve"), [["resolve", ID, choice]]);
      assert.deepEqual(moves, ["/items"]);
    }
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
  const names = ["keep_mine", "keep_theirs", "restore", "accept_deletion", "delete_mine", "keep_server_version", "delete_both_mine", "delete_both_theirs"];
  for (const name of names) dynamic.push(`conflict.choice.${name}`, `conflict.help.${name}`);
  for (const name of names.slice(0, 6)) dynamic.push(`conflict.dialog.${name}_title`, `conflict.dialog.${name}_body`, `conflict.dialog.${name}_confirm`);
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

// ------------------------------------------------------------ the second round

/** A page context over fakes, as the route modules get it. */
function rig(spec = bankConflict()) {
  const engine = fakeConflictEngine({ conflicts: { [ID]: spec } });
  engine.stop = () => {};
  const client = fakeReveal(engine);
  const session = fakeSession({ client });
  const sync = { current: () => engine, start: async () => engine, stop() {} };
  const moves = [];
  const ctx = (path, params = {}) => ({
    params, path, i18n: { t, lang: "en", missing: [] }, client, services: { crypto: session, sync }, go: (p) => moves.push(p),
  });
  return { engine, ctx, done: () => autoLockFor(session, sync).stop() };
}

test("the_routes_are_in_the_build_and_the_conflict_route_loads_in_the_frame_and_refuses_a_non_hex_id", async () => {
  await withDom(async () => {
    assert.equal(conflictRoute.path, "/items/:id/conflict");
    assert.equal(trashRoute.path, "/trash");
    assert.equal(conflictRoute.title, "conflict.title");
    assert.equal(trashRoute.title, "conflict.trash.title");
    const r = rig();
    try {
      for (const bad of ["not-an-id", "11".repeat(15), "zz".repeat(16), "../x"]) {
        const node = await conflictRoute.load(r.ctx("/items/x/conflict", { id: bad }));
        assert.ok(find(node, "message"), `${bad}: a message, not a view`);
        assert.equal(find(node, "conflict"), null);
      }
      assert.deepEqual(r.engine.calls, [], "the engine is not asked about an id that is not an id");
      const node = await conflictRoute.load(r.ctx(`/items/${ID}/conflict`, { id: ID }));
      assert.ok(find(node, "shell"));
      assert.ok(find(node, "conflict"));
      assert.deepEqual(r.engine.calls, [["conflict", ID]]);
      const page = await trashRoute.load(r.ctx("/trash"));
      assert.ok(find(page, "trash"));
    } finally {
      r.done();
    }
  });
});

test("the_routes_are_files_the_build_picks_up", () => {
  for (const file of ["conflict.route.mjs", "trash.route.mjs"]) {
    assert.ok(readdirSync(new URL("../../src/routes/", import.meta.url)).includes(file));
  }
  assert.ok(readdirSync(new URL("../../src/styles/", import.meta.url)).includes("conflict.css"));
});

test("an_item_the_server_deleted_while_it_is_in_conflict_links_to_the_conflict", async () => {
  await withDom(async () => {
    const entry = {
      id: ID, name: "Bank", type: "login", favorite: false, urls: [], username: "", rev: 2,
      pending: true, damaged: false, quarantined: false, missingOnServer: false, blocked: true, blockedReason: "conflict",
      readOnly: false, conflict: true,
    };
    // The engine cannot open the item: there is no live version to show.
    const engine = fakeEngine({ items: [entry], views: {} });
    const root = await itemView({ engine, sync: engine, client: fakeClient(engine), id: ID, t });
    assert.equal(find(root, "unavailable"), null, "not the dead end");
    assert.equal(find(root, "open-conflict").getAttribute("href"), `#/items/${ID}/conflict`);
    assert.ok(textOf(find(root, "notice")).includes("conflict.notice"));
    assert.ok(textOf(root).includes("Bank"));
    assert.ok(find(root, "back"));
    // Without a conflict mark the item is still not found.
    const plain = fakeEngine({ items: [{ ...entry, conflict: false }], views: {} });
    const dead = await itemView({ engine: plain, sync: plain, client: fakeClient(plain), id: ID, t });
    assert.ok(find(dead, "unavailable"));
    assert.equal(find(dead, "open-conflict"), null);
  });
});

test("addresses_and_the_one_time_password_are_compared_as_text", async () => {
  await withDom(async () => {
    const spec = bankConflict();
    spec.local.view = loginView({ urls: [{ url: "https://bank.example", matching: "host" }, { url: "https://b.example", matching: "host" }], has_totp: true });
    spec.server.view = loginView({ urls: [{ url: "https://bank.example", matching: "host" }], has_totp: false, modified: MODIFIED_THEIRS });
    const { root } = await open({ spec });
    const urls = find(root, "conflict-field", "~urls");
    assert.equal(urls.getAttribute("data-same"), "differs");
    assert.deepEqual(all(urls, "url").map((n) => textOf(n).trim()).sort(), ["https://b.example", "https://bank.example", "https://bank.example"]);
    const totp = find(root, "conflict-field", "~totp");
    assert.equal(totp.getAttribute("data-same"), "differs");
    assert.deepEqual(all(totp, "totp").map((n) => textOf(n).trim()), ["conflict.totp_yes", "conflict.totp_no"]);
    // Differing rows come before the rows that agree.
    const keys = all(root, "conflict-field").map((n) => n.getAttribute("data-key"));
    assert.ok(keys.indexOf("~urls") < keys.indexOf("username"));
    assert.ok(keys.indexOf("~totp") < keys.indexOf("username"));

    // Equal addresses, in another order, agree; a version without any says so.
    const same = bankConflict();
    same.local.view = loginView({ urls: [{ url: "https://a.example", matching: "host" }, { url: "https://b.example", matching: "host" }] });
    same.server.view = loginView({ urls: [{ url: "https://b.example", matching: "host" }, { url: "https://a.example", matching: "host" }] });
    const two = await open({ spec: same });
    assert.equal(find(two.root, "conflict-field", "~urls").getAttribute("data-same"), "same");
    assert.equal(find(two.root, "conflict-field", "~totp"), null, "no row when neither version has a one-time password");
    const none = bankConflict();
    none.local.view = loginView({ urls: [] });
    const three = await open({ spec: none });
    assert.equal(find(three.root, "conflict-field", "~urls").getAttribute("data-same"), "differs");
    assert.ok(find(find(three.root, "conflict-field", "~urls"), "none"));
    // A deleted side has neither.
    const gone = bankConflict();
    gone.server = { rev: 4, deleted: true, view: null };
    const four = await open({ spec: gone });
    assert.equal(find(four.root, "conflict-field", "~urls").getAttribute("data-same"), "differs");
    assert.ok(find(find(four.root, "conflict-field", "~urls"), "absent"));
  });
});

test("the_next_conflict_is_the_one_after_this_in_the_list_and_the_list_wraps", async () => {
  await withDom(async () => {
    const [a, b, c] = ["aa".repeat(16), "bb".repeat(16), "cc".repeat(16)];
    const conflicts = Object.fromEntries([a, b, c].map((id) => [id, bankConflict()]));
    const engine = fakeConflictEngine({ conflicts });
    engine.items = [{ id: a, conflict: true }, { id: "dd".repeat(16), conflict: false }, { id: b, conflict: true }, { id: c, conflict: true }];
    const next = async (id) => {
      const root = await conflictView({ engine, client: fakeReveal(engine), id, t, router: { go() {} } });
      const note = find(root, "more-conflicts");
      assert.ok(textOf(note).includes('"count":2'));
      return find(note, "next-conflict").getAttribute("href");
    };
    assert.equal(await next(a), `#/items/${b}/conflict`);
    assert.equal(await next(b), `#/items/${c}/conflict`, "from the second to the third, not back to the first");
    assert.equal(await next(c), `#/items/${a}/conflict`, "and round again");
  });
});

test("the_button_comes_before_the_value_and_a_long_value_is_only_text", async () => {
  await withDom(async () => {
    const { root, engine } = await open();
    const long = "L".repeat(64);
    for (const handle of engine.handles.values()) handle.secrets.password = long;
    const cell = find(root, "cell", cellKey("local", "password"));
    const order = (node) => [...node.childNodes].map((n) => n.getAttribute("data-role") ?? "side");
    assert.deepEqual(order(cell), ["side", "reveal", "value"], "the button sits above the value");
    await reveal(root, "local", "password");
    assert.equal(value(root, "local", "password").trim(), long);
    assert.deepEqual(order(cell), ["side", "reveal", "value"], "showing changes the value's text only");
  });
});

test("rows_are_groups_named_by_their_label", async () => {
  await withDom(async () => {
    const { root } = await open();
    for (const row of all(root, "conflict-field")) {
      assert.equal(row.getAttribute("role"), "group");
      const id = row.getAttribute("aria-labelledby");
      const label = [...row.childNodes].find((n) => n.getAttribute("id") === id);
      assert.ok(label, `${row.getAttribute("data-key")}: the label has the id the group names`);
      assert.ok(textOf(label).trim() !== "");
      assert.notEqual(row.tagName, "section");
    }
    assert.equal(all(root, "conflict-field").length, new Set(all(root, "conflict-field").map((n) => n.getAttribute("aria-labelledby"))).size);
  });
});

test("rows_that_differ_are_kept_when_the_list_is_cut_and_the_cut_is_said", async () => {
  await withDom(async () => {
    const many = Array.from({ length: 205 }, (_, i) => ({ id: `f${i}`, label: `Field ${i}`, kind: "text", value: `v${i}` }));
    const spec = bankConflict({
      fields: many.map((f, i) => ({ key: f.id, label: f.label, kind: "text", same: i >= 202 ? false : true })),
    });
    spec.local.view = loginView({ fields: many, urls: [] });
    spec.server.view = loginView({ fields: many, urls: [] });
    const { root } = await open({ spec });
    const keys = all(root, "conflict-field").map((n) => n.getAttribute("data-key"));
    assert.equal(keys.length, 200);
    assert.deepEqual(keys.slice(0, 3), ["f202", "f203", "f204"], "the rows that differ are shown first and survive the cut");
    assert.ok(textOf(find(root, "rows-cut")).includes('"count":6'), "205 fields and the notes row make 206; six are left out");
    // Under the limit there is no line.
    const small = await open();
    assert.equal(find(small.root, "rows-cut"), null);
  });
});

test("leaving_the_view_wipes_the_values_and_closes_the_handles_at_once", async () => {
  await withDom(async () => {
    for (const type of ["hashchange", "pagehide"]) {
      const listeners = new Map();
      const win = {
        addEventListener: (event, fn) => listeners.set(event, fn),
        removeEventListener: (event, fn) => listeners.get(event) === fn && listeners.delete(event),
      };
      const { root, engine } = await open({ extra: { win } });
      await reveal(root, "local", "password");
      assert.ok(textOf(root).includes(MINE_PASSWORD));
      assert.ok(listeners.has(type));
      listeners.get(type)();
      await settle();
      assert.equal(root.childNodes.length, 0);
      assert.equal(engine.handles.size, 0, `${type}: both handles closed`);
      assert.equal(listeners.size, 0, "the listeners are gone");
    }
  });
});

test("a_view_that_is_found_detached_closes_its_handles_and_never_reopens_them", async () => {
  await withDom(async () => {
    const { root, engine } = await open();
    root.isConnected = true;
    engine.emit("changed", { ids: [OTHER] });
    assert.equal(engine.handles.size, 2, "on the page, nothing changes");
    root.isConnected = false; // the page moved on without telling the view
    const calls = engine.calls.length;
    engine.emit("changed", { ids: [ID] });
    await settle();
    assert.equal(engine.calls.length, calls, "the conflict is not read again");
    assert.equal(engine.handles.size, 0);
    assert.equal(root.childNodes.length, 0);

    // A reading that finishes after the view has been left is closed, not shown.
    const second = await open();
    second.root.isConnected = true;
    second.engine.emit("changed", { ids: [OTHER] });
    let release;
    const gate = new Promise((resolve) => {
      release = resolve;
    });
    const original = second.engine.conflict;
    second.engine.conflict = async (id) => {
      await gate;
      return original.call(second.engine, id);
    };
    second.engine.emit("changed", { ids: [ID] });
    await settle();
    second.root.isConnected = false;
    release();
    await settle();
    assert.equal(second.engine.handles.size, 0, "the handles that came late are closed");
    assert.equal(second.root.childNodes.length, 0);
  });
});

test("a_failure_after_the_lock_writes_to_no_node", async () => {
  await withDom(async () => {
    const { root, client, scope, engine } = await open();
    const message = find(root, "message");
    let fail;
    client.delay = new Promise((_, reject) => {
      fail = reject;
    });
    const pending = reveal(root, "local", "password");
    await settle(3);
    scope.run();
    fail(coded("reveal_failed"));
    await pending;
    await settle();
    assert.equal(textOf(message).trim(), "", "the detached message node stays empty");
    assert.equal(engine.handles.size, 0);
  });
});

test("a_choice_the_engine_answers_with_not_found_reads_the_item_again_and_says_it_is_settled", async () => {
  await withDom(async () => {
    const { root, engine, moves } = await open();
    // Another tab chose already: the engine has no conflict for the item any more.
    engine.onResolve = async () => {
      engine.failConflict = coded("not_found");
    };
    engine.failWith = coded("not_found");
    await choose(root, "keep-mine");
    assert.deepEqual(moves, []);
    assert.ok(textOf(find(root, "no-conflict")).includes("conflict.not_in_conflict"));
    assert.equal(all(root, "keep-mine").length, 0);
    assert.equal(engine.handles.size, 0, "the old handles were closed");
  });
});
