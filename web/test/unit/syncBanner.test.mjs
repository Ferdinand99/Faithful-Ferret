// The banner for warnings and stops of the sync engine: every code of the table has
// its text in both languages and its action; a warning that is cleared goes away; and
// no banner shows what an item is called.
import assert from "node:assert/strict";
import { test } from "node:test";
import { WARNING_TABLE } from "../../src/sync/checkpoint.mjs";
import { createWipeScope } from "../../src/views/common.mjs";
import { shellView } from "../../src/views/shell.mjs";
import { BANNERS, isBannerCode, syncBanner } from "../../src/views/syncBanner.mjs";
import { click, all, find, settle, textOf, withDom } from "./vaultHelpers.mjs";
import { EN, NB, fakeWarningsEngine, translator } from "./syncWarningsHelpers.mjs";

/** What the design table says each code offers, in words of the catalog. */
const ACTIONS = {
  server_shows_older_state: ["check_again"],
  checkpoint_rolled_back: ["check_again"],
  checkpoint_forged: ["check_again"],
  bad_feed: ["try_again"],
  server_hid_item: [],
  verify_deferred: [],
  rollback_suspected: ["try_again", "forget"],
  server_restored: ["see_what_happened"],
  restore_epoch_lowered: ["try_again", "forget"],
  sync_memory_full: ["forget"],
  unsupported: [],
};

const banners = (root) => all(root, "sync-banner");
const bannerOf = (root, code) => banners(root).find((node) => node.getAttribute("data-code") === code) ?? null;
const actionsOf = (node) => all(node, "banner-action");

/** A banner for an engine in the state the code stands for. */
function bannerFor(code, lang = "en") {
  const engine = WARNING_TABLE[code].kind === "stop" ? fakeWarningsEngine({ halted: code }) : fakeWarningsEngine({ warnings: [code] });
  const went = [];
  const root = syncBanner({ engine, router: { go: (path) => went.push(path) }, t: translator(lang) });
  return { engine, root, went };
}

test("each_code_in_the_section_7_table_has_text_in_both_languages_and_its_action", async () => {
  await withDom(async () => {
    assert.deepEqual(Object.keys(BANNERS).sort(), Object.keys(WARNING_TABLE).sort(), "the banner follows the table, no more and no less");
    assert.deepEqual(Object.keys(ACTIONS).sort(), Object.keys(WARNING_TABLE).sort());
    for (const [code, entry] of Object.entries(WARNING_TABLE)) {
      // The kind of the table decides how it looks: a stop holds sync, the rest are warnings (a notice for the hidden item).
      const level = entry.kind === "stop" ? "stop" : code === "server_hid_item" ? "info" : "warning";
      assert.equal(BANNERS[code].level, level, code);
      assert.deepEqual(BANNERS[code].actions, ACTIONS[code], `${code}: actions`);
      for (const [lang, catalog] of [["en", EN], ["nb", NB]]) {
        assert.ok(catalog[`syncwarnings.banner.${code}`], `${lang}: text for ${code}`);
        for (const action of ACTIONS[code]) assert.ok(catalog[`syncwarnings.action.${action}`], `${lang}: label for ${action}`);
        const { root } = bannerFor(code, lang);
        const node = bannerOf(root, code);
        assert.ok(node, `${lang}: ${code} has a banner`);
        assert.equal(node.getAttribute("data-level"), level);
        assert.match(textOf(node), new RegExp(catalog[`syncwarnings.banner.${code}`].slice(0, 40).replace(/[()]/g, "\\$&")));
        assert.match(textOf(node), new RegExp(catalog[`syncwarnings.kind.${level}`]), "the kind is a word, not a colour");
        const labels = actionsOf(node).map((button) => textOf(button).trim());
        assert.deepEqual(labels, ACTIONS[code].map((action) => catalog[`syncwarnings.action.${action}`]), `${lang}: ${code} actions`);
        // The message is read out when it appears; the notice about a hidden item is polite.
        assert.equal(find(node, "banner-text").getAttribute("role"), level === "info" ? "status" : "alert");
      }
    }
    assert.equal(isBannerCode("constructor"), false);
    assert.equal(isBannerCode("__proto__"), false);
  });
});

test("the_actions_do_what_the_table_says", async () => {
  await withDom(async () => {
    // Check again and try again (on a warning) read the feed and check the checkpoint.
    for (const code of ["server_shows_older_state", "checkpoint_rolled_back", "checkpoint_forged", "bad_feed"]) {
      const { engine, root } = bannerFor(code);
      engine.verifyResult = code;
      await click(actionsOf(bannerOf(root, code))[0]);
      assert.deepEqual(engine.calls, ["verifyNow"], code);
      // It still stands, and the note says so.
      assert.ok(bannerOf(root, code), `${code} stays while the check still finds it`);
      assert.match(textOf(find(bannerOf(root, code), "banner-note")), /still stands/);
    }
    // Try again on a stop lifts the stop through the engine.
    for (const code of ["rollback_suspected", "restore_epoch_lowered"]) {
      const { engine, root, went } = bannerFor(code);
      engine.onResume = () => {
        engine.halted = null;
        engine.emit("state", { kind: "syncing" });
      };
      await click(actionsOf(bannerOf(root, code))[0]);
      assert.deepEqual(engine.calls, ["resumeAfterHalt"], code);
      assert.equal(bannerOf(root, code), null, `${code} is gone once the engine runs`);
      assert.deepEqual(went, []);
    }
    // The other actions go to their screens, and call nothing.
    const restored = bannerFor("server_restored");
    await click(actionsOf(bannerOf(restored.root, "server_restored"))[0]);
    assert.deepEqual(restored.went, ["/restored"]);
    const forget = bannerFor("sync_memory_full");
    await click(actionsOf(bannerOf(forget.root, "sync_memory_full"))[0]);
    assert.deepEqual(forget.went, ["/forget"]);
    const both = bannerFor("rollback_suspected");
    await click(actionsOf(bannerOf(both.root, "rollback_suspected"))[1]);
    assert.deepEqual(both.went, ["/forget"]);
    assert.deepEqual([restored.engine.calls, forget.engine.calls, both.engine.calls], [[], [], []]);
  });
});

test("verify_deferred_shows_a_lasting_warning_banner_that_checkpoint_checks_are_paused", async () => {
  await withDom(async () => {
    for (const lang of ["en", "nb"]) {
      const { engine, root } = bannerFor("verify_deferred", lang);
      const node = bannerOf(root, "verify_deferred");
      assert.ok(node, `${lang}: the banner is there from the start`);
      assert.equal(node.getAttribute("data-level"), "warning", "warning level, not a stop and not a mere notice");
      assert.match(textOf(node), lang === "en" ? /Checkpoint checks are paused/ : /Kontrollen av sjekkpunkter er satt på pause/);
      assert.equal(find(node, "banner-text").getAttribute("role"), "alert");
      // Lasting: it has no way to hide it, and no action; passes, other warnings and a stop come and go around it.
      assert.equal(actionsOf(node).length, 0);
      assert.equal(find(node, "banner-dismiss"), null);
      for (const kind of ["syncing", "idle"]) engine.emit("state", { kind });
      engine.raise("checkpoint_forged");
      engine.clear("checkpoint_forged");
      assert.ok(bannerOf(root, "verify_deferred"), `${lang}: it stands through passes and other warnings`);
      // Only the engine's own all-clear removes it.
      engine.clear("verify_deferred");
      assert.equal(bannerOf(root, "verify_deferred"), null);
    }
    // A page that is built later (a reload, another screen) finds it again, since the engine reports it.
    const engine = fakeWarningsEngine({ warnings: ["verify_deferred"] });
    const later = syncBanner({ engine, router: { go() {} }, t: translator() });
    assert.ok(bannerOf(later, "verify_deferred"));
  });
});

test("banner_disappears_on_warning_cleared", async () => {
  await withDom(async () => {
    const engine = fakeWarningsEngine();
    const root = syncBanner({ engine, router: { go() {} }, t: translator() });
    assert.equal(banners(root).length, 0, "nothing stands, nothing shows");
    engine.raise("server_shows_older_state");
    engine.raise("checkpoint_forged");
    assert.deepEqual(banners(root).map((node) => node.getAttribute("data-code")), ["server_shows_older_state", "checkpoint_forged"]);
    // The same warning raised twice is one banner.
    engine.emit("state", { kind: "warning", code: "checkpoint_forged" });
    assert.equal(banners(root).length, 2);
    engine.clear("server_shows_older_state");
    assert.deepEqual(banners(root).map((node) => node.getAttribute("data-code")), ["checkpoint_forged"]);
    engine.clear("checkpoint_forged");
    assert.equal(banners(root).length, 0);
    // A stop goes away when the engine runs again, and it comes back if it halts again.
    engine.halt("restore_epoch_lowered");
    assert.ok(bannerOf(root, "restore_epoch_lowered"));
    engine.halted = null;
    engine.emit("state", { kind: "syncing" });
    assert.equal(banners(root).length, 0);
    engine.halt("restore_epoch_lowered");
    assert.ok(bannerOf(root, "restore_epoch_lowered"));
  });
});

test("banner_shows_no_item_names", async () => {
  await withDom(async () => {
    const engine = fakeWarningsEngine();
    const root = syncBanner({ engine, router: { go() {} }, t: translator() });
    const secret = "Bank login 4111 1111 1111 1111";
    // The events carry ids and reasons; the banner reads neither.
    engine.raise("server_hid_item", { id: "ab".repeat(16), name: secret, reason: secret });
    engine.raise("checkpoint_forged", { id: "cd".repeat(16), name: secret });
    engine.halt("rollback_suspected");
    engine.emit("state", { kind: "halted", code: "rollback_suspected", name: secret, id: "ef".repeat(16) });
    engine.emit("error", { code: "bad_feed", id: "01".repeat(16), name: secret, reason: secret });
    // Warnings that are not in the table (an item's own trouble) get no banner here.
    engine.emit("state", { kind: "warning", code: "row_damaged", id: "23".repeat(16), name: secret });
    assert.deepEqual(banners(root).map((node) => node.getAttribute("data-code")).sort(), ["bad_feed", "checkpoint_forged", "rollback_suspected", "server_hid_item"]);
    const text = textOf(root);
    assert.doesNotMatch(text, /Bank login|4111|abab|cdcd|efef|0101|2323/);
    // Nor does it put anything of the payload in an attribute.
    for (const node of banners(root)) for (const value of node.attributes.values()) assert.doesNotMatch(value, /Bank|4111|abab/);
  });
});

test("a_bad_feed_that_came_as_an_error_has_try_again_and_goes_with_a_good_pass", async () => {
  await withDom(async () => {
    const engine = fakeWarningsEngine();
    const root = syncBanner({ engine, router: { go() {} }, t: translator() });
    engine.emit("error", { code: "bad_feed" });
    const node = bannerOf(root, "bad_feed");
    assert.ok(node);
    assert.deepEqual(actionsOf(node).map((b) => textOf(b).trim()), [EN["syncwarnings.action.try_again"]]);
    // Try again: the feed is read and checked; a good answer clears it, though the engine raised no warning.
    await click(actionsOf(node)[0]);
    assert.deepEqual(engine.calls, ["verifyNow"]);
    assert.equal(bannerOf(root, "bad_feed"), null);
    // A pass that ends well clears it too.
    engine.emit("error", { code: "bad_feed" });
    assert.ok(bannerOf(root, "bad_feed"));
    engine.emit("state", { kind: "idle" });
    assert.equal(bannerOf(root, "bad_feed"), null);
    // An error that is not a bad feed is not this banner's.
    engine.emit("error", { code: "storage" });
    assert.equal(banners(root).length, 0);
    // A bad feed that the checkpoint check found stands as a warning of the engine and is not cleared by an idle pass.
    engine.raise("bad_feed");
    engine.emit("state", { kind: "idle" });
    assert.ok(bannerOf(root, "bad_feed"));
  });
});

test("an_action_runs_once_at_a_time_says_it_is_working_and_reports_what_it_found", async () => {
  await withDom(async () => {
    const engine = fakeWarningsEngine({ warnings: ["server_shows_older_state"] });
    const root = syncBanner({ engine, router: { go() {} }, t: translator() });
    const button = actionsOf(bannerOf(root, "server_shows_older_state"))[0];
    let release;
    engine.gate = new Promise((resolve) => (release = resolve));
    engine.verifyResult = "not_checked";
    const first = click(button);
    await settle(2);
    assert.equal(button.disabled, true, "disabled while it runs");
    assert.equal(bannerOf(root, "server_shows_older_state").getAttribute("aria-busy"), "true");
    assert.match(textOf(find(root, "banner-note")), /Working/);
    await click(button); // a second press while it runs does nothing
    release();
    await first;
    await settle();
    assert.deepEqual(engine.calls, ["verifyNow"], "once");
    assert.equal(button.disabled, false);
    assert.match(textOf(find(root, "banner-note")), /could not be reached/);
    // A stop that stays says so, and stays.
    const halted = fakeWarningsEngine({ halted: "restore_epoch_lowered" });
    const stop = syncBanner({ engine: halted, router: { go() {} }, t: translator("nb") });
    await click(actionsOf(bannerOf(stop, "restore_epoch_lowered"))[0]);
    assert.deepEqual(halted.calls, ["resumeAfterHalt"]);
    assert.ok(bannerOf(stop, "restore_epoch_lowered"));
    assert.match(textOf(find(stop, "banner-note")), /Årsaken er der fortsatt/);
    // A try that throws says it did not work, and the button is usable again.
    halted.resumeError = new Error("boom");
    await click(actionsOf(bannerOf(stop, "restore_epoch_lowered"))[0]);
    assert.match(textOf(find(stop, "banner-note")), /Det virket ikke/);
    assert.doesNotMatch(textOf(stop), /boom/);
  });
});

test("the_notice_about_a_hidden_item_can_be_hidden_and_comes_back_if_raised_again", async () => {
  await withDom(async () => {
    const engine = fakeWarningsEngine({ warnings: ["server_hid_item"] });
    const root = syncBanner({ engine, router: { go() {} }, t: translator() });
    await click(find(bannerOf(root, "server_hid_item"), "banner-dismiss"));
    assert.equal(bannerOf(root, "server_hid_item"), null);
    engine.emit("state", { kind: "idle" }); // the engine still reports it, and the user said no
    assert.equal(bannerOf(root, "server_hid_item"), null);
    engine.emit("state", { kind: "warning", code: "server_hid_item", id: "ab".repeat(16) });
    assert.ok(bannerOf(root, "server_hid_item"));
    // The stops and the warnings of a check have nothing to hide them.
    for (const code of ["server_restored", "verify_deferred", "bad_feed"]) assert.equal(find(bannerFor(code).root, "banner-dismiss"), null, code);
  });
});

test("the_banner_stops_listening_with_its_page", async () => {
  await withDom(async () => {
    const engine = fakeWarningsEngine();
    const root = syncBanner({ engine, router: { go() {} }, t: translator() });
    assert.equal(engine.listening, 2);
    // Once shown and then gone, the next event removes the listeners instead of calling them.
    root.isConnected = true;
    engine.emit("state", { kind: "idle" });
    engine.emit("error", { code: "storage" });
    root.isConnected = false;
    engine.emit("state", { kind: "idle" });
    engine.emit("error", { code: "bad_feed" });
    assert.equal(engine.listening, 0);
    assert.equal(banners(root).length, 0);
  });
});

// ------------------------------------------------------------ in the frame

function frame(engine, lang = "en") {
  const root = shellView({
    t: translator(lang),
    engine: Object.assign(engine, { list: () => [] }),
    session: { onLock() {} },
    content: globalThis.document.createElement("div"),
    lock: async () => {},
    touch: () => true,
    scope: createWipeScope(),
    onLocked: () => globalThis.document.createElement("div"),
    win: undefined,
    router: { go() {} },
  });
  return root;
}

test("the_frame_shows_the_banner_once_and_the_stopped_state_in_the_bar", async () => {
  await withDom(async () => {
    const engine = fakeWarningsEngine({ halted: "server_restored" });
    const root = frame(engine);
    assert.ok(bannerOf(root, "server_restored"), "a frame built while the engine is stopped shows the stop");
    assert.equal(textOf(find(root, "sync-status")).trim(), EN["syncwarnings.pill.halted"]);
    assert.equal(find(root, "sync-status").getAttribute("data-state"), "halted");
    // A warning of the table is the banner's, so the frame's own list of notices does not repeat it.
    engine.raise("checkpoint_forged");
    engine.emit("error", { code: "bad_feed" });
    assert.equal(all(root, "banner").length, 0, "no second banner");
    assert.ok(bannerOf(root, "checkpoint_forged"));
    assert.ok(bannerOf(root, "bad_feed"));
    // A warning that is not in the table still gets the frame's own banner.
    engine.emit("state", { kind: "warning", code: "rev_below_remembered", id: "ab".repeat(16) });
    assert.equal(all(root, "banner").length, 1);
    assert.equal(banners(root).length, 3);
  });
});

test("an_engine_without_health_gets_a_frame_without_the_banner", async () => {
  await withDom(async () => {
    const engine = fakeWarningsEngine();
    delete engine.health;
    const root = frame(engine);
    assert.equal(find(root, "sync-banners"), null);
  });
});
