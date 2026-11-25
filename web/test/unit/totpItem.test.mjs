// The item page of an item with a one-time password: the code is live and follows the clock, the countdown is plain text and the
// code is the only live region, Copy hands a fresh code to the clipboard helper (cleared after 30 seconds), and a lock, a page
// change or a failed code leave nothing running. The codes are checked against the reference in totpHelpers.mjs, which the
// RFC 6238 vectors back (totpModel.test.mjs).
import assert from "node:assert/strict";
import { mock, test } from "node:test";
import { secretClipboardFor } from "../../src/secretClipboard.mjs";
import { createWipeScope } from "../../src/views/common.mjs";
import { itemView } from "../../src/views/item.mjs";
import { RFC_SECRET, RFC_URI, everything, fakeTotpClient, reference } from "./totpHelpers.mjs";
import { all, click, fakeClock, fakeEngine, find, settle, t, textOf, walk, withDom } from "./vaultHelpers.mjs";

const ID = "11".repeat(16);

const VIEW = Object.freeze({
  item_type: "login", name: "Example", fields: [{ id: "username", label: "User name", kind: "text", value: "ada" }, { id: "password", label: "Password", kind: "password", value: null }],
  urls: [{ url: "https://example.test", matching: "host" }], has_totp: true, has_notes: false, favorite: false, read_only: false,
});
const ENTRY = Object.freeze({
  id: ID, name: "Example", type: "login", favorite: false, urls: ["https://example.test"], username: "ada", rev: 1,
  pending: false, damaged: false, quarantined: false, missingOnServer: false, blocked: false, blockedReason: null, readOnly: false,
});

/** An item screen over fakes and a clock set to `seconds` (Unix time). */
async function open({ uri = RFC_URI, view = {}, seconds = 59, scope, touch, failCode = false } = {}) {
  const engine = fakeEngine({ items: [ENTRY], views: { [ID]: { ...VIEW, ...view } }, secrets: { [ID]: ["ada", "pw-SECRET-1"] } });
  const client = fakeTotpClient(engine, { uris: { [ID]: uri } });
  if (failCode) client.vault.totp_code = async () => Promise.reject(Object.assign(new Error("x"), { code: "internal" }));
  const clock = fakeClock(seconds * 1000);
  const written = [];
  const clipboard = { writes: written, async writeText(text) { written.push(text); } };
  const root = await itemView({ engine, sync: engine, client, id: ID, t, scope, touch, clipboard, clock });
  await settle();
  return { engine, client, clock, root, clipboard, written };
}

const codeOf = (root) => textOf(find(root, "totp-code")).trim();
const leftOf = (root) => textOf(find(root, "totp-left")).trim();

test("the_item_shows_a_live_code_and_the_countdown", async () => {
  await withDom(async () => {
    // RFC 6238 appendix B: at 59 s the 6 digit code is 287082 and the period has 1 s left.
    const { root, client, clock, engine } = await open({ seconds: 59 });
    assert.equal(codeOf(root), "287 082");
    assert.equal(leftOf(root), 'vault.item.totp_left {"seconds":1}');
    assert.deepEqual(all(root, "item-card").map((c) => c.getAttribute("data-card")), ["login", "totp"]);
    assert.equal(client.calls.filter((c) => c[0] === "totp_code").length, 1);
    assert.deepEqual(client.calls.find((c) => c[0] === "totp_code").slice(2), [59], "the worker is given the time of the page's clock");
    assert.equal(engine.handles.size, 0, "the handle lived for the one call");
    assert.equal(client.calls.some((c) => c[0] === "reveal_totp_secret"), false, "the secret is not asked for to show a code");

    // The second turns over: the next period has a new code, made by the worker; the page holds no old one.
    clock.advance(1_010);
    await settle();
    assert.equal(codeOf(root), `${reference({ secret: RFC_SECRET }, 60).slice(0, 3)} ${reference({ secret: RFC_SECRET }, 60).slice(3)}`);
    assert.equal(leftOf(root), 'vault.item.totp_left {"seconds":30}');
    assert.notEqual(codeOf(root), "287 082", "the old code is gone");
    assert.equal(client.calls.filter((c) => c[0] === "totp_code").length, 2);

    // Inside a period the countdown moves and no new code is made.
    clock.advance(10_000);
    await settle();
    assert.equal(leftOf(root), 'vault.item.totp_left {"seconds":20}');
    assert.equal(client.calls.filter((c) => c[0] === "totp_code").length, 2);
    const data = find(root, "totp-left").getAttribute("data-state");
    assert.equal(data, "ok");
    clock.advance(16_000);
    await settle();
    assert.equal(find(root, "totp-left").getAttribute("data-state"), "low", "the last seconds are marked");
  });
});

test("an_eight_digit_code_is_written_in_two_groups_of_four", async () => {
  await withDom(async () => {
    const uri = `otpauth://totp/Example:ada?secret=${RFC_SECRET}&digits=8&period=60`;
    const { root } = await open({ uri, seconds: 59 });
    assert.equal(codeOf(root), `${reference({ secret: RFC_SECRET, digits: 8, period: 60 }, 59).slice(0, 4)} ${reference({ secret: RFC_SECRET, digits: 8, period: 60 }, 59).slice(4)}`);
    assert.equal(leftOf(root), 'vault.item.totp_left {"seconds":1}');
  });
});

test("only_the_code_is_a_live_region_and_the_countdown_is_plain_text", async () => {
  await withDom(async () => {
    const { root } = await open();
    const live = [...walk(root)].filter((n) => n.getAttribute?.("aria-live") !== null && n.getAttribute?.("aria-live") !== undefined);
    assert.equal(live.length, 1, "one live region on the page");
    assert.equal(live[0].getAttribute("data-role"), "totp-code");
    assert.equal(live[0].getAttribute("aria-live"), "polite");
    assert.equal(live[0].getAttribute("aria-atomic"), "true");
    assert.equal(find(root, "totp-left").getAttribute("aria-live"), null);
    assert.equal(find(root, "totp-left").getAttribute("role"), null);
    // Copy names what it copies, as the other buttons of the page do.
    assert.equal(find(root, "copy", "totp").getAttribute("aria-label"), 'vault.item.copy_label {"label":"vault.item.totp_label"}');
    assert.equal(find(root, "copy", "totp").tagName, "button");
  });
});

test("copy_clears_the_clipboard_after_30_seconds", async () => {
  mock.timers.enable({ apis: ["setTimeout"] });
  try {
    await withDom(async () => {
      const { root, written, clipboard, client } = await open({ seconds: 59 });
      await click(find(root, "copy", "totp"));
      // The code is the plain digits, made for this moment, not the grouped text of the page.
      assert.deepEqual(written, ["287082"]);
      assert.equal(client.calls.filter((c) => c[0] === "totp_code").length, 2, "a fresh code for the click");
      assert.ok(textOf(root).includes("vault.item.copied_secret"), "the text says it is cleared");
      const helper = secretClipboardFor(clipboard);
      assert.equal(helper.pending(), true);
      mock.timers.tick(29_999);
      await settle();
      assert.deepEqual(written, ["287082"], "not yet");
      mock.timers.tick(1);
      await settle();
      assert.deepEqual(written, ["287082", ""], "the clipboard is emptied at 30 seconds");
      assert.equal(helper.pending(), false);
    });
  } finally {
    mock.timers.reset();
  }
});

test("a_lock_and_leaving_the_page_stop_the_code_and_take_it_off_the_page", async () => {
  await withDom(async () => {
    const scope = createWipeScope();
    const { root, client, clock } = await open({ scope });
    assert.ok(codeOf(root) !== "");
    const asked = client.calls.length;
    scope.run();
    await settle();
    assert.equal(textOf(root).trim(), "", "the page is empty");
    assert.equal(clock.pending, 0, "no timer is left");
    clock.advance(120_000);
    await settle();
    assert.equal(client.calls.length, asked, "nothing is asked for any more");
  });
});

test("an_item_without_a_one_time_password_has_no_card_and_no_note", async () => {
  await withDom(async () => {
    const { root, client, clock } = await open({ view: { has_totp: false } });
    assert.deepEqual(all(root, "item-card").map((c) => c.getAttribute("data-card")), ["login"]);
    assert.equal(find(root, "totp-note"), null);
    assert.equal(client.calls.some((c) => c[0] === "totp_code"), false);
    assert.equal(clock.pending, 0);
  });
});

test("a_code_that_cannot_be_made_shows_one_plain_line_and_stops", async () => {
  await withDom(async () => {
    const { root, clock, client } = await open({ failCode: true });
    assert.equal(codeOf(root), "••• •••");
    assert.equal(leftOf(root), "vault.item.totp_error");
    assert.equal(find(root, "totp-left").getAttribute("data-state"), "error");
    assert.equal(clock.pending, 0);
    const asked = client.calls.length;
    clock.advance(60_000);
    await settle();
    assert.equal(client.calls.length, asked);
  });
});

test("the_secret_is_never_on_the_item_page", async () => {
  await withDom(async () => {
    const { root, clock } = await open();
    clock.advance(31_000);
    await settle();
    const page = everything(root);
    for (const secret of [RFC_SECRET, RFC_URI, "otpauth"]) assert.ok(!page.includes(secret), `the page holds ${secret}`);
  });
});

test("a_page_that_is_never_put_on_the_screen_stops_asking_after_a_while", async () => {
  await withDom(async () => {
    const engine = fakeEngine({ items: [ENTRY], views: { [ID]: VIEW }, secrets: { [ID]: ["ada", "pw-SECRET-1"] } });
    const client = fakeTotpClient(engine, { uris: { [ID]: RFC_URI } });
    const clock = fakeClock(59_000);
    const root = await itemView({ engine, sync: engine, client, id: ID, t, clock });
    root.isConnected = false; // built, and the route was replaced before it was mounted
    await settle();
    for (let i = 0; i < 100; i += 1) {
      clock.advance(1_000); // a code is made again at each end of a period, which takes a turn of the event loop
      await settle(3);
    }
    assert.equal(clock.pending, 0, "the ticker ended");
    const asked = client.calls.length;
    clock.advance(200_000);
    await settle();
    assert.equal(client.calls.length, asked);
    assert.ok(asked <= 8, `only a few codes were made for a page nobody saw (${asked} calls)`);
  });
});

test("a_screen_that_is_off_the_page_stops_asking_at_its_next_tick", async () => {
  await withDom(async () => {
    const { root, clock, client } = await open();
    // The page was on the screen and has been taken out of it: the next tick ends the ticking.
    root.isConnected = true;
    clock.advance(1_010);
    await settle();
    root.isConnected = false;
    clock.advance(1_000);
    await settle();
    assert.equal(clock.pending, 0);
    const asked = client.calls.length;
    clock.advance(60_000);
    await settle();
    assert.equal(client.calls.length, asked);
  });
});
