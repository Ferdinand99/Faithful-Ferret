// A malicious server. The proxy in front of the real server (web/test/e2e-stack/evil) lies about what it holds, in each of
// the ways the design names, and the vault says so out loud and keeps everything it has. Every scenario takes a
// screenshot of the warning and checks that nothing local is gone. Browser A is caught up and sees the lie when browser B
// changes something; a new device is made where the lie must be caught by the checkpoint.
import {
  createItem, editItem, evil, evilNow, evilSession, expect, feedOf, itemIdOf, newDevice, noViolations, openItem, openList,
  putCheckpointOnTop, rowsNamed, shot, synced, syncBanner, test, useAccount, warningBanner,
} from "./support.mjs";

const SEEN = 20_000;
const WARNED = 60_000;

test.describe.configure({ mode: "serial" });
noViolations();

/** @typedef {{ context: import("@playwright/test").BrowserContext, page: import("@playwright/test").Page }} Device */
/** @type {Device} */
let a;
/** @type {Device} */
let b;

test.beforeAll(async ({ browser }) => {
  test.setTimeout(400_000);
  useAccount();
  a = await newDevice(browser);
  b = await newDevice(browser);
});

test.afterAll(async () => {
  await evil("honest").catch(() => {});
  await a?.context.close();
  await b?.context.close();
});

test.afterEach(async () => {
  await evil("honest");
});

// What an earlier scenario left on the screens that can be hidden (a notice), so that each one shows only its own.
test.beforeEach(async () => {
  if (!a || !b) return;
  for (const { page } of [a, b]) {
    const dismiss = page.locator('[data-role="banner-dismiss"]');
    for (let left = 10; left > 0 && (await dismiss.count()) > 0; left -= 1) await dismiss.first().click({ timeout: 5_000 });
  }
});

/**
 * A makes an item, and both browsers show it. Returns its id.
 * @param {string} name
 * @param {{ username?: string, notes?: string }} [fields]
 */
async function make(name, fields = {}) {
  await createItem(a.page, { name, username: fields.username ?? "evil-user", notes: fields.notes });
  await openList(b.page);
  await expect(rowsNamed(b.page, name)).toHaveCount(1, { timeout: SEEN });
  await openList(a.page);
  await synced(a.page);
  return itemIdOf(a.page, name);
}

/**
 * Every sync banner except the notice that an item was hidden: that one stays on the device that met it (it is saved with
 * the record of what the server showed) and comes back after it has been hidden.
 * @param {import("@playwright/test").Page} page
 */
const warned = (page) => page.locator('[data-role="sync-banner"]:not([data-code="server_hid_item"])');

/** The names on both lists, which must all still be there. @param {string[]} names */
async function nothingIsGone(...names) {
  await openList(a.page);
  for (const name of names) await expect(rowsNamed(a.page, name), `${name} is still in the list`).toHaveCount(1);
}

/** The banner's way on after the server is honest again. @param {import("@playwright/test").Page} page @param {string} code */
async function tryAgain(page, code) {
  await syncBanner(page, code).locator('[data-role="banner-action"][data-action="try_again"]').click();
  await expect(syncBanner(page, code)).toHaveCount(0, { timeout: WARNED });
}

test("swap_blobs_gives_row_damaged_and_the_last_good_version_is_kept", async () => {
  test.setTimeout(400_000);
  const x = `Swap-x-${Date.now()}`;
  const y = `Swap-y-${Date.now()}`;
  const xid = await make(x);
  const yid = await make(y);
  await evil("swap_blobs", { a: xid, b: yid });
  // B changes x; the row that A is sent for x carries y's body.
  await editItem(b.page, x, { name: `${x}-b`, username: "changed-by-b" });
  await expect(warningBanner(a.page, "row_damaged")).toBeVisible({ timeout: WARNED });
  await shot(a.page, "14-evil-swap-blobs");
  await nothingIsGone(x, y);
  await openItem(a.page, x);
  await expect(a.page.locator('[data-role="item"]')).toContainText("evil-user");
});

test("replay_old_gives_rev_lower_than_local_and_a_new_device_sees_an_older_state", async () => {
  test.setTimeout(400_000);
  const r = `Replay-${Date.now()}`;
  const id = await make(r);
  await editItem(a.page, r, { name: `${r}-2`, username: "second-version" });
  await openList(b.page);
  await expect(rowsNamed(b.page, `${r}-2`)).toHaveCount(1, { timeout: SEEN });
  await synced(a.page);
  await evil("replay_old", { id });
  await editItem(b.page, `${r}-2`, { name: `${r}-3`, username: "third-version" });
  // The row A is sent is the first version, older than what A has.
  await expect(warningBanner(a.page, "rev_lower_than_local")).toBeVisible({ timeout: WARNED });
  await shot(a.page, "14-evil-replay-old");
  await nothingIsGone(`${r}-2`);
  await openItem(a.page, `${r}-2`);
  await expect(a.page.locator('[data-role="item"]')).toContainText("second-version");
});

test("hide_with_gone_gives_server_hid_item_and_the_item_is_kept_and_uploaded_again", async () => {
  test.setTimeout(400_000);
  const h = `Hidden-${Date.now()}`;
  const p = `Poke-hide-${Date.now()}`;
  const hid = await make(h, { username: "hidden-user" });
  await make(p);
  const top = (await feedOf(a.context)).latest_seq;
  // The server forgets that it ever held the item, and says that A's place in the feed is too old: B's change moves the top one past it, so one read of the whole list brings A level.
  await evil("gone", { min_valid_since: top + 1, hide: hid });
  await editItem(b.page, p, { name: `${p}-b` });
  await expect(syncBanner(a.page, "server_hid_item")).toBeVisible({ timeout: WARNED });
  await shot(a.page, "14-evil-hide-and-gone");
  await nothingIsGone(h);
  await openItem(a.page, h);
  await expect(a.page.locator('[data-role="item"]')).toContainText("hidden-user");
  await evil("honest");
  // The real server held it all along, so it still holds it, once.
  expect((await feedOf(a.context)).changes.filter((c) => c.id === hid)).toHaveLength(1);
});

test("gone_makes_a_full_reconciliation_and_everything_is_kept", async () => {
  test.setTimeout(400_000);
  const g = `Gone-${Date.now()}`;
  await make(g);
  const top = (await feedOf(a.context)).latest_seq;
  const listing = a.page.waitForRequest((r) => r.url().includes("/api/sync/items?"), { timeout: WARNED });
  // A's place is just below what the server still can answer from: one read of the whole list, then it is caught up.
  await evil("gone", { min_valid_since: top + 1 });
  await editItem(b.page, g, { name: `${g}-b`, username: "after-gone" });
  await listing;
  await openList(a.page);
  await expect(rowsNamed(a.page, `${g}-b`)).toHaveCount(1, { timeout: WARNED });
  await shot(a.page, "14-evil-gone");
  await expect(warned(a.page)).toHaveCount(0);
  await synced(a.page);
});

test("fake_tombstone_puts_the_item_in_quarantine_and_nothing_is_deleted", async () => {
  test.setTimeout(400_000);
  const t = `Tombstone-${Date.now()}`;
  const id = await make(t, { username: "tomb-user" });
  await evil("fake_tombstone", { id });
  await editItem(b.page, t, { name: `${t}-b`, username: "changed-by-b" });
  await expect(warningBanner(a.page, "tombstone_unverified")).toBeVisible({ timeout: WARNED });
  await shot(a.page, "14-evil-fake-tombstone");
  await nothingIsGone(t);
  await openItem(a.page, t);
  await expect(a.page.locator('[data-role="item"]')).toContainText("tomb-user");
  // Not in the trash: a deletion that could not be checked is not one.
  await a.page.locator('[data-role="nav-items"]').click();
  await a.page.locator('[data-role="trash-link"]').click();
  await expect(a.page.locator('[data-role="trash-item"]', { hasText: t })).toHaveCount(0);
});

test("fork_is_not_detected_in_v1_and_nothing_is_lost", async ({ browser }) => {
  test.setTimeout(600_000);
  const e = `Fork-existing-${Date.now()}`;
  await make(e);
  const f1 = `Fork-from-b-${Date.now()}`;
  const f2 = `Fork-from-a-${Date.now()}`;
  // A is shown a frozen state from now on. Its own writes still reach the real server.
  await evil("fork", { sid: (await evilSession(a.context)).slice(0, 24) });
  await createItem(b.page, { name: f1 });
  await editItem(b.page, e, { name: `${e}-b`, username: "changed-by-b" });
  await createItem(a.page, { name: f2 });
  await synced(a.page);
  await openList(b.page);
  await expect(rowsNamed(b.page, f2)).toHaveCount(1, { timeout: SEEN });
  await openList(a.page);
  // A does not see what B did and is not warned: a fork is not detected in the first version.
  await a.page.waitForTimeout(8_000);
  await expect(rowsNamed(a.page, f1)).toHaveCount(0);
  await expect(rowsNamed(a.page, e)).toHaveCount(1);
  await expect(warned(a.page)).toHaveCount(0);
  await expect(a.page.locator('[data-role="banner"]')).toHaveCount(0);
  await shot(a.page, "14-evil-fork");
  await nothingIsGone(e, f2);

  // Nothing is lost: everything is on the real server, so a device that is not forked has all of it ...
  await evil("honest");
  await openList(b.page);
  await expect(rowsNamed(b.page, f1)).toHaveCount(1);
  await expect(rowsNamed(b.page, f2)).toHaveCount(1);
  await expect(rowsNamed(b.page, `${e}-b`)).toHaveCount(1);
  const fresh = await newDevice(browser);
  try {
    for (const name of [f1, f2, `${e}-b`]) await expect(rowsNamed(fresh.page, name)).toHaveCount(1, { timeout: SEEN });
  } finally {
    await fresh.context.close();
  }
  // ... and when A writes over the item that B changed meanwhile, the two writes conflict as they always do.
  await editItem(a.page, e, { name: `${e}-a`, username: "changed-by-a" }, { waitForName: false });
  await expect(b.page.locator('[data-role="conflict-note"]')).toHaveCount(0);
  await openList(a.page);
  await expect(a.page.locator('[data-role="conflict-note"]')).toBeVisible({ timeout: WARNED });
  await shot(a.page, "14-evil-fork-conflict-as-usual");
  // Settled with the server's version, so that A is clean for what follows.
  await a.page.locator('[data-role="first-conflict"]').click();
  await a.page.locator('[data-role="keep-theirs"]').click();
  await a.page.locator('[data-role="dialog-confirm"]').click();
  await expect(a.page.locator('[data-role="item"] h1')).toBeVisible({ timeout: 30_000 });
  await openList(a.page);
  await expect(a.page.locator('[data-role="conflict-note"]')).toHaveCount(0);
});

test("rollback_stops_sync_with_no_offer_to_accept_and_nothing_is_lost", async () => {
  test.setTimeout(400_000);
  const first = `Rollback-before-${Date.now()}`;
  await make(first);
  await a.page.waitForTimeout(1_500);
  const at = await evilNow();
  const later = `Rollback-after-${Date.now()}`;
  await make(later);
  // The server shows the state of a moment ago, with its restore number unchanged.
  await evil("rollback", { at });
  await editItem(b.page, first, { name: `${first}-b` });
  await expect(syncBanner(a.page, "rollback_suspected")).toBeVisible({ timeout: WARNED });
  await expect(a.page.locator('[data-role="sync-status"]')).toHaveAttribute("data-state", "halted");
  // It is a rollback, not a restore: the page offers to try again or to forget the server, and not to accept.
  await expect(syncBanner(a.page, "rollback_suspected").locator('[data-action="see_what_happened"]')).toHaveCount(0);
  await expect(syncBanner(a.page, "rollback_suspected").locator('[data-action="forget"]')).toBeVisible();
  await shot(a.page, "14-evil-rollback");
  await nothingIsGone(first, later);
  // The server tells the truth again, and the way on is the button.
  await evil("honest");
  await tryAgain(a.page, "rollback_suspected");
  if ((await syncBanner(b.page, "rollback_suspected").count()) > 0) await tryAgain(b.page, "rollback_suspected");
  await expect(rowsNamed(a.page, `${first}-b`)).toHaveCount(1, { timeout: WARNED });
});

test("seq_lie_lower_gives_rollback_suspected_and_nothing_is_lost", async () => {
  test.setTimeout(400_000);
  const s = `Seq-${Date.now()}`;
  await make(s);
  await evil("seq_lie", { latest_seq: 1 });
  await editItem(b.page, s, { name: `${s}-b` });
  await expect(syncBanner(a.page, "rollback_suspected")).toBeVisible({ timeout: WARNED });
  await shot(a.page, "14-evil-seq-lie-lower");
  await nothingIsGone(s);
  await evil("honest");
  await tryAgain(a.page, "rollback_suspected");
  if ((await syncBanner(b.page, "rollback_suspected").count()) > 0) await tryAgain(b.page, "rollback_suspected");
  await expect(rowsNamed(a.page, `${s}-b`)).toHaveCount(1, { timeout: WARNED });
});

test.describe("on a new device the checkpoint catches the lies", () => {
  test.beforeAll(async ({ browser }) => {
    test.setTimeout(400_000);
    // Something that is edited twice and something that is not, in a checkpoint at the top of the feed.
    const r = `Check-replay-${Date.now()}`;
    const h = `Check-hide-${Date.now()}`;
    await make(r);
    await editItem(a.page, r, { name: `${r}-2`, username: "second" });
    await make(h);
    await synced(a.page);
    await openList(b.page);
    await expect(rowsNamed(b.page, `${r}-2`)).toHaveCount(1, { timeout: SEEN });
    await putCheckpointOnTop(browser);
    state.r = { name: `${r}-2`, id: await itemIdOf(a.page, `${r}-2`) };
    state.h = { name: h, id: await itemIdOf(a.page, h) };
  });

  /** @type {{ r?: { name: string, id: string }, h?: { name: string, id: string } }} */
  const state = {};

  test("replay_old_on_a_new_device_gives_server_shows_older_state", async ({ browser }) => {
    test.setTimeout(400_000);
    await evil("replay_old", { id: state.r?.id });
    const device = await newDevice(browser);
    try {
      await expect(syncBanner(device.page, "server_shows_older_state")).toBeVisible({ timeout: WARNED });
      await shot(device.page, "14-evil-replay-old-new-device");
    } finally {
      await device.context.close();
    }
  });

  test("hide_on_a_new_device_gives_server_shows_older_state", async ({ browser }) => {
    test.setTimeout(400_000);
    await evil("hide", { id: state.h?.id });
    const device = await newDevice(browser);
    try {
      await expect(syncBanner(device.page, "server_shows_older_state")).toBeVisible({ timeout: WARNED });
      await expect(rowsNamed(device.page, state.h?.name ?? "")).toHaveCount(0);
      await shot(device.page, "14-evil-hide-new-device");
    } finally {
      await device.context.close();
    }
  });

  for (const field of ["mac", "entries"]) {
    test(`forge_checkpoint_${field}_gives_checkpoint_forged_and_the_items_are_all_there`, async ({ browser }) => {
      test.setTimeout(400_000);
      await evil("forge_checkpoint", { field });
      const device = await newDevice(browser);
      try {
        await expect(syncBanner(device.page, "checkpoint_forged")).toBeVisible({ timeout: WARNED });
        // The rows are the real ones: the lie is in the checkpoint only, and the items show.
        await expect(rowsNamed(device.page, state.h?.name ?? "")).toHaveCount(1, { timeout: SEEN });
        await expect(device.page.locator('[data-role="sync-status"]')).not.toHaveAttribute("data-state", "halted");
        await shot(device.page, `14-evil-forge-${field}`);
      } finally {
        await device.context.close();
      }
    });
  }

  test("drop_checkpoint_head_gives_no_warning", async ({ browser }) => {
    test.setTimeout(400_000);
    await evil("drop_checkpoint_head");
    const device = await newDevice(browser);
    try {
      await expect(rowsNamed(device.page, state.h?.name ?? "")).toHaveCount(1, { timeout: SEEN });
      await synced(device.page);
      await device.page.waitForTimeout(3_000);
      await expect(warned(device.page)).toHaveCount(0);
      await expect(device.page.locator('[data-role="banner"]')).toHaveCount(0);
      await shot(device.page, "14-evil-drop-checkpoint-head");
    } finally {
      await device.context.close();
    }
  });
});

test("seq_lie_higher_is_the_known_gap_and_nothing_is_lost", async ({ browser }) => {
  test.setTimeout(600_000);
  // Two devices of their own: the lie is a mark that this scenario leaves on them.
  const [oldA, oldB] = [a, b];
  a = await newDevice(browser);
  b = await newDevice(browser);
  try {
    const s = `Seq-high-${Date.now()}`;
    await make(s);
    const top = (await feedOf(a.context)).latest_seq;
    await evil("seq_lie", { latest_seq: top + 1_000_000 });
    await editItem(b.page, s, { name: `${s}-b`, username: "after-the-lie" });
    // The change comes through and nothing is said or stopped: a number that is too high is not a sign of a rollback, and
    // the number is not signed (the known gap).
    await expect(rowsNamed(a.page, `${s}-b`)).toHaveCount(1, { timeout: WARNED });
    await expect(warned(a.page)).toHaveCount(0);
    await expect(a.page.locator('[data-role="sync-status"]')).not.toHaveAttribute("data-state", "halted");
    await shot(a.page, "14-evil-seq-lie-higher");
    await nothingIsGone(`${s}-b`);
    await openItem(a.page, `${s}-b`);
    await expect(a.page.locator('[data-role="item"]')).toContainText("after-the-lie");
    // The number has been taken in. The honest answers after it are lower, and the vault stops, loudly: the safe side of the
    // gap. The way out is the button, or forgetting the server.
    await evil("honest");
    await editItem(b.page, `${s}-b`, { name: `${s}-c`, username: "after-the-honest-answer" });
    await expect(syncBanner(a.page, "rollback_suspected")).toBeVisible({ timeout: WARNED });
    await shot(a.page, "14-evil-seq-lie-higher-then-honest");
    await nothingIsGone(`${s}-b`);
  } finally {
    await a.context.close();
    await b.context.close();
    [a, b] = [oldA, oldB];
  }
});
