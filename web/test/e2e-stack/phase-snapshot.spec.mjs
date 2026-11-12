// Snapshot and restore, the browser half: a write, a snapshot, a second write, a
// restore. After it the server shows the first write only, and a restore epoch
// that is one higher. Run only by scripts/lanbox-ferret-e2e-check.sh (the phases
// snapshot-first, snapshot-second and snapshot-restored), which takes the
// snapshot and puts it back between the phases with
// scripts/lanbox-ferret-test.sh e2e-snapshot and e2e-restore-snapshot, and hands
// the state of one phase to the next in FERRET_E2E_STATE.
import { adopt, createItem, expect, freshContext, leave, previousState, rowsNamed, secrets, setUpAccount, signInOn, test, vaultUrl } from "./support.mjs";

const phase = process.env.FERRET_E2E_PHASE ?? "";
test.skip(!phase.startsWith("snapshot-"), "run by the check script, around e2e-snapshot and e2e-restore-snapshot");

/**
 * The feed of the vault as the server has it now, read with the session of the context.
 * @param {import("@playwright/test").BrowserContext} context
 * @returns {Promise<{ changes: { seq: number }[], latest_seq: number, restore_epoch: number }>}
 */
async function feed(context) {
  const response = await context.request.get(`${vaultUrl}/api/sync/changes?since=0&limit=500`, { headers: { "Ferret-Protocol": "1" } });
  expect(response.status()).toBe(200);
  return response.json();
}

test("snapshot_first_write", async ({ browser }) => {
  test.skip(phase !== "snapshot-first", "another phase");
  test.setTimeout(300_000);
  const context = await freshContext(browser);
  const page = await context.newPage();
  await setUpAccount(page);
  const before = await feed(context);
  await createItem(page, { name: `First-${secrets.itemTitle}` });
  // The write has reached the server when the feed has moved on.
  await expect.poll(async () => (await feed(context)).latest_seq, { timeout: 30_000 }).toBeGreaterThan(before.latest_seq);
  const after = await feed(context);
  leave("state", { ...secrets, snapSeq: after.latest_seq, snapEpoch: after.restore_epoch });
  await context.close();
});

test("snapshot_second_write", async ({ browser }) => {
  test.skip(phase !== "snapshot-second", "another phase");
  test.setTimeout(300_000);
  const state = previousState();
  adopt(state);
  const context = await freshContext(browser);
  const page = await context.newPage();
  await signInOn(page);
  await expect(rowsNamed(page, `First-${state.itemTitle}`)).toHaveCount(1, { timeout: 30_000 });
  await createItem(page, { name: `Second-${state.itemTitle}` });
  await expect.poll(async () => (await feed(context)).latest_seq, { timeout: 30_000 }).toBeGreaterThan(state.snapSeq);
  leave("second", { ok: true });
  await context.close();
});

test("e2e_snapshot_and_restore_raise_restore_epoch", async ({ browser }) => {
  test.skip(phase !== "snapshot-restored", "another phase");
  test.setTimeout(300_000);
  const state = previousState();
  adopt(state);
  const context = await freshContext(browser);
  const page = await context.newPage();
  await signInOn(page);
  // The first write is there, the second is gone with the data that was put back.
  await expect(rowsNamed(page, `First-${state.itemTitle}`)).toHaveCount(1, { timeout: 30_000 });
  await expect(rowsNamed(page, `Second-${state.itemTitle}`)).toHaveCount(0);
  const restored = await feed(context);
  expect(restored.restore_epoch, "the restore epoch is one higher").toBe(state.snapEpoch + 1);
  expect(restored.latest_seq, "the feed ends where the snapshot was taken").toBe(state.snapSeq);
  expect(restored.changes.every((c) => c.seq <= state.snapSeq), "no row is newer than the snapshot").toBe(true);
  // The gate script requires this marker: Playwright exits 0 when a file is skipped.
  leave("restored", { ok: true, epoch: restored.restore_epoch, seq: restored.latest_seq });
  await context.close();
});
