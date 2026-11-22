// The browser half of the drill (scripts/ferret-home.sh drill): an account and one item on a
// stack that is about to be backed up, copied off the machine, wiped and restored from the
// decrypted copy; then signing in again on the restored server. Run only by that script,
// in two phases (drill-first, drill-restored), which hands the state of the first to the second
// in FERRET_E2E_STATE. The data is made up for the run.
import { adopt, createItem, expect, freshContext, leave, previousState, findRows, secrets, setUpAccount, signInOn, test, vaultUrl } from "./support.mjs";

const phase = process.env.FERRET_E2E_PHASE ?? "";
test.skip(!phase.startsWith("drill-"), "run by scripts/ferret-home.sh drill");

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

test("drill_account_and_item", async ({ browser }) => {
  test.skip(phase !== "drill-first", "another phase");
  test.setTimeout(300_000);
  const context = await freshContext(browser);
  const page = await context.newPage();
  await setUpAccount(page);
  const before = await feed(context);
  await createItem(page, { name: `Drill-${secrets.itemTitle}` });
  // The write has reached the server when the feed has moved on.
  await expect.poll(async () => (await feed(context)).latest_seq, { timeout: 30_000 }).toBeGreaterThan(before.latest_seq);
  const after = await feed(context);
  leave("state", { ...secrets, drillSeq: after.latest_seq, drillEpoch: after.restore_epoch });
  await context.close();
});

test("drill_sign_in_on_the_restored_server", async ({ browser }) => {
  test.skip(phase !== "drill-restored", "another phase");
  test.setTimeout(300_000);
  const state = previousState();
  adopt(state);
  const context = await freshContext(browser);
  const page = await context.newPage();
  await signInOn(page);
  // The item of the first phase came back through the encrypted copy.
  await expect((await findRows(page, `Drill-${state.itemTitle}`))).toHaveCount(1, { timeout: 30_000 });
  const restored = await feed(context);
  expect(restored.restore_epoch, "the restore epoch is higher than before").toBeGreaterThan(state.drillEpoch);
  expect(restored.latest_seq, "the feed ends where the backup was taken").toBe(state.drillSeq);
  // The runner of the script requires this marker: Playwright exits 0 when a file is skipped.
  leave("restored", { ok: true, epoch: restored.restore_epoch, seq: restored.latest_seq });
  await context.close();
});
