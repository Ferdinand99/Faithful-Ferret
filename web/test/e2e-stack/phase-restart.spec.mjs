// Restart, the browser half: after the host script has restarted the server
// container, the account and its data are still there and the sign-in works.
// Run only by scripts/lanbox-ferret-e2e-gate.sh (FERRET_E2E_PHASE=restart), with
// the state of the main run in FERRET_E2E_STATE.
import { adopt, expect, freshContext, leave, previousState, rowsNamed, secrets, signInOn, test, vaultUrl } from "./support.mjs";

test.skip(process.env.FERRET_E2E_PHASE !== "restart", "run by the gate script, after the container was restarted");

test("restart_container_keeps_data", async ({ browser }) => {
  test.setTimeout(300_000);
  const state = previousState();
  adopt(state);
  const context = await freshContext(browser);
  const page = await context.newPage();
  await signInOn(page);
  // The items the main run left are there (this device had never seen them).
  await expect(rowsNamed(page, `Still-in-${state.itemTitle}`)).toHaveCount(1, { timeout: 15_000 });
  expect((await context.request.get(`${vaultUrl}/api/auth/session`)).status()).toBe(200);
  expect(secrets.email).toBe(state.email);
  // The gate script requires this marker: Playwright exits 0 when a file is skipped.
  leave("restart", { ok: true });
  await context.close();
});
