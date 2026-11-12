// The account for the sync scenarios 10 to 16: made through the whole path a first user takes (as 01-setup does), and its
// values left for the phases that follow. Run only by scripts/lanbox-ferret-e2e-gate.sh m2.
import { freshContext, leave, secrets, setUpAccount, test } from "./support.mjs";

test.skip(process.env.FERRET_E2E_PHASE !== "m2-account", "run by the gate script, before the sync scenarios");

test("the_account_for_the_sync_scenarios_is_made", async ({ browser }) => {
  test.setTimeout(300_000);
  const context = await freshContext(browser);
  const page = await context.newPage();
  await setUpAccount(page);
  leave("state", { ...secrets });
  await context.close();
});
