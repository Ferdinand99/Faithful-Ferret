// Scenario 13, the browser half. The server clock can only be moved from the
// host (scripts/lanbox-ferret-test.sh e2e-clock), so this scenario is driven by
// scripts/lanbox-ferret-e2e-gate.sh in steps:
//
//   FERRET_E2E_PHASE=limits-setup  make the account (on a fresh stack, clock offset 0)
//   FERRET_E2E_PHASE=limits-signin sign in twice, hand both over to the admin
//                                  origin, and leave the cookies of the four sessions
//
// and then the host script moves the clock forward and asks `probe.mjs` about
// the sessions at each step. The clock is never set back: a session made at
// offset 0 is the only kind the kit accepts, and the limits are checked at
// Ferret's own guard (`GET /api/auth/session` on each origin).
import { adminUrl, adopt, confirmSheet, expect, fillSetup, freshContext, leave, previousState, readSheet, secrets, setupToken, signInHere, SLOW, test, vaultUrl } from "./support.mjs";

const phase = process.env.FERRET_E2E_PHASE;

test.describe("limits", () => {
  test.skip(phase !== "limits-setup" && phase !== "limits-signin", "run by the gate script");

  test("limits_setup_makes_the_account", async ({ page }) => {
    test.skip(phase !== "limits-setup");
    test.setTimeout(300_000);
    await page.goto(`${adminUrl}/setup?token=${setupToken}`);
    await expect(page.locator('[data-role="setup-page"]')).toBeVisible({ timeout: 20_000 });
    await fillSetup(page, { token: null });
    const keys = await readSheet(page);
    secrets.recoveryKey = keys.recoveryKey;
    secrets.secretKey = keys.secretKey;
    await confirmSheet(page, keys);
    leave("state", { ...secrets });
  });

  test("limits_sign_in_four_sessions", async ({ browser }) => {
    test.skip(phase !== "limits-signin");
    test.setTimeout(600_000);
    adopt(previousState());
    const sessions = {};
    // Two browsers: "idle" is never used again after this; "kept" is used at every step.
    for (const name of ["idle", "kept"]) {
      const context = await freshContext(browser);
      const page = await context.newPage();
      await page.goto(`${adminUrl}/settings/general`);
      await expect(page.locator('[data-role="credentials"]')).toBeVisible({ timeout: 20_000 });
      await signInHere(page, { expectList: false });
      await page.waitForURL((url) => url.origin === adminUrl && !url.pathname.startsWith("/auth/handoff"), { timeout: SLOW });
      const header = async (origin) =>
        (await context.cookies(origin)).filter((c) => c.name.startsWith("__Host-ferret_sid") || c.name === "__Host-ferret_session").map((c) => `${c.name}=${c.value}`).join("; ");
      sessions[name] = { vault: await header(vaultUrl), admin: await header(adminUrl) };
      expect(sessions[name].vault).toContain("__Host-ferret_sid=");
      expect(sessions[name].admin).toContain("__Host-ferret_sid=");
      await context.close();
    }
    leave("sessions", sessions);
  });
});
