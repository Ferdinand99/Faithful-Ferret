// Signing in with a passkey of Ferret at both fixture relying parties (the `passkeys` feature, run by
// `scripts/lanbox-ext.sh e2e --passkey-rp` with the fixture container up): the signed-in extension against the end-to-end stack,
// and the fixture container's two relying parties (webauthn-rs and SimpleWebAuthn) on rp-a.test.
//
// The passkey is the test's own: the page makes a P-256 key, registers it at the relying party with an attestation of the kind
// "none" (as Ferret's own would be), and the key goes into a new item of the vault through the core's import (the test build's
// `item_import_probe`), so that this spec does not depend on making a passkey in Ferret. Then the page calls `get` after a real
// click: the chooser window lists the passkey from the vault, the person clicks it, and
//   - `userVerification: "required"` with no recent unlock: the window asks the person to verify (at the first relying party with
//     a sentinel PIN, at the second with the "recent unlock" setting off and the master password, which signs in to the server),
//     the core signs with UV, and the relying party sees UV;
//   - `discouraged`: the click only, and the relying party sees no UV;
//   - `required` again within five minutes of that verification: the click only, with UV.
// The relying party checks the signature, the RP ID hash, the origin, the flags (BE and BS as registered) and the counter. At the
// end no file of the browser's profile holds the sentinel PIN (the run also scans the stack's logs for it).
import assert from "node:assert/strict";
import { after, test } from "node:test";
import { KEEP_BACKGROUND, SLOW, extensionSignIn, webVaultAccount } from "./e2e.mjs";
import { revokeLeftDevices } from "./adversary.mjs";
import { TEST_ADDON_ID, channels, launch, openBridge, stopFixtures } from "./harness.mjs";
import { chooserHandle, core, grantHttps, pressInWindow, readWindow, registerTestKey } from "./passkeyFerret.mjs";
import { SENTINEL_PREFIX, scanFolder, setPin } from "./unlock.mjs";

after(() => stopFixtures());

const PREFS = Object.freeze({ ...KEEP_BACKGROUND });
const RP = "https://rp-a.test";
const RP_ID = "rp-a.test";
const LIBS = Object.freeze(["rs", "swa"]);

/**
 * A get at the relying party `lib` from a real click: the page's own ceremony (auth/start, `navigator.credentials.get`,
 * auth/finish). Returns the chooser window's handle.
 * @param {import("./driver.mjs").Session} session @param {{ lib: string, sid: string, uv: string }} o
 */
async function startGet(session, { lib, sid, uv }) {
  const run = `xp-${Math.random().toString(16).slice(2, 10)}`;
  const spec = { run, sid, lib, client: "manual", steps: ["get"], get: { userVerification: uv, allow: "all" } };
  await session.navigate(`${RP}/ceremony.html?spec=${Buffer.from(JSON.stringify(spec), "utf8").toString("base64url")}`);
  await session.waitFor(() => session.content(() => document.documentElement.dataset.ready === "1"), 20_000, "the ceremony page");
  const known = new Set(await session.windowHandles());
  const [go] = await session.findAll("#go");
  assert.ok(go, "the page's button");
  await session.click(go);
  return chooserHandle(session, known);
}

/** What the page's ceremony ended with. @param {import("./driver.mjs").Session} session @param {string} pageTab */
async function outcome(session, pageTab) {
  await session.switchTo(pageTab);
  await session.waitFor(() => session.content(() => ["ok", "failed"].includes(document.getElementById("result")?.dataset.state ?? "")), 45_000, "the ceremony's end");
  return session.content(() => /** @type {any} */ (window).__result);
}

test("get_on_both_fixtures_verifies_with_uv_and_without", async () => {
  assert.ok(process.env.FERRET_PASSKEY_CA_PEM, "FERRET_PASSKEY_CA_PEM is not set (run through scripts/lanbox-ext.sh e2e --passkey-rp)");
  for (const channel of channels()) {
    const session = await launch({ channel, prefs: PREFS });
    try {
      await session.waitFor(() => session.addonInfo(TEST_ADDON_ID), 30_000, "the add-on");
      const account = await webVaultAccount(session, channel);
      await revokeLeftDevices(session);
      const bridgeTab = await session.newTab();
      await session.switchTo(bridgeTab);
      const signed = await extensionSignIn(session, account);
      assert.equal(signed.ok, true, `${channel}: ${signed.text}`);
      const bridge = await openBridge(session);
      await grantHttps(session);
      await bridge.invoke("storage.local.set", { use_passkeys: true });
      await core(session, "passkey_reconcile");
      // A PIN to verify with: a sentinel that must reach the background and the core and nothing else.
      const sentinel = `${SENTINEL_PREFIX}${channel}-${Math.random().toString(16).slice(2, 8)}`;
      await setPin(session, account, sentinel, "session");
      const pageTab = await session.newTab();

      for (const [n, lib] of LIBS.entries()) {
        // The passkey: registered at the relying party by the page, then put into a new item of the vault.
        await session.switchTo(pageTab);
        await session.navigate(`${RP}/ceremony.html`);
        await session.waitFor(() => session.content(() => document.documentElement.dataset.ready === "1"), 20_000, "the relying party's page");
        if (n === 0) {
          // The static methods in real Firefox, where the bridge is connected: Ferret can verify, and conditional get is there.
          const statics = /** @type {any} */ (await session.content(async () => ({
            uvpaa: await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable(),
            conditional: await PublicKeyCredential.isConditionalMediationAvailable(),
            capabilities: typeof PublicKeyCredential.getClientCapabilities === "function" ? await PublicKeyCredential.getClientCapabilities() : null,
          })));
          assert.equal(statics.uvpaa, true, `${channel}: isUserVerifyingPlatformAuthenticatorAvailable`);
          assert.equal(statics.conditional, true, `${channel}: isConditionalMediationAvailable`);
          if (statics.capabilities !== null) {
            assert.equal(statics.capabilities.userVerifyingPlatformAuthenticator, true, channel);
            assert.equal(statics.capabilities["extension:prf"], true, channel);
          }
        }
        const key = /** @type {any} */ (await registerTestKey(session, lib, RP_ID, `anna-${lib}`));
        assert.equal(key.ok, true, `${channel} ${lib}: the registration of the test key: ${JSON.stringify(key)}`);
        await session.switchTo(bridgeTab);
        const planted = await core(session, "item_import_probe", { name: `Test ${lib}`, rp_id: RP_ID, user_name: `anna-${lib}`, cred_id: key.cred_id, user_handle: key.user_handle, key_pkcs8: key.key_pkcs8 });
        assert.match(planted.item_id, /^[0-9a-f]{32}$/);

        // 1. `required`, nothing recent (the sign-in is no unlock; in the second round the setting is off): the window asks to
        // verify first.
        if (n === 1) await bridge.invoke("storage.local.set", { passkey_recent_unlock: false });
        await session.switchTo(pageTab);
        let handle = await startGet(session, { lib, sid: key.sid, uv: "required" });
        let shown = await readWindow(session);
        assert.equal(shown.kind, "get", `${channel} ${lib}`);
        assert.equal(shown.candidates.length, 1, `${channel} ${lib}: the passkey from the vault (${JSON.stringify(shown)})`);
        assert.match(shown.candidates[0], new RegExp(`anna-${lib}`));
        await pressInWindow(session, "passkey-candidate");
        await session.waitFor(async () => (await session.findAll('[data-role="passkey-verify-step"]')).length === 1, 15_000, "the verification step");
        if (n === 0) {
          // The PIN, checked like an unlock (an attempt of the five), in a worker of its own.
          const [field] = await session.findAll('[data-role="passkey-verify-pin"]');
          await session.type(field, sentinel);
          await pressInWindow(session, "passkey-verify-pin-submit");
        } else {
          assert.equal((await session.findAll('[data-role="passkey-verify-signs-in"]')).length, 1, "the master password says it signs in");
          const [field] = await session.findAll('[data-role="passkey-verify-password"]');
          await session.type(field, account.password);
          await pressInWindow(session, "passkey-verify-password-submit");
        }
        await session.waitFor(async () => !(await session.windowHandles()).includes(handle), 30_000, "the window closed");
        let result = await outcome(session, pageTab);
        assert.equal(result.ok, true, `${channel} ${lib}: required: ${JSON.stringify(result)}`);
        assert.equal(result.steps[0].server.flags.uv, true, `${channel} ${lib}: the relying party saw UV`);
        assert.equal(result.steps[0].credential.attachment, "platform");

        // 2. `discouraged`: the click only, and no UV.
        handle = await startGet(session, { lib, sid: key.sid, uv: "discouraged" });
        shown = await readWindow(session);
        assert.equal(shown.candidates.length, 1);
        await pressInWindow(session, "passkey-candidate");
        await session.waitFor(async () => !(await session.windowHandles()).includes(handle), 30_000, "the window closed");
        result = await outcome(session, pageTab);
        assert.equal(result.ok, true, `${channel} ${lib}: discouraged: ${JSON.stringify(result)}`);
        assert.equal(result.steps[0].server.flags.uv, false, `${channel} ${lib}: no UV without verification`);

        // 3. `required` again, within five minutes of the verification (and the setting on): the click is enough, with UV.
        if (n === 1) {
          await session.switchTo(bridgeTab);
          await bridge.invoke("storage.local.set", { passkey_recent_unlock: true });
          await session.switchTo(pageTab);
        }
        handle = await startGet(session, { lib, sid: key.sid, uv: "required" });
        shown = await readWindow(session);
        assert.equal(shown.recent, true, `${channel} ${lib}: the window says one click is enough`);
        await pressInWindow(session, "passkey-candidate");
        await session.waitFor(async () => !(await session.windowHandles()).includes(handle), 30_000, "the window closed");
        result = await outcome(session, pageTab);
        assert.equal(result.ok, true, `${channel} ${lib}: recent: ${JSON.stringify(result)}`);
        assert.equal(result.steps[0].server.flags.uv, true);
      }
      // The PIN was used (the relying party saw UV after it), and no file of the profile holds it.
      const leaked = scanFolder(session.profileDir, [sentinel, sentinel.normalize("NFKD")]);
      assert.deepEqual(leaked, [], `${channel}: the sentinel PIN is in a file of the profile`);
    } finally {
      await session.quit();
    }
  }
}, { timeout: 6 * SLOW });
