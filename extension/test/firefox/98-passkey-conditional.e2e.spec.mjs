// A conditional passkey request (the site's autofill UI) answered from Ferret's popup, at both fixture relying parties (the
// `passkeys` feature, run by `scripts/lanbox-ext.sh e2e --passkey-rp` with the fixture container up): the signed-in extension
// against the end-to-end stack, and the fixture container's two relying parties (webauthn-rs and SimpleWebAuthn) on rp-a.test.
//
// The passkey is the test's own, registered at the relying party by the page and put into a new item of the vault through the
// core's import (as in 97-passkey-get). Then:
//   - conditional sign-in: the page starts `get` with `mediation: "conditional"` without any click. No window opens; the popup
//     (about the page's tab) lists the passkey under "Passkeys for rp-a.test"; a click on it is the presence. At the first relying
//     party the page asks for `required` and nothing recent counts, so the popup asks for the PIN (a sentinel) and the relying party
//     sees UV; at the second, `preferred` within five minutes of that verification is one click, with UV. The relying party checks
//     the signature, the RP ID hash, the origin and the flags. The popup's passkey part, in the light and the dark scheme, is saved
//     as a screenshot.
//   - the switch from conditional to modal: the page's conditional get, then a modal get after a real click, with the page aborting
//     the conditional one first and without (then Ferret ends it with AbortError, as Firefox does). The modal one is answered in
//     Ferret's window; the conditional one ends with AbortError either way, and the popup's list is gone.
import assert from "node:assert/strict";
import { after, test } from "node:test";
import { KEEP_BACKGROUND, POPUP_URL, SLOW, extensionSignIn, webVaultAccount } from "./e2e.mjs";
import { revokeLeftDevices, shotPath } from "./adversary.mjs";
import { TEST_ADDON_ID, channels, launch, openBridge, stopFixtures } from "./harness.mjs";
import { chooserHandle, core, grantHttps, pressInWindow, readWindow, registerTestKey } from "./passkeyFerret.mjs";
import { SENTINEL_PREFIX, scanFolder, setPin } from "./unlock.mjs";

after(() => stopFixtures());

const PREFS = Object.freeze({ ...KEEP_BACKGROUND });
const RP = "https://rp-a.test";
const RP_ID = "rp-a.test";
const LIBS = Object.freeze(["rs", "swa"]);
const sleep = (/** @type {number} */ ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * The page's conditional get, in the page's own world and with no click: auth/start, `navigator.credentials.get` with
 * `mediation: "conditional"`, auth/finish with what came back. What it ended with is in `data-cond` of the root.
 * @param {{ lib: string, sid: string, uv: string }} o
 */
function conditionalScript(o) {
  return `(async (o) => {
    const root = document.documentElement;
    const say = (v) => { root.dataset.cond = JSON.stringify(v); };
    const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/, "");
    const from = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
    const post = async (path, body) => (await fetch(path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) })).json();
    try {
      const start = await post("/api/" + o.lib + "/auth/start", { sid: o.sid, rpId: location.hostname, userVerification: o.uv, allow: "none" });
      if (!start.ok) return say({ ok: false, stage: "start", error: String(start.error) });
      const opt = start.options;
      const controller = new AbortController();
      window.__condAbort = () => controller.abort();
      root.dataset.condStarted = "1";
      const cred = await navigator.credentials.get({ mediation: "conditional", signal: controller.signal, publicKey: { challenge: from(opt.challenge), rpId: opt.rpId, userVerification: opt.userVerification, allowCredentials: [] } });
      const r = cred.response;
      const credential = {
        id: cred.id, rawId: b64u(cred.rawId), type: cred.type, authenticatorAttachment: cred.authenticatorAttachment, clientExtensionResults: cred.getClientExtensionResults(),
        response: { clientDataJSON: b64u(r.clientDataJSON), authenticatorData: b64u(r.authenticatorData), signature: b64u(r.signature), userHandle: r.userHandle ? b64u(r.userHandle) : null },
      };
      const finish = await post("/api/" + o.lib + "/auth/finish", { sid: o.sid, credential });
      say({ ok: finish.ok === true, server: finish, attachment: cred.authenticatorAttachment });
    } catch (e) {
      say({ ok: false, name: e && e.name });
    }
  })(${JSON.stringify(o)})`;
}

/** Runs a script in the page's own world. @param {import("./driver.mjs").Session} session @param {string} code */
const inPage = (session, code) =>
  session.content((/** @type {string} */ text) => {
    const script = document.createElement("script");
    script.textContent = text;
    document.body.append(script);
  }, code);

/**
 * The extension's state with the passkey of `lib` in the vault, the page tab on rp-a.test and the popup about it in a window of its
 * own. @param {import("./driver.mjs").Session} session
 */
async function setUp(session, channel) {
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
  const pageTab = await session.newTab();
  /** @type {Record<string, { sid: string }>} */
  const keys = {};
  for (const lib of LIBS) {
    await session.switchTo(pageTab);
    await session.navigate(`${RP}/ceremony.html`);
    await session.waitFor(() => session.content(() => document.documentElement.dataset.ready === "1"), 20_000, "the relying party's page");
    const key = /** @type {any} */ (await registerTestKey(session, lib, RP_ID, `anna-${lib}`));
    assert.equal(key.ok, true, `${channel} ${lib}: the registration of the test key: ${JSON.stringify(key)}`);
    await session.switchTo(bridgeTab);
    const planted = await core(session, "item_import_probe", { name: `Test ${lib}`, rp_id: RP_ID, user_name: `anna-${lib}`, cred_id: key.cred_id, user_handle: key.user_handle, key_pkcs8: key.key_pkcs8 });
    assert.match(planted.item_id, /^[0-9a-f]{32}$/);
    keys[lib] = { sid: key.sid };
  }
  await session.switchTo(bridgeTab);
  const tabs = /** @type {any[]} */ (await bridge.invoke("tabs.query", { url: `${RP}/*` }));
  assert.equal(tabs.length, 1, "one tab of the relying party");
  return { account, bridge, bridgeTab, pageTab, pageTabId: /** @type {number} */ (tabs[0].id), keys };
}

/** The popup, popped out into a window of its own, about the page's tab. @param {import("./driver.mjs").Session} session @param {number} tabId */
async function openPopup(session, tabId) {
  const popup = await session.newWindow();
  await session.switchTo(popup);
  await session.navigate(`${POPUP_URL}?tab=${tabId}`);
  await session.waitFor(() => session.content(() => document.body?.dataset.ready === "1"), 30_000, "the popup");
  return popup;
}

/** What the popup's passkey part shows. @param {import("./driver.mjs").Session} session */
const popupPart = (session) =>
  session.content(() => ({
    shown: !(document.querySelector('[data-role="passkey-popup"]')?.hasAttribute("hidden") ?? true),
    title: document.querySelector('[data-role="passkey-popup-title"]')?.textContent ?? "",
    picks: [...document.querySelectorAll('[data-role="passkey-popup-pick"]')].map((n) => n.textContent ?? ""),
    verify: document.querySelector('[data-role="passkey-verify-step"]') !== null,
  }));

/** A real click on a control of the popup's part, after its 400 ms guard. @param {import("./driver.mjs").Session} session @param {string} css */
async function pressInPopup(session, css) {
  await sleep(900);
  const [button] = await session.findAll(css);
  assert.ok(button, css);
  await session.click(button);
}

/** What the page's conditional get ended with. @param {import("./driver.mjs").Session} session @param {string} pageTab */
async function conditionalOutcome(session, pageTab) {
  await session.switchTo(pageTab);
  const text = await session.waitFor(() => session.content(() => document.documentElement.dataset.cond ?? null), 45_000, "the conditional get's end");
  return JSON.parse(/** @type {string} */ (text));
}

test("conditional_sign_in_from_the_popup_on_both_fixtures", async () => {
  assert.ok(process.env.FERRET_PASSKEY_CA_PEM, "FERRET_PASSKEY_CA_PEM is not set (run through scripts/lanbox-ext.sh e2e --passkey-rp)");
  for (const channel of channels()) {
    const session = await launch({ channel, prefs: PREFS });
    try {
      const world = await setUp(session, channel);
      const sentinel = `${SENTINEL_PREFIX}${channel}-${Math.random().toString(16).slice(2, 8)}`;
      await setPin(session, world.account, sentinel, "session");
      for (const [n, lib] of LIBS.entries()) {
        await session.switchTo(world.pageTab);
        await session.navigate(`${RP}/ceremony.html`);
        await session.waitFor(() => session.content(() => document.documentElement.dataset.ready === "1"), 20_000, "the relying party's page");
        const before = new Set(await session.windowHandles());
        await inPage(session, conditionalScript({ lib, sid: world.keys[lib].sid, uv: n === 0 ? "required" : "preferred" }));
        await session.waitFor(() => session.content(() => document.documentElement.dataset.condStarted === "1"), 20_000, "the conditional get");
        const popup = await openPopup(session, world.pageTabId);
        await session.waitFor(async () => (await popupPart(session)).picks.length > 0, 30_000, "the popup's list");
        const part = await popupPart(session);
        assert.equal(part.title, `Passkeys for ${RP_ID}`, `${channel} ${lib}`);
        assert.ok(part.picks.some((p) => p.includes(`anna-${lib}`)), `${channel} ${lib}: the passkey of the vault (${JSON.stringify(part)})`);
        // No window of Ferret's own for a conditional request: the list is the popup's.
        assert.deepEqual((await session.windowHandles()).filter((h) => !before.has(h) && h !== popup), [], `${channel} ${lib}: no chooser window`);
        if (n === 0) {
          for (const [scheme, value] of /** @type {const} */ ([["light", 1], ["dark", 0]])) {
            await session.chrome((/** @type {number} */ v) => Services.prefs.setIntPref("layout.css.prefers-color-scheme.content-override", v), value);
            await sleep(500);
            await session.screenshot(shotPath(channel, `ext-popup-passkeys-${scheme}`));
          }
        }
        const pick = await session.content((/** @type {string} */ wanted) => {
          const row = [...document.querySelectorAll('[data-role="passkey-popup-pick"]')].find((r) => (r.textContent ?? "").includes(wanted));
          return row?.getAttribute("data-item") ?? null;
        }, `anna-${lib}`);
        await pressInPopup(session, `[data-role="passkey-popup-pick"][data-item="${pick}"]`);
        if (n === 0) {
          // `required`, nothing recent: the popup's own verification step (the PIN, checked like an unlock). No passkey call here.
          await session.waitFor(async () => (await popupPart(session)).verify, 15_000, "the verification step");
          assert.equal((await session.findAll('[data-role="passkey-verify-prf"]')).length, 0, "no WebAuthn call from the popup");
          await session.screenshot(shotPath(channel, "ext-popup-passkeys-verify-dark"));
          await session.chrome(() => Services.prefs.clearUserPref("layout.css.prefers-color-scheme.content-override"));
          const [field] = await session.findAll('[data-role="passkey-verify-pin"]');
          await session.type(field, sentinel);
          await pressInPopup(session, '[data-role="passkey-verify-pin-submit"]');
        }
        const result = await conditionalOutcome(session, world.pageTab);
        assert.equal(result.ok, true, `${channel} ${lib}: ${JSON.stringify(result)}`);
        assert.equal(result.server.flags.uv, true, `${channel} ${lib}: the relying party saw UV`);
        assert.equal(result.attachment, "platform");
        // Answered: the popup's list is gone.
        await session.switchTo(popup);
        await session.waitFor(async () => (await popupPart(session)).picks.length === 0, 15_000, "the list is gone");
        await session.closeTab();
      }
      const leaked = scanFolder(session.profileDir, [sentinel, sentinel.normalize("NFKD")]);
      assert.deepEqual(leaked, [], `${channel}: the sentinel PIN is in a file of the profile`);
    } finally {
      await session.quit();
    }
  }
}, { timeout: 6 * SLOW });

test("conditional_to_modal_switch_with_and_without_the_pages_abort", async () => {
  assert.ok(process.env.FERRET_PASSKEY_CA_PEM, "FERRET_PASSKEY_CA_PEM is not set (run through scripts/lanbox-ext.sh e2e --passkey-rp)");
  for (const channel of channels()) {
    const session = await launch({ channel, prefs: PREFS });
    try {
      const world = await setUp(session, channel);
      for (const abort of [true, false]) {
        const lib = abort ? "rs" : "swa";
        const label = `${channel} ${abort ? "with" : "without"} the page's abort`;
        await session.switchTo(world.pageTab);
        // The fixture's own ceremony: a conditional get, then (on the click) a modal get with `discouraged` (the click is enough).
        const run = `xp-${Math.random().toString(16).slice(2, 10)}`;
        const spec = { run, sid: world.keys[lib].sid, lib, client: "manual", steps: ["conditional", "get"], get: { userVerification: "discouraged", allow: "none", ...(abort ? { abortConditional: true } : {}) } };
        await session.navigate(`${RP}/ceremony.html?spec=${Buffer.from(JSON.stringify(spec), "utf8").toString("base64url")}`);
        await session.waitFor(() => session.content(() => document.documentElement.dataset.ready === "1"), 20_000, "the ceremony page");
        const known = new Set(await session.windowHandles());
        const [go] = await session.findAll("#go");
        await session.click(go);
        const handle = await chooserHandle(session, known);
        const shown = await readWindow(session);
        assert.equal(shown.kind, "get", label);
        assert.equal(shown.candidates.length, 1, `${label}: ${JSON.stringify(shown)}`);
        await pressInWindow(session, "passkey-candidate");
        await session.waitFor(async () => !(await session.windowHandles()).includes(handle), 30_000, "the window closed");
        await session.switchTo(world.pageTab);
        await session.waitFor(() => session.content(() => ["ok", "failed"].includes(document.getElementById("result")?.dataset.state ?? "")), 45_000, "the ceremony's end");
        const result = /** @type {any} */ (await session.content(() => /** @type {any} */ (window).__result));
        assert.equal(result.ok, true, `${label}: the modal get: ${JSON.stringify(result)}`);
        // The conditional get ended with AbortError: aborted by the page, or replaced by the modal one as Firefox does it.
        const reports = /** @type {any} */ (await session.content(async (/** @type {string} */ id) => (await fetch(`/api/report?run=${encodeURIComponent(id)}`)).json(), run));
        const conditional = reports.reports.find((/** @type {any} */ r) => r.kind === "conditional");
        assert.ok(conditional, `${label}: the conditional get ended (${JSON.stringify(reports.reports.map((/** @type {any} */ r) => r.kind))})`);
        assert.equal(conditional.ok, false, label);
        assert.equal(conditional.error?.name, "AbortError", `${label}: ${JSON.stringify(conditional)}`);
        // Nothing waits for the popup any more.
        const popup = await openPopup(session, world.pageTabId);
        await sleep(1500);
        assert.deepEqual((await popupPart(session)).picks, [], label);
        await session.closeTab();
        await session.switchTo(world.pageTab);
      }
    } finally {
      await session.quit();
    }
  }
}, { timeout: 6 * SLOW });
