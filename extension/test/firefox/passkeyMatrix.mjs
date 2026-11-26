// The passkey matrix runner (U4): drives a real Firefox through the cases of test/fixtures/passkey (and the hold-out and
// demo sets) against the fixture container (test/passkey-rp), and hands what it saw to passkeyCases.mjs. Not a spec
// (run.sh picks up *.spec.mjs only); 96-passkey-matrix.e2e.spec.mjs uses it.
//
// The browser trusts the fixture's test CA (FERRET_PASSKEY_CA_PEM, written to a file for the profile's policies) and nothing
// else; the host names are the ones of the container's network (Docker DNS), never localDomains. A WebDriver virtual
// authenticator plays the platform authenticator. The PROVIDER says who answers a call that Ferret takes:
//
//   stub    nobody: the call goes the browser's way and the virtual authenticator answers. The route (Ferret or browser)
//           cannot be seen, so a case that expects Ferret is judged on what the page and the relying party saw, and
//           cases that need Ferret to answer (a window, a verification, a navigation while a request waits) are not run.
//           This is what U4-3 can do, and it proves the fixtures, the pages, the runner and the report.
//   ferret  the extension answers: it is signed in to the end-to-end stack of the run (scripts/lanbox-ext.sh passkey-matrix
//           --provider ferret joins both networks), with passkeys on, and the runner presses in Ferret's window what a person
//           would: "Save in Ferret" for a new passkey, the first passkey of a sign-in (or "Use the browser" when Ferret offers
//           none: a cancel would count toward the tab's calm period and keep the next cases' windows from opening).
//           A case whose last step is a conditional get (the site's autofill UI) is answered from Ferret's popup, about the
//           case's tab: the newest passkey of the list, with the master password when the popup asks to verify; the case then
//           fails unless the page's conditional get ended with a credential.
//           The cases that need a driver step of their own (a lock, a navigation, the network going away while a request
//           waits) are reported as not run.
//
// FERRET_PASSKEY_BRIDGE=1 (scripts/lanbox-ext.sh passkey-matrix --bridge) turns the test build's passkey scripts on before the
// first case (the permission for https pages with a click in the extension's own page, the setting, and the fixture's vault as
// the signed-in server). While the background hands every request back to the browser, the stub judgement then also shows that
// the bridge leaves each ceremony as the browser alone would end it; the runner counts the requests that went through the
// bridge, and a run in which none did proves nothing about it.
//
// A case that did not run counts as failed (UK125); nothing here ever turns "no result" into "passed".
import { writeFileSync } from "node:fs";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { startFirefox } from "./driver.mjs";
import { appliesTo, caseAddress, computeMatrix, loadCases, observe, specOf, writeReport } from "./passkeyCases.mjs";
import { BRIDGE_URL, defaultManifest, e2eCertificateFile, EXTENSION_ORIGIN, openBridge, TEST_ADDON_ID, xpiPath } from "./harness.mjs";
import { KEEP_BACKGROUND, extensionSignIn, pace, webVaultAccount } from "./e2e.mjs";
import { addPasskey, ask } from "./unlock.mjs";
import { runActionCase, secondProfile, vaultRows } from "./passkeyDrive.mjs";
import { runDemoCase } from "./passkeyDemo.mjs";
import { revokeLeftDevices } from "./adversary.mjs";

const here = dirname(fileURLToPath(import.meta.url));

/** The directories of the sets. The hold-out set is written by another agent and copied in later (U4-13). */
export const SET_DIRS = Object.freeze({
  fixtures: resolve(here, "..", "fixtures", "passkey"),
  adversarial: resolve(here, "..", "fixtures", "passkey"),
  holdout: process.env.FERRET_PASSKEY_HOLDOUT_DIR ?? resolve(here, "..", "fixtures", "passkey-holdout"),
  demo: resolve(here, "..", "fixtures", "passkey", "demo"),
});

/** The preferences of the matrix's profile: the soft token answers (the virtual authenticator), the USB token does not. */
export const MATRIX_PREFS = Object.freeze({
  "security.webauth.webauthn_enable_softtoken": true,
  "security.webauth.webauthn_enable_usbtoken": false,
  // The names are the network's (Docker DNS), not a local override.
  "network.dns.localDomains": "",
});

/** @type {string | undefined} */
let caFile;
/** The file of the fixture's CA, written once from FERRET_PASSKEY_CA_PEM. */
export function fixtureCaFile() {
  const pem = process.env.FERRET_PASSKEY_CA_PEM;
  if (!pem) throw new Error("FERRET_PASSKEY_CA_PEM is not set (run through scripts/lanbox-ext.sh passkey-matrix, with the fixtures up)");
  if (!caFile) {
    caFile = join(mkdtempSync(join(tmpdir(), "ferret-passkey-ca-")), "passkey-rp-ca.pem");
    writeFileSync(caFile, `${pem.trim()}\n`);
  }
  return caFile;
}

/** Whether the test build's passkey scripts are turned on before the first case (see the head of the file). */
export const BRIDGE_ON = process.env.FERRET_PASSKEY_BRIDGE === "1";
/** The server the extension counts as signed in to when the scripts are on: the fixture's vault origin (left out by them). */
export const BRIDGE_SERVER = "https://vault-fixture.test";

/**
 * Turns the passkey scripts on in a tab of the extension's test bridge that stays open and counts the bridge's requests, and
 * comes back to the tab the session was in.
 * @param {import("./driver.mjs").Session} session
 * @returns {Promise<string>} the handle of the bridge tab
 */
export async function turnOnPasskeyScripts(session) {
  const back = await session.windowHandle();
  const tab = await session.newTab();
  await session.switchTo(tab);
  await session.navigate(BRIDGE_URL);
  await session.waitFor(() => session.content(() => document.documentElement.dataset.ready === "1"), 20_000, "the bridge page");
  await session.content(() => {
    const w = /** @type {any} */ (window);
    w.passkeyRequests = 0;
    browser.runtime.onMessage.addListener((/** @type {unknown} */ raw) => {
      try {
        if (JSON.parse(String(raw)).type === "passkey_request") w.passkeyRequests += 1;
      } catch {
        // Not a message of the bridge.
      }
      return undefined;
    });
    const button = document.createElement("button");
    button.id = "pk-grant";
    button.textContent = "grant";
    button.addEventListener("click", () => {
      browser.permissions.request({ origins: ["https://*/*"] }).then((ok) => { document.documentElement.dataset.pkGranted = String(ok); });
    });
    document.body.append(button);
  });
  const [button] = await session.findAll("#pk-grant");
  await session.click(button);
  const granted = await session.waitFor(() => session.content(() => document.documentElement.dataset.pkGranted), 15_000, "the permission for https pages");
  if (granted !== "true") throw new Error("the permission for https pages was not granted");
  await session.content((/** @type {string} */ server) => browser.storage.local.set({ use_passkeys: true, server }), BRIDGE_SERVER);
  // The background has no storage listener: the test build's `passkey_reconcile` makes the registration agree now.
  await session.content(() => new Promise((resolve, reject) => {
    const port = browser.runtime.connect({ name: "ferret-test-core" });
    const timer = setTimeout(() => reject(new Error("passkey_reconcile did not answer")), 15_000);
    port.onMessage.addListener((/** @type {any} */ reply) => {
      clearTimeout(timer);
      port.disconnect();
      if (reply?.ok) resolve(true);
      else reject(new Error(`passkey_reconcile: ${reply?.code}`));
    });
    port.postMessage({ id: "r1", op: "passkey_reconcile" });
  }));
  await session.waitFor(
    () => session.content(async () => (await browser.scripting.getRegisteredContentScripts({ ids: ["ferret-passkey-main", "ferret-passkey-bridge"] })).length === 2),
    15_000,
    "both passkey scripts registered",
  );
  await session.switchTo(back);
  return tab;
}


/** The address of Ferret's chooser window. */
export const CHOOSER_PAGE = `${EXTENSION_ORIGIN}/pages/passkey.html?r=`;

/** The account the extension is signed in to (the Ferret provider): the master password is what a person types to verify. */
let ferretAccount = /** @type {{ email: string, password: string, secretKey: string, qrText: string } | null} */ (null);

/** The popup's page (the Ferret provider answers a conditional get there). */
const POPUP_PAGE = `${EXTENSION_ORIGIN}/pages/popup.html`;


/**
 * The Ferret provider: an account on the end-to-end stack (made by the first channel, signed in to by the next), the extension
 * signed in to it, the permission for https pages, the setting, and both passkey scripts registered. Comes back to the tab the
 * session was in. `revoke`: the devices an earlier run left in the account are revoked first (not for a second profile of the
 * same run, which would end the first one's device).
 * @param {import("./driver.mjs").Session} session @param {string} channel @param {{ revoke?: boolean, prf?: boolean }} [o]
 * @returns {Promise<{ tab: string, account: { email: string, password: string, secretKey: string, qrText: string } }>} the handle of the
 *   extension's tab (the test bridge page) and the account
 */
export async function turnOnFerret(session, channel, { revoke = true, prf = false } = {}) {
  if (!process.env.FERRET_E2E_CA_PEM) throw new Error("the Ferret provider needs the end-to-end stack (scripts/lanbox-ext.sh passkey-matrix --provider ferret)");
  const back = await session.windowHandle();
  await session.waitFor(() => session.addonInfo(TEST_ADDON_ID), 30_000, "the add-on");
  const account = await webVaultAccount(session, channel);
  ferretAccount = account;
  if (revoke) await revokeLeftDevices(session);
  // The account's passkey for verifying with PRF (the cases with "verify-prf"), made in the web vault while it is open here: the
  // virtual authenticator of this browser holds it.
  if (prf) await addPasskey(session, account, `Matrix passkey ${channel}`);
  const tab = await session.newTab();
  await session.switchTo(tab);
  const signed = await extensionSignIn(session, account);
  if (!signed.ok) throw new Error(`${channel}: the extension's sign-in failed: ${signed.text}`);
  const bridge = await openBridge(session);
  await session.content(() => {
    const button = document.createElement("button");
    button.id = "pk-grant";
    button.textContent = "grant";
    button.addEventListener("click", () => {
      browser.permissions.request({ origins: ["https://*/*"] }).then((ok) => { document.documentElement.dataset.pkGranted = String(ok); });
    });
    document.body.append(button);
  });
  const [button] = await session.findAll("#pk-grant");
  await session.click(button);
  const granted = await session.waitFor(() => session.content(() => document.documentElement.dataset.pkGranted), 15_000, "the permission for https pages");
  if (granted !== "true") throw new Error("the permission for https pages was not granted");
  await bridge.invoke("storage.local.set", { use_passkeys: true });
  await reconcile(session);
  await session.waitFor(
    () => session.content(async () => (await browser.scripting.getRegisteredContentScripts({ ids: ["ferret-passkey-main", "ferret-passkey-bridge"] })).length === 2),
    15_000,
    "both passkey scripts registered",
  );
  await session.switchTo(back);
  return { tab, account };
}

/** The test build's `passkey_reconcile`, from an extension page (the background has no storage listener). @param {import("./driver.mjs").Session} session */
async function reconcile(session) {
  await session.content(() => new Promise((resolve, reject) => {
    const port = browser.runtime.connect({ name: "ferret-test-core" });
    const timer = setTimeout(() => reject(new Error("passkey_reconcile did not answer")), 15_000);
    port.onMessage.addListener((/** @type {any} */ reply) => {
      clearTimeout(timer);
      port.disconnect();
      if (reply?.ok) resolve(true);
      else reject(new Error(`passkey_reconcile: ${reply?.code}`));
    });
    port.postMessage({ id: "r1", op: "passkey_reconcile" });
  }));
}

/**
 * Runs `fn` while the extension counts `server` as its signed-in server (`storage.local` `server`, as the session keeps it), and the
 * passkey scripts are registered for that: a case on the fixture's vault host (vault-fixture.test) is then a page on the Ferret
 * server's origin, which the registration leaves out and the background refuses. The real server is put back afterwards.
 * @template T
 * @param {{ session: import("./driver.mjs").Session, extTab: string }} profile @param {string} server @param {() => Promise<T>} fn
 * @returns {Promise<T>}
 */
export async function withServer(profile, server, fn) {
  const s = profile.session;
  const back = await s.windowHandle();
  await s.switchTo(profile.extTab);
  const was = /** @type {any} */ (await s.content(async () => (await browser.storage.local.get("server")).server ?? null));
  await s.content((/** @type {string} */ value) => browser.storage.local.set({ server: value }), server);
  await reconcile(s);
  await s.switchTo(back);
  try {
    return await fn();
  } finally {
    const now = await s.windowHandle().catch(() => back);
    await s.switchTo(profile.extTab);
    await s.content((/** @type {string | null} */ value) => (value === null ? browser.storage.local.remove("server") : browser.storage.local.set({ server: value })), was);
    await reconcile(s);
    await s.switchTo(now).catch(() => {});
  }
}

/**
 * Watches the browser's own WebAuthn prompts (chrome context): every `webauthn-prompt` notification of the browser is counted, with
 * its kind. A call that the browser took and holds (an enterprise attestation waits for the person's consent, which an automated
 * profile never gives) has no step report; its prompt is the evidence that the browser took it.
 * @param {import("./driver.mjs").Session} session
 */
export async function watchBrowserPrompts(session) {
  await session.chrome(() => {
    const w = /** @type {any} */ (globalThis);
    // A chrome script runs in a sandbox of its own: what must outlive it is kept on the shared global of the Services module.
    const g = w.Components.utils.getGlobalForObject(w.Services);
    if (g.__ferretPrompts) return;
    g.__ferretPrompts = [];
    g.__ferretPromptObserver = {
      observe(/** @type {unknown} */ _subject, /** @type {string} */ _topic, /** @type {string} */ data) {
        let type = "unknown";
        try {
          type = String(JSON.parse(data)?.prompt?.type ?? JSON.parse(data)?.action ?? "unknown");
        } catch {
          // Not JSON: counted all the same.
        }
        g.__ferretPrompts.push(type);
      },
    };
    w.Services.obs.addObserver(g.__ferretPromptObserver, "webauthn-prompt");
  });
}

/** The browser's WebAuthn prompts so far (their kinds). @param {import("./driver.mjs").Session} session @returns {Promise<string[]>} */
export async function browserPrompts(session) {
  if (typeof session?.chrome !== "function") return [];
  return /** @type {string[]} */ (await session.chrome(() => {
    const w = /** @type {any} */ (globalThis);
    return [...(w.Components.utils.getGlobalForObject(w.Services).__ferretPrompts ?? [])];
  }).catch(() => []));
}

/**
 * Presses in every chooser window of Ferret that is ready what a person would: "Save in Ferret" for a new passkey (with the name
 * `name` for its item when one is given); for a sign-in the newest passkey Ferret offers (the one this case made; a page that lists
 * no credentials gets the passkeys of earlier cases too), or "Use the browser" when it offers none. `choose` "browser" or "never"
 * presses that instead. A window that shows the vault locked is unlocked there with the master password first. When the window then
 * asks the person to verify, `method` says how ("password", "pin" with MATRIX_PIN, "prf" with the account's passkey, "none":
 * nothing); when it says nothing can verify now, "Use the browser" is pressed. Windows already pressed in (`pressed`) and the ones
 * that were there before the case (`baseline`) are left alone; the session comes back to `main`. Returns what was pressed, per window.
 * A case whose page aborts its own call while Ferret has nothing to offer (`browserWhenEmpty` false) is left waiting: the page's
 * abort is what it is about.
 * @param {import("./driver.mjs").Session} session @param {Set<string>} baseline @param {Set<string>} pressed @param {string} main
 * @param {{ browserWhenEmpty?: boolean, choose?: "auto" | "browser" | "never", method?: string, name?: string | null, password?: string }} [o]
 * @returns {Promise<Array<{ kind: string, role: string }>>}
 */
export async function pressInChooser(session, baseline, pressed, main, { browserWhenEmpty = true, choose = "auto", method = "password", name = null, password = ferretAccount?.password ?? "" } = {}) {
  /** @type {Array<{ kind: string, role: string }>} */
  const done = [];
  try {
    for (const handle of await session.windowHandles().catch(() => /** @type {string[]} */ ([]))) {
      if (baseline.has(handle) || pressed.has(handle)) continue;
      // A window that goes away while the runner is in it (the page aborted, the request ended) is left alone.
      if (!(await session.switchTo(handle).then(() => true, () => false))) continue;
      const url = await session.currentUrl().catch(() => "");
      if (!url.startsWith(CHOOSER_PAGE)) continue;
      const shown = await session
        .content(() => {
          const root = document.querySelector('[data-role="passkey-chooser"]');
          return { ready: document.body?.dataset.ready === "1", kind: root?.getAttribute("data-kind") ?? "", state: root?.getAttribute("data-state") ?? "", busy: root?.getAttribute("aria-busy") === "true" };
        })
        .catch(() => null);
      if (shown === null || !shown.ready || shown.busy) continue;
      if (shown.state === "locked") {
        // The vault locked: the window shows the unlock. The master password (and the secret key, when the window asks for it).
        await unlockInChooser(session, password);
        done.push({ kind: shown.kind, role: "passkey-unlock" });
        continue;
      }
      if (shown.state !== "ready") continue;
      // The window's guard: a click counts only 400 ms after its content was built.
      await sleep(900);
      const candidates = await session.findAll('[data-role="passkey-candidate"]');
      const offline = (await session.findAll('[data-role="passkey-offline"]')).length > 0;
      let role = shown.kind === "create" ? (offline ? "passkey-browser" : "passkey-create-new") : candidates.length > 0 ? "passkey-candidate" : "passkey-browser";
      if (choose === "browser") role = "passkey-browser";
      if (choose === "never") role = "passkey-never";
      if (role === "passkey-browser" && choose === "auto" && !browserWhenEmpty) {
        pressed.add(handle);
        continue;
      }
      if (role === "passkey-create-new" && name !== null) {
        await session.content((/** @type {string} */ value) => {
          const input = /** @type {HTMLInputElement | null} */ (document.querySelector('[data-role="passkey-name"]'));
          if (input) {
            input.value = value;
            input.dispatchEvent(new Event("input", { bubbles: true }));
          }
        }, name);
      }
      const [button] = role === "passkey-candidate" ? candidates.slice(-1) : await session.findAll(`[data-role="${role}"]`).catch(() => []);
      if (!button) continue;
      if (!(await session.click(button).then(() => true, () => false))) continue;
      pressed.add(handle);
      done.push({ kind: shown.kind, role });
      if (role === "passkey-candidate" || role === "passkey-create-new") {
        const after = await verifyInChooser(session, handle, method, password);
        if (after === "unavailable") {
          // Nothing can verify now (no server, no PIN that works offline, no recent unlock): the window offers the browser.
          await sleep(900);
          const [browserButton] = await session.findAll('[data-role="passkey-browser"]');
          if (browserButton) {
            await session.click(browserButton);
            done.push({ kind: shown.kind, role: "passkey-browser" });
          }
        }
      }
    }
  } finally {
    await session.switchTo(main).catch(() => {});
  }
  return done;
}

/**
 * What the Ferret windows that are not in `baseline` show (for the log of a case that did not end): state, kind, visible notices and
 * the visible controls. The session comes back to `back`.
 * @param {import("./driver.mjs").Session} session @param {Set<string>} baseline @param {string} back
 */
export async function chooserSnapshot(session, baseline, back) {
  /** @type {any[]} */
  const out = [];
  for (const h of await session.windowHandles().catch(() => /** @type {string[]} */ ([]))) {
    if (baseline.has(h) || !(await session.switchTo(h).then(() => true, () => false))) continue;
    if (!(await session.currentUrl().catch(() => "")).startsWith(CHOOSER_PAGE)) continue;
    out.push(await session.content(() => {
      const root = document.querySelector('[data-role="passkey-chooser"]');
      const texts = [...document.querySelectorAll('[role="alert"], [role="status"], .ff-error, .ff-notice')].filter((n) => !n.closest("[hidden]") && (n.textContent ?? "").trim() !== "").map((n) => (n.textContent ?? "").trim().slice(0, 120));
      const roles = [...document.querySelectorAll("[data-role]")].filter((n) => n.getClientRects().length > 0).map((n) => n.getAttribute("data-role")).slice(0, 30);
      return { state: root?.getAttribute("data-state"), kind: root?.getAttribute("data-kind"), texts, roles };
    }).catch((e) => ({ error: String(e).slice(0, 120) })));
  }
  await session.switchTo(back).catch(() => {});
  return out;
}

/**
 * How many of `handles` are Ferret's chooser windows (a page's own popups are not); each window's address is read once (`known`),
 * and the session comes back to `back`.
 * @param {import("./driver.mjs").Session} session @param {string[]} handles @param {Map<string, boolean>} known @param {string} back
 */
export async function ferretWindows(session, handles, known, back) {
  let read = false;
  for (const h of handles) {
    if (known.has(h)) continue;
    if (!(await session.switchTo(h).then(() => true, () => false))) continue;
    read = true;
    // A new window shows about:blank for a moment before its page: it is read again until it has another address (a page's own
    // about:blank popup is read every time, and never counts).
    const url = await session.currentUrl().catch(() => "");
    if (url !== "" && url !== "about:blank") known.set(h, url.startsWith(CHOOSER_PAGE));
  }
  if (read) await session.switchTo(back).catch(() => {});
  return handles.filter((h) => known.get(h) === true).length;
}

/** The unlock in a window that shows the vault locked. @param {import("./driver.mjs").Session} session @param {string} password */
async function unlockInChooser(session, password) {
  await sleep(900);
  const [field] = await session.findAll('[data-role="passkey-password"]');
  if (!field) return;
  await session.type(field, password);
  const [sk] = await session.findAll('[data-role="passkey-sk"]');
  const skShown = sk ? await session.content(() => {
    const node = document.querySelector('[data-role="passkey-sk"]');
    return node !== null && node.closest("[hidden]") === null && node.getClientRects().length > 0;
  }) : false;
  if (sk && skShown && ferretAccount) await session.type(sk, ferretAccount.secretKey);
  await pace();
  const [submit] = await session.findAll('[data-role="passkey-unlock"]');
  if (submit) await session.click(submit);
  // The unlock takes a few seconds (Argon2id): the window is pressed in when it shows the choices again.
  await session.waitFor(() => session.content(() => document.querySelector('[data-role="passkey-chooser"]')?.getAttribute("data-state") !== "locked").catch(() => true), 120_000, "the unlock in the window").catch(() => {});
}

/**
 * When Ferret's window asks the person to verify after a choice, verifies there with `method`; a window that answers or closes
 * needs nothing. Returns what happened: "closed", "verified", "unavailable" (the window says nothing can verify now) or "skipped".
 * @param {import("./driver.mjs").Session} session @param {string} handle @param {string} method @param {string} password
 */
async function verifyInChooser(session, handle, method, password) {
  const step = await session
    .waitFor(async () => {
      if (!(await session.windowHandles()).includes(handle)) return "closed";
      const state = await session.content(() => ({
        verify: document.querySelector('[data-role="passkey-verify-step"]') !== null,
        none: document.querySelector('[data-role="passkey-verify-none"]') !== null,
        error: (() => {
          const node = document.querySelector('[data-role="passkey-error"]');
          return node !== null && !node.hidden && (node.textContent ?? "").trim() !== "";
        })(),
      })).catch(() => null);
      if (state === null) return "closed";
      if (state.none || state.error) return "unavailable";
      return state.verify ? "verify" : null;
    }, 15_000, "the answer of the window or its verification step")
    .catch(() => "closed");
  if (step !== "verify") return step;
  if (method === "none") return "skipped";
  if (method === "pin") {
    const [field] = await session.findAll('[data-role="passkey-verify-pin"]');
    if (!field) return "skipped";
    await session.type(field, MATRIX_PIN);
    await sleep(900);
    const [submit] = await session.findAll('[data-role="passkey-verify-pin-submit"]');
    if (submit) await session.click(submit);
    return "verified";
  }
  if (method === "prf") {
    await sleep(900);
    const [button] = await session.findAll('[data-role="passkey-verify-prf"]');
    if (!button) return "skipped";
    await session.click(button);
    return "verified";
  }
  const [field] = await session.findAll('[data-role="passkey-verify-password"]');
  if (!field || password === "") return "skipped";
  await session.type(field, password);
  await sleep(900);
  // The master password signs in to the server: one sign-in start, under the server's limit.
  await pace();
  const [submit] = await session.findAll('[data-role="passkey-verify-password-submit"]');
  if (submit) await session.click(submit);
  return "verified";
}

/** The PIN the matrix sets when a case verifies with one (passkeyDrive.mjs sets it). */
// It starts with the sentinel prefix, so the run's scan of the stack's logs looks for it too (scripts/lanbox-ext.sh).
export const MATRIX_PIN = "ferret-sentinel-pin-matrix-4826";
/**
 * Opens Ferret's window for a request that waits without one, from the popup's card, as a person would (the popup in a window of its
 * own about the case's tab). Returns whether the card was there and pressed. The session comes back to `main`.
 * @param {import("./driver.mjs").Session} session @param {string} main @param {string} top the page's origin
 */
export async function openWaitingFromPopup(session, main, top) {
  const popup = await session.newWindow();
  try {
    await session.switchTo(popup);
    await session.navigate(POPUP_PAGE);
    const tabId = await session.content(async (/** @type {string} */ origin) => {
      const tabs = await browser.tabs.query({ url: `${origin}/*` });
      return tabs.length === 1 ? tabs[0].id : null;
    }, top);
    if (typeof tabId !== "number") return false;
    await session.navigate(`${POPUP_PAGE}?tab=${tabId}`);
    const shown = await session.waitFor(async () => (await session.findAll('[data-role="passkey-popup-open"]')).length > 0, 5000, "the popup's card").catch(() => false);
    if (!shown) return false;
    await sleep(900);
    const [open] = await session.findAll('[data-role="passkey-popup-open"]');
    if (!open) return false;
    await session.click(open);
    return true;
  } finally {
    await session.closeTab().catch(() => {});
    await session.switchTo(main).catch(() => {});
  }
}

/**
 * Answers the page's conditional get from Ferret's popup, as a person would: the popup in a window of its own about the case's tab
 * (`top` is the page's origin), the newest passkey of its list (the one the case made), and the master password when the popup asks
 * to verify. Returns what was done, or why nothing could be. The session comes back to `main`.
 * @param {import("./driver.mjs").Session} session @param {string} main @param {string} top
 * @returns {Promise<{ picked: boolean, verified: boolean, reason?: string }>}
 */
export async function pickInPopup(session, main, top) {
  const popup = await session.newWindow();
  try {
    await session.switchTo(popup);
    await session.navigate(POPUP_PAGE);
    const tabId = await session.content(async (/** @type {string} */ origin) => {
      const tabs = await browser.tabs.query({ url: `${origin}/*` });
      return tabs.length === 1 ? tabs[0].id : null;
    }, top);
    if (typeof tabId !== "number") return { picked: false, verified: false, reason: "no single tab of the case" };
    await session.navigate(`${POPUP_PAGE}?tab=${tabId}`);
    const listed = await session
      .waitFor(async () => (await session.findAll('[data-role="passkey-popup-pick"]')).length > 0, 20_000, "the popup's list")
      .catch(() => false);
    if (!listed) return { picked: false, verified: false, reason: "the popup listed no passkey for the conditional get" };
    // The popup's guard: a click counts only 400 ms after its content was built.
    await sleep(900);
    const picks = await session.findAll('[data-role="passkey-popup-pick"]');
    await session.click(/** @type {any} */ (picks.at(-1)));
    const step = await session
      .waitFor(async () => ((await session.findAll('[data-role="passkey-verify-password"]')).length > 0 ? "verify" : (await session.findAll('[data-role="passkey-popup-pick"]')).length === 0 ? "done" : null), 10_000, "the popup's answer")
      .catch(() => "done");
    if (step !== "verify" || (ferretAccount?.password ?? "") === "") return { picked: true, verified: false };
    const [field] = await session.findAll('[data-role="passkey-verify-password"]');
    await session.type(field, ferretAccount?.password ?? "");
    await sleep(900);
    // The master password signs in to the server: one sign-in start, under the server's limit.
    await pace();
    const [submit] = await session.findAll('[data-role="passkey-verify-password-submit"]');
    if (submit) await session.click(submit);
    return { picked: true, verified: true };
  } finally {
    await session.switchTo(main).catch(() => {});
  }
}

/** How many requests went through the bridge so far. @param {import("./driver.mjs").Session} session @param {string} tab */
export async function bridgeRequests(session, tab) {
  const back = await session.windowHandle();
  await session.switchTo(tab);
  try {
    return Number(await session.content(() => /** @type {any} */ (window).passkeyRequests ?? 0));
  } finally {
    await session.switchTo(back);
  }
}

/** The fixture container's base address, for the runner's own requests (reports). */
export const FIXTURE_BASE = process.env.FERRET_PASSKEY_BASE ?? "https://rp-a.test";

/** @param {number} ms */
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * The cases of a set (those of the fixtures and adversarial sets share a folder and are told apart by `set`).
 * @param {"fixtures" | "adversarial" | "holdout" | "demo"} set @param {string} [grep] a text that the id contains (or several, comma-separated)
 * @returns {{ cases: any[], problems: string[] }}
 */
export function selectCases(set, grep = "") {
  const { cases, problems } = loadCases([SET_DIRS[set]]);
  // The filter is a text the id contains, or several of them separated by commas (any of them).
  const parts = grep.split(",").filter((x) => x !== "");
  return { cases: cases.filter((c) => c.set === set && (parts.length === 0 || parts.some((x) => c.id.includes(x)))), problems };
}

/**
 * Starts Firefox for the matrix: the fixture CA trusted (not for the demo set, which runs against the public sites), the soft
 * token on, a virtual authenticator, the test build installed, and the browser's own WebAuthn prompts watched.
 * @param {{ channel: "release" | "esr", manifest?: "mv3" | "mv2", headless?: boolean, fixtures?: boolean, prefs?: Record<string, unknown> }} o
 */
export async function launchMatrixBrowser({ channel, manifest = defaultManifest(), headless = process.env.FERRET_HEADLESS !== "0", fixtures = process.env.FERRET_PASSKEY_SET !== "demo", prefs = {} }) {
  // With the Ferret provider the end-to-end stack's CA is trusted too (its server is the one the extension signs in to), and the
  // event page is kept alive as in the end-to-end specs.
  const e2e = e2eCertificateFile();
  const session = await startFirefox({
    channel,
    headless,
    addon: xpiPath(manifest),
    hosts: [],
    certificateFiles: [...(fixtures ? [fixtureCaFile()] : []), ...(e2e ? [e2e] : [])],
    prefs: { ...MATRIX_PREFS, ...(e2e ? KEEP_BACKGROUND : {}), ...prefs },
  });
  await session.addVirtualAuthenticator();
  await watchBrowserPrompts(session);
  return session;
}

/** The reports of a run from the fixture server. @param {string} run */
export async function fetchReports(run) {
  const res = await fetch(`${FIXTURE_BASE}/api/report?run=${encodeURIComponent(run)}`);
  const body = /** @type {any} */ (await res.json());
  return /** @type {any[]} */ (body.reports ?? []);
}

/**
 * Enters the frames of a case's chain and returns when the ceremony page in the last one is ready.
 * @param {import("./driver.mjs").Session} session @param {{ id: string }[]} frames
 */
async function enterFrames(session, frames) {
  await session.switchToTopFrame();
  for (const frame of frames) {
    const el = await session.waitFor(async () => (await session.findAll(`#${frame.id}`))[0], 15_000, `the frame #${frame.id}`);
    await session.switchToFrame(el);
  }
  await session.waitFor(() => session.content(() => document.documentElement.dataset.ready === "1"), 20_000, "the ceremony page");
}

/**
 * Runs one case in the session's selected tab. With the Ferret provider, `drive` is what the driver steps need (passkeyDrive.mjs):
 * a case that needs Ferret to answer runs there, a demo case in passkeyDemo.mjs.
 * @param {import("./driver.mjs").Session} session @param {any} c
 * @param {{ channel: string, provider: "stub" | "ferret", drive?: import("./passkeyDrive.mjs").DriveContext | null }} o
 * @returns {Promise<import("./passkeyCases.mjs").CaseResult>}
 */
export async function runCase(session, c, { channel, provider, drive = null, manifest = drive?.manifest ?? defaultManifest() }) {
  // A case ruled not applicable to this manifest is listed as such, outside the total (not as not run, which counts as failed).
  if (!appliesTo(c, manifest)) return { status: "not-applicable", reason: `the case applies to ${c.manifests.join(", ")} only` };
  if (c.set === "demo") {
    if (c.hand) return { status: "not-run", reason: `hand check: ${c.hand}` };
    if (provider === "ferret" && drive) return runDemoCase(drive, c);
    return { status: "not-run", reason: "the demo pages are run with the Ferret provider only (a person's sign-up and sign-in at a public site)" };
  }
  // No browser: the provider's setup did not run (nothing that ran can be judged).
  if (!session && c.needs !== "provider") return { status: "not-run", reason: "no browser session: the provider was not set up" };
  // A case that needs Ferret but has no driver steps of its own is one click and the page's own steps, as a person would do it
  // (with the popup's card when the request waits without a window).
  const plain = !Array.isArray(c.actions) || c.actions.length === 0;
  if (c.needs === "provider" && !(plain && provider === "ferret" && drive)) {
    if (provider === "ferret" && drive) return runActionCase(drive, c);
    return provider === "ferret"
      ? { status: "not-run", reason: "the Ferret provider was not set up" }
      : { status: "not-run", reason: "the case needs Ferret to answer (a window, a verification or a navigation while a request waits); the stub provider cannot run it" };
  }
  // A page on the fixture's vault host is a page on the signed-in Ferret server's origin for the case (the Ferret provider).
  if (provider === "ferret" && drive && (c.page?.chain ?? []).includes("vault-fixture.test")) {
    return withServer(drive.a, "https://vault-fixture.test", () => runPlainCase(session, c, { channel, provider, drive }));
  }
  return runPlainCase(session, c, { channel, provider, drive });
}

/** The categories whose cases are about a request that waits without a window: there the popup's card is the way on. */
const CARD_CATEGORIES = Object.freeze(["adv-window", "create-gesture", "get-conditional"]);

/**
 * A case with one click (or none) and the page's own steps.
 * @param {import("./driver.mjs").Session} session @param {any} c
 * @param {{ channel: string, provider: "stub" | "ferret", drive?: import("./passkeyDrive.mjs").DriveContext | null }} o
 * @returns {Promise<import("./passkeyCases.mjs").CaseResult>}
 */
async function runPlainCase(session, c, { provider, drive = null }) {
  const run = `${Math.random().toString(16).slice(2, 10)}-${c.id}`.slice(0, 80);
  const spec = specOf(c, run);
  const address = caseAddress(c, { spec, auto: c.gesture === "none" });
  const main = await session.windowHandle();
  const baseline = new Set(await session.windowHandles());
  const promptsBefore = (await browserPrompts(session)).length;
  let windowsOpened = 0;
  /** The chooser windows the runner pressed in (the Ferret provider). @type {Set<string>} */
  const pressed = new Set();
  try {
    await session.navigate(address.url);
    if (c.gesture === "click") {
      await enterFrames(session, address.frames);
      const [go] = await session.findAll("#go");
      if (!go) return { status: "not-run", reason: "the page has no #go button" };
      await session.click(go);
    }
    // Wait for the page's "done" report, counting the windows that appear meanwhile. The time counts from the last thing the
    // runner did (a verification signs in to the server and waits for the sign-in limit).
    const started = Date.now();
    // A hold-out case whose page aborts its call, leaves its frame or changes its address after a while: nothing is pressed in
    // Ferret's window until that has happened (the case is about what the page does while the call waits).
    const lifecycle = c.set === "holdout" ? [c.spec?.abort, c.spec?.removeFrame, c.spec?.navigate].map((x) => Number(x?.afterMs) || 0) : [0];
    const holdMs = Math.max(...lifecycle) > 0 ? Math.max(...lifecycle) + 700 : 0;
    // Nothing should be answered: nothing is pressed in Ferret's window (the case is about what happens without an answer).
    const pressNothing = c.expected.ceremony === "none";
    // A create that must end without an answer: the vault before, to see that nothing reached it (the hold-out cases whose page takes
    // its frame away or aborts while the call waits).
    const watchVault = provider === "ferret" && drive !== null && holdMs > 0 && pressNothing && (spec.steps ?? []).includes("create");
    const rowsBefore = watchVault ? await vaultRows(/** @type {any} */ (drive).a) : [];
    /** The window of a request was opened from the popup's card. */
    let viaCard = false;
    /** When each new window was first seen. @type {Map<string, number>} */
    const firstSeen = new Map();
    let deadline = started + (c.waitMs ?? 20_000);
    let quietSince = started;
    let cardTries = 0;
    /** @type {any[]} */
    let reports = [];
    /** The URL of each new window, once read. @type {Map<string, boolean>} */
    const isFerret = new Map();
    for (;;) {
      await sleep(250);
      const handles = await session.windowHandles().catch(() => /** @type {string[]} */ ([]));
      windowsOpened = Math.max(windowsOpened, await ferretWindows(session, handles.filter((h) => !baseline.has(h)), isFerret, main));
      for (const h of handles) if (!baseline.has(h) && !firstSeen.has(h)) firstSeen.set(h, Date.now());
      if (provider === "ferret" && holdMs > 0 && handles.some((h) => !baseline.has(h) && !pressed.has(h) && Date.now() - (firstSeen.get(h) ?? 0) < holdMs)) {
        // The page does something to its own call first (an abort, a frame taken out): a person has not clicked yet.
      } else if (provider === "ferret" && !pressNothing && handles.some((h) => !baseline.has(h) && !pressed.has(h))) {
        const did = await pressInChooser(session, baseline, pressed, main, { browserWhenEmpty: c.expected.error !== "AbortError" });
        if (did.length > 0) {
          deadline = Math.max(deadline, Date.now() + (c.waitMs ?? 20_000));
          quietSince = Date.now();
        }
      } else if (provider === "ferret" && c.gesture === "click" && c.expected.ceremony !== "none" && cardTries < 3 && Date.now() - quietSince > 6000 && !handles.some((h) => isFerret.get(h) === true && !pressed.has(h))) {
        // A request that waits without a window (the tab's calm period, or no user activation left): the popup shows a card for it,
        // and a person opens Ferret's window from there.
        cardTries += 1;
        quietSince = Date.now();
        const opened = await openWaitingFromPopup(session, main, new URL(address.url).origin);
        console.error(`${c.id}: no window for ${Math.round((Date.now() - started) / 1000)} s; the popup's card ${opened ? "opened Ferret's window" : "was not there"}`);
        if (opened) {
          viaCard = true;
          deadline = Math.max(deadline, Date.now() + (c.waitMs ?? 20_000));
        }
      }
      reports = await fetchReports(run);
      if (reports.some((r) => r.kind === "done") || Date.now() > deadline) break;
    }
    // A conditional get as the last step (the page's autofill UI): Ferret answers it from its popup, and the case passes only when the
    // page's conditional get ended with a credential.
    const steps = Array.isArray(spec.steps) ? spec.steps : [];
    /** @type {any} */
    let conditional = null;
    // Only where the person acted on the page (a case without a click is about nothing happening without one).
    if (provider === "ferret" && c.gesture === "click" && steps.at(-1) === "conditional" && reports.some((r) => r.kind === "conditional-started")) {
      const top = new URL(address.url).origin;
      const picked = await pickInPopup(session, main, top);
      for (let i = 0; i < 80 && !reports.some((r) => r.kind === "conditional"); i++) {
        await sleep(250);
        reports = await fetchReports(run);
      }
      conditional = { ...picked, report: reports.find((r) => r.kind === "conditional") ?? null };
    }
    // An adversarial page reports what it saw itself after the ceremony's "done": give it a moment (a page that threw, or that
    // went away, has none, and the checks of its case then say so).
    if (c.page.path?.startsWith("/adversarial/") && reports.some((r) => r.kind === "done")) {
      for (let i = 0; i < 20 && !reports.some((r) => r.kind === "adv"); i++) {
        await sleep(250);
        reports = await fetchReports(run);
      }
    }
    // A page that never started (a 404, a TLS error, a script error) is not a page that did nothing: it proves nothing, and the cases
    // that expect "nothing happened" must not pass on it.
    if (!reports.some((r) => r.kind === "started")) return { status: "not-run", reason: "the page never started (no report from it at all)" };
    /** What the runner found wrong itself. @type {string[]} */
    const problems = [];
    /** @type {string[]} */
    const unsafeSeen = [];
    // The page took its call away (a frame removed, an abort, a new address): Ferret's window must close, and nothing may reach the vault.
    if (provider === "ferret" && holdMs > 0) {
      const until = started + holdMs + 10_000;
      let open = 0;
      for (;;) {
        const handles = await session.windowHandles().catch(() => /** @type {string[]} */ ([]));
        open = await ferretWindows(session, handles.filter((h) => !baseline.has(h)), isFerret, main);
        if (open === 0 || Date.now() > until) break;
        await sleep(250);
      }
      if (open > 0 && pressNothing) problems.push("Ferret's window stayed open after the page took its call away");
      if (watchVault) {
        await sleep(3000);
        const added = (await vaultRows(/** @type {any} */ (drive).a)).filter((r) => !rowsBefore.includes(r));
        if (added.length > 0) unsafeSeen.push("passkey-not-delivered");
      }
    }
    // A window opened only from the popup's card is right where the case is about a waiting request; elsewhere a clicked request should
    // have opened it itself.
    if (viaCard && !(CARD_CATEGORIES.includes(c.category) || c.gesture === "none")) problems.push("Ferret's window opened only from the popup's card, not for the click");
    // A page that left (nav-before-click) or never answered has no "done": that is an outcome (ceremony none), not an error.
    const observed = observe(reports, { windowShown: windowsOpened > 0, windowsOpened });
    if (problems.length > 0) observed.problems = problems;
    if (viaCard) /** @type {any} */ (observed).viaCard = true;
    if (!reports.some((r) => r.kind === "done") && windowsOpened > 0) /** @type {any} */ (observed).windowsAtEnd = await chooserSnapshot(session, baseline, main);
    // A call the browser took and holds (its own prompt waits for the person) has no step report: the prompt shows the route.
    if (observed.route === "none" && windowsOpened === 0 && (await browserPrompts(session)).length > promptsBefore) observed.route = "browser";
    if (conditional !== null) {
      // Answered in Ferret's popup: the route is Ferret's; the ceremony is the conditional get's own end.
      if (conditional.picked) observed.route = "ferret";
      if (conditional.report?.ok !== true) {
        observed.ceremony = "client-error";
        observed.error = conditional.report?.error?.name ?? (conditional.reason ? `not answered: ${conditional.reason}` : "none");
        observed.failStep = "conditional";
      }
    }
    return { status: "ran", observed, unsafe: [...detectUnsafe(c, observed, provider), ...unsafeSeen], provider };
  } catch (e) {
    return { status: "not-run", reason: `the run threw: ${e instanceof Error ? e.message : String(e)}` };
  } finally {
    // Close what the case opened (a Ferret window, a popup the page made) and go back to the first tab.
    try {
      for (const h of await session.windowHandles()) {
        if (!baseline.has(h)) {
          await session.switchTo(h);
          await session.closeTab();
        }
      }
      await session.switchTo(main);
      await session.switchToTopFrame();
      await session.navigate("about:blank");
    } catch {
      // The next case starts with a fresh navigation anyway.
    }
  }
}

/**
 * The unsafe answers that can be seen from outside, whatever the provider. (What only Ferret's internals know, such as a
 * verification token, is measured by the specs of U4-6 to U4-8 and the end-to-end spec.)
 * @param {any} c @param {NonNullable<import("./passkeyCases.mjs").CaseResult["observed"]>} o @param {"stub" | "ferret"} provider
 * @returns {string[]}
 */
export function detectUnsafe(c, o, provider) {
  /** @type {string[]} */
  const out = [];
  const ids = new Set(c.unsafe.map((/** @type {any} */ u) => u.id));
  // A window although the page had no user activation.
  if (c.gesture === "none" && o.windowShown && ids.has("window-without-gesture")) out.push("window-without-gesture");
  // More windows than one at a time.
  if ((o.windowsOpened ?? 0) > (c.expected.maxWindows ?? 1)) out.push("too-many-windows");
  // A passkey made or used where the browser had to refuse the RP ID: the answer must be an error.
  if (c.expected.ceremony === "client-error" && c.expected.error === "SecurityError" && o.ceremony === "ok" && ids.has("signature-for-other-rp-id")) out.push("signature-for-other-rp-id");
  // A frame with a foreign ancestor or another origin than the top: Ferret must not answer.
  // Only when the chain really has a frame of another origin than the top (or a sandboxed one): a Ferret window for a chain of one
  // origin is a route that does not match the case (a plain failure), not an answer to a foreign ancestor.
  const chain = Array.isArray(c.page?.chain) ? c.page.chain : [];
  const kinds = Array.isArray(c.page?.kinds) ? c.page.kinds : [];
  const foreignInChain = chain.some((/** @type {string} */ host) => host !== chain[0]) || kinds.some((/** @type {string} */ k) => String(k).startsWith("sandbox"));
  // Whatever route the case expects (browser, none or any): a Ferret window for such a chain is never allowed (UK105 d).
  if (provider === "ferret" && c.expected.route !== "ferret" && o.windowShown && foreignInChain && (ids.has("response-to-foreign-ancestor") || ids.has("response-to-other-frame"))) out.push("response-to-foreign-ancestor");
  return out;
}

/**
 * The vault's state, the sync's status and the passkey scripts' registration, read in the extension's tab (the session comes back).
 * @param {import("./driver.mjs").Session} session @param {string} extTab
 */
async function extensionState(session, extTab) {
  const back = await session.windowHandle().catch(() => null);
  await session.switchTo(extTab);
  try {
    const state = /** @type {any} */ (await ask(session, "state", {}))?.state;
    const sync = /** @type {any} */ (await ask(session, "sync_state", {}));
    const scripts = await session.content(async () => (await browser.scripting.getRegisteredContentScripts({ ids: ["ferret-passkey-main", "ferret-passkey-bridge"] })).length);
    return { state, sync: `${sync?.running}/${sync?.status}/${sync?.live}`, scripts };
  } finally {
    if (back) await session.switchTo(back).catch(() => {});
  }
}

/**
 * Runs a set in one Firefox of one channel and writes the report.
 * @param {{ channel: "release" | "esr", manifest: "mv3" | "mv2", set: "fixtures" | "adversarial" | "holdout" | "demo", grep?: string, provider?: "stub" | "ferret", outDir: string, log?: (line: string) => void }} o
 *   With BRIDGE_ON, `throughBridge` in the answer is the number of requests that went through the passkey bridge.
 */
export async function runSet({ channel, manifest, set, grep = "", provider = "stub", outDir, log = () => {} }) {
  /** The requests that went through the bridge (BRIDGE_ON), or null. @type {number | null} */
  let throughBridge = null;
  const { cases, problems } = selectCases(set, grep);
  if (problems.length) throw new Error(`the cases of ${set} have problems: ${problems.join("; ")}`);
  /** @type {Map<string, import("./passkeyCases.mjs").CaseResult>} */
  const results = new Map();
  /** @type {import("./driver.mjs").Session | undefined} */
  let session;
  /** The second profile of the sync cases, once one needed it. @type {import("./passkeyDrive.mjs").Profile | null} */
  let second = null;
  try {
    const runnable = provider === "ferret" || cases.some((c) => c.set !== "demo" && c.needs !== "provider" && appliesTo(c, manifest));
    if (runnable) session = await launchMatrixBrowser({ channel, manifest });
    /** @type {import("./passkeyDrive.mjs").DriveContext | null} */
    let drive = null;
    if (session && provider === "ferret") {
      const withPrf = cases.some((c) => (c.actions ?? []).some((/** @type {any} */ a) => a.do === "verify-prf"));
      const { tab, account } = await turnOnFerret(session, channel, { prf: withPrf });
      const s = session;
      drive = {
        channel,
        manifest,
        account,
        a: { name: "a", session: s, extTab: tab, pageTab: null },
        b: async () => {
          second ??= await secondProfile({ channel, manifest });
          return second;
        },
        prf: async () => withPrf,
        pinSet: { value: false },
      };
    }
    const bridgeTab = session && BRIDGE_ON && provider === "stub" ? await turnOnPasskeyScripts(session) : null;
    let lastState = "";
    for (const c of cases) {
      if (session && provider === "ferret") {
        // A tab of its own for each case: Ferret's calm period (several requests of a tab that ended without an answer) is per
        // tab, and the cases that end without an answer on purpose must not change how the next case is shown.
        const old = await session.windowHandle();
        const fresh = await session.newTab();
        await session.switchTo(old);
        if (old !== drive?.a.extTab) await session.closeTab();
        await session.switchTo(fresh);
        if (drive) drive.a.pageTab = fresh;
      }
      const r = session ? await runCase(session, c, { channel, provider, drive, manifest }) : await runCase(/** @type {any} */ (undefined), c, { channel, provider, manifest });
      if (session && drive) {
        // What the extension says of itself after the case (a change is logged: a case that left it locked, offline or signed out
        // would change what every later case sees).
        const now = await extensionState(session, drive.a.extTab).catch((e) => ({ error: String(e).slice(0, 120) }));
        const text = JSON.stringify(now);
        if (text !== lastState) log(`${set} ${c.id}: the extension after the case: ${text}`);
        lastState = text;
      }
      results.set(c.id, r);
      const failing = r.observed?.reports?.find((/** @type {any} */ x) => x.kind === "step" && !x.ok);
      log(`${set} ${c.id}: ${r.status === "ran" ? JSON.stringify({ ceremony: r.observed?.ceremony, error: r.observed?.error, route: r.observed?.route, ...(failing ? { step: failing.step, message: failing.error?.message } : {}), ...(r.observed?.problems?.length ? { problems: r.observed.problems } : {}), ...(/** @type {any} */ (r.observed)?.windowsAtEnd?.length ? { windowsAtEnd: /** @type {any} */ (r.observed).windowsAtEnd } : {}) }) : `${r.status === "not-applicable" ? "not applicable" : "not run"} (${r.reason})`}`);
      // The case's tab may be gone (a case that closes it): the next case starts from a tab that is there.
      if (session && drive && !(await session.windowHandles()).includes(await session.windowHandle().catch(() => ""))) {
        const handles = await session.windowHandles();
        await session.switchTo(handles.find((h) => h !== drive?.a.extTab) ?? handles[0]);
      }
    }
    if (session && bridgeTab !== null) throughBridge = await bridgeRequests(session, bridgeTab);
  } finally {
    if (second) await /** @type {import("./passkeyDrive.mjs").Profile} */ (second).session.quit().catch(() => {});
    if (session) await session.quit();
  }
  // A run of some cases (--grep) is not a run of the set: its gate is never met.
  const matrix = computeMatrix(cases, results, provider, grep === "");
  writeReport(outDir, matrix, { channel, manifest, set });
  return { cases, results, matrix, throughBridge };
}
