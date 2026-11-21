// The sign-in of the extension against the end-to-end stack (run by
// `scripts/lanbox-ext.sh e2e`): a real server, the real core and a real Firefox.
//
// The first channel makes the stack's first account the way a person does (the
// setup link of the admin origin, the web vault's form, the emergency sheet)
// and keeps its e-mail, master password, secret key and sheet text in a file
// for the next channel's process. The stack must be fresh (`e2e-up`).
//
// The server limits sign-in starts per account and address, and an unlock of
// the extension starts one too, so the tests pace their starts (as the web
// vault's scenarios do) instead of turning the limit off.
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import { EXTENSION_ORIGIN, TEST_ADDON_ID, channels, launch, openBridge, readHosts, stopFixtures } from "./harness.mjs";

after(() => stopFixtures());

const SIGNIN_URL = `${EXTENSION_ORIGIN}/pages/signin.html`;
const POPUP_URL = `${EXTENSION_ORIGIN}/pages/popup.html`;
const [VAULT_HOST, ADMIN_HOST] = /** @type {[string, string]} */ (readHosts().e2e);
const VAULT_URL = `https://${VAULT_HOST}`;
const ADMIN_URL = `https://${ADMIN_HOST}`;
/** What the server calls the extension in the list of devices (the runner is Linux). */
const DEVICE_NAME = "Ferret for Firefox (Linux)";
/** Argon2id runs for seconds in Firefox. */
const SLOW = 120_000;

// ------------------------------------------------------------ the run's account

const ACCOUNT_FILE = join(tmpdir(), "ferret-ext-e2e-account.json");
const STARTS_FILE = join(tmpdir(), "ferret-ext-e2e-starts.json");

/** @typedef {{ email: string, password: string, secretKey: string, qrText: string }} Account */

/** @returns {Account | null} */
function knownAccount() {
  return existsSync(ACCOUNT_FILE) ? JSON.parse(readFileSync(ACCOUNT_FILE, "utf8")) : null;
}

// The server allows 5 sign-in starts per account and address per minute, and 10 per address.
const PACE_WINDOW_MS = 62_000;
const PACE_MAX = 4;

/** Waits until one more sign-in start fits under the server's limit, and counts it. */
async function pace() {
  for (;;) {
    /** @type {number[]} */
    const starts = (existsSync(STARTS_FILE) ? JSON.parse(readFileSync(STARTS_FILE, "utf8")) : []).filter((/** @type {number} */ at) => Date.now() - at < PACE_WINDOW_MS);
    if (starts.length < PACE_MAX) {
      starts.push(Date.now());
      writeFileSync(STARTS_FILE, JSON.stringify(starts));
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, starts[0] + PACE_WINDOW_MS - Date.now() + 100));
  }
}

// ------------------------------------------------------------ driving pages

/** @param {import("./driver.mjs").Session} session */
function helpers(session) {
  /** @param {string} css */
  const visible = (css) =>
    session.content((/** @type {string} */ selector) => {
      const node = document.querySelector(selector);
      return node !== null && node.closest("[hidden]") === null && node.getClientRects().length > 0;
    }, css);
  const page = {
    visible,
    /** @param {string} css @param {number} [ms] */
    waitVisible: (css, ms = 20_000) => session.waitFor(() => visible(css), ms, css),
    /** The first of `choices` that becomes visible. @param {string[]} choices @param {number} [ms] */
    waitAny: (choices, ms = SLOW) =>
      session.waitFor(async () => {
        for (const css of choices) if (await visible(css)) return css;
        return null;
      }, ms, choices.join(" or ")),
    /** @param {string} css */
    text: (css) => session.content((/** @type {string} */ selector) => (document.querySelector(selector)?.textContent ?? "").trim(), css),
    /** @param {string} css */
    click: async (css) => {
      const [el] = await session.findAll(css);
      assert.ok(el, css);
      await session.click(el);
    },
    /** @param {string} css @param {string} value */
    type: async (css, value) => {
      const [el] = await session.findAll(css);
      assert.ok(el, css);
      await session.type(el, value);
    },
    /** Sets a long value at once (the text of a QR code), as a paste does. @param {string} css @param {string} value */
    paste: (css, value) =>
      session.content((/** @type {string} */ selector, /** @type {string} */ text) => {
        const node = /** @type {HTMLTextAreaElement} */ (document.querySelector(selector));
        node.value = text;
        node.dispatchEvent(new Event("input", { bubbles: true }));
      }, css, value),
    /** A page of the extension has built itself. */
    ready: () => session.waitFor(() => session.content(() => document.body?.dataset.ready === "1"), 20_000, "the page"),
  };
  return page;
}

/**
 * Makes the stack's first account in the web vault (in this browser, which stays signed in there), or, when an
 * earlier channel made it, signs in to the web vault with it.
 * @param {import("./driver.mjs").Session} session
 * @param {string} channel
 * @returns {Promise<Account>}
 */
async function webVaultAccount(session, channel) {
  const page = helpers(session);
  const known = knownAccount();
  if (known === null) {
    const token = process.env.FERRET_E2E_SETUP_TOKEN;
    assert.ok(token, "FERRET_E2E_SETUP_TOKEN is not set (run through scripts/lanbox-ext.sh e2e on a fresh stack)");
    const tag = randomBytes(5).toString("hex");
    const account = { email: `ext-${tag}@e2e.example.test`, password: `Tr0ub4dor-${tag}-horse-staple`, secretKey: "", qrText: "" };
    await session.navigate(`${ADMIN_URL}/setup?token=${token}`);
    await page.waitVisible('[data-role="setup-page"]');
    await page.type('[data-role="email"]', account.email);
    await page.type('[data-role="password"]', account.password);
    await page.type('[data-role="password-repeat"]', account.password);
    await page.click('[data-role="setup-form"] [data-role="submit"]');
    await page.waitVisible('[data-role="sheet-page"]', SLOW);
    const recoveryKey = await page.text('[data-role="sheet-recovery-key"]');
    account.secretKey = await page.text('[data-role="sheet-secret-key"]');
    account.qrText = await page.text('[data-role="sheet-qr"]');
    assert.ok(recoveryKey.length > 10 && account.secretKey.length > 10 && account.qrText.startsWith("ferret-setup:"), "the sheet");
    await page.type('[data-role="rk-typed"]', recoveryKey);
    await page.type('[data-role="sk-typed"]', account.secretKey);
    await page.click('[data-role="confirm"]');
    await page.waitVisible('[data-role="open-vault"]', SLOW);
    writeFileSync(ACCOUNT_FILE, JSON.stringify(account));
    await page.click('[data-role="open-vault"]');
    await page.waitVisible('[data-role="list"]', SLOW);
    return account;
  }
  await session.navigate(`${VAULT_URL}/vault/login`);
  await page.waitVisible('[data-role="credentials"]');
  await page.type('[data-role="email"]', known.email);
  await page.click('[data-role="password"]');
  await page.type('[data-role="password"]', known.password);
  await page.waitVisible('[data-role="sk-question"]');
  await page.click('[data-role="sk-yes"]');
  await page.type('[data-role="sk-code"]', known.secretKey);
  await pace();
  await page.click('[data-role="credentials"] [data-role="submit"]');
  await page.waitVisible('[data-role="list"]', SLOW).catch(async (error) => {
    throw new Error(`${channel}: the web vault sign-in did not open the list (${await page.text('[data-role="error"]')}): ${error}`);
  });
  return known;
}

/**
 * Signs in in the extension's sign-in tab, from its first step.
 * @param {import("./driver.mjs").Session} session
 * @param {{ email: string, password: string, secretKey?: string, qrText?: string }} fields
 * @returns {Promise<{ ok: boolean, text: string }>} `text`: what the page says
 */
async function extensionSignIn(session, fields) {
  const page = helpers(session);
  await session.navigate(SIGNIN_URL);
  await page.ready();
  await page.waitVisible('[data-role="server"]');
  await page.type('[data-role="server"]', VAULT_URL);
  await page.click('[data-role="server-submit"]');
  await page.waitVisible('[data-role="grant"]');
  assert.equal(await page.text('[data-role="server-checked"] [data-role="server-host"]'), VAULT_HOST);
  await page.click('[data-role="grant"]');
  await page.waitVisible('[data-role="credentials"]');
  await page.type('[data-role="email"]', fields.email);
  await page.type('[data-role="password"]', fields.password);
  await page.click('[data-role="sk-yes"]');
  await page.type('[data-role="sk-code"]', fields.secretKey ?? "");
  if (fields.qrText) await page.paste('[data-role="qr-text"]', fields.qrText);
  await pace();
  await page.click('[data-role="submit"]');
  const shown = await page.waitAny(['[data-role="signed-in"]', '[data-role="credentials"] [data-role="error"]']);
  if (shown === '[data-role="signed-in"]') return { ok: true, text: await page.text('[data-role="account-line"]') };
  return { ok: false, text: await page.text('[data-role="credentials"] [data-role="error"]') };
}

/** The server key in a setup text as hex. @param {string} text */
function keyHex(text) {
  const value = new URLSearchParams(text.slice(text.indexOf("?") + 1)).get("o");
  assert.ok(value, "the setup text has a server key");
  return /^[0-9a-f]{64}$/i.test(value) ? value.toLowerCase() : Buffer.from(value, "base64url").toString("hex");
}

/**
 * What the extension has pinned (read through the test bridge, a page of the same origin).
 * @param {import("./driver.mjs").Session} session
 * @returns {Promise<Array<{ server_public_key: string }>>}
 */
async function pinnedRecords(session) {
  await openBridge(session);
  return session.content(() => new Promise((resolve, reject) => {
    const open = indexedDB.open("ferret");
    // Never make the database here: the background makes it with its own version and stores.
    open.onupgradeneeded = () => open.transaction?.abort();
    open.onerror = () => (open.error?.name === "AbortError" ? resolve([]) : reject(open.error));
    open.onsuccess = () => {
      const db = open.result;
      if (!db.objectStoreNames.contains("pinned")) {
        db.close();
        resolve([]);
        return;
      }
      const all = db.transaction(["pinned"], "readonly").objectStore("pinned").getAll();
      all.onerror = () => reject(all.error);
      all.onsuccess = () => {
        const hex = (/** @type {Uint8Array} */ b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
        resolve(all.result.map((row) => ({ server_public_key: hex(row.record.server_public_key) })));
        db.close();
      };
    };
  }));
}

/** @param {string} channel */
async function start(channel) {
  assert.ok(process.env.FERRET_E2E_CA_PEM, "FERRET_E2E_CA_PEM is not set (run through scripts/lanbox-ext.sh e2e)");
  const session = await launch({ channel });
  await session.waitFor(() => session.addonInfo(TEST_ADDON_ID), 30_000, "the add-on");
  return session;
}

// ------------------------------------------------------------------- tests

test("sign_in_against_the_e2e_stack_opens_the_vault_and_unlock_after_lock_needs_only_the_password", async () => {
  for (const channel of channels()) {
    const session = await start(channel);
    try {
      const account = await webVaultAccount(session, channel);
      // Without the sheet: the first sign-in trusts the server the first time.
      const signedIn = await extensionSignIn(session, { ...account, qrText: "" });
      assert.equal(signedIn.ok, true, `${channel}: ${signedIn.text}`);
      assert.ok(signedIn.text.includes(account.email) && signedIn.text.includes(VAULT_HOST), `${channel}: ${signedIn.text}`);

      // The popup: the open vault, with the lock button in the header.
      const page = helpers(session);
      await session.navigate(POPUP_URL);
      await page.ready();
      await page.waitVisible('[data-role="unlocked-view"]');
      assert.equal(await page.visible('[data-role="lock"]'), true, channel);
      assert.equal(await page.text('[data-role="account"]'), account.email);
      assert.equal(await page.text('[data-role="server-host"]'), VAULT_HOST);

      // The lock button locks, and the popup shows the unlock view: the master password only.
      await page.click('[data-role="lock"]');
      await page.waitVisible('[data-role="locked-view"]');
      assert.equal(await page.visible('[data-role="lock"]'), false, `${channel}: no lock button on a locked vault`);
      assert.equal(await page.visible('[data-role="password"]'), true, channel);
      for (const role of ["email", "sk-code", "qr-text", "server"]) assert.equal(await page.visible(`[data-role="${role}"]`), false, `${channel}: ${role}`);

      // A wrong password is refused and leaves it locked; the right one opens it.
      await page.type('[data-role="password"]', `${account.password}-wrong`);
      await pace();
      await page.click('[data-role="unlock"]');
      await page.waitVisible('[data-role="locked-view"] [data-role="error"]', SLOW);
      assert.match(await page.text('[data-role="error"]'), /could not be opened/i, channel);
      await page.type('[data-role="password"]', account.password);
      await pace();
      await page.click('[data-role="unlock"]');
      await page.waitVisible('[data-role="unlocked-view"]', SLOW);
      assert.equal(await page.text('[data-role="account"]'), account.email);

      // A reload of the popup asks the background: still open.
      await session.navigate(POPUP_URL);
      await page.ready();
      await page.waitVisible('[data-role="unlocked-view"]');
    } finally {
      await session.quit();
    }
  }
});

test("the_device_appears_with_the_extension_name", async () => {
  for (const channel of channels()) {
    const session = await start(channel);
    try {
      const account = await webVaultAccount(session, channel);
      const vaultTab = await session.windowHandle();
      const extensionTab = await session.newTab();
      await session.switchTo(extensionTab);
      const signedIn = await extensionSignIn(session, account);
      assert.equal(signedIn.ok, true, `${channel}: ${signedIn.text}`);
      await session.switchTo(vaultTab);
      // The web vault's list of devices (its own session cookie).
      const listed = await session.content(async () => {
        const response = await fetch("/api/auth/devices", { headers: { "Ferret-Protocol": "1" } });
        return { status: response.status, body: await response.text() };
      });
      assert.equal(listed.status, 200, `${channel}: ${listed.body}`);
      const devices = JSON.parse(listed.body).devices.filter((/** @type {any} */ d) => d.kind === "device");
      assert.ok(devices.some((/** @type {any} */ d) => d.name === DEVICE_NAME && d.platform === "linux"), `${channel}: ${JSON.stringify(devices)}`);
    } finally {
      await session.quit();
    }
  }
});

test("wrong_password_and_unknown_email_give_the_same_message", async () => {
  for (const channel of channels()) {
    const session = await start(channel);
    try {
      const account = knownAccount() ?? (await webVaultAccount(session, channel));
      const wrong = await extensionSignIn(session, { ...account, password: `${account.password}-wrong` });
      const unknown = await extensionSignIn(session, { ...account, email: `nobody-${randomBytes(4).toString("hex")}@e2e.example.test` });
      assert.equal(wrong.ok, false, channel);
      assert.equal(unknown.ok, false, channel);
      assert.equal(unknown.text, wrong.text, `${channel}: the two refusals read the same`);
      assert.match(wrong.text, /could not be opened/i, channel);
    } finally {
      await session.quit();
    }
  }
});

test("a_pasted_sheet_qr_pins_the_server_key_and_a_different_server_key_is_refused", async () => {
  for (const channel of channels()) {
    const session = await start(channel);
    try {
      const account = knownAccount() ?? (await webVaultAccount(session, channel));
      const original = keyHex(account.qrText);
      const flipped = (original[0] === "0" ? "1" : "0") + original.slice(1);
      const forged = account.qrText.replace(/([?&]o=)[^&]+/, (_, lead) => `${lead}${flipped}`);
      assert.notEqual(forged, account.qrText);

      // A sheet with another server key: refused, and nothing is pinned.
      const refused = await extensionSignIn(session, { ...account, qrText: forged });
      assert.equal(refused.ok, false, channel);
      assert.match(refused.text, /different identity than the one on your emergency sheet/i, channel);
      assert.deepEqual(await pinnedRecords(session), [], `${channel}: nothing was pinned`);

      // The real sheet: the sign-in pins the server key the sheet states.
      const signedIn = await extensionSignIn(session, account);
      assert.equal(signedIn.ok, true, `${channel}: ${signedIn.text}`);
      const pinned = await pinnedRecords(session);
      assert.equal(pinned.length, 1, channel);
      assert.equal(pinned[0].server_public_key, original, `${channel}: the pinned server key is the sheet's`);
    } finally {
      await session.quit();
    }
  }
});
