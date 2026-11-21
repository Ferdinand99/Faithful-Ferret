// Helpers of the specs that run against the end-to-end stack (run by
// `scripts/lanbox-ext.sh e2e`): the run's account, made once in the web vault
// and kept in a file for the next channel's process, the pacing of sign-in
// starts under the server's limit, and the steps of the web vault's and the
// extension's pages. Not a spec (run.sh picks up *.spec.mjs only).
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { EXTENSION_ORIGIN, TEST_ADDON_ID, launch, readHosts } from "./harness.mjs";

export const SIGNIN_URL = `${EXTENSION_ORIGIN}/pages/signin.html`;
export const POPUP_URL = `${EXTENSION_ORIGIN}/pages/popup.html`;
export const [VAULT_HOST, ADMIN_HOST] = /** @type {[string, string]} */ (readHosts().e2e);
export const VAULT_URL = `https://${VAULT_HOST}`;
export const ADMIN_URL = `https://${ADMIN_HOST}`;
/** What the server calls the extension in the list of devices (the runner is Linux). */
export const DEVICE_NAME = "Ferret for Firefox (Linux)";
/** Argon2id runs for seconds in Firefox. */
export const SLOW = 120_000;

// ------------------------------------------------------------ the run's account

const ACCOUNT_FILE = join(tmpdir(), "ferret-ext-e2e-account.json");
const STARTS_FILE = join(tmpdir(), "ferret-ext-e2e-starts.json");

/** @typedef {{ email: string, password: string, secretKey: string, qrText: string }} Account */

/** @returns {Account | null} */
export function knownAccount() {
  return existsSync(ACCOUNT_FILE) ? JSON.parse(readFileSync(ACCOUNT_FILE, "utf8")) : null;
}

// The server allows 5 sign-in starts per account and address per minute, and 10 per address.
const PACE_WINDOW_MS = 62_000;
const PACE_MAX = 4;

/** Waits until one more sign-in start fits under the server's limit, and counts it. */
export async function pace() {
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
export function helpers(session) {
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
export async function webVaultAccount(session, channel) {
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
export async function extensionSignIn(session, fields) {
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


/** @param {string} channel */
export async function start(channel) {
  assert.ok(process.env.FERRET_E2E_CA_PEM, "FERRET_E2E_CA_PEM is not set (run through scripts/lanbox-ext.sh e2e)");
  const session = await launch({ channel });
  await session.waitFor(() => session.addonInfo(TEST_ADDON_ID), 30_000, "the add-on");
  return session;
}
