// Helpers for the scenarios that run against the end-to-end stack (the real
// server over https on the test host names). They drive the page the way a person
// does: through the fields and buttons, never through the page's own modules, with
// two exceptions that are named where they are used (reading what the browser
// keeps, and asking the running page for facts that no screen shows).
//
// Every context made here is watched: security policy violations, uncaught
// errors and the traffic that crosses the wire are collected, and a test fails
// at its end when the policy was violated. The same traffic is searched for the
// secrets of the run by `08-plaintext.spec.mjs`.
import { expect, test as base } from "@playwright/test";
import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";

export { expect };

export const vaultUrl = process.env.FERRET_E2E_VAULT_URL ?? "";
export const adminUrl = process.env.FERRET_E2E_ADMIN_URL ?? "";
export const setupToken = process.env.FERRET_E2E_SETUP_TOKEN ?? "";

/** Where the runner collects what the host script needs after a phase. */
export const outDir = process.env.FERRET_E2E_OUT ?? "test-results/out";

// ------------------------------------------------------------ the run's data

const tag = randomBytes(5).toString("hex");

/**
 * The secrets of this run. They are made up for the run and are searched for in
 * the traffic and in the database afterwards.
 */
export const secrets = {
  email: `owner-${tag}@e2e.example.test`,
  password: `Tr0ub4dor-${tag}-horse-staple`,
  // Filled in by the setup scenario from the emergency sheet.
  secretKey: "",
  recoveryKey: "",
  itemTitle: `Bank-${tag}-title`,
  itemUsername: `user-${tag}-name`,
  itemPassword: `Pw-${tag}-s3cret!`,
  itemNotes: `Notes-${tag}-private`,
  itemUrl: `https://bank-${tag}.example.test/login`,
};

// A test that fails ends the worker, and the next test runs in a new one: the
// run's values are kept in a file so that the new worker has the same account.
const keep = `${outDir}/secrets.state`;
if (existsSync(keep)) Object.assign(secrets, JSON.parse(readFileSync(keep, "utf8")));
else remember();

/** Writes the run's values where a new worker finds them. */
export function remember() {
  mkdirSync(outDir, { recursive: true });
  writeFileSync(keep, JSON.stringify(secrets));
}

// The server limits sign-in starts to 5 per account and address per minute (and
// 10 per address). The scenarios sign in a lot, so they pace themselves to stay
// under it instead of turning the limit off: the limit is part of what is tested.
const PACE_WINDOW_MS = 62_000;
const PACE_MAX = 4;
const starts = /** @type {number[]} */ ([]);

/** Waits until one more sign-in start fits under the server's limit. */
export async function pace() {
  for (;;) {
    const now = Date.now();
    while (starts.length > 0 && now - starts[0] > PACE_WINDOW_MS) starts.shift();
    if (starts.length < PACE_MAX) return;
    await new Promise((resolve) => setTimeout(resolve, starts[0] + PACE_WINDOW_MS - now + 50));
  }
}

/** Every context that was made, for the whole-run check at the end. */
const watched = [];

/** What the run collected (shared by all tests of the worker). */
export const findings = {
  violations: /** @type {string[]} */ ([]),
  pageErrors: /** @type {string[]} */ ([]),
  consoleErrors: /** @type {string[]} */ ([]),
  pages: 0,
  /** Everything sent to the servers and received from them, as text. */
  traffic: /** @type {string[]} */ ([]),
};

// ------------------------------------------------------------- watching

/**
 * The script that watches one page for policy violations. Every `securitypolicyviolation`
 * event is passed on as a violation; nothing is set apart. (Until Playwright 1.65, WebKit
 * reported a `style-src-attr` violation for the inner style of each of its own `<select>`
 * elements, and these reports were set apart under a canary that failed when WebKit stopped.
 * It stopped, so the exception is gone.)
 */
const watchScript = () => `
  (() => {
    document.addEventListener("securitypolicyviolation", (e) => {
      try {
        window.__e2eViolation(e.violatedDirective + " " + e.blockedURI + " " + (e.sample || "") + "(target " + (e.target && e.target.nodeName) + ", at " + (e.sourceFile || "?") + ":" + e.lineNumber + ", page " + location.href + ")");
      } catch {}
    });
  })();
`;

/**
 * Watches a context: policy violations, uncaught errors, console errors, and the
 * text of the traffic. Idempotent.
 * @param {import("@playwright/test").BrowserContext} context
 */
export async function watch(context) {
  if (watched.includes(context)) return context;
  watched.push(context);
  await context.exposeFunction("__e2eViolation", (/** @type {string} */ text) => findings.violations.push(text));
  await context.addInitScript(watchScript());
  const onPage = (/** @type {import("@playwright/test").Page} */ page) => {
    findings.pages += 1;
    page.on("pageerror", (e) => findings.pageErrors.push(String(e)));
    page.on("console", (m) => {
      if (m.type() !== "error") return;
      const text = m.text();
      // A refused request (a sign-in that fails on purpose, a session that ended)
      // is logged by the browser itself; it is not an error of the page.
      if (/^Failed to load resource/.test(text)) return;
      // WebKit does not know the `interactive-widget` viewport key of the page's meta tag and says so.
      if (/^Viewport argument key "interactive-widget" not recognized/.test(text)) return;
      findings.consoleErrors.push(text);
    });
  };
  context.on("page", onPage);
  for (const page of context.pages()) onPage(page);
  context.on("request", (request) => {
    if (request.url().includes("/api/auth/opaque/login/start")) starts.push(Date.now());
    const body = request.postData();
    findings.traffic.push(`${request.method()} ${request.url()}\n${JSON.stringify(request.headers())}\n${body ?? ""}`);
  });
  context.on("response", async (response) => {
    try {
      const type = response.headers()["content-type"] ?? "";
      if (/json|text/.test(type)) findings.traffic.push(`${response.status()} ${response.url()}\n${await response.text()}`);
    } catch {
      // A response that is gone (the page moved on) has no body to keep.
    }
  });
  return context;
}

/**
 * A context that is watched, in English, on the stack's CA.
 * @param {import("@playwright/test").Browser} browser
 * @param {import("@playwright/test").BrowserContextOptions} [options]
 */
export async function freshContext(browser, options = {}) {
  const context = await browser.newContext({ locale: "en-US", ignoreHTTPSErrors: browser.browserType().name() === "firefox", ...options });
  await watch(context);
  return context;
}

/** The tests use this `test`: the default context is watched, and a violation fails the test. */
export const test = base.extend({
  context: async ({ context }, use) => {
    await watch(context);
    const before = findings.violations.length;
    await use(context);
    expect(findings.violations.slice(before), "security policy violations during the test").toEqual([]);
  },
});

// -------------------------------------------------- recording the Worker

/**
 * Makes the page remember every Worker it starts and whether it was ended, so a
 * test can see that locking ends the worker that holds the keys. Call before the
 * first navigation of the page.
 * @param {import("@playwright/test").Page} page
 */
export async function recordWorkers(page) {
  await page.addInitScript(() => {
    const W = window.Worker;
    /** @type {{ url: string, ended: boolean }[]} */
    const list = [];
    // @ts-ignore
    window.__e2eWorkers = list;
    // @ts-ignore
    window.Worker = class extends W {
      constructor(url, options) {
        super(url, options);
        const entry = { url: String(url), ended: false };
        list.push(entry);
        this.__entry = entry;
      }
      terminate() {
        this.__entry.ended = true;
        super.terminate();
      }
    };
  });
}

/** @param {import("@playwright/test").Page} page */
export const workers = (page) => page.evaluate(() => /** @type {any} */ (window).__e2eWorkers ?? []);

// ----------------------------------------------------------- the pages

/**
 * What a screen shows: its text, its markup and the values typed into its fields.
 * @param {import("@playwright/test").Page} page
 */
export const bodyText = (page) =>
  page.evaluate(
    () =>
      document.body.innerText +
      "\n" +
      document.body.innerHTML +
      "\n" +
      Array.from(document.querySelectorAll("input, textarea"), (i) => /** @type {HTMLInputElement} */ (i).value).join("\n"),
  );

/**
 * Waits until the vault is up (the page's boot has finished).
 * @param {import("@playwright/test").Page} page
 */
export async function booted(page) {
  await page.evaluate(async () => {
    const { ready } = await import("/app/boot.mjs");
    await ready;
  });
}

/**
 * Facts from the running page that no screen shows: whether a sync engine
 * exists, and how many items it holds. This is the test hook for "nothing is in
 * memory after a lock".
 * @param {import("@playwright/test").Page} page
 * @returns {Promise<{ engine: boolean, items: number }>}
 */
export function memory(page) {
  return page.evaluate(async () => {
    const { ready } = await import("/app/boot.mjs");
    const { services } = await ready;
    const engine = services.sync.current();
    return { engine: engine !== null, items: engine ? engine.list().length : 0 };
  });
}

/** Argon2id runs for seconds in the browser (more in WebKit and Firefox). */
export const SLOW = 90_000;

// ------------------------------------------------------------ setup

/**
 * The setup form, filled in and sent. Returns after the emergency sheet shows.
 * @param {import("@playwright/test").Page} page
 * @param {{ token?: string | null, useSecretKey?: boolean }} [options] `token: null` leaves the token field to the page
 */
export async function fillSetup(page, { token = setupToken, useSecretKey = true } = {}) {
  await page.locator('[data-role="email"]').fill(secrets.email);
  await page.locator('[data-role="password"]').fill(secrets.password);
  await page.locator('[data-role="password-repeat"]').fill(secrets.password);
  if (!useSecretKey) await page.locator('[data-role="use-sk"]').uncheck();
  if (token !== null) {
    const field = page.locator('[data-role="setup-token"]');
    if (await field.count()) await field.fill(token);
  }
  await page.locator('[data-role="setup-form"] [data-role="submit"]').click();
  await expect(page.locator('[data-role="sheet-page"]')).toBeVisible({ timeout: SLOW });
}

/**
 * Reads the keys off the emergency sheet.
 * @param {import("@playwright/test").Page} page
 */
export async function readSheet(page) {
  const text = async (/** @type {string} */ role) => (await page.locator(`[data-role="${role}"]`).textContent()) ?? "";
  const recoveryKey = (await text("sheet-recovery-key")).trim();
  const hasSecretKey = (await page.locator('[data-role="sheet-secret-key"]').count()) > 0;
  const secretKey = hasSecretKey ? (await text("sheet-secret-key")).trim() : "";
  return { recoveryKey, secretKey };
}

/**
 * Types the keys back and waits for the done page.
 * @param {import("@playwright/test").Page} page
 * @param {{ recoveryKey: string, secretKey: string }} keys
 */
export async function confirmSheet(page, keys) {
  await page.locator('[data-role="rk-typed"]').fill(keys.recoveryKey);
  if (keys.secretKey !== "") await page.locator('[data-role="sk-typed"]').fill(keys.secretKey);
  await page.locator('[data-role="confirm"]').click();
  await expect(page.locator('[data-role="open-vault"]')).toBeVisible({ timeout: SLOW });
}

/**
 * Makes the first account by the whole path an owner takes: the setup link on the
 * admin origin, the form, the sheet, the typed-back keys. Returns the item list.
 * The keys are kept in `secrets`.
 * @param {import("@playwright/test").Page} page
 */
export async function setUpAccount(page) {
  await page.goto(`${adminUrl}/setup?token=${setupToken}`);
  await expect(page.locator('[data-role="setup-page"]')).toBeVisible({ timeout: 20_000 });
  await fillSetup(page, { token: null });
  const keys = await readSheet(page);
  secrets.recoveryKey = keys.recoveryKey;
  secrets.secretKey = keys.secretKey;
  await confirmSheet(page, keys);
  await page.locator('[data-role="open-vault"]').click();
  await expect(page.locator('[data-role="list"]')).toBeVisible({ timeout: 30_000 });
}

// ------------------------------------------------------------ sign-in

/**
 * Opens the vault again on the unlock screen with a password (waits for the
 * server's limit first: an unlock asks the server too).
 * @param {import("@playwright/test").Page} page
 * @param {string} password
 */
export async function unlockWith(page, password) {
  await page.locator('[data-role="password"]').fill(password);
  await pace();
  await page.locator('[data-role="unlock-form"] [data-role="submit"]').click();
}

/**
 * Signs in on the sign-in page of the vault. A device that does not know the
 * account is asked about the secret key; the answer is yes and the key is typed.
 * @param {import("@playwright/test").Page} page
 * @param {{ remember?: boolean, expectList?: boolean }} [options]
 */
export async function signInOn(page, options = {}) {
  await page.goto(`${vaultUrl}/vault/login`);
  await signInHere(page, options);
}

/**
 * The same, on a sign-in page that is already open (for example the one a
 * hand-over from the admin origin leads to).
 * @param {import("@playwright/test").Page} page
 * @param {{ remember?: boolean, expectList?: boolean }} [options]
 */
export async function signInHere(page, { remember = true, expectList = true } = {}) {
  await expect(page.locator('[data-role="credentials"]')).toBeVisible({ timeout: 20_000 });
  await page.locator('[data-role="email"]').fill(secrets.email);
  await page.locator('[data-role="email"]').blur();
  await page.locator('[data-role="password"]').fill(secrets.password);
  const question = page.locator('[data-role="sk-question"]');
  // The question is shown when this browser has never seen the account.
  await expect.poll(async () => (await question.isVisible()) || (await page.locator('[data-role="sk-remembered"]').isVisible()) || (await page.locator('[data-role="sk-code"]').isVisible()), { timeout: 15_000 }).toBe(true);
  if (await question.isVisible()) {
    await page.locator('[data-role="sk-yes"]').check();
    await page.locator('[data-role="sk-code"]').fill(secrets.secretKey);
    const keep = page.locator('[data-role="remember"]');
    if (await keep.isVisible()) {
      if (remember) await keep.check();
      else await keep.uncheck();
    }
  } else if (await page.locator('[data-role="sk-code"]').isVisible()) {
    await page.locator('[data-role="sk-code"]').fill(secrets.secretKey);
  }
  // The server's limit counts the starts of earlier phases too, which this process does not know of: when it says so, the
  // wait it names is taken and the form is sent again.
  const limit = page.locator('[data-role="error"]').filter({ hasText: /Too many attempts/ });
  for (let tries = 0; ; tries += 1) {
    await pace();
    await page.locator('[data-role="credentials"] [data-role="submit"]').click();
    if (!expectList) return;
    // The message of the try that was refused goes when the next one starts.
    if (tries > 0) await limit.first().waitFor({ state: "hidden", timeout: 15_000 }).catch(() => {});
    const outcome = await Promise.race([
      page.locator('[data-role="list"]').waitFor({ timeout: SLOW }).then(() => "list", () => "timeout"),
      limit.waitFor({ timeout: SLOW }).then(() => "limited", () => "timeout"),
    ]);
    if (outcome !== "limited" || tries >= 5) break;
    const named = /in (\d+) second/.exec((await limit.first().textContent()) ?? "");
    await page.waitForTimeout((named ? Number(named[1]) : 20) * 1000 + 2_000);
  }
  await expect(page.locator('[data-role="list"]')).toBeVisible({ timeout: 5_000 });
}

/**
 * Opens the sign-in page of a signed-in browser and signs out.
 * @param {import("@playwright/test").Page} page
 */
export async function signOutOn(page) {
  await page.goto(`${vaultUrl}/vault/login`);
  await page.locator('[data-role="sign-out"]').click();
  // The sign-in form (with the e-mail field) only shows when the server session is over; the
  // unlock form of a signed-in page has no e-mail field.
  await expect(page.locator('[data-role="email"]')).toBeVisible({ timeout: 20_000 });
}

// -------------------------------------------------------------- items

/**
 * Makes a login item through the form. Returns once the item page shows.
 * @param {import("@playwright/test").Page} page
 * @param {{ name: string, username?: string, password?: string, url?: string, notes?: string }} item
 */
export async function createItem(page, item) {
  await page.locator('[data-role="nav-new"]').click();
  await expect(page.locator('[data-role="edit-form"]')).toBeVisible();
  await page.locator('[data-role="name"]').fill(item.name);
  if (item.username) await page.locator('[data-role="username"]').fill(item.username);
  if (item.password) await page.locator('[data-role="password"]').fill(item.password);
  if (item.url) await page.locator('[data-role="url"]').fill(item.url);
  if (item.notes) await page.locator('[data-role="notes"]').fill(item.notes);
  await page.locator('[data-role="save"]').click();
  await expect(page.locator('[data-role="item"] h1')).toContainText(item.name, { timeout: 30_000 });
}

/** The list rows with this name. @param {import("@playwright/test").Page} page @param {string} name */
export const rowsNamed = (page, name) => page.locator('[data-role="item"]', { hasText: name });

/**
 * Opens the list and waits for an item to show.
 * @param {import("@playwright/test").Page} page
 */
export async function openList(page) {
  await page.locator('[data-role="nav-items"]').click();
  await expect(page.locator('[data-role="list"]')).toBeVisible();
}

// ------------------------------------------------------------- browser store

/**
 * What the browser keeps for the vault, as plain data: the number of records in
 * each store, and the pinned records with their byte fields as hex. (A test
 * helper that reads IndexedDB; the page does the same thing when it runs.)
 * @param {import("@playwright/test").Page} page
 */
export function readStores(page) {
  return page.evaluate(
    async () => {
      const empty = { count: 0, keys: [], values: [] };
      // Opening a database that does not exist would make it, empty, at version 1.
      if (!(await indexedDB.databases()).some((d) => d.name === "ferret")) {
        return { pinned: empty, rows: empty, outbox: empty, settings: empty, device_secrets: empty };
      }
      return new Promise((resolve, reject) => {
        const open = indexedDB.open("ferret");
        open.onerror = () => reject(open.error);
        open.onsuccess = () => {
          const db = open.result;
          const hex = (/** @type {any} */ v) => {
            if (v instanceof Uint8Array) return Array.from(v, (n) => n.toString(16).padStart(2, "0")).join("");
            if (Array.isArray(v)) return v.map(hex);
            if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, hex(x)]));
            return v;
          };
          const out = {};
          const names = Array.from(db.objectStoreNames);
          const tx = db.transaction(names, "readonly");
          let left = names.length;
          for (const name of names) {
            const all = tx.objectStore(name).getAll();
            const keys = tx.objectStore(name).getAllKeys();
            all.onsuccess = () => {
              keys.onsuccess = () => {
                out[name] = { count: all.result.length, keys: hex(keys.result), values: hex(all.result) };
                if (--left === 0) {
                  db.close();
                  resolve(out);
                }
              };
            };
          }
        };
      });
    },
  );
}

/**
 * Flips the first byte of the server's public key in the pinned record that
 * this browser holds. Returns how many records were changed.
 * @param {import("@playwright/test").Page} page
 */
export function tamperPinnedServerKey(page) {
  return page.evaluate(
    () =>
      new Promise((resolve, reject) => {
        const open = indexedDB.open("ferret");
        open.onerror = () => reject(open.error);
        open.onsuccess = () => {
          const db = open.result;
          const tx = db.transaction("pinned", "readwrite");
          const store = tx.objectStore("pinned");
          const cursor = store.openCursor();
          let changed = 0;
          cursor.onsuccess = () => {
            const c = cursor.result;
            if (!c) return;
            const record = c.value.record;
            if (record.server_public_key instanceof Uint8Array && record.server_public_key.length > 0) {
              const key = new Uint8Array(record.server_public_key);
              key[0] ^= 0xff;
              record.server_public_key = key;
              c.update(c.value);
              changed += 1;
            }
            c.continue();
          };
          tx.oncomplete = () => {
            db.close();
            resolve(changed);
          };
          tx.onerror = () => reject(tx.error);
        };
      }),
  );
}

// ------------------------------------------------------------- phase output

/**
 * Leaves a JSON file for the host script (the runner prints it on stdout when
 * the tests are done). Only the throwaway values of the run go in.
 * @param {string} name
 * @param {unknown} data
 */
export function leave(name, data) {
  mkdirSync(outDir, { recursive: true });
  writeFileSync(`${outDir}/${name}.json`, JSON.stringify(data));
}

/** Parses the state a previous phase left (passed in by the host script). */
export function previousState() {
  const raw = process.env.FERRET_E2E_STATE;
  if (!raw) throw new Error("FERRET_E2E_STATE is not set: this phase needs the state of an earlier phase");
  return JSON.parse(raw);
}

/** Puts the values of an earlier phase back. @param {Record<string, string>} state */
export function adopt(state) {
  Object.assign(secrets, state);
}

/** The scenarios after the setup need its account; fail with a clear message when it was not made. */
export function requireAccount() {
  if (secrets.secretKey === "" || secrets.recoveryKey === "") {
    throw new Error("no account yet: run 01-setup.spec.mjs first (the scenarios share the account it makes)");
  }
}

// ------------------------------------------------- the malicious server

/** The control port of the malicious server (web/test/e2e-stack/evil), on the network of the stack only. */
export const evilUrl = process.env.FERRET_E2E_EVIL_URL ?? "";

/** @param {string} path @param {RequestInit} [init] */
async function evilCall(path, init) {
  if (evilUrl === "") throw new Error("FERRET_E2E_EVIL_URL is not set: run the scenarios with scripts/lanbox-ferret-test.sh e2e-run");
  const response = await fetch(`${evilUrl}${path}`, init);
  const body = await response.json();
  if (!response.ok) throw new Error(`the malicious server answered ${response.status} for ${path}: ${JSON.stringify(body)}`);
  return body;
}

/**
 * Switches the malicious server to a mode, for example `evil("hide", { id })`,
 * `evil("rollback", { at })`, `evil("honest")`. The modes and their parameters are
 * in web/test/e2e-stack/evil/modes.mjs.
 * @param {string} mode
 * @param {Record<string, unknown>} [params]
 */
export function evil(mode, params = {}) {
  return evilCall("/mode", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ ...params, mode }) });
}

/** The clock of the malicious server in milliseconds, for `rollback {at}`. */
export async function evilNow() {
  return (await evilCall("/recorded")).now;
}

/**
 * The session cookie of a context on the vault host, for `fork {sid}`.
 * @param {import("@playwright/test").BrowserContext} context
 */
export async function evilSession(context) {
  const cookie = (await context.cookies(vaultUrl)).find((c) => c.name === "__Host-ferret_sid");
  if (!cookie) throw new Error("this context has no vault session");
  return cookie.value;
}

// ------------------------------------------------------ the sync scenarios

/**
 * The account of the run, for the scenarios that need an account that already exists: the one an
 * earlier phase left (FERRET_E2E_STATE), or the one 01-setup made in the same run.
 */
export function useAccount() {
  if (process.env.FERRET_E2E_STATE) {
    adopt(previousState());
    // A worker that starts again (after a failure) reads the account from this file.
    remember();
  } else {
    requireAccount();
  }
}

/**
 * A new device: a fresh context of the browser, signed in, with its list on the screen.
 * @param {import("@playwright/test").Browser} browser
 */
export async function newDevice(browser) {
  const context = await freshContext(browser);
  const page = await context.newPage();
  await signInOn(page);
  return { context, page };
}

/**
 * Waits until everything this device wrote has gone to the server (the outbox is empty) and the status does not say that
 * the sync is waiting or stopped. (A screen that was built after the last event shows its first word, "Syncing", until the
 * next event, so the word "Up to date" is not waited for.)
 * @param {import("@playwright/test").Page} page
 */
export async function synced(page, timeout = 30_000) {
  await expect
    .poll(
      async () => {
        const state = await page.locator('[data-role="sync-status"]').getAttribute("data-state");
        if (state !== null && /^(failed|halted|offline|retrying|unauthorized)$/.test(state)) return `status ${state}`;
        return (await readStores(page)).outbox.count === 0 ? "sent" : "waiting";
      },
      { timeout, message: "everything written here is on the server" },
    )
    .toBe("sent");
}

/**
 * The id of the first list row with this name (the list must be on the screen).
 * @param {import("@playwright/test").Page} page @param {string} name
 */
export async function itemIdOf(page, name) {
  const id = await rowsNamed(page, name).first().getAttribute("data-id");
  if (!id) throw new Error(`no list row named ${name}`);
  return id;
}

/**
 * Opens an item from the list.
 * @param {import("@playwright/test").Page} page @param {string} name
 */
export async function openItem(page, name) {
  await openList(page);
  await rowsNamed(page, name).locator('[data-role="item-link"]').first().click();
  await expect(page.locator('[data-role="item"] h1')).toContainText(name);
}

/**
 * Edits an item through the form and saves it. Returns when the item page shows the new name.
 * @param {import("@playwright/test").Page} page
 * @param {string} name the name now
 * @param {{ name?: string, username?: string, notes?: string, password?: string }} change
 * @param {{ waitForName?: boolean }} [options] `waitForName: false`: do not wait for the item page to show the new name (a
 * change that the server is going to refuse shows the old one)
 */
export async function editItem(page, name, change, { waitForName = true } = {}) {
  await openItem(page, name);
  await page.locator('[data-role="edit"]').click();
  await expect(page.locator('[data-role="edit-form"]')).toBeVisible();
  if (change.name !== undefined) await page.locator('[data-role="name"]').fill(change.name);
  if (change.username !== undefined) await page.locator('[data-role="username"]').fill(change.username);
  if (change.password !== undefined) await page.locator('[data-role="password"]').fill(change.password);
  if (change.notes !== undefined) {
    // The notes of an item that has some are read into the form only on request.
    const load = page.locator('[data-role="load-notes"]');
    if (await load.count()) await load.click();
    await page.locator('[data-role="notes"]').fill(change.notes);
  }
  await page.locator('[data-role="save"]').click();
  if (waitForName) await expect(page.locator('[data-role="item"] h1')).toContainText(change.name ?? name, { timeout: 30_000 });
  else await expect(page.locator('[data-role="item"]')).toBeVisible({ timeout: 30_000 });
}

/**
 * The change feed as the server has it now, read with the session of the context.
 * @param {import("@playwright/test").BrowserContext} context
 * @returns {Promise<{ changes: { id: string, rev: number, seq: number, deleted: boolean }[], latest_seq: number, restore_epoch: number }>}
 */
export async function feedOf(context) {
  const response = await context.request.get(`${vaultUrl}/api/sync/changes?since=0&limit=500`, { headers: { "Ferret-Protocol": "1" } });
  if (response.status() !== 200) throw new Error(`the change feed answered ${response.status()}`);
  return response.json();
}

/**
 * The revision the server holds for an item (0 when it holds no row).
 * @param {import("@playwright/test").BrowserContext} context @param {string} id
 */
export async function serverRev(context, id) {
  return (await feedOf(context)).changes.find((c) => c.id === id)?.rev ?? 0;
}

/**
 * The sequence number of the checkpoint the server holds (0 when it holds none).
 * @param {import("@playwright/test").BrowserContext} context
 */
export async function checkpointSeq(context) {
  const response = await context.request.get(`${vaultUrl}/api/sync/checkpoint`, { headers: { "Ferret-Protocol": "1" } });
  if (response.status() === 404) return 0;
  if (response.status() !== 200) throw new Error(`the checkpoint answered ${response.status()}`);
  return (await response.json()).seq;
}

/**
 * Signs in a new device and waits until a checkpoint at the top of the feed is on the server. A device that has never
 * uploaded one does so once its first check has passed. The device is closed again.
 * @param {import("@playwright/test").Browser} browser
 */
export async function putCheckpointOnTop(browser) {
  const { context, page } = await newDevice(browser);
  try {
    await synced(page);
    await expect
      .poll(async () => (await checkpointSeq(context)) >= (await feedOf(context)).latest_seq, { timeout: 60_000, message: "a checkpoint at the top of the feed" })
      .toBe(true);
  } finally {
    await context.close();
  }
}

/** The sync banner of a code. @param {import("@playwright/test").Page} page @param {string} code */
export const syncBanner = (page, code) => page.locator(`[data-role="sync-banner"][data-code="${code}"]`);
/** The one-shot banner of a warning code. @param {import("@playwright/test").Page} page @param {string} code */
export const warningBanner = (page, code) => page.locator(`[data-role="banner"][data-banner="warning:${code}"]`);

/** The names in the list on the screen. @param {import("@playwright/test").Page} page */
export const listNames = (page) => page.locator('[data-role="item"] [data-role="item-link"]').allTextContents();

// ------------------------------------------------------------ the shots

/**
 * Saves a screenshot of the page. The gate script collects it on the host into test-results/out/m2-shots from what the
 * phase leaves on stdout (as JSON), so no mounted folder is needed. The browser's name is part of the name.
 * @param {import("@playwright/test").Page} page @param {string} name
 */
export async function shot(page, name) {
  const full = `${test.info().project.name}-${name}`.replace(/[^A-Za-z0-9._-]/g, "-");
  mkdirSync(`${outDir}/m2-shots`, { recursive: true });
  const png = await page.screenshot({ path: `${outDir}/m2-shots/${full}.png`, fullPage: true });
  leave(`shot-${full}`, { name: full, png: png.toString("base64") });
}

/**
 * Whether a policy violation is one that these scenarios leave out: in WebKit only, the style element that Playwright itself
 * puts in a page to take a screenshot (`style-src-elem`, blocked `inline`, no source file). It is narrow and not a fault of what
 * is tested here. Any other violation fails the test.
 * @param {string} browserName @param {string} violation
 */
function leftOut(browserName, violation) {
  return browserName === "webkit" && /^style-src-elem inline \(target [^,]*, at \??:\d+, /.test(violation);
}

/**
 * After each test: no policy violation and no uncaught error in the pages the test made (apart from `leftOut`).
 */
export function noViolations() {
  const mark = { violations: 0, errors: 0 };
  test.beforeEach(() => {
    mark.violations = findings.violations.length;
    mark.errors = findings.pageErrors.length;
  });
  test.afterEach(({ browserName }) => {
    const violations = findings.violations.slice(mark.violations).filter((v) => !leftOut(browserName, v));
    expect(violations, "security policy violations during the test").toEqual([]);
    expect(findings.pageErrors.slice(mark.errors), "uncaught errors during the test").toEqual([]);
  });
}

// --------------------------------------------------------- the host's part

/** Whether the run has a host script that does the Docker steps for `hostStep`. */
export const existsHost = () => existsSync("/tmp/host-ready");

/**
 * Whether the host is there. In the phase that the gate script runs with a host (`m2-restore`) the tests fail when it is not,
 * they do not skip: a skipped scenario must not read as a passed one. The file shows a moment after the runner starts.
 */
export async function hostAvailable() {
  if (process.env.FERRET_E2E_PHASE !== "m2-restore") return existsHost();
  const until = Date.now() + 120_000;
  while (!existsHost()) {
    if (Date.now() > until) throw new Error("the gate script did not make the host ready: the restore scenarios cannot run");
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  return true;
}

/**
 * Asks the host script for something only the Docker host can do while the browsers stay open: `snapshot`, `restore`
 * or `clock-<seconds>`. The host script (scripts/lanbox-ferret-e2e-gate.sh m2) watches for the request file in the
 * runner container, does the step and answers with a done file, or with a failed file when the step failed (the test then
 * fails). The test is skipped when the run has no host script, except in the phase that the gate script runs with one.
 * @param {string} step
 */
export async function hostStep(step) {
  if (!(await hostAvailable())) test.skip(true, "needs the host script (scripts/lanbox-ferret-e2e-gate.sh m2)");
  // The answers to an earlier request for the same step.
  rmSync(`/tmp/host-done-${step}`, { force: true });
  rmSync(`/tmp/host-failed-${step}`, { force: true });
  writeFileSync(`/tmp/host-request-${step}`, "");
  const until = Date.now() + 600_000;
  for (;;) {
    if (existsSync(`/tmp/host-failed-${step}`)) throw new Error(`the host failed the step ${step}`);
    if (existsSync(`/tmp/host-done-${step}`)) return;
    if (Date.now() > until) throw new Error(`the host did not do ${step} within 10 minutes`);
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
}
