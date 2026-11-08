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
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";

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
  /** Reports that WebKit makes about the inner style of its own select (see `watchScript`); not violations of the page. */
  engineReports: /** @type {string[]} */ ([]),
  /** The console lines that go with those reports; there is at most one per report. */
  engineConsole: /** @type {string[]} */ ([]),
  /** How many selects the pages of WebKit contexts made; each one must have had a report in `engineReports`. */
  selectsMade: 0,
  pages: 0,
  /** Everything sent to the servers and received from them, as text. */
  traffic: /** @type {string[]} */ ([]),
};

// ------------------------------------------------------------- watching

/**
 * The script that watches one page for policy violations.
 *
 * One report is not ours and is set apart: WebKit builds the inner parts of a
 * `<select>` with an inline `style` attribute, and reports a `style-src-attr`
 * violation for each `<select>` that a page makes, with or without our code (a bare
 * `document.createElement("select")` on this page does it, and the element has no
 * `style` attribute afterwards). Chromium and Firefox report nothing.
 *
 * In WebKit the page keeps the `<select>` elements that `document.createElement` made.
 * A report is set apart only when all of this is true: the directive is `style-src-attr`,
 * the blocked source is `inline`, and the report belongs to one of those elements that
 * has no `style` attribute and has not had a report yet. It belongs to an element when
 * the event's target is that element, or when the target is the document and the element
 * is not in the page (WebKit reports for a select that is made and never shown, such as
 * the one of the edit screen, at the document). The script and line that the report names
 * are not used: WebKit gives the code that happens to run when the report is sent (in
 * these runs Playwright's own script), not the code that made the element. Any other
 * inline style, a select that got a `style` attribute, and a second report for the same
 * select, still fail the run. The CSP is not loosened for this: the page keeps `style-src 'self'`.
 * (The sample is not checked: without `'report-sample'` in the policy it is always empty.)
 *
 * The exception must not outlive the problem: 09-csp requires one set-apart report for
 * every select that was made in WebKit, and the WebKit canary (08b) checks both ways.
 * @param {string} engine the name of the browser engine (`chromium`, `firefox`, `webkit`)
 */
const watchScript = (engine) => `
  (() => {
    const webkit = ${JSON.stringify(engine === "webkit")};
    /** @type {{ node: Element, file: string, line: number }[]} selects that await their report */
    const made = [];
    // The place a call came from, as "file", "line" (from a stack line "name@file:line:column").
    const caller = () => {
      const frame = String(new Error().stack).split("\\n")[2] || "";
      const colon = frame.lastIndexOf(":");
      const colon2 = frame.lastIndexOf(":", colon - 1);
      const head = frame.slice(0, colon2);
      return { file: head.slice(head.lastIndexOf("@") + 1), line: Number(frame.slice(colon2 + 1, colon)) };
    };
    if (webkit) {
      const create = Document.prototype.createElement;
      Document.prototype.createElement = function (name, ...rest) {
        const node = create.call(this, name, ...rest);
        if (this === document && node instanceof HTMLSelectElement) {
          made.push({ node, ...caller() });
          try { window.__e2eSelectMade(); } catch {}
        }
        return node;
      };
    }
    document.addEventListener("securitypolicyviolation", (e) => {
      try {
        const text = e.violatedDirective + " " + e.blockedURI + " " + (e.sample || "");
        if (webkit && e.effectiveDirective === "style-src-attr" && e.blockedURI === "inline") {
          const at = made.findIndex((m) =>
            (e.target === m.node || (e.target === document && !m.node.isConnected)) &&
            !m.node.hasAttribute("style"));
          if (at >= 0) {
            const [m] = made.splice(at, 1);
            window.__e2eEngineReport(text + " (the inner style of a select, WebKit; made at " + (m.file || "?") + ":" + m.line + ")");
            return;
          }
        }
        // What a failure needs to be understood: where the report came from, and what selects wait for one.
        const waiting = made.map((m) => (m.file || "?") + ":" + m.line + (m.node.isConnected ? " shown" : " not shown") + (m.node.hasAttribute("style") ? " with style" : ""));
        window.__e2eViolation(text + "(target " + (e.target && e.target.nodeName) + ", at " + (e.sourceFile || "?") + ":" + e.lineNumber + ", selects waiting: " + waiting.join("; ") + ")");
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
  await context.exposeFunction("__e2eEngineReport", (/** @type {string} */ text) => findings.engineReports.push(text));
  await context.exposeFunction("__e2eSelectMade", () => {
    findings.selectsMade += 1;
  });
  const engine = context.browser()?.browserType().name() ?? "";
  await context.addInitScript(watchScript(engine));
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
      // WebKit also logs the report of its own select widget (see `watchScript`). These are
      // counted apart, and 09-csp holds them to the number of reports set apart in the page.
      if (engine === "webkit" && /^Refused to apply a stylesheet because its hash, its nonce, or 'unsafe-inline' does not appear in the style-src directive/.test(text)) {
        findings.engineConsole.push(text);
        return;
      }
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
  // Every report that WebKit made about its own select (see `watchScript`) shows in the
  // report of the test that was running, so that the exception is seen and not silent.
  engineIssues: [
    async ({}, use, testInfo) => {
      const before = findings.engineReports.length;
      await use(undefined);
      for (const description of findings.engineReports.slice(before)) {
        testInfo.annotations.push({ type: "known-engine-issue", description });
      }
    },
    { auto: true },
  ],
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
  await pace();
  await page.locator('[data-role="credentials"] [data-role="submit"]').click();
  if (expectList) await expect(page.locator('[data-role="list"]')).toBeVisible({ timeout: SLOW });
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
