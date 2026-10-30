// The page under the strict CSP and Trusted Types of the design document's
// section 12 (served by test/serve.mjs from web/dist). Run in Chromium,
// Firefox and WebKit.
import { expect, test } from "@playwright/test";
import { loadHeaders } from "../serve.mjs";

const headers = loadHeaders();

/** Collects every CSP and Trusted Types violation and every page error. */
async function watch(page) {
  const seen = { violations: [], errors: [], console: [] };
  await page.addInitScript(() => {
    // @ts-ignore
    window.__violations = [];
    document.addEventListener("securitypolicyviolation", (e) => {
      // @ts-ignore
      window.__violations.push(`${e.violatedDirective} ${e.blockedURI} ${e.sample ?? ""}`);
    });
  });
  page.on("pageerror", (e) => seen.errors.push(String(e)));
  page.on("console", (m) => {
    if (m.type() === "error" || m.type() === "warning") seen.console.push(`${m.type()}: ${m.text()}`);
  });
  return seen;
}

const violations = (page) => page.evaluate(() => /** @type {any} */ (window).__violations);

test("loads_without_csp_or_trusted_types_violations", async ({ page }) => {
  const seen = await watch(page);
  const response = await page.goto("/");
  expect(response?.status()).toBe(200);
  // Every header of the list is on the page response, unchanged.
  const got = response?.headers() ?? {};
  for (const [name, value] of Object.entries(headers)) {
    expect(got[name.toLowerCase()], name).toBe(value);
  }
  await expect(page.locator("#app h1")).toHaveText("Faithful Ferret");
  // The boot has finished; a late violation is counted below.
  await page.evaluate(async () => (await import("/app/boot.mjs")).ready.then(() => undefined));
  expect(await violations(page)).toEqual([]);
  expect(seen.errors).toEqual([]);
  expect(seen.console).toEqual([]);
});

test("crypto_worker_starts_under_the_csp", async ({ page }) => {
  const seen = await watch(page);
  /** @type {{ url: string, type: string, status: number }[]} */
  const wasm = [];
  page.on("response", (r) => {
    if (r.url().endsWith(".wasm")) wasm.push({ url: r.url(), type: r.headers()["content-type"], status: r.status() });
  });
  await page.goto("/");
  await expect(page.locator("#app h1")).toBeVisible();
  const result = await page.evaluate(async () => {
    const { ready } = await import("/app/boot.mjs");
    const { client, tt } = await ready;
    // The first call starts the vault worker (a TrustedScriptURL when the
    // browser has Trusted Types), loads the WASM module and runs the core.
    const bytes = await client.vault.sync_memory_new();
    await client.lock();
    return { length: bytes.length, isBytes: bytes instanceof Uint8Array, trustedTypes: tt.available };
  });
  expect(result.isBytes).toBe(true);
  expect(result.length).toBeGreaterThan(0);
  // The three pinned browsers all have Trusted Types: the string fallback is a regression here.
  expect(result.trustedTypes).toBe(true);
  expect(wasm.length).toBeGreaterThan(0);
  for (const r of wasm) {
    expect(r.status).toBe(200);
    expect(r.type).toBe("application/wasm");
  }
  expect(await violations(page)).toEqual([]);
  expect(seen.errors).toEqual([]);
});

test("job_worker_starts_under_the_csp", async ({ page }) => {
  const seen = await watch(page);
  await page.goto("/");
  await expect(page.locator("#app h1")).toBeVisible();
  const reply = await page.evaluate(async () => {
    const { ready } = await import("/app/boot.mjs");
    const { tt } = await ready;
    const worker = new Worker(/** @type {string} */ (tt.workerUrl("job")), { type: "module" });
    try {
      // An unknown method gets an error reply, but only after the worker has loaded the WASM module.
      return await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error("no reply from the job worker")), 15_000);
        worker.onmessage = (e) => { clearTimeout(timer); resolve(e.data); };
        worker.onerror = () => { clearTimeout(timer); reject(new Error("the job worker failed")); };
        worker.postMessage({ id: 7, target: "job", method: "no_such_method", args: [] });
      });
    } finally {
      worker.terminate();
    }
  });
  expect(reply).toEqual({ id: 7, ok: false, code: "invalid_input" });
  expect(await violations(page)).toEqual([]);
  expect(seen.errors).toEqual([]);
});

// Code that runs as a page script (a module from the page's own origin, served
// with the page's headers), not through the test runner's evaluation, which the
// browsers do not hold to the page's policy.
const PROBE = `
const attempt = (fn) => {
  try {
    fn();
    return "allowed";
  } catch (e) {
    return e.name;
  }
};
export const result = {
  hasTrustedTypes: "trustedTypes" in window,
  // A string where a TrustedScriptURL is required.
  worker: attempt(() => new Worker("/js/vault.worker.mjs", { type: "module" }).terminate()),
  // A string where a TrustedHTML is required.
  html: attempt(() => { document.createElement("div").innerHTML = "<b>x</b>"; }),
  // A policy name that the CSP does not list, and the listed one a second time.
  defaultPolicy: attempt(() => window.trustedTypes.createPolicy("default", {})),
  otherPolicy: attempt(() => window.trustedTypes.createPolicy("other", {})),
  duplicatePolicy: attempt(() => window.trustedTypes.createPolicy("ferret", {})),
  // Only 'wasm-unsafe-eval' is allowed, so text cannot become code.
  eval: attempt(() => (0, eval)("1 + 1")),
  newFunction: attempt(() => new Function("return 1")()),
};
`;

test("the_browser_enforces_trusted_types_and_the_script_policy", async ({ page }) => {
  await watch(page);
  await page.route("**/app/probe.mjs", (route) =>
    route.fulfill({ status: 200, headers: { ...headers, "content-type": "text/javascript; charset=utf-8" }, body: PROBE }));
  await page.goto("/");
  await expect(page.locator("#app h1")).toBeVisible();
  const before = (await violations(page)).length;
  const result = await page.evaluate(async () => (await import("/app/probe.mjs")).result);
  // Reports are queued as events; give them a turn.
  await page.waitForTimeout(200);
  const reported = (await violations(page)).length - before;
  expect(result.hasTrustedTypes).toBe(true);
  expect(result).toMatchObject({
    worker: "TypeError",
    html: "TypeError",
    defaultPolicy: "TypeError",
    otherPolicy: "TypeError",
    duplicatePolicy: "TypeError",
  });
  // A string is refused as code: a blocked eval is an EvalError, and a string where
  // Trusted Types wants a TrustedScript is a TypeError. Never "allowed".
  expect(["EvalError", "TypeError"]).toContain(result.eval);
  expect(["EvalError", "TypeError"]).toContain(result.newFunction);
  // The browser reported what it blocked.
  expect(reported).toBeGreaterThan(0);
});
