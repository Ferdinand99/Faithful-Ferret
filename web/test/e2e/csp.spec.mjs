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
  expect(wasm.length).toBeGreaterThan(0);
  for (const r of wasm) {
    expect(r.status).toBe(200);
    expect(r.type).toBe("application/wasm");
  }
  expect(await violations(page)).toEqual([]);
  expect(seen.errors).toEqual([]);
});

test("string_worker_url_and_html_sinks_are_blocked_by_trusted_types", async ({ page }) => {
  await page.goto("/");
  await expect(page.locator("#app h1")).toBeVisible();
  const out = await page.evaluate(() => {
    if (!("trustedTypes" in window)) return null;
    const attempt = (fn) => {
      try {
        fn();
        return "allowed";
      } catch (e) {
        return /** @type {Error} */ (e).name;
      }
    };
    return {
      worker: attempt(() => new Worker("/js/vault.worker.mjs", { type: "module" }).terminate()),
      html: attempt(() => { document.createElement("div").innerHTML = "<b>x</b>"; }),
    };
  });
  test.skip(out === null, "this browser has no Trusted Types");
  expect(out).toEqual({ worker: "TypeError", html: "TypeError" });
});
