// The import worker in the real browsers (Chromium, Firefox, WebKit): it starts through the page's
// Trusted Types policy under its own policy (`connect-src 'none'`), takes a File and a port by
// structured clone, and answers with envelopes and a report only.
import { expect, test } from "@playwright/test";
import { IMPORT_WORKER_PATHS, importWorkerHeaders, loadHeaders } from "../serve.mjs";

const headers = loadHeaders();

/** Collects every CSP and Trusted Types violation and every page error. */
async function watch(page) {
  const seen = { errors: [] };
  await page.addInitScript(() => {
    // @ts-ignore
    window.__violations = [];
    document.addEventListener("securitypolicyviolation", (e) => {
      // @ts-ignore
      window.__violations.push(`${e.violatedDirective} ${e.blockedURI} ${e.sample ?? ""}`);
    });
  });
  page.on("pageerror", (e) => seen.errors.push(String(e)));
  return seen;
}

const violations = (page) => page.evaluate(() => /** @type {any} */ (window).__violations);

test("import_worker_files_carry_a_policy_that_allows_no_connection", async ({ request }) => {
  const expected = importWorkerHeaders(headers);
  for (const path of IMPORT_WORKER_PATHS) {
    const response = await request.get(path);
    expect(response.status(), path).toBe(200);
    const got = response.headers();
    for (const [name, value] of Object.entries(expected)) expect(got[name.toLowerCase()], `${path} ${name}`).toBe(value);
    expect(got["content-security-policy"], path).toContain("connect-src 'none';");
  }
  // The page and the other workers keep the policy of the section.
  for (const path of ["/", "/js/vault.worker.mjs", "/js/job.worker.mjs"]) {
    const response = await request.get(path);
    expect(response.headers()["content-security-policy"], path).toBe(headers["Content-Security-Policy"]);
  }
});

test("import_worker_starts_under_the_csp_and_answers_unsupported", async ({ page }) => {
  const seen = await watch(page);
  await page.goto("/");
  await expect(page.locator("#app h1")).toBeVisible();
  const reply = await page.evaluate(async () => {
    const { ready } = await import("/app/boot.mjs");
    const { tt } = await ready;
    const worker = new Worker(/** @type {string} */ (tt.workerUrl("import")), { type: "module" });
    try {
      return await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error("no reply from the import worker")), 15_000);
        worker.onmessage = (e) => {
          clearTimeout(timer);
          resolve({ data: e.data, trustedTypes: tt.available });
        };
        worker.onerror = () => {
          clearTimeout(timer);
          reject(new Error("the import worker failed to start"));
        };
        // Not an import request: no kind, no file, no port.
        worker.postMessage({ id: 7, nothing: "to import" });
      });
    } finally {
      worker.terminate();
    }
  });
  expect(reply.trustedTypes).toBe(true);
  expect(reply.data).toEqual({ id: 7, ok: false, error: "unsupported" });
  expect(await violations(page)).toEqual([]);
  expect(seen.errors).toEqual([]);
});

test("import_worker_reads_a_file_it_is_given_and_answers_with_envelopes_and_a_report_only", async ({ page }) => {
  const seen = await watch(page);
  await page.goto("/");
  await expect(page.locator("#app h1")).toBeVisible();
  const result = await page.evaluate(async () => {
    const { ready } = await import("/app/boot.mjs");
    const { tt } = await ready;
    const worker = new Worker(/** @type {string} */ (tt.workerUrl("import")), { type: "module" });
    // The page plays the vault worker on the other end of the port, so the test sees what the import
    // worker sends over it (the real vault worker takes the port in the same way).
    const { port1, port2 } = new MessageChannel();
    /** @type {any[]} */
    const drafts = [];
    port2.onmessage = (e) => {
      drafts.push(e.data);
      port2.postMessage({ id: e.data.id, ok: true, value: { rev: 1, envelope: new Uint8Array([0xe0, 1, 2, 3]), tag: new Uint8Array(32) } });
    };
    const text = JSON.stringify({
      encrypted: false,
      folders: [],
      items: [
        { type: 1, name: "Synthetic login", notes: null, favorite: false, login: { username: "synthetic-user", password: "synthetic-password", uris: [{ uri: "example.test", match: 0 }], totp: "GEZDGNBVGY3TQOJQ" } },
        { type: 2, name: "Synthetic note", notes: "synthetic body" },
      ],
    });
    const file = new File([text], "synthetic.json", { type: "application/json" });
    try {
      const reply = await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error("no reply from the import worker")), 15_000);
        worker.onmessage = (e) => {
          clearTimeout(timer);
          resolve(e.data);
        };
        worker.onerror = () => {
          clearTimeout(timer);
          reject(new Error("the import worker failed"));
        };
        worker.postMessage({ id: 1, kind: "bitwarden_json", file, port: port1 }, [port1]);
      });
      const replyText = JSON.stringify(reply, (_, v) => (v instanceof Uint8Array ? `<${v.length} bytes>` : v));
      return {
        reply: JSON.parse(replyText),
        sealedAreBytes: /** @type {any} */ (reply).sealed.every((s) => s.id instanceof Uint8Array && s.envelope instanceof Uint8Array && s.tag instanceof Uint8Array),
        // What the port got: one message per item, and the items as the vault takes them.
        messages: drafts.map((m) => ({ method: m.method, args: m.args.length, existing: m.args[3], rev: m.args[1], idLength: m.args[0].length, draft: m.args[2] })),
        replyText,
      };
    } finally {
      worker.terminate();
      port1.close();
      port2.close();
    }
  });
  expect(result.reply.ok).toBe(true);
  expect(result.reply.id).toBe(1);
  expect(Object.keys(result.reply).sort()).toEqual(["id", "ok", "report", "sealed"]);
  expect(result.sealedAreBytes).toBe(true);
  expect(result.reply.sealed).toHaveLength(2);
  expect(result.reply.report.counts).toMatchObject({ items: 2, login: 1, note: 1, sealed: 2, totp: 1 });
  expect(result.reply.report.warnings).toEqual([{ code: "uri_https_added", index: 0 }]);
  // Nothing of the file is in what the page got.
  for (const word of ["synthetic-user", "synthetic-password", "Synthetic login", "Synthetic note", "synthetic body", "example.test", "GEZDGNBV"]) {
    expect(result.replyText, word).not.toContain(word);
  }
  // The port got the drafts.
  expect(result.messages).toHaveLength(2);
  for (const m of result.messages) expect(m).toMatchObject({ method: "encrypt_item", args: 5, existing: "no_existing", rev: 1, idLength: 16 });
  const login = result.messages.find((m) => m.draft.name === "Synthetic login").draft;
  expect(login.urls).toEqual([{ url: "https://example.test", matching: "domain" }]);
  expect(login.totp).toEqual({ uri: "otpauth://totp/?secret=GEZDGNBVGY3TQOJQ" });
  expect(await violations(page)).toEqual([]);
  expect(seen.errors).toEqual([]);
});

test("import_worker_refuses_a_zip_file_deep_nesting_and_hostile_keys_in_the_browser", async ({ page }) => {
  await page.goto("/");
  await expect(page.locator("#app h1")).toBeVisible();
  const replies = await page.evaluate(async () => {
    const { ready } = await import("/app/boot.mjs");
    const { tt } = await ready;
    /** @param {File} file */
    const ask = async (file) => {
      const worker = new Worker(/** @type {string} */ (tt.workerUrl("import")), { type: "module" });
      const { port1, port2 } = new MessageChannel();
      try {
        return await new Promise((resolve, reject) => {
          const timer = setTimeout(() => reject(new Error("no reply")), 15_000);
          worker.onmessage = (e) => {
            clearTimeout(timer);
            resolve(e.data);
          };
          worker.postMessage({ id: 2, kind: "bitwarden_json", file, port: port1 }, [port1]);
        });
      } finally {
        worker.terminate();
        port2.close();
      }
    };
    const zip = new File([new Uint8Array([0x50, 0x4b, 0x03, 0x04, 0x14, 0, 0, 0, 8, 0])], "export.zip");
    const deep = new File(["[".repeat(100_000)], "deep.json");
    const hostile = new File(['{"items":[{"__proto__":{"x":1}}]}'], "hostile.json");
    return { zip: await ask(zip), deep: await ask(deep), hostile: await ask(hostile) };
  });
  expect(replies.zip).toEqual({ id: 2, ok: false, error: "import_zip" });
  expect(replies.deep).toEqual({ id: 2, ok: false, error: "import_too_deep" });
  expect(replies.hostile).toEqual({ id: 2, ok: false, error: "import_bad_key" });
});
