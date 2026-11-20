// The key of a device client in a real browser (Chromium, Firefox and WebKit),
// on the page under the strict CSP: WebCrypto makes it non-extractable,
// IndexedDB keeps it across a reload, it still signs DPoP proofs that its
// public JWK verifies, and nothing of it reaches localStorage, sessionStorage
// or the console. Spec: Fase 1 § 7.6.
import { expect, test } from "@playwright/test";

const SERVER = "https://vault.ferret.test";

/**
 * Collects page errors and console messages (as csp.spec.mjs does) while `seen.paused` is false. A reload is not
 * watched: Firefox warns there about the page's own module loads that the reload cuts off.
 */
function watch(page) {
  const seen = { errors: [], console: [], paused: false };
  page.on("pageerror", (e) => {
    if (!seen.paused) seen.errors.push(String(e));
  });
  const webkit = page.context().browser()?.browserType().name() === "webkit";
  page.on("console", (m) => {
    if (seen.paused) return;
    // WebKit (Playwright 1.65) logs this note about cross-origin isolation after a reload; it is not about our code.
    if (webkit && /^This document is not cross-origin isolated because the Cross-Origin-Embedder-Policy header is missing/.test(m.text())) return;
    seen.console.push(`${m.type()}: ${m.text()}`);
  });
  return seen;
}

/** Opens the page and waits for the boot, so the app's own messages are not counted. */
async function open(page) {
  await page.goto("/");
  await expect(page.locator("#app h1")).toBeVisible();
  await page.evaluate(async () => (await import("/app/boot.mjs")).ready.then(() => undefined));
}

/** Everything in localStorage and sessionStorage. */
const storage = (page) =>
  page.evaluate(() => {
    const all = (s) => Object.fromEntries(Array.from({ length: s.length }, (_, i) => s.key(i)).map((k) => [k, s.getItem(k)]));
    return { local: all(localStorage), session: all(sessionStorage) };
  });

test("device_key_is_not_extractable_and_survives_reopening_the_db", async ({ page }) => {
  await open(page);
  const seen = watch(page);
  const before = await storage(page);

  const made = await page.evaluate(async (server) => {
    const { generateDeviceKey, saveDeviceKey, loadDeviceKey, thumbprint } = await import("/app/auth/deviceKey.mjs");
    const { openStore } = await import("/app/store/idb.mjs");
    const refreshToken = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE";
    let store = await openStore(indexedDB, "ferret");
    const version = store.db.version;
    const stores = [...store.db.objectStoreNames].sort();
    const key = await generateDeviceKey(server);
    await saveDeviceKey(store, key, { deviceId: "7e3a9c1f5b2d48a6b0c4d8e2f6a1b3c5", accountId: "0a1b2c3d4e5f60718293a4b5c6d7e8f9", refreshToken });
    store.close();
    // Reopened in the same page.
    store = await openStore(indexedDB, "ferret");
    const loaded = await loadDeviceKey(store, server);
    store.close();
    let exported = "refused";
    try {
      await crypto.subtle.exportKey("jwk", loaded.privateKey);
      exported = "exported";
    } catch {
      // the private key cannot be exported
    }
    return {
      version,
      stores,
      extractable: loaded.privateKey.extractable,
      usages: loaded.privateKey.usages,
      sameJwk: JSON.stringify(loaded.publicJwk) === JSON.stringify(key.publicJwk),
      members: Object.keys(loaded.publicJwk),
      exported,
      jkt: await thumbprint(loaded.publicJwk),
      refreshToken: loaded.refreshToken === refreshToken,
    };
  }, SERVER);
  expect(made.version).toBe(3);
  expect(made.stores).toContain("device_keys");
  expect(made.extractable).toBe(false);
  expect(made.usages).toEqual(["sign"]);
  expect(made.sameJwk).toBe(true);
  expect(made.members).toEqual(["kty", "crv", "x", "y"]);
  expect(made.exported).toBe("refused");
  expect(made.jkt).toMatch(/^[A-Za-z0-9_-]{43}$/);
  expect(made.refreshToken).toBe(true);

  // After a reload the browser gives the stored key back, and it still signs proofs that its public JWK verifies.
  seen.paused = true;
  await page.reload();
  await open(page);
  seen.paused = false;
  const after = await page.evaluate(async (server) => {
    const { loadDeviceKey, deleteDeviceKey, thumbprint } = await import("/app/auth/deviceKey.mjs");
    const { createClock, createProof } = await import("/app/auth/dpop.mjs");
    const { openStore } = await import("/app/store/idb.mjs");
    const store = await openStore(indexedDB, "ferret");
    const key = await loadDeviceKey(store, server);
    const clock = createClock();
    const proof = await createProof(key, { method: "GET", url: `${server}/api/sync/changes?since=1#x`, accessToken: "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI", clock });
    const [header, claims, signature] = proof.split(".");
    const decode = (s) => Uint8Array.from(atob(s.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - (s.length % 4)) % 4)), (c) => c.charCodeAt(0));
    const verifier = await crypto.subtle.importKey("jwk", key.publicJwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    const valid = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, verifier, decode(signature), new TextEncoder().encode(`${header}.${claims}`));
    const result = {
      extractable: key.privateKey.extractable,
      jkt: await thumbprint(key.publicJwk),
      header: JSON.parse(new TextDecoder().decode(decode(header))),
      claims: JSON.parse(new TextDecoder().decode(decode(claims))),
      signatureBytes: decode(signature).length,
      valid,
    };
    await deleteDeviceKey(store, server);
    result.gone = (await loadDeviceKey(store, server)) === null;
    store.close();
    return result;
  }, SERVER);
  expect(after.extractable).toBe(false);
  expect(after.jkt).toBe(made.jkt);
  expect(Object.keys(after.header)).toEqual(["typ", "alg", "jwk"]);
  expect(after.header.typ).toBe("dpop+jwt");
  expect(after.header.alg).toBe("ES256");
  expect(Object.keys(after.header.jwk)).toEqual(["kty", "crv", "x", "y"]);
  expect(Object.keys(after.claims)).toEqual(["jti", "htm", "htu", "iat", "ath"]);
  expect(after.claims.htu).toBe(`${SERVER}/api/sync/changes`);
  expect(after.claims.ath).toMatch(/^[A-Za-z0-9_-]{43}$/);
  expect(after.signatureBytes).toBe(64);
  expect(after.valid).toBe(true);
  expect(after.gone).toBe(true);

  expect(await storage(page)).toEqual(before);
  expect(seen.errors).toEqual([]);
  expect(seen.console).toEqual([]);
});

test("nothing_reaches_local_storage_session_storage_or_console", async ({ page }) => {
  await open(page);
  const seen = watch(page);
  const before = await storage(page);
  const marks = await page.evaluate(async (server) => {
    const { generateDeviceKey, saveDeviceKey, saveRefreshToken, loadDeviceKey, deleteDeviceKey } = await import("/app/auth/deviceKey.mjs");
    const { createClock, createProof } = await import("/app/auth/dpop.mjs");
    const { openStore } = await import("/app/store/idb.mjs");
    const store = await openStore(indexedDB, "ferret");
    const key = await generateDeviceKey(server);
    const clock = createClock();
    clock.observe(new Date().toUTCString());
    const login = await createProof(key, { method: "POST", url: `${server}/api/auth/opaque/login/finish`, clock });
    await saveDeviceKey(store, key, { deviceId: "7e3a9c1f5b2d48a6b0c4d8e2f6a1b3c5", accountId: "0a1b2c3d4e5f60718293a4b5c6d7e8f9", refreshToken: "Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0M" });
    await saveRefreshToken(store, server, "REREREREREREREREREREREREREREREREREREREREREQ");
    const loaded = await loadDeviceKey(store, server);
    const read = await createProof(loaded, { method: "GET", url: `${server}/api/sync/events`, accessToken: "RUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUU", clock });
    try {
      await saveDeviceKey(store, key, { deviceId: null, accountId: null, refreshToken: null });
    } catch {
      // refused, and quietly
    }
    await deleteDeviceKey(store, server);
    store.close();
    // What must never show up in storage: the proofs, the tokens and the key's coordinates.
    return [login, read, key.publicJwk.x, key.publicJwk.y, "Q0NDQ0NDQ0NDQ0", "RERERERERERERER", "RUVFRUVFRUVFRUVF"];
  }, SERVER);
  const after = await storage(page);
  expect(after).toEqual(before);
  const text = JSON.stringify(after);
  for (const mark of marks) expect(text.includes(mark)).toBe(false);
  expect(seen.errors).toEqual([]);
  expect(seen.console).toEqual([]);
});
