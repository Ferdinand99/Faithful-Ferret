// What the Firefox specs and the passkey matrix need when Ferret itself answers a page's passkey request: the permission for
// https pages, the test build's core operations, a test key registered at a fixture relying party and put into the vault (so a
// get does not depend on making a passkey in Ferret), and the chooser window.
import assert from "node:assert/strict";
import { EXTENSION_ORIGIN } from "./harness.mjs";

/** The address of the chooser window's page. */
export const WINDOW_PAGE = `${EXTENSION_ORIGIN}/pages/passkey.html`;

/** The optional permission for https pages, asked in the bridge page with a real click. @param {import("./driver.mjs").Session} session */
export async function grantHttps(session) {
  await session.content(() => {
    if (document.getElementById("pk-grant")) return;
    const button = document.createElement("button");
    button.id = "pk-grant";
    button.textContent = "grant";
    button.addEventListener("click", () => {
      browser.permissions.request({ origins: ["https://*/*"] }).then(
        (ok) => { document.documentElement.dataset.pkGranted = String(ok); },
        (error) => { document.documentElement.dataset.pkGranted = `error ${error}`; },
      );
    });
    document.body.append(button);
  });
  const [button] = await session.findAll("#pk-grant");
  await session.click(button);
  const answer = await session.waitFor(() => session.content(() => document.documentElement.dataset.pkGranted), 15_000, "the permission");
  assert.equal(answer, "true", "the permission for https pages was granted");
}

/**
 * One operation of the core over the test build's core port, from the bridge tab.
 * @param {import("./driver.mjs").Session} session @param {string} op @param {unknown} [args]
 */
export async function core(session, op, args = {}) {
  const reply = await session.content(
    (/** @type {string} */ name, /** @type {string} */ json) =>
      new Promise((resolve) => {
        const port = browser.runtime.connect({ name: "ferret-test-core" });
        const timer = setTimeout(() => resolve({ ok: false, code: "no_answer" }), 45_000);
        port.onMessage.addListener((/** @type {any} */ message) => {
          clearTimeout(timer);
          port.disconnect();
          resolve(message);
        });
        port.postMessage({ id: "c1", op: name, args: JSON.parse(json) });
      }),
    op,
    JSON.stringify(args),
  );
  assert.equal(/** @type {any} */ (reply)?.ok, true, `${op}: ${JSON.stringify(reply)}`);
  return /** @type {any} */ (reply).value;
}

/**
 * In the relying party's page: a new P-256 key (or the one given as PKCS #8, base64url: the leak scan's sentinel), registered at the
 * relying party `lib` with an attestation of the kind "none" (BE and BS set, as Ferret's passkeys have them). Gives what the vault's
 * import needs.
 * @param {import("./driver.mjs").Session} session @param {string} lib @param {string} rpIdOf the RP ID @param {string} name
 * @param {string} [givenPkcs8]
 */
export async function registerTestKey(session, lib, rpIdOf, name, givenPkcs8 = "") {
  return session.content(async (/** @type {string} */ libName, /** @type {string} */ rpId, /** @type {string} */ userName, /** @type {string} */ given) => {
    const b64u = (/** @type {ArrayBuffer | Uint8Array} */ buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const fromB64u = (/** @type {string} */ s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
    const post = async (/** @type {string} */ path, /** @type {unknown} */ body) =>
      (await fetch(path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) })).json();
    /** @param {number} major @param {number} n */
    const head = (major, n) => (n < 24 ? [(major << 5) | n] : n < 256 ? [(major << 5) | 24, n] : [(major << 5) | 25, n >> 8, n & 255]);
    /** A small CBOR writer: integers, text, bytes and maps. @param {any} v @returns {number[]} */
    const cbor = (v) => {
      if (typeof v === "number") return v >= 0 ? head(0, v) : head(1, -1 - v);
      if (typeof v === "string") {
        const b = [...new TextEncoder().encode(v)];
        return [...head(3, b.length), ...b];
      }
      if (v instanceof Uint8Array) return [...head(2, v.length), ...v];
      /** @type {number[]} */
      const out = head(5, v.size);
      for (const [k, x] of v) out.push(...cbor(k), ...cbor(x));
      return out;
    };
    const sid = `xp-${Math.random().toString(16).slice(2, 12)}`;
    const start = await post(`/api/${libName}/register/start`, { sid, rpId, user: { name: userName, displayName: userName }, userVerification: "preferred", residentKey: "required", attestation: "none" });
    if (!start.ok) return { ok: false, stage: "start", error: String(start.error) };
    const options = start.options;
    const privateKey = given !== ""
      ? await crypto.subtle.importKey("pkcs8", fromB64u(given), { name: "ECDSA", namedCurve: "P-256" }, true, ["sign"])
      : (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])).privateKey;
    // The private key's JWK carries the public point too.
    const jwk = await crypto.subtle.exportKey("jwk", privateKey);
    const pkcs8 = given !== "" ? fromB64u(given) : await crypto.subtle.exportKey("pkcs8", privateKey);
    const credId = crypto.getRandomValues(new Uint8Array(32));
    const cose = new Map([[1, 2], [3, -7], [-1, 1], [-2, fromB64u(/** @type {string} */ (jwk.x))], [-3, fromB64u(/** @type {string} */ (jwk.y))]]);
    const rpHash = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(rpId)));
    // UP, BE, BS and AT, without UV (a strict relying party asks for UV on every sign-in with a key registered with it, and the
    // specs sign in without it too); the counter 0; an AAGUID of zeros.
    const authData = new Uint8Array([...rpHash, 0x59, 0, 0, 0, 0, ...new Uint8Array(16), 0, credId.length, ...credId, ...cbor(cose)]);
    const clientData = new TextEncoder().encode(JSON.stringify({ type: "webauthn.create", challenge: options.challenge, origin: location.origin, crossOrigin: false }));
    const attestation = new Uint8Array(cbor(new Map([["fmt", "none"], ["attStmt", new Map()], ["authData", authData]])));
    const credential = {
      id: b64u(credId),
      rawId: b64u(credId),
      type: "public-key",
      response: { clientDataJSON: b64u(clientData), attestationObject: b64u(attestation), transports: ["hybrid", "internal"] },
      clientExtensionResults: {},
      authenticatorAttachment: "platform",
    };
    const finish = await post(`/api/${libName}/register/finish`, { sid, credential });
    if (!finish.ok) return { ok: false, stage: "finish", error: String(finish.error) };
    return { ok: true, sid, cred_id: b64u(credId), user_handle: options.user.id, key_pkcs8: b64u(pkcs8) };
  }, lib, rpIdOf, name, givenPkcs8);
}

/** The window of the broker: its handle once it is there. @param {import("./driver.mjs").Session} session @param {Set<string>} known */
export async function chooserHandle(session, known) {
  return session.waitFor(async () => {
    for (const handle of await session.windowHandles()) {
      if (known.has(handle)) continue;
      await session.switchTo(handle);
      if ((await session.currentUrl()).startsWith(`${WINDOW_PAGE}?r=`)) return handle;
    }
    return null;
  }, 30_000, "the chooser window");
}

/** Waits for the window to be built, and reads what it shows. @param {import("./driver.mjs").Session} session */
export async function readWindow(session) {
  await session.waitFor(() => session.content(() => document.body?.dataset.ready === "1"), 30_000, "the window page");
  return session.content(() => ({
    state: document.querySelector('[data-role="passkey-chooser"]')?.getAttribute("data-state"),
    kind: document.querySelector('[data-role="passkey-chooser"]')?.getAttribute("data-kind"),
    candidates: [...document.querySelectorAll('[data-role="passkey-candidate"]')].map((n) => n.textContent),
    recent: document.querySelector('[data-role="passkey-recent"]') !== null,
  }));
}

/** A real click on an element of the window, after the 400 ms guard. @param {import("./driver.mjs").Session} session @param {string} role */
export async function pressInWindow(session, role) {
  await new Promise((resolve) => setTimeout(resolve, 900));
  const [button] = await session.findAll(`[data-role="${role}"]`);
  assert.ok(button, role);
  await session.click(button);
}
