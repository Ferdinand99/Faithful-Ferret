// Helpers for the tests of a device client's tokens: a device signed in to a
// fake server, whose answers each test writes, and readers for what was sent.
import assert from "node:assert/strict";
import { createApi } from "../../src/api.mjs";
import { generateDeviceKey } from "../../src/auth/deviceKey.mjs";
import { createClock } from "../../src/auth/dpop.mjs";
import { createTokenAuth } from "../../src/auth/tokens.mjs";
import { ACCOUNT, freshStore, SERVER, VAULT } from "./idbHelpers.mjs";

export { ACCOUNT, SERVER, VAULT };
export const DEVICE = "7e3a9c1f5b2d48a6b0c4d8e2f6a1b3c5";
/** The local clock of the device, in milliseconds (2026-11-01). */
export const LOCAL_MS = 1_793_491_200_000;

/** A token on the wire: 32 bytes of `fill` as base64url. */
export const tok = (/** @type {number} */ fill) => Buffer.alloc(32, fill).toString("base64url");

/** The answer of a device sign-in. */
export const loginRes = (access = tok(1), refresh = tok(2)) => ({
  account_id: ACCOUNT,
  vault_id: VAULT,
  vk_epoch: 1,
  device_id: DEVICE,
  access_token: access,
  refresh_token: refresh,
  token_type: "DPoP",
  expires_in: 900,
});

/** The answer of a renewal. */
export const tokenRes = (access, refresh) => ({ access_token: access, refresh_token: refresh, token_type: "DPoP", expires_in: 900 });

/**
 * A JSON answer the way the server writes it: `no-store`, and a `Date` when given.
 * @param {number} status
 * @param {unknown} body null for no body
 * @param {{ date?: string, headers?: Record<string, string> }} [options]
 */
export function answer(status, body, { date, headers = {} } = {}) {
  /** @type {Record<string, string>} */
  const all = { "cache-control": "no-store", ...(body === null ? {} : { "content-type": "application/json" }), ...headers };
  if (date !== undefined) all.date = date;
  return new Response(body === null ? null : JSON.stringify(body), { status, headers: all });
}

/** A refusal with the server's code. */
export const refusal = (code, options = {}) => answer(401, { error: code }, options);

/** A 200 event stream. */
export const eventStream = () =>
  new Response("event: hello\ndata: {}\n\n", { status: 200, headers: { "content-type": "text/event-stream", "cache-control": "no-store" } });

/** The claims of a DPoP proof. */
export function claimsOf(proof) {
  const [, claims] = proof.split(".");
  return JSON.parse(Buffer.from(claims, "base64url").toString("utf8"));
}

/** The header of a DPoP proof. */
export function headerOf(proof) {
  const [header] = proof.split(".");
  return JSON.parse(Buffer.from(header, "base64url").toString("utf8"));
}

/** Whether `proof` is signed by the key of `publicJwk` (WebCrypto). */
export async function verifies(proof, publicJwk) {
  const [header, claims, signature] = proof.split(".");
  const key = await crypto.subtle.importKey("jwk", publicJwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  return crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    Buffer.from(signature, "base64url"),
    new TextEncoder().encode(`${header}.${claims}`),
  );
}

/**
 * A fake server: records every request and answers with `handle`, which a
 * test may replace at any time. A call is `{ url, path, init, headers, body }`
 * with the body parsed as JSON when it is a string.
 */
export function fakeServer() {
  /** @type {Array<{ url: string, path: string, init: RequestInit, headers: Record<string, string>, body: any }>} */
  const calls = [];
  const server = {
    calls,
    /** @type {(call: (typeof calls)[number]) => Response | Promise<Response>} */
    handle: () => assert.fail("the server got a request no test expected"),
    /** @type {typeof fetch} */
    fetchImpl: async (url, init = {}) => {
      const call = {
        url: String(url),
        path: new URL(String(url)).pathname,
        init,
        headers: /** @type {Record<string, string>} */ (init.headers ?? {}),
        body: typeof init.body === "string" ? JSON.parse(init.body) : init.body,
      };
      calls.push(call);
      return server.handle(call);
    },
    /** The calls to one path. */
    to: (/** @type {string} */ path) => calls.filter((call) => call.path === path),
  };
  return server;
}

/**
 * A device signed in to a fake server: the sign-in answer gave it the access
 * token `tok(1)` and the refresh token `tok(2)`.
 * @param {{ now?: () => number }} [options] the local clock in milliseconds
 */
export async function signedInDevice({ now = () => LOCAL_MS } = {}) {
  const db = await freshStore();
  const clock = createClock({ now });
  const key = await generateDeviceKey(SERVER);
  const server = fakeServer();
  const auth = createTokenAuth({ serverUrl: SERVER, store: db.store, key, clock, fetchImpl: server.fetchImpl });
  await auth.accept(loginRes());
  assert.equal(server.calls.length, 0, "a first sign-in on a server has no older device to sign out");
  const api = createApi({ base: SERVER, fetchImpl: server.fetchImpl, auth });
  return { db, clock, key, server, auth, api };
}
