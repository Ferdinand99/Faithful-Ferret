// A device client for the end-to-end scenarios: what the browser extension is, run in Node. There is no browser, so
// there is no CORS and no cookie jar, and the requests go to the vault the way an extension sends them: `credentials:
// "omit"`, `Authorization: DPoP`, a proof per request, `Ferret-Protocol: 1`, and fetch metadata that Node does not
// send by itself (`Sec-Fetch-Site: none`, as Chromium sends from an extension; `cross-site` in a run of its own).
//
// It is the real client code: `src/api.mjs`, `src/auth/*` (the device key in IndexedDB through `fake-indexeddb`, the
// proofs, the tokens) and the WebAssembly package of the pinned release (`wasm.lock.json`), the Node build of it, which
// is fetched and checked here the way the web build checks its own (the SHA-256 of the release's checksum list is
// tied to the pin). Only the sign-in is written here, because the extension's own does not exist yet: OPAQUE through the
// core's `UnlockJob`, then the device's finish with a proof, then `auth.accept`.
//
// Nothing here knows a test shortcut of the server: it signs in with the account's e-mail, master password and secret
// key, like a person would.
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { IDBFactory, IDBKeyRange } from "fake-indexeddb";
import { readTarGz } from "../../scripts/build.mjs";
import { ApiError, createApi } from "../../src/api.mjs";
import { createProof, createClock } from "../../src/auth/dpop.mjs";
import { generateDeviceKey } from "../../src/auth/deviceKey.mjs";
import { createTokenAuth } from "../../src/auth/tokens.mjs";
import { b64u } from "../../src/b64.mjs";
import { openStore } from "../../src/store/idb.mjs";

export { ApiError };

const here = dirname(fileURLToPath(import.meta.url));
const WEB = join(here, "..", "..");

/** The name the extension gives itself (what the web vault's list shows). */
export const DEVICE_NAME = "Ferret for Firefox (Windows)";

/** Where the Node build of the pinned WebAssembly package is kept. */
export const WASM_NODE_DIR = process.env.FERRET_E2E_WASM_NODE ?? join(WEB, ".wasm-node");

const sha256 = (/** @type {Uint8Array} */ bytes) => createHash("sha256").update(bytes).digest("hex");

// ------------------------------------------------------- the pinned package

/**
 * Fetches the Node build of the pinned release into `dir`. The pin (`wasm.lock.json`) names the web package and its
 * SHA-256. The release's checksum list must give the web package that same digest (so the list is the one the pin was
 * taken from), and the Node package is then checked against the list. Needs the network: run it where `npm ci` runs,
 * not in the container that has no way out.
 * @param {string} [dir]
 * @param {{ fetchImpl?: typeof fetch }} [options]
 */
export async function prepareWasmNode(dir = WASM_NODE_DIR, { fetchImpl = fetch } = {}) {
  const lock = JSON.parse(readFileSync(join(WEB, "wasm.lock.json"), "utf8"));
  const base = lock.url.slice(0, lock.url.lastIndexOf("/") + 1);
  const webName = `ferret-core-wasm-web-${lock.version}.tar.gz`;
  const nodeName = `ferret-core-wasm-node-${lock.version}.tar.gz`;
  if (!lock.url.endsWith(`/${webName}`)) throw new Error("wasm.lock.json does not name the web package of its version");
  const get = async (/** @type {string} */ name) => {
    const response = await fetchImpl(base + name);
    if (!response.ok) throw new Error(`${name}: the release answered ${response.status}`);
    return new Uint8Array(await response.arrayBuffer());
  };
  const sums = new Map(
    Buffer.from(await get("SHA256SUMS"))
      .toString("utf8")
      .split("\n")
      .map((line) => /^([0-9a-f]{64}) [ *](\S+)$/.exec(line.trim()))
      .filter((m) => m !== null)
      .map((m) => /** @type {[string, string]} */ ([m[2], m[1]])),
  );
  if (sums.get(webName) !== lock.sha256) throw new Error("the release's checksum list does not carry the pinned digest");
  const nodeSum = sums.get(nodeName);
  if (nodeSum === undefined) throw new Error("the release's checksum list has no Node package");
  const tar = await get(nodeName);
  if (sha256(tar) !== nodeSum) throw new Error("the Node package does not match its checksum");
  const files = readTarGz(tar);
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  for (const [path, bytes] of files) {
    if (!path.startsWith("pkg-node/")) continue;
    writeFileSync(join(dir, path.slice("pkg-node/".length)), bytes);
  }
  // The package is CommonJS; no `type` of the web folder's package.json may reach it.
  writeFileSync(join(dir, "package.json"), JSON.stringify({ type: "commonjs" }));
  if (!existsSync(join(dir, "ferret_core_wasm.js"))) throw new Error("the Node package has no ferret_core_wasm.js");
}

/** @type {Promise<any> | null} */
let core = null;

/** The core, from the pinned Node package (fetched on the first use when it is not there). */
export function loadCore(dir = WASM_NODE_DIR) {
  core ??= (async () => {
    if (!existsSync(join(dir, "ferret_core_wasm.js"))) await prepareWasmNode(dir);
    return createRequire(import.meta.url)(join(dir, "ferret_core_wasm.js"));
  })();
  return core;
}

// ------------------------------------------------------------ the transport

/**
 * `fetch` as an extension's background page sends it: the fetch metadata Node leaves out.
 * @param {{ site?: string | null, origin?: string | null, answers?: { url: string, status: number, code: string }[] | null }} [options] `site`: the `Sec-Fetch-Site` value (null: none is sent);
 *   `origin`: an `Origin` the extension's pages send on a request that is not a `GET`; `answers`: where the refusals (status 400 and up) are noted
 * @returns {typeof fetch}
 */
export function extensionFetch({ site = "none", origin = null, answers = null } = {}) {
  return async (input, init = {}) => {
    const headers = new Headers(init.headers ?? {});
    if (site !== null) headers.set("Sec-Fetch-Site", site);
    if (origin !== null && (init.method ?? "GET").toUpperCase() !== "GET") headers.set("Origin", origin);
    const response = await fetch(input, { ...init, headers });
    if (answers !== null && response.status >= 400) {
      // What the server refused, for a scenario that counts refusals (the body is read from a copy).
      const body = await response.clone().json().catch(() => null);
      answers.push({ url: String(input), status: response.status, code: typeof body?.error === "string" ? body.error : "" });
    }
    return response;
  };
}

// ----------------------------------------------------------------- sign-in

/** The sign-in starts (and their end) that this process made, so that it stays under the server's limit. */
const starts = /** @type {number[]} */ ([]);

/** Waits until one more sign-in start fits under the server's limit of 5 a minute (the scenarios' browsers share it). */
async function pace() {
  for (;;) {
    const now = Date.now();
    while (starts.length > 0 && now - starts[0] > 62_000) starts.shift();
    if (starts.length < 3) {
      starts.push(now);
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, starts[0] + 62_000 - now + 50));
  }
}

/**
 * @typedef {object} Device
 * @property {string} vaultUrl
 * @property {string} deviceId
 * @property {string} accountId
 * @property {import("../../src/api.mjs").Api} api the API client of the device: tokens and proofs on every request
 * @property {import("../../src/auth/tokens.mjs").TokenAuth} auth
 * @property {import("../../src/auth/dpop.mjs").Clock} clock
 * @property {{ ms: number, runaway: number, reads: number }} skew how far the device's clock is from the server's (see signInDevice)
 * @property {typeof fetch} fetchImpl the transport, with the fetch metadata of this device
 * @property {{ url: string, status: number, code: string }[]} answers the refusals the device met
 * @property {CryptoKey} privateKey
 * @property {any} publicJwk
 * @property {import("../../src/store/idb.mjs").Store} store
 */

/**
 * Signs a device in with the account's e-mail, master password and secret key, as the extension will: OPAQUE with the
 * core, then the device's finish with a DPoP proof.
 * @param {object} options
 * @param {string} options.vaultUrl
 * @param {string} options.email
 * @param {string} options.password
 * @param {string} [options.secretKey] the account's secret key code (`FFS1-…`), when it has one
 * @param {string} [options.name]
 * @param {string} [options.platform]
 * @param {string | null} [options.site] the `Sec-Fetch-Site` this device sends (null: none)
 * @param {string | null} [options.origin] an `Origin` for the requests that are not a `GET`
 * @param {Pick<LockManager, "request"> | null} [options.locks]
 * @param {number} [options.skewMs] how far this device's clock is from the server's, in milliseconds
 * @returns {Promise<Device>}
 */
export async function signInDevice({ vaultUrl, email, password, secretKey = "", name = DEVICE_NAME, platform = "windows", site = "none", origin = null, locks = null, skewMs = 0 }) {
  const wasm = await loadCore();
  const store = await openStore(new IDBFactory(), "ferret", IDBKeyRange);
  const key = await generateDeviceKey(vaultUrl);
  // The device's own clock, which a scenario can move: `ms` is a fixed distance from the server's, `runaway` makes each reading
  // another `runaway` milliseconds later than the one before (a clock that no answer can set right).
  const skew = { ms: skewMs, runaway: 0, reads: 0 };
  const clock = createClock({ now: () => { skew.reads += skew.runaway === 0 ? 0 : 1; return Date.now() + skew.ms + skew.reads * skew.runaway; } });
  /** @type {{ url: string, status: number, code: string }[]} */
  const answers = [];
  const fetchImpl = extensionFetch({ site, origin, answers });
  const auth = createTokenAuth({ serverUrl: vaultUrl, store, key, clock, fetchImpl, locks });
  const api = createApi({ base: vaultUrl, fetchImpl, auth });
  const open = createApi({ base: vaultUrl, fetchImpl });
  const job = new wasm.UnlockJob();
  try {
    for (let attempt = 0; ; attempt += 1) {
      await pace();
      try {
        const ke1 = job.login_start(new TextEncoder().encode(password), secretKey === "" ? undefined : secretKey);
        const start = await open.post("/api/auth/opaque/login/start", { email, ke1: b64u.encode(ke1), purpose: "login" }, { shape: "login_start_res" });
        const finished = job.login_finish(b64u.decode(start.ke2), start.ksf_profile, { kind: "first_use", sk_bit: secretKey !== "" });
        const body = { login_id: start.login_id, ke3: b64u.encode(finished.ke3), client: "device", device_name: name, platform };
        const answer = await finishSignIn({ vaultUrl, key, clock, fetchImpl, body });
        await auth.accept(answer);
        return { vaultUrl, deviceId: answer.device_id, accountId: answer.account_id, api, auth, clock, fetchImpl, answers, skew, privateKey: key.privateKey, publicJwk: key.publicJwk, store };
      } catch (error) {
        // The server's limit on sign-in starts counts the browsers of the run too: take the wait it names.
        if (error instanceof ApiError && error.status === 429 && attempt < 5) {
          await new Promise((resolve) => setTimeout(resolve, (error.retryAfter ?? 20) * 1000 + 2_000));
          continue;
        }
        throw error;
      }
    }
  } finally {
    job.free?.();
  }
}

/**
 * `POST login/finish` of a device: the proof is for the request and carries no token. A `dpop_invalid` answer sets the
 * clock from the server's `Date` and the request is sent once more (the sign-in is not used up by a refused proof).
 * @param {{ vaultUrl: string, key: { privateKey: CryptoKey, publicJwk: any }, clock: import("../../src/auth/dpop.mjs").Clock, fetchImpl: typeof fetch, body: unknown }} options
 */
async function finishSignIn({ vaultUrl, key, clock, fetchImpl, body }) {
  const url = new URL("/api/auth/opaque/login/finish", vaultUrl).href;
  for (let attempt = 0; ; attempt += 1) {
    const proof = await createProof(key, { method: "POST", url, clock });
    const response = await fetchImpl(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Ferret-Protocol": "1", DPoP: proof },
      body: JSON.stringify(body),
      credentials: "omit",
      redirect: "error",
      cache: "no-store",
    });
    const text = await response.text();
    /** @type {any} */
    let json = null;
    try {
      json = text === "" ? null : JSON.parse(text);
    } catch {
      json = null;
    }
    if (response.status === 200) return json;
    if (response.status === 401 && json?.error === "dpop_invalid" && attempt === 0) {
      clock.resync(response.headers.get("date"));
      continue;
    }
    throw new ApiError(response.status, typeof json?.error === "string" ? json.error : "bad_response", null, json);
  }
}

// ------------------------------------------------------------------ the sync

/** The change feed, as the device reads it (the rows are sealed: the device holds no vault key here). */
export const changes = (/** @type {Device} */ device) => device.api.get("/api/sync/changes?since=0&limit=500");

/**
 * The frames of an event stream. Ends when the stream does (an error of the connection ends it too).
 * @param {ReadableStreamDefaultReader<Uint8Array>} reader
 * @returns {AsyncGenerator<{ event: string, data: string }>}
 */
export async function* frames(reader) {
  const decoder = new TextDecoder();
  let buffer = "";
  for (;;) {
    /** @type {ReadableStreamReadResult<Uint8Array>} */
    let chunk;
    try {
      chunk = await reader.read();
    } catch {
      return;
    }
    if (chunk.done) return;
    buffer += decoder.decode(chunk.value, { stream: true });
    for (;;) {
      const end = buffer.indexOf("\n\n");
      if (end === -1) break;
      const block = buffer.slice(0, end);
      buffer = buffer.slice(end + 2);
      let event = "message";
      const data = [];
      for (const line of block.split("\n")) {
        if (line.startsWith(":")) continue;
        if (line.startsWith("event:")) event = line.slice(6).trim();
        else if (line.startsWith("data:")) data.push(line.slice(5).trim());
      }
      yield { event, data: data.join("\n") };
    }
  }
}

/**
 * Holds the device's event stream open and keeps what it sees: `hello` first, and whether it has ended.
 * @param {Device} device
 */
export async function holdStream(device) {
  const controller = new AbortController();
  const reader = await device.api.stream("/api/sync/events", { signal: controller.signal });
  /** @type {{ event: string, data: string }[]} */
  const seen = [];
  const state = { ended: false, endedAt: 0 };
  const done = (async () => {
    for await (const frame of frames(reader)) seen.push(frame);
    state.ended = true;
    state.endedAt = Date.now();
  })();
  return {
    seen,
    state,
    done,
    /** Ends the stream from this side. */
    close: () => controller.abort(),
  };
}

/** Closes what a device holds. @param {Device} device */
export function closeDevice(device) {
  try {
    device.store.close();
  } catch {
    // Already closed.
  }
}

/** Waits `ms` milliseconds. @param {number} ms */
export const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
