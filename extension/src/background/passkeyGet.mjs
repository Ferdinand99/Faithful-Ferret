// Signing in with a passkey of Ferret (the `passkeys` feature, design document § 9.2, § 9.3 and § 9.5): the background's side of
// a page's call of `get` that Ferret's chooser window answers.
//
// Three operations of the window (the handler of passkeyWindow.handler.mjs lets only that window reach them, for the request in
// its address, and only the window session that owns the request gets anything):
//
//   passkey_candidates  the passkeys of the vault that may answer the request: the core decides (`Vault.passkey_candidates`,
//                       which checks the whole request first and then compares the exact RP ID and the page's allow list), never
//                       the page and never this file. Each is named by the vault (the item's name, the passkey's user name and
//                       when it was made), and the list goes to the window only. With the list: whether a recent unlock is
//                       enough (`recent`) and which ways to verify there are now (`methods`).
//   passkey_choose      the person clicked a passkey in the window (a click with `isTrusted`, after the window's 400 ms guard:
//                       that click is the evidence of user presence). The item must still be a candidate; then user
//                       verification (below); then the core signs (`Vault.passkey_get`) and the broker answers the page.
//   passkey_verify      the verification step of the window: the recent unlock, Windows Hello or another passkey of the vault
//                       (PRF), the PIN or the master password (passkeyVerify.mjs).
//
// User verification (UV) follows what the page asked:
//   - `required` and `preferred` ask for it: UV is true only with the one-time mark of this request (passkeyVerify.mjs). Without
//     one, the window is told `verification_needed` and shows the step. When there is no way to verify at all (no server, no PIN
//     that works offline, no recent unlock), `preferred` is answered with UV false after the click, as an authenticator without
//     verification would, and `required` is told `verification_unavailable`: the window says why and offers the browser (the page gets
//     NotAllowedError only when the person cancels).
//   - `discouraged` needs only the click: UV is false (a mark that is there is dropped, not used).
// The PRF results go to the page only when it asked for them, and the core picks the seed that follows UV.
//
// A get writes nothing: no counter, no "last used", no change of the item (design § 9.5). It works without the server.

import { pageErrorOf } from "./passkeyRequests.mjs";
import { VERIFY_METHODS } from "./passkeyVerify.mjs";
import { fromB64u, responseToWire } from "../shared/webauthnWire.mjs";

/** The window's operations of a get (beside the broker's). */
export const PASSKEY_GET_OPS = Object.freeze(["passkey_candidates", "passkey_choose", "passkey_verify"]);

/** How many items are opened at once to ask the core which of them may answer. */
export const CANDIDATE_BATCH = 64;
/** The most candidates the window is told about. */
export const MAX_CANDIDATES = 200;

const UV = Object.freeze(["required", "preferred", "discouraged"]);
const ITEM_ID = /^[0-9a-f]{32}$/;
/** The core's codes that say the vault or its worker is gone: the core host handles those (the window unlocks first). */
const VAULT_GONE = Object.freeze(["vault_locked", "locked", "worker_failed", "internal", "kdf_out_of_memory"]);
/** The core's codes that refuse the request itself (its options, its RP ID, its caller): the request ends as the browser would end it. */
const REQUEST_CODES = Object.freeze(["malformed_rp_id", "invalid_input", "too_large", "invalid_state", "not_allowed"]);
/** What the window is told when the core refused the request itself (the page gets the error the browser would give). */
const REFUSED_REASONS = Object.freeze({ SecurityError: "security_error", TypeError: "type_error", InvalidStateError: "not_allowed", NotAllowedError: "not_allowed" });

/** @param {string} code */
const fail = (code) => Object.assign(new Error(code), { code });

/**
 * The request of a page's `get` as the core reads it (`passkey_get`, `passkey_candidates`), from the wire options
 * (PASSKEY_GET_OPTIONS): the bytes as Uint8Array, the allow list as credential ids, the page's `userVerification` (an unknown
 * value is `preferred`, as WebAuthn reads it) and the PRF inputs only when the page asked for them. Null for options it cannot
 * read (the bridge checked them already, so this is not expected).
 * @param {any} options
 * @returns {{ challenge: Uint8Array, rp_id?: string, allow: Uint8Array[], user_verification: string, prf?: { eval?: { first: Uint8Array, second?: Uint8Array }, eval_by_credential: Array<{ id: Uint8Array, first: Uint8Array, second?: Uint8Array }> } } | null}
 */
export function getRequestOf(options) {
  try {
    if (typeof options !== "object" || options === null || typeof options.challenge !== "string") return null;
    /** @param {any} s */
    const salts = (s) => ({ first: fromB64u(s.first), ...(typeof s.second === "string" ? { second: fromB64u(s.second) } : {}) });
    const allow = (Array.isArray(options.allow_credentials) ? options.allow_credentials : [])
      .filter((/** @type {any} */ c) => c?.type === "public-key" && typeof c.id === "string")
      .map((/** @type {any} */ c) => fromB64u(c.id));
    /** @type {any} */
    const out = {
      challenge: fromB64u(options.challenge),
      allow,
      user_verification: UV.includes(options.user_verification) ? options.user_verification : "preferred",
    };
    if (typeof options.rp_id === "string") out.rp_id = options.rp_id;
    const prf = options.extensions?.prf;
    if (typeof prf === "object" && prf !== null) {
      out.prf = {
        ...(typeof prf.eval === "object" && prf.eval !== null ? { eval: salts(prf.eval) } : {}),
        eval_by_credential: (Array.isArray(prf.eval_by_credential) ? prf.eval_by_credential : []).map((/** @type {any} */ e) => ({ id: fromB64u(e.id), ...salts(e) })),
      };
    }
    return out;
  } catch {
    return null;
  }
}

/** @param {unknown} value @returns {Uint8Array | null} */
const bytesOf = (value) => (value instanceof Uint8Array ? value : null);

/**
 * The answer for the page on the wire (PASSKEY_RESPONSE), from the core's answer to `passkey_get`. The PRF results go only to a
 * page that asked for them: `prf: {}` when it asked and the passkey has none (one made without PRF), nothing when it did not.
 * @param {any} signed what `Vault.passkey_get` returned @param {boolean} askedPrf
 * @returns {Record<string, unknown>}
 */
export function getAnswerOf(signed, askedPrf) {
  /** @type {any} */
  const ext = {};
  if (askedPrf) {
    const first = bytesOf(signed?.prf?.first);
    const second = bytesOf(signed?.prf?.second);
    ext.prf = first !== null ? { results: { first, ...(second !== null ? { second } : {}) } } : {};
  }
  return responseToWire("get", {
    id: /** @type {Uint8Array} */ (bytesOf(signed?.id)),
    client_data_json: /** @type {Uint8Array} */ (bytesOf(signed?.client_data_json)),
    authenticator_data: /** @type {Uint8Array} */ (bytesOf(signed?.authenticator_data)),
    authenticator_attachment: typeof signed?.authenticator_attachment === "string" ? signed.authenticator_attachment : null,
    signature: /** @type {Uint8Array} */ (bytesOf(signed?.signature)),
    user_handle: bytesOf(signed?.user_handle),
    client_extension_results: ext,
  });
}

/**
 * @typedef {{ id: string, name?: string, hasPasskey?: boolean, passkeySite?: string | null, damaged?: boolean, quarantined?: boolean }} Summary
 * @typedef {{ list(): Summary[], open(id: string): Promise<{ handle: number, close(): Promise<void> }> }} ItemSource the sync
 *   engine's list and its `open` (nothing that writes)
 * @typedef {{
 *   requestOf(id: string, session: string): { kind: "create" | "get", options: any } | null,
 *   callerOf(id: string, session: string): Readonly<Record<string, unknown>> | null,
 *   answer(id: string, session: string, response: Record<string, unknown>): Promise<boolean>,
 *   fail(id: string, session: string, name: string): boolean,
 * }} Broker the request broker (passkeyRequests.mjs): every call names the window session that owns the request
 */

/**
 * @param {{
 *   requests: Broker,
 *   verify: ReturnType<typeof import("./passkeyVerify.mjs").createPasskeyVerify>,
 *   items: () => ItemSource | null,
 *   create?: ((client: any, args: any) => Promise<unknown>) | null,
 * }} deps `items`: the sync engine's items of the open vault (null while none runs); `create`: the create side of
 *   `passkey_choose` (a build without it refuses a create choice as `not_available`)
 */
export function createPasskeyGet({ requests, verify, items, create = null }) {
  /** @param {any} args */
  const refOf = (args) => ({ request_id: typeof args?.request_id === "string" ? args.request_id : "", session: typeof args?.session === "string" ? args.session : "" });

  /**
   * A refusal of the core for the request itself (malformed options, an RP ID the origin may not use, a refused caller): the
   * request ends as the browser would end it, and the window is told why. The vault going away is the core host's.
   * @param {unknown} error @param {{ request_id: string, session: string }} ref
   */
  const refusal = (error, ref) => {
    const code = /** @type {{ code?: unknown }} */ (error)?.code;
    if (typeof code === "string" && VAULT_GONE.includes(code)) throw error;
    // Only the core's refusal of the request itself ends it; anything else (an item that changed since the list, a busy engine)
    // leaves the request to the person, who can choose again or use the browser.
    if (typeof code !== "string" || !REQUEST_CODES.includes(code)) return { ok: false, reason: "internal_error" };
    const name = pageErrorOf(code);
    requests.fail(ref.request_id, ref.session, name);
    return { ok: false, reason: /** @type {Record<string, string>} */ (REFUSED_REASONS)[name] ?? "not_allowed" };
  };

  /** The ids of the items that hold a passkey (the engine's summary says so; the core decides which may answer). */
  const passkeyItems = (/** @type {ItemSource} */ source) =>
    source
      .list()
      .filter((s) => (s?.hasPasskey === true || typeof s?.passkeySite === "string") && s.damaged !== true && s.quarantined !== true && typeof s.id === "string" && ITEM_ID.test(s.id))
      .map((s) => s.id);

  /**
   * Opens the items of `ids` in batches and asks the core which of them may answer `request`; calls `found` with each open
   * candidate (its handle is open while `found` runs) and closes every handle before it returns, whatever happened.
   * @param {any} client @param {ItemSource} source @param {string[]} ids @param {any} caller @param {any} request
   * @param {(id: string, handle: number) => Promise<boolean | void>} found returns true to stop
   */
  async function eachCandidate(client, source, ids, caller, request, found) {
    for (let from = 0; from < ids.length; from += CANDIDATE_BATCH) {
      /** @type {Array<{ id: string, handle: number, close(): Promise<void> }>} */
      const open = [];
      try {
        for (const id of ids.slice(from, from + CANDIDATE_BATCH)) {
          try {
            const ref = await source.open(id);
            open.push({ id, handle: ref.handle, close: () => ref.close() });
          } catch (error) {
            const code = /** @type {{ code?: unknown }} */ (error)?.code;
            if (typeof code === "string" && VAULT_GONE.includes(code)) throw error;
            // An item that does not open (damaged since the list was read) is no candidate.
          }
        }
        if (open.length === 0) continue;
        /** @type {unknown} */
        const handles = await client.vault.passkey_candidates(caller, request);
        const mine = new Map(open.map((o) => [o.handle, o]));
        for (const handle of Array.isArray(handles) ? handles : []) {
          const item = mine.get(handle);
          if (item !== undefined && (await found(item.id, item.handle)) === true) return;
        }
      } finally {
        for (const o of open) await o.close().catch(() => {});
      }
    }
  }

  /**
   * The request a window op names, for the session that owns it: its options, the caller the broker built and the core's
   * request. Null when it has ended or is not this session's.
   * @param {{ request_id: string, session: string }} ref
   */
  const getOf = (ref) => {
    const req = requests.requestOf(ref.request_id, ref.session);
    if (req === null) return null;
    const caller = requests.callerOf(ref.request_id, ref.session);
    if (caller === null) return null;
    return { kind: req.kind, options: req.options, caller, request: req.kind === "get" ? getRequestOf(req.options) : null };
  };

  /** @type {import("./coreHost.mjs").CoreOp} */
  const candidates = {
    vault: true,
    worker: "vault",
    async run(client, args) {
      const ref = refOf(args);
      const got = getOf(ref);
      if (got === null) return { ok: false, reason: "gone" };
      if (got.kind !== "get") return { ok: false, reason: "invalid_input" };
      if (got.request === null) {
        requests.fail(ref.request_id, ref.session, "TypeError");
        return { ok: false, reason: "type_error" };
      }
      const source = items();
      if (source === null) return { ok: false, reason: "busy" };
      /** @type {Array<{ item_id: string, name: string, user_name: string, created: number | null }>} */
      const list = [];
      try {
        await eachCandidate(client, source, passkeyItems(source), got.caller, got.request, async (id, handle) => {
          const view = await client.vault.item_view(handle);
          const created = view?.passkey?.created;
          list.push({
            item_id: id,
            name: typeof view?.name === "string" ? view.name.slice(0, 1024) : "",
            user_name: typeof view?.passkey?.user_name === "string" ? view.passkey.user_name.slice(0, 1024) : "",
            created: Number.isSafeInteger(created) && created > 0 ? created : null,
          });
          return false;
        });
      } catch (error) {
        return refusal(error, ref);
      }
      const ways = await verify.methods();
      // The order of the window (oldest first, the item id breaking a tie), then the cap: a vault with more keeps the oldest.
      list.sort((x, y) => (x.created ?? Number.MAX_SAFE_INTEGER) - (y.created ?? Number.MAX_SAFE_INTEGER) || (x.item_id < y.item_id ? -1 : x.item_id > y.item_id ? 1 : 0));
      list.length = Math.min(list.length, MAX_CANDIDATES);
      return { ok: true, candidates: list, recent: await verify.recent(), methods: VERIFY_METHODS.filter((m) => /** @type {Record<string, boolean>} */ (/** @type {unknown} */ (ways))[m] === true), online: ways.online };
    },
  };

  /**
   * A get: the person's click on a passkey of the list. See the head of the file for UV.
   * @param {any} client @param {{ request_id: string, session: string }} ref @param {any} got @param {unknown} itemId
   */
  async function chooseGet(client, ref, got, itemId) {
    if (typeof itemId !== "string" || !ITEM_ID.test(itemId)) return { ok: false, reason: "invalid_input" };
    if (got.request === null) {
      requests.fail(ref.request_id, ref.session, "TypeError");
      return { ok: false, reason: "type_error" };
    }
    const source = items();
    if (source === null) return { ok: false, reason: "busy" };
    const request = got.request;
    const wanted = request.user_verification;
    /** @type {Record<string, unknown> | null} */
    let answer = null;
    /** @type {{ ok: false, reason: string } | null} */
    let refused = null;
    try {
      await eachCandidate(client, source, passkeyItems(source).filter((id) => id === itemId), got.caller, request, async (_id, handle) => {
        // The item is a candidate of this request (the core said so just now). Then UV, and only then the signature.
        const decided = await verify.decide(ref, wanted);
        if (!decided.ok) {
          refused = decided;
          return true;
        }
        const signed = await client.vault.passkey_get(handle, request, got.caller, { user_present: true, user_verified: decided.uv });
        answer = getAnswerOf(signed, request.prf !== undefined);
        return true;
      });
    } catch (error) {
      return refusal(error, ref);
    }
    if (refused !== null) return refused;
    // Not a candidate of this request (never was one, or the item changed since the list): nothing is signed.
    if (answer === null) return { ok: false, reason: "not_found" };
    return (await requests.answer(ref.request_id, ref.session, answer)) ? { ok: true } : { ok: false, reason: "gone" };
  }

  /** @type {import("./coreHost.mjs").CoreOp} */
  const choose = {
    vault: true,
    worker: "vault",
    async run(client, args) {
      const ref = refOf(args);
      const got = getOf(ref);
      if (got === null) return { ok: false, reason: "gone" };
      if (args?.kind !== got.kind) return { ok: false, reason: "invalid_input" };
      if (got.kind === "get") return chooseGet(client, ref, got, args?.item_id);
      // A new passkey is the create side's (its own task); a build without it has nothing to offer.
      if (create === null) return { ok: false, reason: "not_available" };
      return create(client, args);
    },
  };

  /** @type {import("./coreHost.mjs").CoreOp} */
  const verifyOp = {
    vault: true,
    worker: "vault",
    async run(_client, args) {
      const ref = refOf(args);
      if (getOf(ref) === null) return { ok: false, reason: "gone" };
      const method = typeof args?.method === "string" ? args.method : "";
      /** @type {Record<string, unknown>} */
      const input = {};
      for (const key of ["pin", "mp", "sk", "credential_id", "prf_output"]) if (typeof args?.[key] === "string") input[key] = args[key];
      return verify.verify(ref, method, input);
    },
  };

  return {
    ops: Object.freeze({ passkey_candidates: candidates, passkey_choose: choose, passkey_verify: verifyOp }),
  };
}
