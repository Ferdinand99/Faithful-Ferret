// What Ferret's chooser window asks for a page's passkey request and what the person chooses (the `passkeys` feature, design
// document § 9.3 and § 9.4), on the background's side. The window's handler (handlers/passkeyWindow.handler.mjs) gates every
// message (a top-level `pages/passkey.html?r=<id>` of this extension, the session that owns the request, its browser window); the
// broker (passkeyRequests.mjs) is the one that knows the request, builds the caller for the core and answers the page.
//
// passkey_create_options  what the vault has for a create request: the items a new passkey can be added to (a login of this
//                         address by host or exactly, without a passkey; `same_user` when its user name is the page's), the item
//                         that already holds a passkey for the same RP ID and user handle (`existing`), and the folders, each
//                         named by a reference good for this request only; with it, whether a recent unlock is enough and the
//                         ways to verify
// chooseCreate            the create side of the window's `passkey_choose` (the op is passkeyGet.mjs's, which hands a create choice
//                         on here): a new item (a name, a folder) or an item to add to. The click in the window is the evidence of
//                         user presence (only this top-level window sends it); user verification is decided as for a get
//                         (passkeyVerify.mjs `decide`). The passkey is made in the core and written by passkeyWrite.mjs, and the
//                         page gets its answer only after the server has the item.
//
// Everything the window gets is the vault's and the core's, never the page's: the RP ID is the one the core checked, and the
// items are read in the core. The page learns nothing from the window's messages: it gets its answer, or the error the browser
// would give, when the request ends.

import { fromB64u, responseToWire } from "../shared/webauthnWire.mjs";
import { pageErrorOf } from "./passkeyRequests.mjs";
import { VERIFY_METHODS } from "./passkeyVerify.mjs";

/** The core operations of this module (also the chooser window's UI types). */
export const PASSKEY_CHOICE_OPS = Object.freeze(["passkey_create_options"]);

/** The core's codes that say the vault or its worker is gone: the core host handles those (the window asks for the unlock). */
const VAULT_GONE = Object.freeze(["vault_locked", "locked", "worker_failed", "internal", "kdf_out_of_memory", "stopped"]);
/** What the window is told when the core ended the request, by the page's error. */
const ENDED = Object.freeze({
  SecurityError: "security_error",
  TypeError: "type_error",
  NotSupportedError: "type_error",
  InvalidStateError: "excluded",
  NotAllowedError: "not_allowed",
});
const UV = Object.freeze(["required", "preferred", "discouraged"]);
const REF = /^[0-9a-f]{32}$/;
/** The most requests whose folder references are kept. */
const MAX_REF_REQUESTS = 8;
/** The longest name of a new item. */
const MAX_NAME = 200;

/**
 * The core's create request from the page's options on the wire (PASSKEY_CREATE_OPTIONS): the bytes decoded, the algorithms and
 * excluded credentials of type `public-key` only, `cred_props` always a boolean, the PRF salts only when the page gave them.
 * @param {any} o
 */
export function createRequestOf(o) {
  const params = Array.isArray(o.pub_key_cred_params) ? o.pub_key_cred_params : [];
  const excluded = Array.isArray(o.exclude_credentials) ? o.exclude_credentials : [];
  const uv = o.authenticator_selection?.user_verification;
  /** @type {Record<string, unknown>} */
  const request = {
    challenge: fromB64u(o.challenge),
    rp_id: typeof o.rp?.id === "string" ? o.rp.id : null,
    rp_name: typeof o.rp?.name === "string" ? o.rp.name : "",
    user_id: fromB64u(o.user.id),
    user_name: typeof o.user?.name === "string" ? o.user.name : "",
    user_display_name: typeof o.user?.display_name === "string" ? o.user.display_name : "",
    algorithms: params.filter((/** @type {any} */ p) => p?.type === "public-key").map((/** @type {any} */ p) => p.alg),
    exclude: excluded.filter((/** @type {any} */ c) => c?.type === "public-key").map((/** @type {any} */ c) => fromB64u(c.id)),
    user_verification: UV.includes(uv) ? uv : "preferred",
    cred_props: o.extensions?.cred_props === true,
  };
  const prf = o.extensions?.prf;
  if (prf !== undefined) {
    const salts = prf.eval;
    request.prf = salts ? { eval: { first: fromB64u(salts.first), ...(typeof salts.second === "string" ? { second: fromB64u(salts.second) } : {}) } } : {};
  }
  return request;
}

/**
 * The answer for the page on the wire, from the core's answer of `passkey_create_confirm`.
 * @param {any} r
 */
export function createResponseOf(r) {
  /** @type {Record<string, unknown>} */
  const ext = {};
  if (r.cred_props) ext.cred_props = { rk: r.cred_props.rk === true };
  if (r.prf) ext.prf = { enabled: r.prf.enabled === true, ...(r.prf.results ? { results: r.prf.results } : {}) };
  return responseToWire("create", {
    id: r.id,
    client_data_json: r.client_data_json,
    authenticator_data: r.authenticator_data,
    authenticator_attachment: r.authenticator_attachment ?? null,
    attestation_object: r.attestation_object,
    spki: r.public_key_spki ?? null,
    public_key_algorithm: r.alg,
    transports: Array.isArray(r.transports) ? r.transports : [],
    client_extension_results: ext,
  });
}

/**
 * @param {{
 *   requests: ReturnType<typeof import("./passkeyRequests.mjs").createPasskeyRequests>,
 *   writer: () => ReturnType<typeof import("./passkeyWrite.mjs").createPasskeyWrite> | null,
 *   verify: ReturnType<typeof import("./passkeyVerify.mjs").createPasskeyVerify>,
 *   random?: (bytes: Uint8Array) => Uint8Array,
 * }} deps `writer`: the passkey writer of the open vault (null when the sync does not run); `verify`: user verification
 */
export function createPasskeyFlow({ requests, writer, verify, random = (bytes) => globalThis.crypto.getRandomValues(/** @type {Uint8Array<ArrayBuffer>} */ (bytes)) }) {
  /** The folder references a window was given, per request: reference -> folder name. @type {Map<string, Map<string, string>>} */
  const folderRefs = new Map();

  const newRef = () => Array.from(random(new Uint8Array(16)), (b) => b.toString(16).padStart(2, "0")).join("");

  /** @param {string} id @param {string[]} names */
  function issueFolders(id, names) {
    const known = folderRefs.get(id) ?? new Map();
    folderRefs.delete(id);
    folderRefs.set(id, known);
    while (folderRefs.size > MAX_REF_REQUESTS) folderRefs.delete(/** @type {string} */ (folderRefs.keys().next().value));
    /** @type {Array<{ id: string, name: string }>} */
    const out = [];
    for (const name of names) {
      let ref = [...known].find(([, n]) => n === name)?.[0];
      if (ref === undefined) {
        ref = newRef();
        known.set(ref, name);
      }
      out.push({ id: ref, name });
    }
    return out;
  }

  /**
   * The site the core checked for a request, or the reason the window is told when the core refused it (the request has then
   * ended as the browser would end it). The vault's own loss is the core host's: it is thrown.
   * @param {any} client @param {any} req
   * @returns {Promise<{ site: { rp_id: string } } | { reason: string }>}
   */
  async function siteOf(client, req) {
    try {
      return { site: await client.vault.passkey_site(req.caller, req.askedRpId) };
    } catch (error) {
      const code = /** @type {{ code?: unknown }} */ (error)?.code;
      if (typeof code === "string" && VAULT_GONE.includes(code)) throw error;
      const name = pageErrorOf(code);
      requests.fail(req.id, req.session, name);
      return { reason: name === "InvalidStateError" ? "not_allowed" : ENDED[name] };
    }
  }

  /** The scan of the vault for a request. @param {any} w @param {any} req @param {string} rpId */
  const scanFor = (w, req, rpId) =>
    w.scan({ url: req.url, rpId, userId: fromB64u(req.options.user.id), userName: typeof req.options.user?.name === "string" ? req.options.user.name : "" });

  /**
   * A create choice: a new item or an item to add to.
   * @param {any} client @param {any} args
   */
  async function chooseCreate(client, args) {
    const req = /** @type {any} */ (requests.createOf(args));
    if (req === null) return { ok: false, reason: "gone" };
    const mode = args?.mode;
    if (mode !== "new" && mode !== "attach") return { ok: false, reason: "invalid_input" };
    const w = writer();
    if (w === null || !w.ready()) return { ok: false, reason: "network" };
    /** @type {string | null} */
    let folder = null;
    /** @type {string} */
    let name = "";
    if (mode === "new") {
      name = typeof args.name === "string" ? args.name.trim() : "";
      if (name === "" || [...name].length > MAX_NAME) return { ok: false, reason: "invalid_input" };
      if (args.folder_id !== undefined) {
        folder = typeof args.folder_id === "string" && REF.test(args.folder_id) ? folderRefs.get(req.id)?.get(args.folder_id) ?? null : null;
        if (folder === null) return { ok: false, reason: "invalid_input" };
      }
    } else if (typeof args.item_id !== "string" || !REF.test(args.item_id)) {
      return { ok: false, reason: "invalid_input" };
    }
    const level = UV.includes(req.options.authenticator_selection?.user_verification) ? req.options.authenticator_selection.user_verification : "preferred";
    const found = await siteOf(client, req);
    if ("reason" in found) return { ok: false, reason: found.reason };
    const scanned = await scanFor(w, req, found.site.rp_id);
    /** @type {{ item_id: string, rev: number } | null} */
    let attach = null;
    if (mode === "attach") {
      const target = scanned.targets.find((/** @type {any} */ t) => t.item_id === args.item_id);
      if (target === undefined) return { ok: false, reason: "not_found" };
      attach = { item_id: target.item_id, rev: target.rev };
    }
    // Nothing is written for a page that is no longer the one that asked.
    if (!(await requests.recheck(req.id, req.session))) return { ok: false, reason: "gone" };
    // User verification, decided as for a get (passkeyVerify.mjs): the request's one-time mark or the recent unlock gives UV, and
    // the mark is used here. A write the server refused gave the page nothing, so the mark is given back for the person's next try
    // of the same request.
    const ref = { request_id: req.id, session: req.session };
    const decided = await verify.decide(ref, level);
    if (!decided.ok) return decided;
    /** A refusal that answered the page nothing: the mark goes back to the request. @param {{ ok: false, reason: string }} out */
    const giveBack = (out) => {
      if (decided.uv) verify.restore(ref);
      return out;
    };
    // User presence: the click in this window is the evidence (only the window's own choice reaches this op).
    const uv = { user_present: true, user_verified: decided.uv };
    const write = w;
    const rpId = found.site.rp_id;
    /** @type {(() => void) | null} */
    let release = null;
    // The deadline is held from the upload's start until the page is answered (or the write is refused).
    const hold = () => {
      release = requests.holdDeadline(req.id, req.session);
    };
    try {
      return await saveAndAnswer();
    } finally {
      /** @type {(() => void) | null} */ (release)?.();
    }

    async function saveAndAnswer() {
      /** @type {any} */
      let outcome;
      try {
        outcome = await write.save(
          { request: createRequestOf(req.options), caller: req.caller, uv, stored: scanned.stored, name, folder, attach, rpId },
          { started: hold, wanted: () => requests.waiting(req.id, req.session) },
        );
      } catch (error) {
        const code = /** @type {{ code?: unknown }} */ (error)?.code;
        if (typeof code === "string" && VAULT_GONE.includes(code)) throw error;
        // The core refused: excludeCredentials named a passkey of the vault (InvalidStateError after the click), or options it
        // cannot take. The request ends as the browser would end it.
        const page = pageErrorOf(code);
        if (page === "NotAllowedError") return giveBack({ ok: false, reason: "internal_error" });
        requests.fail(req.id, req.session, page);
        return { ok: false, reason: ENDED[page] };
      }
      if (outcome.kind === "late") return { ok: false, reason: "gone" };
      if (outcome.kind === "refused") return giveBack({ ok: false, reason: outcome.reason });
      /** @type {Record<string, unknown>} */
      let wire;
      try {
        wire = createResponseOf(outcome.response);
      } catch {
        outcome.undo();
        requests.fail(req.id, req.session, "NotAllowedError");
        return { ok: false, reason: "internal_error" };
      }
      if (await requests.answer(req.id, req.session, wire)) {
        folderRefs.delete(req.id);
        return { ok: true };
      }
      // The page went (or its frame chain changed) between the server's yes and the answer: nobody got the passkey.
      outcome.undo();
      return { ok: false, reason: "gone" };
    }
  }

  return Object.freeze({
    ops: Object.freeze({
      passkey_create_options: {
        vault: true,
        worker: /** @type {const} */ ("vault"),
        run: async (/** @type {any} */ client, /** @type {any} */ args) => {
          const req = /** @type {any} */ (requests.createOf(args));
          if (req === null) return { ok: false, reason: "gone" };
          const w = writer();
          if (w === null || !w.ready()) return { ok: false, reason: "network" };
          const found = await siteOf(client, req);
          if ("reason" in found) return { ok: false, reason: found.reason };
          const scanned = await scanFor(w, req, found.site.rp_id);
          if (!requests.waiting(req.id, req.session)) return { ok: false, reason: "gone" };
          const ways = await verify.methods();
          return {
            ok: true,
            targets: scanned.targets.map((/** @type {any} */ t) => ({ item_id: t.item_id, name: t.name, user_name: t.user_name, same_user: t.same_user })),
            existing: scanned.existing,
            folders: issueFolders(req.id, scanned.folders),
            recent: await verify.recent(),
            methods: VERIFY_METHODS.filter((m) => /** @type {Record<string, boolean>} */ (/** @type {unknown} */ (ways))[m] === true),
          };
        },
      },
    }),
    // The create side of the window's one `passkey_choose` (passkeyGet.mjs holds the op and hands a create choice on here).
    chooseCreate,
  });
}
