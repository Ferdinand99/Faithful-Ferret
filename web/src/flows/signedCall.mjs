// A write with a signed proof (spec Fase 1 § 4.6, "The signature"). The order:
//
//   POST challenge          a single-use nonce (32 bytes), bound to the session
//   (the body)              the request shape's checks, then the exact bytes
//   sign                    the core signs `TLV[label, op, account_id, nonce, vk_epoch, SHA-256(body)]`
//   PUT / POST              those same bytes, with `Ferret-Nonce` and `Ferret-Proof`
//
// The body is built once, as bytes. The bytes that are signed are the bytes that are
// sent, never a second serialisation of the same value: the server hashes what it
// receives. A failure of the write itself carries `afterSend: true`; one of the challenge does not.
// Nothing here is a secret: the nonce and the proof are public, and the body
// holds only wraps, a registration record and a manifest row, which the server stores.
import { b64u } from "../b64.mjs";
import { MAX_SIGNED_BODY, NONCE_LEN, PROOF_LEN, SHAPES, encodeWireBytes } from "../wire.mjs";
import { AccountError } from "../crypto/errors.mjs";

/** @typedef {import("../crypto/env.mjs").Env} Env */

/**
 * The name of the answer shape that goes with a request shape: `password_put_req` -> `password_put_res`.
 * @param {string} shape
 * @returns {string | undefined}
 */
export function replyShapeOf(shape) {
  if (!shape.endsWith("_req")) return undefined;
  const reply = `${shape.slice(0, -"_req".length)}_res`;
  return reply in SHAPES ? reply : undefined;
}

/**
 * Makes a signed call and gives the server's answer.
 *
 * `shape` names the request shape of `wire.mjs`; the answer is checked against the
 * shape of the same name ending in `_res`, unless `reply` names another (or `null`
 * for none). `sign` is `(nonce, bytes) => proof` and defaults to the open vault's
 * `auth_sign(op, nonce, bytes)`; it receives copies, so the array that is sent is
 * never changed by it.
 * @param {Env} env
 * @param {{
 *   op: string,
 *   method: "PUT" | "POST",
 *   path: string,
 *   shape: string,
 *   body: Record<string, any>,
 *   reply?: string | null,
 *   sign?: (nonce: Uint8Array, body: Uint8Array) => Promise<Uint8Array>,
 * }} call
 * @returns {Promise<any>}
 */
export async function signedCall(env, { op, method, path, shape, body, reply, sign }) {
  const { api, client } = env;
  const bytes = encodeWireBytes(shape, body);
  if (bytes.length > MAX_SIGNED_BODY) throw new AccountError("body_too_large");
  const challenge = await api.post("/api/auth/challenge", undefined, { shape: "challenge_res" });
  const nonce = b64u.decode(challenge.nonce);
  if (nonce.length !== NONCE_LEN) throw new AccountError("bad_response");
  const signer = sign ?? ((/** @type {Uint8Array} */ n, /** @type {Uint8Array} */ b) => client.vault.auth_sign(op, n, b));
  const proof = await signer(nonce.slice(), bytes.slice());
  if (!(proof instanceof Uint8Array) || proof.length !== PROOF_LEN) throw new AccountError("bad_response");
  const answerShape = reply === undefined ? replyShapeOf(shape) : (reply ?? undefined);
  try {
    return await api.sendSigned(method, path, bytes, { nonce, proof }, answerShape === undefined ? {} : { shape: answerShape });
  } catch (error) {
    // The write was sent: the caller can tell a failure before it (nothing happened) from one after it.
    if (error !== null && typeof error === "object") /** @type {any} */ (error).afterSend = true;
    throw error;
  }
}
