// The steps of the unlock window (design document, sections 7.2 and 7.3), with no DOM: what the background says the window
// needs, the one WebAuthn call, and the one message that carries what the passkey gave. The page (unlockWindow.mjs) is the
// only code with a WebAuthn call and hands it in as `getAssertion`; nothing here touches the browser.
//
// Two requests to the background, both over the UI port:
//
//   prf_options {}                            ->  { ok: true, rp_id, credentials: [{ id, salt }] } | { ok: false, reason }
//   prf_unlock { credential_id, prf_output }  ->  { ok: true, account_email, server } | { ok: false, reason }
//
// The 32 bytes a passkey gives are a lasting secret of the vault. They live here from the browser's answer until the
// message is on its way: they are encoded for that one message and the buffer is zeroed at once (the text of the request
// is all that is left in the page, as for a typed PIN), and never go anywhere but that message. The refusals of the
// ceremony (the browser said no, the user closed the prompt, the answer was not what was asked for) are the reasons the page
// has a text for; a key the vault does not open is `prf_failed`, the one answer for a wrong, a missing and a wrong-sized key.

import { b64u } from "../shared/b64.mjs";
import { codeOf } from "../shared/crypto/errors.mjs";
import { evaluateOneOf } from "../shared/flows/passkeyAnswer.mjs";

/**
 * The origin Firefox (150 and later) writes into the client data of an extension's page: `moz-extension://` and the SHA-256 of the
 * extension's id, each nibble of its hex written as a letter from a to p (64 letters). It is not the address of the page.
 * @param {string} extensionId `browser.runtime.id`
 * @param {(data: Uint8Array) => Promise<Uint8Array>} sha256
 * @returns {Promise<string>}
 */
export async function extensionOrigin(extensionId, sha256) {
  const digest = await sha256(new TextEncoder().encode(extensionId));
  return `moz-extension://${Array.from(digest, (b) => "abcdefghijklmnop"[b >> 4] + "abcdefghijklmnop"[b & 15]).join("")}`;
}

/** The reasons the page has a text of its own for (`passkey.error.<reason>`). */
export const PASSKEY_REASONS = Object.freeze([
  "passkey_bad_answer",
  "passkey_blocked",
  "passkey_cancelled",
  "passkey_failed",
  "passkey_not_verified",
  "passkey_other_credential",
  "passkey_security",
  "passkey_unlock_failed",
  "passkey_unsupported",
  "prf_failed",
  "prf_unavailable",
  "method_removed",
]);

/** The reasons that the session's own texts say (`session.error.<reason>`). */
const SESSION_REASONS = Object.freeze(["attack_warning", "network", "signed_out", "vault_locked", "busy", "worker_failed", "internal_error", "disconnected", "not_available"]);

/** A key the passkey gave of the wrong size or none at all is the same answer as a key that does not open the vault. */
const SAME_AS = Object.freeze({ passkey_no_output: "passkey_unlock_failed", passkey_bad_output: "passkey_unlock_failed" });

/**
 * The reason of an error of the ceremony or of the port, as the page shows it. One that the page has no text for is a
 * failed passkey.
 * @param {unknown} error
 * @returns {string}
 */
export function reasonOfFailure(error) {
  const code = codeOf(error);
  if (Object.hasOwn(SAME_AS, code)) return /** @type {Record<string, string>} */ (SAME_AS)[code];
  return PASSKEY_REASONS.includes(code) || SESSION_REASONS.includes(code) ? code : "passkey_failed";
}

/** The key of the text of a reason. @param {unknown} reason */
export function passkeyErrorKey(reason) {
  if (typeof reason === "string" && PASSKEY_REASONS.includes(reason)) return `passkey.error.${reason}`;
  if (typeof reason === "string" && SESSION_REASONS.includes(reason)) return `session.error.${reason}`;
  return "session.error.unknown";
}

/** Whether another try can make sense with the same window (a refusal of the browser or a closed prompt does; a removed passkey does not). @param {unknown} reason */
export function retryable(reason) {
  return reason === "passkey_blocked" || reason === "passkey_cancelled" || reason === "passkey_failed" || reason === "passkey_unlock_failed" || reason === "prf_failed" || reason === "network";
}

/** @param {unknown} value @returns {value is Record<string, unknown>} */
const isRecord = (value) => typeof value === "object" && value !== null && !Array.isArray(value);

/**
 * @typedef {{ rpId: string, credentials: Array<{ id: Uint8Array, salt: Uint8Array }> }} Offer what the WebAuthn call needs
 * @typedef {{ ok: true, offer: Offer } | { ok: false, reason: string }} OfferOutcome
 * @typedef {{ ok: true, email: string | null } | { ok: false, reason: string }} UnlockOutcome
 * @param {import("./ui.mjs").Request} request
 * @param {{
 *   getAssertion: (publicKey: any) => Promise<any>,
 *   deps: Omit<import("../shared/flows/passkeyAnswer.mjs").CeremonyDeps, "credentials">,
 *   evaluate?: typeof evaluateOneOf,
 * }} how `getAssertion` is the page's WebAuthn call; `deps` are the random source, the clock, SHA-256 and the page's origin;
 *   `evaluate` is the evaluation of the shared flow (the tests give their own)
 */
export function createUnlockWindowFlow(request, { getAssertion, deps, evaluate = evaluateOneOf }) {
  return Object.freeze({
    /**
     * What the call needs, from the background (which reads the server's list now). Nothing is offered when the background
     * says no, or says something of another shape.
     * @returns {Promise<OfferOutcome>}
     */
    async options() {
      /** @type {unknown} */
      let reply;
      try {
        reply = await request("prf_options", {});
      } catch (error) {
        return { ok: false, reason: reasonOfFailure(error) };
      }
      if (!isRecord(reply)) return { ok: false, reason: "passkey_failed" };
      if (reply.ok !== true) return { ok: false, reason: typeof reply.reason === "string" ? reasonOfFailure({ code: reply.reason }) : "passkey_failed" };
      if (typeof reply.rp_id !== "string" || !Array.isArray(reply.credentials) || reply.credentials.length === 0) return { ok: false, reason: "prf_unavailable" };
      try {
        const credentials = reply.credentials.map((/** @type {any} */ c) => ({ id: b64u.decode(c.id), salt: b64u.decode(c.salt) }));
        return { ok: true, offer: { rpId: reply.rp_id, credentials } };
      } catch {
        return { ok: false, reason: "passkey_failed" };
      }
    },

    /**
     * The one WebAuthn call and the one message after it. Call it from the click: the call is the first thing it does.
     * @param {Offer} offer what `options` gave
     * @returns {Promise<UnlockOutcome>}
     */
    async unlock(offer) {
      /** @type {{ credentialId: Uint8Array, output: Uint8Array }} */
      let answer;
      try {
        answer = await evaluate({ rpId: offer.rpId, credentials: offer.credentials, getAssertion }, deps);
      } catch (error) {
        return { ok: false, reason: reasonOfFailure(error) };
      }
      const { credentialId, output } = answer;
      /** @type {unknown} */
      let reply;
      try {
        const body = { credential_id: b64u.encode(credentialId), prf_output: b64u.encode(output) };
        const pending = request("prf_unlock", body);
        // The message is on its way: the buffer is wiped before anything is awaited.
        output.fill(0);
        reply = await pending;
      } catch (error) {
        return { ok: false, reason: reasonOfFailure(error) };
      } finally {
        output.fill(0);
      }
      if (!isRecord(reply)) return { ok: false, reason: "passkey_failed" };
      if (reply.ok === true) return { ok: true, email: typeof reply.account_email === "string" ? reply.account_email : null };
      return { ok: false, reason: typeof reply.reason === "string" ? reasonOfFailure({ code: reply.reason }) : "passkey_failed" };
    },
  });
}
