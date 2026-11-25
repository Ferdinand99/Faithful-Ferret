// The verification step of Ferret's chooser window (the `passkeys` feature, design document § 9.3): what the person does when a
// website asks Ferret to check that it is them (user verification) and no unlock in the last five minutes is enough.
//
// The ways, in the order the background gives them and the window shows them:
//   - Windows Hello, Touch ID or another passkey of the vault: one WebAuthn call against the vault's host from this window (a
//     top-level window of the extension, never the toolbar popup, which closes when the system's dialog takes the focus). What the
//     call needs is read from the background before the button can be pressed, so nothing is awaited between the press and the
//     call. The 32 bytes the passkey gives go to the background in one message and are wiped here at once.
//   - the PIN;
//   - the master password, which signs in to the server (the window says so).
// Each goes to the background as `passkey_verify` with the request's id. The background checks it like an unlock, without
// touching the open vault, and issues the one-time mark for this request; the window then sends the person's choice again.
// The window never says "verified" itself.
//
// What the person types is read from its field once, when the form is sent, and the field is emptied at once (before the request
// goes out); every field is emptied again when the step is wiped (the window is built again, closes, or the vault locks).

import { b64u } from "../shared/b64.mjs";
import { codeOf } from "../shared/crypto/errors.mjs";
import { el } from "../shared/dom.mjs";
import { evaluateOneOf } from "../shared/flows/passkeyAnswer.mjs";
import { field } from "./page.mjs";

/** The feature mark on every control of the step (the build's checks look for it). */
const FEATURE = Object.freeze({ "data-feature": "passkeys" });

/** The ways to verify the window can show, in their order. */
export const VERIFY_WAYS = Object.freeze(["prf", "pin", "password"]);

/** The reasons the step has a text for (`passkeys.verify.error.<reason>`); any other reason gets the general one. */
export const VERIFY_REASONS = Object.freeze([
  "wrong_pin",
  "pin_wait",
  "pin_wiped",
  "pin_stale",
  "pin_offline_expired",
  "pin_unavailable",
  "pin_rule",
  "out_of_memory",
  "wrong_credentials",
  "sk_required",
  "network",
  "signed_out",
  "attack_warning",
  "prf_failed",
  "prf_unavailable",
  "passkey_blocked",
  "passkey_cancelled",
  "passkey_failed",
  "passkey_unsupported",
  "not_verified",
]);

/** @param {unknown} reason */
export const verifyErrorKey = (reason) => `passkeys.verify.error.${typeof reason === "string" && VERIFY_REASONS.includes(reason) ? reason : "unknown"}`;

/** A ceremony's codes that mean the same as one of the reasons above. */
const SAME_AS = Object.freeze({ passkey_no_output: "passkey_failed", passkey_bad_output: "passkey_failed", passkey_unlock_failed: "prf_failed", passkey_other_credential: "passkey_failed", passkey_bad_answer: "passkey_failed", passkey_security: "passkey_failed", passkey_not_verified: "passkey_failed" });

/** @param {unknown} error */
function reasonOfFailure(error) {
  const code = codeOf(error);
  if (Object.hasOwn(SAME_AS, code)) return /** @type {Record<string, string>} */ (SAME_AS)[code];
  return VERIFY_REASONS.includes(code) ? code : "passkey_failed";
}

/**
 * The origin Firefox writes into the client data of an extension's page: `moz-extension://` and the SHA-256 of the extension's
 * id, each nibble of its hex written as a letter from a to p. (The same rule as the unlock window's, which a package without the
 * passkey unlock does not hold.)
 * @param {string} extensionId @param {(data: Uint8Array) => Promise<Uint8Array>} sha256
 */
export async function extensionOrigin(extensionId, sha256) {
  const digest = await sha256(new TextEncoder().encode(extensionId));
  return `moz-extension://${Array.from(digest, (b) => "abcdefghijklmnop"[b >> 4] + "abcdefghijklmnop"[b & 15]).join("")}`;
}

/** @param {unknown} value @returns {value is Record<string, unknown>} */
const isRecord = (value) => typeof value === "object" && value !== null && !Array.isArray(value);

/**
 * @typedef {{ rpId: string, credentials: Array<{ id: Uint8Array, salt: Uint8Array }> }} Offer what the one WebAuthn call needs
 * @typedef {{ ok: true, credential_id: string, prf_output: string } | { ok: false, reason: string }} Proof
 */

/**
 * A passkey of the vault as the proof of the person: what the call needs (`prf_options`, read from the server now) and the one
 * call. The bytes become text for the one message to the background and are wiped at once.
 * @param {import("./ui.mjs").Request} request
 * @param {{ getAssertion: (publicKey: any) => Promise<any>, deps: Omit<import("../shared/flows/passkeyAnswer.mjs").CeremonyDeps, "credentials">, evaluate?: typeof evaluateOneOf }} how
 */
export function createPasskeyProof(request, { getAssertion, deps, evaluate = evaluateOneOf }) {
  return Object.freeze({
    /** @returns {Promise<{ ok: true, offer: Offer } | { ok: false, reason: string }>} */
    async options() {
      /** @type {unknown} */
      let reply;
      try {
        reply = await request("prf_options", {});
      } catch (error) {
        return { ok: false, reason: reasonOfFailure(error) };
      }
      if (!isRecord(reply) || reply.ok !== true) return { ok: false, reason: isRecord(reply) && typeof reply.reason === "string" ? reply.reason : "passkey_failed" };
      if (typeof reply.rp_id !== "string" || !Array.isArray(reply.credentials) || reply.credentials.length === 0) return { ok: false, reason: "prf_unavailable" };
      try {
        return { ok: true, offer: { rpId: reply.rp_id, credentials: reply.credentials.map((/** @type {any} */ c) => ({ id: b64u.decode(c.id), salt: b64u.decode(c.salt) })) } };
      } catch {
        return { ok: false, reason: "passkey_failed" };
      }
    },
    /**
     * The one WebAuthn call (call it from the click: it is the first thing it does).
     * @param {Offer} offer @returns {Promise<Proof>}
     */
    async prove(offer) {
      /** @type {{ credentialId: Uint8Array, output: Uint8Array }} */
      let answer;
      try {
        answer = await evaluate({ rpId: offer.rpId, credentials: offer.credentials, getAssertion }, deps);
      } catch (error) {
        return { ok: false, reason: reasonOfFailure(error) };
      }
      try {
        return { ok: true, credential_id: b64u.encode(answer.credentialId), prf_output: b64u.encode(answer.output) };
      } finally {
        answer.output.fill(0);
      }
    },
  });
}

/**
 * @typedef {{ ok: true } | { ok: false, reason: string, left?: number, wait_ms?: number }} Outcome
 * @param {{
 *   texts: import("./page.mjs").Texts,
 *   ways: readonly string[],
 *   verify: (method: "prf" | "pin" | "password", input: Record<string, string>) => Promise<Outcome>,
 *   proof?: ReturnType<typeof createPasskeyProof> | null,
 *   action: (attrs: Record<string, string | number | boolean | null>, label: string, run: () => void | Promise<void>) => HTMLButtonElement,
 *   onVerified: () => void,
 * }} deps
 *   `ways`: the ways the background offers (VERIFY_WAYS order); `verify`: one `passkey_verify`; `proof`: the passkey ceremony (null
 *   without it); `action`: a guarded button of the window (a click counts only when the person made it, after the 400 ms guard);
 *   `onVerified`: the background issued the mark.
 * @returns {{ root: HTMLElement, focus: () => void, wipe: () => void }}
 */
export function createVerifyStep({ texts, ways, verify, proof = null, action, onVerified }) {
  const t = (/** @type {string} */ key, /** @type {Record<string, string | number>} */ vars = {}) => texts.t(key, vars);
  /** @type {HTMLInputElement[]} */
  const secrets = [];
  let busy = false;
  let done = false;
  const error = el("p", { class: "ff-error", role: "alert", "data-role": "passkey-verify-error", hidden: true });

  /** @param {Outcome} outcome */
  const shown = (outcome) => {
    if (outcome.ok) return;
    /** @type {Record<string, string | number>} */
    const vars = typeof outcome.left === "number" ? { left: outcome.left } : {};
    error.textContent = t(outcome.reason === "wrong_pin" && typeof outcome.left !== "number" ? "passkeys.verify.error.not_verified" : verifyErrorKey(outcome.reason), vars);
    error.hidden = false;
  };

  /** @param {() => Promise<Outcome>} run */
  async function attempt(run) {
    if (busy || done) return;
    busy = true;
    error.hidden = true;
    root.setAttribute("aria-busy", "true");
    /** @type {Outcome} */
    let outcome;
    try {
      outcome = await run();
    } catch {
      outcome = { ok: false, reason: "not_verified" };
    }
    busy = false;
    root.setAttribute("aria-busy", "false");
    if (outcome.ok) {
      done = true;
      wipe();
      onVerified();
      return;
    }
    shown(outcome);
  }

  /** Enter in a field does nothing beyond sending its own form. @param {HTMLFormElement} form @param {() => void} send */
  const onSubmit = (form, send) =>
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      send();
    });

  /** @type {HTMLElement[]} */
  const parts = [];

  if (ways.includes("prf") && proof !== null) {
    /** @type {Offer | null} */
    let offer = null;
    const button = action({ class: "ff-button", "data-role": "passkey-verify-prf", disabled: true }, t("passkeys.verify.prf"), () =>
      attempt(async () => {
        if (offer === null) return { ok: false, reason: "prf_unavailable" };
        // The call first: nothing is awaited between the click and it.
        const answer = await proof.prove(offer);
        if (!answer.ok) return answer;
        return verify("prf", { credential_id: answer.credential_id, prf_output: answer.prf_output });
      }),
    );
    void proof.options().then((got) => {
      if (got.ok) {
        offer = got.offer;
        button.removeAttribute("disabled");
      } else {
        button.setAttribute("hidden", "");
      }
    });
    parts.push(el("div", { class: "ff-actions", "data-role": "passkey-verify-prf-row" }, button));
  }

  if (ways.includes("pin")) {
    const pin = field({ id: "ff-pk-verify-pin", label: t("passkeys.verify.pin"), role: "passkey-verify-pin", type: "password", autocomplete: "off", inputmode: "numeric" });
    secrets.push(pin.input);
    const submit = el("button", { type: "submit", class: "ff-button", "data-role": "passkey-verify-pin-submit", ...FEATURE }, t("passkeys.verify.confirm"));
    const form = /** @type {HTMLFormElement} */ (el("form", { class: "ff-form ff-pk-verify-form", "data-role": "passkey-verify-pin-form", ...FEATURE }, pin.row, submit));
    onSubmit(form, () => {
      const value = pin.input.value;
      pin.input.value = "";
      if (value === "") return;
      void attempt(() => verify("pin", { pin: value }));
    });
    parts.push(form);
  }

  if (ways.includes("password")) {
    const mp = field({ id: "ff-pk-verify-mp", label: t("session.password"), role: "passkey-verify-password", type: "password", autocomplete: "current-password" });
    const sk = field({ id: "ff-pk-verify-sk", label: t("session.sk.code"), role: "passkey-verify-sk", autocomplete: "off" });
    sk.row.hidden = true;
    secrets.push(mp.input, sk.input);
    const submit = el("button", { type: "submit", class: "ff-button", "data-role": "passkey-verify-password-submit", ...FEATURE }, t("passkeys.verify.confirm"));
    const form = /** @type {HTMLFormElement} */ (
      el(
        "form",
        { class: "ff-form ff-pk-verify-form", "data-role": "passkey-verify-password-form", ...FEATURE },
        mp.row,
        sk.row,
        // The master password is checked by signing in to the server: the window says so.
        el("p", { class: "ff-hint", "data-role": "passkey-verify-signs-in" }, t("passkeys.verify.signs_in")),
        submit,
      )
    );
    onSubmit(form, () => {
      const input = { mp: mp.input.value, ...(sk.input.value !== "" ? { sk: sk.input.value } : {}) };
      mp.input.value = "";
      sk.input.value = "";
      if (input.mp === "") return;
      void attempt(async () => {
        const outcome = await verify("password", input);
        if (!outcome.ok && outcome.reason === "sk_required") sk.row.hidden = false;
        return outcome;
      });
    });
    parts.push(form);
  }

  const root = el(
    "section",
    { class: "ff-pk-verify-step", "data-role": "passkey-verify-step", role: "group", "aria-labelledby": "ff-pk-verify-title", ...FEATURE },
    el("h2", { class: "ff-pk-h2", id: "ff-pk-verify-title" }, t("passkeys.verify.title")),
    ...(parts.length === 0 ? [el("p", { class: "ff-notice", "data-role": "passkey-verify-none" }, t("passkeys.verify.none"))] : parts),
    error,
  );

  function wipe() {
    for (const input of secrets) input.value = "";
  }

  return {
    root,
    // The focus goes to a field only when the person moves it there: the window opens under their hand.
    focus() {},
    wipe,
  };
}
