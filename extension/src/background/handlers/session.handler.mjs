// The session's messages from the extension's own pages (the sign-in tab and
// the popup, over the UI port): the state, the check of a server address, the
// sign-in and the unlock (the lock button is in lock.handler.mjs).
//
// The sign-in and the unlock carry what the user typed (the master password,
// the secret key) to the core host's session and nowhere else. The answer is
// `{ ok, account_email, server }` or `{ ok: false, reason }` with a reason from
// REASONS: never a text of the server, of the core or of the user. A wrong
// password and an unknown e-mail give the same reason.

/**
 * The reasons a page has a text for. Every other code becomes `unknown`.
 */
export const REASONS = Object.freeze([
  "wrong_credentials",
  "attack_warning",
  "pinned_sk_bit",
  "pinned_elsewhere",
  "server_invalid",
  "server_not_https",
  "server_reserved",
  "another_server",
  "busy",
  "permission_needed",
  "signed_out",
  "network",
  "throttled",
  "quota_exceeded",
  "email_required",
  "sk_answer_required",
  "sk_required",
  "two_factor_unsupported",
  "kdf_profile_unknown",
  "methods_invalid",
  "bad_response",
  "malformed_setup_qr",
  "qr_unsupported",
  "qr_too_large",
  "qr_server_url",
  "qr_server_key",
  "qr_account",
  "qr_profile",
  "qr_sk_bit",
  "vault_locked",
  "worker_failed",
  "unknown",
]);

/** Codes that each mean one of the reasons above. */
const SAME_AS = Object.freeze({
  // The core cannot open what the server sent: a wrong password, a wrong secret key or an e-mail the server does not
  // know (it answers from a made-up record) all look the same, on purpose.
  decrypt: "wrong_credentials",
  denied: "wrong_credentials",
  // The device's sign-in has ended: it signs in again in the tab.
  session_ended: "signed_out",
  device_revoked: "signed_out",
  token_reused: "signed_out",
  token_expired: "signed_out",
  unauthorized: "signed_out",
  // What this device has pinned and the server's answers disagree: it can be an attack.
  pinned_account_id: "attack_warning",
  pinned_account_mismatch: "attack_warning",
  pinned_auth_key: "attack_warning",
  pinned_epoch_ahead: "attack_warning",
  pinned_epoch_downgrade: "attack_warning",
  pinned_floor_downgrade: "attack_warning",
  pinned_floor_missing: "attack_warning",
  pinned_identity_changed: "attack_warning",
  pinned_kek_generation: "attack_warning",
  pinned_profile_downgrade: "attack_warning",
  pinned_server_key: "attack_warning",
  pinned_server_key_changed: "attack_warning",
  pinned_server_url: "attack_warning",
  pinned_vault_id: "attack_warning",
  pinned_vk_epoch: "attack_warning",
  method_list_changed: "attack_warning",
  method_list_missing: "attack_warning",
  method_list_unknown: "attack_warning",
  epoch_mismatch: "attack_warning",
  kdf_profile_downgrade: "attack_warning",
  forbidden: "two_factor_unsupported",
  // The worker that holds the keys stopped.
  internal: "worker_failed",
  kdf_out_of_memory: "worker_failed",
});

/**
 * The reason a page shows for an error of the core host.
 * @param {unknown} error
 * @returns {string}
 */
export function reasonOf(error) {
  const code = /** @type {{ code?: unknown }} */ (error)?.code;
  if (typeof code !== "string") return "unknown";
  if (Object.hasOwn(SAME_AS, code)) return /** @type {Record<string, string>} */ (SAME_AS)[code];
  return REASONS.includes(code) ? code : "unknown";
}

/**
 * Runs a core-host operation whose failure is the user's to read: the answer
 * is the op's, or `{ ok: false, reason }`.
 * @param {() => Promise<unknown>} run
 */
async function answer(run) {
  try {
    return await run();
  } catch (error) {
    return { ok: false, reason: reasonOf(error) };
  }
}

/** @param {any} body @param {import("../router.mjs").HandlerContext} ctx */
async function handle(body, ctx) {
  const call = /** @type {NonNullable<typeof ctx.call>} */ (ctx.call);
  const lock = /** @type {NonNullable<typeof ctx.lock>} */ (ctx.lock);
  switch (ctx.type) {
    case "state": {
      const info = /** @type {Record<string, any>} */ (await call("session_state"));
      const open = ctx.state() === "unlocked";
      /** @type {Record<string, unknown>} */
      const reply = { state: open ? "unlocked" : info.signed_in === true ? "locked" : "signed_out" };
      for (const key of ["server", "host", "host_a_label", "account"]) {
        if (typeof info[key] === "string") reply[key] = info[key];
      }
      return reply;
    }
    case "server_check":
      return answer(() => call("server_check", { server: body.server }));
    case "sign_in":
      // A sign-in never runs on top of an open vault: that one is locked first.
      if (ctx.state() === "unlocked") await lock("manual");
      return answer(() => call("sign_in", body));
    case "unlock":
      if (ctx.state() === "unlocked") await lock("manual");
      return answer(() => call("unlock", body));
    default:
      throw Object.assign(new Error("not_available"), { code: "not_available" });
  }
}

export default {
  types: ["state", "server_check", "sign_in", "unlock"],
  channel: /** @type {"ui"} */ ("ui"),
  handle,
};
