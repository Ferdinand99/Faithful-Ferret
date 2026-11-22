// The steps of the sign-in tab (design document, sections 4.2, 6.2, 7.2 and
// 10.7), with no DOM, so the tests run them as they are:
//
//   1. the server address: `https` only; the background shows its host from
//      the core's `display_host`;
//   2. the permission for that server, asked on the user's click in this tab
//      (`permissions.request`); a refusal stops here, nothing is sent;
//   3. the e-mail, the master password and the secret key question, and, if
//      the user has it, the text of the emergency sheet's QR code (it pins the
//      server, the account and the server's key before the sign-in; without it
//      the first sign-in trusts the server the first time);
//   4. the background signs in as a device and answers the account's e-mail
//      and the server, or a reason.
//
// The master password and the secret key go to the background over the UI
// port, in the request of `sign_in` or `unlock`, and nowhere else.

/**
 * @typedef {import("./ui.mjs").Request} Request
 * @typedef {{ ok: true, server: string, host?: string, host_a_label?: string } | { ok: false, reason: string }} Checked
 * @typedef {{
 *   email: string,
 *   password: string,
 *   skAnswer?: "yes" | "no" | null,
 *   secretKey?: string,
 *   remember?: boolean,
 *   qrText?: string,
 * }} SignInFields
 */

/**
 * The host permission of a server: a match pattern has no port, so it is the
 * host's (it covers the server on any port). The background checks the same.
 * @param {string} server an origin the background checked
 */
export function permissionOf(server) {
  return `https://${new URL(server).hostname}/*`;
}

/** @param {unknown} value @returns {string} */
const trimmed = (value) => (typeof value === "string" ? value.trim() : "");

/**
 * @param {{
 *   request: Request,
 *   requestPermission: (permissions: { origins: string[] }) => Promise<boolean>,
 * }} deps `requestPermission` is `browser.permissions.request`
 */
export function createSignInFlow({ request, requestPermission }) {
  /** The server the user checked, and whether this tab was given its permission. @type {{ server: string, granted: boolean } | null} */
  let chosen = null;

  return {
    /** The server checked last, or null. */
    server: () => chosen?.server ?? null,

    /** Whether the permission for the checked server was given. */
    granted: () => chosen?.granted === true,

    /**
     * Step 1: the background reads the address and shows its host.
     * @param {string} text
     * @returns {Promise<Checked>}
     */
    async check(text) {
      chosen = null;
      const typed = trimmed(text);
      if (typed === "") return { ok: false, reason: "server_invalid" };
      if (typed.length > 300) return { ok: false, reason: "server_invalid" };
      const answer = await request("server_check", { server: typed });
      if (answer?.ok !== true || typeof answer.server !== "string") {
        return { ok: false, reason: typeof answer?.reason === "string" ? answer.reason : "server_invalid" };
      }
      chosen = { server: answer.server, granted: false };
      return answer;
    },

    /**
     * Step 2: asks for the permission for the checked server. Call it in the
     * click handler, before anything else is awaited: the browser grants a
     * request only in the turn of the user's click.
     * @returns {Promise<{ ok: true } | { ok: false, reason: string }>}
     */
    grant() {
      if (chosen === null) return Promise.resolve({ ok: false, reason: "server_invalid" });
      const asked = chosen;
      return requestPermission({ origins: [permissionOf(asked.server)] }).then(
        (given) => {
          if (given !== true) return { ok: false, reason: "permission_refused" };
          asked.granted = true;
          return { ok: true };
        },
        () => ({ ok: false, reason: "permission_refused" }),
      );
    },

    /**
     * Steps 3 and 4. Nothing is sent before the permission was given.
     * @param {SignInFields} fields
     * @returns {Promise<{ ok: true, account_email: string, server: string } | { ok: false, reason: string }>}
     */
    async signIn(fields) {
      if (chosen === null) return { ok: false, reason: "server_invalid" };
      if (!chosen.granted) return { ok: false, reason: "permission_needed" };
      const email = trimmed(fields.email);
      if (email === "") return { ok: false, reason: "email_required" };
      if (typeof fields.password !== "string" || fields.password === "") return { ok: false, reason: "password_required" };
      /** @type {Record<string, unknown>} */
      const body = { server: chosen.server, email, mp: fields.password, remember_sk: fields.remember !== false };
      const code = trimmed(fields.secretKey);
      if (fields.skAnswer === "yes") {
        if (code === "") return { ok: false, reason: "sk_required" };
        body.sk = code;
      } else if (fields.skAnswer === "no") {
        body.sk_bit = false;
      }
      const qr = trimmed(fields.qrText);
      if (qr !== "") body.qr_text = qr;
      return request("sign_in", body);
    },
  };
}

/**
 * The unlock of a signed-in device, in the tab or the popup: the master
 * password, and the secret key only when this device does not keep it.
 * @param {Request} request
 * @param {{ password: string, secretKey?: string }} fields
 * @returns {Promise<{ ok: boolean, reason?: string }>}
 */
export async function unlockWith(request, fields) {
  if (typeof fields.password !== "string" || fields.password === "") return { ok: false, reason: "password_required" };
  const code = trimmed(fields.secretKey);
  return request("unlock", code === "" ? { mp: fields.password } : { mp: fields.password, sk: code });
}
