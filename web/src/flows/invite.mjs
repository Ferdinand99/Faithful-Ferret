// The check of an invitation link before the person chooses a master password
// (spec Fase 1 § 4.2, `POST /api/auth/invite/check`). The token goes in the
// body, never in the address of the request. The server answers alike for an
// unknown, used, withdrawn or expired link (`403 invite_invalid`), so the page
// cannot say which, and does not try to.
import { codeOf } from "../crypto/errors.mjs";
import { encodeWire, INVITE_CHARS } from "../wire.mjs";

/** The token of an invitation link: the kit's 43 characters of base62. */
const INVITE = new RegExp(`^[0-9A-Za-z]{${INVITE_CHARS}}$`);

/** @typedef {{ post(path: string, body?: unknown, options?: object): Promise<any> }} InviteApi */

/**
 * Asks the server whether an invitation link still works. Never throws: a
 * refusal, a limit or a lost connection is `{ ok: false, code }`.
 * @param {InviteApi} api
 * @param {string} invite
 * @returns {Promise<{ ok: true, expiresAt: number, invitedBy: string } | { ok: false, code: string }>}
 *   `expiresAt` in Unix seconds (the server's clock); `invitedBy` the e-mail of the administrator who made
 *   the link, `""` when that account is gone
 */
export async function checkInvite(api, invite) {
  if (typeof invite !== "string" || !INVITE.test(invite)) return { ok: false, code: "invite_invalid" };
  try {
    const res = await api.post("/api/auth/invite/check", encodeWire("invite_check_req", { invite }), { shape: "invite_check_res" });
    return { ok: true, expiresAt: res.expires_at, invitedBy: res.invited_by };
  } catch (error) {
    return { ok: false, code: codeOf(error) };
  }
}
