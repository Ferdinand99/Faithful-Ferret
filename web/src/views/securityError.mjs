// The text of an error on the account page, the password page and the password
// dialog. The codes that mean something particular there (a refused signed change,
// a stale password check, a conflict on the server) have a text of their own in the
// security catalog; every other code is the sign-in page's (its error texts), so a wrong
// secret key or a lost connection reads the same everywhere. The message of an error
// is never shown, because it can quote what the user typed.
import { codeOf } from "../crypto/errors.mjs";
import { describeError } from "./form.mjs";

/** The codes with a text of their own in the security catalog (one key per code). */
export const SECURITY_ERRORS = Object.freeze([
  "body_too_large", "change_unconfirmed", "decrypt", "denied", "generation_exhausted", "password_unchanged", "pin_missing", "pin_save_failed",
  "reauth_required", "second_factor_required", "secret_key_not_held", "write_conflict",
]);

/**
 * @param {import("./form.mjs").Translate} t
 * @param {unknown} error
 * @returns {string}
 */
export function securityErrorText(t, error) {
  const code = codeOf(error);
  if (SECURITY_ERRORS.includes(code)) return t(`security.error.${code}`);
  return describeError(t, error);
}
