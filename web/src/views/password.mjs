// `/vault/password`: where the admin pages send people who want to change the
// master password. Changing it is not part of this version of the vault; the
// page says so, and does not start a sign-in hand-over (which would only end
// with a new admin session and never reach a password form).
import { el } from "../dom.mjs";

/** @param {{ t: import("./form.mjs").Translate }} options */
export function passwordView({ t }) {
  return el(
    "section",
    { class: "card account", "data-role": "password-page" },
    el("h1", null, t("account.password.heading")),
    el("p", null, t("account.password.body")),
    el("p", null, el("a", { href: "#/login" }, t("account.password.back"))),
  );
}
