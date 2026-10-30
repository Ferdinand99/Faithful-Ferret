// The emergency sheet after registration (spec Fase 1 § 6.1): the access page
// (address, e-mail, account id, secret key, setup QR text) and the recovery
// key, shown once. Nothing is uploaded until the user has typed the recovery
// key (and the secret key) back and the core has checked them. When that has
// happened the sheet is removed from the page.
import { clear, el, mount } from "../dom.mjs";
import { busyState, describeError, field, setText } from "./form.mjs";

/**
 * @param {{
 *   t: import("./form.mjs").Translate,
 *   sheet: { access: Record<string, any>, recoveryKeyCode: string },
 *   useSecretKey: boolean,
 *   onConfirm: (recoveryKey: string, secretKey: string) => Promise<void>,
 *   onPrint?: () => void,
 * }} options
 * @returns {{ root: HTMLElement, wipe(): void }}
 */
export function sheetView({ t, sheet, useSecretKey, onConfirm, onPrint }) {
  const root = el("section", { class: "card account sheet", "data-role": "sheet-page" });
  const status = el("p", { class: "status", role: "status", "data-role": "status" });
  const errorBox = el("p", { class: "error", role: "alert", "data-role": "error" });
  errorBox.hidden = true;

  /** @param {string} label @param {string} role @param {string} value */
  const row = (label, role, value) => [el("dt", null, t(label)), el("dd", { class: "secret", "data-role": role }, value)];
  const access = sheet.access;
  const page = el(
    "dl",
    { class: "sheet-fields", "data-role": "sheet" },
    ...row("account.sheet.server", "sheet-server", String(access.server_url)),
    ...row("account.sheet.email", "sheet-email", String(access.email)),
    ...row("account.sheet.account_id", "sheet-account-id", String(access.account_id)),
    ...row("account.sheet.profile", "sheet-profile", String(access.ksf_profile)),
    ...(useSecretKey && typeof access.secret_key_code === "string" ? row("account.sheet.secret_key", "sheet-secret-key", access.secret_key_code) : []),
    ...(typeof access.qr_payload === "string" ? row("account.sheet.qr", "sheet-qr", access.qr_payload) : []),
  );
  const recovery = el("dl", { class: "sheet-fields", "data-role": "sheet-recovery" }, ...row("account.sheet.recovery_key", "sheet-recovery-key", sheet.recoveryKeyCode));

  const rk = field(t, { id: "rk-typed", role: "rk-typed", label: "account.sheet.type_recovery", autocomplete: "off" });
  const sk = useSecretKey ? field(t, { id: "sk-typed", role: "sk-typed", label: "account.sheet.type_secret", autocomplete: "off" }) : null;
  const submit = el("button", { type: "submit", class: "primary", "data-role": "confirm" }, t("account.sheet.confirm"));
  const form = el("form", { class: "stack", "data-role": "confirm-form" }, rk.row, ...(sk ? [sk.row] : []), submit);
  const busy = busyState({ root: form, status, controls: [rk.input, submit, ...(sk ? [sk.input] : [])], t, key: "account.sheet.checking" });

  let running = false;
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    if (running) return;
    running = true;
    errorBox.hidden = true;
    busy.set(true);
    // What was typed is read and emptied before the check starts.
    const typedRk = rk.input.value;
    const typedSk = sk ? sk.input.value : "";
    rk.input.value = "";
    if (sk) sk.input.value = "";
    void onConfirm(typedRk, typedSk)
      .catch((error) => {
        setText(errorBox, describeError(t, error));
        errorBox.hidden = false;
      })
      .finally(() => {
        // After a success the sheet is gone, and so is the form.
        busy.set(false);
        running = false;
      });
  });

  const print = onPrint ? el("button", { type: "button", "data-role": "print" }, t("account.sheet.print")) : null;
  print?.addEventListener("click", () => onPrint?.());

  mount(
    root,
    el("h1", null, t("account.sheet.heading")),
    el("p", { class: "notice", role: "note" }, t("account.sheet.warning")),
    el("h2", null, t("account.sheet.page_access")),
    page,
    el("h2", null, t("account.sheet.page_recovery")),
    el("p", null, t("account.sheet.recovery_note")),
    recovery,
    ...(print ? [print] : []),
    el("h2", null, t("account.sheet.confirm_heading")),
    el("p", null, t("account.sheet.confirm_note")),
    form,
    status,
    errorBox,
  );
  return {
    root,
    /** Removes the sheet's text and the form from the page. */
    wipe() {
      clear(root);
    },
  };
}
