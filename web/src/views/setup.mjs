// The setup page: the first administrator makes the account. The setup token
// comes from the address fragment (read once at start, see `flows/entry.mjs`)
// or is pasted into the field. After the form the emergency sheet is shown;
// the account is uploaded only when the recovery key and the secret key have
// been typed back and checked (Spec: Fase 1 § 6.1).
import { AccountError } from "../crypto/errors.mjs";
import { el, mount } from "../dom.mjs";
import { busyState, choice, describeError, field, setText, trustNotice } from "./form.mjs";
import { sheetView } from "./sheet.mjs";

/**
 * @typedef {object} SetupDeps
 * @property {import("./form.mjs").Translate} t
 * @property {any} session the crypto session (`services.crypto`)
 * @property {string | null} setupToken the token the address carried, if any
 * @property {() => void} [spentToken] called once the token has been used
 * @property {string | null} adminUrl
 * @property {(path: string) => void} go
 * @property {{ goToAdmin: (options: any) => Promise<void> }} handoff
 * @property {() => void} [print]
 */

/** @param {SetupDeps} deps */
export function setupView(deps) {
  const { t, session, adminUrl, go, handoff } = deps;
  const root = el("section", { class: "card account", "data-role": "setup-page" });
  const status = el("p", { class: "status", role: "status", "data-role": "status" });
  const errorBox = el("p", { class: "error", role: "alert", "data-role": "error" });
  errorBox.hidden = true;
  const trust = trustNotice(t);

  const email = field(t, { id: "email", role: "email", label: "account.setup.email", type: "email", autocomplete: "username" });
  const password = field(t, { id: "password", role: "password", label: "account.setup.password", type: "password", autocomplete: "new-password", help: "account.setup.password_help" });
  const repeat = field(t, { id: "password-repeat", role: "password-repeat", label: "account.setup.repeat", type: "password", autocomplete: "new-password" });
  const useSk = choice(t, { id: "use-sk", role: "use-sk", label: "account.setup.use_sk", checked: true });
  const noSkWarning = el("p", { class: "notice", role: "note", "data-role": "no-sk-warning" }, t("account.setup.no_sk_warning"));
  noSkWarning.hidden = true;
  const remember = choice(t, { id: "remember", role: "remember", label: "account.remember.label", checked: true });
  const rememberNote = el("small", { class: "help" }, t("account.remember.note"));
  const rememberRow = el("div", { class: "remember", "data-role": "remember-row" }, remember.row, rememberNote);
  const token = deps.setupToken ? null : field(t, { id: "setup-token", role: "setup-token", label: "account.setup.token", autocomplete: "off", required: false });
  const tokenNote = deps.setupToken ? el("p", { class: "help", "data-role": "token-received" }, t("account.setup.token_received")) : null;
  const submit = el("button", { type: "submit", class: "primary", "data-role": "submit" }, t("account.setup.submit"));
  const form = el("form", { class: "stack", "data-role": "setup-form" });

  function layout() {
    const on = useSk.input.checked === true;
    noSkWarning.hidden = on;
    rememberRow.hidden = !on;
  }
  useSk.input.addEventListener("change", layout);
  layout();

  const controls = [email.input, password.input, repeat.input, useSk.input, remember.input, submit, ...(token ? [token.input] : [])];
  const busy = busyState({ root: form, status, controls, t, key: "account.setup.working" });
  let running = false;

  /** @param {unknown} error */
  function showError(error) {
    setText(errorBox, describeError(t, error));
    errorBox.hidden = false;
  }

  /**
   * The upload, after both keys were checked. A failure keeps the account in
   * the page's memory so that the user can try again or give up.
   * @param {any} flow
   */
  async function finishUp(flow) {
    mount(root, el("p", { role: "status", "data-role": "creating" }, t("account.sheet.creating")));
    try {
      await flow.finish();
    } catch (error) {
      const retry = el("button", { type: "button", class: "primary", "data-role": "retry" }, t("account.setup.retry"));
      const cancel = el("button", { type: "button", "data-role": "cancel" }, t("account.setup.cancel"));
      retry.addEventListener("click", () => void finishUp(flow));
      cancel.addEventListener("click", () => {
        void flow.abort().finally(() => go("/login"));
      });
      mount(
        root,
        el("p", { class: "error", role: "alert", "data-role": "error" }, describeError(t, error)),
        el("div", { class: "actions" }, retry, cancel),
      );
      return;
    }
    deps.spentToken?.();
    showDone();
  }

  /** The page after the form: the sheet, the confirmation, the upload. */
  /** @param {any} flow @param {boolean} usedSecretKey */
  function showSheet(flow, usedSecretKey) {
    const sheet = sheetView({
      t,
      sheet: flow.sheet,
      useSecretKey: usedSecretKey,
      onPrint: deps.print,
      onConfirm: async (rkTyped, skTyped) => {
        await flow.confirm(rkTyped, skTyped);
        // Both keys check out: the sheet's text leaves the page before the upload.
        sheet.wipe();
        await finishUp(flow);
      },
    });
    mount(root, sheet.root);
  }

  function showDone() {
    const open = el("button", { type: "button", class: "primary", "data-role": "open-vault" }, t("account.setup.done_open"));
    open.addEventListener("click", () => go("/"));
    const admin =
      adminUrl === null
        ? null
        : el("button", { type: "button", "data-role": "admin" }, t("account.signedin.admin"));
    admin?.addEventListener("click", () => {
      if (adminUrl !== null) void handoff.goToAdmin({ adminUrl, next: "/", purpose: "login" }).catch(showError);
    });
    mount(root, el("h1", null, t("account.setup.done_heading")), el("p", null, t("account.setup.done_body")), el("div", { class: "actions" }, open, admin), errorBox);
  }

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    if (running) return;
    running = true;
    errorBox.hidden = true;
    // The fields are read and emptied before anything is awaited.
    const typedPassword = password.input.value;
    const typedRepeat = repeat.input.value;
    password.input.value = "";
    repeat.input.value = "";
    const typedToken = deps.setupToken ?? (token ? token.input.value.trim() : "");
    const useSecretKey = useSk.input.checked === true;
    const args = {
      email: email.input.value,
      password: typedPassword,
      setupToken: typedToken === "" ? null : typedToken,
      useSecretKey,
      rememberSk: useSecretKey ? remember.input.checked === true : false,
    };
    busy.set(true);
    void (async () => {
      if (typedPassword !== typedRepeat) throw new AccountError("password_mismatch");
      const flow = await session.register(args);
      showSheet(flow, useSecretKey);
    })()
      .catch(showError)
      .finally(() => {
        busy.set(false);
        running = false;
      });
  });

  mount(form, email.row, password.row, repeat.row, useSk.row, noSkWarning, rememberRow, ...(token ? [token.row] : []), ...(tokenNote ? [tokenNote] : []), submit);
  mount(
    root,
    el("h1", null, t("account.setup.heading")),
    el("p", null, t("account.setup.intro")),
    form,
    status,
    errorBox,
    el("p", null, el("a", { href: "#/login" }, t("account.setup.login_link"))),
    trust,
  );
  return root;
}
