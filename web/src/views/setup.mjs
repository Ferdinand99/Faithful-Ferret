// The setup page: the first administrator makes the account. The setup token
// comes from the address fragment (read once at start, see `flows/entry.mjs`)
// or is pasted into the field. After the form the emergency sheet is shown;
// the account is uploaded only when the recovery key and the secret key have
// been typed back and checked (Spec: Fase 1 § 6.1).
//
// With an invitation (`#invite=` in the fragment) the page is "Join Ferret on
// <host>": it checks the link first and asks for nothing while it does, so a
// dead link is said before anyone chooses a master password. A good link shows
// who made it and when it runs out, then the same form, sheet and checks as for
// the first administrator. An invited account is not an administrator, so the
// done page has no way to the admin pages. A page that came from an invitation
// but has lost its token (a reload after the token was read, a tab the browser
// brought back, a link that was not complete) says so and asks for nothing.
import { AccountError, codeOf } from "../crypto/errors.mjs";
import { ADMIN_LANDING } from "../flows/adminUrl.mjs";
import { el, mount } from "../dom.mjs";
import { busyState, choice, describeError, field, setText, trustNotice } from "./form.mjs";
import { sheetView } from "./sheet.mjs";

/**
 * @typedef {object} SetupDeps
 * @property {import("./form.mjs").Translate} t
 * @property {any} session the crypto session (`services.crypto`)
 * @property {string | null} setupToken the token the address carried, if any
 * @property {() => void} [spentToken] called once the token has been used
 * @property {string | null} [invite] the token of the invitation link the address carried, if any
 * @property {(invite: string) => Promise<{ ok: true, expiresAt: number, invitedBy: string } | { ok: false, code: string }>} [checkInvite]
 *   asks the server whether the link still works (`flows/invite.mjs`)
 * @property {() => void} [spentInvite] called once the account the invitation made exists
 * @property {boolean} [joinLost] the page came from an invitation link but no longer has a usable token
 * @property {string} [host] the host of this vault, for the heading of the join page
 * @property {string} [locale] the language of the page, for the expiry of the link
 * @property {string | null} adminUrl
 * @property {(path: string) => void} go
 * @property {{ goToAdmin: (options: any) => Promise<void> }} handoff
 * @property {() => void} [print]
 */

/** @param {SetupDeps} deps */
export function setupView(deps) {
  const { t, session, adminUrl, go, handoff } = deps;
  const invite = typeof deps.invite === "string" && deps.invite !== "" ? deps.invite : null;
  const joining = invite !== null;
  const joinLost = !joining && deps.joinLost === true;
  const root = el("section", { class: "auth-card account", "data-role": "setup-page" });
  const status = el("p", { class: "status", role: "status", "data-role": "status" });
  const errorBox = el("p", { class: "error", role: "alert", "data-role": "error" });
  errorBox.hidden = true;
  const trust = trustNotice(t);

  const email = field(t, { id: "email", role: "email", label: "account.setup.email", type: "email", autocomplete: "username" });
  const password = field(t, { id: "password", role: "password", label: "account.setup.password", type: "password", autocomplete: "new-password", help: "account.setup.password_help" });
  const repeat = field(t, { id: "password-repeat", role: "password-repeat", label: "account.setup.repeat", type: "password", autocomplete: "new-password" });
  const useSk = choice(t, { id: "use-sk", role: "use-sk", label: "account.setup.use_sk", checked: true });
  const noSkWarning = el("p", { class: "notice notice-warning", role: "note", "data-role": "no-sk-warning" }, t("account.setup.no_sk_warning"));
  noSkWarning.hidden = true;
  const remember = choice(t, { id: "remember", role: "remember", label: "account.remember.label", checked: true });
  const rememberNote = el("small", { class: "help" }, t("account.remember.note"));
  const rememberRow = el("div", { class: "remember", "data-role": "remember-row" }, remember.row, rememberNote);
  const token = deps.setupToken || joining ? null : field(t, { id: "setup-token", role: "setup-token", label: "account.setup.token", autocomplete: "off", required: false, secret: true });
  const tokenNote = deps.setupToken && !joining ? el("p", { class: "help", "data-role": "token-received" }, t("account.setup.token_received")) : null;
  const submit = el("button", { type: "submit", class: "btn btn-primary btn-block", "data-role": "submit" }, t("account.setup.submit"));
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
    mount(root, el("p", { role: "status", "data-role": "creating" }, t("sheet.creating")));
    try {
      await flow.finish();
    } catch (error) {
      const retry = el("button", { type: "button", class: "btn btn-primary", "data-role": "retry" }, t("account.setup.retry"));
      const cancel = el("button", { type: "button", class: "btn btn-secondary", "data-role": "cancel" }, t("account.setup.cancel"));
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
    if (joining) deps.spentInvite?.();
    else deps.spentToken?.();
    showDone();
  }

  /** The page after the form: the sheet, the confirmation, the upload. */
  /** @param {any} flow @param {boolean} usedSecretKey */
  function showSheet(flow, usedSecretKey) {
    const sheet = sheetView({
      t,
      sheet: flow.sheet,
      useSecretKey: usedSecretKey,
      mode: "setup",
      print: deps.print,
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
    const open = el("button", { type: "button", class: "btn btn-primary", "data-role": "open-vault" }, t("account.setup.done_open"));
    open.addEventListener("click", () => go("/"));
    // Only the first administrator is one; an account made with an invitation is not.
    const admin =
      adminUrl === null || joining
        ? null
        : el("button", { type: "button", class: "btn btn-secondary", "data-role": "admin" }, t("account.signedin.admin"));
    admin?.addEventListener("click", () => {
      if (adminUrl !== null) void handoff.goToAdmin({ adminUrl, next: ADMIN_LANDING, purpose: "login" }).catch(showError);
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
    const typedToken = joining ? "" : deps.setupToken ?? (token ? token.input.value.trim() : "");
    const useSecretKey = useSk.input.checked === true;
    const args = {
      email: email.input.value,
      password: typedPassword,
      setupToken: typedToken === "" ? null : typedToken,
      invite,
      useSecretKey,
      rememberSk: useSecretKey ? remember.input.checked === true : false,
    };
    busy.set(true);
    void (async () => {
      if (typedPassword !== typedRepeat) throw new AccountError("password_mismatch");
      const flow = await session.register(args);
      showSheet(flow, useSecretKey);
    })()
      .catch((error) => {
        // The link died between the check and the start (used elsewhere, withdrawn, run out).
        if (joining && codeOf(error) === "invite_invalid") showDead("invite_invalid");
        else showError(error);
      })
      .finally(() => {
        busy.set(false);
        running = false;
      });
  });

  mount(form, email.row, password.row, repeat.row, useSk.row, noSkWarning, rememberRow, ...(token ? [token.row] : []), ...(tokenNote ? [tokenNote] : []), submit);
  const loginLink = el("p", null, el("a", { href: "#/login" }, t("account.setup.login_link")));
  if (joinLost) {
    // Not the first administrator's form: on a server with accounts it would end in `registration_closed` only
    // after the master password was typed.
    mount(
      root,
      el("h1", { "data-role": "join-heading" }, t("account.join.heading", { host: deps.host ?? "" })),
      el("p", { class: "error", role: "alert", "data-role": "invite-lost" }, t("account.join.lost")),
      loginLink,
      trust,
    );
    return root;
  }
  if (!joining) {
    mount(root, el("h1", null, t("account.setup.heading")), el("p", null, t("account.setup.intro")), form, status, errorBox, loginLink, trust);
    return root;
  }

  // ------------------------------------------------------------- joining

  const heading = el("h1", { "data-role": "join-heading" }, t("account.join.heading", { host: deps.host ?? "" }));

  /** When the link runs out, in the language of the page. @param {number} seconds */
  function whenText(seconds) {
    const at = new Date(seconds * 1000);
    try {
      return new Intl.DateTimeFormat(deps.locale, { dateStyle: "long", timeStyle: "short" }).format(at);
    } catch {
      return at.toISOString().slice(0, 16).replace("T", " ");
    }
  }

  /** The link does not work, or could not be checked: say so, and ask for nothing. @param {string} code */
  function showDead(code) {
    const dead = el("p", { class: "error", role: "alert", "data-role": "invite-dead" }, describeError(t, { code }));
    // A dead link stays dead; only a check that could not be made is worth another try.
    const retry =
      code === "invite_invalid"
        ? null
        : el("button", { type: "button", class: "btn btn-primary", "data-role": "invite-retry" }, t("account.setup.retry"));
    retry?.addEventListener("click", () => void checkLink());
    if (retry) mount(root, heading, dead, el("div", { class: "actions" }, retry), loginLink, trust);
    else mount(root, heading, dead, loginLink, trust);
  }

  async function checkLink() {
    if (invite === null) return;
    mount(root, heading, el("p", { class: "status", role: "status", "data-role": "invite-checking" }, t("account.join.checking")), trust);
    const check = deps.checkInvite ?? (async () => ({ ok: false, code: "unknown" }));
    /** @type {{ ok: true, expiresAt: number, invitedBy: string } | { ok: false, code: string }} */
    const answer = await check(invite).catch(() => ({ ok: false, code: "unknown" }));
    if (!answer.ok) {
      showDead(answer.code);
      return;
    }
    const who = answer.invitedBy === "" ? t("account.join.invited_unknown") : t("account.join.invited_by", { name: answer.invitedBy });
    mount(
      root,
      heading,
      el("p", { "data-role": "invited-by" }, who),
      el("p", { "data-role": "invite-expires" }, t("account.join.expires", { when: whenText(answer.expiresAt) })),
      el("p", null, t("account.join.intro")),
      form,
      status,
      errorBox,
      loginLink,
      trust,
    );
  }

  void checkLink();
  return root;
}
