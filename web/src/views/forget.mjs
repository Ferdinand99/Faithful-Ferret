// The "forget this server" page. It says what is removed and what is not, asks
// once more in a dialog (with the count of writes that were never sent), and
// then runs the flow. Nothing here is a secret.
//
// The account is the open one, or the one the server session names. A device that
// has neither (signed out) asks for the e-mail address, and looks it up among the
// records this device itself holds: no request is made.
import { hex16 } from "../b64.mjs";
import { el, mount } from "../dom.mjs";
import { forgetServer } from "../flows/forgetServer.mjs";
import { askConfirm } from "./common.mjs";

/** @typedef {import("./common.mjs").Translate} Translate */

/**
 * @param {{
 *   t: Translate,
 *   session: any,
 *   store: any,
 *   api: any,
 *   serverUrl: string,
 *   accountId: string | null,
 *   go: (path: string) => void,
 *   forget?: typeof forgetServer,
 * }} options
 * `accountId` is the account that is open or signed in, or null.
 * @returns {HTMLElement}
 */
export function forgetView({ t, session, store, api, serverUrl, accountId, go, forget = forgetServer }) {
  const root = el("section", { class: "auth-card account forget", "data-role": "forget-page" });
  const status = el("p", { class: "status", role: "status", "data-role": "forget-status" });
  const errorBox = el("p", { class: "error", role: "alert", "data-role": "forget-error" });
  errorBox.hidden = true;
  const noteBox = el("p", { class: "notice", role: "status", "data-role": "forget-note" });
  noteBox.hidden = true;
  /** @param {HTMLElement} node @param {string} text */
  const setText = (node, text) => mount(node, document.createTextNode(text));
  function clearMessages() {
    for (const box of [errorBox, noteBox]) {
      setText(box, "");
      box.hidden = true;
    }
  }
  /** @param {HTMLElement} box @param {string} key */
  const say = (box, key) => {
    setText(box, t(key));
    box.hidden = false;
  };

  /** @type {any[]} */
  const controls = [];
  /** @param {boolean} on */
  const busy = (on) => {
    for (const control of controls) control.disabled = on;
    root.setAttribute("aria-busy", on ? "true" : "false");
    setText(status, on ? t("syncwarnings.forget.working") : "");
  };

  /** @param {import("../flows/forgetServer.mjs").ForgetResult} result */
  function showDone(result) {
    const toLogin = el("button", { type: "button", class: "btn btn-primary", "data-role": "forget-to-login" }, t("syncwarnings.forget.to_login"));
    toLogin.addEventListener("click", () => go("/login"));
    const text = el("p", { role: "status", tabindex: "-1", "data-role": "forget-done", "data-shared": result.shared === true ? "true" : "false" },
      t(result.shared === true ? "syncwarnings.forget.done_shared" : "syncwarnings.forget.done"));
    mount(root, el("h1", null, t("syncwarnings.forget.heading")), text, el("div", { class: "actions" }, toLogin));
    /** @type {any} */ (text).focus?.();
  }

  /** @param {string} id the account to forget */
  async function run(id) {
    clearMessages();
    busy(true);
    try {
      const outcome = await forget({
        api, session, store, serverUrl, accountId: id,
        confirm: ({ pending }) => askConfirm({
          t, host: root, title: "syncwarnings.forget.dialog_title",
          body: pending > 0 ? "syncwarnings.forget.dialog_body_pending" : "syncwarnings.forget.dialog_body",
          confirm: "syncwarnings.forget.dialog_confirm", cancel: "syncwarnings.forget.dialog_cancel", vars: { count: pending },
        }),
        navigate: (_hash, result) => showDone(result),
      });
      if (outcome === "cancelled") {
        busy(false);
        say(noteBox, "syncwarnings.forget.cancelled");
      }
    } catch {
      busy(false);
      say(errorBox, "syncwarnings.forget.error");
    }
  }

  /** @type {HTMLElement[]} */
  const parts = [el("h1", null, t("syncwarnings.forget.heading")), el("p", null, t("syncwarnings.forget.intro"))];
  if (accountId !== null) {
    const start = el("button", { type: "button", class: "btn btn-danger", "data-role": "forget-start" }, t("syncwarnings.forget.start"));
    controls.push(start);
    start.addEventListener("click", () => void run(accountId));
    parts.push(el("div", { class: "actions" }, start));
  } else {
    // Signed out: the account is found by the e-mail address, among this device's own records.
    const input = el("input", { id: "forget-email", name: "forget-email", type: "email", autocomplete: "username", required: true, "data-role": "forget-email" });
    const submit = el("button", { type: "submit", class: "btn btn-primary", "data-role": "forget-lookup" }, t("syncwarnings.forget.lookup"));
    controls.push(input, submit);
    const form = el("form", { class: "stack", "data-role": "forget-form" },
      el("div", { class: "field" }, el("label", { for: "forget-email" }, t("syncwarnings.forget.email")), input), el("div", { class: "actions" }, submit));
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      clearMessages();
      const email = /** @type {any} */ (input).value;
      let found = null;
      try {
        const record = await store.pinHintForEmail(await store.open(), serverUrl, email);
        const id = record ? hex16.encode(record.account_id) : null;
        found = id !== null && hex16.is(id) ? id : null;
      } catch {
        say(errorBox, "syncwarnings.forget.error");
        return;
      }
      if (found === null) say(noteBox, "syncwarnings.forget.not_found");
      else await run(found);
    });
    parts.push(form);
  }
  parts.push(status, noteBox, errorBox, el("p", null, el("a", { href: "#/login" }, t("syncwarnings.forget.to_login"))));
  mount(root, ...parts);
  return root;
}
