// The grant tab: asks for the host permission of one frame origin (see
// grantFlow.mjs). Built with `el()` only.

import { el, mount } from "../shared/dom.mjs";
import { createGrantFlow, originParam } from "./grantFlow.mjs";
import { loadTexts } from "./page.mjs";
import { connectUi, shownHost } from "./ui.mjs";

async function main() {
  const texts = await loadTexts();
  const root = /** @type {HTMLElement} */ (document.getElementById("root"));
  const ui = connectUi(browser.runtime);
  const flow = createGrantFlow({ request: ui.request, requestPermission: (wanted) => browser.permissions.request(wanted) });
  const checked = await flow.check(originParam(location.search));

  if (!checked.ok) {
    mount(root, el("h1", null, texts.t("grant.title")), el("p", { class: "ff-error", role: "alert", "data-role": "grant-invalid" }, texts.t(`grant.error.${checked.reason === "vault_locked" ? "vault_locked" : "origin_invalid"}`)));
    document.body.dataset.ready = "1";
    return;
  }

  const status = el("p", { class: "ff-status", "aria-live": "polite", "data-role": "grant-status" });
  const allow = /** @type {HTMLButtonElement} */ (el("button", { type: "button", class: "ff-button ff-primary", "data-role": "grant-allow" }, texts.t("grant.allow")));
  allow.addEventListener("click", async () => {
    // The request first, in the click itself: the browser asks only for a request a user made.
    const outcome = await flow.grant(checked);
    status.textContent = texts.t(`grant.${outcome}`);
    status.dataset.outcome = outcome;
    allow.disabled = outcome === "granted";
  });
  mount(
    root,
    el("h1", null, texts.t("grant.title")),
    el("p", { class: "ff-lead" }, texts.t("grant.lead"), " ", el("strong", { class: "ff-host", dir: "ltr", "data-role": "grant-host" }, shownHost({ host: checked.host.unicode, host_a_label: checked.host.a_label }))),
    el("p", { class: "ff-hint" }, texts.t("grant.why")),
    el("div", { class: "ff-actions" }, allow),
    status,
  );
  document.body.dataset.ready = "1";
}

main().catch(() => {
  // Nothing to show without the background; the page never prints what went wrong.
});
