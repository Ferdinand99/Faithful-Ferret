// The unlock window (design document, sections 7.2 and 7.3; build flag `unlock`): the one page that makes the WebAuthn call
// of a passkey unlock. The toolbar popup cannot: it closes when the system's dialog takes the focus, and the call never
// ends. The popup asks the background to open this page in a window of its own (a top-level page of the extension that no
// web page can frame: no web_accessible_resources, CSP frame-ancestors 'none'); here the person presses one button, the
// browser asks for the fingerprint, face or PIN, the 32 bytes the passkey gives go to the background in one message, and the
// window closes. The steps are in unlockWindowFlow.mjs; this file builds the page and makes the call.
//
// One WebAuthn call is made for each press of the button (a browser allows no more for a user gesture), and nothing is
// awaited between the press and the call. The relying party id is the exact host of the vault, which the background
// reads from the server's list together with each passkey's credential id and salt: nothing is kept between windows.

import { el, mount } from "../shared/dom.mjs";
import { FEATURES } from "../shared/features.mjs";
import { loadTexts, translateStatic } from "./page.mjs";
import { connectUi } from "./ui.mjs";
import { createUnlockWindowFlow, extensionOrigin, passkeyErrorKey, retryable } from "./unlockWindowFlow.mjs";

/** The feature mark on the controls the tests and the build's checks look for. */
const FEATURE = Object.freeze({ "data-feature": "unlock" });

/** How long the window stays after the vault is open (milliseconds), so the person sees that it worked. */
const CLOSE_AFTER_MS = 1200;

/** @param {Uint8Array} data */
async function sha256(data) {
  return new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", /** @type {Uint8Array<ArrayBuffer>} */ (data)));
}

/** The call, as the browser makes it. @param {any} publicKey */
const getAssertion = (publicKey) => navigator.credentials.get({ publicKey });

/**
 * Closes this page: its own tab only (the page can be open in a tab of an ordinary window, which must stay). The tab of the
 * dedicated popup window is that window's only one, so the window goes with it.
 */
async function closeWindow() {
  try {
    const tab = await browser.tabs.getCurrent();
    if (typeof tab?.id === "number") {
      await browser.tabs.remove(tab.id);
      return;
    }
  } catch {
    // No tab API: the page closes itself.
  }
  window.close();
}

async function main() {
  if (!FEATURES.unlock) return;
  const root = /** @type {HTMLElement} */ (document.getElementById("root"));
  if (!root) return;
  const texts = await loadTexts();
  translateStatic(document, texts);
  const ui = connectUi(browser.runtime);
  const flow = createUnlockWindowFlow(ui.request, {
    getAssertion,
    deps: {
      rand: (/** @type {Uint8Array} */ bytes) => globalThis.crypto.getRandomValues(/** @type {Uint8Array<ArrayBuffer>} */ (bytes)),
      now: () => Date.now(),
      sha256,
      // Firefox writes an origin of its own making into the client data of an extension's page, not the page's address.
      origin: await extensionOrigin(browser.runtime.id, sha256),
    },
  });
  // The page goes away: the port closes with it, and nothing of a passkey is left in the page.
  globalThis.addEventListener("pagehide", () => ui.close(), { once: true });

  /** @type {import("./unlockWindowFlow.mjs").Offer | null} */
  let offer = null;

  /** What to check when the browser refuses the passkey at once, before it has asked the person anything. */
  const blockedHelp = () =>
    el(
      "ul",
      { class: "ff-hint", "data-role": "passkey-blocked-help", ...FEATURE },
      el("li", null, texts.t("passkey.blocked.other_manager")),
      el("li", null, texts.t("passkey.blocked.mac")),
      el("li", null, texts.t("passkey.blocked.windows")),
    );

  /** The window while the background reads the list. */
  function checking() {
    mount(root, el("h1", null, texts.t("passkey.window.title")), el("p", { class: "ff-status", "data-role": "passkey-status" }, texts.t("passkey.window.checking")));
  }

  /**
   * The window with its button.
   * @param {string | null} reason a refusal to say first, or null
   * @param {string} label
   */
  function ready(reason, label) {
    const used = /** @type {import("./unlockWindowFlow.mjs").Offer} */ (offer);
    const status = el("p", { class: "ff-status", "aria-live": "polite", "data-role": "passkey-status" });
    const button = /** @type {HTMLButtonElement} */ (el("button", { type: "button", class: "ff-button ff-primary", "data-role": "passkey-unlock", ...FEATURE }, label));
    const error = el("p", { class: "ff-error", role: "alert", "data-role": "passkey-error", hidden: reason === null }, reason === null ? "" : texts.t(passkeyErrorKey(reason)));
    button.addEventListener("click", async () => {
      // Nothing is awaited before the call: it has to be made from the press.
      const pending = flow.unlock(used);
      button.disabled = true;
      error.hidden = true;
      status.textContent = texts.t("passkey.window.busy");
      const outcome = await pending;
      if (outcome.ok) {
        done();
        return;
      }
      status.textContent = "";
      // A passkey that was refused or a prompt that was closed can be tried again with the same list; anything else reads the list again.
      if (outcome.reason === "passkey_blocked" || outcome.reason === "passkey_cancelled" || outcome.reason === "passkey_failed") ready(outcome.reason, texts.t("passkey.window.retry"));
      else failed(outcome.reason);
    });
    mount(
      root,
      el("h1", null, texts.t("passkey.window.title")),
      el("p", { class: "ff-lead", "data-role": "passkey-host" }, texts.t("passkey.window.lead", { host: used.rpId })),
      el("p", { class: "ff-hint" }, texts.t("passkey.window.help")),
      button,
      status,
      error,
      ...(reason === "passkey_blocked" ? [blockedHelp()] : []),
    );
    button.focus();
  }

  /** The window after the vault opened. */
  function done() {
    offer = null;
    mount(root, el("h1", { "data-role": "passkey-done" }, texts.t("passkey.window.title")), el("p", null, texts.t("passkey.window.done")));
    document.body.dataset.done = "1";
    setTimeout(() => void closeWindow(), CLOSE_AFTER_MS);
  }

  /** @param {string} reason */
  function failed(reason) {
    offer = null;
    const close = el("button", { type: "button", class: "ff-button", "data-role": "passkey-close", ...FEATURE }, texts.t("passkey.window.close"));
    close.addEventListener("click", () => void closeWindow());
    const retry = el("button", { type: "button", class: "ff-button ff-primary", "data-role": "passkey-retry", ...FEATURE }, texts.t("passkey.window.retry"));
    retry.addEventListener("click", () => void start());
    mount(
      root,
      el("h1", null, texts.t("passkey.window.title")),
      el("p", { class: "ff-error", role: "alert", "data-role": "passkey-error" }, texts.t(passkeyErrorKey(reason))),
      el("div", { class: "ff-actions" }, ...(retryable(reason) ? [retry, close] : [close])),
    );
    (retryable(reason) ? retry : close).focus();
  }

  async function start() {
    checking();
    const outcome = await flow.options();
    if (!outcome.ok) {
      failed(outcome.reason);
      return;
    }
    offer = outcome.offer;
    ready(null, texts.t("passkey.button"));
  }

  await start();
  document.body.dataset.ready = "1";
}

main().catch(() => {
  // The page has nothing to show without the background; it never prints what went wrong.
});
