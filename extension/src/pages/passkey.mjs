// The chooser window of the passkey provider (the `passkeys` feature; design document § 9.4 and § 10.3.3): the one page that
// asks the person what to do with a website's request for a passkey. The background opens it in a window of its own
// (`pages/passkey.html?r=<request id>`): a top-level page of the extension that no web page can frame (no web_accessible_resources,
// CSP `frame-ancestors 'none'`), and that refuses to build itself inside a frame all the same.
//
// This file only joins the pieces: the texts, the UI port, the request id from the address, the focus and the closing of the
// window. What the window shows and does is in passkeyChooser.mjs, its steps and guards in passkeyFlow.mjs. A window opened without
// a request id of its own (an address typed by hand) has nothing to answer and closes.

import { el, mount } from "../shared/dom.mjs";
import { FEATURES } from "../shared/features.mjs";
import { loadTexts, translateStatic } from "./page.mjs";
import { createChooserBackend, requestIdOf } from "./passkeyFlow.mjs";
import { createChooser } from "./passkeyChooser.mjs";
import { createPasskeyProof, extensionOrigin } from "./passkeyVerify.mjs";
import { createPopupFlow } from "./popupFlow.mjs";
import { connectUi } from "./ui.mjs";

/** @param {Uint8Array} data */
async function sha256(data) {
  return new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", /** @type {Uint8Array<ArrayBuffer>} */ (data)));
}

/** The one WebAuthn call of this window, as the browser makes it: a passkey of the vault, to verify the person. @param {any} publicKey */
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
  if (!FEATURES.passkeys) return;
  const root = /** @type {HTMLElement} */ (document.getElementById("root"));
  if (!root) return;
  // A framed copy of the page shows nothing and asks nothing (the CSP already refuses it; this is the second lock).
  if (window.top !== window.self) return;
  const texts = await loadTexts();
  translateStatic(document, texts);
  const requestId = requestIdOf(location.search);
  if (requestId === null) {
    mount(root, el("h1", { class: "ff-pk-title", "data-role": "passkey-title" }, texts.t("passkeys.gone")));
    document.body.dataset.ready = "1";
    setTimeout(() => void closeWindow(), 1500);
    return;
  }
  const ui = connectUi(browser.runtime);
  // Windows Hello, Touch ID or another passkey of the vault as the verification: a call against the vault's host from this window
  // (never the popup). Firefox writes the extension's own origin into the client data, which the check compares exactly.
  const proof = createPasskeyProof(ui.request, {
    getAssertion,
    deps: {
      rand: (/** @type {Uint8Array} */ bytes) => globalThis.crypto.getRandomValues(/** @type {Uint8Array<ArrayBuffer>} */ (bytes)),
      now: () => Date.now(),
      sha256,
      origin: await extensionOrigin(browser.runtime.id, sha256),
    },
  });
  const chooser = createChooser({
    texts,
    backend: createChooserBackend(ui.request, requestId),
    unlock: createPopupFlow(ui.request),
    proof,
    closeWindow: () => void closeWindow(),
    formatDate: (ms) => {
      try {
        return new Intl.DateTimeFormat(texts.lang, { dateStyle: "medium" }).format(new Date(ms));
      } catch {
        return new Date(ms).toISOString().slice(0, 10);
      }
    },
  });
  mount(root, chooser.root);
  // The 400 ms start again each time the window gets the focus again, and what it shows is read again.
  window.addEventListener("focus", () => chooser.focused());
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) chooser.focused();
  });
  // The page goes away: the port closes with it, and nothing typed is left in the page.
  window.addEventListener(
    "pagehide",
    () => {
      chooser.stop();
      ui.close();
    },
    { once: true },
  );
  await chooser.loaded;
  chooser.focus();
  document.body.dataset.ready = "1";
}

main().catch(() => {
  // The page has nothing to show without the background; it never prints what went wrong.
});
