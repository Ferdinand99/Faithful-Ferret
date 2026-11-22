// The control page of the passkey spike (test-only): lets the browser tests steer the
// background. Opened in a tab by the test; it relays a named call to the background.
Object.defineProperty(globalThis, "spikeControl", {
  value: Object.freeze({
    /** @param {string} ctl @param {string} [argsJson] @returns {Promise<string>} the result as JSON */
    call: (ctl, argsJson = "null") => browser.runtime.sendMessage({ ctl, args: JSON.parse(argsJson) }),
  }),
});
document.documentElement.dataset.ready = "1";

// permissions.request needs a user action: a click on this button (a real one, from the test).
document.getElementById("grant").addEventListener("click", () => {
  browser.permissions.request({ origins: ["https://*/*", "http://localhost/*"] }).then(
    (granted) => document.body.setAttribute("data-grant", JSON.stringify({ granted })),
    (error) => document.body.setAttribute("data-grant", JSON.stringify({ error: String(error) })),
  );
});
