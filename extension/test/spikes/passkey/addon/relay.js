// Isolated-world relay of the passkey spike (content script, run_at document_start).
// Test-only code. It makes the private MessageChannel, hands one port to the
// MAIN-world script in a single window message, and from then on forwards between
// that port and a runtime port to the background. It adds no origin, trusts none
// and holds no keys: the background takes the origin from the port's sender.
(() => {
  "use strict";
  const KINDS = new Set(["create", "get", "cma", "cancel"]);
  const MAX_BYTES = 64 * 1024;

  const channel = new MessageChannel();
  const background = browser.runtime.connect({ name: "passkey" });

  channel.port1.onmessage = (event) => {
    const m = event.data;
    if (!m || typeof m !== "object" || typeof m.id !== "number" || !KINDS.has(m.kind)) return;
    let size = 0;
    try {
      size = JSON.stringify(m).length;
    } catch {
      return;
    }
    if (size > MAX_BYTES) return;
    background.postMessage({ id: m.id, kind: m.kind, payload: m.payload });
  };
  background.onMessage.addListener((answer) => channel.port1.postMessage(answer));
  background.onDisconnect.addListener(() => channel.port1.close());

  // The single offer. The target origin is the page's own; an opaque origin needs "*".
  const target = window.location.origin === "null" ? "*" : window.location.origin;
  window.postMessage({ ferretSpike: "offer", v: 1 }, target, [channel.port2]);
})();
