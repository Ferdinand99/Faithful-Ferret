// The generic ceremony page: the runner sets window.__spec (or puts ?spec=<base64url JSON> in the
// address) and clicks #go, which is a real user gesture. ?auto=1 runs the spec at once, with no
// gesture (the case "no user activation"). The outcome is in #result (data-state), on window.__result
// and at /api/report.
import { pageSpec, report, runCeremony } from "/lib.mjs";

const result = /** @type {HTMLElement} */ (document.getElementById("result"));
const spec = () => pageSpec();
document.getElementById("origin").textContent = location.origin;
const s0 = spec();
if (s0) {
  document.getElementById("rp-lib").textContent = s0.lib;
  document.getElementById("rp-client").textContent = s0.client;
}

async function go() {
  const s = spec();
  if (!s) {
    result.textContent = "no spec";
    return;
  }
  result.dataset.state = "running";
  result.textContent = "running";
  const out = await runCeremony(s);
  result.dataset.state = out.ok ? "ok" : "failed";
  result.textContent = JSON.stringify(out, null, 1);
}

document.getElementById("go").addEventListener("click", go);
window.__ceremony = go;
if (new URLSearchParams(location.search).get("auto") === "1") go();
document.documentElement.dataset.ready = "1";
// The runner tells a page that did nothing from a page that never loaded by this report.
if (s0) report(s0.run, { kind: "started", href: location.href });
