// Shared by the adversarial pages: the spec of the run, the button the runner clicks (#go, a real user gesture), and the
// outcome in #result, on window.__result and at /api/report. An adversarial page does something to the page, the built-ins
// or the options first and then runs a ceremony the usual way (or its own sequence), so the run still ends in the same
// kind of report the matrix judges. What the page itself saw goes into the report as `adv`.
import { pageSpec, report, runCeremony } from "/lib.mjs";

/**
 * @param {{ name: string, run?: (spec: any, note: (key: string, value: unknown) => void) => Promise<any> }} options
 *   run: replaces the plain ceremony (it returns the same shape as runCeremony)
 */
export function adversarial({ name, run }) {
  const result = /** @type {HTMLElement} */ (document.getElementById("result"));
  /** @type {Record<string, unknown>} */
  const notes = { page: name, userActivationAtLoad: navigator.userActivation?.isActive ?? null };
  /** @param {string} key @param {unknown} value */
  const note = (key, value) => {
    notes[key] = value;
  };
  async function go() {
    const spec = pageSpec();
    if (!spec) {
      result.textContent = "no spec";
      return;
    }
    result.dataset.state = "running";
    notes.userActivationAtStart = navigator.userActivation?.isActive ?? null;
    /** @type {any} */
    let out;
    try {
      out = run ? await run(spec, note) : await runCeremony(spec);
    } catch (e) {
      // What the page itself could not do is part of what it saw.
      notes.pageError = String(/** @type {any} */ (e)?.stack ?? e).slice(0, 400);
      out = { ok: false };
    }
    await report(spec.run, { kind: "adv", ...notes });
    result.dataset.state = out?.ok ? "ok" : "failed";
    result.textContent = JSON.stringify({ out, notes }, null, 1);
    return out;
  }
  document.getElementById("go")?.addEventListener("click", go);
  window.__ceremony = go;
  if (new URLSearchParams(location.search).get("auto") === "1") go();
  document.documentElement.dataset.ready = "1";
  return { go, note };
}
