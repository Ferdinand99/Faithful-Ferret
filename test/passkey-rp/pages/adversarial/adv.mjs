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
  /** The run the page reports to, once the click started it. @type {unknown} */
  let running = null;
  /** The reports go one after the other, so they arrive in the order they were made (the runner takes the last). */
  let chain = Promise.resolve();
  /** @param {Record<string, unknown>} payload */
  const send = (payload) => (chain = chain.then(() => report(running, payload)));
  /**
   * What the page saw goes to the runner at once as well, not only after the ceremony: a case whose ceremony is meant not to
   * finish (it only waits with the badge and the card) still reports it. The last report counts.
   * @param {string} key @param {unknown} value
   */
  const note = (key, value) => {
    notes[key] = value;
    if (running !== null) void send({ kind: "adv", ...notes });
  };
  async function go() {
    const spec = pageSpec();
    if (!spec) {
      result.textContent = "no spec";
      return;
    }
    running = spec.run;
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
    await send({ kind: "adv", ...notes });
    result.dataset.state = out?.ok ? "ok" : "failed";
    result.textContent = JSON.stringify({ out, notes }, null, 1);
    return out;
  }
  // The runner tells a page that did nothing from a page that never loaded by this report.
  const loaded = pageSpec();
  if (loaded) report(loaded.run, { kind: "started", href: location.href });
  document.getElementById("go")?.addEventListener("click", go);
  window.__ceremony = go;
  if (new URLSearchParams(location.search).get("auto") === "1") go();
  document.documentElement.dataset.ready = "1";
  return { go, note };
}
