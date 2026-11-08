// The scenarios of the lifetime measurement (test build only). Each one opens a
// vault-like state in the background page and then leaves the page alone, so the
// log (measureLog.mjs) shows what the browser does to a page in that state:
//
//   idle    the vault is open (the vault worker holds a WASM instance), nothing else
//   sse     the same, and an open `fetch` stream reads server-sent events
//   popup   the same; the test opens the popup page as a tab and leaves it open
//   argon   the same, and an Argon2id job runs over and over in the job worker
//
// A scenario never keeps the page alive on purpose: it starts the work and
// returns, and the work is what a real vault would be doing.

export const SCENARIOS = Object.freeze(["idle", "sse", "popup", "argon"]);

/** A job that is long on purpose: 256 MiB, 8 passes. */
const DEFAULT_ARGON = Object.freeze({ m_kib: 262_144, t: 8, p: 1 });

/** @param {unknown} n @param {number} min @param {number} max @returns {n is number} */
const whole = (n, min, max) => typeof n === "number" && Number.isInteger(n) && n >= min && n <= max;

/**
 * @param {{
 *   coreHost: { call: (op: string, args?: unknown) => Promise<unknown>, state: () => string },
 *   log: { append: (kind: string, details?: Record<string, unknown>) => Promise<unknown>, clear: () => Promise<unknown> },
 *   storageLocal: { set: (items: Record<string, unknown>) => Promise<void>, remove: (key: string) => Promise<void> },
 *   scenarioKey: string,
 *   fetchImpl?: typeof fetch,
 *   now?: () => number,
 * }} options
 */
export function createScenarios({ coreHost, log, storageLocal, scenarioKey, fetchImpl = (...a) => fetch(...a), now = Date.now }) {
  /** @type {{ name: string, stopped: boolean, abort: AbortController } | null} */
  let current = null;

  /** @param {unknown} error @returns {string} a short code, never a message */
  const codeOf = (error) => {
    const code = /** @type {{ code?: unknown }} */ (error)?.code;
    return typeof code === "string" && /^[a-z][a-z0-9_]{0,63}$/.test(code) ? code : "failed";
  };

  /** @param {{ name: string, stopped: boolean, abort: AbortController }} run @param {string} url */
  async function readStream(run, url) {
    try {
      const response = await fetchImpl(url, { cache: "no-store", credentials: "omit", signal: run.abort.signal });
      if (!response.ok || !response.body) throw Object.assign(new Error("status"), { code: `http_${response.status}` });
      await log.append("stream_open", { status: response.status });
      const reader = response.body.getReader();
      let ticks = 0;
      for (;;) {
        const { done } = await reader.read();
        if (done) break;
        ticks += 1;
      }
      if (!run.stopped) await log.append("stream_end", { chunks: ticks });
    } catch (error) {
      if (!run.stopped) await log.append("stream_error", { code: codeOf(error) });
    }
  }

  /** @param {{ name: string, stopped: boolean, abort: AbortController }} run @param {{ m_kib: number, t: number, p: number }} params */
  async function runJobs(run, params) {
    while (!run.stopped) {
      try {
        const result = /** @type {{ ms: number }} */ (await coreHost.call("argon2_bench", params));
        if (run.stopped) break;
        await log.append("job_done", { ms: result.ms, ...params });
      } catch (error) {
        if (!run.stopped) await log.append("job_error", { code: codeOf(error) });
        break;
      }
    }
  }

  return {
    SCENARIOS,

    /** What runs now, or null. */
    current: () => (current ? { name: current.name, stopped: current.stopped } : null),

    /**
     * Starts a scenario: a clean log, the vault open, the scenario's work. Any
     * scenario that runs is stopped first.
     *
     * @param {{ scenario?: unknown, url?: unknown, m_kib?: unknown, t?: unknown }} [args]
     */
    async start(args = {}) {
      const name = args.scenario;
      if (typeof name !== "string" || !SCENARIOS.includes(name)) throw Object.assign(new Error("bad_scenario"), { code: "bad_scenario" });
      /** @type {string | undefined} */
      let url;
      if (name === "sse") {
        try {
          const parsed = new URL(typeof args.url === "string" && args.url.length <= 300 ? args.url : "");
          if (parsed.protocol !== "https:") throw new Error("scheme");
          url = parsed.href;
        } catch {
          throw Object.assign(new Error("bad_url"), { code: "bad_url" });
        }
      }
      /** @type {{ m_kib: number, t: number, p: number }} */
      const params = { ...DEFAULT_ARGON };
      if (name === "argon") {
        if (args.m_kib !== undefined) {
          if (!whole(args.m_kib, 1, 524_288)) throw Object.assign(new Error("bad_params"), { code: "bad_params" });
          params.m_kib = args.m_kib;
        }
        if (args.t !== undefined) {
          if (!whole(args.t, 1, 16)) throw Object.assign(new Error("bad_params"), { code: "bad_params" });
          params.t = args.t;
        }
      }

      if (current) {
        current.stopped = true;
        current.abort.abort();
      }
      const run = { name, stopped: false, abort: new AbortController() };
      current = run;
      await log.clear();
      await storageLocal.set({ [scenarioKey]: { name, startedAt: now(), ...(url ? { url } : {}), ...(name === "argon" ? params : {}) } });
      // The vault opens: the worker is started and holds a WASM instance, and the lock's deadline starts.
      await coreHost.call("measure_open");
      await log.append("scenario_start", { scenario: name, ...(url ? { url } : {}), ...(name === "argon" ? params : {}) });
      if (name === "sse" && url) readStream(run, url);
      if (name === "argon") runJobs(run, params);
      return { ok: true, core: coreHost.state() };
    },

    /** Stops the work of the scenario. The vault stays as it is. */
    async stop() {
      if (current) {
        current.stopped = true;
        current.abort.abort();
        current = null;
      }
      await storageLocal.remove(scenarioKey);
      return { ok: true };
    },
  };
}
