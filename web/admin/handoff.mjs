// The one script of the admin origin: it finishes a hand-over from the vault
// origin. The URL fragment carries the one-time code and nothing else. The
// script reads it, removes it from the address, redeems it with a POST and goes
// to the `next` that the server answers with, but only when `next` stays on
// this origin (checked with the URL parser, not by looking at the first
// characters: a tab or a line feed inside `/\t/evil.test` is dropped by the
// parser and makes it `//evil.test`).
//
// No WASM, no password field, no framework. The page is served with
// `Referrer-Policy: no-referrer`.

const CODE_PATTERN = /^[A-Za-z0-9_-]{43}$/;

const MESSAGES = {
  en: {
    working: "Signing you in to the admin pages\u2026",
    failed: "The hand-over did not work.",
    retry: "Try again",
  },
  nb: {
    working: "Logger deg inn p\u00e5 administrasjonssidene\u2026",
    failed: "Overleveringen virket ikke.",
    retry: "Pr\u00f8v igjen",
  },
};

/**
 * The code in a URL fragment such as `#code=abc`, or `null` when the fragment
 * holds anything else (another name, a second parameter, a code of the wrong
 * shape).
 * @param {string} hash
 * @returns {string | null}
 */
export function codeFromHash(hash) {
  const text = hash.startsWith("#") ? hash.slice(1) : hash;
  const params = new URLSearchParams(text);
  const names = [...params.keys()];
  if (names.length !== 1 || names[0] !== "code") return null;
  const code = params.get("code") ?? "";
  return CODE_PATTERN.test(code) ? code : null;
}

/**
 * The URL to go to for a `next` from the server, or `null` when it does not
 * stay on `origin`.
 * @param {string} next
 * @param {string} origin
 * @returns {string | null}
 */
export function safeTarget(next, origin) {
  if (typeof next !== "string") return null;
  let target;
  try {
    target = new URL(next, origin);
  } catch {
    return null;
  }
  return target.origin === origin ? target.href : null;
}

/**
 * Runs the hand-over: reads and removes the code, redeems it, navigates.
 * Returns `true` when it navigated.
 * @param {{
 *   location: { hash: string, pathname: string, search: string, origin: string, replace(url: string): void },
 *   history: { replaceState(state: unknown, title: string, url: string): void },
 *   fetch: typeof fetch,
 * }} env
 * @returns {Promise<boolean>}
 */
export async function run(env) {
  const { location, history } = env;
  const code = codeFromHash(location.hash);
  // The fragment goes out of the address bar and the history entry at once,
  // whatever it held.
  history.replaceState(null, "", location.pathname + location.search);
  if (code === null) return false;
  let response;
  try {
    response = await env.fetch("/api/auth/handoff/redeem", {
      method: "POST",
      credentials: "same-origin",
      cache: "no-store",
      referrerPolicy: "no-referrer",
      headers: { "content-type": "application/json", "ferret-protocol": "1" },
      body: JSON.stringify({ code }),
    });
  } catch {
    return false;
  }
  if (!response.ok) return false;
  let answer;
  try {
    answer = await response.json();
  } catch {
    return false;
  }
  const target = safeTarget(answer?.next, location.origin);
  if (target === null) return false;
  location.replace(target);
  return true;
}

/** @param {string} language */
function messagesFor(language) {
  const primary = String(language).toLowerCase().split("-")[0];
  return primary === "nb" || primary === "no" || primary === "nn" ? MESSAGES.nb : MESSAGES.en;
}

// In a browser the script starts itself; a test imports the functions.
if (typeof document !== "undefined" && document.getElementById("handoff-status")) {
  const status = /** @type {HTMLElement} */ (document.getElementById("handoff-status"));
  const retry = document.getElementById("handoff-retry");
  const text = messagesFor(navigator.language);
  status.textContent = text.working;
  run({ location, history, fetch: globalThis.fetch.bind(globalThis) }).then((went) => {
    if (went) return;
    status.textContent = text.failed;
    if (retry) {
      const link = retry.querySelector("a");
      if (link) link.textContent = text.retry;
      retry.hidden = false;
    }
  });
}
