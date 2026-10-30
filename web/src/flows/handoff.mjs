// The vault origin's half of the hand-over to the admin origin (Spec: Fase 1
// section 2.4). The password is typed here and nowhere on the admin origin.
//
//   goToAdmin           the user is signed in and wants the admin pages: go to
//                       `{admin}/auth/handoff/begin`, which sets a verifier
//                       cookie on the admin origin and comes back to the sign-in
//                       page with `?handoff=1&challenge=...&next=...`.
//   completeHandoff     the sign-in page was opened that way and the user has
//                       signed in (or confirmed the password again): ask the
//                       server for a one-time code and go to
//                       `{admin}/auth/handoff#code=<code>`. The fragment holds
//                       the code and nothing else, so it is not in a request,
//                       a `Referer` or a log.
//
// Both take the navigation as a parameter so a test can watch it.

/** The shape of the API client that these functions need. */
/** @typedef {{ post(path: string, body?: unknown, options?: object): Promise<any> }} HandoffApi */

const CHALLENGE = /^[A-Za-z0-9_-]{43}$/;
const CODE = /^[A-Za-z0-9_-]{43}$/;
const PURPOSES = Object.freeze(["login", "reauth"]);

/**
 * `adminUrl` as an origin (`scheme://host[:port]`, no path), or throws.
 * @param {string} adminUrl
 * @returns {string}
 */
function adminOrigin(adminUrl) {
  const url = new URL(adminUrl);
  if (url.protocol !== "https:" && url.protocol !== "http:") throw new Error("handoff: the admin URL is not http(s)");
  if (url.username !== "" || url.password !== "") throw new Error("handoff: the admin URL has credentials");
  return url.origin;
}

/**
 * A `next` that is a path on the admin origin, else `/`. The server cleans it
 * again; this only keeps an obviously foreign value from being sent at all.
 * @param {unknown} next
 * @returns {string}
 */
function plainPath(next) {
  if (typeof next !== "string") return "/";
  if (!next.startsWith("/") || next.startsWith("//") || /[\\\s\u0000-\u001f\u007f]/.test(next)) return "/";
  return next;
}

/**
 * Starts the hand-over from the vault origin: navigates to the begin page of
 * the admin origin.
 * @param {{
 *   api?: HandoffApi,
 *   adminUrl: string,
 *   next?: string,
 *   purpose?: "login" | "reauth",
 *   navigate?: (url: string) => void,
 * }} options
 * @returns {Promise<void>}
 */
export async function goToAdmin({ adminUrl, next = "/", purpose = "login", navigate = (url) => location.assign(url) }) {
  if (!PURPOSES.includes(purpose)) throw new Error("handoff: unknown purpose");
  const begin = new URL("/auth/handoff/begin", adminOrigin(adminUrl));
  begin.searchParams.set("next", plainPath(next));
  if (purpose === "reauth") begin.searchParams.set("purpose", "reauth");
  navigate(begin.href);
}

/**
 * Finishes the hand-over on the vault origin: mints the code and navigates to
 * the admin origin with the code in the fragment.
 * @param {{
 *   api: HandoffApi,
 *   challenge: string,
 *   next?: string,
 *   purpose?: "login" | "reauth",
 *   adminUrl: string,
 *   navigate?: (url: string) => void,
 * }} options
 * @returns {Promise<void>}
 */
export async function completeHandoff({ api, challenge, next = "/", purpose = "login", adminUrl, navigate = (url) => location.assign(url) }) {
  if (!PURPOSES.includes(purpose)) throw new Error("handoff: unknown purpose");
  if (typeof challenge !== "string" || !CHALLENGE.test(challenge)) throw new Error("handoff: the challenge is not 43 characters of base64url");
  const origin = adminOrigin(adminUrl);
  const answer = await api.post("/api/auth/handoff", { purpose, next: plainPath(next), challenge });
  const code = answer?.code;
  if (typeof code !== "string" || !CODE.test(code)) throw new Error("handoff: the server's code is not 43 characters of base64url");
  // The fragment is the one place a code may go.
  navigate(`${origin}/auth/handoff#code=${code}`);
}
