// The origins of the adversarial test sites. Each one is a host name (all of
// them in test/fixtures/hosts.json, so the runner maps them to the fixture
// server) on one of three listeners of the fixture server:
//
//   https  the main https port (443 in the runner, so a plain https://host/ has no port)
//   alt    a second https port (8443): the same host name on another port
//   http   the plain http port (80)
//
// Test-only: nothing under test/ is ever packaged (the release check refuses it),
// and the host names are internal hosts the release check refuses as well.

/** The Unicode form of the homograph host: a Cyrillic small o (U+043E) for the Latin one in "login". */
export const HOMOGRAPH_UNICODE_HOST = "l\u043egin.example.test";
/** Its A-label form, which is what the browser sends and what the fixture server's certificate names. */
export const HOMOGRAPH_A_LABEL_HOST = "xn--lgin-55d.example.test";

/**
 * @typedef {"https" | "alt" | "http"} Listener
 * @typedef {{ scheme: "https" | "http", host: string, listener: Listener }} Origin
 */

/** @type {Readonly<Record<string, Origin>>} */
export const ORIGINS = Object.freeze({
  // The host a vault entry is made for.
  login: { scheme: "https", host: "login.example.test", listener: "https" },
  // Same site as login (same registrable domain), another host.
  www: { scheme: "https", host: "www.example.test", listener: "https" },
  shop: { scheme: "https", host: "shop.example.test", listener: "https" },
  // A foreign site.
  evil: { scheme: "https", host: "evil.test", listener: "https" },
  // The entry's host over http, and on another port.
  loginHttp: { scheme: "http", host: "login.example.test", listener: "http" },
  loginAlt: { scheme: "https", host: "login.example.test", listener: "alt" },
  // Lookalikes: a dash for the dot, the real host as the left part of a foreign
  // one, and a homograph (Cyrillic o) that the browser turns into an xn-- host.
  dash: { scheme: "https", host: "login-example.test", listener: "https" },
  suffix: { scheme: "https", host: "login.example.test.evil.test", listener: "https" },
  homograph: { scheme: "https", host: HOMOGRAPH_A_LABEL_HOST, listener: "https" },
  // Two sites on a private suffix of the real Public Suffix List (github.io).
  ghA: { scheme: "https", host: "a.github.io", listener: "https" },
  ghB: { scheme: "https", host: "b.github.io", listener: "https" },
});

/** Every host name the sites use. */
export const ORIGIN_HOSTS = Object.freeze([...new Set(Object.values(ORIGINS).map((o) => o.host))]);

/**
 * The ports of a running fixture server.
 * @typedef {{ https: number, alt: number, http: number }} Ports
 */

/**
 * The origin text of a named origin, with the port left out when it is the
 * scheme's default.
 * @param {string} name
 * @param {Ports} ports
 * @returns {string}
 */
export function originText(name, ports) {
  const origin = ORIGINS[name];
  if (!origin) throw new Error(`fixtures: no origin named ${name}`);
  const port = ports[origin.listener];
  const standard = origin.scheme === "https" ? 443 : 80;
  return `${origin.scheme}://${origin.host}${port === standard ? "" : `:${port}`}`;
}
