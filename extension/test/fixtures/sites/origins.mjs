// The origins of the adversarial test sites. Each one is a host name (all of
// them in test/fixtures/hosts.json, so the runner maps them to the fixture
// server) on one of three listeners of the fixture server:
//
//   https  the main https port (443 in the runner, so a plain https://host/ has no port)
//   alt    a second https port (8443): the same host name on another port
//   http   the plain http port (80)
//
// The example family lives under example.net and example.org (reserved by RFC
// 2606 for documentation), because the core's Public Suffix List knows their
// top-level domains: example.net is a registrable domain, so www.example.net and
// login.example.net are on the same site, and a `domain` entry can match across
// them. A name under .test has no registrable domain (the list does not know
// it), so `.test` is used only where a case needs that: evil.test is a foreign
// site, the look-alike that puts the real host in front of a foreign one lives
// under it, and the harness hosts.
//
// Test-only: nothing under test/ is ever packaged (the release check refuses it),
// and the host names are internal hosts the release check refuses as well.

/** The name a person types for the mixed-script homograph: a Cyrillic small o (U+043E) for the Latin one in "login". */
export const HOMOGRAPH_UNICODE_HOST = "lоgin.example.net";
/** Its A-label form, which is what the browser sends and what the fixture server's certificate names. */
export const HOMOGRAPH_A_LABEL_HOST = "xn--lgin-55d.example.net";

/** A label written entirely in Cyrillic that looks like "apple" (one script, so it is shown in Unicode). */
export const CONFUSABLE_UNICODE_HOST = "аррӏе.example.net";
export const CONFUSABLE_A_LABEL_HOST = "xn--80ak6aa92e.example.net";

/** "login" with a Devanagari digit zero for the o: digits do not count as a script, so the label is shown in Unicode. */
export const DIGIT_UNICODE_HOST = "l०gin.example.net";
export const DIGIT_A_LABEL_HOST = "xn--lgin-qkj.example.net";

/**
 * @typedef {"https" | "alt" | "http"} Listener
 * @typedef {{ scheme: "https" | "http", host: string, listener: Listener, ip?: boolean }} Origin
 */

/** @type {Readonly<Record<string, Origin>>} */
export const ORIGINS = Object.freeze({
  // The host a vault entry is made for.
  login: { scheme: "https", host: "login.example.net", listener: "https" },
  // Same site as login (same registrable domain), another host.
  www: { scheme: "https", host: "www.example.net", listener: "https" },
  shop: { scheme: "https", host: "shop.example.net", listener: "https" },
  // A foreign site.
  evil: { scheme: "https", host: "evil.test", listener: "https" },
  // The entry's host over http, and on another port; a sibling over http.
  loginHttp: { scheme: "http", host: "login.example.net", listener: "http" },
  loginAlt: { scheme: "https", host: "login.example.net", listener: "alt" },
  wwwHttp: { scheme: "http", host: "www.example.net", listener: "http" },
  // Look-alikes: a dash for the dot, the real host as the left part of a foreign
  // one, another top-level domain, a mixed-script homograph (Cyrillic o in
  // login), an all-Cyrillic label and a label with a Devanagari digit.
  dash: { scheme: "https", host: "login-example.net", listener: "https" },
  suffix: { scheme: "https", host: "login.example.net.evil.test", listener: "https" },
  tld: { scheme: "https", host: "login.example.org", listener: "https" },
  homograph: { scheme: "https", host: HOMOGRAPH_A_LABEL_HOST, listener: "https" },
  confusable: { scheme: "https", host: CONFUSABLE_A_LABEL_HOST, listener: "https" },
  digit: { scheme: "https", host: DIGIT_A_LABEL_HOST, listener: "https" },
  // Two sites on a private suffix of the real Public Suffix List (github.io).
  ghA: { scheme: "https", host: "a.github.io", listener: "https" },
  ghB: { scheme: "https", host: "b.github.io", listener: "https" },
  // The loopback address over http: a secure context, and the one place where
  // an http page may be an ancestor. An IP host, so it is not in hosts.json.
  loopback: { scheme: "http", host: "127.0.0.1", listener: "http", ip: true },
});

/** Every host name the sites use (IP addresses are not names: they need no entry in hosts.json). */
export const ORIGIN_HOSTS = Object.freeze([...new Set(Object.values(ORIGINS).filter((o) => !o.ip).map((o) => o.host))]);

/** The IP hosts the server accepts besides the listed names. */
export const IP_HOSTS = Object.freeze(Object.values(ORIGINS).filter((o) => o.ip).map((o) => o.host));

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
