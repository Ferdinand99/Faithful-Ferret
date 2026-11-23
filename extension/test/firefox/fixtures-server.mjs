// The fixture server of the Firefox tests: https with a certificate authority
// made at start (nothing is baked into the image), the host names of
// test/fixtures/hosts.json, a server-sent-events stream and one sign-in page.
//
//   /sse                  an event every `sseIntervalMs` (10 s by default)
//   /static/login.html    one sign-in form (user name and password)
//   /static/signup.html   one sign-up form (e-mail, a new password with a maxlength of 24, and its confirmation)
//   /static/blank.html    an empty page
//   /static/cover/<id>.html  a sign-in page of coverPages.mjs (layouts the extra pass for covers must keep filling, and covers it must refuse)
//   /static/frames.html   one page with an iframe of each kind that has an opaque or special origin
//                         (srcdoc, sandboxed without allow-same-origin, about:blank) and one ordinary one
//   /healthz              "ok"
//
// The adversarial test sites of test/fixtures/sites (phishing and clickjacking
// pages) are served on three listeners: the main https port, a second https port
// and plain http, so one host name can be tested on another port and over http.
//
// The detection corpus of test/fixtures/forms is served the same way, from any listed
// host on any listener: `/<case id>/` is the case's index.html and `/<case id>/<file>`
// another page or script of the case (GET, HEAD and POST, so a form may post to a page of
// its own). `{{origin:<name>}}` in a file becomes the origin of a named origin of the
// sites, with the run's ports.
import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createServer as createHttpServer } from "node:http";
import { createServer } from "node:https";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { findSite, siteById } from "../fixtures/sites/index.mjs";
import { coverPage } from "./coverPages.mjs";
import { IP_HOSTS, originText } from "../fixtures/sites/origins.mjs";

const here = dirname(fileURLToPath(import.meta.url));

/** The detection corpus (extension/test/fixtures/forms). */
export const FORMS_DIR = resolve(here, "..", "fixtures", "forms");
/** The set that is added to the repository later (a folder that does not exist is skipped). */
const HOLDOUT_FORMS_DIR = resolve(here, "..", "fixtures", "forms-holdout");
const FORM_FILE_TYPES = /** @type {Record<string, string>} */ ({
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
});

/**
 * The case folders of the corpus directories (a folder holds the pages of one case), by case id.
 * A later directory does not replace an earlier one's case.
 * @param {string[]} dirs
 * @returns {Map<string, string>}
 */
export function listFormCases(dirs) {
  /** @type {Map<string, string>} */
  const cases = new Map();
  for (const dir of dirs) {
    if (!existsSync(dir)) continue;
    for (const name of readdirSync(dir)) {
      const folder = join(dir, name);
      if (/^[a-z0-9_][a-z0-9-]*$/.test(name) && statSync(folder).isDirectory() && !cases.has(name)) cases.set(name, folder);
    }
  }
  return cases;
}

/**
 * The file of a corpus request, or undefined: `/<id>/` or `/<id>/<file>` with a plain file name of a known type.
 * @param {Map<string, string>} cases
 * @param {string} path
 * @returns {{ file: string, type: string } | undefined}
 */
export function formFile(cases, path) {
  const m = /^\/([a-z0-9_][a-z0-9-]*)\/([a-z0-9][a-z0-9._-]*)?$/.exec(path);
  if (!m) return undefined;
  const folder = cases.get(m[1]);
  if (!folder) return undefined;
  const name = m[2] ?? "index.html";
  const type = FORM_FILE_TYPES[name.slice(name.lastIndexOf("."))];
  const file = join(folder, name);
  return type && existsSync(file) && statSync(file).isFile() ? { file, type } : undefined;
}

/**
 * The host names in test/fixtures/hosts.json. A run against an end-to-end stack of its own
 * (FERRET_E2E_SUFFIX, set by scripts/lanbox-ext.sh) has that stack's names in place of "e2e".
 * @returns {{ fixture: string[], e2e: string[] }}
 */
export function readHosts() {
  const data = JSON.parse(readFileSync(resolve(here, "..", "fixtures", "hosts.json"), "utf8"));
  /** @type {string[]} */
  let e2e = data.e2e ?? [];
  const suffix = process.env.FERRET_E2E_SUFFIX ?? "";
  if (suffix !== "") {
    if (!/^[a-z0-9]{1,12}$/.test(suffix)) throw new Error(`FERRET_E2E_SUFFIX is 1 to 12 lower-case letters and digits, not ${JSON.stringify(suffix)}`);
    e2e = e2e.map((host) => host.replace(/-e2e\.test$/, `-${suffix}.test`));
  }
  return { fixture: data.fixture ?? [], e2e };
}

const COVER_PATH_PREFIX = "/static/cover/";
const COVER_PATH_SUFFIX = ".html";
const COVER_PATH = new RegExp("^/static/cover/[a-z0-9-]+\\.html$");

const LOGIN_HTML = `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Fixture sign-in</title></head>
<body>
  <form id="login" method="post" action="/static/login-done.html">
    <label>User name <input id="username" name="username" type="text" autocomplete="username"></label>
    <label>Password <input id="password" name="password" type="password" autocomplete="current-password"></label>
    <button id="submit" type="submit">Sign in</button>
  </form>
</body>
</html>
`;

const SIGNUP_HTML = `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Fixture sign-up</title></head>
<body>
  <form id="signup" method="post" action="/static/login-done.html">
    <label>E-mail <input id="email" name="email" type="email" autocomplete="email"></label>
    <label>Password <input id="new-password" name="password" type="password" autocomplete="new-password" maxlength="24"></label>
    <label>Repeat the password <input id="confirm-password" name="password2" type="password" autocomplete="new-password"></label>
    <button id="submit" type="submit">Create account</button>
  </form>
</body>
</html>
`;

// Frames of every kind the fill engine has to tell apart. The sandboxed one has an https
// address but an opaque origin; the srcdoc and about:blank ones inherit the parent's.
const FRAMES_HTML = `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Fixture frames</title></head>
<body>
  <h1>Frames</h1>
  <input id="top" type="text" name="top">
  <iframe id="srcdoc" srcdoc="&lt;!doctype html&gt;&lt;title&gt;srcdoc&lt;/title&gt;&lt;input id=f1 type=text&gt;"></iframe>
  <iframe id="sandboxed" sandbox="allow-scripts" src="/static/blank.html"></iframe>
  <iframe id="blank"></iframe>
  <iframe id="same" src="/static/login.html"></iframe>
</body>
</html>
`;

const BLANK_HTML = "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title>Fixture</title></head><body></body></html>\n";

/**
 * Makes a certificate authority and a server certificate for `hosts` with the
 * openssl program. The key of the authority is deleted again once the server
 * certificate is signed, so nothing can mint more certificates later.
 * @param {string} dir
 * @param {string[]} hosts
 * @returns {{ caPem: string, caFile: string, keyPem: string, certPem: string }}
 */
export function makeCertificates(dir, hosts) {
  if (hosts.length === 0) throw new Error("fixtures: no host names");
  const run = (/** @type {string[]} */ ...args) => execFileSync("openssl", args, { cwd: dir, stdio: ["ignore", "ignore", "pipe"] });
  const ec = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes"];
  run("req", "-x509", ...ec, "-keyout", "ca.key", "-out", "ca.pem", "-days", "2", "-subj", "/CN=Ferret test fixtures CA",
    "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0", "-addext", "keyUsage=critical,keyCertSign,cRLSign");
  run("req", "-new", ...ec, "-keyout", "server.key", "-out", "server.csr", "-subj", `/CN=${hosts[0]}`);
  writeFileSync(join(dir, "server.ext"), [
    `subjectAltName=${hosts.map((h) => `DNS:${h}`).join(",")}`,
    "basicConstraints=critical,CA:FALSE",
    "keyUsage=critical,digitalSignature",
    "extendedKeyUsage=serverAuth",
    "",
  ].join("\n"));
  run("x509", "-req", "-in", "server.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-days", "2", "-out", "server.pem", "-extfile", "server.ext");
  rmSync(join(dir, "ca.key"));
  chmodSync(join(dir, "server.key"), 0o600);
  return {
    caPem: readFileSync(join(dir, "ca.pem"), "utf8"),
    caFile: join(dir, "ca.pem"),
    keyPem: readFileSync(join(dir, "server.key"), "utf8"),
    certPem: readFileSync(join(dir, "server.pem"), "utf8"),
  };
}

/**
 * @typedef {{
 *   hosts: string[], port: number, altPort: number, httpPort: number,
 *   ports: import("../fixtures/sites/origins.mjs").Ports,
 *   caFile: string, caPem: string, dir: string,
 *   requests: { host: string, method: string, path: string, listener: string }[],
 *   url: (host: string, path?: string) => string,
 *   origin: (name: string) => string,
 *   siteUrl: (id: string) => string,
 *   close: () => Promise<void>,
 * }} Fixtures
 *   `port` is the main https port, `altPort` the second https port, `httpPort` the
 *   plain http port. `origin(name)` is the origin text of a named origin of the
 *   sites (no port when it is the scheme's default); `siteUrl(id)` the address of a site.
 */

/**
 * Starts the server on 127.0.0.1. The host names resolve to this machine (the
 * runner's /etc/hosts and the profile's network.dns.localDomains).
 *
 * `port`, `altPort` and `httpPort` are the three listeners; 0 picks a free port.
 * The runner uses 443, 8443 and 80, so the test sites have the same origins as
 * a real site (https://login.example.net/ has no port in it). Two listeners
 * cannot share a port.
 * `forms` lists the corpus directories (default: the corpus of test/fixtures/forms and, where it exists, forms-holdout).
 * @param {{ hosts?: string[], port?: number, altPort?: number, httpPort?: number, sseIntervalMs?: number, dir?: string, forms?: string[] }} [options]
 * @returns {Promise<Fixtures>}
 */
export async function startFixtures({ hosts = readHosts().fixture, port = 0, altPort = 0, httpPort = 0, sseIntervalMs = 10_000, dir, forms = [FORMS_DIR, HOLDOUT_FORMS_DIR] } = {}) {
  const formCases = listFormCases(forms);
  const wanted = [port, altPort, httpPort].filter((p) => p !== 0);
  if (new Set(wanted).size !== wanted.length) throw new Error(`fixtures: two listeners want the same port (${port}, ${altPort}, ${httpPort})`);
  const work = dir ?? mkdtempSync(join(tmpdir(), "ferret-fixtures-"));
  mkdirSync(work, { recursive: true });
  const { caPem, caFile, keyPem, certPem } = makeCertificates(work, hosts);

  /** @type {Fixtures["requests"]} */
  const requests = [];
  /** @type {Set<import("node:http").ServerResponse>} */
  const streams = new Set();
  /** @type {import("../fixtures/sites/origins.mjs").Ports} */
  const ports = { https: 0, alt: 0, http: 0 };

  /** @param {import("../fixtures/sites/origins.mjs").Listener} listener */
  const handler = (listener) => (/** @type {import("node:http").IncomingMessage} */ req, /** @type {import("node:http").ServerResponse} */ res) => {
    const host = String(req.headers.host ?? "").split(":")[0].toLowerCase();
    const path = new URL(req.url ?? "/", "https://placeholder.invalid").pathname;
    requests.push({ host, method: req.method ?? "GET", path, listener });
    // The listed names, and (over http only) the IP hosts of the sites, which need no certificate.
    if (!hosts.includes(host) && !(listener === "http" && IP_HOSTS.includes(host))) {
      res.writeHead(421, { "content-type": "text/plain" }).end("unknown host\n");
      return;
    }
    const common = { "cache-control": "no-store", "x-content-type-options": "nosniff" };
    const site = req.method === "GET" || req.method === "HEAD" ? findSite(listener, host, path) : undefined;
    const form = req.method === "GET" || req.method === "HEAD" || req.method === "POST" ? formFile(formCases, path) : undefined;
    if (form) {
      // A form posts to a page of its own: the body is not needed.
      req.resume();
      const text = readFileSync(form.file, "utf8").replace(/\{\{origin:([A-Za-z]+)\}\}/g, (_, name) => originText(name, ports));
      res.writeHead(200, { ...common, "content-type": form.type }).end(req.method === "HEAD" ? undefined : text);
    } else if (site) {
      const html = site.render({ url: (origin, p = "/") => `${originText(origin, ports)}${p}` });
      res.writeHead(200, { ...common, "content-type": "text/html; charset=utf-8" }).end(req.method === "HEAD" ? undefined : html);
    } else if (path === "/sse" && req.method === "GET") {
      // CORS for the stream only, so the extension's own pages can read it without a host permission.
      res.writeHead(200, { ...common, "content-type": "text/event-stream", connection: "keep-alive", "access-control-allow-origin": "*" });
      res.write(": open\n\n");
      streams.add(res);
      let n = 0;
      const timer = setInterval(() => res.write(`id: ${++n}\nevent: tick\ndata: ${n}\n\n`), sseIntervalMs);
      res.on("close", () => { clearInterval(timer); streams.delete(res); });
    } else if (path === "/static/login.html") {
      res.writeHead(200, { ...common, "content-type": "text/html; charset=utf-8" }).end(LOGIN_HTML);
    } else if (path === "/static/signup.html") {
      res.writeHead(200, { ...common, "content-type": "text/html; charset=utf-8" }).end(SIGNUP_HTML);
    } else if (COVER_PATH.test(path) && coverPage(path.slice(COVER_PATH_PREFIX.length, -COVER_PATH_SUFFIX.length))) {
      const cover = /** @type {NonNullable<ReturnType<typeof coverPage>>} */ (coverPage(path.slice(COVER_PATH_PREFIX.length, -COVER_PATH_SUFFIX.length)));
      res.writeHead(200, { ...common, "content-type": "text/html; charset=utf-8" }).end(req.method === "HEAD" ? undefined : cover.html);
    } else if (path === "/static/frames.html") {
      res.writeHead(200, { ...common, "content-type": "text/html; charset=utf-8" }).end(FRAMES_HTML);
    } else if (path === "/static/blank.html" || path === "/static/login-done.html") {
      res.writeHead(200, { ...common, "content-type": "text/html; charset=utf-8" }).end(BLANK_HTML);
    } else if (path === "/healthz") {
      res.writeHead(200, { ...common, "content-type": "text/plain" }).end("ok\n");
    } else {
      res.writeHead(404, { ...common, "content-type": "text/plain" }).end("not found\n");
    }
  };

  const tls = { key: keyPem, cert: certPem };
  const servers = {
    https: createServer(tls, handler("https")),
    alt: createServer(tls, handler("alt")),
    http: createHttpServer(handler("http")),
  };
  const wantedPorts = { https: port, alt: altPort, http: httpPort };
  const listening = [];
  try {
    for (const name of /** @type {const} */ (["https", "alt", "http"])) {
      const server = servers[name];
      await new Promise((resolveListen, rejectListen) => {
        server.once("error", rejectListen);
        server.listen(wantedPorts[name], "127.0.0.1", () => resolveListen(undefined));
      });
      listening.push(server);
      ports[name] = /** @type {import("node:net").AddressInfo} */ (server.address()).port;
    }
  } catch (error) {
    for (const server of listening) server.close();
    rmSync(work, { recursive: true, force: true });
    throw error;
  }
  return {
    hosts,
    port: ports.https,
    altPort: ports.alt,
    httpPort: ports.http,
    ports,
    caFile,
    caPem,
    dir: work,
    requests,
    url: (host, path = "/") => `https://${host}${ports.https === 443 ? "" : `:${ports.https}`}${path}`,
    origin: (name) => originText(name, ports),
    siteUrl: (id) => {
      const site = siteById(id);
      return `${originText(site.origin, ports)}${site.path}`;
    },
    close: () => new Promise((done) => {
      for (const res of streams) res.destroy();
      let open = listening.length;
      const finished = () => {
        if (--open > 0) return;
        rmSync(work, { recursive: true, force: true });
        done(undefined);
      };
      for (const server of listening) {
        server.close(finished);
        server.closeAllConnections();
      }
    }),
  };
}
