// The minimal fixture server of the Firefox tests: https with a certificate
// authority made at start (nothing is baked into the image), the host names of
// test/fixtures/hosts.json, a server-sent-events stream and one sign-in page.
//
//   /sse                  an event every `sseIntervalMs` (10 s by default)
//   /static/login.html    one sign-in form (user name and password)
//   /static/blank.html    an empty page
//   /healthz              "ok"
//
// More sites (the test pages for the fill engine) are added under sites/ later.
import { execFileSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:https";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

/** The host names in test/fixtures/hosts.json. @returns {{ fixture: string[], e2e: string[] }} */
export function readHosts() {
  const data = JSON.parse(readFileSync(resolve(here, "..", "fixtures", "hosts.json"), "utf8"));
  return { fixture: data.fixture ?? [], e2e: data.e2e ?? [] };
}

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
 *   hosts: string[], port: number, caFile: string, caPem: string, dir: string,
 *   requests: { host: string, method: string, path: string }[],
 *   url: (host: string, path?: string) => string,
 *   close: () => Promise<void>,
 * }} Fixtures
 */

/**
 * Starts the server on 127.0.0.1. The host names resolve to this machine (the
 * runner's /etc/hosts and the profile's network.dns.localDomains).
 * @param {{ hosts?: string[], port?: number, sseIntervalMs?: number, dir?: string }} [options]
 * @returns {Promise<Fixtures>}
 */
export async function startFixtures({ hosts = readHosts().fixture, port = Number(process.env.FERRET_FIXTURE_PORT ?? 8443), sseIntervalMs = 10_000, dir } = {}) {
  const work = dir ?? mkdtempSync(join(tmpdir(), "ferret-fixtures-"));
  mkdirSync(work, { recursive: true });
  const { caPem, caFile, keyPem, certPem } = makeCertificates(work, hosts);

  /** @type {Fixtures["requests"]} */
  const requests = [];
  /** @type {Set<import("node:http").ServerResponse>} */
  const streams = new Set();
  const server = createServer({ key: keyPem, cert: certPem }, (req, res) => {
    const host = String(req.headers.host ?? "").split(":")[0].toLowerCase();
    const path = new URL(req.url ?? "/", "https://placeholder.invalid").pathname;
    requests.push({ host, method: req.method ?? "GET", path });
    if (!hosts.includes(host)) {
      res.writeHead(421, { "content-type": "text/plain" }).end("unknown host\n");
      return;
    }
    const common = { "cache-control": "no-store", "x-content-type-options": "nosniff" };
    if (path === "/sse" && req.method === "GET") {
      res.writeHead(200, { ...common, "content-type": "text/event-stream", connection: "keep-alive" });
      res.write(": open\n\n");
      streams.add(res);
      let n = 0;
      const timer = setInterval(() => res.write(`id: ${++n}\nevent: tick\ndata: ${n}\n\n`), sseIntervalMs);
      res.on("close", () => { clearInterval(timer); streams.delete(res); });
    } else if (path === "/static/login.html") {
      res.writeHead(200, { ...common, "content-type": "text/html; charset=utf-8" }).end(LOGIN_HTML);
    } else if (path === "/static/blank.html" || path === "/static/login-done.html") {
      res.writeHead(200, { ...common, "content-type": "text/html; charset=utf-8" }).end(BLANK_HTML);
    } else if (path === "/healthz") {
      res.writeHead(200, { ...common, "content-type": "text/plain" }).end("ok\n");
    } else {
      res.writeHead(404, { ...common, "content-type": "text/plain" }).end("not found\n");
    }
  });
  await new Promise((resolveListen, rejectListen) => {
    server.once("error", rejectListen);
    server.listen(port, "127.0.0.1", () => resolveListen(undefined));
  });
  const address = /** @type {import("node:net").AddressInfo} */ (server.address());
  const bound = address.port;
  return {
    hosts,
    port: bound,
    caFile,
    caPem,
    dir: work,
    requests,
    url: (host, path = "/") => `https://${host}:${bound}${path}`,
    close: () => new Promise((done) => {
      for (const res of streams) res.destroy();
      server.close(() => {
        rmSync(work, { recursive: true, force: true });
        done(undefined);
      });
      server.closeAllConnections();
    }),
  };
}
