// The passkey fixture server (U4-3): https on 443 and http on 80 for every host name of
// hosts.json (and localhost), one certificate from a test CA made at start (tls.mjs), the
// test pages (../pages), two relying parties behind /api/swa/ (SimpleWebAuthn, swa.mjs) and
// /api/rs/ (webauthn-rs, the binary of ../webauthn-rs-fixture, started here), and a place
// where the pages leave their results for the runner (/api/report).
//
//   GET  /healthz                 "ok"
//   GET  /.fixture/ca.pem         the test CA (PEM), over http and https
//   GET  /.fixture/info           {hosts, caSha256}
//   GET  /<page>                  a file of ../pages (/ is index.html)
//   POST /api/{swa|rs}/<step>     see swa.mjs and the webauthn-rs fixture; ?hold=<ms> delays the answer of a finish step
//   POST /api/report              {run, ...} one result of a page for the run
//   GET  /api/report?run=<id>     the results of the run, in order
//   POST /api/report/clear?run=   forget the run
//
// The origin a relying party expects is the Origin header of the request, and only a
// header that names one of the fixture's own origins is taken (https://<host>, and
// http(s)://localhost): an opaque origin ("null") or a foreign one is refused.
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, statSync } from "node:fs";
import { createServer as createHttpServer, request as httpRequest } from "node:http";
import { createServer } from "node:https";
import { dirname, extname, join, normalize, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { handleSwa } from "./swa.mjs";
import { makeCertificates } from "./tls.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const config = JSON.parse(readFileSync(resolve(here, "..", "hosts.json"), "utf8"));
/** @type {string[]} */
const hosts = config.hosts;
/** @type {string[]} */
const localhostNames = config.localhostNames;
const pagesDir = resolve(here, "..", "pages");
const httpsPort = Number(process.env.FIXTURE_HTTPS_PORT ?? 443);
const httpPort = Number(process.env.FIXTURE_HTTP_PORT ?? 80);
const rsAddr = process.env.FIXTURE_RS_ADDR ?? "127.0.0.1:8081";
const workDir = process.env.FIXTURE_WORK ?? "/work";

/**
 * The origin text of a fixture origin, or undefined for any other.
 * @param {string | undefined} text
 */
export function fixtureOrigin(text) {
  if (!text) return undefined;
  let url;
  try {
    url = new URL(text);
  } catch {
    return undefined;
  }
  if (url.origin === "null" || url.port !== "") return undefined;
  // A trailing dot names the same host (https://rp-a.test./); the origin the relying party expects keeps it, as the browser sends it.
  const name = url.hostname.endsWith(".") ? url.hostname.slice(0, -1) : url.hostname;
  if (url.protocol === "https:" && (hosts.includes(name) || localhostNames.includes(name))) return url.origin;
  if (url.protocol === "http:" && localhostNames.includes(name)) return url.origin;
  return undefined;
}

const TYPES = /** @type {Record<string, string>} */ ({
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json",
  ".txt": "text/plain; charset=utf-8",
});

/** @type {Map<string, any[]>} */
const reports = new Map();

mkdirSync(workDir, { recursive: true });
const { caPem, keyPem, certPem } = makeCertificates(workDir, hosts, localhostNames);
const caSha256 = createHash("sha256").update(caPem).digest("hex");

// The webauthn-rs fixture, when its binary is there.
if (process.env.FIXTURE_RS_BIN) {
  const child = spawn(process.env.FIXTURE_RS_BIN, [], { env: { ...process.env, FIXTURE_RS_ADDR: rsAddr }, stdio: ["ignore", "inherit", "inherit"] });
  child.on("exit", (code) => {
    console.error(`fixture: the webauthn-rs fixture ended (${code})`);
    process.exit(1);
  });
}

/** @param {import("node:http").IncomingMessage} req @returns {Promise<Buffer>} */
function readBody(req) {
  return new Promise((resolveBody, reject) => {
    /** @type {Buffer[]} */
    const chunks = [];
    let size = 0;
    req.on("data", (c) => {
      size += c.length;
      if (size > 16 << 20) {
        reject(new Error("body too large"));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolveBody(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

/** @param {string} route @param {Buffer} body @param {string} origin @returns {Promise<{ status: number, json: any }>} */
function callRs(route, body, origin) {
  return new Promise((resolveCall) => {
    const [host, port] = rsAddr.split(":");
    let payload;
    try {
      payload = JSON.stringify({ ...JSON.parse(body.toString("utf8")), origin });
    } catch {
      resolveCall({ status: 400, json: { ok: false, error: "bad json" } });
      return;
    }
    const req = httpRequest({ host, port: Number(port), path: `/${route}`, method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(payload) } }, (res) => {
      /** @type {Buffer[]} */
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => {
        try {
          resolveCall({ status: res.statusCode ?? 500, json: JSON.parse(Buffer.concat(chunks).toString("utf8")) });
        } catch {
          resolveCall({ status: 502, json: { ok: false, error: "the webauthn-rs fixture sent no JSON" } });
        }
      });
    });
    req.on("error", (e) => resolveCall({ status: 502, json: { ok: false, error: `the webauthn-rs fixture: ${e.message}` } }));
    req.end(payload);
  });
}

const sleep = (/** @type {number} */ ms) => new Promise((r) => setTimeout(r, ms));

/** @param {"https" | "http"} listener */
const handler = (listener) => async (/** @type {import("node:http").IncomingMessage} */ req, /** @type {import("node:http").ServerResponse} */ res) => {
  const host = String(req.headers.host ?? "").split(":")[0].toLowerCase().replace(/\.$/, "");
  const url = new URL(req.url ?? "/", "https://placeholder.invalid");
  const common = { "cache-control": "no-store", "x-content-type-options": "nosniff" };
  // A sandboxed frame (opaque origin, Origin: null) may read the answers of the API, so that the browser's own refusal of it can be seen.
  const opaqueCors = req.headers.origin === "null" ? { "access-control-allow-origin": "null", vary: "origin" } : {};
  if (req.method === "OPTIONS" && url.pathname.startsWith("/api/")) {
    res.writeHead(204, { ...common, ...opaqueCors, "access-control-allow-methods": "POST, OPTIONS", "access-control-allow-headers": "content-type" }).end();
    return;
  }
  /** @param {number} status @param {any} json */
  const sendJson = (status, json) => res.writeHead(status, { ...common, ...opaqueCors, "content-type": "application/json" }).end(JSON.stringify(json));
  try {
    if (url.pathname === "/healthz") {
      res.writeHead(200, { ...common, "content-type": "text/plain" }).end("ok\n");
      return;
    }
    if (!hosts.includes(host) && !localhostNames.includes(host)) {
      res.writeHead(421, { ...common, "content-type": "text/plain" }).end("unknown host\n");
      return;
    }
    if (url.pathname === "/.fixture/ca.pem") {
      res.writeHead(200, { ...common, "content-type": "application/x-pem-file" }).end(caPem);
      return;
    }
    if (url.pathname === "/.fixture/info") {
      sendJson(200, { hosts, localhostNames, caSha256, listener });
      return;
    }
    if (url.pathname === "/api/report") {
      if (req.method === "POST") {
        const body = JSON.parse((await readBody(req)).toString("utf8"));
        const run = String(body.run ?? "");
        if (!/^[a-z0-9-]{1,80}$/.test(run)) return sendJson(400, { ok: false, error: "bad run id" });
        const list = reports.get(run) ?? [];
        list.push({ ...body, at: Date.now(), reportedFrom: { host, origin: req.headers.origin ?? null } });
        reports.set(run, list);
        return sendJson(200, { ok: true });
      }
      const run = url.searchParams.get("run") ?? "";
      return sendJson(200, { ok: true, reports: reports.get(run) ?? [] });
    }
    if (url.pathname === "/api/report/clear" && req.method === "POST") {
      reports.delete(url.searchParams.get("run") ?? "");
      return sendJson(200, { ok: true });
    }
    const api = /^\/api\/(swa|rs)\/([a-z]+\/[a-z]+|reset)$/.exec(url.pathname);
    if (api) {
      if (req.method !== "POST") return sendJson(405, { ok: false, error: "POST only" });
      const body = await readBody(req);
      let origin = fixtureOrigin(String(req.headers.origin ?? ""));
      if (!origin && req.headers.origin === "null" && api[2].endsWith("/start")) {
        // A sandboxed frame has an opaque origin. It may fetch the options (so the browser's own answer to it can be seen), for the
        // RP ID it names, and never finish: the finish step takes no opaque origin.
        const named = fixtureOrigin(`https://${String(JSON.parse(body.toString("utf8") || "{}").rpId ?? "")}`);
        if (named) origin = named;
      }
      if (!origin) return sendJson(403, { ok: false, error: `the origin ${JSON.stringify(req.headers.origin ?? null)} is not one of the fixture's` });
      const result = api[1] === "swa" ? await handleSwa(api[2], JSON.parse(body.toString("utf8") || "{}"), origin) : await callRs(api[2], body, origin);
      const hold = Number(url.searchParams.get("hold") ?? 0);
      if (hold > 0 && api[2].endsWith("/finish")) await sleep(Math.min(hold, 120_000));
      return sendJson(result.status, result.json);
    }
    if (req.method !== "GET" && req.method !== "HEAD") return sendJson(405, { ok: false, error: "method not allowed" });
    if (url.pathname === "/vendor/simplewebauthn-browser.js") {
      // The browser library of SimpleWebAuthn (MIT), the UMD bundle that its package ships.
      res.writeHead(200, { ...common, "access-control-allow-origin": "*", "content-type": TYPES[".js"] });
      res.end(readFileSync(resolve(here, "node_modules", "@simplewebauthn", "browser", "dist", "bundle", "index.umd.min.js")));
      return;
    }
    const rel = normalize(decodeURIComponent(url.pathname === "/" ? "/index.html" : url.pathname)).replace(/^([/\\])+/, "");
    const file = join(pagesDir, rel);
    if (!file.startsWith(pagesDir) || rel.startsWith("..")) return sendJson(404, { ok: false, error: "not found" });
    let st;
    try {
      st = statSync(file);
    } catch {
      return sendJson(404, { ok: false, error: "not found" });
    }
    if (!st.isFile()) return sendJson(404, { ok: false, error: "not found" });
    // The pages are public test pages: a sandboxed frame (opaque origin) has to be able to load their module scripts.
    res.writeHead(200, { ...common, "access-control-allow-origin": "*", "content-type": TYPES[extname(file)] ?? "application/octet-stream" });
    res.end(req.method === "HEAD" ? undefined : readFileSync(file));
  } catch (e) {
    if (!res.headersSent) sendJson(500, { ok: false, error: e instanceof Error ? e.message : String(e) });
  }
};

const tls = { key: keyPem, cert: certPem };
createServer(tls, handler("https")).listen(httpsPort, "0.0.0.0", () => console.log(`fixture: https on ${httpsPort}`));
createHttpServer(handler("http")).listen(httpPort, "0.0.0.0", () => console.log(`fixture: http on ${httpPort}`));
console.log(`fixture: CA sha256 ${caSha256}; hosts ${hosts.join(", ")}`);
