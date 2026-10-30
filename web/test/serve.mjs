// A static server for the browser tests: it serves web/dist the way the vault
// listener will (same paths, same content types) and sends the section 12
// headers on every answer, including 404.
//
// The headers come from crates/ferret-server/tests/fixtures/wire/headers.json,
// the file the server's own tests compare its header constant with. The
// loader fails closed: the file must be the flat object with exactly the five
// section 12 headers and a CSP that has the key directives, else it throws.
// While the server crate is not in the checkout, test/fixtures/headers.stub.json
// (the same values from the design document) can stand in, but only when
// FERRET_HEADERS_STUB=1 is set; if crates/ferret-server/ exists and its
// fixture is missing, nothing is served.
//
//   node test/serve.mjs     port 4578 (FERRET_WEB_PORT overrides it)
import { existsSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const web = resolve(here, "..");
const repo = resolve(web, "..");

export const SERVER_HEADERS_JSON = join(repo, "crates", "ferret-server", "tests", "fixtures", "wire", "headers.json");
export const STUB_HEADERS_JSON = join(here, "fixtures", "headers.stub.json");

export const HEADER_NAMES = Object.freeze([
  "Content-Security-Policy",
  "Cross-Origin-Opener-Policy",
  "Cross-Origin-Resource-Policy",
  "Referrer-Policy",
  "Strict-Transport-Security",
]);

/**
 * Throws unless `data` is the flat object of exactly the five section 12
 * headers, with a CSP that keeps the directives the vault depends on.
 * @param {unknown} data
 * @returns {Record<string, string>}
 */
export function validateHeaders(data) {
  if (data === null || typeof data !== "object" || Array.isArray(data)) {
    throw new Error("headers: expected one flat object of header names and values");
  }
  const flat = /** @type {Record<string, unknown>} */ (data);
  const names = Object.keys(flat).sort();
  if (names.join(",") !== [...HEADER_NAMES].sort().join(",")) {
    throw new Error(`headers: expected exactly ${HEADER_NAMES.join(", ")}; got ${names.join(", ") || "nothing"}`);
  }
  for (const name of names) {
    if (typeof flat[name] !== "string" || flat[name] === "") throw new Error(`headers: ${name} is not a text value`);
  }
  const csp = /** @type {string} */ (flat["Content-Security-Policy"]);
  /** @type {Map<string, string[]>} */
  const directives = new Map();
  for (const part of csp.split(";")) {
    const [name, ...tokens] = part.trim().split(/\s+/);
    // A browser uses the first of a repeated directive.
    if (name && !directives.has(name)) directives.set(name, tokens);
  }
  const is = (/** @type {string} */ name, /** @type {string[]} */ expected) =>
    directives.get(name)?.join(" ") === expected.join(" ");
  const problems = [];
  if (!is("default-src", ["'none'"])) problems.push("default-src 'none'");
  if (!is("require-trusted-types-for", ["'script'"])) problems.push("require-trusted-types-for 'script'");
  if (!is("trusted-types", ["ferret"])) problems.push("trusted-types ferret");
  if (!is("frame-ancestors", ["'none'"])) problems.push("frame-ancestors 'none'");
  for (const tokens of directives.values()) {
    if (tokens.some((t) => t === "'unsafe-inline'" || t === "'unsafe-eval'" || t === "*")) {
      problems.push("no 'unsafe-inline', 'unsafe-eval' or *");
      break;
    }
  }
  if (problems.length > 0) throw new Error(`headers: the CSP lacks: ${problems.join("; ")}`);
  return /** @type {Record<string, string>} */ (flat);
}

/**
 * The file to read the headers from.
 * @param {{ env?: Record<string, string | undefined>, repoDir?: string }} [options]
 */
export function headersFile({ env = process.env, repoDir = repo } = {}) {
  const real = join(repoDir, "crates", "ferret-server", "tests", "fixtures", "wire", "headers.json");
  if (existsSync(real)) return real;
  if (existsSync(join(repoDir, "crates", "ferret-server"))) {
    throw new Error("headers: crates/ferret-server exists but tests/fixtures/wire/headers.json is missing");
  }
  if (env.FERRET_HEADERS_STUB !== "1") {
    throw new Error("headers: the server fixture is missing; set FERRET_HEADERS_STUB=1 to use the stub");
  }
  return join(repoDir, "web", "test", "fixtures", "headers.stub.json");
}

/**
 * The header list of the vault origin.
 * @param {string} [file]
 * @returns {Record<string, string>}
 */
export function loadHeaders(file = headersFile()) {
  return validateHeaders(JSON.parse(readFileSync(file, "utf8")));
}

/**
 * @param {{ dist?: string, port?: number, headers?: Record<string, string> }} [options]
 */
export function start({ dist = join(web, "dist"), port = Number(process.env.FERRET_WEB_PORT ?? 4578), headers = loadHeaders() } = {}) {
  /** @type {Record<string, { type: string, bytes: Buffer }>} */
  const files = {};
  const manifest = JSON.parse(readFileSync(join(dist, "manifest.json"), "utf8"));
  for (const [path, { type }] of Object.entries(manifest)) {
    files[`/${path}`] = { type, bytes: readFileSync(join(dist, ...path.split("/"))) };
  }
  const server = createServer((req, res) => {
    let path;
    try {
      path = new URL(req.url ?? "/", "http://127.0.0.1").pathname;
    } catch {
      path = "";
    }
    if (path === "/") path = "/index.html";
    // The single-page app: /vault/* is the app too.
    if (path.startsWith("/vault/")) path = "/index.html";
    const served = /^\/(?:index\.html|app\/|js\/|pkg-web\/|assets\/)/.test(path) ? files[path] : undefined;
    if (req.method !== "GET" && req.method !== "HEAD") {
      res.writeHead(405, headers).end();
      return;
    }
    if (!served) {
      res.writeHead(404, { ...headers, "content-type": "text/plain; charset=utf-8" }).end("not found");
      return;
    }
    res.writeHead(200, {
      ...headers,
      "content-type": served.type,
      "content-length": served.bytes.length,
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
    });
    res.end(req.method === "HEAD" ? undefined : served.bytes);
  });
  server.listen(port, "127.0.0.1");
  return server;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const server = start();
  server.on("listening", () => console.log(`serving on http://127.0.0.1:${/** @type {any} */ (server.address()).port}`));
}
