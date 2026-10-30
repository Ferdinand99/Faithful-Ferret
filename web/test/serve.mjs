// A static server for the browser tests: it serves web/dist the way the vault
// listener will (same paths, same content types) and sends the section 12
// headers on every answer, including 404.
//
// The headers come from crates/ferret-server/tests/fixtures/wire/headers.json,
// the file the server's own tests compare its header constant with. Until
// that file exists in the checkout, test/fixtures/headers.stub.json (the same
// values from the design document) stands in.
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

/**
 * The header list as a flat object. The file may be that object, or hold it
 * under `headers` or `vault`.
 * @param {string} [file]
 * @returns {Record<string, string>}
 */
export function loadHeaders(file = existsSync(SERVER_HEADERS_JSON) ? SERVER_HEADERS_JSON : STUB_HEADERS_JSON) {
  const data = JSON.parse(readFileSync(file, "utf8"));
  const flat = data.headers ?? data.vault ?? data;
  for (const [name, value] of Object.entries(flat)) {
    if (typeof value !== "string") throw new Error(`headers: ${name} is not a string`);
  }
  return flat;
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
