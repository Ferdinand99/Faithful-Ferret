// A small static server for the browser tests, on 127.0.0.1 only.
//
// It serves four trees under one origin:
//
//   /                   tests/browser           the test page and its modules
//   /vectors/           vectors                  the test vectors
//   /test/js/           bindings/wasm/js         the page client and the workers
//   /test/pkg-web/      bindings/wasm/pkg-web-test   the web package with `test-support`
//   /release/js/        bindings/wasm/js         the same workers ...
//   /release/pkg-web/   bindings/wasm/pkg-web    ... on the release package
//
// The workers import `../pkg-web/ferret_core_wasm.js` next to themselves, so
// the same worker file runs on the test build under /test/ and on the release
// build under /release/ without a change. Nothing here is a production
// server: it only reads files below the four roots, never lists a directory
// and sends no cache headers.
//
//   node serve.mjs            port 4577 (FERRET_BROWSER_PORT overrides it)
import { createReadStream, statSync } from "node:fs";
import { createServer } from "node:http";
import { dirname, extname, join, normalize, sep } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, "..", "..");
const wasm = join(repo, "bindings", "wasm");

/** URL prefix -> directory, longest prefix first. */
const MOUNTS = [
  ["/test/pkg-web/", join(wasm, "pkg-web-test")],
  ["/test/js/", join(wasm, "js")],
  ["/release/pkg-web/", join(wasm, "pkg-web")],
  ["/release/js/", join(wasm, "js")],
  ["/vectors/", join(repo, "vectors")],
  ["/", here],
];

const TYPES = {
  ".html": "text/html; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".md": "text/plain; charset=utf-8",
  ".wasm": "application/wasm",
};

/** Files of tests/browser that the page may fetch (not node_modules, not results). */
const PAGE_FILES = /^\/[A-Za-z0-9._-]+\.(html|mjs)$/;

function resolve(pathname) {
  for (const [prefix, dir] of MOUNTS) {
    if (!pathname.startsWith(prefix)) continue;
    const rest = pathname.slice(prefix.length);
    if (prefix === "/" && !PAGE_FILES.test(pathname)) return null;
    const file = normalize(join(dir, rest));
    if (file !== dir && !file.startsWith(dir + sep)) return null;
    return file;
  }
  return null;
}

export function start(port = Number(process.env.FERRET_BROWSER_PORT ?? 4577)) {
  const server = createServer((req, res) => {
    let pathname;
    try {
      pathname = decodeURIComponent(new URL(req.url, "http://127.0.0.1").pathname);
    } catch {
      res.writeHead(400).end();
      return;
    }
    if (pathname === "/") pathname = "/index.html";
    if (req.method !== "GET" && req.method !== "HEAD") {
      res.writeHead(405).end();
      return;
    }
    const file = pathname.includes("\0") ? null : resolve(pathname);
    let size = -1;
    try {
      const st = file ? statSync(file) : null;
      if (st?.isFile()) size = st.size;
    } catch {
      // not found
    }
    if (size < 0) {
      res.writeHead(404, { "content-type": "text/plain" }).end("not found");
      return;
    }
    res.writeHead(200, {
      "content-type": TYPES[extname(file)] ?? "application/octet-stream",
      "content-length": size,
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
    });
    if (req.method === "HEAD") res.end();
    else createReadStream(file).pipe(res);
  });
  server.listen(port, "127.0.0.1");
  return server;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const server = start();
  server.on("listening", () => console.log(`serving on http://127.0.0.1:${server.address().port}`));
}
