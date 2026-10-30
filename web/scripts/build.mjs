#!/usr/bin/env node
// Builds web/dist: the static files the server embeds.
//
//   node scripts/build.mjs [--wasm-tar <path>] [--root <web dir>] [--out <dir>]
//
// 1. Reads wasm.lock.json ({version, url, sha256}), fetches the published
//    ferret-core-wasm-web-<version>.tar.gz (or takes --wasm-tar or
//    FERRET_WASM_TAR), checks its SHA-256 and unpacks pkg-web/ and js/.
// 2. Scans the feature files and writes the generated files:
//      src/routes/*.route.mjs       -> src/routes.gen.mjs
//      src/services/*.service.mjs   -> src/services.gen.mjs
//      src/locales/<lang>/<feature>.json -> dist/app/locales.<lang>.json
//      src/styles/<feature>.css     -> dist/assets/app.css
//    A feature adds its own files and edits no shared file.
// 3. Writes dist/ (index.html, app/*, js/*, pkg-web/*, assets/app.css,
//    admin/*, manifest.json with path -> SHA-256 and content type) and refuses
//    source maps, inline script or style in HTML, and files over 4 MiB that
//    are not .wasm.
//
// The route and service files are imported to read their `default` export, so
// they must have no side effects when imported.
import { createHash } from "node:crypto";
import {
  copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync,
} from "node:fs";
import { dirname, join, posix, relative, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { gunzipSync } from "node:zlib";
import { BASE_SERVICES, orderServices } from "../src/app.mjs";

export const MAX_FILE_BYTES = 4 * 1024 * 1024;

export const CONTENT_TYPES = Object.freeze({
  ".html": "text/html; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".wasm": "application/wasm",
});

const here = dirname(fileURLToPath(import.meta.url));

/** @param {Uint8Array | string} data */
export const sha256 = (data) => createHash("sha256").update(data).digest("hex");

/** @param {string} dir @returns {string[]} sorted names, [] when the folder is missing */
function listDir(dir) {
  return existsSync(dir) ? readdirSync(dir).sort() : [];
}

/** All files below `dir` as sorted posix paths relative to `dir`. @param {string} dir @returns {string[]} */
function walk(dir) {
  /** @type {string[]} */
  const out = [];
  /** @param {string} current */
  const visit = (current) => {
    for (const name of listDir(current)) {
      const full = join(current, name);
      if (statSync(full).isDirectory()) visit(full);
      else out.push(relative(dir, full).split(sep).join("/"));
    }
  };
  visit(dir);
  return out;
}

// ---------------------------------------------------------------- tar.gz

/** @param {Buffer} block @param {number} start @param {number} length */
function field(block, start, length) {
  const end = block.indexOf(0, start);
  return block.toString("utf8", start, end === -1 || end > start + length ? start + length : end);
}

/** @param {string} text @returns {Record<string, string>} */
function parsePax(text) {
  /** @type {Record<string, string>} */
  const out = {};
  let rest = Buffer.from(text, "utf8");
  while (rest.length > 0) {
    const space = rest.indexOf(0x20);
    const length = Number.parseInt(rest.toString("utf8", 0, space), 10);
    if (!(length > space) || length > rest.length) break;
    const record = rest.toString("utf8", space + 1, length - 1);
    const eq = record.indexOf("=");
    if (eq > 0) out[record.slice(0, eq)] = record.slice(eq + 1);
    rest = rest.subarray(length);
  }
  return out;
}

/**
 * Reads a .tar.gz into a map of path -> bytes. Only regular files and folders
 * are accepted (no link, no device), and a path must be relative and plain.
 * The one top-level folder of the archive is stripped.
 * @param {Uint8Array} gz
 * @returns {Map<string, Buffer>}
 */
export function readTarGz(gz) {
  const tar = gunzipSync(gz);
  /** @type {Map<string, Buffer>} */
  const files = new Map();
  let offset = 0;
  let longName = null;
  /** @type {Record<string, string>} */
  let pax = {};
  while (offset + 512 <= tar.length) {
    const header = tar.subarray(offset, offset + 512);
    offset += 512;
    if (header.every((b) => b === 0)) break;
    const stored = Number.parseInt(field(header, 148, 8).trim(), 8);
    let sum = 0;
    for (let i = 0; i < 512; i++) sum += i >= 148 && i < 156 ? 0x20 : header[i];
    if (stored !== sum) throw new Error("tar: bad header checksum");
    const size = Number.parseInt(field(header, 124, 12).trim() || "0", 8);
    const type = String.fromCharCode(header[156] || 0x30);
    const body = tar.subarray(offset, offset + size);
    if (body.length !== size) throw new Error("tar: truncated archive");
    offset += Math.ceil(size / 512) * 512;
    if (type === "x") { pax = parsePax(body.toString("utf8")); continue; }
    if (type === "g") continue;
    if (type === "L") { longName = field(body, 0, body.length); continue; }
    let name = pax.path ?? longName ?? field(header, 0, 100);
    const prefix = field(header, 345, 155);
    if (prefix && pax.path === undefined && longName === null) name = `${prefix}/${name}`;
    pax = {};
    longName = null;
    if (type === "5") continue;
    if (type !== "0") throw new Error(`tar: entry type ${type} is not allowed (${name})`);
    const parts = name.split("/").filter((p) => p !== "" && p !== ".");
    if (name.startsWith("/") || name.includes("\\") || name.includes("\0") || parts.includes("..") || parts.length < 2) {
      throw new Error(`tar: path not allowed: ${name}`);
    }
    files.set(parts.slice(1).join("/"), Buffer.from(body));
  }
  return files;
}

// --------------------------------------------------------------- features

/** @param {string} file */
async function importDefault(file) {
  const module = await import(pathToFileURL(file).href);
  return module.default;
}

/** @param {string} root @param {string} dir @param {string} suffix */
function featureFiles(root, dir, suffix) {
  const base = join(root, "src", dir);
  return listDir(base).filter((n) => n.endsWith(suffix)).map((n) => join(base, n));
}

/** @param {string} root */
async function generateRoutes(root) {
  const files = featureFiles(root, "routes", ".route.mjs");
  /** @type {Set<string>} */
  const paths = new Set();
  const lines = [];
  for (const [i, file] of files.entries()) {
    const route = await importDefault(file);
    const label = relative(root, file);
    if (!route || typeof route.path !== "string" || !/^\/[A-Za-z0-9_./:-]*$/.test(route.path)
      || typeof route.title !== "string" || typeof route.load !== "function") {
      throw new Error(`${label}: a route exports { path, title, load } as default`);
    }
    if (paths.has(route.path)) throw new Error(`${label}: route path used twice: ${route.path}`);
    paths.add(route.path);
    lines.push(`import route${i} from "./routes/${posix.basename(file)}";`);
  }
  const list = files.map((_, i) => `route${i}`).join(", ");
  return [
    "// Generated by scripts/build.mjs from src/routes/*.route.mjs. Do not edit.",
    ...lines,
    "",
    `/** @type {import("./app.mjs").Route[]} */`,
    `export default [${list}];`,
    "",
  ].join("\n");
}

/** @param {string} root */
async function generateServices(root) {
  const files = featureFiles(root, "services", ".service.mjs");
  const defs = [];
  const lines = [];
  for (const [i, file] of files.entries()) {
    const def = await importDefault(file);
    const label = relative(root, file);
    if (!def || typeof def.name !== "string" || !/^[a-z][A-Za-z0-9]*$/.test(def.name)
      || !Array.isArray(def.deps) || !def.deps.every((d) => typeof d === "string")
      || typeof def.create !== "function") {
      throw new Error(`${label}: a service exports { name, deps, create } as default`);
    }
    defs.push(def);
    lines.push(`import service${i} from "./services/${posix.basename(file)}";`);
  }
  orderServices(defs, BASE_SERVICES); // throws on a duplicate, an unknown dependency or a cycle
  const list = files.map((_, i) => `service${i}`).join(", ");
  return [
    "// Generated by scripts/build.mjs from src/services/*.service.mjs. Do not edit.",
    ...lines,
    "",
    `/** @type {import("./app.mjs").ServiceDef[]} */`,
    `export default [${list}];`,
    "",
  ].join("\n");
}

/** @param {string} root @returns {Map<string, string>} language -> catalog JSON */
function generateLocales(root) {
  const base = join(root, "src", "locales");
  /** @type {Map<string, string>} */
  const out = new Map();
  for (const lang of listDir(base)) {
    if (!/^[a-z]{2}(?:-[A-Z]{2})?$/.test(lang)) throw new Error(`locales/${lang}: not a language code`);
    /** @type {Record<string, string>} */
    const catalog = {};
    /** @type {Map<string, string>} */
    const owner = new Map();
    for (const name of listDir(join(base, lang))) {
      const match = /^([a-z][a-z0-9-]*)\.json$/.exec(name);
      if (!match) throw new Error(`locales/${lang}/${name}: expected <feature>.json`);
      const feature = match[1];
      const entries = JSON.parse(readFileSync(join(base, lang, name), "utf8"));
      if (entries === null || typeof entries !== "object" || Array.isArray(entries)) {
        throw new Error(`locales/${lang}/${name}: expected a flat JSON object`);
      }
      for (const [key, text] of Object.entries(entries)) {
        if (!key.startsWith(`${feature}.`)) {
          throw new Error(`locales/${lang}/${name}: key ${key} must start with ${feature}.`);
        }
        if (typeof text !== "string") throw new Error(`locales/${lang}/${name}: ${key} is not a string`);
        if (owner.has(key)) throw new Error(`locales/${lang}: key ${key} is in ${owner.get(key)} and ${name}`);
        owner.set(key, name);
        catalog[key] = text;
      }
    }
    const sorted = Object.fromEntries(Object.entries(catalog).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)));
    out.set(lang, `${JSON.stringify(sorted, null, 2)}\n`);
  }
  return out;
}

/** @param {string} root */
function generateCss(root) {
  const base = join(root, "src", "styles");
  const names = listDir(base).filter((n) => n.endsWith(".css"));
  // base.css first, the rest by name.
  names.sort((a, b) => (a === "base.css" ? -1 : b === "base.css" ? 1 : a < b ? -1 : a > b ? 1 : 0));
  const parts = [];
  for (const name of names) {
    const text = readFileSync(join(base, name), "utf8");
    if (/@import/i.test(text) || /url\(\s*['"]?(?!data:)/i.test(text) || /expression\(/i.test(text)) {
      throw new Error(`styles/${name}: no @import and no url() other than data: URLs`);
    }
    parts.push(`/* ${name} */\n${text.trimEnd()}\n`);
  }
  return parts.join("\n");
}

// ------------------------------------------------------------------ checks

/** @param {string} label @param {string} html */
function checkHtml(label, html) {
  const scripts = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi)];
  if ((html.match(/<script\b/gi) ?? []).length !== scripts.length) {
    throw new Error(`${label}: unclosed <script>`);
  }
  for (const [, attrs, body] of scripts) {
    if (!/\ssrc\s*=/i.test(` ${attrs}`) || body.trim() !== "") {
      throw new Error(`${label}: inline script is not allowed`);
    }
  }
  if (/<style\b/i.test(html)) throw new Error(`${label}: <style> is not allowed`);
  if (/\sstyle\s*=/i.test(html)) throw new Error(`${label}: a style attribute is not allowed`);
  if (/\son[a-z]+\s*=/i.test(html)) throw new Error(`${label}: an event handler attribute is not allowed`);
  if (/javascript:/i.test(html)) throw new Error(`${label}: javascript: is not allowed`);
  if (/(?:src|href)\s*=\s*["']?\s*(?:https?:)?\/\//i.test(html)) {
    throw new Error(`${label}: no third-party resource is allowed`);
  }
}

/** @param {string} path @param {Buffer} bytes */
function checkFile(path, bytes) {
  if (path.endsWith(".map")) throw new Error(`${path}: source maps are not allowed`);
  const ext = path.slice(path.lastIndexOf("."));
  if (!Object.hasOwn(CONTENT_TYPES, ext)) throw new Error(`${path}: file type is not allowed`);
  if (bytes.length > MAX_FILE_BYTES && ext !== ".wasm") throw new Error(`${path}: over 4 MiB`);
  if (ext === ".html") checkHtml(path, bytes.toString("utf8"));
  if ((ext === ".mjs" || ext === ".js" || ext === ".css") && /sourceMappingURL=/.test(bytes.toString("utf8"))) {
    throw new Error(`${path}: source map reference is not allowed`);
  }
}

// ------------------------------------------------------------------- build

const WASM_FILES = [
  "js/client.mjs", "js/protocol.mjs", "js/vault.worker.mjs", "js/job.worker.mjs",
  "pkg-web/ferret_core_wasm.js", "pkg-web/ferret_core_wasm_bg.wasm",
];

/**
 * @param {{ root?: string, out?: string, wasmTar?: string, fetchImpl?: typeof fetch }} [options]
 * @returns {Promise<{ out: string, manifest: Record<string, { sha256: string, type: string }> }>}
 */
export async function build({ root = resolve(here, ".."), out, wasmTar, fetchImpl = fetch } = {}) {
  root = resolve(root);
  out = resolve(out ?? join(root, "dist"));

  // 1. The published WASM package, checked against the lock.
  const lock = JSON.parse(readFileSync(join(root, "wasm.lock.json"), "utf8"));
  if (!/^[0-9a-f]{64}$/.test(lock.sha256) || typeof lock.version !== "string" || typeof lock.url !== "string") {
    throw new Error("wasm.lock.json: expected { version, url, sha256 }");
  }
  const tarPath = wasmTar ?? process.env.FERRET_WASM_TAR;
  /** @type {Uint8Array} */
  let archive;
  if (tarPath) {
    archive = readFileSync(tarPath);
  } else {
    const response = await fetchImpl(lock.url);
    if (!response.ok) throw new Error(`wasm package: ${lock.url} answered ${response.status}`);
    archive = new Uint8Array(await response.arrayBuffer());
  }
  if (sha256(archive) !== lock.sha256) {
    throw new Error(`wasm package: checksum mismatch (expected ${lock.sha256}, got ${sha256(archive)})`);
  }
  const tar = readTarGz(archive);
  for (const name of WASM_FILES) {
    if (!tar.has(name)) throw new Error(`wasm package: ${name} is missing`);
  }

  // 2. Generated files from the feature files.
  const generated = {
    "routes.gen.mjs": await generateRoutes(root),
    "services.gen.mjs": await generateServices(root),
  };
  for (const [name, text] of Object.entries(generated)) {
    writeFileSync(join(root, "src", name), text);
  }
  const locales = generateLocales(root);
  const css = generateCss(root);

  // 3. The tree of files, then the checks, then the disk.
  /** @type {Map<string, Buffer>} */
  const dist = new Map();
  const src = join(root, "src");
  for (const path of walk(src)) {
    if (path.startsWith("locales/") || path.startsWith("styles/")) continue;
    const bytes = readFileSync(join(src, path));
    if (path === "index.html") dist.set("index.html", bytes);
    else if (path.endsWith(".mjs")) dist.set(`app/${path}`, bytes);
    else throw new Error(`src/${path}: only .mjs files and index.html live in src`);
  }
  if (!dist.has("index.html")) throw new Error("src/index.html is missing");
  for (const [lang, text] of locales) dist.set(`app/locales.${lang}.json`, Buffer.from(text));
  dist.set("assets/app.css", Buffer.from(css));
  for (const path of walk(join(root, "admin"))) dist.set(`admin/${path}`, readFileSync(join(root, "admin", path)));
  /** @type {Map<string, Buffer>} */
  const staged = new Map();
  for (const [path, bytes] of tar) {
    if (path.endsWith(".map")) throw new Error(`wasm package: ${path}: source maps are not allowed`);
    const isJs = path.startsWith("js/") && path.endsWith(".mjs") && !path.startsWith("js/vector-");
    const isPkg = path.startsWith("pkg-web/") && (path.endsWith(".js") || path.endsWith(".wasm"));
    if (isJs || isPkg) dist.set(path, bytes);
    if (isJs) staged.set(path, bytes);
  }

  /** @type {Record<string, { sha256: string, type: string }>} */
  const manifest = {};
  for (const path of [...dist.keys()].sort()) {
    const bytes = /** @type {Buffer} */ (dist.get(path));
    checkFile(path, bytes);
    const type = CONTENT_TYPES[/** @type {keyof typeof CONTENT_TYPES} */ (path.slice(path.lastIndexOf(".")))];
    manifest[path] = { sha256: sha256(bytes), type };
  }

  // The worker client is also unpacked to js/ next to src/, where the sources
  // import it from ("../js/client.mjs", as on the server) and the type check
  // reads it. The folder is not tracked.
  rmSync(join(root, "js"), { recursive: true, force: true });
  for (const [path, bytes] of staged) {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    writeFileSync(join(root, path), bytes);
  }

  copyFileSync(join(root, "types", "client.d.mts"), join(root, "js", "client.d.mts"));

  rmSync(out, { recursive: true, force: true });
  for (const [path, bytes] of dist) {
    const target = join(out, ...path.split("/"));
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, bytes);
  }
  writeFileSync(join(out, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  return { out, manifest };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  /** @type {{ wasmTar?: string, root?: string, out?: string }} */
  const options = {};
  for (let i = 0; i < args.length; i += 2) {
    const value = args[i + 1];
    if (value === undefined) { console.error(`build: ${args[i]} needs a value`); process.exit(2); }
    if (args[i] === "--wasm-tar") options.wasmTar = value;
    else if (args[i] === "--root") options.root = value;
    else if (args[i] === "--out") options.out = value;
    else { console.error(`build: unknown option ${args[i]}`); process.exit(2); }
  }
  build(options).then(
    ({ out, manifest }) => console.log(`build: ${Object.keys(manifest).length} files in ${out}`),
    (error) => { console.error(`build: ${error.message}`); process.exit(1); },
  );
}
