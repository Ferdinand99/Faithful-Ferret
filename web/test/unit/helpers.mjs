// Shared test helpers: a very small DOM, a tar.gz writer and a throwaway web/
// tree for the build tests. No dependency.
import { createHash } from "node:crypto";
import { cpSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";

export const web = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

// ------------------------------------------------------------------- DOM

export class FakeNode {
  constructor(nodeType) {
    this.nodeType = nodeType;
    this.childNodes = [];
    this.parentNode = null;
  }
  get firstChild() {
    return this.childNodes[0] ?? null;
  }
  appendChild(child) {
    child.parentNode = this;
    this.childNodes.push(child);
    return child;
  }
  removeChild(child) {
    this.childNodes = this.childNodes.filter((c) => c !== child);
    child.parentNode = null;
    return child;
  }
}

export class FakeText extends FakeNode {
  constructor(data) {
    super(3);
    this.data = data;
  }
}

export class FakeElement extends FakeNode {
  constructor(tagName) {
    super(1);
    this.tagName = tagName;
    this.attributes = new Map();
    this.listeners = [];
    this.clicked = false;
  }
  setAttribute(name, value) {
    this.attributes.set(name, String(value));
  }
  getAttribute(name) {
    return this.attributes.get(name) ?? null;
  }
  addEventListener(type, fn) {
    this.listeners.push([type, fn]);
  }
  click() {
    this.clicked = true;
  }
  remove() {
    this.parentNode?.removeChild(this);
  }
  set innerHTML(_) {
    throw new Error("innerHTML was used");
  }
  set outerHTML(_) {
    throw new Error("outerHTML was used");
  }
}

export function fakeDocument() {
  const body = new FakeElement("body");
  const document = {
    body,
    created: [],
    createElement(tag) {
      const node = new FakeElement(tag);
      document.created.push(node);
      return node;
    },
    createTextNode: (data) => new FakeText(data),
  };
  return document;
}

/** Runs `fn` with a fake `document` as the global one. */
export function withDocument(fn) {
  const saved = globalThis.document;
  const document = fakeDocument();
  globalThis.document = document;
  try {
    return fn(document);
  } finally {
    if (saved === undefined) delete globalThis.document;
    else globalThis.document = saved;
  }
}

// ------------------------------------------------------------------- tar

/** One ustar header and padded body. */
function entry(name, body, type = "0") {
  const header = Buffer.alloc(512);
  header.write(name, 0, 100, "utf8");
  header.write("0000644\0", 100);
  header.write("0000000\0", 108);
  header.write("0000000\0", 116);
  header.write(`${body.length.toString(8).padStart(11, "0")}\0`, 124);
  header.write("00000000000\0", 136);
  header.write("        ", 148);
  header.write(type, 156);
  header.write("ustar\0", 257);
  header.write("00", 263);
  let sum = 0;
  for (const b of header) sum += b;
  header.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148);
  const padding = Buffer.alloc((512 - (body.length % 512)) % 512);
  return Buffer.concat([header, body, padding]);
}

/**
 * A .tar.gz of `files` (path -> string | Buffer) under one top-level folder.
 * @param {Record<string, string | Buffer>} files
 * @param {{ top?: string, extra?: [string, string, string][] }} [options] extra: [name, body, type]
 */
export function makeTar(files, { top = "ferret-core-wasm-web-9.9.9", extra = [] } = {}) {
  const parts = [];
  for (const [path, body] of Object.entries(files)) {
    parts.push(entry(`${top}/${path}`, Buffer.from(body)));
  }
  for (const [name, body, type] of extra) parts.push(entry(name, Buffer.from(body), type));
  parts.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(parts));
}

export const sha256 = (data) => createHash("sha256").update(data).digest("hex");

/** The files a WASM package must have for the build to accept it. */
export function wasmFiles() {
  return {
    "js/client.mjs": "export const client = 1;\n",
    "js/protocol.mjs": "export const protocol = 1;\n",
    "js/vault.worker.mjs": "export const vault = 1;\n",
    "js/job.worker.mjs": "export const job = 1;\n",
    "js/vector-runner.mjs": "export const vectors = 1;\n",
    "js/helper.mjs": "export const helper = 1;\n",
    "pkg-web/ferret_core_wasm.js": "export default 1;\n",
    "pkg-web/ferret_core_wasm_bg.wasm": Buffer.from([0, 0x61, 0x73, 0x6d, 1, 0, 0, 0]),
    "pkg-web/ferret_core_wasm.d.ts": "export {};\n",
    "pkg-web/package.json": "{}\n",
    LICENSE: "text\n",
  };
}

// ----------------------------------------------------------- throwaway root

/**
 * A copy of the real web/ sources in a temp folder, with a lock for a tar made
 * from `makeTar(wasmFiles())`. `extra` adds files (path -> text) to the copy.
 * @param {Record<string, string>} [extra]
 */
export function makeRoot(extra = {}) {
  const root = mkdtempSync(join(tmpdir(), "ferret-web-"));
  cpSync(join(web, "src"), join(root, "src"), {
    recursive: true,
    filter: (path) => !path.endsWith(".gen.mjs"),
  });
  cpSync(join(web, "types"), join(root, "types"), { recursive: true });
  const tar = makeTar(wasmFiles());
  const tarPath = join(root, "wasm.tar.gz");
  writeFileSync(tarPath, tar);
  writeFileSync(
    join(root, "wasm.lock.json"),
    JSON.stringify({ version: "9.9.9", url: "https://example.invalid/x.tar.gz", sha256: sha256(tar) }),
  );
  for (const [path, text] of Object.entries(extra)) {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    writeFileSync(join(root, path), text);
  }
  return { root, tarPath, out: join(root, "dist") };
}
