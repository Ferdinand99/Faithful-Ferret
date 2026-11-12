// Helpers for the build tests: a tar.gz writer and a throwaway copy of the
// extension's build inputs with a fake WASM package, so no test needs the
// network. Not a test file (the runner picks up *.test.mjs only).
import { cpSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";
import { sha256, WASM_FILES } from "../../scripts/build.mjs";

/** The real extension folder. */
export const extensionRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
/** The repository root. */
export const repoRoot = resolve(extensionRoot, "..");

/** @param {number} n @param {number} width */
const octal = (n, width) => `${n.toString(8).padStart(width - 1, "0")}\0`;

/**
 * A .tar.gz with one top-level folder, as the release archive has.
 * @param {Record<string, string | Buffer>} files path inside the folder -> bytes
 * @returns {Buffer}
 */
export function makeTar(files) {
  /** @type {Buffer[]} */
  const blocks = [];
  for (const [path, content] of Object.entries(files)) {
    const body = Buffer.from(content);
    const header = Buffer.alloc(512);
    header.write(`pkg/${path}`, 0, "utf8");
    header.write(octal(0o644, 8), 100);
    header.write(octal(0, 8), 108);
    header.write(octal(0, 8), 116);
    header.write(octal(body.length, 12), 124);
    header.write(octal(0, 12), 136);
    header.write("        ", 148);
    header.write("0", 156);
    header.write("ustar\0", 257);
    header.write("00", 263);
    let sum = 0;
    for (const b of header) sum += b;
    header.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148);
    blocks.push(header, body, Buffer.alloc((512 - (body.length % 512)) % 512));
  }
  blocks.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(blocks));
}

/** The files of a fake WASM package. @returns {Record<string, string>} */
export function wasmFiles() {
  return Object.fromEntries(WASM_FILES.map((p) => [p, `// fake ${p}\n`]));
}

/**
 * A copy of the build inputs under a fresh temp folder, with a fake web/wasm.lock.json
 * and the matching archive. Remember to call `cleanup()`.
 * @param {Record<string, string | null>} [extra] path below extension/ -> text (null removes the file)
 * @returns {{ root: string, webRoot: string, out: string, tarPath: string, dir: string, cleanup: () => void }}
 */
export function makeRoot(extra = {}) {
  const dir = mkdtempSync(join(tmpdir(), "ferret-ext-"));
  const root = join(dir, "extension");
  const webRoot = join(dir, "web");
  mkdirSync(webRoot, { recursive: true });
  for (const name of ["manifest", "src", "shared.json", "package.json"]) {
    cpSync(join(extensionRoot, name), join(root, name), { recursive: true });
  }
  // The shared files come from the real web/src (the pages import them), so the copy is byte-equal to its source.
  cpSync(join(repoRoot, "web", "src"), join(webRoot, "src"), { recursive: true });
  // The release check needs the list of internal host names.
  mkdirSync(join(root, "test", "fixtures"), { recursive: true });
  cpSync(join(extensionRoot, "test", "fixtures", "hosts.json"), join(root, "test", "fixtures", "hosts.json"));
  for (const [path, text] of Object.entries(extra)) {
    const file = join(root, ...path.split("/"));
    if (text === null) {
      rmSync(file, { force: true });
    } else {
      mkdirSync(dirname(file), { recursive: true });
      writeFileSync(file, text);
    }
  }
  const tar = makeTar(wasmFiles());
  const tarPath = join(dir, "wasm.tar.gz");
  writeFileSync(tarPath, tar);
  writeFileSync(
    join(webRoot, "wasm.lock.json"),
    `${JSON.stringify({ version: "0.0.0", url: "https://example.invalid/wasm.tar.gz", sha256: sha256(tar) })}\n`,
  );
  return { root, webRoot, out: join(dir, "out"), tarPath, dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}
