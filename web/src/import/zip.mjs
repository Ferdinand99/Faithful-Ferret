// A bounded reader for one named entry of a ZIP file.
//
// Some exports are a ZIP file with the data in one entry (a `manifest.json` or a `data.json`) next to
// attachments and pictures. This reader takes that one entry and nothing else, with no library: the
// central directory is read from the end of the file, the entry is found by its exact name, and it
// is unpacked with the browser's `DecompressionStream("deflate-raw")`.
//
// Bounds: the file is at most `MAX_FILE_BYTES`; the central directory holds at most `MAX_ZIP_ENTRIES`
// entries; the entry is at most `MAX_FILE_BYTES` unpacked, may not grow more than `MAX_ZIP_RATIO` times
// (a zip bomb), and may not unpack to more or fewer bytes than the directory says. Refused: an
// encrypted entry (any entry), a file in several parts, ZIP64, a method other than stored and
// deflate, a name with a `..` part, a leading `/`, a backslash or a control character, two entries
// with the same name, a local header that does not agree with the directory, and a checksum that is
// wrong. Nothing about the file is put in an error but its code.

import { ImportError, MAX_FILE_BYTES, MAX_ZIP_ENTRIES, MAX_ZIP_RATIO } from "./limits.mjs";

const EOCD = 0x06054b50;
const EOCD64_LOCATOR = 0x07064b50;
const CENTRAL = 0x02014b50;
const LOCAL = 0x04034b50;
/** The end record, without its comment. */
const EOCD_SIZE = 22;
/** The longest comment a ZIP file can have. */
const MAX_COMMENT = 0xffff;
/** The largest central directory that is read. */
const MAX_DIRECTORY_BYTES = 8 * 1024 * 1024;
/** An entry this small is not checked for its ratio: it cannot hurt. */
const RATIO_FLOOR = 1024 * 1024;

const bad = () => new ImportError("import_bad_zip");

/** The table of the CRC-32 of ZIP (the reflected polynomial 0xEDB88320). */
const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

/**
 * The CRC-32 of bytes.
 * @param {Uint8Array} bytes
 */
export function crc32(bytes) {
  let c = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) c = CRC_TABLE[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

/**
 * @typedef {{ name: string, method: number, crc: number, compressed: number, size: number, offset: number }} ZipEntry
 */

/**
 * Whether an entry name is safe: no `..` part, no leading `/`, no backslash, no drive letter, no control character.
 * @param {string} name
 */
function safeName(name) {
  if (name === "" || name.startsWith("/") || name.includes("\\") || /[\u0000-\u001f\u007f]/.test(name)) return false;
  if (/^[A-Za-z]:/.test(name)) return false;
  return !name.split("/").some((part) => part === "..");
}

/**
 * Reads the central directory of a ZIP file.
 * @param {Blob} blob
 * @returns {Promise<{ entries: ZipEntry[], directoryStart: number }>}
 */
async function readDirectory(blob) {
  const size = blob.size;
  if (size < EOCD_SIZE) throw bad();
  const tailStart = Math.max(0, size - (EOCD_SIZE + MAX_COMMENT));
  const tail = new DataView(await blob.slice(tailStart, size).arrayBuffer());
  let at = -1;
  for (let i = tail.byteLength - EOCD_SIZE; i >= 0; i--) {
    if (tail.getUint32(i, true) === EOCD && i + EOCD_SIZE + tail.getUint16(i + 20, true) === tail.byteLength) {
      at = i;
      break;
    }
  }
  if (at < 0) throw bad();
  // ZIP64 (a locator just before the end record) and anything split over several disks.
  if (at >= 20 && tail.getUint32(at - 20, true) === EOCD64_LOCATOR) throw bad();
  const disk = tail.getUint16(at + 4, true);
  const directoryDisk = tail.getUint16(at + 6, true);
  const onThisDisk = tail.getUint16(at + 8, true);
  const total = tail.getUint16(at + 10, true);
  const directorySize = tail.getUint32(at + 12, true);
  const directoryStart = tail.getUint32(at + 16, true);
  if (disk !== 0 || directoryDisk !== 0 || onThisDisk !== total) throw bad();
  if (total === 0xffff || directorySize === 0xffffffff || directoryStart === 0xffffffff) throw bad();
  if (total > MAX_ZIP_ENTRIES) throw new ImportError("import_too_many");
  if (directorySize > MAX_DIRECTORY_BYTES) throw bad();
  const endOfDirectory = tailStart + at;
  if (directoryStart + directorySize !== endOfDirectory) throw bad();

  const dir = new DataView(await blob.slice(directoryStart, endOfDirectory).arrayBuffer());
  const bytes = new Uint8Array(dir.buffer);
  const names = new Set();
  /** @type {ZipEntry[]} */
  const entries = [];
  let p = 0;
  for (let n = 0; n < total; n++) {
    if (p + 46 > dir.byteLength || dir.getUint32(p, true) !== CENTRAL) throw bad();
    const flags = dir.getUint16(p + 8, true);
    const method = dir.getUint16(p + 10, true);
    const crc = dir.getUint32(p + 16, true);
    const compressed = dir.getUint32(p + 20, true);
    const unpacked = dir.getUint32(p + 24, true);
    const nameLength = dir.getUint16(p + 28, true);
    const extraLength = dir.getUint16(p + 30, true);
    const commentLength = dir.getUint16(p + 32, true);
    const diskStart = dir.getUint16(p + 34, true);
    const offset = dir.getUint32(p + 42, true);
    const next = p + 46 + nameLength + extraLength + commentLength;
    if (next > dir.byteLength) throw bad();
    // Bit 0 (encrypted), bit 6 (strong encryption), bit 13 (the directory is masked).
    if (flags & 0x2041) throw new ImportError("import_zip_encrypted");
    if (diskStart !== 0) throw bad();
    if (compressed === 0xffffffff || unpacked === 0xffffffff || offset === 0xffffffff) throw bad();
    let name;
    try {
      name = new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(p + 46, p + 46 + nameLength));
    } catch {
      throw bad();
    }
    if (!safeName(name) || names.has(name)) throw bad();
    names.add(name);
    entries.push({ name, method, crc, compressed, size: unpacked, offset });
    p = next;
  }
  if (p !== dir.byteLength) throw bad();
  return { entries, directoryStart };
}

/**
 * Unpacks a deflate stream into exactly `size` bytes.
 * @param {Blob} packed
 * @param {number} size
 * @returns {Promise<Uint8Array>}
 */
async function inflate(packed, size) {
  const out = new Uint8Array(size);
  let filled = 0;
  const reader = packed.stream().pipeThrough(new DecompressionStream("deflate-raw")).getReader();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (filled + value.length > size) throw bad();
      out.set(value, filled);
      filled += value.length;
    }
  } catch (error) {
    await reader.cancel().catch(() => {});
    throw error instanceof ImportError ? error : bad();
  }
  if (filled !== size) throw bad();
  return out;
}

/**
 * The bytes of one entry of a ZIP file.
 * @param {Blob} blob the ZIP file (a `File`)
 * @param {string} entryName the exact name of the entry (for example `manifest.json`)
 * @param {{ maxBytes?: number, maxRatio?: number }} [options]
 * @returns {Promise<Uint8Array>}
 * @throws {ImportError} `import_too_large`, `import_too_many`, `import_bad_zip`, `import_zip_encrypted`, `import_zip_entry_missing`
 */
export async function readZipEntry(blob, entryName, { maxBytes = MAX_FILE_BYTES, maxRatio = MAX_ZIP_RATIO } = {}) {
  if (blob.size > MAX_FILE_BYTES) throw new ImportError("import_too_large");
  const { entries, directoryStart } = await readDirectory(blob);
  const entry = entries.find((e) => e.name === entryName);
  if (!entry) throw new ImportError("import_zip_entry_missing");
  if (entry.method !== 0 && entry.method !== 8) throw bad();
  if (entry.size > maxBytes) throw new ImportError("import_too_large");
  if (entry.method === 0 && entry.compressed !== entry.size) throw bad();
  if (entry.method === 8 && entry.size > RATIO_FLOOR && entry.size > entry.compressed * maxRatio) throw bad();

  if (entry.offset + 30 > directoryStart) throw bad();
  const local = new DataView(await blob.slice(entry.offset, entry.offset + 30).arrayBuffer());
  if (local.byteLength < 30 || local.getUint32(0, true) !== LOCAL) throw bad();
  if (local.getUint16(6, true) & 0x2041) throw new ImportError("import_zip_encrypted");
  if (local.getUint16(8, true) !== entry.method) throw bad();
  const nameLength = local.getUint16(26, true);
  const extraLength = local.getUint16(28, true);
  const nameBytes = new Uint8Array(await blob.slice(entry.offset + 30, entry.offset + 30 + nameLength).arrayBuffer());
  if (new TextDecoder("utf-8").decode(nameBytes) !== entry.name) throw bad();
  const start = entry.offset + 30 + nameLength + extraLength;
  const end = start + entry.compressed;
  if (end > directoryStart) throw bad();

  const packed = blob.slice(start, end);
  const bytes = entry.method === 0 ? new Uint8Array(await packed.arrayBuffer()) : await inflate(packed, entry.size);
  if (bytes.length !== entry.size || crc32(bytes) !== entry.crc) throw bad();
  return bytes;
}
