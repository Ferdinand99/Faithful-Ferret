// Archives for the build: a strict .tar.gz reader (the published WASM package)
// and a deterministic .zip writer and reader (the .xpi). No dependency.
import { createHash } from "node:crypto";
import { gunzipSync, inflateRawSync } from "node:zlib";

/** @param {Uint8Array | string} data @returns {string} lower-case hex SHA-256 */
export const sha256 = (data) => createHash("sha256").update(data).digest("hex");

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
  /** @type {string | null} */
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

// -------------------------------------------------------------------- zip

/** @type {Uint32Array} */
const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

/** @param {Uint8Array} bytes @returns {number} */
export function crc32(bytes) {
  let c = 0xffffffff;
  for (const b of bytes) c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

// 1980-01-01 00:00:00 in DOS date and time, the earliest time a zip can hold.
const DOS_TIME = 0;
const DOS_DATE = (0 << 9) | (1 << 5) | 1;
// Regular file, mode 0644, made on Unix.
const EXTERNAL_ATTRIBUTES = (0o100644 << 16) >>> 0;
const MADE_BY = (3 << 8) | 20;
const UTF8_FLAG = 0x0800;

/**
 * Packs files into a deterministic zip: names sorted in code unit order,
 * entries stored (no compression, so no dependency on the zlib version), a
 * fixed time, fixed permissions, no extra fields and no folder entries.
 * @param {Map<string, Uint8Array>} files path -> bytes
 * @returns {Buffer}
 */
export function packZip(files) {
  const names = [...files.keys()].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  /** @type {Buffer[]} */
  const parts = [];
  /** @type {Buffer[]} */
  const central = [];
  let offset = 0;
  for (const name of names) {
    const data = /** @type {Uint8Array} */ (files.get(name));
    const nameBytes = Buffer.from(name, "utf8");
    const crc = crc32(data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(UTF8_FLAG, 6);
    local.writeUInt16LE(0, 8);
    local.writeUInt16LE(DOS_TIME, 10);
    local.writeUInt16LE(DOS_DATE, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBytes.length, 26);
    local.writeUInt16LE(0, 28);
    parts.push(local, nameBytes, Buffer.from(data));
    const entry = Buffer.alloc(46);
    entry.writeUInt32LE(0x02014b50, 0);
    entry.writeUInt16LE(MADE_BY, 4);
    entry.writeUInt16LE(20, 6);
    entry.writeUInt16LE(UTF8_FLAG, 8);
    entry.writeUInt16LE(0, 10);
    entry.writeUInt16LE(DOS_TIME, 12);
    entry.writeUInt16LE(DOS_DATE, 14);
    entry.writeUInt32LE(crc, 16);
    entry.writeUInt32LE(data.length, 20);
    entry.writeUInt32LE(data.length, 24);
    entry.writeUInt16LE(nameBytes.length, 28);
    entry.writeUInt32LE(EXTERNAL_ATTRIBUTES, 38);
    entry.writeUInt32LE(offset, 42);
    central.push(entry, nameBytes);
    offset += 30 + nameBytes.length + data.length;
  }
  const directory = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(names.length, 8);
  end.writeUInt16LE(names.length, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...parts, directory, end]);
}

/**
 * Reads a zip (stored or deflated entries, no zip64) into path -> bytes and
 * checks every CRC. Used to inspect the .xpi the build made.
 * @param {Uint8Array} zip
 * @returns {Map<string, Buffer>}
 */
export function readZip(zip) {
  const buf = Buffer.from(zip.buffer, zip.byteOffset, zip.byteLength);
  let end = -1;
  for (let i = buf.length - 22; i >= 0 && i >= buf.length - 22 - 0xffff; i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { end = i; break; }
  }
  if (end < 0) throw new Error("zip: no end of central directory");
  const count = buf.readUInt16LE(end + 10);
  let cursor = buf.readUInt32LE(end + 16);
  /** @type {Map<string, Buffer>} */
  const files = new Map();
  for (let n = 0; n < count; n++) {
    if (buf.readUInt32LE(cursor) !== 0x02014b50) throw new Error("zip: bad central directory entry");
    const method = buf.readUInt16LE(cursor + 10);
    const crc = buf.readUInt32LE(cursor + 16);
    const compressed = buf.readUInt32LE(cursor + 20);
    const nameLength = buf.readUInt16LE(cursor + 28);
    const extraLength = buf.readUInt16LE(cursor + 30);
    const commentLength = buf.readUInt16LE(cursor + 32);
    const localOffset = buf.readUInt32LE(cursor + 42);
    const name = buf.toString("utf8", cursor + 46, cursor + 46 + nameLength);
    cursor += 46 + nameLength + extraLength + commentLength;
    if (buf.readUInt32LE(localOffset) !== 0x04034b50) throw new Error(`zip: bad local header for ${name}`);
    const dataStart = localOffset + 30 + buf.readUInt16LE(localOffset + 26) + buf.readUInt16LE(localOffset + 28);
    const raw = buf.subarray(dataStart, dataStart + compressed);
    let data;
    if (method === 0) data = Buffer.from(raw);
    else if (method === 8) data = inflateRawSync(raw);
    else throw new Error(`zip: compression method ${method} is not supported (${name})`);
    if (crc32(data) !== crc) throw new Error(`zip: bad CRC for ${name}`);
    files.set(name, data);
  }
  return files;
}
