// A ZIP file builder for the import tests: also writes files that lie, to test the bounded reader.
import { deflateRawSync } from "node:zlib";
import { crc32 } from "../../src/import/zip.mjs";

/**
 * A ZIP file. An entry is `{ name, data, method?, flags?, crc?, size?, packed?, localName?, nameBytes?, descriptor? }`: `data` is the
 * unpacked bytes, and the rest overrides what is written, to make files that lie. `nameBytes` are the bytes
 * of the name, as written; `descriptor` writes the entry as a streaming tool does: bit 3 set, no size
 * or checksum in the local header, and a data descriptor after the data.
 * @param {any[]} entries
 * @param {{ comment?: string, locator?: boolean, disks?: number, count?: number, truncateDirectory?: number }} [options]
 */
export function zip(entries, { comment = "", locator = false, disks = 0, count, truncateDirectory = 0 } = {}) {
  const parts = [];
  const central = [];
  let offset = 0;
  for (const e of entries) {
    const data = Buffer.from(e.data);
    const method = e.method ?? 8;
    const packed = e.packed ?? (method === 8 ? deflateRawSync(data) : data);
    const name = Buffer.from(e.nameBytes ?? e.name);
    const localName = Buffer.from(e.nameBytes ?? e.localName ?? e.name);
    const crc = e.crc ?? crc32(data);
    const size = e.size ?? data.length;
    const flags = (e.flags ?? 0x0800) | (e.descriptor ? 0x0008 : 0);
    const descriptor = e.descriptor ? Buffer.alloc(16) : Buffer.alloc(0);
    if (e.descriptor) {
      descriptor.writeUInt32LE(0x08074b50, 0);
      descriptor.writeUInt32LE(crc, 4);
      descriptor.writeUInt32LE(packed.length, 8);
      descriptor.writeUInt32LE(size, 12);
    }
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(flags, 6);
    local.writeUInt16LE(e.localMethod ?? method, 8);
    if (!e.descriptor) {
      local.writeUInt32LE(crc, 14);
      local.writeUInt32LE(packed.length, 18);
      local.writeUInt32LE(size, 22);
    }
    local.writeUInt16LE(localName.length, 26);
    parts.push(local, localName, packed, descriptor);
    const c = Buffer.alloc(46);
    c.writeUInt32LE(0x02014b50, 0);
    c.writeUInt16LE(20, 4);
    c.writeUInt16LE(20, 6);
    c.writeUInt16LE(flags, 8);
    c.writeUInt16LE(method, 10);
    c.writeUInt32LE(crc, 16);
    c.writeUInt32LE(packed.length, 20);
    c.writeUInt32LE(size, 24);
    c.writeUInt16LE(name.length, 28);
    c.writeUInt32LE(offset, 42);
    central.push(c, name);
    offset += 30 + localName.length + packed.length + descriptor.length;
  }
  let directory = Buffer.concat(central);
  if (truncateDirectory) directory = directory.subarray(0, directory.length - truncateDirectory);
  const tail = Buffer.alloc(22);
  tail.writeUInt32LE(0x06054b50, 0);
  tail.writeUInt16LE(disks, 4);
  tail.writeUInt16LE(0, 6);
  tail.writeUInt16LE(count ?? entries.length, 8);
  tail.writeUInt16LE(count ?? entries.length, 10);
  tail.writeUInt32LE(directory.length, 12);
  tail.writeUInt32LE(offset, 16);
  tail.writeUInt16LE(Buffer.byteLength(comment), 20);
  const locatorBytes = locator ? Buffer.concat([Buffer.from([0x50, 0x4b, 0x06, 0x07]), Buffer.alloc(16)]) : Buffer.alloc(0);
  return new File([Buffer.concat([...parts, directory, locatorBytes, tail, Buffer.from(comment)])], "export.zip");
}
