// The bounded ZIP reader for one named entry.
import assert from "node:assert/strict";
import { deflateRawSync } from "node:zlib";
import { test } from "node:test";
import { ImportError, MAX_FILE_BYTES, MAX_ZIP_ENTRIES } from "../../src/import/limits.mjs";
import { crc32, readZipEntry } from "../../src/import/zip.mjs";

/**
 * A ZIP file. An entry is `{ name, data, method?, flags?, crc?, size?, packed?, localName? }`: `data` is the
 * unpacked bytes, and the rest overrides what is written, to make files that lie.
 * @param {any[]} entries
 * @param {{ comment?: string, locator?: boolean, disks?: number, count?: number, truncateDirectory?: number }} [options]
 */
function zip(entries, { comment = "", locator = false, disks = 0, count, truncateDirectory = 0 } = {}) {
  const parts = [];
  const central = [];
  let offset = 0;
  for (const e of entries) {
    const data = Buffer.from(e.data);
    const method = e.method ?? 8;
    const packed = e.packed ?? (method === 8 ? deflateRawSync(data) : data);
    const name = Buffer.from(e.name);
    const localName = Buffer.from(e.localName ?? e.name);
    const crc = e.crc ?? crc32(data);
    const size = e.size ?? data.length;
    const flags = e.flags ?? 0x0800;
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(flags, 6);
    local.writeUInt16LE(e.localMethod ?? method, 8);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(packed.length, 18);
    local.writeUInt32LE(size, 22);
    local.writeUInt16LE(localName.length, 26);
    parts.push(local, localName, packed);
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
    offset += 30 + localName.length + packed.length;
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

const refusal = (code) => (error) => error instanceof ImportError && error.code === code;
const text = (bytes) => Buffer.from(bytes).toString("utf8");
const manifest = JSON.stringify({ items: [{ name: "Synthetic" }] });

test("crc32_matches_the_check_value_of_the_standard", () => {
  assert.equal(crc32(new TextEncoder().encode("123456789")), 0xcbf43926);
  assert.equal(crc32(new Uint8Array(0)), 0);
});

test("zip_reads_one_named_entry_stored_or_deflated", async () => {
  const file = zip([
    { name: "logos/a.png", data: Buffer.alloc(2000, 7) },
    { name: "manifest.json", data: manifest },
    { name: "attachments/b.bin", data: Buffer.alloc(5000, 1), method: 0 },
  ]);
  assert.equal(text(await readZipEntry(file, "manifest.json")), manifest);
  assert.equal((await readZipEntry(file, "attachments/b.bin")).length, 5000);
  const stored = zip([{ name: "data.json", data: manifest, method: 0 }]);
  assert.equal(text(await readZipEntry(stored, "data.json")), manifest);
  // An empty entry, a comment at the end, and a name with non-ASCII letters.
  assert.equal((await readZipEntry(zip([{ name: "empty", data: "" }], { comment: "a comment" }), "empty")).length, 0);
  assert.equal(text(await readZipEntry(zip([{ name: "æøå.json", data: manifest }]), "æøå.json")), manifest);
});

test("zip_refuses_a_missing_entry_and_a_name_that_is_not_exact", async () => {
  const file = zip([{ name: "dir/manifest.json", data: manifest }]);
  await assert.rejects(readZipEntry(file, "manifest.json"), refusal("import_zip_entry_missing"));
  await assert.rejects(readZipEntry(file, "Dir/manifest.json"), refusal("import_zip_entry_missing"));
  await assert.rejects(readZipEntry(zip([]), "manifest.json"), refusal("import_zip_entry_missing"));
});

test("zip_refuses_encrypted_entries", async () => {
  for (const flags of [0x0001, 0x0801, 0x0040, 0x2000]) {
    const file = zip([{ name: "manifest.json", data: manifest, flags }]);
    await assert.rejects(readZipEntry(file, "manifest.json"), refusal("import_zip_encrypted"), String(flags));
  }
  // One encrypted entry anywhere in the file is enough, also when it is not the one that is read.
  const other = zip([{ name: "manifest.json", data: manifest }, { name: "secret.bin", data: "x", flags: 0x0001 }]);
  await assert.rejects(readZipEntry(other, "manifest.json"), refusal("import_zip_encrypted"));
});

test("zip_refuses_names_that_climb_or_start_at_the_root_and_duplicates", async () => {
  for (const name of ["../evil.json", "a/../b.json", "/abs.json", "a\\b.json", "C:evil.json", "ctl\u0001.json", "..", ""]) {
    const file = zip([{ name, data: manifest }, { name: "manifest.json", data: manifest }]);
    await assert.rejects(readZipEntry(file, "manifest.json"), refusal("import_bad_zip"), JSON.stringify(name));
  }
  // `..` as a part of a name that is only a lookalike is fine.
  assert.equal(text(await readZipEntry(zip([{ name: "a..b/manifest.json", data: manifest }]), "a..b/manifest.json")), manifest);
  const duplicate = zip([{ name: "manifest.json", data: manifest }, { name: "manifest.json", data: "{}" }]);
  await assert.rejects(readZipEntry(duplicate, "manifest.json"), refusal("import_bad_zip"));
});

test("zip_refuses_a_bomb_and_an_entry_that_lies_about_its_size", async () => {
  // 3 MiB of zeros packs to a few KiB: far above the ratio.
  const bomb = zip([{ name: "manifest.json", data: Buffer.alloc(3 * 1024 * 1024) }]);
  await assert.rejects(readZipEntry(bomb, "manifest.json"), refusal("import_bad_zip"));
  // The same entry is fine when the ratio is allowed.
  assert.equal((await readZipEntry(bomb, "manifest.json", { maxRatio: 100_000 })).length, 3 * 1024 * 1024);
  // Larger than the bound the caller sets: refused by the size in the directory, before anything is unpacked.
  await assert.rejects(readZipEntry(zip([{ name: "manifest.json", data: Buffer.alloc(5000, 1) }]), "manifest.json", { maxBytes: 4999 }), refusal("import_too_large"));
  // A directory that says 10 bytes while the stream holds 5000: stopped as soon as it passes 10.
  const liar = zip([{ name: "manifest.json", data: Buffer.alloc(5000, 1), size: 10 }]);
  await assert.rejects(readZipEntry(liar, "manifest.json"), refusal("import_bad_zip"));
  // A directory that says more than the stream holds.
  const short = zip([{ name: "manifest.json", data: "tiny", size: 9999 }]);
  await assert.rejects(readZipEntry(short, "manifest.json"), refusal("import_bad_zip"));
  // A stored entry whose two sizes differ.
  const stored = zip([{ name: "manifest.json", data: "tiny", method: 0, size: 3 }]);
  await assert.rejects(readZipEntry(stored, "manifest.json"), refusal("import_bad_zip"));
  // A declared size over the file bound is refused without any allocation.
  await assert.rejects(readZipEntry(zip([{ name: "manifest.json", data: "x", size: MAX_FILE_BYTES + 1 }]), "manifest.json"), refusal("import_too_large"));
});

test("zip_refuses_a_wrong_checksum_a_damaged_stream_and_a_method_it_does_not_know", async () => {
  await assert.rejects(readZipEntry(zip([{ name: "manifest.json", data: manifest, crc: 1 }]), "manifest.json"), refusal("import_bad_zip"));
  await assert.rejects(readZipEntry(zip([{ name: "manifest.json", data: manifest, packed: Buffer.from("not a deflate stream at all, no") }]), "manifest.json"), refusal("import_bad_zip"));
  await assert.rejects(readZipEntry(zip([{ name: "manifest.json", data: manifest, method: 12, packed: Buffer.from(manifest) }]), "manifest.json"), refusal("import_bad_zip"));
  // The local header disagrees with the directory.
  await assert.rejects(readZipEntry(zip([{ name: "manifest.json", data: manifest, localName: "other.json" }]), "manifest.json"), refusal("import_bad_zip"));
  await assert.rejects(readZipEntry(zip([{ name: "manifest.json", data: manifest, localMethod: 0 }]), "manifest.json"), refusal("import_bad_zip"));
});

test("zip_refuses_a_file_that_is_not_one_it_reads", async () => {
  const good = zip([{ name: "manifest.json", data: manifest }]);
  const bytes = Buffer.from(await good.arrayBuffer());
  // Not a ZIP file, too short, cut off, and with its directory cut.
  await assert.rejects(readZipEntry(new File(["hello"], "x"), "manifest.json"), refusal("import_bad_zip"));
  await assert.rejects(readZipEntry(new File([new Uint8Array(0)], "x"), "manifest.json"), refusal("import_bad_zip"));
  await assert.rejects(readZipEntry(new File([bytes.subarray(0, bytes.length - 5)], "x"), "manifest.json"), refusal("import_bad_zip"));
  await assert.rejects(readZipEntry(new File([bytes.subarray(30)], "x"), "manifest.json"), refusal("import_bad_zip"));
  await assert.rejects(readZipEntry(zip([{ name: "manifest.json", data: manifest }], { truncateDirectory: 3 }), "manifest.json"), refusal("import_bad_zip"));
  // ZIP64, several disks, and a count that is not the number of entries.
  await assert.rejects(readZipEntry(zip([{ name: "manifest.json", data: manifest }], { locator: true }), "manifest.json"), refusal("import_bad_zip"));
  await assert.rejects(readZipEntry(zip([{ name: "manifest.json", data: manifest }], { disks: 1 }), "manifest.json"), refusal("import_bad_zip"));
  await assert.rejects(readZipEntry(zip([{ name: "manifest.json", data: manifest }], { count: 2 }), "manifest.json"), refusal("import_bad_zip"));
  await assert.rejects(readZipEntry(zip([{ name: "manifest.json", data: manifest }], { count: 0xffff }), "manifest.json"), refusal("import_bad_zip"));
  // More entries than the reader allows.
  const many = zip(Array.from({ length: MAX_ZIP_ENTRIES + 1 }, (_, i) => ({ name: `f${i}`, data: "", method: 0 })));
  await assert.rejects(readZipEntry(many, "f1"), refusal("import_too_many"));
  assert.equal((await readZipEntry(zip(Array.from({ length: MAX_ZIP_ENTRIES }, (_, i) => ({ name: `f${i}`, data: "x", method: 0 }))), "f9")).length, 1);
  // A file over the bound is refused for its size alone.
  const big = new File(["x"], "big.zip");
  Object.defineProperty(big, "size", { value: MAX_FILE_BYTES + 1 });
  big.slice = () => {
    throw new Error("read");
  };
  await assert.rejects(readZipEntry(big, "manifest.json"), refusal("import_too_large"));
});
