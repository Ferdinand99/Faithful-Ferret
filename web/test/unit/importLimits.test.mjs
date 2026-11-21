// The bounds of an import, the one kind of error, and the first check of a file: its size.
import assert from "node:assert/strict";
import { test } from "node:test";
import { IMPORT_ERROR_TEXT, ImportError, MAX_COLUMNS, MAX_DEPTH, MAX_FIELD_BYTES, MAX_FILE_BYTES, MAX_ITEMS, MAX_NODES, MAX_ZIP_ENTRIES, MAX_ZIP_RATIO, overFieldBound } from "../../src/import/limits.mjs";
import { runImport } from "../../src/workers/import.worker.mjs";
import { vaultPort } from "./importHelpers.mjs";

test("the_bounds_are_the_ones_of_the_design", () => {
  assert.equal(MAX_FILE_BYTES, 50 * 1024 * 1024);
  assert.equal(MAX_ITEMS, 10_000);
  assert.equal(MAX_FIELD_BYTES, 64 * 1024);
  assert.equal(MAX_DEPTH, 16);
  assert.ok(MAX_NODES >= MAX_ITEMS * 50, "a real export (about 45 values an item) is below the bound on values");
  assert.ok(MAX_NODES <= MAX_ITEMS * 100, "the bound on values keeps the memory of a worker down");
  assert.ok(MAX_COLUMNS >= 16 && MAX_ZIP_ENTRIES >= 100 && MAX_ZIP_RATIO >= 10);
});

test("an_import_error_has_a_code_and_a_fixed_text_that_holds_nothing_of_the_file", () => {
  for (const [code, text] of Object.entries(IMPORT_ERROR_TEXT)) {
    const error = new ImportError(/** @type {any} */ (code));
    assert.equal(error.code, code);
    assert.equal(error.message, text);
    assert.equal(error.name, "ImportError");
    assert.ok(error instanceof Error);
    assert.ok(text.length > 10 && text.endsWith("."), code);
  }
  assert.equal(new ImportError("import_bad_csv", { line: 12 }).line, 12);
  assert.equal(new ImportError("import_bad_csv", { line: -1.5 }).line, undefined);
  assert.equal(new ImportError("import_seal_failed", { reason: "too_large" }).reason, "too_large");
  // A reason is a code of the vault, never a text that could hold something of the file.
  assert.equal(new ImportError("import_seal_failed", { reason: "Alice's password is hunter2" }).reason, undefined);
  assert.ok(Object.isFrozen(IMPORT_ERROR_TEXT));
});

test("over_field_bound_counts_utf8_bytes_near_the_bound_only", () => {
  assert.equal(overFieldBound("a".repeat(MAX_FIELD_BYTES)), false);
  assert.equal(overFieldBound("a".repeat(MAX_FIELD_BYTES + 1)), true);
  // Two bytes each: 32 769 of them are over, 32 768 are exactly the bound.
  assert.equal(overFieldBound("é".repeat(MAX_FIELD_BYTES / 2)), false);
  assert.equal(overFieldBound("é".repeat(MAX_FIELD_BYTES / 2 + 1)), true);
  assert.equal(overFieldBound(""), false);
});

test("files_over_50_mib_are_refused_before_reading_further", async () => {
  let touched = 0;
  const trap = () => {
    touched++;
    throw new Error("the file was read");
  };
  // A file whose size is over the bound, and whose every reader is a trap.
  const file = /** @type {any} */ (new File(["x"], "big.json"));
  Object.defineProperty(file, "size", { value: MAX_FILE_BYTES + 1 });
  file.slice = trap;
  file.text = trap;
  file.arrayBuffer = trap;
  file.stream = trap;
  for (const kind of ["bitwarden_json", "bitwarden_csv"]) {
    const port = vaultPort();
    await assert.rejects(runImport({ id: 1, kind, file, port }), (error) => error instanceof ImportError && error.code === "import_too_large");
    assert.equal(port.sent.length, 0);
  }
  assert.equal(touched, 0);

  // Exactly at the bound is not refused for its size.
  const edge = /** @type {any} */ (new File(["{}"], "edge.json"));
  Object.defineProperty(edge, "size", { value: MAX_FILE_BYTES });
  edge.slice = () => new Blob(["{}"]);
  edge.text = async () => "{}";
  await assert.rejects(runImport({ id: 2, kind: "bitwarden_json", file: edge, port: vaultPort() }), (error) => error instanceof ImportError && error.code === "import_bad_format");
});
