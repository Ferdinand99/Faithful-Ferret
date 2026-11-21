// The bounds of an import and the one kind of error the import code throws.
//
// An import file comes from outside and is read in a worker before anything of it is stored.
// Every reader of this folder holds these bounds, so a hostile file ends in an `ImportError`
// and never in a hung or crashed worker. The numbers are Spec: Fase 1 § 5.2 and § 8.2 sized
// for one person's vault: they are far above a real export and far below what hurts.

/** The largest file the import reads, in bytes (50 MiB). */
export const MAX_FILE_BYTES = 50 * 1024 * 1024;
/** The most items in one file, and the most elements of any one array or members of any one object. */
export const MAX_ITEMS = 10_000;
/** The longest single text value in a file, in bytes of UTF-8 (64 KiB). */
export const MAX_FIELD_BYTES = 64 * 1024;
/** The deepest nesting of objects and arrays in a JSON file. A real export is 6 deep. */
export const MAX_DEPTH = 16;
/**
 * The most values (scalars, arrays and objects together) in one JSON file: 60 for each of the most
 * items (a login with its addresses and a few custom fields is about 35 values; an identity about
 * 45). The bound is what keeps a worker's memory down, as the parsed tree and its copy in objects
 * without a prototype cost about 300 bytes a value: the worst file it lets through (10 000 items of
 * 29 empty objects each, 590 000 values) took about 90 MiB to parse and copy, so two million values
 * would have been over 300 MiB on top of the text of the file.
 */
export const MAX_NODES = MAX_ITEMS * 60;
/** The most columns in a CSV file. */
export const MAX_COLUMNS = 256;
/**
 * The largest `.avux` file the import takes, in bytes (2 GiB). An export of AliasVault holds every attachment and logo of the vault,
 * and the import reads none of them: only the directory and `manifest.json` are read, by slices of the file. ZIP64 is refused, so the
 * offsets of such a file are below 4 GiB anyway; 2 GiB is far above a real vault and keeps the numbers of the reader in the range of a
 * safe integer and of a 32-bit offset.
 */
export const MAX_AVUX_FILE_BYTES = 2 * 1024 * 1024 * 1024;
/** The most entries in the directory of an `.avux` file: all that a ZIP file without ZIP64 can hold (65 535 is its marker). */
export const MAX_AVUX_ENTRIES = 65_534;
/** The most entries in the central directory of a ZIP file. */
export const MAX_ZIP_ENTRIES = 1_000;
/** The most a ZIP entry may grow when it is unpacked: unpacked bytes per packed byte. */
export const MAX_ZIP_RATIO = 100;

/**
 * The codes of an `ImportError` and the text that says what happened. The text is fixed: it never
 * holds a value from the file, so showing it (or logging it) cannot leak an import. The view picks
 * its own words from the code; this text is the fallback and the clear text of the tests.
 */
export const IMPORT_ERROR_TEXT = Object.freeze({
  import_zip:
    "This is a ZIP file. Ferret cannot read ZIP exports. Export the vault again as an unencrypted .json or .csv file without attachments.",
  import_encrypted_export:
    "This export is encrypted. Ferret cannot read it. Export the vault again as an unencrypted .json or .csv file.",
  import_too_large: "The file is larger than the import allows (50 MiB).",
  import_too_deep: "The file is nested too deeply to be an export of a vault.",
  import_too_many: "The file holds more items than the import allows.",
  import_archive_too_large: "The archive is larger than the import allows (2 GiB). Only its list of items is read, but a file this large is not an export that Ferret reads. Export as CSV instead, which has no attachments.",
  import_archive_too_many: "The archive holds more files than the import allows. Export as CSV instead, which has no attachments.",
  import_manifest_too_large: "The list of items in the archive (manifest.json) is larger than the import allows (50 MiB).",
  import_field_too_large: "A value in the file is longer than the import allows (64 KiB).",
  import_bad_json: "The file is not valid JSON.",
  import_bad_key: "The file holds a key that an export never has, so it is refused.",
  import_bad_csv: "The file is not valid CSV.",
  import_bad_format: "The file is not an export that Ferret can read.",
  import_empty: "The file holds no items.",
  import_bad_zip: "The ZIP file is damaged or not one that Ferret reads.",
  import_zip_encrypted: "The ZIP file is encrypted. Ferret cannot read it.",
  import_zip_entry_missing: "The ZIP file lacks the file that the export is read from.",
  import_unreadable: "The file could not be read.",
  import_seal_failed: "The vault refused to store an item, so the import stopped.",
  import_port_closed: "The vault was locked or closed before the import finished.",
  unsupported: "This request is not one that the import worker answers.",
});

/**
 * A refusal of an import. `code` is one of the keys of {@link IMPORT_ERROR_TEXT}; `message` is
 * its fixed text; `line` is the line of a CSV file (from 1) when the error is about one; `reason` is
 * the code that the vault gave when it refused an item (a code of letters, digits and underscores,
 * never a text). Nothing of the file is ever put in it.
 */
export class ImportError extends Error {
  /**
   * @param {keyof typeof IMPORT_ERROR_TEXT} code
   * @param {{ line?: number, reason?: string }} [details]
   */
  constructor(code, details = {}) {
    super(IMPORT_ERROR_TEXT[code]);
    this.name = "ImportError";
    /** @type {keyof typeof IMPORT_ERROR_TEXT} */
    this.code = code;
    /** @type {number | undefined} */
    this.line = Number.isSafeInteger(details.line) ? details.line : undefined;
    /** @type {string | undefined} */
    this.reason = typeof details.reason === "string" && /^[a-z0-9_]{1,64}$/.test(details.reason) ? details.reason : undefined;
  }
}

/**
 * Whether a text is longer than `MAX_FIELD_BYTES` in UTF-8. Cheap for every text that is plainly
 * shorter or longer; counts the bytes only for one near the bound.
 * @param {string} text
 */
export function overFieldBound(text) {
  // One UTF-16 unit is one to three bytes of UTF-8 (a pair is four bytes for two units).
  if (text.length * 3 <= MAX_FIELD_BYTES) return false;
  if (text.length > MAX_FIELD_BYTES) return true;
  return new TextEncoder().encode(text).length > MAX_FIELD_BYTES;
}
