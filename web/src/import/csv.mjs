// SPDX-License-Identifier: AGPL-3.0-only
// Modified by Faithful Ferret: this file is a port to JavaScript of
// core/client/src/transfer/import/readers/CsvParser.ts of AliasVault
// (https://github.com/aliasvault/aliasvault, commit 7e7cd6f3141c94f884ddd1666987aec3ffcdcdf3,
// GNU Affero General Public License v3). Kept from the original: the byte order mark, the choice of
// the delimiter from the first rows (a comma or a semicolon), blank lines skipped, the `""` escape.
// Changed: the quoting rules are RFC 4180 and strict (a quote that is not doubled and does not end
// the field is an error, and so is a quote inside an unquoted field), every error names the line,
// the reader is bounded (rows, columns, field size), it is written with slices instead of one
// character at a time, and it throws `ImportError`. The original header follows.
/*
 * CSV parser utility.
 */

import { ImportError, MAX_COLUMNS, MAX_ITEMS, overFieldBound } from "./limits.mjs";

/** The delimiters a file may use: a comma, or a semicolon as spreadsheet apps write for locales with a decimal comma. */
const CANDIDATE_DELIMITERS = [",", ";"];

/** How many rows the choice of the delimiter looks at. */
const DETECTION_ROW_COUNT = 10;

/**
 * The most rows that are read: the header and `MAX_ITEMS` records.
 */
const MAX_ROWS = MAX_ITEMS + 1;

/**
 * Splits CSV text into rows of fields. The delimiter (comma or semicolon) is chosen from the first
 * rows, blank lines are skipped and a byte order mark is ignored. Line breaks are CRLF, LF or a
 * lone CR.
 *
 * @param {string} content the CSV text
 * @returns {string[][]} the rows, each an array of field values
 * @throws {ImportError} `import_bad_csv` (with `line`) for a quote that breaks the rules or a field
 *   that is never closed, a row of more than `MAX_COLUMNS` fields; `import_too_many` for more than
 *   `MAX_ITEMS` records; `import_field_too_large` for a field over `MAX_FIELD_BYTES`.
 */
export function parseCsvRows(content) {
  return parseCsv(content).rows;
}

/**
 * Like {@link parseCsvRows}, and also the line (from 1) on which each row starts.
 * @param {string} content
 * @returns {{ rows: string[][], lines: number[] }}
 */
export function parseCsv(content) {
  const text = content.charCodeAt(0) === 0xfeff ? content.slice(1) : content;
  const result = splitRows(text, detectDelimiter(text), MAX_ROWS + 1);
  if (result.error) throw new ImportError("import_bad_csv", { line: result.error.line });
  if (result.rows.length > MAX_ROWS) throw new ImportError("import_too_many");
  return { rows: result.rows, lines: result.lines };
}

/**
 * Picks the delimiter that the first rows split on most evenly. A candidate under which the first
 * rows do not even parse is passed over; when none fits, the comma is used and the real read reports
 * the error.
 * @param {string} text
 */
function detectDelimiter(text) {
  /** @type {{ delimiter: string, delta: number } | null} */
  let best = null;
  for (const delimiter of CANDIDATE_DELIMITERS) {
    /** @type {ReturnType<typeof splitRows>} */
    let sample;
    try {
      sample = splitRows(text, delimiter, DETECTION_ROW_COUNT);
    } catch (error) {
      // Under this delimiter a row is one huge field or has too many columns: it is not the delimiter.
      if (error instanceof ImportError) continue;
      throw error;
    }
    const { rows, error } = sample;
    if (error || rows.length === 0) continue;
    const averageFieldCount = rows.reduce((sum, row) => sum + row.length, 0) / rows.length;
    const delta = rows.slice(1).reduce((sum, row, index) => sum + Math.abs(row.length - rows[index].length), 0);
    if (averageFieldCount >= 2 && (!best || delta < best.delta)) best = { delimiter, delta };
  }
  return best?.delimiter ?? ",";
}

/**
 * How many line breaks `text[from, to)` holds: LF, CRLF and a lone CR count once each.
 * @param {string} text
 * @param {number} from
 * @param {number} to
 */
function breaksIn(text, from, to) {
  let count = 0;
  for (let i = from; i < to; i++) {
    const c = text.charCodeAt(i);
    if (c === 10) count++;
    else if (c === 13 && text.charCodeAt(i + 1) !== 10) count++;
  }
  return count;
}

/**
 * Splits CSV text into rows of fields on the given delimiter.
 * @param {string} text the CSV text, without a byte order mark
 * @param {string} delimiter the field delimiter
 * @param {number} [maxRows] stop after this many rows
 * @returns {{ rows: string[][], lines: number[], error?: { line: number } }} the rows read, the line on which
 *   each starts, and where the text broke the rules, if it did
 */
function splitRows(text, delimiter, maxRows = Infinity) {
  /** @type {string[][]} */
  const rows = [];
  /** @type {number[]} */
  const lines = [];
  /** @type {string[]} */
  let row = [];
  let rowLine = 1;
  let line = 1;
  let field = "";
  // Nothing of the field has been read yet: only here may a quote open a quoted field.
  let fresh = true;
  let i = 0;
  const n = text.length;
  const delim = delimiter.charCodeAt(0);
  /** @param {number} at */
  const fail = (at) => ({ rows, lines, error: { line: at } });
  const endRow = () => {
    if (row.length > 0 || field !== "") {
      row.push(field);
      if (row.length > MAX_COLUMNS) throw new ImportError("import_bad_csv", { line: rowLine });
      if (row.some(overFieldBound)) throw new ImportError("import_field_too_large");
      rows.push(row);
      lines.push(rowLine);
    }
    row = [];
    field = "";
    fresh = true;
  };

  while (i < n && rows.length < maxRows) {
    const c = text.charCodeAt(i);
    if (c === 34) {
      if (!fresh) return fail(line); // a quote inside an unquoted field
      const startLine = line;
      i++;
      let out = "";
      for (;;) {
        const q = text.indexOf('"', i);
        if (q < 0) return fail(startLine); // never closed: it would swallow every row after it
        line += breaksIn(text, i, q);
        out += text.slice(i, q);
        const next = q + 1 < n ? text.charCodeAt(q + 1) : -1;
        if (next === 34) {
          out += '"';
          i = q + 2;
          continue;
        }
        if (next === -1 || next === delim || next === 10 || next === 13) {
          i = q + 1;
          break;
        }
        return fail(line); // a quote that is neither doubled nor the end of the field
      }
      field = out;
      fresh = false;
    } else if (c === delim) {
      if (row.length >= MAX_COLUMNS) return fail(line);
      row.push(field);
      field = "";
      fresh = true;
      i++;
    } else if (c === 13 || c === 10) {
      i += c === 13 && text.charCodeAt(i + 1) === 10 ? 2 : 1;
      line++;
      endRow();
      rowLine = line;
    } else {
      let j = i + 1;
      while (j < n) {
        const d = text.charCodeAt(j);
        if (d === delim || d === 34 || d === 13 || d === 10) break;
        j++;
      }
      field += text.slice(i, j);
      fresh = false;
      i = j;
    }
  }
  if (rows.length < maxRows) endRow();
  return { rows, lines };
}
