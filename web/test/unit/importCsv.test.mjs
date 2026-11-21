// The CSV reader: RFC 4180 with bounds, a byte order mark, CRLF and LF, both delimiters.
import assert from "node:assert/strict";
import { test } from "node:test";
import { ImportError, MAX_COLUMNS, MAX_FIELD_BYTES, MAX_ITEMS } from "../../src/import/limits.mjs";
import { parseCsv, parseCsvRows } from "../../src/import/csv.mjs";
import { fixture } from "./importHelpers.mjs";

const refusal = (code, line) => (error) => error instanceof ImportError && error.code === code && (line === undefined || error.line === line);

test("csv_reads_plain_quoted_and_multiline_fields", () => {
  const rows = parseCsvRows('a,b,c\n1,"two, with comma","three ""quoted"""\n"line\nbreak",,x\n');
  assert.deepEqual(rows, [
    ["a", "b", "c"],
    ["1", "two, with comma", 'three "quoted"'],
    ["line\nbreak", "", "x"],
  ]);
  // An empty quoted field, and a quoted field that is the last of its row and of the file.
  assert.deepEqual(parseCsvRows('a,b\n"",""'), [["a", "b"], ["", ""]]);
  assert.deepEqual(parseCsvRows('a,b\n1,"x"'), [["a", "b"], ["1", "x"]]);
});

test("csv_takes_a_byte_order_mark_crlf_lf_and_a_lone_cr_and_skips_blank_lines", () => {
  const expected = [["a", "b"], ["1", "2"], ["3", "4"]];
  assert.deepEqual(parseCsvRows("a,b\n1,2\n3,4"), expected);
  assert.deepEqual(parseCsvRows("a,b\r\n1,2\r\n3,4\r\n"), expected);
  assert.deepEqual(parseCsvRows("a,b\r1,2\r3,4\r"), expected);
  assert.deepEqual(parseCsvRows("﻿a,b\n1,2\n\n\n3,4\n\n"), expected);
  // A quoted field keeps its own line breaks as written.
  assert.deepEqual(parseCsvRows('a,b\r\n"x\r\ny",z\r\n'), [["a", "b"], ["x\r\ny", "z"]]);
  assert.deepEqual(parseCsvRows(""), []);
});

test("csv_detects_the_semicolon_delimiter", () => {
  assert.deepEqual(parseCsvRows("name;login_username;login_password\nExample;alice;pw,1\n"), [
    ["name", "login_username", "login_password"],
    ["Example", "alice", "pw,1"],
  ]);
  assert.deepEqual(parseCsvRows('name;notes\n"a;b";"c,d"\n'), [["name", "notes"], ["a;b", "c,d"]]);
  // A comma file whose text holds semicolons stays a comma file.
  assert.deepEqual(parseCsvRows("a,b\nx;y,z\np;q,r\n"), [["a", "b"], ["x;y", "z"], ["p;q", "r"]]);
  // One column: the comma, and nothing is split.
  assert.deepEqual(parseCsvRows("name\nExample\n"), [["name"], ["Example"]]);
});

test("csv_with_a_bad_quote_names_the_line", () => {
  // A quote in the middle of an unquoted field: line 3.
  assert.throws(() => parseCsvRows('a,b\n1,2\n3,x"y\n'), refusal("import_bad_csv", 3));
  // A quote that closes early and is followed by text: line 2.
  assert.throws(() => parseCsvRows('a,b\n"x"y,2\n'), refusal("import_bad_csv", 2));
  // A quote that is not doubled inside a quoted field.
  assert.throws(() => parseCsvRows('a,b\n"x"y"z",2\n'), refusal("import_bad_csv", 2));
  // A quoted field that is never closed: the line where it started, even when it runs on for lines.
  assert.throws(() => parseCsvRows('a,b\n1,2\n3,"never closed\n4,5\n6,7\n'), refusal("import_bad_csv", 3));
  // Line numbers count the breaks inside quoted fields before the error.
  assert.throws(() => parseCsvRows('a,b\n"one\ntwo\nthree",2\n3,x"y\n'), refusal("import_bad_csv", 5));
  // With CRLF and with a lone CR.
  assert.throws(() => parseCsvRows('a,b\r\n1,2\r\n3,x"y\r\n'), refusal("import_bad_csv", 3));
  assert.throws(() => parseCsvRows('a,b\r1,2\r3,x"y\r'), refusal("import_bad_csv", 3));
  // A space before the opening quote makes the quote a quote inside an unquoted field.
  assert.throws(() => parseCsvRows('a,b\n1, "2"\n'), refusal("import_bad_csv", 2));
  // The message holds nothing of the file.
  try {
    parseCsvRows('a,b\n1,secret"text\n');
    assert.fail("no error");
  } catch (error) {
    assert.ok(!error.message.includes("secret"));
    assert.equal(error.line, 2);
  }
});

test("csv_reports_the_line_on_which_each_row_starts", () => {
  const { rows, lines } = parseCsv('a,b\n\n1,"x\ny"\n\n2,3\n');
  assert.equal(rows.length, 3);
  assert.deepEqual(lines, [1, 3, 6]);
});

test("csv_is_bounded_in_rows_columns_and_field_size", () => {
  // Rows: the header and MAX_ITEMS records are fine, one more is not.
  const header = "a,b\n";
  const rows = (n) => header + "1,2\n".repeat(n);
  assert.equal(parseCsvRows(rows(MAX_ITEMS)).length, MAX_ITEMS + 1);
  assert.throws(() => parseCsvRows(rows(MAX_ITEMS + 1)), refusal("import_too_many"));
  // Columns.
  const wide = (n) => Array.from({ length: n }, (_, i) => `c${i}`).join(",");
  assert.equal(parseCsvRows(wide(MAX_COLUMNS)).at(0).length, MAX_COLUMNS);
  assert.throws(() => parseCsvRows(`${wide(MAX_COLUMNS + 1)}\n`), refusal("import_bad_csv", 1));
  // A field of 64 KiB is fine, one byte more is not; counted in UTF-8 bytes.
  assert.equal(parseCsvRows(`a,b\n${"x".repeat(MAX_FIELD_BYTES)},1\n`)[1][0].length, MAX_FIELD_BYTES);
  assert.throws(() => parseCsvRows(`a,b\n${"x".repeat(MAX_FIELD_BYTES + 1)},1\n`), refusal("import_field_too_large"));
  assert.throws(() => parseCsvRows(`a,b\n"${"é".repeat(MAX_FIELD_BYTES / 2 + 1)}",1\n`), refusal("import_field_too_large"));
});

test("csv_reads_the_bitwarden_fixture", () => {
  const rows = parseCsvRows(fixture("small.csv"));
  assert.equal(rows.length, 4);
  assert.deepEqual(rows[0], ["folder", "favorite", "type", "name", "notes", "fields", "reprompt", "login_uri", "login_username", "login_password", "login_totp"]);
  assert.equal(rows[1][5], "Pin: 0000\nMemo: none");
  assert.equal(rows[1][7], "https://www.example.test/login\nandroidapp://example.test.app");
  assert.equal(rows[3][3], 'Quoted, "name"');
  assert.ok(rows.every((r) => r.length === 11));
});
