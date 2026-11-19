// The PDF writer: a file that a reader opens (pages, a valid cross-reference table), that holds
// nothing active and no metadata, that escapes what a string needs, and that refuses a character
// WinAnsi does not have.
import assert from "node:assert/strict";
import { test } from "node:test";
import { createPdf, PAGE_HEIGHT, PAGE_WIDTH, wipe } from "../../src/pdf.mjs";

const latin1 = (bytes) => Buffer.from(bytes).toString("latin1");

/** A small reader: the objects, the cross-reference table and the streams of a file that this writer made. */
function read(bytes) {
  const text = latin1(bytes);
  assert.ok(text.startsWith("%PDF-1.7\n"), "header");
  assert.ok(text.endsWith("\n%%EOF\n"), "end marker");
  const start = /\nstartxref\n(\d+)\n%%EOF\n$/.exec(text);
  assert.ok(start, "startxref");
  const xrefAt = Number(start[1]);
  assert.equal(text.slice(xrefAt, xrefAt + 5), "xref\n", "startxref points at the table");
  const table = /^xref\n0 (\d+)\n/.exec(text.slice(xrefAt));
  assert.ok(table, "xref header");
  const count = Number(table[1]);
  const first = xrefAt + table[0].length;
  const entries = [];
  for (let i = 0; i < count; i += 1) {
    const raw = text.slice(first + 20 * i, first + 20 * i + 20);
    assert.match(raw, /^\d{10} \d{5} [nf] \n$/, `entry ${i} is 20 bytes`);
    entries.push({ offset: Number(raw.slice(0, 10)), generation: Number(raw.slice(11, 16)), kind: raw[17] });
  }
  assert.deepEqual(entries[0], { offset: 0, generation: 65535, kind: "f" });
  const trailer = new RegExp(`^trailer\\n<< /Size ${count} /Root 1 0 R >>\\nstartxref\\n`).exec(text.slice(first + 20 * count));
  assert.ok(trailer, "trailer names the size and the root");
  const objects = new Map();
  for (let id = 1; id < count; id += 1) {
    const { offset, kind } = entries[id];
    assert.equal(kind, "n");
    const head = `${id} 0 obj\n`;
    assert.equal(text.slice(offset, offset + head.length), head, `object ${id} is where the table says`);
    const end = text.indexOf("\nendobj\n", offset);
    assert.ok(end > offset, `object ${id} ends`);
    objects.set(id, text.slice(offset + head.length, end));
  }
  return { text, count, objects, xrefAt };
}

/** The dictionary names (/Word) of the file, with the contents of the streams left out (text can hold a slash). */
function names(parsed) {
  const withoutStreams = parsed.text.replace(/stream\n[\s\S]*?\nendstream/g, "stream endstream");
  return new Set([...withoutStreams.matchAll(/\/([A-Za-z0-9]+)/g)].map((m) => m[1]));
}

function sample(pages = 1) {
  const pdf = createPdf();
  for (let i = 0; i < pages; i += 1) {
    const page = pdf.page();
    page.text(72, 760, 14, `Page ${i + 1}`);
    page.rect(72, 700, 50, 50);
  }
  return pdf;
}

test("pdf_has_the_pages_asked_for_and_a_valid_xref", () => {
  for (const pages of [1, 2, 3]) {
    const parsed = read(sample(pages).bytes());
    assert.equal(parsed.count, 4 + 2 * pages);
    assert.equal(parsed.objects.get(1), "<< /Type /Catalog /Pages 2 0 R >>");
    const tree = /^<< \/Type \/Pages \/Kids \[([^\]]*)\] \/Count (\d+) >>$/.exec(parsed.objects.get(2));
    assert.ok(tree);
    assert.equal(Number(tree[2]), pages);
    const kids = tree[1].split(" R").filter((k) => k.trim() !== "").map((k) => Number(k.trim().split(" ")[0]));
    assert.equal(kids.length, pages);
    for (const [i, kid] of kids.entries()) {
      const page = parsed.objects.get(kid);
      assert.match(page, /^<< \/Type \/Page \/Parent 2 0 R /);
      assert.ok(page.includes(`/MediaBox [0 0 ${PAGE_WIDTH} ${PAGE_HEIGHT}]`), "A4");
      const contents = Number(/\/Contents (\d+) 0 R/.exec(page)[1]);
      assert.equal(contents, kid + 1);
      // The stream is as long as its /Length says.
      const stream = /^<< \/Length (\d+) >>\nstream\n([\s\S]*)\nendstream$/.exec(parsed.objects.get(contents));
      assert.ok(stream, `stream of page ${i + 1}`);
      assert.equal(Buffer.byteLength(stream[2], "latin1"), Number(stream[1]));
      assert.match(stream[2], new RegExp(`\\(Page ${i + 1}\\) Tj`));
      assert.match(stream[2], /72 700 50 50 re f/);
    }
    assert.match(parsed.objects.get(3), /\/BaseFont \/Helvetica \/Encoding \/WinAnsiEncoding/);
  }
});

test("pdf_has_the_same_bytes_for_the_same_pages_and_nothing_of_the_time_or_the_maker", () => {
  const a = sample(2).bytes();
  const b = sample(2).bytes();
  assert.deepEqual(a, b);
  const pdf = sample(1);
  assert.deepEqual(pdf.bytes(), pdf.bytes(), "a second call gives the same file");
  assert.throws(() => createPdf().bytes(), /pdf_no_pages/);
});

test("pdf_refuses_characters_outside_win_ansi", () => {
  const page = createPdf().page();
  const refused = ["日本", "ā", "😀", "\n", "\t", "\r", "\u0000", "\u007f", "\u0080", "\u009d", " ", "á", "₿"];
  for (const text of refused) {
    assert.throws(() => page.text(10, 10, 12, text), (e) => e instanceof TypeError && e.message === "pdf_char", JSON.stringify(text));
  }
  assert.throws(() => page.text(10, 10, 12, /** @type {any} */ (5)), (e) => e instanceof TypeError && e.message === "pdf_char");
  // A refused call writes nothing: the page is as it was.
  const pdf = createPdf();
  const p = pdf.page();
  p.text(10, 10, 12, "ok");
  const before = pdf.bytes();
  assert.throws(() => p.text(10, 10, 12, "x日"), TypeError);
  assert.deepEqual(pdf.bytes(), before);
  // What WinAnsi has is accepted: Latin-1 and the printable part of the 0x80 block.
  for (const text of ["", "A z 0 ~", "æøå ÆØÅ", " ÿ", "€ – — ‘x’ “y” • … ™ Œœ Šš Žž Ÿ"]) {
    page.text(10, 10, 12, text);
  }
});

test("pdf_has_no_javascript_links_forms_or_metadata", () => {
  const pdf = createPdf();
  const page = pdf.page();
  // Even text that looks like the dangerous things stays text inside a string.
  page.text(72, 700, 12, "/JavaScript /OpenAction /URI /AcroForm /Info /Launch");
  page.text(72, 680, 12, "http://example.com/x");
  const parsed = read(pdf.bytes());
  const used = names(parsed);
  const allowed = new Set([
    "Type", "Catalog", "Pages", "Kids", "Count", "Font", "Subtype", "Type1", "BaseFont", "Helvetica", "Encoding",
    "WinAnsiEncoding", "Page", "Parent", "MediaBox", "Resources", "Contents", "Length", "Size", "Root", "F1",
  ]);
  for (const name of used) assert.ok(allowed.has(name), `/${name} is not one of the names this writer uses`);
  for (const forbidden of [
    "JS", "JavaScript", "AA", "OpenAction", "Launch", "URI", "GoTo", "GoToR", "SubmitForm", "ImportData", "Annots", "Annot",
    "Link", "AcroForm", "XFA", "Info", "Metadata", "Producer", "Creator", "CreationDate", "ModDate", "Author", "Title",
    "Subject", "Keywords", "ID", "Names", "Outlines", "EmbeddedFile", "EmbeddedFiles", "Filespec", "RichMedia", "Encrypt",
    "ObjStm", "Filter", "XRef", "Perms", "Collection", "PieceInfo", "StructTreeRoot", "MarkInfo", "OCProperties",
  ]) {
    assert.ok(!used.has(forbidden), `/${forbidden} must not be in the file`);
  }
  // The only objects are the catalog, the page tree, one font, and a page with its stream.
  assert.equal(parsed.count, 6);
  // The file is plain: the contents are readable text, and the file is the pages and nothing after the end marker.
  assert.ok(parsed.text.includes("(http://example.com/x) Tj"));
  assert.ok(parsed.text.endsWith("%%EOF\n"));
});

test("pdf_escapes_parentheses_and_backslashes", () => {
  const pdf = createPdf();
  const page = pdf.page();
  page.text(10, 10, 12, "a(b)c\\d");
  page.text(10, 30, 12, "((");
  page.text(10, 50, 12, "))");
  page.text(10, 70, 12, "\\)\\(");
  page.text(10, 90, 12, "é€");
  const text = latin1(pdf.bytes());
  assert.ok(text.includes("(a\\(b\\)c\\\\d) Tj"), "balanced and unbalanced marks are escaped");
  assert.ok(text.includes("(\\(\\() Tj"));
  assert.ok(text.includes("(\\)\\)) Tj"));
  assert.ok(text.includes("(\\\\\\)\\\\\\() Tj"));
  // A byte above 0x7E is an octal escape, so the text of the file stays ASCII there: e-acute is 0xE9, the euro sign 0x80.
  assert.ok(text.includes("(\\351\\200) Tj"));
  const stream = /stream\n([\s\S]*)\nendstream/.exec(text)[1];
  assert.ok([...stream].every((ch) => ch === "\n" || (ch >= " " && ch <= "~")), "the page content is printable ASCII");
  // A string cannot end early: remove the escaped pairs and the marks that are left are the string's own.
  for (const line of stream.split("\n").filter((l) => l.includes(" Tj"))) {
    const literal = /\((.*)\) Tj ET$/.exec(line)[1];
    let depth = 0;
    for (let i = 0; i < literal.length; i += 1) {
      if (literal[i] === "\\") i += 1;
      else assert.ok(literal[i] !== "(" && literal[i] !== ")", `an unescaped mark in ${line}`);
    }
    assert.equal(depth, 0);
  }
});

test("pdf_refuses_numbers_that_are_not_numbers", () => {
  const page = createPdf().page();
  for (const bad of [Number.NaN, Number.POSITIVE_INFINITY, "5", null, 1e9]) {
    assert.throws(() => page.rect(bad, 0, 1, 1), (e) => e instanceof TypeError && e.message === "pdf_number");
    assert.throws(() => page.text(bad, 0, 12, "x"), (e) => e instanceof TypeError && e.message === "pdf_number");
  }
  for (const size of [0, -1, Number.NaN, 5000]) assert.throws(() => page.text(0, 0, size, "x"), TypeError);
  // Small and negative values are written plainly, never with an exponent.
  const pdf = createPdf();
  pdf.page().rect(0.0001, -2.5, 1e-7, 100.12345);
  const text = latin1(pdf.bytes());
  assert.ok(text.includes("0 -2.5 0 100.123 re f"));
  assert.ok(!/e[+-]?\d/.test(/stream\n([\s\S]*)\nendstream/.exec(text)[1]));
});

test("pdf_bytes_can_be_wiped_and_the_writer_can_be_disposed", () => {
  const pdf = sample(1);
  const bytes = pdf.bytes();
  assert.ok(bytes.some((b) => b !== 0));
  wipe(bytes);
  assert.ok(bytes.every((b) => b === 0));
  assert.throws(() => wipe(/** @type {any} */ ("text")), TypeError);
  pdf.dispose();
  assert.throws(() => pdf.bytes(), /pdf_disposed/);
  assert.throws(() => pdf.page(), /pdf_disposed/);
});
