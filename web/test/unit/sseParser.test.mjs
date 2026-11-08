// The event-stream reader: the WHATWG line rules, and the two limits that keep a
// server we do not trust from making the page hold on to unbounded text.
import assert from "node:assert/strict";
import { test } from "node:test";
import { parseEventStream } from "../../src/sync/events.mjs";

const bytes = (text) => new TextEncoder().encode(text);

/** All items the parser gives for these chunks. */
function read(...chunks) {
  const parser = parseEventStream();
  return chunks.flatMap((chunk) => parser.push(typeof chunk === "string" ? bytes(chunk) : chunk));
}

test("parser_handles_split_chunks_crlf_multiline_data_and_comments", () => {
  // An event split at every byte is the same event.
  const text = 'event: sync\ndata: {"seq":5}\n\n';
  const split = parseEventStream();
  const items = [];
  for (const byte of bytes(text)) items.push(...split.push(Uint8Array.of(byte)));
  assert.deepEqual(items, [{ event: "sync", data: '{"seq":5}' }]);

  // CRLF, a lone CR and a lone LF all end a line, and a CRLF cut between two chunks is one line end.
  assert.deepEqual(read("event: a\r\ndata: 1\r\n\r\n"), [{ event: "a", data: "1" }]);
  assert.deepEqual(read("event: a\rdata: 1\r\r"), [{ event: "a", data: "1" }]);
  assert.deepEqual(read("event: a\r", "\ndata: 1\r", "\n\r", "\n"), [{ event: "a", data: "1" }]);
  assert.deepEqual(read("data: x\r", "\ndata: y\n\n"), [{ event: "message", data: "x\ny" }]);

  // Several data lines are joined with a line feed; one space after the colon is dropped, no more.
  assert.deepEqual(read("data: one\ndata:two\ndata:  three\ndata\n\n"), [{ event: "message", data: "one\ntwo\n three\n" }]);
  // An event with no data is not an event.
  assert.deepEqual(read("event: lonely\n\n"), []);
  // The name does not carry over to the next event.
  assert.deepEqual(read("event: a\ndata: 1\n\ndata: 2\n\n"), [{ event: "a", data: "1" }, { event: "message", data: "2" }]);

  // Comments are told apart from events, and a comment does not end an event.
  assert.deepEqual(read(": keep-alive\n\n"), [{ comment: true }]);
  assert.deepEqual(read("data: 1\n: between\ndata: 2\n\n"), [{ comment: true }, { event: "message", data: "1\n2" }]);
  assert.deepEqual(read(":\n"), [{ comment: true }]);

  // `id`, `retry` and unknown fields are ignored.
  assert.deepEqual(read("id: 9\nretry: 1\nwhatever: x\ndata: 1\n\n"), [{ event: "message", data: "1" }]);

  // An event that is not finished waits; nothing is given for it.
  const parser = parseEventStream();
  assert.deepEqual(parser.push(bytes("event: sync\ndata: 1\n")), []);
  assert.deepEqual(parser.push(bytes("\n")), [{ event: "sync", data: "1" }]);

  // A multi-byte character cut between two chunks is whole; a byte order mark is dropped.
  const snowman = bytes("data: ☃\n\n");
  assert.deepEqual(read(snowman.subarray(0, 7), snowman.subarray(7)), [{ event: "message", data: "☃" }]);
  assert.deepEqual(read(Uint8Array.of(0xef, 0xbb, 0xbf), "data: 1\n\n"), [{ event: "message", data: "1" }]);
});

test("parser_caps_line_length_and_never_evaluates_data", () => {
  const LIMIT = 64 * 1024;
  // A line of exactly the limit is read; one byte more ends the stream, even when it comes in pieces.
  const atLimit = `data: ${"a".repeat(LIMIT - 6)}\n\n`;
  assert.equal(read(atLimit)[0].data.length, LIMIT - 6);
  assert.throws(() => read(`data: ${"a".repeat(LIMIT - 5)}\n\n`), RangeError);
  const parser = parseEventStream();
  assert.throws(() => {
    for (let i = 0; i < 10; i += 1) parser.push(bytes("a".repeat(LIMIT / 8)));
  }, RangeError);
  // Without any line end the limit holds as well, and a comment line counts too.
  assert.throws(() => read(`:${"x".repeat(LIMIT)}`), RangeError);
  // Many short data lines do not get round the limit.
  assert.throws(() => {
    const p = parseEventStream();
    for (let i = 0; i < 200_000; i += 1) p.push(bytes("data: 0123456789\n"));
  }, RangeError);
  // Multi-byte text counts in bytes, not characters.
  assert.throws(() => read(`data: ${"☃".repeat(LIMIT / 3)}\n`), RangeError);

  // Data is text and stays text: whatever it looks like, it comes back as the same string.
  const hostile = ['{"seq":1}', "__proto__", "constructor", "<img src=x onerror=alert(1)>", "alert(1)", "${1+1}", "{{7*7}}", "\u0000‮"];
  for (const data of hostile) {
    const [item] = read(`event: sync\ndata: ${data}\n\n`);
    assert.deepEqual(Object.keys(item).sort(), ["data", "event"]);
    assert.equal(item.data, data);
    assert.equal(typeof item.data, "string");
  }
  // An event name that names a prototype key is just a name.
  assert.deepEqual(read("event: __proto__\ndata: 1\n\n"), [{ event: "__proto__", data: "1" }]);
});
