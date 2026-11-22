import assert from "node:assert/strict";
import { test } from "node:test";

import { narrowOrigin } from "../../src/shared/origin.mjs";
import {
  CONTENT_TYPES,
  ProtocolError,
  decode,
  encode,
} from "../../src/shared/protocol.mjs";

const report = { request_id: "r1", self_origin: "https://example.com", fields: [] };

test("self_origin_can_only_narrow", () => {
  // The same origin passes, and the value returned is the browser's.
  assert.equal(narrowOrigin("https://example.com", "https://example.com"), "https://example.com");
  assert.equal(narrowOrigin("http://localhost:3000", "http://localhost:3000"), "http://localhost:3000");
  // An opaque origin is refused, on either side, also when both are "null".
  assert.equal(narrowOrigin("https://example.com", "null"), null);
  assert.equal(narrowOrigin("null", "null"), null);
  assert.equal(narrowOrigin("null", "https://example.com"), null);
  assert.equal(narrowOrigin("", ""), null);
  // Another origin is refused: wider, narrower, other scheme, other port, other case.
  for (const other of [
    "https://evil.example",
    "https://sub.example.com",
    "https://example.com:8443",
    "http://example.com",
    "https://EXAMPLE.com",
    "https://example.com/",
    "",
  ]) {
    assert.equal(narrowOrigin("https://example.com", other), null, other);
  }
  // It never returns a value other than the browser's, and never the page's.
  const origins = ["https://example.com", "null", "", "https://a.example", "http://[::1]:80", "x"];
  for (const fromBrowser of origins) {
    for (const selfOrigin of origins) {
      const out = narrowOrigin(fromBrowser, selfOrigin);
      assert.ok(out === null || out === fromBrowser, `${fromBrowser} / ${selfOrigin}`);
    }
  }
  for (const bad of [undefined, null, 1, {}, ["https://example.com"]]) {
    assert.equal(narrowOrigin(/** @type {any} */ (bad), "https://example.com"), null);
    assert.equal(narrowOrigin("https://example.com", /** @type {any} */ (bad)), null);
  }

  // `frame_report` takes `self_origin` and no other origin or address key.
  const decoded = decode(encode("frame_report", report), CONTENT_TYPES);
  assert.equal(decoded.body.self_origin, "https://example.com");
  const raw = (/** @type {Record<string, unknown>} */ body) =>
    JSON.stringify({ v: 1, id: "a", type: "frame_report", body });
  for (const key of ["origin", "url", "frame_url", "frameUrl", "top_origin", "page_origin", "href", "host"]) {
    assert.throws(
      () => decode(raw({ ...report, [key]: "https://example.com" }), CONTENT_TYPES),
      (err) => err instanceof ProtocolError && err.code === "bad_shape",
      key,
    );
  }
  // The key is required, and it is a string.
  const { self_origin: _gone, ...without } = report;
  assert.throws(() => decode(raw(without), CONTENT_TYPES), ProtocolError);
  assert.throws(() => decode(raw({ ...report, self_origin: null }), CONTENT_TYPES), ProtocolError);
  assert.throws(() => decode(raw({ ...report, self_origin: ["https://example.com"] }), CONTENT_TYPES), ProtocolError);
  // "null" is a valid report: the background refuses the frame with narrowOrigin.
  assert.equal(decode(raw({ ...report, self_origin: "null" }), CONTENT_TYPES).body.self_origin, "null");
});
