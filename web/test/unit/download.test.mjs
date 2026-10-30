import assert from "node:assert/strict";
import { test } from "node:test";
import { downloadBlob } from "../../src/download.mjs";
import { fakeDocument } from "./helpers.mjs";

function env() {
  const calls = [];
  const timers = [];
  const document = fakeDocument();
  return {
    calls,
    timers,
    document,
    URL: {
      createObjectURL(blob) {
        calls.push(["create", blob.type, blob.size]);
        return "blob:https://vault.test/1234";
      },
      revokeObjectURL(url) {
        calls.push(["revoke", url]);
      },
    },
    Blob,
    setTimeout: (fn, ms) => timers.push([fn, ms]),
  };
}

test("download_helper_creates_and_revokes_the_object_url", () => {
  const e = env();
  downloadBlob(new Uint8Array([1, 2, 3]), "export.json", "application/json", e);
  const link = e.document.created[0];
  assert.equal(link.tagName, "a");
  assert.equal(link.getAttribute("href"), "blob:https://vault.test/1234");
  assert.equal(link.getAttribute("download"), "export.json");
  assert.equal(link.clicked, true);
  assert.equal(link.parentNode, null, "the link is removed again");
  assert.deepEqual(e.calls, [["create", "application/json", 3]]);
  // The URL is revoked once the click has been handled.
  assert.equal(e.timers.length, 1);
  e.timers[0][0]();
  assert.deepEqual(e.calls.at(-1), ["revoke", "blob:https://vault.test/1234"]);
});

test("download_helper_revokes_the_url_when_the_click_fails_and_cleans_the_name", () => {
  const e = env();
  e.document.createElement = () => ({
    setAttribute() {},
    click() {
      throw new Error("blocked");
    },
    remove() {},
  });
  assert.throws(() => downloadBlob(new Uint8Array(1), "a", "text/plain", e), /blocked/);
  assert.equal(e.timers.length, 1);

  const f = env();
  downloadBlob(new Uint8Array(1), "../../etc/pass\u0000wd\\x", "text/plain", f);
  assert.equal(f.document.created[0].getAttribute("download"), ".._.._etc_pass_wd_x");
  assert.throws(() => downloadBlob("text", "a", "text/plain", env()), TypeError);
  assert.throws(() => downloadBlob(new Uint8Array(1), "a", "text/html; charset=x", env()), TypeError);
});
