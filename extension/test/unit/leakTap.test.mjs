// The message side of the passkey leak scan (background/test-only/leakTap.mjs): it reads port and runtime messages only once
// started, finds a needle in either direction, says where and never what, and refuses needles it cannot use.
import assert from "node:assert/strict";
import { test } from "node:test";
import { createLeakTap } from "../../src/background/test-only/leakTap.mjs";

/** A port as the background is given one. @param {string} name */
function fakePort(name) {
  /** @type {Array<(m: unknown) => void>} */
  const listeners = [];
  /** @type {unknown[]} */
  const sent = [];
  return {
    name,
    sent,
    onMessage: { addListener: (/** @type {(m: unknown) => void} */ fn) => listeners.push(fn) },
    postMessage: (/** @type {unknown} */ m) => sent.push(m),
    receive: (/** @type {unknown} */ m) => listeners.forEach((fn) => fn(m)),
  };
}

const NEEDLE = "sentinel-needle-0123456789";

test("the_tap_finds_a_needle_on_ports_and_in_runtime_messages_and_says_only_where", async () => {
  const tap = createLeakTap();
  // Before the start nothing is read, and a port then is left alone.
  const before = fakePort("ferret-ui");
  tap.tapPort(before);
  before.receive({ text: NEEDLE });
  tap.tapMessage({ text: NEEDLE });
  assert.deepEqual(await tap.ops.leak_watch.run(null, { cmd: "read" }, /** @type {any} */ ({})), { ok: true, on: false, port_messages: 0, runtime_messages: 0, hits: [] });
  assert.deepEqual(await tap.ops.leak_watch.run(null, { cmd: "start", needles: [NEEDLE] }, /** @type {any} */ ({})), { ok: true });
  const port = fakePort("ferret-ui");
  tap.tapPort(port);
  port.receive({ text: "nothing here" });
  port.receive(`x${NEEDLE}y`);
  port.postMessage({ deep: { value: NEEDLE } });
  tap.tapMessage({ other: 1 });
  tap.tapMessage({ value: NEEDLE });
  assert.deepEqual(port.sent, [{ deep: { value: NEEDLE } }], "the message still goes out unchanged");
  const read = await tap.ops.leak_watch.run(null, { cmd: "read" }, /** @type {any} */ ({}));
  assert.deepEqual(read, { ok: true, on: true, port_messages: 3, runtime_messages: 2, hits: ["received on ferret-ui", "sent on ferret-ui", "runtime message"] });
  assert.equal(JSON.stringify(read).includes(NEEDLE), false, "the answer never holds the needle");
});

test("the_tap_refuses_needles_it_cannot_use", async () => {
  const tap = createLeakTap();
  for (const needles of [[], ["short"], Array.from({ length: 17 }, (_, i) => `needle-number-${i}`), [42], "x".repeat(20)]) {
    await assert.rejects(tap.ops.leak_watch.run(null, { cmd: "start", needles }, /** @type {any} */ ({})), /invalid_input/);
  }
  await assert.rejects(tap.ops.leak_watch.run(null, { cmd: "other" }, /** @type {any} */ ({})), /invalid_input/);
});
