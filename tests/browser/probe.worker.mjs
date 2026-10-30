// The shipped vault worker (bindings/wasm/js/vault.worker.mjs, unchanged, on
// the build with `test-support`), plus a probe channel for the tests.
//
// This file imports the shipped worker, which sets `self.onmessage` and starts
// the WASM module. A normal message goes to that handler untouched. A message
// with `probe: true` is the test talking to the worker directly: it can read
// the vault key out of this instance's memory (the page cannot, the memory is
// the worker's), ask for a key the dispatcher does not return (the item key,
// the private scalar of a passkey), and make the worker post a message of the
// test's choosing.
//
// The probe asks the shipped handler for the test methods like any caller
// would, with a negative request id, and takes the reply before it is posted
// to the page. The page's spy therefore never sees a probe reply, and the
// dispatcher, the vault and the memory are those of the shipped worker (the
// module is one instance per worker, so `test_read_memory` reads the same
// memory).
import "/test/js/vault.worker.mjs";
import * as wasm from "/test/pkg-web/ferret_core_wasm.js";

const shipped = self.onmessage;
if (typeof shipped !== "function") throw new Error("the shipped vault worker did not set onmessage");

const post = self.postMessage.bind(self);
const waiting = new Map();
// Replies to probe requests (negative ids) stay in this worker.
self.postMessage = (message, transfer) => {
  const waiter = message && typeof message.id === "number" && message.id < 0 ? waiting.get(message.id) : undefined;
  if (waiter) {
    waiting.delete(message.id);
    waiter(message);
  } else {
    post(message, transfer);
  }
};

let nextId = -1;
const viaShipped = (method, args) =>
  new Promise((resolve) => {
    const id = nextId--;
    waiting.set(id, resolve);
    shipped({ data: { id, target: "vault", method, args } });
  });

const toHex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, "0")).join("");

async function region() {
  const r = await viaShipped("test_vk_region", []);
  if (!r.ok) throw new Error(`test_vk_region: ${r.code}`);
  return r.value;
}

async function probe(data) {
  switch (data.op) {
    case "vk": {
      const [ptr, len] = await region();
      return { vk: toHex(wasm.test_read_memory(ptr, len)) };
    }
    case "call": {
      // A vault method of the dispatcher (`test_item_key`, `test_passkey_secret`).
      const r = await viaShipped(data.method, data.args);
      if (!r.ok) throw new Error(`${data.method}: ${r.code}`);
      return { value: r.value instanceof Uint8Array ? toHex(r.value) : r.value };
    }
    case "lock_wipe": {
      // The key region before and after `lock`: the second must be all zero.
      const [ptr, len] = await region();
      const before = toHex(wasm.test_read_memory(ptr, len));
      const r = await viaShipped("lock", []);
      if (!r.ok) throw new Error(`lock: ${r.code}`);
      return { before, after: toHex(wasm.test_read_memory(ptr, len)) };
    }
    case "emit":
      // A reply (not a probe reply) with a payload of the test's choosing.
      post({ id: data.id, ok: true, value: data.value });
      return { emitted: true };
    default:
      throw new Error(`unknown probe ${data.op}`);
  }
}

self.onmessage = async (event) => {
  const data = event.data;
  if (data && data.probe === true) {
    try {
      const out = await probe(data);
      post({ probe: true, probeId: data.probeId, ok: true, ...out });
    } catch (e) {
      post({ probe: true, probeId: data.probeId, ok: false, error: String(e?.message ?? e) });
    }
    return;
  }
  shipped(event);
};
