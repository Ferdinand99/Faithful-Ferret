// The vault worker of bindings/wasm/js/vault.worker.mjs on the build with
// `test-support`, plus a probe channel for the tests.
//
// A normal message goes to the real dispatcher, exactly as in the production
// worker. A message with `probe: true` is the test talking to the worker
// directly: it can read the vault key out of this instance's memory (the
// page cannot, the memory is the worker's), ask for a key the dispatcher
// does not return (the item key, the private scalar of a passkey), and
// make the worker post a message of the test's choosing. Probe replies carry
// `probe: true`; the page's spy does not record them.
import init, * as wasm from "/test/pkg-web/ferret_core_wasm.js";
import { createDispatcher } from "/test/js/protocol.mjs";

const ready = init().then(() => createDispatcher(wasm));

const toHex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, "0")).join("");

function vaultRegion(dispatch) {
  const r = dispatch({ id: 0, target: "vault", method: "test_vk_region", args: [] }).reply;
  if (!r.ok) throw new Error(`test_vk_region: ${r.code}`);
  return r.value;
}

async function probe(data) {
  const dispatch = await ready;
  switch (data.op) {
    case "vk": {
      const [ptr, len] = vaultRegion(dispatch);
      return { vk: toHex(wasm.test_read_memory(ptr, len)) };
    }
    case "call": {
      // A vault method of the dispatcher (`test_item_key`, `test_passkey_secret`).
      const r = dispatch({ id: 0, target: "vault", method: data.method, args: data.args }).reply;
      if (!r.ok) throw new Error(`${data.method}: ${r.code}`);
      return { value: r.value instanceof Uint8Array ? toHex(r.value) : r.value };
    }
    case "lock_wipe": {
      // The key region before and after `lock`: the second must be all zero.
      const [ptr, len] = vaultRegion(dispatch);
      const before = toHex(wasm.test_read_memory(ptr, len));
      const r = dispatch({ id: 0, target: "vault", method: "lock", args: [] }).reply;
      if (!r.ok) throw new Error(`lock: ${r.code}`);
      return { before, after: toHex(wasm.test_read_memory(ptr, len)) };
    }
    case "emit":
      // A reply (not a probe reply) with a payload of the test's choosing.
      self.postMessage({ id: data.id, ok: true, value: data.value });
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
      self.postMessage({ probe: true, probeId: data.probeId, ok: true, ...out });
    } catch (e) {
      self.postMessage({ probe: true, probeId: data.probeId, ok: false, error: String(e?.message ?? e) });
    }
    return;
  }
  let dispatch;
  try {
    dispatch = await ready;
  } catch {
    self.postMessage({ id: data?.id, ok: false, code: "worker_failed" });
    return;
  }
  const { reply, transfer } = dispatch(data);
  self.postMessage(reply, transfer);
};
