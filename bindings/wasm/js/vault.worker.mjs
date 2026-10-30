// The long-lived crypto worker: it holds the Vault and the UnlockJob. Argon2id
// of the sign-in, the registration, the PIN and the recovery runs here, so the
// keys never leave WASM memory. `client.lock()` ends this worker, which frees
// the heap (it stays at its high-water mark until then).
import init, * as wasm from "../pkg-web/ferret_core_wasm.js";
import { createDispatcher } from "./protocol.mjs";

const ready = init().then(() => createDispatcher(wasm));

self.onmessage = async (event) => {
  const dispatch = await ready;
  const { reply, transfer } = dispatch(event.data);
  self.postMessage(reply, transfer);
};
