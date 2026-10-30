// The short-lived worker for the slow step of an export or an import file
// (Argon2id with up to 512 MiB). It answers one call and the page ends it, so
// that the large heap is freed. It never sees a vault key.
import init, * as wasm from "../pkg-web/ferret_core_wasm.js";
import { createJobDispatcher } from "./protocol.mjs";

const ready = init().then(() => createJobDispatcher(wasm));

self.onmessage = async (event) => {
  let dispatch;
  try {
    dispatch = await ready;
  } catch {
    // The module did not load: every call gets an answer instead of waiting.
    self.postMessage({ id: event.data?.id, ok: false, code: "worker_failed" });
    return;
  }
  const { reply, transfer } = dispatch(event.data);
  self.postMessage(reply, transfer);
};
