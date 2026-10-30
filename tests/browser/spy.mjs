// A wrapper around a module Worker that records every message in both
// directions, for the test that no vault secret leaves the vault worker.
//
// * `snapshot(value)` flattens a message the way the Node walker does: byte
//   values (every TypedArray, DataView and ArrayBuffer, and arrays of byte
//   numbers) and strings are the leaves; a Map or a Set is walked (keys and
//   values), objects by their own keys. Bytes are copied at the time of the
//   call, because the client wipes and transfers its buffers right after.
// * `SpyWorker` has the surface the client uses (`postMessage`, `terminate`,
//   `onmessage`, `onerror`, `onmessageerror`). Replies of a probe (see
//   `probe.worker.mjs`) are not recorded: they carry test secrets on purpose.

const toHex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, "0")).join("");

/** The leaves of a message: `{ path, hex }` for bytes, `{ path, text }` for strings. */
export function snapshot(value, path = "", out = [], depth = 0) {
  if (depth > 16) throw new Error(`${path}: message too deep`);
  if (value instanceof ArrayBuffer) {
    out.push({ path: `${path}<ArrayBuffer>`, hex: toHex(new Uint8Array(value)) });
  } else if (ArrayBuffer.isView(value)) {
    const kind = value instanceof Uint8Array ? "" : `<${value.constructor.name}>`;
    out.push({
      path: `${path}${kind}`,
      hex: toHex(new Uint8Array(value.buffer, value.byteOffset, value.byteLength)),
    });
  } else if (Array.isArray(value)) {
    if (value.length >= 8 && value.every((n) => Number.isInteger(n) && n >= 0 && n < 256)) {
      out.push({ path: `${path}(numbers)`, hex: toHex(Uint8Array.from(value)) });
    } else {
      for (const v of value) snapshot(v, `${path}[]`, out, depth + 1);
    }
  } else if (typeof value === "string") {
    out.push({ path, text: value });
  } else if (value instanceof Map) {
    for (const [k, v] of value) {
      snapshot(k, `${path}{key}`, out, depth + 1);
      snapshot(v, `${path}{}`, out, depth + 1);
    }
  } else if (value instanceof Set) {
    for (const v of value) snapshot(v, `${path}{}`, out, depth + 1);
  } else if (value !== null && typeof value === "object") {
    for (const key of Object.keys(value)) {
      snapshot(value[key], path ? `${path}.${key}` : key, out, depth + 1);
    }
  }
  return out;
}

/** What the spies saw: messages, and which workers were created and ended. */
export class Recorder {
  constructor() {
    this.messages = [];
    this.workers = [];
  }

  /** The recorded messages, as plain data for the test process. */
  dump() {
    return this.messages;
  }
}

export class SpyWorker {
  /**
   * @param label    "vault" or "job"
   * @param url      the module worker to start
   * @param recorder a Recorder
   */
  constructor(label, url, recorder) {
    this.label = label;
    this.recorder = recorder;
    this.terminated = false;
    this.raw = new Worker(url, { type: "module" });
    this.methods = new Map();
    this.handler = null;
    this.probes = new Map();
    this.nextProbe = 1;
    recorder.workers.push(this);
    this.raw.addEventListener("message", (event) => {
      const data = event.data;
      if (data && data.probe === true) {
        const waiter = this.probes.get(data.probeId);
        if (waiter) {
          this.probes.delete(data.probeId);
          waiter(data);
        }
        return;
      }
      recorder.messages.push({
        worker: label,
        dir: "in",
        method: this.methods.get(data?.id) ?? null,
        leaves: snapshot(data),
      });
      this.handler?.(event);
    });
  }

  set onmessage(fn) {
    this.handler = fn;
  }

  get onmessage() {
    return this.handler;
  }

  set onerror(fn) {
    this.raw.onerror = fn;
  }

  set onmessageerror(fn) {
    this.raw.onmessageerror = fn;
  }

  postMessage(message, transfer = []) {
    this.recorder.messages.push({
      worker: this.label,
      dir: "out",
      method: message?.method ?? null,
      leaves: snapshot(message),
    });
    if (message && message.id !== undefined) this.methods.set(message.id, message.method ?? null);
    this.raw.postMessage(message, transfer);
  }

  terminate() {
    this.terminated = true;
    this.raw.terminate();
  }

  /** A message to the probe worker that is not recorded. Resolves with the probe reply. */
  probe(message) {
    return new Promise((resolve, reject) => {
      const probeId = this.nextProbe++;
      const timer = setTimeout(() => {
        this.probes.delete(probeId);
        reject(new Error(`probe ${message.op} timed out`));
      }, 60_000);
      this.probes.set(probeId, (reply) => {
        clearTimeout(timer);
        resolve(reply);
      });
      this.raw.postMessage({ ...message, probe: true, probeId });
    });
  }
}
