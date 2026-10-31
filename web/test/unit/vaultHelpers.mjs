// Helpers for the vault screen tests: a DOM walker over the small fake DOM, a
// fake sync engine and a fake worker client, a fake account session, and a
// clock with timers that only move when told. Every secret here is a test value.
import { FakeElement, FakeText, fakeDocument } from "./helpers.mjs";

export { FakeElement, FakeText };

/** Runs an async `fn` with a fake `document` as the global one. */
export async function withDom(fn) {
  const saved = globalThis.document;
  globalThis.document = fakeDocument();
  try {
    return await fn();
  } finally {
    if (saved === undefined) delete globalThis.document;
    else globalThis.document = saved;
  }
}

/** Every node below `root`, `root` included. */
export function* walk(root) {
  yield root;
  for (const child of root.childNodes) yield* walk(child);
}

/** The text of a node and everything below it. */
export function textOf(root) {
  let out = "";
  for (const node of walk(root)) if (node instanceof FakeText) out += `${node.data} `;
  return out;
}

/** Elements with `data-role` (and optionally `data-key`). */
export function all(root, role, key = null) {
  return [...walk(root)].filter(
    (n) => n instanceof FakeElement && n.getAttribute("data-role") === role && (key === null || n.getAttribute("data-key") === key),
  );
}

/** The first element with that role, or null. */
export function find(root, role, key = null) {
  return all(root, role, key)[0] ?? null;
}

/** Calls the listeners of `node` for `type` and waits for them. */
export async function fire(node, type, event = {}) {
  const e = { type, target: node, key: undefined, preventDefault() { this.prevented = true; }, ...event };
  for (const [kind, fn] of [...node.listeners]) if (kind === type) await fn(e);
  return e;
}

export const click = (node) => fire(node, "click");

/** Submits a form: the `onsubmit` handler is stored as a "submit" listener. */
export const submit = (form) => fire(form, "submit");

/** Lets pending promises run. */
export async function settle(turns = 20) {
  for (let i = 0; i < turns; i += 1) await new Promise((resolve) => setImmediate(resolve));
}

/** A clock and a set of timers that only move with `advance`. */
export function fakeClock(start = 1_000_000) {
  const clock = {
    time: start,
    next: 1,
    waiting: [],
    now: () => clock.time,
    setTimeout(fn, ms) {
      const id = clock.next;
      clock.next += 1;
      clock.waiting.push({ id, at: clock.time + ms, fn });
      return id;
    },
    clearTimeout(id) {
      clock.waiting = clock.waiting.filter((t) => t.id !== id);
    },
    get pending() {
      return clock.waiting.length;
    },
    /** Moves the clock and runs the timers that came due, in order. */
    advance(ms) {
      const target = clock.time + ms;
      for (;;) {
        const due = clock.waiting.filter((t) => t.at <= target).sort((a, b) => a.at - b.at || a.id - b.id)[0];
        if (!due) break;
        clock.waiting = clock.waiting.filter((t) => t !== due);
        clock.time = due.at;
        due.fn();
      }
      clock.time = target;
    },
    /** Moves the clock without running any timer: a background tab, or a sleeping laptop. */
    jump(ms) {
      clock.time += ms;
    },
  };
  return clock;
}

/** A page document that only has what the idle lock uses. */
export function fakePage() {
  const listeners = new Set();
  const page = {
    visibilityState: "visible",
    addEventListener: (type, fn) => type === "visibilitychange" && listeners.add(fn),
    removeEventListener: (type, fn) => type === "visibilitychange" && listeners.delete(fn),
    get listening() {
      return listeners.size;
    },
    change(state) {
      page.visibilityState = state;
      for (const fn of [...listeners]) fn();
    },
  };
  return page;
}

/** An error with a code, as the engine, the worker client and the session reject. */
export function coded(code, extra = {}) {
  return Object.assign(new Error(code), { code, ...extra });
}

/** The sync engine as the screens see it. `views` maps an item id to what `item_view` returns. */
export function fakeEngine({ items = [], views = {}, secrets = {} } = {}) {
  const listeners = { changed: new Set(), state: new Set(), error: new Set() };
  const handles = new Map();
  let next = 1;
  const engine = {
    items,
    handles,
    calls: [],
    expectedRevs: [],
    stopped: false,
    list: () => (engine.stopped ? [] : engine.items),
    async open(id) {
      engine.calls.push(["open", id]);
      if (!views[id]) throw coded("not_found");
      const handle = next;
      next += 1;
      handles.set(handle, id);
      return { handle, view: views[id], close: async () => void handles.delete(handle) };
    },
    async create(draft) {
      engine.calls.push(["create", structuredClone(draft)]);
      if (engine.failWith) throw engine.failWith;
      return "ab".repeat(16);
    },
    async update(id, draft, expectedRev) {
      engine.calls.push(["update", id, structuredClone(draft)]);
      engine.expectedRevs.push(expectedRev);
      if (engine.failWith) throw engine.failWith;
    },
    async remove(id) {
      engine.calls.push(["remove", id]);
      if (engine.failWith) throw engine.failWith;
    },
    async discard(id) {
      engine.calls.push(["discard", id]);
    },
    async discardMissing(id) {
      engine.calls.push(["discardMissing", id]);
    },
    stop() {
      engine.stopped = true;
      handles.clear();
      for (const set of Object.values(listeners)) set.clear();
    },
    on(event, fn) {
      listeners[event].add(fn);
      return () => void listeners[event].delete(fn);
    },
    emit(event, payload) {
      for (const fn of [...listeners[event]]) fn(payload);
    },
    listeners,
    failWith: null,
    secrets,
  };
  return engine;
}

/** The worker client's reveal calls over the fake engine's open handles. */
export function fakeClient(engine, { notes = {} } = {}) {
  const calls = [];
  return {
    calls,
    locked: 0,
    vault: {
      async reveal_item_field(handle, index) {
        calls.push(["reveal_item_field", handle, index]);
        const id = engine.handles.get(handle);
        if (id === undefined) throw coded("invalid_handle");
        return engine.secrets[id][index];
      },
      async reveal_item_notes(handle) {
        calls.push(["reveal_item_notes", handle]);
        const id = engine.handles.get(handle);
        if (id === undefined) throw coded("invalid_handle");
        return notes[id] ?? "";
      },
    },
  };
}

/** An account session with the surface the vault screens use. */
export function fakeSession({ client = null, open = true, info = { accountId: "aa".repeat(16), email: "ada@example.test" }, status = { pinned: true, skBit: true, skStored: true } } = {}) {
  const listeners = new Set();
  const session = {
    client,
    isOpen: open,
    locked: 0,
    unlocks: [],
    unlockError: null,
    attached: null,
    current: () => (session.isOpen ? { accountId: info?.accountId, vaultId: "bb".repeat(16), vkEpoch: 1, email: info?.email } : null),
    attachSync: (sync) => {
      session.attached = sync;
    },
    info: async () => info,
    deviceStatus: async () => status,
    async unlock(args) {
      session.unlocks.push({ ...args });
      if (session.unlockError) throw session.unlockError;
      session.isOpen = true;
    },
    async lock() {
      session.locked += 1;
      session.isOpen = false;
      if (session.client) session.client.locked += 1;
      for (const fn of [...listeners]) fn();
    },
    onLock(fn) {
      listeners.add(fn);
      return () => void listeners.delete(fn);
    },
  };
  return session;
}

/** A translate function that shows the key and the variables, so tests read keys. */
export const t = (key, vars) => (vars ? `${key} ${JSON.stringify(vars)}` : key);
