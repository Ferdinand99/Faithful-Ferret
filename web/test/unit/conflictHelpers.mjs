// A fake of the engine's conflict surface and of the worker's reveal calls, for
// the conflict view and the trash view. Every secret here is a test value.
import { coded } from "./vaultHelpers.mjs";

export const ID = "11".repeat(16);
export const OTHER = "22".repeat(16);
export const MINE_PASSWORD = "mine-PASSWORD-1";
export const THEIR_PASSWORD = "their-PASSWORD-2";
export const MINE_PIN = "mine-PIN-3";
export const THEIR_PIN = "their-PIN-4";
export const MINE_NOTES = "mine-NOTES-5";
export const THEIR_NOTES = "their-NOTES-6";
export const MODIFIED_MINE = 1_700_000_000_000;
export const MODIFIED_THEIRS = 1_700_000_600_000;

/** The core's view of a login: the user name shows, the rest is hidden. */
export function loginView(overrides = {}) {
  return {
    item_type: "login",
    name: "Bank",
    fields: [
      { id: "username", label: "User name", kind: "text", value: "ada" },
      { id: "password", label: "Password", kind: "password", value: null },
      { id: "pin", label: "PIN", kind: "hidden", value: null },
    ],
    urls: [{ url: "https://bank.example", matching: "host" }],
    has_totp: false,
    passkey: null,
    has_notes: true,
    favorite: false,
    modified: MODIFIED_MINE,
    device: "Firefox on Windows",
    read_only: false,
    ...overrides,
  };
}

/** What the engine compares: the user name is the same, the hidden ones are not compared. */
export const FIELDS = Object.freeze([
  { key: "username", label: "User name", kind: "text", same: true },
  { key: "password", label: "Password", kind: "password", same: null },
  { key: "pin", label: "PIN", kind: "hidden", same: null },
]);

/**
 * An engine with conflicts. `conflicts` maps an item id to `{ local, server, fields, secrets }`;
 * `secrets` maps "local" or "server" to the hidden values of that version by field id.
 */
export function fakeConflictEngine({ conflicts = {}, trash = [] } = {}) {
  /** @type {Record<string, Set<Function>>} */
  const listeners = {};
  const handles = new Map();
  let next = 100;
  const engine = {
    handles,
    calls: [],
    seenArgs: [], // the third argument of every resolve
    closed: 0,
    items: [],
    trashed: trash.map((e) => ({ ...e })),
    failWith: null,
    failConflict: null,
    onResolve: null,
    list: () => engine.items,
    on(event, fn) {
      (listeners[event] ??= new Set()).add(fn);
      return () => void listeners[event].delete(fn);
    },
    emit(event, payload) {
      for (const fn of [...(listeners[event] ?? [])]) fn(payload);
    },
    listeners,
    async conflict(id) {
      engine.calls.push(["conflict", id]);
      if (engine.failConflict) throw engine.failConflict;
      const spec = conflicts[id];
      if (!spec) throw coded("not_found");
      const sides = {};
      const opened = [];
      for (const name of ["local", "server"]) {
        const side = spec[name];
        const handle = next;
        next += 1;
        handles.set(handle, { id, side: name, secrets: spec.secrets?.[name] ?? {}, view: side.view });
        opened.push(handle);
        sides[name] = { rev: side.rev ?? 1, deleted: side.deleted === true, view: side.view ?? null, handle };
      }
      let closedOnce = false;
      return {
        ...sides,
        fields: spec.fields ?? FIELDS,
        seen: spec.seen ?? { rev: spec.server.rev ?? 1, deleted: spec.server.deleted === true },
        async close() {
          if (closedOnce) return;
          closedOnce = true;
          engine.closed += 1;
          for (const handle of opened) handles.delete(handle);
        },
      };
    },
    async resolve(id, choice, seen) {
      engine.calls.push(["resolve", id, choice]);
      engine.seenArgs.push(seen);
      if (engine.onResolve) await engine.onResolve(id, choice);
      if (engine.failWith) throw engine.failWith;
    },
    async keepMine(id) {
      engine.calls.push(["keepMine", id]);
      if (engine.failWith) throw engine.failWith;
    },
    async trash() {
      engine.calls.push(["trash"]);
      if (engine.failTrash) throw engine.failTrash;
      return engine.trashed.map((e) => ({ ...e }));
    },
    async restoreFromTrash(id) {
      engine.calls.push(["restoreFromTrash", id]);
      if (engine.failWith) throw engine.failWith;
      engine.trashed = engine.trashed.filter((e) => e.id !== id);
    },
    async removeFromTrash(id) {
      engine.calls.push(["removeFromTrash", id]);
      if (engine.failWith) throw engine.failWith;
      engine.trashed = engine.trashed.filter((e) => e.id !== id);
    },
  };
  return engine;
}

/** The worker's reveal calls over the handles the fake engine has open. */
export function fakeReveal(engine) {
  const client = {
    calls: [],
    delay: null,
    vault: {
      async reveal_item_field(handle, index) {
        client.calls.push(["reveal_item_field", handle, index]);
        if (client.delay) await client.delay;
        const open = engine.handles.get(handle);
        if (!open) throw coded("invalid_handle");
        const field = open.view.fields[index];
        return open.secrets[field.id];
      },
      async reveal_item_notes(handle) {
        client.calls.push(["reveal_item_notes", handle]);
        if (client.delay) await client.delay;
        const open = engine.handles.get(handle);
        if (!open) throw coded("invalid_handle");
        return open.secrets.notes;
      },
    },
  };
  return client;
}

/** The usual conflict: both versions of the bank item changed, with their own passwords. */
export function bankConflict(extra = {}) {
  return {
    local: { rev: 3, view: loginView({ modified: MODIFIED_MINE, device: "Firefox on Windows" }) },
    server: { rev: 4, view: loginView({ modified: MODIFIED_THEIRS, device: "Safari on iPhone" }) },
    secrets: {
      local: { password: MINE_PASSWORD, pin: MINE_PIN, notes: MINE_NOTES },
      server: { password: THEIR_PASSWORD, pin: THEIR_PIN, notes: THEIR_NOTES },
    },
    ...extra,
  };
}
