// What the Firefox tests of the sync's write side need from the background, in
// the test build only (a folder named test-only: a release leaves it out). Core
// operations, called over the test build's core port:
//
//   item_rename_probe  renames one item with the sync engine, as an edit made
//                      from the revision `rev` (the test's stand-in for a change
//                      saved on this device; the change waits in the outbox and
//                      goes out like any other). The name is one the test made up.
//   item_find_probe    the id and revision of the one item of the open vault whose
//                      name is `name` (a name the test gave a passkey's item in
//                      Ferret's window), or null: the passkey matrix waits with it
//                      for a sync to bring an item in or take it away.
//   item_delete_probe  deletes the item named `name` with the sync engine, as the
//                      person's delete would (a tombstone that goes out like any
//                      other change): "a passkey deleted in one profile is gone in
//                      the other".
//
// They answer with `ok` and at most an id and a revision: never a key, a value or a handle.

/** @param {string} code */
const fail = (code) => Object.assign(new Error(code), { code });

/**
 * The one item of the engine's list whose name is `name` (a test's own name), or null; two of that name are an error.
 * @param {any} running @param {unknown} name
 * @returns {{ id: string, rev: number } | null}
 */
function byName(running, name) {
  if (typeof name !== "string" || name === "" || name.length > 256) throw fail("invalid_input");
  const found = running.list().filter((/** @type {{ name?: string }} */ item) => item.name === name);
  if (found.length > 1) throw fail("ambiguous");
  return found.length === 1 ? { id: found[0].id, rev: found[0].rev } : null;
}

/**
 * @param {{ engine: () => any }} deps `engine`: the sync engine of the open vault, or null
 */
export function createWriteProbe({ engine }) {
  /** The engine of the open vault, or the error a probe gives without one. */
  const engineOf = () => {
    const made = engine();
    if (made === null) throw fail("sync_not_running");
    return made;
  };
  /** @type {Readonly<Record<string, import("../coreHost.mjs").CoreOp>>} */
  const ops = Object.freeze({
    item_rename_probe: {
      vault: true,
      worker: "vault",
      async run(_client, args) {
        const running = engineOf();
        const ok = typeof args?.id === "string" && /^[0-9a-f]{32}$/.test(args.id) && typeof args?.name === "string" &&
          args.name !== "" && args.name.length <= 256 && Number.isSafeInteger(args?.rev) && args.rev > 0;
        if (!ok) throw fail("invalid_input");
        await running.update(args.id, { name: args.name }, args.rev);
        return { ok: true };
      },
    },
    item_find_probe: {
      vault: true,
      worker: "vault",
      async run(_client, args) {
        return { ok: true, item: byName(engineOf(), args?.name) };
      },
    },
    item_delete_probe: {
      vault: true,
      worker: "vault",
      async run(_client, args) {
        const running = engineOf();
        const found = byName(running, args?.name);
        if (found === null) throw fail("not_found");
        await running.remove(found.id);
        return { ok: true, id: found.id };
      },
    },
  });
  return { ops };
}
