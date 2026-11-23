// What the Firefox tests of the sync's write side need from the background, in
// the test build only (a folder named test-only: a release leaves it out). A
// core operation, called over the test build's core port:
//
//   item_rename_probe  renames one item with the sync engine, as an edit made
//                      from the revision `rev` (the test's stand-in for a change
//                      saved on this device; the change waits in the outbox and
//                      goes out like any other). The name is one the test made up.
//
// It answers with nothing but `ok`: never a key, a value or a handle.

/** @param {string} code */
const fail = (code) => Object.assign(new Error(code), { code });

/**
 * @param {{ engine: () => any }} deps `engine`: the sync engine of the open vault, or null
 */
export function createWriteProbe({ engine }) {
  /** @type {Readonly<Record<string, import("../coreHost.mjs").CoreOp>>} */
  const ops = Object.freeze({
    item_rename_probe: {
      vault: true,
      worker: "vault",
      async run(_client, args) {
        const running = engine();
        if (running === null) throw fail("sync_not_running");
        const ok = typeof args?.id === "string" && /^[0-9a-f]{32}$/.test(args.id) && typeof args?.name === "string" &&
          args.name !== "" && args.name.length <= 256 && Number.isSafeInteger(args?.rev) && args.rev > 0;
        if (!ok) throw fail("invalid_input");
        await running.update(args.id, { name: args.name }, args.rev);
        return { ok: true };
      },
    },
  });
  return { ops };
}
