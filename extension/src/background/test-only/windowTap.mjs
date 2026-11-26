// The exact count of Ferret's chooser windows for the passkey matrix (extension/test/firefox/passkeyMatrix.mjs), in the test build
// only (a folder named test-only: a release leaves it out). The background page's chooser windows are made through the
// `windows` object the test hooks hand it (`tap`), so every window is counted when it is asked for, also one that opens and closes
// again before a runner could see it. A core operation, called over the test build's core port:
//
//   window_watch  { cmd: "reset" } starts the count again; { cmd: "read" } answers how many chooser windows were asked for since
//                 (`opened`) and the most that were open at once (`most`, a window counts from the moment it is asked for until
//                 the background asks to remove it, which it does whenever its request ends). A reset forgets the windows open before it.
//
// It adds no listener (a listener of the browser's would wake a Manifest V3 event page and change what the lifetime
// measurement sees).
//
// It answers with a count only.

/** @param {string} code */
const fail = (code) => Object.assign(new Error(code), { code });

/** The counter, and the `windows` object that counts. */
export function createWindowTap() {
  const state = { opened: 0, most: 0, asking: 0 };
  /** The chooser windows open now. @type {Set<number>} */
  const open = new Set();
  const count = () => {
    state.most = Math.max(state.most, open.size + state.asking);
  };

  /**
   * The browser's `windows`, with each `create` counted.
   * @param {{ create(o: any): Promise<any>, remove(id: number): Promise<void> }} windows
   * @returns {{ create(o: any): Promise<any>, remove(id: number): Promise<void> }}
   */
  const tap = (windows) => {
    return {
      create: async (o) => {
        state.opened += 1;
        state.asking += 1;
        count();
        try {
          const made = await windows.create(o);
          if (Number.isInteger(made?.id)) open.add(made.id);
          return made;
        } finally {
          state.asking -= 1;
          count();
        }
      },
      // A window counts as gone when the background asks to remove it.
      remove: (id) => {
        open.delete(id);
        return windows.remove(id);
      },
    };
  };

  /** @type {Readonly<Record<string, import("../coreHost.mjs").CoreOp>>} */
  const ops = Object.freeze({
    window_watch: {
      vault: false,
      worker: "none",
      async run(_client, args) {
        if (args?.cmd === "reset") {
          state.opened = 0;
          open.clear();
          state.most = state.asking;
          return { ok: true };
        }
        if (args?.cmd === "read") return { ok: true, opened: state.opened, most: state.most };
        throw fail("invalid_input");
      },
    },
  });
  return { ops, tap };
}
