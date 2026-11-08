// One file per feature.
//
// A feature adds `<feature>.handler.mjs` in this folder and touches no other
// file. The file's default export is
//
//     export default { types: ["..."], channel: "ui" | "content", handle(body, ctx) }
//
// - `types` are message types from the table of the channel (`UI_TYPES` for
//   "ui", `CONTENT_TYPES` for "content") in `src/shared/protocol.mjs`.
// - `handle` receives the checked body and a context that the router builds.
//   The router has already checked the sender and decoded the message.
//
// The router reads a generated register of these files. There is no central
// list and no central `switch`: two features never edit the same file.
//
// A handler for the test build only goes in the test folder that scripts/build.mjs
// names (TEST_ONLY_DIR), below this one: a release
// leaves it out. A handler never answers a refusal itself: it returns its
// reply, or throws, and the router sends the typed `refused` reply.
//
// This file holds only the rule above. The build accepts only `.mjs` and
// `.html` files under `src`, so the rule is a comment in a module with no code.
export {};
