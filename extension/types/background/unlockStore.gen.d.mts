// The type of background/unlockStore.gen.mjs, which scripts/build.mjs writes into every package: the PIN store when the
// `unlock` feature is on, `null` when it is off.
export declare const createLocalUnlock: typeof import("../../src/background/localUnlock.mjs").createLocalUnlock | null;
export declare const UNLOCK_WINDOW_PAGE: string | null;
