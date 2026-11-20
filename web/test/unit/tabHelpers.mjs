// Helpers for the tests of the hand-over between tabs: a browser (the storage, the locks, the channels and a clock that its
// tabs share) with tabs that each have their own sync service, window and document.
import syncService from "../../src/services/sync.service.mjs";
import { ownerName } from "../../src/sync/owner.mjs";
import { serverKey } from "../../src/store/idb.mjs";
import { ACCOUNT, freshStore, SERVER, VAULT } from "./idbHelpers.mjs";
import { createFakeApi, createFakeClient, createFakeStore, FakeChannels, FakeLocks, FakeTimers, Model } from "./syncHelpers.mjs";

export const scope = { accountId: ACCOUNT, vaultId: VAULT, vkEpoch: 1 };
export const NAME = ownerName(serverKey(SERVER), ACCOUNT);

/** A browser: the storage, the locks and the channels that its tabs share, one server, and a clock. */
export async function browser() {
  const db = await freshStore();
  const locks = new FakeLocks();
  const channels = new FakeChannels();
  const clock = new FakeTimers();
  const model = new Model();
  const client = createFakeClient();
  const tabs = [];
  /** A tab: its own service over the shared storage, a window and a document whose visibility the test sets. */
  async function tab({ visible = true } = {}) {
    const win = new Map();
    const doc = {
      visibilityState: visible ? "visible" : "hidden",
      addEventListener: (type, fn) => win.set(type, fn),
      show() {
        doc.visibilityState = "visible";
        win.get("visibilitychange")?.();
      },
      hide() {
        doc.visibilityState = "hidden";
        win.get("visibilitychange")?.();
      },
    };
    const pageWin = { addEventListener: (type, fn) => win.set(type, fn), fire: (type, event = {}) => win.get(type)?.(event) };
    const api = createFakeApi(model);
    const store = await createFakeStore({ db });
    const sync = syncService.create({
      api, store, client: { vault: client.vault }, serverUrl: SERVER, locks, nav: { userAgent: "" }, win: pageWin, doc,
      makeChannel: (name) => channels.channel(name), timers: { setTimeout: clock.set, clearTimeout: clock.clear }, tabId: `tab-${tabs.length + 1}`,
    });
    const standby = [];
    sync.onStandby((on) => standby.push(on));
    const one = { sync, api, store, doc, win: pageWin, standby };
    tabs.push(one);
    return one;
  }
  const stopAll = () => tabs.forEach((t) => t.sync.stop());
  return { db, locks, channels, clock, model, client, tab, stopAll };
}

/** A form with edits that are not saved, as the edit screen registers it. */
export function form(key = "new", { dirty = true } = {}) {
  const state = { dirty, frozen: false, thawed: [] };
  return {
    state,
    key,
    root: { isConnected: true },
    dirty: () => state.dirty,
    freeze: () => {
      state.frozen = true;
    },
    thaw: (next) => state.thawed.push(next),
  };
}

