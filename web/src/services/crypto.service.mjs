// The account session as a service: registration, sign-in, unlock, lock and
// sign-out over the crypto client, the API client and the local stores.
import { createVaultSession } from "../crypto/vaultSession.mjs";

/** @type {import("../app.mjs").ServiceDef} */
export default {
  name: "crypto",
  deps: ["api", "store", "client", "sync", "createImportWorker"],
  create: ({ api, store, client, sync, createImportWorker }) => createVaultSession({ client, api, store, sync, createImportWorker }),
};
