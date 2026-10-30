// The account session as a service: registration, sign-in, unlock, lock and
// sign-out over the crypto client, the API client and the local stores.
import { createCryptoSession } from "../crypto/session.mjs";

/** @type {import("../app.mjs").ServiceDef} */
export default {
  name: "crypto",
  deps: ["api", "store", "client"],
  create: ({ api, store, client }) => createCryptoSession({ client, api, store }),
};
