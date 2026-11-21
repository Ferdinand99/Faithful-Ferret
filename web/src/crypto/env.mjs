// The things the account flows are given. One object, made by the session.
//
// @typedef Env
//   client   the crypto client (the vault worker): `client.vault.<method>`, `client.lock()`
//   api      the API client
//   store    the store service: `open()` and the functions that take its handle
//   server   the vault's address as one canonical origin (the only form that reaches the core or the store)
//   lock     the session's lock; the flows end the worker only through it
//   now      the clock, in milliseconds
//   rand     fills a byte array with random values
//   secrets  options for the sealing of the secret key (WebCrypto and the random source), for tests
//   createImportWorker  makes the import worker; only a page that imports needs it
//   mode     "cookie" (the web vault, the default) or "device" (a device client: the extension)
//   deviceName  what the server calls this client in the list of devices
//   platform    a device's platform, one of the wire's words (a device only)
//   tokens   a device's tokens (`auth/tokens.mjs`): its sign-in, its sign-out (a device only)
//   deviceKey   a device's key, new for this sign-in (`auth/deviceKey.mjs`; a device only)

/**
 * @typedef {object} Env
 * @property {any} client
 * @property {import("../api.mjs").Api} api
 * @property {any} store
 * @property {string} server
 * @property {() => Promise<void>} lock the session's lock: stops the sync engine, forgets the open account, tells the lock listeners and ends the worker
 * @property {() => number} now
 * @property {(bytes: Uint8Array<ArrayBuffer>) => Uint8Array<ArrayBuffer>} rand
 * @property {import("../flows/deviceSecret.mjs").Env} [secrets]
 * @property {() => any} [createImportWorker] makes the import worker (the page's own file, through the Trusted Types policy)
 * @property {"cookie" | "device"} [mode] left out: "cookie"
 * @property {string} [deviceName] left out: the web vault's name
 * @property {string} [platform]
 * @property {import("../auth/tokens.mjs").TokenAuth} [tokens]
 * @property {import("../auth/deviceKey.mjs").DeviceKey} [deviceKey]
 */

/**
 * @typedef {object} Unlocked
 * @property {string} accountId
 * @property {string} vaultId
 * @property {number} vkEpoch
 * @property {string} email
 * @property {Record<string, any>} pinned
 * @property {"saved" | "unavailable" | "forgotten" | "unchanged"} [secretKey] what became of the remembered secret key
 * @property {"login" | "reauth"} [purpose] which kind of sign-in opened the vault
 */

export {};
