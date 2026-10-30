// The things the account flows are given. One object, made by the session.
//
// @typedef Env
//   client   the crypto client (the vault worker): `client.vault.<method>`, `client.lock()`
//   api      the API client
//   store    the store service: `open()` and the functions that take its handle
//   server   the vault's address as one canonical origin (the only form that reaches the core or the store)
//   now      the clock, in milliseconds
//   rand     fills a byte array with random values
//   secrets  options for the sealing of the secret key (WebCrypto and the random source), for tests

/**
 * @typedef {object} Env
 * @property {any} client
 * @property {import("../api.mjs").Api} api
 * @property {any} store
 * @property {string} server
 * @property {() => number} now
 * @property {(bytes: Uint8Array) => Uint8Array} rand
 * @property {import("../flows/deviceSecret.mjs").Env} [secrets]
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
