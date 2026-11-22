// The address of a folder's page. A folder's name is an encrypted label of the vault, and the address stays in the
// browser's history (on disk), so the name is never put in it: the page of a folder is `#/folders/<token>`, where the
// token is a random word that this page made for that folder and keeps in memory only. The tokens are forgotten when
// the vault locks; an old address then leads to the list of folders, never to another folder.
import { foldKey } from "../folders.mjs";

/** A token: 16 lower-case hex characters. */
export const TOKEN = /^[0-9a-f]{16}$/;

/** The token of each folder (by its key), and the key of each token. */
const tokens = new Map();
const keys = new Map();

/** More folders than this are never given a token in one session (a vault has far fewer). */
const MAX_TOKENS = 10_000;

/** @returns {string} */
function freshToken() {
  const bytes = new Uint8Array(8);
  globalThis.crypto.getRandomValues(bytes);
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * The token of a folder, made the first time it is asked for.
 * @param {string} name
 * @returns {string}
 */
export function tokenFor(name) {
  const key = foldKey(name);
  const known = tokens.get(key);
  if (known !== undefined) return known;
  if (tokens.size >= MAX_TOKENS) clearFolderLinks();
  let token = freshToken();
  while (keys.has(token)) token = freshToken();
  tokens.set(key, token);
  keys.set(token, key);
  return token;
}

/** The address of a folder's page. @param {string} name */
export const folderHref = (name) => `#/folders/${tokenFor(name)}`;

/**
 * The key of the folder a token was made for, or null (an address from before a lock, or one that was never made here).
 * @param {unknown} token
 * @returns {string | null}
 */
export function keyOfToken(token) {
  return typeof token === "string" && TOKEN.test(token) ? keys.get(token) ?? null : null;
}

/** Forgets every token (the vault locked). */
export function clearFolderLinks() {
  tokens.clear();
  keys.clear();
}
