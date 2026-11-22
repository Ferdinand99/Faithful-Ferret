// The self-distributed updates of the signed release build (Firefox, unlisted).
//
// Every release manifest carries `browser_specific_settings.gecko.update_url` =
// UPDATE_URL. Firefox fetches that file (the update manifest) now and then and
// installs a newer version that it lists, after it has checked the file it
// downloads against `update_hash` and Mozilla's signature.
//
// Where the files live (the GitHub releases of this repository, never a `v*` tag,
// which belong to the core releases, and never marked as the latest release):
//
//   - the update manifest: the asset `updates.json` of the release with the fixed
//     tag `extension-updates`, replaced by each publication. Its URL depends on the
//     repository name only, and it goes into every release build, so it must not
//     change: an installed build keeps asking the URL it was built with.
//   - the signed package of version V: the asset
//     `ferret-firefox-mv2-release-V-signed.xpi` of the release `extension-vV`.
//
// The writer below keeps every older entry, adds the new version only when it is
// newer than every listed one, and refuses an update manifest that is not in the
// exact shape it writes (fail closed: a hand-edited or damaged file stops the
// publication instead of being carried forward).

/** The GitHub repository that hosts the releases. */
export const REPOSITORY = "Ferdinand99/Faithful-Ferret";

/** The add-on id of every release (the update manifest is keyed by it). */
export const RELEASE_ID = "ferret@hedgerow.tools";

/** The fixed tag of the release that holds the update manifest. */
export const UPDATES_TAG = "extension-updates";

/** The name of the update manifest asset. */
export const UPDATES_ASSET = "updates.json";

/** The update manifest URL that every release build carries. Never change it: installed builds keep the old one. */
export const UPDATE_URL = `https://github.com/${REPOSITORY}/releases/download/${UPDATES_TAG}/${UPDATES_ASSET}`;

/** A plain dotted version, as AMO and the manifest use it (one to four numbers, no leading zeros). */
const VERSION = /^(?:0|[1-9][0-9]{0,8})(?:\.(?:0|[1-9][0-9]{0,8})){0,3}$/;

/** @param {unknown} version @returns {version is string} */
export function isVersion(version) {
  return typeof version === "string" && VERSION.test(version);
}

/**
 * The tag of the release that holds the signed package of `version`.
 * @param {string} version
 */
export function releaseTag(version) {
  if (!isVersion(version)) throw new Error(`not a plain dotted version: ${JSON.stringify(version)}`);
  return `extension-v${version}`;
}

/**
 * The name of the signed package asset of `version` (the name the sign job gives it).
 * @param {string} version
 */
export function assetName(version) {
  if (!isVersion(version)) throw new Error(`not a plain dotted version: ${JSON.stringify(version)}`);
  return `ferret-firefox-mv2-release-${version}-signed.xpi`;
}

/**
 * The HTTPS link to the signed package of `version`.
 * @param {string} version
 */
export function updateLink(version) {
  return `https://github.com/${REPOSITORY}/releases/download/${releaseTag(version)}/${assetName(version)}`;
}

/**
 * Compares two plain dotted versions numerically (a missing part counts as 0).
 * @param {string} a @param {string} b
 * @returns {number} below 0, 0 or above 0
 */
export function compareVersions(a, b) {
  if (!isVersion(a) || !isVersion(b)) throw new Error(`not plain dotted versions: ${JSON.stringify(a)}, ${JSON.stringify(b)}`);
  // The numbers of a checked version (isVersion above): its runs of digits.
  const pa = (a.match(/[0-9]+/g) ?? []).map(Number);
  const pb = (b.match(/[0-9]+/g) ?? []).map(Number);
  for (let i = 0; i < 4; i += 1) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d !== 0) return d;
  }
  return 0;
}

/** @param {unknown} value @returns {value is Record<string, unknown>} */
const isObject = (value) => typeof value === "object" && value !== null && !Array.isArray(value);

/** @param {Record<string, unknown>} value @param {string[]} keys */
const hasExactly = (value, keys) => {
  const own = Object.keys(value).sort();
  return own.length === keys.length && [...keys].sort().every((k, i) => own[i] === k);
};

/** @typedef {{ version: string, update_link: string, update_hash: string }} UpdateEntry */

/**
 * Checks one entry: exactly the three keys, a plain version, the HTTPS link this
 * repository gives that version, and a SHA-256 hash. Returns the problem, or "".
 * @param {unknown} entry
 * @returns {string}
 */
export function entryProblem(entry) {
  if (!isObject(entry) || !hasExactly(entry, ["update_hash", "update_link", "version"])) {
    return "an entry must have exactly version, update_link and update_hash";
  }
  const { version, update_link: link, update_hash: hash } = entry;
  if (!isVersion(version)) return `the version ${JSON.stringify(version)} is not a plain dotted version`;
  if (typeof link !== "string" || !link.startsWith("https://")) return `the update_link of ${version} is not an HTTPS link`;
  if (link !== updateLink(version)) return `the update_link of ${version} is not ${updateLink(version)}`;
  if (typeof hash !== "string" || !/^sha256:[0-9a-f]{64}$/.test(hash)) return `the update_hash of ${version} is not sha256:<64 lower-case hex>`;
  return "";
}

/**
 * Reads an update manifest written by `appendUpdate` and returns its entries.
 * Anything else (another add-on, another key, an entry in another shape, versions
 * out of order or twice) is refused.
 * @param {string} text
 * @returns {UpdateEntry[]}
 */
export function parseUpdates(text) {
  /** @type {unknown} */
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    throw new Error("updates.json: not valid JSON");
  }
  if (!isObject(data) || !hasExactly(data, ["addons"]) || !isObject(data.addons) || !hasExactly(data.addons, [RELEASE_ID])) {
    throw new Error(`updates.json: expected { "addons": { "${RELEASE_ID}": { "updates": [...] } } } and nothing else`);
  }
  const addon = data.addons[RELEASE_ID];
  if (!isObject(addon) || !hasExactly(addon, ["updates"]) || !Array.isArray(addon.updates)) {
    throw new Error(`updates.json: the entry of ${RELEASE_ID} must have exactly an updates list`);
  }
  /** @type {UpdateEntry[]} */
  const entries = [];
  for (const entry of addon.updates) {
    const problem = entryProblem(entry);
    if (problem) throw new Error(`updates.json: ${problem}`);
    const typed = /** @type {UpdateEntry} */ (entry);
    const last = entries.at(-1);
    if (last && compareVersions(last.version, typed.version) >= 0) {
      throw new Error(`updates.json: ${typed.version} comes after ${last.version} (the versions must rise)`);
    }
    entries.push(typed);
  }
  return entries;
}

/**
 * The text of an update manifest with these entries (oldest first).
 * @param {UpdateEntry[]} entries
 * @returns {string}
 */
export function formatUpdates(entries) {
  const updates = entries.map(({ version, update_link: link, update_hash: hash }) => ({ version, update_link: link, update_hash: hash }));
  return `${JSON.stringify({ addons: { [RELEASE_ID]: { updates } } }, null, 2)}\n`;
}

/**
 * Adds `version` to the update manifest `previous` (null: there is none yet) and
 * returns the new text. Every older entry is kept as it was. The new version must
 * be newer than every listed one; the same entry again (a re-run) returns the file
 * unchanged, and the same version with another hash or link is refused.
 * @param {string | null} previous the current updates.json, or null for the first publication
 * @param {{ version: string, sha256: string }} update the version and the SHA-256 of its signed package
 * @returns {{ text: string, changed: boolean }}
 */
export function appendUpdate(previous, { version, sha256 }) {
  if (typeof sha256 !== "string" || !/^[0-9a-f]{64}$/.test(sha256)) throw new Error("the SHA-256 must be 64 lower-case hex digits");
  const entry = { version, update_link: updateLink(version), update_hash: `sha256:${sha256}` };
  const problem = entryProblem(entry);
  if (problem) throw new Error(problem);
  const entries = previous === null ? [] : parseUpdates(previous);
  const same = entries.find((e) => compareVersions(e.version, version) === 0);
  if (same) {
    if (same.version === entry.version && same.update_link === entry.update_link && same.update_hash === entry.update_hash) {
      return { text: formatUpdates(entries), changed: false };
    }
    throw new Error(`updates.json already lists ${same.version} with another file (${same.update_hash}); a version is never published twice`);
  }
  const newest = entries.at(-1);
  if (newest && compareVersions(newest.version, version) > 0) {
    throw new Error(`${version} is older than ${newest.version}, the newest listed version`);
  }
  return { text: formatUpdates([...entries, entry]), changed: true };
}
