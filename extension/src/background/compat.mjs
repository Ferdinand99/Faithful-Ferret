// The action API under one name. MV3 has `browser.action`, MV2 has
// `browser.browserAction`, with the same methods for the popup and the badge.
// The code reaches it only through this export.

const manifestVersion = browser.runtime.getManifest().manifest_version;
const chosen = manifestVersion === 3 ? browser.action : browser.browserAction;
if (!chosen) throw new Error(`compat: no action API for manifest version ${manifestVersion}`);

/** @type {typeof browser.action} */
export const action = chosen;
