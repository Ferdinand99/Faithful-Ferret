// What the extension's pages and its background agree on about capturing the
// forms that people submit (design document, section 10.9): the one host
// permission the capture needs, and the content script it registers once the
// user has allowed it. Plain ESM, no dependencies.

/**
 * The optional host permission of the capture: every `https` page. It is asked for in the settings tab when the user
 * turns on "Offer to save passwords", and nowhere else.
 */
export const CAPTURE_ORIGINS = Object.freeze(["https://*/*"]);

/** The id the background registers the capture script under. */
export const CAPTURE_SCRIPT_ID = "ferret-capture";

/** The capture script in the package (written by the build; a release has none while saving is off). */
export const CAPTURE_SCRIPT_FILE = "/content/capture.inject.js";

/** The most hosts the "never" list keeps. */
export const MAX_NEVER = 500;
