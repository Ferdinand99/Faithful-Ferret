// Names that exist only in the test variant and its profile. The browser tests
// (extension/test/firefox) and the release check (scripts/build.mjs) read them
// from here, so a release can be refused when it carries any of them.

/** The fixed UUID of the test build in the test profile (moz-extension://<this>/). */
export const FIXED_UUID = "5c1d6b3e-2f8a-4d0c-9a57-3e7b1c9a4f10";
/** The command and the menu item of the test variant (manifest/test-parts, test/bridge.mjs). */
export const TEST_COMMAND_ID = "ferret-test-command";
export const TEST_MENU_ITEM_ID = "ferret-test-menu-item";
