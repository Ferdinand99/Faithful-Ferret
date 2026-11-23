// "Settings" in the popup's header: opens the settings page (the add-on's options page) and closes the popup. It is in every
// build; the page has content for everyone (the lock time, the credits), and more where saving passwords is on.

/**
 * @param {{ runtime: { openOptionsPage(): Promise<unknown> | unknown }, close: () => void }} deps
 * @returns {Promise<boolean>} whether the page was opened (the popup stays open when it was not)
 */
export async function openSettings({ runtime, close }) {
  try {
    await runtime.openOptionsPage();
  } catch {
    return false;
  }
  close();
  return true;
}
