// A build with the `unlock` feature off (a release until PIN and passkey unlock are released, a rollback to an older
// build) has no PIN store and opens no unlock database. The one thing it does at start is to ask the browser to delete
// the database that a build with the feature on may have left, so that no PIN blob stays behind with no code to delete
// it. Deleting a database that is not there does nothing and creates nothing.
//
// This is the only place where a build with the feature off names the database, and it only deletes it. The module is
// small on purpose: the release-package test lists every file of the package that holds the name.

/**
 * Asks the browser to delete the unlock database. Never throws and never rejects; the answer says whether the browser
 * confirmed the deletion (a refused or failed deletion is tried again at the next start).
 * @param {{ deleteDatabase(name: string): any } | null | undefined} indexedDB the extension's `indexedDB`
 * @returns {Promise<boolean>}
 */
export function deleteUnlockDatabase(indexedDB) {
  return new Promise((resolve) => {
    if (!indexedDB) {
      resolve(false);
      return;
    }
    /** @type {any} */
    let request;
    try {
      request = indexedDB.deleteDatabase("ferret-unlock");
    } catch {
      resolve(false);
      return;
    }
    if (!request) {
      resolve(false);
      return;
    }
    request.onsuccess = () => resolve(true);
    request.onerror = () => resolve(false);
    // `onblocked` only says that another connection is still open; the deletion goes on when it closes.
  });
}
