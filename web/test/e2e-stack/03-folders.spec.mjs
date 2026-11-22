// Folders are labels inside each item, encrypted with it, against the real server and the real core: a folder is made
// from the edit form, an edit that does not touch the folders keeps them, a folder is pinned to the side menu (and the
// pin comes back after a lock, from its sealed record), renamed and deleted from the Folders page, and a second device
// sees each change after it syncs. The names never reach the server, the browser's storage or the address in clear: the
// traffic and the stores are searched here, and the names are added to the secrets the host script looks for in the
// server's data files (scenario 08 and the data search of the gate).
import {
  addNeedle, createItem, expect, findings, freshContext, lockNow, openItem, openList, readStores, requireAccount, findRows, secrets, signInOn,
  synced, test, unlockWith,
} from "./support.mjs";

const SEEN = 30_000;

/** The tag of the run (in the item title the setup made). */
const tagOf = () => secrets.itemTitle.split("-")[1] ?? "run";

/** The names of this run's folders: made up for the run, long enough to be searched for. */
function names() {
  const tag = tagOf();
  return { first: `Folder-${tag}-alpha`, renamed: `Folder-${tag}-renamed`, second: `Mappe-${tag}-økonomi` };
}

/** The pinned folders in the side menu. @param {import("@playwright/test").Page} page */
const pinned = (page) => page.locator('[data-role="nav-folder"]');

/** Puts the item that is open into a folder through its edit form. */
async function addFolderInForm(page, name) {
  await page.locator('[data-role="edit"]').click();
  await expect(page.locator('[data-role="edit-form"]')).toBeVisible();
  await page.locator('[data-role="folder-input"]').fill(name);
  await page.locator('[data-role="folder-input"]').press("Enter");
  await expect(page.locator('[data-role="folder-picked-chip"]', { hasText: name })).toBeVisible();
  await page.locator('[data-role="save"]').click();
  await expect(page.locator('[data-role="folder-chip"]', { hasText: name })).toBeVisible({ timeout: SEEN });
}

/** Opens the Folders page from the side menu. */
async function openFolders(page) {
  await page.locator('[data-role="nav-folders"]').click();
  await expect(page.locator('[data-role="folders-page"]')).toBeVisible();
}

/** Nothing this browser keeps, and no address it has been at, holds a folder name in clear. */
async function nothingInClear(page, list) {
  const stores = JSON.stringify(await readStores(page));
  const local = await page.evaluate(() => JSON.stringify({ ...localStorage }) + JSON.stringify({ ...sessionStorage }) + location.href);
  for (const name of list) {
    expect(stores.includes(name), `a store holds ${name}`).toBe(false);
    expect(local.includes(name), `the page's storage or address holds ${name}`).toBe(false);
  }
}

test("folders_are_made_pinned_renamed_and_deleted_and_a_second_device_follows", async ({ browser }) => {
  test.setTimeout(600_000);
  requireAccount();
  const { first, renamed, second } = names();
  for (const [label, value] of [["folder name", first], ["renamed folder name", renamed], ["second folder name", second]]) addNeedle(label, value);
  const a = await (await freshContext(browser)).newPage();
  await signInOn(a);

  // Two items, both put in the first folder from the edit form; the second also in a second folder.
  // Not named after the item title of the run: the other scenarios search the list for that title and expect one row.
  const one = `Foldered-${tagOf()}-1`;
  const two = `Foldered-${tagOf()}-2`;
  await createItem(a, { name: one, username: "folder-user-1" });
  await addFolderInForm(a, first);
  await createItem(a, { name: two, username: "folder-user-2" });
  await addFolderInForm(a, first);
  await addFolderInForm(a, second);
  await expect(a.locator('[data-role="folder-chip"]')).toHaveText([first, second].sort((x, y) => x.localeCompare(y)));

  // An edit that does not touch the folders keeps them (the real core starts from the item's own body).
  await a.locator('[data-role="edit"]').click();
  await a.locator('[data-role="name"]').fill(`${two}-edited`);
  await a.locator('[data-role="save"]').click();
  await expect(a.locator('[data-role="item"] h1')).toContainText(`${two}-edited`, { timeout: SEEN });
  await expect(a.locator('[data-role="folder-chip"]')).toHaveCount(2);

  // The Folders page lists both, with their counts; pin the first: it shows in the side menu.
  await openFolders(a);
  const row = a.locator('[data-role="folder-row"]', { hasText: first });
  await expect(row.locator('[data-role="folder-count"]')).toContainText("2");
  await row.locator('[data-role="folder-pin"]').click();
  await expect(pinned(a)).toHaveText([first]);
  // The pinned entry leads to the folder's items; the address holds a token, not the name.
  await pinned(a).click();
  await expect(a.locator('[data-role="list-title"]')).toHaveText(first);
  expect(a.url()).toMatch(/#\/folders\/[0-9a-f]{16}$/);
  await expect(a.locator('[data-role="item"]')).toHaveCount(2);
  await synced(a);

  // A second device sees the folders after it syncs.
  const b = await (await freshContext(browser)).newPage();
  await signInOn(b);
  await openFolders(b);
  await expect(b.locator('[data-role="folder-row"]', { hasText: first })).toBeVisible({ timeout: SEEN });
  await expect(b.locator('[data-role="folder-row"]', { hasText: second })).toBeVisible();
  await expect(pinned(b)).toHaveCount(0); // a pin belongs to one device

  // The pin comes back after a lock, from its sealed record. (The address of a folder's page does not outlive a lock, so
  // the lock is made on the list.)
  await openList(a);
  await lockNow(a);
  await expect(a.locator('[data-role="unlock-form"]')).toBeVisible();
  await expect(pinned(a)).toHaveCount(0);
  await unlockWith(a, secrets.password);
  await expect(a.locator('[data-role="list"]')).toBeVisible({ timeout: SEEN });
  await expect(pinned(a)).toHaveText([first], { timeout: SEEN });

  // Rename the first folder: both items carry the new name, the pin follows, and the second device follows after a sync.
  await openFolders(a);
  await a.locator('[data-role="folder-row"]', { hasText: first }).locator('[data-role="folder-rename"]').click();
  await a.locator('[data-role="folder-new-name"]').fill(renamed);
  await a.locator('[data-role="folder-rename-save"]').click();
  await expect(a.locator('[data-role="message"]')).toContainText("renamed", { timeout: SEEN });
  await expect(a.locator('[data-role="folder-row"]', { hasText: renamed })).toBeVisible();
  await expect(a.locator('[data-role="folder-row"]', { hasText: first })).toHaveCount(0);
  await expect(pinned(a)).toHaveText([renamed]);
  await synced(a);
  await openList(b);
  await openFolders(b);
  await expect(b.locator('[data-role="folder-row"]', { hasText: renamed })).toBeVisible({ timeout: SEEN });
  await expect(b.locator('[data-role="folder-row"]', { hasText: first })).toHaveCount(0);
  await openItem(b, one);
  await expect(b.locator('[data-role="folder-chip"]')).toHaveText([renamed]);

  // Delete the second folder: the item stays, without the label, here and on the second device.
  await openFolders(a);
  await a.locator('[data-role="folder-row"]', { hasText: second }).locator('[data-role="folder-delete"]').click();
  await a.locator('[data-role="dialog-confirm"]').click();
  await expect(a.locator('[data-role="folder-row"]', { hasText: second })).toHaveCount(0, { timeout: SEEN });
  await synced(a);
  await openItem(a, `${two}-edited`);
  await expect(a.locator('[data-role="folder-chip"]')).toHaveText([renamed]);
  await openList(b);
  await expect.poll(async () => {
    await openFolders(b);
    return b.locator('[data-role="folder-row"]', { hasText: second }).count();
  }, { timeout: SEEN }).toBe(0);
  await openItem(b, `${two}-edited`);
  await expect(b.locator('[data-role="folder-chip"]')).toHaveText([renamed]);
  await openList(b);
  await expect(await findRows(b, `${two}-edited`)).toHaveCount(1);

  // No folder name in clear: not in the traffic of the run so far, not in either browser's storage or address.
  const traffic = findings.traffic.join("\n");
  for (const name of [first, renamed, second]) expect(traffic.includes(name), `the traffic holds ${name}`).toBe(false);
  await nothingInClear(a, [first, renamed, second]);
  await nothingInClear(b, [first, renamed, second]);

  // Clean up: the folders of this run go, so the later scenarios start from a vault without them.
  await openFolders(a);
  await a.locator('[data-role="folder-row"]', { hasText: renamed }).locator('[data-role="folder-delete"]').click();
  await a.locator('[data-role="dialog-confirm"]').click();
  await expect(a.locator('[data-role="folders-empty"]')).toBeVisible({ timeout: SEEN });
  await synced(a);
  await a.context().close();
  await b.context().close();
});
