// A password changed on one device keeps the old one inside the item, and another device shows it under "Previous passwords"
// (hidden until Show), with the real server and the real core. The change is made through the edit form, so the form's own
// request to keep the history is part of what is tested.
import { createItem, editItem, expect, findings, leaveMore, newDevice, noViolations, openItem, synced, test, useAccount } from "./support.mjs";

test.describe.configure({ mode: "serial" });
noViolations();

const SEEN = 30_000;

/** @type {{ context: import("@playwright/test").BrowserContext, page: import("@playwright/test").Page }} */
let a;
/** @type {{ context: import("@playwright/test").BrowserContext, page: import("@playwright/test").Page }} */
let b;

test.beforeAll(async ({ browser }) => {
  test.setTimeout(400_000);
  useAccount();
  a = await newDevice(browser);
  b = await newDevice(browser);
});

test.afterAll(async () => {
  await a?.context.close();
  await b?.context.close();
});

/** @param {import("@playwright/test").Page} page */
const historyCard = (page) => page.locator('[data-role="item-card"][data-card="history"]');

test("an_update_from_another_device_shows_the_old_password_under_previous_passwords", async () => {
  test.setTimeout(400_000);
  const stamp = Date.now();
  const name = `History-${stamp}`;
  const first = `first-Pw-${stamp}-A`;
  const second = `second-Pw-${stamp}-B`;
  const third = `third-Pw-${stamp}-C`;
  const secretsOfRun = [["history first password", first], ["history second password", second], ["history third password", third]];

  // Device A makes the item; device B has it.
  await createItem(a.page, { name, username: "history-user", password: first });
  await expect(historyCard(a.page)).toHaveCount(0); // a new item has no earlier passwords
  await synced(a.page);
  await openItem(b.page, name);
  await expect(historyCard(b.page)).toHaveCount(0);

  // Device B changes the password. Device A, with the item open, shows the old one without a reload.
  await editItem(b.page, name, { password: second });
  await synced(b.page);
  const card = historyCard(a.page);
  await expect(card).toBeVisible({ timeout: SEEN });
  await expect(card.locator("h2")).toContainText("(1)");
  // The date came through the real core and worker as a number: the row names it, it does not say the date is unknown.
  await expect(card).toContainText("Replaced ");
  await expect(card).not.toContainText("date unknown");
  await expect(card.locator('[data-role="field"]')).toHaveCount(1);
  // Hidden until Show: neither the old nor the new password is in the page.
  const text = () => a.page.locator('[data-role="item"]').innerText();
  expect(await text()).not.toContain(first);
  expect(await text()).not.toContain(second);
  await card.locator('[data-role="reveal"]').click();
  await expect(card.locator('[data-role="value"]')).toHaveText(first);
  expect(await text()).not.toContain(second);
  // Showing the current password hides the old one.
  await a.page.locator('[data-card="login"] [data-role="reveal"][data-key="f1"]').click();
  await expect(a.page.locator('[data-card="login"] [data-role="value"][data-key="f1"]')).toHaveText(second);
  expect(await text()).not.toContain(first);

  // A second change from device A: the newest old password comes first, and device B sees both.
  await editItem(a.page, name, { password: third });
  await synced(a.page);
  await openItem(b.page, name);
  const there = historyCard(b.page);
  await expect(there.locator("h2")).toContainText("(2)", { timeout: SEEN });
  await there.locator('[data-role="reveal"]').first().click();
  await expect(there.locator('[data-role="value"]').first()).toHaveText(second);
  await there.locator('[data-role="reveal"]').nth(1).click();
  await expect(there.locator('[data-role="value"]').nth(1)).toHaveText(first);
  expect(await b.page.locator('[data-role="item"]').innerText()).not.toContain(second);

  // A change that leaves the password alone adds nothing.
  await editItem(b.page, name, { username: "history-user-2" });
  await synced(b.page);
  // Device A must have the change before the count means anything: wait for the new user name, then check the list.
  await openItem(a.page, name);
  await expect(a.page.locator('[data-role="value"][data-key="f0"]')).toHaveText("history-user-2", { timeout: SEEN });
  await expect(historyCard(a.page).locator("h2")).toContainText("(2)");

  // None of the three passwords went to a server in the clear: not in what the browsers sent and received, and (through the
  // list the host script searches) not in the server's data files, its backup sets or its log.
  const traffic = findings.traffic.join("\n");
  expect(traffic.length).toBeGreaterThan(1000);
  expect(traffic).toContain("/api/sync/items/"); // the capture is real: it holds the writes of this scenario
  for (const [label, value] of secretsOfRun) expect(traffic.includes(value), `the traffic holds the ${label}`).toBe(false);
  leaveMore(secretsOfRun.map(([name, value]) => ({ name, value })));
});
