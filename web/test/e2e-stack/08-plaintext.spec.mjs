// The traffic of the whole run (everything the browsers
// sent to the servers and got back) holds none of the secrets of the run. The
// second half, the same search in the server's database file, is made by the
// host script (scripts/lanbox-ferret-e2e-gate.sh) from the list this test leaves.
import { expect, findings, leave, requireAccount, secrets, test } from "./support.mjs";

/** The values that must never leave the browser in the clear. */
function needles() {
  const list = {
    password: secrets.password,
    secret_key: secrets.secretKey,
    secret_key_plain: secrets.secretKey.replaceAll("-", ""),
    recovery_key: secrets.recoveryKey,
    recovery_key_plain: secrets.recoveryKey.replaceAll("-", ""),
    item_title: secrets.itemTitle,
    item_username: secrets.itemUsername,
    item_password: secrets.itemPassword,
    item_notes: secrets.itemNotes,
    item_url: secrets.itemUrl,
  };
  return Object.entries(list).filter(([, value]) => value.length >= 8);
}

test("server_never_sees_plaintext", async () => {
  requireAccount();
  const list = needles();
  expect(list.length).toBeGreaterThanOrEqual(8);
  // The capture is real: it holds the sign-ins and the writes of the earlier scenarios.
  const all = findings.traffic.join("\n");
  expect(findings.traffic.length).toBeGreaterThan(100);
  // Bodies are captured too: the e-mail address travels in the clear on purpose.
  expect(all).toContain(secrets.email);
  expect(all).toContain("/api/auth/opaque/register/finish");
  expect(all).toContain("/api/auth/opaque/login/finish");
  expect(all).toContain("/api/sync/items/");
  for (const [name, value] of list) {
    expect(all.includes(value), `the traffic holds the ${name}`).toBe(false);
  }
  // What the host script searches the database file for.
  leave("needles", list.map(([name, value]) => ({ name, value })));
  leave("state", { ...secrets });
});
