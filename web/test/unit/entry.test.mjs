// How the page reads an invitation link (`/vault/setup#invite=<43 characters>`):
// from the fragment only, on the setup page only, and the address is rewritten
// at once so that the token is in no history entry and no bookmark.
import assert from "node:assert/strict";
import { test } from "node:test";
import { clearInvite, consumeEntry, getEntry, readEntry } from "../../src/flows/entry.mjs";

const INVITE = "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dE3fG5hJ7kL9x";

const win = (pathname, search = "", hash = "") => {
  const replaced = [];
  return {
    replaced,
    location: { pathname, search, hash },
    history: { replaceState: (_state, _title, url) => replaced.push(url) },
  };
};

test("invite_in_the_fragment_is_read_and_removed_from_the_address", () => {
  assert.equal(INVITE.length, 43);
  const w = win("/vault/setup", "", `#invite=${INVITE}`);
  const entry = consumeEntry(w);
  assert.equal(entry.page, "setup");
  assert.equal(entry.invite, INVITE);
  assert.equal(entry.setupToken, null, "an invitation is not a setup token");
  // The address is rewritten once, to a page address that holds nothing of the link.
  assert.deepEqual(w.replaced, ["/vault/#/setup"]);
  assert.ok(!w.replaced[0].includes(INVITE));
  assert.equal(getEntry().invite, INVITE);
  // Once used, the page forgets it.
  clearInvite();
  assert.equal(getEntry().invite, null);
  assert.equal(getEntry().page, "setup");

  // A trailing slash is the same page; the setup token keeps working as before.
  assert.equal(readEntry({ pathname: "/vault/setup/", search: "", hash: `#invite=${INVITE}` }).invite, INVITE);
  const first = readEntry({ pathname: "/vault/setup", search: "", hash: "#token=abc.DEF" });
  assert.equal(first.setupToken, "abc.DEF");
  assert.equal(first.invite, null);
  // Every entry has the field, also one for another page.
  assert.equal(readEntry({ pathname: "/vault/", search: "", hash: "#/items" }).invite, null);
});

test("a_malformed_invite_is_ignored", () => {
  const bad = [
    "#invite=",
    `#invite=${INVITE.slice(1)}`, // 42 characters
    `#invite=${INVITE}a`, // 44 characters
    `#invite=${INVITE.slice(1)}-`, // not base62
    `#invite=${INVITE.slice(1)}_`,
    `#invite=${INVITE.slice(1)}.`,
    `#invite=${INVITE}&token=abc`,
    `#token=abc&invite=${INVITE}`,
    `#invite=${INVITE.slice(0, 20)}%20${INVITE.slice(23)}`,
    `#Invite=${INVITE}`,
    `#invite=${INVITE.slice(1)}é`,
  ];
  for (const hash of bad) {
    const entry = readEntry({ pathname: "/vault/setup", search: "", hash });
    assert.equal(entry.invite, null, hash);
    assert.equal(entry.page, "setup", hash);
  }
  // Not from the query string, where a server log or a Referer could show it.
  assert.equal(readEntry({ pathname: "/vault/setup", search: `?invite=${INVITE}`, hash: "" }).invite, null);
  // Not on another page.
  for (const pathname of ["/vault/login", "/vault/reauth", "/vault/password", "/vault/", "/setup"]) {
    assert.equal(readEntry({ pathname, search: "", hash: `#invite=${INVITE}` }).invite, null, pathname);
  }
  // A malformed link is still taken out of the address of the setup page.
  const w = win("/vault/setup", "", `#invite=${INVITE.slice(1)}-`);
  assert.equal(consumeEntry(w).invite, null);
  assert.deepEqual(w.replaced, ["/vault/#/setup"]);
});
