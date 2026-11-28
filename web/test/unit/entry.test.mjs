// How the page reads an invitation link (`/vault/setup#invite=<43 characters>`):
// from the fragment only, on the setup page only, and the address is rewritten
// at once so that the token is in no history entry and no bookmark.
import assert from "node:assert/strict";
import { test } from "node:test";
import { clearInvite, consumeEntry, getEntry, JOIN_STATE, readEntry } from "../../src/flows/entry.mjs";

const INVITE = "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dE3fG5hJ7kL9x";

/** A window whose history keeps the state of its one entry, as a reload keeps it. */
const win = (pathname, search = "", hash = "", state = null) => {
  const replaced = [];
  const states = [];
  const w = {
    replaced,
    states,
    location: { pathname, search, hash },
    history: {
      state,
      replaceState(next, _title, url) {
        this.state = next;
        states.push(next);
        replaced.push(url);
        const at = new URL(url, "https://vault.example");
        w.location = { pathname: at.pathname, search: at.search, hash: at.hash };
      },
    },
  };
  return w;
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

test("a_reload_after_the_token_was_read_is_a_lost_invitation", () => {
  // The first load: the token is read, the address rewritten, and the entry marked with a state that holds no token.
  const w = win("/vault/setup", "", `#invite=${INVITE}`);
  const first = consumeEntry(w);
  assert.equal(first.invite, INVITE);
  assert.equal(first.joinLost, false);
  assert.deepEqual(w.states, [JOIN_STATE]);
  assert.ok(!JSON.stringify(w.history.state).includes(INVITE));
  assert.deepEqual(w.location, { pathname: "/vault/", search: "", hash: "#/setup" });

  // A reload of that entry (or a tab the browser brought back): the address and the state are what the rewrite left.
  const again = consumeEntry(w);
  assert.equal(again.invite, null);
  assert.equal(again.joinLost, true);
  assert.equal(again.page, null);
  assert.equal(w.replaced.length, 1, "nothing more is rewritten");

  // Once the account exists, the mark is taken off: a reload is then an ordinary page.
  clearInvite();
  assert.equal(w.history.state, null);
  assert.deepEqual(w.location, { pathname: "/vault/", search: "", hash: "#/setup" });
  assert.equal(consumeEntry(w).joinLost, false);

  // The first administrator's setup leaves no mark, and an unmarked reload is not a lost invitation.
  const admin = win("/vault/setup", "", "#token=abc.DEF");
  assert.equal(consumeEntry(admin).joinLost, false);
  assert.deepEqual(admin.states, [null]);
  assert.equal(consumeEntry(admin).joinLost, false);
  // The mark counts only on the setup page.
  assert.equal(consumeEntry(win("/vault/", "", "#/items", JOIN_STATE)).joinLost, false);
  assert.equal(consumeEntry(win("/vault/", "", "#/setup", { other: true })).joinLost, false);

  // A link that was not complete is lost at once, and its entry is marked too.
  const broken = win("/vault/setup", "", `#invite=${INVITE.slice(3)}`);
  const cut = consumeEntry(broken);
  assert.equal(cut.invite, null);
  assert.equal(cut.joinLost, true);
  assert.deepEqual(broken.states, [JOIN_STATE]);
  assert.equal(consumeEntry(broken).joinLost, true);
});
