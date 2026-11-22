// The frame's way to the admin pages and its Sign out, over `enterVault` with a stubbed account session: the switch
// shows only for an administrator of a vault that has an admin address, the answer is asked once per account, a
// failed answer shows nothing and is asked again, and a sign-out that could not reach the server is said out loud.
import assert from "node:assert/strict";
import { test } from "node:test";
import { autoLockFor } from "../../src/lock.mjs";
import { enterVault } from "../../src/views/shell.mjs";
import { click, coded, fakeClient, fakeEngine, fakeSession, find, settle, t, textOf, withDom } from "./vaultHelpers.mjs";

const ADMIN_URL = "https://admin.ferret.test";

/** A page context over fakes, with the admin address in a meta tag (or none). */
function rig({ adminAddress = ADMIN_URL, info } = {}) {
  const engine = fakeEngine({ items: [] });
  const session = fakeSession({ client: fakeClient(engine), ...(info === undefined ? {} : { info: undefined }) });
  const asked = { info: 0 };
  session.info = async () => {
    asked.info += 1;
    return typeof info === "function" ? info() : info;
  };
  const sync = { current: () => engine, start: async () => engine, stop: () => engine.stop() };
  const moves = [];
  const ctx = (path = "/items") => ({
    params: {}, path, i18n: { t, lang: "en", missing: [] }, client: session.client, services: { crypto: session, sync }, go: (p) => moves.push(p), routes: [],
  });
  globalThis.document.querySelector = (selector) => (selector.includes("ferret-admin-url") && adminAddress !== null ? { getAttribute: () => adminAddress } : null);
  return { session, sync, asked, moves, ctx, done: () => autoLockFor(session, sync).stop() };
}

const page = async (r) => (await enterVault(r.ctx())).page(globalThis.document.createElement("div"));

test("the_switch_shows_for_an_administrator_and_leads_to_the_hand_over_to_the_admin_pages", async () => {
  await withDom(async () => {
    const savedLocation = globalThis.location;
    const assigned = [];
    globalThis.location = { origin: "https://vault.ferret.test", assign: (url) => assigned.push(url) };
    const r = rig({ info: { accountId: "aa".repeat(16), email: "ada@example.test", admin: true } });
    try {
      const frame = await page(r);
      await settle();
      const button = find(frame, "switch-admin");
      assert.equal(button.hidden, false);
      await click(button);
      await settle();
      assert.equal(assigned.length, 1);
      const url = new URL(assigned[0]);
      assert.equal(url.origin, ADMIN_URL);
      assert.equal(url.pathname, "/auth/handoff/begin");
      assert.equal(url.searchParams.get("next"), "/settings/general");
      assert.deepEqual([...url.searchParams.keys()], ["next"], "no code, no token, nothing but the way back");
    } finally {
      r.done();
      if (savedLocation === undefined) delete globalThis.location;
      else globalThis.location = savedLocation;
    }
  });
});

test("the_answer_is_asked_once_for_an_account_and_not_again_on_the_next_page", async () => {
  await withDom(async () => {
    const r = rig({ info: { accountId: "aa".repeat(16), email: "ada@example.test", admin: true } });
    try {
      await page(r);
      await settle();
      assert.equal(r.asked.info, 1);
      const second = await page(r);
      await settle();
      assert.equal(r.asked.info, 1, "kept for this session and account");
      assert.equal(find(second, "switch-admin").hidden, false);
    } finally {
      r.done();
    }
  });
});

test("a_user_who_is_not_an_administrator_has_no_switch", async () => {
  await withDom(async () => {
    for (const admin of [false, undefined, "yes", 1]) {
      const r = rig({ info: { accountId: "aa".repeat(16), email: "ada@example.test", admin } });
      try {
        const frame = await page(r);
        await settle();
        assert.equal(find(frame, "switch-admin").hidden, true, String(admin));
      } finally {
        r.done();
      }
    }
  });
});

test("a_vault_with_no_admin_address_has_no_switch_and_does_not_ask", async () => {
  await withDom(async () => {
    for (const adminAddress of [null, "", "not a url", "https://vault.ferret.test"]) {
      const savedLocation = globalThis.location;
      globalThis.location = { origin: "https://vault.ferret.test" };
      const r = rig({ adminAddress, info: { accountId: "aa".repeat(16), email: "ada@example.test", admin: true } });
      try {
        const frame = await page(r);
        await settle();
        assert.equal(find(frame, "switch-admin").hidden, true, String(adminAddress));
        assert.equal(r.asked.info, 0, String(adminAddress));
      } finally {
        r.done();
        if (savedLocation === undefined) delete globalThis.location;
        else globalThis.location = savedLocation;
      }
    }
  });
});

test("a_failed_answer_shows_no_switch_and_is_asked_again_on_the_next_page", async () => {
  await withDom(async () => {
    let fail = true;
    const r = rig({
      info: () => {
        if (fail) throw coded("network");
        return { accountId: "aa".repeat(16), email: "ada@example.test", admin: true };
      },
    });
    try {
      const first = await page(r);
      await settle();
      assert.equal(find(first, "switch-admin").hidden, true);
      assert.equal(r.asked.info, 1);
      fail = false;
      const second = await page(r);
      await settle();
      assert.equal(r.asked.info, 2, "a failure is not kept");
      assert.equal(find(second, "switch-admin").hidden, false);
    } finally {
      r.done();
    }
  });
});

test("sign_out_ends_the_session_and_goes_to_the_sign_in_page", async () => {
  await withDom(async () => {
    const r = rig({ info: { accountId: "aa".repeat(16), email: "ada@example.test" } });
    let signedOut = 0;
    r.session.signOut = async () => void (signedOut += 1);
    try {
      const frame = await page(r);
      await click(find(frame, "sign-out"));
      await settle();
      assert.equal(signedOut, 1);
      assert.deepEqual(r.moves, ["/login"]);
      assert.equal(find(frame, "signout-incomplete"), null);
    } finally {
      r.done();
    }
  });
});

test("a_sign_out_that_could_not_reach_the_server_says_so_and_offers_the_sign_in_page", async () => {
  await withDom(async () => {
    const r = rig({ info: { accountId: "aa".repeat(16), email: "ada@example.test" } });
    r.session.signOut = async () => {
      throw coded("signout_incomplete");
    };
    try {
      const frame = await page(r);
      await click(find(frame, "sign-out"));
      await settle();
      const card = find(frame, "signout-incomplete");
      assert.ok(card, "the user is told");
      assert.equal(card.getAttribute("role"), "alert");
      assert.ok(textOf(card).includes("account.error.signout_incomplete"));
      assert.ok(textOf(card).includes("shell.signout.login"));
      assert.deepEqual(r.moves, [], "it does not leave before the user has read it");
    } finally {
      r.done();
    }
  });
});

test("any_other_failure_of_the_sign_out_still_leaves_for_the_sign_in_page", async () => {
  await withDom(async () => {
    const r = rig({ info: { accountId: "aa".repeat(16), email: "ada@example.test" } });
    r.session.signOut = async () => {
      throw coded("unknown");
    };
    try {
      const frame = await page(r);
      await click(find(frame, "sign-out"));
      await settle();
      assert.deepEqual(r.moves, ["/login"]);
      assert.equal(find(frame, "signout-incomplete"), null);
    } finally {
      r.done();
    }
  });
});
