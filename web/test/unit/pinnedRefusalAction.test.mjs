// The refusal of an older password after the server was restored from a backup (spec Fase 1
// § 4.5, § 6.3 and § 8.8, "After a restore"): with a raised restore epoch the sign-in page
// offers the recovery key (in the same session, with the newest password typed as the new one),
// or, when the recovery key was renewed after the backup too, it names the older sheet and the
// way out. Without a raised epoch the refusal keeps the text that it can be an attack. No path
// lowers a pinned floor.
import assert from "node:assert/strict";
import { test } from "node:test";
import { pinnedRefusalAction } from "../../src/flows/signin.mjs";
import { loginView } from "../../src/views/login.mjs";
import { accountDocument, byRole, fire, settle, textOf } from "./accountHelpers.mjs";
import { ACCOUNT, EMAIL, PASSWORD, SERVER, SK_CODE, coded, pinHere, pinnedRecord, recoverIn, recoverWorld, recoveredDto } from "./recoverHelpers.mjs";
import { EN, NB, translator } from "./syncWarningsHelpers.mjs";

/** A sync state that says this device accepted restore epoch `epoch` (or none, with null). */
const state = (epoch) => ({ memory: new Uint8Array(4), restoreEpoch: epoch, verifiedAt: null, verifiedSeq: null, uploadedAt: null, uploadedSeq: null, hardWarning: null, restore: null });

/**
 * A device that pinned password floor `pw` and recovery floor `rk`, a server whose wraps are at generation 1 and whose
 * restore epoch is `serverEpoch`, and a core that refuses the older password while `world.refuse` is true.
 */
async function restoredWorld({ pw = 3, rk = 1, storedEpoch = 4, serverEpoch = 5, session = null, overrides = {} } = {}) {
  const flags = { refuse: true };
  const world = await recoverWorld({
    session,
    overrides,
    restoreEpoch: serverEpoch,
    handlers: {
      unlock_password: (_server, _ctx, _wrap, pin) => {
        if (flags.refuse) throw coded("pinned_kek_generation");
        return { pinned: pin.record };
      },
      // The core raises the password above the pinned floor and keeps the recovery floor.
      recover: () => recoveredDto({ floors: [["password", pw + 1], ["recovery", Math.max(rk, 1) + 1]] }),
    },
  });
  world.flags = flags;
  const db = await pinHere(world, { floors: [["password", pw], ["recovery", rk]], keepSk: true });
  if (storedEpoch !== null) await world.store.saveSyncState(db, SERVER, ACCOUNT, state(storedEpoch));
  world.db = db;
  return world;
}

const signInRefused = (world) => world.session.signIn({ email: EMAIL, password: PASSWORD, skCode: SK_CODE }).catch((e) => e);
const loggedOut = (world) => world.requests.some((r) => r.method === "POST" && r.url === "/api/auth/logout");

/** The sign-in page over a session whose sign-in fails with `error`. */
async function refusedPage(error, lang = "en") {
  const went = [];
  const session = {
    deviceStatus: async () => ({ pinned: true, skBit: true, skStored: true }),
    signIn: async () => {
      throw error;
    },
    unlock: async () => {
      throw error;
    },
    current: () => null,
    freshReauth: () => true,
  };
  const root = loginView({
    t: translator(lang),
    session,
    entry: { page: "login", handoff: null, brokenHandoff: false, setupToken: null },
    adminUrl: null,
    api: {},
    go: (path) => went.push(path),
    handoff: { completeHandoff: async () => undefined, goToAdmin: async () => undefined },
    info: null,
  });
  await settle();
  byRole(root, "email").value = EMAIL;
  byRole(root, "password").value = PASSWORD;
  await fire(byRole(root, "credentials"), "submit");
  await settle();
  return { root, went };
}

async function withDom(body) {
  const saved = globalThis.document;
  globalThis.document = accountDocument();
  try {
    return await body();
  } finally {
    if (saved === undefined) delete globalThis.document;
    else globalThis.document = saved;
  }
}

test("a_pinned_refusal_after_a_raised_restore_epoch_offers_the_recovery_key_and_never_lowers_a_floor", async () => {
  const world = await restoredWorld({ pw: 3, rk: 1 });
  const error = await signInRefused(world);
  assert.equal(error.code, "pinned_kek_generation", "the refusal stands");
  assert.equal(error.recoveryOffer, "recover");
  assert.equal(loggedOut(world), false, "the session stays: the recovery runs in it");
  assert.equal(world.session.current(), null, "the vault did not open");
  // The record was not touched by the refusal.
  const before = await world.store.pinHintForEmail(world.db, SERVER, EMAIL);
  assert.deepEqual(before.kek_generation_max.map((f) => [f.type, f.generation]), [["password", 3], ["recovery", 1]]);

  // The recovery in that session: no code, no sheet (this device is pinned), the newest password as the new one.
  world.flags.refuse = false;
  assert.equal(await recoverIn(world, { email: "", code: "", qrText: null, skCode: "" }), "recovered");
  assert.ok(!world.requests.some((r) => r.url === "/api/auth/redeem"), "a full session needs no code");
  const [call] = world.client.called("recover");
  assert.equal(call.args[5].kind, "pinned");
  assert.deepEqual(call.args[5].record.kek_generation_max.map((f) => f.generation), [3, 1], "the core got the floors as pinned");
  const after = await world.store.pinHintForEmail(world.db, SERVER, EMAIL);
  for (const floor of after.kek_generation_max) {
    const old = before.kek_generation_max.find((f) => f.type === floor.type);
    assert.ok(floor.generation >= old.generation, `${floor.type}: ${floor.generation} >= ${old.generation}`);
  }
  // And the store refuses any record that would lower one, whatever a page asks.
  await assert.rejects(
    world.store.savePinned(world.db, SERVER, ACCOUNT, EMAIL, pinnedRecord({ floors: [["password", 1], ["recovery", 1]], serverKey: 9 })),
    (e) => /floor/.test(e.code),
  );

  // The page: the restore text and "Use the recovery key", which leads to the recovery page.
  await withDom(async () => {
    for (const [lang, catalog] of [["en", EN], ["nb", NB]]) {
      const { root, went } = await refusedPage(Object.assign(coded("pinned_kek_generation"), { recoveryOffer: "recover" }), lang);
      assert.equal(textOf(byRole(root, "error")).trim(), catalog["recover.offer.recover"]);
      // The offer stands only for a restore the user made; otherwise the text names the attack.
      const text = textOf(byRole(root, "error"));
      const own = lang === "en" ? "If you restored the server yourself" : "Har du gjenopprettet tjeneren selv";
      const attack = lang === "en" ? "this can be an attack" : "kan dette være et angrep";
      assert.ok(text.includes(own) && text.includes(attack), lang);
      assert.match(text, lang === "en" ? /^The server says it was restored/ : /^Tjeneren sier at den er gjenopprettet/, "the restore is the server's word, not a fact");
      const button = byRole(root, "use-recovery-key");
      assert.ok(button, `${lang}: the offer is there`);
      await fire(button, "click");
      assert.deepEqual(went, ["/recover"]);
    }
  });
});

test("restoring_a_set_from_before_a_renewal_offers_forget_and_names_the_old_sheet", async () => {
  // Both floors above the server's wraps: the recovery key was renewed after the backup, too.
  const world = await restoredWorld({ pw: 3, rk: 2 });
  const error = await signInRefused(world);
  assert.equal(error.code, "pinned_kek_generation");
  assert.equal(error.recoveryOffer, "old_sheet");
  assert.equal(loggedOut(world), true, "nothing runs in this session, so it ends as after any refused sign-in");
  assert.equal(await pinnedRefusalAction(world.env, world.db, {
    accountId: ACCOUNT,
    record: pinnedRecord({ floors: [["password", 3], ["recovery", 2]] }),
    methods: { methods: [{ method_type: 1, kek_generation: 1 }, { method_type: 2, kek_generation: 1 }] },
  }), "old_sheet");

  await withDom(async () => {
    for (const [lang, catalog] of [["en", EN], ["nb", NB]]) {
      const { root } = await refusedPage(Object.assign(coded("pinned_kek_generation"), { recoveryOffer: "old_sheet" }), lang);
      const text = textOf(byRole(root, "error")).trim();
      assert.equal(text, catalog["recover.offer.old_sheet"]);
      // It names the older sheet, says the newest key does not work here, and the way out.
      assert.match(text, lang === "en" ? /sheet you had before the renewal/ : /arket du hadde før fornyelsen/);
      assert.match(text, lang === "en" ? /newest recovery key does not work/ : /nyeste gjenopprettingsnøkkelen din virker ikke/);
      assert.ok(text.includes(catalog["syncwarnings.forget.link"]), "the way out by its name");
      // Forgetting the server's pins is suggested only for a restore the user made; otherwise it is named as an attack
      // and the user is told not to forget the server.
      const own = lang === "en" ? "If you restored the server yourself" : "Har du gjenopprettet tjeneren selv";
      const otherwise = lang === "en"
        ? "If you did not restore the server yourself, this can be an attack: do not forget the server, and contact the person who runs it."
        : "Har du ikke gjenopprettet tjeneren selv, kan dette være et angrep: ikke glem tjeneren, og kontakt den som drifter den.";
      assert.ok(text.indexOf(own) >= 0 && text.indexOf(own) < text.indexOf(catalog["syncwarnings.forget.link"]), `${lang}: the condition comes before the way out`);
      assert.ok(text.endsWith(otherwise), `${lang}: the attack sentence closes the text`);
      assert.match(text, lang === "en" ? /^The server says it was restored/ : /^Tjeneren sier at den er gjenopprettet/);
      if (lang === "nb") assert.doesNotMatch(text, /server/i, "the Norwegian texts say «tjeneren»");
      assert.equal(byRole(root, "use-recovery-key"), null, "the key this device has does not work here: no offer to use it");
      assert.equal(byRole(root, "offer-forget").getAttribute("href"), "#/forget");
    }
  });
});

test("without_a_raised_restore_epoch_the_attack_text_stays", async () => {
  // The same epoch, a device that never stored one, and an answer that cannot be read: no offer.
  const unreadable = { [`GET /api/sync/changes?since=${Number.MAX_SAFE_INTEGER}&limit=1`]: () => new Response("{}", { status: 500, headers: { "content-type": "application/json" } }) };
  for (const options of [
    { storedEpoch: 5, serverEpoch: 5 },
    { storedEpoch: 6, serverEpoch: 5 },
    { storedEpoch: null, serverEpoch: 5 },
    { storedEpoch: 4, serverEpoch: 5, overrides: unreadable },
  ]) {
    const world = await restoredWorld(options);
    const error = await signInRefused(world);
    assert.equal(error.code, "pinned_kek_generation", JSON.stringify(options));
    assert.equal(error.recoveryOffer, undefined, JSON.stringify(options));
    assert.equal(loggedOut(world), true, "a refused sign-in leaves no session behind");
  }
  // A refusal that is not about the password wrap being older gets no offer either.
  const world = await restoredWorld({ pw: 1, rk: 1 });
  assert.equal(await pinnedRefusalAction(world.env, world.db, {
    accountId: ACCOUNT,
    record: pinnedRecord({ floors: [["password", 1], ["recovery", 1]] }),
    methods: { methods: [{ method_type: 1, kek_generation: 1 }, { method_type: 2, kek_generation: 1 }] },
  }), null);
  // The page keeps the attack text, in both languages, and offers nothing.
  await withDom(async () => {
    for (const [lang, catalog] of [["en", EN], ["nb", NB]]) {
      for (const offer of [undefined, "something_else"]) {
        const error = coded("pinned_kek_generation");
        if (offer !== undefined) error.recoveryOffer = offer;
        const { root } = await refusedPage(error, lang);
        assert.equal(textOf(byRole(root, "error")).trim(), catalog["account.error.pinned_kek_generation"]);
        assert.match(textOf(byRole(root, "error")), lang === "en" ? /can be an attack/ : /Det kan være et angrep/);
        assert.equal(byRole(root, "recovery-offer").hidden, true);
      }
      // An offer on another refusal is not shown: it belongs to the older password only.
      const { root } = await refusedPage(Object.assign(coded("decrypt"), { recoveryOffer: "recover" }), lang);
      assert.equal(textOf(byRole(root, "error")).trim(), catalog["account.error.decrypt"]);
      assert.equal(byRole(root, "use-recovery-key"), null);
    }
  });
});
