// The refusal at an unlock when the server shows an older unlock method than this device has seen
// (`pinned_kek_generation`, `method_list_*`): the plain warning stays as it is, and a device that accepted
// a restore lately gets a text that names the restore, the date and the one way out ("Forget this server").
// The note only picks the text. No path here lowers a floor.
import assert from "node:assert/strict";
import { test } from "node:test";
import { describeError, errorKey, OLDER_METHOD_ERRORS, restoreTextApplies } from "../../src/views/form.mjs";
import { loginView } from "../../src/views/login.mjs";
import { unlockScreen } from "../../src/views/unlock.mjs";
import { ACCOUNT, EMAIL, PASSWORD, accountDocument, byRole, coded as accountCoded, fire, settle as accountSettle, textOf as accountText } from "./accountHelpers.mjs";
import { EN, NB, translator } from "./syncWarningsHelpers.mjs";
import { FakeElement } from "./helpers.mjs";
import { all, coded, fakeSession, find, settle, submit, textOf, walk, withDom } from "./vaultHelpers.mjs";

const T0 = Date.UTC(2026, 10, 8, 12);
const note = (over = {}) => ({ acceptedAt: T0, restoreEpoch: 3, manifestOlder: true, ...over });
const KEY = "account.error.restored_older_method";
const day = (lang) => new Intl.DateTimeFormat(lang, { dateStyle: "medium" }).format(new Date(T0));
const PASSWORD_TYPED = "master-password-for-tests";

test("pinned_refusal_after_an_accepted_restore_shows_the_restore_text_with_the_date", () => {
  for (const [lang, catalog] of [["en", EN], ["nb", NB]]) {
    const t = translator(lang);
    for (const code of OLDER_METHOD_ERRORS) {
      const text = describeError(t, coded(code), { restoreNote: note(), locale: lang });
      assert.equal(text, catalog[KEY].replace("{date}", day(lang)), `${lang}: ${code}`);
      assert.ok(text.includes(day(lang)), "the date is in the text");
      assert.equal(errorKey(coded(code), { restoreNote: note() }), KEY);
    }
  }
  // The wording the design asks for (the date stands where {date} is).
  assert.equal(
    NB[KEY],
    "Tjeneren ble gjenopprettet {date}, fra før du sist endret opplåsingsmåte. Denne enheten nekter den eldre måten for å beskytte deg mot et angrep. Er gjenopprettingen din egen, kan du bruke «Glem denne tjeneren» her og logge inn som på en ny enhet med det gamle passordet. Er den ikke det, si fra til den som drifter tjeneren.",
  );
  assert.match(EN[KEY], /^The server was restored on \{date\}, from before you last changed an unlock method\./);
});

test("pinned_refusal_without_a_note_keeps_the_attack_text", () => {
  for (const [lang, catalog] of [["en", EN], ["nb", NB]]) {
    const t = translator(lang);
    for (const code of OLDER_METHOD_ERRORS) {
      const plain = describeError(t, coded(code));
      assert.equal(plain, catalog[`account.error.${code}`], `${lang}: ${code} has its own plain text`);
      assert.match(plain, lang === "en" ? /This can be an attack/ : /Det kan være et angrep/);
      // No note, an expired note (the store gives null), a note without manifestOlder, or a note that is not one: the same text.
      for (const none of [null, undefined, note({ manifestOlder: false }), { manifestOlder: true }, "note", {}]) {
        assert.equal(describeError(t, coded(code), { restoreNote: none, locale: lang }), plain, `${lang}: ${code} with ${JSON.stringify(none)}`);
      }
    }
    // Other refusals keep their text, note or not: the note is about older unlock methods only.
    for (const code of ["decrypt", "pinned_epoch_downgrade", "pinned_identity_changed", "kdf_profile_downgrade", "network"]) {
      assert.equal(describeError(t, coded(code), { restoreNote: note(), locale: lang }), describeError(t, coded(code)), `${lang}: ${code}`);
      assert.equal(restoreTextApplies(coded(code), note()), false);
    }
  }
  assert.equal(restoreTextApplies(coded("pinned_kek_generation"), note()), true);
  assert.equal(restoreTextApplies(coded("pinned_kek_generation"), null), false);
});

/** The unlock screen over a session that refuses, with a finder that answers from `found`. */
async function unlockPage({ refuse = "pinned_kek_generation", found = note(), lang = "en", finder } = {}) {
  const session = fakeSession();
  session.unlockError = refuse ? coded(refuse) : null;
  const asked = [];
  const restoreNote = finder ?? (async (who) => {
    asked.push(who);
    return found;
  });
  const host = unlockScreen({ session, t: translator(lang), go() {}, onUnlocked() {}, restoreNote, locale: lang });
  await settle();
  find(host, "password").value = PASSWORD_TYPED;
  await submit(find(host, "unlock-form"));
  await settle();
  return { host, session, asked };
}

test("the_unlock_screen_gives_the_restore_text_and_the_way_out_after_an_accepted_restore", async () => {
  await withDom(async () => {
    for (const [lang, catalog] of [["en", EN], ["nb", NB]]) {
      const { host, session, asked } = await unlockPage({ lang });
      assert.equal(textOf(find(host, "error")).trim(), catalog[KEY].replace("{date}", day(lang)));
      assert.deepEqual(asked, [{ accountId: "aa".repeat(16), email: "ada@example.test" }], "the note is asked for by the signed-in account");
      const row = find(host, "forget-row");
      assert.equal(row.hidden, false, `${lang}: the way out is shown`);
      assert.equal(find(host, "forget-link").getAttribute("href"), "#/forget");
      assert.equal(session.unlocks.length, 1, "one try, no retry on its own");
      assert.equal(find(host, "password").value, "");
    }
  });
});

test("the_unlock_screen_keeps_the_attack_text_without_a_note_and_for_other_refusals", async () => {
  await withDom(async () => {
    for (const found of [null, note({ manifestOlder: false })]) {
      const { host } = await unlockPage({ found });
      assert.equal(textOf(find(host, "error")).trim(), EN["account.error.pinned_kek_generation"]);
      assert.match(textOf(find(host, "error")), /can be an attack/);
      assert.equal(find(host, "forget-row").hidden, true, "no extra way out");
    }
    // A finder that fails is no note.
    const failing = await unlockPage({ finder: async () => { throw new Error("disk"); } });
    assert.equal(textOf(find(failing.host, "error")).trim(), EN["account.error.pinned_kek_generation"]);
    // A wrong password asks nobody for a note, and shows no restore text.
    const asked = [];
    const wrong = await unlockPage({ refuse: "decrypt", finder: async (who) => { asked.push(who); return note(); } });
    assert.deepEqual(asked, []);
    assert.equal(textOf(find(wrong.host, "error")).trim(), EN["account.error.decrypt"]);
    assert.equal(find(wrong.host, "forget-row").hidden, true);
    // And a screen without a finder behaves as before.
    const bare = await unlockPage({ finder: undefined, found: null });
    assert.match(textOf(find(bare.host, "error")), /can be an attack/);
  });
});

test("the_forget_link_goes_away_with_the_next_try", async () => {
  await withDom(async () => {
    const { host, session } = await unlockPage();
    assert.equal(find(host, "forget-row").hidden, false);
    session.unlockError = null;
    find(host, "password").value = PASSWORD_TYPED;
    await submit(find(host, "unlock-form"));
    await settle();
    assert.equal(find(host, "forget-row").hidden, true);
    assert.equal(find(host, "error").hidden, true);
  });
});

test("the_restore_text_never_offers_to_lower_a_floor_in_place", async () => {
  // The words of a text that would let the user accept, allow or lower something here.
  const offers = {
    en: /\b(accept|allow|lower|ignore|trust this|continue anyway|proceed|override|reset the)\b/i,
    nb: /\b(godta|tillat|senk|ignorer|stol på|fortsett likevel|overstyr|nullstill)/i,
  };
  for (const [lang, catalog] of [["en", EN], ["nb", NB]]) {
    const text = catalog[KEY];
    assert.doesNotMatch(text, offers[lang], `${lang}: no offer to accept or lower`);
    // The one way out is to forget the server, which removes the record and asks for the secret key again; the other is the operator.
    assert.match(text, lang === "en" ? /“Forget this server”/ : /«Glem denne tjeneren»/);
    assert.match(text, lang === "en" ? /sign in as on a new device/ : /logge inn som på en ny enhet/);
    assert.match(text, lang === "en" ? /tell whoever runs the server/ : /si fra til den som drifter tjeneren/);
    assert.match(text, lang === "en" ? /protect you from an attack/ : /beskytte deg mot et angrep/);
  }
  await withDom(async () => {
    // On the unlock screen the refusal adds a link to the page that forgets the server, and no control that retries or accepts.
    const { host, session } = await unlockPage();
    const controls = [...all(host, "submit"), ...all(host, "forget-link"), ...all(host, "other-account")];
    const everyControl = [...walk(host)]
      .filter((node) => node instanceof FakeElement && ["BUTTON", "A"].includes(String(node.tagName).toUpperCase()))
      .map((node) => node.getAttribute("data-role"));
    assert.deepEqual(everyControl.sort(), ["forget-link", "other-account", "submit"].sort());
    assert.ok(controls.length >= 3);
    assert.equal(session.unlocks.length, 1);
  });
});

test("texts_exist_in_both_languages", () => {
  const placeholders = (text) => [...text.matchAll(/\{([a-z]+)\}/g)].map((m) => m[1]).sort();
  for (const key of [KEY, "syncwarnings.restored.manifest_older"]) {
    assert.equal(typeof EN[key], "string", `en: ${key}`);
    assert.equal(typeof NB[key], "string", `nb: ${key}`);
    assert.notEqual(EN[key], NB[key]);
    assert.deepEqual(placeholders(EN[key]), placeholders(NB[key]), `${key}: the same placeholders`);
  }
  assert.deepEqual(placeholders(EN[KEY]), ["date"]);
  // The Norwegian text says "tjeneren", never "serveren".
  assert.doesNotMatch(NB[KEY], /server/i);
  assert.doesNotMatch(NB["syncwarnings.restored.manifest_older"], /server/i);
});

// ----------------------------------------------------------------- the sign-in page

async function withAccountDom(body) {
  const saved = globalThis.document;
  globalThis.document = accountDocument();
  try {
    return await body();
  } finally {
    if (saved === undefined) delete globalThis.document;
    else globalThis.document = saved;
  }
}

/** The sign-in page over a session that refuses with `code`. */
function loginPage({ info = null, refuse = "pinned_kek_generation", found = note(), lang = "en" } = {}) {
  const asked = [];
  const session = {
    deviceStatus: async () => ({ pinned: true, skBit: false, skStored: false }),
    signIn: async () => { throw accountCoded(refuse); },
    unlock: async () => { throw accountCoded(refuse); },
    current: () => null,
    freshReauth: () => true,
  };
  const root = loginView({
    t: translator(lang),
    session,
    entry: { page: "login", handoff: null, brokenHandoff: false, setupToken: null },
    adminUrl: null,
    api: {},
    go() {},
    handoff: {},
    info,
    restoreNote: async (who) => {
      asked.push(who);
      return found;
    },
    locale: lang,
  });
  return { root, asked };
}

test("the_sign_in_page_gives_the_restore_text_for_the_typed_address", async () => {
  await withAccountDom(async () => {
    for (const [lang, catalog] of [["en", EN], ["nb", NB]]) {
      const { root, asked } = loginPage({ lang });
      await accountSettle();
      byRole(root, "email").value = EMAIL;
      byRole(root, "password").value = PASSWORD;
      await fire(byRole(root, "credentials"), "submit");
      await accountSettle();
      assert.equal(accountText(byRole(root, "error")).trim(), catalog[KEY].replace("{date}", day(lang)));
      assert.deepEqual(asked, [{ accountId: null, email: EMAIL }]);
      assert.ok(byRole(root, "forget-link"), "the page always has the way out");
    }
    // Without a note, the plain warning.
    const plain = loginPage({ found: null });
    await accountSettle();
    byRole(plain.root, "email").value = EMAIL;
    byRole(plain.root, "password").value = PASSWORD;
    await fire(byRole(plain.root, "credentials"), "submit");
    await accountSettle();
    assert.equal(accountText(byRole(plain.root, "error")).trim(), EN["account.error.pinned_kek_generation"]);
  });
});

test("the_sign_in_page_asks_for_the_note_of_the_open_account_when_locked", async () => {
  await withAccountDom(async () => {
    const { root, asked } = loginPage({ info: { accountId: ACCOUNT, email: EMAIL }, refuse: "method_list_changed" });
    await accountSettle();
    byRole(root, "password").value = PASSWORD;
    await fire(byRole(root, "credentials"), "submit");
    await accountSettle();
    assert.deepEqual(asked, [{ accountId: ACCOUNT, email: null }]);
    assert.equal(accountText(byRole(root, "error")).trim(), EN[KEY].replace("{date}", day("en")));
  });
});
