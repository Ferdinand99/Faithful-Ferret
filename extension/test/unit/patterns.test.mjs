// The word lists of the detection module (src/content/patterns.mjs): the terms taken from AliasVault keep their
// source's licence header and are listed in notices-extra.json, and the lists compare text the way the head of the
// file says.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import {
  CONFIRM, LOGIN, NEW, NEXT, OTP, PIN, SEARCH, SIGNUP, SUBMIT, SUBMIT_WORDS, USERNAME, normalize, termsRegex,
} from "../../src/content/patterns.mjs";
import { extensionRoot } from "./buildHelpers.mjs";

const FILE = "extension/src/content/patterns.mjs";
const COMMIT = "7e7cd6f3141c94f884ddd1666987aec3ffcdcdf3";

/**
 * What is missing from an adapted file and its notice: the SPDX line and the change note at the head of the file,
 * the source and its commit named there, and an entry in notices-extra.json for the file with the same source.
 * @param {string} head the first lines of the file @param {any} notices notices-extra.json
 */
function noticeProblems(head, notices) {
  /** @type {string[]} */
  const out = [];
  if (!/^\/\/ SPDX-License-Identifier: AGPL-3\.0-only\n/.test(head)) out.push("no SPDX line first");
  if (!head.includes("// Modified by Faithful Ferret:")) out.push("no change note");
  if (!head.includes("aliasvault/aliasvault") || !head.includes(COMMIT) || !head.includes("FieldPatterns.ts")) out.push("the source is not named");
  const entry = (notices.adapted ?? []).find((/** @type {any} */ a) => Array.isArray(a.files) && a.files.includes(FILE));
  if (!entry) out.push("no entry in notices-extra.json");
  else {
    if (entry.license !== "AGPL-3.0-only" || entry.origin !== "https://github.com/aliasvault/aliasvault") out.push("the entry names another licence or origin");
    if (!String(entry.source).includes("FieldPatterns.ts") || !String(entry.source).includes(COMMIT)) out.push("the entry names another source");
    if (!String(entry.note).startsWith("Modified by Faithful Ferret")) out.push("the entry does not say what was changed");
  }
  return out;
}

test("patterns_carry_their_header_and_notice", () => {
  const head = readFileSync(join(extensionRoot, "src", "content", "patterns.mjs"), "utf8").split("\n").slice(0, 16).join("\n");
  const notices = JSON.parse(readFileSync(join(extensionRoot, "..", "notices-extra.json"), "utf8"));
  assert.deepEqual(noticeProblems(head, notices), []);
  // The check finds what it is for.
  assert.deepEqual(noticeProblems(head.replace("// SPDX-License-Identifier: AGPL-3.0-only\n", ""), notices), ["no SPDX line first"]);
  assert.deepEqual(noticeProblems(head.replace("Modified by Faithful Ferret:", "Changed:"), notices), ["no change note"]);
  assert.deepEqual(noticeProblems(head, { adapted: [] }), ["no entry in notices-extra.json"]);
  // The detection module itself is Faithful Ferret's own code and claims no other source.
  const forms = readFileSync(join(extensionRoot, "src", "content", "forms.mjs"), "utf8");
  assert.equal(forms.includes("SPDX-License-Identifier"), false);
});

test("text_is_compared_in_lower_case_with_separators_as_spaces_and_short_terms_as_words", () => {
  assert.equal(normalize("newPassword"), "new password");
  assert.equal(normalize("user[login]"), "user login");
  assert.equal(normalize("NEW_PASSWORD-confirmation"), "new password confirmation");
  assert.equal(normalize("Bestätigungscode"), "bestätigungscode");
  assert.equal(normalize(undefined), "");
  assert.equal(normalize("x".repeat(2000)).length, 512, "a long attribute is cut");
  // A term of three characters or fewer stands as a word; a longer one may be part of a word.
  const re = termsRegex(["pin", "passwort"]);
  assert.equal(re.test("pin"), true);
  assert.equal(re.test("code pin"), true);
  assert.equal(re.test("spinner"), false);
  assert.equal(re.test("neues passwort"), true);
  assert.equal(re.test("kennpasswortfeld"), true);
  assert.equal(PIN.test(normalize("PIN-Code")), true);
  assert.equal(OTP.test(normalize("one-time-code")), true);
  assert.equal(OTP.test(normalize("2FA")), true);
  assert.equal(OTP.test(normalize("hotpot")), false, "otp and the other short terms are words only");
  assert.equal(SEARCH.test(normalize("Søk")), true);
  assert.equal(USERNAME.test(normalize("Gebruikersnaam")), true);
  assert.equal(CONFIRM.test(normalize("Passwort bestätigen")), true);
  assert.equal(NEW.test(normalize("Nouveau mot de passe")), true);
});

test("the_words_of_a_forms_purpose_cover_the_five_languages", () => {
  for (const words of ["Sign in", "Logg inn", "Anmelden", "Se connecter", "Inloggen"]) assert.equal(LOGIN.test(normalize(words)), true, words);
  for (const words of ["Create account", "Opprett konto", "Konto erstellen", "Créer un compte", "Account aanmaken"]) assert.equal(SIGNUP.test(normalize(words)), true, words);
  for (const words of ["Next", "Neste", "Weiter", "Suivant", "Volgende"]) assert.equal(NEXT.test(normalize(words)), true, words);
  for (const [lang, words] of Object.entries(SUBMIT_WORDS)) {
    for (const w of words) assert.equal(SUBMIT.test(normalize(w)), true, `${lang}: ${w}`);
  }
});
