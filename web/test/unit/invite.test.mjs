// The check of an invitation link before the person chooses a master password
// (`POST /api/auth/invite/check`), and the texts of the refusals a join can meet.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { createApi } from "../../src/api.mjs";
import { checkInvite } from "../../src/flows/invite.mjs";
import { createI18n } from "../../src/i18n.mjs";
import { describeError, KNOWN_ERRORS } from "../../src/views/form.mjs";
import { web } from "./helpers.mjs";

const INVITE = "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dE3fG5hJ7kL9x";

const json = (value, status = 200, headers = {}) =>
  new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json", ...headers } });

/** An API client whose server answers `answer` and records what it was sent. */
function apiAnswering(answer) {
  const requests = [];
  const fetchImpl = async (url, init) => {
    requests.push({ url, method: init.method, body: init.body === undefined ? undefined : JSON.parse(typeof init.body === "string" ? init.body : new TextDecoder().decode(init.body)) });
    return typeof answer === "function" ? answer() : answer.clone();
  };
  return { api: createApi({ fetchImpl }), requests };
}

test("check_invite_asks_the_server_with_the_token_in_the_body_and_reads_the_answer", async () => {
  const { api, requests } = apiAnswering(json({ expires_at: 1_800_604_800, invited_by: "ada@example.test" }));
  const answer = await checkInvite(api, INVITE);
  assert.deepEqual(answer, { ok: true, expiresAt: 1_800_604_800, invitedBy: "ada@example.test" });
  assert.equal(requests.length, 1);
  assert.equal(requests[0].method, "POST");
  assert.equal(requests[0].url, "/api/auth/invite/check");
  assert.deepEqual(requests[0].body, { invite: INVITE });
  assert.ok(!requests[0].url.includes(INVITE));

  // An inviter whose account is gone is "".
  const gone = await checkInvite(apiAnswering(json({ expires_at: 5, invited_by: "" })).api, INVITE);
  assert.deepEqual(gone, { ok: true, expiresAt: 5, invitedBy: "" });
});

test("check_invite_answers_a_refusal_with_its_code_and_never_throws", async () => {
  for (const [body, status, code] of [
    [{ error: "invite_invalid" }, 403, "invite_invalid"],
    [{ error: "throttled" }, 429, "throttled"],
    [{ error: "internal" }, 500, "internal"],
  ]) {
    assert.deepEqual(await checkInvite(apiAnswering(json(body, status)).api, INVITE), { ok: false, code }, code);
  }
  // An answer of the wrong form is not taken as a good link.
  const odd = await checkInvite(apiAnswering(json({ expires_at: "soon", invited_by: "x" })).api, INVITE);
  assert.equal(odd.ok, false);
  assert.equal(odd.code, "bad_response");
  // No server at all.
  const offline = createApi({ fetchImpl: async () => { throw new TypeError("offline"); } });
  assert.deepEqual(await checkInvite(offline, INVITE), { ok: false, code: "network" });
  // A malformed token is refused here, without a request.
  const { api, requests } = apiAnswering(json({ expires_at: 1, invited_by: "" }));
  for (const bad of ["", INVITE.slice(1), `${INVITE}a`, `${INVITE.slice(1)}-`, null, 42]) {
    assert.deepEqual(await checkInvite(api, /** @type {any} */ (bad)), { ok: false, code: "invite_invalid" });
  }
  assert.equal(requests.length, 0);
});

test("invite_invalid_email_taken_and_registration_closed_have_their_texts", () => {
  const catalog = (lang) => JSON.parse(readFileSync(join(web, "src", "locales", lang, "account.json"), "utf8"));
  const i18n = (lang) => createI18n({ en: catalog("en"), nb: catalog("nb") }, lang);
  for (const code of ["invite_invalid", "email_taken", "registration_closed"]) {
    assert.ok(KNOWN_ERRORS.includes(code), code);
    for (const lang of ["en", "nb"]) {
      const text = describeError(i18n(lang).t, { code });
      assert.notEqual(text, i18n(lang).t("account.error.unknown"), `${lang} ${code}`);
      assert.ok(!text.includes(`(${code})`), `${lang} ${code}: the general text`);
    }
  }
  const en = i18n("en").t;
  // A dead link says it no longer works, whatever the reason, and what to do.
  assert.match(describeError(en, { code: "invite_invalid" }), /invitation link/i);
  assert.match(describeError(en, { code: "invite_invalid" }), /new link/i);
  // A taken e-mail asks for another one.
  assert.match(describeError(en, { code: "email_taken" }), /another e-mail/i);
  assert.match(describeError(i18n("nb").t, { code: "email_taken" }), /e-post/i);
  // The first administrator's refusal keeps its text.
  assert.match(describeError(en, { code: "registration_closed" }), /first administrator already exists/);
});
