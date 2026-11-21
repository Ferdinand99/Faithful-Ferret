// Signed writes (spec Fase 1 § 4.6, "The signature"): the nonce, the exact bytes and the proof.
import assert from "node:assert/strict";
import { test } from "node:test";
import { createApi } from "../../src/api.mjs";
import { b64u } from "../../src/b64.mjs";
import { replyShapeOf, signedCall } from "../../src/flows/signedCall.mjs";
import { filled } from "./accountHelpers.mjs";
import { NONCE, PROOF, answer } from "./securityHelpers.mjs";

const BODY = {
  registration_record: b64u.encode(filled(192, 2)),
  ksf_profile: 1,
  wrap: b64u.encode(filled(104, 8)),
  kek_generation: 2,
  manifest: { rev: 2, envelope: b64u.encode(filled(80, 9)), tag: b64u.encode(filled(32, 10)) },
};

/** An environment with a fetch that records what it was sent and a core that records what it signed. */
function rig({ put = () => answer(200, { kek_generation: 2, seq: 12 }), sign } = {}) {
  /** @type {{ method: string, url: string, headers: Record<string, string>, bytes: Uint8Array | null }[]} */
  const sent = [];
  /** @type {{ op: string, nonce: Uint8Array, body: Uint8Array }[]} */
  const signed = [];
  const fetchImpl = async (url, init) => {
    sent.push({
      method: init.method,
      url,
      headers: init.headers,
      bytes: init.body === undefined ? null : init.body instanceof Uint8Array ? init.body.slice() : new TextEncoder().encode(init.body),
    });
    if (url === "/api/auth/challenge") return answer(200, { nonce: b64u.encode(NONCE), expires_in: 300 });
    return put();
  };
  const env = {
    api: createApi({ fetchImpl }),
    client: {
      vault: {
        auth_sign: async (op, nonce, body) => {
          signed.push({ op, nonce: nonce.slice(), body: body.slice() });
          return sign ? sign(op, nonce, body) : PROOF;
        },
      },
    },
  };
  return { env, sent, signed };
}

const call = (env, extra = {}) =>
  signedCall(env, { op: "unlock-method.password.put", method: "PUT", path: "/api/vault/unlock-methods/password", shape: "password_put_req", body: BODY, ...extra });

test("signed_call_signs_the_exact_bytes_it_sends", async () => {
  const { env, sent, signed } = rig();
  const reply = await call(env);
  assert.deepEqual({ ...reply }, { kek_generation: 2, seq: 12 });

  // The challenge comes first, then the write; nothing else is sent.
  assert.deepEqual(sent.map((r) => `${r.method} ${r.url}`), ["POST /api/auth/challenge", "PUT /api/vault/unlock-methods/password"]);
  const put = sent[1];
  // The bytes that were signed are the bytes that were sent: the same array content, and the body the page built.
  assert.equal(signed.length, 1);
  assert.equal(signed[0].op, "unlock-method.password.put");
  assert.deepEqual(signed[0].body, put.bytes);
  assert.deepEqual(put.bytes, new TextEncoder().encode(JSON.stringify(BODY)));
  // The nonce that was signed is the one the server gave, and the headers carry it with the proof.
  assert.deepEqual(signed[0].nonce, NONCE);
  assert.equal(put.headers["Ferret-Nonce"], b64u.encode(NONCE));
  assert.equal(put.headers["Ferret-Proof"], b64u.encode(PROOF));
  assert.equal(put.headers["Ferret-Protocol"], "1");
  // The challenge call has no proof headers.
  assert.equal(sent[0].headers["Ferret-Nonce"], undefined);
});

test("a_signer_that_changes_its_copy_cannot_change_what_is_sent", async () => {
  const { env, sent } = rig();
  await call(env, {
    sign: async (nonce, body) => {
      body.fill(1);
      nonce.fill(1);
      return PROOF;
    },
  });
  assert.deepEqual(sent[1].bytes, new TextEncoder().encode(JSON.stringify(BODY)));
  assert.equal(sent[1].headers["Ferret-Nonce"], b64u.encode(NONCE));
});

test("a_body_that_is_not_the_shape_is_refused_before_anything_is_sent", async () => {
  for (const body of [{ ...BODY, extra: 1 }, { ...BODY, wrap: b64u.encode(filled(72, 1)) }, { ...BODY, kek_generation: -1 }, {}]) {
    const { env, sent, signed } = rig();
    await assert.rejects(call(env, { body }));
    assert.deepEqual([sent.length, signed.length], [0, 0]);
  }
});

test("a_proof_of_the_wrong_length_is_never_sent", async () => {
  for (const proof of [filled(63, 1), filled(65, 1), null, "x"]) {
    const { env, sent } = rig({ sign: () => proof });
    await assert.rejects(call(env), { code: "bad_response" });
    assert.deepEqual(sent.map((r) => r.url), ["/api/auth/challenge"], "only the challenge went out");
  }
});

test("the_answer_is_checked_and_the_servers_refusals_keep_their_codes", async () => {
  // An answer that is not the shape of the reply.
  let rigged = rig({ put: () => answer(200, { kek_generation: "2" }) });
  await assert.rejects(call(rigged.env), { code: "bad_response" });
  // Each refusal the page has a text for arrives as its code, with its status.
  for (const [status, code] of [[403, "reauth_required"], [403, "second_factor_required"], [409, "write_conflict"], [401, "denied"], [422, "bad_request"], [429, "throttled"]]) {
    rigged = rig({ put: () => answer(status, { error: code }) });
    await assert.rejects(call(rigged.env), (error) => error.status === status && error.code === code);
  }
  // A refused challenge stops the call before the write.
  const sent = [];
  const env = {
    api: createApi({ fetchImpl: async (url, init) => {
      sent.push(`${init.method} ${url}`);
      return answer(429, { error: "throttled" });
    } }),
    client: { vault: { auth_sign: async () => assert.fail("nothing to sign") } },
  };
  await assert.rejects(call(env), { code: "throttled" });
  assert.deepEqual(sent, ["POST /api/auth/challenge"]);
});

test("the_reply_shape_follows_the_request_shape", () => {
  assert.equal(replyShapeOf("password_put_req"), "password_put_res");
  assert.equal(replyShapeOf("recovery_put_req"), "recovery_put_res");
  assert.equal(replyShapeOf("recover_req"), "recover_res");
  assert.equal(replyShapeOf("login_start_res"), undefined);
  assert.equal(replyShapeOf("no_such_req"), undefined);
});

test("a_failure_of_the_write_is_marked_as_after_the_send_and_one_of_the_challenge_is_not", async () => {
  const rigged = rig({ put: () => answer(500, { error: "internal" }) });
  await assert.rejects(call(rigged.env), (error) => error.afterSend === true && error.status === 500);
  const env = {
    api: createApi({ fetchImpl: async () => {
      throw new Error("offline");
    } }),
    client: { vault: { auth_sign: async () => assert.fail("nothing to sign") } },
  };
  await assert.rejects(call(env), (error) => error.code === "network" && error.afterSend === undefined);
});
