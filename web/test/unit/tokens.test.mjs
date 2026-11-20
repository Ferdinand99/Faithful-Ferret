// The tokens of a device client: one renewal at a time, the new refresh token
// stored before the new access token is used, the final refusals, sign-in and
// sign-out. Spec: Fase 1 § 7.6; RFC 9449.
import assert from "node:assert/strict";
import { test } from "node:test";
import { ApiError, createApi } from "../../src/api.mjs";
import { generateDeviceKey, loadDeviceKey, saveDeviceKey } from "../../src/auth/deviceKey.mjs";
import { createClock } from "../../src/auth/dpop.mjs";
import { createTokenAuth, REFRESH_PATH, REVOKE_PATH } from "../../src/auth/tokens.mjs";
import { freshStore } from "./idbHelpers.mjs";
import {
  ACCOUNT, answer, claimsOf, DEVICE, fakeServer, headerOf, LOCAL_MS, loginRes, refusal, SERVER, signedInDevice, tok, tokenRes,
  verifies,
} from "./tokenHelpers.mjs";

const CHANGES = "/api/sync/changes";
const changes = { items: [], next: 0, more: false };

/** Runs `promise` and returns the ApiError it rejects with. */
async function failure(promise) {
  try {
    await promise;
  } catch (error) {
    assert.ok(error instanceof ApiError, `expected an ApiError, got ${error}`);
    return error;
  }
  return assert.fail("expected an ApiError");
}

test("refresh_writes_the_new_refresh_token_before_using_the_new_access_token", async () => {
  const { db, key, server, api } = await signedInDevice();
  /** @type {string[]} */
  const storedWhenUsed = [];
  server.handle = async (call) => {
    if (call.path === REFRESH_PATH) {
      assert.deepEqual(call.body, { refresh_token: tok(2) });
      return answer(200, tokenRes(tok(3), tok(4)));
    }
    if (call.headers.Authorization === `DPoP ${tok(1)}`) return refusal("token_expired");
    // The new access token reaches the server only after the new refresh token is in the record.
    storedWhenUsed.push((await loadDeviceKey(db.store, SERVER))?.refreshToken ?? "none");
    return answer(200, changes);
  };
  assert.deepEqual({ ...(await api.get(CHANGES)) }, changes);
  assert.deepEqual(storedWhenUsed, [tok(4)]);
  assert.deepEqual(server.calls.map((c) => c.path), [CHANGES, REFRESH_PATH, CHANGES]);
  assert.equal(server.calls[2].headers.Authorization, `DPoP ${tok(3)}`);

  // When the new refresh token cannot be written, the new access token is never used.
  const other = await generateDeviceKey(SERVER);
  server.calls.length = 0;
  server.handle = async (call) => {
    if (call.path === REFRESH_PATH) {
      // A newer sign-in on this server took the record while the renewal was under way.
      await saveDeviceKey(db.store, other, { deviceId: DEVICE, accountId: ACCOUNT, refreshToken: tok(9) });
      return answer(200, tokenRes(tok(5), tok(6)));
    }
    return refusal("token_expired");
  };
  await assert.rejects(api.get(CHANGES), (error) => error.code === "device_key_missing");
  assert.deepEqual(server.calls.map((c) => c.headers.Authorization ?? "proof only"), [`DPoP ${tok(3)}`, "proof only"]);
  const kept = await loadDeviceKey(db.store, SERVER);
  assert.equal(kept?.refreshToken, tok(9), "the newer device's record is left as it is");
  assert.deepEqual(kept?.publicJwk, other.publicJwk);
  assert.notDeepEqual(other.publicJwk, key.publicJwk);
});

test("a_lost_refresh_answer_is_retried_with_the_same_token", async () => {
  const { db, server, auth, api } = await signedInDevice();
  let lose = true;
  server.handle = (call) => {
    if (call.path === REFRESH_PATH) {
      if (lose) {
        lose = false;
        throw new TypeError("the connection dropped");
      }
      return answer(200, tokenRes(tok(3), tok(4)));
    }
    return call.headers.Authorization === `DPoP ${tok(3)}` ? answer(200, changes) : refusal("token_expired");
  };
  const lost = await failure(api.get(CHANGES));
  assert.equal(lost.code, "network");
  assert.equal(auth.state, "ok", "a lost answer ends nothing");
  assert.equal((await loadDeviceKey(db.store, SERVER))?.refreshToken, tok(2), "the record still has the token that was sent");

  assert.deepEqual({ ...(await api.get(CHANGES)) }, changes);
  const renewals = server.to(REFRESH_PATH);
  assert.equal(renewals.length, 2);
  assert.deepEqual(renewals.map((c) => c.body.refresh_token), [tok(2), tok(2)], "the same refresh token is sent again");
  const [first, second] = renewals.map((c) => claimsOf(c.headers.DPoP));
  assert.notEqual(first.jti, second.jti, "with a new proof");
  for (const claims of [first, second]) {
    assert.equal(claims.htm, "POST");
    assert.equal(claims.htu, `${SERVER}${REFRESH_PATH}`);
    assert.equal(claims.ath, undefined, "a renewal carries no access token");
  }
  assert.equal((await loadDeviceKey(db.store, SERVER))?.refreshToken, tok(4));
});

test("one_renewal_at_a_time", async () => {
  const { server, auth } = await signedInDevice();
  /** @type {(value: Response) => void} */
  let release = () => {};
  const asked = new Promise((called) => {
    server.handle = (call) => {
      assert.equal(call.path, REFRESH_PATH);
      called(undefined);
      return new Promise((resolve) => {
        release = resolve;
      });
    };
  });
  const used = await auth.prepare("GET", `${SERVER}${CHANGES}`);
  const renewals = [auth.refresh(used), auth.refresh(used), auth.refresh()];
  await asked;
  // A fourth ask while the answer is still out joins the same renewal.
  renewals.push(auth.refresh(used));
  release(answer(200, tokenRes(tok(3), tok(4))));
  await Promise.all(renewals);
  assert.equal(server.calls.length, 1, "four asks, one renewal");
  // The headers of an attempt made before the renewal ask for nothing more once the token has changed.
  await auth.refresh(used);
  assert.equal(server.calls.length, 1);
  assert.equal((await auth.prepare("GET", `${SERVER}${CHANGES}`)).Authorization, `DPoP ${tok(3)}`);
});

test("device_revoked_and_token_reused_are_terminal_and_clear_the_tokens", async () => {
  // From a sync route, and from the renewal.
  const cases = [
    ["device_revoked", "sync"],
    ["token_reused", "sync"],
    ["device_revoked", "refresh"],
    ["token_reused", "refresh"],
  ];
  for (const [code, where] of cases) {
    const { db, server, auth, api } = await signedInDevice();
    server.handle = (call) => {
      if (call.path === REFRESH_PATH) return refusal(code);
      return where === "sync" ? refusal(code) : refusal("token_expired");
    };
    const error = await failure(api.get(CHANGES));
    assert.equal(error.code, code, `${code} from ${where}`);
    assert.equal(auth.state, "revoked");
    assert.equal(await loadDeviceKey(db.store, SERVER), null, "the record with the refresh token is gone");
    assert.deepEqual(
      server.calls.map((c) => c.path),
      where === "sync" ? [CHANGES] : [CHANGES, REFRESH_PATH],
      "no retry after a final refusal",
    );

    // Nothing is sent with the tokens again.
    const sent = server.calls.length;
    assert.equal((await failure(api.get(CHANGES))).code, "device_revoked");
    assert.equal((await failure(api.stream("/api/sync/events"))).code, "device_revoked");
    await assert.rejects(auth.refresh(), (e) => e instanceof ApiError && e.code === "device_revoked");
    await assert.rejects(auth.prepare("GET", `${SERVER}${CHANGES}`), (e) => e instanceof ApiError && e.code === "device_revoked");
    assert.equal(server.calls.length, sent);
  }
});

test("token_expired_on_refresh_signs_out", async () => {
  const { db, server, auth, api } = await signedInDevice();
  server.handle = () => refusal("token_expired");
  const error = await failure(api.get(CHANGES));
  assert.equal(error.code, "token_expired");
  assert.equal(auth.state, "signed_out");
  assert.equal(await loadDeviceKey(db.store, SERVER), null);
  assert.deepEqual(server.calls.map((c) => c.path), [CHANGES, REFRESH_PATH], "one renewal, no second one");

  const sent = server.calls.length;
  assert.equal((await failure(api.get(CHANGES))).code, "signed_out");
  assert.equal(server.calls.length, sent);
});

test("a_refusal_that_is_not_final_keeps_the_tokens", async () => {
  for (const [status, code] of [[429, "throttled"], [503, "busy"], [401, "dpop_invalid"]]) {
    const { db, server, auth, api } = await signedInDevice();
    server.handle = (call) => (call.path === REFRESH_PATH ? answer(status, { error: code }) : refusal("token_expired"));
    assert.equal((await failure(api.get(CHANGES))).code, code);
    assert.equal(auth.state, "ok");
    assert.equal((await loadDeviceKey(db.store, SERVER))?.refreshToken, tok(2));
    // A proof refused at the renewal is sent once more after the clock resync, never more.
    assert.equal(server.to(REFRESH_PATH).length, code === "dpop_invalid" ? 2 : 1);
  }
});

test("accept_signs_the_older_device_out_before_storing_the_new_one", async () => {
  const db = await freshStore();
  const clock = createClock({ now: () => LOCAL_MS });
  const older = await generateDeviceKey(SERVER);
  await saveDeviceKey(db.store, older, { deviceId: DEVICE, accountId: ACCOUNT, refreshToken: tok(9) });

  const key = await generateDeviceKey(SERVER);
  const server = fakeServer();
  /** @type {Array<string | null>} */
  const storedDuringSignOut = [];
  server.handle = async (call) => {
    assert.equal(call.path, REVOKE_PATH);
    storedDuringSignOut.push((await loadDeviceKey(db.store, SERVER))?.refreshToken ?? null);
    return answer(204, null);
  };
  const auth = createTokenAuth({ serverUrl: SERVER, store: db.store, key, clock, fetchImpl: server.fetchImpl });
  assert.equal(auth.state, "signed_out");
  await auth.accept(loginRes(tok(3), tok(4)));

  assert.equal(server.calls.length, 1);
  const [revoke] = server.calls;
  assert.deepEqual(revoke.body, { refresh_token: tok(9) });
  assert.equal(revoke.init.credentials, "omit");
  assert.equal(revoke.headers["Ferret-Protocol"], "1");
  assert.equal(revoke.headers.Authorization, undefined);
  assert.deepEqual(headerOf(revoke.headers.DPoP).jwk, older.publicJwk, "the older device signs its own sign-out");
  assert.equal(await verifies(revoke.headers.DPoP, older.publicJwk), true);
  assert.deepEqual(storedDuringSignOut, [tok(9)], "the older record is replaced only after its sign-out");

  const stored = await loadDeviceKey(db.store, SERVER);
  assert.deepEqual(stored?.publicJwk, key.publicJwk);
  assert.equal(stored?.refreshToken, tok(4));
  assert.equal(stored?.deviceId, DEVICE);
  assert.equal(auth.state, "ok");
  assert.equal((await auth.prepare("GET", `${SERVER}${CHANGES}`)).Authorization, `DPoP ${tok(3)}`);

  // When the server cannot be reached, the new device is stored all the same.
  const next = await generateDeviceKey(SERVER);
  server.handle = () => {
    throw new TypeError("offline");
  };
  const nextAuth = createTokenAuth({ serverUrl: SERVER, store: db.store, key: next, clock, fetchImpl: server.fetchImpl });
  await nextAuth.accept(loginRes(tok(5), tok(6)));
  assert.equal(server.to(REVOKE_PATH).at(-1)?.body.refresh_token, tok(4));
  assert.deepEqual((await loadDeviceKey(db.store, SERVER))?.publicJwk, next.publicJwk);
  assert.equal(nextAuth.state, "ok");
});

test("accept_refuses_what_is_not_the_answer_of_a_device_sign_in", async () => {
  const db = await freshStore();
  const key = await generateDeviceKey(SERVER);
  const server = fakeServer();
  const auth = createTokenAuth({ serverUrl: SERVER, store: db.store, key, clock: createClock(), fetchImpl: server.fetchImpl });
  const bad = [
    null,
    "token",
    { ...loginRes(), token_type: "Bearer" },
    { ...loginRes(), access_token: "short" },
    { ...loginRes(), extra: 1 },
    (({ device_id: _, ...rest }) => rest)(loginRes()),
  ];
  for (const value of bad) {
    await assert.rejects(auth.accept(value), TypeError);
  }
  assert.equal(auth.state, "signed_out");
  assert.equal(await loadDeviceKey(db.store, SERVER), null);
  assert.equal(server.calls.length, 0);
});

test("revoke_signs_the_device_out_and_forgets_its_tokens", async () => {
  for (const reachable of [true, false]) {
    const { db, key, server, auth } = await signedInDevice();
    server.handle = () => {
      if (!reachable) throw new TypeError("offline");
      return answer(204, null);
    };
    if (reachable) await auth.revoke();
    else assert.equal((await failure(auth.revoke())).code, "network");
    const [call] = server.calls;
    assert.equal(call.path, REVOKE_PATH);
    assert.deepEqual(call.body, { refresh_token: tok(2) });
    assert.equal(call.headers.Authorization, undefined);
    assert.equal(await verifies(call.headers.DPoP, key.publicJwk), true);
    assert.equal(auth.state, "signed_out", "the tokens are forgotten even when the server cannot be reached");
    assert.equal(await loadDeviceKey(db.store, SERVER), null);
    await assert.rejects(auth.prepare("GET", `${SERVER}${CHANGES}`), (e) => e instanceof ApiError && e.code === "signed_out");
  }
});

test("a_stored_device_renews_before_its_first_request", async () => {
  const { db, clock, key, server } = await signedInDevice();
  // A new start: the key comes from the store, the access token is gone.
  const loaded = await loadDeviceKey(db.store, SERVER);
  assert.ok(loaded);
  const auth = createTokenAuth({ serverUrl: SERVER, store: db.store, key: loaded, clock, fetchImpl: server.fetchImpl });
  assert.equal(auth.state, "ok");
  server.handle = (call) => (call.path === REFRESH_PATH ? answer(200, tokenRes(tok(3), tok(4))) : answer(200, changes));
  const api = createApi({ base: SERVER, fetchImpl: server.fetchImpl, auth });
  assert.deepEqual({ ...(await api.get(CHANGES)) }, changes);
  assert.deepEqual(server.calls.map((c) => c.path), [REFRESH_PATH, CHANGES]);
  assert.equal(server.calls[1].headers.Authorization, `DPoP ${tok(3)}`);
  assert.deepEqual(headerOf(server.calls[1].headers.DPoP).jwk, key.publicJwk);
});

test("a_replaced_device_leaves_the_newer_record_alone", async () => {
  const { db, server, auth, api } = await signedInDevice();
  const newer = await generateDeviceKey(SERVER);
  await saveDeviceKey(db.store, newer, { deviceId: DEVICE, accountId: ACCOUNT, refreshToken: tok(9) });
  server.handle = () => refusal("token_expired");
  assert.equal((await failure(api.get(CHANGES))).code, "signed_out");
  assert.equal(auth.state, "signed_out");
  assert.deepEqual(server.calls.map((c) => c.path), [CHANGES], "the newer device's refresh token is never sent");
  assert.equal((await loadDeviceKey(db.store, SERVER))?.refreshToken, tok(9));

  // Ending the tokens of the replaced device does not remove the newer record either.
  await auth.revoke();
  assert.equal((await loadDeviceKey(db.store, SERVER))?.refreshToken, tok(9));
});

test("the_clock_follows_only_a_401_answer_of_the_server_itself", async () => {
  const offsets = [];
  const { clock, auth } = await signedInDevice();
  const at = (/** @type {number} */ seconds) => new Date(LOCAL_MS + seconds * 1000).toUTCString();
  const shifted = (/** @type {Response} */ response, props) => {
    for (const [name, value] of Object.entries(props)) Object.defineProperty(response, name, { value });
    return response;
  };
  const before = clock.nowSeconds();
  const ignored = [
    answer(200, {}, { date: at(100) }),
    answer(204, null, { date: at(100) }),
    answer(400, { error: "bad_request" }, { date: at(100) }),
    refusal("dpop_invalid", { date: at(100), headers: { "cache-control": "max-age=60" } }),
    refusal("dpop_invalid", { date: at(100), headers: { "cache-control": "no-cache" } }),
    shifted(refusal("dpop_invalid", { date: at(100) }), { redirected: true }),
    shifted(refusal("dpop_invalid", { date: at(100) }), { url: "https://proxy.example/api/sync/changes" }),
    shifted(refusal("dpop_invalid", { date: at(100) }), { type: "opaqueredirect" }),
  ];
  for (const response of ignored) {
    auth.observe(response);
    offsets.push(clock.nowSeconds() - before);
  }
  assert.deepEqual(offsets, ignored.map(() => 0));

  auth.observe(shifted(refusal("dpop_invalid", { date: at(100) }), { url: `${SERVER}/api/sync/changes` }));
  assert.equal(clock.nowSeconds() - before, 100);
  auth.observe(refusal("dpop_invalid", { date: at(-30), headers: { "cache-control": "private, no-store" } }));
  assert.equal(clock.nowSeconds() - before, -30, "each 401 of the server resyncs");
});

test("a_token_goes_to_its_own_server_only", async () => {
  const { server, auth } = await signedInDevice();
  for (const url of ["https://other.example/api/sync/changes", "/api/sync/changes", "http://vault.example/api/sync/changes", "not a url"]) {
    await assert.rejects(auth.prepare("GET", url), TypeError);
  }
  const api = createApi({ base: "https://other.example", fetchImpl: server.fetchImpl, auth });
  await assert.rejects(api.get(CHANGES), TypeError);
  assert.equal(server.calls.length, 0);
});

test("the_token_auth_shows_no_token", async () => {
  const { auth } = await signedInDevice();
  assert.equal(JSON.stringify(auth), '{"state":"ok"}');
  assert.ok(Object.isFrozen(auth));
  for (const name of Object.keys(auth)) assert.ok(!String(Reflect.get(auth, name)).includes(tok(1)));
});
