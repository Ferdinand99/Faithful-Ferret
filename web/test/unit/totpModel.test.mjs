// The pure parts of the one-time password screens: the grouping of a code, the reading of the field, the address a bare secret
// becomes, the host warning, and the clock that keeps a code current. The reference code in the helpers is checked against the
// RFC 6238 vectors first, so every other test can trust it.
import assert from "node:assert/strict";
import { test } from "node:test";
import { groupCode, labelOf, namesOwnHost, readInput, uriFromSecret } from "../../src/views/totpModel.mjs";
import { codeTicker } from "../../src/views/totpTicker.mjs";
import { RFC_SECRET, encodeBase32, parseUri, reference } from "./totpHelpers.mjs";
import { fakeClock, settle } from "./vaultHelpers.mjs";

test("the_reference_code_matches_the_rfc_6238_vectors", () => {
  // RFC 6238 appendix B: the 8 digit codes for SHA-1 with the ASCII secret 12345678901234567890.
  const sha1 = { secret: RFC_SECRET, digits: 8 };
  assert.equal(reference(sha1, 59), "94287082");
  assert.equal(reference(sha1, 1111111109), "07081804");
  assert.equal(reference(sha1, 1111111111), "14050471");
  assert.equal(reference(sha1, 1234567890), "89005924");
  assert.equal(reference(sha1, 2000000000), "69279037");
  assert.equal(reference(sha1, 20000000000), "65353130");
  // The same codes with 6 digits are the last 6 of those.
  assert.equal(reference({ secret: RFC_SECRET }, 59), "287082");
  // SHA-256 and SHA-512 use secrets of 32 and 64 bytes (the ASCII digits repeated), also from appendix B.
  const digits = "1234567890";
  const secret = (bytes) => encodeBase32(Buffer.from(digits.repeat(7).slice(0, bytes)));
  assert.equal(reference({ secret: secret(32), algorithm: "SHA256", digits: 8 }, 59), "46119246");
  assert.equal(reference({ secret: secret(64), algorithm: "SHA512", digits: 8 }, 59), "90693936");
  assert.equal(reference({ secret: secret(32), algorithm: "SHA256", digits: 8 }, 1111111109), "68084774");
  assert.equal(reference({ secret: secret(64), algorithm: "SHA512", digits: 8 }, 1111111109), "25091201");
});

test("a_code_is_written_in_groups_of_three_or_four", () => {
  assert.equal(groupCode("287082"), "287 082");
  assert.equal(groupCode("94287082"), "9428 7082");
  assert.equal(groupCode("1234567"), "123 4567");
  assert.equal(groupCode("12345"), "12345");
});

test("the_field_is_read_as_an_address_or_a_bare_secret", () => {
  assert.deepEqual(readInput(""), { kind: "empty" });
  assert.deepEqual(readInput("   \n"), { kind: "empty" });
  assert.deepEqual(readInput("jbsw y3dp ehpk 3pxp"), { kind: "secret", secret: "JBSWY3DPEHPK3PXP" });
  assert.deepEqual(readInput(" JBSWY3DPEHPK3PXP== "), { kind: "secret", secret: "JBSWY3DPEHPK3PXP==" });
  assert.deepEqual(readInput(" otpauth://totp/x?secret=JBSWY3DP "), { kind: "uri", uri: "otpauth://totp/x?secret=JBSWY3DP" });
  // Whatever is not a Base32 secret goes to the core as it is, which refuses it.
  assert.equal(readInput("steam://JBSWY3DP").kind, "uri");
  assert.equal(readInput("otpauth://hotp/x?secret=JBSWY3DP&counter=1").kind, "uri");
  assert.equal(readInput("JBSWY3DP1").kind, "uri");
});

test("a_bare_secret_becomes_an_address_with_the_defaults_and_the_name_as_label", () => {
  const uri = uriFromSecret("JBSWY3DPEHPK3PXP", "My bank");
  assert.equal(uri, "otpauth://totp/My%20bank?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&period=30");
  assert.deepEqual(parseUri(uri), { secret: "JBSWY3DPEHPK3PXP", algorithm: "SHA1", digits: 6, period: 30, issuer: null, label: "My bank" });
  // A colon in the name would be read as the issuer separator, a control character is dropped, a long name is cut to 200 bytes.
  assert.equal(labelOf("Acme: admin\u0000"), "Acme admin");
  assert.equal(labelOf("   "), "account");
  assert.ok(new TextEncoder().encode(labelOf("å".repeat(300))).length <= 200);
  assert.equal(parseUri(uriFromSecret("JBSWY3DP", "A:b (c) 'd' *!")).issuer, null, "no issuer from a colon in the name");
});

test("the_host_warning_matches_the_issuer_or_the_label_ignoring_case", () => {
  const hosts = ["vault.example.test", "vault.example.test:8443"];
  assert.equal(namesOwnHost({ issuer: "Vault.Example.Test", label: "ada" }, ...hosts), true);
  assert.equal(namesOwnHost({ issuer: null, label: "ada@vault.example.test" }, ...hosts), true);
  assert.equal(namesOwnHost({ issuer: "GitHub", label: "ada" }, ...hosts), false);
  assert.equal(namesOwnHost({ issuer: "GitHub", label: "ada" }, "", undefined), false);
  assert.equal(namesOwnHost(null, ...hosts), false);
});

/** A ticker over a fake clock; `load` makes the reference code and counts its calls. */
function tickerOver(clock, { digits = 6, period = 30, active = () => true, fail = false } = {}) {
  const seen = { loads: [], codes: [], lefts: [], errors: 0 };
  const ticker = codeTicker({
    clock,
    active,
    load: async (seconds) => {
      seen.loads.push(seconds);
      if (fail) throw new Error("x");
      return { code: reference({ secret: RFC_SECRET, digits, period }, seconds), seconds_left: period - (seconds % period) };
    },
    onCode: (code, left) => seen.codes.push([code, left]),
    onLeft: (left) => seen.lefts.push(left),
    onError: () => {
      seen.errors += 1;
    },
  });
  return { ticker, seen };
}

test("the_ticker_asks_when_a_code_runs_out_and_counts_down_in_between", async () => {
  const clock = fakeClock(54_000); // 6 s before the second period starts
  const { ticker, seen } = tickerOver(clock);
  await ticker.start();
  assert.deepEqual(seen.loads, [54]);
  assert.deepEqual(seen.codes, [[reference({ secret: RFC_SECRET }, 54), 6]]);
  clock.advance(1_010);
  await settle();
  assert.deepEqual(seen.loads, [54], "a tick in the same period makes no new code");
  assert.deepEqual(seen.lefts, [5]);
  clock.advance(4_000);
  await settle();
  assert.deepEqual(seen.lefts.slice(-1), [1]);
  assert.equal(seen.codes.length, 1);
  clock.advance(1_000);
  await settle();
  assert.deepEqual(seen.loads, [54, 60], "the next period asks again");
  assert.equal(seen.codes[1][0], reference({ secret: RFC_SECRET }, 60));
  assert.equal(seen.codes[1][1], 30);
  ticker.stop();
  const before = seen.loads.length;
  clock.advance(120_000);
  await settle();
  assert.equal(seen.loads.length, before, "a stopped ticker asks for nothing");
  assert.equal(clock.pending, 0, "and holds no timer");
});

test("a_reply_that_comes_after_stop_is_dropped_and_an_error_ends_the_ticking", async () => {
  const clock = fakeClock(1_000_000);
  let release = () => {};
  const seen = { codes: 0, errors: 0 };
  const ticker = codeTicker({
    clock,
    load: () => new Promise((resolve) => {
      release = () => resolve({ code: "123456", seconds_left: 10 });
    }),
    onCode: () => {
      seen.codes += 1;
    },
    onLeft: () => {},
    onError: () => {
      seen.errors += 1;
    },
  });
  const started = ticker.start();
  ticker.stop();
  release();
  await started;
  assert.equal(seen.codes, 0, "the code of a stopped run is not shown");
  assert.equal(clock.pending, 0);

  const failing = tickerOver(clock, { fail: true });
  await failing.ticker.start();
  assert.equal(failing.seen.errors, 1);
  assert.equal(clock.pending, 0, "after an error no timer is left");

  // A reply that is not a code is an error too, never a blank or odd value on the screen.
  const odd = codeTicker({ clock, load: async () => ({ code: "12ab56", seconds_left: 5 }), onCode: () => assert.fail("shown"), onLeft: () => {}, onError: () => { seen.errors += 1; } });
  await odd.start();
  assert.equal(seen.errors, 1);
});

test("a_ticker_that_is_no_longer_active_stops_at_its_next_tick", async () => {
  const clock = fakeClock(10_000);
  let on = true;
  const { ticker, seen } = tickerOver(clock, { active: () => on });
  await ticker.start();
  clock.advance(2_010);
  await settle();
  assert.equal(seen.lefts.length, 2);
  on = false;
  clock.advance(1_000);
  await settle();
  assert.equal(seen.lefts.length, 2);
  assert.equal(clock.pending, 0);
});
