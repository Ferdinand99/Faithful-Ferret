// The answer objects of the passkey script (src/content/passkeyResponse.mjs) in real Firefox (Release and ESR), against the
// browser's own objects from a WebDriver virtual authenticator (design document § 9.5 and § 10.8):
//
//   response_objects_match_the_browsers_own_field_for_field
//
// The page (test/fixtures/passkey-pages/pk-response) makes a registration and a sign-in with the browser's own WebAuthn, builds
// the same answer again from the same bytes with the builder of the script, and lists every difference a script of the page
// can see: `Object.keys`, `for...in` and its order, the tag, the kind and flags of each member (and the names and lengths of
// the functions), the prototypes behind the object, `instanceof`, what each member and method gives, and `JSON.stringify`. What
// can not be the same (an object of a script is not a platform object) is listed as `known` and asserted as it is.
//
// The extension is not asked to answer here; the test add-on only has to be installed, as in every spec of this folder.
import assert from "node:assert/strict";
import { after, describe, test } from "node:test";
import { builderScript } from "./passkeyAnswer.mjs";
import { channels, fixtures, launch, stopFixtures } from "./harness.mjs";

after(() => stopFixtures());

/** The soft token answers (the virtual authenticator), the USB token does not. */
const PREFS = Object.freeze({ "security.webauth.webauthn_enable_softtoken": true, "security.webauth.webauthn_enable_usbtoken": false });

/** What cannot be the same, and how it is: the brand of the browser's own functions, and what a platform object does that ours does not. */
const KNOWN = Object.freeze({
  "the object's own prototype is the browser's": false,
  "then in object": true,
});

describe("passkey_response", () => {
  test("response_objects_match_the_browsers_own_field_for_field", async () => {
    const script = builderScript();
    for (const channel of channels()) {
      const session = await launch({ channel, prefs: PREFS });
      try {
        await session.addVirtualAuthenticator();
        const server = await fixtures();
        await session.navigate(server.url("fixture.test", "/pk-response/"));
        await session.waitFor(() => session.content(() => document.getElementById("go") !== null), 15_000, "the page");
        await session.content((/** @type {string} */ text) => {
          const element = document.createElement("script");
          element.textContent = text;
          document.head.append(element);
        }, script);
        const [go] = await session.findAll("#go");
        await session.click(go);
        const raw = await session.waitFor(() => session.content(() => document.documentElement.dataset.result), 30_000, "the comparison");
        const result = JSON.parse(raw);
        assert.equal(result.error, undefined, `${channel}: ${result.error}`);
        for (const kind of ["create", "get"]) {
          const { differences, known, seen } = result[kind];
          console.error(`${channel} ${kind}: browser's own: ${JSON.stringify(seen)}`);
          console.error(`${channel} ${kind}: known: ${JSON.stringify(known)}`);
          assert.deepEqual(differences, [], `${channel} ${kind}: what a script of the page can see differs`);
          // What is left that differs is what it must be.
          for (const [what, value] of Object.entries(KNOWN)) {
            for (const name of [`${kind} credential`, `${kind} response`]) {
              const key = `${name}: ${what}`;
              if (what === "then in object" && name.endsWith("response")) continue;
              assert.equal(known[key], value, `${channel}: ${key}`);
            }
          }
          // The browser's own methods do not work on ours (they check their brand), as on any object that is not the browser's.
          for (const [key, value] of Object.entries(known)) {
            if (/the browser's \w+ on ours$/.test(key)) assert.match(String(value), /^throws TypeError$/, `${channel}: ${key}`);
          }
        }
      } finally {
        await session.quit();
      }
    }
  });
});
