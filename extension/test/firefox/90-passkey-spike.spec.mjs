// Spike: can a Firefox extension act as a passkey provider? What these probes find
// out, in real Firefox (unbranded Release and ESR), with a local relying party that
// verifies everything in Node:
//
//  * a MAIN-world content script can replace navigator.credentials.create/get and
//    answer a relying party with a key held by the extension's background, over a
//    private MessageChannel (design document 10.8);
//  * that script is in place before the first script of the page, in the top frame
//    and in a same-origin frame, whether it is declared in the manifest or
//    registered with scripting.registerContentScripts;
//  * PublicKeyCredential.isConditionalMediationAvailable can be answered by the
//    extension, and a conditional request can be held and answered later.
//
// All code is under extension/test/spikes/passkey and never reaches a release. The
// spike add-on runs beside the Ferret test build, in the same profile.
import assert from "node:assert/strict";
import { after, test } from "node:test";
import { channels, stopFixtures } from "./harness.mjs";
import {
  endSession, launchWithSpike, openControl, SPIKE_ID, startRelyingParties,
} from "../spikes/passkey/launch.mjs";
import { DYNAMIC_MATCHES } from "../spikes/passkey/build.mjs";

after(() => stopFixtures());

/** Both manifest versions: MV3 is the plan, MV2 is the fallback, so the spike must hold on both. */
const MANIFESTS = /** @type {const} */ (["mv3", "mv2"]);

/**
 * Runs `body` in a fresh Firefox with the spike add-on and the relying parties.
 * @template T
 * @param {{ channel: "release" | "esr", manifest: "mv3" | "mv2" }} options
 * @param {(ctx: { session: Awaited<ReturnType<typeof launchWithSpike>>, rps: Awaited<ReturnType<typeof startRelyingParties>>, control: Awaited<ReturnType<typeof openControl>> }) => Promise<T>} body
 */
async function withSpike({ channel, manifest }, body) {
  const rps = await startRelyingParties();
  const session = await launchWithSpike({ channel, manifest });
  try {
    await session.waitFor(() => session.addonInfo(SPIKE_ID), 30_000, "the spike add-on");
    const control = await openControl(session);
    return await body({ session, rps, control });
  } finally {
    await endSession(session);
    await rps.close();
  }
}

/** Opens a page of a relying party and waits for its load handler. */
async function openPage(/** @type {any} */ session, /** @type {string} */ url) {
  await session.navigate(url);
  await session.waitFor(() => session.content(() => document.getElementById("out")?.getAttribute("data-loaded")), 15_000, `the page ${url}`);
}

/** Clicks a button of the relying party page (a real click, so the page has user activation). */
async function press(/** @type {any} */ session, /** @type {string} */ id) {
  const found = await session.findAll(`#${id}`);
  assert.equal(found.length, 1, `button ${id}`);
  await session.click(found[0]);
}

/** The JSON a page flow published under `data-<name>`, waiting for it. */
async function published(/** @type {any} */ session, /** @type {string} */ name, timeoutMs = 20_000) {
  const raw = await session.waitFor(() => session.content((/** @type {string} */ n) => document.getElementById("out")?.getAttribute(`data-${n}`), name), timeoutMs, `the result ${name}`);
  return JSON.parse(raw);
}

/** Forgets a published result so the next run of the same flow can be waited for. */
async function forget(/** @type {any} */ session, /** @type {string} */ name) {
  await session.content((/** @type {string} */ n) => document.getElementById("out")?.removeAttribute(`data-${n}`), name);
}

/** Registers the scripts for https://fixture.test at run time. @returns {Promise<string>} "ok" or the error */
async function registerDynamic(/** @type {Awaited<ReturnType<typeof openControl>>} */ control, persist = false) {
  return control.call("registerDynamic", { matches: DYNAMIC_MATCHES, persist });
}

/** The page's own first-script notes, parsed. @param {any} session @param {string} attribute */
async function firstScript(session, attribute) {
  const raw = await session.content((/** @type {string} */ a) => document.documentElement.getAttribute(a), attribute);
  return raw ? JSON.parse(raw) : null;
}

const NATIVE_CREATE = "function create() {\n    [native code]\n}";

test("firefox_main_world_override_answers_a_local_rp_create_and_get", async () => {
  for (const channel of channels()) {
    for (const manifest of MANIFESTS) {
      await withSpike({ channel, manifest }, async ({ session, rps, control }) => {
        await registerDynamic(control);
        const label = `${channel}/${manifest}`;

        // The same flow for a page matched by the manifest (http://localhost) and one matched by a registration at run time.
        for (const [via, rp] of /** @type {const} */ ([["manifest", rps.local], ["registered at run time", rps.dynamic]])) {
          await openPage(session, rps.urlOf(rp));
          await press(session, "register");
          const registered = await published(session, "register");
          assert.equal(registered.ok, true, `${label} ${via}: create answered: ${JSON.stringify(registered)}`);
          assert.deepEqual(registered.server, { ok: true, errs: [] }, `${label} ${via}: the relying party verified the registration`);
          assert.equal(rp.rp.verified.registration, true);
          // What a page checks before it trusts the object.
          const { checks } = registered;
          assert.equal(checks.instanceOfPKC && checks.responseInstanceOf && checks.typeIsPublicKey && checks.rawIdMatchesId, true, `${label} ${via}: the credential looks like a PublicKeyCredential: ${JSON.stringify(checks)}`);
          assert.deepEqual([checks.transports, checks.publicKeyAlg, checks.extensions, checks.attachment], [["internal"], -7, "{}", "platform"]);
          assert.equal(checks.publicKeyBytes, 91, `${label} ${via}: SPKI of a P-256 key`);

          await press(session, "login");
          const login = await published(session, "login");
          assert.equal(login.ok, true, `${label} ${via}: get answered: ${JSON.stringify(login)}`);
          assert.deepEqual(login.server, { ok: true, errs: [], signatureValid: true }, `${label} ${via}: the relying party verified the signature`);
          assert.equal(rp.rp.verified.authentication, 1);
          assert.equal(login.checks.userHandlePresent, true);
        }

        // The origin the background used is the one the browser reported for the sender, for both pages.
        const events = await control.call("events");
        for (const rp of [rps.local, rps.dynamic]) {
          const used = events.filter((/** @type {any} */ e) => e.origin === rp.rp.origin && (e.kind === "create" || e.kind === "get"));
          assert.equal(used.length, 2, `${label}: a create and a get from ${rp.rp.origin}`);
          for (const e of used) {
            assert.equal(e.frameId, 0, `${label}: top frame`);
            assert.equal(e.outcome, "ok");
            assert.equal(e.hasOriginField, true, `${label}: the sender has an origin field`);
          }
        }

        // The key is not extractable and is never handed out.
        assert.equal(await control.call("count"), 2);
        assert.deepEqual(await control.call("keyFlags"), [{ type: "private", extractable: false }, { type: "private", extractable: false }]);
        assert.equal(await control.call("tryExportPrivate"), "refused: InvalidAccessError");

        // Control: on a page that no script matches, create is the browser's own, and without an authenticator it fails.
        // So the successes above came from the extension and not from Firefox.
        await openPage(session, rps.urlOf(rps.unmatched));
        assert.equal((await firstScript(session, "data-first-inline")).probe, false, `${label}: no override on the unmatched page`);
        await press(session, "native-create");
        const native = await published(session, "native-create");
        assert.equal(native.ok, false, `${label}: the browser's own create does not succeed here`);
        assert.equal(rps.unmatched.rp.verified.registration, false);

        // The override refuses what the design says it must (section 9.2 and 9.3), through the same channel.
        await openPage(session, rps.urlOf(rps.local) + "?uv=required");
        await control.call("setUv", false);
        await press(session, "login");
        const noUv = await published(session, "login");
        assert.equal(noUv.ok, false);
        assert.equal(noUv.error.name, "NotAllowedError", `${label}: user verification required but not done`);
      });
    }
  }
});

test("the_override_is_in_place_before_the_first_page_script", async () => {
  for (const channel of channels()) {
    for (const manifest of MANIFESTS) {
      await withSpike({ channel, manifest }, async ({ session, rps, control }) => {
        await registerDynamic(control);
        const label = `${channel}/${manifest}`;
        const ours = { probe: true, createOurs: true, getOurs: true, cmaOurs: true, createSrc: NATIVE_CREATE, readyState: "loading", hasBody: false };
        const noClaim = (/** @type {any} */ r) => ({ ...r, claimedAtFirstScript: undefined });
        // Twenty loads of each, so a race that goes wrong now and then shows.
        for (const [via, rp] of /** @type {const} */ ([["manifest", rps.local], ["run-time registration", rps.dynamic]])) {
          for (let i = 0; i < 20; i++) {
            await openPage(session, rps.urlOf(rp, "/?frame=1"));
            assert.deepEqual(noClaim(await firstScript(session, "data-first-inline")), noClaim(ours), `${label} ${via} #${i}: the first inline script`);
            assert.deepEqual(noClaim(await firstScript(session, "data-first-external")), noClaim(ours), `${label} ${via} #${i}: the first external script`);
            const frame = JSON.parse(await published(session, "frame-first-inline"));
            assert.deepEqual(noClaim(frame), noClaim(ours), `${label} ${via} #${i}: the first script of a same-origin frame`);
          }
        }
        // A frame the page makes itself (about:blank) is a new realm. Is the function in it the override too?
        await openPage(session, rps.urlOf(rps.local));
        await press(session, "blank-frame");
        const blank = await published(session, "blank-frame");
        console.log(`# blank-frame ${label} ${JSON.stringify(blank)}`);
        assert.equal(typeof blank.sync.probe, "boolean");
        // The relay of a frame reached the background with the frame's own ids.
        await openPage(session, rps.urlOf(rps.local, "/?frame=1"));
        const connects = (await control.call("events")).filter((/** @type {any} */ e) => e.kind === "connect" && e.frameId !== 0);
        for (const c of connects) assert.equal(c.topOrigin, c.origin, `${label}: a frame of the same origin as the top frame`);
        assert.ok(connects.some((/** @type {any} */ c) => /\/frame$/.test(String(c.frameUrl))), `${label}: the same-origin frame connected with its own URL`);
        assert.ok(connects.some((/** @type {any} */ c) => c.frameUrl === "about:blank"), `${label}: the about:blank frame of the page connected`);
      });
    }
  }
});

test("conditional_mediation_availability_can_be_answered", async () => {
  for (const channel of channels()) {
    for (const manifest of MANIFESTS) {
      await withSpike({ channel, manifest }, async ({ session, rps, control }) => {
        const label = `${channel}/${manifest}`;
        // What Firefox itself says, on a page without the override.
        await openPage(session, rps.urlOf(rps.unmatched));
        await press(session, "cma");
        const nativeAnswer = await published(session, "cma");
        console.log(`# native cma ${label} ${JSON.stringify(nativeAnswer)}`);
        assert.equal(nativeAnswer.fnType, "function", `${label}: Firefox has isConditionalMediationAvailable`);

        // With the override the extension decides, both ways, whatever Firefox says.
        await openPage(session, rps.urlOf(rps.local));
        for (const wanted of [true, false, true]) {
          await control.call("setConditionalAvailable", wanted);
          await forget(session, "cma");
          await press(session, "cma");
          const answer = await published(session, "cma");
          assert.equal(answer.value, wanted, `${label}: the page got the extension's answer ${wanted}: ${JSON.stringify(answer)}`);
        }
        console.log(`# overridden cma ${label} native-behind-override ${JSON.stringify((await published(session, "cma")).native)}`);

        // A conditional request is held by the extension, and answered later (the user picks in the extension's own UI).
        await press(session, "register");
        assert.equal((await published(session, "register")).ok, true);
        await press(session, "conditional");
        await session.waitFor(async () => (await control.call("heldConditional")) === 1, 10_000, "a held conditional request");
        await control.call("resolveConditional");
        const picked = await published(session, "conditional");
        assert.equal(picked.ok, true, `${label}: ${JSON.stringify(picked)}`);
        assert.deepEqual(picked.server, { ok: true, errs: [], signatureValid: true }, `${label}: the relying party verified the conditional assertion`);
        assert.equal(await control.call("heldConditional"), 0);

        // The page aborts: the extension is told, the page gets AbortError.
        await forget(session, "conditional");
        await press(session, "conditional");
        await session.waitFor(async () => (await control.call("heldConditional")) === 1, 10_000, "a second held request");
        await press(session, "abort");
        const aborted = await published(session, "conditional");
        assert.equal(aborted.ok, false);
        assert.equal(aborted.error.name, "AbortError", `${label}: ${JSON.stringify(aborted)}`);
        await session.waitFor(async () => (await control.call("heldConditional")) === 0, 10_000, "the held request dropped");

        // A navigation drops a held request (the port of the document closes).
        await forget(session, "conditional");
        await press(session, "conditional");
        await session.waitFor(async () => (await control.call("heldConditional")) === 1, 10_000, "a third held request");
        await openPage(session, rps.urlOf(rps.unmatched));
        await session.waitFor(async () => (await control.call("heldConditional")) === 0, 10_000, "a navigation drops the held request");
      });
    }
  }
});

test("the_bridge_is_a_private_message_channel_not_window_post_message", async () => {
  for (const channel of channels()) {
    for (const manifest of MANIFESTS) {
      await withSpike({ channel, manifest }, async ({ session, rps, control }) => {
        const label = `${channel}/${manifest}`;
        // The page is hostile from its first script: it listens for every message, patches the messaging
        // functions, and offers its own port before anything else could.
        await openPage(session, rps.urlOf(rps.local, "/?hostile=1"));
        await press(session, "register");
        assert.equal((await published(session, "register")).ok, true, `${label}: register`);
        await press(session, "login");
        assert.equal((await published(session, "login")).ok, true, `${label}: login`);
        // After the handshake the page offers a second port and floods the window with answers nobody asked for,
        // while a real sign-in runs. The relying party verifies the signature, so a forged answer would fail it.
        await press(session, "forge");
        const forge = await published(session, "forge");
        assert.equal(forge.login.ok, true, `${label}: sign-in during the forgery: ${JSON.stringify(forge)}`);
        assert.deepEqual(forge.login.server, { ok: true, errs: [], signatureValid: true });
        assert.equal(forge.forgedPortGotRequests, 0, `${label}: the page's second port got no request`);
        assert.equal(forge.earlyForgedPortRequests, 0, `${label}: the page's first port got no request`);
        assert.equal(forge.hostileOfferSentAtFirstScript, true);
        assert.equal(rps.local.rp.verified.authentication, 2);

        await press(session, "dump");
        const spy = await published(session, "spy");
        console.log(`# spy ${label} ${JSON.stringify({ messages: spy.messages.length, offers: spy.messages.filter((/** @type {any} */ m) => m.hasPorts).length, windowPostMessage: spy.windowPostMessage, portPostMessage: spy.portPostMessage })}`);
        // The spy works: it saw what the page itself sent (control).
        assert.ok(spy.messages.length >= 2, `${label}: the spy sees window messages`);
        // The page sent two offers (its early one and the one after the handshake) and each shows twice (capture and
        // bubble listener). The extension's own offer is not among them: the capture listener of the override took it first.
        assert.equal(spy.messages.filter((/** @type {any} */ m) => m.hasPorts).length, 4, `${label}: offers the page's listeners saw`);
        // The page's own 40 window.postMessage calls are the only ones it can see: the override never
        // calls the page's window.postMessage, and none of its requests go through the patched port function.
        assert.equal(spy.windowPostMessage, 40, `${label}: window.postMessage calls the page saw`);
        assert.equal(spy.portPostMessage, 0, `${label}: MessagePort.postMessage calls the page saw`);
        assert.equal(spy.channels, 1, `${label}: MessageChannel objects the page saw (its own)`);
        // Every window message the spy saw is one the page sent (an offer or a forged answer), none is a request or an answer.
        const keys = new Set(spy.messages.map((/** @type {any} */ m) => m.keys.join(",")));
        assert.deepEqual([...keys].sort(), ["ferretSpike,v", "id,error"], `${label}: shapes of the window messages`);
        // Requests and answers carry an id and a kind or a result; none of those appeared as a window message.
        assert.equal(spy.messages.some((/** @type {any} */ m) => m.keys.includes("kind") || m.keys.includes("result")), false);
        // The background heard from the real relay only.
        const kinds = (await control.call("events")).filter((/** @type {any} */ e) => e.kind === "create" || e.kind === "get").map((/** @type {any} */ e) => e.outcome);
        assert.deepEqual(kinds, ["ok", "ok", "ok"], `${label}: the background answered the three real requests`);
      });
    }
  }
});

test("optional_host_permission_gates_the_override_until_the_user_grants_it", async () => {
  for (const channel of channels()) {
    for (const manifest of MANIFESTS) {
      const label = `${channel}/${manifest}`;
      const rps = await startRelyingParties();
      const session = await launchWithSpike({ channel, manifest, hosts: "optional" });
      try {
        const control = await openControl(session);
        // Host access is only optional: nothing is granted, so no script is injected anywhere yet.
        const before = await control.call("permissions");
        console.log(`# granted at install ${label}: ${JSON.stringify(before.origins)}`);
        assert.equal(before.origins.some((/** @type {string} */ o) => o.startsWith("https://")), false, `${label}: no https origin granted at install`);
        const registration = await registerDynamic(control);
        console.log(`# registerContentScripts without a grant ${label}: ${registration}`);
        // The declared match (http://localhost) was granted with the install in this profile; the https origins were not.
        await openPage(session, rps.urlOf(rps.local));
        console.log(`# declared match without a grant ${label}: probe=${(await firstScript(session, "data-first-inline")).probe}`);
        await openPage(session, rps.urlOf(rps.dynamic));
        assert.equal((await firstScript(session, "data-first-inline")).probe, false, `${label}: a page that only the optional permission covers has no override before the grant`);
        // The user grants https and localhost access, in the extension's own page (a real click, as permissions.request needs).
        await control.press("grant");
        await session.waitFor(() => control.published("grant"), 10_000, "the answer to the permission request");
        assert.deepEqual(JSON.parse(await control.published("grant")), { granted: true }, `${label}: the request was granted`);
        const registrationAfter = await registerDynamic(control);
        console.log(`# registerContentScripts after the grant ${label}: ${registrationAfter}`);
        for (const [what, rp] of /** @type {const} */ ([["manifest-declared page", rps.local], ["registered page", rps.dynamic]])) {
          await openPage(session, rps.urlOf(rp));
          const first = await firstScript(session, "data-first-inline");
          console.log(`# after the grant ${label} ${what}: probe=${first.probe} createOurs=${first.createOurs}`);
          assert.equal(first.createOurs, true, `${label}: ${what} has the override from its first script after the grant`);
          await press(session, "register");
          assert.equal((await published(session, "register")).ok, true, `${label}: ${what}: and it answers`);
        }
      } finally {
        await endSession(session);
        await rps.close();
      }
    }
  }
});

test("registered_content_scripts_survive_a_restart_when_asked_to", async () => {
  for (const channel of channels()) {
    for (const manifest of MANIFESTS) {
      const label = `${channel}/${manifest}`;
      const rps = await startRelyingParties();
      const session = await launchWithSpike({ channel, manifest });
      try {
        const control = await openControl(session);
        await registerDynamic(control, true);
        assert.equal((await control.call("registered")).length, 2, `${label}: two scripts registered`);
        await session.restart();
        await session.waitFor(() => session.addonInfo(SPIKE_ID), 30_000, "the spike add-on after the restart");
        const afterRestart = await openControl(session);
        const registered = await afterRestart.call("registered");
        assert.deepEqual(registered.map((/** @type {{ id: string }} */ s) => s.id).sort(), ["spike-main", "spike-relay"], `${label}: still registered`);
        await openPage(session, rps.urlOf(rps.dynamic));
        assert.equal((await firstScript(session, "data-first-inline")).createOurs, true, `${label}: the override is in place after the restart`);
        await press(session, "register");
        assert.equal((await published(session, "register")).ok, true, `${label}: and it answers`);
      } finally {
        await endSession(session);
        await rps.close();
      }
    }
  }
});
