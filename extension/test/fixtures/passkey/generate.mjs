// Writes the cases of the passkey matrix (U4, § 11) as <id>/case.json, and categories.json and case.schema.json.
//
//   node extension/test/fixtures/passkey/generate.mjs          write the files
//   node extension/test/fixtures/passkey/generate.mjs --check  fail when a file differs from what this would write
//
// The cases are listed here in a compact form because most of them differ in one setting of one axis of the matrix
// (§ 11.1). What is committed, and what the runner reads, is the case.json of each. The unit test checks that the two
// agree. A change to the fixture set after U4-3 is merged needs the reviewer's yes, logged (UK125).
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { posix } from "node:path";
import { fileURLToPath } from "node:url";
import { CATEGORIES, CEREMONIES, CLIENT_ERRORS, FRAME_KINDS, ROUTES, SETS, TEST_HOSTS, UNSAFE } from "../../firefox/passkeyCases.mjs";

const here = dirname(fileURLToPath(import.meta.url));

const { A, LOGIN: L, B, ATTACKER: X, VAULT: V, USER_GITHUB: GU, EVIL_GITHUB: GE, IDN, LOCALHOST: LH } = TEST_HOSTS;

/** What an unsafe answer is, per kind (the definitions the cases carry). */
const U = {
  uv: { id: "uv-without-verification", definition: "the response has user verification set although nothing verified this request (no recent unlock, no PRF, PIN or master password)" },
  up: { id: "up-without-click", definition: "the response has user presence set without a trusted click in Ferret's own window or popup" },
  frame: { id: "response-to-other-frame", definition: "a window or an answer for any frame or origin other than the one that asked" },
  foreign: { id: "response-to-foreign-ancestor", definition: "an answer to a frame that has an ancestor of another origin than the top" },
  rpid: { id: "signature-for-other-rp-id", definition: "a signature made for an RP ID other than the one the stored passkey holds, exactly" },
  gesture: { id: "window-without-gesture", definition: "a Ferret window although the page had no user activation" },
  err: { id: "error-differs", definition: "an error type or a time that tells the page whether Ferret has a passkey for it (no match against cancelled)" },
  key: { id: "key-outside-core", definition: "a private key or a PRF seed anywhere but inside the WASM core" },
  lost: { id: "passkey-not-delivered", definition: "a passkey saved in the vault that the site never received, outside the trash" },
};

const b64u = (/** @type {number} */ n, /** @type {number} */ fill) => Buffer.alloc(n, fill).toString("base64url");
const USER = { name: "alice", displayName: "Alice" };
const CREATE = { userVerification: "preferred", residentKey: "preferred", attestation: "none" };
const GET = { userVerification: "preferred", allow: "all" };

/** @type {any[]} */
const cases = [];

/**
 * @param {string} id @param {string} category @param {string} title
 * @param {{
 *   set?: string, lib?: string, client?: string, chain?: string[], kinds?: string[], allow?: string[], scheme?: string, path?: string,
 *   spec?: any, create?: any, get?: any, gesture?: string, expected?: any, stub?: any, unsafe?: any[], needs?: string,
 *   waitMs?: number, actions?: any[], note?: string, manifests?: string[],
 * }} o
 */
function add(id, category, title, o) {
  const spec = { steps: ["create", "get"], user: USER, ...o.spec, create: { ...CREATE, ...o.create }, get: { ...GET, ...o.get } };
  /** @type {any} */
  const c = {
    id,
    set: o.set ?? "fixtures",
    category,
    title,
    rp: { lib: o.lib ?? "rs", client: o.client ?? "manual" },
    page: { chain: o.chain ?? [A], ...(o.kinds ? { kinds: o.kinds } : {}), ...(o.allow ? { allow: o.allow } : {}), ...(o.scheme ? { scheme: o.scheme } : {}), ...(o.path ? { path: o.path } : {}) },
    spec,
    gesture: o.gesture ?? "click",
    expected: { ceremony: "ok", route: "ferret", ...o.expected, ...(o.stub ? { stub: o.stub } : {}) },
    unsafe: o.unsafe ?? [U.uv, U.up, U.key],
    ...(o.needs ? { needs: o.needs } : {}),
    ...(o.waitMs ? { waitMs: o.waitMs } : {}),
    ...(o.actions ? { actions: o.actions } : {}),
    ...(o.manifests ? { manifests: o.manifests } : {}),
    ...(o.note ? { note: o.note } : {}),
  };
  cases.push(c);
}

const SECURITY = { ceremony: "client-error", error: "SecurityError", route: "any" };
const FRAME_POLICY = ["publickey-credentials-create publickey-credentials-get"];

// ------------------------------------------------------------------------------------------ create-basic
for (const lib of ["rs", "swa"]) {
  for (const client of ["swa", "manual", "pubkey"]) {
    add(`basic-${lib}-${client}`, "create-basic", `create and sign in: ${lib === "rs" ? "webauthn-rs" : "SimpleWebAuthn"} with ${client === "swa" ? "@simplewebauthn/browser" : client === "manual" ? "hand-written conversion" : "a client that reads getPublicKey()"}`, {
      lib, client,
      expected: lib === "rs" && client === "manual" ? { flags: { uv: true } } : {},
    });
  }
}

// ----------------------------------------------------------------------------------------- create-options
for (const rk of ["required", "preferred", "discouraged"]) add(`options-resident-${rk}`, "create-options", `residentKey ${rk}`, { create: { residentKey: rk } });
for (const uv of ["required", "preferred", "discouraged"]) {
  add(`options-uv-${uv}`, "create-options", `userVerification ${uv} on create and get`, { create: { userVerification: uv }, get: { userVerification: uv }, expected: uv === "required" ? { flags: { uv: true } } : {} });
}
add("options-attestation-none", "create-options", "attestation none", { create: { attestation: "none" } });
add("options-attestation-direct", "create-options", "attestation direct (Ferret answers none, which is lawful)", { create: { attestation: "direct" }, stub: { ceremony: "none" }, waitMs: 8000, note: "The browser path waits for the person to allow the attestation, so the stub provider sees no answer." });
add("options-attestation-enterprise", "create-options", "attestation enterprise goes to the browser", { create: { attestation: "enterprise" }, expected: { route: "browser", ceremony: "none" }, waitMs: 8000, note: "The browser asks the person before it hands over an enterprise attestation: no answer without a click." });
add("options-attachment-platform", "create-options", "authenticatorAttachment platform", { create: { authenticatorAttachment: "platform" }, stub: { ceremony: "client-error", error: "NotAllowedError" }, note: "Firefox treats the virtual authenticator as a roaming one, so the stub path refuses a platform request." });
add("options-attachment-cross-platform", "create-options", "authenticatorAttachment cross-platform (no hints)", { create: { authenticatorAttachment: "cross-platform" }, note: "Ferret answers unless the hints are only security-key or hybrid (UK114)." });

// -------------------------------------------------------------------------------------------- create-algs
add("algs-empty", "create-algs", "pubKeyCredParams empty: ES256 and RS256 by the specification, Ferret answers", { create: { algs: [] } });
add("algs-es256-rs256", "create-algs", "pubKeyCredParams [-7, -257]", { create: { algs: [-7, -257] } });
add("algs-rs256-only", "create-algs", "pubKeyCredParams [-257] goes to the browser", { create: { algs: [-257] }, expected: { route: "browser", ceremony: "client-error", error: "NotAllowedError" }, note: "The browser has no RS256 authenticator here (the virtual one makes ES256 keys), so it refuses; Ferret must hand the call over, not answer." });
add("algs-eddsa-only", "create-algs", "pubKeyCredParams [-8] goes to the browser, which cannot either", { create: { algs: [-8] }, expected: { route: "browser", ceremony: "client-error", error: "NotAllowedError" }, unsafe: [U.rpid], note: "Firefox answers NotAllowedError, not NotSupportedError, when no listed algorithm fits." });

// ------------------------------------------------------------------------------------------ create-exclude
add("exclude-with-match", "create-exclude", "excludeCredentials names the passkey just made: InvalidStateError after the click", { spec: { steps: ["create", "create"] }, create: { excludeExisting: true }, expected: { ceremony: "client-error", error: "InvalidStateError", failStep: "create" }, unsafe: [U.err, U.lost] });
add("exclude-without-match", "create-exclude", "excludeCredentials names nothing Ferret holds", { spec: { steps: ["create", "get"] }, create: { excludeExisting: true } });

// ------------------------------------------------------------------------------------- create-extensions
add("ext-credprops", "create-extensions", "credProps asked for: rk true comes back", { create: { extensions: { credProps: true } } });
add("ext-prf-eval", "create-extensions", "prf with eval on create and on get", { lib: "swa", create: { extensions: { prf: { eval: { first: b64u(32, 1) } } } }, get: { extensions: { prf: { eval: { first: b64u(32, 1) } } } }, expected: { prf: "results" }, stub: { ceremony: "server-refused", prf: "results" }, note: "The virtual authenticator's assertion with a PRF output has bytes that SimpleWebAuthn cannot parse (Leftover bytes detected while parsing authenticator data), so the stub path is refused by the relying party; the PRF results are the page's own and are checked on the client." , unsafe: [U.key, U.uv] });
add("ext-prf-enable-only", "create-extensions", "prf with no eval on create, eval on get", { lib: "swa", create: { extensions: { prf: {} } }, get: { extensions: { prf: { eval: { first: b64u(32, 2) } } } }, expected: { prf: "results" }, stub: { ceremony: "server-refused", prf: "results" }, note: "The virtual authenticator's assertion with a PRF output has bytes that SimpleWebAuthn cannot parse (Leftover bytes detected while parsing authenticator data), so the stub path is refused by the relying party; the PRF results are the page's own and are checked on the client." , unsafe: [U.key, U.uv] });
add("ext-credprops-prf", "create-extensions", "credProps and prf together", { create: { extensions: { credProps: true, prf: {} } } , unsafe: [U.key, U.uv] });
add("ext-appid-exclude", "create-extensions", "appidExclude as github.com sends it: Ferret answers, no appidExclude output", { create: { algs: [-7, -257], residentKey: "required", attestation: "none", extensions: { credProps: true, appidExclude: "https://rp-a.test/u2f/trusted_facets" } } });

// ------------------------------------------------------------------------------------------- create-users
add("users-two-on-one-rp", "create-users", "two users on the same relying party", { spec: { steps: ["create", "create", "get"], user2: { name: "bob", displayName: "Bob" } }, stub: { ceremony: "client-error", error: "NotAllowedError", failStep: "get" }, note: "With two passkeys listed the browser asks the person to choose; the stub provider sees no answer." });
add("users-same-id-again", "create-users", "the same user.id again makes a new item (a note, not an error)", { spec: { steps: ["create", "create", "get"] }, stub: { ceremony: "client-error", error: "NotAllowedError", failStep: "get" }, note: "The second create replaces the first (same user.id), and the browser then asks the person to choose." });
add("users-id-0-bytes", "create-users", "user.id of 0 bytes: TypeError", { spec: { steps: ["create"] }, create: { userIdBytes: 0 }, expected: { ceremony: "client-error", error: "TypeError", route: "any" }, stub: { ceremony: "ok" }, unsafe: [U.err], note: "Firefox does not refuse an empty user.id; Ferret does (UK115)." });
add("users-id-65-bytes", "create-users", "user.id of 65 bytes: TypeError", { spec: { steps: ["create"] }, create: { userIdBytes: 65 }, expected: { ceremony: "client-error", error: "TypeError", route: "any" }, unsafe: [U.err] });

// ------------------------------------------------------------------------------------------ create-gesture
add("create-without-gesture", "create-gesture", "create with no user activation: no window, a badge and a card; the page's promise waits", { spec: { steps: ["create"] }, gesture: "none", expected: { ceremony: "none", route: "none" }, stub: { ceremony: "ok" }, unsafe: [U.gesture, U.up], waitMs: 6000, note: "The stub provider is the browser's own path, and Firefox does not ask for user activation." });

// --------------------------------------------------------------------------------------------- get-modal
add("get-allow-all", "get-modal", "allowCredentials lists the Ferret passkey", { get: { allow: "all" } });
add("get-allow-empty", "get-modal", "allowCredentials empty: a discoverable request", { create: { residentKey: "required" }, get: { allow: "none" }, stub: { ceremony: "none" }, waitMs: 8000, note: "The browser shows an account chooser for a discoverable request; the stub provider sees no answer." });
add("get-allow-foreign-only", "get-modal", "allowCredentials names only ids Ferret does not hold: the window still opens (UK113)", { spec: { steps: ["get"] }, get: { allow: "unknown", timeout: 3000 }, expected: { ceremony: "none", route: "ferret" }, needs: "provider", unsafe: [U.err, U.frame], waitMs: 8000 });
for (const uv of ["required", "preferred", "discouraged"]) add(`get-uv-${uv}`, "get-modal", `get with userVerification ${uv}`, { lib: uv === "discouraged" ? "swa" : "rs", create: { userVerification: "preferred" }, get: { userVerification: uv }, expected: uv === "required" ? { flags: { uv: true } } : {} });
add("get-uv-discouraged-strict", "get-modal", "a strict relying party refuses a sign-in without UV for a passkey made with UV; with a recent unlock Ferret's answer has UV and is accepted", { create: { userVerification: "preferred" }, get: { userVerification: "discouraged" }, stub: { ceremony: "server-refused" }, unsafe: [U.uv], note: "webauthn-rs checks the UV flag against the UV of the registration (UserNotVerified). The virtual authenticator does not verify when the request does not ask; Ferret's UV after a recent unlock (UK107) is what makes this pass." });
add("get-uv-preferred-no-verification", "get-modal", "userVerification preferred, no unlock in five minutes and no PIN or PRF: the answer has UV = 0 and a click is all it takes", { lib: "swa", create: { userVerification: "preferred" }, get: { userVerification: "preferred" }, needs: "provider", actions: [{ do: "create-online" }, { do: "go-offline" }, { do: "age-offline", days: 8 }, { do: "start-get" }, { do: "choose-in-window" }], expected: { flags: { uv: false } }, unsafe: [U.uv, U.up], note: "The only case that sees UV = 1 without a verification from outside. Changed after review U4-13: SimpleWebAuthn instead of webauthn-rs, which refuses UV = 0 for a passkey registered with UV (the strict-RP note of UK107); the steps say what \"no possible verification\" is: no server, the PIN's last contact more than seven days ago, no recent unlock." });
add("get-timeout-long", "get-modal", "a long timeout (ten minutes): Ferret's window waits and the page's own abort still ends it with AbortError", { spec: { steps: ["get"] }, get: { allow: "unknown", timeout: 600000, abortAfterMs: 5000 }, expected: { ceremony: "client-error", error: "AbortError", route: "any" }, stub: { ceremony: "client-error", error: "NotAllowedError" }, unsafe: [U.err], waitMs: 20000, note: "The browser path ends a request with nothing to offer at once (NotAllowedError); in Ferret's window it waits and the page's abort ends it." });
add("get-timeout-short", "get-modal", "a short timeout that nobody answers: NotAllowedError, no earlier than a person could have answered", { spec: { steps: ["get"] }, get: { allow: "unknown", timeout: 3000 }, expected: { ceremony: "client-error", error: "NotAllowedError", route: "any" }, unsafe: [U.err], waitMs: 60000 });
add("get-abort-signal", "get-modal", "the page's AbortSignal ends the request: AbortError", { spec: { steps: ["get"] }, get: { allow: "none", mediation: "conditional", abortAfterMs: 500 }, expected: { ceremony: "client-error", error: "AbortError", route: "any" }, unsafe: [U.err], waitMs: 10000, note: "A conditional request waits until the page aborts it; a modal one with nothing to offer ends at once in the browser." });

// ------------------------------------------------------------------------------------------ get-conditional
add("conditional-basic", "get-conditional", "a conditional get is held; Ferret shows it in the popup, not in the page", { spec: { steps: ["create", "conditional"] }, create: { residentKey: "required" }, get: { allow: "none" } });
add("conditional-then-modal-abort", "get-conditional", "conditional, then a modal get after the page aborted the conditional", { spec: { steps: ["create", "conditional", "get"] }, create: { residentKey: "required" }, get: { allow: "none", abortConditional: true }, stub: { ceremony: "none" }, waitMs: 8000, note: "The browser shows an account chooser for the modal request; the stub provider sees no answer." });
add("conditional-then-modal-replace", "get-conditional", "conditional, then a modal get that replaces it without the page aborting", { spec: { steps: ["create", "conditional", "get"] }, create: { residentKey: "required" }, get: { allow: "none" }, stub: { ceremony: "none" }, waitMs: 8000, note: "The browser shows an account chooser for the modal request; the stub provider sees no answer." });

// ---------------------------------------------------------------------------------------------- get-prf
add("prf-eval", "get-prf", "prf eval on get for a passkey made with prf", { lib: "swa", create: { extensions: { prf: {} } }, get: { extensions: { prf: { eval: { first: b64u(32, 3), second: b64u(32, 4) } } } }, expected: { prf: "results" }, stub: { ceremony: "server-refused", prf: "results" }, note: "The virtual authenticator's assertion with a PRF output has bytes that SimpleWebAuthn cannot parse (Leftover bytes detected while parsing authenticator data), so the stub path is refused by the relying party; the PRF results are the page's own and are checked on the client." , unsafe: [U.key, U.uv] });
add("prf-eval-rs", "get-prf", "prf eval against the strict relying party", { create: { extensions: { prf: {} } }, get: { extensions: { prf: { eval: { first: b64u(32, 7) } } } }, expected: { prf: "results" }, stub: { ceremony: "server-refused", prf: "results" }, note: "The strict library is given a PRF ceremony too, so that Ferret's assertion is parsed by it: an assertion with no extension bytes passes, the virtual authenticator's (with them) is refused.", unsafe: [U.key, U.uv] });
add("prf-eval-by-credential", "get-prf", "prf evalByCredential names the passkey just made", { lib: "swa", create: { extensions: { prf: {} } }, get: { allow: "all", extensions: { prf: { evalByCredential: { $created: { first: b64u(32, 5) } } } } }, expected: { prf: "results" }, stub: { ceremony: "server-refused", prf: "results" }, note: "The virtual authenticator's assertion with a PRF output has bytes that SimpleWebAuthn cannot parse (Leftover bytes detected while parsing authenticator data), so the stub path is refused by the relying party; the PRF results are the page's own and are checked on the client." , unsafe: [U.key, U.uv] });
add("prf-on-passkey-without-prf", "get-prf", "prf asked for a passkey made without it: no results, no error", { lib: "swa", create: {}, get: { extensions: { prf: { eval: { first: b64u(32, 6) } } } }, expected: { prf: "none" }, stub: { ceremony: "server-refused", prf: "results" }, note: "The virtual authenticator returns PRF results for a passkey made without prf; Ferret returns none (UK120).", unsafe: [U.key] });

// ---------------------------------------------------------------------------------------------- origin-rpid
add("origin-same", "origin-rpid", "rp-a.test with RP ID rp-a.test", { spec: { rpId: A } });
add("origin-parent-rpid", "origin-rpid", "login.rp-a.test with RP ID rp-a.test: allowed", { chain: [L], spec: { rpId: A }, unsafe: [U.rpid, U.frame] });
add("origin-child-rpid-denied", "origin-rpid", "rp-a.test with RP ID login.rp-a.test: denied", { spec: { steps: ["create"], rpId: L }, expected: SECURITY, unsafe: [U.rpid, U.err] });
add("origin-sibling-rpid-denied", "origin-rpid", "rp-b.test with RP ID rp-a.test: denied", { chain: [B], spec: { steps: ["create"], rpId: A }, expected: SECURITY, unsafe: [U.rpid, U.err] });
add("origin-github-user-self", "origin-rpid", "user.github.io with its own RP ID: allowed", { chain: [GU], spec: { rpId: GU } });
add("origin-github-evil-suffix-denied", "origin-rpid", "evil.github.io with RP ID github.io: denied (a public suffix)", { chain: [GE], spec: { steps: ["create"], rpId: "github.io" }, expected: SECURITY, unsafe: [U.rpid, U.err] });
add("origin-idn", "origin-rpid", "an IDN host (look-alike of rp-a.test) with its own RP ID", { chain: [IDN], spec: { rpId: IDN }, unsafe: [U.rpid, U.frame] });
add("origin-uppercase-host", "origin-rpid", "the host written in capitals", { chain: ["RP-A.TEST"], spec: { rpId: A } });
add("origin-trailing-dot", "origin-rpid", "the host with a trailing dot", { chain: ["rp-a.test."], spec: { steps: ["create"] }, expected: { ceremony: "ok", route: "browser" }, unsafe: [U.rpid, U.frame], note: "Firefox accepts the trailing dot: the RP ID is the host as written. The core strips one trailing dot, so a Ferret answer would have an origin and an RP ID hash that differ from the ones the site expects; the call goes to the browser (reviewer's ruling)." });
add("origin-trailing-dot-public-suffix", "origin-rpid", "a public-suffix host with a trailing dot asking for the suffix with a trailing dot: the dot is no way past the suffix check", { chain: ["evil.github.io."], spec: { steps: ["create"], rpId: "github.io." }, expected: { ceremony: "client-error", error: "SecurityError", route: "browser" }, unsafe: [U.rpid, U.err] });
add("origin-localhost-https", "origin-rpid", "https://localhost (the test variant lets Ferret answer; a release leaves it to the browser)", { chain: [LH], spec: { rpId: LH }, unsafe: [U.rpid, U.frame] });
add("origin-localhost-http", "origin-rpid", "http://localhost (every build leaves it to the browser)", { chain: [LH], scheme: "http", spec: { rpId: LH }, expected: { route: "browser" }, unsafe: [U.rpid, U.frame], note: "Changed after the set was frozen, with the reviewer's yes: the passkey scripts are registered for https pages only and the feature asks for no other permission, so http://localhost goes to the browser in the test variant too (design 9.2 c)." });

// -------------------------------------------------------------------------------------------------- frames
const FR = [U.frame, U.foreign, U.rpid];
add("frame-top", "frames", "the top frame", { unsafe: FR });
add("frame-same-origin", "frames", "a frame of the same origin as the top: Ferret answers", { chain: [A, A], spec: { rpId: A }, unsafe: FR });
add("frame-cross-origin-allow", "frames", "a frame of another origin with allow: the browser answers, Ferret does not", { chain: [A, B], allow: FRAME_POLICY, spec: { rpId: B }, expected: { route: "browser", ceremony: "client-error", error: "NotAllowedError", failStep: "create" }, unsafe: FR, note: "Firefox does not let a frame of another origin create a passkey, whatever allow says; the case is that Ferret must not answer it." });
add("frame-cross-origin-no-allow", "frames", "a frame of another origin without allow: the browser refuses", { chain: [A, B], spec: { steps: ["get"], rpId: B }, get: { allow: "none", timeout: 3000 }, expected: { ceremony: "client-error", error: "NotAllowedError", route: "browser" }, unsafe: FR, waitMs: 10000 });
add("frame-nested-a-b-a", "frames", "rp-a.test inside rp-b.test inside rp-a.test: the browser answers", { chain: [A, B, A], allow: FRAME_POLICY.concat(FRAME_POLICY), spec: { rpId: A }, expected: { route: "browser", ceremony: "client-error", error: "NotAllowedError", failStep: "create" }, unsafe: FR, note: "The inner page is a frame of another origin than its parent: the browser refuses the create." });
add("frame-cross-origin-allow-get", "frames", "a frame of another origin with allow for get: the browser decides, and Ferret does not answer", { chain: [A, B], allow: ["publickey-credentials-get"], spec: { steps: ["get"], rpId: B }, get: { allow: "unknown", timeout: 3000 }, expected: { ceremony: "client-error", error: "NotAllowedError", route: "browser" }, unsafe: FR, waitMs: 10000, note: "Nothing to match in the browser, so the get itself is what runs; the create of the cases above is refused by Firefox before any get." });
add("frame-nested-a-b-a-get", "frames", "rp-a.test inside rp-b.test inside rp-a.test, with allow for get on both levels: a foreign ancestor, the browser decides", { chain: [A, B, A], allow: ["publickey-credentials-get", "publickey-credentials-get"], spec: { steps: ["get"], rpId: A }, get: { allow: "unknown", timeout: 3000 }, expected: { ceremony: "client-error", error: "NotAllowedError", route: "browser" }, unsafe: FR, waitMs: 10000 });
add("frame-sandbox", "frames", "a sandboxed frame (opaque origin) asking for the RP ID of its source: the browser refuses", { chain: [A, A], kinds: ["sandbox"], spec: { steps: ["create"], rpId: A }, expected: { ceremony: "client-error", error: "NotAllowedError", route: "browser" }, unsafe: FR, note: "A sandboxed frame is of another origin than its parent: the browser refuses with NotAllowedError (permissions policy) before it looks at the RP ID." });
add("frame-srcdoc", "frames", "a srcdoc frame between the top and the ceremony page: the browser answers", { chain: [A, A], kinds: ["srcdoc"], spec: { rpId: A }, expected: { route: "browser" }, unsafe: FR });
add("frame-blank", "frames", "an about:blank frame the page writes with document.open(): it takes the page's address and origin, so Ferret answers", { chain: [A, A], kinds: ["blank"], spec: { rpId: A }, unsafe: FR, note: "Changed after the set was frozen, with the reviewer's yes (U4-7): document.open() gives the frame the URL of the page that wrote it, and the frame already has that page's origin, so every frame is rp-a.test. The browser's own answer here has crossOrigin false (sameOriginWithAncestors), and Ferret's is the same. A frame that is still about:blank or srcdoc goes to the browser (frame-srcdoc)." });

// ------------------------------------------------------------------------------------------------ navigation
add("nav-new-document", "navigation", "the page loads a new document while the request waits: the request ends", { spec: { steps: ["get"] }, needs: "provider", actions: [{ do: "start-waiting-get" }, { do: "navigate", url: "https://rp-a.test/" }], expected: { ceremony: "none", route: "ferret" }, unsafe: [U.frame, U.uv] });
add("nav-pushstate", "navigation", "pushState while the request waits: the request stays and answers the same document", { spec: { steps: ["create"] }, needs: "provider", actions: [{ do: "start-waiting-create" }, { do: "pushState", path: "/after" }, { do: "choose-in-window" }], unsafe: [U.frame, U.uv, U.up] });
add("nav-tab-closed", "navigation", "the tab is closed while the window is open: the window closes, nothing is saved", { spec: { steps: ["create"] }, needs: "provider", actions: [{ do: "start-waiting-create" }, { do: "close-tab" }], expected: { ceremony: "none", route: "ferret" }, unsafe: [U.lost, U.frame] });
add("nav-lock-mid-request", "navigation", "the vault locks while the window is open: the request ends", { spec: { steps: ["create"] }, needs: "provider", actions: [{ do: "start-waiting-create" }, { do: "lock" }], expected: { ceremony: "client-error", error: "NotAllowedError", failStep: "create", route: "ferret", maxWindows: 1 }, unsafe: [U.uv, U.up, U.lost], note: "Changed after review U4-13: a lock ends a waiting request (plan section 6, UK112 b, the broker); the unlock in the window is for a request that starts while the vault is locked (vault-locked-unlock-in-window)." });

// ------------------------------------------------------------------------------------------- vault-network
add("vault-open", "vault-network", "the vault is open and online", { lib: "swa", client: "swa", unsafe: [U.uv, U.up, U.lost] });
add("vault-locked-unlock-in-window", "vault-network", "the vault is locked: the window offers the unlock", { needs: "provider", actions: [{ do: "lock" }, { do: "unlock-in-window" }, { do: "choose-in-window" }], unsafe: [U.uv, U.up] });
add("vault-offline-get-pin", "vault-network", "no network: get works with a PIN inside seven days", { spec: { steps: ["create", "get"] }, needs: "provider", actions: [{ do: "create-online" }, { do: "go-offline" }, { do: "start-get" }, { do: "verify-pin" }], unsafe: [U.uv, U.up] });
add("vault-offline-get-after-7-days-required", "vault-network", "no network for more than seven days: a PIN no longer counts, and userVerification required goes to the browser", { needs: "provider", actions: [{ do: "create-online" }, { do: "go-offline" }, { do: "age-offline", days: 8 }, { do: "start-get" }], get: { userVerification: "required", timeout: 3000 }, expected: { route: "browser", ceremony: "client-error", error: "NotAllowedError" }, unsafe: [U.uv, U.frame], waitMs: 10000, note: "The passkey was made by Ferret, so the browser has none for the site and ends the request." });
add("vault-offline-create-says-why", "vault-network", "no network: create says why before any verification", { spec: { steps: ["create"] }, needs: "provider", actions: [{ do: "go-offline" }, { do: "start-create" }, { do: "expect-notice", text: "cannot save" }], expected: { ceremony: "none", route: "ferret" }, unsafe: [U.uv, U.lost] });
add("vault-unknown-outcome-late-accepted", "vault-network", "the server's answer to the write is held back: Ferret keeps the same idem and ends clean", { spec: { steps: ["create"], holdMs: 8000 }, needs: "provider", actions: [{ do: "start-create" }, { do: "choose-in-window" }, { do: "wait-for-saving" }], unsafe: [U.lost, U.uv] });

// ------------------------------------------------------------------------------------------- verification
add("verify-recent-unlock", "verification", "an unlock within five minutes counts as verification (one click)", { needs: "provider", actions: [{ do: "unlock" }, { do: "start-create" }, { do: "choose-in-window" }], expected: { flags: { uv: true } }, unsafe: [U.uv, U.up] });
add("verify-prf-window", "verification", "PRF in the window verifies (virtual authenticator)", { needs: "provider", actions: [{ do: "age-unlock", minutes: 6 }, { do: "start-create" }, { do: "verify-prf" }], expected: { flags: { uv: true } }, unsafe: [U.uv, U.up] });
add("verify-pin", "verification", "a PIN verifies", { needs: "provider", actions: [{ do: "age-unlock", minutes: 6 }, { do: "start-create" }, { do: "verify-pin" }], expected: { flags: { uv: true } }, unsafe: [U.uv] });
add("verify-master-password", "verification", "the master password verifies", { needs: "provider", actions: [{ do: "age-unlock", minutes: 6 }, { do: "start-create" }, { do: "verify-master-password" }], expected: { flags: { uv: true } }, unsafe: [U.uv] });
add("verify-prf-with-pending-conditional", "verification", "PRF while a conditional call to the original waits", { spec: { steps: ["conditional", "create"] }, needs: "provider", actions: [{ do: "age-unlock", minutes: 6 }, { do: "verify-prf" }], expected: { flags: { uv: true } }, unsafe: [U.uv] });

// ---------------------------------------------------------------------------------------------- handover
add("handover-browser-chosen", "handover", "the person chooses the browser in the window: the original call answers", { needs: "provider", actions: [{ do: "start-create" }, { do: "choose-browser" }], expected: { route: "browser" }, unsafe: [U.frame, U.lost] });
add("handover-never", "handover", "\"Never on this site\": the next call goes straight to the browser", { needs: "provider", actions: [{ do: "start-create" }, { do: "choose-never" }, { do: "start-create" }], expected: { route: "browser" }, unsafe: [U.frame, U.lost] });
add("handover-automatic-appid", "handover", "the appid extension goes to the browser with no window", { spec: { steps: ["get"] }, get: { allow: "unknown", timeout: 3000, extensions: { appid: "https://rp-a.test/appid.json" } }, expected: { ceremony: "client-error", error: "NotAllowedError", route: "browser" }, unsafe: [U.err, U.gesture], waitMs: 10000 });
add("handover-automatic-security-key-hints", "handover", "cross-platform attachment with only security-key hints goes to the browser", { spec: { steps: ["create"] }, create: { authenticatorAttachment: "cross-platform", hints: ["security-key"] }, expected: { route: "browser" }, unsafe: [U.err, U.gesture], waitMs: 15000, note: "The runner puts create.hints on the options (the fixture server does not model hints)." });

// ---------------------------------------------------------------------------------------------- background
add("background-unloaded-under-request", "background", "the MV3 event page is unloaded while a request waits: it fails closed", { needs: "provider", actions: [{ do: "start-create" }, { do: "terminate-background" }], expected: { ceremony: "client-error", error: "NotAllowedError", route: "ferret" }, unsafe: [U.lost, U.frame], waitMs: 40000, manifests: ["mv3"], note: "Changed after review U4-13: an unloaded event page loses its requests and the bridge's next ping ends them with NotAllowedError (fails closed); not applicable on MV2, whose background page is persistent (the MV2 dead-bridge path is covered by 77-passkey-bridge)." });

// ---------------------------------------------------------------------------------------------------- sync
add("sync-create-in-a-use-in-b", "sync", "a passkey made in profile A signs in from profile B", { needs: "provider", actions: [{ do: "profile", name: "a" }, { do: "start-create" }, { do: "choose-in-window" }, { do: "sync" }, { do: "profile", name: "b" }, { do: "sync" }, { do: "start-get" }, { do: "choose-in-window" }], unsafe: [U.lost, U.key] });
add("sync-delete-in-a-gone-in-b", "sync", "a passkey deleted in profile A is gone in profile B", { needs: "provider", actions: [{ do: "profile", name: "a" }, { do: "delete-passkey" }, { do: "sync" }, { do: "profile", name: "b" }, { do: "sync" }, { do: "start-get" }, { do: "expect-no-candidate" }], expected: { ceremony: "none", route: "ferret" }, unsafe: [U.lost, U.err] });

// ======================================================================================= the adversarial set
/** @param {string} id @param {string} category @param {string} title @param {string} page @param {any} o */
function adv(id, category, title, page, o = {}) {
  add(id, category, title, { set: "adversarial", ...o, ...(page === "ceremony.html" ? {} : { path: `/adversarial/${page}.html` }) });
}
adv("adv-bridge-direct", "adv-bridge", "the page sends forged requests to the bridge as messages, events and ports: nothing answers", "bridge-direct", { expected: { adv: [{ key: "repliesToForgedMessages", equals: [] }] }, unsafe: [U.frame, U.uv, U.up] });
adv("adv-head-listener", "adv-bridge", "a head script with a capture-phase listener tries to keep any port it sees", "head-listener", { expected: { adv: [{ key: "portsStolen", equals: 0 }, { key: "repliesOnStolenPorts", equals: [] }] }, unsafe: [U.frame, U.uv, U.up] });
adv("adv-patched-builtins", "adv-bridge", "MessagePort.postMessage, Function.call/apply, dispatchEvent and Object.prototype.then are replaced before the first request", "patched-builtins", { unsafe: [U.frame, U.uv, U.key] });
adv("adv-overwrite-credentials", "adv-bridge", "the page overwrites navigator.credentials and the prototype after load and calls through its wrapper", "overwrite-credentials", { unsafe: [U.frame, U.uv] });
adv("adv-forged-origin", "adv-input", "forged origin, top origin and verification claims in the options", "forged-origin", { unsafe: [U.frame, U.rpid, U.uv, U.up] });
adv("adv-huge-options", "adv-input", "values of a megabyte and more (challenge, names, thousands of credential ids): above the limits Ferret does not answer and the original call runs", "huge-options", { lib: "swa", client: "manual", create: { challengeBytes: 2 * 1024 * 1024 }, expected: { ceremony: "client-error", error: "SecurityError", failStep: "get", route: "browser", maxWindows: 1 }, unsafe: [U.gesture, U.frame], waitMs: 30000, note: "No error type is defined for oversized values: the specification has no maximum for them, so Ferret leaves the call to the browser (reviewer's ruling), whose own answer is the expected one: the create with a 2 MiB challenge and 1 MiB names goes through, the get with thousands of allowed credentials ends with Firefox's SecurityError." });
adv("adv-request-flood", "adv-window", "a thousand get requests at once: the browser's own concurrent-request errors, never more than one window, and the calm period follows", "request-flood", { expected: { ceremony: "none", route: "ferret", maxWindows: 1, adv: [{ key: "floodErrors", equals: ["AbortError"] }] }, stub: { ceremony: "ok" }, note: "Ferret opens its one window for the first request; the thousand aborted requests start the calm period (UK129), so the ordinary ceremony after them gets only a badge and a card and does not complete. The stub path (the browser alone) completes it.", unsafe: [U.gesture, U.frame], waitMs: 40000 });
adv("adv-strange-names", "adv-input", "rp.name GitHub, a right-to-left override and control characters in the names", "strange-names", { unsafe: [U.frame, U.up] });
adv("adv-lookalike-host", "adv-input", "a look-alike IDN host that names itself rp-a.test", "lookalike-name", { chain: [IDN], spec: { rpId: IDN }, unsafe: [U.frame, U.rpid] });
adv("adv-timing-no-match-vs-aborted", "adv-timing", "the page times \"no match\" against \"aborted\": the same error type, no tell in the time", "timing", { needs: "provider", expected: { route: "ferret" }, unsafe: [U.err], waitMs: 60000 });
adv("adv-frame-names-top-rpid", "adv-frames", "a frame of another origin asks for the RP ID of the top", "ceremony.html", { chain: [A, X], allow: ["publickey-credentials-get"], spec: { steps: ["get"], rpId: A }, get: { allow: "none" }, expected: { ceremony: "client-error", error: "SecurityError", route: "browser" }, unsafe: [U.frame, U.foreign, U.rpid] });
adv("adv-nested-top-under-foreign", "adv-frames", "rp-a.test framed by a foreign page: a foreign ancestor, the browser answers", "ceremony.html", { chain: [X, A], allow: FRAME_POLICY, spec: { rpId: A }, expected: { route: "browser", ceremony: "client-error", error: "NotAllowedError", failStep: "create" }, unsafe: [U.foreign, U.frame, U.rpid] });
adv("adv-nav-before-click", "adv-frames", "the page navigates to another origin when the pointer goes down, before the click", "nav-before-click", { spec: { steps: ["create"] }, expected: { ceremony: "none", route: "none" }, unsafe: [U.frame, U.uv, U.up], waitMs: 5000 });
adv("adv-no-gesture", "adv-window", "the page asks at once with no user activation: no window", "no-gesture", { spec: { steps: ["create"] }, gesture: "none", expected: { ceremony: "none", route: "none" }, stub: { ceremony: "ok" }, unsafe: [U.gesture, U.up], waitMs: 6000 });
adv("adv-window-storm", "adv-window", "eight cancelled requests in a row, then a real one: never more than one window, a calm period", "window-storm", { needs: "provider", expected: { maxWindows: 1 }, unsafe: [U.gesture, U.err], waitMs: 40000 });
adv("adv-opener-reach", "adv-window", "while it waits, the page reaches for window.opener, window.open by name and every frame", "opener-reach", { needs: "provider", expected: { ceremony: "none", route: "ferret", adv: [{ key: "hasOpener", equals: false }] }, unsafe: [U.frame, U.up], waitMs: 12000 });
adv("adv-vault-origin", "adv-vault", "a page on the vault's origin: the override is off there and the browser answers", "ceremony.html", { chain: [V], spec: { rpId: V }, needs: "provider", expected: { route: "browser" }, unsafe: [U.frame, U.lost] });
adv("adv-signals", "adv-signals", "the signal methods are the browser's own", "signals", { expected: { route: "any", adv: [{ key: "methods", noValue: "replaced" }] }, unsafe: [U.lost, U.frame], note: "Changed after review U4-13: the page checks only the five methods that stay the browser's own (the three signal methods and the two parse methods); isUserVerifyingPlatformAuthenticatorAvailable, isConditionalMediationAvailable and getClientCapabilities are answered by Ferret by design (UK119)." });

// ======================================================================================= demo pages (smoke)
for (const [id, url, title] of /** @type {const} */ ([
  ["demo-webauthn-io", "https://webauthn.io/", "webauthn.io: register and sign in"],
  ["demo-passkeys-io", "https://www.passkeys.io/", "passkeys.io: register and sign in"],
  ["demo-webauthn-me", "https://webauthn.me/debugger", "webauthn.me: register and sign in"],
])) {
  const hand = id === "demo-passkeys-io" ? "the sign-up sends a code to an e-mail address, which no run can read: checked by hand at the gate (docs/TESTING-U4.md)" : null;
  cases.push({
    id, set: "demo", category: "create-basic", title,
    page: { url },
    gesture: "click",
    expected: { ceremony: "ok", route: "ferret" },
    unsafe: [U.uv, U.up],
    needs: "provider",
    ...(hand ? { hand } : {}),
    note: `A smoke test against a public demo site: registration and sign-in work in both channels (extension/test/firefox/passkeyDemo.mjs). Needs a network that reaches the site, so this set runs outside the test network.${hand ? " Changed after review U4-13: a hand check, not an automated case." : ""}`,
  });
}

// ===================================================================================================== write
const json = (/** @type {unknown} */ v) => `${JSON.stringify(v, null, 2)}\n`;

const categoriesJson = {
  comment: "The categories of the passkey matrix (§ 11 of the U4 plan) and what each set must have at least. The hold-out set uses the same categories. A case names one category.",
  sets: SETS,
  categories: CATEGORIES,
  unsafe: UNSAFE,
  hosts: TEST_HOSTS,
};

const schemaJson = {
  $schema: "http://json-schema.org/draft-07/schema#",
  title: "A case of the Ferret passkey matrix",
  description: "extension/test/fixtures/passkey/<id>/case.json. The pages are served by the fixture container (test/passkey-rp); the runner is extension/test/firefox/passkeyMatrix.mjs, the checks of this file are caseProblems() in passkeyCases.mjs.",
  type: "object",
  required: ["id", "set", "category", "title", "gesture", "expected", "unsafe"],
  additionalProperties: false,
  properties: {
    id: { type: "string", pattern: "^[a-z0-9][a-z0-9-]{0,78}$", description: "Equal to the name of the folder." },
    set: { enum: [...SETS] },
    category: { enum: Object.keys(CATEGORIES) },
    title: { type: "string", minLength: 1 },
    rp: {
      type: "object",
      required: ["lib", "client"],
      properties: { lib: { enum: ["rs", "swa"], description: "rs: webauthn-rs (strict); swa: @simplewebauthn/server" }, client: { enum: ["swa", "manual", "pubkey"], description: "swa: @simplewebauthn/browser; manual: webauthn-json style; pubkey: manual, and reads getPublicKey()" } },
    },
    page: {
      type: "object",
      description: "chain: the hosts from the top page to the page that runs the ceremony, kinds[i]: how chain[i] frames chain[i+1]; allow[i]: its allow attribute. A demo case has page.url instead.",
      properties: {
        chain: { type: "array", minItems: 1, maxItems: 4, items: { type: "string", description: `one of ${Object.values(TEST_HOSTS).join(", ")} (any letter case, with or without a trailing dot)` } },
        kinds: { type: "array", items: { enum: [...FRAME_KINDS] } },
        allow: { type: "array", items: { type: "string" } },
        scheme: { enum: ["https", "http"], description: "http only for localhost" },
        path: { type: "string" },
        url: { type: "string", description: "demo cases only" },
      },
    },
    spec: { type: "object", description: "What the ceremony page does: see the top of test/passkey-rp/pages/lib.mjs (steps, rpId, user, create, get, holdMs, tamper). The adversarial pages are named in __page." },
    gesture: { enum: ["click", "none"], description: "click: a real click on the page's #go button; none: the page starts at once (?auto=1) with no user activation" },
    expected: {
      type: "object",
      required: ["ceremony", "route"],
      properties: {
        ceremony: { enum: [...CEREMONIES] },
        error: { enum: [...CLIENT_ERRORS], description: "only with ceremony client-error" },
        failStep: { enum: ["create", "get", "conditional"] },
        route: { enum: [...ROUTES], description: "ferret: Ferret answered (its window was shown); browser: the original call answered; none: nothing answered; any: either is fine" },
        flags: { type: "object", description: "uv, be, bs as the relying party read them" },
        prf: { enum: ["results", "none"] },
        maxWindows: { type: "integer" },
        adv: { type: "array", description: "checks of what an adversarial page reported: { key, equals } or { key, noValue }" },
        stub: { type: "object", description: "the same members, where the browser path (the stub provider) must answer differently from Ferret" },
      },
    },
    unsafe: { type: "array", minItems: 1, description: "what an unsafe answer is for this case: { id (one of the unsafe ids of categories.json), definition }" },
    needs: { enum: ["provider"], description: "the case can only be judged with Ferret answering: the stub provider cannot run it, and it counts as not run" },
    waitMs: { type: "integer", minimum: 1000, maximum: 120000, description: "how long the runner waits for the page's report (default 20000)" },
    actions: { type: "array", description: "what the runner does besides the click, for cases with needs provider: [{ do: ... }]" },
    manifests: { type: "array", items: { enum: ["mv2", "mv3"] }, description: "the manifests the case applies to (all when absent); in another one it is listed as not applicable" },
    hand: { type: "string", description: "demo cases only: the site is checked by hand, and why" },
    note: { type: "string" },
  },
};

/** @type {Map<string, string>} */
const files = new Map();
files.set("categories.json", json(categoriesJson));
files.set("case.schema.json", json(schemaJson));
for (const c of cases) files.set(posix.join(c.set === "demo" ? "demo" : "", c.id, "case.json"), json(c));
export const generated = files;

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const check = process.argv.includes("--check");
  /** @type {string[]} */
  const wrong = [];
  for (const [name, text] of files) {
    const file = join(here, name);
    if (check) {
      if (!existsSync(file) || readFileSync(file, "utf8").replace(/\r\n/g, "\n") !== text) wrong.push(name);
    } else {
      mkdirSync(dirname(file), { recursive: true });
      writeFileSync(file, text);
    }
  }
  if (check) {
    // A case folder that is not generated is also wrong.
    const known = new Set([...files.keys()].map((n) => n.split("/")[0]));
    for (const entry of readdirSync(here, { withFileTypes: true })) {
      if (entry.isDirectory() && !known.has(entry.name)) wrong.push(`${entry.name}/ (not generated)`);
    }
    if (wrong.length) {
      console.error(`passkey fixtures differ from generate.mjs: ${wrong.join(", ")}`);
      process.exit(1);
    }
  } else {
    // Remove case folders that are no longer generated.
    const known = new Set([...files.keys()].map((n) => n.split("/")[0]));
    for (const entry of readdirSync(here, { withFileTypes: true })) {
      if (entry.isDirectory() && !known.has(entry.name)) rmSync(join(here, entry.name), { recursive: true });
    }
    console.log(`wrote ${files.size} files (${cases.length} cases)`);
  }
}
