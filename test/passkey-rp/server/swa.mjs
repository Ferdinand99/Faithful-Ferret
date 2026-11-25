// The SimpleWebAuthn relying-party fixture (@simplewebauthn/server): what many real sites use.
// It checks what that library checks (challenge, origin, RP ID hash, flags, signature,
// counter) and, unlike webauthn-rs, does not look at crossOrigin; the page reports it, and
// the result carries it, so a test can see what the site was told.
//
//   POST /api/swa/register/start  {sid, rpId, user:{name, displayName, id?}, userVerification, residentKey,
//                                  attestation, algs?, excludeExisting?, authenticatorAttachment?, extensions?}
//   POST /api/swa/register/finish {sid, credential}
//   POST /api/swa/auth/start      {sid, rpId, userVerification, allow: "all"|"none"|"unknown", extensions?}
//   POST /api/swa/auth/finish     {sid, credential}
//   POST /api/swa/reset           {sid}
import { generateAuthenticationOptions, generateRegistrationOptions, verifyAuthenticationResponse, verifyRegistrationResponse } from "@simplewebauthn/server";

/** @typedef {{ id: string, publicKey: Uint8Array, counter: number, transports?: string[], userId: string }} StoredCredential */
/** @type {Map<string, { challenge?: string, kind?: "reg" | "auth", rpId?: string, origin?: string, userVerification?: string, credentials: StoredCredential[], userId?: string }>} */
const sessions = new Map();

/** @param {string} sid */
function session(sid) {
  let s = sessions.get(sid);
  if (!s) {
    s = { credentials: [] };
    sessions.set(sid, s);
  }
  return s;
}

const b64u = (/** @type {Uint8Array} */ bytes) => Buffer.from(bytes).toString("base64url");
const unb64u = (/** @type {string} */ text) => new Uint8Array(Buffer.from(text, "base64url"));

/** @param {string | undefined} uv */
const requireUv = (uv) => uv === "required";

/**
 * @param {string} route  "register/start", "register/finish", "auth/start", "auth/finish" or "reset"
 * @param {any} body
 * @param {string} origin  the validated Origin header of the request
 * @returns {Promise<{ status: number, json: any }>}
 */
export async function handleSwa(route, body, origin) {
  try {
    const sid = String(body?.sid ?? "");
    if (!sid) return { status: 400, json: { ok: false, error: "sid is missing" } };
    const s = session(sid);
    if (route === "reset") {
      sessions.delete(sid);
      return { status: 200, json: { ok: true } };
    }
    if (route === "register/start") {
      const userId = body.user.id ? unb64u(body.user.id) : new TextEncoder().encode(`${body.rpId}:${body.user.name}`);
      const options = await generateRegistrationOptions({
        rpName: "Ferret passkey fixture (SimpleWebAuthn)",
        rpID: body.rpId,
        userName: body.user.name,
        userDisplayName: body.user.displayName,
        userID: userId,
        attestationType: body.attestation === "enterprise" || body.attestation === "direct" || body.attestation === "indirect" ? body.attestation : "none",
        excludeCredentials: body.excludeExisting ? s.credentials.filter((c) => c.userId === b64u(userId)).map((c) => ({ id: c.id, transports: c.transports })) : [],
        authenticatorSelection: {
          residentKey: body.residentKey ?? "preferred",
          userVerification: body.userVerification ?? "preferred",
          ...(body.authenticatorAttachment ? { authenticatorAttachment: body.authenticatorAttachment } : {}),
        },
      });
      const out = /** @type {any} */ (options);
      if (Array.isArray(body.algs)) out.pubKeyCredParams = body.algs.map((/** @type {number} */ alg) => ({ type: "public-key", alg }));
      if (body.extensions) out.extensions = body.extensions;
      Object.assign(s, { challenge: options.challenge, kind: "reg", rpId: body.rpId, origin, userVerification: body.userVerification ?? "preferred", userId: b64u(userId) });
      return { status: 200, json: { ok: true, options: out } };
    }
    if (route === "register/finish") {
      if (s.kind !== "reg" || !s.challenge) return { status: 400, json: { ok: false, error: "no registration in progress" } };
      const challenge = s.challenge;
      s.challenge = undefined;
      const verification = await verifyRegistrationResponse({
        response: body.credential,
        expectedChallenge: challenge,
        expectedOrigin: s.origin,
        expectedRPID: s.rpId,
        requireUserVerification: requireUv(s.userVerification),
      });
      if (!verification.verified || !verification.registrationInfo) return { status: 400, json: { ok: false, error: "not verified" } };
      const info = verification.registrationInfo;
      s.credentials.push({ id: info.credential.id, publicKey: info.credential.publicKey, counter: info.credential.counter, transports: info.credential.transports, userId: s.userId ?? "" });
      return {
        status: 200,
        json: {
          ok: true,
          credentialId: info.credential.id,
          flags: { uv: info.userVerified, be: info.credentialDeviceType === "multiDevice", bs: info.credentialBackedUp },
          clientCrossOrigin: crossOrigin(body.credential),
        },
      };
    }
    if (route === "auth/start") {
      /** @type {{ id: string, transports?: string[] }[]} */
      let allowCredentials = [];
      if (body.allow === "all") allowCredentials = s.credentials.map((c) => ({ id: c.id, transports: c.transports }));
      else if (body.allow === "unknown") allowCredentials = [{ id: b64u(new Uint8Array(32).fill(0xa5)) }];
      const options = await generateAuthenticationOptions({
        rpID: body.rpId,
        userVerification: body.userVerification ?? "preferred",
        allowCredentials,
      });
      const out = /** @type {any} */ (options);
      if (body.extensions) out.extensions = body.extensions;
      Object.assign(s, { challenge: options.challenge, kind: "auth", rpId: body.rpId, origin, userVerification: body.userVerification ?? "preferred" });
      return { status: 200, json: { ok: true, options: out } };
    }
    if (route === "auth/finish") {
      if (s.kind !== "auth" || !s.challenge) return { status: 400, json: { ok: false, error: "no authentication in progress" } };
      const challenge = s.challenge;
      s.challenge = undefined;
      const credential = s.credentials.find((c) => c.id === body.credential?.id);
      if (!credential) return { status: 400, json: { ok: false, error: "CredentialNotFound" } };
      const verification = await verifyAuthenticationResponse({
        response: body.credential,
        expectedChallenge: challenge,
        expectedOrigin: s.origin,
        expectedRPID: s.rpId,
        credential: { id: credential.id, publicKey: credential.publicKey, counter: credential.counter, transports: /** @type {any} */ (credential.transports) },
        requireUserVerification: requireUv(s.userVerification),
      });
      if (!verification.verified) return { status: 400, json: { ok: false, error: "not verified" } };
      credential.counter = verification.authenticationInfo.newCounter;
      const info = verification.authenticationInfo;
      return {
        status: 200,
        json: {
          ok: true,
          counter: info.newCounter,
          flags: { uv: info.userVerified, be: info.credentialDeviceType === "multiDevice", bs: info.credentialBackedUp },
          clientCrossOrigin: crossOrigin(body.credential),
        },
      };
    }
    return { status: 404, json: { ok: false, error: "not found" } };
  } catch (e) {
    return { status: 400, json: { ok: false, error: e instanceof Error ? e.message : String(e) } };
  }
}

/** The crossOrigin member of the clientDataJSON the page sent (what this library does not look at). @param {any} credential */
function crossOrigin(credential) {
  try {
    const data = JSON.parse(Buffer.from(String(credential?.response?.clientDataJSON ?? ""), "base64url").toString("utf8"));
    return data.crossOrigin === true;
  } catch {
    return false;
  }
}
