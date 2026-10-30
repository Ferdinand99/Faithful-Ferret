// Passkey authenticator pieces (Fase 1 section 9). Byte formats are those of WebAuthn L3.
import nodeCrypto, { webcrypto } from 'node:crypto';
import { sha256, hmac256 } from './crypto.mjs';
import { concat, fail, ascii, utf8, hex, unhex, equal } from './util.mjs';
import { C, encode } from './cbor.mjs';
import { canonicalOrigin, validateRpId } from './origin.mjs';
import * as p256 from './p256.mjs';

// "One fixed AAGUID (a UUIDv4) for all installations" (section 9.3). The design does not give the value;
// this one is read from the vectors. It is a version 4, variant 1 UUID (bytes 6 and 8 checked below).
export const AAGUID = unhex('dc704a44b994410ca689ed8d71a84ac3');
if ((AAGUID[6] >> 4) !== 4 || (AAGUID[8] >> 6) !== 2) throw new Error('AAGUID is not a UUIDv4');

const FLAG = { UP: 0x01, UV: 0x04, BE: 0x08, BS: 0x10, AT: 0x40, ED: 0x80 };

export const b64url = (b) => Buffer.from(b).toString('base64url');

export function clientDataJson(type, challenge, origin) {
  return `{"type":"${type}","challenge":"${b64url(challenge)}","origin":"${origin}","crossOrigin":false}`;
}

// PRF (section 9.5): HMAC-SHA256(seed, SHA-256("WebAuthn PRF" || 0x00 || input))
export const prfSalt = (input) => sha256(ascii('WebAuthn PRF'), Uint8Array.of(0), input);
export const prfOutput = (seed, input) => hmac256(seed, prfSalt(input));

export function pkcs8(scalar, pub) {
  const point = concat(Uint8Array.of(0x04), pub.x, pub.y);
  return concat(
    unhex('308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b020101' + '0420'),
    scalar,
    unhex('a144034200'),
    point,
  );
}
export function spki(pub) {
  return concat(unhex('3059301306072a8648ce3d020106082a8648ce3d03010703420004'), pub.x, pub.y);
}
// d out of PKCS#8 as written above
export const scalarFromPkcs8 = (der) => der.subarray(36, 68);

function coseKey(pub) {
  // {1: 2, 3: -7, -1: 1, -2: x, -3: y}
  return concat(unhex('a501020326200121' + '5820'), pub.x, unhex('225820'), pub.y);
}

function resolveRp(input, requestRpId) {
  const o = canonicalOrigin(input.origin);
  const rpId = requestRpId === null || requestRpId === undefined ? o.host : validateRpId(requestRpId, o.host);
  return { origin: o.origin, rpId };
}

function prfResults(seed, ev) {
  if (!ev) return { first: null, second: null };
  return {
    first: hex(prfOutput(seed, unhex(ev.first))),
    second: ev.second === null || ev.second === undefined ? null : hex(prfOutput(seed, unhex(ev.second))),
  };
}

export function create(input, rng) {
  const req = input.request;
  if (!input.top_origin_is_same) fail('not_allowed');
  const { origin, rpId } = resolveRp(input, req.rp_id);
  if (unhex(req.challenge).length > 1024) fail('too_large');
  if (req.exclude.length > 200) fail('too_large');
  const handle = unhex(req.user_id);
  if (handle.length === 0 || handle.length > 64) fail('malformed_webauthn_options');
  if (!req.algorithms.includes(-7)) fail('unsupported');
  if (!input.uv.user_present) fail('not_allowed');
  if (req.user_verification === 'required' && !input.uv.user_verified) fail('not_allowed');
  const stored = new Set(input.existing_credentials.filter((c) => c.rp_id === rpId).map((c) => c.id));
  if (req.exclude.some((id) => stored.has(id))) fail('invalid_state');

  const credId = rng.draw(32);
  const scalar = rng.draw(32);
  const prf = req.prf !== null && req.prf !== undefined;
  const seedUv = prf ? rng.draw(32) : null;
  const seedNouv = prf ? rng.draw(32) : null;
  const pub = p256.publicKey(scalar);

  const flags = FLAG.UP | (input.uv.user_verified ? FLAG.UV : 0) | FLAG.BE | FLAG.BS | FLAG.AT | (prf ? FLAG.ED : 0);
  const ext = prf ? encode(C.map([['hmac-secret', C.bool(true)]])) : new Uint8Array(0);
  const authData = concat(
    sha256(utf8(rpId)),
    Uint8Array.of(flags),
    new Uint8Array(4), // signCount is always 0
    AAGUID,
    Uint8Array.of(credId.length >> 8, credId.length & 255),
    credId,
    coseKey(pub),
    ext,
  );
  const attestation = encode(C.map([['fmt', C.text('none')], ['attStmt', C.map([])], ['authData', C.bytes(authData)]]));
  let prfOut = null;
  if (prf) {
    const seed = input.uv.user_verified ? seedUv : seedNouv;
    const r = prfResults(seed, req.prf.eval);
    prfOut = { enabled: true, ...r };
  }
  return {
    expect: {
      record: {
        cred_id: hex(credId),
        rp_id: rpId,
        user_handle: hex(handle),
        user_name: req.user_name,
        created: input.created_ms,
        private_scalar: hex(scalar),
        priv_pkcs8: hex(pkcs8(scalar, pub)),
        prf_seed_uv: seedUv ? hex(seedUv) : null,
        prf_seed_nouv: seedNouv ? hex(seedNouv) : null,
      },
      response: {
        id: hex(credId),
        attestation_object: hex(attestation),
        client_data_json: clientDataJson('webauthn.create', unhex(req.challenge), origin),
        authenticator_data: hex(authData),
        public_key_spki: hex(spki(pub)),
        alg: -7,
        prf: prfOut,
      },
    },
    intermediate: { flags, cose_key: hex(coseKey(pub)) },
  };
}

// ECDSA P-256 / SHA-256 verification by WebCrypto; the DER signature is converted to r || s (P1363) first.
export async function webcryptoVerify(spkiBytes, data, derSignature) {
  const raw = p256.derToP1363(derSignature);
  if (raw === null) return false;
  const key = await webcrypto.subtle.importKey('spki', spkiBytes, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  return webcrypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, raw, data);
}

export async function get(input, expected) {
  const req = input.request;
  const rec = input.record;
  if (!input.top_origin_is_same) fail('not_allowed');
  const { origin, rpId } = resolveRp(input, req.rp_id);
  // the stored RP ID must be exactly the requested one: no suffix logic when signing
  if (rec.rp_id !== rpId) fail('not_allowed');
  const challenge = unhex(req.challenge);
  if (challenge.length > 1024) fail('too_large');
  if (req.allow.length > 200) fail('too_large');
  const byCred = req.prf && req.prf.eval_by_credential ? req.prf.eval_by_credential : [];
  if (byCred.length > 0 && req.allow.length === 0) fail('unsupported');
  if (byCred.some((e) => !req.allow.includes(e.id))) fail('malformed_webauthn_options');
  if (req.allow.length > 0 && !req.allow.includes(rec.cred_id)) fail('not_allowed');
  if (!input.uv.user_present) fail('not_allowed');
  if (req.user_verification === 'required' && !input.uv.user_verified) fail('not_allowed');

  const flags = FLAG.UP | (input.uv.user_verified ? FLAG.UV : 0) | FLAG.BE | FLAG.BS;
  const authData = concat(sha256(utf8(rpId)), Uint8Array.of(flags), new Uint8Array(4));
  const cdj = clientDataJson('webauthn.get', challenge, origin);
  const signed = concat(authData, sha256(utf8(cdj)));

  const pkcs = unhex(rec.priv_pkcs8);
  const scalar = scalarFromPkcs8(pkcs);
  const pub = p256.publicKey(scalar);
  const point = concat(Uint8Array.of(4), pub.x, pub.y);
  // 1. my own P-256 code and Node's ECDH must agree on the public key of the stored private scalar
  const ecdh = nodeCrypto.createECDH('prime256v1');
  ecdh.setPrivateKey(scalar);
  if (!equal(new Uint8Array(ecdh.getPublicKey()), point)) throw new Error('p256.mjs and Node ECDH disagree on the public key');
  // 2. the public key written inside the stored PKCS#8 must be the one that belongs to its scalar
  if (!equal(pkcs.subarray(pkcs.length - 65), point)) throw new Error('the public key in priv_pkcs8 does not belong to its private key');
  const mine = p256.sign(scalar, signed);
  // 3. WebCrypto, with the public key taken from the record, must accept my signature and the vector's
  const recordSpki = concat(unhex('3059301306072a8648ce3d020106082a8648ce3d030107034200'), pkcs.subarray(pkcs.length - 65));
  if (!(await webcryptoVerify(recordSpki, signed, mine.der))) throw new Error('WebCrypto rejects the signature made by p256.mjs');
  let signature = hex(mine.der);
  if (expected && expected.signature && !(await webcryptoVerify(recordSpki, signed, unhex(expected.signature)))) {
    throw new Error('WebCrypto rejects the signature of the vector');
  }

  let prf = null;
  if (req.prf && rec.prf_seed_uv) {
    const seed = unhex(input.uv.user_verified ? rec.prf_seed_uv : rec.prf_seed_nouv);
    const entry = byCred.find((e) => e.id === rec.cred_id);
    const ev = entry ? { first: entry.first, second: entry.second } : req.prf.eval;
    prf = ev ? prfResults(seed, ev) : null;
  }
  return {
    expect: {
      id: rec.cred_id,
      authenticator_data: hex(authData),
      client_data_json: cdj,
      signature,
      user_handle: rec.user_handle,
      prf,
    },
    intermediate: { flags },
  };
}

export { equal };
