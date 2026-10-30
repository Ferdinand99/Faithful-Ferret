// Primitives. libsodium-wrappers for XChaCha20-Poly1305 and Ed25519; Node crypto for the rest.
import sodium from 'libsodium-wrappers';
import nodeCrypto from 'node:crypto';
import { fail, concat, equal } from './util.mjs';

await sodium.ready;

export const sha256 = (...parts) => new Uint8Array(nodeCrypto.createHash('sha256').update(concat(...parts)).digest());
export const hmac256 = (key, ...parts) => new Uint8Array(nodeCrypto.createHmac('sha256', key).update(concat(...parts)).digest());

// HKDF-SHA256. An absent salt (null) is the RFC 5869 default: HashLen zero bytes.
export function hkdf(salt, ikm, info, len = 32) {
  const s = salt === null ? new Uint8Array(32) : salt;
  return new Uint8Array(nodeCrypto.hkdfSync('sha256', ikm, s, info, len));
}

// AEAD(key, nonce, pt, aad) -> nonce(24) || ct || tag(16)  (Fase 1 section 3.1)
export function aeadSeal(key, nonce, pt, aad) {
  if (key.length !== 32 || nonce.length !== 24) throw new Error('bad key or nonce length');
  const ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(pt, aad, null, nonce, key);
  return concat(nonce, ct);
}

// Returns plaintext or throws decrypt.
export function aeadOpen(key, blob, aad) {
  if (blob.length < 24 + 16) fail('decrypt');
  const nonce = blob.subarray(0, 24);
  const ct = blob.subarray(24);
  try {
    return new Uint8Array(sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ct, aad, nonce, key));
  } catch {
    fail('decrypt');
  }
}

export function ed25519FromSeed(seed) {
  const kp = sodium.crypto_sign_seed_keypair(seed);
  return { sk: kp.privateKey, pk: kp.publicKey };
}
export const ed25519Sign = (msg, sk) => sodium.crypto_sign_detached(msg, sk);
export function ed25519Verify(sig, msg, pk) {
  try {
    return sodium.crypto_sign_verify_detached(sig, msg, pk);
  } catch {
    return false;
  }
}

// Argon2id v1.3 with the Node built-in (OpenSSL). libsodium's crypto_pwhash is not in the
// non-sumo libsodium-wrappers build and fixes p = 1, so Node's implementation is used for all p.
export function argon2id(password, salt, mKib, t, p, outLen) {
  return new Uint8Array(
    nodeCrypto.argon2Sync('argon2id', {
      message: password,
      nonce: salt,
      parallelism: p,
      tagLength: outLen,
      memory: mKib,
      passes: t,
    }),
  );
}

export const ctEqual = equal;
export const randomBytes = (n) => new Uint8Array(nodeCrypto.randomBytes(n));
export { sodium };
