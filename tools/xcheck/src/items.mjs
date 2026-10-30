// Item and manifest envelopes (section 5.1, 5.2), item tags (8.6) and tombstones (8.4).
import { aeadSeal, aeadOpen, hmac256, sha256, ctEqual } from './crypto.mjs';
import { tlvs, label, fU8, fU64, fBytes, T } from './tlv.mjs';
import { concat, fail, equal } from './util.mjs';
import { pad, unpad, isPaddedClass } from './body.mjs';

export const ZERO_ID = new Uint8Array(16);
export const KIND = { item: 1, manifest: 2 };

export function bodyAad(hdr, vaultId, itemId, rev) {
  const lab = hdr.kind === KIND.manifest ? 'ferret/v1/manifest' : 'ferret/v1/item';
  return tlvs(label(lab), fU8(T.version, hdr.version), fU8(T.suite, hdr.suite), fU8(T.kind, hdr.kind), fBytes(T.vault_id, vaultId), fBytes(T.item_id, itemId), fU64(T.rev, rev));
}

export function ikAad(hdr, vaultId, itemId, vkEpoch) {
  return tlvs(label('ferret/v1/item-key'), fU8(T.version, hdr.version), fU8(T.suite, hdr.suite), fBytes(T.vault_id, vaultId), fBytes(T.item_id, itemId), fU64(T.vk_epoch, vkEpoch));
}

// Splits an envelope by the layout the operation expects. The header bytes are not judged here:
// they only enter the AAD, so a wrong one fails authentication (section 5.3).
export function splitEnvelope(env, withIkWrap) {
  const ikLen = withIkWrap ? 72 : 0;
  const fixed = 3 + ikLen + 24 + 16;
  if (env.length < fixed + 256) fail('malformed_envelope');
  const paddedLen = env.length - fixed;
  if (!isPaddedClass(paddedLen)) fail('malformed_envelope');
  return {
    hdr: { version: env[0], suite: env[1], kind: env[2] },
    ikWrap: withIkWrap ? env.subarray(3, 3 + ikLen) : null,
    body: env.subarray(3 + ikLen),
  };
}

export function itemTag(kHead, itemId, rev, blob) {
  const msg = tlvs(label('ferret/v1/item-tag'), fBytes(T.item_id, itemId), fU64(T.rev, rev), fBytes(T.hash, sha256(blob)));
  return { message: msg, tag: hmac256(kHead, msg) };
}

export function verifyItemTag(kHead, itemId, rev, blob, tag) {
  if (tag.length !== 32 || !ctEqual(tag, itemTag(kHead, itemId, rev, blob).tag)) fail('decrypt');
}

// plain: CBOR bytes of the body. Returns the envelope and the intermediate values.
export function sealEnvelope({ kind, vk, kKey, vaultId, itemId, vkEpoch, rev, plain, ik, ikWrapNonce, bodyNonce, ikWrapExisting }) {
  const hdr = { version: 1, suite: 1, kind };
  const padded = pad(plain);
  const baad = bodyAad(hdr, vaultId, itemId, rev);
  let ikWrap = null;
  let ikAadBytes = null;
  let key = kKey;
  if (kind === KIND.item) {
    ikAadBytes = ikAad(hdr, vaultId, itemId, vkEpoch);
    if (ikWrapExisting) {
      ikWrap = ikWrapExisting;
      ik = aeadOpen(vk, ikWrap, ikAadBytes);
    } else {
      ikWrap = aeadSeal(vk, ikWrapNonce, ik, ikAadBytes);
    }
    key = ik;
  }
  const body = aeadSeal(key, bodyNonce, padded, baad);
  const envelope = concat(Uint8Array.of(1, 1, kind), ...(ikWrap ? [ikWrap] : []), body);
  return { envelope, ik, ikAad: ikAadBytes, bodyAad: baad, paddedLen: padded.length };
}

// Returns the CBOR plaintext of the body.
export function openEnvelope({ kind, vk, kKey, vaultId, itemId, vkEpoch, rev, env }) {
  const withIk = kind === KIND.item;
  const { hdr, ikWrap, body } = splitEnvelope(env, withIk);
  let key = kKey;
  if (withIk) key = aeadOpen(vk, ikWrap, ikAad(hdr, vaultId, itemId, vkEpoch));
  // The header bytes (version, suite, kind) are used as read, so any change fails here.
  const padded = aeadOpen(key, body, bodyAad({ ...hdr }, vaultId, itemId, rev));
  return unpad(padded);
}

export function tombAad(vaultId, itemId, rev) {
  return tlvs(label('ferret/v1/tomb'), fU8(T.version, 1), fU8(T.suite, 1), fBytes(T.vault_id, vaultId), fBytes(T.item_id, itemId), fU64(T.rev, rev));
}

export function tombSeal(kDel, vaultId, itemId, rev, nonce) {
  if (equal(itemId, ZERO_ID)) fail('malformed_envelope');
  const aad = tombAad(vaultId, itemId, rev);
  return { aad, tomb: aeadSeal(kDel, nonce, new Uint8Array(0), aad) };
}

export function tombVerify(kDel, vaultId, itemId, rev, tomb) {
  if (tomb.length !== 40 || equal(itemId, ZERO_ID)) fail('tombstone_invalid');
  try {
    aeadOpen(kDel, tomb, tombAad(vaultId, itemId, rev));
  } catch {
    fail('tombstone_invalid');
  }
}
