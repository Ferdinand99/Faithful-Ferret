// Wraps of Fase 1 section 4.3 (and the PIN wrap of section 7.2 as clarified 29.10).
import { aeadSeal, aeadOpen, ctEqual } from './crypto.mjs';
import { tlvs, label, fU8, fU64, fBytes, T } from './tlv.mjs';
import { concat, u32be, fail } from './util.mjs';
import { commitOf, vkDerive, ksfParams, pinParams } from './keys.mjs';

// `pin_mobile` is the mobile PIN: method type 4 like `pin`, and the 64 MiB profile 1 of the sign-in in its kdf.
export const METHOD = { password: 1, recovery: 2, prf: 3, pin: 4, pin_mobile: 4, device: 5 };
function methodType(type) {
  if (!Object.hasOwn(METHOD, type)) fail('unsupported');
  return METHOD[type];
}

function kdfBytes(p) {
  return fBytes(T.kdf, concat(u32be(p.m), u32be(p.t), u32be(p.p)));
}

function kdfField(profile) {
  const p = ksfParams(profile);
  if (!p) fail('kdf_profile_unknown');
  return kdfBytes(p);
}

// type: password | recovery | prf | pin | pin_mobile | device
export function wrapAad(type, v) {
  const common = [fU8(T.suite, 1), fBytes(T.account_id, v.accountId), fBytes(T.vault_id, v.vaultId), fU8(T.method_type, methodType(type)), fBytes(T.method_id, v.methodId), fU64(T.vk_epoch, v.vkEpoch)];
  if (type === 'pin' || type === 'pin_mobile') {
    // The PIN AAD has its own label, vault_id and method_id, no kek_generation, the device salt and, last, the kdf.
    let p;
    if (type === 'pin') {
      p = pinParams(v.pinProfile);
      if (!p) fail('kdf_profile_unknown');
    } else {
      p = ksfParams(1);
    }
    return tlvs(label('ferret/v1/pin'), ...common, fBytes(T.device_salt, v.deviceSalt), kdfBytes(p));
  }
  const tail = [fU64(T.kek_generation, v.kekGeneration)];
  if (type === 'password') tail.push(kdfField(v.ksfProfile));
  if (type === 'prf') tail.push(fBytes(T.credential_id, v.credentialId), fBytes(T.prf_salt, v.prfSalt));
  return tlvs(label('ferret/v1/wrap'), ...common, ...tail);
}

const hasCommit = (type) => type === 'password' || type === 'pin' || type === 'pin_mobile';

export function wrapSeal(type, v, kek, vk, nonce) {
  const aad = wrapAad(type, v);
  const blob = aeadSeal(kek, nonce, vk, aad);
  const commit = hasCommit(type) ? commitOf(kek) : null;
  return { aad, commit, wrap: commit ? concat(blob, commit) : blob };
}

export function wrapOpen(type, v, kek, wrap) {
  // a passkey record with an all-zero PRF salt does not open
  if (type === 'prf' && v.prfSalt.every((x) => x === 0)) fail('decrypt');
  const want = hasCommit(type) ? 104 : 72;
  if (wrap.length !== want) fail('decrypt');
  let body = wrap;
  if (hasCommit(type)) {
    body = wrap.subarray(0, 72);
    // The commitment is compared in constant time before the AEAD is opened.
    if (!ctEqual(wrap.subarray(72), commitOf(kek))) fail('decrypt');
  }
  const vk = aeadOpen(kek, body, wrapAad(type, v));
  if (vk.length !== 32) fail('decrypt');
  return { vk, pkA: vkDerive(v.accountId, v.vaultId, v.vkEpoch, vk).pkA };
}
