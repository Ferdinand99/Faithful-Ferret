// Wraps of Fase 1 section 4.3 (and the PIN wrap of section 7.2 as clarified 29.10).
import { aeadSeal, aeadOpen, ctEqual } from './crypto.mjs';
import { tlvs, label, fU8, fU64, fBytes, T } from './tlv.mjs';
import { concat, u32be, fail } from './util.mjs';
import { commitOf, vkDerive, KSF_PROFILES } from './keys.mjs';

export const METHOD = { password: 1, recovery: 2, prf: 3, pin: 4, device: 5 };

function kdfField(profile) {
  const p = KSF_PROFILES[profile];
  if (!p) fail('kdf_profile_unknown');
  return fBytes(T.kdf, concat(u32be(p.m), u32be(p.t), u32be(p.p)));
}

// type: password | recovery | prf | pin | device
export function wrapAad(type, v) {
  const common = [fU8(T.suite, 1), fBytes(T.account_id, v.accountId), fBytes(T.vault_id, v.vaultId), fU8(T.method_type, METHOD[type]), fBytes(T.method_id, v.methodId), fU64(T.vk_epoch, v.vkEpoch)];
  if (type === 'pin') {
    // The PIN AAD has its own label, vault_id and method_id, no kek_generation, and the device salt.
    return tlvs(label('ferret/v1/pin'), ...common, fBytes(T.device_salt, v.deviceSalt));
  }
  const tail = [fU64(T.kek_generation, v.kekGeneration)];
  if (type === 'password') tail.push(kdfField(v.ksfProfile));
  if (type === 'prf') tail.push(fBytes(T.credential_id, v.credentialId), fBytes(T.prf_salt, v.prfSalt));
  return tlvs(label('ferret/v1/wrap'), ...common, ...tail);
}

const hasCommit = (type) => type === 'password' || type === 'pin';

export function wrapSeal(type, v, kek, vk, nonce) {
  const aad = wrapAad(type, v);
  const blob = aeadSeal(kek, nonce, vk, aad);
  const commit = hasCommit(type) ? commitOf(kek) : null;
  return { aad, commit, wrap: commit ? concat(blob, commit) : blob };
}

export function wrapOpen(type, v, kek, wrap) {
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
