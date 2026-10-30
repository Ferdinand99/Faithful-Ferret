// Key derivations of Fase 1 sections 4.3 and 4.5, and the Argon2id range of section 4.1.
import { hkdf, argon2id, ed25519FromSeed } from './crypto.mjs';
import { tlvs, label, fBytes, fU64, T } from './tlv.mjs';
import { ascii, concat, fail } from './util.mjs';

// Section 4.1 point 5: floor m >= 64 MiB, t >= 3, p in 1..4; ceiling m <= 512 MiB, t <= 16, p <= 4.
export function checkKdfRange(m, t, p) {
  if (!(m >= 65536 && m <= 524288 && t >= 3 && t <= 16 && p >= 1 && p <= 4)) fail('kdf_out_of_range');
}

export const KSF_PROFILES = { 1: { m: 65536, t: 3, p: 1 } };

export function kekPassword(accountId, exportKey) {
  const salt = tlvs(label('ferret/v1/kek/password'), fBytes(T.account_id, accountId));
  return hkdf(salt, exportKey, ascii('ferret/v1/kek/password'), 32);
}

export function kekRecovery(accountId, rk) {
  const salt = tlvs(label('ferret/v1/recovery'), fBytes(T.account_id, accountId));
  return hkdf(salt, rk, ascii('ferret/v1/kek/recovery'), 32);
}

export function recoverySeed(accountId, rk) {
  const salt = tlvs(label('ferret/v1/recovery-sign'), fBytes(T.account_id, accountId));
  return hkdf(salt, rk, ascii('ferret/v1/recovery-sign'), 32);
}

export function recoveryKeypair(accountId, rk) {
  const seed = recoverySeed(accountId, rk);
  return { seed, ...ed25519FromSeed(seed) };
}

export function kekPrf(credentialId, prfOutput) {
  const salt = tlvs(label('ferret/v1/prf'), fBytes(T.credential_id, credentialId));
  return hkdf(salt, prfOutput, ascii('ferret/v1/kek/prf'), 32);
}

// Section 7.2: a PIN is at least 6 ASCII digits.
export function checkPin(pin) {
  if (!/^[0-9]*$/.test(pin)) fail('input_forbidden_character');
  if (pin.length < 6) fail('input_too_short');
}

export function kekPinExtension(pin, deviceSalt) {
  checkPin(pin);
  return argon2id(ascii(pin), deviceSalt, 65536, 3, 1, 32);
}

export function kekPinMobile(pin, deviceSalt, kekDevPin) {
  checkPin(pin);
  const stretched = argon2id(ascii(pin), deviceSalt, 65536, 3, 1, 32);
  const salt = tlvs(label('ferret/v1/kek/pin'), fBytes(T.device_salt, deviceSalt));
  return hkdf(salt, concat(kekDevPin, stretched), ascii('ferret/v1/kek/pin'), 32);
}

// Section 4.5
export function vkDerive(accountId, vaultId, vkEpoch, vk) {
  const salt = tlvs(label('ferret/v1/vk-derive'), fBytes(T.account_id, accountId), fBytes(T.vault_id, vaultId), fU64(T.vk_epoch, vkEpoch));
  const d = (name) => hkdf(salt, vk, ascii(name), 32);
  const seedA = d('ferret/v1/auth-sign');
  const { sk, pk } = ed25519FromSeed(seedA);
  return {
    kHead: d('ferret/v1/head'),
    kDel: d('ferret/v1/tomb'),
    kMeta: d('ferret/v1/meta'),
    seedA,
    skA: sk,
    pkA: pk,
  };
}

// Commitment of section 4.3: HKDF(salt = none, ikm = KEK, info = "ferret/v1/commit").
export const commitOf = (kek) => hkdf(null, kek, ascii('ferret/v1/commit'), 32);
