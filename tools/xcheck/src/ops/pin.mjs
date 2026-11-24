// pin.* : the PIN text rules, the rule of the server, the PIN profile, the PIN AAD and the KEK of a PIN,
// from the rules in vectors/OPS.md (Fase 1 section 7.2).
import { unhex, hex, fail } from '../util.mjs';
import { pinNormalize, pinMeetsRule, pinFloor } from '../text.mjs';
import { pinParams, kekPinExtension } from '../keys.mjs';
import { wrapAad } from '../wrap.mjs';

export const ops = {};

ops['pin.normalize'] = ({ input }) => ({ expect: { pin: hex(pinNormalize(unhex(input.utf8)).nfkd) } });

ops['pin.rule'] = ({ input }) => {
  const r = pinNormalize(unhex(input.utf8));
  pinMeetsRule(r.text, input.rule);
  return { expect: {} };
};

ops['pin.profile'] = ({ input }) => {
  const p = pinParams(input.pin_profile);
  if (!p) fail('kdf_profile_unknown');
  return { expect: { m_kib: p.m, t: p.t, p: p.p } };
};

ops['pin.aad'] = ({ input }) => {
  const m = input.method;
  const aad = wrapAad(m.type, {
    accountId: unhex(input.account_id),
    vaultId: unhex(input.vault_id),
    methodId: unhex(input.method_id),
    vkEpoch: BigInt(input.vk_epoch),
    deviceSalt: unhex(m.device_salt),
    pinProfile: m.pin_profile,
  });
  return { expect: { aad: hex(aad), kdf: hex(aad.subarray(aad.length - 12)) } };
};

// The profile and the PIN are checked before Argon2id runs.
ops['pin.kek'] = ({ input }) => {
  if (!pinParams(input.pin_profile)) fail('kdf_profile_unknown');
  const r = pinNormalize(unhex(input.utf8));
  pinFloor(r.text);
  const pin = r.nfkd;
  return { expect: { kek: hex(kekPinExtension(pin, unhex(input.device_salt), input.pin_profile)) } };
};
