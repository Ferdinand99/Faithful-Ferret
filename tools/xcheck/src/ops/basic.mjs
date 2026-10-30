// tlv.build, kdf.*, wrap.*
import { unhex, hex, fail, concat, u8, u64be, repeat } from '../util.mjs';
import { tlv, label, T } from '../tlv.mjs';
import { argon2id } from '../crypto.mjs';
import { checkKdfRange, kekPassword, kekRecovery, recoveryKeypair, kekPrf, kekPinExtension, kekPinMobile, vkDerive } from '../keys.mjs';
import { wrapSeal, wrapOpen } from '../wrap.mjs';

export const ops = {};

ops['tlv.build'] = ({ input }) => {
  const parts = input.fields.map((f) => {
    switch (f.type) {
      case 'label':
        return label(f.value);
      case 'label_hex': {
        const b = unhex(f.value);
        if (b.some((x) => x > 0x7f)) fail('malformed_tlv', 'label is not ASCII');
        return tlv(T.label, b);
      }
      case 'u8':
        return tlv(parseInt(f.tag, 16), u8(f.value));
      case 'u64':
        return tlv(parseInt(f.tag, 16), u64be(f.value));
      case 'bytes':
        return tlv(parseInt(f.tag, 16), f.fill ? repeat(unhex(f.fill.byte), f.fill.len) : unhex(f.value));
      default:
        throw new Error(`unknown field type ${f.type}`);
    }
  });
  return { expect: { tlv: hex(concat(...parts)) } };
};

ops['kdf.argon2id'] = ({ input }) => {
  const { m_kib: m, t, p, out_len: outLen } = input;
  checkKdfRange(m, t, p);
  const salt = unhex(input.salt);
  // RFC 9106 asks for a salt of at least 8 bytes; the design does not say. (AMBIGUITIES.md)
  if (salt.length < 8) fail('input_too_short');
  return { expect: { hash: hex(argon2id(unhex(input.password), salt, m, t, p, outLen)) } };
};

ops['kdf.kek.password'] = ({ input }) => ({ expect: { kek: hex(kekPassword(unhex(input.account_id), unhex(input.export_key))) } });

ops['kdf.kek.recovery'] = ({ input }) => {
  const accountId = unhex(input.account_id);
  const rk = unhex(input.rk);
  const kp = recoveryKeypair(accountId, rk);
  return { expect: { kek: hex(kekRecovery(accountId, rk)), seed_r: hex(kp.seed), pk_r: hex(kp.pk) } };
};

ops['kdf.vk_derive'] = ({ input }) => {
  const d = vkDerive(unhex(input.account_id), unhex(input.vault_id), BigInt(input.vk_epoch), unhex(input.vk));
  return { expect: { k_head: hex(d.kHead), k_del: hex(d.kDel), k_meta: hex(d.kMeta), seed_a: hex(d.seedA), pk_a: hex(d.pkA) } };
};

ops['kdf.kek.prf'] = ({ input }) => ({ expect: { kek: hex(kekPrf(unhex(input.credential_id), unhex(input.prf_output))) } });
ops['kdf.kek.pin_extension'] = ({ input }) => ({ expect: { kek: hex(kekPinExtension(input.pin, unhex(input.device_salt))) } });
ops['kdf.kek.pin_mobile'] = ({ input }) => ({ expect: { kek: hex(kekPinMobile(input.pin, unhex(input.device_salt), unhex(input.kek_dev_pin))) } });

function wrapFields(input) {
  return {
    accountId: unhex(input.account_id),
    vaultId: unhex(input.vault_id),
    methodId: unhex(input.method_id),
    vkEpoch: BigInt(input.vk_epoch),
    kekGeneration: BigInt(input.kek_generation),
    ksfProfile: input.ksf_profile,
    credentialId: input.credential_id !== undefined ? unhex(input.credential_id) : undefined,
    prfSalt: input.prf_salt !== undefined ? unhex(input.prf_salt) : undefined,
    deviceSalt: input.device_salt !== undefined ? unhex(input.device_salt) : undefined,
  };
}

function sealCase(type, getKek) {
  return ({ input, rng }) => {
    const v = wrapFields(input);
    const kek = getKek(input, v, rng);
    // the PRF salt is 32 random bytes per registration: all zero is a missing salt (before anything is drawn)
    if (type === 'prf' && v.prfSalt.every((x) => x === 0)) fail('input_all_zero');
    const nonce = rng.draw(24);
    const r = wrapSeal(type, v, kek, unhex(input.vk), nonce);
    const intermediate = { kek: hex(kek), aad: hex(r.aad) };
    if (r.commit) intermediate.commit = hex(r.commit);
    return { expect: { wrap: hex(r.wrap) }, intermediate };
  };
}

ops['wrap.seal.password'] = sealCase('password', (i, v) => kekPassword(v.accountId, unhex(i.export_key)));
ops['wrap.seal.recovery'] = sealCase('recovery', (i, v) => kekRecovery(v.accountId, unhex(i.rk)));
ops['wrap.seal.prf'] = sealCase('prf', (i) => kekPrf(unhex(i.credential_id), unhex(i.prf_output)));
ops['wrap.seal.pin'] = sealCase('pin', (i) => kekPinExtension(i.pin, unhex(i.device_salt)));
ops['wrap.seal.pin_mobile'] = sealCase('pin', (i) => kekPinMobile(i.pin, unhex(i.device_salt), unhex(i.kek_dev_pin)));
// Two draws: the 32-byte KEK, then the 24-byte nonce.
ops['wrap.seal.device'] = sealCase('device', (i, v, rng) => rng.draw(32));

ops['wrap.open'] = ({ input }) => {
  const m = input.method;
  const v = {
    accountId: unhex(input.account_id),
    vaultId: unhex(input.vault_id),
    methodId: unhex(input.method_id),
    vkEpoch: BigInt(input.vk_epoch),
    kekGeneration: BigInt(input.kek_generation),
    ksfProfile: m.ksf_profile,
    credentialId: m.credential_id !== undefined ? unhex(m.credential_id) : undefined,
    prfSalt: m.prf_salt !== undefined ? unhex(m.prf_salt) : undefined,
    deviceSalt: m.device_salt !== undefined ? unhex(m.device_salt) : undefined,
  };
  const r = wrapOpen(m.type, v, unhex(input.kek), unhex(input.wrap));
  return { expect: { vk: hex(r.vk), pk_a: hex(r.pkA) } };
};
