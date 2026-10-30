// checkpoint.*, proof.*
import { unhex, hex, fail } from '../util.mjs';
import { sha256, ed25519Sign, ed25519Verify } from '../crypto.mjs';
import { tlvs, label, fU64, fBytes, T } from '../tlv.mjs';
import { ascii } from '../util.mjs';
import { vkDerive, recoveryKeypair } from '../keys.mjs';
import { makeCheckpoint, generatedRows, verifyCheckpoint, parseEntries } from '../checkpoint.mjs';

export const ops = {};

const vault = (i) => ({ accountId: unhex(i.account_id), vaultId: unhex(i.vault_id), vkEpoch: BigInt(i.vk_epoch), vk: unhex(i.vk) });

function rowsOf(input) {
  if (input.generate) return generatedRows(input.generate.count);
  return input.entries.map((e) => ({ itemId: unhex(e.item_id), rev: BigInt(e.rev), hash: e.hash === null ? null : unhex(e.hash) }));
}

ops['checkpoint.make'] = ({ input }) => {
  const v = vault(input);
  const keys = vkDerive(v.accountId, v.vaultId, v.vkEpoch, v.vk);
  const cp = makeCheckpoint(keys.kHead, BigInt(input.seq), rowsOf(input));
  const expect = { entries_len: cp.entries.length, entries_sha256: hex(sha256(cp.entries)), digest: hex(cp.digest), mac: hex(cp.mac) };
  if (cp.entries.length <= 20 * 56) expect.entries = hex(cp.entries);
  return { expect, intermediate: { message: hex(cp.message) } };
};

ops['checkpoint.verify'] = ({ input }) => {
  const v = vault(input);
  const keys = vkDerive(v.accountId, v.vaultId, v.vkEpoch, v.vk);
  const c = input.checkpoint;
  let entries;
  if (c.generate) entries = makeCheckpoint(keys.kHead, BigInt(c.seq), generatedRows(c.generate.count)).entries;
  else entries = unhex(c.entries);
  const cp = { seq: BigInt(c.seq), digest: unhex(c.digest), mac: unhex(c.mac), entries };
  let rows;
  if (Array.isArray(input.rows)) {
    rows = input.rows.map((r) => ({ itemId: unhex(r.item_id), rev: BigInt(r.rev), live: r.state === 'live', hash: r.hash ? unhex(r.hash) : new Uint8Array(32) }));
  } else {
    // One row per entry of the checkpoint, in sorted order, without the omitted indexes. The entries
    // are read the same way a client reads them (unsorted entries cannot be used here).
    const omit = new Set(input.rows.omit);
    rows = parseEntries(entries)
      .map((e, idx) => ({ e, idx }))
      .filter(({ idx }) => !omit.has(idx))
      .map(({ e }) => ({ itemId: e.itemId, rev: e.rev, live: !e.tomb, hash: e.h }));
  }
  verifyCheckpoint(keys.kHead, BigInt(input.top_seq), cp, rows);
  return { expect: { ok: true } };
};

// ---- mutation proofs (section 4.6) -----------------------------------------------------------
const AUTH_OPS = ['unlock-method.add', 'unlock-method.remove', 'unlock-method.password.put', 'unlock-method.recovery.put', 'rekey'];

export function proofMessage(lab, op, accountId, nonce, vkEpoch, body) {
  return tlvs(label(lab), fBytes(T.op, ascii(op)), fBytes(T.account_id, accountId), fBytes(T.nonce, nonce), fU64(T.vk_epoch, vkEpoch), fBytes(T.hash, sha256(body)));
}

ops['proof.sign'] = ({ input }) => {
  const v = vault(input);
  // `recover` is signed by the recovery key, not by sk_a (proof.recovery_sign).
  if (!AUTH_OPS.includes(input.op)) fail('unsupported');
  const keys = vkDerive(v.accountId, v.vaultId, v.vkEpoch, v.vk);
  const msg = proofMessage('ferret/v1/mutation', input.op, v.accountId, unhex(input.nonce), v.vkEpoch, unhex(input.body));
  return { expect: { proof: hex(ed25519Sign(msg, keys.skA)), pk_a: hex(keys.pkA) }, intermediate: { message: hex(msg) } };
};

ops['proof.recovery_sign'] = ({ input }) => {
  const accountId = unhex(input.account_id);
  const kp = recoveryKeypair(accountId, unhex(input.rk));
  const msg = proofMessage('ferret/v1/recovery-req', 'recover', accountId, unhex(input.nonce), BigInt(input.vk_epoch), unhex(input.body));
  return { expect: { proof: hex(ed25519Sign(msg, kp.sk)), pk_r: hex(kp.pk) }, intermediate: { message: hex(msg) } };
};

ops['proof.verify'] = ({ input }) => {
  const isRecover = input.op === 'recover';
  if (!isRecover && !AUTH_OPS.includes(input.op)) fail('decrypt');
  const msg = proofMessage(isRecover ? 'ferret/v1/recovery-req' : 'ferret/v1/mutation', input.op, unhex(input.account_id), unhex(input.nonce), BigInt(input.vk_epoch), unhex(input.body));
  const pk = unhex(input.pk);
  const sig = unhex(input.proof);
  if (pk.length !== 32 || sig.length !== 64 || !ed25519Verify(sig, msg, pk)) fail('decrypt');
  return { expect: { ok: true } };
};
