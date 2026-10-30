// account.* (Fase 1 sections 4.2, 4.3, 4.6, 6.1 to 6.3 and vectors/OPS.md)
//
// The OPAQUE registration is an input here ("recorded; no Argon2id runs"): xcheck does not run OPAQUE.
import { unhex, hex, fail, equal, textInputToBytes, utf8, concat } from '../util.mjs';
import { sha256, ed25519Sign } from '../crypto.mjs';
import { C, decode, encode } from '../cbor.mjs';
import { vkDerive, kekPassword, kekRecovery, recoveryKeypair, ksfParams } from '../keys.mjs';
import { wrapSeal, wrapOpen } from '../wrap.mjs';
import { KIND, ZERO_ID, sealEnvelope, openEnvelope, splitEnvelope, itemTag, verifyItemTag } from '../items.mjs';
import { parseManifest } from '../body.mjs';
import { makeCheckpoint } from '../checkpoint.mjs';
import { masterPassword, decodeCode, encodeCode } from '../text.mjs';
import { proofMessage } from './checkpoint.mjs';

export const ops = {};

const GENERATION_LIMIT = 2n ** 32n - 1n;

function checkPassword(input) {
  // `unlock` is the password of an existing account: it has no creation floor, so it cannot be set
  if (input.policy === 'unlock') fail('input_too_short');
  const bytes = typeof input.password === 'string' ? utf8(input.password) : textInputToBytes(input.password);
  const mp = masterPassword(bytes, input.policy).nfkd;
  // Section 4.1: without a secret key the floor is 15, whatever policy the text was first built under.
  if (input.input_secret_key === null || input.input_secret_key === undefined) masterPassword(bytes, 'without_secret_key');
  return mp;
}

function manifestCbor(epoch, methods) {
  return encode(
    C.map([
      ['v', C.uint(1)],
      ['vk_epoch', C.uint(epoch)],
      ['methods', C.array(methods.map((m) => C.map([['t', C.uint(m.t)], ['id', C.bytes(m.id)], ['g', C.uint(m.g)]])))],
    ]),
  );
}

ops['account.create'] = ({ input, rng }) => {
  const accountId = unhex(input.account_id);
  const vaultId = unhex(input.vault_id);
  checkPassword(input);
  const a = input.input_secret_key ?? null;
  const b = input.secret_key ?? null;
  if (a !== b) fail('input_secret_key_mismatch');
  const pwId = unhex(input.password_method_id);
  const rkId = unhex(input.recovery_method_id);
  if (equal(pwId, rkId)) fail('malformed_entries');

  const vk = rng.draw(32);
  const rk = rng.draw(32);
  const epoch = 1n;
  const keys = vkDerive(accountId, vaultId, epoch, vk);
  const pw = wrapSeal('password', { accountId, vaultId, methodId: pwId, vkEpoch: epoch, kekGeneration: 1n, ksfProfile: input.ksf_profile }, kekPassword(accountId, unhex(input.registration.export_key)), vk, rng.draw(24));
  const rkw = wrapSeal('recovery', { accountId, vaultId, methodId: rkId, vkEpoch: epoch, kekGeneration: 1n }, kekRecovery(accountId, rk), vk, rng.draw(24));
  const m = sealEnvelope({
    kind: KIND.manifest, vk, kKey: keys.kMeta, vaultId, itemId: ZERO_ID, vkEpoch: epoch, rev: 1n,
    plain: manifestCbor(epoch, [{ t: 1, id: pwId, g: 1n }, { t: 2, id: rkId, g: 1n }]), bodyNonce: rng.draw(24),
  });
  const cp = makeCheckpoint(keys.kHead, 1n, [{ itemId: ZERO_ID, rev: 1n, hash: sha256(m.envelope) }]);
  return {
    expect: {
      vk: hex(vk),
      rk: hex(rk),
      pk_a: hex(keys.pkA),
      pk_r: hex(recoveryKeypair(accountId, rk).pk),
      wraps: [
        { method_id: hex(pwId), kek_generation: '1', wrap: hex(pw.wrap) },
        { method_id: hex(rkId), kek_generation: '1', wrap: hex(rkw.wrap) },
      ],
      manifest: { rev: '1', envelope: hex(m.envelope), tag: hex(itemTag(keys.kHead, ZERO_ID, 1n, m.envelope).tag) },
      checkpoint: { seq: '1', digest: hex(cp.digest), mac: hex(cp.mac), entries: hex(cp.entries) },
      registration_record: input.registration.record,
      server_public_key: input.registration.server_public_key,
    },
  };
};

// ---- shared checks of change_password and recover --------------------------------------------
function pinnedFloors(pinned) {
  if (!pinned) return { pw: 0n, rk: 0n };
  if (pinned.password_floor === null || pinned.recovery_floor === null) fail('malformed_pinned_record');
  const pw = BigInt(pinned.password_floor);
  const rk = BigInt(pinned.recovery_floor);
  if (pw >= GENERATION_LIMIT || rk >= GENERATION_LIMIT) fail('malformed_pinned_record');
  return { pw, rk };
}

function checkPinnedVault(pinned, epoch, pkA) {
  if (!pinned) return;
  if (BigInt(pinned.vk_epoch_max) > epoch) fail('pinned_vk_epoch');
  if (BigInt(pinned.vk_epoch_max) === epoch && pinned.pk_a !== hex(pkA)) fail('pinned_auth_key');
}

function checkRegistration(pinned, input, hasSk, currentProfile) {
  if (pinned) {
    if (input.registration.server_public_key !== pinned.server_public_key) fail('pinned_server_key');
    if (hasSk !== pinned.sk_bit) fail('pinned_sk_bit');
  }
  if (!ksfParams(input.ksf_profile)) fail('kdf_profile_unknown');
  if ((pinned && input.ksf_profile < pinned.ksf_profile) || (currentProfile !== undefined && input.ksf_profile < currentProfile)) fail('kdf_profile_downgrade');
  checkPassword(input);
}

function openManifestRow(keys, accountId, vaultId, epoch, vk, row) {
  const env = unhex(row.envelope);
  const rev = BigInt(row.rev);
  splitEnvelope(env, false);
  verifyItemTag(keys.kHead, ZERO_ID, rev, env, unhex(row.tag));
  const plain = openEnvelope({ kind: KIND.manifest, vk, kKey: keys.kMeta, vaultId, itemId: ZERO_ID, vkEpoch: epoch, rev, env });
  const m = parseManifest(plain);
  if (m.epoch !== epoch) fail('decrypt');
  return { rev, parsed: m };
}

// A copy of the manifest with the entries rewritten by `edit`; unknown keys stay where they were.
function rewriteManifest(parsed, edit) {
  const value = structuredCloneValue(parsed.value);
  const methods = value.v.find(([k]) => k === 'methods')[1];
  for (const m of methods.v) edit(m);
  return encode(value);
}
function structuredCloneValue(v) {
  return decode(encode(v));
}
const entryOf = (m) => ({ t: Number(m.v.find(([k]) => k === 't')[1].v), id: m.v.find(([k]) => k === 'id')[1].v });
const setKey = (m, key, val) => {
  const e = m.v.find(([k]) => k === key);
  e[1] = val;
};

function sealNewManifest(keys, vk, vaultId, epoch, rev, plain, nonce) {
  const m = sealEnvelope({ kind: KIND.manifest, vk, kKey: keys.kMeta, vaultId, itemId: ZERO_ID, vkEpoch: epoch, rev, plain, bodyNonce: nonce });
  return { rev: String(rev), envelope: hex(m.envelope), tag: hex(itemTag(keys.kHead, ZERO_ID, rev, m.envelope).tag) };
}

const max = (...xs) => xs.reduce((a, b) => (b > a ? b : a));

ops['account.change_password'] = ({ input, rng }) => {
  const accountId = unhex(input.account_id);
  const vaultId = unhex(input.vault_id);
  const epoch = BigInt(input.vk_epoch);
  const vk = unhex(input.vk);
  const keys = vkDerive(accountId, vaultId, epoch, vk);
  const pinned = input.pinned;
  const floors = pinnedFloors(pinned);
  checkPinnedVault(pinned, epoch, keys.pkA);
  const hasSk = input.input_secret_key !== null && input.input_secret_key !== undefined;
  checkRegistration(pinned, input, hasSk, input.current.ksf_profile);
  if (input.current.type !== 'password') fail('unsupported');
  const row = openManifestRow(keys, accountId, vaultId, epoch, vk, input.manifest);
  const currentId = unhex(input.current.method_id);
  const listed = row.parsed.methods.find((m) => m.t === 1 && equal(m.id, currentId));
  if (!listed) fail('malformed_entries');

  const gen = max(floors.pw, listed.g, BigInt(input.current.kek_generation)) + 1n;
  if (gen > GENERATION_LIMIT) fail('malformed_pinned_record');
  const wrap = wrapSeal('password', { accountId, vaultId, methodId: currentId, vkEpoch: epoch, kekGeneration: gen, ksfProfile: input.ksf_profile }, kekPassword(accountId, unhex(input.registration.export_key)), vk, rng.draw(24));
  const plain = rewriteManifest(row.parsed, (m) => {
    const e = entryOf(m);
    if (e.t === 1 && equal(e.id, currentId)) setKey(m, 'g', C.uint(gen));
  });
  const manifest = sealNewManifest(keys, vk, vaultId, epoch, row.rev + 1n, plain, rng.draw(24));
  const out = {
    wrap: { method_id: hex(currentId), kek_generation: String(gen), wrap: hex(wrap.wrap) },
    manifest,
    registration_record: input.registration.record,
    server_public_key: input.registration.server_public_key,
    ksf_profile: input.ksf_profile,
  };
  if (input.sign) {
    const msg = proofMessage('ferret/v1/mutation', 'unlock-method.password.put', accountId, unhex(input.sign.nonce), epoch, unhex(input.sign.body));
    out.proof = hex(ed25519Sign(msg, keys.skA));
    out.proof_op = 'unlock-method.password.put';
  }
  return { expect: out };
};

ops['account.recover'] = ({ input, rng }) => {
  const accountId = unhex(input.account_id);
  const vaultId = unhex(input.vault_id);
  const epoch = BigInt(input.vk_epoch);
  const vk = unhex(input.vk);
  const keys = vkDerive(accountId, vaultId, epoch, vk);
  // the typed code is read first: a typo is found before any key is used
  const oldRk = decodeCode('rk', input.rk_code);
  const pinned = input.pinned;
  const floors = pinnedFloors(pinned);
  const w = input.rk_wrap;
  const rkMethodId = unhex(w.method_id);
  const opened = wrapOpen('recovery', { accountId, vaultId, methodId: rkMethodId, vkEpoch: epoch, kekGeneration: BigInt(w.kek_generation) }, kekRecovery(accountId, oldRk), unhex(w.wrap));
  if (!equal(opened.vk, vk)) fail('decrypt');
  checkPinnedVault(pinned, epoch, keys.pkA);
  if (pinned && floors.rk > BigInt(w.kek_generation)) fail('pinned_kek_generation');
  const hasSk = input.input_secret_key !== null && input.input_secret_key !== undefined;
  checkRegistration(pinned, input, hasSk, undefined);
  const row = openManifestRow(keys, accountId, vaultId, epoch, vk, input.manifest);
  const pwEntry = row.parsed.methods.find((m) => m.t === 1);
  const rkEntry = row.parsed.methods.find((m) => m.t === 2 && equal(m.id, rkMethodId));
  if (!pwEntry || !rkEntry) fail('malformed_entries');
  const newRkId = unhex(input.new_recovery_method_id);
  // the new id may not be the password wrap's, nor that of any entry but the old recovery entry
  if (row.parsed.methods.some((m) => equal(m.id, newRkId) && m !== rkEntry)) fail('malformed_entries');

  const genPw = max(floors.pw, pwEntry.g) + 1n;
  const genRk = max(floors.rk, rkEntry.g, BigInt(w.kek_generation)) + 1n;
  if (genPw > GENERATION_LIMIT || genRk > GENERATION_LIMIT) fail('malformed_pinned_record');

  const pw = wrapSeal('password', { accountId, vaultId, methodId: pwEntry.id, vkEpoch: epoch, kekGeneration: genPw, ksfProfile: input.ksf_profile }, kekPassword(accountId, unhex(input.registration.export_key)), vk, rng.draw(24));
  const newRk = rng.draw(32);
  const rkw = wrapSeal('recovery', { accountId, vaultId, methodId: newRkId, vkEpoch: epoch, kekGeneration: genRk }, kekRecovery(accountId, newRk), vk, rng.draw(24));
  const plain = rewriteManifest(row.parsed, (m) => {
    const e = entryOf(m);
    if (e.t === 1 && equal(e.id, pwEntry.id)) setKey(m, 'g', C.uint(genPw));
    if (e.t === 2 && equal(e.id, rkMethodId)) {
      setKey(m, 'id', C.bytes(newRkId));
      setKey(m, 'g', C.uint(genRk));
    }
  });
  const manifest = sealNewManifest(keys, vk, vaultId, epoch, row.rev + 1n, plain, rng.draw(24));
  const out = {
    vk: hex(vk),
    recovery_key: hex(newRk),
    pk_r: hex(recoveryKeypair(accountId, newRk).pk),
    password_wrap: { method_id: hex(pwEntry.id), kek_generation: String(genPw), wrap: hex(pw.wrap) },
    recovery_wrap: { method_id: hex(newRkId), kek_generation: String(genRk), wrap: hex(rkw.wrap) },
    manifest,
    registration_record: input.registration.record,
    server_public_key: input.registration.server_public_key,
    sk_bit: hasSk,
  };
  if (input.sign) {
    // a `recover` proof by sk_r of the OLD recovery key, vk_epoch the current one
    const msg = proofMessage('ferret/v1/recovery-req', 'recover', accountId, unhex(input.sign.nonce), epoch, unhex(input.sign.body));
    out.proof = hex(ed25519Sign(msg, recoveryKeypair(accountId, oldRk).sk));
    out.proof_op = 'recover';
  }
  return { expect: out };
};

ops['account.verify_recovery'] = ({ input }) => {
  const accountId = unhex(input.account_id);
  const vaultId = unhex(input.vault_id);
  const epoch = BigInt(input.vk_epoch);
  const rk = decodeCode('rk', input.entered);
  const w = input.rk_wrap;
  const opened = wrapOpen('recovery', { accountId, vaultId, methodId: unhex(w.method_id), vkEpoch: epoch, kekGeneration: BigInt(w.kek_generation) }, kekRecovery(accountId, rk), unhex(w.wrap));
  if (!equal(opened.vk, unhex(input.vk))) fail('decrypt');
  return { expect: { ok: true } };
};

ops['account.verify_secret_key'] = ({ input }) => {
  const sk = decodeCode('sk', input.entered);
  // compared in constant time in the clients; the value is public here
  if (!equal(sk, unhex(input.secret_key))) fail('decrypt');
  return { expect: { ok: true } };
};

export { encodeCode, concat };
