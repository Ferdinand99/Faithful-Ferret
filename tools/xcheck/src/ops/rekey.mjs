// rekey.run (Fase 1 section 4.7 and 8.6)
import { unhex, hex, fail, equal } from '../util.mjs';
import { sha256 } from '../crypto.mjs';
import { C, encode } from '../cbor.mjs';
import { vkDerive, kekRecovery, recoveryKeypair } from '../keys.mjs';
import { wrapSeal } from '../wrap.mjs';
import { KIND, ZERO_ID, sealEnvelope, openEnvelope, splitEnvelope, itemTag, verifyItemTag, tombSeal, tombVerify } from '../items.mjs';
import { parseBody, parseManifest } from '../body.mjs';
import { makeCheckpoint, verifyCheckpoint } from '../checkpoint.mjs';

export const ops = {};

const U64_MAX = 2n ** 64n - 1n;
// The next generation must be one that every pinned device accepts (see AMBIGUITIES.md, "generation limit").
const GENERATION_LIMIT = 2n ** 32n - 1n;

ops['rekey.run'] = ({ input, rng }) => {
  const accountId = unhex(input.account_id);
  const vaultId = unhex(input.vault_id);
  const epoch = BigInt(input.vk_epoch);
  const vk = unhex(input.vk);
  const baseSeq = BigInt(input.base_seq);
  const old = vkDerive(accountId, vaultId, epoch, vk);
  const cp = input.old_checkpoint;

  if (BigInt(cp.seq) !== baseSeq) fail('malformed_entries');

  const items = input.items.map((i) => ({ itemId: unhex(i.item_id), rev: BigInt(i.rev), env: unhex(i.envelope), tag: unhex(i.tag) }));
  const tombs = input.tombstones.map((t) => ({ itemId: unhex(t.item_id), rev: BigInt(t.rev), tomb: unhex(t.tomb) }));

  // ids: none may be the manifest's, none may repeat
  const seen = new Set();
  for (const x of [...items, ...tombs]) {
    if (equal(x.itemId, ZERO_ID)) fail('malformed_envelope');
    const k = hex(x.itemId);
    if (seen.has(k)) fail('malformed_entries');
    seen.add(k);
  }
  for (const x of [...items, ...tombs]) if (x.rev === U64_MAX) fail('malformed_entries'); // cannot be raised
  if (BigInt(input.old_manifest.rev) === U64_MAX) fail('malformed_entries');

  // tags first
  const man = { rev: BigInt(input.old_manifest.rev), env: unhex(input.old_manifest.envelope), tag: unhex(input.old_manifest.tag) };
  for (const it of items) verifyItemTag(old.kHead, it.itemId, it.rev, it.env, it.tag);
  for (const t of tombs) tombVerify(old.kDel, vaultId, t.itemId, t.rev, t.tomb);
  verifyItemTag(old.kHead, ZERO_ID, man.rev, man.env, man.tag);

  // the old checkpoint, against these rows, at the top
  const rows = [
    ...items.map((it) => ({ itemId: it.itemId, rev: it.rev, live: true, hash: sha256(it.env) })),
    ...tombs.map((t) => ({ itemId: t.itemId, rev: t.rev, live: false, hash: new Uint8Array(32) })),
    { itemId: ZERO_ID, rev: man.rev, live: true, hash: sha256(man.env) },
  ];
  verifyCheckpoint(old.kHead, baseSeq, { seq: BigInt(cp.seq), digest: unhex(cp.digest), mac: unhex(cp.mac), entries: unhex(cp.entries) }, rows);

  // the old manifest and the pinned floors
  const oldManifest = parseManifest(openEnvelope({ kind: KIND.manifest, vk, kKey: old.kMeta, vaultId, itemId: ZERO_ID, vkEpoch: epoch, rev: man.rev, env: man.env }));
  const gen = (type, floorText) => {
    if (floorText === null) fail('malformed_pinned_record');
    const inManifest = oldManifest.methods.filter((m) => m.t === type).reduce((a, m) => (m.g > a ? m.g : a), 0n);
    const floor = BigInt(floorText);
    const next = (floor > inManifest ? floor : inManifest) + 1n;
    if (next > GENERATION_LIMIT) fail('malformed_pinned_record');
    return next;
  };
  const genPw = gen(1, input.password_floor);
  const genRk = gen(2, input.recovery_floor);

  // ---- draws ----
  const newVk = rng.draw(32);
  const newEpoch = epoch + 1n;
  const nk = vkDerive(accountId, vaultId, newEpoch, newVk);

  const outItems = items.map((it) => {
    const ik = rng.draw(32);
    const ikWrapNonce = rng.draw(24);
    const bodyNonce = rng.draw(24);
    const plain = openEnvelope({ kind: KIND.item, vk, vaultId, itemId: it.itemId, vkEpoch: epoch, rev: it.rev, env: it.env });
    const { value } = parseBody(plain);
    const rev = it.rev + 1n;
    const r = sealEnvelope({ kind: KIND.item, vk: newVk, vaultId, itemId: it.itemId, vkEpoch: newEpoch, rev, plain: encode(value), ik, ikWrapNonce, bodyNonce });
    return { itemId: it.itemId, rev, envelope: r.envelope, tag: itemTag(nk.kHead, it.itemId, rev, r.envelope).tag };
  });
  const outTombs = tombs.map((t) => {
    const rev = t.rev + 1n;
    return { itemId: t.itemId, rev, tomb: tombSeal(nk.kDel, vaultId, t.itemId, rev, rng.draw(24)).tomb };
  });

  const pwMethodId = unhex(input.password_method_id);
  const rkMethodId = unhex(input.recovery_method_id);
  const pwWrap = wrapSeal('password', { accountId, vaultId, methodId: pwMethodId, vkEpoch: newEpoch, kekGeneration: genPw, ksfProfile: input.password_ksf_profile }, unhex(input.password_kek), newVk, rng.draw(24)).wrap;
  const newRk = rng.draw(32);
  const rkWrap = wrapSeal('recovery', { accountId, vaultId, methodId: rkMethodId, vkEpoch: newEpoch, kekGeneration: genRk }, kekRecovery(accountId, newRk), newVk, rng.draw(24)).wrap;
  const kpR = recoveryKeypair(accountId, newRk);

  const manifestCbor = encode(
    C.map([
      ['v', C.uint(1)],
      ['vk_epoch', C.uint(newEpoch)],
      [
        'methods',
        C.array([
          C.map([['t', C.uint(1)], ['id', C.bytes(pwMethodId)], ['g', C.uint(genPw)]]),
          C.map([['t', C.uint(2)], ['id', C.bytes(rkMethodId)], ['g', C.uint(genRk)]]),
        ]),
      ],
    ]),
  );
  const manRev = man.rev + 1n;
  const mEnv = sealEnvelope({ kind: KIND.manifest, vk: newVk, kKey: nk.kMeta, vaultId, itemId: ZERO_ID, vkEpoch: newEpoch, rev: manRev, plain: manifestCbor, bodyNonce: rng.draw(24) });
  const mTag = itemTag(nk.kHead, ZERO_ID, manRev, mEnv.envelope).tag;

  const newCp = makeCheckpoint(nk.kHead, baseSeq, [
    ...outItems.map((o) => ({ itemId: o.itemId, rev: o.rev, hash: sha256(o.envelope) })),
    ...outTombs.map((o) => ({ itemId: o.itemId, rev: o.rev, hash: null })),
    { itemId: ZERO_ID, rev: manRev, hash: sha256(mEnv.envelope) },
  ]);

  return {
    expect: {
      vk_epoch: String(newEpoch),
      vk: hex(newVk),
      pk_a: hex(nk.pkA),
      pk_r: hex(kpR.pk),
      recovery_key: hex(newRk),
      items: outItems.map((o) => ({ item_id: hex(o.itemId), rev: String(o.rev), envelope: hex(o.envelope), tag: hex(o.tag) })),
      tombstones: outTombs.map((o) => ({ item_id: hex(o.itemId), rev: String(o.rev), tomb: hex(o.tomb) })),
      wraps: [
        { method_id: hex(pwMethodId), kek_generation: String(genPw), wrap: hex(pwWrap) },
        { method_id: hex(rkMethodId), kek_generation: String(genRk), wrap: hex(rkWrap) },
      ],
      manifest: { rev: String(manRev), envelope: hex(mEnv.envelope), tag: hex(mTag) },
      checkpoint: { seq: String(baseSeq), digest: hex(newCp.digest), mac: hex(newCp.mac), entries: hex(newCp.entries) },
    },
  };
};
