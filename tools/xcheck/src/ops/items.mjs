// pad.*, cbor.decode, item.*, tomb.*
import { unhex, hex, fail, equal, segmentsToBytes } from '../util.mjs';
import { sha256 } from '../crypto.mjs';
import { decode, encode } from '../cbor.mjs';
import { pad, unpad, parseBody, parseManifest } from '../body.mjs';
import { vkDerive } from '../keys.mjs';
import { KIND, ZERO_ID, sealEnvelope, openEnvelope, splitEnvelope, itemTag, verifyItemTag, tombSeal, tombVerify } from '../items.mjs';

export const ops = {};

ops['pad.apply'] = ({ input }) => {
  const padded = pad(segmentsToBytes(input.plain));
  return { expect: { padded_len: padded.length, padded_sha256: hex(sha256(padded)) } };
};

ops['pad.remove'] = ({ input }) => {
  const plain = unpad(segmentsToBytes(input.padded));
  return { expect: { plain_len: plain.length, plain_sha256: hex(sha256(plain)) } };
};

ops['cbor.decode'] = ({ input }) => {
  const out = encode(decode(segmentsToBytes(input.segments)));
  return { expect: { len: out.length, sha256: hex(sha256(out)) } };
};

const vault = (i) => ({ accountId: unhex(i.account_id), vaultId: unhex(i.vault_id), vkEpoch: BigInt(i.vk_epoch), vk: unhex(i.vk) });

function itemSeal(digest) {
  return ({ input, rng }) => {
    const v = vault(input);
    const itemId = unhex(input.item_id);
    const rev = BigInt(input.rev);
    if (equal(itemId, ZERO_ID)) fail('malformed_envelope');
    const { value, readOnly } = parseBody(segmentsToBytes(input.body));
    if (readOnly) fail('read_only_schema');
    const plain = encode(value);
    const keys = vkDerive(v.accountId, v.vaultId, v.vkEpoch, v.vk);
    let args;
    if (input.existing !== undefined) {
      const ex = splitEnvelope(unhex(input.existing), true);
      args = { ikWrapExisting: ex.ikWrap, bodyNonce: rng.draw(24) };
    } else {
      args = { ik: rng.draw(32), ikWrapNonce: rng.draw(24), bodyNonce: rng.draw(24) };
    }
    const r = sealEnvelope({ kind: KIND.item, vk: v.vk, vaultId: v.vaultId, itemId, vkEpoch: v.vkEpoch, rev, plain, ...args });
    const tag = itemTag(keys.kHead, itemId, rev, r.envelope).tag;
    const intermediate = { ik: hex(r.ik), ik_aad: hex(r.ikAad), body_aad: hex(r.bodyAad), padded_len: r.paddedLen };
    if (digest) return { expect: { envelope_len: r.envelope.length, envelope_sha256: hex(sha256(r.envelope)), tag: hex(tag) }, intermediate };
    return { expect: { envelope: hex(r.envelope), tag: hex(tag) }, intermediate };
  };
}
ops['item.seal'] = itemSeal(false);
ops['item.seal.digest'] = itemSeal(true);

ops['item.open'] = ({ input }) => {
  const v = vault(input);
  const itemId = unhex(input.item_id);
  const rev = BigInt(input.rev);
  const env = unhex(input.envelope);
  splitEnvelope(env, true); // structure first (malformed_envelope)
  if (equal(itemId, ZERO_ID)) fail('malformed_envelope');
  const keys = vkDerive(v.accountId, v.vaultId, v.vkEpoch, v.vk);
  verifyItemTag(keys.kHead, itemId, rev, env, unhex(input.tag));
  const plain = openEnvelope({ kind: KIND.item, vk: v.vk, vaultId: v.vaultId, itemId, vkEpoch: v.vkEpoch, rev, env });
  const { value, readOnly } = parseBody(plain);
  return { expect: { read_only: readOnly, body: hex(encode(value)) } };
};

ops['item.manifest.seal'] = ({ input, rng }) => {
  const v = vault(input);
  const rev = BigInt(input.rev);
  const m = parseManifest(unhex(input.manifest));
  if (m.epoch !== v.vkEpoch) fail('malformed_item_body'); // the manifest names the epoch it belongs to
  const keys = vkDerive(v.accountId, v.vaultId, v.vkEpoch, v.vk);
  const r = sealEnvelope({ kind: KIND.manifest, vk: v.vk, kKey: keys.kMeta, vaultId: v.vaultId, itemId: ZERO_ID, vkEpoch: v.vkEpoch, rev, plain: encode(m.value), bodyNonce: rng.draw(24) });
  return { expect: { envelope: hex(r.envelope), tag: hex(itemTag(keys.kHead, ZERO_ID, rev, r.envelope).tag) } };
};

ops['item.manifest.open'] = ({ input }) => {
  const v = vault(input);
  const rev = BigInt(input.rev);
  const env = unhex(input.envelope);
  splitEnvelope(env, false);
  const keys = vkDerive(v.accountId, v.vaultId, v.vkEpoch, v.vk);
  verifyItemTag(keys.kHead, ZERO_ID, rev, env, unhex(input.tag));
  const plain = openEnvelope({ kind: KIND.manifest, vk: v.vk, kKey: keys.kMeta, vaultId: v.vaultId, itemId: ZERO_ID, vkEpoch: v.vkEpoch, rev, env });
  const m = parseManifest(plain);
  // A manifest names its own epoch; one that disagrees with the key's epoch is not authentic.
  if (m.epoch !== v.vkEpoch) fail('decrypt');
  return { expect: { manifest: hex(encode(m.value)) } };
};

ops['tomb.seal'] = ({ input, rng }) => {
  const v = vault(input);
  const keys = vkDerive(v.accountId, v.vaultId, v.vkEpoch, v.vk);
  const r = tombSeal(keys.kDel, v.vaultId, unhex(input.item_id), BigInt(input.rev), rng.draw(24));
  return { expect: { tomb: hex(r.tomb) }, intermediate: { k_del: hex(keys.kDel), aad: hex(r.aad) } };
};

ops['tomb.verify'] = ({ input }) => {
  const v = vault(input);
  const keys = vkDerive(v.accountId, v.vaultId, v.vkEpoch, v.vk);
  tombVerify(keys.kDel, v.vaultId, unhex(input.item_id), BigInt(input.rev), unhex(input.tomb));
  return { expect: { ok: true } };
};

ops['item.tag'] = ({ input }) => {
  const v = vault(input);
  const keys = vkDerive(v.accountId, v.vaultId, v.vkEpoch, v.vk);
  const r = itemTag(keys.kHead, unhex(input.item_id), BigInt(input.rev), unhex(input.envelope));
  return { expect: { tag: hex(r.tag) }, intermediate: { message: hex(r.message) } };
};

ops['item.tag.verify'] = ({ input }) => {
  const v = vault(input);
  const keys = vkDerive(v.accountId, v.vaultId, v.vkEpoch, v.vk);
  verifyItemTag(keys.kHead, unhex(input.item_id), BigInt(input.rev), unhex(input.envelope), unhex(input.tag));
  return { expect: { ok: true } };
};
