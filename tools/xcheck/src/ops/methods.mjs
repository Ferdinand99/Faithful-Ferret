// methods.*, prf.salt_new, sync.memory (Fase 1 sections 4.3, 4.6 and 8.6, as written in vectors/OPS.md)
import { unhex, hex, fail, equal, concat, u32be, u64be, ascii } from '../util.mjs';
import { ed25519Sign } from '../crypto.mjs';
import { encode, C } from '../cbor.mjs';
import { parseManifest, normalizeManifest } from '../body.mjs';
import { vkDerive } from '../keys.mjs';
import { KIND, ZERO_ID, sealEnvelope, openEnvelope, splitEnvelope, itemTag, verifyItemTag } from '../items.mjs';
import { verifyCheckpoint } from '../checkpoint.mjs';
import { proofMessage } from './checkpoint.mjs';

export const ops = {};

const vault = (i) => ({ accountId: unhex(i.account_id), vaultId: unhex(i.vault_id), vkEpoch: BigInt(i.vk_epoch), vk: unhex(i.vk) });

ops['prf.salt_new'] = ({ rng }) => ({ expect: { salt: hex(rng.draw(32)) } });

// ---- the server's list against the manifest -------------------------------------------------

ops['methods.check_server'] = ({ input }) => {
  const manifest = input.manifest.methods.map((m) => ({ type: m.type, id: hex(unhex(m.id)), generation: BigInt(m.generation) }));
  const server = input.server.map((s) => ({ type: s.method_type, id: hex(unhex(s.method_id)), generation: BigInt(s.kek_generation) }));
  // 1. an id the manifest does not list, or one id twice
  const seen = new Set();
  for (const s of server) {
    if (seen.has(s.id) || !manifest.some((m) => m.id === s.id)) fail('method_list_unknown');
    seen.add(s.id);
  }
  // 2. the same id with another type or generation
  for (const s of server) {
    if (!manifest.some((m) => m.id === s.id && m.type === s.type && m.generation === s.generation)) fail('method_list_changed');
  }
  // 3. a method of the manifest that the server lacks
  if (manifest.some((m) => !server.some((s) => s.id === m.id))) fail('method_list_missing');
  return { expect: { ok: true } };
};

// ---- adding and removing a method ---------------------------------------------------------------

const MAX_METHODS = 64;
const MAX_GENERATION = 0xffffffffn;
const MAX_CREDENTIAL = 1024;

// Opens the manifest row the server holds.
function openCurrent(v, keys, current) {
  const rev = BigInt(current.rev);
  const env = unhex(current.envelope);
  splitEnvelope(env, false);
  verifyItemTag(keys.kHead, ZERO_ID, rev, env, unhex(current.tag));
  const plain = openEnvelope({ kind: KIND.manifest, vk: v.vk, kKey: keys.kMeta, vaultId: v.vaultId, itemId: ZERO_ID, vkEpoch: v.vkEpoch, rev, env });
  const m = parseManifest(plain);
  if (m.epoch !== v.vkEpoch) fail('malformed_entries');
  return { rev, value: m.value, methods: m.methods };
}

function nextManifest(v, keys, current, value, rng) {
  const rev = current.rev + 1n;
  const plain = encode(normalizeManifest(value));
  const r = sealEnvelope({ kind: KIND.manifest, vk: v.vk, kKey: keys.kMeta, vaultId: v.vaultId, itemId: ZERO_ID, vkEpoch: v.vkEpoch, rev, plain, bodyNonce: rng.draw(24) });
  const tag = itemTag(keys.kHead, ZERO_ID, rev, r.envelope).tag;
  return { plain, rev, envelope: r.envelope, tag };
}

const rowJson = (n) => `{"rev":${n.rev},"envelope":"${hex(n.envelope)}","tag":"${hex(n.tag)}"}`;

function result(n, body, input, v, keys, op) {
  const expect = {
    manifest: hex(n.plain),
    sealed: { rev: n.rev.toString(), envelope: hex(n.envelope), tag: hex(n.tag) },
    body: hex(body),
  };
  if (input.sign) {
    const msg = proofMessage('ferret/v1/mutation', op, v.accountId, unhex(input.sign.nonce), v.vkEpoch, body);
    expect.op = op;
    expect.pk_a = hex(keys.pkA);
    expect.proof = hex(ed25519Sign(msg, keys.skA));
  }
  return { expect };
}

const withMethods = (value, change) =>
  C.map(value.v.map(([k, x]) => (k === 'methods' ? [k, C.array(change(x.v))] : [k, x])));

ops['methods.add'] = ({ input, rng }) => {
  const v = vault(input);
  const keys = vkDerive(v.accountId, v.vaultId, v.vkEpoch, v.vk);
  const cur = openCurrent(v, keys, input.current);
  const w = input.wrap;
  // only a passkey wrap is added with this call
  if (w.method_type !== 3) fail('unsupported');
  const wrap = unhex(w.wrap);
  const credential = unhex(w.credential_id);
  const salt = unhex(w.prf_salt);
  const methodId = unhex(w.method_id);
  const generation = BigInt(w.kek_generation);
  if (wrap.length !== 72) fail('malformed_envelope');
  if (credential.length === 0) fail('input_too_short');
  if (credential.length > MAX_CREDENTIAL) fail('input_too_long');
  if (salt.every((b) => b === 0)) fail('input_all_zero');
  if (generation > MAX_GENERATION) fail('malformed_entries');
  if (
    cur.methods.length >= MAX_METHODS ||
    cur.methods.some((m) => equal(m.id, methodId) || (m.t === 3 && m.c && equal(m.c, credential)))
  ) {
    fail('malformed_entries');
  }
  const entry = C.map([['t', C.uint(3)], ['id', C.bytes(methodId)], ['g', C.uint(generation)], ['c', C.bytes(credential)]]);
  const value = withMethods(cur.value, (list) => [...list, entry]);
  const n = nextManifest(v, keys, cur, value, rng);
  const body = ascii(
    `{"method_type":3,"method_id":"${hex(methodId)}","wrap":"${hex(wrap)}","kek_generation":${generation},"credential_id":"${hex(credential)}","prf_salt":"${hex(salt)}","manifest":${rowJson(n)}}`,
  );
  return result(n, body, input, v, keys, 'unlock-method.add');
};

ops['methods.remove'] = ({ input, rng }) => {
  const v = vault(input);
  const keys = vkDerive(v.accountId, v.vaultId, v.vkEpoch, v.vk);
  const cur = openCurrent(v, keys, input.current);
  const methodId = unhex(input.method_id);
  const target = cur.methods.find((m) => equal(m.id, methodId));
  if (!target) fail('malformed_entries');
  // at least one password and one recovery method must stay
  if ((target.t === 1 || target.t === 2) && cur.methods.filter((m) => m.t === target.t).length <= 1) fail('input_last_method');
  const value = withMethods(cur.value, (list) => list.filter((m) => !equal(m.v.find(([k]) => k === 'id')[1].v, methodId)));
  const n = nextManifest(v, keys, cur, value, rng);
  const body = ascii(`{"method_id":"${hex(methodId)}","manifest":${rowJson(n)}}`);
  return result(n, body, input, v, keys, 'unlock-method.remove');
};

// ---- the rollback memory (section 8.6, "Lokalt minne") ----------------------------------------------

const MAX_TRACKED = 50000;
const cmp16 = (a, b) => {
  for (let i = 0; i < 16; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return 0;
};

// version (1) | max_seq (8) | checkpoint_seq (8) | count (4) | count x (item_id (16) | rev (8)), ascending by item_id
function decodeMemory(bytes) {
  const bad = () => fail('malformed_pinned_record');
  if (bytes.length < 21 || bytes[0] !== 1) bad();
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.length);
  const maxSeq = dv.getBigUint64(1, false);
  const checkpointSeq = dv.getBigUint64(9, false);
  const count = dv.getUint32(17, false);
  if (count > MAX_TRACKED || checkpointSeq > maxSeq || bytes.length !== 21 + count * 24) bad();
  const revs = [];
  for (let i = 0; i < count; i++) {
    const o = 21 + i * 24;
    const id = bytes.subarray(o, o + 16);
    if (revs.length && cmp16(revs[revs.length - 1].id, id) >= 0) bad();
    revs.push({ id: id.slice(), rev: dv.getBigUint64(o + 16, false) });
  }
  return { maxSeq, checkpointSeq, revs };
}

function encodeMemory(m) {
  const list = [...m.revs].sort((a, b) => cmp16(a.id, b.id));
  return concat(Uint8Array.of(1), u64be(m.maxSeq), u64be(m.checkpointSeq), u32be(list.length), ...list.map((r) => concat(r.id, u64be(r.rev))));
}

const emptyMemory = () => ({ maxSeq: 0n, checkpointSeq: 0n, revs: [] });
const revOf = (m, id) => m.revs.find((r) => equal(r.id, id))?.rev;

const rowOf = (r) => ({ itemId: unhex(r.item_id), rev: BigInt(r.rev), live: r.state === 'live', hash: r.hash ? unhex(r.hash) : new Uint8Array(32) });

function checkMemoryRows(m, rows, top) {
  if (top < m.maxSeq) fail('checkpoint_top_seq_below_remembered');
  for (const r of rows) {
    const known = revOf(m, r.itemId);
    if (known !== undefined && r.rev < known) fail('checkpoint_rev_below_remembered');
  }
}

// Returns the record after the rows (and the checkpoint seq) are taken in; the argument is not changed.
function recordRows(m, rows, top, checkpointSeq) {
  const next = { maxSeq: m.maxSeq, checkpointSeq: m.checkpointSeq, revs: m.revs.map((r) => ({ id: r.id, rev: r.rev })) };
  for (const r of rows) {
    const found = next.revs.find((x) => equal(x.id, r.itemId));
    if (found) found.rev = found.rev > r.rev ? found.rev : r.rev;
    else next.revs.push({ id: r.itemId, rev: r.rev });
  }
  if (next.revs.length > MAX_TRACKED) fail('too_large');
  if (top > next.maxSeq) next.maxSeq = top;
  if (checkpointSeq !== undefined && checkpointSeq > next.checkpointSeq) next.checkpointSeq = checkpointSeq;
  return next;
}

ops['sync.memory'] = ({ input }) => {
  let m = input.memory === null ? emptyMemory() : decodeMemory(unhex(input.memory));
  if (input.action !== 'decode') {
    const rows = input.rows.map(rowOf);
    const top = BigInt(input.top_seq);
    if (input.action === 'accept_rows') {
      checkMemoryRows(m, rows, top);
      m = recordRows(m, rows, top);
    } else {
      const v = vault(input);
      const keys = vkDerive(v.accountId, v.vaultId, v.vkEpoch, v.vk);
      const c = input.checkpoint;
      const cp = { seq: BigInt(c.seq), digest: unhex(c.digest), mac: unhex(c.mac), entries: unhex(c.entries) };
      // the checkpoint's own checks come first, with no memory
      verifyCheckpoint(keys.kHead, top, cp, rows);
      if (input.action === 'verify_checkpoint') {
        if (cp.seq < m.checkpointSeq) fail('checkpoint_seq_below_remembered');
        checkMemoryRows(m, rows, top);
        m = recordRows(m, rows, top, cp.seq);
      } else if (input.action === 'accept_older_state') {
        // the older, verified state replaces the record
        m = recordRows(emptyMemory(), rows, top, cp.seq);
      } else {
        fail('unsupported');
      }
    }
  }
  return {
    expect: { memory: hex(encodeMemory(m)), max_seq: m.maxSeq.toString(), checkpoint_seq: m.checkpointSeq.toString(), tracked: m.revs.length },
  };
};
