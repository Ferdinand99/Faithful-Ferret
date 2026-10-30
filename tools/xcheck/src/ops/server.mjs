// server.*: the secret files, the fingerprint of the set-up, the made-up pre-login answers, the key of a
// challenge nonce and the sealed login state of the server library.
//
// Written from the section "Server operations" of vectors/OPS.md and the rows of its table (and Fase 1
// section 4.2 for the made-up credential id). The OPAQUE messages (server.register_response, server.login_start,
// server.login_finish) and the signed replacement (server.replace_authorize) are not here: see NOT_COVERED.
import nodeCrypto from 'node:crypto';
import { unhex, hex, fail, concat, u8, ascii, utf8, equal } from '../util.mjs';
import { sha256, hmac256, hkdf, aeadSeal, aeadOpen } from '../crypto.mjs';
import { tlv, label, T } from '../tlv.mjs';

export const ops = {};

const bytesOf = (s, n, what) => {
  const b = unhex(s);
  if (b.length !== n) throw new Error(`${what}: expected ${n} bytes, the vector has ${b.length}`);
  return b;
};

// ------------------------------------------------------------------- secret files

const FILE_KIND = { opaque_setup: { code: 1, payload: 128 }, prelogin_secret: { code: 2, payload: 32 } };
const kindOf = (name) => {
  if (!Object.hasOwn(FILE_KIND, name)) throw new Error(`unknown file kind ${name}`);
  return FILE_KIND[name];
};
const MAGIC = ascii('FSEC');
const HEADER = 9;

function encodeFile(kind, payload) {
  if (payload.length !== kind.payload) fail('bad_length');
  const body = concat(MAGIC, u8(1), u8(kind.code), u8(1), Uint8Array.of(payload.length >> 8, payload.length & 0xff), payload);
  return concat(body, sha256(body));
}

function decodeFile(kind, file) {
  // Only the part of the magic that is there is compared.
  const seen = Math.min(file.length, MAGIC.length);
  for (let i = 0; i < seen; i++) if (file[i] !== MAGIC[i]) fail('bad_magic');
  if (file.length < HEADER) fail('bad_length');
  if (file[4] !== 1) fail('unsupported_version');
  if (file[5] !== kind.code) fail('wrong_kind');
  if (file[6] !== 1) fail('unsupported_suite');
  const declared = (file[7] << 8) | file[8];
  if (declared !== kind.payload) fail('bad_length');
  const end = HEADER + declared;
  if (file.length < end + 32) fail('bad_length');
  if (file.length > end + 32) fail('trailing_bytes');
  if (!equal(sha256(file.subarray(0, end)), file.subarray(end))) fail('bad_checksum');
  return file.subarray(HEADER, end);
}

ops['server.secret_file.encode'] = ({ input }) => ({ expect: { file: hex(encodeFile(kindOf(input.kind), unhex(input.payload))) } });
ops['server.secret_file.decode'] = ({ input }) => ({ expect: { payload: hex(decodeFile(kindOf(input.kind), unhex(input.file))) } });

// ---------------------------------------------------------------- the set-up

ops['server.setup_fingerprint'] = ({ input }) => ({
  expect: { fingerprint: hex(sha256(ascii('ferret/v1/setup-fp'), bytesOf(input.setup_hex, 128, 'setup_hex'))) },
});

// ------------------------------------------------------------------ login names

const INVISIBLE = /[\u00ad\u061c\u180e\u200b-\u200f\u2028-\u202e\u2060-\u2064\u2066-\u206f\ufeff\ufff9-\ufffb]/u;
const MAX_ROUNDS = 4;
// OPS.md: trimmed of Unicode White_Space (not String.prototype.trim, which differs on U+0085 and U+FEFF).
const WHITE_SPACE_ENDS = /^\p{White_Space}+|\p{White_Space}+$/gu;

function normalizeName(raw) {
  const round = (t) => t.normalize('NFKC').toLowerCase().normalize('NFKC').replace(WHITE_SPACE_ENDS, '');
  let text = raw;
  let stable = false;
  for (let i = 0; i < MAX_ROUNDS; i++) {
    const next = round(text);
    if (next === text) {
      stable = true;
      break;
    }
    text = next;
  }
  if (!stable) fail('malformed_login_name');
  if (text === '' || /\p{Cc}/u.test(text) || INVISIBLE.test(text) || utf8(text).length > 254) fail('malformed_login_name');
  return text;
}

// ------------------------------------------------------- made-up pre-login answers

const prelogin = (input) => bytesOf(input.prelogin_secret, 32, 'prelogin_secret');

// Fase 1 section 4.2: HMAC-SHA256(server_secret_prelogin, "prelogin-id" || lower(email))[..16].
function fakeId(secret, name) {
  return hmac256(secret, ascii('prelogin-id'), utf8(name)).subarray(0, 16);
}

ops['server.fake_credential_id'] = ({ input }) => ({ expect: { credential_id: hex(fakeId(prelogin(input), normalizeName(input.name))) } });

function checkPolicy(policy) {
  const profiles = policy.profiles;
  const total = profiles.reduce((n, p) => n + p[1], 0);
  const distinct = new Set(profiles.map((p) => p[0])).size === profiles.length;
  if (total !== 1000 || !distinct || profiles.some((p) => p[0] === 0) || policy.sk_true_permille > 1000) fail('internal');
}

ops['server.fake_prelogin'] = ({ input }) => {
  checkPolicy(input.policy);
  const secret = prelogin(input);
  const d = hmac256(secret, ascii('prelogin-hint'), utf8(normalizeName(input.name)));
  const view = new DataView(d.buffer, d.byteOffset, d.byteLength);
  const a = view.getBigUint64(0, false) % 1000n;
  const b = view.getBigUint64(8, false) % 1000n;
  let sum = 0n;
  let profile = input.policy.profiles[input.policy.profiles.length - 1][0];
  for (const [number, share] of input.policy.profiles) {
    sum += BigInt(share);
    if (a < sum) {
      profile = number;
      break;
    }
  }
  return { expect: { ksf_profile: profile, sk_hint: b < BigInt(input.policy.sk_true_permille) } };
};

ops['server.fake_record'] = ({ input }) => {
  const setup = bytesOf(input.setup_hex, 128, 'setup_hex');
  const id = bytesOf(input.credential_id, 16, 'credential_id');
  // HKDF-SHA512 without a salt: 64 zero bytes (RFC 5869).
  const body = new Uint8Array(
    nodeCrypto.hkdfSync('sha512', prelogin(input), new Uint8Array(64), concat(ascii('ferret/v1/prelogin/record'), id), 160),
  );
  return { expect: { record: hex(concat(setup.subarray(96, 128), body)) } };
};

// -------------------------------------------------------------------- challenges

ops['server.challenge_key'] = ({ input }) => ({
  expect: { key: hex(sha256(bytesOf(input.session, 32, 'session'), bytesOf(input.nonce, 32, 'nonce'))) },
});

// ---------------------------------------------------------------- the login state

const BLOB_LEN = 244;
const PLAIN_LEN = 203;

function loginIdBytes(text) {
  if (!/^[0-9a-f]{32}$/.test(text)) fail('malformed_login_id');
  return unhex(text);
}

function stateAad(id) {
  return concat(label('ferret/v1/server/login-state'), tlv(T.version, u8(1)), tlv(T.suite, u8(1)), tlv(T.nonce, id));
}

// The purpose as the plaintext holds it: [code, flag, binding(48)].
function purposeBytes(purpose) {
  if (purpose.type === 'login') return concat(u8(0), u8(0), new Uint8Array(48));
  if (purpose.type === 'reauth') return concat(u8(1), u8(1), bytesOf(purpose.session, 32, 'session'), bytesOf(purpose.account, 16, 'account'));
  throw new Error(`unknown purpose ${purpose.type}`);
}

function u64(v) {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(v), false);
  return b;
}

function plaintext(state) {
  return concat(
    u64(state.expires_at),
    purposeBytes(state.purpose),
    bytesOf(state.credential, 16, 'credential'),
    u8(state.ksf_profile),
    bytesOf(state.server_login, 128, 'server_login'),
  );
}

ops['server.state_seal'] = ({ input, rng }) => {
  const id = loginIdBytes(input.login_id);
  const key = hkdf(null, prelogin(input), ascii('ferret/v1/state-seal'), 32);
  // A state that is dead when it is made is not sealed.
  if (BigInt(input.now) >= BigInt(input.state.expires_at)) fail('internal');
  const nonce = rng.draw(24);
  const blob = concat(u8(1), aeadSeal(key, nonce, plaintext(input.state), stateAad(id)));
  if (blob.length !== BLOB_LEN) throw new Error(`blob of ${blob.length} bytes`);
  return { expect: { blob: hex(blob) } };
};

ops['server.state_open'] = ({ input }) => {
  const id = loginIdBytes(input.login_id);
  const key = hkdf(null, prelogin(input), ascii('ferret/v1/state-seal'), 32);
  const blob = unhex(input.blob);
  if (blob.length !== BLOB_LEN || blob[0] !== 1) fail('denied');
  let plain;
  try {
    plain = aeadOpen(key, blob.subarray(1), stateAad(id));
  } catch {
    fail('denied');
  }
  if (plain.length !== PLAIN_LEN) fail('denied');
  const view = new DataView(plain.buffer, plain.byteOffset, plain.byteLength);
  const expiresAt = view.getBigUint64(0, false);
  const code = plain[8];
  const flag = plain[9];
  const binding = plain.subarray(10, 58);
  const login = code === 0 && flag === 0 && binding.every((x) => x === 0);
  const reauth = code === 1 && flag === 1;
  if (!login && !reauth) fail('denied');
  // The purpose and the session must be the ones the request expects.
  if (!equal(concat(plain.subarray(8, 10), binding), purposeBytes(input.expected))) fail('denied');
  if (BigInt(input.now) >= expiresAt) fail('denied');
  const purpose = login
    ? { type: 'login' }
    : { type: 'reauth', session: hex(binding.subarray(0, 32)), account: hex(binding.subarray(32, 48)) };
  return {
    expect: {
      state: {
        expires_at: expiresAt.toString(),
        purpose,
        credential: hex(plain.subarray(58, 74)),
        ksf_profile: plain[74],
        server_login: hex(plain.subarray(75, 203)),
      },
    },
  };
};
