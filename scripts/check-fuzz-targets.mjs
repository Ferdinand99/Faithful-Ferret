#!/usr/bin/env node
// Checks that every function of the server library that reads bytes or text
// from a client, a file or a store has a fuzz target, or a stated reason why
// it has none.
//
//   node scripts/check-fuzz-targets.mjs             check
//   node scripts/check-fuzz-targets.mjs --list      print what the scan finds
//   node scripts/check-fuzz-targets.mjs --self-test check that the scan sees what it must
//
// The scan reads crates/ferret-server-auth/src (not the `testing` module and
// not the unit tests, which it cuts off at the `#[cfg(test)] mod` block) for
// every function, public or crate-private, `async` or not, with a parameter
// that carries bytes or text: `&[u8]`, `&[u8; N]`, `&str`, `&Path`,
// `&SealedState`, `Vec<u8>`, `Box<[u8]>`, `String`, or `impl AsRef<[u8]>`
// (`Option<&str>` and a tuple of slices count too). Each one must be in COVERED below, with the fuzz target that
// calls it (the target's source must name the function), or in EXEMPT, with
// the reason. A function that is in neither list fails the check, so a new
// parser cannot be added without a target; a name in a list that the scan no
// longer finds fails as well, so the lists do not rot.
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const src = join(root, 'crates', 'ferret-server-auth', 'src');
const targets = join(root, 'fuzz', 'fuzz_targets');
// The fixed server the targets share (see fuzz/common/server.rs) calls login_start and login_finish for them.
const common = join(root, 'fuzz', 'common', 'server.rs');

/**
 * module::function -> the fuzz target that calls it, or [target, symbol] when
 * the target calls it under another name (a wrapper of `testing`, or a path
 * that tells two functions of the same name apart).
 */
const COVERED = {
  'secret_file::decode_secret_file': 'fuzz_server_secret_file',
  'secret_file::encode_secret_file': 'fuzz_server_secret_file',
  'keys::ServerKeys::from_payload': ['fuzz_server_secret_file', 'ServerKeys::from_payload'],
  'keys::PreloginSecret::from_payload': ['fuzz_server_secret_file', 'PreloginSecret::from_payload'],
  'record::ValidatedRecord::parse': ['fuzz_server_messages', 'ValidatedRecord::parse'],
  'registration::register_start': 'fuzz_server_messages',
  'registration::register_finish': 'fuzz_server_messages',
  'login::login_start': ['fuzz_server_messages', 'login_start'],
  'login::login_finish': ['fuzz_server_messages', 'login_finish'],
  'state::open_state': ['fuzz_server_sealed_state', 'open_fields'],
  'state::StatePlain::parse': ['fuzz_server_sealed_state', 'parse_state_plain'],
  'ids::LoginId::parse': ['fuzz_server_wire_fields', 'LoginId::parse'],
  'scope::SessionScope::parse_stored': 'fuzz_server_wire_fields',
  'name::normalize_login_name': 'fuzz_server_login_name',
  'replace::authorize_replacement': 'fuzz_server_replace_body',
  'replace::authorize_signed': 'fuzz_server_wire_fields',
};

/** module::function -> why no target calls it on bytes of its own. */
const REACHED = 'a private step of a function that has a target; the target reaches it through that function';
const FILES =
  'reads or writes a file of the server; the bytes it reads go to decode_secret_file, which has a target, and the rules for the file itself (owner, mode, symlinks, size) are in tests/startup.rs';
const EXEMPT = {
  'login::parse_ke1': REACHED + ' (login_start)',
  'login::parse_ke3': REACHED + ' (login_finish)',
  'login::start_with': REACHED + ' (login_start)',
  'login::start_admitted': REACHED + ' (login_start)',
  'login::refuse_without_id': REACHED + ' (login_finish)',
  'registration::start_admitted': REACHED + ' (register_start)',
  'registration::start_for_identifier': REACHED + ' (register_start)',
  'replace::authorize_admitted': REACHED + ' (authorize_replacement)',
  'replace::consume_and_verify': REACHED + ' (authorize_replacement and authorize_signed)',
  'name::round': REACHED + ' (normalize_login_name)',
  'state::take': REACHED + ' (StatePlain::parse)',
  'keys::array32': REACHED + ' (PreloginSecret::from_payload)',
  'keys::load_or_create': FILES,
  'keys::load_one': FILES,
  'keys::read_settled': FILES,
  'secret_file::read_secret_file': FILES,
  'secret_file::write_new_secret_file': FILES,
  'secret_file::create_and_fill': FILES,
  'secret_file::effective_uid': FILES,
  'secret_file::probe_uid': FILES,
  'secret_file::sync_directory': FILES,
  'prelogin::hmac_with_name': 'private; the secret and the label belong to the server and the name is already normalized, so it is reached through fake_credential_id and fake_prelogin, whose only client input is a name from normalize_login_name',
  'prelogin::permille': REACHED + ' (fake_prelogin); the eight bytes are an HMAC output',
  'prelogin::pick_account': 'private; chooses between two references the caller already holds (an account id from the lookup, or a fixed zero id), and reads nothing from a request',
  'prelogin::step': 'a trace label that tests record to check the order of effects; no client input',
  'replace::ChallengeKey::new': REACHED + ' (authorize_replacement and authorize_signed); it hashes the session and the nonce, whose lengths are checked before',
  'state::SealedState::from_bytes': 'wraps stored bytes without reading them; the length and the content are checked in open_state, which has a target',
  'record::ProfileRules::for_tests': 'a constructor behind test-support that takes the numbers a test chooses; no client input',
};

// ------------------------------------------------------------------ scan

function files(dir) {
  const out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name !== 'testing') out.push(...files(path));
    } else if (entry.name.endsWith('.rs') && entry.name !== 'testing.rs') {
      out.push(path);
    }
  }
  return out.sort();
}

/**
 * The text of the file before its unit tests: it ends at the `#[cfg(test)]`
 * that is followed by a `mod` block. A `#[cfg(test)]` on anything else (a
 * helper, a `thread_local!`) does not end it, so the functions below such an
 * item are still scanned.
 */
function production(text) {
  const at = text.search(/^#\[cfg\(test\)\]\s*\n\s*(?:pub(?:\([a-z]+\))?\s+)?mod\s+\w+/m);
  return at < 0 ? text : text.slice(0, at);
}

/** The text between the parenthesis that opens at `open` and its match. */
function balanced(text, open) {
  let depth = 0;
  for (let i = open; i < text.length; i++) {
    if (text[i] === '(') depth++;
    else if (text[i] === ')' && --depth === 0) return text.slice(open + 1, i);
  }
  return '';
}

const TAKES_BYTES = new RegExp(
  [
    // A borrowed slice, array, string, path or sealed state.
    String.raw`&\s*(?:'\w+\s+)?(?:mut\s+)?(?:\[u8(?:\s*;[^\]]*)?\]|str\b|Path\b|SealedState\b)`,
    // Owned bytes and text.
    String.raw`\bVec<\s*u8\s*>`,
    String.raw`\bBox<\s*\[u8\]\s*>`,
    String.raw`\bString\b`,
    // Generic inputs.
    String.raw`\bAsRef<\s*(?:\[u8\]|str|Path)\s*>`,
    String.raw`\bInto<\s*(?:Vec<\s*u8\s*>|String)\s*>`,
  ].join('|'),
);

/** The impl type in force at `index`: the last `impl [Trait for] Type {` before it. */
function implAt(text, index) {
  let found = '';
  for (const m of text.slice(0, index).matchAll(/^impl(?:<[^>]*>)?\s+(?:[\w:<>', ]+\s+for\s+)?(\w+)/gm)) found = m[1];
  return found;
}

/** The request structs that carry bytes or text from a client. */
function requestStructsIn(text) {
  const names = [];
  for (const m of text.matchAll(/^pub struct (\w+)<'a>\s*\{([^}]*)\}/gm)) {
    if (TAKES_BYTES.test(m[2])) names.push(m[1]);
  }
  return names;
}

/** Adds the functions of one file's text that take bytes or text to `found`. */
function scanText(module, text, structs, found) {
  const fn = /^(\s*)(pub(?:\([a-z]+\))?\s+)?(?:(?:const|async|unsafe)\s+)*fn\s+(\w+)\s*(?:<[^(]*>)?\s*\(/gm;
  for (const m of text.matchAll(fn)) {
    const open = m.index + m[0].length - 1;
    // The generics count too: `fn a<T: AsRef<str>>(b: T)` takes text.
    const params = m[0].slice(m[0].indexOf('fn')) + balanced(text, open);
    if (!TAKES_BYTES.test(params) && !structs.some((name) => new RegExp(String.raw`\b${name}\b`).test(params))) continue;
    // A method sits in an `impl` block (indented); a free function does not.
    const owner = m[1].length > 0 ? implAt(text, m.index) : '';
    found.set(`${module}::${owner ? `${owner}::` : ''}${m[3]}`, { module, name: m[3], public: Boolean(m[2]) });
  }
}

function scan() {
  const found = new Map();
  const sources = files(src).map((file) => ({
    module: relative(src, file).replace(/\.rs$/, '').replaceAll('\\', '/').replaceAll('/', '::'),
    text: production(readFileSync(file, 'utf8')),
  }));
  const structs = sources.flatMap(({ text }) => requestStructsIn(text));
  for (const { module, text } of sources) scanText(module, text, structs, found);
  return found;
}

// ------------------------------------------------------------- self-test

/**
 * The scan must see a new function that takes bytes or text, whatever its
 * type or place in the file, and nothing else. Each case is a fixture file.
 */
function selfTest() {
  const cases = [
    ['plain slice', 'pub fn parse(bytes: &[u8]) -> u8 { 0 }', ['t::parse']],
    ['below a cfg(test) helper', '#[cfg(test)]\nthread_local! { static X: u8 = 0; }\n\npub fn parse_hint(bytes: &[u8]) {}\n\n#[cfg(test)]\nmod tests {\n    fn t(x: &[u8]) {}\n}\n', ['t::parse_hint']],
    ['below a cfg(test) fn', '#[cfg(test)]\nfn recorder() {}\n\nfn later(text: &str) {}\n', ['t::later']],
    ['in the test module only', 'fn plain(x: u32) {}\n\n#[cfg(test)]\nmod tests {\n    fn t(x: &[u8]) {}\n}\n', []],
    ['owned bytes', 'pub fn a(blob: Vec<u8>) {}', ['t::a']],
    ['owned text', 'pub fn a(body: String) {}', ['t::a']],
    ['fixed array', 'pub fn a(id: &[u8; 16]) {}', ['t::a']],
    ['mutable slice', 'pub fn a(out: &mut [u8]) {}', ['t::a']],
    ['boxed slice', 'pub fn a(b: Box<[u8]>) {}', ['t::a']],
    ['generic bytes', 'pub fn a(b: impl AsRef<[u8]>) {}', ['t::a']],
    ['generic text', 'pub fn a<T: AsRef<str>>(b: T) {}', ['t::a']],
    ['async', 'pub async fn a(b: &[u8]) {}', ['t::a']],
    ['async crate-private', '    pub(crate) async fn a(b: &str) {}', ['t::a']],
    ['method', 'impl Thing {\n    pub fn parse(b: &[u8]) {}\n}\n', ['t::Thing::parse']],
    ['numbers only', 'pub fn a(n: u64, flag: bool, id: &Id) {}', []],
  ];
  let failed = 0;
  for (const [name, source, want] of cases) {
    const found = new Map();
    scanText('t', production(source), [], found);
    const got = [...found.keys()].sort();
    if (JSON.stringify(got) !== JSON.stringify(want)) {
      console.error(`check-fuzz-targets self-test: ${name}: found [${got}], expected [${want}]`);
      failed++;
    }
  }
  if (failed) process.exit(1);
  console.log(`check-fuzz-targets self-test: ${cases.length} cases ok`);
}

// ----------------------------------------------------------------- check

/** Rust source without its line comments. */
const code = (text) => text.replace(/\/\/.*$/gm, '');

if (process.argv.includes('--self-test')) {
  selfTest();
  process.exit(0);
}

const found = scan();
if (process.argv.includes('--list')) {
  for (const key of [...found.keys()].sort()) console.log(key);
  process.exit(0);
}

const problems = [];
for (const key of [...found.keys()].sort()) {
  if (COVERED[key] === undefined && EXEMPT[key] === undefined) {
    problems.push(`${key} takes bytes or text and has neither a fuzz target nor a reason (see scripts/check-fuzz-targets.mjs)`);
  }
}
for (const [key, entry] of Object.entries(COVERED)) {
  const [target, symbol] = Array.isArray(entry) ? entry : [entry, key.split('::').at(-1)];
  if (!found.has(key)) {
    problems.push(`${key} is listed as covered but the scan does not find it`);
    continue;
  }
  const path = join(targets, `${target}.rs`);
  if (!existsSync(path)) {
    problems.push(`${key}: the target ${target} does not exist`);
    continue;
  }
  const escaped = symbol.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  // Comments do not count, and the shared server counts only for a target that uses it.
  const own = code(readFileSync(path, 'utf8'));
  const text = /\bmod server\b/.test(own) ? own + code(readFileSync(common, 'utf8')) : own;
  if (!new RegExp(`\\b${escaped}\\b`).test(text)) {
    problems.push(`${key}: the target ${target} does not call ${symbol}`);
  }
}
for (const [key, why] of Object.entries(EXEMPT)) {
  if (!found.has(key)) problems.push(`${key} is exempt but the scan does not find it`);
  if (!why || why.length < 20) problems.push(`${key}: the reason is missing`);
}
if (problems.length) {
  for (const p of problems) console.error(`check-fuzz-targets: ${p}`);
  process.exit(1);
}
console.log(`check-fuzz-targets: ${found.size} functions that take bytes or text are covered or exempt`);
