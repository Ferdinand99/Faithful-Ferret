#!/usr/bin/env node
// Checks that every function of the server library that reads bytes or text
// from a client, a file or a store has a fuzz target, or a stated reason why
// it has none.
//
//   node scripts/check-fuzz-targets.mjs           check
//   node scripts/check-fuzz-targets.mjs --list    print what the scan finds
//
// The scan reads crates/ferret-server-auth/src (not the `testing` module and
// not the unit tests) for every function, public or crate-private, with a
// parameter of type `&[u8]` or `&str` (`Option<&str>` and a tuple of slices
// count too). Each one must be in COVERED below, with the fuzz target that
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

/** The text of the file before its unit tests (`#[cfg(test)] mod tests`). */
function production(text) {
  const at = text.search(/^#\[cfg\(test\)\]/m);
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

const TAKES_BYTES = /&\s*(?:'\w+\s+)?(?:\[u8\]|str\b|Path\b|SealedState\b)/;

/** The impl type in force at `index`: the last `impl [Trait for] Type {` before it. */
function implAt(text, index) {
  let found = '';
  for (const m of text.slice(0, index).matchAll(/^impl(?:<[^>]*>)?\s+(?:[\w:<>', ]+\s+for\s+)?(\w+)/gm)) found = m[1];
  return found;
}

/** The request structs that carry bytes or text from a client. */
function requestStructs() {
  const names = new Set();
  for (const file of files(src)) {
    const text = production(readFileSync(file, 'utf8'));
    for (const m of text.matchAll(/^pub struct (\w+)<'a>\s*\{([^}]*)\}/gm)) {
      if (TAKES_BYTES.test(m[2])) names.add(m[1]);
    }
  }
  return names;
}

function scan() {
  const found = new Map();
  const structs = [...requestStructs()];
  for (const file of files(src)) {
    const module = relative(src, file).replace(/\.rs$/, '').replaceAll('\\', '/').replaceAll('/', '::');
    const text = production(readFileSync(file, 'utf8'));
    for (const m of text.matchAll(/^(\s*)(pub(?:\([a-z]+\))?\s+)?(?:const\s+)?fn\s+(\w+)\s*(?:<[^(]*>)?\s*\(/gm)) {
      const open = m.index + m[0].length - 1;
      const params = balanced(text, open);
      if (!TAKES_BYTES.test(params) && !structs.some((name) => new RegExp(`\\b${name}\\b`).test(params))) continue;
      // A method sits in an `impl` block (indented); a free function does not.
      const owner = m[1].length > 0 ? implAt(text, m.index) : '';
      found.set(`${module}::${owner ? `${owner}::` : ''}${m[3]}`, { module, name: m[3], public: Boolean(m[2]) });
    }
  }
  return found;
}

// ----------------------------------------------------------------- check

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
  if (!new RegExp(`\\b${escaped}\\b`).test(readFileSync(path, 'utf8') + readFileSync(common, 'utf8'))) {
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
