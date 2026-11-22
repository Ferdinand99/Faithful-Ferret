// generator.* : the password and passphrase generator, from the rules in vectors/OPS.md.
// The words are derived here from EFF's original file (dice digits, a tab, the word), a copy of
// https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt in data/ that is checked by its
// SHA-256, as published by EFF (CC BY 3.0 US).
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { fail } from '../util.mjs';

export const ops = {};

const EFF_SHA256 = 'addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e';
const original = fs.readFileSync(path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../data/eff_large_wordlist.txt'));
if (createHash('sha256').update(original).digest('hex') !== EFF_SHA256) {
  throw new Error('data/eff_large_wordlist.txt is not the EFF large word list');
}
const WORDS = original
  .toString('utf8')
  .split('\n')
  .filter((line) => line !== '')
  .map((line) => line.split('\t')[1]);

const CLASSES = ['abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', '0123456789', '!#$%&*+-.:=?@^_~'];
const AMBIGUOUS = 'Il1|O0o';
const SEPARATORS = ['-', '.', '_', ' '];

// Uniform in 0..n: a little-endian u32 per draw, refused at or above n * floor(2^32 / n).
function uniformIndex(rng, n) {
  if (n === 0) fail('generator_options');
  const limit = BigInt(n) * ((1n << 32n) / BigInt(n));
  for (;;) {
    const b = rng.draw(4);
    const x = BigInt(b[0] | (b[1] << 8) | (b[2] << 16)) + (BigInt(b[3]) << 24n);
    if (x < limit) return Number(x % BigInt(n));
  }
}

// log2 by squaring, as OPS.md describes it: the same doubles as the core's.
function log2(n) {
  let intPart = 31 - Math.clz32(n);
  let m = n;
  for (let i = 0; i < intPart; i++) m *= 0.5;
  let fraction = 0;
  let bit = 0.5;
  for (let i = 0; i < 52; i++) {
    m *= m;
    if (m >= 2) {
      m *= 0.5;
      fraction += bit;
    }
    bit *= 0.5;
  }
  return intPart + fraction;
}

function done(rng, value, bits) {
  if (rng.left !== 0) throw new Error(`${rng.left} draws left over`);
  return { expect: { value, bits } };
}

ops['generator.uniform_index'] = ({ input, rng }) => {
  const index = uniformIndex(rng, input.n);
  if (rng.left !== 0) throw new Error(`${rng.left} draws left over`);
  return { expect: { index } };
};

ops['generator.password'] = ({ input: o, rng }) => {
  const classes = [o.lower, o.upper, o.digits, o.symbols]
    .map((on, i) => (on ? [...CLASSES[i]].filter((c) => !(o.avoid_ambiguous && AMBIGUOUS.includes(c))).join('') : null))
    .filter((c) => c !== null);
  if (o.length < 4 || o.length > 128 || o.min_each > 8 || classes.length === 0 || o.min_each * classes.length > o.length) {
    fail('generator_options');
  }
  const alphabet = classes.join('');
  const chars = [];
  for (const c of classes) for (let k = 0; k < o.min_each; k++) chars.push(c[uniformIndex(rng, c.length)]);
  while (chars.length < o.length) chars.push(alphabet[uniformIndex(rng, alphabet.length)]);
  for (let i = chars.length - 1; i >= 1; i--) {
    const j = uniformIndex(rng, i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return done(rng, chars.join(''), o.length * log2(alphabet.length));
};

ops['generator.passphrase'] = ({ input: o, rng }) => {
  if (o.words < 3 || o.words > 20 || !SEPARATORS.includes(o.separator)) fail('generator_options');
  const words = [];
  for (let k = 0; k < o.words; k++) {
    const w = WORDS[uniformIndex(rng, WORDS.length)];
    words.push(o.capitalize ? w[0].toUpperCase() + w.slice(1) : w);
  }
  let bits = o.words * log2(WORDS.length);
  if (o.number) {
    const digit = uniformIndex(rng, 10);
    const at = uniformIndex(rng, o.words);
    words[at] += String(digit);
    bits += log2(10) + log2(o.words);
  }
  return done(rng, words.join(o.separator), bits);
};
