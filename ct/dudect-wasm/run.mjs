// dudect on the WebAssembly build of the timing targets, timed in Node.
//
//   node ct/dudect-wasm/run.mjs target/wasm32-unknown-unknown/release/ferret_ct.wasm
//
// The module (ct/dudect, built for wasm32) exports the same targets as the
// native bench: for every measurement the class and the input are chosen at
// random, the input is copied into the target's working cell (`ct_prepare`,
// not timed), and `ct_run` is timed with `process.hrtime.bigint()`. The
// statistic is the one of dudect: Welch's t-test on all measurements and on
// the measurements below 100 cropped percentiles, and the largest |t| counts.
// Plan section 10 point 5: |t| < 4.5 after 10^6 measurements. Browser timing
// is not used (`performance.now` is too coarse there).
//
// Controls, as in the native run: `control_null` (the same inputs in both
// classes) must stay below the threshold and `control_leaky*` (early-exit
// comparisons) must be far above it, or the run is not valid. Targets whose
// name starts with `info_` are reported and not gated. A gated target with
// |t| >= 4.5 is measured once more with ten times the measurements and fails
// if that is still >= 4.5 (exit 1; exit 4 if it is also >= CT_GROSS, which the
// smoke run on a hosted runner treats as a failure, and a lesser one as a
// warning).
//
// Environment: FERRET_CT_N (measurements, default 1000000), CT_CPU and CT_HOST
// (for the log), CT_GROSS (default 100), CT_WASM_SMALL_REPS (repetitions inside one
// measurement for the targets that are repeated once natively; default 8), CT_ONLY (only targets whose name
// contains this), CT_REPEAT (measure each selected target this often, to see
// the spread of t).

import { readFileSync } from "node:fs";

const THRESHOLD = 4.5;
const N = Number(process.env.FERRET_CT_N ?? 1_000_000);
const SMALL_REPS = Number(process.env.CT_WASM_SMALL_REPS ?? 8);
const GROSS = Number(process.env.CT_GROSS ?? 100);
const ONLY = process.env.CT_ONLY ?? "";
const REPEAT = Number(process.env.CT_REPEAT ?? 1);
const WARMUP = 200_000;
const PERCENTILES = 100;

const wasmPath = process.argv[2];
if (!wasmPath) {
  console.error("usage: run.mjs <ferret_ct.wasm>");
  process.exit(2);
}

// ------------------------------------------------------------ the module

const module = new WebAssembly.Module(readFileSync(wasmPath));
const imports = {};
const importList = WebAssembly.Module.imports(module);
for (const imp of importList) {
  imports[imp.module] ??= {};
  imports[imp.module][imp.name] = () => {
    throw new Error(`unexpected call of import ${imp.module}.${imp.name}`);
  };
}
const instance = new WebAssembly.Instance(module, imports);
const ex = instance.exports;
const memory = ex.memory;

const targetCount = ex.ct_setup(0x1234_5678, 0x9abc_def0);
const targets = [];
for (let t = 0; t < targetCount; t++) {
  const name = new TextDecoder().decode(new Uint8Array(memory.buffer, ex.ct_name_ptr(t), ex.ct_name_len(t)));
  // An operation of a few hundred nanoseconds is repeated inside one measurement,
  // so that the call and the timer are a smaller part of what is timed.
  const reps = ex.ct_reps(t);
  targets.push({ t, name, info: ex.ct_info(t) === 1, reps: reps === 1 ? SMALL_REPS : reps });
}

// ------------------------------------------------------------- statistics

/** Welch's t of two sets given as running sums. */
function welch(a, b) {
  if (a.n < 2 || b.n < 2) return 0;
  const va = (a.sq - (a.sum * a.sum) / a.n) / (a.n - 1);
  const vb = (b.sq - (b.sum * b.sum) / b.n) / (b.n - 1);
  const se = Math.sqrt(va / a.n + vb / b.n);
  return se === 0 ? 0 : (a.sum / a.n - b.sum / b.n) / se;
}

function summarize(times, classes, limit) {
  const a = { n: 0, sum: 0, sq: 0 };
  const b = { n: 0, sum: 0, sq: 0 };
  for (let i = 0; i < times.length; i++) {
    const x = times[i];
    if (x > limit) continue;
    const s = classes[i] === 0 ? a : b;
    s.n++;
    s.sum += x;
    s.sq += x * x;
  }
  return { a, b };
}

/** The largest |t| over the raw data and the 100 cropped sets, with its n. */
function maxT(times, classes) {
  const sorted = Float64Array.from(times).sort();
  let best = { t: 0, n: 0 };
  const consider = (limit) => {
    const { a, b } = summarize(times, classes, limit);
    const t = welch(a, b);
    if (Math.abs(t) > Math.abs(best.t)) best = { t, n: a.n + b.n };
  };
  consider(Infinity);
  for (let k = 0; k < PERCENTILES; k++) {
    const p = 1 - Math.pow(0.5, (10 * (k + 1)) / PERCENTILES);
    consider(sorted[Math.min(sorted.length - 1, Math.floor(p * sorted.length))]);
  }
  return best;
}

// -------------------------------------------------------------- measuring

/** A small xorshift generator: the class and input of each measurement. */
function plan(seed, count) {
  let x = seed >>> 0 || 1;
  const next = () => {
    x ^= x << 13;
    x >>>= 0;
    x ^= x >>> 17;
    x ^= x << 5;
    x >>>= 0;
    return x;
  };
  const classes = new Uint8Array(count);
  const inputs = new Uint32Array(count);
  for (let i = 0; i < count; i++) {
    classes[i] = next() & 1;
    inputs[i] = next();
  }
  return { classes, inputs };
}

function measure(target, seed, count) {
  const { t, reps } = target;
  const { classes, inputs } = plan(seed, count);
  // Warm up, so that the engine has compiled the module's hot code with its
  // optimizing compiler before the first measurement.
  for (let i = 0; i < WARMUP; i++) {
    ex.ct_prepare(t, classes[i % count], inputs[i % count]);
    ex.ct_run(t, reps);
  }
  const times = new Float64Array(count);
  let sink = 0;
  for (let i = 0; i < count; i++) {
    ex.ct_prepare(t, classes[i], inputs[i]);
    const t0 = process.hrtime.bigint();
    sink ^= ex.ct_run(t, reps);
    const t1 = process.hrtime.bigint();
    times[i] = Number(t1 - t0);
  }
  if (sink === 0.5) console.log(sink); // keeps `sink` alive
  return maxT(times, classes);
}

const over = (t, limit = THRESHOLD) => Math.abs(t) >= limit;
const fmt = (name, r, label) =>
  `[${label}] bench ${name.padEnd(32)} ... : n == ${(r.n / 1e6).toFixed(3)}M, max t = ${r.t >= 0 ? "+" : ""}${r.t.toFixed(5)}`;

const info = {
  node: process.version,
  v8: process.versions.v8,
  measurements: N,
  cpu: process.env.CT_CPU ?? "unknown",
  host: process.env.CT_HOST ?? "unknown",
  imports: importList.map((i) => `${i.module}.${i.name}`),
};
console.log(`dudect wasm in Node: ${JSON.stringify(info)}, ${new Date().toISOString()}`);
console.log(`module: ${wasmPath}, ${readFileSync(wasmPath).length} bytes, targets: ${targets.map((x) => x.name).join(" ")}`);

let failed = false;
let invalid = false;
let gross = false;
const order = [
  ...targets.filter((x) => x.name === "control_null"),
  ...targets.filter((x) => /control_.*leaky/.test(x.name)),
  ...targets.filter((x) => !x.name.startsWith("control_")),
].filter((x) => !ONLY || x.name.includes(ONLY));
let seed = 0x2545f491;
const nextSeed = () => (seed = (seed * 1664525 + 1013904223) >>> 0);
for (const target of order) {
  for (let rep = 0; rep < REPEAT; rep++) {
    const r = measure(target, nextSeed(), N);
    console.log(fmt(target.name, r, `run n=${N}`));
    if (/control_.*leaky/.test(target.name)) {
      if (over(r.t)) console.log(`[ok] ${target.name}: the setup sees an early-exit comparison`);
      else {
        console.log(`[FAIL] ${target.name}: the setup does not see an early-exit comparison, the run is not valid`);
        invalid = true;
      }
    } else if (target.info && target.name !== "control_null") {
      console.log(`[info] ${target.name} is reported, not gated`);
    } else if (!over(r.t)) {
      console.log(`[ok] ${target.name}`);
    } else {
      const again = measure(target, nextSeed(), N * 10);
      console.log(fmt(target.name, again, `rerun n=${N * 10}`));
      if (over(again.t)) {
        console.log(`[FAIL] ${target.name}: |t| >= ${THRESHOLD} at n=${N} and again at n=${N * 10}`);
        failed = true;
        if (over(again.t, GROSS)) gross = true;
      } else {
        console.log(`[ok, rerun] ${target.name}: |t| >= ${THRESHOLD} at n=${N}, below at n=${N * 10}`);
      }
    }
  }
}
// 0 all fine, 1 a bench over the threshold, 3 the run is not valid, 4 a gross failure.
process.exitCode = invalid ? 3 : gross ? 4 : failed ? 1 : 0;
