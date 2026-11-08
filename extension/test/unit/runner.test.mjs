// The runner: its container names and labels, its networks, its pins. These run
// in the unit step with a stand-in for docker; nothing here starts Firefox (the
// Firefox probes are test/firefox/*.spec.mjs).
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { repoRoot } from "./buildHelpers.mjs";

const read = (/** @type {string} */ path) => readFileSync(join(repoRoot, ...path.split("/")), "utf8");

test("the_runner_container_is_named_and_labelled", () => {
  const result = spawnSync("bash", [join(repoRoot, "scripts", "check-lanbox-ext-labels.sh")], { encoding: "utf8" });
  assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);
  assert.match(result.stderr + result.stdout, /check-lanbox-ext-labels: ok/);
});

/**
 * Runs lanbox-ext.sh with a stand-in docker and a stand-in stack script, and
 * returns what was called.
 * @param {string[]} args
 * @returns {{ status: number | null, calls: string[][], stack: string[], output: string }}
 */
function runExt(args) {
  const dir = mkdtempSync(join(tmpdir(), "ferret-ext-stub-"));
  try {
    const calls = join(dir, "calls");
    mkdirSync(calls);
    mkdirSync(join(dir, "bin"));
    writeFileSync(join(dir, "bin", "docker"), [
      "#!/usr/bin/env bash",
      'n=$(( $(ls "$STUB_CALLS" | wc -l) + 1 ))',
      'printf "%s\\n" "$@" > "$STUB_CALLS/call-$n"',
      'for arg in "$@"; do',
      '  case "$arg" in',
      '    run) cat > /dev/null; if grep -qx "FERRET_EXT_STEP=fetch" "$STUB_CALLS/call-$n"; then printf wasm; fi; exit 0 ;;',
      "    build) cat > /dev/null; exit 0 ;;",
      "  esac",
      "done",
      "exit 0",
      "",
    ].join("\n"));
    chmodSync(join(dir, "bin", "docker"), 0o755);
    writeFileSync(join(dir, "stack.sh"), [
      "#!/usr/bin/env bash",
      'printf "%s\\n" "$1" >> "$STUB_STACK"',
      '[ "$1" = e2e-ca ] && printf "PEM\\n"',
      "exit 0",
      "",
    ].join("\n"));
    const result = spawnSync("bash", [join(repoRoot, "scripts", "lanbox-ext.sh"), ...args], {
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: `${join(dir, "bin")}:${process.env.PATH}`,
        STUB_CALLS: calls,
        STUB_STACK: join(dir, "stack.log"),
        FERRET_EXT_STACK_SCRIPT: join(dir, "stack.sh"),
      },
    });
    const files = readdirSync(calls).sort((a, b) => Number(a.slice(5)) - Number(b.slice(5)));
    /** @type {string[]} */
    let stack = [];
    try {
      stack = readFileSync(join(dir, "stack.log"), "utf8").split("\n").filter(Boolean);
    } catch {
      // the stack script was not called
    }
    return {
      status: result.status,
      calls: files.map((f) => readFileSync(join(calls, f), "utf8").split("\n")),
      stack,
      output: `${result.stdout}${result.stderr}`,
    };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** The value after a flag in a recorded call. @param {string[]} call @param {string} flag */
const flagValue = (call, flag) => call[call.indexOf(flag) + 1];

test("firefox_steps_have_no_network_outside_the_test_networks", () => {
  // firefox: the tests run with no network at all; only the step that fetches the WASM package has one.
  const firefox = runExt(["firefox", "--channel", "release"]);
  assert.equal(firefox.status, 0, firefox.output);
  const runs = firefox.calls.filter((call) => call.includes("run"));
  assert.equal(runs.length, 2, "a fetch step and a test step");
  const [fetchStep, testStep] = runs;
  assert.ok(fetchStep.includes("FERRET_EXT_STEP=fetch"));
  assert.equal(fetchStep.includes("--network"), false, "the fetch step uses the default network");
  assert.ok(!fetchStep.some((a) => a.startsWith("FERRET_CHANNELS=")), "the fetch step runs no test");
  assert.equal(flagValue(testStep, "--network"), "none");
  // The fetch step needs the network and nothing else.
  assert.equal(flagValue(fetchStep, "--cap-drop"), "ALL");
  assert.equal(flagValue(fetchStep, "--user"), "10001:10001");
  assert.ok(fetchStep.includes("--read-only") && fetchStep.includes("no-new-privileges:true"));
  assert.deepEqual(testStep.filter((a) => a === "--network"), ["--network"], "one network option");

  // e2e: the only network of the test step is the stack's.
  const e2e = runExt(["e2e"]);
  assert.equal(e2e.status, 0, e2e.output);
  assert.deepEqual(e2e.stack, ["e2e-up", "e2e-ca"]);
  const e2eRuns = e2e.calls.filter((call) => call.includes("run"));
  assert.equal(flagValue(e2eRuns[1], "--network"), "ferret-e2e-net");
  assert.ok(e2eRuns[1].includes("FERRET_E2E_CA_PEM=PEM"), "the stack's CA reaches the test step");
  assert.equal(e2eRuns[0].includes("--network"), false);
  assert.deepEqual(runExt(["e2e", "--no-up"]).stack, ["e2e-ca"], "--no-up leaves the stack alone");

  // Nothing ever joins the host's network or another container's, or publishes a port.
  for (const call of [...firefox.calls, ...e2e.calls]) {
    const network = call.includes("--network") ? flagValue(call, "--network") : undefined;
    assert.ok(network === undefined || network === "none" || network === "ferret-e2e-net", `network ${network}`);
    assert.ok(!call.some((a) => a === "-p" || a === "--publish" || a === "--publish-all" || a.startsWith("--network=") || a === "--privileged"), call.join(" "));
  }

  // The workflow does the same: one network option, none.
  const workflow = read(".github/workflows/extension-firefox.yml")
    .split(/\r?\n/)
    .filter((line) => !line.trim().startsWith("#"))
    .join("\n");
  assert.deepEqual([...workflow.matchAll(/--network\s+(\S+)/g)].map((m) => m[1]), ["none"]);
});

test("runner_image_pins_every_download_by_version_and_sha256", () => {
  const dockerfile = read("docker/ext-runner.Dockerfile");
  assert.match(dockerfile, /^FROM debian:[a-z0-9-]+@sha256:[0-9a-f]{64}$/m, "the base image by digest");
  const sums = [...dockerfile.matchAll(/^ARG (\w+_SHA(?:256|512))=(\S+)$/gm)];
  assert.ok(sums.length >= 5);
  for (const [, name, value] of sums) {
    assert.match(value, new RegExp(`^[0-9a-f]{${name.endsWith("512") ? 128 : 64}}$`), name);
  }
  // Every download is checked: as many checks as downloads.
  const downloads = (dockerfile.match(/curl -fsSL -o /g) ?? []).length;
  const checks = (dockerfile.match(/sha256sum -c -/g) ?? []).length;
  assert.equal(downloads, 4);
  assert.equal(checks, downloads);
  // No floating version, and the versions the tests expect are the pinned ones.
  assert.doesNotMatch(dockerfile, /\/(?:latest|nightly)[/-]/);
  const arg = (/** @type {string} */ name) => /** @type {RegExpMatchArray} */ (dockerfile.match(new RegExp(`^ARG ${name}=(\\S+)$`, "m")))[1];
  const dots = (/** @type {string} */ text) => text.replaceAll(".", "\\.");
  assert.match(dockerfile, new RegExp(`FERRET_FIREFOX_ESR=${dots(arg("ESR_VERSION").replace("esr", ""))} `));
  assert.match(dockerfile, new RegExp(`FERRET_FIREFOX_RELEASE=${dots(arg("RELEASE_VERSION"))} `));
  assert.match(dockerfile, new RegExp(`FERRET_GECKODRIVER=${dots(arg("GECKODRIVER_VERSION"))} `));
  assert.match(dockerfile, new RegExp(`FERRET_NODE=${dots(arg("NODE_VERSION"))} `));
});

test("the_unbranded_release_pin_is_renewed_before_mozilla_deletes_it", () => {
  const dockerfile = read("docker/ext-runner.Dockerfile");
  const expires = /** @type {RegExpMatchArray} */ (dockerfile.match(/^ARG RELEASE_EXPIRES=(\d{4}-\d{2}-\d{2})$/m))[1];
  const days = (Date.parse(expires) - Date.now()) / 86_400_000;
  assert.ok(days > 30, `Mozilla deletes the unbranded Release build on ${expires}: move RELEASE_TASK, RELEASE_VERSION and the checksums in docker/ext-runner.Dockerfile (and RELEASE_EXPIRES)`);
  assert.match(dockerfile, /has expired and RELEASE_TASK/, "the download failure says what to do");
});

test("an_empty_channel_list_fails_the_run", () => {
  const run = (/** @type {string} */ channels) => spawnSync("node", ["--input-type=module", "-e", "import('./test/firefox/harness.mjs').then((m) => console.log(m.channels().join(',')))"], {
    encoding: "utf8", cwd: join(repoRoot, "extension"), env: { ...process.env, FERRET_CHANNELS: channels },
  });
  for (const channels of ["", ",", " , "]) {
    const result = run(channels);
    assert.ok(result.status !== 0 && /names no channel/.test(result.stderr), `FERRET_CHANNELS='${channels}' must fail: ${result.stdout}${result.stderr}`);
  }
  assert.equal(run("esr").stdout.trim(), "esr");
});

test("the_signing_workflow_is_manual_read_only_and_keeps_the_secrets_in_one_step", () => {
  const text = read(".github/workflows/extension-sign-measure.yml");
  const code = text.split("\n").filter((line) => !line.trimStart().startsWith("#")).join("\n");
  // Only a manual run: no push, tag, pull request or schedule.
  assert.match(code, /^on:\n {2}workflow_dispatch:\n/m);
  for (const trigger of ["push:", "pull_request", "schedule:", "tags:", "workflow_run", "release:"]) {
    assert.equal(code.includes(trigger), false, trigger);
  }
  assert.match(code, /^permissions:\n {2}contents: read\n/m);
  assert.equal(/contents: write|id-token|packages:/.test(code), false);
  // Every third-party action is pinned by a full commit SHA.
  const uses = [...code.matchAll(/uses:\s*(\S+)/g)].map((m) => m[1]);
  assert.ok(uses.length >= 3);
  for (const use of uses) assert.match(use, /@[0-9a-f]{40}$/, use);
  // The secrets: two names, in the environment of the signing step only, never on a command line or echoed.
  const secretUses = [...code.matchAll(/secrets\.(\w+)/g)].map((m) => m[1]).sort();
  assert.deepEqual(secretUses, ["AMO_JWT_ISSUER", "AMO_JWT_SECRET"]);
  const steps = code.split(/\n {6}- /);
  const holders = steps.filter((step) => step.includes("secrets."));
  assert.equal(holders.length, 1);
  assert.match(holders[0], /name: Sign with Mozilla \(unlisted\)/);
  assert.match(holders[0], /WEB_EXT_API_KEY: \$\{\{ secrets\.AMO_JWT_ISSUER \}\}/);
  assert.match(holders[0], /WEB_EXT_API_SECRET: \$\{\{ secrets\.AMO_JWT_SECRET \}\}/);
  assert.match(holders[0], /--channel unlisted/);
  assert.equal(/--api-key|--api-secret/.test(code), false, "no secret as a flag");
  assert.equal(/echo[^\n]*(WEB_EXT|AMO_JWT)/.test(code), false, "no secret echoed");
  // It signs the test variant (MV3 or MV2 by the input), and nothing else of ours signs anything.
  assert.match(code, /--variant test/);
  assert.equal(/--variant release/.test(code), false);
  assert.match(code, /--source-dir "dist\/ferret-firefox-\$\{MANIFEST\}-test"/);
  assert.match(code, /type: choice\n\s+options: \[mv3, mv2\]/);
  // The input reaches the shell through the environment only, never spliced into a command line.
  const shellLines = code.split("\n").filter((line) => !/^\s*(?:name|path|description):/.test(line) && !/^\s*MANIFEST:/.test(line));
  assert.equal(shellLines.some((line) => /\$\{\{\s*inputs\./.test(line)), false, "an input is used outside an env value or a name or path");
  for (const name of ["extension.yml", "extension-firefox.yml", "release.yml", "ci.yml"]) {
    const other = read(`.github/workflows/${name}`);
    assert.equal(/web-ext sign|AMO_JWT|WEB_EXT_API/.test(other), false, `${name} must not sign`);
  }
});
