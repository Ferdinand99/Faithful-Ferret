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

/** The rule the publish job checks the live update manifest with before it replaces it (jq). */
const LIVE_RULE = '($live[0].addons["ferret@hedgerow.tools"].updates) as $l | ($new[0].addons["ferret@hedgerow.tools"].updates) as $n | ($l | type) == "array" and ($n | type) == "array" and ($n[:-1] == $l or $n == $l)';

test("the_runner_container_is_named_and_labelled", () => {
  const result = spawnSync("bash", [join(repoRoot, "scripts", "check-lanbox-labels.sh"), "ext"], { encoding: "utf8" });
  assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);
  assert.match(result.stderr + result.stdout, /check-lanbox-labels: ok \(ext\)/);
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
      // The log scan of an e2e run asks for the ids of the stack's containers: it needs one to read.
      '    ps) if grep -qx -- -q "$STUB_CALLS/call-$n"; then echo stubcontainer; fi; exit 0 ;;',
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
      '[ "$1" = e2e-token ] && printf "TOKEN\\n"',
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

  // e2e: the only network of the test step is the stack's, a stack of the run's own that is removed at the end.
  const e2e = runExt(["e2e"]);
  assert.equal(e2e.status, 0, e2e.output);
  assert.deepEqual(e2e.stack, ["e2e-up", "e2e-ca", "e2e-token", "e2e-chromium", "e2e-down"]);
  const e2eRuns = e2e.calls.filter((call) => call.includes("run"));
  assert.match(flagValue(e2eRuns[1], "--network"), /^ferret-x[0-9a-f]{8}-net$/);
  assert.ok(e2eRuns[1].includes("FERRET_E2E_CA_PEM=PEM"), "the stack's CA reaches the test step");
  assert.ok(e2eRuns[1].includes("FERRET_E2E_SETUP_TOKEN=TOKEN"), "the stack's setup token reaches the test step");
  assert.ok(runs[1].includes("FERRET_E2E_SETUP_TOKEN="), "and no token outside e2e");
  assert.equal(e2eRuns[0].includes("--network"), false);
  assert.deepEqual(runExt(["e2e", "--no-up"]).stack, ["e2e-ca", "e2e-token", "e2e-chromium"], "--no-up leaves the stack alone");

  // Nothing ever joins the host's network or another container's, or publishes a port.
  for (const call of [...firefox.calls, ...e2e.calls]) {
    const network = call.includes("--network") ? flagValue(call, "--network") : undefined;
    assert.ok(network === undefined || network === "none" || /^ferret-x[0-9a-f]{8}-net$/.test(network), `network ${network}`);
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
  // The token `secrets` appears on exactly those two lines: no index syntax, no `toJSON(secrets)`, no `secrets: inherit`.
  assert.deepEqual(code.split("\n").filter((line) => /\bsecrets\b/.test(line)).map((line) => line.trim()), [
    "WEB_EXT_API_KEY: ${{ secrets.AMO_JWT_ISSUER }}",
    "WEB_EXT_API_SECRET: ${{ secrets.AMO_JWT_SECRET }}",
  ]);
  // The secrets are those of an environment that waits for a reviewer: the job names it, and only the one job exists.
  assert.deepEqual([...code.matchAll(/^ {4}environment: (\S+)$/gm)].map((m) => m[1]), ["amo-signing"]);
  assert.equal([...code.matchAll(/^ {2}\w[\w-]*:\n {4}name:/gm)].length, 1, "one job");
  assert.match(code, /retention-days: 1\n/);
  // Every attempt of every run has a version of its own, and the build is checked before it is signed.
  assert.match(code, /manifest\.version = `0\.0\.\$\{RUN_NUMBER\}\.\$\{RUN_ATTEMPT\}`/);
  assert.match(code, /id !== "ferret-test@hedgerow\.tools"\) throw/);
  const checkAt = code.indexOf("the add-on id is");
  assert.ok(checkAt > 0 && checkAt < code.indexOf("web-ext sign"), "the id check comes before the signing");
  // No input or expression is spliced into script text (node -e '...').
  const script = code.slice(code.indexOf("node -e '"), code.indexOf("\n          '\n"));
  assert.equal(/\$\{\{/.test(script), false, "no expression inside the script");
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
  const names = readdirSync(join(repoRoot, ".github", "workflows")).filter((n) => /\.ya?ml$/.test(n));
  assert.ok(names.includes("extension.yml") && names.length >= 5);
  // The two signing workflows are pinned by their own tests; no other workflow signs.
  for (const name of names.filter((n) => n !== "extension-sign-measure.yml" && n !== "extension-sign-release.yml")) {
    const other = read(`.github/workflows/${name}`);
    assert.equal(/web-ext sign|AMO_JWT|WEB_EXT_API|amo-signing/.test(other), false, `${name} must not sign`);
  }
});

test("the_release_signing_workflow_is_manual_read_only_and_keeps_the_secrets_in_one_step", () => {
  const text = read(".github/workflows/extension-sign-release.yml");
  const code = text.split("\n").filter((line) => !line.trimStart().startsWith("#")).join("\n");
  // Only a manual run: no push, tag, pull request, schedule, workflow run or release.
  assert.match(code, /^on:\n {2}workflow_dispatch:\n/m);
  for (const trigger of ["push:", "pull_request", "schedule:", "tags:", "workflow_run", "release:"]) {
    assert.equal(code.includes(trigger), false, trigger);
  }
  assert.match(code, /^permissions:\n {2}contents: read\n/m);
  // The only write access is contents: write, in the publish job (pinned by the next test).
  assert.equal(/id-token|packages:|pull-requests:|actions:|deployments:|pages:|statuses:|: write-all|permissions: write/.test(code), false);
  assert.equal([...code.matchAll(/contents: write/g)].length, 1);
  // Every third-party action is pinned by a full commit SHA.
  const uses = [...code.matchAll(/uses:\s*(\S+)/g)].map((m) => m[1]);
  assert.ok(uses.length >= 6);
  for (const use of uses) assert.match(use, /@[0-9a-f]{40}$/, use);
  // The secrets: two names, on the two WEB_EXT_API_* lines of the signing step only.
  const secretUses = [...code.matchAll(/secrets\.(\w+)/g)].map((m) => m[1]).sort();
  assert.deepEqual(secretUses, ["AMO_JWT_ISSUER", "AMO_JWT_SECRET"]);
  assert.deepEqual(code.split("\n").filter((line) => /\bsecrets\b/.test(line)).map((line) => line.trim()), [
    "WEB_EXT_API_KEY: ${{ secrets.AMO_JWT_ISSUER }}",
    "WEB_EXT_API_SECRET: ${{ secrets.AMO_JWT_SECRET }}",
  ]);
  const steps = code.split(/\n {6}- /);
  const holders = steps.filter((step) => step.includes("secrets."));
  assert.equal(holders.length, 1);
  assert.match(holders[0], /name: Sign with Mozilla \(unlisted\)/);
  assert.match(holders[0], /WEB_EXT_API_KEY: \$\{\{ secrets\.AMO_JWT_ISSUER \}\}/);
  assert.match(holders[0], /WEB_EXT_API_SECRET: \$\{\{ secrets\.AMO_JWT_SECRET \}\}/);
  assert.match(holders[0], /web-ext sign/);
  assert.match(holders[0], /--channel unlisted/);
  assert.match(holders[0], /--no-config-discovery/);
  assert.equal(/--api-key|--api-secret/.test(code), false, "no secret as a flag");
  assert.equal(/echo[^\n]*(WEB_EXT|AMO_JWT)/.test(code), false, "no secret echoed");
  // The secrets are those of an environment that waits for a reviewer: exactly one job names it.
  assert.deepEqual([...code.matchAll(/^ {4}environment: (\S+)$/gm)].map((m) => m[1]), ["amo-signing"]);
  // The input reaches the shell through the environment only, never spliced into a command line.
  const shellLines = code.split("\n").filter((line) => !/^\s*(?:name|path|description):/.test(line) && !/^\s*[A-Z][A-Z0-9_]*:/.test(line));
  assert.equal(shellLines.some((line) => /\$\{\{\s*inputs\./.test(line)), false, "an input is used outside an env value or a name or path");
  // It signs a copy and checks the signed files against the untouched source: META-INF/ may differ,
  // manifest.json is compared as parsed JSON (Mozilla rewrites it), every other file byte for byte.
  assert.match(holders[0], /cp -a "\$RUNNER_TEMP\/source" "\$RUNNER_TEMP\/sign-src"/);
  assert.match(holders[0], /--source-dir "\$RUNNER_TEMP\/sign-src"/);
  const verify = steps.filter((step) => step.includes("name: Check and name the signed file"));
  assert.equal(verify.length, 1);
  assert.equal(verify[0].includes("secrets."), false);
  assert.match(verify[0], /rm -r "\$RUNNER_TEMP\/signed-files\/META-INF"\n/);
  const metaAt = verify[0].indexOf('rm -r "$RUNNER_TEMP/signed-files/META-INF"');
  const jsonAt = verify[0].indexOf("isDeepStrictEqual(built, signed)");
  const dropAt = verify[0].indexOf('rm "$RUNNER_TEMP/source/manifest.json" "$RUNNER_TEMP/signed-files/manifest.json"');
  const diffAt = verify[0].indexOf('diff -r "$RUNNER_TEMP/source" "$RUNNER_TEMP/signed-files"');
  assert.ok(metaAt >= 0 && metaAt < jsonAt && jsonAt < dropAt && dropAt < diffAt, "META-INF removed, then manifest.json compared as JSON and set aside, then everything else diffed");
  assert.match(verify[0], /JSON\.parse\(fs\.readFileSync\(file, "utf8"\)\)/);
  assert.match(verify[0], /' "\$RUNNER_TEMP\/source\/manifest\.json" "\$RUNNER_TEMP\/signed-files\/manifest\.json"/);
  assert.equal(/diff [^\n]*(-x|--exclude)/.test(verify[0]), false, "no file is excluded from the byte comparison");
  // The build job builds the release variant twice, compares the SHA-256 and runs the release check.
  assert.match(code, /for n in 1 2; do\n\s+node scripts\/build\.mjs [^\n]*--variant release /);
  assert.match(code, /if \[ "\$first" != "\$second" \]; then/);
  assert.match(code, /sha256sum "\$RUNNER_TEMP\/build-1\/[^"]+"/);
  assert.match(code, /sha256sum "\$RUNNER_TEMP\/build-2\/[^"]+"/);
  assert.match(code, /bash scripts\/check-ext-release\.sh /);
  // The release carries an update_url, so it is linted as a self-hosted add-on (that only drops AMO's hosting rules).
  assert.match(code, /web-ext lint --source-dir "\$RUNNER_TEMP\/build-1\/ferret-firefox-mv2-release" --warnings-as-errors --self-hosted\n/);
  assert.equal(/--variant test/.test(code), false, "the test variant is signed by the measure workflow");
});

/**
 * The jobs of a workflow (comments removed), by name.
 * @param {string} code
 * @returns {Map<string, string>}
 */
function jobsOf(code) {
  const body = code.slice(code.indexOf("\njobs:\n") + "\njobs:\n".length);
  /** @type {Map<string, string>} */
  const jobs = new Map();
  const parts = body.split(/^ {2}([a-z][\w-]*):\n/m);
  for (let i = 1; i < parts.length; i += 2) jobs.set(parts[i], parts[i + 1]);
  return jobs;
}

test("the_release_publish_jobs_have_the_least_access_and_announce_only_the_signed_file", () => {
  const text = read(".github/workflows/extension-sign-release.yml");
  const code = text.split("\n").filter((line) => !line.trimStart().startsWith("#")).join("\n");
  const jobs = jobsOf(code);
  assert.deepEqual([...jobs.keys()], ["build", "sign", "manifest", "publish"]);
  const manifest = /** @type {string} */ (jobs.get("manifest"));
  const publish = /** @type {string} */ (jobs.get("publish"));
  const sign = /** @type {string} */ (jobs.get("sign"));
  // The order: publishing needs the signing (and so its approval) and the written manifest.
  assert.match(manifest, /^ {4}needs: \[build, sign\]\n/m);
  assert.match(publish, /^ {4}needs: \[build, sign, manifest\]\n/m);
  // Only a run started on main, for a commit on main, publishes.
  const guard = "    if: github.ref == 'refs/heads/main' && needs.build.outputs.on_main == 'true'\n";
  for (const job of [manifest, publish]) assert.equal(job.split(guard).length, 2, "the main-only guard, once, on the job");
  assert.equal([...code.matchAll(/^ {4}if:/gm)].length, 2, "no other job-level condition");
  const build = /** @type {string} */ (jobs.get("build"));
  assert.match(build, /^ {6}on_main: \$\{\{ steps\.resolve\.outputs\.on_main \}\}\n/m);
  assert.match(build, /if git merge-base --is-ancestor "\$commit" refs\/remotes\/origin\/main; then\n\s+echo "on_main=true" >> "\$GITHUB_OUTPUT"\n\s+else\n\s+echo "on_main=false" >> "\$GITHUB_OUTPUT"/);
  assert.equal([...code.matchAll(/on_main=true/g)].length, 1);
  // The sign job hands over the name and the SHA-256 of the signed file, nothing else.
  assert.match(sign, /^ {4}outputs:\n {6}name: \$\{\{ steps\.signed\.outputs\.name \}\}\n {6}sha256: \$\{\{ steps\.signed\.outputs\.sha256 \}\}\n {4}steps:/m);
  // Permissions: only the publish job widens them, to contents: write and nothing else; no environment, no secret.
  for (const name of ["build", "sign", "manifest"]) {
    assert.equal(/^ {4}permissions:/m.test(/** @type {string} */ (jobs.get(name))), false, `${name} keeps the read-only default`);
  }
  assert.match(publish, /^ {4}permissions:\n {6}contents: write\n {4}steps:/m);
  for (const job of [manifest, publish]) {
    assert.equal(job.includes("secrets"), false);
    assert.equal(/^ {4}environment:/m.test(job), false);
  }
  // Actions pinned by commit SHA in both jobs.
  for (const job of [manifest, publish]) {
    const uses = [...job.matchAll(/uses:\s*(\S+)/g)].map((m) => m[1]);
    assert.ok(uses.length >= 2);
    for (const use of uses) assert.match(use, /@[0-9a-f]{40}$/, use);
  }
  // The publish job runs no code from the repository: no checkout, no node, no npm, no script of ours.
  assert.equal(/actions\/checkout|setup-node|\bnode |\bnpm |scripts\//.test(publish), false);
  // The manifest job checks out only the build scripts of the built commit, without credentials, and has no write token.
  assert.match(manifest, /ref: \$\{\{ needs\.build\.outputs\.commit \}\}\n\s+persist-credentials: false\n\s+sparse-checkout: \|\n\s+extension\/scripts\/\n/);
  assert.match(manifest, /node extension\/scripts\/updates-json\.mjs \\\n\s+--xpi "\$RUNNER_TEMP\/signed\/\$NAME" \\\n\s+--sha256 "\$SHA256"/);
  // A missing release is the first publication only on a 404; any other answer stops the run.
  assert.match(manifest, /"HTTP\/"\*" 404"\*\)\n[^;]*exists=false/);
  assert.match(manifest, /\*\)\n\s+echo "::error::Unexpected answer/);
  // Both jobs check the signed file against the SHA-256 the sign job reported, and its name against the version.
  for (const job of [manifest, publish]) {
    assert.match(job, /SHA256: \$\{\{ needs\.sign\.outputs\.sha256 \}\}/);
    assert.match(job, /if \[ "\$actual" != "\$SHA256" \]; then/);
    assert.match(job, /if \[ "\$NAME" != "ferret-firefox-mv2-release-\$\{VERSION\}-signed\.xpi" \]; then/);
  }
  // The token reaches gh through the environment of the steps that call it, never the writer step.
  const steps = (/** @type {string} */ job) => job.split(/\n {6}- /);
  for (const step of [...steps(manifest), ...steps(publish)]) {
    if (step.includes("github.token")) {
      assert.match(step, /^ {10}GH_TOKEN: \$\{\{ github\.token \}\}$/m);
      assert.match(step, /\bgh (?:api|release) /);
    }
    if (step.includes("updates-json.mjs")) assert.equal(step.includes("github.token") || step.includes("GH_TOKEN"), false, "no token for the writer");
  }
  // Releases: an extension-v<version> tag (never v*), never the latest, an existing release is never replaced.
  assert.match(publish, /tag="extension-v\$\{VERSION\}"/);
  assert.equal(/gh release create "?v/.test(publish), false);
  assert.equal([...publish.matchAll(/gh release create /g)].length, 2);
  assert.equal([...publish.matchAll(/--latest=false/g)].length, 2);
  assert.equal(/gh release (?:delete|edit)|git push|git tag|--draft|--prerelease/.test(publish), false);
  assert.match(publish, /if \[ "\$existing" != "\$SHA256" \]; then/);
  // Only updates.json is ever replaced (--clobber), never a package.
  const clobbers = publish.split("\n").filter((line) => line.includes("--clobber"));
  assert.deepEqual(clobbers.map((line) => line.trim()), ['gh release upload extension-updates "$RUNNER_TEMP/updates/updates.json" --repo "$GITHUB_REPOSITORY" --clobber']);
  // Right before the replacement the live file is read again and must be the one the new file was written from.
  const liveAt = publish.indexOf('gh release download extension-updates --repo "$GITHUB_REPOSITORY" --pattern updates.json --dir "$RUNNER_TEMP/live"');
  const ruleAt = publish.indexOf(`'${LIVE_RULE}'`);
  const refuseAt = publish.indexOf('echo "::error::The live updates.json is not the one the new file was written from; nothing was replaced."\n              exit 1');
  const clobberAt = publish.indexOf("--clobber");
  assert.ok(liveAt > 0 && liveAt < ruleAt && ruleAt < refuseAt && refuseAt < clobberAt, "live file read, compared, refused on a mismatch, and only then replaced");
  assert.match(publish, /if ! jq -e -n --slurpfile live "\$RUNNER_TEMP\/live\/updates\.json" --slurpfile new "\$RUNNER_TEMP\/updates\/updates\.json" \\\n/);
  // The newest entry is this version with this hash, and what is served afterwards is compared, over HTTPS only.
  assert.match(publish, /\.version == \$v and \.update_hash == \$h/);
  assert.match(publish, /--arg h "sha256:\$SHA256"/);
  assert.equal([...publish.matchAll(/curl -fsSL --proto '=https' --proto-redir '=https' /g)].length, 2);
  assert.match(publish, /cmp -s "\$RUNNER_TEMP\/fetched\.json" "\$RUNNER_TEMP\/updates\/updates\.json"/);
  assert.match(publish, /if \[ "\$fetched" != "\$SHA256" \]; then/);
  // No input or expression is spliced into a run script of these jobs: values come through env.
  for (const job of [manifest, publish]) {
    for (const block of job.matchAll(/run: \|\n((?: {10}.*\n?)+)/g)) {
      assert.equal(/\$\{\{/.test(block[1]), false, `an expression inside a run script: ${block[1].slice(0, 80)}`);
    }
  }
});

test("the_live_update_manifest_rule_accepts_one_appended_entry_or_the_same_file_only", (t) => {
  // The rule is the jq program of the publish job (pinned above); it runs here when jq is installed (the CI runners
  // have it; the test container may not).
  if (spawnSync("jq", ["--version"], { encoding: "utf8" }).status !== 0) {
    t.skip("jq is not installed");
    return;
  }
  const id = "ferret@hedgerow.tools";
  /** @param {unknown} updates */
  const file = (updates) => JSON.stringify({ addons: { [id]: { updates } } });
  /** @param {string} version @param {string} hex */
  const entry = (version, hex) => ({
    version,
    update_link: `https://github.com/Ferdinand99/Faithful-Ferret/releases/download/extension-v${version}/ferret-firefox-mv2-release-${version}-signed.xpi`,
    update_hash: `sha256:${hex.repeat(64)}`,
  });
  const a = entry("0.7.1", "a");
  const b = entry("0.7.2", "b");
  const c = entry("0.7.3", "c");
  const dir = mkdtempSync(join(tmpdir(), "ferret-live-"));
  try {
    /** @param {string} live @param {string} next */
    const passes = (live, next) => {
      writeFileSync(join(dir, "live.json"), live);
      writeFileSync(join(dir, "new.json"), next);
      const result = spawnSync("jq", ["-e", "-n", "--slurpfile", "live", join(dir, "live.json"), "--slurpfile", "new", join(dir, "new.json"), LIVE_RULE], { encoding: "utf8" });
      return result.status === 0;
    };
    // Accepted: one entry appended, or the same file (a re-run).
    assert.equal(passes(file([a]), file([a, b])), true);
    assert.equal(passes(file([]), file([a])), true);
    assert.equal(passes(file([a, b]), file([a, b])), true);
    // Refused: another publication in between, an entry dropped or changed, two entries at once, a broken live file.
    assert.equal(passes(file([a, b]), file([a, c])), false, "the live file gained an entry the new one lacks");
    assert.equal(passes(file([a, b]), file([b, c])), false, "an older entry was dropped");
    assert.equal(passes(file([a]), file([{ ...a, update_hash: `sha256:${"f".repeat(64)}` }, b])), false, "an older entry was changed");
    assert.equal(passes(file([a]), file([a, b, c])), false, "two entries at once");
    assert.equal(passes(file([]), file([a, b])), false);
    assert.equal(passes(JSON.stringify({ addons: {} }), file([a])), false, "no list in the live file");
    assert.equal(passes(file({}), file([a])), false);
    assert.equal(passes("{", file([a])), false, "not JSON");
    assert.equal(passes(file([a]), JSON.stringify({ addons: { "other@example.com": { updates: [a] } } })), false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
