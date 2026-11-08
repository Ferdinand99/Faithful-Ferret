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
