#!/usr/bin/env bash
# Checks the progress markers of scripts/progress.sh: the marker lines of every
# helper, the numbering of phases when a script is a part of a longer job, the
# cargo test flow with a stand-in `cargo` (no compiler needed; the output of the
# tests must come through unchanged and the exit status must be the tests') and
# the `node --test` flow with the reporter scripts/progress-node-reporter.mjs.
set -euo pipefail
cd "$(dirname "$0")/.."
root="$PWD"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir "$work/bin"

fail() { echo "check-progress: $*" >&2; exit 1; }

# expect <name> <wanted text> <got text>
expect() {
  if [ "$2" != "$3" ]; then
    printf 'check-progress: %s\n--- wanted\n%s\n--- got\n%s\n' "$1" "$2" "$3" >&2
    exit 1
  fi
}

# The marker lines, one by one.
(
  . scripts/progress.sh
  progress_begin 2
  progress_phase build
  progress_done
  progress_phase unit
  progress_total 120
  progress_step 17 120
  progress_done
) 2> "$work/markers" || fail "the helpers failed"
expect "marker lines" "::progress:: phase 1/2 build
::progress:: done
::progress:: phase 2/2 unit
::progress:: total 120
::progress:: 17/120
::progress:: done" "$(cat "$work/markers")"

# A part of a longer job: base and total come from the environment.
got="$(
  FERRET_PROGRESS_PHASE_BASE=3 FERRET_PROGRESS_PHASES=6 bash -c '
    . scripts/progress.sh
    progress_begin 1
    progress_phase wasm
    progress_advance 1
    progress_phase after
  ' 2>&1
)"
expect "phase base" "::progress:: phase 4/6 wasm
::progress:: phase 6/6 after" "$got"

# The markers are on stderr, never on stdout.
out="$({ . scripts/progress.sh; progress_begin 1; progress_phase x; progress_done; } 2>/dev/null)"
[ -z "$out" ] || fail "a marker went to stdout"

# A stand-in cargo. It logs its arguments and behaves like cargo test does.
cat > "$work/bin/cargo" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$STUB_LOG"
case " $* " in
  *" --no-run "*)
    echo "   Compiling demo v0.1.0" >&2
    echo "    Finished test profile" >&2
    exit "${STUB_BUILD_RC:-0}"
    ;;
  *" --list "*)
    printf 'first: test\nsecond: test\nthird: test\nbench_one: benchmark\n'
    echo "     Running unittests (target/debug/deps/demo)" >&2
    exit 0
    ;;
  *" build "* | *" check "*)
    echo "   Compiling demo v0.1.0" >&2
    exit 0
    ;;
esac
echo "     Running unittests (target/debug/deps/demo)" >&2
echo
echo "running 3 tests"
echo "test first ... ok"
echo "test second ... FAILED"
echo "test third ... ignored, not now"
echo
echo "test result: FAILED. 1 passed; 1 failed; 1 ignored"
exit "${STUB_RC:-101}"
STUB
chmod +x "$work/bin/cargo"
export STUB_LOG="$work/cargo.log"

run_cargo() { # args of progress_cargo; stderr and stdout together, status in $rc
  : > "$STUB_LOG"
  rc=0
  PATH="$work/bin:$PATH" bash -c '
    . scripts/progress.sh
    progress_begin "$(progress_cargo_phases "$@")"
    progress_cargo "$@"
  ' bash "$@" > "$work/out" 2>&1 || rc=$?
}

expect "phases of cargo test" "2" "$(. scripts/progress.sh; progress_cargo_phases test -p demo)"
expect "phases of +toolchain test" "2" "$(. scripts/progress.sh; progress_cargo_phases +nightly test)"
expect "phases of test --no-run" "1" "$(. scripts/progress.sh; progress_cargo_phases test --no-run)"
expect "phases of cargo build" "1" "$(. scripts/progress.sh; progress_cargo_phases build --release)"

run_cargo test -p demo -- --nocapture
[ "$rc" -eq 101 ] || fail "the exit status of the tests was lost (got $rc)"
expect "cargo test output" "::progress:: phase 1/2 build
   Compiling demo v0.1.0
    Finished test profile
::progress:: done
::progress:: phase 2/2 test
::progress:: total 3
     Running unittests (target/debug/deps/demo)

running 3 tests
test first ... ok
::progress:: 1/3
test second ... FAILED
::progress:: 2/3
test third ... ignored, not now
::progress:: 3/3

test result: FAILED. 1 passed; 1 failed; 1 ignored
::progress:: done" "$(cat "$work/out")"
# The build pass, the list pass and the run pass get the same flags.
expect "cargo calls" "test -p demo --no-run
test -p demo -- --nocapture --list
test -p demo -- --nocapture" "$(cat "$STUB_LOG")"

# A build that fails stops before the test phase, with its own status.
STUB_BUILD_RC=7 run_cargo test -p demo
[ "$rc" -eq 7 ] || fail "the exit status of the build was lost (got $rc)"
! grep -q 'phase 2/2' "$work/out" || fail "the test phase started after a failed build"
grep -qx '::progress:: done' "$work/out" || fail "no done after a failed build"

# Tests that pass: status 0, no flags after --.
STUB_RC=0 run_cargo test
[ "$rc" -eq 0 ] || fail "a passing run gave status $rc"
expect "cargo calls without test flags" "test --no-run
test -- --list
test" "$(cat "$STUB_LOG")"

# Another subcommand is one phase named after it.
run_cargo build --release
[ "$rc" -eq 0 ] || fail "cargo build gave status $rc"
expect "cargo build output" "::progress:: phase 1/1 build
   Compiling demo v0.1.0
::progress:: done" "$(cat "$work/out")"

# node --test, with the real reporter. Needs a Node with test:summary (22 and later).
if command -v node > /dev/null 2>&1 \
   && [ "$(node -p 'process.versions.node.split(".")[0]')" -ge 22 ]; then
  mkdir "$work/node"
  for n in a b c; do
    printf "import test from 'node:test';\ntest('%s one', () => {});\ntest('%s two', async (t) => { await t.test('inner', () => {}); });\n" "$n" "$n" > "$work/node/$n.test.mjs"
  done
  run_node() { # files...; status in $rc
    rc=0
    (cd "$work/node" && bash -c '
      . "$1"/scripts/progress.sh
      progress_begin 1
      shift
      progress_node_test unit "$@"
    ' bash "$root" "$@") > "$work/out" 2>&1 || rc=$?
  }
  run_node "*.test.mjs"
  [ "$rc" -eq 0 ] || { cat "$work/out" >&2; fail "node --test failed (status $rc)"; }
  expect "node markers" "::progress:: phase 1/1 unit
::progress:: total 3
::progress:: 1/3
::progress:: 2/3
::progress:: 3/3
::progress:: done" "$(grep '^::progress::' "$work/out")"
  grep -q 'a one' "$work/out" || fail "the normal test output is missing"
  grep -q 'c two' "$work/out" || fail "the normal test output is missing"

  printf "import test from 'node:test';\ntest('broken', () => { throw new Error('no'); });\n" > "$work/node/d.test.mjs"
  run_node "*.test.mjs"
  [ "$rc" -ne 0 ] || fail "a failing test file gave status 0"
  expect "node markers after a failure" "::progress:: phase 1/1 unit
::progress:: total 4
::progress:: 1/4
::progress:: 2/4
::progress:: 3/4
::progress:: 4/4
::progress:: done" "$(grep '^::progress::' "$work/out")"
else
  echo "check-progress: node 22 or later not found; the node --test part is skipped" >&2
fi

echo "check-progress: ok"
