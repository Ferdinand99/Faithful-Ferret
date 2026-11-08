#!/bin/sh
# Runs inside the runner container (docker/ext-runner.Dockerfile), with the tree
# in /work: `sh extension/test/firefox/run.sh firefox|e2e`. Started by
# scripts/lanbox-ext.sh and by .github/workflows/extension-firefox.yml.
#
# As root: add the fixture host names to /etc/hosts and hand /work to the test
# user, then run everything else as that user (Firefox does not run as root).
# As the test user: build the test variant (both manifest versions) from the WASM
# package that the caller fetched and checked (/work/wasm.tar.gz), then run the
# specs once per channel. FERRET_CHANNELS, FERRET_MANIFEST, FERRET_GREP and
# FERRET_HEADLESS come from the caller. The specs find the build and the profile
# settings in FERRET_EXT_XPI, FERRET_EXT_UUID and FERRET_EXT_CHANNEL, set here.
#
# A spec that is skipped, or a run in which no test ran, is a failure: a missing
# piece of the environment must never pass as green.
set -eu

mode="${1:-firefox}"
cd /work

if [ "$(id -u)" = 0 ]; then
  node extension/test/firefox/harness.mjs hosts >> /etc/hosts
  chown -R ferret:ferret /work
  exec setpriv --reuid=10001 --regid=10001 --clear-groups env HOME=/home/ferret sh "$0" "$mode"
fi

cd /work/extension
for mv in mv3 mv2; do
  node scripts/build.mjs --browser firefox --manifest "$mv" --variant test --wasm-tar /work/wasm.tar.gz >&2
done

case "$mode" in
  firefox) specs=$(ls test/firefox/*.spec.mjs | grep -v '\.e2e\.spec\.mjs$') ;;
  e2e) specs=$(ls test/firefox/*.e2e.spec.mjs) ;;
  *) echo "run.sh: unknown mode $mode" >&2; exit 2 ;;
esac

manifest="${FERRET_MANIFEST:-mv3}"
FERRET_EXT_XPI="/work/extension/dist/ferret-firefox-$manifest-test.xpi"
FERRET_EXT_UUID=$(node -e 'import("/work/extension/test/firefox/profile.mjs").then((m) => console.log(m.FIXED_UUID))')
export FERRET_EXT_XPI FERRET_EXT_UUID
[ -f "$FERRET_EXT_XPI" ] || { echo "run.sh: $FERRET_EXT_XPI is missing" >&2; exit 1; }

failed=0
for channel in $(echo "${FERRET_CHANNELS:-release,esr}" | tr ',' ' '); do
  echo "run.sh: channel $channel" >&2
  report=$(mktemp)
  set -- --test --test-concurrency=1 --test-timeout=600000
  if [ -n "${FERRET_GREP:-}" ]; then
    set -- "$@" "--test-name-pattern=$FERRET_GREP"
  fi
  status=0
  # shellcheck disable=SC2086
  if [ "${FERRET_HEADLESS:-1}" = 0 ]; then
    FERRET_CHANNELS=$channel FERRET_EXT_CHANNEL=$channel xvfb-run -a -s "-screen 0 1280x1024x24" node "$@" $specs > "$report" || status=$?
  else
    FERRET_CHANNELS=$channel FERRET_EXT_CHANNEL=$channel node "$@" $specs > "$report" || status=$?
  fi
  cat "$report" >&2
  if [ "$status" -ne 0 ]; then
    failed=1
  fi
  if ! grep -q '^# pass [1-9]' "$report"; then
    echo "run.sh: no test passed on $channel" >&2
    failed=1
  fi
  if ! grep -q '^# skipped 0$' "$report"; then
    echo "run.sh: a test was skipped on $channel (the environment is incomplete)" >&2
    failed=1
  fi
  rm -f "$report"
done
exit $failed
