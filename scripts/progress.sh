#!/usr/bin/env bash
# Progress markers for the build and test scripts. Source this file inside the
# container (or anywhere else) that runs a build or a test run:
#
#   . scripts/progress.sh
#   progress_begin 2                    two phases in this run
#   progress_phase build                ::progress:: phase 1/2 build
#   cargo build ...
#   progress_done                       ::progress:: done
#   progress_phase unit                 ::progress:: phase 2/2 unit
#   progress_total 120                  ::progress:: total 120
#   progress_step 17 120                ::progress:: 17/120
#   progress_done
#
# Every marker is a line of its own, at column 0, on stderr (stdout stays free
# for data such as a tar archive). The protocol, for a tool that follows the
# output of a run and shows a progress bar:
#
#   ::progress:: phase <i>/<n> <label>  a phase starts (i of n phases)
#   ::progress:: total <N>              the current phase has N units of work
#   ::progress:: <k>/<N>                k of the N units are finished
#   ::progress:: done                   the phase ended (also after a failure;
#                                       the exit status is the script's own)
#
# A phase without `total` has no unit count; cargo prints its own
# `Building [====>  ] k/N` bar while it compiles (the scripts set
# CARGO_TERM_PROGRESS_WHEN=always for that).
#
# A script that runs only a part of a longer job (for example one of several
# containers) sets FERRET_PROGRESS_PHASE_BASE (the number of phases that came
# before, default 0) and FERRET_PROGRESS_PHASES (the total number of phases of the
# whole job) so that the numbers add up.
#
# Besides the markers, these helpers run the usual commands without changing
# their output or their exit status:
#
#   progress_cargo <cargo args>      one phase, or build + test for `cargo test`
#   progress_cargo_test <cargo args> build, then count the tests (`-- --list`,
#                                    nothing is built twice) and run them with a
#                                    marker per finished test
#   progress_node_test <label> <node args>
#                                    one phase: `node --test` with one marker per
#                                    finished test file (the total is the number
#                                    of files)
#   progress_run <label> <command>   one phase around any command
#   progress_cargo_phases <cargo args>  how many phases progress_cargo prints
#   progress_advance <n>             skip n phase numbers (a phase that a child
#                                    process printed, see FERRET_PROGRESS_PHASE_BASE)
#
# progress_cargo_test and progress_node_test forward the output of the tests on
# stderr; progress_run and progress_cargo leave the streams of the command alone.

_pg_n=1
_pg_i=0

# progress_begin <n>: the run has n phases (unless FERRET_PROGRESS_PHASES says otherwise).
progress_begin() {
  _pg_n="${FERRET_PROGRESS_PHASES:-$1}"
  _pg_i=0
}

# progress_advance <n>: n phase numbers were used by a child process.
progress_advance() {
  _pg_i=$((_pg_i + $1))
}

progress_phase() { # label
  _pg_i=$((_pg_i + 1))
  printf '::progress:: phase %d/%d %s\n' "$((${FERRET_PROGRESS_PHASE_BASE:-0} + _pg_i))" "$_pg_n" "$1" >&2
}

progress_total() { # N
  printf '::progress:: total %s\n' "$1" >&2
}

progress_step() { # k N
  printf '::progress:: %s/%s\n' "$1" "$2" >&2
}

progress_done() {
  printf '::progress:: done\n' >&2
}

# progress_run <label> <command...>: one phase around a command; returns its status.
progress_run() {
  local label="$1" rc=0
  shift
  progress_phase "$label"
  "$@" || rc=$?
  progress_done
  return "$rc"
}

# The cargo subcommand of an argument list: the first word that is not +toolchain.
_pg_cargo_sub() {
  local a
  for a in "$@"; do
    case "$a" in
      +*) ;;
      *) printf '%s' "$a"; return 0 ;;
    esac
  done
}

# Number of phases progress_cargo prints for these cargo arguments.
progress_cargo_phases() {
  case "$(_pg_cargo_sub "$@")" in
    test | t)
      local a
      for a in "$@"; do
        [ "$a" = -- ] && break
        [ "$a" = --no-run ] && { printf 1; return 0; }
      done
      printf 2
      ;;
    *) printf 1 ;;
  esac
}

# progress_cargo <cargo args>: runs cargo. `cargo test` gets a build phase and a
# test phase, every other subcommand one phase named after it. Call progress_begin
# with progress_cargo_phases first.
progress_cargo() {
  local sub
  sub="$(_pg_cargo_sub "$@")"
  case "$sub" in
    test | t) progress_cargo_test "$@"; return $? ;;
  esac
  progress_run "${sub:-cargo}" cargo "$@"
}

# progress_cargo_test <cargo args, with `test` in them>: see the header.
progress_cargo_test() {
  local pre=() post=() after=0 a no_run=0 rc=0 listing total=0 k
  for a in "$@"; do
    if [ "$after" = 0 ] && [ "$a" = -- ]; then
      after=1
    elif [ "$after" = 0 ]; then
      pre+=("$a")
      [ "$a" = --no-run ] && no_run=1
    else
      post+=("$a")
    fi
  done

  # Phase 1: compile everything the run needs (the same flags, plus --no-run).
  progress_phase build
  if [ "$no_run" = 1 ]; then
    cargo "${pre[@]}" ${post[@]+-- "${post[@]}"} || rc=$?
  else
    cargo "${pre[@]}" --no-run || rc=$?
  fi
  progress_done
  if [ "$rc" -ne 0 ] || [ "$no_run" = 1 ]; then
    return "$rc"
  fi

  # Phase 2: count, then run. The list pass finds everything built already, so
  # it compiles nothing; its own output is only counted, never shown. When it
  # fails the run goes on without a total (the real run shows the error).
  progress_phase test
  if listing="$(cargo "${pre[@]}" -- ${post[@]+"${post[@]}"} --list 2>/dev/null)"; then
    total="$(printf '%s\n' "$listing" | grep -c ': test$' || true)"
  fi
  if [ "${total:-0}" -gt 0 ]; then
    progress_total "$total"
  fi

  cargo "${pre[@]}" ${post[@]+-- "${post[@]}"} 2>&1 \
    | awk -v total="${total:-0}" '
        { print; fflush() }
        total > 0 && /^test .* \.\.\. (ok|FAILED|ignored)/ {
          k++
          printf "::progress:: %d/%d\n", (k > total ? total : k), total
          fflush()
        }' >&2
  rc=${PIPESTATUS[0]}
  progress_done
  return "$rc"
}

# progress_node_test <label> <node --test args>: one phase; the unit is a test
# file, so the total is known before the run. The default reporter keeps printing
# the usual output; a second reporter (progress-node-reporter.mjs) adds the markers.
progress_node_test() {
  local label="$1" a files=0 n default_reporter reporter rc=0
  shift
  progress_phase "$label"
  for a in "$@"; do
    case "$a" in
      -*) ;;
      *)
        n="$(compgen -G "$a" | wc -l)"
        files=$((files + n))
        ;;
    esac
  done
  if [ "$files" -gt 0 ]; then
    progress_total "$files"
  fi
  # What `node --test` prints without a terminal: tap before Node 23, spec after.
  default_reporter=tap
  if [ "$(node -p 'process.versions.node.split(".")[0]')" -ge 23 ]; then
    default_reporter=spec
  fi
  reporter="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/progress-node-reporter.mjs"
  FERRET_PROGRESS_TOTAL="$files" node --test \
    --test-reporter="$default_reporter" --test-reporter-destination=stdout \
    --test-reporter="$reporter" --test-reporter-destination=stdout \
    "$@" >&2 || rc=$?
  progress_done
  return "$rc"
}
