#!/bin/bash
# The copy container of a Faithful Ferret stack with real data.
#
#   backup-copy.sh loop     one cycle now, then one every FERRET_COPY_EVERY_MINUTES (the default
#                           command of the container)
#   backup-copy.sh once     one cycle, then exit (the exit code tells if it worked)
#   backup-copy.sh check    check the settings and exit; nothing is sent
#
# One cycle:
#   1. Every complete backup set in the backup folder (mounted read-only here) that is
#      not on the target yet is packed (tar), encrypted with `age` to the public key
#      FERRET_BACKUP_AGE_RECIPIENT, and written to the target over SFTP as
#      `<set>.tar.age` and `<set>.tar.age.sha256`. A file is written under a `.part` name
#      and renamed, so the target never holds half a copy under the final name.
#   2. Each copy is read back from the target and checked there: the SHA-256 of the file
#      on the target is the one that was made here, the SHA-256 file on the target says
#      the same, and the file is an age file. A plain set never goes to the target.
#   3. The target is trimmed, in its own folder only and only for names this script writes:
#      copies older than FERRET_COPY_KEEP_DAYS (30) go, but the three newest stay.
#   4. After a new copy that was checked, the monitor (Vigilant Vole push monitor)
#      is told. No new copy, or a copy that did not check out, sends nothing, so the monitor
#      alerts when none has come for its interval.
#
# The private key of age is never here: only the public key is. The script refuses to run
# when an environment variable holds an age secret key, or when the backup folder is writable.
# Logs name set names (a time stamp) and fixed texts; never the push address, the key or the
# target's address.
#
# Settings (environment):
#   FERRET_BACKUP_AGE_RECIPIENT      the public key (age1...), or FERRET_BACKUP_AGE_RECIPIENT_FILE
#   FERRET_COPY_SFTP_HOST            the target
#   FERRET_COPY_SFTP_PORT            default 22
#   FERRET_COPY_SFTP_USER            the account on the target (key login only)
#   FERRET_COPY_SFTP_HOST_KEY        the public host key of the target, as in a known_hosts file
#                                    ("ssh-ed25519 AAAA..."); the host is never trusted on first use
#   FERRET_COPY_SFTP_DIR             the folder on the target to write to, default "."
#   FERRET_COPY_SFTP_KEY_FILE        the private SSH key, default /run/secrets/copy_sftp_key
#   FERRET_COPY_PUSH_URL             the monitor's push address; optional
#   FERRET_COPY_KEEP_DAYS            default 30
#   FERRET_COPY_EVERY_MINUTES        default 60 (1 to 1440)
#   FERRET_COPY_BACKUPS_DIR          default /backups
#   FERRET_COPY_WORK                 default /work (a tmpfs: the copy is made there)
# The style notes about `a && b || c` and `ls` are accepted: every use has been read.
# shellcheck disable=SC2015,SC2012
set -euo pipefail
umask 077

self="$(readlink -f "$0")"
backups="${FERRET_COPY_BACKUPS_DIR:-/backups}"
work="${FERRET_COPY_WORK:-/work}"
keep_newest=3
set_re='^[0-9]{8}T[0-9]{6}Z(-[0-9]{1,6})?$'

log() { printf '%s backup-copy: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
fail() { log "$*"; exit 1; }

# The settings, checked. Sets the variables the cycle uses.
settings() {
  if env | grep -q 'AGE-SECRET-KEY-'; then
    fail "an environment variable holds an age secret key: this container must never have it"
  fi
  recipient="${FERRET_BACKUP_AGE_RECIPIENT:-}"
  if [ -z "$recipient" ] && [ -n "${FERRET_BACKUP_AGE_RECIPIENT_FILE:-}" ]; then
    [ -r "$FERRET_BACKUP_AGE_RECIPIENT_FILE" ] || fail "the recipient file cannot be read"
    recipient="$(head -n 1 "$FERRET_BACKUP_AGE_RECIPIENT_FILE")"
  fi
  [[ "$recipient" =~ ^age1[a-z0-9]{50,}$ ]] \
    || fail "FERRET_BACKUP_AGE_RECIPIENT must be an age public key (age1...); an age secret key is never accepted"
  host="${FERRET_COPY_SFTP_HOST:-}"
  [[ "$host" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] || fail "FERRET_COPY_SFTP_HOST is not a host name or an IPv4 address"
  port="${FERRET_COPY_SFTP_PORT:-22}"
  [[ "$port" =~ ^[0-9]{1,5}$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ] || fail "FERRET_COPY_SFTP_PORT is not a port"
  user="${FERRET_COPY_SFTP_USER:-}"
  [[ "$user" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || fail "FERRET_COPY_SFTP_USER is not a user name"
  remote_dir="${FERRET_COPY_SFTP_DIR:-.}"
  if [[ ! "$remote_dir" =~ ^[A-Za-z0-9._/-]+$ ]] || [[ "$remote_dir" == *..* ]]; then
    fail "FERRET_COPY_SFTP_DIR is not a plain folder name"
  fi
  host_key="${FERRET_COPY_SFTP_HOST_KEY:-}"
  [[ "$host_key" =~ ^(ssh-ed25519|ecdsa-sha2-nistp[0-9]+|ssh-rsa)\ [A-Za-z0-9+/=]+ ]] \
    || fail "FERRET_COPY_SFTP_HOST_KEY must be the host key of the target (ssh-ed25519 AAAA...)"
  key_file="${FERRET_COPY_SFTP_KEY_FILE:-/run/secrets/copy_sftp_key}"
  [ -r "$key_file" ] || fail "the SSH key cannot be read (it must be owned by the user of this container, mode 0400)"
  # A secret mounted from the host keeps the mode of the host file: refuse a key that others can read.
  # Fails closed: if the mode cannot be read, or is not an octal number, the key is refused too.
  local key_mode
  key_mode="$(stat -c %a "$key_file" 2> /dev/null)" || fail "the mode of the SSH key cannot be read; the key is refused"
  [[ "$key_mode" =~ ^[0-7]{3,4}$ ]] || fail "the mode of the SSH key is not readable as a number ($key_mode); the key is refused"
  if [ $((8#$key_mode & 8#077)) -ne 0 ]; then
    fail "the SSH key is readable by group or others (mode $key_mode): make it owned by the user of this container with mode 0400"
  fi
  keep_days="${FERRET_COPY_KEEP_DAYS:-30}"
  [[ "$keep_days" =~ ^[0-9]{1,3}$ ]] && [ "$keep_days" -ge 1 ] || fail "FERRET_COPY_KEEP_DAYS is not a number of days"
  push_url="${FERRET_COPY_PUSH_URL:-}"
  if [ -n "$push_url" ] && [[ ! "$push_url" =~ ^https://[A-Za-z0-9._~:/?#@!\$\&\'()*+,\;=%-]+$ ]]; then
    fail "FERRET_COPY_PUSH_URL must be an https address (the push token is a secret)"
  fi
  [ -d "$backups" ] || fail "the backup folder is not mounted"
  if [ -w "$backups" ]; then
    fail "the backup folder is writable: it must be mounted read-only"
  fi
  [ -d "$work" ] && [ -w "$work" ] || fail "the work folder is not writable"
}

# The SSH settings and the copy of the key (ssh wants a key that only its user can read).
connect_setup() {
  local pattern="$host"
  [ "$port" = 22 ] || pattern="[$host]:$port"
  printf '%s %s\n' "$pattern" "$(printf '%s' "$host_key" | cut -d' ' -f1,2)" > "$work/known_hosts"
  install -m 600 "$key_file" "$work/key"
  ssh_opts=(-o BatchMode=yes -o IdentitiesOnly=yes -o PreferredAuthentications=publickey
    -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$work/known_hosts" -o GlobalKnownHostsFile=/dev/null
    -o ConnectTimeout=20 -o ServerAliveInterval=15 -o ServerAliveCountMax=4 -i "$work/key")
}

# Runs SFTP commands from stdin in the target folder. A failing command ends the batch.
sftp_run() {
  { printf 'cd %s\n' "$remote_dir"; cat; } | sftp -q -b - "${ssh_opts[@]}" -P "$port" "$user@$host"
}

# The names in the target folder that this script writes (a copy, its checksum, or a part).
remote_names() {
  local out
  out="$(printf 'ls -1\n' | sftp_run)" || return 1
  printf '%s\n' "$out" | sed 's#.*/##; s/\r$//' \
    | grep -E '^[0-9]{8}T[0-9]{6}Z(-[0-9]{1,6})?\.tar\.age(\.sha256)?(\.part)?$' || true
}

# The Unix time of a set name.
set_time() {
  local n="$1"
  date -u -d "${n:0:4}-${n:4:2}-${n:6:2} ${n:9:2}:${n:11:2}:${n:13:2}" +%s
}

# Packs, encrypts, writes and checks one set on the target.
copy_set() {
  local name="$1" file="$work/$1.tar.age" sum_file="$work/$1.tar.age.sha256" dl="$work/check"
  local sum remote_sum back_sum mode
  rm -rf "$dl" "$file" "$sum_file"
  mkdir -p "$dl"
  tar -C "$backups" -cf - -- "$name" | age -r "$recipient" -o "$file"
  [ "$(head -c 21 "$file")" = "age-encryption.org/v1" ] || fail "the packed set is not an age file"
  sum="$(sha256sum "$file" | cut -d' ' -f1)"
  printf '%s  %s\n' "$sum" "$name.tar.age" > "$sum_file"
  sftp_run <<EOF
-rm $name.tar.age.part
-rm $name.tar.age.sha256.part
put $file $name.tar.age.part
put $sum_file $name.tar.age.sha256.part
-rm $name.tar.age
-rm $name.tar.age.sha256
rename $name.tar.age.part $name.tar.age
rename $name.tar.age.sha256.part $name.tar.age.sha256
-chmod 600 $name.tar.age
-chmod 600 $name.tar.age.sha256
get $name.tar.age $dl/copy
get $name.tar.age.sha256 $dl/sum
EOF
  back_sum="$(sha256sum "$dl/copy" | cut -d' ' -f1)"
  remote_sum="$(cut -d' ' -f1 "$dl/sum")"
  [ "$back_sum" = "$sum" ] || fail "the copy of $name on the target is not the file that was sent"
  [ "$remote_sum" = "$sum" ] || fail "the checksum file of $name on the target does not match the copy"
  [ "$(head -c 21 "$dl/copy")" = "age-encryption.org/v1" ] || fail "the copy of $name on the target is not an age file"
  # The mode on the target, reported as it is (a share that squashes users can show something
  # else than 600; the file is encrypted either way).
  mode="$(printf 'ls -l %s.tar.age\n' "$name" | sftp_run | grep -oE '^-[rwx-]{9}' | head -n 1 || true)"
  if [ -n "$mode" ] && [ "${mode:4:6}" != "------" ]; then
    log "warning: the copy of $name on the target has mode $mode (readable by others); it is encrypted either way"
  fi
  rm -rf "$dl" "$file" "$sum_file"
  log "copied and checked $name"
}

# Tells the monitor. The address is read by curl from stdin, never put on a command line or in a log.
tell_monitor() {
  [ -n "$push_url" ] || return 0
  local sep='?'
  [[ "$push_url" == *'?'* ]] && sep='&'
  if printf 'url = "%s%sstatus=up&msg=backup+copy+checked"\n' "$push_url" "$sep" \
      | curl -fsS -K - --max-time 10 --max-redirs 0 -o /dev/null 2>/dev/null; then
    log "the monitor was told"
  else
    log "the monitor could not be told"
  fi
}

# Whether a name is a set this script may rank and trim: the form of a set name, a real date, and
# not in the future (a clock that is a day ahead is allowed for). A name with a date far ahead
# would otherwise count as one of the three newest and push the real copies out of the keep list.
valid_set_name() { # name
  local t
  [[ "$1" =~ $set_re ]] || return 1
  t="$(set_time "$1" 2> /dev/null)" || return 1
  [ "$t" -le "$future_limit" ] || return 1
}

# The sets on the target that have both files (a copy and its checksum), one per line.
remote_sets() {
  local n
  printf '%s\n' "$remote" | grep -E '\.tar\.age$' | sed 's/\.tar\.age$//' | while read -r n; do
    if printf '%s\n' "$remote" | grep -qx "$n.tar.age.sha256"; then printf '%s\n' "$n"; fi
  done
}

# What stays: the three newest and everything younger than the keep time, over the names given.
# Sets the array keep. Names that are not valid sets (not a date, or in the future) are not ranked.
decide_keep() {
  local all n rank=0 t
  all="$(printf '%s\n' "$@" | grep -E "$set_re" | sort -ru || true)"
  keep=()
  while IFS= read -r n; do
    [ -n "$n" ] || continue
    valid_set_name "$n" || continue
    t="$(set_time "$n")"
    rank=$((rank + 1))
    if [ "$rank" -le "$keep_newest" ] || [ $((now - t)) -le $((keep_days * 86400)) ]; then
      keep+=("$n")
    fi
  done <<< "$all"
}

in_list() { # name, list...
  local want="$1" item
  shift
  for item in "$@"; do [ "$item" = "$want" ] && return 0; done
  return 1
}

cycle() {
  settings
  connect_setup
  # Nothing from a cycle is left in the work folder, whatever happens in it.
  trap 'rm -rf "$work/key" "$work/known_hosts" "$work/check" "$work"/*.tar.age "$work"/*.tar.age.sha256' EXIT
  local name n local_sets=() on_target=() uploaded=0
  now="$(date -u +%s)"
  future_limit=$((now + 86400))

  # What is on the target now; parts from an earlier, broken run go first.
  remote="$(remote_names)"
  for name in $(printf '%s\n' "$remote" | grep -E '\.part$' || true); do
    printf -- '-rm %s\n' "$name" | sftp_run
  done
  remote="$(remote_names)"

  # The complete sets here, newest first.
  while IFS= read -r name; do
    [ -n "$name" ] || continue
    [[ "$name" =~ $set_re ]] || continue
    if ! valid_set_name "$name"; then
      log "ignoring $name: not a date, or a date in the future"
      continue
    fi
    if [ -d "$backups/$name" ] && [ ! -L "$backups/$name" ] && [ -f "$backups/$name/.complete" ]; then
      local_sets+=("$name")
    fi
  done < <(ls -1 "$backups" | sort -r)

  mapfile -t on_target < <(remote_sets)
  decide_keep "${local_sets[@]}" "${on_target[@]}"
  for name in "${local_sets[@]}"; do
    in_list "$name" "${keep[@]}" || continue
    if in_list "$name" "${on_target[@]}"; then continue; fi
    copy_set "$name"
    uploaded=$((uploaded + 1))
    on_target+=("$name")
  done

  # Trim the target: only names this script writes, only valid sets that are no longer kept.
  decide_keep "${on_target[@]}"
  remote="$(remote_names)"
  for name in $(printf '%s\n' "$remote" | grep -E '\.tar\.age(\.sha256)?$' || true); do
    n="${name%.sha256}"
    n="${n%.tar.age}"
    valid_set_name "$n" || continue
    if ! in_list "$n" "${keep[@]}"; then
      printf -- '-rm %s\n' "$name" | sftp_run
      log "removed the old copy $name from the target"
    fi
  done

  if [ "$uploaded" -gt 0 ]; then
    tell_monitor
  else
    log "nothing new to copy"
  fi
}

case "${1:-loop}" in
  check)
    settings
    log "settings are fine"
    ;;
  once)
    cycle
    ;;
  loop)
    settings
    minutes="${FERRET_COPY_EVERY_MINUTES:-60}"
    [[ "$minutes" =~ ^[0-9]{1,4}$ ]] && [ "$minutes" -ge 1 ] && [ "$minutes" -le 1440 ] \
      || fail "FERRET_COPY_EVERY_MINUTES must be 1 to 1440"
    trap 'exit 0' TERM INT
    while true; do
      "$self" once || log "the cycle failed; the next one is in $minutes minutes"
      sleep "$((minutes * 60))" &
      wait $! || true
    done
    ;;
  *)
    echo "usage: backup-copy.sh loop | once | check" >&2
    exit 2
    ;;
esac
