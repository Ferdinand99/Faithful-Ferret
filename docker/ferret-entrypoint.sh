#!/bin/sh
# Container entrypoint.
#
# Started as root (the default), it:
#   1. hands the data directory to the uid/gid from PUID/PGID (default
#      1000:1000, the `ferret` user),
# and then runs the server as that uid/gid.
#
# Started with an explicit non-root user (`--user`, `user:` in compose), it runs
# the binary directly and leaves everything alone.
set -e

app=/usr/local/bin/ferret

if [ "$(id -u)" != "0" ]; then
    exec "$app" "$@"
fi

uid="${PUID:-1000}"
gid="${PGID:-1000}"
# Numbers from 1 to 65534 only: never root, and nothing a 32-bit uid would wrap.
for id in "$uid" "$gid"; do
    case "$id" in
        '' | *[!0-9]*) echo "PUID and PGID must be numbers (got PUID=$uid PGID=$gid)" >&2; exit 1 ;;
    esac
    if [ "${#id}" -gt 5 ] || [ "$id" -lt 1 ] || [ "$id" -gt 65534 ]; then
        echo "PUID and PGID must be between 1 and 65534 (got PUID=$uid PGID=$gid)" >&2
        exit 1
    fi
done

# The user is given to su-exec by number, so /etc/passwd stays untouched (the
# root file system may be read-only). The server checks that its secret files
# belong to the user it runs as: chown and run use the same numbers.
data_dir="${FERRET_DATA_DIR:-/data}"
mkdir -p "$data_dir"
chown -R "$uid:$gid" "$data_dir" 2>/dev/null \
    || echo "warning: could not chown $data_dir; make it writable for uid $uid" >&2

exec su-exec "$uid:$gid" "$app" "$@"
