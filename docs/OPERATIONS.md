# Operating a Faithful Ferret server

Notes for the person who runs the server. The server is one container with one SQLite database in its data
directory (`FERRET_DATA_DIR`, `/data` in the image). Keep a copy of that directory somewhere else: Ferret has no
backup feature of its own yet, and the data on a test server is disposable.

## Restoring a backup: stop, restore, bump, start

When the data directory is put back from an older copy, every browser that has synced with the server has already
seen newer data. Each client checks this on every sync. The server therefore keeps a counter, the *restore epoch*,
and a restore must raise it. Clients then see "the server was restored from an older backup" and offer the choice to
accept the older state. Without the bump they show a different, more alarming notice ("the server may have been
rolled back"), because from where they stand the server went backwards without a reason.

The order matters. Do all four steps:

1. **Stop the server.** The bump command refuses to run while the server is up. Both take an exclusive lock on
   `ferret.lock` in the data directory, so one cannot change the database under the other.
2. **Restore the data directory as a whole.** First remove everything in it, in particular `ferret.sqlite-wal` and `ferret.sqlite-shm`, and then copy the backup in. If an older `ferret.sqlite` is copied over the current one while the current `-wal` and `-shm` files stay, SQLite replays that log onto the older file when it opens it, and the result is a mixed, probably corrupt database. Copy a backup that was taken with the server stopped, or one that comes with its own `-wal` file.
3. **Bump the restore epoch** with the same image and the same data directory:

   ```
   docker compose run --rm <service> restore-epoch bump --yes
   ```

   `<service>` is the service of your compose file (the test stack calls it `ferret-test-app`). The entrypoint already
   runs `ferret`, so do not type `ferret` again. Without `--yes` the command changes nothing. It prints the new
   epoch, for example `restore epoch is now 3 (1 vault raised)`.
4. **Start the server.**

The bump also records the vault's current position (`restore_seq`) and freezes the list of items the vault held at
that moment. Clients use that list when a user accepts the older state, so that a change written after the restore is
never overwritten silently.

**Write down the epoch that each bump prints.** You need it below.

On the test stack the same steps are one command each: `scripts/lanbox-ferret-test.sh snapshot --yes-ferret-test`
takes a snapshot, and `scripts/lanbox-ferret-test.sh restore-snapshot --yes-ferret-test` stops the app, puts the
snapshot back, runs the bump and starts the app.

### A backup that is older than the last bump

The bump raises the epoch by one from the number stored in the database you restored. If that backup is older than
an earlier bump, the number it holds is lower than one that browsers have already stored, and the bump can land on
an epoch they have seen. Browsers then see the same epoch with older data, and stop with the "this looks like a
rollback" notice. That is safe, nothing is lost, but the notice offers "Try again" and "Forget this server", and
"Forget" removes the changes on that device that were not sent yet (the page that asks first lists them).

To avoid it: when you restore a backup that is older than the last bump, run the bump again until the printed epoch
is above the highest value you wrote down. If users already see the rollback notice after a restore, stop the
server, bump again, and start it. Their "Try again" then shows "the server was restored", and they can accept the
older state. Do not tell them to forget the server.

### A backup from before migration 0006

A bump needs a database that has every migration of the server version you run. Backups made before the
`restore_seq` column existed (all backups made by an M1 build, and by M2 builds before the migration `0006`) are
refused: the command says `the database is missing the migrations …: start the server once to migrate it, stop it,
and run this again`. Do that: start the server once with its ports closed to users (or accept that open tabs show the
rollback notice until the bump), let it migrate, stop it, bump, and start it again. The server also writes a copy of the
database to `/data/backups` before it applies a migration.

### After a restore or a deploy

Ask users to reload every open vault tab. A tab that was loaded before a deploy still runs the old scripts, and
those refuse the answers of a newer server.

## Event streams behind a proxy

The change hints are a Server-Sent Events stream (`GET /api/sync/events`). The proxy must not buffer or compress it
into a block: the server sends `Cache-Control: no-store, no-transform` and `X-Accel-Buffering: no`. If a proxy
buffers anyway, the vault falls back to reading changes every five minutes, plus on focus, on unlock and after its own
writes, so nothing breaks; changes from other devices only arrive more slowly.
