# Operating a Faithful Ferret server

Notes for the person who runs the server. The server is one container with one SQLite database in its data
directory (`FERRET_DATA_DIR`, `/data` in the image). It makes its own backup sets, an optional second container copies
them off the machine, encrypted, and a restore is one command. This file says how each of those works, what to check
before real data goes in, and what to do when something goes wrong.

There are two kinds of stack in the repository:

* **The test stack** (`docker/compose.ferret-test.yml`) holds disposable test data. It is never given real data.
* **The stack for real data** (`docker/compose.ferret-home.yml`, started with `scripts/ferret-home.sh`) runs a release
  image only, publishes the server on the loopback address of its host and nowhere else, and has the copy container.
  `docker/compose.ferret-drill.yml` is a throwaway copy of that template with test data, for rehearsing a restore.

In the commands below `<service>` is the service of your compose file (`ferret-home-app` on the stack for real data,
`ferret-test-app` on the test stack) and `<compose>` stands for the whole compose invocation of that stack, for example
`docker compose -p ferret-home -f docker/compose.ferret-home.yml`. The stack for real data takes its image from the
digest that `scripts/ferret-home.sh up` wrote in `docker/home-image`: put its `FERRET_IMAGE=` value in the environment
before you run a `<compose>` command by hand. The entrypoint already runs `ferret`, so do not type `ferret` after the
service name.

## Backup

The server writes a backup set every 24 hours (`FERRET_BACKUP_EVERY_HOURS`, 1 to 168; the first one 15 minutes after it
starts) and right after every change of the master password, every recovery and every new recovery key, so that the
newest set always holds the newest unlock methods. "Take a backup now" on the Backup page of the admin pages asks for
one at once; it starts in about a minute.

* **A set** is a folder named with its time (`20261120T010000Z`) in the backup folder (`FERRET_BACKUP_DIR`; the default
  is `backups/auto` under the data directory, and on the stack for real data a volume of its own, `/backups`). It holds
  the database (made with `VACUUM INTO`, so it is consistent while the server runs), `opaque_setup`, `prelogin_secret`,
  `session.key` and `MANIFEST.json`. Without the three secret files nobody can sign in after a restore, so a set that
  lacks one is refused. The set is written under a temporary name and renamed when it is complete, so a set that is
  listed is whole.
* **Every set is checked after it is written** (opened read-only, `integrity_check`, the files against the manifest,
  the fingerprint of the setup, the migrations). Only a set that passes counts as good. If there is less free space
  than twice the database, the run is marked failed and no older set is touched.
* **Retention.** A set is kept while it is younger than `FERRET_BACKUP_KEEP_DAYS` (30 by default, 1 to 365), and the
  three newest verified sets are always kept, however old, by their creation time (the name only breaks a tie). A set
  that was never finished is not listed and is removed after a day.
* **The Backup page** shows the state, the last good time, the last failure as a fixed code with a sentence, the number
  of sets, the last message to the monitor and the next run. It never shows a path, a set name or the monitor's address.
* **The monitor.** After every checked set the server sends one push to an uptime monitor: set `FERRET_BACKUP_PUSH_URL`
  to the push URL of a "push" monitor with an interval of 24 hours plus a grace period of two hours. The URL is a secret:
  it belongs in the environment file, is never logged and is never shown. No push in time makes the monitor alert you.
  There is no health path to poll, because the stack for real data accepts nothing from outside.
* **By hand** (the commands change nothing that exists, so they need no `--yes`): `backup list`, `backup verify <set>`
  and `backup create`. `backup create` needs the server to be stopped, because it takes the lock of the data directory.

A backup set on the same disk is not a backup against losing the disk, and a set together with its secret files lets
whoever takes the machine try master passwords at the cost of one Argon2id per try (the secret key stops that). So copy
the sets off the machine, and encrypted.

## The encrypted copy off the machine

The copy container (`ferret-home-copy`) reads the backup folder read-only and never writes into it. For every new set it
packs the folder with `tar`, encrypts it with `age` to a **public** key that you own, writes `<set>.tar.age` and
`<set>.tar.age.sha256` to an SFTP target, reads the file back from the target and checks it there (the SHA-256 is the
one it made, and the file is an age file), trims the target by the retention rule above (`FERRET_COPY_KEEP_DAYS`, 30 by
default, and the three newest always stay), and only then pushes to its own monitor. A plain set never leaves the machine.
`age` is a separate, widely used tool; Ferret adds no cryptography of its own here. The container refuses to run if it
finds an age secret key in its environment or if the backup folder is writable.

What you set up before the first start:

1. **An age key pair, made off the server.** On a machine of yours: `age-keygen -o ferret-backup-key.txt`. The line that
   starts with `age1` is the public key and goes in `docker/copy.env` as `FERRET_BACKUP_AGE_RECIPIENT`. The file itself,
   which holds the secret key, never goes to the server. Keep it (and a copy of it) in a password manager or on paper in a
   safe place: without it the copies cannot be opened, and nobody can recover it for you.
2. **An SFTP target** with an account that logs in with a key only and is locked to one folder (no shell, no
   forwarding), on a port of its own. Put its address, port and user in `docker/copy.env`, and the folder as
   `FERRET_COPY_SFTP_DIR`. The private SSH key of that account is the file `docker/secrets/copy_sftp_key` (owned by uid 1000,
   mode `0400`), and its public key goes in the account's `authorized_keys` on the target.
3. **The host key of the target**, read on the target itself (its `.pub` file) and put in `FERRET_COPY_SFTP_HOST_KEY`.
   Never take it with `ssh-keyscan` over the same path the copy will use: that is trust on first use. The copy container
   refuses a host that shows another key.
4. **A second push monitor** for the copies (`FERRET_COPY_PUSH_URL`, https only), with the same interval and grace.
5. **A snapshot of the copy folder on the target**, if its file system can make them (ZFS or btrfs). The copy container
   can delete its own old copies and the server can delete its own sets, so nothing in this release protects you from
   ransomware on the machine that runs both; a snapshot that the account cannot reach does. A job on the target that
   copies (never moves) the files into a folder the copy account cannot write also works. Moving them would make the
   container upload everything again.

### Opening a copy with your key

On a machine that holds your age key (never on the server), with the files of a copy at hand:

```
sha256sum -c 20261120T010000Z.tar.age.sha256        # the file is the one that was written
age -d -i ferret-backup-key.txt 20261120T010000Z.tar.age | tar -x
```

The second command makes a folder `20261120T010000Z/` with the files of the set. `ferret backup verify
20261120T010000Z` (run through the image, with the folder mounted read-only) checks it as a restore would. Opening a
copy with your key is the proof that the key is the right one; do it once before you depend on it, and once more after
any change of key.

## Restoring a backup set

A restore needs a stopped server and one command. It puts a whole set in place, brings it up to the migrations of the
build you run, raises the restore epoch, ends every session and every pending sign-in code, and starts nothing. Every
device then signs in again, and browsers that have synced before see "the server was restored from an older backup" and
offer to accept the older state.

1. **Stop the server.** The command takes an exclusive lock on `ferret.lock` in the data directory and refuses while a
   server holds it. It also refuses unless the user that runs it owns the data directory, so run it with
   `<compose> run --rm --no-deps <service> …` (the entrypoint drops to the user that the data directory belongs to) and not with `exec` as root.
2. **Make the set readable by the container.** A set on the backup volume is at `/backups/<set>`. A set you opened
   from an encrypted copy needs a folder the container can read, mounted read-only (a volume or a bind mount, for
   example at `/restore-in`). The command copies a set nowhere but into the data directory, and needs room for twice the
   size of the set's files there.
3. **Restore:**

   ```
   <compose> run --rm --no-deps <service> backup restore --from /backups/20261120T010000Z --yes
   ```

   Without `--yes` it changes nothing. Before anything is written it checks the set (the files, the fingerprint, a
   newer migration than this build knows, a trigger or view that the schema does not have) and refuses a set that does
   not pass; nothing has changed then. It prints the new restore epoch, how many sessions it ended and the folder the old files
   went to. If it warns that the epoch of the data that was there could not be read, follow the warning: bump again with
   `--at-least` above any epoch clients may have seen, before you start the server.
4. **Start the server** and ask the users to reload every open vault tab: a tab loaded before a deploy still runs the
   old scripts, and those refuse the answers of a newer server.
5. **Delete the folder `pre-restore-<time>/`** in the data directory once you are satisfied. The command moves the old
   database and the old secret files there and never deletes them; they hold everything the old server held.

### The marker, and what to do when a restore is cut off

The restore works in steps (copy the set into a staging folder inside the data directory, check it, migrate it, raise
the epoch and end the sessions, move the live files aside, put the staged files in place, clean up). Before it moves
anything it writes the marker file `RESTORE_IN_PROGRESS` in the data directory, and the server, `restore-epoch bump` and
`backup create` refuse to start while the marker is there. That is what makes a restore that was cut off (a power cut, a
full disk, a killed command) safe: the server never starts on half a restore and never creates a new, empty database with
new keys.

When the command says the restore is not finished:

* **Run the same command again** (with the same `--from`). It goes on from the step that is stored in the marker. Before
  the epoch has been raised it may be given a higher `--at-least`, never a lower one; after that a higher `--at-least` is
  refused.
* **Or undo it:** `<compose> run --rm --no-deps <service> backup restore --abort --yes`. It puts the moved files
  back and removes the staging folder and the marker. Running the abort again after it was cut off is safe: it goes on
  and never touches data that is already back. When an error message itself names `--abort` (an abort that is under way,
  or files that are not all in place), use that and not the rerun.
* A restore that fails before the epoch step removes its staging folder and its marker by itself, and the message says
  that the data directory was not changed.
* Empty `-wal` and `-shm` files that the server leaves are harmless.

### The restore epoch

Clients keep a counter, the *restore epoch*, that only a restore raises. A client that sees the epoch go up while the
vault went back accepts the older state only after the user chooses it. **The new epoch is
`max(stored + 1, now, at_least)`** for every vault: one more than the epoch in the database you restored, or the
server's clock in Unix seconds, or the number you give with `--at-least`, whichever is largest. The epoch therefore never
lands on one that browsers have already stored, even when you restore a set that is older than an earlier restore.

It rests on the server's clock. If the clock has gone backwards (so that `now` is below an epoch that browsers saw), give
`--at-least` a number above the highest epoch that any earlier restore printed:

```
<compose> run --rm --no-deps <service> backup restore --from /backups/<set> --yes --at-least 1900000000
```

If users nevertheless see a notice that "this looks like a rollback" after a restore, stop the server, run
`restore-epoch bump --yes --at-least <a higher number>` (below), start it, and tell them to press "Try again". Nobody
should press "Forget this server" for it: that removes the changes of that device that were not sent yet.

### A data directory that was put back by hand

If you restored the files some other way (a snapshot of the volume, for example), the data directory has no bump yet.
Do it with the server stopped:

1. Remove everything in the data directory first, in particular `ferret.sqlite-wal` and `ferret.sqlite-shm`, then
   copy the backup in. If an older `ferret.sqlite` is copied over a newer one while the newer `-wal` and `-shm` stay,
   SQLite replays that log onto the older file and the result is a mixed, probably corrupt database.
2. Raise the epoch with the same image and data directory:

   ```
   <compose> run --rm --no-deps <service> restore-epoch bump --yes
   ```

   It uses the same rule as the restore (`--at-least <n>` works too), ends the sessions the same way, and prints the new
   epoch, for example `restore epoch is now 1763640000 (1 vault raised)`. Without `--yes` it changes nothing.
3. Start the server.

A bump needs a database that has every migration of the build you run. A backup that was made before migration `0006`
(every backup of the first milestone, and of the second one before that migration) is refused with `the database is
missing the migrations …: start the server once to migrate it, stop it, and run this again`. Do that with the ports
closed to users; open tabs can show the rollback notice until the bump. `ferret backup restore` migrates a set by itself,
in its staging folder, so this does not apply to it.

On the throwaway stacks the repository has helper scripts that take a snapshot of the data volume and put it back with
the bump, for rehearsals. They are for those stacks only and are never run by a test.

## The one-time sign-in code

When the administrator has forgotten the master password, OPAQUE cannot run, so the account is recovered with a
one-time code, the recovery key and the pages of the emergency sheet (a new browser needs both pages).

* **Make a code** on the Users page of the admin pages for another person, or, while the server runs, on its host:

  ```
  docker compose exec -u 1000:1000 <service> ferret sign-in-code issue --email you@example.org --yes
  ```

  It prints the code and the time it is good until. Whoever has a shell on the server can do this, so such a person can
  reset the sign-in of an account, never open a vault.
* **A code is good for 24 hours and once.** A newer code for the same user replaces it, every successful sign-in
  revokes it, and a restore of the server revokes every pending code.
* **It is typed in one place only:** `https://vault.example.org/vault/#/recover`, with the e-mail address of the account.
  The admin pages redirect the kit's own sign-in-code pages there, so nothing asks for the master password that was
  forgotten.
* **Redeeming ends every other session of the account at once**, also one that is in the middle of a change of master
  password (that change then fails with "session ended"). The recovery session it opens lasts 30 minutes.
* **Every try counts**, a good code too: 5 per hour for one typed e-mail address from one network address, and 10 a minute
  from one network address. A try that was throttled does not count, and the throttled answer (`429`) says nothing about
  whether the account exists. Someone who knows only the e-mail address can use up the five and keep the real code
  waiting for an hour; with a single administrator that is accepted. Wait, or restart the server (the counts are in
  memory).

## The stack for real data

The stack never gets real data before the checks in the last section of this file are done, and nothing on it is started
without an explicit yes: `scripts/ferret-home.sh up <release tag> --yes-ferret-home`. The script refuses unless the tag is
a release of this checkout, the image of that release exists for this machine's architecture and for arm64, its
signature verifies (`cosign`, or `--no-cosign`, which is said openly and recorded), the image's revision label is the
commit of the tag, the image has no test features, and the compose file passes its own check
(`scripts/ferret-home.sh config`). It then runs the image by digest and writes the digest down. The header of the compose
file has the full list of what the host needs (Docker 28 or newer, buildx, compose v2, git with the tags, node).

* **No ports but two, and those on loopback.** The server is published on `127.0.0.1:3041` (the vault) and
  `127.0.0.1:3040` (the admin pages) and nowhere else, never on `0.0.0.0` and never on an address of the LAN. The stack
  has a network of its own with a fixed subnet and gateway. A connection from the host to a published loopback port
  reaches the container from that gateway, so `FERRET_TRUSTED_PROXIES` is exactly the gateway: what the proxy on the host
  forwards in `X-Forwarded-*` is believed, and nothing else is. (The server refuses a gateway that ends in `.1` inside
  Docker's address pools; change subnet and gateway together.) Your reverse proxy on the host points
  `https://vault.example.org` at `http://127.0.0.1:3041` and `https://admin.example.org` at `http://127.0.0.1:3040`. The
  two public names must differ, because cookies do not tell ports apart.
* **The rules that keep trusting the gateway safe.** The server believes `X-Forwarded-For` and `X-Forwarded-Proto` from the
  gateway, and only processes on the host can reach the loopback ports. Anything that lets a remote client connect to
  those ports through the tunnel client's own network path, instead of through the proxy's web layer, makes every such
  client "the proxy":
  * **Never make a raw TCP or UDP resource for port 3040 or 3041** on the tunnel's site for this host, and never give
    client access (for example an Olm client) or a private resource on that site that reaches the host or its loopback
    address. A forged `X-Forwarded-For` would then be believed (the throttles and the https check are defeated), and a
    sign-in in front of the admin pages would be bypassed. If that site is shared with other apps, look at what is on it
    first.
  * **The private resource from the host toward the backup target is limited to the SFTP host and port.** Containers on
    the host, the app included, reach it through the host's routes.
  * **A raw TCP fallback toward the target must never expose the target's main `sshd`:** use a dedicated SFTP-only server
    (the copy account only, no passwords, a chroot folder, `ForceCommand internal-sftp`, no forwarding) on a port of its own.
  * **Read the host key on the target itself** (above), never through the tunnel.
* **After the first start**, send one request through the public address of the vault with a forged
  `X-Forwarded-For` header and look at what the server recorded (`scripts/ferret-home.sh status` shows the peers and
  the addresses it has seen): the client address must be the real one, not the forged one. If the forged one shows, the
  proxy passes the client's value on as the entry the server believes; fix that before any real use.
* **Residual risk, accepted:** any process on the host that can open a connection to the loopback ports counts as the
  proxy. They are the host's own processes. Allowing only the tunnel client's user to connect to them (an `iptables` match on the user id
  of the process, on `OUTPUT`) is an optional hardening.
* **Settings and secrets.** The server's settings are in `docker/home.env` and those of the copy container in
  `docker/copy.env` (templates with names and no values are in the repository). Neither is in git, only compose reads them,
  and each container gets only its own. The setup token (`FERRET_SETUP_TOKEN`) is needed only until the first account
  exists; registration closes after it.
* **The rehearsal.** `scripts/ferret-home.sh drill` runs the same template as a throwaway stack with test data and a test
  target on a build machine: an account and an item, a backup, the encrypted copy, a wrong host key refused, decryption
  with a test key, a restore into a fresh instance, a sign-in again. It removes everything it made, also after a failure.
  Rehearse a restore like that, never on the stack for real data.

## Migrations and rolling back a deploy

Every change to the SQL schema (Ferret's and the kit's), the browser's stored records, the backup set, the export file
and the setup text of the sheet comes with a migration or a read path for the old form, and a test that starts from the
old form. The server migrates its database when it starts.

* **A server build that is older than its database refuses to open it** (it names the newer migration and changes
  nothing). So a deploy that migrated cannot be rolled back by starting the old image on the same data.
* **The way back** is the copy of the database that the server writes to `/data/backups` before it applies a migration,
  or a backup set from before the deploy, restored with `ferret backup restore`. **What was written after the deploy is
  lost**, and so is every change of master password or recovery key made since: devices will see the restore and offer
  the older state, and the unlock methods may be older than the ones a device has seen (the vault explains the way out).
* **Before a deploy that migrates**, make a set ("Take a backup now", or `backup create` on a stopped server) and check
  that it is listed.

## Event streams behind a proxy

The change hints are a Server-Sent Events stream (`GET /api/sync/events`). The proxy must not buffer or compress it
into a block: the server sends `Cache-Control: no-store, no-transform` and `X-Accel-Buffering: no`. If a proxy
buffers anyway, the vault falls back to reading changes every five minutes, plus on focus, on unlock and after its own
writes, so nothing breaks; changes from other devices only arrive more slowly.

## An import that outlives its session

An import runs in an *import window* on the server: one per vault, bound to the device that opened it, open for at most 30
minutes. If the session that opened it ends first (the master password was changed in another browser, or the server
was restored), the window stays open until it runs out, and another device that tries to import is told that an import is
open although none is running. The page says how long that can take: finish the import on the first device, or wait up to
30 minutes. Restarting the server clears every window. The same device that signs in again replaces its own window.

## Before real data goes in

Do these in order, on the test instance first, and write down the result of each:

1. The recovery key and an encrypted export have been tested on a new browser (the hand test in `docs/TESTING-M3.md`).
2. The automatic backup runs: a set is listed on the Backup page, the encrypted copy is on the target, you have opened it
   with your age key once, and **both** monitors have received a push and would alert you when the pushes stop.
3. The trust in the proxy for the stack for real data is checked (the forged `X-Forwarded-For` request above, and the rules
   about raw TCP resources and client access).
4. A restore has been rehearsed from the encrypted copy on the throwaway stack, and the freeze tests (the migrations, the
   stored formats) are green on the release you start.
5. The first start is with an explicit yes, from a released image, by digest.
