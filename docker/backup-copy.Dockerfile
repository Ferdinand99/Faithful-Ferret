# syntax=docker/dockerfile:1
#
# The copy container of a Faithful Ferret stack with real data: it takes each new
# backup set from the backup folder (mounted read-only), encrypts it with `age` to
# a public key, writes `<set>.tar.age` and its SHA-256 to a target over SFTP with
# an SSH key, checks the file there, and trims the old copies of its own folder.
# See docker/backup-copy.sh. The private age key is never in this image or in the
# container; only the public key is.
#
# Two targets, built with the docker/ folder as the context (backup-copy.Dockerfile.dockerignore
# keeps everything but the script out of it):
#
#   copy         the copy container (the default)
#   test-target  an SFTP server for the drill stack (docker/compose.ferret-drill.yml):
#                key-only login, chroot to one folder, no shell. It is never used on a
#                stack with real data.
#
# The base image is pinned by digest (an index, so it exists for amd64 and arm64
# and is built on the machine that runs it). It is the same image as the server's
# (docker/server.Dockerfile); scripts/check-ferret-home-stack.sh checks that.
# The apk packages are not pinned to a version, for the reason given there.

ARG ALPINE_IMAGE=alpine:3.22@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f

# --- The SFTP server of the drill stack ----------------------------------------
FROM ${ALPINE_IMAGE} AS test-target
RUN apk add --no-cache openssh-server \
    && adduser -D -s /sbin/nologin -u 1000 backup \
    # sshd refuses a locked account even for key logins: give it a password nobody knows.
    && echo "backup:$(head -c 32 /dev/urandom | base64)" | chpasswd 2>/dev/null \
    && mkdir -p /etc/ssh/drill
COPY --chmod=644 <<'EOF' /etc/ssh/drill/sshd_config
Port 2222
HostKey /host-key/ssh_host_ed25519_key
AuthorizedKeysFile /host-key/authorized_keys
PidFile none
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
AllowUsers backup
AuthenticationMethods publickey
PubkeyAuthentication yes
Subsystem sftp internal-sftp
AllowTcpForwarding no
X11Forwarding no
PermitTTY no
StrictModes no
ChrootDirectory /srv/target
ForceCommand internal-sftp
LogLevel ERROR
EOF
COPY --chmod=755 <<'EOF' /usr/local/bin/target-start.sh
#!/bin/sh
set -eu
# The chroot folder is owned by root; the folder inside it belongs to the backup user.
chown root:root /srv/target
chmod 755 /srv/target
mkdir -p /srv/target/ferret
chown 1000:1000 /srv/target/ferret
chmod 700 /srv/target/ferret
exec /usr/sbin/sshd -D -e -f /etc/ssh/drill/sshd_config
EOF
EXPOSE 2222
ENTRYPOINT ["/usr/local/bin/target-start.sh"]

# --- The copy container --------------------------------------------------------
FROM ${ALPINE_IMAGE} AS copy
LABEL org.opencontainers.image.title="Faithful Ferret backup copy" \
      org.opencontainers.image.source="https://github.com/Ferdinand99/Faithful-Ferret" \
      org.opencontainers.image.licenses="AGPL-3.0-only"
# age: the encryption; openssh-client: the SFTP client (sftp; ssh-keygen
# is only used by the drill stack); curl: the message to the monitor; tar and coreutils:
# GNU tar and date; bash: the script.
RUN apk add --no-cache age bash ca-certificates coreutils curl openssh-client tar \
    && addgroup -S -g 1000 ferret \
    && adduser -S -D -H -u 1000 -G ferret -h /work -s /sbin/nologin ferret \
    && mkdir -p /work \
    && chown ferret:ferret /work
COPY --chmod=755 backup-copy.sh /usr/local/bin/backup-copy.sh
USER 1000:1000
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/backup-copy.sh"]
CMD ["loop"]
