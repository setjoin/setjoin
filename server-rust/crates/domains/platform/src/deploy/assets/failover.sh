#!/bin/bash
# Pgpool-II failover script — promotes a standby to primary.
# Called by Pgpool-II when the primary backend fails.
# Arguments from Pgpool-II:
#   %d = failed backend node id
#   %P = old primary node id
#   %H = new primary hostname
#   %R = old primary port
#
# Host-identity policy (fail closed, D-MAILSERVER-DEPLOY-002): the SSH client
# trusts ONLY peer host keys pre-provisioned in /etc/pgpool2/known_hosts.
# StrictHostKeyChecking=yes refuses unknown or substituted keys instead of
# accepting them (TOFU/accept-new is deliberately rejected), and BatchMode=yes
# disables every interactive prompt, so an unattended failover toward an
# unauthenticated or spoofed host fails, is logged, and returns nonzero to
# pgpool instead of hanging or silently promoting an impostor. The wizard
# provisions /etc/pgpool2/known_hosts in this same deployment step from the
# operator-pinned deployment host key (see buildPgpoolKnownHosts); the
# install.sh HA leg provisions it from operator-verified host keys instead.

FAILED_NODE=$1
OLD_PRIMARY=$2
NEW_HOST=$3
# shellcheck disable=SC2034  # OLD_PORT documents pgpool's %R argument position
OLD_PORT=$4

LOG="/var/log/pgpool/failover.log"
PGCTL="/usr/lib/postgresql/18/bin/pg_ctl"
PGDATA="/var/lib/postgresql/18/main"
KNOWN_HOSTS="/etc/pgpool2/known_hosts"

echo "$(date): Failover triggered — failed=$FAILED_NODE old=$OLD_PRIMARY new=$NEW_HOST" >> "$LOG"

# Promote the new primary
if [ "$NEW_HOST" = "$(hostname -f)" ] || [ "$NEW_HOST" = "$(hostname)" ] || [ "$NEW_HOST" = "localhost" ]; then
    echo "$(date): Promoting local PostgreSQL to primary" >> "$LOG"
    if "$PGCTL" promote -D "$PGDATA" >> "$LOG" 2>&1; then
        echo "$(date): Promote successful" >> "$LOG"
        exit 0
    else
        echo "$(date): Promote FAILED" >> "$LOG"
        exit 1
    fi
else
    echo "$(date): Promoting remote PostgreSQL on $NEW_HOST" >> "$LOG"
    if ssh -o StrictHostKeyChecking=yes \
           -o UserKnownHostsFile="$KNOWN_HOSTS" \
           -o GlobalKnownHostsFile="$KNOWN_HOSTS" \
           -o BatchMode=yes \
           -o ConnectTimeout=5 \
           "root@$NEW_HOST" \
           "$PGCTL promote -D $PGDATA" >> "$LOG" 2>&1; then
        echo "$(date): Remote promote successful" >> "$LOG"
        exit 0
    else
        echo "$(date): Remote promote FAILED" >> "$LOG"
        exit 1
    fi
fi
