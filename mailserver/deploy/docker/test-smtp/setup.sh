#!/bin/sh
set -e

# Postfix needs /etc/mailname and working aliases
echo "test.local" > /etc/mailname
newaliases 2>/dev/null || true

# Create test mailbox
mkdir -p /var/mail
echo "test mailbox" > /var/mail/alice
chown postfix:postfix /var/mail/alice 2>/dev/null || true

# Ensure postfix spool directories exist
mkdir -p /var/spool/postfix
