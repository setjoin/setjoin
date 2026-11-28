#!/bin/sh
set -e

mkdir -p /var/lib/openldap/data

# Seed using slapadd
slapadd -l /seed.ldif -f /etc/openldap/slapd.conf -n 1
echo "LDAP seed complete"
