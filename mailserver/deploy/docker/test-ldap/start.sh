#!/bin/sh
set -e

mkdir -p /var/lib/openldap/data /run/openldap

# Start slapd with Alpine's default config
slapd -d 0 -h "ldap://0.0.0.0:389/" &
SLAPD_PID=$!

# Wait for slapd to be ready
for _ in $(seq 1 10); do
    if ldapsearch -x -H ldap://localhost:389/ -b "" -s base "(objectClass=*)" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

# Seed data
ldapadd -x -H ldap://localhost:389/ \
    -D "cn=Manager,dc=my-domain,dc=com" -w secret \
    -f /seed.ldif || true
echo "LDAP seeding done (status: $?)"

wait $SLAPD_PID
