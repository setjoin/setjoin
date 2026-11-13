# OpenLDAP 2.6.8 — Test Configuration

Used in `deploy/docker/test-ldap/` for E2E LDAP integration testing.

## Key Finding: slapd.conf vs mdb backend

Alpine's OpenLDAP 2.6.8 package requires `moduleload back_mdb` in slapd.conf.
Without it, `database mdb` fails with "Unrecognized database type (mdb)".

The `openldap-back-mdb` package provides `/usr/lib/openldap/back_mdb.so`.

## Solution: Runtime seeding via ldapadd

We start slapd first, then seed entries via ldapadd. This avoids the
slapadd/build-time issues with module loading.

## Container pattern

```dockerfile
FROM alpine:3.21
RUN apk add --no-cache openldap openldap-clients openldap-back-mdb
```

## Default config (Alpine)

Alpine's default OpenLDAP uses a built-in slapd.conf with:
- Suffix: `dc=my-domain,dc=com`
- Root DN: `cn=Manager,dc=my-domain,dc=com`
- Root password: `secret`
- Database: mdb with module back_mdb loaded internally

## RTFM: Database backends

The `mdb` (Memory-Mapped DB) backend replaces the older `hdb` and `bdb` backends.
It is the only supported backend in OpenLDAP 2.6+.

Module files are in `/usr/lib/openldap/`. Alpine packages them as `.so` shared objects
(not `.la` libtool archives).

## Test data structure

```
dc=my-domain,dc=com
├── ou=Engineering
│   └── cn=Alice (mail: alice@test.local)
└── ou=Sales
    └── cn=Bob (mail: bob@test.local)
```

Bind DN: `cn=Manager,dc=my-domain,dc=com`
Bind password: `secret`
