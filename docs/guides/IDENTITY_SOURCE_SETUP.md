# Identity Source Setup

Configure one lifecycle authority and optional authentication-only providers
without enabling the normalized identity read path.

## Supported topology

Each member has exactly one lifecycle authority:

- Setjoin local;
- one AD source;
- one generic LDAP source with a uniqueness-proven immutable attribute; or
- one source-bound SCIM integration.

SAML and OIDC are authentication-only. A member may have up to eight active
authentication links. Email, UPN, display name, employee number, and phone are
never durable link proof.

Guest accounts, shared/resource mailboxes, and service identities are outside
this transition workflow. See
[`IDENTITY_ACCOUNT_CLASSES.md`](../standards/IDENTITY_ACCOUNT_CLASSES.md).

## Before configuration

1. Back up PostgreSQL and the deployment configuration.
2. Confirm schema V165 or later:

   ```bash
   mailctl schema check --json
   ```

3. Record the PII-free baseline:

   ```bash
   mailctl identity inventory --json
   mailctl identity source list --json
   ```

4. Keep these flags OFF during setup:

   ```text
   feature.identity_model_v2
   feature.identity_normalized_reads
   feature.identity_transitions
   ```

## Normalized source workflow

Write a secret-free `setjoin.io/v1` source document. For example:

```json
{
  "apiVersion": "setjoin.io/v1",
  "kind": "IdentitySource",
  "metadata": {
    "sourceKey": "ad:corp",
    "displayName": "Corporate AD"
  },
  "spec": {
    "type": "ad",
    "endpoint": {
      "host": "dc.corp.example",
      "port": 636,
      "tls": "ldaps"
    },
    "subjectAttribute": "objectGUID",
    "baseDN": "dc=corp,dc=example",
    "bindDN": "cn=setjoin,ou=services,dc=corp,dc=example"
  }
}
```

Validate locally, inspect the server-side plan, then apply a draft:

```bash
mailctl identity source validate --file source.json
mailctl identity source plan --file source.json
mailctl identity source apply --file source.json --reason "create corporate AD source"
```

`plan` exits 2 when it finds a create/update. Apply never activates a source.
Every mutating command prints the generated idempotency UUID unless `--quiet`
is used; save that UUID to replay an uncertain request safely.

Provide credentials only through standard input or a mode-0600 regular file:

```bash
mailctl identity source set-secret ad:corp --name bindPassword \
  --file /secure/path/ad-bind-password --reason "install AD bind credential"
```

Allowed names are closed per kind: AD/LDAP `bindPassword`, SCIM
`bearerToken`, SAML `metadataClientSecret`, and OIDC `clientSecret`. Local
sources accept no secret. Values are sent as raw bytes, encrypted before
PostgreSQL, and never returned by detail/export. Rotation retains only the prior
ciphertext for a bounded one-hour grace:

```bash
mailctl identity source rotate-secret ad:corp --name bindPassword \
  --stdin --reason "rotate AD bind credential"
```

Dry-run validates schema, required-secret posture, and AD/LDAP transport while
performing zero person writes. Only a successful dry-run advances a draft to
`validated`; activation remains separate:

```bash
mailctl identity source dry-run ad:corp --reason "validate before activation"
mailctl identity source activate ad:corp --reason "activate approved source"
```

Pause fences new discovery immediately but lets already-accepted batches drain.
Resume reopens admission. Retirement is terminal:

```bash
mailctl identity source pause ad:corp --reason "directory maintenance"
mailctl identity source resume ad:corp --reason "directory maintenance complete"
mailctl identity source retire ad:corp --reason "directory permanently retired"
```

## Active Directory

Open **Admin → Identity → Active directory**. Enter the domain, bind DN,
password, sync interval, and optional department/alias settings. Save, run
**Test connection**, then **Sync now**.

AD `objectGUID` is the immutable subject. `uSNChanged` is a cursor, not an
identity. A stale source generation is rejected before any source-owned write.
Configuration secrets are envelope-encrypted and never returned by the read API.

Verify:

```bash
mailctl ad health --json
mailctl ad sync-log --json
mailctl identity source list --json
mailctl identity conflict list --json
```

## Generic LDAP

Open **Admin → Identity → Custom LDAP**. Configure host, either LDAPS or
StartTLS (plaintext binds are unsupported), bind DN, base DN,
filter, and `ldap_sync_subject_attribute`. The subject attribute must be:

- present for every in-scope person;
- immutable for that person's lifetime;
- unique across the discovered directory; and
- returned byte-for-byte consistently.

DN and `mail` are never implicit anchors. Preview and test before selecting
**Enable sync**. Enablement requires explicit confirmation because a later
directory disable/removal can disable the local person.

Verify:

```bash
mailctl ldap health --json
mailctl ldap sync-log --json
mailctl identity conflict list --json
```

Missing or duplicate immutable subjects remain quarantined. Correct the
attribute or scope and rerun discovery; never resolve them by email.

## SCIM

Create a source-bound token with
`mailctl scim create-token --name entra --source scim:entra`. The named source
must already be active and of kind `scim`; token creation fails closed for a
paused, missing, or non-SCIM source. Store the returned secret once in the IdP;
Setjoin retains only its verifier. Every SCIM User must
carry a non-empty `externalId`, which is immutable within that exact source.

SCIM user requests must use `application/scim+json` (JSON is accepted for
compatibility). A token cannot mutate a person owned by another SCIM source.
Use `active=false` for normal deprovisioning; do not use hard deletion as a
directory replacement mechanism.

## SAML and OIDC

Configure the provider under **Admin → Identity → Auth methods**. Setjoin binds:

- OIDC: exact issuer plus `sub`;
- SAML: exact IdP entity ID plus persistent NameID.

A current member can begin a link only from a fresh AAL2 session. The callback
is bound to the same person, session digest, provider registration, and a
ten-minute expiry. The link endpoint does not enable a feature flag.

## Acceptance

Setup is complete only when:

- the source is `active` and has no attention backlog;
- every directory person has one source lifecycle link;
- zero open `person_mismatch`, `authority_mismatch`, `access_mismatch`, or
  `missing_projection` divergence remains;
- expected legacy ambiguity is explained, not ignored; and
- all three identity feature flags remain OFF until the upgrade runbook.

Continue with
[`IDENTITY_INVENTORY_AND_CONFLICTS.md`](IDENTITY_INVENTORY_AND_CONFLICTS.md).
