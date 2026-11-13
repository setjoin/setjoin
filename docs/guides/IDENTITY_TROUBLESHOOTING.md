# Identity Troubleshooting

Diagnose identity failures from aggregate health and durable state before
changing configuration.

## Quick checks

```bash
mailctl health check
mailctl identity doctor --json
mailctl identity inventory --json
mailctl identity upgrade status --json
mailctl identity source list --json
mailctl identity conflict list --json
mailctl identity transition list --json
```

Check `/metrics` for the eight `gateway_identity_*` gauges. If the collector is
down, treat all other identity gauges as stale.

## Symptoms

### Source needs attention

Check AD/LDAP health and sync logs. A paused/error source or non-empty
pending/quarantined inbox requires correction before cutover. Do not advance or
edit cursors manually.

### LDAP entry is quarantined

Confirm `ldap_sync_subject_attribute` exists and is unique for every in-scope
entry. DN and email are not fallbacks. Narrow the search filter or correct the
directory, rerun discovery, and verify the same source generation.

### SCIM request is rejected

Confirm the bearer token is active and source-bound, `externalId` is present,
and the person belongs to that source. Reusing another source's external ID is
allowed only because the source ID scopes it; moving a retained exact subject is
not.

### SAML/OIDC login resolves the wrong path

Stop normalized admission. Verify exact issuer/entity ID and subject/NameID,
provider key binding, source read mode, and cohort membership. Never repair by
editing email or the legacy scalar pair.

### Transition preview is stale

`BZ229` or `BZ235` means a generation, mapping, link, recovery, or approval fact
changed. Discard the preview and create a new one.

### Transition stays pending

Read the report and identify the exact incomplete effect. Follow
[`IDENTITY_RECOVERY.md`](IDENTITY_RECOVERY.md). Workers reclaim stale `running`
effects and retry boundedly; do not replay authority.

### Backfill job stops or partially fails

Read durable state and exact person results:

```bash
mailctl identity job show "$JOB_ID" --json
mailctl identity job results "$JOB_ID" --after 0 --limit 500 --json
```

`completed_with_failures` is not success. Resolve each `blocked`/`failed`
person, generate a fresh preflight checksum, and start a genuinely new job with
a new idempotency UUID. A watch timeout does not cancel accepted server work.

### Support needs a diagnostic bundle

Create the smallest authorized scope and time window:

```bash
mailctl identity diagnostics \
  --source "$SOURCE_KEY" --since 1h \
  --reason "Support case CASE-123" \
  --output identity-diagnostic.zip
```

The CLI verifies the completed job checksum and response `Digest` before an
atomic mode-0600 write. The ZIP contains only a versioned manifest and bounded
JSONL evidence; delete it through the diagnostics API after the handoff.

### User cannot sign in after detach

Use independent administrator recovery. Verify the remaining local/passkey/auth
link and session state. Do not delete the detached tombstone or re-enable the old
source as a shortcut.

## BZ map

The canonical catalog is
[`reducer-error-codes.md`](../reducer-error-codes.md#BZ228). Common identity
codes:

- `BZ230`: source subject collision/tombstone;
- `BZ232`: eight active authentication links already exist;
- `BZ233`: lifecycle authority/link mismatch;
- `BZ234`: preflight failed;
- `BZ236`: approval/elevation invalid;
- `BZ237`: final recovery route would be removed;
- `BZ239`: unsupported account class.

## Safe evidence

Keep IDs, generations, source keys, timestamps, counts, BZ/correlation codes,
redacted explanations, and transition reports. Remove tokens, assertions,
subjects, secrets, ciphertext, profile values, email contents, and customer
files.

## When to rollback

Invoke global rollback when critical divergence is non-zero, a canary subject
resolves differently, an unexplained access mismatch appears, or the collector
cannot prove safe state. See
[`IDENTITY_UPGRADE_AND_ROLLBACK.md`](IDENTITY_UPGRADE_AND_ROLLBACK.md).
