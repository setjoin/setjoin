# Identity Inventory and Conflicts

Use the inventory before changing a source, linking an account, or previewing a
directory-to-local transition.

## Read-only inventory

```bash
mailctl identity inventory --json
mailctl identity source list --json
mailctl identity people list --json
mailctl identity conflict list --json
mailctl identity transition list --json
```

`inventory` is aggregate-only and exits non-zero when stable blockers remain.
It contains no email address, external subject, or connector ciphertext.
`people` is an admin-only bounded view containing internal user ID, email,
lifecycle authority, source key, and link counts. External subjects are never
returned by list APIs.

The admin console shows the same jobs under **Admin → Identity → Identity
model**:

- **Sources**: source state, generation, and attention count;
- **People**: local/source lifecycle ownership and link counts;
- **Conflicts**: redacted proof failures;
- **Transitions**: current state and pending effects;
- **Identity audit**: bounded event history and reasons.

## Interpret conflict evidence

| Evidence | Meaning | Allowed action |
|---|---|---|
| `hard` | One source-scoped immutable subject identifies one person | Link only after generation and ownership checks |
| `composite` | Several soft facts suggest a person | Review only; it cannot authorize |
| `soft` | Email, UPN, alias, name, phone, or similar | Never auto-link |
| `conflict` | The subject is reserved, duplicated, or points elsewhere | Correct source data or make an explicit operator decision |

Detached links retain their source subject as a tombstone. A delayed sync,
rehire, or address reuse cannot silently move it to another person.

## Triage order

1. Record `sourceKey`, generation, candidate ID, evidence class, and correlation
   ID. Do not copy the raw external subject into tickets.
2. Check source health and pending/quarantined inbox counts.
3. Confirm the source's immutable attribute is present and unique.
4. Confirm the candidate is a member person, not a guest or mailbox-only shape.
5. Check whether the target is protected or would lose its final recovery path.
6. Correct remote data or mapping, then rerun discovery.
7. Re-read the conflict list; do not reuse a stale generation.

## Expected ambiguity

`expected_legacy_ambiguity` is not a clean bill of health. It records a legacy
shape that cannot be proven from an immutable source subject. An operator may
explain it, but normalized cutover remains blocked by every unexplained critical
divergence.

## Export evidence safely

Download a transition report from the transition table or:

```bash
curl --fail-with-body \
  -H "Authorization: Bearer $SETJOIN_TOKEN" \
  "https://mail.example.com/api/admin/identity/v2/transitions/$TRANSITION_ID/report" \
  -o "identity-transition-$TRANSITION_ID.json"
```

The report is versioned and bounded. Treat it as administrator evidence because
it contains internal user and transition IDs and the audited reason.

For a redacted cross-source inventory with no email, raw subject, profile, or
connector ciphertext:

```bash
mailctl identity inventory export --output identity-inventory.json
```

The CLI verifies the exact response `Digest` before atomically creating the
mode-0600 file. The report is capped at 10,000 people and includes schema
version, source/link/conflict counts, redaction counts, and a canonical report
checksum.

## Stop conditions

Stop and investigate if:

- the same immutable subject appears for two people;
- a critical divergence count increases after a no-op sync;
- the source generation changes during review;
- the candidate is protected and no independent approval exists;
- a source cursor advances while an entry is pending or retryable; or
- a list or report contains a raw connector secret or external subject.

Next: [`IDENTITY_TRANSITION.md`](IDENTITY_TRANSITION.md).
