# Identity Transition Recovery

Recover an accepted transition without replaying authority changes or weakening
the identity boundary.

## First response

1. Record the transition ID and correlation ID.
2. Do not rerun `transition execute` or invent a new transition.
3. Read current state:

   ```bash
   mailctl identity transition show "$TRANSITION_ID" --json
   mailctl identity people show "$USER_ID" --json
   mailctl identity upgrade status --json
   ```

4. Download the transition report from the admin console.
5. Check identity alerts and worker logs using the same transition ID.

## State-specific recovery

| State | Meaning | Action |
|---|---|---|
| `previewed` | No authority mutation | Correct the blocker and preview again |
| `authority_committed` | Database truth changed; effects are not all queued/observed | Keep flags stable and inspect worker startup |
| `effects_pending` | Claimed effects are still converging | Wait; the worker may reclaim only stale `running` work |
| `completed` | Authority and effects converged | Verify login, revocation, content IDs, and report |
| `failed_precommit` | Transaction did not commit | Correct preflight/generation/approval and make a new preview |
| `failed_recoverable` | Authority may be committed; a named effect failed | Repair the dependency, then explicitly retry only that effect ID or use the reviewed rollback procedure |

## Effect recovery

### Authentication sessions

Confirm the authserver is reachable and refresh-family revocation is processing.
Never mint a replacement token for the old external subject.

### LiveKit sessions

Confirm LiveKit credentials and room reachability. A transition with zero
matching participants completes without requiring LiveKit. `not found` is a
successful idempotent eviction.

### Subscriber notice

Repair the notification channel, read the current generation, then request one
exact retry:

```bash
mailctl identity transition retry "$TRANSITION_ID" \
  --effect "$EFFECT_ID" \
  --expected-generation "$TRANSITION_GENERATION" \
  --reason "Notification dependency restored"
```

Failed effects are never auto-claimed. Transition authority does not roll back
merely because delivery is delayed; the report must continue showing the
outstanding obligation.

## Lockout recovery

Use an independent administrator and the normal account-recovery flow. Do not
reattach a detached subject by deleting its tombstone. If the member has no
verified remaining method, stop: that condition should have been rejected as
`BZ237`, and bypassing it creates an account-takeover path.

## Rollback

Global read-path rollback is covered by
[`IDENTITY_UPGRADE_AND_ROLLBACK.md`](IDENTITY_UPGRADE_AND_ROLLBACK.md). It turns
off normalized admission and clears canary cohorts but preserves links, events,
transitions, and pending effect evidence. Already accepted effects still drain.

## Source-to-source migration recovery

AD, LDAP, and SCIM provisioning authority may move between two already verified,
active links for the same durable Setjoin person. The preview must name the exact
target link ID. Execution preserves `users.id`, every mailbox ID, mailbox ownership,
addresses, and lifecycle address claims byte-for-byte; it detaches the former link,
makes the target link lifecycle authority, and fences old sessions.

Use the admin Identity console to preview and authorize the exact target link. Do
not detach the mailbox or create a replacement user. A recoverable post-commit effect
failure uses the same independently approved rollback flow. Rollback reactivates the
original link, detaches the replacement link, restores source attributes and grants,
and rechecks the mailbox/address invariant before committing. A new login, subscriber
notice, expired four-hour boundary, source-generation drift, or link drift closes
rollback; continue forward recovery instead.

`identity_source_rebind.pg` is the executable regression: it performs AD→SCIM and
the exact approved rollback while asserting the mailbox/address snapshot remains
byte-identical in both directions.

## Escalation bundle

Provide only:

- schema version;
- transition/correlation ID;
- source key and generation;
- transition state and named effect states;
- BZ code;
- sanitized health/alert output; and
- the bounded transition report.

Do not provide connector ciphertext, bearer/refresh tokens, raw IdP assertions,
external subjects, customer messages, or database dumps.
