# Directory-to-Local Identity Transition

Detach one AD, LDAP, or SCIM lifecycle source while preserving the same
`users.id`, mailbox, content ownership, collaboration history, and independent
SAML/OIDC authentication links.

## Safety contract

A transition is refused unless:

- `feature.identity_model_v2` and `feature.identity_transitions` are explicitly
  enabled for the rehearsal;
- the target has exactly one active source lifecycle link;
- a verified local credential, passkey, or independent authentication link
  remains;
- every authorization, approval, execution, or rollback command consumes its
  own transition-scoped elevation created from a fresh AAL2 session;
- the exact preview digest and generations still match;
- protected users have a separate approved request; and
- the source has no unresolved critical divergence.

Preview is read-only. Execute is transactional. Session revocation, subscriber
notice, and LiveKit eviction are durable post-commit effects that continue
draining even if the feature flags are later disabled.

## Preview

Use a fresh UUID and an explicit reason:

```bash
mailctl identity transition preview \
  --person "$USER_ID" \
  --reason "Approved retirement of corporate AD" \
  --idempotency-key "$IDEMPOTENCY_UUID" \
  --json
```

Record `transitionId`, `previewDigest`, `sourceGeneration`,
`lifecycleGeneration`, `protected`, and `recoveryReady`. A preview expires on
generation drift and must never be edited by hand.

The equivalent REST request requires the same reason in the body and
`X-Audit-Reason` header:

```bash
curl --fail-with-body -X POST \
  -H "Authorization: Bearer $SETJOIN_TOKEN" \
  -H "Content-Type: application/json" \
  -H "X-Audit-Reason: Approved retirement of corporate AD" \
  -H "Idempotency-Key: $IDEMPOTENCY_UUID" \
  -d "{\"userId\":\"$USER_ID\",\"reason\":\"Approved retirement of corporate AD\",\"idempotencyKey\":\"$IDEMPOTENCY_UUID\"}" \
  https://mail.example.com/api/admin/identity/v2/transitions/preview
```

## Authorize, request, and execute

First exchange a durable challenge using a currently authenticated fresh AAL2
session. The returned elevation is valid for one command only:

```bash
mailctl identity transition authorize "$TRANSITION_ID" \
  --preview-digest "$PREVIEW_DIGEST" \
  --json
```

Use that elevation to request authorization:

```bash
mailctl identity transition start "$TRANSITION_ID" \
  --preview-digest "$PREVIEW_DIGEST" \
  --elevation "$REQUEST_ELEVATION_ID" \
  --reason "Approved retirement of corporate AD" \
  --json
```

For a protected target, a different eligible break-glass administrator signs in,
runs `transition authorize`, and consumes that separate elevation with:

```bash
mailctl identity transition approve "$TRANSITION_ID" \
  --preview-digest "$PREVIEW_DIGEST" \
  --elevation "$APPROVER_ELEVATION_ID" \
  --reason "Independent approval of directory retirement" \
  --json
```

The requester then performs a new step-up and executes:

```bash
mailctl identity transition authorize "$TRANSITION_ID" \
  --preview-digest "$PREVIEW_DIGEST" \
  --json

mailctl identity transition execute "$TRANSITION_ID" \
  --preview-digest "$PREVIEW_DIGEST" \
  --elevation "$EXECUTION_ELEVATION_ID" \
  --reason "Approved retirement of corporate AD" \
  --approval-request "$APPROVAL_ID" \
  --json
```

An ordinary session token is never accepted as an elevation, and the request
elevation cannot be reused for execute. Omit `--approval-request` only for an
unprotected transition. Success means durable acceptance, not necessarily
terminal completion.

## Observe completion

```bash
mailctl identity transition watch "$TRANSITION_ID" --json
mailctl identity people show "$USER_ID" --json
```

Expected sequence:

```text
previewed → authorized → executing → authority_committed → effects_pending → completed
```

The person must now show `lifecycleAuthority=local`; the old provisioning link
must be `detached`; the immutable subject remains reserved; and independent auth
links remain active.

## Verify the outcome

1. Log in with the approved remaining method.
2. Confirm old refresh/access sessions no longer work.
3. Confirm the old IdP subject cannot authenticate.
4. Confirm active Meet/LiveKit sessions are evicted.
5. Confirm mail, Drive, Chat, Meet, audit, groups, and delegated resources still
   reference the same internal user ID.
6. Download the transition report.

## Failure handling

- `BZ229`/`BZ235`: state moved; discard the preview and start again.
- `BZ236`: approval or elevation is missing/stale; obtain a new independent
  approval and fresh AAL2.
- `BZ237`: enroll and verify another recovery/authentication method.
- `failed_recoverable`: do not replay the transition. Repair the dependency,
  then use the named effect ID with `transition retry`; failed effects are never
  auto-retried.
- `failed_precommit`: no authority change committed; correct the preflight and
  create a new preview.

Never edit lifecycle/link rows directly and never clear the old source subject.
