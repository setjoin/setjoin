# Drive ACL integration

Drive node ACLs add exact, reducer-authoritative permissions below a Drive
space. They are rollout-gated and disabled by default. Existing space-role
clients continue to work until an operator explicitly creates an ACL-mode pilot
space and enables the read/write flags.

## Prerequisites and discovery

- Use a current client that understands ACL epoch and access invalidation.
- Send bearer credentials only over the deployment's trusted HTTPS origin.
- Treat every node, grant, epoch, and subject ID as a decimal string on the
  wire. Do not coerce it to a JavaScript `number`.
- `feature.drive_node_acl_reads` and `feature.drive_node_acl_writes` must be
  enabled only through the reviewed pilot procedure. Group subjects, access
  requests, and emergency access have separate flags.

Read the exact access projection before presenting an action:

```bash
curl --fail-with-body \
  -H "Authorization: Bearer $SETJOIN_TOKEN" \
  "$SETJOIN_ORIGIN/api/drive/nodes/$NODE_ID/access"
```

The response supplies the current `epoch`, exact `capabilities`, bounded
sources, whether the node is `traverseOnly`, and whether the caller can manage
access. Never infer a capability from the folder path, space role, or UI state.

## Preview, grant, and revoke

Preview a direct Viewer grant first:

```bash
curl --fail-with-body -X POST \
  -H "Authorization: Bearer $SETJOIN_TOKEN" \
  -H 'Content-Type: application/json' \
  "$SETJOIN_ORIGIN/api/drive/nodes/$NODE_ID/acl/preview" \
  --data "{\"subjectKind\":\"user\",\"subjectId\":\"$SUBJECT_ID\",\"preset\":\"viewer\",\"scope\":\"subtree\",\"reason\":\"Quarterly project access\"}"
```

After the user confirms the impact, commit with the epoch returned by the
latest access read and one UUID retained across retries:

```bash
IDEMPOTENCY_KEY="$(uuidgen | tr '[:upper:]' '[:lower:]')"
curl --fail-with-body -X POST \
  -H "Authorization: Bearer $SETJOIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -H "Idempotency-Key: $IDEMPOTENCY_KEY" \
  "$SETJOIN_ORIGIN/api/drive/nodes/$NODE_ID/acl" \
  --data "{\"subjectKind\":\"user\",\"subjectId\":\"$SUBJECT_ID\",\"preset\":\"viewer\",\"scope\":\"subtree\",\"reason\":\"Quarterly project access\",\"expectedEpoch\":\"$ACL_EPOCH\",\"idempotencyKey\":\"$IDEMPOTENCY_KEY\"}"
```

The header and body UUID must match exactly. Retry the identical header and body
after a timeout. A changed body needs a new UUID and a fresh epoch. Revoke uses
the latest epoch and a non-empty audit reason; a retry by the same still-authorized
revoker returns the existing terminal result without duplicating audit or
invalidation rows:

```bash
curl --fail-with-body -X DELETE \
  -H "Authorization: Bearer $SETJOIN_TOKEN" \
  -H 'Content-Type: application/json' \
  "$SETJOIN_ORIGIN/api/drive/acl-grants/$GRANT_ID" \
  --data "{\"expectedEpoch\":\"$ACL_EPOCH\",\"reason\":\"Project access ended\"}"
```

The public presets are `viewer`, `contributor`, `editor`, and
`folder_manager`. Public clients do not send arbitrary capability arrays.

## Three independent currencies

| Currency | Meaning | Recovery |
|---|---|---|
| content sequence | file/tree content changes | resume the ordinary Drive change feed |
| ACL epoch | exact authorization generation for a space | re-read access and re-present mutation impact |
| invalidation cursor | opaque managed-client revocation stream | page normally; on `fullReconcile`, discard the cursor and take an epoch-consistent visibility snapshot |

Never reuse one currency as another. A successful content sync does not prove
the local cache is still authorized.

Managed clients page:

```text
GET /api/drive/access-invalidations?space=<decimal>&cursor=<opaque-uuid>&max=200
GET /api/drive/visibility-snapshot?space=<decimal>&epoch=<decimal>&after=<decimal>&max=500
```

Apply invalidations before exposing cached bytes. Unknown/pruned cursors and
fan-out overflow require a full visibility reconcile. Quarantine anything no
longer visible; do not wait for a later content event.

## Failure handling

| Status | Meaning | Required client action |
|---:|---|---|
| 404 | target absent or inaccessible, intentionally oracle-identical | stop and reveal no additional metadata |
| 409 | stale epoch, changed request binding, or snapshot race | fetch current access once; require confirmation again |
| 422 | malformed/unsupported ACL input | correct the named input; do not retry unchanged |
| 429 | bounded mutation rate reached | honor `Retry-After` |
| 503 | closure/invalidation safety stop | keep the space unavailable and give the correlation ID to an operator |

Chat/Meet-bound spaces reject ad-hoc ACL grants. Guest authority remains capped
by the Guest profile. Secure/GxP/export policy can only narrow an ACL result.
Old clients that cannot consume invalidations must not enter a narrowed ACL-mode
space.

## Disposable first success

From a development checkout with local PostgreSQL prerequisites:

```bash
RUN_PREFIX=driveacl-local bash scripts/drive-acl-smoke.sh all
RUN_PREFIX=driveacl-selftest bash scripts/drive-acl-smoke.sh self-test
```

The first command creates a scratch database, seeds synthetic identities and a
file, grants and verifies Viewer access, revokes it, verifies removal, and drops
the database. The self-test plants an inconsistent active grant and proves the
verification step fails. Neither command starts or changes a production service.
