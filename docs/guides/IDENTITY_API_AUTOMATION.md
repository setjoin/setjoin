# Identity API and Automation

Automate read-only inventory and bounded transition/canary operations without
placing credentials, assertions, or external subjects in scripts.

## Authentication and output

Run `mailctl login https://mail.example.com` interactively. Prefer `--json` for
automation:

```bash
mailctl identity inventory --json
mailctl identity doctor --json
mailctl identity upgrade status --json
```

Do not pass access/refresh tokens on the command line. Protect the mailctl
credential file and use a dedicated governed admin account.

## Read-only commands

```text
mailctl identity inventory
mailctl identity source list
mailctl identity people list
mailctl identity conflict list
mailctl identity transition list
mailctl identity upgrade status
mailctl identity upgrade preflight
```

`inventory` exits non-zero when blockers remain. Other list responses are
bounded to 200 items and do not return raw external subjects.

## Mutation contract

Every identity mutation requires:

- an audited reason of 1–1024 bytes with no control characters;
- an exact generation or preview digest;
- a governed identity-write permission;
- fresh AAL2 where the operation changes a person; and
- independent approval for a protected target.

For REST, the body `reason` and `X-Audit-Reason` must match exactly.

## Preview and execute

```bash
mailctl identity transition preview \
  --person "$USER_ID" \
  --reason "$REASON" \
  --idempotency-key "$UUID" \
  --json > preview.json

mailctl identity transition authorize "$TRANSITION_ID" \
  --preview-digest "$PREVIEW_DIGEST" \
  --json > elevation.json

mailctl identity transition start "$TRANSITION_ID" \
  --preview-digest "$PREVIEW_DIGEST" \
  --elevation "$REQUEST_ELEVATION_ID" \
  --reason "$REASON" \
  --json
```

Every later approve, deny, execute, or rollback command needs a newly completed
step-up and its own one-use elevation. A protected request also needs a
different administrator's approval before the requester can execute. Reuse an
idempotency key only for the byte-equivalent operation; `BZ240` means a key was
reused for different canonical input.

## Canary and rollback

```bash
mailctl identity upgrade shadow --source "$SOURCE_KEY" --json

mailctl identity upgrade canary enable \
  --source "$SOURCE_KEY" \
  --expected-generation "$GENERATION" \
  --users "$CSV_USER_IDS" \
  --reason "$REASON" \
  --json

mailctl identity upgrade rollback --reason "$REASON" --json
```

Treat a successful execute response as durable acceptance. Poll
`identity transition watch "$TRANSITION_ID"`; do not assume terminal completion
until state is `completed`.

## Durable jobs and diagnostics

Backfill start requires the exact stable preflight checksum and one UUID:

```bash
mailctl identity upgrade backfill start \
  --preflight-checksum "$PREFLIGHT_SHA256" \
  --idempotency-key "$UUID" \
  --reason "$REASON" --json
mailctl identity job watch "$JOB_ID" --timeout 30m --json
mailctl identity job results "$JOB_ID" --after 0 --limit 500 --json
```

Creation success means durable acceptance. `completed_with_failures` exits 1;
cancel is honored only between batches and never reverses committed people.
Diagnostics additionally require `audit.export`, one source or transition
scope, and a lookback from one second through 24 hours. The CLI writes only
after matching both the job's SHA-256 and the wire `Digest`.

## REST example

```bash
curl --fail-with-body -X POST \
  -H "Authorization: Bearer $SETJOIN_TOKEN" \
  -H "Content-Type: application/json" \
  -H "X-Audit-Reason: $REASON" \
  -H "Idempotency-Key: $UUID" \
  -d @preview-request.json \
  https://mail.example.com/api/admin/identity/v2/transitions/preview
```

Construct `preview-request.json` with a normal JSON tool. Do not interpolate
untrusted text into a shell command.

## Error handling

Parse RFC 7807 fields and the BZ code; never match human prose.

| Code | Automation action |
|---|---|
| `BZ228` | Correct bounded input/source configuration |
| `BZ229` | Re-read source/person state and rebuild the request |
| `BZ230` | Stop; immutable subject is reserved |
| `BZ234` | Resolve the named preflight blocker |
| `BZ235` | Discard stale preview/generation and preview again |
| `BZ236` | Obtain fresh AAL2/independent approval |
| `BZ237` | Enroll a remaining login/recovery method |
| `BZ239` | Route the excluded account class to its owning workflow |
| `BZ240` | Use a new idempotency key for changed input |

## Data boundary

Automation logs may retain source key, generation, internal user/transition ID,
state, BZ code, correlation ID, and aggregate counts. They must not retain raw
IdP assertions, external subjects, connector secrets/ciphertext, access tokens,
personal profile payloads, or customer content.
