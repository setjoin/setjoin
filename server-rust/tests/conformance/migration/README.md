# F05 migration provider oracle (#431, #446)

`migration_runner` records the actual frozen Go front door plus one settled worker
run. Replay uses Rust only and asserts its proxied-to-Go count is zero. It compares
HTTP bytes/headers, job/progress/checkpoints/source operations, messages/tags,
calendar/contact projections, notification payloads, audit and S3 requests/content.
Fixtures own two accounts and restore global profiles/toggles after each case.

Use the assigned disposable schema and all five DSNs with `REQUIRE_DB=1`:

```
cargo test --locked -p setjoin-gateway --test migration_runner --test migration_providers --test migration_startup --test migration_runner_startup -- --test-threads=1
```

Recording sets `GOFREE_RECORD_GO_BINARY` to a covered frozen Go binary and
`GOFREE_GO_SOURCE` to its full source SHA. Set an owned `GOFREE_RESOURCE_PREFIX`.
The CI image mounts the source read-only and the shared Go module cache. Existing
goldens are compared, never overwritten; `GOFREE_VERIFY_GO=1` also requires an
existing recording. Unset recording variables for replay. Status mutants must fail
the same comparison. F05's audit/notify/tenant/state mutants are in `mailboxes`.

Provider fixture selection uses the `provider_` test namespace explicitly; legacy
EWS/M365 rejection labels retain their original plans. Provider cases run real HTTPS fake SOAP, Graph and OAuth endpoints.
Their ephemeral CA lives under `test-results/gofree-mbox7-providers-*` so Go can
trust it with `SSL_CERT_FILE` under `/src`. Isolated DNS at `127.0.0.86:53` and
`GOFREE_ORACLE_RESOLV_CONF` direct every provider hostname to the fake endpoint:
recording binds the fixture public IP on port 443, replay `127.0.0.87:443`.
Serial execution and privileges to bind these ports are required. No Microsoft
request is made. The fixtures drop listener tasks, files and owned DB rows.
NTLM transcripts normalize random cryptographic frames to scheme/message type;
provider request comparison preserves selected resource, mailbox anchor and
immutable-ID preference. S3 compares the actual MIME and uploaded ICS/VCF bytes.

Calendar and Graph contact cases deliberately preserve frozen Go failures:
identity calendar projection expects a nonexistent `created` result, and Graph
contact conversion lacks UID. Contacts-only EWS and file uploads exercise positive
projections independently. See `crates/domains/mailboxes/MICROSOFT.md` for the
worker/transaction contract and documented source quirks.
