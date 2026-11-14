# F07 MDM HTTP oracle (#310)

Eleven routes (`mdm` inventory slice) run through the HTTP front door. The case
table is `bins/gateway/tests/devices.rs`; `devices_oracle/plan.rs` defines requests
and fixtures. Two identities have distinct user/mailbox IDs and domains. Every
recording includes wire status/headers/body, before/after device and policy rows,
audit and `device_policy`/`conditional_access` notifications. The companion
`*-row-effects.json` is the mutator effect oracle. Only generated identities,
dates/checksums and ID-dependent wire lengths are normalized; problem bodies and
JSON field order remain byte-exact. Domain IDs embedded in denial audit text are
normalized too.

Normal replay requires the disposable schema and owner/app DSNs:

```sh
cd server-rust
REQUIRE_DB=1 cargo test --locked -p setjoin-gateway --test devices -- --test-threads=1
REQUIRE_DB=1 cargo test --locked -p setjoin-gateway --test devices_startup -- --test-threads=1
```

Replay sets no Go upstream and asserts the F07 proxy counter stays zero. Eleven
HTTP status mutants and four real database mutants (tenant predicate, audit,
notify, duplicate event) must be rejected. Startup tests run the executable with
the bundled inventory, global kill switch and per-route rollback; later F07
slices still forward to Go.

Recording uses a frozen `go build -cover` mailserver binary. Set
`GOFREE_RECORD_GO_BINARY` to its absolute path and `GOFREE_GO_SOURCE` to its
40-character commit. The common Go recorder mounts it read-only in the CI image;
`GOFREE_GO_COVERAGE_DIR` optionally retains Go profiles. Use the same exact test
selectors, excluding mutants/faults; `GOFREE_VERIFY_GO=1` rechecks existing
recordings without overwriting. Goldens are immutable. Each owned recorder
container has prefix `gofree-devices1-http`; `GOFREE_RESOURCE_LEDGER` records its
lifecycle. Serial execution is required: fixtures temporarily replace global MDM
policies, and fault tests temporarily replace shared DB objects.

Parity: policy writes require global `mam.write`; MDM device reads/wipe carry
the live grant's domain scope. The lockdown console and policy reads are
org-wide even for domain-scoped administrators. Read routes without validated
query fields record ignored malformed input or a permission denial. Policy
create/update/delete/reorder each record repeated calls, including duplicate
create and missing-after-delete behavior. The two `transition_rls*` cases keep
`setjoin_app`: Go's missing user GUC makes even an admin's own-device transition
fail with 500 and no committed effects. Rust preserves this through an
invoker-rights scope wrapper. Explicit `foreign-target` cases use a domain-scoped
administrator against another domain's user/device; the lockdown console allows
them in Go, including mutation. These replace own-target `foreign` fixtures as
the catalog's cross-domain cases; the original immutable recordings remain.
No accepted divergences.

SQL seam: `rust_mdm_policy.pg`, `rust_device_enroll_transition.pg` and the existing
device lifecycle/wipe/RLS suites. MAM (#311), offline and MDM notify (#312), and
request-time device/CAE gates (#187) remain outside this ticket.
