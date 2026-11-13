# Guests coverage receipt (#272)

Frozen production source: `1d9d2b58caa0c73bac2eba9331414c8bf411b1e8`.
The HTTP binary SHA-256 is
`2817e2b7ac2cfa6e49f759a4514904d9648ca44851d2818a8ffa743938f86710`;
the tagged worker recorder binary is
`7ae57e371186c0eb2112da63c6cc78fbf6863bda5754c1fdfdf70394c9b9e423`.
The worker hook adds observation only; production Go remains frozen.

All 112 original HTTP selectors and six worker ticks were compared again with
the existing immutable recordings. Another 22 HTTP selectors were recorded and
replayed for malformed bodies, policy fields, feature admission and query limits.
The ordinary Rust target contains 164 tests, including status and effect mutants.
The two executable startup tests check registrations, both rollback switches and
the named worker lifecycle. The route catalog selects qualified recordings;
historical unqualified files remain provenance, not comparison inputs.

`go tool covdata textfmt` and `go tool covdata func` measured these Go
statement/block counts on 2026-11-01. They are not branch-coverage percentages.
Only Guests source is included below; unrelated admin/approval handlers are
excluded from the denominator.

| Frozen Go source | Covered / statements | Percent |
| --- | ---: | ---: |
| `internal/admin/admin_guest_profiles.go` | 105 / 131 | 80.2% |
| `internal/admin/admin_guests.go` | 280 / 378 | 74.1% |
| `internal/approval/guest_invite.go` | 36 / 40 | 90.0% |
| `internal/approval/handler.go:440` (`decideGuestInvite` only) | 17 / 21 | 81.0% |
| `internal/guestinvite/invite.go` | 41 / 50 | 82.0% |
| `internal/guestlifecycle/worker.go` | 56 / 86 | 65.1% |

The retained local evidence is `test-results/gofree-guests1/`: source archive,
binary receipts, `go-coverage/`, `go-coverage.out`,
`go-coverage-functions.txt`, `go-uncovered-blocks.txt`, per-selector logs and
the required Rust guard log. Coverage is reproducible by supplying
`GOFREE_GO_COVERAGE_DIR` during exact-selector recording or verification;
`GOFREE_VERIFY_GO=1` compares existing files without replacing them. Worker
recording also supplies `-test.gocoverdir` to flush its counters.

## Unreached Go error branches

The following inventory records why branches cannot be reached under the stated
recorder conditions. It does not claim they are impossible in a failed production
process. Ordinary request-validation branches are exercised, rather than
classified as infrastructure failures. Line references below are to frozen Go.

| Branches | Reason / boundary evidence |
| --- | --- |
| Profile `Gate:79`, `authorize:203–220`; guest `authorize:757–779`; member submission missing claims at `guest_invite.go:31` | These repeat admission already enforced by the registered auth/console middleware. A real routed request with missing permission, feature OFF or absent identity is rejected before these inner guards. Cross-scope/permission goldens and feature-OFF recordings exercise the observable boundary; nil handler dependencies are not constructed by the daemon. |
| `admin_guests.go:107–109` generic email-validation error | Frozen `ValidateAndCanonicalizeEmail` returns its typed validation error for invalid input. The preceding typed-error arm is recorded. The generic arm would require replacing that validator. |
| Profile set begin/commit at `159–162`, `179–182`; guest begin/commit/fence/prelock at `118–121`, `208–211`, `266–269`, `294–297`, `488–491`, `514–517`, `590–598`, `608–611`, `617–620`; approval decision begin/commit | The recorder uses a live owner pool and canonical schema; it does not terminate connections or inject transport loss during commit. These branches require pool/connection failures, rather than another request value. Foundation transaction/unknown-outcome tests exercise Rust's failure boundary; the adapter never forwards after attempting a command. |
| Guest SQL/scan errors at `125–128`, `144–145`, `175–176`, `195–196`, `277–280`, `291–292`, `331–334`, `341–342`, `362–363`, `458–461`, `502–505`, `511–512`, `662–684`, `742–745`, `753`; approval `handler.go:451–453` | These are unclassified database/row-stream failures under valid canonical schema and seeded rows. They need connection faults, invalid result types or replacement reducers. Classified reducer errors are recorded (including stale invite, inaccessible target and repeated mutation). Profile post-write read failure and invitation metadata failure have explicit rollback recordings. |
| Guest profile/provision JSON errors at `151–154`, `181–188`; revoke default result at `305–306` | Canonical reducers return valid JSON, a positive provisioned user ID, and the documented revoke result enum. These arms require a substituted/corrupt reducer, not an accepted request. |

No alternate canonical reducer path is left unrecorded: profiles set/get/delete,
status and revocation, assignment/transfer, allowlist, direct/repeated/recovery
invitation, member request and approval apply/deny all have effect observations.

## Other structural gaps

Helper gaps include kernel entropy failure, broken metadata queries, invalid
configured sender, malformed recipient passed directly to the mail helper, and
logger/dependency nil fallbacks. The daemon constructs the dependencies and the
HTTP validator supplies a valid recipient; the recorder does not replace the OS
random source. Invalid public URL/TTL and failed object storage have recorded
rollback or committed-delivery-failure observations.

The Go worker oracle intentionally invokes one tick, not the hour-long scheduler;
`Run`/its timer dispatch therefore contributes uncovered statements. Native
startup/cancellation is checked by `guests_startup`. Six ticks cover natural
expiry with admission OFF, SFU success/absence, horizon completion, retry and
dead-letter. Database claim/update failures and worker nil-dependency fallbacks
are not injected into frozen Go. The absence/success cadence and retry effects
are compared with actual HTTP JWT/protobuf observations.

No response or business-effect divergence is accepted. Foundation recovery
receipts are documented operational metadata and excluded from the Go business
effect comparison.
