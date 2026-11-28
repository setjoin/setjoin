# F12 Part B HTTP oracle (#268)

The public seam is the front door at `/api/chat/*`; inventory paths omit `/api`.
Go is frozen. Record each new case once through the actual Go executable and
replay through the production Rust adapter with no Go upstream. Use the app
credential and divergent user/mailbox IDs. Observe status, headers, body,
committed business rows, audit, sequence and commit-ordered notifications.

| Registration | Behaviour under test |
| --- | --- |
| GET /chat/saves | Personal saves; current membership hides departed channels. No request inputs. |
| POST /chat/messages/{id}/save | Personal toggle; unsave remains possible after deletion/departure. |
| PATCH /chat/messages/{id} | Author edit, revision and sequence; permission/content/JSON failures. |
| DELETE /chat/messages/{id} | Author/moderator soft deletion, retained evidence and sequence. |
| POST /chat/messages/{id}/reactions | Membership-scoped emoji toggle and notification. |
| POST /chat/messages/{id}/pin | Channel curation toggle, permission and replay sequence. |
| GET /chat/messages/{id}/thread | Root/replies, membership and invalid message ID. |
| GET /chat/my-threads | Current membership, replies/mentions, optional limit parsing. |
| GET /chat/search | Required query, numeric filters, Han substring and Latin full text. |
| GET /chat/scheduled | Caller-owned pending/failed actions; no request inputs. |
| DELETE /chat/scheduled/{actionId} | Atomic owner/status cancellation; UUID parsing and anti-oracle errors. |
| POST /chat/polls/{id}/vote | Single/multiple option semantics and membership. |
| POST /chat/polls/{id}/close | Creator/moderator authority; repeated closure. |
| GET /chat/polls/{id}/results | Membership-scoped non-anonymous voter projection. |
| GET /chat/presence | Process-local live connection counts; raw trimmed response keys. |
| POST /chat/messages/{id}/translate | Native since #271; recordings and ledger in `../static1/`. |
| GET /chat/unfurl/image/{sha256} | Chat-capability gate, global successful preview-cache ownership and untrusted object headers. |

`* /chat/` is the Go sub-router mount, not a wildcard Rust handler. Unknown
requests continue to Go under ARCH-027. Each concrete route needs its recorded
success, foreign actor and invalid-input observation; writes also need repeats
and committed effects. Where Go deliberately accepts ignored input or returns
an empty self-scoped collection, preserve and document that observation rather
than inventing a denial or validation failure.

Recording environment: `GOFREE_RECORD_GO_BINARY`, `GOFREE_GO_SOURCE`, optional
`GOFREE_GO_COVERAGE_DIR`; `GOFREE_RESOURCE_PREFIX=gofree-chat3` and an existing
`GOFREE_RESOURCE_LEDGER`. Ordinary replay clears recording variables and uses
`REQUIRE_DB=1`, `TEST_DB_DSN`, `DB_DIRECT_DSN`, `DB_APP_DSN`. Run serially.

The actual frozen `chat_link_preview_image_owner` reducer checks only for a
successful global preview-cache row referencing the hash. It takes no user ID
and checks no channel membership. Preserve that behaviour; the Go handler's
comment is broader than its SQL. An authenticated Chat-capable foreign member
can fetch that same cached image. Presence is likewise an organization-wide
coarse signal for members; its guest restriction remains with the deferred
guest admission chain.

ScheduledAction observations normalize the generated UUID in `actionId`, row IDs
and `dedup_key`, including older immutable recordings at load time; ownership,
status, payload, errors and business effects remain compared.

Image recordings use a signed fake S3 peer and an active SVG to verify sandbox
headers. An unrelated Go startup multipart listing gets its own empty inventory
response. Image GET signatures remain checked; immutable recordings cover HEAD,
ignored Range, a larger chunked response, missing cache and missing object.

Additional wire cases retain raw payload JSON separately from parsed observations
to catch number rounding and escaping. Decoder, encoded mount/path, language,
feature-OFF and entitlement-denial cases run through the same HTTP seam. The
entitlement case enables full routine auditing temporarily and restores its prior
policy; its row recording includes the independent `app_blocked` act.

Qualification uses the additive `v2-*` corpus, which records the required
registration request metadata, top-level core audit, full before/after snapshots
and notifications for reads as well as writes. Earlier immutable observations
remain unchanged. `wireMethod` distinguishes HEAD from its GET registration.
All fifteen qualified entries default ON, with a real status mutant per entry
and bundled-inventory replay. Both rollback switches preserve original bytes;
presence/translation/the mount retain explicit forward checks. Search recordings
also cover malformed `in`, `from` and `before` filters.

The six `deferred-*` files record actual frozen-Go presence/translation floors.
`chat_deferred_recorded` ordinarily checks forwarding bytes, recorded response
and the F12 proxy counter, not native provider/presence execution. Translation's
recorded fake-provider boundary independently observes the committed egress
audit before accepting the request. Presence's foreign member is intentionally
allowed the same coarse signal. Keep these routes OFF until Assist/config-secret
#271 and live WebSocket/SSE registries #318/#319 are available.

Image fault recordings retain the bytes copied before S3 truncation, including
Content-Length, and large HEAD's absent length/chunking. Signed S3 traces exclude
only Go's independent startup bucket HEAD when comparing, and normalize the SDK
signed-header set after independent signature verification. Metadata-query faults
use a private view; canonical SQL and the cache/blob relationship remain intact.
