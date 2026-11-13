# Mailserver self-service identity surface (#494)

The 25 registrations in the historical #333 closing audit are mailserver
handlers, despite the F21 inventory prefix. Their HTTP boundary belongs in the
Rust gateway, beside the mail and migration infrastructure they consume. They
must not be sent to the auth process as if they were aliases of authserver APIs.
`AuthContext` supplies the authenticated actor and primary mailbox; body, path
and query identity fields never supply write ownership.

Frozen-Go transaction map (qualification is tracked in the route catalog):

| Routes | Frozen authority and transaction |
| --- | --- |
| App passwords (GET, POST, DELETE) | Owned list; one owned INSERT of a SHA-256 token hash; one owned soft-delete UPDATE. Raw random `mail-ap-` token is returned once. No audit, notify or state bump. |
| Org chart (GET) | Optional target requires live `users.read`; actor/target domain check precedes existing chart reducers and profile read. |
| MailTips (GET) | Advisory audience/external/OOO/send-as reads; OOO uses the existing mailbox-scoped reducer. |
| DLP check (POST) | Feature OFF short-circuits before decode; existing `dlp_evaluate_draft` is a read-only, mailbox-scoped advisory. Errors project clean. |
| Read receipt (POST) | Existing mailbox-scoped `send_read_receipt` owns consent policy, outbound enqueue and receipt deduplication atomically. |
| Own S/MIME certificates (GET, POST, DELETE, default POST) | Owned reads and encrypted-key upsert. Delete/promote and default selection are multi-statement transactions requiring parity reducers. |
| Recipient S/MIME certificates (GET, POST, DELETE) | Owned reads, deduplicated single-statement upsert and one owned DELETE. Only metadata leaves the list endpoint. |
| User webhooks (GET, POST, DELETE) | Owned list; decoded body followed by event catalog and SSRF URL validation; sealed signing secret in one INSERT; one owned DELETE. |
| Migration (GET, POST, DELETE, cancel, pause, resume, test-imap, upload) | Self-service actor selects only owned jobs. Configuration is sealed using the existing migration codec; the existing native orchestrator owns job tasks and uploads. History deletion is one owned statement. |

The HTTP/effect seam records frozen Go once, then replays with Go upstreams
unset. It compares response bytes, headers, owned row state, audit and actual
LISTEN/NOTIFY observations. Generated credentials/envelopes must be independently
validated before normalization. Tests use the assigned disposable database,
`REQUIRE_DB=1`, and a single test thread. Recording files are exclusively created;
replay cannot rewrite expectations.

Go compatibility facts identified during source audit:

- Self-service M365 start rejects nonempty `targets` at ingress, then requires
  nonempty `targets` in its M365 branch. No successful self-service M365 job is
  reachable; preserve the refusal rather than enabling an admin operation here.
- Own-certificate delete returns 500 when the ID is missing or foreign; recipient
  certificate delete returns 404. These are distinct frozen projections.
- S/MIME upload parses the certificate and key independently and does not check
  their correspondence or certificate validity. Preserve this acceptance.
- Webhook delete ignores a parse/database error and projects no affected row as
  404. App-password revoke instead checks parsing and SQL errors.

App-password creation generates its token with ring, hashes it with RustCrypto
SHA-256 and binds the INSERT owner to the verified context. The user-command
executor supplies actor-bound infrastructure receipts and explicit COMMIT.
Only `Committed` releases the plaintext. Unknown outcomes return an operation ID
without credentials; no blind retry or extra session/key mutation is introduced.

App-password revoke binds both credential ID and verified user in the UPDATE,
returns 404 for a foreign, missing or already revoked row, and uses the same
explicit-COMMIT/unknown-outcome contract as creation. Its request ID parser is
strict; encoded ServeMux path segments are decoded before matching/parsing.

DLP is a read-only scoped transaction calling the existing draft-policy reducer.
Feature OFF short-circuits before body decoding; reducer failure returns the
clean advisory. No violation, audit, state bump or notification is published.
Policy-hit, foreign-policy and fault replays verify this boundary explicitly.

Org-chart optional targets use the verified token's users.read projection
(live governed grants for admin tokens), then a same-domain actor/target gate.
Each profile/reducer read retains that actor/domain reach. Go's decimal-prefix
scanner and independently swallowed chart/profile errors are preserved. Nested
RawMessage JSON keeps PostgreSQL key order while Go compaction/HTML escaping is
applied. Manager/report fixtures restore the peer's original domain before
deleting either account, so their temporary shared-domain reach leaves no rows.

MailTips uses the dedicated worker credential only for delegate-side rows,
filtered by the verified actor as delegate. The request pool owns preferences,
domain classification and the existing dates-only OOO reducer. A freshly
resolved owned primary mailbox supplies OOO/DLP scope. These are read-only;
recipient duplicates and Go's warning-group order are retained. Ordering
between distinct external-domain groups is unspecified by Go's map iteration.
Org-chart target scanning skips horizontal Unicode space but rejects a leading
newline, as fmt.Sscanf does; it still accepts a decimal prefix with trailing
text. The encoded-newline HTTP recording prevents a generic trim regression.

Read receipts call send_read_receipt once in a mailbox-scoped receipted command.
The existing reducer owns message reach, ask/always/never policy, deduplication
and atomic queue/receipt publication. It does not mark a message read or bump
JMAP state. Go maps a foreign message to 500 and ignores ParseInt range errors
(positive overflow saturates); these HTTP projections are retained. Consent
and policy replays validate real queued MIME and matching receipt timestamps
before masking the transaction clock. Unknown COMMIT never reports success.

The webhook list selects only the verified actor's subscriptions, newest first,
without returning plaintext, sealed or previous signing secrets. It preserves
Go's ignored deferred row errors and event-types decoding (non-arrays become
null; non-string array elements keep their zero value). Request identity fields
and an unused malformed body do not change list ownership.

Webhook creation validates self scope, the existing event catalog (including
duplicates), then the shared Go URL/SSRF policy before sealing. The gateway
composes the existing webhook codec; the identity crate receives only the sealed
bytes and binds user_id from AuthContext in one receipted INSERT. A confirmed
COMMIT releases the one-time secret; Unknown returns only the operation id.

Go's ignored Rows.Err also turns a SELECT permission failure into an empty
webhook list. The local driver may surface42501 before row metadata, so this
list alone projects that code to the recorded200[]; infrastructure failures
retain the database-error response. The fault fixture restores the exact grant.

Webhook deletion binds subscription id and verified actor in the same DELETE.
It preserves Go's ignored ParseInt errors (including positive saturation) and
404 on a database error or a missing/foreign row; a repeated DELETE is404.
Unknown COMMIT still returns503 with an operation id. The privilege-fault
recording verifies the existing subscription survives Go's misleading404.

The S/MIME adapter is gateway `identity_smime.rs`, composed after the same
verified-session admission. Own-certificate listing selects only actor-owned
public fields, excludes private_key_enc, and derives optional dates from the
first PEM certificate through the existing parser. Empty results are certs:null;
invalid stored PEM keeps the row and omits its dates.

Own-certificate list permission errors are also deferred by pgx and swallowed
by Go; the recorded42501 case is200 with certs:null. The local reader retains
that projection. Long-label framing is already handled by the shared gateway
and replays unchanged; no extra transport implementation is needed here.

Own S/MIME upload bounds the full multipart body to5MiB, gives query labels
precedence, and parses certificate/key independently through existing PEM/X.509
and OpenSSL decoders. Go accepts an expired own cert, a mismatched valid key,
and a non-CERTIFICATE PEM label; those captures remain authoritative. One owned
upsert uses pgp_sym_encrypt under the executor's configured encryption GUC.
First uploads default only when that actor has no certificate; replacements
preserve created_at/default. HTTP success follows explicit COMMIT, with
actor-bound receipts and Unknown surfaced as an operation id.

Own-certificate deletion calls rust_identity_smime_cert_delete once under the
verified user command. Its delete/promotion exception block restores all rows
before returning a fixed phase; failed decoding rolls back the receipt as well.
Missing/foreign rows retain Go500, and committed deletion promotes only the
newest owned survivor. The public database contract has a pgTAP rollback fault
in addition to the front-door effect corpus.

Default selection calls rust_identity_smime_cert_default under the same verified
user command. Foreign/missing ids return404 before flags change. The reducer
updates only actor-owned rows and rolls back every flag on a lookup/update fault;
confirmed COMMIT alone releases ok:true. No audit, state bump or notify is added.

Recipient listing filters owner_user_id by AuthContext and orders last_seen.
It derives isEncryptCapable from the parsed certificate, while dates/fingerprint
come from stored metadata. The response excludes cert_pem and private material;
empty labels and zero/null dates are omitted. Empty results remain certs:null.

Recipient list also preserves Go's ignored deferred42501 as200 certs:null;
other database failures retain the database-error projection. The real grant
fault capture and native replay verify this compatibility boundary.

Recipient import bounds multipart to2MiB, parses the first certificate, rejects
expiry/missing SAN email/non-RSA or non-enciphering usage, and normalizes the first
SAN email. One actor-owned upsert deduplicates owner/email/SHA-256 DER fingerprint;
on conflict it preserves PEM/dates/first_seen and a blank incoming label preserves
the stored label. Source becomes imported and last_seen advances. Success follows
explicit COMMIT; Unknown returns an operation id without an acknowledgement.

Recipient deletion binds certificate id and AuthContext owner_user_id in one
DELETE. Missing/foreign/repeated ids abort the receipt and return404; SQL failure
returns500, while explicit COMMIT alone acknowledges deletion. No extra business
audit, notification or state bump is added. Cross-user effects stay unchanged.

Migration status selects the actor's newest job whose status is not completed;
failed/cancelled jobs remain visible and newer completed jobs are excluded. It
returns stored progress/error JSON with Go RawMessage compaction/order, optional
dates and metadata only, excluding source_config_enc. Any query/scan failure
maps to200 status:none, matching frozen Go. The gateway adapter is identity_migration.rs.

Migration history deletion uses one user-owned DELETE for completed/cancelled/
failed jobs; active/paused jobs and foreign jobs remain. Foreign keys cascade
source records inside that transaction. An empty or repeated deletion succeeds
with deleted:0, SQL failure is500, and explicit COMMIT alone acknowledges the
count; Unknown retains an operation id. Request body/query ownership is ignored.

The webhook decoder preserves Go's distinction between nullable scalars and
slices: null leaves a prior string intact, but clears eventTypes even after a
duplicate nonempty eventTypes field. The captured duplicate-null case refuses
creation400 and leaves both users' subscriptions unchanged.

Migration start composes the same native Runner as the F05 admin API (one shared
Orchestrator). A verified user selects an owned mailbox without imposing an
is_primary filter; the INSERT repeats that mailbox/user ownership fence. One
receipted INSERT admits pending work, preserving the one-active-job409 verdict;
only a committed id reaches StartJob. Unknown returns an operation id.
The gateway retains Go's provider validation order, seals IMAP/EWS configs with
the existing migration codec and explicit self_service:true, and refuses bulk,
impersonation and caller private-network policy. EWS requires caller credentials
even with global defaults. M365's unreachable self-service branch stays refused.
Typed serde seeds preserve nullable scalars, clearing slices, nested duplicate
object merging and RawMessage explicit null. Existing workers own job effects.

For a user with no owned mailbox, start retains Go's400 no-mailbox response.
The shared user-currency admission for the migration registrations is described
below; a lifecycle-denied owned mailbox still cannot use that proof.

Resume selects only the verified actor's newest paused job; lookup/scan failures
retain Go's404. The gateway signals the same process-local orchestrator used by
F05 and returns202 for admission. Its worker owns subsequent reducer transactions;
the HTTP handler adds no second writer or durable-success claim. Unused bodies
are ignored. Replay waits for the actual worker to settle and preserves the
foreign paused job.

Cancel selects the verified actor's newest pending/testing/fetching/importing/paused
job and signals the shared orchestrator. A stale owned job with no process-local
task is500; missing/foreign jobs and lookup failures are404. Its204 acknowledges
the signal. A real ICS job held at S3 GET proves cancellation settles through the
existing reducer without completing or appending a missing-upload error.

Pause selects only the actor's fetching/importing job and signals the same
process-local runner. Lookup failures/missing jobs are404; an owned stale row
without a task is500. Go acknowledges202 even for ICS/VCF phases that never
consume the pause token and complete normally; that behavior stays mirrored.

Migration upload proves job id and verified actor together before reading the
64 MiB-bounded multipart body. The first ICS/VCF files are stored as raw bytes by
the shared orchestrator, ICS first. Empty files are accepted but produce no PUT.
Go ignores storage errors and returns200 input sizes, including partial storage
failure; preserve that projection without adding a DB mutation or rollback.
Signed S3 effect observations validate keys/bytes independently of response sizes.

IMAP connection testing decodes Go's direct IMAP config, rejects caller-provided
private-host/CIDR exceptions, and invokes the existing connector under a 30-second
whole-operation deadline. The shared dialer checks every resolved address before
connecting. It creates no job or local data; failures keep Go200 success:false
with its fixed sanitized message, never the upstream error or credentials.

All exact native migration registrations use the existing mailserver
identity proof for an existing non-guest principal with zero owned mailboxes.
It grants user currency only (mailbox 0), retains live revocation/security checks,
and never admits a lifecycle-denied owned mailbox. Their job queries still bind
the verified actor; connection testing requires no local mailbox. Other routes
keep their existing strict mailbox admission.

Webhook create runs Go's `requireWebhookCap` first: after auth and before body decode, it counts the caller's `webhook_subscriptions` on the request pool. At 20 it returns 409 and a count failure returns 503 (fail closed); both bodies are recorded (`hook-create-cap`, `hook-create-count-error`).
