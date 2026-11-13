# Metadata P0 first-read binding and body evidence — proposed, HOLD

## Status and provenance

This is a fixture-specific source contract for independent Spec/Standards review. It proposes reuse of the existing retained READ interfaces; it does not adopt them into the clean P0 branch, create a provider, grant authority, or authorize database, runtime, publication or UI actions.

The READ interface analysis and source excerpts were independently materialized and hashed in Library `libfile_bd5b002e976c81919a1055f91364f2c7`, archive SHA-256 `ea069bec4ab6772bb4d727e75a032bf9aaf01f0ae3987cf6e50cb6cee4b9610f`. Its source lineage is READ union Library `libfile_8203593db2cc8191a0f9fd3f7a631dd1` v1, archive SHA-256 `82d2962317eb56e1711c69b95fbf74a8b0a544d24f96a55d70613794ad55fcd7`, nested source SHA-256 `6d4396510e5298b533968ac7796627930472f0e350c1ab924665dbba762a11fc`.

The delegating owner supplies the synthetic fixture JSON identity `a398c4501f8fd49b5d3645c4321cd3a3fd59ace6d3ea83533952efd07583d934` and fixture contract identity `ca21c4123b119b7ff82a8a14f8a23bdbf1f52d42e99974f90245b647f70950b6`. Their immutable bytes were not independently inspected in this document turn. The two body literals below are supplied synthetic expectations, not observed database or UI values.

## Fixture binding contract

For one identified `t03_metadata_20261027` synthetic run, retain an evidence binding that identifies the run and fixture identities above and the captured positive decimal actor/user ID, domain/tenant identity, mailbox/account ID, root message ID and reply message ID from independently qualified fixture evidence. Preserve each source and capture identity; do not guess values, infer an actor from a mailbox, assume domain equals an external tenant identifier, or trust a caller-provided authorization flag. Distinguish missing from zero, null, ambiguous, mismatched, foreign or stale captures; such input cannot establish a read success.

The intended existing READ owner interface accepts `RequestConnector`, `Arc<VerifiedRetainedAccess>`, untrusted public JSON bytes and an absolute deadline. The opaque verified principal supplies its authenticated user ID and optional domain scope. The owner, not the fixture or caller, resolves the requested positive i64 account/mailbox ID, actor/domain relationship, current permission and lifecycle. The current retained Get facts check enforces the existing domain relationship; this document does not assert that an external tenant identifier maps to that domain. Primary-mailbox ownership or current delegate read/send_as/send_on_behalf/full_access is evaluated by existing source, with account-not-found and forbidden distinctions retained. The same authenticated principal, privately admitted mailbox and request IDs must govern the relevant read and rechecks.

**HOLD:** no concrete P0 supplier for `Arc<VerifiedRetainedAccess>` is established. Do not fabricate a principal, construct a custody/profile seal, add `authorized=true`, or pass fixture observations as authority. Existing retained admission, observed-venue, role/posture, catalog, Get-profile, current actor/account/lifecycle/freshness, backend and same-domain checks must be satisfied by separately reviewed owners. `require_email_get_profile()` currently unconditionally returns `Held(ReadProfile)`. The private `StagedGetPage` contains page and connection fields without output accessor, sink or transfer implementation. No P0 adapter/publication binding has been admitted. Denial and cleanup-uncertain outcomes must remain failures with no body publication.

## Three distinct evidence boundaries

The following are separate obligations; one cannot be substituted for another:

1. **Persisted-row observation.** A separately authorized, scoped observer records the captured root and reply identities and the actual row facts `body_text` and `body_html`, with provenance, row identity and observation status. Expected synthetic values are below. Record SQL NULL as NULL; never treat an absent field, empty string, or unobserved row as NULL. This contract does not itself authorize or perform SQL.
2. **Scoped adapter response.** Once the existing READ owner, its authenticated principal supply and publication boundary are separately admitted, an `Email/get` request for the captured mailbox and exact two captured message IDs explicitly selects `id`, `preview`, `bodyText`, and `bodyHTML`. Check a separately recorded scoped response: each returned message's `id` binds to the captured root or reply; both are found exactly once. For each row, the specified properties must be present with exactly the corresponding values below. A present JSON null differs from a missing key, string `"null"`, or empty string. A successful response has matching accountId and nonempty state; absent misses serialize `notFound` as JSON null in the inspected row-only assembler. Verify the actual response rather than manufacturing it from row observations. No row order is assumed beyond recorded source behavior; bind by captured identity and reject ambiguity.
3. **UI rendering.** Once a separately admitted UI path exists, record the visible body rendered for each captured message and compare it to the matching full body expectation. The evidence must identify the message and the body field used. Because these short bodies equal their 256-character previews, a preview fallback can look identical; a matching display alone does not prove the full body field was consumed. The scoped adapter response must independently show `bodyText` present and exact, and the UI evidence must establish which field supplied the rendered content. Missing or ambiguous field provenance remains HOLD.

## Exact expected row-derived values

| Captured message | `body_text` / required `bodyText` | Required `preview` | `body_html` / required `bodyHTML` |
| --- | --- | --- | --- |
| Root | `T03 t03_metadata_20261027 root body` | `T03 t03_metadata_20261027 root body` | SQL NULL / JSON null |
| Reply | `T03 t03_metadata_20261027 reply body` | `T03 t03_metadata_20261027 reply body` | SQL NULL / JSON null |

The retained source projects preview from the first 256 Unicode characters of body_text; these synthetic strings are shorter. Source projection treats `None` body text or HTML as JSON null, but only for a selected property. The requested body contract requires the exact strings above, not null or absence for text/preview. Attachments are a separate metadata-only scope and require their own evidence and qualification; do not infer their presence from these body values. Blob loading and download are excluded.

## Source boundaries and unresolved work

- Row projection `source/inputs/assembly/server-rust-pilot/crates/pilot-projection/src/message_projection.rs`, SHA-256 `cbed2cde1de57ec6d3a3998485dab18763a8ae0dc31b542f9b341da81f4a1ffe`.
- Private checked row decoder/composer `source/retained/upstream/crates/pg-adapter/src/mail/read/get.rs`, SHA-256 `d4670d22b9e9b6c920b388a73089c88f1a0a542c174bf9ec0635372dbb75d0de`.
- Private owner `source/retained/upstream/crates/pg-adapter/src/mail/read/get_owner.rs`, SHA-256 `443876a77614c482233a033278fc7aec136c0e9778482980a7350fad02d1ba54`.
- Private read policy and staging `source/retained/upstream/crates/pg-adapter/src/request/read.rs`, SHA-256 `808a71abbc4cf4eaccc255004bdc35dc52f45685c5f390a56aeac101db7b2372`.
- Opaque principal `source/retained/upstream/crates/identity-adapter/src/retained.rs`, SHA-256 `4dc456256eecb9538c93d3678837eb8154b4f37f085899a695186957cda372e6`.
- Get-specific current facts `source/retained/upstream/crates/pg-adapter/src/request/authority/retained/get_read.rs`, SHA-256 `b77fbf630cd12b82d1847d8e2101833ce33c7b64f9c5fad3261b9be674dc1789`.
- Row-only envelope `source/inputs/assembly/server-rust-pilot/crates/pilot-read-result/src/read_result.rs`, SHA-256 `acbe0d90cd5535ca034e51243ff53e7ce5bf942eeb8cb099964931345425d81d`.

Remaining acceptance dependencies include verified fixture bytes and captures, principal supplier, tenant/domain binding, closed venue/catalog/profile/custody qualification, current policy and lifecycle checks, scoped output/publication owner, audit/decrypt obligations where applicable, UI field provenance, and independently reviewed evidence at all three boundaries. Split-statement snapshot parity and cross-domain delegation are not established. No loader, oracle, provider, SQL, service, source edit or runtime action is supplied by this document.
