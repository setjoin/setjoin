# Composable scope and manifest map

Date: 2026-09-06
Status: CP0.2 draft; proposed field rules, not a published schema or implementation.
Parent: contract freeze.
Normative product direction: [extension design](extension-control-plane-public-system-apps.md).
Dependency authority: Manifest v2.

## One owner per representation

| Representation | Existing or proposed owner | Relationship; forbidden conflation |
|---|---|---|
| Closed managed CODE package | Existing appmarket.Manifest and config/office-managed-app-v1.json | Fixed schema v1; not a public arbitrary-app manifest |
| Public extension manifest/configuration | Proposed versioned JSON Schema under extension E0 | Declares requested capabilities, never grants them |
| Commands and queries | Owning domain schemas and OpenAPI projection | Routes carry a contract major, not independent route SemVer |
| Committed events | Domain JSON Schema inside owned event envelope | AsyncAPI is a projection; no raw WAL or internal NOTIFY for plugins |
| WASI ABI | Future E5 WIT | No HTTP-to-ABI equivalence or implicit native fallback |
| Dependency release | Existing updater extended by Manifest v2 | Fixed dependency graph/receipts; no parallel app-store updater |
| Runtime operation and grants | Reducer-owned state | Never serialized back into a publisher's signed manifest as authority |
| SDK package | Generated projection plus thin idiomatic wrappers | SDK version does not change wire meaning or contract retirement |

Freeze generator/output paths within each owning implementation packet. This
document does not create a second runtime catalog in docs or promote examples into
production configuration. A retained internal module needs no public wrapper.

## Proposed field groups

These bounds are reviewable draft constraints. They are not assertions about
current decoders. Unsupported fields/kinds fail closed; names below are documentary
labels until the owning schema and fixtures are approved.

| Field group | Proposed shape and source | Validation / separation |
|---|---|---|
| extension identity | Registry-issued publisher-qualified opaque string, 1–255 ASCII bytes | Immutable; publisher authorization checked separately from signature; no path semantics |
| release version | SemVer string, at most 128 ASCII bytes | Display/resolution identity; immutable manifest digest is required too |
| manifest grammar | Positive integer schemaVersion | Supported explicit versions only; never inferred from app version |
| platform levels | Positive minApiLevel and testedApiLevel integers | tested >= min; tested level is information, not authority or automatic upper compatibility cutoff |
| domain requirements | Unique typed contract IDs with exact major | Required unknown major blocks admission; optional capability explicitly absent rather than guessed |
| artifacts | Typed platform and canonical sha256 digest | Lowercase 64-hex digest; platform manifest and per-platform image digests remain distinct |
| installation scope | Closed scope kind plus opaque server-resolved reference | Authenticated existing organization/account scope; email domain is not tenant identity |
| grant request | Unique capability/action/resource/data-class tuples | Bounds come from capability registry; request never grants itself |
| egress | Typed approved destination references | No wildcard/unbounded destination, raw proxy rules, shell or arbitrary interpolation |
| configuration | Typed public values, generated values, secret references and storage claims | Secret values excluded from manifests, previews, logs and event bodies |
| compatibility | Exact required domain majors plus runtime/profile constraints | Package version range alone does not prove compatible DB/storage formats |
| data declaration | stateless, Setjoin-managed or app-managed classes plus backup/export profile | App-owned Drive files do not cover arbitrary external state or unmanaged databases |
| resource profile | Closed runtime-specific profile and bounded limits | No host paths, Docker socket, privilege escalation or install script |
| deployment ID | Existing installation identity, opaque to extension authors | Not interchangeable with a scoped extension installation ID |
| operation identity | Server UUID plus independent generation, executor and lease | Neither publisher nor browser chooses the active executor/lease |
| revision/fence | Monotonic server values, encoded without JavaScript precision loss | Config revision, grant revision, provider generation and session fence are not aliases |
| request identity | Caller correlation ID separate from operation idempotency key | Lost response observation is authorized; retry cannot change accepted inputs |

For new public integer identities/revisions use canonical decimal strings when
values may exceed JSON safe integers. Existing native Go/SQL types do not change
through this document. Any adapter changing an existing wire encoding needs a
versioned domain contract and retained-client compatibility tests.

Signed input uses one schema-owned canonical serialization; reject duplicate keys,
unsupported mandatory fields, invalid UTF-8 and noncanonical digest spellings before
signature verification. Exact canonicalization algorithm, byte limits for nested
collections, Unicode policy for display text and signature-envelope ownership remain
SC-P1 gates. Do not assume current json.Unmarshal already enforces these rules.

## Scope authorization map

| Requested scope | Admission proof required | Current source anchor / unresolved mapping |
|---|---|---|
| Deployment-managed CODE | apps.manage and exact inactive provider generation | office_app_operation_request; existing install only |
| Office administration | Existing office.manage authority where required | office_launch_revoke distinguishes actor ownership from administrator |
| File operation | Authenticated actor plus current node capability | drive_runtime_has_node_capability through WOPI callback/save reducers |
| Organization app installation | Existing organization/account authority plus explicit app grant | General installation reducer and exact admin permission mapping pending |
| Group installation | Existing group membership/owner/delegate authority plus parent-approved envelope | Exact group owner reducer mapping pending; do not invent a new role/table |
| User installation | Current user and administrator-allowed envelope/catalog | No user consent escalation to organization data, egress or stronger runtime |

“Tenant app administrator” in the conceptual design is a responsibility, not proof
that such a role already exists. Resolve it to existing permissions or seek an
explicit role decision. Never derive ownership from request-body user/mailbox/domain
IDs. Revalidate membership and resource scope at use, not only at install time.

## Current CODE identity example

The existing static manifest excludes ExecutionIdentity and ProviderBinding from
JSON. CompileRuntimePlan canonicalizes a fixed runtime plan; execution ownership
labels additionally bind installation and operation. Preserve that useful separation.
Do not extrapolate closed CODE validation into acceptance of arbitrary publisher apps.

An Office session must eventually bind the qualified runtime/configuration and
proof material needed for that session. That binding is not satisfied simply by
storing providerId, and is distinct from current authority checks. See
[LC-P1](composable-lifecycle-transitions.md).

## Compatibility and retirement

Retirement follows the accepted later-of rule: at least 12 calendar months after a
stable successor release and 12 calendar months after explicit deprecation notice.
No successor/notice means no ordinary retirement deadline; clocks run concurrently,
and reaching a minimum never automatically removes a contract. Security exceptions
retain reason, affected range and supported remediation. This policy does not
promise support for every old Setjoin binary or dependency build.

Keep compatible additive changes within a domain major only when meaning,
authorization, idempotency, ordering and required fields remain compatible. A new
required grant or changed ordering is not “just another optional JSON field.”
Capability discovery reports current availability separately from advertised schema
support and installed SDK version.

## Completion and mutation tests

| Packet | Required oracle before freeze |
|---|---|
| SC-P1 Grammar | Golden canonical bytes/digest; duplicate keys, unknown mandatory fields, overbounds and malformed Unicode reject; supported optional additions preserve meaning |
| SC-P2 Identity | Swap deployment/install IDs, config/grant revisions, provider/session fences and manifest/runtime IDs; each rejects without effects |
| SC-P3 Scope | Auth-derived user/mailbox deliberately differ; cross-scope and changed group membership deny at the authoritative mutation |
| SC-P4 Compatibility | Old supported major passes, absent required capability blocks, optional absence degrades; SDK version cannot grant a capability |
| SC-P5 Handoff | D5 and updater cannot concurrently mutate the same CODE runtime; exclusive receipt transfers ownership without inventing another executor |
| SC-P6 Registry | Exact schema/OpenAPI/WIT/generated paths, generator pins, numerical bounds, scope guards and fixtures resolved in owning packets |

This draft covers every CP0.2 identity category, not every field of the future
production schemas. SC-P1–P6 are explicit open work, not implementation permission.
