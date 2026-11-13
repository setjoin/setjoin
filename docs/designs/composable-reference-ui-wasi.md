# CP0.4 paper reference — isolated UI and WASI reporting

Date: 2026-09-06
Status: complete illustrative fixture for review; NOT a frozen contract, executable
manifest, implemented app, approved runtime or passing conformance result.
Owner: CP0.4/Webmail and extension E5; Tasks owns source-data authorization.
Task: `sj-plan-all-20260906`, local Mac; no runtime resources created.

## Authority and present-day limit

CP0.4
requests a UI/WASI reporting reference. The
[extension design](extension-control-plane-public-system-apps.md#ui-model) owns
slots, isolated rich UI, capability mediation and the future E5 WIT boundary.
CP5
owns integration and native lifetimes;
Unified Workplace
owns visual/interaction direction, not a second authorization system.

**WASI reporting is future and unavailable today.** This paper cannot pull E5 into
CP1/CP2, turn an existing component test into runtime evidence, or enable a flag.
No browser-WASM, Electron subprocess, mobile downloaded module, remote service or
ordinary native fallback substitutes for an unavailable WASI runtime. Mobile may
eventually expose an approved declarative/bundled view of a server-computed result;
it does not download this example's rich UI or executable as a native contribution.

Current source anchors are navigation and capability-filtered first-party UI, not
an extension host: [navConfig.ts](../../mailserver/webmail/src/lib/nav/navConfig.ts:28),
[root layout](../../mailserver/webmail/src/routes/+layout.svelte:379), and
[TasksApp](../../mailserver/webmail/src/lib/components/TasksApp.svelte:40).
There is no claim that these sources implement the protocol below.

## Deliberately small use case

An authorized member requests an on-screen count of their readable Tasks in an
explicitly selected, bounded list set, grouped by completion and due bucket.
Tasks supplies a minimal read projection; a server-side WASI guest counts it; an
isolated view renders the aggregate. The example does not export files, send mail,
change Tasks, run background schedules, retain reports or read across the organization.
Selecting a list does not grant access to it. Guest eligibility and task-list ACLs
come from existing domain authority, not an app-defined role.

Titles, descriptions, people, email addresses, raw task IDs and attachment contents
are unnecessary and excluded. Aggregate results still inherit the source scope and
data class: counting is not declassification. Source snapshot/context references are
opaque, host-held and short-lived; possession alone does not authorize later reads.

## Illustrative manifest, not normative grammar

Everything inside this example, including field names, capability labels, contract
major labels and bounds, is a **paper proposal**. Angle-bracket placeholders are
deliberately non-installable. CP0.2/E0 must bind the actual closed JSON Schema,
registry IDs, digests and scope mapping before implementation review. This is not
the existing closed CODE manifest and must never be passed to its loader.

```yaml
paperFixture: ui-wasi-task-summary
schemaVersion: <E0-manifest-grammar-not-allocated>
identity: <publisher-qualified-example-identity>
release: <immutable-example-release>
compatibility:
  minimumApiLevel: <E0-level-not-allocated>
  domainContracts: [<Tasks-read-projection-major>, <UI-message-major>, <WIT-world>]
artifacts:
  isolatedView: { digest: <pinned-ui-digest>, mediaType: <reviewed-ui-type> }
  reportGuest: { digest: <pinned-wasm-digest>, mediaType: application/wasm }
placement:
  richView: isolated-web-origin
  reportGuest: server-wasi-future-E5
  mobile: unavailable-until-approved-declarative-or-bundled-view
contributions:
  - { kind: UI, slot: <reviewed-Tasks-inspector-slot>, label: Task summary }
requestedCapabilities:
  - <Tasks-query-authorized-minimal-projection>
  - <bounded-server-report-transform>
scope: <auth-derived-existing-organization-and-readable-selected-task-lists>
dataClass: <inherited-source-classification>
egress: []
secrets: []
persistentReportData: none
migrations: none
export: none
lifecycleProfile: cancelable-read-only-view-work
resources: <reviewed-finite-fixture-budget-profile>
support: <named-example-owner>
license: <reviewed-artifact-license>
```

The UI artifact origin is generated/approved by the host from the admitted release,
not an arbitrary URL in a message. No SQL, shell command, host path, socket, ambient
environment, executable install hook, raw credential or permissive egress is added.
An unsupported mandatory contract/runtime is refused before mounting or data access.
Installation, actor grant, domain scope and runtime qualification are separate gates.

## Capability and disclosure matrix

| Actor/boundary | Allowed purpose in this fixture | Explicitly excluded / authoritative check |
|---|---|---|
| Member in first-party Tasks UI | Discover an eligible summary action; select already-readable lists | Discovery is not permission; server rechecks actor and each list |
| Isolated rich frame | Request the one typed summary action; receive authorized aggregate and presentation tokens | No host DOM/CSS access, auth token, arbitrary method, list enumeration, native bridge or direct data API |
| Host message adapter | Resolve opaque view context, validate typed request, call broker | Cannot manufacture a role or positively cache a grant across requests |
| Broker and Tasks owner | Compare current installation/security fence, actor, authenticated scope, purpose and list ACL; return minimized bounded projection | No request-owned tenant/actor, raw SQL, admin export or private endpoint shortcut |
| WASI guest | Read the admitted input buffer through a typed WIT interface; produce typed counts | No network, filesystem/preopened directory, environment, process, clock/random source or unlisted host call |
| Result publisher | Revalidate current authority before disclosing counts to the still-current view | Computation success alone does not authorize publication; revoke or changed context discards output |

The logical broker is reducer-authoritative, not necessarily a new service. Loss of
current-fence connectivity is unavailable/denied before data disclosure. An app token
is never placed in a URL, frame message, log or browser storage. No new permission
allocation or role is established here.

## Four input paths and exact distinctions

All paths below assume a **future admitted E5 test fixture**, never today's runtime.
Availability/grant checks occur first; unavailable WASI does not fetch source data.

```text
current view request -> broker + Tasks authorization -> bounded source projection
                                      |
            +-------------------------+-------------------------+
            | valid rows              | authorized empty         |
            v                         v                          |
       WASI count only          typed empty result               |
            +-------------------------+                          |
            | recheck fence / current view                       |
            v                                                    |
     disclose aggregate                                          |
                                                                 |
missing/denied source -> safe not-available, no existence detail <--+
upstream failure     -> unavailable/retry, never zero-count success
```

| Path | Illustrative input/result | UI and independent negative oracle |
|---|---|---|
| Valid | Authorized snapshot contains `[{completion: open, dueBucket: overdue}, {completion: done, dueBucket: none}]`; typed output totals two with one per matching bucket | Show snapshot time and counts; output totals reconcile to admitted rows; no source title/ID leaves host |
| Missing | Required list/input is missing, no longer readable, or mandatory request field is absent | Missing/denied resource uses the same safe unavailable-resource response; malformed request uses validation failure before query; neither becomes empty or leaks existence |
| Empty | Successful authorized query returns zero rows and an explicit complete snapshot marker | Show “No tasks in this selection”; no error/retry implication and no fabrication of a populated chart |
| Upstream failure | Tasks query times out, loses authoritative-fence access, returns malformed projection or fails mid-page | Show unavailable with safe retry; discard partial input; no zero-count or complete report, no alternate provider/data path |

Source paging is bounded and must establish complete coverage for the selected scope.
Exceeding the fixture bound returns “Narrow the selection”; truncating at the bound
cannot produce an apparently complete count. A refreshed report has a new snapshot;
it cannot silently combine pages from incompatible snapshots. The existing Tasks API
does not gain this snapshot contract merely because the fixture needs it: E3/Tasks
must approve and bind its exact projection semantics, or this reference remains held.

## Illustrative query, command, message and event flow

These names denote paper messages, not existing endpoints, public methods or events.
The only command is a cancelable, read-only report request; no durable Tasks command
is needed. Adding saved reports or scheduled jobs would be a separate scope change.

Illustrative WIT-boundary type sketch (not compilable WIT or an allocated world):
`InputRow = {completion: open|done, dueBucket: overdue|upcoming|none}`;
`Counts = {total, openOverdue, openUpcoming, openNoDue, done}` with bounded unsigned
integers and `total = openOverdue + openUpcoming + openNoDue + done`.
The sole imported host operation reads one admitted bounded input handle; the sole
guest export returns `Counts` or a closed validation/resource failure. Handle reuse,
unknown enum values, overflow and extra fields fail validation. No generic host-call
dispatcher or guest-controlled callback name is part of the sketch.

```text
frame -> host: ReportRequest(messageMajor, requestId, viewNonce,
                            contextHandle, grouping = completion-and-due)
host -> broker -> Tasks: QueryAuthorizedSummaryInput(selectedListHandles,
                                                   boundedSnapshotRequest)
host -> WASI: summarize(typedInputHandle) -> typedCountResult
host -> broker: recheck current disclosure authority for captured context/fence
host -> frame: ReportResult(requestId, viewNonce, sourceSnapshotLabel,
                           complete = true, totals)
frame -> host: CancelReport(requestId, viewNonce)
host -> frame: ReportState(requestId, viewNonce, cancelled | unavailable | failed)
```

`ReportState` is a volatile correlated view event, **not a committed domain event**.
This read-only computation emits no new Tasks event and does not subscribe to raw
`LISTEN/NOTIFY`, WAL or internal tables. A future Tasks change subscription, if needed,
must use its separately approved committed semantic-event contract and reauthorize
each refetch; it is deliberately absent from this minimal fixture.

1. Host checks current release, runtime support, actor/list scope and slot eligibility.
   It binds a fresh view nonce to the actual frame window, installation/runtime
   generation and captured authenticated context. Caller fields cannot replace those.
2. Frame handshake must match exact admitted origin, `event.source`, message major
   and nonce. Only then may the host transfer a dedicated port. Opaque `null` origins
   are unsupported in this illustrative profile; never compensate with `*` trust.
3. Accept only the closed request shape, one grouping enum, bounded strings/arrays
   and scoped correlation identity. Unknown version/type/fields, conflicting
   duplicate requests, request-owned actor/tenant and unbounded payloads are rejected.
4. Input fetch, guest execution and final disclosure each remain fenced. A successful
   read before revocation does not authorize a later result. A result for a replaced
   nonce/request/context is discarded; no stale callback remounts the frame.
5. Duplicate identical requests within the same live view return the same in-flight
   or terminal observation, not concurrent work. Reuse with changed input is rejected.
   After teardown/restart there is no durable report to replay: fresh authorization
   and a new view/request are required.

## Origin, frame and presentation profile

Proposed fixture origins such as `https://report-ui.example.invalid` are reserved
examples, not deployment endpoints. Use a dedicated origin different from the shell;
the shell's frame allowlist and the frame's ancestor policy name exact approved
origins. This profile permits scripts inside that separate-origin sandbox but no
top navigation, popups, downloads, forms, camera/microphone or native bridge. If a
non-opaque origin is retained for exact-origin checks, its sandbox permission never
makes it same-origin with Setjoin. Review concrete CSP/sandbox/Permissions-Policy
headers against the actual E5 ingress before implementation; no wildcard policy.

The host owns navigation/title, user context, safe error/status, loading boundary,
focus entry/return, theme-token projection and unavailable-state controls. The frame
owns its internal report layout only. Pass a versioned allowlisted token/locale
projection, never CSS text or a parent document reference. Unknown theme major gets
a host-rendered compatibility/unavailable state, not a style injection fallback.
Host and frame announce their own asynchronous outcomes once, with non-color-only
status and a keyboard exit. Test light/dark, Chinese/English/German and narrow/touch
layouts; no visual direction is selected by this document.

## Resource lifetime and cancellation receipt

Budgets below are **finite proposed synthetic-fixture constants**, not production
defaults or a universal drain timeout: one report per view, four per actor and
sixteen per installation, with an organization-wide admission ceiling of sixteen;
request envelope 8 KiB; handshake timeout 5 seconds;
at most 1,000 input rows and 1 MiB serialized input; 64 KiB output; 32 MiB guest
memory; 5,000,000 fuel units; 2 seconds execution; 5 seconds input fetch; 1 second
supervisor cancellation observation. E5 must calibrate/freeze them with its chosen
runtime and fixtures. Do not increase limits or retry automatically after exhaustion.
Admission over a ceiling is unavailable/busy, not an unbounded queue; concurrent
installations cannot evade the organization ceiling by creating more view handles.

| Resource | Sole effect owner | Termination and observable evidence |
|---|---|---|
| Frame, handshake listener, port, view nonce | Host view adapter | Detach/close/invalidate on navigation, logout, permission loss, slot removal or generation replacement; return focus if safe |
| Fetch and its timeout | Broker/input adapter | Abort owned fetch, clear timer and discard input; late response cannot publish |
| Input handle, guest instance, fuel/memory/output buffers | Future E5 supervisor | Cancellation terminates owned instance and invalidates handle; exhaustion is failure, never native fallback |
| In-flight dedupe and presentation result | Host view adapter | Clear on teardown; no browser storage/cache of source or output |
| Audit/lifecycle facts and underlying Tasks | Existing authoritative owners | Never part of view cleanup; do not delete domain data or audit to remove a report |

The supervisor, not an untrusted frame acknowledgment, proves termination. Cancel is
idempotent; a lost cancellation response is “cleanup unconfirmed,” not “stopped.”
If the observation deadline expires, block new work for that view and expose a safe
unavailable state; an owned supervisor reconciles the instance. No global process
kill, shared runtime teardown or deletion follows from this paper receipt.

Illustrative non-secret observation (not a schema or database row):

```yaml
paperReceipt: cancelled-view-report
viewNonce: <opaque-nonce>
requestId: <correlation-id>
capturedInstallationGeneration: <separate-generation>
capturedSecurityFence: <separate-current-fence>
reason: navigation
newRequests: refused
resultDisclosure: fenced
ownedFetch: aborted
ownedGuest: termination-observed
ownedPort: closed
ownedBuffers: released
durableDomainEffects: none
cleanup: observed-complete
```

On security revocation, fence before cleanup; never keep a revoked token alive for
the last report. On planned installation drain, stop new reports and cancel this
fixture's transient reports; it has no durable accepted-write obligation. That narrow
choice does not alter Office's accepted-save drain or Mail's pending obligations.
Removal defaults and backup rules still apply to installation settings/grants under
their owners; there are no persistent report bytes to purge or restore here.

## Proposed conformance packet — not existing test evidence

Reuse the existing Vitest/browser and owning Go/runtime front doors. Proposed new
test locations, subject to E5 package review, are
`mailserver/webmail/src/lib/extensions/report-host.test.ts`,
`mailserver/webmail/e2e/extension-report.spec.ts`, and
`mailserver/internal/extensions/report_test.go`. These files are **not created or
claimed to exist**. WIT world/source and runtime harness paths remain E5-owned freeze
gates, not a second public IDL invented by this fixture.

| Proposed ID | Input / fault | Independent oracle and gate |
|---|---|---|
| UR01 Valid/empty | Two-row fixture and zero-row complete snapshot | Exact bucket totals and distinct empty copy; no raw source metadata; future merge |
| UR02 Missing/invalid | Missing list, denied list, malformed request/input | Missing/denied public response parity; malformed before effects; no data fetch on invalid shape; future merge |
| UR03 Upstream failure | Timeout, malformed page, changed snapshot, fence unavailable | No complete/empty success; discarded partial input; bounded retry requires fresh request; future merge |
| UR04 Capability availability | Missing E5, revoked/expired grant, wrong actor/list scope | Zero guest starts/data reads when not admitted; no private/native/remote fallback; future merge |
| UR05 Trust protocol | Forged origin/source, null origin, wrong version/nonce, unknown message, oversize input | No broker call/result/native access; exact target-origin handshake; future merge/browser |
| UR06 Navigation/revoke race | Delay input, compute and result; cancel or change context/fence at each boundary | No protected result after revoke/navigation, no remount, all owned resources terminal; future merge/browser |
| UR07 Budgets | Row/byte/output cap, fuel/memory/time exhaustion, refused host calls | Whole report fails with correct classification, no truncation-success or retry loop; future runtime merge |
| UR08 Replay/cancel | Identical duplicate, changed duplicate, repeated cancel, lost cancel response, supervisor restart | At most one live instance; changed input refused; unknown cleanup not success; restart requires fresh authority; future merge |
| UR09 Accessibility/isolation | Keyboard, focus, zoom, themes, CJK/long text, narrow viewport; hostile frame CSS | No host styling/DOM escape; accessible state/return path; future browser/device where applicable |
| UR10 Lifecycle | Installation drain, slot removal, logout, release/generation replacement | No new work, transient report cancellation receipt; Tasks/audit untouched; future integration |

Current [CommandPalette focus tests](../../mailserver/webmail/src/lib/components/CommandPalette.test.ts:85),
[guest navigation tests](../../mailserver/webmail/src/lib/components/GlobalDrawer.test.ts:93)
and [Tasks shell tests](../../mailserver/webmail/src/lib/components/TasksApp.test.ts:52)
are patterns to reuse, **not evidence for UR01–UR10**. Link these obligations to
UI-T04/05/06/08/09/10 and CP5 rather than adding a competing verification framework.

## Freeze gates and decisions

The reference is complete as a paper exercise; CP0 freeze remains open until E0/E3/E5
bind scope/grants, snapshot semantics, closed messages/manifest, WIT types, origin
deployment profile, resource measurements and exact test selectors. A need for raw
SQL, private endpoints, same-origin code, ambient I/O or native fallback rejects the
reference and returns to contract design; it is not a workaround to implement.

No new product decision is requested to author this bounded read-only fixture.
Persistent/scheduled reports, cross-organization aggregates, export, external egress,
new permissions or mobile downloaded code would be material expansions requiring
separate approval. No mockup, runtime qualification, score or implementation approval
is supplied here.
