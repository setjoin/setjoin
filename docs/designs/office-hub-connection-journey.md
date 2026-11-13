# Office hub and existing-editor connection — design contract

Date: 2026-09-08.
Status: proposed planning supplement; bounded bilingual storyboard evidence only,
no visual approval, numeric Design score or implementation authority.
Packet ID: `OFFICE-HUB-A`. Rendering checkpoint.
Connected configuration checks and open corrections
cover only the configuration slice; later steps and whole Design remain open.

## Authority and scope

This packet expands the existing Office task hub
and D5.0 connection wizard.
It does not redefine provider, Drive, WOPI, operation or permission authority.
Unified Workplace U1
owns the shared visual direction. The current [design contract](../../mailserver/webmail/DESIGN.md)
continues to bind product source; no competing root design system is introduced.

The first packet covers six view templates and their directed failure branches.
It is one of the seven remaining Office UI families,
not whole Office coverage. Existing/BYOL means the customer owns the editor runtime;
connection does not install, patch or remove it. Qualification uses synthetic
temporary documents, never a customer's working file or a production save receipt.

## Information hierarchy and journey

```text
Administration → Office hub
  ├─ Connect an existing editor
  │    Endpoint → Trust/support → Discovery → Temporary-document test
  │      → Qualified, inactive → Review routing → Explicit activation
  │      → Office hub with current authoritative result
  ├─ Install Setjoin test editor → Apps / curated Collabora detail
  └─ Contextual prerequisite remedy → Sources / owning configuration page
```

The routing review is the final wizard template, not a sixth wizard step or a
second activation mechanism. The hub plus five wizard steps make six templates.
Back/forward retain permitted non-secret form values but do not replay mutations.
No fixture arrow represents a permission grant. Returning to the hub preserves
the original permitted navigation destination and focus; unsafe or unauthorized
return destinations fall back to the authorized Office hub.

| Template / stable view value | First information | Next action and secondary detail | User outcome |
| --- | --- | --- | --- |
| Hub / `hub` | Editing availability, observation age, active provider and scope | One state-appropriate primary action; operation details and diagnostics second | In five seconds, know whether editing is available and what to do |
| Endpoint / `endpoint` | Persistent endpoint label and deployment ownership | Continue after local validation; server discovery remains a separate step | Connect without mistaking URL acceptance for trust or health |
| Trust/support / `trust` | Customer/BYOL runtime, security-update and support responsibility | Continue with current required acknowledgements; review permitted trust configuration | Know who maintains the editor; no invented commercial entitlement |
| Discovery / `discovery` | Named check, current result and timestamp | Retry only the failed check or change endpoint; diagnostic ID on demand | Distinguish unreachable, disallowed target and invalid/missing proof |
| Temporary-document test / `qualification` | Open/save check progress and last confirmed result | Qualify through the owning operation; inspect failure or current status | Know whether the candidate passed, without altering the existing route |
| Routing review / `routing` | Qualified but inactive candidate, affected scope and prior route/rollback target | Explicit Activate only when currently allowed; Back remains safe | Make the routing change deliberately, then see its authoritative result |

Over repeated use, the hub keeps history and diagnostic details discoverable but
does not turn receipt IDs into the primary reading task. A previously active
provider remains separately visible while a new candidate is checked or fails.

## View states and allowed actions

The fixture identifiers below are proposed design/test identifiers, not wire codes.
The owning generated API supplies actual states, permissions and allowed actions.
Use `data-office-view`, `data-office-fixture` and `data-office-action` only as
stable prototype/test hooks; none controls authorization or fabricates backend data.

| Fixture | Visible state | Action / negative oracle |
| --- | --- | --- |
| `hub-loading` | Section busy, navigation usable, availability not yet known | No fabricated healthy or no-provider verdict |
| `hub-empty` | No configured editor; explain preview/download remain capability-dependent | Connect existing; secondary Install test editor links to Apps, never starts installation |
| `hub-active` | Confirmed route/scope plus separately aged health | Inspect or manage through current allowed actions, not an unconditional healthy badge |
| `hub-stale` | Last confirmed permitted facts and age, current availability uncertain | Check status; stale health cannot authorize a new launch |
| `hub-disabled` | Editing disabled for the confirmed scope; permitted preview/download/local-open availability shown separately | One currently allowed configure/enable remedy through the owning flow, not an activation bypass |
| `hub-degraded` | Supported partial capability and current safe-launch policy, with observation age | One owner-projected remedy; no blanket healthy claim or unsupported editing action |
| `hub-failed` | Editor unavailable, safe failure reason and capability-filtered alternatives | One permitted recovery action; no inference that Drive files or versions were lost |
| `hub-denied` | Safe access error, no protected provider/scope/operation facts | Return to an authorized destination; no existence leak |
| `endpoint-invalid` | Error beside labelled input and an error summary | Focus first invalid field; preserve permitted non-secret input |
| `trust-required` | Required ownership/approved trust information incomplete | Explain the missing prerequisite; no license entitlement invented by a checkbox |
| `discovery-running` | Named bounded phase, elapsed and last-update times | Observe existing check; no duplicate request on reload |
| `discovery-unreachable` | Connection failed, safe remedy and correlation ID | Retry current check when allowed; no automatic mirror or insecure trust fallback |
| `discovery-disallowed` | Target refused under Office egress policy | Edit endpoint or use the authorized policy-owner remedy; no bypass toggle |
| `discovery-proof-invalid` | Proof absent/invalid, candidate not qualified | Correct provider configuration; never downgrade into a qualified read-only editor |
| `qualification-running` | Synthetic open/save steps, no production save claim | Observe owning operation; closing the view does not cancel it |
| `qualification-save-failed` | Candidate test failed; previous route fact unchanged | Show safe remedy; never label customer files saved or activate candidate |
| `qualification-unknown` | Checking result; last confirmed stage/age and operation identity | Status reconciliation, not a new qualification request |
| `routing-inactive` | Current qualification receipt plus scope/rollback target | Explicit Activate only if reducer-projected allowed; success of qualification alone does nothing |
| `routing-stale` | Candidate/config/receipt no longer current or expired | Refresh and requalify as required; no reuse of old confirmation |
| `activation-pending` | Activation requested, route not yet confirmed changed | Reconcile same request after ambiguous response; disable duplicate submission |
| `activation-confirmed` | Authoritative activated scope, receipt and next action | Return to hub; health and file launch permissions remain separate facts |
| `activation-denied` | Safe refusal; no authority-restoring retry | Remove newly unauthorized content; preserve only still-permitted input |

For every mutation, bind expected generation, idempotency identity, audit reason
and explicit confirmation according to D5.0a. The UI does not allocate wire paths,
new roles, numeric exit codes or a second pending-operation store. Do not import
the force-end step-up requirement into ordinary activation without its own policy.
Authentication denial takes precedence over rendering a cached successful result.

Long checks show the named current step and total steps, elapsed time, last update
and operation identity. Use determinate download progress only when totals exist;
discovery/verification/qualification use named phases, not invented percentages.
When a phase exceeds twice its expected duration, show the warning, diagnostics
and owner-projected recovery action without starting another operation. Unknown
expected duration is shown as unavailable, not guessed or silently treated as zero.

## Cross-owner lifecycle snapshots

These are read-only companion frames, not additional connection-wizard actions.
They reuse D5.4
and the representative lifecycle matrix.

| Fixture | Must remain separate | Forbidden interpretation |
| --- | --- | --- |
| `update-postponed` | Coordinator result, retained compatible identity, Core admission and current Office availability | Postponed Office update displayed as installed target or Office update success |
| `removal-uncertain` | Route revocation and owned-runtime cleanup progress, operation age/recovery | Runtime removed while cleanup remains uncertain |
| `removed-data-retained` | Confirmed uninstall result and independent retained-data disposition | Endless uninstall watch, implicit purge or deletion of Drive files/history |
| `purge-blocked` | Separate purge operation/authorization and legal-hold refusal where disclosure is allowed | Uninstall success used as purge permission or an all-data-erased claim |

Drive versions, branches, ACLs and receipts are never editor-uninstall targets.
Source pages remain contextual links, not copies of provider configuration.
BYOL does not expose Setjoin-owned runtime-removal actions for external resources.

## Shared components, responsive behavior and accessibility

Reuse the common administration shell, labelled fields, buttons, status rows,
inline errors, operation detail and disclosure patterns. Before implementation,
bind each to its exact U2 primitive/route owner and keep/replace/retire mapping;
these are semantic reuse requirements, not a claim that every needed component
already exists. Avoid card mosaics, decorative progress percentages, generic
success toasts and ornamental icons. Keep the first viewport focused on the task.

Use the shared proposed board's token layer while preserving current production
rules. No external fonts/CDN, route-local palette or fake upstream editing chrome.
New visual values remain proposals until U1 approval. Each required message and
status has text independent of color; diagnostic identifiers stay stable Latin text.

- Wide: persistent navigation, main task workspace and optional details region.
  Narrow: retain page identity, status and action before details; fields use full
  available width, labels wrap and controls remain reachable without hover.
- Tab order follows visual reading order. Step transitions focus the new heading;
  validation focuses the first invalid field with a linked error summary. Safe
  return restores the invoking control when present, otherwise the page heading.
- Polite progress announcements report phase changes, not each clock tick. Busy
  sections retain stable navigation. Unknown, denied and failed results have
  distinct text; focus does not jump during background observation.
- Visible labels survive filled inputs. Dialogs have names and safe initial focus;
  Escape/view close affects observation only, never operation cancellation.
- Required body text targets at least16px in the proposed packet; actual token
  succession remains U2/U3 work. Verify contrast, focus visibility, 44px touch
  targets, reduced motion, 200% text zoom and 400% reflow. Chinese/English and
  long synthetic names must not hide consequences, labels or recovery actions.

## Finite acceptance and evidence plan

Freeze the following ten case groups as directed assertions before authoring the
rendered packet. A group is not one assertion and the count is not whole UI coverage.

| Group | Required fixtures / exact acceptance intent |
| --- | --- |
| OHD01 Initial truth | All seven non-denied hub states: loading is not empty; age/route/health remain distinct; disabled/degraded/failed show remaining authorized capabilities and one allowed next action; no implicit activation |
| OHD02 Endpoint and ownership | Invalid input, trust requirement and BYOL happy path; values survive permitted back/retry, external runtime remains customer-owned |
| OHD03 Discovery | Running/unreachable/disallowed/proof-invalid plus successful discovery; each remedy routes to its real owner, no trust downgrade; current/total steps and the >2× expected-duration warning preserve the same operation |
| OHD04 Qualification | Running/save-failed/unknown plus confirmed pass; test uses synthetic data, failure preserves prior route, pass stays inactive; named progress, elapsed/last-update times and delayed/unknown-duration fixtures remain truthful |
| OHD05 Activation | Inactive/stale/pending/confirmed/denied; expired and mismatched receipts refuse, duplicate/lost-response cases reconcile the same request |
| OHD06 Revocation | Revoke at every protected step and while observing activation; safe error, protected content removed, no cached success disclosure or revived authority |
| OHD07 Return and reload | Back/forward/reload/view close at running checks and mutation ambiguity; focus/input preservation only while authorized, no duplicate effects or implicit cancel |
| OHD08 Lifecycle composition | All four companion snapshots; operation owner and distinct data/runtime/Core/Office outcomes remain visible and truthful |
| OHD09 Presentation | Every fixture with identical content in light/dark × Chinese/English × 360×800/768×1024/1024×768/1440×900; verify layout, labels and next action, include directed long-name fixtures; 390px may supplement, not replace these U1 widths |
| OHD10 Accessibility | Keyboard reachability/order/focus/announcements, contrast, zoom/reflow, coarse pointer and reduced motion across all six templates and failure dialogs |

Authoring must enumerate controls and their exact selectors, initial fixtures,
action sequences and expected visible/hidden/disabled/results per group. Add the
successful discovery and qualification fixtures explicitly; do not leave them
implicit in the failure matrix. Record impossible combinations with reasons.
Security/generation/response-loss combinations are directed, not reduced to
pairwise coverage. Static assertions do not prove server enforcement, real assistive
technology behavior, browser editing or accessibility conformance.

Retain source/input hashes, artifact hash, exact fixture/control denominator,
browser/platform, viewport/theme/locale, screenshots, observed focus and failed
assertions. Unrun, unavailable and synthetic observations remain labelled. Store
rendered artifacts in the task's existing external gstack designs directory and
link the shared board; do not place HTML mockups in product source or this folder.

## Connected control inventory

These are exact proposed prototype hooks, not frozen production API names. The
existing snapshot storyboard's generic `primary` button does not satisfy this
inventory. Each control must have a visible English/Chinese label, accessible
name and the state-dependent behavior below. `data-office-action` selects actions;
`data-office-field` selects editable fields. Read-only facts are not form inputs.
There are20 distinct hooks, including three previously implicit confirmation,
ownership-acknowledgment and optional scope controls. Conditional absence is an
explicit test outcome, not a missing-control pass.

| Hook / control | Present and enabled when | Required behavior |
| --- | --- | --- |
| `connect-existing` | Authorized hub, no conflicting candidate mutation | Enter endpoint; carry a safe return target, not a reusable grant |
| `apps-detail` | Authorized discoverable test-editor entry | Navigate to existing Apps detail; do not install or activate |
| `endpoint` field | Endpoint step, permitted candidate configuration | Visible HTTPS label/error; no URL credentials; client validation is not SSRF or trust enforcement |
| `audit-reason` field | Confirmation for a candidate mutation or activation | Preserve permitted reason on failure; bind the reason to the particular submitted request |
| `secret-reference` field | Only if the qualified provider contract actually requires an approved secret reference | Select a permitted reference; never display secret value or invent a required credential |
| `support-ack` field | Only when the owner requires acknowledgment of the displayed BYOL responsibility | Initially unchecked; binds the current ownership text/configuration, never grants license entitlement or runtime authority |
| `routing-scope` field | Only when the owner admits a choice between allowed scopes | Select only owner-projected values; change invalidates local routing confirmation without changing the route |
| `confirm-action` field | At the current explicit configure/discover/qualify/activate submission preview | Initially unchecked; names the particular effect and scope; no reusable wizard-wide consent |
| `support-details` disclosure | Permitted trust step | Customer/BYOL runtime and update owner, permitted claim and relevant consequences; acknowledgment is not license entitlement |
| `next` | Valid current local step and required completed authoritative predecessor | Move one wizard step only; must not silently configure, qualify or activate |
| `back` | Prior step exists and is still authorized | Preserve permitted input; show in-flight work as continuing; never cancel it |
| `configure` | Current candidate preview, reason, explicit confirmation and current allowed action | Submit the exact candidate change; show accepted/unknown/refused separately; no route change |
| `discover` | Current configured candidate, approved prerequisites and allowed check | Start the owning bounded discovery operation; no second operation on double click |
| `qualify` | Current discovery/proof succeeds and qualification is allowed | Explicit temporary-document test confirmation; no customer file picker and no route activation |
| `review-routing` | Current successful qualification | Display candidate identity, scope, receipt and previous route/rollback target; no mutation |
| `activate` | Fresh routing review, valid bound receipt, reason, explicit confirmation and current allowed action | Submit only to the activation owner; pending or response loss cannot display confirmed activation |
| `check-status` | Authorized observation of an accepted or ambiguous request | Reconcile that request/operation; do not allocate new mutation identity |
| `retry` | Authoritative failure explicitly permits another attempt | Refresh applicable preview/generation first; distinguish a new admitted attempt from same-request response-loss reconciliation |
| `diagnostics` disclosure | Current permission admits the related facts | Safe code, owner, remedy, correlation ID and documentation link; no secret/document payload |
| `return` | Safe permitted destination available | Return focus to the invoking control or owning heading; close observation without cancellation |

Configuration and explicit confirmation fit within the Endpoint/Trust steps;
they do not add a sixth wizard step. The preview shows which fields will change
before `configure`; neither `next` nor editing a field submits that change.
Support acknowledgment and any required reference follow the approved provider
contract, not a newly invented list of roles or mandatory form fields.
Scope selection, if supported, is restricted to the owner's allowed values and
requires a refreshed routing review; this packet does not grant arbitrary scopes.

In-flight work disables duplicate mutation controls while leaving authorized
observation and navigation usable. Unknown response before an operation ID arrives
uses the original request identity for lookup; it must not fabricate an operation
ID. A confirmed ID may then replace that lookup presentation without creating a
second request. Provider/configuration changes invalidate their dependent discovery,
qualification and routing evidence; local field edits alone are unsaved input,
not proof of a committed generation change.

### Draft, request and observation boundaries

The connected prototype keeps three visibly synthetic records separate. A draft
contains permitted form inputs; a submitted request freezes its exact action,
candidate/configuration, expected generation, scope, approved secret reference
when applicable, audit reason and confirmation context; an observation contains
only the current permitted projection of the owning result. This is a test model,
not another database, wire schema or browser persistence contract.

- Changing candidate, endpoint, approved reference, scope, effect or relevant
  ownership text clears the affected local confirmation. Changing the audit reason
  also requires reconfirmation before a new submission. Back/forward may preserve
  permitted input, but never carries consent into a different request preview.
- A submitted request remains immutable after response loss. Edits to the draft
  cannot rewrite its identity or payload; `check-status` addresses the submitted
  record. A retry after an authoritative, retryable terminal failure uses a fresh
  preview and confirmation. It is not an alias for ambiguous-request reconciliation.
- Successful configuration invalidates prior dependent discovery/qualification
  evidence. A merely edited field instead displays “unsaved changes”; it does not
  claim a new server generation. Activation cannot silently discard or incorporate
  those changes: require the user to commit/requalify or explicitly discard them
  and inspect the still-current candidate before confirming activation.
- Losing view permission removes protected observations and draft fields no longer
  readable. Losing only mutation permission removes the relevant submit controls
  while still-permitted read/status/navigation remains available. Neither case
  cancels already-admitted work or upgrades a last-known result into current truth.
  Both clear the affected unsent confirmation; later permission restoration requires
  a fresh authorized preview and new confirmation, not revival of cached consent.
- The fake response driver accepts a request identity and supplied outcome. It
  cannot attach a response to another candidate/request or replace a current
  observation with older progress. Denial overrides cached success; an invalid or
  mismatched response is unknown/invalid observation, never synthetic success.

Extend OHC02 with unchecked confirmation and acknowledgment, each confirmation-
invalidating input, and conditional absence/presence of reference/scope controls.
Extend OHC03 with edits while awaiting a response and unchanged frozen payload.
Extend OHC04 with unsaved edits versus confirmed configuration; extend OHC10 with
wrong-request, wrong-candidate and older-progress responses. Assert zero new
submission for local navigation, editing, response injection and status lookup.
These are required future checks, not observations from the snapshot artifact.

## Directed connected sequences

These twelve sequences are future prototype/domain assertions, not executed
results. The fake response driver is outside the product UI and visibly labelled.
It supplies independent outcomes; clicking a product action cannot auto-generate
its own success receipt. Tests inspect both action count/identity and visible state.

| ID | Sequence and injected outcome | Required observation |
| --- | --- | --- |
| OHC01 | Empty hub → endpoint → invalid input → correct → trust → preview → configure confirmed → discovery confirmed → qualify confirmed → review → activate confirmed | Each step has a visible action/receipt boundary; existing route stays unchanged until activation confirmation |
| OHC02 | Enter permitted endpoint/reason → next/back; inject configure failure → retry | Values preserved while authorized; first invalid field gets focus; no background submission by navigation |
| OHC03 | Double-click configure, discover, qualify and activate separately; lose each response | One original request per action admission; status lookup uses its identity; no duplicate effects or invented operation ID |
| OHC04 | Change candidate after successful discovery or qualification | Dependent results become stale; cannot activate old receipt; refreshing the view does not revive it |
| OHC05 | Routing review → receipt expiry, config mismatch or stale expected generation before submission | Stable refusal and refresh/requalification remedy; current route not replaced |
| OHC06 | Qualification save fails with previous active provider, then repeat with no provider | Respectively previous active route and no-provider remain unchanged; no customer save claim |
| OHC07 | Revoke viewing/configuration/routing authority at each applicable step and during unknown activation | Remove newly protected facts; disable/refuse actions under current authority; no cached-success or auth-restoring retry |
| OHC08 | Reload/back/close observer during discovery, qualification or activation ambiguity | Re-entry reconciles original request under fresh authorization; no implied cancel or operation retirement |
| OHC09 | Observe running check past twice synthetic expected duration; separately omit expected duration | Named step/total, elapsed, update age and warning where measurable; no guessed deadline or duplicate operation |
| OHC10 | Lose status transport, then receive terminal outcome; separately receive authentication denial | Unknown until verified outcome; denial takes precedence over cached terminal success; focus remains stable during observation |
| OHC11 | Change allowed routing scope or navigate to a candidate with different generation | New explicit review/confirmation binds current candidate/scope; prior candidate's reason, receipt and identity cannot be silently replayed |
| OHC12 | Return to caller after success/failure, then invalidate caller permission | Restore valid origin/focus; otherwise explain safe fallback to an authorized owning view without leaking the old target |

Run OHC03 separately for each of its four named actions; OHC04 for discovery and
qualification; OHC05 for all three listed stale-evidence causes; OHC06 for both
initial routes. OHC07 varies view versus mutation versus routing permission only
where that permission applies; freeze the action-to-owner mapping before claiming
the denial matrix complete. OHC08 varies three operation kinds and three departure
mechanisms. Do not report twelve rows as twelve exhaustive tests.

Reload durability is a domain contract, not permission to persist provider facts,
tokens or secret references in browser storage. The prototype may retain a visibly
synthetic fake-service state for a reload fixture; product re-entry must query the
authorized server. Any proposed persistence of actual drafts needs its owning
data/security contract and is not authorized here.

## Work order and open boundaries

1. Produce the six-template fixture/control inventory and external HTML packet,
   reusing the existing board. This is planning visualization, not product code.
2. Inspect each state and directed transition; repair visible contradictions and
   retain bounded evidence, then obtain independent Astra/Fable Design assessment.
3. Integrate the other six Office UI families and connected Drive journey; complete
   all seven Design passes. Do not promote this packet to a whole-phase score.
4. Continue DX, Engineering last and final integration; preserve user visual,
   security, implementation and real runtime/release gates.

Not in this packet: three managed-install ingress wizards, Sources mutation,
domain provider setup, host effects, general Apps lifecycle and the actual
Drive/editor conflict UI. They stay required in their owning families, not cut.
Actual palette/type/density/navigation approval stays with U1; this document adds
no new commercial license decision, backend capability or permission policy.
