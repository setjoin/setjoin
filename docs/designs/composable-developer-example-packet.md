# Composable developer example packet

Date: 2026-09-07. Status: proposed CP7/E7 documentation input; no executable sample, public schema, qualified runtime, timing result or implementation approval is supplied here.
Owner: CP7 DX amendment, with the first qualified example delivered by its E2 or domain-beta owner.
Authorities: DX contract, [extension design](extension-control-plane-public-system-apps.md), restricted WebApp authoring, [scope/manifest map](composable-scope-and-manifest-map.md), [error contract](composable-errors-and-threat-cases.md).

## Scope and evidence boundary

This synthetic learning fixture is not a third required product alongside Collabora / first-party Outbound Mail Approval. Its WebApp needs only a qualified manifest/ingress profile, not every SDK. A separate eligible-capability fixture exercises denial without giving the learning app business-data authority.

All paths, sample values, fixtures and actions below are proposed. No command, schema field, error allocation, selector, generated package or current interface implementation is asserted. This is contract-based planning, not a source-code audit. CP0 must freeze production paths and semantics before executable instructions are published.

WASI, native fallback, raw Compose execution, host mounts and direct SQL/S3 credentials are excluded. Remote cannot substitute for failed managed-OCI qualification. Non-effectful compilation yields neither a grant nor execution authority.

## Proposed sample and pin record

Documentary fixture edition: `CP7-EX/1`. This identifier is not a manifest schema version, platform apiLevel, domain contract major or app release version. The proposed bundle label is `cp7-example-v1`; no such directory is created by this packet.

| Input | Proposed fixed content / pin requirement | Before executable publication |
|---|---|---|
| Learning app | One-service “Hello” WebApp; versions `0.1.0` and compatible `0.1.1`; labels `Hello, Setjoin` → `Hello, developer` | Select maintained, license-checked source; pin source revision/archive and lockfile digests |
| Author input | One restricted-Compose `web` service, internal port `8080`; no undeclared egress or Setjoin business-data request | Freeze grammar, input bytes/digest, canonical compiled output and mutations |
| Image/runtime | Qualified managed OCI host/platform profile with bounded resources | Pin repository, distinct per-platform image/platform-manifest digests, profile revision and host facts; no mutable-tag-only pin |
| Installation | Synthetic organization/account scope; separate author, approver and denied actor | Resolve actual permissions/IDs through the scope contract; these responsibilities create no roles or tables |
| App-owned data | Synthetic record `note-001`, value `retain this synthetic note`; no customer content, mail or external database | Freeze the qualified app-owned storage claim/profile and format revision; record a content oracle independent of the app response |
| Grant fixture | Separate registry-selected eligible action; narrow scope, approved/unapproved actors | Pin capability/action/resource/data-class tuple and eligibility proof; Sensitive access needs all accepted conditions, unqualified authority-affecting access stays unavailable |
| Tool/schema | Registry-owned validation/compiler projection | Pin source/generator/tool versions and digests, entrypoints, schema/apiLevel/domain majors and canonicalization fixtures; no parallel schema |
| Documentation/receipts | Four deliverables bound to the same sample/contracts | Pin bundle digest, case manifest, evidence paths, observation permissions and owned cleanup plan; missing pins mean NOT RUNNABLE |

The learning content is fixed; unknown artifact digests/tool paths are explicit freeze slots, not pins. Changed inputs require a new bundle record and affected-example reruns; retained evidence must still match its inputs.

## Prerequisites and learner path

Prerequisites: healthy authorized test installation, qualified profile/ingress, pinned tooling/docs, synthetic identities, available approver, storage quota and task-owned namespace. Report Setjoin installation, downloads, qualification and approval waiting separately, not as hidden tutorial steps.

| Conceptual action — not executable command syntax | Required visible result and boundary |
|---|---|
| Inspect the supported profile and sample pin record | Required capabilities, unavailable options, source/version/digest and prerequisites visible before effects; stop on missing qualification |
| Edit the label and validate the author input | Safe field diagnostics or a deterministic closed plan; validation creates no host/runtime/network resources and obtains no credentials |
| Inspect consequences and request approval | Exact scope, requested capabilities, resources and data treatment visible; author cannot approve its own elevated authority by changing a manifest |
| Apply the approved intent and observe its operation | Authorized receipt binds accepted intent, installation and generation; lost response uses status reconciliation, not a blind second install |
| Open the app through admitted ingress | Correct label and release identity visible; origin/audience and current capability fences hold; a validator or mock tile is not proof of this result |
| Change to the compatible version, then remove with keep-data | Distinct version/digest shown, synthetic record preserved across qualified update, explicit retained-data result after removal |

CLI/CP0 must freeze commands, arguments, noninteractive behavior, exits, machine output and observation route before copyable instructions. Never expose secrets in history, previews or evidence. UI selectors require implementing-owner binding to real controls.

## Five failure exercises

Each exercise changes one pinned input. Wording is illustrative, not a wire enum/status; exact mappings and diagnostics remain [EP-P1/P2](composable-errors-and-threat-cases.md).

| Exercise | Proposed deliberate mutation | Safe outcome and correction | Receipt / negative oracle |
|---|---|---|---|
| Invalid manifest | Add one schema-disallowed field; retain original/mutated digests | Show safe field location/expected form; correct against that schema and revalidate | Reject before privileged effects; corrected positive compiles; DX-E02 / D6 compile boundary |
| Unavailable runtime | Request an unadmitted profile or remove required host capability | Select a genuinely compatible admitted profile or stop; no privileged/native fallback | No runtime, route or host-resource creation; D6 runtime discriminator / zero ambient effects |
| Missing grant | Authenticated but unapproved actor uses eligible-action fixture | Explain safely discoverable missing approval; authorized approver may approve eligible scope. Ineligible/unqualified action stays unavailable | No domain effect before approval or outside scope; paired approved positive; DX-E03 / SC-P3 |
| Incompatible contract | Separate fixture requires unsupported domain major | Select genuinely compatible app/host or qualify migration; declaration edits alone do not repair semantics | Candidate blocked; valid old generation retains existing grants; DX-E06 / SC-P4 |
| Revoked artifact digest | Controlled catalog revokes selected candidate digest | Block new admission; show authorized advisory/corrected qualified artifact; no relabelling or verification bypass | No admission of revoked bytes; no catalog-only shutdown of existing installation; DX-E06 / ET18 |

Catalog withdrawal is not explicit local revocation; advisory, grant, health and signature are distinct facts. Errors exclude secrets, foreign-resource existence and unauthorized diagnostics.

## Finite lifecycle fixtures

| Fixture | Before → action → required observable outcome | Owner / unresolved concrete binding |
|---|---|---|
| Compatible update | `0.1.0`, original label, `note-001` → approved `0.1.1` addition → new identity/label visible; same synthetic record and current scoped authority | E1/E2 and app-data owner; pin exact before/after bytes and data-format compatibility proof; DX-E06 |
| Broader grant | Valid generation with narrow grants → candidate requests an additional eligible capability → candidate waits for explicit approval, acquires no new authority; old still-valid generation retains only old grants | E0/E1/domain; freeze actual eligible tuple and approval predicate; grant eligibility is not inferred from signature or administrator willingness |
| Explicit local revoke | Eligible fixture already approved → authorized revocation → fresh requests denied, protected view invalidated, Setjoin-mediated connections closed under the qualified owner contract | E1/E2/CP5; bind current fence and independent connection oracle. D6’s proposed generic bound requires qualification; do not borrow it as an observed measurement or weaken D5 accepted-save rules |
| Lost response | One approved intent → response deliberately lost after acceptance → authorized receipt resolves that same operation; changed intent with the same key cannot execute | E1/domain; pin exact idempotency/receipt lookup and permission contract; DX-E05 / ET06–07; missing receipt remains unresolved, not “safe to retry” |
| New domain major | Working admitted generation → candidate requires unsupported semantics → candidate blocked while old valid authority remains | Domain/registry owner; pin supported/unsupported contracts and a real migration path before any success example; DX-E06 |
| Catalog withdrawal | Running installation plus candidate → candidate digest withdrawn → new admission denied and advisory visible, existing runtime not silently stopped | E7 with runtime security owner; explicit emergency mitigation is a separate decision, not this fixture |
| Remove, keep data | Updated app with `note-001` → inspect exact target/ownership preview, confirm removal retaining data → inactive installation and itemized retained app metadata/owned volume, quota/tombstone facts | E1/app-data owner; pin exact preview, resulting receipt and independent content/ownership oracle; DX-E07 |
| Unsafe image rollback | App-data format changed incompatibly or compatibility unknown → request prior image → do not claim restoration from image rollback alone; expose the qualified recovery requirement or safe refusal | App-data/domain owner; no automatic reverse migration, restore success or erased-data claim is fabricated |

Keep-data removal distinguishes Setjoin domain records, app metadata, managed volumes, secret references/credential authority, runtime resources and historical backups. Retention does not preserve active credentials or routes. Legal holds, shared resources and other installations remain protected. Later purge is separately authorized and is not part of this tutorial. Remote-provider deletion would require its own receipt; local removal cannot prove remote erasure.

## Four versioned deliverables

The following are reserved paths **inside a future example bundle**, not existing repository files or links. All four carry the bundle edition plus exact admitted contract, sample/source and tool/generator pins; local installed-bundle search and reading must work without implying offline `.sjapp` installation.

| Deliverable / proposed bundle-relative path | Required concrete content | Completion evidence, not claimed here |
|---|---|---|
| Tutorial — `docs/tutorial-first-app.md` | Prerequisite checklist; the learner sequence above with actual commands/UI controls once frozen; expected label/version result; deliberately invalid input and corrected run; explicit ending cleanup | Independent learner receipt for DX-E01/02/04/07; copied commands tested against exactly the supported sample; real ingress required |
| How-to — `docs/how-to-debug-update-remove.md` | Five failures; operation-status reconciliation; compatible update, new-grant and local-revoke steps; keep-data preview/receipt; when to stop for migration or qualified recovery | Matched before/after and negative-effect receipts for DX-E03/05/06/07; no unconditional mutation retry, global prune or shared reset |
| Reference — `docs/reference-contract-and-tools.md` | Registry-generated exact supported input/CLI contracts, field bounds, compatibility axes, errors and machine output; provenance and supported versions; unsupported features explicitly absent | Generated references match pinned registry/generator bytes; CP0 SC-P1/P6 and EP-P1/P2 resolved; illustrative fields cannot masquerade as parser support |
| Explanation — `docs/explanation-authority-and-data.md` | Author request versus grant versus eligibility; compile versus execution; app version versus schema/apiLevel/domain major; catalog withdrawal versus local revoke; retained app data versus domain records/backups | Owning security/data/version contracts cross-checked; no new policy or licensing promise; maintainer/escalation owner identified before support claims |

Author reference/explanation before copyable procedures. These four production guides are specified, not delivered or executed here. Stale examples block their documentation gate.

## Evidence ownership and remaining gates

DX-E01–08 and D6’s named cases are proposed obligations, not executed selectors. Bind each to source/test path, selector/command, fixture bytes, positive/negative oracles, output and cleanup receipt before execution.

Separate paper, compiler, fake-runner and live evidence. Opt-in synthetic receipts record completion, every assistance request, first failure/fix, warm loop, cold provisioning and approval wait. The proposed 10-minute warm-loop target is unmeasured, not an installation SLA. This fixture cannot alone satisfy the stable two-external-developer/two-different-category gate.

| Still required | Owning gate; effect of absence |
|---|---|
| Exact sample source/license, image/platform digests, locks, profile/resource/storage pins and source-bound fixture bytes | E2/app-data owner; sample remains non-runnable until selected and qualified |
| Production schema/generator/tool paths, canonicalization/limits, exact eligible capability and scope-permission mappings, CLI/error/receipt semantics | CP0/E0/E1/domain; no public contract freeze or copyable operational commands |
| Real ingress/fence/revocation/data-update/keep-data oracles and exact automated selectors | E2/CP5/domain; compiler/mock output cannot close lifecycle or runtime evidence |
| Four executable version-bound guides, maintainer/escalation ownership, applicable licensing clearance and independent receipts | First owning E2/domain-beta slice, then E7 aggregate; no publishing/support/stable claim from this paper |

No new policy is decided. New roles, unqualified capabilities, stronger privilege, erasure or publication/license decisions return to their owners.

## Authoring receipt

Only this document is created; no sample, image, service, volume, credential, test run or external resource. Runtime and visual/keyboard behavior are unverified. Root owns integration, indices and Graphify refresh; ledger: planning continuation.
