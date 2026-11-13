# Compatibility and support-cell vocabulary

Compatibility is an evidence-bounded statement about a named support cell and
business outcome. It is not a count of familiar Exchange cmdlets.

## Support cell

The canonical support-cell tuple is:

```text
(Exchange product family,
 named CU,
 exact build/security-update allowlist,
 topology,
 directory authority,
 PowerShell/runtime,
 cloud-adapter version if any,
 collector version,
 discovery-catalog/schema version,
 registry version,
 Setjoin release)
```

The tuple is serialized and digested. Unknown builds are `unsupported_source`
until admitted by evidence. All behavior-bearing fields match exactly except for
finite CU/build members covered by an approved equivalence predicate. A Setjoin
release change requires a rerun or a code-equivalence receipt tied to changed files
and cases.

### Current A0 metadata is narrower

The A0 input carries `organization`, `topology`, `builds`, collector version, and
registry digest. It does **not** establish the full product support-cell tuple,
server compatibility, or a publishable claim. The A0 registry currently describes:

| Capability ID | Administrator outcome | Fixed source commands |
|---|---|---|
| `EX-A0-TOPOLOGY` | identify Exchange build and topology | `Get-ExchangeServer`, `Get-OrganizationConfig` |
| `EX-A0-MAILBOX-DELEGATION` | inventory explicit mailbox access and send delegation | `Get-Mailbox`, `Get-MailboxPermission`, `Get-RecipientPermission` |
| `EX-A0-CALENDAR-VISIBILITY` | assess default and explicit calendar-folder visibility | `Get-Mailbox`, `Get-MailboxFolderStatistics`, `Get-MailboxFolderPermission` |
| `EX-A0-RESOURCE-BOOKING` | inventory resource booking, approval, and conflict policy | `Get-Mailbox`, `Get-CalendarProcessing`, `Get-DistributionGroup`, `Get-DistributionGroupMember` |

The PowerShell collector's compiled allowlist contains those ten literal
read-only cmdlets. A registry file cannot add a dynamic command. This is a static
A0 boundary, not a claim that every listed command has been executed successfully
against a live estate.

The initial planned product support cell is one bounded on-premises Exchange 2019
build family. Exchange 2016 and hybrid remain explicitly unassessed until their
adapters and live evidence exist. The fact that A0 accepts `on-premises` and
`hybrid` labels does not change that gate.

## Three independent status axes — future canonical vocabulary

Never compress these axes into one compatibility score:

| Axis | Allowed values | Question answered |
|---|---|---|
| `outcome_mapping` | `native`, `transformed`, `alternative`, `none` | How does the business outcome map to Setjoin? |
| `assessment_state` | `observed`, `not_observed`, `incomplete`, `unknown` | What did this run actually establish? |
| `claim_state` | `supported`, `provisional`, `experimental`, `unassessed`, `unsupported`, `excluded` | What claim, if any, may the evidence policy publish? |

`native` means the existing Setjoin behavior preserves the outcome. `transformed`
means an explicit migration transform is required. `alternative` means a named
different workflow preserves the outcome and must explain its operational cost or
degradation. `none` means no mapped outcome is established. A mapping is not a
claim state.

The current A0 row statuses (`observed`, `unassessed`, `blocked`, `unsupported`)
are pre-product discovery statuses. They must not be copied into `claim_state`
without the future evidence resolver.

## Phases and run vocabulary — future reference

The product contract separates business phase from run status:

```text
migration_phase = assessment | initial_copy | shadow | cutover
run_status      = active | paused | failed | rollback_in_progress |
                  rolled_back | forward_recovery
```

A0 is only an assessment/discovery artifact. It has no initial-copy, shadow,
cutover, rollback, or server-run authority. Do not add a cutover call-to-action to
an A0 report.

## Evidence tiers — no live claim implied

The design defines these future evidence tiers:

| Tier | Claim label | Minimum evidence shape |
|---|---|---|
| T0 fixture | `experimental` | deterministic schema/parser/report/native-mapping fixtures with digests and source fingerprint |
| T1 controlled live | `provisional` | controlled-lab Exchange support cell, retained commands/results, digests, reconciliation, and negatives |
| T2 representative live | `supported` | customer-approved representative support cell, retained sanitized evidence, named acceptance cases, and release receipt |

A cell without T1 remains `experimental` or `unassessed`; only T1 may be
`provisional`, and a `supported` claim requires current non-invalidated T2 evidence
or an approved finite equivalence predicate. This documentation corpus does not
claim any T1 or T2 evidence, customer approval, acceptance case, or release
receipt exists.

## Planned compatibility skew rules — reference only

The future artifact contract is semantic-versioned:

- patch changes remain byte/behavior compatible;
- minor versions may add preserved optional fields;
- a major change requires an explicit migration;
- the current server reads current and N-1 bundles;
- unknown fields are preserved and block affected claims rather than disappearing;
- unsupported skew fails before collection/import.

The plan's example is illustrative contract vocabulary: server `1.5.x` reads
`1.5.x` and `1.4.x`, rejects `1.3.x` and unknown `1.6.x`, and prints a supported
range plus safe upgrade order. It is not a statement that a server with this
behavior is shipped.
