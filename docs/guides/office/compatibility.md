# Office compatibility and evidence boundary

This document defines how Office compatibility is classified for Setjoin V1.
It deliberately separates a testable contract from an external rendering,
licensing, and support claim.

## Evidence identity

Every claimed cell must identify all of the following before promotion:

- Setjoin release/build and provider-manifest version;
- exact OS, CPU architecture, browser or Electron runtime, and editor build;
- producer/version used to create the fixture;
- fixture/corpus ID and SHA-256 digest;
- required fonts and their distribution rights;
- reference-renderer identity and digest;
- retained output, semantic-loss notes, visual-delta result, and owner;
- license, source, notice, SBOM, security-response, and support evidence paths.

“Runs on Linux”, “runs on ARM”, “supports domestic platforms”, and similar
generic statements are not compatibility evidence or certification. A cell is
`supported` only when its exact evidence is retained. `candidate`,
`external-gate`, `unassessed`, and `unsupported` are distinct outcomes.

## Frozen V1 baseline

The versioned baseline is
`config/office-v1-acceptance-manifest.json`. Its matrix is intentionally
explicit about what is not yet claimed:

| Surface | Contract baseline | Promotion condition |
|---|---|---|
| Chromium/Edge | Current and previous stable at the freeze date | Browser open/edit/co-edit/save/reconnect/close cases and declared P95 budgets. |
| Firefox | Current and previous stable at the freeze date | The same semantic and recovery cases; no browser-version inference. |
| Electron | Pinned repository runtime | Windows, macOS, and Linux cells each need retained Electron evidence. |
| Desktop local-open | Customer-installed Microsoft Office, WPS Office, LibreOffice, or Collabora Office | Exact app/OS/build cell proves path containment, temporary-file filtering, crash/reconnect, and stale-base branching. |
| Mobile browser/WebView | Read-only Drive History, Preview, authorized Download, and metadata compare | No editing or local-open claim in V1. |
| Collabora web adapter | First qualified candidate | Pinned source/build, WOPI authority/isolation, corpus, load, removal, legal, and support gates. |

The matrix does not authorize a release claim. V227 enables
`feature.office_editing` and `feature.office_local_open` for the pre-release
product, while exact compatibility/support cells remain evidence-gated.

## Corpus and rendering policy

The V1 corpus has 50 licensed, customer-safe files stratified by producer and
risk: Word layout/tracked changes/comments/fields, Excel formulas/pivots/charts,
PowerPoint masters/notes/transitions/animations/fonts/media, legacy Office,
modern and legacy WPS, macOS Office, and iWork conversion cases. Each fixture
retains its original bytes and records round-trip, visual, semantic, warning,
and producer-reopen observations.

The licensed reference renderer is evidence input, not Setjoin authority. The
upstream Office rendering kernel is explicitly **excluded from compatibility
tests**: Setjoin does not fork, reimplement, silently download, or certify an
upstream renderer through this lane. A missing renderer, font, source digest,
notice, or license path is an external gate, not a pass and not a fabricated
failure of Drive History.

Hard failures are fixed before a run: corrupt or unopenable originals, lost
tracked changes/comments, incorrect critical formulas, active-content
execution, unauthorized data access, and silent loss of critical media. Any
non-critical visual tolerance or semantic loss must be declared before the run;
thresholds cannot be changed after seeing results. Visual comparison evidence
uses the predeclared region masks and SSIM threshold from the acceptance
manifest; it is not a substitute for byte identity of Drive originals.

## Protocol and local-open boundaries

Online adapters are evaluated through the provider-core contract and, for WOPI,
the discovery-derived WOPI profile: `CheckFileInfo`, `GetFile`, `PutFile`,
lock transitions, retry/idempotency, limits, expiry,
revocation, rename/trash, and provider removal.

`PutRelativeFile` (provider-side Save As) is not advertised by the V1 adapter.
Setjoin Save As remains a Drive operation so the new node, ACL, version lineage,
and audit record stay reducer-authoritative. A future WOPI capability may map
the protocol operation onto that same reducer instead of duplicating storage.

Local-open is a separate desktop adapter. It may invoke an administrator-allowed
application already installed and licensed on the device, but it may not pass
Drive/WOPI authority credentials to that application. The adapter must constrain
paths to the authorized FolderMirror root, exclude lock/recovery/autosave
temporary files, preserve the base version offline, and reconnect through the
normal Drive save path. A stale base creates a visible branch; it never silently
moves Main.

## Reading outcomes

Use the following vocabulary in evidence and support output:

- `pass`: exact evidence exists and all required cases pass;
- `blocked`: a required dependency or decision is missing;
- `external_gate`: evidence must come from an approved Collabora/editor/legal/
  customer path outside this repository;
- `unassessed`: no run has established a result;
- `unsupported`: the product intentionally does not claim the cell.

The fake-provider quick lane proves only the Setjoin authority contract:
launch, lock, accepted receipt, immutable version, History visibility, and
stale-save branch with Main unchanged. It is not a renderer-fidelity test, a
WOPI compatibility test, a license test, or customer support evidence.
