# Office operations and verification

This runbook is for a repository contributor or platform operator after the
normal Setjoin clone-to-green checks. It owns the Office-specific front door;
it does not enable production features or replace the normal build/test lanes.

## Start with the fake path

```bash
bash scripts/verify-office-foundation.sh doctor
bash scripts/verify-office-foundation.sh quick
bash scripts/verify-office-foundation.sh evidence <manifest.json>
```

The fake path is offline-capable and contains no tenant, database, object-store,
editor, browser-session, or credential input. A passing result means the
contract scaffold proved:

1. a choice opened a bounded session;
2. the session acquired an opaque lock;
3. a save produced one accepted receipt and one immutable Drive version;
4. History exposed the same receipt/version fact;
5. a stale-base save produced a branch and left Main unchanged.

The retained manifest is under
`test-results/office-foundation/<run-id>/manifest.json`. It contains source
manifest digests, exact stages, the contract boundary, and external-gate state;
it contains no document bytes, credentials, tokens, or personal data.

`core` runs the focused provider-core unit tests. The database-backed vertical
lane additionally proves CheckFileInfo, lock, PutFile, GetFile, immutable Drive
versioning, and the resulting save receipt against a fresh Setjoin schema. The
deterministic fake provider remains labelled `contract_scaffold`: it does not
prove renderer fidelity, deployment readiness, licensing, or live Collabora
interoperability.

## Doctor output

```bash
bash scripts/verify-office-foundation.sh doctor --json
```

Doctor checks only local, non-secret prerequisites and manifest shape. It reports
the fake path as ready and classifies live Collabora separately. Missing live
inputs are an `external_gate`, not a reason to hide or disable the fake path.
Doctor does not download binaries, fonts, licenses, or entitlements.

The live profile may be supplied through approved operator paths using:

```text
OFFICE_COLLABORA_URL
OFFICE_COLLABORA_IMAGE_DIGEST
OFFICE_COLLABORA_SOURCE_DIGEST
OFFICE_COLLABORA_FONT_DIGEST
OFFICE_COLLABORA_LICENSE_EVIDENCE
```

The values are not printed or copied into evidence. The verifier records only
presence and file/digest validation status. Do not put secrets in these
variables. A live WOPI/Collabora run still needs pinned upstream inputs plus the
authority/isolation, security, capacity, corpus, and removal lanes.

## Live profile and provider removal

```bash
bash scripts/verify-office-foundation.sh live-collabora
```

Without all approved prerequisites this command exits non-zero with
`E_OFFICE_EXTERNAL_GATE` and names the missing category. It does not claim that
Collabora is installed or healthy. With prerequisites present, the command only
admits the profile for the later live adapter lane; it does not promote a
provider or flip a feature.

The removal rehearsal must stop new launches, fence callbacks, drain active
cohorts within a bound, preserve accepted receipts and Drive versions, remove
provider routing/binaries/secrets, and prove that originals, History, Preview,
Download, Compare, Restore, audit, and authorized local-open alternatives still
work. A provider may never become the authority for bytes or recovery.

## Stable diagnostics

Use the offline catalog when a lane fails:

```bash
bash scripts/verify-office-foundation.sh explain E_OFFICE_PROVIDER_UNREADY
bash scripts/verify-office-foundation.sh explain E_OFFICE_PROOF_REJECTED
bash scripts/verify-office-foundation.sh explain E_OFFICE_SAVE_RECEIPT_REPLAY
bash scripts/verify-office-foundation.sh explain E_OFFICE_UNSUPPORTED_OFFLINE_WEB
```

Every operator-facing failure should state the problem, cause, effect, next
action, stable code, documentation path, and run ID. Unauthorized or fenced
callbacks must keep an existence-safe response. A delayed response after a
committed save must resolve to the stored receipt/version and never encourage a
duplicate write.

## Evidence hygiene

`evidence` validates the retained manifest and recomputes the SHA-256 digests of
its two versioned source manifests. It does not read customer documents or
credentials. Failed or incomplete runs stay inspectable but cannot be described
as a rollout pass. Production rollout remains a separate decision after legal,
security, compatibility, licensing, load, backup/restore, and removal evidence.
