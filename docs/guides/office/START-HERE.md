# Office Foundation: start here

This is the contributor and operator entry point for the Office Foundation and
Drive History work. It describes the frozen contracts and the safe local proof;
it is not a production-support claim. The design authority is
[`docs/designs/office-drive-history-explorer.md`](../../designs/office-drive-history-explorer.md),
and the executable plan is
`retired-docs:superpowers/plans/2026-08-24-office-foundation-history-explorer.md`.

## The two-minute route

From a clone that already passes the normal repository bootstrap:

```bash
bash scripts/verify-office-foundation.sh doctor
bash scripts/verify-office-foundation.sh quick
bash scripts/verify-office-foundation.sh core
```

`doctor` is read-only and reports the fake-provider path separately from the
optional live-Collabora path. `quick` is deterministic, local, and does not
need Collabora, a license, a browser session, a database, object-store
credentials, or customer data. Its contract proof reports an accepted receipt,
an immutable Drive version, a matching History event, and a stale save that
creates a branch while leaving Main unchanged. `core` repeats the manifest and
provider-core contract checks and runs the available Office protocol unit tests.
The dependency-light in-memory `testprovider` conformance adapter is still a
later O0/DX slice, so the deterministic proof remains explicitly labelled a
contract scaffold rather than production evidence.

Inspect a stable explanation without a server:

```bash
bash scripts/verify-office-foundation.sh explain E_OFFICE_PROVIDER_UNREADY
bash scripts/verify-office-foundation.sh explain E_OFFICE_PROOF_REJECTED
```

Once the gateway is available, the read-only operator view is:

```bash
mailctl office doctor --json
mailctl office diagnostics --json
```

The CLI reports the server's feature-registry facts only; it does not expose
provider credentials or replace this repository-level verification front door.

## Connect or install a test editor

The provider-neutral path and the managed CODE test path use the same Office
authority but remain separate operations:

```bash
mailctl office status
mailctl office configure --provider collabora --base-url https://office.example.test --reason "lab setup"
mailctl office qualify --provider collabora --reason "lab qualification"
mailctl office activate --provider collabora --reason "approved lab route"

mailctl office install --app collabora-code --reason "install pinned test editor"
```

Administrators can perform the same tasks in `/admin/office` and `/admin/apps`.
The managed card is explicitly `测试版`: it requests installation of only the
root-controlled, digest-pinned manifest in
`config/office-managed-app-v1.json`. The updater pulls and verifies that digest,
starts the fixed Docker profile on `127.0.0.1:9980`, probes Collabora discovery,
records the immutable revision and stops at `connected_inactive`. Installation
never activates Office routing. A failed stage/start/health check records
rollback and removes only the manifest-owned test resources.

For the dedicated worker mode, provide only the worker DSN and pinned manifest:

```bash
setjoin-updater --office-app-only --office-app-execution \
  --office-app-worker-dsn-file /run/credentials/setjoin-updater.service/app-worker-dsn \
  --office-app-manifest /etc/setjoin/office-managed-app-v1.json
```

The worker receives no Drive/object-store or migration-owner credentials. V227
admits `feature.office_managed_delivery`; the standard updater service starts the
closed runner with the worker credential and pinned manifest. Install still ends
inactive, and legal/support, capacity/HA, domestic-platform and independent-operator
evidence continue to gate release claims and provider activation policy.

The retained executable install proofs are:

```bash
bash scripts/e2e-office-managed-install.sh
cd mailserver
SETJOIN_LIVE_COLLABORA=1 go test -v ./internal/appmarket -run '^TestLiveDockerCollaboraInstall$' -count=1
```

Successful focused runs retain a manifest beneath
`test-results/office-foundation/<run-id>/`. Verify a retained run with:

```bash
bash scripts/verify-office-foundation.sh evidence test-results/office-foundation/<run-id>/manifest.json
```

## Product boundaries

- The pre-release defaults are ON for the implemented Office/Drive path. The relevant controls are
  `feature.drive`, `feature.drive_history`, `feature.office_editing`, and
  `feature.office_local_open`; operators can still disable each independently.
- Drive remains the only authority for bytes, versions, branches, locks,
  retention, authorization, audit, state bumps, and notifications. An editor
  receives only a scoped action and never PostgreSQL, object-store, signing, or
  tenant-wide credentials.
- Drive History is a Drive capability. It is a bounded, permission-filtered
  read over authoritative Drive facts; it never becomes a second version store
  or a mutation authority.
- The web product promises online editing only. It does not advertise offline
  editing or device-local applications. Local open-with is an installed-app
  capability of Setjoin desktop clients and is separately gated and evidenced.
- Collabora is the first web adapter candidate, not a permanent dependency.
  Missing Collabora is an honest external gate; it must never make the fake
  quick path appear unavailable or make an unqualified production claim green.
- Upstream Office rendering engines are not part of the repository's
  compatibility test. The compatibility manifest records the licensed corpus
  and reference-renderer evidence needed for a later external gate; it does not
  claim to reproduce or certify an upstream renderer.

## What each contract freezes

| File | Purpose |
|---|---|
| `config/office-provider-manifest-v1.json` | Provider-neutral IDs, modes, actions, data-egress posture, entitlement/build state, and removal boundary. |
| `config/office-v1-acceptance-manifest.json` | Browser/Electron/OS cells, corpus, limits, latency targets, named cases, owners, and rollout blockers. |
| `docs/guides/office/compatibility.md` | How exact producer, OS, CPU, browser, editor, build, font, and license evidence is classified. |
| `docs/guides/office/operations.md` | Doctor, focused verification, retained evidence, live gate, drain/removal, and stable error handling. |

These manifests are versioned contracts, not a marketing feature list. An
unknown required field, unpinned build, missing evidence owner, or ambiguous
verdict blocks the corresponding promotion.

## If the live path is needed

The live profile is intentionally separate:

```bash
bash scripts/verify-office-foundation.sh live-collabora
```

The command reports the exact missing prerequisites and exits non-zero until a
customer-approved or lab-approved Collabora URL, source/image/build digest,
font evidence, and license/notice evidence are supplied through approved
operator paths. It never downloads an editor, proprietary fonts, or an
entitlement automatically. A live-ready report is still not a production
enablement decision; WOPI, security, load, removal, legal, and support evidence
remain required.

## Expected handoff

The provider-neutral authority/WOPI path and closed managed-install test slice
are implemented. The next bounded delivery work is update/drain/remove, final
ingress qualification and source/profile management; rollout additionally needs
licensed compatibility-corpus, legal/support, security/load/HA and independent
operator evidence. None may move authority into a provider or silently enable a
feature. When a provider is connected, add its exact observed build and callback
behavior to the manifests, retain evidence under the run ID, and update the
compatibility/support boundary instead of broadening a generic “Office
supported” claim.
