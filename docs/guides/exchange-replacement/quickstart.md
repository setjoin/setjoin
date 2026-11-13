# Quickstart

This quickstart has two deliberately separate paths: internal non-importable A0,
and implemented default-OFF V1A. Neither is a replacement-readiness claim.

## Current A0: local, read-only discovery

Before starting, obtain the organization's approved handling and retention terms,
choose a new restricted output directory, and identify the named operator. The
collector is fixed to literal read-only `Get-*` cmdlets. It does not accept a
customer-supplied command name and does not mutate Exchange.

The script declares PowerShell 5.1 as its minimum version. Repository parsing and
static no-mutating-command checks are not evidence of live Windows execution
parity; the environment owner must supply any required runtime evidence separately.

### 1. Export the embedded A0 registry

Run from the directory containing the `mailctl` executable:

```powershell
.\mailctl.exe exchange-a0 registry --output .\a0-registry.json
```

The command writes a new private file and prints its SHA-256 digest. Do not
replace an existing output file. The registry is `v0` and contains four bounded
capability rows; see [compatibility-and-vocabulary.md](compatibility-and-vocabulary.md).

### 2. Run the fixed collector on the Exchange-side workstation

Run the script from the approved Exchange Management Shell context:

```powershell
.\Collect-SetjoinExchangeA0.ps1 `
  -RegistryPath .\a0-registry.json `
  -OutputPath .\collector.json `
  -OrganizationLabel '<approved organization label>' `
  -Topology on-premises
```

`-Topology hybrid` is accepted by the A0 input shape, but it is not a hybrid
support claim. The initial V1A support cell is one bounded on-premises
Exchange 2019 build family; Exchange 2016 and hybrid remain unassessed until
their own adapter and live evidence exist.

The collector writes aggregate configuration facts, not message content or raw
mailbox identities. A blocked probe remains a blocked probe with an A0 diagnostic
ID. If mailbox enumeration is unavailable, calendar and resource rows become
explicitly `unassessed`.

### 3. Validate without contacting a server

```powershell
.\mailctl.exe exchange-a0 validate --input .\collector.json
```

Validation is strict: the schema, collector version, exact embedded registry
digest, bounded text/facts, canonical UTC timestamp, capability IDs, statuses,
and JSON fields must match. A missing or unknown row is not treated as observed.

### 4. Generate the local report

```powershell
.\mailctl.exe exchange-a0 report `
  --input .\collector.json `
  --output .\report `
  --locale en-US
```

Use `--locale zh-CN` for the default Chinese rendering. Add `--pdf` only when a
locally installed Microsoft Edge is approved and available; otherwise
`report.html` is the canonical human-readable artifact. The command refuses to
replace an existing output directory and installs artifacts atomically.

Inspect these files locally:

```text
report/report.json   structured report; phase says A0 only and importable=false
report/report.html   escaped, print-ready human report
report/manifest.json artifact and input/registry/row-set digest bindings
report/report.pdf    optional local-Edge rendering
```

The report is a completeness view, not a replacement-readiness promise. Missing
capabilities appear as `unassessed` rows, and the report phase is
`A0 concierge discovery only — replacement readiness not established`.

### 5. Record a real event only when it exists

The following is a shape, not a sample event. Replace every placeholder with
truthful approved values; do not execute it merely to make evidence appear.

```powershell
.\mailctl.exe exchange-a0 attest `
  --kind handling `
  --report .\report\report.json `
  --organization '<approved organization>' `
  --actor '<named human actor>' `
  --decision accepted `
  --purpose '<actual handling purpose>' `
  --retention-days 30 `
  --issued-at '<canonical UTC RFC3339 time>' `
  --output .\handling-receipt.json

.\mailctl.exe exchange-a0 verify-receipt `
  --receipt .\handling-receipt.json `
  --report .\report\report.json
```

For a decision-use receipt, use `--kind decision-use` and one of `go`, `no-go`,
or `defer`. A receipt is unsigned customer attestation metadata and remains
non-importable. `--retention-days` records the asserted term; it does not enforce
deletion or prove that the named event happened.

## Default-OFF V1A public assessment

Run the fixed V1 collector first; it writes strict
`setjoin.exchange.collector-output/v1` JSON. Then use:

```powershell
.\mailctl.exe exchange assess preflight --offline
.\mailctl.exe exchange assess sample --output .\setjoin-sample
.\mailctl.exe exchange assess collect --input .\collector-v1.json --output .\assessment --non-interactive
.\mailctl.exe exchange assess inspect .\assessment\bundle.sja
.\mailctl.exe exchange assess report .\assessment\bundle.sja --output .\assessment-report --format html,json
.\mailctl.exe exchange assess import .\assessment\bundle.sja --project-id 42 --server https://setjoin.example
.\mailctl.exe exchange assess diagnose .\assessment\bundle.sja --output .\support.json
```

`sample`, `collect`, `inspect`, `report`, and `diagnose` are zero-network.
`import` is the only
explicit upload: the server revalidates the complete registry denominator and
digest, then encrypts the artifact under a per-artifact DEK. The UI remains
assessment-only and publication remains evidence-gated.

## Safe rerun rules

- Preserve the prior input, report, manifest, and receipt. A0 commands refuse to
  overwrite existing output paths.
- Re-run with a new output path and retain the digest chain that explains which
  input and registry produced the new report.
- Treat partial, blocked, unsupported, and unassessed rows as blockers for the
  affected outcome. Never summarize them as green or supported.
- For current A0 air-gap handling, follow [air-gapped-transfer.md](air-gapped-transfer.md).
