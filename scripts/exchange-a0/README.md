# Exchange A0 concierge collector

This directory is the pre-productization G3 tool for two approved design partners.
It is not the planned public `mailctl exchange assess` interface and its artifacts
must not be imported as V1A runs.

The collector invokes only the literal `Get-*` cmdlets compiled into
`Collect-SetjoinExchangeA0.ps1`. The v0 registry describes that fixed allowlist;
it cannot add a command at runtime. Output contains aggregate configuration facts,
not message content or raw mailbox identities. Run it only under customer-approved
handling and retention terms. `mailctl` requests restrictive file modes and refuses
to overwrite outputs; on Windows, run inside a customer-approved directory whose
NTFS ACL has already been restricted because POSIX `0600` is not an NTFS ACL policy.

```powershell
.\mailctl.exe exchange-a0 registry --output .\a0-registry.json
.\Collect-SetjoinExchangeA0.ps1 `
  -RegistryPath .\a0-registry.json `
  -OutputPath .\collector.json `
  -OrganizationLabel 'Design Partner A' `
  -Topology hybrid
.\mailctl.exe exchange-a0 validate --input .\collector.json
.\mailctl.exe exchange-a0 report --input .\collector.json --output .\report --pdf
```

Without Microsoft Edge, omit `--pdf`; `report.html` is print-ready and remains the
canonical human-readable artifact. `report.json`, `report.html`, optional
`report.pdf`, and `manifest.json` bind the input, registry, and row-set digests.

After an authorized human actually accepts handling terms or uses the report in a
real decision, record that event. The v0 receipt is deliberately marked
`unsigned_customer_attestation` and `importable:false`; signing is product work and
does not happen in A0.

```powershell
.\mailctl.exe exchange-a0 attest `
  --kind handling `
  --report .\report\report.json `
  --organization 'Design Partner A' `
  --actor 'Named customer owner' `
  --decision accepted `
  --purpose 'Approved A0 discovery handling terms' `
  --retention-days 30 `
  --issued-at '2026-08-23T12:00:00Z' `
  --output .\handling-receipt.json
.\mailctl.exe exchange-a0 verify-receipt `
  --receipt .\handling-receipt.json `
  --report .\report\report.json
```

Never create a receipt for an event that did not happen. Two comparable reports,
one real decision-use receipt, accepted handling terms, named partners, and a
product-owner promotion decision are all required before V1A implementation.
