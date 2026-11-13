# Command reference

This reference separates the internal A0 surface from the implemented,
default-OFF V1A product surface and its remaining release-evidence gates.

## Current A0 command surface — implemented internal command

Top-level dispatch is local and has no server/UI product workflow:

```text
mailctl exchange-a0
```

The command is explicitly a timeboxed A0/v0 concierge tool. It is not an alias
for `mailctl exchange assess`.

| Command | Required arguments | Effect and important boundaries |
|---|---|---|
| `exchange-a0 registry` | `--output <new-file>` | Exports the embedded `setjoin.exchange.a0.registry/v0` JSON and prints its SHA-256. Refuses replacement of an existing file. |
| `exchange-a0 validate` | `--input <collector.json>` | Strictly validates one A0 input file, including the exact embedded registry digest. It is local and non-importing. |
| `exchange-a0 report` | `--input <collector.json> --output <new-dir>` | Writes `report.json`, `report.html`, and `manifest.json`; `--locale zh-CN\|en-US` selects rendering and `--pdf` invokes only local Microsoft Edge. |
| `exchange-a0 attest` | `--kind handling\|decision-use --report <report.json> --organization TEXT --actor TEXT --decision VALUE --purpose TEXT --retention-days N --issued-at UTC --output <new-file>` | Binds an explicitly supplied event to a valid A0 report. Handling decisions are `accepted\|rejected`; decision-use decisions are `go\|no-go\|defer`. |
| `exchange-a0 verify-receipt` | `--receipt <receipt.json> --report <report.json>` | Recomputes receipt ID and report/input/registry/row-set bindings. It does not validate the truth of the human event. |

`report` also has `--generated-at <canonical UTC RFC3339>` for deterministic
reproduction/tests. It is not a substitute for collection time and is not part
of a public assessment contract.

### A0 PowerShell collector parameters

The fixed script is separate from the `mailctl exchange-a0` subcommands:

| Parameter | Required/default | Contract |
|---|---|---|
| `-RegistryPath` | required | Existing regular registry file; its schema and command list are checked. |
| `-OutputPath` | required | New collector JSON path; existing output is refused. |
| `-OrganizationLabel` | required, 1–256 characters | Label supplied by the approved operator; it is metadata, not a customer-evidence receipt. |
| `-Topology` | `on-premises` | Allowed values are `on-premises` or `hybrid`; the value does not widen the V1A support-cell gate. |
| `-MaxMailboxes` | `10000`, range 1–100000 | Bounds mailbox enumeration before the collector writes the artifact. |

The script requires PowerShell 5.1 or later by declaration and calls only its
compiled ten-command read-only allowlist. That declaration and repository parser
coverage do not establish live Windows execution or Exchange support evidence.

### A0 input and output schemas

The current implementation recognizes these exact schema identifiers:

```text
setjoin.exchange.a0.registry/v0
setjoin.exchange.a0.input/v0
setjoin.exchange.a0.report/v0
setjoin.exchange.a0.manifest/v0
setjoin.exchange.a0.receipt/v0
```

The collector version is `a0-v0`. Input files are bounded to 16 MiB by the Go
validator, must be regular files, reject unknown JSON fields and duplicate JSON
values, and must contain a canonical UTC `collectedAt`. Reports bind the input,
registry, and ordered row-set digests. A0 receipts are limited to 0–3650 asserted
retention days and carry:

```text
signatureStatus = unsigned_customer_attestation
importable       = false
```

The A0 manifest is an artifact digest manifest. It is not the V1A product
inclusion manifest described in [generated-content-and-manifests.md](generated-content-and-manifests.md).

### A0 status and failure behavior

Collector/report rows use `observed`, `unassessed`, `blocked`, or `unsupported`.
An `observed` row must not carry a diagnostic ID. An incomplete row must carry a
diagnostic ID and bounded detail. A missing capability is synthesized as
`unassessed` with `A0-MISSING` in the report path. This status vocabulary is not
the future three-axis claim vocabulary.

The A0 implementation does not publish the planned numeric public exit taxonomy
or a public JSON error envelope. Do not infer public meanings from a local process
failure message.

## V1A public command contract — implemented, default OFF

The approved X0/X3 contract uses one portable `mailctl exchange assess` workflow:

```text
preflight  sample  collect  inspect  report  import  diagnose
```

The implemented guarantees are:

- top-level `--help`/`--version`, `--json` on preflight/sample/inspect/import,
  explicit output paths on artifact-producing commands, and non-interactive
  operation throughout;
- the V1A commands never prompt; `collect --non-interactive` is accepted so
  automation can state that policy explicitly;
- machine output on stdout in JSON mode and progress/diagnostics on stderr;
- local/offline operation, path-with-spaces and CJK fixtures are tested locally;
  live PowerShell 5.1/7 parity remains a release-evidence gate;
- no network, telemetry, auto-update, or upload without a separate operator
  action and destination confirmation;
- V1A `collect` is a bounded atomic conversion of an already completed collector
  JSON. `--resume` is reserved and explicitly rejected with `COLLECT-005`; source
  collection checkpoint/resume remains a release gate instead of a silent no-op;
- `diagnose` creates a consented redacted support bundle and lists every included
  file before creation.

The numeric exit classes are:

| Exit | Meaning |
|---:|---|
| `0` | complete success |
| `2` | usage/configuration error |
| `3` | preflight blocked |
| `4` | partial/incomplete result |
| `5` | integrity/security failure |
| `6` | retryable dependency or throttle |
| `7` | unsupported version/topology |
| `10` | unexpected internal failure |
| `130` | user cancellation after safe checkpoint |

These numbers are pinned by command tests. A0 does not promise them.

The optional generated configuration contract is versioned and allowlisted.
`preflight --write-config <file>` emits a starter with topology,
RBAC/redaction, locale, and retention fields; unknown keys must fail. It is not a
configuration file that current A0 commands consume.

## Server/UI steps — implemented, default OFF

The product journey provides idempotent project/run creation, bounded import,
review/resolve, signed publication, and request/drain deletion. All mutations use
server-enforced permissions and reducer authority; A0 remains excluded. See
[air-gapped-transfer.md](air-gapped-transfer.md) and
[handling-and-retention.md](handling-and-retention.md) for the current boundaries.
