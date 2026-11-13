# Air-gapped transfer

An air gap changes the transport path, not the evidence rules. Keep origin and
import identities, digests, actors, and timestamps distinct. A removable medium
is never an identity authority.

## Current A0: local artifacts only

The implemented A0 lane has no import command and no product server. It can still
be used on disconnected workstations by running validation/reporting against local
files.

1. On the Exchange-side workstation, create the A0 registry and collector output
   under the organization's approved restricted directory.
2. Run `exchange-a0 validate` and `exchange-a0 report` locally. Inspect the HTML,
   JSON, and manifest before any transfer.
3. If transfer is approved, copy only the named artifacts through the
   organization's approved removable-media or one-way-transfer process. Retain the
   media custody record outside this documentation set.
4. On the report-side workstation, verify the manifest and run
   `exchange-a0 verify-receipt` only when a real receipt exists. A0 still has no
   import path; do not upload the report or treat it as a V1A run.
5. Apply the approved external-media return/destruction and backup rules. The A0
   tool does not attest that another system erased its copy.

A0 emits a plain JSON collector artifact. It does not implement the future
`bundle.sja` encryption, detached signature, create/stream/finalize import, or
server-side custody workflow. Do not describe a digest manifest as a publisher
signature.

## V1A air-gapped workflow

The implemented air-gapped flow is:

```text
Exchange-side collect
  -> integrity-bound bundle.sja + manifest under approved media custody
  -> local inspect and redaction preview
  -> approved media or one-way transfer
  -> Setjoin-side inspect
  -> schema/support-cell/origin-digest verification
  -> bounded idempotent import and encrypted server custody
  -> distinct origin/import receipts
```

The future steps are:

1. `mailctl exchange assess collect` writes an integrity-bound `bundle.sja` and
   report manifest on the source workstation. It is not source-side ciphertext;
   use the customer's approved encrypted media/container policy in transit.
2. `inspect` verifies integrity and previews fields locally. Unknown sensitive
   fields fail closed; a stricter redaction profile may be selected, never a
   weaker one.
3. The operator copies only the approved files over the customer's approved
   media/one-way path and follows the customer's media custody policy.
4. The target workstation/server runs `inspect` again and checks publisher/
   integrity, schema, support-cell compatibility, and the same origin digest.
5. The UI or CLI import uses bounded idempotent project/run creation and upload;
   the server immediately stores a random-DEK encrypted envelope. A mismatch or tamper
   fails with `IMPORT-002` and preserves the prior valid run.
6. Origin and import receipts record matching digests plus distinct actor, time,
   and endpoint metadata. Media return/destruction remains an external custody
   claim unless separately attested.

The public `import` command and server/UI stages are implemented but default OFF;
A0 remains non-importable. The server URL is the customer's approved Setjoin
deployment, never an implicit internet dependency.

## Transfer checklist

Before moving a file, confirm:

- the artifact name, schema, registry/support-cell digest, and intended recipient;
- the redaction preview and whether the artifact contains any data outside the
  approved scope;
- the media/one-way path and its custody owner;
- the origin and import actor are recorded separately;
- the prior valid artifact is preserved;
- the receiving side can verify without network access;
- no operator is being asked to bypass TLS, signature, version, authorization,
  redaction, or completeness checks.
