# Generated content and inclusion manifests

The V1A Exchange Replacement corpus is a projection of one registry and one
evidence-bound fact set. Narrative guidance may be handwritten, but capability
definitions and visible claims must not be maintained in parallel tables.

## Projection model

```text
versioned discovery catalog + capability registry
                 +
       normalized, redacted facts
                 +
       evidence/support-cell resolver
                 |
                 +--> executive readiness report
                 +--> administrator detail report
                 +--> unified management UI
                 +--> internal feature inventory
                 +--> Setjoin-vs-Exchange comparison docs
                 +--> migration/acceptance workbook and JSON
                 +--> applicable verification cases
```

The registry defines the vocabulary and maximum permitted claim policy. Reducer
authority resolves dynamic evidence into an immutable snapshot. The UI, docs,
reports, tests, and generated help consume the same canonical join. No projection
may invent a synonym, silently omit an unassessed row, or turn `alternative` into
`native`.

## Inclusion manifest contract — V1A product artifacts

Every generated artifact carries an inclusion manifest with at least:

| Field | Purpose |
|---|---|
| included capability IDs | exact denominator members rendered in the artifact |
| omitted capability IDs | rows not rendered, still named rather than silently dropped |
| omission reasons | excluded scope, unsupported source, incomplete evidence, stale claim, or other typed reason |
| denominator | total applicable registry population used for the artifact |
| registry version and digest | reproducible vocabulary/policy input |
| support-cell identifier/digest | exact source environment scope |
| validation date | when the projection was checked |
| artifact/schema version | consumer and compatibility identity |

Public or customer-facing documents show excluded/unassessed coverage or place the
bounded scope beside the title. A generated diff is reviewed before release. CI is
expected to fail on handwritten capability rows, orphan UI/document IDs,
untranslated visible labels, inconsistent support status, or an unreviewed
generated diff.

## Current A0 manifest is different

The implemented A0 `manifest.json` binds:

```text
schemaVersion
registryDigest
inputDigest
rowSetDigest
artifacts[filename] = SHA-256
```

It proves that the local A0 report files correspond to a particular input,
registry, row set, and artifact bytes. It does not contain the V1A product
denominator/omission vocabulary, does not sign the package, and does not make an
A0 report importable or supported.

## Offline package inclusion

The portable release package must include a top-level offline start page,
README, version-matched quickstart, command/reference, compatibility, and
troubleshooting assets. Every help link resolves inside the extracted package
without internet access. Package verification starts from a clean extraction,
checks the package identity/integrity contract, and runs the deterministic sample;
it does not depend on a repository checkout.

This repository directory is the source documentation corpus, not that signed
package. Its relative links are intentionally suitable for offline copying, but
the presence of these Markdown files is not package-signature, generator, customer,
or live-environment evidence.

## Review checklist for a generated diff

Before accepting a generated artifact, confirm:

- the source registry and digest are recorded;
- the support cell and validation date are present;
- included and omitted IDs sum to the declared denominator;
- every omission has a reason visible to the intended reader;
- the three status axes remain separate;
- stale/expired evidence invalidates claims and documents;
- relative help links resolve in the extracted offline package;
- no generated text claims customer, Windows, T1, T2, or human evidence that was
  not actually retained and approved.
