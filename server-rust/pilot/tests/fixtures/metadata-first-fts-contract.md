# Issue 204 metadata-first FTS expectation contract

Status: **source recipes only; all six golden outputs NOT_GENERATED / NOT_VERIFIED**. No vector values, executions or pass counts are claimed. Source base is commit `4399a2f5eacbfa50206bcbc84883f7b40a53bf6b`, tree `4bbaa6153513646a2bf9e7f3fb4aa7ef4e3aa0e0`. Inputs derive from the independently verified immutable fixture JSON SHA-256 `a398c4501f8fd49b5d3645c4321cd3a3fd59ace6d3ea83533952efd07583d934` and fixture contract SHA-256 `ca21c4123b119b7ff82a8a14f8a23bdbf1f52d42e99974f90245b647f70950b6`; accepted physical mapping SHA-256 `73434dafa967a815add90f1af13a495eff60db2bc2fb18cadf7cb5817a104acf` and setup inventory SHA-256 `557b1a3090e8a79bd595a4a3657295108bed2044cdd2891d954aabec4b790eda`. The companion JSON specifies exactly six ordered literal inputs and recipes.

## Branch and trigger

Require the accepted final schema and UID allocator branch, the deployed `public.messages` BEFORE INSERT trigger `messages_tsv_update` from V001:11104, and its V029 `public.trg_messages_tsv()` body. V001 SHA-256 `a5cfe54ffeb452f51a14ac1d3d896a6ef9bb766f66cd0720051bd68d9b529a14`; V029 SHA-256 `0b2538311ad766d0131a8eb947b3f73fed4437e7fc986111a017383e721fed46`. Future admission must verify the actual trigger, binding, function, enabled state and relevant partition behavior against this branch. It must explicitly set and verify transaction-local `app.skip_fts` value `false`, and require `crypto_type IS NULL` for root and reply. V029 returns NEW unchanged if the setting is exactly `true`; otherwise for NULL crypto_type it computes body_tsv using simple configuration, and always computes subject_tsv and from_tsv within that non-skipped branch. Later update of folder_id alone does not match the trigger's UPDATE OF body_text, subject, from_addr, from_name list. No alternate schema branch is accepted from observation.

## Six independent recipes

Each row is an expected recipe, not an observed result. Inputs are the fixed fixture literals, never candidate output or readback. In sender inputs the separator is exactly one U+0020 space.

| Message | Field | Exact UTF-8 input to `to_tsvector('simple', input)` |
|---|---|---|
| root | body_tsv | `T03 t03_metadata_20261027 root body` |
| root | subject_tsv | `T03 t03_metadata_20261027` |
| root | from_tsv | `fixture-sender@fixture.test T03 Root Sender` |
| reply | body_tsv | `T03 t03_metadata_20261027 reply body` |
| reply | subject_tsv | `Re: T03 t03_metadata_20261027` |
| reply | from_tsv | `fixture-sender@fixture.test T03 Reply Sender` |

For each recipe, select PostgreSQL canonical `tsvector::text` output and encode that returned text as UTF-8. Exact comparison means identical UTF-8 bytes: no trimming, sorting, case folding, position or weight stripping, query-match substitution, or semantic containment. SQL NULL is distinct from the empty non-NULL vector and either differs from a nonempty value. The six outputs are expected to be non-NULL under the specified branch; do not guess their lexemes, position strings, serialization or emptiness before independently generating and verifying them.

## Golden-output and later observation binding

A separately admitted golden-output operation must bind the exact PostgreSQL build and version; database/server and client encodings; locale and relevant collation; resolved `simple` text-search configuration, parser and dictionary identities and definitions; relevant effective settings; schema/trigger/function identity; and the six input bytes. Preserve the build and configuration evidence alongside generated canonical UTF-8 bytes. Derive them solely from these literal inputs through an independent expected-value process, before comparing to candidate rows; do not copy candidate vectors or candidate readback text into the oracle. Review the resulting golden artifact independently. Later runtime verification must separately establish the actual connected build/configuration, transaction setting, non-encrypted inputs, trigger path, full row values and exact observed vector bytes; mismatch or missing evidence holds, never changes the expected artifact.

Controls for later separately admitted checks must detect at least: skip_fts exactly true leaving provided vectors unchanged; altered body/subject/sender input; encrypted crypto_type causing body_tsv NULL with headers still derived; NULL versus empty non-NULL; and changes in positions, weights or bytes. Such controls are requirements, not test results. The exact body provider, result/event schema, comparator and transaction witness remain separate contracts. This metadata-only slice asserts no blob loading, upload, download or object bytes. No SQL, tests, service, credential or runtime operation is authorized or claimed by this document.
