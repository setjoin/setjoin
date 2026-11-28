# Proposed complete receipt envelope v1

Status: source-only design, not implemented or runtime-qualified. This consolidates the reviewed grammar and fallback correction. It retains the accepted field framer and the fixed metadata contract; it does not define a second field codec.

## Encoding and fixed limits

All multibyte integers are unsigned big-endian. Textual evidence is opaque bytes, not decoded or normalized. Reserved enum values, duplicate evidence types, noncanonical lengths, trailing bytes, and unknown versions are rejected.

- Magic: eight literal bytes `53 4a 46 54 53 52 43 50` (`SJFTSRCP`).
- Version: `u16 = 1`.
- Total length: `u64`, including the entire envelope.
- Complete-envelope maximum: 8,388,608 bytes.
- Raw evidence item maximum: 65,536 bytes; at most four items in each evidence section.
- Result maximum: four; column maximum per result: 64; row maximum per witness result: 1,024; result 4 maximum: six.
- Column-name length: `u16`, maximum 1,024 bytes. Names are compared byte-for-byte with the accepted metadata contract.
- Field and field-stream limits remain those of the accepted framer: 65,536 bytes per field and 8,388,608 bytes per invocation. Each row is a separate framer invocation.

## Header and binding identities

After magic, version and total length, encode:

| Bytes | Meaning |
|---:|---|
| 32 | Frozen SQL SHA-256: `778f2ca1a12d71259a0f40950ec8050f4201e4553d8561f5538db662eabb1596` |
| 32 | Metadata contract archive SHA-256: `d5f687102a5f3076239d6e86a3e441c1253c3fe7d61ef5c835950e60e1aff0d4` |
| 32 | Accepted framer archive SHA-256: `a266c7bf0acd4f485c3b1846e5add10f7d8b358872dc3bd0e642489be6f27f8e` |
| 1 | Independent baseline presence: 0 absent, 1 present |
| 0 or 32 | Exact independently reviewed baseline-manifest SHA-256, only when presence is 1 |

Other presence values are invalid. An absent baseline is explicit, never a fabricated all-zero digest, and prevents complete qualification. Binding bytes identify expected inputs and remain distinct from observed witness bytes.

## Runner outcomes

These fields preserve accepted runner semantics from source SHA-256 `a749b57589b48d2e352e64169b7ef79910dae436d4fc1d06643701ee1b6fec78`; they do not introduce another lifecycle.

| Field | Closed values |
|---|---|
| primary_failure:u8 | NONE=0, CONTENT_FAILURE=1, INCOMPLETE=2, PROTOCOL_FAILURE=3, IO_FAILURE=4 |
| cleanup_status:u8 | UNKNOWN=0, CONFIRMED=1, REJECTED=2 |
| cleanup_reason:u8 | NONE=0, INCOMPLETE=1, INVALID=2 |
| sequence_valid:u8 | 0=false, 1=true |

All other values are rejected. Record the first runner primary unchanged; later construction or qualification failure has separate fields below. CONFIRMED/NONE cleanup may coexist with an earlier primary failure and sequence_valid=0.

For setup and query observation, closed u8 codes are 0=not attempted, 1=succeeded, 2=failed, 3=deadline, 4=unknown. For each of rollback command, rollback result exhaustion, and transaction idle, use 0=not attempted, 1=confirmed, 2=failed, 3=unknown. Observation fields describe what was actually seen; they do not replace sticky runner fields.

## Construction or qualification error

This is distinct from primary_failure.

| envelope_error:u8 | Meaning |
|---:|---|
| 0 | None |
| 1 | Capture or field limit exceeded |
| 2 | Arithmetic or representational overflow |
| 3 | Invalid captured metadata or row shape |
| 4 | Missing or inconsistent binding |
| 5 | Independent qualification failed |
| 6 | Framer rejected input or lacked space |
| 7 | Required observation missing or truncated |
| 8 | Snapshot or scratch allocation failed |

Location is `section:u8 | result_ordinal:u8 | row_index:u32 | column_index:u16`. Section is 0=none, 1=bindings, 2=setup, 3=result metadata, 4=result row, 5=query terminal, 6=rollback, 7=cleanup, 8=whole envelope. Result ordinal 0 means not applicable, otherwise 1–4. Row `0xffffffff` and column `0xffff` mean not applicable. Unknown values and inconsistent location combinations are rejected. A later envelope error never overwrites runner primary.

## Required observations and raw evidence

Encode `presence:u16`. Bits 0–6 respectively mean actual setup outcome, query outcome, rollback command, rollback exhaustion, transaction idle, runner sequence validity, and cleanup outcome were observed. Bits 7–15 must be zero. A status can be present with no raw bytes; do not fabricate text to represent it.

Each of four evidence sections—setup, query, rollback, cleanup—is:

```text
item_count:u8
  repeated item_count: type:u8 | length:u32 | raw_bytes[length]
```

At most four unique types in ascending order: 1=protocol status/tag, 2=diagnostic, 3=session/identity observation, 4=transport/cleanup observation. Each item is at most 65,536 bytes. Absence and a present zero-length item differ. Truncation is never accepted as a complete observation. These bytes are observations; structured interpretation must be specified and reviewed with the collector and is not a self-authenticating baseline.

## Results and row framing

```text
result_count:u8
  repeated:
    result_ordinal:u8 | column_count:u8 | row_count:u32
    repeated column_count:
      column_index:u8 | name_length:u16 | name[name_length]
      type_oid:u32 | format:u8
    repeated row_count:
      row_index:u32 | field_stream_length:u64 | field_stream[...]
```

- At most four results, contiguous ordinals from 1. Include only fully copied PGRES_TUPLES_OK results; interrupted capture retains the completed prefix without manufacturing rows or descriptors.
- Column and row indices are contiguous starting at 0.
- Maximum rows by ordinal: result 1: 1; result 2: 1,024; result 3: 1,024; result 4: 6. Complete qualification additionally requires result 1 exactly one, result 4 exactly six, and results 2–3 equal the independently approved baseline.
- At most 64 columns; column names at most 1,024 bytes. A complete candidate matches all accepted names, OIDs, widths 19/24/10/8 and format 0.
- An incomplete record may represent actual observed format 0 or 1; other formats cannot be represented and produce a bounded construction failure. This does not qualify binary data.
- Each row contains exactly column_count fields in order, produced by one call to the accepted framer. A reader parses exactly that many field frames and consumes exactly field_stream_length, rejecting surplus or missing bytes. NULL and non-NULL empty remain distinct.

## Complete grammar and dispositions

```text
header_and_bindings
presence:u16
setup_observation:u8 | setup_evidence_section
result_count:u8 | result_records
query_observation:u8 | query_evidence_section
rollback_command:u8 | rollback_exhaustion:u8 | transaction_idle:u8
rollback_evidence_section
primary_failure:u8 | cleanup_status:u8 | cleanup_reason:u8 | sequence_valid:u8
cleanup_evidence_section
envelope_error:u8 | section:u8 | result_ordinal:u8
row_index:u32 | column_index:u16
disposition:u8
```

Disposition is 0=incomplete or 1=complete candidate; other values are rejected.

A complete candidate requires all seven presence bits; successful setup/query; all three rollback/idle acknowledgements confirmed; sequence_valid=1; primary_failure=NONE; cleanup CONFIRMED/NONE; envelope_error=0; four fully validated results; and all independent baseline, identity, build, resource and ownership checks. Missing, omitted or truncated required evidence prevents it. Expected hashes cannot substitute for actual observations.

A valid disposition-0 envelope contains only the actually captured complete prefix and actual evidence and is eligible only for an incomplete-evidence destination. If a valid envelope cannot be constructed, emit a separate bounded failure record—not a partial envelope—with fixed magic `SJFTSERR`, version u16=1, envelope_error and location above, and a u16 diagnostic length capped at 1,024 bytes followed by that many untruncated diagnostic bytes.

If `SJFTSERR` cannot be constructed, preserve the runner's primary_failure, cleanup_status, cleanup_reason and sequence_valid unchanged. Return separate nonallocating envelope-construction result NO_RECORD=2, meaning no envelope or failure-record bytes were produced or published. This is a construction return value, not a runner state, and does not overwrite previously accepted output.

Other construction return values are ENVELOPE_READY=0 and FAILURE_RECORD_READY=1; they describe an in-memory buffer handed to the caller, not durable publication. Reject unknown return values. Neither incomplete output nor failure record overwrites previously accepted output.

No envelope state represents committed success: the transaction is rolled back. Golden acceptance remains a separate independent comparison and decision.

## Bounds and in-memory handoff

Before each snapshot allocation or copy, reserve its exact requested size with checked arithmetic against both a running projected envelope budget of 8,388,608 bytes, including all fixed overhead and the item being captured, and a separate owned snapshot allocation budget of 16,777,216 bytes, counting every requested snapshot allocation. Reject before allocation/copy if either reservation overflows or exceeds budget. The caller guarantees valid source extents and stable lifetime during each copy. This does not bound libpq's own allocations before capture.

For evidence section E, `size(E) = 1 + Σ(1 + 4 + item_length)`. For result R:

```text
size(R) = 1 + 1 + 4
        + Σcolumns(1 + 2 + name_length + 4 + 1)
        + Σrows(4 + 8 + field_stream_length)
```

Complete envelope size is `141 + 32 * baseline_present + Σ(result sizes) + Σ(5 + evidence_length)` bytes. Equivalently:

```text
8 + 2 + 8 + 32 + 32 + 32 + 1 + (baseline_present ? 32 : 0)
+ 2
+ 1 + size(setup)
+ 1 + Σresults(size(result))
+ 1 + size(query)
+ 3 + size(rollback)
+ 4 + size(cleanup)
+ 1 + 1 + 1 + 4 + 2
+ 1
```

SJFTSERR is 21 + diagnostic length, at most 1,045 bytes. Check every count, conversion, multiplication and addition before allocation or final output. For each row, check `Σ(9 + field_length)` and the frozen framer's 1,024-field, 65,536-byte-per-field and 8 MiB stream limits. Validate the immutable snapshot, frame into separate bounded row scratch, then construct the whole envelope in separate bounded scratch. Only fully successful construction is handed to the caller in memory. Actual durable atomic publication remains an external gate.

## References and external holds

Metadata contract: Library `libfile_cc2de45386f48191b91a0f58df6e85f7` v0, archive `d5f687102a5f3076239d6e86a3e441c1253c3fe7d61ef5c835950e60e1aff0d4`. Accepted framer: Library `libfile_5c161f6e1fe081918145baead1a64747` v2, archive `a266c7bf0acd4f485c3b1846e5add10f7d8b358872dc3bd0e642489be6f27f8e`; header SHA-256 `2f504eca5a3f6f289c16888338744cf78b237d028bde407d026728eb152f1ae7`, implementation SHA-256 `47bd40d61d5b9e1a7be15dacbffd1f60c4298d5a75a9a133ac1b26a45dafc481`.

Independent catalog/function/owner/build/resource baseline and manifest, target and connection custody, qualified search path and observations, actual vector outputs, and rollback/cleanup proof remain external holds. No runtime result or golden acceptance is claimed.
