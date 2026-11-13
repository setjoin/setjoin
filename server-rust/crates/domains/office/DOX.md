# Office (F15, #270)

The domain crate depends only on foundation crates. WOPI uses the SHA-256 of
an opaque launch token, not a browser JWT. `office_wopi_file_query` resolves
actor, file and live authority together; URL IDs never supply ownership.
The HTTP edge is `bins/gateway/src/office.rs`. Office is mounted at `/api`.

All nine F15 registrations are qualified and ON by default. The catalog and
[case ledger](../../../tests/conformance/office/CASES.md) identify the oracle.
`office_recorded` records frozen Go through the real front door and replays
with Go unset. `common/office_go.rs` names and journals its owned containers.
Earlier CheckFileInfo tracer bullets retain raw fixture IDs and remain
immutable historical evidence. The catalog selects the qualified wire corpus,
which validates and substitutes fixture IDs by field and relation.
No accepted divergences. Existing SQL/Go/root contracts are unchanged.

## Qualified adapters

`OfficeRoute` covers CheckFileInfo, chunk-stream GetFile, WOPI locks and PutFile.
The immutable `Launch` is minted only by `office_wopi_file_query`; a primary
mailbox lookup for its reducer-derived actor supplies receipt scope. WOPI tokens
are launch credentials; browser JWT identity is never substituted for them.
`OfficeAdminRoute` uses shared ES256/CSRF/session admission and live Office
permissions. Denials retain Go's separate best-effort `console.denied` audit.
Org-wide Office provider data has no domain isolation dimension in frozen Go.

All durable mutations call the existing Office/Drive reducers through receipted
transactions. A chunk's transaction authorizes and takes Go's advisory lock,
promotes its verified temporary object, calls the existing registration reducer,
and commits. Final save is a separate `office_save_accept` transaction, as in Go.
A lost commit returns 503 plus its operation ID; canonical bytes remain for
recovery. Only temporary upload objects are removed. Saves keep Go's 4 MiB
chunks, 200 MiB bound, lock hash and operation-key derivation.

`office_provider.rs` implements qualification HTTPS, XML proof-key admission,
DNS-answer pinning and the explicit hostname/private-CIDR policy. Tests record
against a temporary TLS provider using the checked-in **test-only** key/CA under
`tests/conformance/office/provider`; no production certificate is replaced.
The frozen recorder maps that CA path into its `/src` mount.

`office_admin` captures complete scoped Office/Drive business rows, core and
Drive audits, and committed notifications. Timestamps and generated identifiers
are validated before normalization; provider notifications are parsed as JSON
and qualification UUIDs are normalized on both old and new observations.
Earlier response-only goldens remain immutable as historical tracer bullets.

`bins/gateway/src/f15.rs` supplies one complete registration to the executable
and `f15_dispatch` HTTP tests. Bundled inventory controls native admission;
global kill and per-family OFF overrides return untouched requests to Go.
Native dispatch has no Go upstream and leaves the proxy counter at zero.
The shared foundation's authenticated-user scope sets Drive's FORCE-RLS GUC
only from the reducer-derived launch actor during chunk registration. After
integration with F10, both scoped reads and writes install this named GUC;
Office needs no family-specific scope opt-in.

Provider discovery keeps Go's 12-hour process-local key cache, 20-minute
Windows-epoch timestamp window and three permitted key/header combinations.
Its native TLS request preserves Go's discovery headers and simple Unicode
uppercase proof payload. Qualification retains the separate explicit paired
hostname/private-CIDR exception; runtime proof discovery has no such exception.
The request-scoped browser auth deferrals remain owned by identity #331–#333.

All canonical mutator observations validate complete business rows, audit
chains, notifications and S3/provider effects. Only Rust operation receipts
are excluded as foundation metadata. Every route rejects its planted status
mutant; actual SQL mutants cover audit, notification, generation and ownership.
No new reducer or Go change was needed; no bypass follow-up is required.

Opaque WOPI lock values and audit reasons preserve valid UTF-8 header bytes,
including current-lock conflict replies. Go-recorded sequences cover lock,
unlock/relock, refresh and unlock, with business rows observed after each step.

WOPI routing splits escaped URI segments before decoding the file ID, matching
Go PathValue. An encoded slash stays inside that ID and fails numeric parsing;
it cannot select the contents route. The recorded negative case asserts 400
and no storage read.
