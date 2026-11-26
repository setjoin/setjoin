# Shared contracts and formats

The existing command/authority contracts remain documented in `src/lib.rs`.
`csv` (#266) is a pure, driver-free encoding seam: frozen Go's default
`encoding/csv` comma/LF record writer and migration `EscapeCSVCell` prefix rule.
Only data cells receive formula escaping; fixed verification/header metadata
stays literal. The Chat audit CSV HTTP recording tests the exported bytes,
including a formula-bearing, comma-containing note. No family dependency or I/O.

`han` is the Go 1.26.6 / Unicode 15 Han property table recorded for F12's
public search oracle. F04 eDiscovery and F12 member search share this pure data
helper; its ranges moved verbatim from gateway `chat_b/han.rs`. No family edge.

`go_quote::quote` preserves frozen Go `strconv.Quote` diagnostics, including
per-byte invalid UTF-8 escapes, ASCII short/hex escapes and Unicode 15.0
printability. Its range data is recorded from the pinned Go 1.26.6 toolchain;
it never follows the Rust host's Unicode version. F04 export HTTP records cover
controls, nonprintable BMP/supplementary runes and malformed UTF-8 query bytes.

`ResourceScope::User(actor)` (#188) represents mailbox-less authenticated user
transactions. Actor and scope are checked by the existing command lifecycle;
mail commands continue requiring `ResourceScope::Mailbox(real_mailbox)`.

## Go UUID identifiers (#455)

`ids::go_uuid` uses the unmodified `uuid` parser and canonical lowercase output.
Its input adapter matches frozen `google/uuid.Parse`: compact, hyphenated,
case-insensitive URN and 38-byte wrapped forms (Go ignores both wrapper bytes).
Callers reject nil when their HTTP contract requires it. This pure format helper
grants no authority and performs no I/O; recovery-admin HTTP goldens exercise it.
