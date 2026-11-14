# Catch-all HTTP oracle (#416)

The public seam is HTTP through the actual front door: unknown paths, method
mismatches, ServeMux redirects, bare mutation aliases and the webmail static
responder. Frozen Go is the expected result, including middleware headers and
raw problem bytes. Goldens are created exclusively, never overwritten.

`bins/gateway/tests/catchall_recorded.rs` owns recording and replay. Recording
uses `GOFREE_RECORD_GO_BINARY`, `GOFREE_GO_SOURCE` and
`GOFREE_RESOURCE_PREFIX=gofree-catchall` with an existing resource ledger in
`GOFREE_RESOURCE_LEDGER`. The assigned disposable schema and standard test DSNs
are required (`REQUIRE_DB=1`). Ordinary replay starts no Go process and leaves
the Go upstream unset. Run serially (`--test-threads=1`).

The asset fixture is an operator build directory with a matching
`static-representations.v1.json`; file bytes and representation hashes are
stable. Date and transfer framing are excluded, and every request has a fixed
request ID. SPA cases also pin Content-Length and SHA-256 of response bytes.
Only multipart's random 60-hex boundary is replaced with `<boundary>` in its
header/body before hashing; actual Content-Length remains checked. Status,
body bytes, cache policy, representation validators and redirects are compared. These paths do not mutate application data.

Run `python3 server-rust/tests/conformance/catchall/catalog.py` after adding
recordings. It updates only the six structural suites, preserves their original
family/slice ownership and leaves recordings unchanged. Per-registration status
mutants run the real fallback with its status deliberately changed; replays also
assert the Go proxy counter remains zero.

`catchall_oracle/assets.rs` creates a complete build with fixed bytes and mtime,
plus valid gzip and Brotli sidecars. The fixtures are temporary, ledgered and
removed after Go exits. `spa_setup*` runs without fixture accounts; every other
case uses independent actor/foreign accounts and restores feature toggles.
The bootstrap cases must run against the exclusively assigned disposable DB.

`catchall_startup` exercises the executable with the Go upstream unset, all six
fallbacks and both rollback switches, then rejects corrupt or incomplete builds.
`SETJOIN_CONFIG` is resolved before startup (#414); unreadable files refuse
startup, and a valid file no longer causes a root fallback forward.
Identity and entitlement-audit deferrals retain the existing family contracts.

Frozen-Go quirks retained: `/api/chat` redirects to bare `/chat/`; the original
request's cache table can cache an SPA fallback for one year under
`/chat/unfurl/image/`. See `mux_inner_slash` and `spa_extra_legacy_cache`.
357d: a denied app entitlement, including a failed entitlement read, is answered natively with Go's RequireApp 403 and app_blocked audit (*_not_entitled; chat_not_entitled_read_fault replays chat_not_entitled.json with a shadowed reducer). An unreadable app toggle answers 503 "service unavailable" (chat_toggle_read_fault; #354's approved precondition-read divergence; Go reads toggles from memory). Fault cases are native-only and inject through a temporary search_path schema on the catch-all's executor.
