# F22 / F20 / translate recordings (#271)

`goldens/<case>.json` are frozen-Go observations (response status, headers,
exact body SHA-256 and length, the small body text, provider exchange, chat audit
rows, notifications). Translate cases also have `<case>-row-effects.json`
(complete `chat_audit_log` rows). `bins/gateway/tests/static_recorded.rs` is the
only test target; its case table (`tests/static_oracle/cases.rs`) is generated
from one list, so a case name is a test name, a golden file name (`_` to `-`) and
a catalog selector. `gen/spec.py` is the single source: `python3 gen/emit_rust.py`
writes the table and tests, `python3 gen/emit_catalog.py` remerges the catalog suites and the
inventory entries while preserving later qualification cases (run both after changing a case; recordings are never regenerated).

Record one case (Go binary and a disposable DB required; exclusive creation,
never overwrites):

```sh
GOFREE_RECORD_GO_BINARY=<path to frozen mailserverd> GOFREE_GO_SOURCE=<40-hex commit> \
GOFREE_RESOURCE_LEDGER=<existing file> cargo test -p setjoin-gateway \
  --test static_recorded <case> -- --exact
```

`GOFREE_ORACLE_EXTRA_ENV` (newline-separated `NAME=value`, read by
`common/go_oracle.rs`) lets a case start Go with `WEBSITE_DIR`, `METRICS_TOKEN`,
`IMAP_TLS_ADDR` and similar. Replay needs no Go. Metrics process counters are
blurred; everything else is exact.

Case kinds: `success`, `cross-tenant` (a foreign principal or a foreign domain;
these routes hold no per-user data, so most answers are identical for every
principal), `invalid-input`, and route-specific extras. A case with
`forwarded: true` is one Rust hands to Go by design; the oracle replays the
recorded Go answer through a fake upstream and requires exactly one forward.
`discover_*` retains Go's no-result 404. Positive DNS/TLS discovery and live
sidecar recordings now live in [static2](../static2/README.md) (#417).

STATIC2 (#417) adds named `toggle-off` and mutating `device-proof` telemetry
suites. The original five unnamed telemetry fixtures remain regression tests;
fresh named recordings partition the inventory (empty and named commands cannot
be mixed). Device-proof cases have complete normalized report, nonce and
credential row companions, including the foreign device. Generated IDs and times
are omitted; nonce lifetime and encrypted-secret usability remain compared.
Record-only teardown restores the full system_config snapshot because frozen
Go boot migrates connector secrets under identity.deployment_id.
