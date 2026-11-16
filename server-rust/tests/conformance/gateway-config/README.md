# Gateway configuration (#414)

Operator seam: Go's `config.LoadWithKoanf` in a test-only overlay records the
configuration precedence table (`layers.json`). `record-layers.sh NEW_OUTPUT`
replays those inputs in the CI image with the shared module cache. Compare the
new output to the immutable recording; never overwrite a golden. No production
Go source is changed. Source revision: e3333b005d960d24b3e55d21ff6f3526bf4fdecc.

`config.env` is a systemd EnvironmentFile, not an additional Go parser layer.
The process receives its values through the environment, above YAML. Reload
re-reads YAML plus the unchanged process environment; editing config.env needs
a process restart. Go's reload report is only `{"status":"reloaded"}`. Its
config pointer has no handler readers; startup routes/configuration remain
unchanged. Trusted proxies and the outbound S/MIME algorithm are refreshed.

Recorded Go quirks: dotted YAML keys do not override nested defaults; login
field/domain hint are declared but never decoded into the gateway Config, so
both remain empty even with YAML and environment overrides. Mirror these.

`gateway_config_runtime` replays `f7.json` (seven configuration conditions),
`reload-http.json` (report, boot snapshot retention, scoped grant, denial audit,
repeat and invalid algorithm), and `proxy-{http,sighup}-v2.json` (client-IP rate
budgets before and after failed/successful refresh), with the Go upstream unset
and proxy count zero. Tests serialize this file's global operator settings and
restore them. For rate proofs both processes first saturate the socket-peer
bucket: Go's readiness requests may already consume a credit; fresh forwarded
IPs discriminate preserved trust after failure from replaced trust after success.

Recording requires the assigned disposable schema and the standard DSNs plus
`REQUIRE_DB=1`, `GOFREE_RECORD_GO_BINARY`, `GOFREE_GO_SOURCE` and an existing
`GOFREE_RESOURCE_LEDGER`. Use the exact `yaml_f7_conditions_...`,
`reload_http_matches_...` or `refreshes_client_ip` selectors for new recordings;
clear recording env for replay. The test-only Go helper signals only the
worker inside its own named container. Run `python3 .../gateway-config/catalog.py`
to generate immutable reload projections and update only the gateway reload
suite in route-catalog. The auth listener's reload suite remains separate.

A JWT sent as a SCIM bearer retains the named #188 guest-belt handoff; the
boot-registration probe uses an opaque invalid SCIM token. Reload's scoped
`system.config` grant succeeds in Go. LDAP on-demand clients come from stored
`ldap_sync_*` rows; Go's startup ReloadConfig clears an initial YAML worker
when no runtime rows exist. AD's feature enable remains pinned to boot config.

`f7-disabled-scim.json` records the configured website root SPA fallback when
SCIM is disabled. `proxy-http-{whitespace,embedded-comma,mapped-cidr}.json`
pins Go's strict individual proxy-list member parsing. The executable also
checks valid JWT_SECRET-only deployments without a JWKS URL; legacy JWT
verification uses the existing audited implementation. Fixture cleanup restores
operator values, encryption flags and descriptions.
