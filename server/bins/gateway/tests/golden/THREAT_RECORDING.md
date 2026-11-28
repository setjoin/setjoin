# Threat response recording (#258)

`go-threat-blocked.json` and `go-ip-blocked.json` are raw response bodies
recorded through the enabled Rust gateway from frozen Go's real
`shared/threat.ThreatInterceptor.Middleware`. The handler behind the middleware
returned 204; this is a middleware-seam recording, not a full authserver run.
Go source commit: `0b4a6246c1623e6ebd1771075ca18ed24b78ee23`;
`interceptor.go` blob `1fd82bbce62c1daf7ab0eaf0c62568d928c1de6e`.
The Go 1.26.6 image was `setjoin-ci-linux-tc:local-amd64` (image SHA-256
`b5c41404ac8126e7d2ab4c7f8c7d45d926f165425d589d197f497313410511b6`).

Seed a disposable test DB with `record-threat.go`: it creates a feed entry for
`198.51.100.72/32` and an IP block for `198.51.100.73/32`, enables threat feed,
disables other toggles, and has no conditional-access engine. It refuses to
run if the recording range is already occupied and deletes its tagged rows on
graceful termination. Set `TEST_DB_DSN` to the disposable DB and
`TRUSTED_PROXY_IP=127.0.0.1`. Run the recorder with Go in the image, point both
Rust gateway Go upstreams at its printed address, and configure gateway trusted
proxies to `127.0.0.1`. POST `/auth/login` with body
`{"email":"gofree-t7@example.invalid"}` and trusted `X-Forwarded-For` `.72`
or `.73`, respectively. Go returned status 403, `Content-Type:
application/json`, and `X-Threat-Reason: threat_blocked` or `ip_blocked`.
`.74` returned 204. The recorder does not exercise conditional-access,
CAPTCHA, lockout, failure handling, or Rust threat decisions; these recordings
alone do not establish full threat-policy parity.

The recording was replayed through the gateway with the `/auth/login` Rust
inventory entry ON and its Rust upstream unreachable. The gateway deferred to
Go and the two bodies matched these files byte for byte; the Go test server's
tagged feed, rule and auth-attempt rows were removed after shutdown.
