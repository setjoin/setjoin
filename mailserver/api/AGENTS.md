# mailserver/api — the integrator-facing OpenAPI contract (DOX rail)

Owns embedded OpenAPI 3.1 and same-origin docs; registrars/auth wrappers own enforcement. openapi.yaml is authoritative; generated DTO schemas stay generator-owned/idempotent. x-visibility derives from wrapper chains, not path guesses; anonymous docs expose filtered public discovery, full docs require auth/system-config. Public discovery never grants anonymous runtime access. Preserve two-way route coverage and named protocol exemptions; remove pending entries when documented, never regenerate away drift. Assets are embedded/same-origin, no CDN/CSP relaxation. Read affected scope/visibility/drift/CSP/files sections. Route/spec changes require API tests and OpenAPI coverage/visibility guards; generator changes idempotence; registrar changes inventory tests.

## DOX sections

- [Purpose](DOX.md#purpose)
- [Scope — broad phased coverage, with explicit remaining debt](DOX.md#scope--broad-phased-coverage-with-explicit-remaining-debt)
- [Visibility split — API docs visibility == the auth boundary (load-bearing)](DOX.md#visibility-split--api-docs-visibility--the-auth-boundary-load-bearing)
- [The drift fence — `scripts/check-openapi-coverage.sh` (load-bearing)](DOX.md#the-drift-fence--scriptscheck-openapi-coveragesh-load-bearing)
- [Air-gap / CSP (load-bearing)](DOX.md#air-gap--csp-load-bearing)
- [Files](DOX.md#files)
