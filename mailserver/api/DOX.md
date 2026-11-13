<!-- Detailed DOX reference, moved from AGENTS.md on 2026-09-11. -->
This is a task-selected reference, not an always-loaded rail. Root and local
AGENTS.md govern agent workflows. Domain contracts below remain binding for their
scope; historical status is not permission to implement or enable flags.

# mailserver/api — the integrator-facing OpenAPI contract (DOX rail)

Read the module `mailserver/AGENTS.md` first. This doc owns `mailserver/api/`.

## Purpose

The gateway's **integrator-facing REST contract** as OpenAPI 3.1 + its serving.
Package `apispec` embeds `openapi.yaml` and serves it. The anonymous routes serve
the **public subset** (admin paths filtered out — see "Visibility split" below);
the **full spec** is admin-gated:

- `GET /api/openapi.yaml` — the spec source of truth, served as the **public subset** (anonymous).
- `GET /api/openapi.json` — the same public subset as JSON (computed once at startup).
- `GET /api/docs` — a Redoc rendering of the public subset (anonymous).
- `GET /api/openapi.full.yaml` / `GET /api/openapi.full.json` — the **complete** spec
  (all paths), **admin-gated** in `main.go` (`adminLimit(requireAuth(requireSystemConfig(...)))` → **401/403** if not a system-config admin).

## Scope — broad phased coverage, with explicit remaining debt

`openapi.yaml` documents auth (including the public password-policy bootstrap
and Guest invite inspection/acceptance), JMAP discovery + request, broad user/admin
gateway coverage, SCIM, and the complete Setjoin Drive sub-router. It is not
yet the entire gateway surface; every remaining method/path is named in
`openapi-pending.txt`.

**Identity modernization tranche (V153–V167).** The current admin surface
documents normalized source/person/conflict/transition/event inventory; source
document plan/apply/detail/export, raw-byte secret set/rotation, dry-run, and
explicit activate/pause/resume/retire; digest-bound transition preview/execute;
bounded People detail; redacted conflict detail and exact
link/create/reject/defer decision; bounded transition-report export; upgrade
status, stable-checksum preflight, restart-safe backfill jobs, the seven-sync /
24-hour shadow gate, generation-fenced canary, rollback, and non-destructive
retirement readiness. It also documents read-only doctor checks, redacted
inventory export, durable job status/cancel/results, and sanitized diagnostic
create/status/download/delete. Every list uses a fixed allowlisted
sort, a 100 default/500 maximum, filter fields capped at 256 bytes, and an
opaque 15-minute cursor bound to actor, domain scope, filters, and sort. List,
status, preview, canary, and report responses expose strong ETags;
`If-None-Match` is honored on reads, while execute/canary validate an optional
compatibility `If-Match` against the digest/generation. Preview accepts the
idempotency UUID in `Idempotency-Key` or the deprecated body field and rejects a
mismatch. All mutation bodies are capped at 64 KiB, reject unknown/trailing
JSON, and require an exact body/header reason of at most 1024 bytes.

Source documents use a discriminator over the closed
`local|ad|ldap|scim|saml|oidc` kinds and reject inline secrets. Source mutations
require a strong generation `If-Match`, exact body/header UUID and reason, and
return a durable generation. Secret routes accept only
`application/octet-stream`; neither detail/export nor mutation responses expose
secret bytes or ciphertext. Dry-run performs schema, required-secret, and
transport checks with zero person writes; successful validation is the only
implicit lifecycle step. AD/LDAP endpoints accept only `ldaps` or `starttls`;
plaintext bind mode is absent from both schema and validation.

Async creation returns 202 with `Location` and bounded polling facts. Generic
jobs retain actor-scoped state and per-person cursor results for seven days;
diagnostic ZIPs are capped at 25 MiB and carry an exact wire `Digest`. The public
authenticated subset documents OIDC/SAML link
completion, link inventory, and unlink. Identity v2 paths may not be placed in
`openapi-pending.txt`: every implemented route needs named request/response
schemas, bounds, permissions, reason headers, and failure states.
`IdentityUpgradeStatus.sources` and `.blockers` are keyed objects, not arrays.
The canonical `Problem` schema includes stable actionable `code`, `retryable`,
`remediation`, and `remediation_tou_id` extensions; internal/transient reducer
failures omit the code. Exact gateway proxy routes are registered and
golden-pinned; coverage and visibility guards must both pass.

**Connectivity-aware sync E1 tranche (V209–V210).** The public authenticated
spec documents strict per-device sync preferences without a body-owned device ID.
The admin-only spec documents full offline/QoS policy writes and live policy
preview with decimal-string IDs. Named schemas preserve closed network/prefetch/
mode enums and the versioned `syncQoS` projection; route coverage and visibility
remain derived from the production registrar.

**Connectivity-aware sync E3 tranche.** `POST /api/mail/attachment-transfer-token`
strictly accepts an account decimal string plus immutable SHA-256 and returns one
five-minute bearer with `no-store`; it is not the byte route. The pinned exact
`GET /mail-attachment/{sha256}` surface documents Range/If-Range, strong ETag,
identity coding, 206/416, live reauthorization 401/403/409, terminal 404, and
storage 503. The scoped bearer is carried only in `Authorization`.

**Transactional updater U4 tranche (V178–V179).** The full admin spec documents
the one release-first console, digest-bound preview, five-minute challenge and
fresh-AAL2 completion, one-use-elevation intent request, exact intent/history,
safe-generation cancellation, ID-driven sanitized diagnostics, non-secret
recovery context, verified recovery-set registration, and new-isolated-target
restore proof. Bodies are strict/capped, IDs remain strings/UUIDs, reasons bind
body to header, and no request accepts a filesystem path, URL, command, unit,
migration filename, raw log, DSN, or arbitrary artifact key. The route/spec/web
client/CLI/doc inventory is additionally pinned by
`scripts/check-upgrade-contracts.sh`.

**Client-assisted continuity U5–U7 tranche (V180–V181).** The full spec names
the signed continuity presentation, receipt/raw-byte fetch, user incident and
resumable upload/abort routes, plus `system.recovery` signal/incident/artifact
review and acceptance. Decimal BIGINTs remain strings; UUIDs, SHA-256 digests,
inventory counts/sizes, JSON/body limits, `Content-Range`, audit reasons,
idempotency, malware/fork/tamper terminal states, and permissions are explicit.
Receipt eligibility is a required signed claim and must equal the top-level
upload request; cumulative admission may return 507 when a fixed reservation
ceiling is exhausted.
No request accepts a path, object key, command, unit, credential, raw journal,
or unsigned content identity. The public subset exposes authenticated user
offer routes but filters admin recovery routes from anonymous OpenAPI output.

People detail is `users.read` plus reducer-enforced no-oracle reach and returns
only bounded lifecycle/field authority, recovery posture, subject
fingerprints, entitlement provenance, and capped histories. Conflict detail is
similarly redacted; a domain-scoped caller cannot inspect an unbound
source-wide candidate. Decision requires `identity.write`, exact strong
generation `If-Match`, matching body/header idempotency UUID, and bounded
reason. Link never accepts soft evidence or a person other than the evidenced
candidate; protected takeover routes to the transition workflow. Responses
have named schemas and decimal-string BIGINT fields. `createAvailable` is false
until the reducer has a batch-bound insert-only account-creation seam; clients
must not infer support merely because `create` remains in the forward-compatible
decision enum.

**Drive tranche (2026-07-22).** The outer `ANY /api/drive/` mount is only an
implementation detail. `check-route-inventory.sh` replays Drive's
production-used private registrar into exact canonical method/path pairs,
including `HEAD`, and removes the opaque mount from the merged inventory. Chat,
Meet, and SCIM use the same owner-emitter contract. All 63 current Drive
operations are documented as public-visibility authenticated routes. Core
space/member/node/chunk/version schemas are explicit;
collaboration, audit, export, trash, search, watch, and compliance routes carry
their real parameters, permission notes, media types, and status classes.

**Drive node-ACL tranche (V184–V193).** Exact access, bounded subject search,
grant/inheritance preview and mutation, quick views, access-request governance,
opaque invalidation paging, and epoch-consistent visibility snapshots are part of
the same authenticated Drive namespace. BIGINT identity and epoch fields are
decimal strings; invalidation cursors are opaque UUIDs. OpenAPI owns the preset,
scope, time/use, body-size, page-size, and typed-problem bounds. All behavior flags
remain OFF by default; route presence is not rollout authorization.
Grant and access-request creation require a canonical UUID in both
`Idempotency-Key` and `body.idempotencyKey`, with exact equality. Revoke and
inheritance instead use durable terminal state and ACL epoch recovery; no generic
receipt table exists. Registered request routes are safe while OFF only because
the reducer returns the target-independent disabled projection before lookup.

**Mostly hand-authored; the schemas are migrating to typed-DTO generation.** The
handler layer is map/anonymous-struct dominated, not typed DTOs: ~317 responses
are `map[string]any`, requests are ~61 inline anonymous `var req struct{…}`. So
most of this contract is hand-authored, **provided drift is fenced** — which it
is, by the coverage guard below. The path forward (Phase 0B+ of
`retired-docs:superpowers/plans/archive/2026-06-20-openapi-coverage-expansion.md`) is to refactor
handlers to named DTOs in tranches and **generate** their schemas from the Go
types, so the DTO IS the schema and the two cannot drift.

**Generated schemas (`cmd/schemagen`).** The admin/users pilot is live: the
`User` / `UserCreate` / `UserUpdate` component schemas are reflected from the
exported DTOs in `internal/admin/admin_users.go` (`UserResponse`,
`UserCreateRequest`, `UserUpdateRequest`) by `cmd/schemagen` (kin-openapi
`openapi3gen`), wired via `//go:generate go run ./cmd/schemagen` in `apidocs.go`.
The generator rewrites **only** the region between
`# BEGIN GENERATED SCHEMAS (schemagen)` and `# END GENERATED SCHEMAS` in
`openapi.yaml`; it is idempotent (re-running is a no-op) and `schemagen_test.go`
proves it (it runs the real generator against the committed spec and asserts no
diff). Run it with `go generate ./mailserver/api/...` after touching a generated
DTO, and commit the regenerated block. The paths `$ref` the schemas by name, so
the names are the public contract — do not rename a DTO's schema name without
updating its `$ref`s. **Reconciliations the reflector can't infer** are carried
on the DTO as `openapi:"…"` struct tags and applied by schemagen's
`SchemaCustomizer`: `format=email|password|int64` (Go strings carry no semantic
format) and `required` (kin-openapi does not derive `required` from Go
non-pointer-ness). One intentional shape change vs the old hand-authored spec:
`UserUpdate`'s optional pointer fields now emit `nullable: true` (they are
`*string`/`*bool`), which the hand-authored version omitted — harmless for a
patch body.

## Visibility split — API docs visibility == the auth boundary (load-bearing)

**Threat model (Phase 0A).** The full admin API contract must not be anonymously
disclosed (a pentest finding), but an integrator must still discover the
integration surface *before* holding credentials. So **API-docs visibility is the
auth boundary, derived from runtime-emitted production registrar wrappers — not a hand-maintained
list** (a hand list drifts; this cannot):

- Each documented path object carries `x-visibility: admin|public`. **admin** =
  the route is wrapped in EITHER (a) a ROLE wrapper — `requireAdmin` /
  `requireSuperAdmin` / `requireReadOnly` / `requireAuditor` / `requireAdminOrAuditor`
  (`RequireAdmin` or a `RequireRole` over an admin/auditor/user_admin/read_only
  role) — OR (b) a PERMISSION wrapper under `requireAuth`:
  `requireAuth(require<Perm>(...))` where `require<Perm>` is a `RequirePermAudited`
  / `RequireAnyPermAudited` gate (the RBAC cut-over's axis — `requireUsersCreate`,
  `requireMailPerm`, `requireSystemConfig`, `requireAuthPerm`, …). The guard
  records these applied wrapper names from the real registrar, so it cannot drift. **public** =
  anonymous, **plain** `requireAuth` (authenticated-but-not-admin), or a
  SCIM/integrator-token route.
- The **anonymous** endpoints (`HandleYAML`/`HandleJSON`/`HandleDocs`) serve the
  **public subset**: every `x-visibility: admin` path is dropped and the
  `x-visibility` keys are stripped, computed once at `init` (alongside `specJSON`).
  Redoc renders this subset.
- The **full spec** (`/api/openapi.full.yaml` + `.json`) is **admin-auth-gated**
  (`adminLimit(requireAuth(requireSystemConfig(...)))` → **401/403** if not a
  system-config admin). No config toggle (YAGNI),
  no new auth mechanism.
- **Guarded by `scripts/check-openapi-visibility.sh`** (wired into `scripts/test.sh`
  next to the coverage guard): for each documented path it re-derives admin/public
  from the runtime-emitted gateway wrapper chain and fails if that disagrees with the stamped
  `x-visibility`, so doc-visibility can never drift from enforcement (an admin path
  can never silently leak into the anonymous spec). `--self-test` plants a mismatch
  and asserts the guard fires. The serving split itself is guarded by
  `visibility_test.go` (public subset omits admin paths + strips the keys; the full
  spec contains them; the public subset still parses).

## The drift fence — `scripts/check-openapi-coverage.sh` (load-bearing)

A "valid OpenAPI" parse proves the spec is well-formed; it does NOT prove it
matches the routes (it can certify a well-formed lie). The real guard is the
**route↔spec coverage diff** (ARCH-006 positive, fail-closed shape):

- **Direction 1 (no stale docs):** every documented path must be a registered
  route. CalDAV/CardDAV remain named protocol-contract exemptions. Drive, Chat,
  Meet, and SCIM are expanded from production-used package registrars.
- **Direction 2 (no silent gaps):** every emitted registered route must be in
  the spec **OR** in `openapi-pending.txt` (the coverage-debt ledger).

So a NEW route can never silently ship undocumented (it is neither in the spec nor
the ledger → CI fails), and a documented path can never point at a dead route.
Paths are normalized `{param}` → `{}` so param-name differences don't false-diff.
`check-route-inventory.sh --self-test` rejects missing, duplicate, stale, and
wrong-prefix artifacts and plants an undocumented private route; the coverage
guard also plants its own private-route miss. Both run through `scripts/test.sh`.

**To document a route:** add it to `openapi.yaml`, then delete its line from
`openapi-pending.txt`. **To regenerate the ledger** after adding/removing routes:
`scripts/check-openapi-coverage.sh --regen-pending`.

## Air-gap / CSP (load-bearing)

`/api/docs` AND its renderer (`/api/redoc.standalone.js`, the vendored Redoc MIT
bundle, embedded via `//go:embed`) are served **same-origin**. This is required,
not a nicety: the gateway's CSP is `script-src 'self'` (`internal/middleware/
security.go`), so a CDN `<script>` is BLOCKED and the page renders **blank on
every install**, not just air-gapped ones (that was the bug before — guarded now
by `apidocs_test.go`, which fails if the HTML references any external/CDN script).
Same-origin passes the CSP and renders with zero internet egress. Licensing is
permissive throughout (OpenAPI spec Apache-2.0, Redoc MIT — `redoc.standalone.js.LICENSE.txt`).
The ~1.1MB bundle is committed; refresh it from the Redoc release when bumping.

The same rule binds the **brand font**: the gateway CSP is also `font-src 'self'`,
so the IBM Plex Sans woff2 faces (400 body / 500 headings, vendored from
`webmail/build/fonts`) are `//go:embed`'d and served same-origin at
`/api/fonts/ibm-plex-sans-{400,500}.woff2` via `HandleFont` (immutable year-long
cache). `redocHTML` declares an `@font-face` (`font-display: swap`) for each;
without it the Redoc page degrades to system-ui. Guarded by `font_test.go`.

## Files

| File | Role |
|---|---|
| `openapi.yaml` | The OpenAPI 3.1 spec (embedded). Source of truth. Mostly hand-authored; the schemas between the `schemagen` markers are generated from typed DTOs. |
| `apidocs.go` | `apispec` package — embeds the spec + Redoc bundle + logo + brand-font woff2; serves the **public subset** (YAML/JSON/Redoc/font, anonymous) + the **full** spec (`HandleFullYAML`/`HandleFullJSON`, admin-gated). Carries the `//go:generate go run ./cmd/schemagen` directive. |
| `cmd/schemagen/` | Generator (`package main`): reflects the admin/users DTOs into the `User`/`UserCreate`/`UserUpdate` component schemas and rewrites the marked region of `openapi.yaml`. Idempotent. Run via `go generate ./mailserver/api/...`. |
| `schemagen_test.go` | Asserts the generated marker block is present + non-empty, the generated schemas carry the DTO fields + reconciled format/required, and the generator is idempotent (runs it against the committed spec, asserts no diff). |
| `apidocs_test.go` | Build-time structural sanity + handler smoke, including `HEAD` operations and representative Drive paths/schemas/public serving (NOT the full coverage check). |
| `visibility_test.go` | The visibility split: public subset omits admin paths + strips `x-visibility`; full spec contains them; public subset still parses. |
| `ibm-plex-sans-{400,500}.woff2` | Brand font (body/heading), vendored from `webmail/build/fonts`, embedded + served same-origin by `HandleFont`. |
| `font_test.go` | Asserts `HandleFont` returns `font/woff2` bytes + `redocHTML` has a same-origin `/api/fonts/` `@font-face`. |
| `openapi-pending.txt` | Coverage-debt ledger: registered routes not yet documented. |
