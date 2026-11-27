# Setjoin Edge API Contract (`contracts/edge/`)

Schema-first TypeSpec definitions that compile to the committed OpenAPI 3.1 baseline (`contracts/edge/openapi/edge.v1.yaml`) and drive deterministic code generation for:

- **Webmail TypeScript types:** `mailserver/webmail/src/lib/edge/schema.d.ts` (consumed by `openapi-fetch` via `mailserver/webmail/src/lib/edge/client.ts`).
- **Rust edge-only DTO crate:** `server-rust/crates/edge-contract/src/generated.rs` (`setjoin-edge-contract`, plain `serde::Serialize`/`serde::Deserialize` structs/enums with zero OpenAPI proc-macros).

## Layout

- `main.tsp` — root service entry point (`SetjoinEdge`).
- `common/problem.tsp` — RFC 9457 `ProblemDetails` model and error response envelopes.
- `common/pagination.tsp` — shared cursor and offset pagination query/envelope models.
- `modules/health.tsp` — `/health`, `/healthz`, `/_gateway/healthz`, `/ready`.
- `modules/rules.tsp` — `/api/settings/rules-list`, `/api/settings/rules`, `/api/settings/rules/{id}`, `/api/settings/rules/{id}/apply`, `/api/settings/rules/apply/{actionId}`.
- `modules/delivery.tsp` — `/api/messages/{emailId}/trace`.
- `modules/offline.tsp` — `/api/offline/size-estimate`, `/api/user/quota`, `/api/settings/view`.
- `openapi/edge.v1.yaml` — committed OpenAPI 3.1.0 baseline emitted by `@typespec/openapi3`.
- `scripts/gen-rust-dtos.mjs` — deterministic OpenAPI 3.1 → plain `serde` Rust DTO generator.
- `approved-breaking.json` — explicit sunset waiver ledger for planned breaking changes.

## Authoring & Compilation

```bash
cd contracts/edge
npm ci
npm run build
```

`npm run build` runs:
1. `npm run compile` — compiles `main.tsp` to `openapi/edge.v1.yaml` (OpenAPI 3.1.0).
2. `npm run gen:ts` — emits `mailserver/webmail/src/lib/edge/schema.d.ts` via `openapi-typescript`.
3. `npm run gen:rust` — emits `server-rust/crates/edge-contract/src/generated.rs` via `scripts/gen-rust-dtos.mjs`.

Verify zero drift against committed artifacts:

```bash
bash scripts/check-edge-contract-drift.sh
```

## 12-Month Compatibility Window Policy

All contracted HTTP edge APIs follow a **12-month compatibility window**:

- **Additive changes** (new endpoints, new optional request fields, new optional response fields, widened unions) are non-breaking and allowed at any time.
- **Breaking changes** (removed paths/methods, removed response properties, newly required request properties, narrowed enums, incompatible property types) are **blocked in CI** by `scripts/check-edge-contract-breaking.sh` (`oasdiff breaking` + deterministic OpenAPI 3.1 diff checker).
- A breaking change may land **only** after a 12-month deprecation period recorded in `contracts/edge/approved-breaking.json` with:
  - `id`: unique waiver identifier (e.g., `EDGE-BREAK-2026-001`)
  - `change_key`: exact breaking change fingerprint reported by `check-edge-contract-breaking.py`
  - `deprecated_on`: `YYYY-MM-DD` date deprecation was announced
  - `sunset_after`: `YYYY-MM-DD` date at least 365 days after `deprecated_on`, and on or before today's UTC date when the breaking removal is merged
  - `issue`: tracking GitHub issue reference
  - `reason`: short operator/client migration rationale

## Coverage Ratchet & Proc-Macro Ban

- `scripts/check-edge-contract-ratchet.sh` + `config/edge-contract-ratchet.json` enforce a monotonic coverage ratchet over non-JMAP/non-DAV HTTP routes in `server-rust/bins/gateway/route-inventory.json`: no new contractable route may land without an `EdgeContract` entry, and covered routes can never regress.
- `scripts/check-openapi-proc-macro-ban.sh` enforces that OpenAPI proc-macro crates (`utoipa`, `aide`, `poem-openapi`, `schemars`, etc.) never enter `server-rust/crates/domains/*`, `server-rust/crates/contracts/*`, or `server-rust/crates/pg/*`.
