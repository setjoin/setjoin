# Schema-First Rust to SvelteKit TypeScript API Contract Tooling for Setjoin

- **Ticket:** [#523 — Research: Schema-first Rust to SvelteKit TypeScript API contract tooling](https://github.com/setjoin/setjoin/issues/523)
- **Parent Map:** [#520 — Wayfinder: Post-Go Target Architecture for Setjoin](https://github.com/setjoin/setjoin/issues/520)
- **Date:** 2026-11-22
- **Status:** Research findings (read-only analysis; no code changes)

---

## 1. Executive Summary & Recommendation

**Adopt OpenAPI 3.1 as Setjoin's canonical HTTP API contract format for the ~920–943 non-JMAP/non-DAV routes**, consumed in SvelteKit (`mailserver/webmail`) via **`openapi-typescript` (`v7.13.0`, MIT) + `openapi-fetch` (`v0.17.0`, MIT)** wrapped around the existing `httpRequest()` DPoP/401-recovery seam (`mailserver/webmail/src/lib/http.ts`).

For Rust contract authoring and enforcement in the 50-crate `server-rust` workspace (currently raw `hyper = "=1.12.0"` + `RouteTable`/`Intercept`, **not** `axum`):

- **Do not** adopt **ConnectRPC / Protobuf** (`connectrpc` `v0.9.1` + `buffa` `v0.9.2`, or `tonic`) as the primary contract layer for Setjoin's ~943 non-JMAP/non-DAV routes: ConnectRPC is an RPC-envelope protocol incompatible with Setjoin's existing REST/HTTP semantics (RFC 9457 Problem Details, `multipart/form-data`, HTTP `Range` Drive chunk downloads, browser `EventSource` SSE, OIDC/SAML redirects, WebSockets) and would introduce a pre-1.0, second Protobuf stack (`buffa`) alongside `prost = "=0.14.4"` (LiveKit).
- **Do not** rely on **type-only exporters** (`ts-rs`, `specta`, `typeshare`) as the HTTP API contract: they export structs/enums only and omit HTTP methods, paths, query params, status codes, headers (`X-Audit-Reason`, `Range`), Problem Details error variants, and binary/SSE shapes, leaving hand-written fetch wrappers (such as the 5,009-line `mailserver/webmail/src/lib/admin/client.ts`) to drift silently.
- **Do not** use **`progenitor`** (`oxidecomputer/progenitor`, MPL-2.0): it targets OpenAPI 3.0.x only (rejects OpenAPI 3.1.0, Issue #1268) and generates `reqwest` clients / Dropshot pairings rather than `hyper`/`axum` servers.
- **Recommended Rust-side OpenAPI 3.1 posture (incremental, edge-isolated):**
  1. **Keep domain crates (`crates/domains/*`, `crates/contracts`, `crates/pg`) free of OpenAPI proc-macros** so the 50-crate workspace pays zero proc-macro compile tax during domain/SQL/conformance work.
  2. **Author contracts at the HTTP edge** via either:
     - **Contract-first TypeSpec (`@typespec/openapi3`, MIT) or modular per-family OpenAPI 3.1 specs** with generated edge DTOs/validators (evaluating `oas3-gen` `v0.29.x` / `openapi-to-rust` `v0.23.x+` if `bins/gateway` adopts `axum::Router` under `RouteTable`), **OR**
     - **Edge-only `aide` (`v0.15.1`, MIT OR Apache-2.0, `schemars` trait-based) or `utoipa` (`v6.0.0`, MIT OR Apache-2.0)** if `bins/gateway` introduces `axum` route handlers family-by-family, gated in CI by OpenAPI breaking-change diffing (`oasdiff`) to preserve schema-first backward compatibility.
  3. **Retain JMAP (`RFC 8620`/`8621`)** for Mail/PIM sync (`POST /jmap`, `/jmap/eventsource`, `/jmap/ws`, blob upload/download), **UniFFI (`0.32`, MPL-2.0)** for Rust-to-native-shell FFI (`offline-core`, `guard-core`), and **AsyncAPI / shared JSON Schema** for WebSocket frames (`/rtc`, `/jmap/ws`).

---

## 2. Setjoin Baseline Observed in Repository

| Dimension | Observed Fact in `c:\Setjoin` | Implication for Contract Tooling |
|---|---|---|
| **Route surface** | `server-rust/bins/gateway/route-inventory.json` lists **954 routes** across 22 families (`F01`–`F22`) and 6 listeners (`gateway` 869, `auth` 72, `fedharness` 6, `asrbot` 4, `control` 2, `acme` 1). Methods: `GET` 381, `POST` 357, `PUT` 88, `DELETE` 75, `*` 44, `PATCH` 8, `HEAD` 1. Only ~11–32 routes are JMAP/DAV; **~920–943 are non-JMAP/non-DAV**. | Any contract system must support standard REST verbs, path params, query params, headers, redirects, and ~900+ routes across 22 domains without requiring a flag-day rewrite. |
| **Rust server stack** | `server-rust/Cargo.toml`: **50 workspace members**, `edition = "2021"`, `rust-version = "1.97.1"`. `bins/gateway/Cargo.toml` uses **raw `hyper = "=1.12.0"` + `hyper-util = "=0.1.21"` + `http-body-util = "=0.1.5"`** via custom `RouteTable` + `Intercept` trait (`bins/gateway/src/routes.rs`). **No `axum`, `tower`, `utoipa`, `aide`, `tonic`, `ts-rs`, or `specta` is present.** `prost = "=0.14.4"` is used only for LiveKit; `multer = "=3.1.0"` for multipart; `tokio-tungstenite = "=0.30.0"` for WS. | Tools tightly coupled to `axum` (`utoipa-axum`, `aide::axum`, `oas3-gen` server traits) either require introducing `axum` per family behind `Intercept`/`RouteTable` (since `axum` runs on `hyper 1.x`) or restricting codegen to pure `serde` DTOs + validation. |
| **Streaming / binary / errors** | SSE (`/jmap/eventsource`, `/api/jmap/guest/.../events`, `/admin/identity/v2/events`, `/admin/mam/devices/{device_id}/events`), WS (`/jmap/ws`, `/rtc`), raw binary & HTTP `Range` (Drive chunks per `ARCH-017`, JMAP blobs), `FormData` multipart (`multer`), ZIP/CSV exports, and RFC 9457/7807 Problem Details (`bins/gateway/src/problem.rs`). | RPC-only wire protocols (ConnectRPC, gRPC-Web) cannot natively model `Range` reads, `multipart/form-data`, browser `EventSource`, or Problem Details without breaking clients. |
| **Webmail TS stack** | `mailserver/webmail/package.json`: Svelte `^5.56.8`, SvelteKit `^2.70.2` (`@sveltejs/adapter-static`), TypeScript `^6.0.3`, Vite `^8.2.0`. Single fetch seam `src/lib/http.ts` handles `AbortController` timeouts, `401` DPoP admission probe & token recovery, ToU/risk remediation, and Problem Details; `src/lib/admin/client.ts` is **5,009 lines** of hand-written fetch calls. | Generated TS clients must emit **zero-runtime-cost or `fetch`-injectable** clients so all calls continue flowing through `httpRequest()` / DPoP recovery without duplicating auth/error logic. |
| **Native clients & longevity** | `clients/`: Electron desktop, Tauri 2 mobile, HarmonyOS NEXT ArkTS/ArkWeb render webmail **and** make direct HTTP calls (`/auth/me`, `/auth/login`, Drive chunks/ranges in `clients/desktop/electron/src/drive/mirror.ts` and `clients/rust/offline-core/src/drive.rs` using `ureq = "2"` + `uniffi = "0.32"`). `docs/research/2026-09-06-extension-api-longevity.md` commits to a **12-month** compatibility/deprecation window for stable APIs. | Wire format must remain standard HTTP/JSON + binary, with CI-enforced additive-only evolution (`oasdiff`) rather than breaking wire rewrites. |
| **Licence & advisory gate** | `server-rust/deny.toml`: allows only `MIT`, `Apache-2.0`, `Apache-2.0 WITH LLVM-exception`, `BSD-2-Clause`, `BSD-3-Clause`, `ISC`, `Zlib`, `0BSD`, `CC0-1.0`, `BSL-1.0`, `Unicode-3.0`, `Unicode-DFS-2016`, `MPL-2.0` (unmodified). Rejects `unmaintained = "all"`, `unsound = "all"`, `yanked = "deny"` via `cargo deny check`. | GPL/AGPL tools are forbidden; `MPL-2.0` crates (e.g., `progenitor`, `uniffi`) are allowed only if unmodified; crates with unpatched RustSec advisories or unmaintained status fail CI. |

---

## 3. Primary-Source Evaluation by Candidate Stack

### 3.1 OpenAPI 3.1 Ecosystem (Code-First Rust, Schema-First Rust, and TypeScript Consumers)

#### A. TypeScript Client Side: `openapi-typescript` + `openapi-fetch`
- **Primary sources:** [openapi-ts.dev](https://openapi-ts.dev), [openapi-ts/openapi-typescript](https://github.com/openapi-ts/openapi-typescript), [npm `openapi-typescript`](https://www.npmjs.com/package/openapi-typescript) (`v7.13.0`), [npm `openapi-fetch`](https://www.npmjs.com/package/openapi-fetch) (`v0.17.0`).
- **License:** **MIT** for both packages.
- **OpenAPI 3.1 & 3.2 support:** Full native support for OpenAPI 3.0 and 3.1 (including JSON Schema 2020-12 nullable type arrays `["string", "null"]`, `oneOf`/`anyOf` discriminated unions).
- **SvelteKit & Setjoin `http.ts` integration:**
  - `openapi-typescript` generates pure TypeScript interfaces (`paths`, `components`) with **zero runtime code** — compatible with Vite 8, `adapter-static`, and TypeScript 6 strictness.
  - `openapi-fetch` is a minimal typed wrapper around native `fetch` (`createClient<paths>({ fetch: setjoinFetch })`), allowing Setjoin to inject its DPoP proof-recovery, timeout `AbortSignal`, and `401`/`403` remediation middleware directly instead of replacing `src/lib/http.ts`.
- **Streaming, Binary, Multipart, SSE:**
  - Supports `parseAs: "stream"` (returns raw `ReadableStream` for chunked downloads, NDJSON, or `fetch`-based SSE with `Authorization`/DPoP headers), `parseAs: "blob"` / `"arrayBuffer"` (binary downloads), and `FormData` (`multipart/form-data` bodies).
  - OpenAPI 3.2 introduces sequential media types (`text/event-stream` with `itemSchema`) for typed SSE chunks; under OpenAPI 3.1, SSE event payloads are defined in `components.schemas` and referenced by a thin typed stream helper.

#### B. Rust Server Side — Code-First OpenAPI 3.1 (`utoipa` vs. `aide`)

| Criterion | `utoipa` (`v6.0.0`) | `aide` (`v0.15.1`) |
|---|---|---|
| **Primary sources** | [juhaku/utoipa](https://github.com/juhaku/utoipa), [docs.rs/utoipa/6.0.0](https://docs.rs/utoipa/6.0.0), [Discussion #1620](https://github.com/juhaku/utoipa/discussions/1620) | [tamasfe/aide](https://github.com/tamasfe/aide), [docs.rs/aide/0.15.1](https://docs.rs/aide/0.15.1), [GREsau/schemars](https://github.com/GREsau/schemars) |
| **License** | `MIT OR Apache-2.0` (`cargo deny` OK) | `MIT OR Apache-2.0` (`cargo deny` OK) |
| **OpenAPI version** | OpenAPI **3.1** (v5+) and **3.2.0** (`Version32` in v6.0.0; MSRV 1.88) | OpenAPI **3.1.0** natively via `schemars` |
| **Schema engine** | Custom proc-macro `#[derive(ToSchema)]` + `#[utoipa::path(...)]` | Uses `schemars` (`v0.9` in `aide 0.15.1`; standalone `schemars` is `1.2.3`) via `#[derive(JsonSchema)]` + `OperationInput`/`OperationOutput` traits |
| **`hyper` vs `axum` coupling** | `utoipa-axum` (`OpenApiRouter`, `routes!`) targets `axum`; core `utoipa` OpenAPI AST is framework-agnostic but requires manual path registration without `axum` | `aide::axum` (`ApiRouter`) mirrors `axum` router ergonomics tightly; raw `hyper` has no built-in extractor/router adapter |
| **Compile-time impact (50-crate workspace)** | **High if placed in domain crates:** `utoipa-gen` parses token streams at compile time for every `ToSchema` and `#[utoipa::path]` across ~900 routes, slowing `cargo check` and IDE expansion (recurring topic in `utoipa` issues #108, #703, #790, #1182). **Mitigated** if isolated strictly to edge adapter crates. | **Moderate:** `schemars_derive` still expands derive macros for DTOs, but route specs use trait composition (`OperationInput`/`OperationOutput`) rather than giant `#[utoipa::path]` attribute macros on every handler. Note `schemars` `0.9` vs `1.x` lag in `aide 0.15.1`. |
| **Contract-first risk** | **Code-first drift risk:** Rust structs drive the OpenAPI JSON; an accidental Rust refactor silently alters the wire contract unless CI enforces `oasdiff` against a committed baseline. | **Same code-first drift risk:** requires CI spec-snapshot diffing (`oasdiff`) to prevent accidental breaking changes for native clients. |

#### C. Rust Server Side — True Schema-First OpenAPI (`TypeSpec` / `oas3-gen` / `openapi-to-rust` / `progenitor`)
- **TypeSpec** ([typespec.io](https://typespec.io), [microsoft/typespec](https://github.com/microsoft/typespec), **MIT**):
  - Concise, TypeScript-like IDL that emits **OpenAPI 3.1** (`@typespec/openapi3`), JSON Schema, and Protobuf (`@typespec/protobuf`). Ideal for reviewing contracts *before* implementation and generating clean OpenAPI 3.1 specs for ~900 routes without 50,000 lines of raw YAML. Node-based compiler fits naturally alongside `mailserver/webmail`'s Node/Vite build (and an independent MIT Rust parser `ejfkdev/typespec-rs` also exists).
- **Rust OpenAPI 3.1 generators (`oas3-gen` & `openapi-to-rust`):**
  - `oas3-gen` ([eklipse2k8/oas3-gen](https://github.com/eklipse2k8/oas3-gen), **MIT**, `v0.29.x`) and `openapi-to-rust` ([gpu-cli/openapi-to-rust](https://github.com/gpu-cli/openapi-to-rust), **MIT**, `v0.23.x+`) parse OpenAPI 3.1 directly into Rust `serde` types, `reqwest` clients, and **`axum` server traits/routers** — including typed `multipart/form-data` and SSE (`text/event-stream`) streams — avoiding `utoipa-gen` proc-macro expansion entirely (generated code is plain Rust structs/traits).
  - *Trade-off:* Both target `axum` (not Setjoin's raw `hyper` `Intercept` trait) and are pre-1.0 (`0.2x`), so adopting them either means mounting generated `axum::Router` slices behind `RouteTable` (`Intercept`) or generating **DTO models/validators only** while keeping Setjoin's existing `hyper` handlers and `authz`/`ScopedExecutor` wiring intact.
- **`progenitor`** ([oxidecomputer/progenitor](https://github.com/oxidecomputer/progenitor), **MPL-2.0**):
  - Generates async `reqwest` Rust clients (not servers), pairs with `dropshot`, and **only supports OpenAPI 3.0.x** (fails on `openapi: 3.1.0`, Issue #1268). Not suitable as Setjoin's primary server contract stack.

---

### 3.2 ConnectRPC / Protobuf (`connectrpc/connect-rust`, `tonic`, `@connectrpc/connect-web`)

- **Primary sources:** [connectrpc/connect-rust](https://github.com/connectrpc/connect-rust), [connectrpc.com/docs/protocol](https://connectrpc.com/docs/protocol), [crates.io/crates/connectrpc](https://crates.io/crates/connectrpc) (`v0.9.1`), [crates.io/crates/buffa](https://crates.io/crates/buffa) (`v0.9.2`), [npm `@connectrpc/connect-web`](https://www.npmjs.com/package/@connectrpc/connect-web) (`v2.3.0`), [hyperium/tonic](https://github.com/hyperium/tonic).
- **Licenses:** `connectrpc` / `connect-rust` / `@connectrpc/connect-web` are **Apache-2.0**; `tonic` / `tonic-web` are **MIT**; `prost` is **Apache-2.0** (`cargo deny` compatible; note `tonic` had `RUSTSEC-2024-0376` fixed in `>=0.12.3`).
- **Rust ecosystem status:**
  - `connectrpc/connect-rust` (contributed by Anthropic) provides `ConnectRpcService` over `tower::Service` (integrating with `hyper` and `axum`), passes the ConnectRPC conformance suite, supports Connect, gRPC, and gRPC-Web protocols over HTTP/1.1 and HTTP/2, and supports unary `GET` (cacheable) & `POST`, JSON + Protobuf dual encoding, and server streaming.
  - However, it is **pre-1.0 (`v0.9.1`)** and builds on **`buffa` (`v0.9.2`)** rather than `prost`, which would introduce a second Protobuf toolchain alongside `prost = "=0.14.4"` in `bins/gateway/Cargo.toml`.
- **Why ConnectRPC fits poorly across Setjoin's ~943 non-JMAP/non-DAV routes:**
  1. **Protocol semantics mismatch:** ConnectRPC mandates `POST /<pkg>.<Service>/<Method>` RPC paths, 16 Connect error codes (`application/json` `{code, message}`), and envelope-framed streaming (`application/connect+proto` / `application/connect+json` returning `HTTP 200 OK` with `EndStreamResponse` trailers). It **breaks** Setjoin's RFC 9457 Problem Details (`bins/gateway/src/problem.rs`), REST resource paths, HTTP `Range` byte-plane downloads (`ARCH-017` Drive), `multipart/form-data` uploads (`multer`), standard browser `EventSource` SSE (`text/event-stream`), OIDC/SAML redirects, and WebSockets (`/rtc`).
  2. **Browser streaming limits:** Browser `fetch` cannot perform client-streaming or full-duplex bidirectional streaming over Connect or gRPC-Web.
  3. **Migration cost & compatibility:** Replacing ~943 HTTP routes with RPC endpoints breaks existing Electron (`mirror.ts`), `offline-core` (`ureq`), Tauri, HarmonyOS, and SCIM/OIDC/webhook integrations, violating incremental route-by-route parity.

---

### 3.3 Type-Only Export (`ts-rs`, `specta`, `typeshare`)

- **Primary sources:** [Aleph-Alpha/ts-rs](https://github.com/Aleph-Alpha/ts-rs) (`v12.x`, **MIT**), [specta-rs/specta](https://github.com/specta-rs/specta) (`v2.0.0-rc.xx`, **MIT**), [1Password/typeshare](https://github.com/1Password/typeshare) (`v1.13.x`, **MIT OR Apache-2.0**).
- **Compile-time & ergonomics comparison:**
  - `ts-rs` uses `#[derive(TS)]` proc-macros and writes `.ts` files when `cargo test` runs.
  - `specta` (`v2.0.0-rc.xx`, still release-candidate status) uses `#[derive(Type)]` proc-macros (`specta-macros`) and targets RPC/IPC (`rspc`, `tauri-specta`) rather than standard REST/OpenAPI HTTP routing.
  - `typeshare` uses a CLI AST parser (`syn`) with minimal `#[typeshare]` markers, avoiding proc-macro expansion overhead during normal `cargo build`/`check` and targeting multi-language FFI (TS, Swift, Kotlin, Go).
- **Why insufficient as the primary HTTP API contract:** None of these three model HTTP methods, URL paths/path-params, query parameters, required headers (`X-Audit-Reason`, `If-Match`, `Range`), status codes, `application/problem+json` error unions, `multipart/form-data`, or SSE/binary streams. Adopting them alone leaves all 900+ route signatures and URL templates unverified between Rust and `mailserver/webmail` (e.g., `adminPathSegment` and `admin/client.ts`). (`typeshare` or `uniffi` remains useful strictly for **local native FFI/IPC** structs, not HTTP contracts.)

---

### 3.4 JMAP-Native Extensions (`urn:setjoin:...`, RFC 8620)

- **Primary source:** [RFC 8620 — JMAP Core](https://datatracker.ietf.org/doc/html/rfc8620) (Capabilities §2, `/jmap` Batch RPC §3, Blob Upload/Download §6, EventSource §7).
- **Assessment for Setjoin:**
  - **Strong fit for PIM/sync domains:** Calendar, Contacts, Tasks (F17/F18) share RFC 8620's `StateChange` + `/get` + `/changes` + `/set` offline-delta model, `blobId` upload/download, and `EventSource` push.
  - **Poor fit for the ~943 non-JMAP/non-DAV routes:** Admin consoles (F01, F03–F08), Auth/OIDC/SAML/WebAuthn/SCIM (F21, F02), Drive Range-based chunk streaming (F14 / `ARCH-017`), Meet SFU/LiveKit signalling & `/rtc` WS (F13), Office WOPI (F15), and public ACME/booking (F08, F20) do not fit `POST /jmap` batched RPC semantics.
  - **No schema IDL or codegen:** RFC 8620 defines a wire protocol, not a machine-readable schema language or Rust↔TS code generator; custom `urn:setjoin:*` capabilities still require OpenAPI / JSON Schema tooling to eliminate hand-written TypeScript types (`src/lib/types/jmap.ts`).

---

## 4. Comparison Matrix Across Setjoin's Evaluation Criteria

| Dimension | **OpenAPI 3.1 + `openapi-typescript` + `openapi-fetch`** (Recommended) | **ConnectRPC (`connect-rust` + `@connectrpc/connect-web`)** | **Type Export (`ts-rs` / `specta` / `typeshare`)** | **JMAP-Native Extensions (`urn:setjoin:*`)** |
|---|---|---|---|---|
| **Primary sources & versions** | `openapi-typescript` `7.13.0`, `openapi-fetch` `0.17.0`; Rust: `utoipa` `6.0.0`, `aide` `0.15.1`, `oas3-gen` `0.29.x`, `TypeSpec` | `connectrpc` `0.9.1`, `buffa` `0.9.2`, `@connectrpc/connect-web` `2.3.0` | `ts-rs` `12.x`, `specta` `2.0.0-rc.xx`, `typeshare` `1.13.x` | IETF RFC 8620 / 8621 |
| **Licence (`deny.toml` check)** | **Pass:** `MIT` / `Apache-2.0` (`progenitor` `MPL-2.0` excluded for 3.0-only) | **Pass:** `Apache-2.0` (`tonic` `MIT`) | **Pass:** `MIT` / `Apache-2.0` | N/A (protocol standard) |
| **Streaming, Uploads, Downloads, SSE** | **Excellent:** `multipart/form-data`, `format: binary`, HTTP `Range`, `parseAs: "stream"`/`"blob"`, RFC 9457 Problem Details, OpenAPI 3.2 SSE `itemSchema` | **Poor for REST/files:** Envelope framing (`200 OK` + `EndStreamResponse`), no `Range`, no `multipart/form-data`, no browser `EventSource`, no Problem Details | **None:** Data structs only; transport unhandled | **Blob + EventSource:** Good for blobs & `StateChange` SSE; no HTTP `Range` chunking or multipart forms |
| **50-Crate Rust Compile-Time Impact** | **Controllable:** Zero in domain crates if isolated to HTTP edge or generated via TypeSpec/`oas3-gen`; high if `utoipa` macros leak into domain crates | **Low–Moderate:** `build.rs` codegen (`buffa-build`), no runtime proc-macros, but adds second Protobuf stack alongside `prost` | `typeshare`: **Zero** proc-macro cost; `ts-rs`/`specta`: moderate derive macro cost | Manual Rust serde structs (no proc-macro codegen required) |
| **Incremental Route-by-Route Adoption** | **Excellent:** Wrap one family/route at a time behind `RouteTable`/`Intercept` & `openapi-fetch` | **Poor:** Requires dual RPC protocol alongside ~943 REST routes or breaking path/error rewrites | **Easy for types**, zero help for routing/client consolidation | **Poor outside PIM:** Forces REST routes into `POST /jmap` batches |
| **Native Client & 12-Month Longevity** | **Excellent:** Wire-compatible HTTP/JSON; CI `oasdiff` enforces additive-only changes for Electron, Tauri, HarmonyOS, `offline-core` | **Poor:** Wire rewrite breaks existing `ureq` / `fetch` native consumers | **Partial:** Protects struct fields only, not URLs/methods/headers | **Good for PIM only** |

---

## 5. Recommended Adoption Architecture for Setjoin

1. **Contract Layer (`openapi/` + `TypeSpec` or modular OpenAPI 3.1):**
   - Organize specs by Setjoin's 22 families (`F01`–`F22`, starting with high-churn REST/admin/Drive/Chat surfaces like `F01`, `F12`, `F14`, `F21`).
   - Run an OpenAPI breaking-change gate (`oasdiff`) in CI to enforce additive-only evolution across the 12-month API longevity window (`docs/research/2026-09-06-extension-api-longevity.md`).
2. **SvelteKit Webmail (`mailserver/webmail`):**
   - Generate `src/lib/api/schema.d.ts` via `openapi-typescript` (`7.13.0`).
   - Expose a single typed `apiClient` built on `openapi-fetch` (`0.17.0`) backed by `httpRequest()` in `src/lib/http.ts` so DPoP proof recovery, `401`/`403` redirects, ToU/risk remediation, and Problem Details parsing stay single-sourced.
   - Retire hand-maintained wrappers in `src/lib/admin/client.ts` (5,009 lines) family by family.
3. **Rust Server (`server-rust`):**
   - Keep `crates/domains/*`, `crates/contracts`, and `crates/pg` **completely free** of OpenAPI proc-macros (`utoipa-gen`, `schemars_derive`).
   - Enforce contract compliance at the `bins/gateway` / `bins/auth` edge: either by generating pure Rust edge DTOs + `axum::Router` slices mounted inside `RouteTable` (`Intercept`) from the OpenAPI 3.1 spec (evaluated via `oas3-gen` / `openapi-to-rust` prototype), or by keeping edge-only `aide`/`utoipa` modules verified against the committed OpenAPI 3.1 contract in `tests/conformance`.
   - Prototype recommendation for #520: spike **one family slice** (e.g., `F14` Drive control-plane + `F01` Admin Users, covering JSON CRUD, `application/problem+json`, `multipart/form-data` CSV import, and SSE) to measure compile-time delta across the 50-crate workspace and validate `openapi-fetch` + DPoP integration before committing to `TypeSpec` + `oas3-gen` vs. edge `aide`/`utoipa`.
