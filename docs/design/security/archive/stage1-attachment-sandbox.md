# Attachment Sandbox / Detonation — Design Spec

> **Roadmap item:** Stage 1.4 — "Enterprise Deal-Qualifier" security checkbox
> **Date:** 2026-05-31 | **Effort:** ~4 weeks | **Filed under:** `mailserver/gateway/internal/smtp/sandbox.go`

## Goal

Detonate email attachments in an isolated CAPE sandbox before delivery, blocking or quarantining payloads that exhibit malicious behavior — built-in and included in the base product, unlike EXO which requires a Defender add-on.

## Architecture

A new `SandboxClient` in the SMTP package wraps the CAPE sandbox REST API. On inbound delivery (port 25), after ClamAV signature scanning passes, MIME attachments of high-risk types (Office docs, PDFs, executables, archives) are submitted to CAPE for behavioral analysis. Results are checked synchronously with a configurable timeout (default 120s); if the sandbox is unreachable, the `fail_mode` setting controls whether delivery proceeds (fail-open, default for initial rollout) or defers (fail-closed). Detonated payloads are either rejected (SMTP 554) or quarantined per admin configuration.

## Files to Create/Modify

| File | Action | Purpose |
|------|--------|---------|
| `mailserver/gateway/internal/smtp/sandbox.go` | **Create** | CAPE sandbox client: submit file, poll task status, interpret score (malicious/suspicious/clean) |
| `mailserver/gateway/internal/smtp/sandbox_test.go` | **Create** | Unit tests with httptest CAPE stub |
| `mailserver/gateway/internal/smtp/inbound.go` | **Modify** | Wire `SandboxClient` into delivery pipeline after ClamAV, before reducer commit; add `SetSandbox()` + health check |
| `mailserver/gateway/internal/smtp/helpers.go` | **Modify** | Add `detectAttachmentTypes()` helper: classify MIME parts into sandbox-relevant categories |
| `mailserver/gateway/internal/config/config.go` | **Modify** | Add env vars: `SANDBOX_CAPE_URL`, `SANDBOX_CAPE_API_KEY`, `SANDBOX_TIMEOUT`, `SANDBOX_FAIL_MODE`, `SANDBOX_ENABLED` |
| `mailserver/sql/migrations/V0NN__sandbox_config.sql` | **Create** | Per-domain sandbox settings: `sandbox_enabled`, `sandbox_action` (reject/quarantine), `sandbox_file_types` |
| `authserver/internal/handlers/admin_domains.go` | **Modify** | Expose sandbox config in domain admin API (if domain CRUD already exists; otherwise defer to Phase 13 admin console) |

## Key Design Decisions

- **CAPE over Cuckoo.** CAPE is the actively maintained fork of Cuckoo Sandbox, supports more file types (Office macros, PDF JavaScript, PowerShell, MSI installers), and has a stable REST API. Cuckoo has been unmaintained since 2019.
- **Two-phase pipeline: signature first, behavior second.** ClamAV runs first (sub-second). Only clean files that match high-risk MIME types proceed to sandbox detonation. This avoids sandbox cost for known-signature malware and text-only emails (>90% of volume).
- **Sync with timeout, not async.** The sandbox check blocks delivery with a configurable deadline (default 120s). Async would require out-of-band notification to recipients and complex retry logic. CAPE can return results in 60-120s for most Office/PDF files. Archival attachment scanning (ZIP/RAR/7z) may take longer; files exceeding the timeout are handled per `fail_mode`.
- **Per-domain configuration.** Sandbox sensitivity varies by organization: a law firm may want every PDF detonated; a marketing agency may only care about executables. Settings live in the `domains` table, overridable via gateway env vars as system defaults. Initially configurable only via SQL; admin UI deferred to Phase 13.

## Dependencies

- **ClamAV (Phase 7)** — already integrated in `clamav.go`; no changes needed except ordering in the pipeline
- **SMTP inbound pipeline (Phase 4)** — the hook point; already has pluggable security steps (SPF → DKIM → DMARC → ClamAV → greylisting → deliver)
- **CAPE Sandbox** — deployed as a separate VM or container, not bundled. The customer provides the CAPE instance URL and API key. We provide an Ansible role and `scripts/setup-cape.sh` for single-command install on Ubuntu 24.04.
- **7-platform competitive matrix** (line 177): EXO and Gmail offer attachment sandboxing only through add-ons (Defender for Office 365 P1/P2). No Chinese competitor documents this capability. We are the **only on-premise platform offering it built-in at no per-seat cost**, matching our structural advantage of "no per-seat licensing."

## Effort Estimate

| Component | Effort |
|-----------|--------|
| `sandbox.go` — CAPE client (submit, poll, score interpretation) | 1 week |
| Pipeline integration in `inbound.go` + MIME classification in `helpers.go` | 1 week |
| Configuration (env vars + DB schema + domain overrides) | 0.5 weeks |
| Unit tests + CAPE stub + integration test | 0.5 weeks |
| Ansible role + `scripts/setup-cape.sh` + documentation | 1 week |
| **Total** | **~4 weeks** |
