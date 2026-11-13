# AI Email Features — Design Spec

> **Roadmap item:** Stage 3.3 — "AI Email Features"
> **Date:** 2026-05-31 | **Effort:** ~8 weeks | **Filed under:** `mailserver/gateway/internal/ai/`

## Goal

Integrate a local LLM backend (Ollama / llama.cpp) for on-premise AI email features with zero cloud dependency. Four capabilities: smart compose (inline draft suggestions while typing), smart reply (one-click contextual responses), auto-tagging (classify incoming mail into categories), and tone adjustment (rewrite drafts as formal/casual/brief). All data stays on-premise — no telemetry, no third-party API calls.

## Architecture

A new `mailserver/gateway/internal/ai/` package provides a single `Client` interface abstracting the LLM backend. Two drivers initially: Ollama (HTTP REST, local) and llama.cpp (HTTP via llama-server). The client sends structured prompts with email context, receives streaming or batch responses, and returns parsed results to callers.

Gateway routes under `/ai/*` proxy to the AI client, enforcing RequireAuth. The webmail SvelteKit frontend calls these routes directly — compose/reply suggestions stream via SSE; tagging and tone are batch requests.

```
┌───────────────┐     HTTP/SSE      ┌──────────┐    REST     ┌──────────┐
│  SvelteKit UI  │ ◄──────────────► │ Gateway  │ ◄─────────► │  Ollama  │
│  (webmail)     │   /ai/compose     │ /ai/*    │            │  :11434  │
└───────────────┘   /ai/reply       └──────────┘            └──────────┘
                    /ai/tag
                    /ai/tone
```

Smart compose and smart reply use SSE streaming so suggestions appear incrementally as the model generates tokens — matching the UX pattern users expect from Gmail's Smart Compose and DingTalk's AI assistant. Auto-tagging and tone adjustment are batch (request → response) since they operate on complete text.

The AI client is **optional**: if no LLM backend is configured (no `AI_BACKEND_URL`), the `/ai/*` routes return 503 with a clear message. The webmail UI hides AI affordances when the capability is absent.

## Files to Create/Modify

| File | Action | Purpose |
|------|--------|---------|
| `mailserver/gateway/internal/ai/client.go` | **Create** | `Client` interface: `Compose(ctx, prompt) <-chan TokenStream`, `Reply(ctx, thread) <-chan TokenStream`, `Tag(ctx, email) ([]Tag, error)`, `Tone(ctx, text, style) (string, error)`, `Health(ctx) error` |
| `mailserver/gateway/internal/ai/ollama.go` | **Create** | Ollama driver: `/api/generate` with structured prompts, streaming SSE parse, model validation |
| `mailserver/gateway/internal/ai/llamacpp.go` | **Create** | llama.cpp driver: `/completion` endpoint, same Client interface |
| `mailserver/gateway/internal/ai/prompts.go` | **Create** | Prompt templates per feature: system prompts, few-shot examples, output format constraints (JSON for tagging, plain text for compose/reply) |
| `mailserver/gateway/internal/ai/client_test.go` | **Create** | Unit tests with httptest LLM stub; prompt template validation; output parse tests |
| `mailserver/gateway/internal/handlers/ai.go` | **Create** | HTTP handlers: `/ai/compose`, `/ai/reply`, `/ai/tag`, `/ai/tone` — RequireAuth, SSE setup, error mapping |
| `mailserver/gateway/internal/config/config.go` | **Modify** | Add env vars: `AI_BACKEND_URL` (default ""), `AI_BACKEND_TYPE` (ollama/llamacpp), `AI_MODEL_NAME` (default "llama3.2"), `AI_MAX_TOKENS`, `AI_TEMPERATURE` |
| `mailserver/gateway/cmd/gateway/main.go` | **Modify** | Init AI client (if configured), register `/ai/*` routes |
| `mailserver/webmail/src/lib/ai/` | **Create** | Frontend AI integration: `compose.ts` (SSE consumer), `reply.ts`, `tag.ts`, `tone.ts` — wrappers around fetch + EventSource |
| `mailserver/webmail/src/lib/components/ComposeAI.svelte` | **Create** | Inline suggestion chip below compose editor; ghost text or suggestion bar |
| `mailserver/webmail/src/lib/components/ReplyAI.svelte` | **Create** | One-click smart reply buttons (3 short suggestions above reply box) |
| `mailserver/webmail/src/lib/components/TagSuggest.svelte` | **Create** | Tag suggestion badges in message view header, accept/reject UX |
| `mailserver/webmail/src/lib/stores/ai.ts` | **Create** | `aiEnabled` store (derived from `/health` or config), per-feature opt-in toggles |

## Key Design Decisions

- **Local-first, not cloud.** Ollama and llama.cpp are the only backends. No OpenAI, Anthropic, or any cloud API. This is a structural differentiator: DingTalk and NetEase AI features phone home to Alibaba/NetEase cloud. Our on-premise customers — especially government, finance, healthcare — cannot send email content to third parties. Local LLM eliminates the data residency objection entirely.

- **One Client interface, pluggable backends.** The `Client` interface abstracts the LLM. Ollama is the primary target (simplest setup, broad model support, built-in GPU acceleration). llama.cpp is the fallback for minimal-resource deployments. Adding a third backend (vLLM, LocalAI) requires only a new `client.go` implementation.

- **Streaming for compose/reply, batch for tag/tone.** Compose and reply suggestions must feel instant — SSE streaming with incremental token delivery matches the UX cadence of Gmail's Smart Compose. Tagging and tone adjustment operate on complete text and benefit from the full model context; batch is simpler and sufficient.

- **Prompt engineering, not fine-tuning.** We ship prompt templates with few-shot examples, not fine-tuned models. This lets customers use any model they have (Llama 3.1/3.2, Qwen 2.5, Mistral, DeepSeek) without retraining. Tagging prompts constrain output to JSON with a closed tag vocabulary; tone prompts include before/after examples. Prompts are stored as Go constants in `prompts.go` — version-controlled, auditable, no runtime prompt injection risk.

- **Tag vocabulary is configurable, not hardcoded.** Default categories (Invoice, Support, Personal, Newsletter, Social, Receipt, Travel, Legal) ship as defaults. Admins can customize via the `system_config` table (`ai.tag_categories`). The model receives the current vocabulary in the system prompt.

- **Privacy boundaries enforced in the gateway, not the model.** The gateway strips email content to a bounded context window before sending to the LLM: compose sends the draft text + subject; reply sends the thread's last N messages (configurable, default 5); tagging sends subject + body preview (first 2KB); tone sends only the selected text. No full-mailbox access, no contact graph, no recipient addresses sent to the model. Attachment content is never sent.

- **Opt-in, not always-on.** Each AI feature has a user-level toggle (stored in `user_settings` or local storage). No suggestions appear without explicit opt-in. The admin can disable AI entirely via `AI_BACKEND_URL=""` or per-feature via `system_config`.

## Dependencies

- **Ollama** (https://ollama.com) — local REST API on `:11434`. Customer provides the Ollama installation and model. We document recommended models (llama3.2:3b for low-resource, qwen2.5:7b for Chinese-language deployments, mistral:7b for general use). Script `scripts/setup-ollama.sh` provides single-command install + model pull.
- **llama.cpp** (https://github.com/ggerganov/llama.cpp) — alternative backend via `llama-server`. Lower resource floor (runs on CPU), but slower and less polished API. Supported for customers who cannot run Ollama.
- **Phase 8 webmail** — TipTap editor integration hooks; existing compose and message-view components are the UI anchor points.
- **Phase 17 tag system** — auto-tagging writes into the existing `message_tags` table via the tag reducer API. No schema changes needed.
- **7-platform competitive matrix** (line item "AI-powered email features"): DingTalk (AI Premium: smart compose, reply, auto-tagging), NetEase (Premier: AI writing, tone adjustment, multi-language), Lark/Feishu (Smart Inbox AI prioritization, writing assistant). All three gate AI behind premium tiers. Gmail and EXO have no on-premise AI email offering. We are the **only on-premise platform offering AI email features with zero cloud dependency**, matching our structural advantage of air-gap-capable deployment.

## Effort Estimate

| Component | Effort |
|-----------|--------|
| `ai/client.go` + `ollama.go` + `llamacpp.go` — Client interface, two drivers, streaming SSE parse | 2 weeks |
| `ai/prompts.go` — Prompt templates per feature, few-shot examples, output format constraints, tag vocabulary | 1 week |
| `handlers/ai.go` — HTTP routes, RequireAuth, SSE setup, error mapping, feature toggles | 1 week |
| Configuration (env vars, `system_config`, health check, feature-flag integration) | 0.5 weeks |
| Unit tests + LLM stub + integration test | 1 week |
| Webmail frontend: `lib/ai/` wrappers, `ComposeAI`, `ReplyAI`, `TagSuggest` Svelte components | 1.5 weeks |
| `scripts/setup-ollama.sh` + model recommendations doc + admin docs | 0.5 weeks |
| Chinese-language prompt quality pass (Qwen-native prompts, not translated English) | 0.5 weeks |
| **Total** | **~8 weeks** |
