# AI Assist API

setjoin exposes a thin HTTP wrapper around an OpenAI-compatible chat-completions
endpoint for compose assist and the ops copilot.

---

## Endpoints

### `POST /assist/complete`

**Auth:** `Authorization: Bearer <access_token>` (standard JWT access token).  
**Rate limit:** same per-IP bucket as `/auth/*` (20 req / 15 min).  
**Feature gate:** `feature.assist` must be enabled (admin toggle); 403 if off.

#### Request

```json
{
  "messages": [
    { "role": "user", "content": "Summarize this email thread." }
  ],
  "context": "compose",
  "locale": "en"
}
```

| Field      | Type              | Required | Description |
|------------|-------------------|----------|-------------|
| `messages` | `Message[]`       | yes      | Conversation turns. Roles: `system`, `user`, `assistant`. |
| `context`  | `string`          | no       | Short descriptor folded into a leading system message (e.g. `"compose"`, `"reply"`). |
| `locale`   | `string` (BCP-47) | no       | User's preferred response locale. |

**Validation:**
- `messages` must be non-empty and each message must have non-empty `content`.
- Total content size (messages + context) must not exceed 512 KiB.
- `role` must be one of `system`, `user`, `assistant`.

#### Response — success (200)

```json
{ "content": "Here is a concise summary..." }
```

#### Response — errors (RFC 7807 Problem Details)

| Status | `type` URI | Condition |
|--------|-----------|-----------|
| 401 | `https://setjoin.com/errors/unauthorized` | Missing or invalid JWT |
| 403 | `https://setjoin.com/errors/forbidden` | `feature.assist` is off for this account |
| 422 | `https://setjoin.com/errors/validation-failed` | Empty messages, oversized content, invalid role |
| 502 | `https://setjoin.com/errors/internal-error` | Upstream provider returned an error |
| 503 | `https://setjoin.com/errors/service-unavailable` | `assist.provider_url` or `assist.model` not configured in `system_config` |

---

### `POST /assist/stream` — Reserved (501)

SSE streaming is reserved for a future wave. This endpoint always returns
`501 Not Implemented` with a problem detail pointing callers to use
`POST /assist/complete` instead.

---

## Provider Configuration

The AI provider is configured at runtime via `system_config` keys (no restart
required):

| Key | Description |
|-----|-------------|
| `assist.provider_url` | Base URL of the OpenAI-compatible endpoint (e.g. `https://api.openai.com/v1`, `http://localhost:11434/v1`). **Required.** |
| `assist.model` | Model name passed in the request body (e.g. `gpt-4o`, `llama3`). **Required.** |
| `assist.api_key` | Bearer token for the provider. Optional for local deployments. |

Use `PUT /admin/system/config/assist.provider_url` (super-admin) to set these
keys at runtime. Until they are set the endpoint returns 503.

Compatibility: any OpenAI-compatible chat-completions API is supported —
OpenAI, Azure OpenAI (in OpenAI-compat mode), Ollama, vLLM, LM Studio.

---

## Feature Gate

The `feature.assist` toggle in the `feature_toggles` table controls the global
kill-switch for all users. Set via `PUT /admin/features/feature.assist`.

Per-user assist token budgets (spec §7 B4) are deferred to a later wave; the
gate currently only checks the global toggle.

---

## Security Notes

- The upstream provider error body is **never** forwarded to clients (prevents
  information disclosure from provider-side error messages).
- The `assist.api_key` is stored as a plaintext JSON string in `system_config`
  (at-rest DB encryption for this key is deferred; see `internal/assist/config.go`
  package comment for the upgrade path).
- The handler respects `context.Context` cancellation — client disconnects abort
  the upstream request.
