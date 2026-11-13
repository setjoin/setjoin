# Webhook System — Design Spec

## Summary

Admin and user webhook subscriptions with CloudEvents 1.0.2 envelope, Standard Webhooks signatures, programmatic replay, dual-secret rotation, queue-first delivery with 3-tier retries, and OpenAPI/AsyncAPI auto-discovery. Designed for AI agent integration.

---

## Part 1: Event Catalog & CloudEvents Envelope

### Event Types

| Category | Event Type | Source | Who Can Subscribe |
|----------|-----------|--------|-------------------|
| `admin` | `user.created` | `mailserver/auth` | Admin only |
| `admin` | `user.deleted` | `mailserver/auth` | Admin only |
| `admin` | `user.updated` | `mailserver/auth` | Admin only |
| `admin` | `auth.login_failed` | `mailserver/auth` | Admin only |
| `admin` | `auth.login` | `mailserver/auth` | Admin only |
| `admin` | `mailbox.quota_warning` | `mailserver/gateway` | Admin only |
| `admin` | `system.health_alert` | `mailserver/gateway` | Admin only |
| `admin` | `migration.completed` | `mailserver/gateway` | Admin only |
| `admin` | `migration.failed` | `mailserver/gateway` | Admin only |
| `mailbox` | `mail.received` | `mailserver/gateway` | Admin, User (own) |
| `mailbox` | `mail.sent` | `mailserver/gateway` | Admin, User (own) |
| `mailbox` | `mail.rule_triggered` | `mailserver/gateway` | Admin, User (own) |
| `mailbox` | `calendar.invitation` | `mailserver/gateway` | Admin, User (own) |

12 initial events. Extensible — new events added to the catalog without schema migration.

### CloudEvents 1.0.2 Envelope

Every webhook POST uses the CloudEvents format:

```json
{
  "specversion": "1.0",
  "id": "evt_clq2z3a4b0001",
  "source": "mailserver/auth",
  "type": "user.created",
  "time": "2026-05-23T15:30:00Z",
  "datacontenttype": "application/json",
  "data": {
    "user_id": 42,
    "email": "alice@local.com",
    "created_by": "admin@local.com"
  }
}
```

`id` format: `evt_` + 13-char nanoid (URL-safe, collision-resistant). All timestamps in RFC 3339 UTC.

### Event Catalog Endpoint

`GET /admin/webhooks/events` returns the full catalog as JSON — machine-readable, no docs needed:

```json
[
  {
    "type": "user.created",
    "category": "admin",
    "source": "mailserver/auth",
    "description": "A new user account was created",
    "data_schema": { "$ref": "#/components/schemas/UserCreatedEvent" }
  }
]
```

`GET /admin/webhooks/events?category=admin` filters by category. `GET /admin/webhooks/events?category=admin,mailbox` for multiple.

---

## Part 2: Signature Verification (Standard Webhooks)

### Format

Every outgoing POST includes:

```
X-Webhook-Signature: v1,t=1716480000,sig=c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2
```

### Construction

1. Take the **raw request body bytes** (never serialized JSON)
2. Construct the signed content: `<timestamp>.<raw_body>`
3. HMAC-SHA256 with the endpoint's signing secret → hex
4. Format: `v1,t=<unix_timestamp>,sig=<hex_hmac>`

### Verification (Receiver Side)

```go
func VerifySignature(body []byte, header string, secret string) bool {
    // Parse: v1,t=<ts>,sig=<sig>
    parts := parseSignatureHeader(header) // v=1, t=1716480000, sig=abc...
    if parts["v"] != "1" { return false }
    
    // Reject old timestamps (5 min tolerance)
    ts, _ := strconv.ParseInt(parts["t"], 10, 64)
    if abs(time.Now().Unix()-ts) > 300 { return false }
    
    // Compute expected signature
    signed := fmt.Sprintf("%s.%s", parts["t"], string(body))
    mac := hmac.New(sha256.New, []byte(secret))
    mac.Write([]byte(signed))
    expected := hex.EncodeToString(mac.Sum(nil))
    
    // Timing-safe comparison
    return subtle.ConstantTimeCompare([]byte(expected), []byte(parts["sig"])) == 1
}
```

### Secret Management

- Each webhook subscription gets a unique 32-byte random secret (auto-generated)
- Dual-secret rotation: subscription stores `secret` and `prev_secret`. During rotation, try `secret` first, fall back to `prev_secret` for 48 hours
- `POST /admin/webhooks/{id}/rotate-secret` triggers rotation
- 90-day rotation reminders via system health notifications

---

## Part 3: Subscription Model

### Schema

```sql
CREATE TABLE webhook_subscriptions (
    id              BIGSERIAL    PRIMARY KEY,
    user_id         BIGINT       REFERENCES users(id) ON DELETE CASCADE,  -- NULL = admin-created
    url             TEXT         NOT NULL,
    secret          TEXT         NOT NULL,  -- current signing secret (SHA-256 hashed)
    prev_secret     TEXT,                   -- previous secret during rotation window
    event_types     JSONB        NOT NULL DEFAULT '[]',  -- array of event type strings
    is_active       BOOL         NOT NULL DEFAULT TRUE,
    retry_enabled   BOOL         NOT NULL DEFAULT TRUE,
    max_retries     INT          NOT NULL DEFAULT 12,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE TABLE webhook_deliveries (
    id              BIGSERIAL    PRIMARY KEY,
    subscription_id BIGINT       NOT NULL REFERENCES webhook_subscriptions(id) ON DELETE CASCADE,
    event_id        TEXT         NOT NULL,  -- CloudEvents id
    event_type      TEXT         NOT NULL,
    request_body    JSONB        NOT NULL,
    response_code   INT,                    -- HTTP status from destination
    response_body   TEXT,
    latency_ms      INT,
    attempt         INT          NOT NULL DEFAULT 1,
    status          TEXT         NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','success','failed','exhausted')),
    error_message   TEXT,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    completed_at    TIMESTAMPTZ
);

CREATE UNIQUE INDEX webhook_deliveries_event_subscription_idx ON webhook_deliveries(subscription_id, event_id);
```

### Routes

| Method | Path | Role | Description |
|--------|------|------|-------------|
| `GET` | `/admin/webhooks/events` | Admin | Event catalog |
| `POST` | `/admin/webhooks` | Super admin | Create admin webhook |
| `GET` | `/admin/webhooks` | Admin | List admin webhooks |
| `GET` | `/admin/webhooks/{id}` | Admin | Get webhook details |
| `PUT` | `/admin/webhooks/{id}` | Super admin | Update webhook |
| `DELETE` | `/admin/webhooks/{id}` | Super admin | Delete webhook |
| `POST` | `/admin/webhooks/{id}/rotate-secret` | Super admin | Rotate signing secret |
| `GET` | `/admin/webhooks/{id}/deliveries` | Admin | Delivery log |
| `POST` | `/admin/webhooks/{id}/replay` | Admin | Replay failed deliveries |
| `GET` | `/admin/webhooks/openapi.json` | Admin | OpenAPI spec |
| `GET` | `/admin/webhooks/asyncapi.json` | Admin | AsyncAPI spec |
| `POST` | `/auth/me/webhooks` | Authenticated | Create user webhook |
| `GET` | `/auth/me/webhooks` | Authenticated | List own webhooks |
| `DELETE` | `/auth/me/webhooks/{id}` | Authenticated | Delete own webhook |

---

## Part 4: Delivery Pipeline

### Queue-First Architecture

```
Event Emitted
    │
    ▼
Find matching subscriptions (WHERE event_type = ANY(sub.event_types))
    │
    ▼
For each subscription:
    ├─ Write delivery row (status=pending)
    ├─ Compute signature
    ├─ HTTP POST to subscription.url
    │   ├─ 2xx → status=success, done
    │   ├─ 4xx (not 429) → status=failed (permanent), DLQ
    │   ├─ 429 → respect Retry-After header, retry
    │   └─ 5xx/timeout → schedule retry
    └─ Queue-retry loop with backoff
```

### 3-Tier Retry Model

| Tier | Attempts | Intervals | Total Window | After |
|------|----------|-----------|-------------|-------|
| 1 — Immediate | 0-2 | 500ms, 1s, 2s | ~3.5s | Move to tier 2 |
| 2 — Short | 3-6 | 30s, 2m, 5m, 15m | ~22min | Move to tier 3 |
| 3 — Long | 7-11 | 1h, 4h, 8h, 16h, 24h | ~53h (~2 days) | DLQ |

All retries include random jitter (±25%). Total: 12 attempts over ~2 days.

### Circuit Breaker

Per-destination circuit breaker:
- Trip after 10 consecutive failures within 5 minutes
- Half-open after 2 minutes: allow 1 test delivery
- If test succeeds → close circuit (resume)
- If test fails → stay open for 5 more minutes

### Delivery Log Retention

`log_retention_webhook_delivery_days` → 30 days (configurable in admin retention page). Auto-pruned by existing `prune_log_tables()`.

---

## Part 5: Programmatic Replay

`POST /admin/webhooks/{id}/replay`

```json
{
  "event_ids": ["evt_abc", "evt_def"],
  "time_window": null
}
```

Or by time window:

```json
{
  "event_ids": null,
  "time_window": {"from": "2026-05-20T00:00:00Z", "to": "2026-05-22T00:00:00Z"}
}
```

Writes to `admin_audit_log` with the admin who triggered the replay, event count, and reason.

---

## Part 6: AI-Friendly API Surface

### OpenAPI 3.1

`GET /admin/webhooks/openapi.json` — full REST API spec for AI agent consumption. Describes all CRUD endpoints, request/response schemas, auth requirements.

### AsyncAPI 3.0

`GET /admin/webhooks/asyncapi.json` — event-driven API spec describing all webhook event types, their CloudEvents envelope, the delivery channel (HTTP POST), and signature verification requirements. AI agents can auto-discover the full integration surface.

### Available to AI Consumers

An AI agent can:
1. `GET /admin/webhooks/events` — discover what events exist
2. `POST /admin/webhooks` — register a webhook with its own URL
3. Receive signed CloudEvents — verify and process
4. `GET /admin/webhooks/{id}/deliveries` — monitor delivery health
5. `POST /admin/webhooks/{id}/replay` — recover from downtime via replay

No SDK needed. No custom protocol. Standard formats throughout.

---

## Part 7: Admin UI

### Admin Webhooks Page

`/admin/webhooks` — lists all webhook subscriptions with status, URL, event count, last delivery. Create/edit/delete/rotate-secret buttons. Delivery log table below with pagination. Replay button for failed deliveries.

Tabs: `[Active Webhooks] [Delivery Log] [Event Catalog]`

### User Settings

Settings page gets a "Webhooks" section. Users see their own webhooks only. Same create/delete flow as admin but scoped to their mailbox events.

---

## Part 8: What's NOT in Scope

| Item | Why |
|------|-----|
| Webhook event filtering (field-level) | Start with type-level subscription. Add JMESPath/JSONPath filtering later. |
| Webhook transformation templates | Transform payload before delivery. V2 feature. |
| Webhook batching | Send multiple events in one call. Optimization for high-volume mailboxes. |
| Kafka/NATS internal bus | Queue-first with PG is sufficient for initial scale. Add event mesh if needed. |
| Webhook rate limiting (per destination) | Covered by circuit breaker initially. |
| User-to-user webhook forwarding | Security concern — needs trust model design. |

---

## Files Summary

| Action | File | Responsibility |
|--------|------|----------------|
| Create | `mailserver/sql/migrations/V021__webhooks.sql` | Schema for subscriptions + deliveries |
| Create | `shared/webhook/sign.go` | HMAC-SHA256 signer/verifier (Standard Webhooks format) |
| Create | `shared/webhook/cloud_event.go` | CloudEvents envelope builder |
| Create | `mailserver/gateway/internal/handlers/admin_webhooks.go` | Admin CRUD + replay + catalog |
| Create | `mailserver/gateway/internal/handlers/user_webhooks.go` | User self-service CRUD |
| Create | `mailserver/gateway/internal/webhook/dispatcher.go` | Queue-first delivery + 3-tier retry |
| Modify | `mailserver/gateway/cmd/gateway/main.go` | Register routes + start dispatcher |
| Create | `mailserver/gateway/internal/webhook/dispatcher_test.go` | Delivery pipeline tests |
| Create | `mailserver/webmail/src/routes/admin/webhooks/+page.svelte` | Admin webhooks UI |
| Modify | `mailserver/webmail/src/routes/settings/+page.svelte` | User webhooks section |
| Modify | `mailserver/webmail/src/routes/admin/+layout.svelte` | Nav entry |
| Modify | `mailserver/webmail/src/lib/admin/client.ts` | Types + API functions |
| Modify | `mailserver/sql/reducers/retention.sql` | Add webhook delivery to prune_log_tables |
| Modify | `mailserver/gateway/internal/handlers/admin_retention.go` | Add webhook delivery days config |
