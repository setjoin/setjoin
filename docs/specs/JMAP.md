# JMAP

## Vendor capability — `urn:setjoin:params:jmap:mail`

All nonstandard JMAP properties and methods this program adds are declared under
one vendor capability URN so the nonstandard surface stays auditable in one place.
Clients declare this URN in `using` when invoking any extension below. The URN is
advertised in the Session object's top-level `capabilities` and per-account
`accountCapabilities` (see `internal/jmap/handler.go`, `VendorCapability`).

| Surface | Shape | Reducer |
|---|---|---|
| `snoozeUntil` on `Email/set` update | `{"<id>":{"snoozeUntil":"<RFC3339>"}}` — patch with a non-null `snoozeUntil` is routed to `message_snooze`; `null`/absent is an ordinary patch | `message_snooze(p_account_id, p_message_id, p_until)` |
| `sendAt` on `EmailSubmission/set` create | `{"<k>":{"emailId":"<id>","sendAt":"<RFC3339>"}}` — future `sendAt` keeps the draft and tags it Scheduled (deferred send via the timer pipeline) | `jmap_email_submission_set` → `message_schedule` |
| `EmailSubmission/get` | Lists pending/deferred submissions (Scheduled-tagged messages) with `sendAt`/`undoSendBefore` | `jmap_email_submission_get(p_account_id, p_ids)` |
| `EmailSubmission/query` | Returns ids of pending/deferred submissions ordered by `sendAt` | `jmap_email_submission_query(p_account_id, p_filter, p_position, p_limit)` |
| `effectiveAccess: true` (vendor flag) | Signals that the server computes per-user app entitlements and B8.4 enforcement is active. Present in the top-level `capabilities[VendorCapability]` map. | (capability declaration only — no reducer) |
| `newsletterBundles: true` (vendor flag) | Signals that the server supports the `Email/bundles` vendor method for computed newsletter grouping. Present in the top-level `capabilities[VendorCapability]` map. | (capability declaration only — see `Email/bundles` below) |
| `delegateGrants` / `sendAsAliases` (per delegated account) | `accountCapabilities[VendorCapability]` carries the caller's raw mail delegate grants plus an ordered alias list. `sendAsAliases` is populated only for an enabled mailbox when the caller has `send_as` or `full_access`; it is empty for read-only and send-on-behalf-only grants. A client selecting an alias must submit with that delegated `accountId`. | `send(p_user_id, p_mailbox_id, …)` remains authoritative |
| `Email/bundles` (vendor method) | Returns computed newsletter bundles grouped by `list_id`. Request: `{accountId, limit?, position?}`. Response: `{accountId, bundles: [{listId, count, latestEmailId, latestReceivedAt}], position}`. Per-user opt-out via `users.view_prefs->'newsletterOptouts'` (set via `PUT /settings/newsletter-bundles`). Excludes Trash/Spam messages and NULL `list_id` (non-newsletter) messages. | `newsletter_bundles_list(p_account_id, p_limit, p_offset)` |

## Session extensions

### `effectiveCapabilities` (B8.3)

Added to the top-level Session object alongside `purgeConfig` and `branding`. Shape:

```json
{
  "apps":     { "mail": true, "calendar": true, "contacts": true, "tasks": true },
  "features": { "assist": false, "bundles": false }
}
```

Resolved by calling `effective_capabilities(mailboxID)` — the PL/pgSQL reducer that ANDs the global `feature.{app}` toggle with any per-user `user_app_entitlements` row. Fails open: on DB error or nil-pool, defaults to all apps `true`, assist/bundles `false`. Enforcement lives in the B8.4 middleware; this session key is informational only (for UI visibility gating in M2/M7).

Standard RFC 8621 §7 `onSuccessUpdateEmail` on `EmailSubmission/set` is also
honoured (tag-on-send): when present, the draft survives the send and the
requested `mailboxIds`/`keywords` patch is applied via `jmap_email_set_update`;
when absent, the draft is deleted (legacy behaviour).
