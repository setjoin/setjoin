# Number-Match Push MFA — Design Spec

> **Roadmap:** 1.2 — Stage 1 "Enterprise Deal-Qualifier"
> **Status:** Design draft
> **Scope:** Auth server push challenge provider + handler; mobile app push receiver; webmail login UI

## Goal

Replace the current 6-digit-code-entry push MFA with industry-standard 2-digit number matching (login screen shows number; push notification offers 3 choices; user taps the match) to prevent MFA fatigue attacks.

## Architecture

The existing `PushMFAProvider` already generates a challenge code, stores it in `push_mfa_challenges`, dispatches Web Push notifications, and validates answers with row-level locking. The change is mechanical: shrink the code space from 6 digits (1M combinations) to 2 digits (100), change the push payload from a code display to a 3-option picker, and wire the picker response to the existing `POST /auth/push/verify` endpoint. The login screen returns the 2-digit challenge number in the MFA-required response so the webmail and mobile apps can display it prominently while the push notification renders the choice UI.

## Files to Create/Modify

| File | Action | Purpose |
|------|--------|---------|
| `authserver/internal/authn/push.go` | Modify (~30 lines changed) | `GenerateChallenge`: 2-digit code; `dispatchNotifications`: payload with 3 options (1 correct + 2 decoys); `sendPush`: updated notification schema |
| `authserver/internal/handlers/push.go` | Modify (~10 lines changed) | `PushMFAVerify`: accept 2-digit answer; return challenge number in login MFA response |
| `authserver/internal/handlers/auth.go` | Modify (~5 lines changed) | `Login`: include `challenge_number` (the 2-digit code) in the push MFA response body alongside `push_nonce` |
| `mailserver/webmail/src/lib/components/MFAChallenge.svelte` | Modify (~20 lines) | Display the 2-digit number prominently; poll or wait for push verification |
| **Mobile apps** (iOS/Android, Phase 12) | New (~100 lines each) | Push notification extension: render 3-button choice UI; POST answer to `/auth/push/verify` |
| **Total** | **~5 files** | **~265 lines** (mostly mobile push extension; Go changes ~45 lines) |

## Key Design Decisions

- **2-digit code space (100 combinations).** Shrinks from current 6-digit (1M). The smaller space is safe because (a) challenges are single-use with 3-attempt lockout, (b) expires in 120 seconds, (c) rate-limited to 3 challenges per user per 5 minutes. Brute-force probability: 3 attempts / 100 combinations = 3% per challenge, further gated by the 5-minute rate window. This matches Microsoft Authenticator's 2-digit design.
- **Number displayed on login screen, matched in push notification.** This is the core anti-fatigue property: the user cannot approve without seeing both screens. The current flow (code sent to device, typed on login screen) lacks this property because a user receiving a push notification can type the code without seeing the login screen. The new flow forces cross-device attention.
- **Push payload carries 3 numbers: 1 correct + 2 random decoys.** The decoys are generated server-side and shuffled. The mobile push extension renders them as 3 labeled buttons. Tapping any button POSTs to `/auth/push/verify` with the `mfa_token`, `nonce`, and selected `answer`. The server validates the answer against the stored challenge — same `VerifyChallenge` path, no new endpoint needed.
- **Webmail login UI shows the challenge number with a countdown timer.** After receiving `{"mfa_required":true, "mfa_method":"push", "push_nonce":"...", "challenge_number":"42"}`, the webmail renders a large 2-digit display with a 120-second expiry countdown. It polls `GET /auth/me` (or receives a WebSocket event) to detect when the push challenge is verified and the session is active. No code entry field — the user acts on their phone, not the login screen.

## Dependencies

- **Phase 12 mobile apps** (Roadmap 1.1): Push notification extension (Notification Service Extension on iOS, FirebaseMessagingService on Android) must render the 3-button choice UI. Until mobile apps ship, number-match works exclusively through webmail + browser push (limited: browsers do not support interactive notification actions reliably in the background).
- **Web Push subscription on webmail**: Browser push must already be registered for webmail users. The existing `push_devices` table and Web Push registration flow (`POST /auth/me/push-devices`) already handles this.
- **Competitive context**: EXO permanently enforces number matching since May 2023. Google enforces it for Google Workspace since 2024. Both display the number on the login screen and require matching in the authenticator app. Our design matches this exact UX.

## Effort Estimate

| Component | Effort |
|-----------|--------|
| Go provider + handler changes | 1 day |
| Webmail login UI (challenge display, countdown, polling) | 1 day |
| Mobile push extension (iOS notification service + Android service) | 2 days |
| Integration testing (web + push + TOTP fallback) | 1 day |
| **Total** | **~5 days (~1 week)** |

## Non-Goals

- **FIDO2/WebAuthn cross-device hybrid** (QR code + Bluetooth). Number-match is the pragmatic step between tap-to-approve and full passkey adoption. WebAuthn passkeys are already implemented and remain the gold standard; number-match push is the bridge for users who cannot or will not enroll passkeys.
- **Push notification without number match** (tap-to-approve fallback). Once number-match ships, tap-to-approve is removed entirely — no kill switch, no legacy path. This matches EXO's May 2023 enforcement.
- **SMS fallback for push.** Not in scope. Backup codes and TOTP remain the fallback methods when push is unavailable.

---

## Mobile Push Extension API

### Push Notification Payload

The push notification JSON payload delivered to devices:

```json
{
  "type": "mfa_challenge",
  "nonce": "a1b2c3d4e5f6...",
  "options": [
    {"value": "42", "label": "42"},
    {"value": "17", "label": "17"},
    {"value": "89", "label": "89"}
  ],
  "timestamp": 1717200000
}
```

- `nonce`: 32-byte hex-encoded challenge identifier, passed back in the verify call
- `options`: 3 labelled buttons in random order — one correct, two decoys
- `timestamp`: Unix epoch seconds for freshness check

### Mobile Extension Requirements

**iOS (UNNotificationContentExtension):**
- Render 3 tappable buttons labelled with the option values
- User taps one button to select their answer
- POST `{"mfa_token": "...", "nonce": "...", "answer": "<selected>"}` to `/auth/push/verify`
- Show success/failure inline in the notification

**Android (FirebaseMessagingService):**
- Use notification actions (up to 3) to display labelled buttons
- Each action triggers a broadcast receiver that POSTs the answer to `/auth/push/verify`
- Show result via a follow-up notification or inline
