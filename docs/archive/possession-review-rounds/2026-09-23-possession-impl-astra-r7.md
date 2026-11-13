**The fix closes round 6 at `6a67dbd42`, but it is absent from the current integration checkout.**

- Current checkout: `codex/wave1-integration`, HEAD `aebb345f8`. [http.ts:138](/mailserver/webmail/src/lib/http.ts:138) still redirects directly on 401; admission recovery and `HttpBodyTransportError` are absent.
- Corrected commit: `6a67dbd42` on `codex/possession-backend`. Independent in-memory verification reproduced failure before the fix and confirmed caller cancellation, timeout, network failure, and wire cancellation preserve the expected error identity with zero redirects or recovery attempts. Malformed/marker-less controls retain the designed redirect; valid admission recovery succeeds.
- No new blocking code findings in that corrective patch. This was an in-memory harness, not a Vitest run. No files changed.

ASTRA REVIEW: HOLD — the corrected patch passes focused re-review, but the requested integration working tree does not contain it.
